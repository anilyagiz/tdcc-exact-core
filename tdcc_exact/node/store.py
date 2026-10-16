"""A content-addressed store for jobs and traces: what the chain names by hash, kept off-chain.

    jobs    keyed by Job.digest (hex): the renter publishes the Job JSON; whoever fetches it
            recomputes the digest and rejects anything that does not match the key
    traces  keyed by the trace root (hex): a provider publishes its checkpoints after it
            reveals; a fetcher recomputes the Merkle root over the checkpoints' leaves
    signed  notes a party signs about one job, keyed by signed_key(topic, job, signer) =
            H(tag || topic || job || signer): the key is computable from the chain alone
            (the job account, its provider or verifier) and only the signer can fill it, so
            no one can squat it. A fetcher checks the key and the ed25519 signature. Topics:
            "challenge"        a verifier's pointer to the trace it challenged with
            "window/<lo>/<hi>" a provider's revealed window of steps (lo, hi] (see
                               tdcc_exact/node/__init__.py for the protocol)

Two backends with one interface (put_job / get_job / put_trace / get_trace / put_signed /
get_signed):

    DirStore(path)        files under path/jobs, path/traces and path/signed
    HttpStore(url)        a client of `serve(DirStore, port)`: GET/PUT /job/<hex>,
                          /trace/<hex>, /signed/<hex>

The server checks every PUT the same way, so it never holds a blob under a key it does not
hash to, but clients do not trust it: they check every GET themselves.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..oracle import Job
from ..trace import Checkpoint, merkle_root

KEY = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 64 << 20              # bytes per PUT (a trace of a large model's run fits)


class StoreError(RuntimeError):
    pass


class NotFound(StoreError):
    pass


class Tampered(StoreError):
    """The blob does not hash to the key it was stored or fetched under."""


def _key(key: str | bytes) -> str:
    k = key.hex() if isinstance(key, (bytes, bytearray)) else str(key).lower()
    if not KEY.match(k):
        raise StoreError(f"not a 32-byte hex key: {k!r}")
    return k


# ------------------------------------------------------------------------------- checks
def job_from_json(raw: bytes | str, key: str | bytes) -> Job:
    """Parse a Job and check that its digest is `key` (Tampered otherwise)."""
    k = _key(key)
    try:
        job = Job(**json.loads(raw))
    except (TypeError, ValueError) as e:
        raise Tampered(f"job {k[:16]}..: not a Job ({e})") from e
    if job.digest.hex() != k:
        raise Tampered(f"job {k[:16]}..: digest is {job.digest.hex()[:16]}..")
    return job


def trace_root(trace: dict) -> str:
    return merkle_root([Checkpoint.from_json(c).leaf for c in trace["checkpoints"]]).hex()


def trace_from_json(raw: bytes | str, key: str | bytes) -> dict:
    """Parse a trace (TraceLog.to_json) and check that its checkpoints' root is `key`."""
    k = _key(key)
    try:
        trace = json.loads(raw)
        root = trace_root(trace)
    except (TypeError, ValueError, KeyError, IndexError) as e:
        raise Tampered(f"trace {k[:16]}..: not a trace ({e})") from e
    if root != k:
        raise Tampered(f"trace {k[:16]}..: root is {root[:16]}..")
    return trace


SIGNED_TAG = b"tdcc-exact/signed/v1"


def _b32(x) -> bytes:
    """32 bytes from a public key, bytes or hex."""
    b = bytes.fromhex(x) if isinstance(x, str) else bytes(x)
    if len(b) != 32:
        raise StoreError(f"not 32 bytes: {len(b)}")
    return b


def signed_key(topic: str, job, signer) -> str:
    """Where `signer`'s note on `topic` about the on-chain `job` lives (hex)."""
    return hashlib.sha256(SIGNED_TAG + topic.encode() + b"\0" + _b32(job)
                          + _b32(signer)).hexdigest()


def _signed_message(key: str, body) -> bytes:
    return hashlib.sha256(SIGNED_TAG + bytes.fromhex(key)
                          + json.dumps(body, sort_keys=True).encode()).digest()


def sign_note(owner, topic: str, job, body) -> dict:
    """A note `owner` (a solders Keypair) signs: {topic, job, signer, body, sig}."""
    signer = bytes(owner.pubkey())
    k = signed_key(topic, job, signer)
    sig = owner.sign_message(_signed_message(k, body))
    return {"topic": topic, "job": _b32(job).hex(), "signer": signer.hex(), "body": body,
            "sig": bytes(sig).hex()}


def signed_from_json(raw: bytes | str, key: str | bytes) -> dict:
    """Parse a signed note and check its key and signature (Tampered otherwise)."""
    from solders.pubkey import Pubkey
    from solders.signature import Signature
    k = _key(key)
    try:
        note = json.loads(raw)
        want = signed_key(note["topic"], note["job"], note["signer"])
        msg = _signed_message(k, note["body"])
        ok = Signature.from_bytes(bytes.fromhex(note["sig"])).verify(
            Pubkey.from_bytes(bytes.fromhex(note["signer"])), msg)
    except (TypeError, ValueError, KeyError, StoreError) as e:
        raise Tampered(f"note {k[:16]}..: not a signed note ({e})") from e
    if want != k:
        raise Tampered(f"note {k[:16]}..: its topic, job and signer give {want[:16]}..")
    if not ok:
        raise Tampered(f"note {k[:16]}..: the signature is not the signer's")
    return note


NAME = {"jobs": "job", "traces": "trace", "signed": "signed note"}
CHECK = {"jobs": lambda raw, k: job_from_json(raw, k),
         "traces": lambda raw, k: trace_from_json(raw, k),
         "signed": lambda raw, k: signed_from_json(raw, k)}


def job_json(job: Job) -> bytes:
    return json.dumps(asdict(job), sort_keys=True).encode()


# ------------------------------------------------------------------------------- backends
class DirStore:
    def __init__(self, path):
        self.path = Path(path)
        for kind in CHECK:
            (self.path / kind).mkdir(parents=True, exist_ok=True)

    def _file(self, kind: str, key) -> Path:
        return self.path / kind / f"{_key(key)}.json"

    def _write(self, kind: str, key, raw: bytes) -> None:
        p = self._file(kind, key)
        if p.exists():
            return                                       # content-addressed: same bytes' worth
        fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        os.replace(tmp, p)

    def _read(self, kind: str, key) -> bytes:
        p = self._file(kind, key)
        if not p.exists():
            raise NotFound(f"no {NAME[kind]} {_key(key)}")
        return p.read_bytes()

    # raw, checked on the way in and out (the server uses these)
    def put_raw(self, kind: str, key, raw: bytes) -> None:
        CHECK[kind](raw, key)
        self._write(kind, key, raw)

    def get_raw(self, kind: str, key) -> bytes:
        return self._read(kind, key)

    def put_job(self, job: Job) -> str:
        k = job.digest.hex()
        self.put_raw("jobs", k, job_json(job))
        return k

    def get_job(self, key) -> Job:
        return job_from_json(self._read("jobs", key), key)

    def put_trace(self, trace: dict) -> str:
        k = trace_root(trace)
        self.put_raw("traces", k, json.dumps(trace).encode())
        return k

    def get_trace(self, key) -> dict:
        return trace_from_json(self._read("traces", key), key)

    def put_signed(self, note: dict) -> str:
        k = signed_key(note["topic"], note["job"], note["signer"])
        self.put_raw("signed", k, json.dumps(note).encode())
        return k

    def get_signed(self, key) -> dict:
        return signed_from_json(self._read("signed", key), key)


class HttpStore:
    def __init__(self, url: str, timeout: float = 30.0):
        self.url, self.timeout = url.rstrip("/"), timeout

    def _req(self, method: str, path: str, body: bytes | None = None) -> bytes:
        req = urllib.request.Request(self.url + path, body, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")
            if e.code == 404:
                raise NotFound(msg) from e
            if e.code == 422:
                raise Tampered(msg) from e
            raise StoreError(f"{method} {path}: {e.code} {msg}") from e

    def put_job(self, job: Job) -> str:
        k = job.digest.hex()
        self._req("PUT", f"/job/{k}", job_json(job))
        return k

    def get_job(self, key) -> Job:
        k = _key(key)
        return job_from_json(self._req("GET", f"/job/{k}"), k)

    def put_trace(self, trace: dict) -> str:
        k = trace_root(trace)
        self._req("PUT", f"/trace/{k}", json.dumps(trace).encode())
        return k

    def get_trace(self, key) -> dict:
        k = _key(key)
        return trace_from_json(self._req("GET", f"/trace/{k}"), k)

    def put_signed(self, note: dict) -> str:
        k = signed_key(note["topic"], note["job"], note["signer"])
        self._req("PUT", f"/signed/{k}", json.dumps(note).encode())
        return k

    def get_signed(self, key) -> dict:
        k = _key(key)
        return signed_from_json(self._req("GET", f"/signed/{k}"), k)


def open_store(where: str):
    """An http(s):// URL is a store server; anything else a directory."""
    return HttpStore(where) if re.match(r"^https?://", where) else DirStore(where)


# ------------------------------------------------------------------------------- server
ROUTE = re.compile(r"^/(job|trace|signed)/([0-9a-fA-F]{64})$")
KINDS = {"job": "jobs", "trace": "traces", "signed": "signed"}


def _handler(store: DirStore):
    class H(BaseHTTPRequestHandler):
        def _route(self):
            m = ROUTE.match(self.path)
            if not m:
                self._send(404, b"no such route")
                return None
            return KINDS[m.group(1)], m.group(2).lower()

        def _send(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if code == 200 else
                             "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            r = self._route()
            if r is None:
                return
            try:
                self._send(200, store.get_raw(*r))
            except NotFound as e:
                self._send(404, str(e).encode())

        def do_PUT(self):  # noqa: N802
            r = self._route()
            if r is None:
                return
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self._send(413, b"too large")
                return
            raw = self.rfile.read(n)
            try:
                store.put_raw(r[0], r[1], raw)
            except Tampered as e:
                self._send(422, str(e).encode())
                return
            self._send(200, b'{"ok": true}')

        def log_message(self, fmt, *args):    # quiet; the CLI prints its own lines
            pass

    return H


def serve(store: DirStore, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    """A store server (not started: call .serve_forever(), or `start` for a thread)."""
    return ThreadingHTTPServer((host, port), _handler(store))


def start(store: DirStore, host: str = "127.0.0.1", port: int = 0):
    """A store server on a daemon thread: (server, its URL). server.shutdown() stops it."""
    srv = serve(store, host, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"
