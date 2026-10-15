"""A content-addressed store for jobs and traces: what the chain names by hash, kept off-chain.

    jobs    keyed by Job.digest (hex): the renter publishes the Job JSON; whoever fetches it
            recomputes the digest and rejects anything that does not match the key
    traces  keyed by the trace root (hex): a provider publishes its checkpoints after it
            reveals; a fetcher recomputes the Merkle root over the checkpoints' leaves

Two backends with one interface (put_job / get_job / put_trace / get_trace):

    DirStore(path)        files under path/jobs and path/traces
    HttpStore(url)        a client of `serve(DirStore, port)`: GET/PUT /job/<hex>, /trace/<hex>

The server checks every PUT the same way, so it never holds a blob under a key it does not
hash to, but clients do not trust it: they check every GET themselves.
"""
from __future__ import annotations

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


def job_json(job: Job) -> bytes:
    return json.dumps(asdict(job), sort_keys=True).encode()


# ------------------------------------------------------------------------------- backends
class DirStore:
    def __init__(self, path):
        self.path = Path(path)
        for kind in ("jobs", "traces"):
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
            raise NotFound(f"no {kind[:-1]} {_key(key)}")
        return p.read_bytes()

    # raw, checked on the way in and out (the server uses these)
    def put_raw(self, kind: str, key, raw: bytes) -> None:
        (job_from_json if kind == "jobs" else trace_from_json)(raw, key)
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


def open_store(where: str):
    """An http(s):// URL is a store server; anything else a directory."""
    return HttpStore(where) if re.match(r"^https?://", where) else DirStore(where)


# ------------------------------------------------------------------------------- server
ROUTE = re.compile(r"^/(job|trace)/([0-9a-fA-F]{64})$")


def _handler(store: DirStore):
    class H(BaseHTTPRequestHandler):
        def _route(self):
            m = ROUTE.match(self.path)
            if not m:
                self._send(404, b"no such route")
                return None
            return ("jobs" if m.group(1) == "job" else "traces"), m.group(2).lower()

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
