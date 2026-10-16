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
# the most a PUT (or a GET's reply) of each kind may carry; serve(max_body=...) overrides
LIMITS = {"jobs": 1 << 20, "traces": MAX_BODY, "signed": 4 << 20}
TIMEOUT = 30.0                   # seconds the server waits on a silent client socket


class StoreError(RuntimeError):
    pass


class NotFound(StoreError):
    pass


class Tampered(StoreError):
    """The blob does not hash to the key it was stored or fetched under."""


class TooLarge(StoreError):
    """The blob is over the store's size limit for its kind (HTTP 413)."""


class Unavailable(StoreError):
    """The store could not be reached (connection refused, reset or timed out)."""


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


# ------------------------------------------------------------------------------- write auth
# A server started with `writers` takes a PUT only when it carries an ed25519 signature, by an
# allow-listed key, over put_message(kind, key, body). Replaying one only rewrites the same
# blob under the same key, so the message needs no nonce.
PUT_TAG = b"tdcc-exact/put/v1"
SIGNER, SIGNATURE = "X-Tdcc-Signer", "X-Tdcc-Signature"


class Unauthorized(StoreError):
    """The server takes writes only from allow-listed keys (HTTP 401/403)."""


def put_message(kind: str, key, raw: bytes) -> bytes:
    return hashlib.sha256(PUT_TAG + kind.encode() + b"\0" + bytes.fromhex(_key(key))
                          + hashlib.sha256(raw).digest()).digest()


def sign_put(owner, kind: str, key, raw: bytes) -> dict:
    """The headers that authorize `owner` (a solders Keypair) to PUT `raw` under key."""
    return {SIGNER: bytes(owner.pubkey()).hex(),
            SIGNATURE: bytes(owner.sign_message(put_message(kind, key, raw))).hex()}


def verify_put(signer: bytes, sig_hex: str, kind: str, key, raw: bytes) -> bool:
    from solders.pubkey import Pubkey
    from solders.signature import Signature
    try:
        return Signature.from_bytes(bytes.fromhex(sig_hex)).verify(
            Pubkey.from_bytes(signer), put_message(kind, key, raw))
    except (TypeError, ValueError):
        return False


def parse_pubkey(s: str) -> bytes:
    """32 bytes from a public key written as 64 hex digits or base58."""
    s = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return bytes.fromhex(s)
    from solders.pubkey import Pubkey
    try:
        return bytes(Pubkey.from_string(s))
    except ValueError as e:
        raise StoreError(f"not a public key: {s!r}") from e


class AllowList:
    """The keys allowed to write: a file of public keys (hex or base58), one per line, `#`
    comments. It is re-read when it changes, so keys can be added without a restart."""

    def __init__(self, path):
        self.path, self._mtime, self._keys = Path(path), None, frozenset()
        self._lock = threading.Lock()
        self.keys()                                     # a bad file fails now, not on a PUT

    def keys(self) -> frozenset:
        with self._lock:
            m = self.path.stat().st_mtime_ns
            if m != self._mtime:
                lines = (ln.split("#", 1)[0].strip() for ln in self.path.read_text().splitlines())
                self._keys, self._mtime = frozenset(parse_pubkey(ln) for ln in lines if ln), m
            return self._keys

    def __contains__(self, signer: bytes) -> bool:
        return signer in self.keys()


def load_keypair(path):
    """A Solana CLI keypair file (a JSON list of 64 bytes)."""
    from solders.keypair import Keypair
    return Keypair.from_bytes(bytes(json.loads(Path(path).read_text())))


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
    """A client of a store server. It checks every blob it fetches, and reads no more of a
    reply than `max_body` allows for its kind (a server cannot make it buffer a huge blob)."""

    def __init__(self, url: str, timeout: float = 30.0, max_body: dict | None = None,
                 key=None):
        """key: a solders Keypair that signs every PUT (for a server that takes writes
        only from allow-listed keys)."""
        self.url, self.timeout, self.key = url.rstrip("/"), timeout, key
        self.max_body = {**LIMITS, **(max_body or {})}

    def _req(self, method: str, path: str, body: bytes | None = None,
             limit: int = MAX_BODY, headers: dict | None = None) -> bytes:
        req = urllib.request.Request(self.url + path, body, method=method,
                                     headers={"Content-Type": "application/json",
                                              **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = r.read(limit + 1)
        except urllib.error.HTTPError as e:
            msg = e.read(4096).decode(errors="replace")
            code = {401: Unauthorized, 403: Unauthorized, 404: NotFound, 413: TooLarge,
                    422: Tampered}.get(e.code)
            if code:
                raise code(msg) from e
            raise StoreError(f"{method} {path}: {e.code} {msg}") from e
        except OSError as e:                 # URLError, reset, timeout
            raise Unavailable(f"{method} {self.url}{path}: {e}") from e
        if len(data) > limit:
            raise TooLarge(f"{method} {path}: the reply is over {limit} bytes")
        return data

    def put_raw(self, kind: str, key, raw: bytes) -> None:
        CHECK[kind](raw, key)
        auth = sign_put(self.key, kind, key, raw) if self.key is not None else None
        self._req("PUT", f"/{ROUTE_OF[kind]}/{_key(key)}", raw, headers=auth)

    def get_raw(self, kind: str, key) -> bytes:
        k = _key(key)
        raw = self._req("GET", f"/{ROUTE_OF[kind]}/{k}", limit=self.max_body[kind])
        CHECK[kind](raw, k)
        return raw

    def put_job(self, job: Job) -> str:
        k = job.digest.hex()
        self.put_raw("jobs", k, job_json(job))
        return k

    def get_job(self, key) -> Job:
        k = _key(key)
        return job_from_json(self.get_raw("jobs", k), k)

    def put_trace(self, trace: dict) -> str:
        k = trace_root(trace)
        self.put_raw("traces", k, json.dumps(trace).encode())
        return k

    def get_trace(self, key) -> dict:
        k = _key(key)
        return trace_from_json(self.get_raw("traces", k), k)

    def put_signed(self, note: dict) -> str:
        k = signed_key(note["topic"], note["job"], note["signer"])
        self.put_raw("signed", k, json.dumps(note).encode())
        return k

    def get_signed(self, key) -> dict:
        k = _key(key)
        return signed_from_json(self.get_raw("signed", k), k)


def open_store(where: str, key=None):
    """An http(s):// URL is a store server (PUTs signed by `key` if given); anything else a
    directory."""
    return HttpStore(where, key=key) if re.match(r"^https?://", where) else DirStore(where)


# ------------------------------------------------------------------------------- server
# A key is exactly 64 lowercase hex digits: anything else (../, %2e%2e, an overlong or short
# key, upper case, a query string) is refused before it comes near the filesystem.
ROUTE = re.compile(r"^/(job|trace|signed)/([0-9a-f]{64})$")
PREFIX = re.compile(r"^/(job|trace|signed)/")
KINDS = {"job": "jobs", "trace": "traces", "signed": "signed"}
ROUTE_OF = {v: k for k, v in KINDS.items()}


class _Refuse(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code, self.msg = code, msg


def _handler(store: DirStore, opts: dict):
    limits = {**LIMITS, **(opts.get("max_body") or {})}
    writers = opts.get("writers")

    class H(BaseHTTPRequestHandler):
        timeout = opts.get("timeout", TIMEOUT)      # socket timeout: a stalled client is cut off

        def _route(self):
            m = ROUTE.match(self.path)
            if not m:
                if PREFIX.match(self.path):
                    raise _Refuse(400, "a key is 64 lowercase hex digits")
                raise _Refuse(404, "no such route")
            return KINDS[m.group(1)], m.group(2)

        def _send(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if code == 200 else
                             "text/plain")
            self.send_header("Content-Length", str(len(body)))
            if code >= 400:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _body(self, kind: str) -> bytes:
            """The PUT's body, refused unread if it is too large, chunked or unsized."""
            if self.headers.get("Transfer-Encoding"):
                raise _Refuse(411, "a PUT needs a Content-Length (no chunked bodies)")
            n = self.headers.get("Content-Length")
            if n is None:
                raise _Refuse(411, "a PUT needs a Content-Length")
            if not n.strip().isdigit():
                raise _Refuse(400, "bad Content-Length")
            n = int(n)
            if n > limits[kind]:
                raise _Refuse(413, f"a {NAME[kind]} is at most {limits[kind]} bytes")
            raw = self.rfile.read(n)
            if len(raw) != n:
                raise _Refuse(400, "the body ended early")
            return raw

        def _do(self, fn):
            try:
                fn()
            except _Refuse as e:
                self._send(e.code, e.msg.encode())
            except NotFound as e:
                self._send(404, str(e).encode())
            except Tampered as e:
                self._send(422, str(e).encode())
            except (TimeoutError, ConnectionError):
                self.close_connection = True         # the client stalled or went away

        def do_GET(self):  # noqa: N802
            self._do(lambda: self._send(200, store.get_raw(*self._route())))

        def _signer(self) -> bytes | None:
            """With an allow list: the PUT's signer, refused before its body is read when
            there is none or it is not on the list."""
            if writers is None:
                return None
            h = self.headers.get(SIGNER)
            if not h or not self.headers.get(SIGNATURE):
                raise _Refuse(401, f"this store takes signed writes only ({SIGNER}, "
                                   f"{SIGNATURE})")
            try:
                signer = parse_pubkey(h)
            except StoreError as e:
                raise _Refuse(401, str(e)) from e
            if signer not in writers:
                raise _Refuse(403, f"{h} may not write here")
            return signer

        def do_PUT(self):  # noqa: N802
            def put():
                kind, key = self._route()
                signer = self._signer()
                raw = self._body(kind)
                if signer is not None and not verify_put(signer, self.headers[SIGNATURE],
                                                         kind, key, raw):
                    raise _Refuse(403, "the signature is not the signer's over this PUT")
                store.put_raw(kind, key, raw)
                self._send(200, b'{"ok": true}')
            self._do(put)

        def log_message(self, fmt, *args):    # quiet; the CLI prints its own lines
            pass

    return H


class StoreServer(ThreadingHTTPServer):
    daemon_threads = True


def serve(store: DirStore, host: str = "127.0.0.1", port: int = 8787, *,
          max_body: dict | None = None, timeout: float = TIMEOUT,
          writers=None) -> StoreServer:
    """A store server (not started: call .serve_forever(), or `start` for a thread).

    max_body  {kind: bytes} over LIMITS: a larger PUT gets 413 before its body is read
    timeout   seconds a request may sit idle on its socket before the server drops it
    writers   None (anyone may write: every blob is checked against its key anyway), or a
              container of 32-byte public keys (an AllowList): a PUT must then be signed by
              one of them (sign_put), else 401 (unsigned) or 403 (not listed, bad signature)
    """
    return StoreServer((host, port), _handler(store, dict(max_body=max_body, timeout=timeout,
                                                          writers=writers)))


def start(store: DirStore, host: str = "127.0.0.1", port: int = 0, **opts):
    """A store server on a daemon thread: (server, its URL). server.shutdown() stops it."""
    srv = serve(store, host, port, **opts)
    threading.Thread(target=srv.serve_forever, args=(0.1,), daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"
