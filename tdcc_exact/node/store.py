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
import queue
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import asdict, dataclass, field
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
BLOB = re.compile(r"^([0-9a-f]{64})\.json$")
TEMP_GRACE = 3600.0              # seconds before gc takes a temp file for a crashed write's


def load_pins(path) -> set[str]:
    """A pin file: keys (64 hex digits) gc never deletes, one per line, `#` comments."""
    lines = (ln.split("#", 1)[0].strip() for ln in Path(path).read_text().splitlines())
    return {_key(ln) for ln in lines if ln}


@dataclass
class GcReport:
    deleted: list = field(default_factory=list)      # (kind, key) of blobs past retention
    pinned: list = field(default_factory=list)       # (kind, key) past it but pinned
    temps: list = field(default_factory=list)        # leftover temp files of crashed writes
    kept: int = 0
    dry_run: bool = False

    def __str__(self) -> str:
        verb = "would delete" if self.dry_run else "deleted"
        return (f"gc: {verb} {len(self.deleted)} blobs and {len(self.temps)} temp files; "
                f"kept {self.kept} ({len(self.pinned)} pinned past retention)")


class DirStore:
    """Blobs in path/<kind>/<key>.json. A write goes to a temp file (.<key>.*.tmp), is
    fsynced, then renamed into place, so a crash leaves at most a temp file, which no read
    sees and gc removes; never a half blob under a key."""

    def __init__(self, path):
        self.path = Path(path)
        for kind in CHECK:
            (self.path / kind).mkdir(parents=True, exist_ok=True)
        # orders gc's check-then-delete against a write refreshing the same blob, so a blob
        # stored again while gc runs is never deleted after the write was acknowledged
        self._gc_lock = threading.Lock()

    def _file(self, kind: str, key) -> Path:
        return self.path / kind / f"{_key(key)}.json"

    def _write(self, kind: str, key, raw: bytes) -> bool:
        """True if the blob is new. Storing one again refreshes its time (gc's clock)."""
        p = self._file(kind, key)
        if p.exists():
            try:
                with self._gc_lock:
                    os.utime(p)
                return False                         # content-addressed: same bytes' worth
            except FileNotFoundError:
                pass                                 # gc took it just now: write it again
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.stem}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp)
            raise
        with suppress(OSError):                      # make the rename itself durable
            d = os.open(p.parent, os.O_RDONLY)
            try:
                os.fsync(d)
            finally:
                os.close(d)
        return True

    def _read(self, kind: str, key) -> bytes:
        try:
            return self._file(kind, key).read_bytes()
        except FileNotFoundError:
            raise NotFound(f"no {NAME[kind]} {_key(key)}") from None

    # raw, checked on the way in and out (the server uses these)
    def put_raw(self, kind: str, key, raw: bytes) -> bool:
        """Store raw under key after checking it; True if it was not there before."""
        CHECK[kind](raw, key)
        return self._write(kind, key, raw)

    def gc(self, retention: float | None = None, pins=(), dry_run: bool = False,
           now: float | None = None, temp_grace: float = TEMP_GRACE) -> GcReport:
        """Delete blobs last stored more than `retention` seconds ago (None: keep all),
        except pinned keys, and temp files older than `temp_grace` (crashed writes).
        dry_run reports what it would delete and deletes nothing."""
        now = time.time() if now is None else now
        pins = {_key(k) for k in pins}
        r = GcReport(dry_run=dry_run)
        for kind in CHECK:
            for f in (self.path / kind).iterdir():
                try:
                    age = now - f.stat().st_mtime
                except FileNotFoundError:
                    continue
                m = BLOB.match(f.name)
                if m is None:
                    if f.name.endswith(".tmp") and age > temp_grace:
                        r.temps.append(str(f))
                        if not dry_run:
                            with suppress(FileNotFoundError):
                                f.unlink()
                    continue
                key = m.group(1)
                if retention is None or age <= retention:
                    r.kept += 1
                elif key in pins:
                    r.pinned.append((kind, key))
                    r.kept += 1
                else:
                    if dry_run:
                        r.deleted.append((kind, key))
                        continue
                    with self._gc_lock, suppress(FileNotFoundError):
                        if now - f.stat().st_mtime > retention:   # not stored again since
                            f.unlink()
                            r.deleted.append((kind, key))
                            continue
                    r.kept += 1
        return r

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
                    422: Tampered, 503: Unavailable}.get(e.code)
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


class QuorumError(StoreError):
    """Fewer stores than the quorum took a write."""


class StoreClient:
    """Several stores as one: a write goes to all of them at once and succeeds when `quorum`
    (default: a majority) have taken it; a read tries them in order and returns the first
    blob that hashes to its key, so a store that is down, lacks the blob or lies is skipped.

    A read is NotFound only when every store answered and none had a good copy; when one
    could not be reached the error is Unavailable, so a node retries rather than concluding
    a blob was never published."""

    def __init__(self, stores, quorum: int | None = None, key=None):
        self.stores = [open_store(s, key=key) if isinstance(s, str) else s for s in stores]
        if not self.stores:
            raise StoreError("no stores")
        n = len(self.stores)
        self.quorum = n // 2 + 1 if quorum is None else quorum
        if not 1 <= self.quorum <= n:
            raise StoreError(f"quorum {self.quorum} of {n} stores")
        self._pool = ThreadPoolExecutor(max_workers=n, thread_name_prefix="store-put")

    def _where(self, s) -> str:
        return getattr(s, "url", None) or str(getattr(s, "path", s))

    def put_raw(self, kind: str, key, raw: bytes) -> None:
        CHECK[kind](raw, key)                          # a bad blob goes nowhere
        futs = {self._pool.submit(s.put_raw, kind, key, raw): s for s in self.stores}
        ok, errors = 0, []
        for f in as_completed(futs):
            try:
                f.result()
                ok += 1
            except (StoreError, OSError) as e:
                errors.append(f"{self._where(futs[f])}: {e}")
            if ok >= self.quorum:
                return                                 # the rest finish in the background
            if len(errors) > len(self.stores) - self.quorum:
                break
        raise QuorumError(f"{NAME[kind]} {_key(key)[:16]}..: {ok} of {len(self.stores)} "
                          f"stores took it, {self.quorum} needed; " + "; ".join(errors))

    def get_raw(self, kind: str, key) -> bytes:
        k, errors = _key(key), []
        for s in self.stores:
            try:
                raw = s.get_raw(kind, k)
                CHECK[kind](raw, k)
                return raw
            except (StoreError, OSError) as e:
                errors.append(e)
        msg = f"{NAME[kind]} {k[:16]}..: " + "; ".join(
            f"{self._where(s)}: {e}" for s, e in zip(self.stores, errors))
        if all(isinstance(e, Tampered) for e in errors):
            raise Tampered(msg)
        if all(isinstance(e, (NotFound, Tampered)) for e in errors):
            raise NotFound(msg)
        raise Unavailable(msg)

    def put_job(self, job: Job) -> str:
        k = job.digest.hex()
        self.put_raw("jobs", k, job_json(job))
        return k

    def get_job(self, key) -> Job:
        return job_from_json(self.get_raw("jobs", key), key)

    def put_trace(self, trace: dict) -> str:
        k = trace_root(trace)
        self.put_raw("traces", k, json.dumps(trace).encode())
        return k

    def get_trace(self, key) -> dict:
        return trace_from_json(self.get_raw("traces", key), key)

    def put_signed(self, note: dict) -> str:
        k = signed_key(note["topic"], note["job"], note["signer"])
        self.put_raw("signed", k, json.dumps(note).encode())
        return k

    def get_signed(self, key) -> dict:
        return signed_from_json(self.get_raw("signed", key), key)


def open_store(where: str, key=None, quorum: int | None = None):
    """An http(s):// URL is a store server (PUTs signed by `key` if given); anything else a
    directory. Several, comma-separated, are one StoreClient (quorum: a majority)."""
    if "," in where:
        return StoreClient([w.strip() for w in where.split(",") if w.strip()], quorum, key)
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
    writers, mirror = opts.get("writers"), opts.get("mirror")

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
                if store.put_raw(kind, key, raw) and mirror is not None:
                    mirror.push(kind, key)
                self._send(200, b'{"ok": true}')
            self._do(put)

        def log_message(self, fmt, *args):    # quiet; the CLI prints its own lines
            pass

    return H


MAX_CLIENTS = 64
BUSY = (b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\n"
        b"Content-Length: 4\r\nRetry-After: 1\r\nConnection: close\r\n\r\nbusy")


class StoreServer(ThreadingHTTPServer):
    """A thread per connection, at most `max_clients` at once (more get 503 at once).
    DirStore is safe under concurrent requests: writes are temp file + rename, so a GET
    racing a PUT of the same key sees the whole blob or none."""
    daemon_threads = True
    _stop: threading.Event | None = None
    mirror: Mirror | None = None
    _slots: threading.BoundedSemaphore | None = None

    def process_request(self, request, client_address):
        if self._slots is not None and not self._slots.acquire(blocking=False):
            with suppress(OSError):
                request.sendall(BUSY)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            if self._slots is not None:
                self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            if self._slots is not None:
                self._slots.release()

    def shutdown(self) -> None:
        if self._stop is not None:
            self._stop.set()
        super().shutdown()


class Mirror:
    """Pushes each blob the server newly accepts to other stores, one worker per mirror (a
    dead one delays no other), retrying with backoff. Blobs stored before it started are not
    pushed; a mirror that refuses a blob as tampered or too large is not retried."""

    def __init__(self, store: DirStore, urls, key=None, stop: threading.Event | None = None,
                 tries: int = 6, backoff: float = 1.0, log=None):
        self.store, self.tries, self.backoff, self.log = store, tries, backoff, log
        self.stop = stop or threading.Event()
        self.queues = []
        for url in urls:
            q: queue.Queue = queue.Queue()
            self.queues.append(q)
            threading.Thread(target=self._work, args=(HttpStore(url, key=key), q),
                             daemon=True).start()

    def push(self, kind: str, key: str) -> None:
        for q in self.queues:
            q.put((kind, key))

    def join(self) -> None:
        """Wait until every queued push is done (delivered or given up)."""
        for q in self.queues:
            q.join()

    def _work(self, dst: HttpStore, q: queue.Queue) -> None:
        while not self.stop.is_set():
            try:
                kind, key = q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._send(dst, kind, key)
            finally:
                q.task_done()

    def _send(self, dst: HttpStore, kind: str, key: str) -> None:
        for i in range(self.tries):
            try:
                dst.put_raw(kind, key, self.store.get_raw(kind, key))
                return
            except NotFound:
                return                                  # gc took it meanwhile
            except (Tampered, TooLarge, Unauthorized) as e:
                err = e
                break                                   # retrying will not help
            except (StoreError, OSError) as e:
                err = e
                if self.stop.wait(min(60.0, self.backoff * 2 ** i)):
                    return
        if self.log:
            self.log(f"mirror {dst.url}: gave up on {kind}/{key}: {err}")


def parse_duration(v: str) -> float:
    """Seconds from 90, 90s, 15m, 12h, 30d or 2w."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", str(v))
    if not m:
        raise ValueError(f"not a duration: {v!r} (want e.g. 90s, 15m, 12h, 30d)")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400,
                                "w": 604800}[m.group(2)]


def _gc_loop(store: DirStore, stop: threading.Event, retention, pins, every: float, log):
    while True:
        try:
            # a pin file is re-read each pass, so pins can be added while the server runs
            p = load_pins(pins) if isinstance(pins, (str, os.PathLike)) else (pins or ())
            r = store.gc(retention, p)
            if log and (r.deleted or r.temps):
                log(str(r))
        except Exception as e:  # noqa: BLE001 - a bad pin file must not stop the server
            if log:
                log(f"gc: {e}")
        if stop.wait(every):
            return


def serve(store: DirStore, host: str = "127.0.0.1", port: int = 8787, *,
          max_body: dict | None = None, timeout: float = TIMEOUT,
          writers=None, retention: float | None = None, pins=None,
          gc_every: float = 3600.0, mirrors=(), mirror_key=None,
          max_clients: int | None = MAX_CLIENTS, log=None) -> StoreServer:
    """A store server (not started: call .serve_forever(), or `start` for a thread).

    max_body  {kind: bytes} over LIMITS: a larger PUT gets 413 before its body is read
    timeout   seconds a request may sit idle on its socket before the server drops it
    writers   None (anyone may write: every blob is checked against its key anyway), or a
              container of 32-byte public keys (an AllowList): a PUT must then be signed by
              one of them (sign_put), else 401 (unsigned) or 403 (not listed, bad signature)
    retention seconds to keep a blob after it was last stored (None: forever); a gc pass
              runs at start (it also clears crashed writes' temp files) and every gc_every
    pins      keys gc never deletes: a set, or a pin file (re-read each pass)
    mirrors   store URLs each newly accepted blob is pushed to (srv.mirror; PUTs signed by
              mirror_key if given)
    max_clients  connections served at once (None: unbounded); more get 503 Busy
    """
    stop = threading.Event()
    mirror = Mirror(store, mirrors, mirror_key, stop, log=log) if mirrors else None
    srv = StoreServer((host, port), _handler(store, dict(max_body=max_body, timeout=timeout,
                                                         writers=writers, mirror=mirror)))
    srv._stop, srv.mirror = stop, mirror
    srv._slots = threading.BoundedSemaphore(max_clients) if max_clients else None
    threading.Thread(target=_gc_loop, args=(store, srv._stop, retention, pins, gc_every, log),
                     daemon=True).start()
    return srv


def start(store: DirStore, host: str = "127.0.0.1", port: int = 0, **opts):
    """A store server on a daemon thread: (server, its URL). server.shutdown() stops it."""
    srv = serve(store, host, port, **opts)
    threading.Thread(target=srv.serve_forever, args=(0.1,), daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"
