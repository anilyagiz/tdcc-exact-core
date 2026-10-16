"""A minimal market explorer: one page over the indexer, served by the standard library.

    tdcc-exact explore --rpc URL [--admin PUBKEY] [--port 8788]

GET /                  the page (static/: index.html, app.js, style.css; no build step, no CDN)
GET /api/snapshot      indexer.build_snapshot's market state, plus every job (`job_list`) and
                       what the page needs to link and time things (`meta`); cached a few seconds
GET /api/events?limit=N   the decoded events of the program's last N transactions, newest first

The data comes from a source with two methods, snapshot() and events(limit): ChainSource reads
an RPC node through tdcc_exact.indexer; the tests pass a fake. An RPC failure is a 502 with
{"error": ...}, and the page keeps showing what it had.

The server binds 127.0.0.1 unless told otherwise: it is a viewer for one person, and every
request it serves may cost the RPC node a getProgramAccounts (or, for events, one getTransaction
per transaction) once the cache is stale.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import indexer

STATIC = Path(__file__).resolve().parent / "static"
PAGES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/index.html": ("index.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/style.css": ("style.css", "text/css; charset=utf-8")}
SLOT_SECONDS = 0.4            # Solana's target slot time; the page's times are approximate
EVENTS_DEFAULT, EVENTS_MAX = 50, 200
TERMINAL = ("Settled", "Slashed", "Expired")


# ------------------------------------------------------------------------------- clusters
def cluster_of(rpc_url: str) -> str:
    """devnet, testnet, mainnet-beta, or custom (a local validator, a private node)."""
    host = (urllib.parse.urlsplit(rpc_url).hostname or "").lower()
    for name in ("devnet", "testnet"):
        if name in host:
            return name
    return "mainnet-beta" if "mainnet" in host else "custom"


def explorer_query(rpc_url: str) -> str:
    """The query string explorer.solana.com needs to look at the same cluster (chain.Market.link
    does the same for devnet and custom). A known cluster's URL is not passed on (it may carry
    an API key); a custom one has to be."""
    c = cluster_of(rpc_url)
    if c == "mainnet-beta":
        return ""
    if c != "custom":
        return f"?cluster={c}"
    return "?cluster=custom&customUrl=" + urllib.parse.quote(rpc_url, safe="")


# ------------------------------------------------------------------------------- jobs
def next_deadline(job: dict, slot: int) -> dict | None:
    """The deadline that matters for a job's state, and what anyone may do once it passes."""
    st = job["state"]
    if st in ("Open", "Committed"):
        d, label, then = job["reveal_deadline"], "reveal by", "expire"
    elif st == "Revealed":
        d, label, then = job["challenge_deadline"], "challenge window ends", "settle"
    elif st == "Challenged":
        d, label, then = job["ruling_deadline"], "ruling by", "dismiss"
    else:
        return None
    return {"label": label, "slot": d, "then": then, "past": slot > d,
            "slots_left": d - slot}


def job_row(address: str, job: dict, slot: int) -> dict:
    """One job for the page: the decoded account, its address, and its next deadline. The
    fingerprint and the answer only once revealed (before that they are zeros / 255)."""
    revealed = job["state"] in ("Revealed", "Challenged", "Settled", "Slashed")
    ans = job.get("answer", 255)
    return {**job, "address": address, "revealed": revealed,
            "answer": ("YES" if ans == 1 else "NO" if ans == 0 else None) if revealed else None,
            "fingerprint": job.get("fingerprint") if revealed else None,
            "next_deadline": next_deadline(job, slot)}


def with_jobs(snap: dict, jobs: dict[str, dict]) -> dict:
    """A build_snapshot result plus `job_list` (newest first) and `late` (live jobs past their
    deadline, a challenge past its ruling deadline included)."""
    slot = snap["slot"]
    rows = [job_row(a, j, slot) for a, j in
            sorted(jobs.items(), key=lambda kv: -kv[1]["opened_slot"])]
    late = [r["address"] for r in rows if r["next_deadline"] and r["next_deadline"]["past"]]
    return {**snap, "job_list": rows, "late": late}


# ------------------------------------------------------------------------------- source
class ChainSource:
    """The market as an RPC node sees it, through tdcc_exact.indexer."""

    def __init__(self, rpc, admin: str | None = None, program: str = indexer.PROGRAM):
        self.rpc, self.admin, self.program = rpc, admin, program

    def snapshot(self) -> dict:
        # indexer.snapshot, keeping the decoded jobs (the snapshot only counts them)
        rpc, program, admin = self.rpc, self.program, self.admin
        slot = rpc.slot()
        configs = {a: indexer.decode_config(d)
                   for a, d in indexer.program_accounts(rpc, "Config", program)}
        job_filter = None
        if admin:
            cfg = indexer.config_address(admin, program)
            configs = {a: c for a, c in configs.items() if a == cfg}
            job_filter = [{"memcmp": {"offset": 8, "bytes": cfg}}]
        jobs = {a: indexer.decode_job(d)
                for a, d in indexer.program_accounts(rpc, "Job", program, job_filter)}
        providers = {a: indexer.decode_provider(d)
                     for a, d in indexer.program_accounts(rpc, "Provider", program)}
        if admin:
            providers = {a: p for a, p in providers.items()
                         if a == indexer.provider_address(cfg, p["owner"], program)}
        return with_jobs(indexer.build_snapshot(slot, configs, providers, jobs), jobs)

    def events(self, limit: int) -> list[dict]:
        return list(indexer.events(self.rpc, self.program, limit=limit))


# ------------------------------------------------------------------------------- handlers
class Explorer:
    """The routes, without HTTP: handle(path) -> (status, content type, body)."""

    def __init__(self, source, rpc_url: str, admin: str | None = None, ttl: float = 4.0,
                 clock=time.time):
        self.source, self.admin, self.ttl, self.clock = source, admin, ttl, clock
        self.meta = {"cluster": cluster_of(rpc_url), "explorer_query": explorer_query(rpc_url),
                     "program": getattr(source, "program", indexer.PROGRAM), "admin": admin,
                     "slot_seconds": SLOT_SECONDS}
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def _cached(self, key: str, make) -> dict:
        with self._lock:                       # one RPC round per stale key, not one per viewer
            hit = self._cache.get(key)
            now = self.clock()
            if hit and now - hit[0] < self.ttl:
                return hit[1]
            value = make()
            self._cache[key] = (now, value)
            return value

    def snapshot(self) -> dict:
        def make():
            s = self.source.snapshot()
            return {**s, "meta": {**self.meta, "fetched_at": self.clock()}}
        return self._cached("snapshot", make)

    def events(self, limit: int) -> dict:
        def make():
            evs = list(self.source.events(limit))
            evs.reverse()                                       # newest first
            return {"limit": limit, "events": evs,
                    "meta": {**self.meta, "fetched_at": self.clock()}}
        return self._cached(f"events:{limit}", make)

    def handle(self, target: str) -> tuple[int, str, bytes]:
        url = urllib.parse.urlsplit(target)
        path = url.path
        try:
            if path == "/api/snapshot":
                return _json(200, self.snapshot())
            if path == "/api/events":
                q = urllib.parse.parse_qs(url.query)
                try:
                    limit = int(q.get("limit", [EVENTS_DEFAULT])[0])
                except ValueError:
                    return _json(400, {"error": "limit must be an integer"})
                return _json(200, self.events(max(1, min(EVENTS_MAX, limit))))
        except Exception as e:  # noqa: BLE001  (the RPC node, a decode: the page shows it)
            return _json(502, {"error": f"{type(e).__name__}: {e}"})
        if path in PAGES:
            name, ctype = PAGES[path]
            return 200, ctype, (STATIC / name).read_bytes()
        return _json(404, {"error": f"no such path: {path}"})


def _json(status: int, obj) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps(obj).encode()


# ------------------------------------------------------------------------------- HTTP
def make_server(app: Explorer, host: str = "127.0.0.1", port: int = 8788) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):              # noqa: N802 (http.server's name)
            status, ctype, body = app.handle(self.path)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):     # quiet: the page polls every few seconds
            pass

    return ThreadingHTTPServer((host, port), Handler)


def cmd_explore(a) -> int:
    from ..chain import RPC, Rpc
    url = a.rpc or os.environ.get("TDCC_EXACT_RPC") or RPC["devnet"]
    app = Explorer(ChainSource(Rpc(url), a.admin), url, a.admin)
    srv = make_server(app, a.host, a.port)
    print(f"tdcc-exact explorer: http://{a.host}:{srv.server_address[1]}/  "
          f"({app.meta['cluster']}; ctrl-c to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
