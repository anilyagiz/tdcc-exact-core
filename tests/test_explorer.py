"""tdcc_exact/explorer: the API handlers over a fake indexer (no chain), the page, the server."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from tdcc_exact import explorer, indexer
from tdcc_exact.explorer import (
    ChainSource,
    Explorer,
    cluster_of,
    explorer_query,
    job_row,
    make_server,
    next_deadline,
    with_jobs,
)

A, B, R, V = "A" * 44, "B" * 44, "R" * 44, "1" * 32
ZERO = "00" * 32


def _job(state, price, opened, reveal=0, challenge=0, ruling=0, answer=255, fp=ZERO):
    return {"config": "C" * 44, "renter": R, "provider": A, "job_id": opened, "job_digest": "11" * 32,
            "model_hash": "22" * 32, "price": price, "state": state, "opened_slot": opened,
            "commit_deadline": reveal - 5, "reveal_deadline": reveal,
            "challenge_deadline": challenge, "commitment": ZERO, "fingerprint": fp,
            "trace_root": ZERO, "checkpoints": 0, "verifier": V, "verifier_fingerprint": ZERO,
            "bond": 0, "challenge_slot": 0, "ruling_deadline": ruling, "answer": answer}


JOBS = {
    "j-open-late": _job("Open", 10, 10, reveal=20),
    "j-open": _job("Open", 20, 990, reveal=1010),
    "j-revealed-late": _job("Revealed", 40, 40, reveal=60, challenge=900, answer=1, fp="ab" * 32),
    "j-challenged-late": _job("Challenged", 60, 60, reveal=70, challenge=80, ruling=95, answer=0,
                              fp="cd" * 32),
    "j-settled": _job("Settled", 70, 70, reveal=80, challenge=90, answer=1, fp="ef" * 32),
}
PROVIDERS = {"pa": {"owner": A, "stake": 5_000_000, "open_jobs": 3, "unlock_slot": 0},
             "pb": {"owner": B, "stake": 9_000_000, "open_jobs": 0, "unlock_slot": 1200}}
EVENTS = [{"name": "JobOpened", "job": "j-open", "renter": R, "provider": A, "price": 20,
           "job_digest": "11" * 32, "sig": "s1", "slot": 990, "index": 0, "block_time": None},
          {"name": "Settled", "job": "j-settled", "provider": A, "host": 63, "fee": 7,
           "sig": "s2", "slot": 995, "index": 0, "block_time": 1_700_000_000}]


class FakeSource:
    """The indexer's view of a market at slot 1000, counting its calls."""

    program = indexer.PROGRAM

    def __init__(self, fail=False):
        self.calls = {"snapshot": 0, "events": []}
        self.fail = fail

    def snapshot(self):
        self.calls["snapshot"] += 1
        if self.fail:
            raise OSError("connection refused")
        return with_jobs(indexer.build_snapshot(1000, {}, PROVIDERS, JOBS), JOBS)

    def events(self, limit):
        self.calls["events"].append(limit)
        return EVENTS[-limit:]


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _get(app, path):
    status, ctype, body = app.handle(path)
    return status, ctype, (json.loads(body) if ctype == "application/json" else body.decode())


# ------------------------------------------------------------------------------- pure parts
def test_cluster_and_explorer_query():
    assert cluster_of("https://api.devnet.solana.com") == "devnet"
    assert cluster_of("https://api.testnet.solana.com") == "testnet"
    assert cluster_of("https://api.mainnet-beta.solana.com") == "mainnet-beta"
    assert cluster_of("http://127.0.0.1:8899") == "custom"
    assert explorer_query("https://api.devnet.solana.com") == "?cluster=devnet"
    assert explorer_query("https://mainnet.helius-rpc.com/?api-key=SECRET") == ""   # no key leak
    assert explorer_query("http://127.0.0.1:8899") == \
        "?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899"


def test_next_deadline_follows_the_state():
    assert next_deadline(JOBS["j-open"], 1000) == {
        "label": "reveal by", "slot": 1010, "then": "expire", "past": False, "slots_left": 10}
    assert next_deadline(JOBS["j-revealed-late"], 1000)["then"] == "settle"
    d = next_deadline(JOBS["j-challenged-late"], 1000)
    assert (d["slot"], d["then"], d["past"]) == (95, "dismiss", True)
    assert next_deadline(JOBS["j-settled"], 1000) is None


def test_job_row_hides_the_unrevealed():
    r = job_row("x", JOBS["j-open"], 1000)
    assert (r["revealed"], r["answer"], r["fingerprint"], r["address"]) == (False, None, None, "x")
    r = job_row("y", JOBS["j-challenged-late"], 1000)
    assert (r["revealed"], r["answer"], r["fingerprint"]) == (True, "NO", "cd" * 32)
    assert job_row("z", JOBS["j-settled"], 1000)["answer"] == "YES"


# ------------------------------------------------------------------------------- handlers
def test_snapshot_json_shape():
    app = Explorer(FakeSource(), "https://api.devnet.solana.com", admin=A, clock=Clock())
    status, ctype, s = _get(app, "/api/snapshot")
    assert (status, ctype) == (200, "application/json")
    for k in ("slot", "configs", "jobs", "jobs_by_state", "escrow", "total_stake", "providers",
              "open_challenges", "actionable", "job_list", "late", "meta"):
        assert k in s, k
    assert s["slot"] == 1000 and s["jobs"] == 5
    assert s["escrow"] == 10 + 20 + 40 + 60
    assert s["total_stake"] == 14_000_000 and s["providers"][0]["provider"] == B
    assert [j["address"] for j in s["job_list"]] == [
        "j-open", "j-settled", "j-challenged-late", "j-revealed-late", "j-open-late"]
    assert s["late"] == ["j-challenged-late", "j-revealed-late", "j-open-late"]
    assert [c["job"] for c in s["open_challenges"]] == ["j-challenged-late"]
    assert s["meta"] == {"cluster": "devnet", "explorer_query": "?cluster=devnet",
                         "program": indexer.PROGRAM, "admin": A, "slot_seconds": 0.4,
                         "fetched_at": 1000.0}


def test_snapshot_is_cached_for_ttl():
    src, clock = FakeSource(), Clock()
    app = Explorer(src, "http://127.0.0.1:8899", ttl=4.0, clock=clock)
    _get(app, "/api/snapshot")
    clock.t += 3.9
    _get(app, "/api/snapshot")
    assert src.calls["snapshot"] == 1
    clock.t += 0.2
    _get(app, "/api/snapshot")
    assert src.calls["snapshot"] == 2


def test_events_newest_first_and_limit_clamped():
    src = FakeSource()
    app = Explorer(src, "http://127.0.0.1:8899", clock=Clock())
    status, _, r = _get(app, "/api/events?limit=5")
    assert status == 200 and r["limit"] == 5
    assert [e["sig"] for e in r["events"]] == ["s2", "s1"]
    assert r["meta"]["explorer_query"].startswith("?cluster=custom&customUrl=")
    _get(app, "/api/events")
    _get(app, "/api/events?limit=100000")
    _get(app, "/api/events?limit=0")
    assert src.calls["events"] == [5, explorer.EVENTS_DEFAULT, explorer.EVENTS_MAX, 1]
    status, _, r = _get(app, "/api/events?limit=lots")
    assert status == 400 and "limit" in r["error"]


def test_rpc_failure_is_a_502_and_not_cached():
    src = FakeSource(fail=True)
    app = Explorer(src, "http://127.0.0.1:8899", clock=Clock())
    status, _, r = _get(app, "/api/snapshot")
    assert status == 502 and "connection refused" in r["error"]
    _get(app, "/api/snapshot")
    assert src.calls["snapshot"] == 2


def test_page_and_assets_are_served():
    app = Explorer(FakeSource(), "http://127.0.0.1:8899")
    status, ctype, html = _get(app, "/")
    assert status == 200 and ctype.startswith("text/html")
    for needle in ('<table id="jobs">', '<table id="providers">', '<table id="events">',
                   'scope="col"', '<label for="state-filter">', 'src="app.js"',
                   'href="style.css"', 'name="viewport"'):
        assert needle in html, needle
    assert "http://" not in html and "https://" not in html          # no CDN
    status, ctype, js = _get(app, "/app.js")
    assert status == 200 and "javascript" in ctype and ".innerHTML" not in js
    status, ctype, css = _get(app, "/style.css")
    assert status == 200 and "prefers-color-scheme: dark" in css
    status, _, r = _get(app, "/../explorer/__init__.py")
    assert status == 404


# ------------------------------------------------------------------------------- source
def test_chain_source_keeps_the_decoded_jobs(monkeypatch):
    accounts = {"Config": [("cfg", {"admin": A})],
                "Job": [(a, j) for a, j in JOBS.items()],
                "Provider": list(PROVIDERS.items())}
    seen = []

    def program_accounts(rpc, kind, program=indexer.PROGRAM, extra=None):
        seen.append((kind, extra))
        return accounts[kind]

    monkeypatch.setattr(indexer, "program_accounts", program_accounts)
    for name in ("decode_config", "decode_job", "decode_provider"):
        monkeypatch.setattr(indexer, name, lambda d: d)

    class Rpc:
        def slot(self):
            return 1000

    s = ChainSource(Rpc()).snapshot()
    assert [k for k, _ in seen] == ["Config", "Job", "Provider"] and seen[1][1] is None
    assert s["jobs"] == 5 and len(s["job_list"]) == 5 and s["configs"] == {"cfg": {"admin": A}}
    assert s["escrow"] == FakeSource().snapshot()["escrow"]


# ------------------------------------------------------------------------------- HTTP
@pytest.fixture
def server():
    srv = make_server(Explorer(FakeSource(), "https://api.devnet.solana.com"), port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_http_server(server):
    with urllib.request.urlopen(server + "/") as r:
        assert r.status == 200 and b"TDCC Exact" in r.read()
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    with urllib.request.urlopen(server + "/api/snapshot") as r:
        assert r.headers["Content-Type"] == "application/json"
        assert json.loads(r.read())["jobs"] == 5
    with urllib.request.urlopen(server + "/api/events?limit=1") as r:
        assert [e["sig"] for e in json.loads(r.read())["events"]] == ["s2"]
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(server + "/nope")
    assert e.value.code == 404


def test_cli_parses_explore(monkeypatch):
    from tdcc_exact import cli
    seen = []
    monkeypatch.setattr(cli, "cmd_explore", lambda a: seen.append(vars(a)) or 0)
    assert cli.main(["explore", "--rpc", "http://x", "--admin", "K", "--port", "9000"]) == 0
    assert cli.main(["explore"]) == 0
    assert [(a["rpc"], a["admin"], a["host"], a["port"]) for a in seen] == [
        ("http://x", "K", "127.0.0.1", 9000), (None, None, "127.0.0.1", 8788)]
