"""The job/trace store under production conditions: limits, write authorization, retention,
replication and concurrency (tests/test_node.py has the round trips)."""
import http.client
import json
import os
import socket
import time

import pytest

from tdcc_exact.node.store import (DirStore, HttpStore, StoreError, TooLarge, job_json, start)
from tdcc_exact.oracle import new_job

EVERY = 512


@pytest.fixture(scope="module")
def job():
    return new_job("tiny", "Will it rain tomorrow?", "n1", every=EVERY)


@pytest.fixture(scope="module")
def trace_and_note(job):
    from tdcc_exact.oracle import run_job, tiny_model
    trace = run_job(job, "A", model=tiny_model()).log.to_json()
    try:
        from solders.keypair import Keypair
    except ImportError:
        return trace, None
    from tdcc_exact.node.store import sign_note
    return trace, sign_note(Keypair(), "challenge", bytes([5]) * 32, {"trace_root": trace["root"]})


@pytest.fixture
def server(tmp_path):
    started = []

    def make(d=None, **opts):
        srv, url = start(d or DirStore(tmp_path / f"store{len(started)}"), **opts)
        started.append(srv)
        return srv, url
    yield make
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _raw(url: str, method: str, path: str, body: bytes | None = None,
         headers: dict | None = None) -> tuple[int, bytes]:
    host, port = url.removeprefix("http://").split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        c.putrequest(method, path, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        if body is not None and "Content-Length" not in (headers or {}):
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


# ------------------------------------------------------------------------------- limits
@pytest.mark.parametrize("path", [
    "/job/../../etc/passwd",
    "/job/..%2f..%2fetc%2fpasswd",
    "/job/" + "ab" * 32 + "/../x",
    "/job/" + "ab" * 33,                     # overlong
    "/job/" + "ab" * 31,                     # short
    "/job/" + "AB" * 32,                     # upper case: not the canonical name
    "/job/" + "zz" * 32,                     # not hex
    "/job/" + "ab" * 32 + "?x=1",
    "/trace/" + "ab" * 32 + ".json",
])
def test_malformed_keys_and_traversal_are_refused(server, job, path):
    srv, url = server()
    for method, body in (("GET", None), ("PUT", job_json(job))):
        code, _ = _raw(url, method, path, body)
        assert code == 400
    assert _raw(url, "GET", "/../../etc/passwd")[0] == 404
    assert _raw(url, "GET", "/jobs/" + "ab" * 32)[0] == 404


def test_the_client_refuses_malformed_keys(tmp_path):
    for bad in ("../" * 10, "ab" * 33, "ab" * 31, "zz" * 32, ""):
        with pytest.raises(StoreError):
            HttpStore("http://127.0.0.1:1").get_job(bad)
        with pytest.raises(StoreError):
            DirStore(tmp_path).get_raw("jobs", bad)


def test_an_oversized_put_is_refused_before_its_body_is_read(server, job, tmp_path):
    d = DirStore(tmp_path / "s")
    srv, url = server(d, max_body={"jobs": 64})
    k = job.digest.hex()
    host, port = url.removeprefix("http://").split(":")
    # announce a 1 GB body and send none of it: the server answers 413 at once
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(f"PUT /job/{k} HTTP/1.1\r\nHost: x\r\nContent-Length: {1 << 30}\r\n\r\n"
                  .encode())
        assert s.recv(4096).split(b"\r\n")[0].split()[1] == b"413"
    # through the client: TooLarge, nothing stored
    with pytest.raises(TooLarge):
        HttpStore(url).put_job(job)
    assert not list((tmp_path / "s" / "jobs").iterdir())
    # per kind: a trace limit does not cap jobs
    srv2, url2 = server(max_body={"traces": 64})
    assert HttpStore(url2).put_job(job) == k


def test_unsized_or_chunked_puts_are_refused(server, job):
    srv, url = server()
    k = job.digest.hex()
    assert _raw(url, "PUT", f"/job/{k}")[0] == 411
    assert _raw(url, "PUT", f"/job/{k}", b"", {"Transfer-Encoding": "chunked"})[0] == 411
    assert _raw(url, "PUT", f"/job/{k}", b"", {"Content-Length": "-5"})[0] == 400


def test_a_client_reads_no_more_than_its_limit(server, job, tmp_path):
    d = DirStore(tmp_path / "s")
    d.put_job(job)
    srv, url = server(d)
    with pytest.raises(TooLarge):
        HttpStore(url, max_body={"jobs": 16}).get_job(job.digest)
    assert HttpStore(url).get_job(job.digest) == job


def test_a_stalled_client_is_cut_off(server, job):
    srv, url = server(timeout=0.3)
    host, port = url.removeprefix("http://").split(":")
    body = job_json(job)
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(f"PUT /job/{job.digest.hex()} HTTP/1.1\r\nHost: x\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n".encode() + body[:10])
        t = time.monotonic()
        assert s.recv(4096) == b""                    # closed without an answer
        assert time.monotonic() - t < 4
    # and the server still serves others
    assert HttpStore(url).put_job(job) == job.digest.hex()


def test_an_unreachable_store_is_a_store_error():
    from tdcc_exact.node.store import Unavailable
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(Unavailable):
        HttpStore(f"http://127.0.0.1:{port}", timeout=2).get_job("ab" * 32)


# ------------------------------------------------------------------------------- write auth
def test_signed_writes(server, job, tmp_path):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact.node.store import AllowList, Unauthorized, sign_put
    ok, other = Keypair(), Keypair()
    allow = tmp_path / "writers"
    allow.write_text(f"# the renter\n{ok.pubkey()}\n")              # base58
    srv, url = server(writers=AllowList(allow))
    k = job.digest.hex()
    with pytest.raises(Unauthorized):                               # unsigned: 401
        HttpStore(url).put_job(job)
    assert _raw(url, "PUT", f"/job/{k}", job_json(job))[0] == 401
    with pytest.raises(Unauthorized):                               # not listed: 403
        HttpStore(url, key=other).put_job(job)
    # a listed signer's signature over another body (or key) does not carry over
    hdr = sign_put(ok, "jobs", k, b"{}")
    assert _raw(url, "PUT", f"/job/{k}", job_json(job), hdr)[0] == 403
    hdr = sign_put(ok, "traces", k, job_json(job))
    assert _raw(url, "PUT", f"/job/{k}", job_json(job), hdr)[0] == 403
    hdr = dict(sign_put(other, "jobs", k, job_json(job)), **{"X-Tdcc-Signer": str(ok.pubkey())})
    assert _raw(url, "PUT", f"/job/{k}", job_json(job), hdr)[0] == 403
    assert HttpStore(url, key=ok).put_job(job) == k                 # listed and signed
    assert HttpStore(url).get_job(k) == job                         # reads stay open
    # the list is re-read when it changes: add `other` in hex, without a restart
    time.sleep(0.01)
    allow.write_text(f"{ok.pubkey()}\n{bytes(other.pubkey()).hex()}  # a provider\n")
    HttpStore(url, key=other).put_job(new_job("tiny", "Other?", every=EVERY))


def test_an_open_store_ignores_signatures(server, job):
    pytest.importorskip("solders")
    from solders.keypair import Keypair
    srv, url = server()
    assert HttpStore(url, key=Keypair()).put_job(job) == job.digest.hex()


def test_a_bad_allow_list_fails_at_start(tmp_path):
    from tdcc_exact.node.store import AllowList
    (tmp_path / "w").write_text("not-a-key!\n")
    with pytest.raises(StoreError):
        AllowList(tmp_path / "w")


def test_cli_writers_and_store_key(tmp_path, job, server):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact.cli import main
    from tdcc_exact.node.cli import store_opts
    k = Keypair()
    (tmp_path / "k.json").write_text(json.dumps(list(bytes(k))))
    (tmp_path / "w").write_text(f"{k.pubkey()}\n")
    opts = store_opts(_node_args("store", "--writers", str(tmp_path / "w")))
    srv, url = server(**opts)
    job.save(tmp_path / "job.json")
    with pytest.raises(StoreError):
        main(["node", "publish", "--job", str(tmp_path / "job.json"), "--store", url])
    assert main(["node", "publish", "--job", str(tmp_path / "job.json"), "--store", url,
                 "--store-key", str(tmp_path / "k.json")]) == 0


# ------------------------------------------------------------------------------- retention
def _age(path, seconds):
    t = time.time() - seconds
    os.utime(path, (t, t))


def test_gc_retention_pins_and_dry_run(tmp_path, job):
    from tdcc_exact.node.store import NotFound
    d = DirStore(tmp_path)
    old, pinned = job, new_job("tiny", "Pinned?", every=EVERY)
    fresh = new_job("tiny", "Fresh?", every=EVERY)
    for j in (old, pinned, fresh):
        d.put_job(j)
    for j in (old, pinned):
        _age(tmp_path / "jobs" / f"{j.digest.hex()}.json", 40 * 86400)
    pins = {pinned.digest.hex()}
    assert d.gc(None, pins).deleted == []                          # default: keep
    r = d.gc(30 * 86400, pins, dry_run=True)
    assert r.deleted == [("jobs", old.digest.hex())] and r.dry_run
    assert r.pinned == [("jobs", pinned.digest.hex())]
    assert d.get_job(old.digest) == old                            # dry run: still there
    r = d.gc(30 * 86400, pins)
    assert r.deleted == [("jobs", old.digest.hex())] and r.kept == 2
    with pytest.raises(NotFound):
        d.get_job(old.digest)
    assert d.get_job(pinned.digest) == pinned and d.get_job(fresh.digest) == fresh


def test_storing_again_restarts_the_clock(tmp_path, job):
    d = DirStore(tmp_path)
    d.put_job(job)
    _age(tmp_path / "jobs" / f"{job.digest.hex()}.json", 40 * 86400)
    d.put_job(job)
    assert d.gc(30 * 86400).deleted == []


def test_a_half_written_temp_file_is_ignored_and_cleaned(tmp_path, job):
    from tdcc_exact.node.store import NotFound
    d = DirStore(tmp_path)
    k = job.digest.hex()
    # a crash mid-write leaves the temp file the write was going to rename into place
    tmp = tmp_path / "jobs" / f".{k}.abc123.tmp"
    tmp.write_bytes(job_json(job)[:20])
    with pytest.raises(NotFound):
        d.get_job(k)
    assert d.gc(temp_grace=3600).temps == []                       # maybe a live write
    _age(tmp, 7200)
    assert d.gc(dry_run=True).temps == [str(tmp)] and tmp.exists()
    assert d.gc().temps == [str(tmp)] and not tmp.exists()
    d.put_job(job)                                                 # and the key still works
    assert d.get_job(k) == job
    assert [p.name for p in (tmp_path / "jobs").iterdir()] == [f"{k}.json"]


def test_a_failed_write_leaves_no_blob(tmp_path, job, monkeypatch):
    from tdcc_exact.node.store import NotFound
    d = DirStore(tmp_path)

    def crash(*a):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        d.put_job(job)
    monkeypatch.undo()
    assert list((tmp_path / "jobs").iterdir()) == []
    with pytest.raises(NotFound):
        d.get_job(job.digest)


def test_the_server_collects_on_a_schedule(tmp_path, job):
    from tdcc_exact.node.store import NotFound
    d = DirStore(tmp_path)
    keep = new_job("tiny", "Keep?", every=EVERY)
    for j in (job, keep):
        d.put_job(j)
        _age(tmp_path / "jobs" / f"{j.digest.hex()}.json", 3600)
    (tmp_path / "pins").write_text(f"# keep this one\n{keep.digest.hex()}\n")
    srv, url = start(d, retention=60, pins=str(tmp_path / "pins"), gc_every=0.05)
    try:
        c = HttpStore(url)
        for _ in range(100):
            try:
                c.get_job(job.digest)
            except NotFound:
                break
            time.sleep(0.05)
        else:
            pytest.fail("gc never ran")
        assert c.get_job(keep.digest) == keep
    finally:
        srv.shutdown()


def test_cli_gc(tmp_path, job, capsys):
    from tdcc_exact.cli import main
    d = DirStore(tmp_path / "s")
    d.put_job(job)
    _age(tmp_path / "s" / "jobs" / f"{job.digest.hex()}.json", 3 * 86400)
    base = ["node", "gc", "--dir", str(tmp_path / "s")]
    assert main(base) == 0 and "kept" in capsys.readouterr().out
    assert main([*base, "--retention", "2d", "--dry-run"]) == 0
    assert "would delete jobs/" in capsys.readouterr().out
    (tmp_path / "pins").write_text(job.digest.hex() + "\n")
    assert main([*base, "--retention", "2d", "--pins", str(tmp_path / "pins")]) == 0
    assert d.get_job(job.digest) == job
    assert main([*base, "--retention", "2d"]) == 0
    assert not list((tmp_path / "s" / "jobs").iterdir())
    from tdcc_exact.node.cli import store_opts
    o = store_opts(_node_args("store", "--retention", "30d", "--gc-every", "15m"))
    assert o["retention"] == 30 * 86400 and o["gc_every"] == 900
    with pytest.raises(SystemExit):
        _node_args("store", "--retention", "soon")


# ------------------------------------------------------------------------------- replication
def _dead_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}"


def test_quorum_writes_and_verified_reads(server, job, tmp_path):
    from tdcc_exact.node.store import NotFound, QuorumError, StoreClient, Tampered, Unavailable
    da, db = DirStore(tmp_path / "a"), DirStore(tmp_path / "b")
    _, ua = server(da)
    _, ub = server(db)
    dead = _dead_url()
    k = job.digest.hex()
    # 2 of 3 with one down: the write succeeds and lands on both live stores
    c = StoreClient([ua, ub, dead], quorum=2)
    assert c.quorum == 2 and StoreClient([ua, ub, dead]).quorum == 2
    assert c.put_job(job) == k
    assert da.get_job(k) == job and db.get_job(k) == job
    # 3 of 3: the dead one fails the write
    with pytest.raises(QuorumError):
        StoreClient([ua, ub, dead], quorum=3).put_job(new_job("tiny", "Q3?", every=EVERY))
    # a bad blob is refused before any store sees it
    with pytest.raises(Tampered):
        c.put_raw("jobs", k, job_json(new_job("tiny", "Other?", every=EVERY)))
    # reads: the first store lies, the client skips to the next with a good copy
    (tmp_path / "a" / "jobs" / f"{k}.json").write_bytes(
        job_json(new_job("tiny", "Lie?", every=EVERY)))
    assert StoreClient([ua, ub]).get_job(k) == job
    assert StoreClient([dead, ub]).get_job(k) == job
    # nobody has it: NotFound only when every store answered; a dead one makes it Unavailable
    with pytest.raises(NotFound):
        StoreClient([ua, ub]).get_job("cd" * 32)
    with pytest.raises(Unavailable):
        StoreClient([ua, dead]).get_job("cd" * 32)
    with pytest.raises(Tampered):
        StoreClient([ua]).get_job(k)
    with pytest.raises(StoreError):
        StoreClient([ua, ub], quorum=3)


def test_open_store_with_several(server, tmp_path, job):
    from tdcc_exact.node.store import StoreClient, open_store
    _, ua = server()
    c = open_store(f"{ua}, {tmp_path / 'local'}", quorum=2)
    assert isinstance(c, StoreClient) and c.quorum == 2
    c.put_job(job)
    assert DirStore(tmp_path / "local").get_job(job.digest) == job


def test_mirror_pushes_accepted_blobs(server, job, trace_and_note, tmp_path):
    db = DirStore(tmp_path / "b")
    _, ub = server(db)
    srv, ua = server(DirStore(tmp_path / "a"), mirrors=[ub, _dead_url()])
    trace, note = trace_and_note
    c = HttpStore(ua)
    c.put_job(job)
    c.put_trace(trace)
    if note:
        c.put_signed(note)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            db.get_job(job.digest)
            db.get_trace(trace["root"])
            break
        except StoreError:
            time.sleep(0.05)
    assert db.get_job(job.digest) == job
    assert db.get_trace(trace["root"])["checkpoints"] == trace["checkpoints"]
    if note:
        while not list((tmp_path / "b" / "signed").glob("*.json")):
            assert time.monotonic() < deadline
            time.sleep(0.05)


def test_mirrors_in_a_ring_do_not_loop(server, job, tmp_path):
    # a mirrors to b and b to a: b already holding what a pushes, it pushes nothing back
    ua_planned = _dead_url()                         # a free port, for a to listen on
    port_a = int(ua_planned.rsplit(":", 1)[1])
    srv_b, ub = server(DirStore(tmp_path / "b"), mirrors=[ua_planned])
    srv_a, ua = start(DirStore(tmp_path / "a"), port=port_a, mirrors=[ub])
    try:
        HttpStore(ua).put_job(job)
        srv_a.mirror.join()
        srv_b.mirror.join()
        assert DirStore(tmp_path / "b").get_job(job.digest) == job
        assert DirStore(tmp_path / "a").get_job(job.digest) == job
    finally:
        srv_a.shutdown()


def test_mirror_signs_for_an_allow_listed_mirror(server, job, tmp_path):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact.node.store import AllowList
    k = Keypair()
    (tmp_path / "w").write_text(f"{k.pubkey()}\n")
    db = DirStore(tmp_path / "b")
    _, ub = server(db, writers=AllowList(tmp_path / "w"))
    srv, ua = server(mirrors=[ub], mirror_key=k)
    HttpStore(ua).put_job(job)
    srv.mirror.join()
    assert db.get_job(job.digest) == job


def test_cli_mirror_and_quorum(tmp_path):
    from tdcc_exact.node.cli import store_opts
    o = store_opts(_node_args("store", "--mirror", "http://a:1", "--mirror", "http://b:2"))
    assert list(o["mirrors"]) == ["http://a:1", "http://b:2"] and o["mirror_key"] is None
    assert o["max_clients"] == 64
    assert store_opts(_node_args("store", "--max-clients", "8"))["max_clients"] == 8
    assert _node_args("publish", "--store", "http://a:1,http://b:2", "--quorum", "1").quorum == 1


# ------------------------------------------------------------------------------- concurrency
def test_concurrent_puts_and_gets_of_one_key(server, job, trace_and_note, tmp_path):
    import threading

    from tdcc_exact.node.store import NotFound
    trace, _ = trace_and_note
    d = DirStore(tmp_path / "s")
    srv, url = server(d, max_clients=None)
    k, root = job.digest.hex(), trace["root"]
    errors, seen = [], {"job": 0, "trace": 0}
    lock = threading.Lock()
    go = threading.Barrier(16)

    def worker(i):
        c = HttpStore(url)
        try:
            go.wait()
            for n in range(15):
                if (i + n) % 2:
                    c.put_job(job)
                    c.put_trace(trace)
                for what, get, key in (("job", c.get_job, k), ("trace", c.get_trace, root)):
                    try:
                        got = get(key)                 # verified: never a partial blob
                    except NotFound:
                        continue                       # not written yet: fine
                    assert got == job if what == "job" else got["root"] == root
                    with lock:
                        seen[what] += 1
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    assert seen["job"] > 0 and seen["trace"] > 0
    for kind in ("jobs", "traces"):
        names = [p.name for p in (tmp_path / "s" / kind).iterdir()]
        assert len(names) == 1 and names[0].endswith(".json")     # no temp files left


def test_concurrent_writes_on_disk(tmp_path, job):
    import threading
    d = DirStore(tmp_path)
    news = []
    threads = [threading.Thread(target=lambda: news.append(d.put_raw("jobs", job.digest,
                                                                        job_json(job))))
               for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert d.get_job(job.digest) == job and len(news) == 32
    assert [p.name for p in (tmp_path / "jobs").iterdir()] == [f"{job.digest.hex()}.json"]


def test_a_full_server_answers_busy(server, job):
    from tdcc_exact.node.store import Unavailable
    srv, url = server(max_clients=1, timeout=5)
    host, port = url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(b"GET /job/")                        # holds the only slot
        time.sleep(0.1)
        with pytest.raises(Unavailable):
            HttpStore(url).get_job(job.digest)
    for _ in range(50):                                # the slot comes back
        try:
            HttpStore(url).put_job(job)
            break
        except Unavailable:
            time.sleep(0.05)
    assert HttpStore(url).get_job(job.digest) == job


def _node_args(*argv):
    import argparse

    from tdcc_exact.node.cli import add_parser
    p = argparse.ArgumentParser()
    add_parser(p.add_subparsers())
    return p.parse_args(["node", *argv])


def test_cli_store_limits():
    from tdcc_exact.node.cli import store_opts
    a = _node_args("store", "--max-body", "job=100", "--max-body", "trace=5000",
                   "--timeout", "3")
    assert store_opts(a)["max_body"] == {"jobs": 100, "traces": 5000}
    assert store_opts(a)["timeout"] == 3
    with pytest.raises(SystemExit):
        _node_args("store", "--max-body", "blob=1")
