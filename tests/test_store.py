"""The job/trace store under production conditions: limits, write authorization, retention,
replication and concurrency (tests/test_node.py has the round trips)."""
import http.client
import json
import socket
import time

import pytest

from tdcc_exact.node.store import (DirStore, HttpStore, StoreError, TooLarge, job_json, start)
from tdcc_exact.oracle import new_job

EVERY = 512


@pytest.fixture(scope="module")
def job():
    return new_job("tiny", "Will it rain tomorrow?", "n1", every=EVERY)


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
