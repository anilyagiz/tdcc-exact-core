"""The market's nodes: the job store (no chain needed), and the provider and verifier nodes
end to end on a local validator (skipped without one, as tests/test_chain.py):

    TDCC_EXACT_RPC=http://127.0.0.1:8899 python -m pytest -q tests/test_node.py
"""
import json

import pytest

from tdcc_exact.node.store import (DirStore, HttpStore, NotFound, Tampered, job_from_json,
                                   job_json, open_store, start)
from tdcc_exact.oracle import new_job, run_job, tiny_model

EVERY = 512


@pytest.fixture(scope="module")
def job():
    return new_job("tiny", "Will it rain tomorrow?", "n1")


@pytest.fixture(scope="module")
def trace(job):
    return run_job(job, "A", every=EVERY, model=tiny_model()).log.to_json()


@pytest.fixture(params=["dir", "http"])
def store(request, tmp_path):
    d = DirStore(tmp_path / "store")
    if request.param == "dir":
        yield d
        return
    srv, url = start(d)
    yield HttpStore(url)
    srv.shutdown()


def test_job_round_trip(store, job):
    k = store.put_job(job)
    assert k == job.digest.hex()
    got = store.get_job(k)
    assert got == job and got.digest == job.digest
    store.put_job(job)                                    # idempotent


def test_unknown_job_is_not_found(store):
    with pytest.raises(NotFound):
        store.get_job("ab" * 32)


def test_trace_round_trip(store, trace):
    k = store.put_trace(trace)
    assert k == trace["root"]
    assert store.get_trace(k)["checkpoints"] == trace["checkpoints"]


def test_job_under_another_key_is_rejected(tmp_path, job):
    d = DirStore(tmp_path)
    other = new_job("tiny", "Will it snow tomorrow?")
    with pytest.raises(Tampered):
        d.put_raw("jobs", job.digest.hex(), job_json(other))
    # a blob changed on disk (or by a server) after it was stored: the fetcher rejects it
    k = d.put_job(job)
    bad = json.loads((tmp_path / "jobs" / f"{k}.json").read_text())
    bad["yes_id"], bad["no_id"] = bad["no_id"], bad["yes_id"]
    (tmp_path / "jobs" / f"{k}.json").write_text(json.dumps(bad))
    with pytest.raises(Tampered):
        d.get_job(k)
    with pytest.raises(Tampered):
        job_from_json(b"not json", k)


def test_the_server_refuses_a_tampered_put(tmp_path, job):
    srv, url = start(DirStore(tmp_path))
    try:
        c = HttpStore(url)
        with pytest.raises(Tampered):
            c._req("PUT", f"/job/{job.digest.hex()}",
                   job_json(new_job("tiny", "Will it snow tomorrow?")))
        with pytest.raises(NotFound):
            c.get_job(job.digest)
    finally:
        srv.shutdown()


def test_the_client_rejects_a_lying_server(tmp_path, job):
    d = DirStore(tmp_path)
    k = d.put_job(job)
    # the server's disk was edited: it serves another job under k; the client catches it
    (tmp_path / "jobs" / f"{k}.json").write_bytes(job_json(new_job("tiny", "Other?")))
    srv, url = start(d)
    try:
        with pytest.raises(Tampered):
            HttpStore(url).get_job(k)
    finally:
        srv.shutdown()


def test_a_tampered_trace_is_rejected(tmp_path, trace):
    d = DirStore(tmp_path)
    bad = json.loads(json.dumps(trace))
    bad["checkpoints"][0][1] = "00" * 32
    with pytest.raises(Tampered):
        d.put_raw("traces", trace["root"], json.dumps(bad).encode())


def test_open_store(tmp_path):
    assert isinstance(open_store(str(tmp_path)), DirStore)
    assert isinstance(open_store("http://127.0.0.1:1"), HttpStore)
