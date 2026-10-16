"""The market's nodes: the job store (no chain needed), and the provider and verifier nodes
end to end on a local validator (skipped without one, as tests/test_chain.py):

    TDCC_EXACT_RPC=http://127.0.0.1:8899 python -m pytest -q tests/test_node.py
"""
import json
import os
import time

import pytest

from tdcc_exact.node.store import (DirStore, HttpStore, NotFound, Tampered, job_from_json,
                                   job_json, open_store, start)
from tdcc_exact.oracle import new_job, run_job, tiny_model

EVERY = 512


@pytest.fixture(scope="module")
def job():
    return new_job("tiny", "Will it rain tomorrow?", "n1", every=EVERY)


@pytest.fixture(scope="module")
def trace(job):
    return run_job(job, "A", model=tiny_model()).log.to_json()


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
    other = new_job("tiny", "Will it snow tomorrow?", every=EVERY)
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
                   job_json(new_job("tiny", "Will it snow tomorrow?", every=EVERY)))
        with pytest.raises(NotFound):
            c.get_job(job.digest)
    finally:
        srv.shutdown()


def test_the_client_rejects_a_lying_server(tmp_path, job):
    d = DirStore(tmp_path)
    k = d.put_job(job)
    # the server's disk was edited: it serves another job under k; the client catches it
    (tmp_path / "jobs" / f"{k}.json").write_bytes(job_json(new_job("tiny", "Other?", every=EVERY)))
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


def test_cli_publish(tmp_path, job, capsys):
    from tdcc_exact.cli import main
    job.save(tmp_path / "job.json")
    assert main(["node", "publish", "--job", str(tmp_path / "job.json"),
                 "--store", str(tmp_path / "store")]) == 0
    assert capsys.readouterr().out.strip() == job.digest.hex()
    assert DirStore(tmp_path / "store").get_job(job.digest) == job


def test_open_store(tmp_path):
    assert isinstance(open_store(str(tmp_path)), DirStore)
    assert isinstance(open_store("http://127.0.0.1:1"), HttpStore)


# ------------------------------------------------------------------------------- the nodes
# against a stand-in for the chain that enforces the program's rules for these three calls
class FakeChain:
    def __init__(self):
        self.now, self.jobs_, self.sent = 100, {}, []
        self.rpc = self

    def wait_slot(self, s):
        self.now = max(self.now, s + 1)

    def slot(self):
        return self.now

    def open(self, key, provider, job_digest, model_hash, window=10):
        from types import SimpleNamespace
        self.jobs_[key] = SimpleNamespace(
            provider=provider, job_digest=job_digest, model_hash=model_hash, state="Open",
            opened_slot=self.now, commit_deadline=self.now + window,
            reveal_deadline=self.now + 2 * window, challenge_deadline=0,
            commitment=bytes(32), fingerprint=bytes(32), trace_root=bytes(32), checkpoints=0)

    def jobs(self, provider=None, states=None):
        return [(k, j) for k, j in sorted(self.jobs_.items(), key=lambda x: str(x[0]))
                if (provider is None or j.provider == provider)
                and (states is None or j.state in states)]

    def commit(self, owner, key, c):
        j = self.jobs_[key]
        assert j.state == "Open" and self.now <= j.commit_deadline
        j.commitment, j.state = c, "Committed"
        self.sent.append(("commit", key))
        return f"sig-commit-{len(self.sent)}"

    def reveal(self, owner, key, fp, salt, model_hash, answer, logits_hash, tree, cps):
        from tdcc_exact.chain import receipt_fingerprint, trace_root
        from tdcc_exact.commit import commitment
        j = self.jobs_[key]
        assert j.state == "Committed" and j.commit_deadline < self.now <= j.reveal_deadline
        assert commitment(fp, bytes(owner.pubkey()), salt) == j.commitment
        assert model_hash == j.model_hash
        root = trace_root(tree, cps)                       # what the program checks
        assert receipt_fingerprint(j.job_digest, model_hash, answer, logits_hash, root) == fp
        j.fingerprint, j.trace_root, j.checkpoints, j.state = fp, root, cps, "Revealed"
        j.challenge_deadline = self.now + 10
        self.sent.append(("reveal", key))
        return f"sig-reveal-{len(self.sent)}"

    def challenge(self, verifier, key, fp):
        j = self.jobs_[key]
        assert j.state == "Revealed" and self.now <= j.challenge_deadline
        assert fp != j.fingerprint
        j.state = "Challenged"
        self.sent.append(("challenge", key))
        return f"sig-challenge-{len(self.sent)}"


class Key(bytes):
    """A job account's key in the fake chain (str() names it, bytes() is 32 bytes)."""

    def __new__(cls, name):
        return super().__new__(cls, name.encode().ljust(32, b"\0"))

    def __str__(self):
        return self.rstrip(b"\0").decode()


@pytest.fixture
def fake(tmp_path):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact import registry
    from tdcc_exact.node.common import Models
    return dict(chain=FakeChain(), store=DirStore(tmp_path / "store"), dir=tmp_path,
                provider=Keypair(), verifier=Keypair(), models=Models(),
                model_hash=bytes.fromhex(registry.expected("tiny", "int8", 256)))


def _provider(f, name="p", **kw):
    from tdcc_exact.node.provider import ProviderNode
    return ProviderNode(f["chain"], f["provider"], f["store"], f["dir"] / name / "state.json",
                        f["models"], log=lambda *a: None, **kw)


def _verifier(f, rate=1.0):
    from tdcc_exact.node.verifier import VerifierNode
    return VerifierNode(f["chain"], f["verifier"], f["store"], f["dir"] / "v" / "state.json",
                        f["models"], rate=rate, log=lambda *a: None)


J1 = Key("J1")


def test_provider_commits_reveals_publishes_once(fake, job):
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"])
    assert _provider(f).run_once() == {"J1": "committed"}
    # a restarted node (same state file) neither commits again nor reveals early
    assert _provider(f).run_once() == {}
    assert _provider(f).run_once(wait=True) == {"J1": "published"}
    assert [s for s, _ in c.sent] == ["commit", "reveal"]
    j = c.jobs_[J1]
    assert f["store"].get_trace(j.trace_root)["root"] == j.trace_root.hex()
    assert _provider(f).run_once(wait=True) == {}
    # the verifier re-runs it and accepts, once
    assert _verifier(f).run_once() == {"J1": "accepted"}
    assert _verifier(f).run_once() == {}


def test_provider_restart_after_an_unrecorded_commit_reveals(fake, job):
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"])
    p = _provider(f)
    p.run_once()
    p.state.set("J1", status="prepared")       # as if the node died before recording it
    assert _provider(f).run_once(wait=True) == {"J1": "published"}
    assert [s for s, _ in c.sent] == ["commit", "reveal"]


def test_provider_refuses_a_job_that_is_not_the_on_chain_one(fake, job, tmp_path):
    f, c = fake, fake["chain"]
    other = new_job("tiny", "Will it snow tomorrow?", every=EVERY)
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), other.digest, f["model_hash"])
    # the renter's file under the on-chain digest is another job: the store's check refuses it
    (tmp_path / "store" / "jobs" / f"{other.digest.hex()}.json").write_bytes(job_json(job))
    p = _provider(f)
    assert p.run_once(wait=True) == {"J1": "refused"}
    assert "digest" in p.state.get("J1")["why"] and c.sent == []


def test_provider_refuses_an_unregistered_model_hash(fake, job):
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, bytes([9]) * 32)
    p = _provider(f)
    assert p.run_once(wait=True) == {"J1": "refused"}
    assert "registered" in p.state.get("J1")["why"] and c.sent == []


def test_provider_waits_for_an_unpublished_job_then_misses_it(fake, job):
    f, c = fake, fake["chain"]
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"])
    assert _provider(f).run_once() == {}
    c.now += 100
    assert _provider(f).run_once() == {"J1": "missed"}
    assert c.sent == []


def test_verifier_challenges_a_skipped_layer(fake, job):
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"])
    assert _provider(f, skip_layer=1).run_once(wait=True) == {"J1": "published"}
    v = _verifier(f)
    assert v.run_once() == {"J1": "challenged"}
    assert c.jobs_[J1].state == "Challenged"
    assert v.state.get("J1")["trace"] == "available"


def test_verifier_sampling(fake):
    keys = [bytes([i]) * 32 for i in range(200)]
    assert not any(_verifier(fake, rate=0.0).sampled(k) for k in keys)
    assert all(_verifier(fake, rate=1.0).sampled(k) for k in keys)
    assert 25 < sum(_verifier(fake, rate=0.25).sampled(k) for k in keys) < 80


# ------------------------------------------------------------------------------- on a validator
URL = os.environ.get("TDCC_EXACT_RPC", "http://127.0.0.1:8899")


def _chain_up() -> bool:
    try:
        from tdcc_exact.chain import PROGRAM_ID, Rpc
        rpc = Rpc(URL)
        rpc.call("getHealth")
        return rpc.account(PROGRAM_ID) is not None
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _chain_up(), reason=f"no validator with the program at {URL}")
def test_nodes_on_a_validator(tmp_path, job):
    from solders.keypair import Keypair

    from tdcc_exact import registry
    from tdcc_exact.chain import Market, Params, Rpc
    from tdcc_exact.cli import main
    from tdcc_exact.node.chainio import Chain
    from tdcc_exact.node.common import Models
    from tdcc_exact.node.provider import ProviderNode
    from tdcc_exact.node.verifier import VerifierNode

    rpc = Rpc(URL)
    admin, renter, verifier, a, b, treasury = (Keypair() for _ in range(6))
    for k in (admin, renter, verifier, a, b):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    m.initialize(treasury.pubkey(), Params(commit_window=20, challenge_window=40,
                                           unstake_cooldown=100))
    for p in (a, b):
        m.mint_to(p.pubkey(), 50_000_000)
        m.register_provider(p)
        m.stake(p, 50_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)
    m.mint_to(verifier.pubkey(), Params().challenge_bond)     # what its challenge puts up

    # the renter publishes the job and opens it with A, with B, and once with A naming a
    # model hash that is not the registry's (A must refuse that one)
    srv, url = start(DirStore(tmp_path / "store"))
    store = HttpStore(url)
    assert store.put_job(job) == job.digest.hex()
    pinned = bytes.fromhex(registry.expected("tiny", job.wformat, job.cap))
    base = int(time.time() * 1000)
    ja, _ = m.open_job(renter, a.pubkey(), base, job.digest, pinned, 1_000_000)
    jb, _ = m.open_job(renter, b.pubkey(), base + 1, job.digest, pinned, 1_000_000)
    jx, _ = m.open_job(renter, a.pubkey(), base + 2, job.digest, bytes([9]) * 32, 1_000_000)

    chain, models, quiet = Chain(m), Models(), (lambda *x: None)
    # A through the CLI (keys: provider.json, admin.json), B as a dishonest node in-process
    keys = tmp_path / "keys"
    keys.mkdir()
    for name, k in (("provider", a), ("admin", admin)):
        (keys / f"{name}.json").write_text(json.dumps(list(bytes(k))))
    pb = ProviderNode(chain, b, store, tmp_path / "b" / "state.json", models,
                      skip_layer=1, log=quiet)
    assert pb.run_once() == {str(jb): "committed"}       # (A's --once waits out the window)
    assert main(["node", "provider", "--rpc", URL, "--keys", str(keys), "--store", url,
                 "--once"]) == 0
    assert pb.run_once(wait=True) == {str(jb): "published"}
    sa = json.loads((keys / "provider.state" / "state.json").read_text())
    assert sa[str(ja)]["status"] == "published" and sa[str(jx)]["status"] == "refused"
    assert m.job(ja).state == "Revealed" and m.job(jb).state == "Revealed"
    assert m.job(jx).state == "Open"
    assert store.get_trace(m.job(ja).trace_root)["root"] == m.job(ja).trace_root.hex()

    # a restarted A does nothing more
    pa = ProviderNode(chain, a, store, keys / "provider.state" / "state.json", models,
                      log=quiet)
    assert pa.run_once(wait=True) == {}

    v = VerifierNode(chain, verifier, store, tmp_path / "v" / "state.json", models,
                     log=quiet)
    assert v.run_once() == {str(ja): "accepted", str(jb): "challenged"}
    assert m.job(jb).state == "Challenged" and m.job(jb).verifier == verifier.pubkey()
    assert m.job(ja).state == "Revealed"
    assert v.run_once() == {}
    srv.shutdown()


# ------------------------------------------------------------------------------- the arbiter
class ArbChain(FakeChain):
    """FakeChain plus what the arbiter reads and sends, with the program's rules for them."""

    def __init__(self, arbiter, window=20):
        super().__init__()
        self.arbiter_key, self.window, self.events = arbiter, window, {}

    def arbiter(self):
        return self.arbiter_key

    def reveal(self, owner, key, fp, salt, model_hash, answer, logits_hash, tree, cps):
        sig = super().reveal(owner, key, fp, salt, model_hash, answer, logits_hash, tree, cps)
        self.events[key] = {"name": "ReceiptRevealed", "job": str(key),
                            "answer": int(answer == "YES"), "logits_hash": logits_hash.hex()}
        return sig

    def revealed(self, key):
        return self.events.get(key)

    def challenge(self, verifier, key, fp):
        sig = super().challenge(verifier, key, fp)
        j = self.jobs_[key]
        j.verifier, j.verifier_fingerprint = verifier.pubkey(), fp
        j.challenge_slot, j.ruling_deadline = self.now, self.now + self.window
        return sig

    def slash(self, arbiter, key, index, step):
        j = self.jobs_[key]
        assert arbiter.pubkey() == self.arbiter_key and j.state == "Challenged"
        assert self.now <= j.ruling_deadline and 0 <= index <= j.checkpoints
        j.state, j.ruling = "Slashed", (index, step)
        self.sent.append(("slash", key))
        return f"sig-slash-{len(self.sent)}"

    def dismiss(self, caller, key):
        j = self.jobs_[key]
        assert j.state == "Challenged"
        assert caller.pubkey() == self.arbiter_key or self.now > j.ruling_deadline
        j.state = "Revealed"
        self.sent.append(("dismiss", key))
        return f"sig-dismiss-{len(self.sent)}"


@pytest.fixture
def arb(fake):
    from solders.keypair import Keypair
    k = Keypair()
    fake["arbiter"], fake["chain"] = k, ArbChain(k.pubkey())
    return fake


def _arbiter(f, **kw):
    from tdcc_exact.node.arbiter import ArbiterNode
    return ArbiterNode(f["chain"], f["arbiter"], f["store"], f["dir"] / "arb" / "state.json",
                       f["models"], log=lambda *a: None, **kw)


def _revealed(f, job, key=J1, **kw):
    f["store"].put_job(job)
    f["chain"].open(key, f["provider"].pubkey(), job.digest, f["model_hash"])
    assert _provider(f, **kw).run_once(wait=True) == {str(key): "published"}
    return f["chain"].jobs_[key]


def test_arbiter_slashes_a_skipped_layer_at_the_divergence(arb, job):
    f, c = arb, arb["chain"]
    _revealed(f, job, skip_layer=1)
    assert _verifier(f).run_once() == {"J1": "challenged"}
    a = _arbiter(f)
    assert a.run_once() == {"J1": "slashed"}
    s = a.state.get("J1")
    j = c.jobs_[J1]
    assert j.state == "Slashed" and j.ruling == (s["divergence_index"], s["fault_step"])
    assert 0 <= s["divergence_index"] <= j.checkpoints and s["fault_step"] >= 1
    assert "differs" in s["why"]
    assert _arbiter(f).run_once() == {}                    # a restart rules once


def test_arbiter_dismisses_a_wrong_challenge(arb, job):
    f, c = arb, arb["chain"]
    j = _revealed(f, job)
    c.challenge(f["verifier"], J1, bytes([7]) * 32)        # a verifier with a fake fingerprint
    a = _arbiter(f)
    assert a.run_once() == {"J1": "dismissed"}
    assert j.state == "Revealed" and a.state.get("J1")["rerun"] == j.fingerprint.hex()
    assert a.run_once() == {}
    c.now += 1                                             # challenged again: a new ruling
    c.challenge(f["verifier"], J1, bytes([8]) * 32)
    assert a.run_once() == {"J1": "dismissed"}


def test_arbiter_slashes_an_output_fault(arb, job):
    """The trace is honest, the receipt's answer is not the one it gives."""
    from tdcc_exact.chain import receipt_fingerprint
    f, c = arb, arb["chain"]
    j = _revealed(f, job)
    e = c.events[J1]
    e["answer"] ^= 1                                       # what a lying reveal would post
    j.fingerprint = receipt_fingerprint(j.job_digest, j.model_hash, e["answer"],
                                        bytes.fromhex(e["logits_hash"]), j.trace_root)
    c.challenge(f["verifier"], J1, bytes([7]) * 32)
    a = _arbiter(f)
    assert a.run_once() == {"J1": "slashed"}
    s = a.state.get("J1")
    assert s["divergence_index"] == j.checkpoints and "answer" in s["why"]


def test_arbiter_missing_trace(arb, job):
    f, c = arb, arb["chain"]
    j = _revealed(f, job)
    (f["dir"] / "store" / "traces" / f"{j.trace_root.hex()}.json").unlink()
    c.challenge(f["verifier"], J1, bytes([7]) * 32)
    assert _arbiter(f).run_once() == {}                    # within the default grace: wait
    assert c.sent[-1][0] == "challenge"
    lenient = _arbiter(f, trace_grace=0, missing_trace_loses=False)
    assert lenient.run_once() == {"J1": "no-trace"} and j.state == "Challenged"
    (f["dir"] / "arb" / "state.json").unlink()
    a = _arbiter(f, trace_grace=0)
    assert a.run_once() == {"J1": "slashed"}
    s = a.state.get("J1")
    assert s["divergence_index"] == 0 and s["trace"] == "missing" and j.state == "Slashed"


def test_arbiter_dismisses_after_the_ruling_deadline(arb, job):
    f, c = arb, arb["chain"]
    j = _revealed(f, job, skip_layer=1)
    c.challenge(f["verifier"], J1, bytes([7]) * 32)
    c.now = j.ruling_deadline + 1
    assert _arbiter(f, dismiss_late=False).run_once() == {}
    assert _arbiter(f).run_once() == {"J1": "dismissed-late"} and j.state == "Revealed"


def test_arbiter_refuses_another_key(arb):
    from solders.keypair import Keypair

    from tdcc_exact.node.arbiter import ArbiterNode, NotArbiter
    with pytest.raises(NotArbiter):
        ArbiterNode(arb["chain"], Keypair(), arb["store"], arb["dir"] / "x.json")


@pytest.mark.skipif(not _chain_up(), reason=f"no validator with the program at {URL}")
def test_arbiter_on_a_validator(tmp_path, job):
    """Honest A, cheating B (a skipped layer), and a job of A's whose trace never reaches the
    store: the verifier challenges B, a verifier challenges A's two with a made-up
    fingerprint, and the arbiter (its own key, not the admin's) slashes B, dismisses A's
    first and slashes the one without a trace."""
    from solders.keypair import Keypair

    from tdcc_exact import registry
    from tdcc_exact.chain import Market, Params, Rpc
    from tdcc_exact.cli import main
    from tdcc_exact.node.chainio import Chain
    from tdcc_exact.node.common import Models
    from tdcc_exact.node.provider import ProviderNode
    from tdcc_exact.node.verifier import VerifierNode

    rpc = Rpc(URL)
    admin, renter, verifier, a, b, arbiter, treasury = (Keypair() for _ in range(7))
    for k in (admin, renter, verifier, a, b, arbiter):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    params = Params(commit_window=20, challenge_window=80, arbiter_window=150,
                    unstake_cooldown=300, arbiter=arbiter.pubkey())
    m.initialize(treasury.pubkey(), params)
    for p in (a, b):
        m.mint_to(p.pubkey(), 50_000_000)
        m.register_provider(p)
        m.stake(p, 50_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)
    m.mint_to(verifier.pubkey(), 3 * params.challenge_bond)

    store_dir = tmp_path / "store"
    srv, url = start(DirStore(store_dir))
    store = HttpStore(url)
    store.put_job(job)
    pinned = bytes.fromhex(registry.expected("tiny", job.wformat, job.cap))
    base = int(time.time() * 1000)
    ja, _ = m.open_job(renter, a.pubkey(), base, job.digest, pinned, 1_000_000)
    jb, _ = m.open_job(renter, b.pubkey(), base + 1, job.digest, pinned, 1_000_000)
    jc, _ = m.open_job(renter, a.pubkey(), base + 2, job.digest, pinned, 1_000_000)

    chain, models, quiet = Chain(m), Models(), (lambda *x: None)
    pa = ProviderNode(chain, a, store, tmp_path / "a" / "state.json", models, log=quiet)
    pb = ProviderNode(chain, b, store, tmp_path / "b" / "state.json", models,
                      skip_layer=1, log=quiet)
    assert pb.run_once() == {str(jb): "committed"}
    assert pa.run_once(wait=True) == {str(ja): "published", str(jc): "published"}
    assert pb.run_once(wait=True) == {str(jb): "published"}
    sa = pa.state.get(str(ja))
    ev = chain.revealed(ja)                     # the reveal's event: what the account lacks
    assert ev["logits_hash"] == sa["logits_hash"] and ev["answer"] == int(sa["answer"] == "YES")
    (store_dir / "traces" / f"{m.job(jc).trace_root.hex()}.json").unlink()

    v = VerifierNode(chain, verifier, store, tmp_path / "v" / "state.json", models, log=quiet)
    assert v.run_once() == {str(ja): "accepted", str(jb): "challenged", str(jc): "accepted"}
    assert v.state.get(str(jc))["trace"] == "missing"
    for k in (ja, jc):                          # challenges the arbiter must sort out
        chain.challenge(verifier, k, bytes([7]) * 32)
    assert {m.job(k).state for k in (ja, jb, jc)} == {"Challenged"}

    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "admin.json").write_text(json.dumps(list(bytes(admin))))
    cmd = ["node", "arbiter", "--rpc", URL, "--keys", str(keys), "--store", url,
           "--trace-grace", "0", "--once"]
    with pytest.raises(SystemExit, match="not the market's arbiter"):
        main(cmd)                               # admin.json alone: the admin is not the arbiter
    (keys / "arbiter.json").write_text(json.dumps(list(bytes(arbiter))))
    assert main(cmd) == 0
    assert m.job(ja).state == "Revealed"
    assert m.job(jb).state == "Slashed" and m.job(jc).state == "Slashed"
    st = json.loads((keys / "arbiter.state" / "state.json").read_text())
    assert st[str(ja)]["ruling"] == "dismissed"
    assert st[str(jb)]["ruling"] == "slashed" and st[str(jb)]["fault_step"] >= 1
    assert st[str(jc)]["ruling"] == "slashed" and st[str(jc)]["divergence_index"] == 0
    assert st[str(jc)]["trace"] == "missing"
    assert m.provider(b.pubkey()).stake == 0 and m.provider(a.pubkey()).stake == 0
    assert main(cmd) == 0                       # nothing left to rule on
    srv.shutdown()
