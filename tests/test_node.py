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


def test_signed_note_round_trip(store):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact.node.store import sign_note, signed_key
    k, job_key = Keypair(), bytes([5]) * 32
    note = sign_note(k, "window/0/512", job_key, {"records": [1, 2]})
    key = store.put_signed(note)
    assert key == signed_key("window/0/512", job_key, k.pubkey())
    assert store.get_signed(key)["body"] == {"records": [1, 2]}
    with pytest.raises(NotFound):
        store.get_signed(signed_key("window/0/1024", job_key, k.pubkey()))


def test_a_signed_note_cannot_be_squatted_or_changed(tmp_path):
    pytest.importorskip("solders")
    from solders.keypair import Keypair

    from tdcc_exact.node.store import sign_note, signed_key
    d, owner, other, job_key = DirStore(tmp_path), Keypair(), Keypair(), bytes([5]) * 32
    key = signed_key("challenge", job_key, owner.pubkey())
    # someone else's note under the owner's key: the key does not match its signer
    with pytest.raises(Tampered):
        d.put_raw("signed", key, json.dumps(sign_note(other, "challenge", job_key, {})).encode())
    # the owner's signer field, someone else's signature
    forged = sign_note(other, "challenge", job_key, {"trace_root": "00" * 32})
    forged["signer"] = bytes(owner.pubkey()).hex()
    with pytest.raises(Tampered):
        d.put_raw("signed", key, json.dumps(forged).encode())
    # a body changed after signing
    note = sign_note(owner, "challenge", job_key, {"trace_root": "00" * 32})
    d.put_signed(note)
    bad = dict(note, body={"trace_root": "11" * 32})
    (tmp_path / "signed" / f"{key}.json").write_text(json.dumps(bad))
    with pytest.raises(Tampered):
        d.get_signed(key)


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

    def open(self, key, provider, job_digest, model_hash, window=10, offered=False):
        """An Open job (as if accepted already), or with offered=True an Offered one."""
        from types import SimpleNamespace
        self.window = window
        self.jobs_[key] = SimpleNamespace(
            provider=provider, job_digest=job_digest, model_hash=model_hash,
            state="Offered" if offered else "Open", opened_slot=self.now,
            accept_deadline=self.now + window,
            commit_deadline=0 if offered else self.now + window,
            reveal_deadline=0 if offered else self.now + 2 * window, challenge_deadline=0,
            commitment=bytes(32), fingerprint=bytes(32), trace_root=bytes(32), checkpoints=0)

    def job(self, key):
        return self.jobs_[key]

    def accept(self, owner, key):
        j = self.jobs_[key]
        assert j.state == "Offered" and self.now <= j.accept_deadline
        assert owner.pubkey() == j.provider
        j.state, j.commit_deadline = "Open", self.now + self.window
        j.reveal_deadline = j.commit_deadline + self.window
        self.sent.append(("accept", key))
        return f"sig-accept-{len(self.sent)}"

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


def test_provider_accepts_an_offer_then_commits(fake, job):
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"], offered=True)
    c.now += 3                                     # a late acceptance: the window runs from it
    p = _provider(f)
    assert p.run_once() == {"J1": "committed"}
    assert [s for s, _ in c.sent] == ["accept", "commit"]
    assert c.jobs_[J1].commit_deadline == 113 and p.state.get("J1")["accept_sig"]
    assert _provider(f).run_once(wait=True) == {"J1": "published"}
    assert [s for s, _ in c.sent] == ["accept", "commit", "reveal"]


def test_provider_does_not_accept_an_offer_it_refuses(fake, job):
    """An offer naming a model hash that is not the registry's is never accepted: the job
    stays Offered (nothing of the stake locked) for the renter to cancel."""
    f, c = fake, fake["chain"]
    f["store"].put_job(job)
    c.open(J1, f["provider"].pubkey(), job.digest, bytes([9]) * 32, offered=True)
    p = _provider(f)
    assert p.run_once(wait=True) == {"J1": "refused"}
    assert "registered" in p.state.get("J1")["why"]
    assert c.sent == [] and c.jobs_[J1].state == "Offered"
    assert _provider(f).run_once() == {}


def test_provider_misses_an_offer_past_its_accept_deadline(fake, job):
    f, c = fake, fake["chain"]
    c.open(J1, f["provider"].pubkey(), job.digest, f["model_hash"], offered=True)
    assert _provider(f).run_once() == {}           # the job is not in the store yet
    f["store"].put_job(job)
    c.now += 11
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
    assert m.job(jx).state == "Offered"              # refused: never accepted
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


def _expected_dispute(f, job, key=J1):
    """What verifier.dispute names for provider p's posted trace (the cheat replayed)."""
    from tdcc_exact.backend import SkipLayer
    from tdcc_exact.oracle import layers_of
    from tdcc_exact.trace import Checkpoint
    from tdcc_exact.verifier import dispute
    j = f["chain"].jobs_[key]
    cps = [Checkpoint.from_json(c) for c in f["store"].get_trace(j.trace_root)["checkpoints"]]
    model = tiny_model()
    _, d, fault = dispute(job, cps, model, replay_cheat=SkipLayer(1, layers_of(model[0])),
                          out=lambda *a: None, binding=bytes(key))
    return d, fault


def test_arbiter_slashes_a_skipped_layer_at_its_first_fault(arb, job):
    """The cheating provider reveals its window (it chains to its posts); the arbiter's
    replay names the first faulty instruction, as verifier.dispute does."""
    f, c = arb, arb["chain"]
    _revealed(f, job, skip_layer=1)
    assert _verifier(f).run_once() == {"J1": "challenged"}
    a = _arbiter(f)
    assert a.run_once() == {}                              # the window is not there yet
    p = _provider(f, skip_layer=1)
    assert p.run_once() == {"J1": "window"}
    assert p.run_once() == {}                              # once per challenge
    assert a.run_once() == {"J1": "slashed"}
    s = a.state.get("J1")
    j = c.jobs_[J1]
    d, fault = _expected_dispute(f, job)
    assert j.state == "Slashed" and j.ruling == (s["divergence_index"], s["fault_step"])
    assert s["revealed"] == "verified" and s["window"] == f"{d.lo}..{d.hi}"
    assert (s["divergence_index"], s["fault_step"]) == (d.index, fault.step)
    assert d.lo < fault.step <= d.hi and "first fault" in s["why"]
    assert _arbiter(f).run_once() == {}                    # a restart rules once


def test_arbiter_slashes_a_withheld_window_after_the_grace(arb, job):
    f, c = arb, arb["chain"]
    j = _revealed(f, job, skip_layer=1)
    assert _verifier(f).run_once() == {"J1": "challenged"}
    assert _provider(f, skip_layer=1, reveal_windows=False).run_once() == {"J1": "withheld"}
    assert _arbiter(f).run_once() == {}                    # within the default grace: wait
    lenient = _arbiter(f, window_grace=0, missing_window_loses=False)
    assert lenient.run_once() == {"J1": "no-window"} and j.state == "Challenged"
    (f["dir"] / "arb" / "state.json").unlink()
    c.now = j.challenge_slot + (j.ruling_deadline - j.challenge_slot) // 2
    a = _arbiter(f)
    assert a.run_once() == {"J1": "slashed"}
    s = a.state.get("J1")
    d, _ = _expected_dispute(f, job)
    assert s["revealed"] == "missing" and "did not reveal" in s["why"]
    assert j.ruling == (d.index, d.lo + 1)


def test_arbiter_slashes_a_window_that_does_not_chain(arb, job):
    """A window the provider signed but did not commit to (one register changed)."""
    from tdcc_exact.node.common import window_topic
    from tdcc_exact.node.store import sign_note, signed_key
    f = arb
    j = _revealed(f, job, skip_layer=1)
    assert _verifier(f).run_once() == {"J1": "challenged"}
    assert _provider(f, skip_layer=1).run_once() == {"J1": "window"}
    d, _ = _expected_dispute(f, job)
    topic = window_topic(d.lo, d.hi)
    key = signed_key(topic, J1, f["provider"].pubkey())
    body = f["store"].get_signed(key)["body"]
    r = next(r for r in body["records"] if r["type"] == "step")
    r["regs"] = "ff" + r["regs"][2:]
    (f["dir"] / "store" / "signed" / f"{key}.json").write_text(
        json.dumps(sign_note(f["provider"], topic, J1, body)))
    a = _arbiter(f)
    assert a.run_once() == {"J1": "slashed"} and j.state == "Slashed"
    s = a.state.get("J1")
    assert s["revealed"] == "bad" and "does not chain" in s["why"]
    assert j.ruling == (d.index, d.lo + 1)


def test_an_honest_provider_reveals_against_a_wrong_challenger(arb, job):
    """A challenger whose published trace is wrong (a skipped layer's): the honest provider
    reveals its window against it, and the arbiter, whose run agrees with the provider's,
    dismisses."""
    from tdcc_exact.backend import SkipLayer
    from tdcc_exact.node.store import sign_note
    f, c = arb, arb["chain"]
    j = _revealed(f, job)
    bad = run_job(job, "v", SkipLayer(1, 2), model=tiny_model(), binding=bytes(J1))
    root = f["store"].put_trace(bad.log.to_json())
    f["store"].put_signed(sign_note(f["verifier"], "challenge", J1, {"trace_root": root}))
    c.challenge(f["verifier"], J1, bytes.fromhex(bad.receipt.fingerprint))
    p = _provider(f)
    assert p.run_once() == {"J1": "window"}
    assert p.state.get("J1")["window"] != "none"
    a = _arbiter(f)
    assert a.run_once() == {"J1": "dismissed"} and j.state == "Revealed"
    assert "honest run" in a.state.get("J1")["why"]


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
    """Honest A, cheating B (a skipped layer) that reveals its disputed window, cheating W
    that withholds it, and a job of A's whose trace never reaches the store: the verifier
    challenges B and W, a verifier challenges A's two with a made-up fingerprint, and the
    arbiter (its own key, not the admin's) slashes B at its first faulty step, dismisses
    A's first, slashes the one without a trace, and slashes W once the grace is over."""
    from solders.keypair import Keypair

    from tdcc_exact import registry
    from tdcc_exact.chain import Market, Params, Rpc
    from tdcc_exact.cli import main
    from tdcc_exact.node.chainio import Chain
    from tdcc_exact.node.common import Models
    from tdcc_exact.node.provider import ProviderNode
    from tdcc_exact.node.verifier import VerifierNode

    rpc = Rpc(URL)
    admin, renter, verifier, a, b, w, arbiter, treasury = (Keypair() for _ in range(8))
    for k in (admin, renter, verifier, a, b, w, arbiter):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    params = Params(commit_window=20, challenge_window=80, arbiter_window=150,
                    unstake_cooldown=300, arbiter=arbiter.pubkey())
    m.initialize(treasury.pubkey(), params)
    for p in (a, b, w):
        m.mint_to(p.pubkey(), 50_000_000)
        m.register_provider(p)
        m.stake(p, 50_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)
    m.mint_to(verifier.pubkey(), 4 * params.challenge_bond)

    store_dir = tmp_path / "store"
    srv, url = start(DirStore(store_dir))
    store = HttpStore(url)
    store.put_job(job)
    pinned = bytes.fromhex(registry.expected("tiny", job.wformat, job.cap))
    base = int(time.time() * 1000)
    ja, _ = m.open_job(renter, a.pubkey(), base, job.digest, pinned, 1_000_000)
    jb, _ = m.open_job(renter, b.pubkey(), base + 1, job.digest, pinned, 1_000_000)
    jc, _ = m.open_job(renter, a.pubkey(), base + 2, job.digest, pinned, 1_000_000)
    jw, _ = m.open_job(renter, w.pubkey(), base + 3, job.digest, pinned, 1_000_000)

    chain, models, quiet = Chain(m), Models(), (lambda *x: None)
    pa = ProviderNode(chain, a, store, tmp_path / "a" / "state.json", models, log=quiet)
    pb = ProviderNode(chain, b, store, tmp_path / "b" / "state.json", models,
                      skip_layer=1, log=quiet)
    pw = ProviderNode(chain, w, store, tmp_path / "w" / "state.json", models,
                      skip_layer=1, reveal_windows=False, log=quiet)
    assert pb.run_once() == {str(jb): "committed"}
    assert pw.run_once() == {str(jw): "committed"}
    assert pa.run_once(wait=True) == {str(ja): "published", str(jc): "published"}
    assert pb.run_once(wait=True) == {str(jb): "published"}
    assert pw.run_once(wait=True) == {str(jw): "published"}
    sa = pa.state.get(str(ja))
    ev = chain.revealed(ja)                     # the reveal's event: what the account lacks
    assert ev["logits_hash"] == sa["logits_hash"] and ev["answer"] == int(sa["answer"] == "YES")
    (store_dir / "traces" / f"{m.job(jc).trace_root.hex()}.json").unlink()

    v = VerifierNode(chain, verifier, store, tmp_path / "v" / "state.json", models, log=quiet)
    assert v.run_once() == {str(ja): "accepted", str(jb): "challenged", str(jc): "accepted",
                            str(jw): "challenged"}
    assert v.state.get(str(jc))["trace"] == "missing"
    assert v.state.get(str(jb))["published"]   # the challenge's trace, for B to bisect
    for k in (ja, jc):                          # challenges the arbiter must sort out
        chain.challenge(verifier, k, bytes([7]) * 32)
    assert {m.job(k).state for k in (ja, jb, jc, jw)} == {"Challenged"}
    assert pb.run_once() == {str(jb): "window"}  # B reveals its (faulty) window
    assert pw.run_once() == {str(jw): "withheld"}
    assert pa.run_once() == {}                  # A's challengers published no trace

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
    assert m.job(jw).state == "Challenged"      # within the window grace: W may still reveal
    st = json.loads((keys / "arbiter.state" / "state.json").read_text())
    assert st[str(ja)]["ruling"] == "dismissed"
    # B's window chains to its posts and its first faulty step is the dispute's
    from tdcc_exact.backend import SkipLayer
    from tdcc_exact.trace import Checkpoint
    from tdcc_exact.verifier import dispute
    cps = [Checkpoint.from_json(c) for c in store.get_trace(m.job(jb).trace_root)["checkpoints"]]
    _, d, fault = dispute(job, cps, tiny_model(), replay_cheat=SkipLayer(1, 2),
                          out=quiet, binding=bytes(jb))
    sb = st[str(jb)]
    assert sb["ruling"] == "slashed" and sb["revealed"] == "verified"
    assert (sb["divergence_index"], sb["fault_step"]) == (d.index, fault.step)
    assert st[str(jc)]["ruling"] == "slashed" and st[str(jc)]["divergence_index"] == 0
    assert st[str(jc)]["trace"] == "missing"
    assert m.provider(b.pubkey()).stake == 0 and m.provider(a.pubkey()).stake == 0
    assert main(cmd + ["--window-grace", "0"]) == 0   # the grace is over: W did not reveal
    assert m.job(jw).state == "Slashed" and m.provider(w.pubkey()).stake == 0
    sw = json.loads((keys / "arbiter.state" / "state.json").read_text())[str(jw)]
    assert sw["revealed"] == "missing" and sw["fault_step"] == d.lo + 1
    assert main(cmd) == 0                       # nothing left to rule on
    srv.shutdown()


def test_the_verifiers_sample_cannot_be_computed_from_public_keys():
    """A provider that knew which jobs go unchecked would cheat only on those: the sample
    must depend on the verifier's secret, not on anything public."""
    import hashlib
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from tdcc_exact.node.verifier import VerifierNode
    owner = Keypair()
    node = VerifierNode.__new__(VerifierNode)
    node.owner, node.rate = owner, 0.5
    keys = [Pubkey.from_bytes(bytes([i]) * 32) for i in range(64)]
    public = [int.from_bytes(hashlib.sha256(b"tdcc-exact/sample/v1" + bytes(k)
                                            + bytes(owner.pubkey())).digest()[:8], "little")
              < 2 ** 63 for k in keys]
    mine = [node.sampled(k) for k in keys]
    assert 10 < sum(mine) < 54                                   # about half
    assert mine != public                                        # not the public formula
    other = VerifierNode.__new__(VerifierNode)
    other.owner, other.rate = Keypair(), 0.5
    assert [other.sampled(k) for k in keys] != mine              # each verifier its own sample


# ------------------------------------------------------------------------------- the settler
class SettleChain(FakeChain):
    """FakeChain plus what the settler sends, with the program's rules for them."""

    def __init__(self):
        super().__init__()
        self.fail = set()                       # actions another settler got to first

    def add(self, key, state, renter, **deadlines):
        from types import SimpleNamespace
        j = {"accept_deadline": 0, "reveal_deadline": 0, "challenge_deadline": 0, **deadlines}
        self.jobs_[key] = SimpleNamespace(state=state, renter=renter, provider=None,
                                          opened_slot=0, **j)

    def _act(self, name, key, states, deadline, then):
        if (name, key) in self.fail:
            raise RuntimeError("WrongState")
        j = self.jobs_[key]
        assert j.state in states and (deadline is None or self.now > getattr(j, deadline))
        if then is None:
            del self.jobs_[key]
        else:
            j.state = then
        self.sent.append((name, key))
        return f"sig-{name}-{len(self.sent)}"

    def settle(self, payer, key):
        return self._act("settle", key, ("Revealed",), "challenge_deadline", "Settled")

    def expire(self, payer, key):
        return self._act("expire", key, ("Open", "Committed"), "reveal_deadline", "Expired")

    def cancel(self, renter, key):
        assert bytes(renter.pubkey()) == bytes(self.jobs_[key].renter)     # NotTheRenter
        return self._act("cancel", key, ("Offered",), "accept_deadline", "Expired")

    def close(self, caller, key):
        return self._act("close", key, ("Settled", "Slashed", "Expired"), None, None)


def test_settler_moves_every_job_past_its_deadline(fake):
    from solders.keypair import Keypair

    from tdcc_exact.node.settler import SettlerNode
    c, me, logs = SettleChain(), Keypair(), []
    other = Keypair().pubkey()
    c.add(Key("rev-due"), "Revealed", other, challenge_deadline=99)
    c.add(Key("rev-wait"), "Revealed", other, challenge_deadline=100)     # == now: still open
    c.add(Key("open-due"), "Open", other, reveal_deadline=50)
    c.add(Key("com-due"), "Committed", other, reveal_deadline=99)
    c.add(Key("com-wait"), "Committed", other, reveal_deadline=120)
    c.add(Key("chal"), "Challenged", other, challenge_deadline=10)        # the arbiter's
    c.add(Key("off-mine"), "Offered", me.pubkey(), accept_deadline=90)
    c.add(Key("off-theirs"), "Offered", other, accept_deadline=90)
    c.add(Key("off-wait"), "Offered", me.pubkey(), accept_deadline=100)
    c.add(Key("slashed"), "Slashed", other)
    s = SettlerNode(c, me, log=logs.append)
    assert s.run_once() == {"rev-due": ["settle", "close"], "open-due": ["expire", "close"],
                            "com-due": ["expire", "close"], "off-mine": ["cancel", "close"],
                            "slashed": ["close"]}
    assert sum("off-thei" in x and "skipped" in x for x in logs) == 1
    assert {str(k): j.state for k, j in c.jobs_.items()} == {
        "rev-wait": "Revealed", "com-wait": "Committed", "chal": "Challenged",
        "off-theirs": "Offered", "off-wait": "Offered"}
    assert s.run_once() == {}
    assert sum("skipped" in x for x in logs) == 1                       # logged once
    c.now = 130
    assert s.run_once() == {"rev-wait": ["settle", "close"], "com-wait": ["expire", "close"],
                            "off-wait": ["cancel", "close"]}
    # under someone else's key the renter's lapsed offer stays; close=False keeps accounts
    c.add(Key("rev2"), "Revealed", other, challenge_deadline=1)
    c.add(Key("off2"), "Offered", me.pubkey(), accept_deadline=1)
    assert SettlerNode(c, Keypair(), close=False, log=logs.append).run_once() == {
        "rev2": ["settle"]}
    assert c.jobs_[Key("rev2")].state == "Settled" and c.jobs_[Key("off2")].state == "Offered"


def test_settler_shrugs_off_a_lost_race(fake):
    from solders.keypair import Keypair

    from tdcc_exact.node.settler import SettlerNode
    c, logs = SettleChain(), []
    c.add(Key("j1"), "Revealed", Keypair().pubkey(), challenge_deadline=1)
    c.add(Key("j2"), "Open", Keypair().pubkey(), reveal_deadline=1)
    c.fail.add(("settle", Key("j1")))
    assert SettlerNode(c, Keypair(), log=logs.append).run_once() == {"j2": ["expire", "close"]}
    assert any("settle failed" in x for x in logs)


@pytest.mark.skipif(not _chain_up(), reason=f"no validator with the program at {URL}")
def test_settler_on_a_validator(tmp_path):
    """Jobs left at every deadline: a third party's settler (the CLI) settles, expires and
    closes them and skips the renter's lapsed offer; the renter's own settler cancels it."""
    from solders.keypair import Keypair

    from tdcc_exact.chain import Market, Params, Rpc, receipt_fingerprint, trace_root
    from tdcc_exact.cli import main
    from tdcc_exact.commit import commitment
    from tdcc_exact.node.chainio import Chain
    from tdcc_exact.node.settler import SettlerNode

    rpc = Rpc(URL)
    admin, renter, prov, treasury, anyone = (Keypair() for _ in range(5))
    for k in (admin, renter, prov, anyone):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    params = Params(commit_window=8, challenge_window=6, arbiter_window=4,
                    unstake_cooldown=40, non_reveal_penalty=1_000_000)
    m.initialize(treasury.pubkey(), params)
    m.mint_to(prov.pubkey(), 20_000_000)
    m.register_provider(prov)
    m.stake(prov, 20_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)
    model, base = bytes([7]) * 32, int(time.time() * 1000)

    def offer(i, accept=True):
        job, _ = m.open_job(renter, prov.pubkey(), base + i, bytes([i]) * 32, model, 1_000_000)
        if accept:
            m.accept_job(prov, job)
        return job

    jr, jc, jo, jf = offer(1), offer(2), offer(3), offer(4, accept=False)
    salts = {}
    for j in (jr, jc):
        fp = receipt_fingerprint(m.job(j).job_digest, model, "YES", b"\x11" * 32,
                                 trace_root(b"\x12" * 32, 3))
        salts[j] = (fp, os.urandom(32))
        m.commit_receipt(prov, j, commitment(fp, bytes(prov.pubkey()), salts[j][1]))
    rpc.wait_slot(m.job(jr).commit_deadline)
    fp, salt = salts[jr]
    m.reveal_receipt(prov, jr, fp, salt, model, "YES", b"\x11" * 32, b"\x12" * 32, 3)
    chain = Chain(m)
    assert SettlerNode(chain, anyone, log=lambda *x: None).run_once() == {}   # nothing due
    rpc.wait_slot(max(m.job(jr).challenge_deadline, m.job(jc).reveal_deadline,
                      m.job(jo).reveal_deadline, m.job(jf).accept_deadline))

    keys = tmp_path / "keys"
    keys.mkdir()
    for name, k in (("settler", anyone), ("admin", admin), ("renter", renter)):
        (keys / f"{name}.json").write_text(json.dumps(list(bytes(k))))
    p0, r0 = m.balance(prov.pubkey()), m.balance(renter.pubkey())
    assert main(["node", "settler", "--rpc", URL, "--keys", str(keys), "--once"]) == 0
    for j in (jr, jc, jo):
        assert rpc.account(j) is None                   # settled or expired, then closed
    assert m.job(jf).state == "Offered"                 # only the renter cancels
    assert m.balance(prov.pubkey()) - p0 == 800_000
    assert m.balance(renter.pubkey()) - r0 == 2 * 1_000_000 + 1_000_000   # + the penalty
    assert m.provider(prov.pubkey()).open_jobs == 0
    assert main(["node", "settler", "--rpc", URL, "--keys", str(keys), "--name", "renter",
                 "--once"]) == 0
    assert rpc.account(jf) is None
    assert m.balance(renter.pubkey()) - r0 == 4 * 1_000_000
