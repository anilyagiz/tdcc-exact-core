"""The renter SDK (tdcc_exact.renter): against a stand-in for the chain that keeps the program's
rules for the calls a renter makes, and end to end on a local validator with a provider node
(skipped without one, as tests/test_node.py):

    TDCC_EXACT_RPC=http://127.0.0.1:8899 python -m pytest -q tests/test_renter.py
"""
import json
import os
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("solders")
from solders.keypair import Keypair  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402

from tdcc_exact import registry  # noqa: E402
from tdcc_exact.node.store import DirStore  # noqa: E402
from tdcc_exact.renter import Handle, MarketIO, Renter  # noqa: E402

EVERY = 512
TINY_HASH = registry.expected("tiny", "int8", 256)


class FakeChain:
    """The renter's chain calls (MarketIO's), with the program's state rules. tick: slots
    each slot() read advances (so a wait loop makes progress)."""

    def __init__(self, commit_window=10, challenge_window=10, tick=0):
        self.now, self.cw, self.chw, self.tick = 100, commit_window, challenge_window, tick
        self.jobs_, self.events, self.sent = {}, {}, []

    def slot(self):
        self.now += self.tick
        return self.now

    def commit_window(self):
        return self.cw

    def open(self, renter, provider, job_id, digest, model_hash, price, deadline):
        assert price > 0 and self.now < deadline <= self.now + self.cw
        key = Pubkey.new_unique()
        self.jobs_[key] = SimpleNamespace(
            renter=renter.pubkey(), provider=provider, job_id=job_id, job_digest=digest,
            model_hash=model_hash, price=price, state="Open", commit_deadline=deadline,
            reveal_deadline=deadline + self.cw, challenge_deadline=0, ruling_deadline=0,
            fingerprint=bytes(32), verifier=Pubkey.default(), answer=255)
        self.sent.append(("open", key))
        return key, f"sig-open-{len(self.sent)}"

    def job(self, key):
        return self.jobs_.get(key)

    def revealed(self, key):
        return self.events.get(key)

    # what providers, verifiers and arbiters do, condensed
    def reveal(self, key, answer, logits_hash, fp=None):
        j = self.jobs_[key]
        assert j.state in ("Open", "Committed")
        self.now = max(self.now, j.commit_deadline + 1)
        j.state, j.answer = "Revealed", int(answer == "YES")
        j.fingerprint = fp or os.urandom(32)
        j.challenge_deadline = self.now + self.chw
        self.events[key] = {"name": "ReceiptRevealed", "job": str(key), "answer": j.answer,
                            "logits_hash": logits_hash}

    def challenge(self, key):
        j = self.jobs_[key]
        assert j.state == "Revealed" and self.now <= j.challenge_deadline
        j.state, j.verifier, j.ruling_deadline = "Challenged", Pubkey.new_unique(), self.now + 5

    # the renter's writes
    def settle(self, payer, key):
        j = self.jobs_[key]
        assert j.state == "Revealed" and self.now > j.challenge_deadline
        j.state = "Settled"
        self.sent.append(("settle", key))

    def expire(self, payer, key):
        j = self.jobs_[key]
        assert j.state in ("Open", "Committed") and self.now > j.reveal_deadline
        j.state = "Expired"
        self.sent.append(("expire", key))

    def close(self, caller, key):
        assert self.jobs_[key].state in ("Settled", "Slashed", "Expired")
        del self.jobs_[key]
        self.sent.append(("close", key))


@pytest.fixture
def env(tmp_path):
    chain, store = FakeChain(), DirStore(tmp_path / "store")
    return SimpleNamespace(chain=chain, store=store, renter=Renter(chain, Keypair(), store),
                           providers=[Pubkey.new_unique() for _ in range(3)])


def _keys(h):
    return [Pubkey.from_string(e["account"]) for e in h.jobs]


def test_ask_publishes_and_opens_a_fan_out_with_one_deadline(env):
    h = env.renter.ask("tiny", "Will it rain?", env.providers, 1_000, every=EVERY)
    assert env.store.get_job(h.job.digest.hex()) == h.job
    assert h.model_hash == TINY_HASH and h.job.every == EVERY
    js = [env.chain.jobs_[k] for k in _keys(h)]
    assert [j.provider for j in js] == env.providers
    assert {j.commit_deadline for j in js} == {h.commit_deadline}
    assert {j.job_digest for j in js} == {h.job.digest}
    assert len({j.job_id for j in js}) == 3
    assert {j.model_hash.hex() for j in js} == {TINY_HASH}
    # the handle survives a file
    h2 = Handle.from_json(json.loads(json.dumps(h.to_json())))
    assert h2.job.digest == h.job.digest and h2.jobs == h.jobs


def test_ask_refuses_what_no_provider_would_answer(env):
    with pytest.raises(ValueError, match="registry"):
        env.renter.ask("tiny:7", "Q?", env.providers[:1], 1_000)
    with pytest.raises(ValueError, match="twice"):
        env.renter.ask("tiny", "Q?", [env.providers[0]] * 2, 1_000)
    with pytest.raises(ValueError, match="price"):
        env.renter.ask("tiny", "Q?", env.providers[:1], 0)
    assert env.chain.sent == []


def test_wait_settle_close_on_agreement(env):
    c, r = env.chain, env.renter
    h = r.ask("tiny", "Will it rain?", env.providers[:2], 1_000, every=EVERY)
    s = r.status(h)
    assert not s["done"] and s["revealed"] == 0 and s["answer"] is None
    for k in _keys(h):
        c.reveal(k, "YES", "ab" * 32)
    s = r.status(h)
    assert not s["done"] and s["answer"] == "YES" and s["agree"]   # the window is open
    assert r.settle_or_expire(h) == {e["account"]: ["waiting (Revealed)"] for e in h.jobs}
    c.tick = 1
    s = r.wait(h, timeout=5, poll=0)
    assert s["done"] and s["answer"] == "YES" and s["agree"] and s["revealed"] == 2
    assert not s["challenged"] and not s["slashed"] and not s["settled"]
    assert {j["logits_hash"] for j in s["jobs"]} == {"ab" * 32}
    assert all(len(j["fingerprint"]) == 64 for j in s["jobs"])
    assert r.settle_or_expire(h) == {e["account"]: ["settled", "closed"] for e in h.jobs}
    assert c.jobs_ == {}
    s = r.status(h)                       # closed accounts: what was read before stays
    assert s["done"] and s["settled"] and s["answer"] == "YES"
    assert r.settle_or_expire(h) == {e["account"]: ["closed"] for e in h.jobs}


def test_disagreement_has_no_answer(env):
    c, r = env.chain, env.renter
    h = r.ask("tiny", "Q?", env.providers[:2], 1_000, every=EVERY)
    a, b = _keys(h)
    c.reveal(a, "YES", "ab" * 32)
    c.reveal(b, "YES", "cd" * 32)          # same word, other logits: one did other work
    s = r.status(h)
    assert not s["agree"] and s["answer"] is None
    c.jobs_[b].answer = 0
    h.jobs[1].pop("answer")
    assert not r.status(h)["agree"]


def test_never_revealed_expires(env):
    c, r = env.chain, env.renter
    h = r.ask("tiny", "Q?", env.providers[:2], 1_000, every=EVERY)
    a, b = _keys(h)
    c.reveal(a, "NO", "ab" * 32)
    s = r.status(h)
    assert s["answer"] == "NO" and s["revealed"] == 1 and not s["done"]
    c.now = max(c.jobs_[b].reveal_deadline, c.jobs_[a].challenge_deadline) + 1
    assert r.wait(h, timeout=1, poll=0)["done"]
    acts = r.settle_or_expire(h)
    assert acts == {str(a): ["settled", "closed"], str(b): ["expired", "closed"]}


def test_a_challenge_holds_the_wait_until_ruled(env):
    c, r = env.chain, env.renter
    h = r.ask("tiny", "Q?", env.providers[:1], 1_000, every=EVERY)
    (k,) = _keys(h)
    c.reveal(k, "YES", "ab" * 32)
    c.challenge(k)
    c.now += 100
    s = r.wait(h, timeout=0.05, poll=0.01)
    assert not s["done"] and s["challenged"] and s["jobs"][0]["state"] == "Challenged"
    assert r.settle_or_expire(h) == {str(k): ["waiting (Challenged)"]}
    c.jobs_[k].state = "Slashed"
    s = r.status(h)
    assert s["done"] and s["challenged"] and s["slashed"]
    assert r.settle_or_expire(h) == {str(k): ["closed"]}


def test_cli_ask_wait_settle(env, tmp_path, monkeypatch, capsys):
    from tdcc_exact.cli import main
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "renter.json").write_text(json.dumps(list(bytes(env.renter.owner))))
    env.chain.tick = 1
    monkeypatch.setattr(MarketIO, "connect", staticmethod(lambda *a, **k: env.chain))
    read = env.chain.job

    def job_answered(key):                    # a provider that answers once the renter looks
        j = read(key)
        if j is not None and j.state == "Open":
            env.chain.reveal(key, "YES", "ab" * 32)
        return j
    env.chain.job = job_answered
    argv = ["renter", "ask", "--keys", str(keys), "--admin", str(Pubkey.new_unique()),
            "--store", str(tmp_path / "store"), "--question", "Q?", "--price", "1000",
            "--every", str(EVERY), "--out", str(tmp_path / "h.json"), "--settle"]
    for p in env.providers[:2]:
        argv += ["--provider", str(p)]
    assert main(argv) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"]["answer"] == "YES" and out["result"]["done"]
    assert all(v == ["settled", "closed"] for v in out["settle"].values())
    assert json.loads((tmp_path / "h.json").read_text())["digest"] == out["handle"]["digest"]
    assert main(["renter", "status", "--keys", str(keys), "--admin", str(Pubkey.new_unique()),
                 "--store", str(tmp_path / "store"), "--handle", str(tmp_path / "h.json")]) == 0
    assert json.loads(capsys.readouterr().out)["result"]["jobs"][0]["state"] == "Closed"


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
def test_renter_on_a_validator(tmp_path):
    from tdcc_exact.chain import Market, Params, Rpc
    from tdcc_exact.node.chainio import Chain, PubOnly
    from tdcc_exact.node.common import Models
    from tdcc_exact.node.provider import ProviderNode

    rpc = Rpc(URL)
    admin, renter, a, b, treasury = (Keypair() for _ in range(5))
    for k in (admin, renter, a, b):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    m.initialize(treasury.pubkey(), Params(commit_window=40, challenge_window=10,
                                           unstake_cooldown=200))
    for p in (a, b):
        m.mint_to(p.pubkey(), 50_000_000)
        m.register_provider(p)
        m.stake(p, 50_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)

    store = DirStore(tmp_path / "store")
    # the renter knows the market by its admin's public key only
    io = MarketIO.connect(URL, PubOnly(admin.pubkey()))
    r = Renter(io, renter, store)
    h = r.ask("tiny", "Will it rain tomorrow?", [a.pubkey(), b.pubkey()], 1_000_000,
              every=EVERY)
    assert m.balance(renter.pubkey()) == 8_000_000
    ka, kb = _keys(h)
    assert m.job(ka).commit_deadline == m.job(kb).commit_deadline == h.commit_deadline

    chain, models, quiet = Chain(m), Models(), (lambda *x: None)
    nodes = [ProviderNode(chain, p, store, tmp_path / n / "state.json", models, log=quiet)
             for n, p in (("a", a), ("b", b))]
    assert nodes[0].run_once() == {str(ka): "committed"}
    assert nodes[1].run_once(wait=True) == {str(kb): "published"}
    assert nodes[0].run_once(wait=True) == {str(ka): "published"}

    t0 = time.time()
    s = r.wait(h, timeout=120, poll=0.5)
    assert s["done"], s
    assert s["answer"] in ("YES", "NO") and s["agree"] and s["revealed"] == 2
    assert not s["challenged"] and not s["slashed"]
    ev = chain.revealed(ka)
    assert s["jobs"][0]["logits_hash"] == ev["logits_hash"]
    assert s["jobs"][0]["fingerprint"] == m.job(ka).fingerprint.hex()
    assert s["jobs"][0]["fingerprint"] != s["jobs"][1]["fingerprint"]   # bound to each job
    assert time.time() - t0 < 120

    lamports = rpc.balance(renter.pubkey())
    rent = rpc.balance(ka) + rpc.balance(kb)
    assert r.settle_or_expire(h) == {str(ka): ["settled", "closed"],
                                     str(kb): ["settled", "closed"]}
    assert rpc.account(ka) is None and rpc.account(kb) is None
    got = rpc.balance(renter.pubkey()) - lamports
    assert rent - 100_000 < got <= rent           # the jobs' rent back, less the fees
    host = Params().host_bps * 1_000_000 // 10_000
    assert m.balance(a.pubkey()) == m.balance(b.pubkey()) == host
    s = r.status(h)
    assert s["settled"] and s["answer"] in ("YES", "NO")
