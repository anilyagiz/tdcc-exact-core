"""programs/tdcc_exact on a local validator, through tdcc_exact/chain.py.

Needs a running validator with the program loaded (skipped otherwise):

    cargo build-sbf --manifest-path programs/tdcc_exact/Cargo.toml
    solana-test-validator --reset --bpf-program \\
        HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A target/deploy/tdcc_exact.so
    TDCC_EXACT_RPC=http://127.0.0.1:8899 python -m pytest -q tests/test_chain.py
"""
import copy
import os

import pytest

solders = pytest.importorskip("solders")

from solders.keypair import Keypair  # noqa: E402

from tdcc_exact.chain import (ChainError, Market, Params, Rpc, ata,  # noqa: E402
                              receipt_fingerprint, trace_root)
from tdcc_exact.commit import commitment  # noqa: E402
from tdcc_exact.settle import accept, dismiss, expire, slash  # noqa: E402

URL = os.environ.get("TDCC_EXACT_RPC", "http://127.0.0.1:8899")
PRICE, STAKE = 2_000_001, 50_000_001          # odd: the rounding is the program's
BOND = 1_000_003
# windows in slots (~0.4 s each): wide enough that a loaded runner still commits, reveals and
# challenges inside them (4 slots flaked), short enough to keep the suite quick
PENALTY = 3_000_007
WORLD = Params(commit_window=10, challenge_window=8, arbiter_window=6, unstake_cooldown=35,
               challenge_bond=BOND, non_reveal_penalty=PENALTY)
MODEL = bytes([7]) * 32


def _up() -> bool:
    try:
        rpc = Rpc(URL)
        rpc.call("getHealth")
        from tdcc_exact.chain import PROGRAM_ID
        return rpc.account(PROGRAM_ID) is not None
    except Exception:  # noqa: BLE001
        return False


if os.environ.get("TDCC_EXACT_REQUIRE_CHAIN") and not _up():
    raise RuntimeError(f"no validator with the program at {URL}")     # CI: never skip quietly
pytestmark = pytest.mark.skipif(not _up(), reason=f"no validator with the program at {URL}")


@pytest.fixture(scope="module")
def world():
    rpc = Rpc(URL)
    import dataclasses
    admin, renter, verifier, arbiter = Keypair(), Keypair(), Keypair(), Keypair()
    a, b, c, treasury = Keypair(), Keypair(), Keypair(), Keypair()
    for k in (admin, renter, verifier, arbiter, a, b, c):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet", arbiter=arbiter)     # the arbiter: its own key
    m.initialize(treasury.pubkey(), dataclasses.replace(WORLD, arbiter=arbiter.pubkey()))
    for p in (a, b, c):
        m.mint_to(p.pubkey(), STAKE)
        m.register_provider(p)
        m.stake(p, STAKE)
    m.mint_to(renter.pubkey(), 100 * PRICE)
    m.mint_to(verifier.pubkey(), 100 * BOND)
    return dict(m=m, rpc=rpc, admin=admin, arbiter=arbiter, renter=renter, verifier=verifier,
                a=a, b=b, c=c,
                treasury=treasury, next=[1])


def _events(w, sig) -> list[str]:
    """The program's events in a transaction's logs, by name (Anchor: "Program data: " and
    the first 8 bytes of SHA-256("event:<Name>"))."""
    import base64
    import hashlib
    import time
    from tdcc_exact.indexer import EVENTS             # every #[event] (test_indexer checks)
    names = list(EVENTS)
    disc = {hashlib.sha256(f"event:{n}".encode()).digest()[:8]: n for n in names}
    for _ in range(20):
        tx = w["rpc"].call("getTransaction", sig, {"encoding": "json", "commitment": "confirmed",
                                                   "maxSupportedTransactionVersion": 0})
        if tx is not None:
            break
        time.sleep(0.5)
    data = [base64.b64decode(l.split(": ", 1)[1]) for l in tx["meta"]["logMessages"]
            if l.startswith("Program data: ")]
    return [disc.get(d[:8], "?") for d in data]


def _open(w, provider):
    jid = w["next"][0]
    w["next"][0] += 1
    job, _ = w["m"].open_job(w["renter"], provider.pubkey(), jid, bytes([jid]) * 32, MODEL,
                             PRICE)
    return job


def _receipt(m, job, seed: bytes, model=MODEL, answer="YES", cps=3):
    """A receipt the program accepts for `job`: (fingerprint, the reveal's arguments after the
    salt). `seed` stands in for both the logits hash and the trace's tree root."""
    fp = receipt_fingerprint(m.job(job).job_digest, model, answer, seed, trace_root(seed, cps))
    return fp, (model, answer, seed, seed, cps)


def _post(w, provider, job, seed, model=MODEL):
    """Commit and reveal a receipt made from `seed`; its fingerprint."""
    m, salt = w["m"], os.urandom(32)
    fp, args = _receipt(m, job, seed, model)
    m.commit_receipt(provider, job, commitment(fp, bytes(provider.pubkey()), salt))
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    m.reveal_receipt(provider, job, fp, salt, *args)
    return fp


def test_honest_job_settles_80_20(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x01" * 32)
    with pytest.raises(ChainError, match="WindowOpen"):                 # the challenge window is still open
        m.settle(w["admin"], job)
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    before_a, before_t = m.balance(w["a"].pubkey()), m.balance(w["treasury"].pubkey())
    m.settle(w["admin"], job)
    want = {t[0]: t[1] for t in accept("j", "A", PRICE).transfers}
    assert m.balance(w["a"].pubkey()) - before_a == want["A"]
    assert m.balance(w["treasury"].pubkey()) - before_t == want["tdcc"]
    assert m.job(job).state == "Settled"
    with pytest.raises(ChainError, match="WrongState"):                 # no double settle
        m.settle(w["admin"], job)


def test_caught_provider_is_slashed(world):
    w, m = world, world["m"]
    job = _open(w, w["b"])
    _post(w, w["b"], job, b"\x02" * 32)
    v_pre = m.balance(w["verifier"].pubkey())
    m.challenge(w["verifier"], job, b"\x03" * 32)
    assert m.job(job).state == "Challenged"
    assert m.job(job).bond == BOND
    assert v_pre - m.balance(w["verifier"].pubkey()) == BOND        # the bond is posted
    impostor = copy.copy(m)
    impostor.arbiter = w["verifier"]
    with pytest.raises(ChainError, match="ConstraintHasOne"):                 # only the arbiter slashes
        impostor.slash(job, 1, 1234)
    r0, v0, t0 = (m.balance(w[k].pubkey()) for k in ("renter", "verifier", "treasury"))
    m.slash(job, 1, 1234)
    want = {}
    for t in slash("j", "B", "renter", "verifier", PRICE, STAKE, BOND).transfers:
        want[t[0]] = want.get(t[0], 0) + t[1]
    assert m.balance(w["renter"].pubkey()) - r0 == want["renter"]
    assert m.balance(w["verifier"].pubkey()) - v0 == want["verifier"]      # share + bond back
    assert m.balance(w["treasury"].pubkey()) - t0 == want["tdcc"]
    assert m.provider(w["b"].pubkey()).stake == 0
    assert m.job(job).state == "Slashed"
    with pytest.raises(ChainError, match="ProviderNotStaked"):                 # a slashed provider takes no new jobs
        _open(w, w["b"])


def test_a_copied_commitment_does_not_reveal(world):
    """C posts A's commitment as its own: it binds A's key, so C's reveal fails."""
    w, m = world, world["m"]
    job = _open(w, w["a"])
    fp, salt = b"\x05" * 32, os.urandom(32)
    copied = commitment(fp, bytes(Keypair().pubkey()), salt)      # someone else's commitment
    m.commit_receipt(w["a"], job, copied)
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    with pytest.raises(ChainError, match="BadReveal"):
        m.reveal_receipt(w["a"], job, fp, salt, MODEL, "YES", fp, fp, 3)


def test_reveal_waits_for_the_commit_window_and_needs_the_job_model(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    salt = os.urandom(32)
    fp, args = _receipt(m, job, b"\x06" * 32)
    m.commit_receipt(w["a"], job, commitment(fp, bytes(w["a"].pubkey()), salt))
    with pytest.raises(ChainError, match="WindowOpen"):                 # too early: others could still copy
        m.reveal_receipt(w["a"], job, fp, salt, *args)
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    with pytest.raises(ChainError, match="ModelMismatch"):                 # another model image (fp4 for int8)
        m.reveal_receipt(w["a"], job, fp, salt, bytes(32), *args[1:])
    m.reveal_receipt(w["a"], job, fp, salt, *args)


def test_wrong_signer_cannot_commit_for_a_provider(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    with pytest.raises(ChainError, match="NotYourJob"):
        m.commit_receipt(w["verifier"], job, b"\x00" * 32)


def test_unrevealed_job_expires_back_to_the_renter(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    with pytest.raises(ChainError, match="WindowOpen"):                 # not before the reveal deadline
        m.expire(w["renter"], job)
    w["rpc"].wait_slot(m.job(job).reveal_deadline)
    r0, s0 = m.balance(w["renter"].pubkey()), m.provider(w["a"].pubkey()).stake
    sig = m.expire(w["renter"], job)
    assert m.balance(w["renter"].pubkey()) - r0 == PRICE           # never committed: no penalty
    assert m.provider(w["a"].pubkey()).stake == s0
    assert _events(w, sig) == ["Expired"]
    assert m.job(job).state == "Expired"


def test_dismissed_challenge_settles(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x08" * 32)
    v0, a0 = m.balance(w["verifier"].pubkey()), m.balance(w["a"].pubkey())
    m.challenge(w["verifier"], job, b"\x09" * 32)
    with pytest.raises(ChainError, match="WrongState"):
        m.settle(w["admin"], job)                   # challenged: no settle
    m.dismiss(job)
    want = {t[0]: t[1] for t in dismiss("j", "A", "verifier", BOND).transfers}
    assert m.balance(w["verifier"].pubkey()) - v0 == want["verifier"]      # the bond is lost
    assert m.balance(w["a"].pubkey()) - a0 == want["A"]                    # ...to the provider
    assert m.job(job).bond == 0
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    m.settle(w["admin"], job)
    assert m.job(job).state == "Settled"


def test_unstake_waits_for_the_cooldown_and_the_open_jobs(world):
    w, m, c = world, world["m"], world["c"]
    job = _open(w, c)
    with pytest.raises(ChainError, match="StakeLocked"):                # no unstake requested
        m.unstake(c)
    assert _events(w, m.request_unstake(c)) == ["UnstakeRequested"]
    with pytest.raises(ChainError, match="ProviderNotStaked"):          # leaving: no new jobs
        _open(w, c)
    with pytest.raises(ChainError, match="StakeLocked"):                # the cooldown runs
        m.unstake(c)
    w["rpc"].wait_slot(m.provider(c.pubkey()).unlock_slot)
    with pytest.raises(ChainError, match="StakeLocked"):                # a job is still open
        m.unstake(c)
    w["rpc"].wait_slot(m.job(job).reveal_deadline)
    m.expire(w["renter"], job)
    before = m.balance(c.pubkey())
    assert _events(w, m.unstake(c)) == ["Unstaked"]
    assert m.balance(c.pubkey()) - before == STAKE
    assert m.provider(c.pubkey()).stake == 0


def test_a_dismissed_challenge_cannot_be_raised_again(world):
    """dismiss and a new challenge by the same verifier in one transaction (so in one slot,
    where the challenge window is still open): the challenge is refused, and the whole
    transaction with it."""
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x0b" * 32)
    m.challenge(w["verifier"], job, b"\x0c" * 32)
    again = [m.dismiss_ix(w["arbiter"].pubkey(), job, w["a"].pubkey()),
             m.challenge_ix(w["verifier"].pubkey(), job, b"\x0d" * 32)]
    with pytest.raises(ChainError, match="AlreadyChallenged"):
        w["rpc"].send(again, w["admin"], w["arbiter"], w["verifier"])
    assert m.job(job).state == "Challenged"            # the transaction rolled back whole


def test_a_job_must_pay_something(world):
    """A free job would let anyone tie up a provider (an open job locks its stake) for nothing."""
    w, m = world, world["m"]
    with pytest.raises(ChainError, match="BadParams"):
        m.open_job(w["renter"], w["a"].pubkey(), 9_999, bytes(32), MODEL, 0)


def test_the_slash_names_a_checkpoint_the_receipt_has(world):
    """The arbiter's ruling points into the posted trace: index <= its checkpoint count (the
    count itself: the provider's list stopped early)."""
    w, m = world, world["m"]
    d = Keypair()                                         # its own provider: this one is slashed
    w["rpc"].airdrop(d.pubkey(), 2_000_000_000)
    m.mint_to(d.pubkey(), STAKE)
    m.register_provider(d)
    m.stake(d, STAKE)
    job = _open(w, d)
    _post(w, d, job, b"\x0e" * 32)                       # 3 checkpoints
    m.challenge(w["verifier"], job, b"\x0f" * 32)
    with pytest.raises(ChainError, match="BadParams"):
        m.slash(job, 4, 1234)
    m.slash(job, 3, 1234)                     # == the count: the provider's list stopped early
    assert m.job(job).state == "Slashed"


@pytest.mark.parametrize("bad", [dict(commit_window=0), dict(challenge_window=0),
                                 dict(min_stake=0)])
def test_a_market_needs_windows_and_a_stake(world, bad):
    """A zero commit window leaves no slot to reveal in, a zero challenge window no slot to
    challenge in, and a zero minimum stake lets unstaked providers take jobs."""
    import dataclasses
    rpc, admin = world["rpc"], Keypair()
    rpc.airdrop(admin.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    with pytest.raises(ChainError, match="BadParams"):
        m.initialize(Keypair().pubkey(), dataclasses.replace(Params(), **bad))


def test_a_new_market_and_provider_are_announced(world):
    rpc, admin, p = world["rpc"], Keypair(), Keypair()
    for k in (admin, p):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    assert "Initialized" in _events(world, m.initialize(Keypair().pubkey(), Params()))
    assert _events(world, m.register_provider(p)) == ["ProviderRegistered"]


def test_a_challenge_after_the_window_is_refused(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x10" * 32)
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    with pytest.raises(ChainError, match="WindowClosed"):
        m.challenge(w["verifier"], job, b"\x11" * 32)
    m.settle(w["admin"], job)


def test_a_committed_but_unrevealed_job_expires(world):
    """The provider committed, then never revealed: the renter gets the escrow back and the
    non-reveal penalty out of the provider's stake (withholding is not free)."""
    w, m = world, world["m"]
    job = _open(w, w["a"])
    m.commit_receipt(w["a"], job, b"\x12" * 32)
    w["rpc"].wait_slot(m.job(job).reveal_deadline)
    r0, s0 = m.balance(w["renter"].pubkey()), m.provider(w["a"].pubkey()).stake
    m.expire(w["renter"], job)
    want = {}
    for t in expire("j", "A", "renter", PRICE, True, PENALTY, s0).transfers:
        want[t[0]] = want.get(t[0], 0) + t[1]
    assert m.balance(w["renter"].pubkey()) - r0 == want["renter"] == PRICE + PENALTY
    assert m.provider(w["a"].pubkey()).stake - s0 == want["A"] == -PENALTY
    assert m.job(job).state == "Expired"


def test_settle_pays_only_the_market_treasury(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x13" * 32)
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    thief = copy.copy(m)
    thief.treasury = ata(w["verifier"].pubkey(), m.mint)    # someone else's USDC account
    with pytest.raises(ChainError, match="ConstraintHasOne"):
        thief.settle(w["admin"], job)
    m.settle(w["admin"], job)
def test_a_challenge_needs_the_bond(world):
    """A verifier with no USDC cannot challenge: challenging is not free."""
    w, m = world, world["m"]
    assert m.params().challenge_bond == BOND
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x0a" * 32)
    broke = Keypair()
    w["rpc"].airdrop(broke.pubkey(), 1_000_000_000)
    m.mint_to(broke.pubkey(), BOND - 1)
    with pytest.raises(ChainError, match="insufficient funds|0x1"):
        m.challenge(broke, job, b"\x0b" * 32)
    assert m.job(job).state == "Revealed"


def test_initialize_needs_a_challenge_bond(world):
    m = Market(world["rpc"], Keypair(), "localnet")
    world["rpc"].airdrop(m.admin.pubkey(), 1_000_000_000)
    with pytest.raises(ChainError, match="BadParams"):
        m.initialize(Keypair().pubkey(), Params(challenge_bond=0))


def test_silent_arbiter_lets_anyone_dismiss_after_the_ruling_deadline(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x0c" * 32)
    m.challenge(w["verifier"], job, b"\x0d" * 32)
    j = m.job(job)
    assert j.ruling_deadline == j.challenge_slot + WORLD.arbiter_window
    with pytest.raises(ChainError, match="ArbiterWindowOpen"):   # the arbiter's turn
        m.dismiss(job, w["renter"])
    w["rpc"].wait_slot(j.ruling_deadline)
    with pytest.raises(ChainError, match="WindowClosed"):        # too late to slash
        m.slash(job, 0, 0)
    a0 = m.balance(w["a"].pubkey())
    m.dismiss(job, w["renter"])                                   # anyone, now
    assert m.balance(w["a"].pubkey()) - a0 == BOND
    assert m.job(job).state == "Revealed"


def test_initialize_needs_an_arbiter_window(world):
    m = Market(world["rpc"], Keypair(), "localnet")
    world["rpc"].airdrop(m.admin.pubkey(), 1_000_000_000)
    with pytest.raises(ChainError, match="BadParams"):
        m.initialize(Keypair().pubkey(), Params(arbiter_window=0))


def test_the_admin_rotates_the_arbiter(world):
    """The arbiter is its own key, not the admin's, and the admin can hand it on (to a multisig,
    or away from a stolen key); only the admin can."""
    w, m = world, world["m"]
    assert m.params().arbiter == w["arbiter"].pubkey()
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x14" * 32)
    m.challenge(w["verifier"], job, b"\x15" * 32)
    new = Keypair()
    w["rpc"].airdrop(new.pubkey(), 1_000_000_000)
    usurper = copy.copy(m)
    usurper.admin = w["verifier"]
    with pytest.raises(ChainError, match="ConstraintSeeds|ConstraintHasOne"):
        usurper.set_arbiter(w["verifier"].pubkey())
    with pytest.raises(ChainError, match="ArbiterWindowOpen"):    # the admin is not the arbiter
        m.dismiss(job, w["admin"])
    assert _events(w, m.set_arbiter(new.pubkey())) == ["ArbiterChanged"]
    try:
        with pytest.raises(ChainError, match="ArbiterWindowOpen"):  # the old arbiter is out
            m.dismiss(job, w["arbiter"])
        m.dismiss(job, new)
        assert m.job(job).state == "Revealed"
    finally:
        m.set_arbiter(w["arbiter"].pubkey())
    assert m.params().arbiter == w["arbiter"].pubkey()


def test_the_arbiter_may_not_challenge(world):
    """A stolen arbiter key must not both raise and rule a challenge (taking verifier_bps of
    every stake it slashes)."""
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x16" * 32)
    m.mint_to(w["arbiter"].pubkey(), BOND)
    with pytest.raises(ChainError, match="ArbiterChallenger"):
        m.challenge(w["arbiter"], job, b"\x17" * 32)


def _verifier(w) -> Keypair:
    v = Keypair()
    w["rpc"].airdrop(v.pubkey(), 1_000_000_000)
    w["m"].mint_to(v.pubkey(), 5 * BOND)
    return v


def _provider(w) -> Keypair:
    """A provider of its own, for a test that slashes it."""
    m, d = w["m"], Keypair()
    w["rpc"].airdrop(d.pubkey(), 2_000_000_000)
    m.mint_to(d.pubkey(), STAKE)
    m.register_provider(d)
    m.stake(d, STAKE)
    return d


def test_a_dismissed_self_challenge_does_not_lock_out_verifiers(world):
    """A cheating provider challenges itself from a second key first; once that is dismissed
    an honest verifier still challenges (until the original deadline) and the provider is
    slashed. Challenge, dismiss and the second challenge go in one transaction, inside the
    window."""
    w, m = world, world["m"]
    d, sock, v2 = _provider(w), _verifier(w), _verifier(w)
    job = _open(w, d)
    _post(w, d, job, b"\x18" * 32)
    deadline = m.job(job).challenge_deadline
    w["rpc"].send([m.challenge_ix(sock.pubkey(), job, b"\x19" * 32),
                   m.dismiss_ix(w["arbiter"].pubkey(), job, d.pubkey()),
                   m.challenge_ix(v2.pubkey(), job, b"\x1a" * 32)],
                  w["admin"], sock, w["arbiter"], v2)
    j = m.job(job)
    assert (j.state, j.verifier, j.challenge_deadline) == ("Challenged", v2.pubkey(), deadline)
    v0 = m.balance(v2.pubkey())
    m.slash(job, 1, 99)
    assert m.balance(v2.pubkey()) - v0 == STAKE // 2 + BOND
    assert m.job(job).state == "Slashed"


def test_a_dismissal_keeps_the_challenge_deadline(world):
    w, m = world, world["m"]
    v2 = _verifier(w)
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x1b" * 32)
    deadline = m.job(job).challenge_deadline
    m.challenge(w["verifier"], job, b"\x1c" * 32)
    m.dismiss(job)
    assert m.job(job).challenge_deadline == deadline
    w["rpc"].wait_slot(deadline)
    with pytest.raises(ChainError, match="WindowClosed"):       # after it: no new challenge
        m.challenge(v2, job, b"\x1d" * 32)
    m.settle(w["admin"], job)


def test_a_finished_job_closes_and_the_rent_goes_back_to_the_renter(world):
    w, m, rpc = world, world["m"], world["rpc"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x1e" * 32)
    with pytest.raises(ChainError, match="WrongState"):             # still live: no close
        m.close_job(job, w["verifier"])
    rpc.wait_slot(m.job(job).challenge_deadline)
    m.settle(w["admin"], job)
    rent, r0 = rpc.balance(job), rpc.balance(w["renter"].pubkey())
    assert rent > 0
    sig = m.close_job(job, w["verifier"])                            # anyone may close it
    assert _events(w, sig) == ["JobClosed"]
    assert rpc.account(job) is None
    assert rpc.balance(w["renter"].pubkey()) - r0 == rent           # to the renter, not the caller


def test_close_job_pays_only_the_renter(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    w["rpc"].wait_slot(m.job(job).reveal_deadline)
    m.expire(w["renter"], job)
    from tdcc_exact.chain import R, S, W
    steal = m._ix("close_job", [S(w["verifier"].pubkey()), R(m.config), W(job),
                                W(w["verifier"].pubkey())])
    with pytest.raises(ChainError, match="ConstraintHasOne"):
        w["rpc"].send([steal], w["verifier"])
    m.close_job(job, w["renter"])
    assert w["rpc"].account(job) is None


def test_the_unstake_cooldown_outlasts_a_job(world):
    """A provider may not be able to leave before a pending challenge can be ruled: the
    cooldown must exceed 2 commit windows + the challenge window + the arbiter window."""
    import dataclasses
    rpc, admin = world["rpc"], Keypair()
    rpc.airdrop(admin.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    p = dataclasses.replace(WORLD, unstake_cooldown=WORLD.job_life)
    with pytest.raises(ChainError, match="BadParams"):
        m.initialize(Keypair().pubkey(), p)
    m.initialize(Keypair().pubkey(), dataclasses.replace(p, unstake_cooldown=p.job_life + 1))


def test_a_slashed_provider_cannot_reveal_its_other_jobs(world):
    """Slashed on one job (stake zeroed), the provider's other committed job is not revealed
    and paid: it expires and the renter gets the escrow back. Reveal, challenge and slash of
    the first job go in one transaction, so the second is still inside its reveal window."""
    w, m, rpc = world, world["m"], world["rpc"]
    d = _provider(w)
    j1, j2 = _open(w, d), _open(w, d)
    salts = (os.urandom(32), os.urandom(32))
    (f1, a1), (f2, a2) = (_receipt(m, j, b"\x1f" * 32) for j in (j1, j2))
    for j, fp, salt in zip((j1, j2), (f1, f2), salts):
        m.commit_receipt(d, j, commitment(fp, bytes(d.pubkey()), salt))
    rpc.wait_slot(max(m.job(j).commit_deadline for j in (j1, j2)))
    rpc.send([m.reveal_ix(d.pubkey(), j1, f1, salts[0], *a1),
              m.challenge_ix(w["verifier"].pubkey(), j1, b"\x20" * 32),
              m.slash_ix(j1, w["renter"].pubkey(), d.pubkey(), w["verifier"].pubkey(), 1, 7)],
             w["admin"], d, w["verifier"], w["arbiter"])
    assert m.provider(d.pubkey()).stake == 0
    with pytest.raises(ChainError, match="ProviderNotStaked"):
        m.reveal_receipt(d, j2, f2, salts[1], *a2)
    rpc.wait_slot(m.job(j2).reveal_deadline)
    r0 = m.balance(w["renter"].pubkey())
    m.expire(w["renter"], j2)
    assert m.balance(w["renter"].pubkey()) - r0 == PRICE


def test_the_reveal_binds_the_answer_and_the_checkpoint_count(world):
    """The fingerprint is checked against its parts: a reveal that changes the answer, the
    logits hash or the checkpoint count (or names no answer) is refused; the accepted one
    stores the answer and the trace root rebuilt from the tree root and the count."""
    w, m = world, world["m"]
    job = _open(w, w["a"])
    seed, salt = b"\x21" * 32, os.urandom(32)
    fp, (model, answer, logits, tree, cps) = _receipt(m, job, seed, answer="NO", cps=5)
    m.commit_receipt(w["a"], job, commitment(fp, bytes(w["a"].pubkey()), salt))
    assert m.job(job).answer == 255                                   # nothing revealed yet
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    for bad in (("YES", logits, tree, cps), ("NO", bytes(32), tree, cps),
                ("NO", logits, tree, cps + 1), ("NO", logits, bytes(32), cps)):
        with pytest.raises(ChainError, match="BadReceipt"):
            m.reveal_receipt(w["a"], job, fp, salt, model, *bad)
    with pytest.raises(ChainError, match="BadParams"):                 # 0 = NO, 1 = YES only
        m.reveal_receipt(w["a"], job, fp, salt, model, 2, logits, tree, cps)
    sig = m.reveal_receipt(w["a"], job, fp, salt, model, answer, logits, tree, cps)
    j = m.job(job)
    assert (j.state, j.answer, j.checkpoints) == ("Revealed", 0, 5)
    assert j.trace_root == trace_root(tree, cps)
    from tdcc_exact.indexer import events_from_logs
    tx = w["rpc"].call("getTransaction", sig, {"encoding": "json", "commitment": "confirmed",
                                               "maxSupportedTransactionVersion": 0})
    ev = [e for e in events_from_logs(tx["meta"]["logMessages"])
          if e["name"] == "ReceiptRevealed"]
    assert (ev[0]["answer"], ev[0]["logits_hash"]) == (0, logits.hex())


def test_a_real_run_reveals(world):
    """A receipt from tdcc_exact.oracle (the tiny model) reveals as it is: the client's
    tree_root/trace_root/receipt_fingerprint are the oracle's and the program's."""
    from tdcc_exact.chain import tree_root
    from tdcc_exact.oracle import fingerprint, new_job, run_job
    w, m = world, world["m"]
    job = new_job("tiny", "Is it raining?", "chain")
    key = m.job_pda(w["renter"].pubkey(), w["next"][0])
    run = run_job(job, "A", binding=bytes(key))
    r = run.receipt
    assert fingerprint(job, r) == r.fingerprint
    leaves = [c.leaf for c in run.log.checkpoints]
    assert trace_root(tree_root(leaves), len(leaves)).hex() == r.trace_root
    jid = w["next"][0]
    w["next"][0] += 1
    onchain, _ = m.open_job(w["renter"], w["a"].pubkey(), jid, job.digest,
                            bytes.fromhex(r.model_hash), PRICE)
    assert onchain == key
    salt = os.urandom(32)
    m.commit_receipt(w["a"], onchain, commitment(bytes.fromhex(r.fingerprint),
                                                 bytes(w["a"].pubkey()), salt))
    w["rpc"].wait_slot(m.job(onchain).commit_deadline)
    m.reveal_run(w["a"], onchain, r, leaves, salt)
    j = m.job(onchain)
    assert j.fingerprint.hex() == r.fingerprint and j.answer == (r.answer == "YES")


def test_a_fan_out_shares_one_commit_deadline(world):
    """The renter opens one job with A and with B in two transactions and gives both the same
    absolute commit deadline; one later than commit_window from now, or already past, is
    refused."""
    w, m, rpc = world, world["m"], world["rpc"]
    other = _provider(w)
    deadline = rpc.slot() + WORLD.commit_window
    jobs = []
    for p in (w["a"], other):
        jid = w["next"][0]
        w["next"][0] += 1
        jobs.append(m.open_job(w["renter"], p.pubkey(), jid, bytes([jid % 256]) * 32, MODEL,
                               PRICE, deadline)[0])
    assert [m.job(j).commit_deadline for j in jobs] == [deadline, deadline]
    assert m.job(jobs[0]).reveal_deadline == deadline + WORLD.commit_window
    for bad in (rpc.slot() + WORLD.commit_window + 5, 1):
        with pytest.raises(ChainError, match="BadParams"):
            m.open_job(w["renter"], w["a"].pubkey(), 99_000 + bad % 1000, bytes(32), MODEL,
                       PRICE, bad)


# ------------------------------------------------------------------ payouts go to their party
def _built(m, method, *args):
    """The instructions (and signers) a Market method would send, without sending them."""
    sent = []
    fake = copy.copy(m)
    fake.rpc = copy.copy(m.rpc)
    fake.rpc.send = lambda ixs, *signers: sent.append((ixs, signers)) or "unsent"
    getattr(Market, method)(fake, *args)
    return sent[0]


def _redirect(w, built, old, new, match):
    """Send `built` with the token account `old` replaced by `new`: refused with `match`."""
    from solders.instruction import AccountMeta, Instruction
    ixs, signers = built
    pid = w["m"].pid                                     # (not in a token-account set-up)
    swapped = [ix if ix.program_id != pid else
               Instruction(ix.program_id, ix.data,
                           [AccountMeta(new if a.pubkey == old else a.pubkey, a.is_signer,
                                        a.is_writable) for a in ix.accounts]) for ix in ixs]
    with pytest.raises(ChainError, match=match):
        w["rpc"].send(swapped, *signers)


def _thief(w):
    return ata(w["verifier"].pubkey(), w["m"].mint)       # a token account of someone else


def test_settle_pays_the_provider_only_into_its_own_account(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x22" * 32)
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    _redirect(w, _built(m, "settle", w["admin"], job), ata(w["a"].pubkey(), m.mint), _thief(w),
              "ConstraintTokenOwner")
    m.settle(w["admin"], job)


def test_slash_pays_the_renter_and_the_verifier_only_into_their_own_accounts(world):
    w, m = world, world["m"]
    d, thief = _provider(w), ata(w["b"].pubkey(), world["m"].mint)
    job = _open(w, d)
    _post(w, d, job, b"\x23" * 32)
    m.challenge(w["verifier"], job, b"\x24" * 32)
    built = _built(m, "slash", job, 1, 5)
    _redirect(w, built, ata(w["verifier"].pubkey(), m.mint), thief, "ConstraintTokenOwner")
    _redirect(w, built, ata(w["renter"].pubkey(), m.mint), thief, "ConstraintTokenOwner")
    m.slash(job, 1, 5)


def test_dismiss_pays_the_bond_only_to_the_provider(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x25" * 32)
    m.challenge(w["verifier"], job, b"\x26" * 32)
    _redirect(w, _built(m, "dismiss", job), ata(w["a"].pubkey(), m.mint), _thief(w),
              "ConstraintTokenOwner")
    m.dismiss(job)


def test_expire_refunds_only_the_renter_in_the_market_mint(world):
    w, m = world, world["m"]
    other = copy.copy(m)
    other.mint, _ = m.create_mint()                       # another token, same renter
    other.mint_to(w["renter"].pubkey(), 0)
    job = _open(w, w["a"])
    w["rpc"].wait_slot(m.job(job).reveal_deadline)
    built = _built(m, "expire", w["renter"], job)
    renter_usdc = ata(w["renter"].pubkey(), m.mint)
    _redirect(w, built, renter_usdc, _thief(w), "ConstraintTokenOwner")
    _redirect(w, built, renter_usdc, ata(w["renter"].pubkey(), other.mint),
              "ConstraintTokenMint")
    m.expire(w["renter"], job)


def test_unstake_pays_only_the_provider(world):
    w, m = world, world["m"]
    d = _provider(w)
    m.request_unstake(d)
    w["rpc"].wait_slot(m.provider(d.pubkey()).unlock_slot)
    _redirect(w, _built(m, "unstake", d), ata(d.pubkey(), m.mint), _thief(w),
              "ConstraintTokenOwner")
    m.unstake(d)
