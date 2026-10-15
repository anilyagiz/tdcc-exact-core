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

from tdcc_exact.chain import ChainError, Market, Params, Rpc  # noqa: E402
from tdcc_exact.commit import commitment  # noqa: E402
from tdcc_exact.settle import accept, slash  # noqa: E402

URL = os.environ.get("TDCC_EXACT_RPC", "http://127.0.0.1:8899")
PRICE, STAKE = 2_000_001, 50_000_001          # odd: the rounding is the program's
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
    admin, renter, verifier = Keypair(), Keypair(), Keypair()
    a, b, c, treasury = Keypair(), Keypair(), Keypair(), Keypair()
    for k in (admin, renter, verifier, a, b, c):
        rpc.airdrop(k.pubkey(), 2_000_000_000)
    m = Market(rpc, admin, "localnet")
    m.initialize(treasury.pubkey(), Params(commit_window=4, challenge_window=4,
                                           unstake_cooldown=4))
    for p in (a, b, c):
        m.mint_to(p.pubkey(), STAKE)
        m.register_provider(p)
        m.stake(p, STAKE)
    m.mint_to(renter.pubkey(), 100 * PRICE)
    m.mint_to(verifier.pubkey(), 0)
    return dict(m=m, rpc=rpc, admin=admin, renter=renter, verifier=verifier, a=a, b=b, c=c,
                treasury=treasury, next=[1])


def _open(w, provider):
    jid = w["next"][0]
    w["next"][0] += 1
    job, _ = w["m"].open_job(w["renter"], provider.pubkey(), jid, bytes([jid]) * 32, MODEL,
                             PRICE)
    return job


def _post(w, provider, job, fp, model=MODEL):
    m, salt = w["m"], os.urandom(32)
    m.commit_receipt(provider, job, commitment(fp, bytes(provider.pubkey()), salt))
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    m.reveal_receipt(provider, job, fp, salt, model, bytes(32), 3)


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
    m.challenge(w["verifier"], job, b"\x03" * 32)
    assert m.job(job).state == "Challenged"
    impostor = copy.copy(m)
    impostor.admin = w["verifier"]
    with pytest.raises(ChainError, match="ConstraintHasOne"):                 # only the arbiter slashes
        impostor.slash(job, 1, 1234)
    r0, v0, t0 = (m.balance(w[k].pubkey()) for k in ("renter", "verifier", "treasury"))
    m.slash(job, 1, 1234)
    want = {t[0]: t[1] for t in slash("j", "B", "renter", "verifier", PRICE, STAKE).transfers}
    assert m.balance(w["renter"].pubkey()) - r0 == want["renter"]
    assert m.balance(w["verifier"].pubkey()) - v0 == want["verifier"]
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
        m.reveal_receipt(w["a"], job, fp, salt, MODEL, bytes(32), 3)


def test_reveal_waits_for_the_commit_window_and_needs_the_job_model(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    fp, salt = b"\x06" * 32, os.urandom(32)
    m.commit_receipt(w["a"], job, commitment(fp, bytes(w["a"].pubkey()), salt))
    with pytest.raises(ChainError, match="WindowOpen"):                 # too early: others could still copy
        m.reveal_receipt(w["a"], job, fp, salt, MODEL, bytes(32), 3)
    w["rpc"].wait_slot(m.job(job).commit_deadline)
    with pytest.raises(ChainError, match="ModelMismatch"):                 # another model image (fp4 for int8)
        m.reveal_receipt(w["a"], job, fp, salt, bytes(32), bytes(32), 3)
    m.reveal_receipt(w["a"], job, fp, salt, MODEL, bytes(32), 3)


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
    r0 = m.balance(w["renter"].pubkey())
    m.expire(w["renter"], job)
    assert m.balance(w["renter"].pubkey()) - r0 == PRICE
    assert m.job(job).state == "Expired"


def test_dismissed_challenge_settles(world):
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x08" * 32)
    m.challenge(w["verifier"], job, b"\x09" * 32)
    with pytest.raises(ChainError, match="WrongState"):
        m.settle(w["admin"], job)                   # challenged: no settle
    m.dismiss(job)
    w["rpc"].wait_slot(m.job(job).challenge_deadline)
    m.settle(w["admin"], job)
    assert m.job(job).state == "Settled"


def test_unstake_waits_for_the_cooldown_and_the_open_jobs(world):
    w, m, c = world, world["m"], world["c"]
    job = _open(w, c)
    with pytest.raises(ChainError, match="StakeLocked"):                # no unstake requested
        m.unstake(c)
    m.request_unstake(c)
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
    m.unstake(c)
    assert m.balance(c.pubkey()) - before == STAKE
    assert m.provider(c.pubkey()).stake == 0


def test_a_dismissed_challenge_cannot_be_raised_again(world):
    """dismiss and a new challenge in one transaction (so in one slot, where the challenge
    window is still open): the arbiter's ruling stands, the job settles."""
    from tdcc_exact.chain import R, S, W, b32
    w, m = world, world["m"]
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x0b" * 32)
    m.challenge(w["verifier"], job, b"\x0c" * 32)
    again = [m._ix("dismiss", [S(w["admin"].pubkey()), R(m.config), W(job)]),
             m._ix("challenge", [S(w["verifier"].pubkey()), W(job)], b32(b"\x0d" * 32))]
    with pytest.raises(ChainError, match="AlreadyChallenged"):
        w["rpc"].send(again, w["admin"], w["verifier"])
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
    job = _open(w, w["a"])
    _post(w, w["a"], job, b"\x0e" * 32)                  # 3 checkpoints
    m.challenge(w["verifier"], job, b"\x0f" * 32)
    with pytest.raises(ChainError, match="BadParams"):
        m.slash(job, 4, 1234)
    m.dismiss(job)
