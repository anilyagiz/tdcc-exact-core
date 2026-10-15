"""TDCC Exact: the trace log, the receipt's fingerprint and the dispute, on the tiny model."""
from pathlib import Path

import pytest

from opentpu import isa as I
from tdcc_exact.backend import SkipLayer
from tdcc_exact.dispute import bisect, first_fault, matches_root
from tdcc_exact.oracle import layers_of, new_job, run_job, tiny_model
from tdcc_exact.settle import accept, slash
from tdcc_exact.trace import Checkpoint, StepRecord, merkle_proof, merkle_root, merkle_verify

EVERY = 512


@pytest.fixture(scope="module")
def setup():
    model = tiny_model()
    job = new_job("tiny", "Will it rain tomorrow?", "t1")
    return job, model, run_job(job, "A", every=EVERY, model=model)


def test_honest_runs_post_the_same_fingerprint(setup):
    job, model, a = setup
    b = run_job(job, "A2", every=EVERY, model=model)
    assert a.receipt.fingerprint == b.receipt.fingerprint
    assert [c.leaf for c in a.log.checkpoints] == [c.leaf for c in b.log.checkpoints]
    assert (a.logits == b.logits).all()
    assert a.receipt.checkpoints > 4


def test_another_question_changes_the_fingerprint(setup):
    job, model, a = setup
    other = run_job(new_job("tiny", "Will it snow tomorrow?"), every=EVERY, model=model)
    assert other.receipt.fingerprint != a.receipt.fingerprint


def test_a_skipped_layer_is_caught_at_the_skipped_instruction(setup):
    job, model, a = setup
    cheat = lambda: SkipLayer(1, layers_of(model[0]))     # noqa: E731
    b = run_job(job, "B", cheat(), every=EVERY, model=model)
    assert b.receipt.extra["skipped_mms"] > 0
    assert b.receipt.fingerprint != a.receipt.fingerprint
    d = bisect(a.log.checkpoints, b.log.checkpoints)
    assert d is not None and d.rounds <= len(a.log.checkpoints).bit_length()
    # every checkpoint before the window agrees, every one from it on differs
    assert all(x.leaf == y.leaf for x, y in zip(a.log.checkpoints[:d.index],
                                                b.log.checkpoints))
    assert all(x.leaf != y.leaf for x, y in zip(a.log.checkpoints[d.index:],
                                                b.log.checkpoints[d.index:]))
    w = (d.lo, d.hi)
    honest = run_job(job, "v", every=EVERY, window=w, model=model).log.records
    other = run_job(job, "B", cheat(), every=EVERY, window=w, model=model).log.records
    f = first_fault(honest, other)
    assert f is not None and f.what == "state" and f.honest.startswith(I.OPNAMES[I.MM])


@pytest.mark.parametrize("change", [dict(no_id=3), dict(prompt_ids=[]), dict(chunk=0),
                                    dict(cap=8), dict(yes_id=512), dict(prompt_ids=[-1])])
def test_a_job_no_run_can_answer_is_refused_before_running(setup, change):
    import dataclasses
    job, model, _ = setup
    bad = dataclasses.replace(job, **change)
    with pytest.raises(ValueError):
        run_job(bad, "A", every=EVERY, model=model)


def test_bisect_agrees_on_equal_traces(setup):
    _, _, a = setup
    assert bisect(a.log.checkpoints, list(a.log.checkpoints)) is None


def _cps(n, bad=()):
    return [Checkpoint(10 * i, (b"x" if i in bad else bytes([i])) * 32, b"s" * 32)
            for i in range(1, n + 1)]


@pytest.mark.parametrize("other, index", [
    (_cps(3), 3),                   # the provider stopped early
    (_cps(7), 5),                   # or posted more checkpoints than there were
    ([], 0),                        # or none
    (_cps(5, bad={2}), 1),          # one checkpoint in the middle, the last one copied
    (_cps(5, bad={2, 4}), 1),
    (_cps(5, bad={5}), 4),
])
def test_bisect_lands_where_the_one_before_agrees(other, index):
    mine = _cps(5)
    d = bisect(mine, other)
    assert d is not None and d.index == index
    assert index == 0 or mine[index - 1].leaf == other[index - 1].leaf
    assert index >= min(len(mine), len(other)) or mine[index].leaf != other[index].leaf


def _rec(i):
    return StepRecord(i, 0, i, "w", f"I{i}", f"c{i}", f"s{i}")


def test_first_fault_names_the_step_only_one_side_ran():
    two, three = [_rec(1), _rec(2)], [_rec(1), _rec(2), _rec(3)]
    f = first_fault(two, three)              # the other run did one step more
    assert (f.step, f.honest, f.other) == (3, "(ended)", "I3")
    f = first_fault(three, two)              # the other run stopped one step early
    assert (f.step, f.honest, f.other) == (3, "I3", "(ended)")
    assert first_fault(two, list(two)) is None


def test_a_trace_must_match_its_posted_root(setup):
    _, _, a = setup
    cps, root = a.log.checkpoints, bytes.fromhex(a.receipt.trace_root)
    assert matches_root(cps, root)
    assert not matches_root(cps[:-1], root)                 # a checkpoint dropped
    assert not matches_root(cps + cps[-1:], root)           # the last one repeated
    assert not matches_root(list(reversed(cps)), root)


def test_merkle_root_commits_to_order():
    x, y = b"a" * 16, b"b" * 16
    assert merkle_root([x, y]) != merkle_root([y, x])
    assert merkle_root([x]) != merkle_root([x, x])
    z = b"c" * 16
    assert merkle_root([x, y, z]) != merkle_root([x, y, z, z])   # a repeated last leaf


def test_merkle_proofs_open_every_leaf_and_nothing_else():
    for n in range(1, 10):
        leaves = [bytes([i]) * 32 for i in range(n)]
        root = merkle_root(leaves)
        for i in range(n):
            path = merkle_proof(leaves, i)
            assert merkle_verify(leaves[i], i, n, path, root)
            assert not merkle_verify(leaves[i], i, n + 1, path, root)       # another count
            assert not merkle_verify(b"x" * 32, i, n, path, root)           # another leaf
            if n > 1:
                assert not merkle_verify(leaves[i], (i + 1) % n, n, path, root)
        assert not merkle_verify(leaves[0], n, n, merkle_proof(leaves, 0), root)


def test_settlement_splits():
    a = accept("j", "A", 1_000_000)
    assert sum(t[1] for t in a.transfers) == 1_000_000
    assert dict((t[0], t[1]) for t in a.transfers)["A"] == 800_000
    s = slash("j", "B", "renter", "verifier", 1_000_000, 10_000_000)
    got = {t[0]: t[1] for t in s.transfers}
    assert got["renter"] == 1_000_000 and got["verifier"] == 5_000_000 and got["B"] == -10_000_000


# ------------------------------------------------------------------ settlement vectors
def test_settlement_takes_only_what_the_program_can_hold():
    for bad in (-1, 2 ** 64):
        with pytest.raises(ValueError):
            accept("j", "A", bad)
        with pytest.raises(ValueError):
            slash("j", "B", "r", "v", 1, bad)
    assert accept("j", "A", 2 ** 64 - 1).transfers[0][1] > 0


def test_settlement_matches_the_shared_vectors():
    """The Solana program's tests read the same file (programs/tdcc_exact)."""
    import json
    from pathlib import Path
    from tdcc_exact.settle import HOST_BPS, VERIFIER_BPS
    v = json.loads((Path(__file__).parent / "data/exact_settle_vectors.json").read_text())
    assert (v["host_bps"], v["verifier_bps"]) == (HOST_BPS, VERIFIER_BPS)
    for c in v["accept"]:
        t = {x[0]: x[1] for x in accept("j", "A", c["price"]).transfers}
        assert (t["A"], t["tdcc"]) == (c["host"], c["tdcc"])
    for c in v["slash"]:
        t = {x[0]: x[1] for x in slash("j", "B", "r", "v", 1, c["stake"]).transfers}
        assert (t["v"], t["tdcc"]) == (c["verifier"], c["tdcc"])


# ------------------------------------------------------------------ the security fixes
def test_digest_is_256_bits():
    from tdcc_exact.trace import DIGEST, h
    assert DIGEST == 32 and len(h(b"x")) == 32


COMMIT_VECTOR = {   # programs/tdcc_exact/tests checks the same hash
    "fingerprint": "11" * 32, "provider": "22" * 32, "salt": "33" * 32,
    "commitment": "00ccd4f49b63c10bc652bb5eab7217fa9a073baa49f8818e68fa47fcb64fa255"}


def test_commitment_vector():
    from tdcc_exact.commit import commitment
    v = COMMIT_VECTOR
    got = commitment(bytes.fromhex(v["fingerprint"]), bytes.fromhex(v["provider"]),
                     bytes.fromhex(v["salt"]))
    assert got.hex() == v["commitment"]


def test_a_copied_receipt_does_not_open_the_copiers_commitment(setup):
    """The copy attack: C copies A's fingerprint. A's commitment binds A's key, and C had to
    commit before A revealed, so C's commitment was made without the fingerprint."""
    from tdcc_exact.commit import check_reveal, commitment, new_salt
    _, _, a = setup
    fp = bytes.fromhex(a.receipt.fingerprint)
    sa = new_salt()
    ca = commitment(fp, "A", sa)
    assert check_reveal(ca, fp, "A", sa)
    assert not check_reveal(ca, fp, "C", sa)            # A's commitment is useless to C
    guess = commitment(bytes(32), "C", sa)               # what C could commit before the reveal
    assert not check_reveal(guess, fp, "C", sa)


def test_a_provider_running_fp4_instead_of_int8_is_caught(setup):
    import dataclasses
    from tdcc_exact import registry
    job, model, a = setup
    assert registry.check(job, a.receipt.model_hash) is None    # the honest int8 run
    cheap = run_job(dataclasses.replace(job, wformat="fp4"), "B", every=EVERY, model=model)
    assert registry.check(job, cheap.receipt.model_hash) is not None
    assert cheap.receipt.fingerprint != a.receipt.fingerprint


def test_a_provider_running_other_weights_is_caught(setup):
    """A smaller or cheaper model in place of the job's: same shape, other weights."""
    from tdcc_exact import registry
    job, _, a = setup
    other = run_job(job, "B", every=EVERY, model=tiny_model(1))
    assert other.receipt.model_hash != a.receipt.model_hash
    assert registry.check(job, other.receipt.model_hash) is not None
    assert other.receipt.fingerprint != a.receipt.fingerprint


def test_a_provider_skipping_prompt_tokens_is_caught(setup):
    """Feeding fewer prompt tokens saves work; even with the job's digest forged into the
    fingerprint, the trace root differs."""
    import dataclasses
    job, model, a = setup
    short = run_job(dataclasses.replace(job, prompt_ids=job.prompt_ids[:-4]), "B",
                    every=EVERY, model=model)
    assert short.receipt.trace_root != a.receipt.trace_root
    assert short.receipt.steps < a.receipt.steps
    assert short.receipt.fingerprint != a.receipt.fingerprint


def test_a_receipt_with_no_run_behind_it_is_challenged(setup, tmp_path):
    """An answer posted without running anything, the rest of A's receipt copied: the
    verifier's re-run (tdcc-exact verify) challenges it, and accepts A's own."""
    import dataclasses
    import os
    from tdcc_exact.cli import main
    job, _, a = setup
    job.save(tmp_path / "job.json")
    a.receipt.save(tmp_path / "a.json")
    forged = dataclasses.replace(a.receipt, provider="B", fingerprint=os.urandom(32).hex(),
                                 extra={})
    forged.save(tmp_path / "b.json")
    verify = ["verify", "--job", str(tmp_path / "job.json"), "--every", str(EVERY)]
    assert main(verify + ["--receipt", str(tmp_path / "a.json")]) == 0
    assert main(verify + ["--receipt", str(tmp_path / "b.json")]) == 1


def test_the_verifier_needs_no_fcntl():
    """Verifiers run on any laptop, Windows included: nothing on tdcc-exact's path may import
    fcntl (only the card and RTL hosts in opentpu/ do)."""
    import subprocess
    import sys
    code = ("import sys; sys.modules['fcntl'] = None\n"
            "from tdcc_exact.cli import main\n"
            "from tdcc_exact.oracle import new_job, run_job, tiny_model\n"
            "run_job(new_job('tiny', 'x', 't'), 'A', model=tiny_model())\n")
    root = Path(__file__).resolve().parents[1]
    r = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]


LFM2 = Path(__file__).resolve().parents[1] / "models" / "LFM2.5-230M"


@pytest.mark.skipif(not LFM2.exists(), reason="models/LFM2.5-230M is not downloaded")
def test_lfm2_job_is_reproducible_and_a_skipped_layer_is_seen():
    """The real model (about a minute): the chat template's job, two honest runs of its first
    8 tokens (one prefill run) post one fingerprint, and skipping a layer inside the hardware
    loop of LFM2's repeated (conv, attention) unit changes it."""
    pytest.importorskip("transformers")
    pytest.importorskip("torch")
    from tdcc_exact.oracle import load_model
    job = new_job(str(LFM2), "Is Paris the capital of France?", "lfm2")
    assert (job.yes_id, job.no_id) == (12948, 5048)
    job.prompt_ids = job.prompt_ids[:8]
    model = load_model(job.model)
    a = run_job(job, "A", model=model)
    b = run_job(job, "A2", model=model)
    assert a.receipt.fingerprint == b.receipt.fingerprint
    cheat = SkipLayer(5, layers_of(model[0]))
    c = run_job(job, "B", cheat, model=model)
    assert c.receipt.extra["skipped_mms"] == 88       # layer 5 (conv): 8 mixer + 80 MLP MMs
    assert c.receipt.fingerprint != a.receipt.fingerprint
