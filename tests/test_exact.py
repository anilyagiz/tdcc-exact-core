"""TDCC Exact: the trace log, the receipt's fingerprint and the dispute, on the tiny model."""
from pathlib import Path

import pytest

from opentpu import isa as I
from tdcc_exact.backend import SkipLayer
from tdcc_exact.dispute import bisect, first_fault
from tdcc_exact.oracle import layers_of, new_job, run_job, tiny_model
from tdcc_exact.settle import accept, slash
from tdcc_exact.trace import merkle_root

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


def test_bisect_agrees_on_equal_traces(setup):
    _, _, a = setup
    assert bisect(a.log.checkpoints, list(a.log.checkpoints)) is None


def test_merkle_root_commits_to_order():
    x, y = b"a" * 16, b"b" * 16
    assert merkle_root([x, y]) != merkle_root([y, x])
    assert merkle_root([x]) != merkle_root([x, x])


def test_settlement_splits():
    a = accept("j", "A", 1_000_000)
    assert sum(t[1] for t in a.transfers) == 1_000_000
    assert dict((t[0], t[1]) for t in a.transfers)["A"] == 800_000
    s = slash("j", "B", "renter", "verifier", 1_000_000, 10_000_000)
    got = {t[0]: t[1] for t in s.transfers}
    assert got["renter"] == 1_000_000 and got["verifier"] == 5_000_000 and got["B"] == -10_000_000


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
