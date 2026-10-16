"""Generate jobs on TDCC Exact: greedy decoding on the tiny model, verified and disputed."""
import json

import numpy as np
import pytest

from tdcc_exact.backend import SkipLayer
from tdcc_exact.commit import provider_key
from tdcc_exact.oracle import (Job, StopEarly, WrongToken, answer_bytes, answer_ids,
                               fingerprint, gen_answer, greedy, layers_of, new_job, run_job,
                               tiny_model)
from tdcc_exact.verifier import dispute, verify

EVERY = 512
BIND = provider_key("A")
N = 6


@pytest.fixture(scope="module", autouse=True)
def _no_user_registry(tmp_path_factory):
    import os
    from tdcc_exact import registry
    old = os.environ.get(registry.ENV)
    os.environ[registry.ENV] = str(tmp_path_factory.mktemp("reg") / "none.json")
    yield
    if old is None:
        os.environ.pop(registry.ENV, None)
    else:
        os.environ[registry.ENV] = old


@pytest.fixture(scope="module")
def gen():
    model = tiny_model()
    job = new_job("tiny", "Write a short poem", "g1", every=EVERY, kind="generate",
                  max_tokens=N)
    return job, model, run_job(job, "A", every=EVERY, model=model, binding=BIND)


def _quiet(_):
    pass


def test_greedy_generation_is_deterministic(gen):
    job, model, a = gen
    assert len(a.tokens) == N and a.receipt.answer == gen_answer(a.tokens)
    b = run_job(job, "A2", every=EVERY, model=model, binding=BIND)
    assert b.tokens == a.tokens
    assert b.receipt.fingerprint == a.receipt.fingerprint
    assert [c.leaf for c in b.log.checkpoints] == [c.leaf for c in a.log.checkpoints]
    assert fingerprint(job, a.receipt) == a.receipt.fingerprint
    # each decode is a device run in the trace, after the prompt's
    assert a.token_cps == sorted(a.token_cps) and a.token_cps[0] > 0
    assert len(set(a.token_cps)) == N


def test_the_tokens_are_the_engines_greedy_decode(gen):
    """The same tokens as Engine.generate's argmax (no trace), so the trace changes nothing."""
    from opentpu.llm.qwen3 import Engine
    job, model, a = gen
    spec, W = model
    eng = Engine(spec, W, cap=job.cap, wformat=job.wformat, rows=job.chunk, pipeline=False)
    logits = eng.prefill(job.prompt_ids, chunk=job.chunk)
    out = []
    for _ in range(N):
        out.append(greedy(logits, spec.vocab))
        if len(out) < N:
            logits = eng.step(out[-1])
    assert out == a.tokens


def test_greedy_breaks_ties_to_the_lowest_id():
    assert greedy(np.array([0, 2, 5, 5, 1], np.float32)) == 2
    assert greedy(np.array([7, 7], np.float32)) == 0
    assert greedy(np.array([0, 1, 9], np.float32), vocab=2) == 1


def test_a_stop_id_ends_the_answer(gen):
    job, model, a = gen
    stop = Job(**{**job.__dict__, "stop_ids": [a.tokens[2]]})
    r = run_job(stop, every=EVERY, model=model, binding=BIND)
    assert r.tokens == a.tokens[:3]
    assert r.receipt.checkpoints < a.receipt.checkpoints


def test_the_answer_encoding():
    assert answer_bytes("GEN:1,256") == b"GEN" + b"\x01\0\0\0" + b"\0\x01\0\0"
    assert answer_bytes("YES") == b"YES" and answer_bytes("NO") == b"NO"
    assert answer_ids("GEN:3,4") == [3, 4]
    for bad in ("GEN:03,4", "GEN:3, 4", "GEN:-1", "GEN:x", "YES"):
        assert answer_ids(bad) is None
    assert answer_bytes("GEN:03,4") != answer_bytes("GEN:3,4")


def test_generate_fields_are_in_the_digest(gen):
    job, _, _ = gen
    for k, v in (("max_tokens", N + 1), ("stop_ids", [7])):
        assert Job(**{**job.__dict__, k: v}).digest != job.digest


def test_a_yesno_job_keeps_its_digest():
    """The digest a yes/no job had before generate jobs existed (bdf3288), and an old file
    without the new fields loads as a yes/no job."""
    j = Job("tiny", [5, 6, 7], 3, 4, question="q", nonce="ab" * 32, every=512, job_id="x")
    assert j.digest.hex() == "e45b5e74fc6373d7522e8302ba7f682217920a6b1f4864541fe1515da91fd755"
    old = {k: v for k, v in j.__dict__.items() if k not in ("kind", "max_tokens", "stop_ids")}
    j2 = Job(**json.loads(json.dumps(old)))
    assert j2.kind == "yesno" and j2.digest == j.digest


@pytest.mark.parametrize("change", [dict(max_tokens=0), dict(max_tokens=300),
                                    dict(stop_ids=[9999]), dict(kind="sample")])
def test_a_generate_job_no_run_can_do_is_refused(gen, change):
    job, model, _ = gen
    with pytest.raises(ValueError):
        bad = Job(**{**job.__dict__, **change})
        run_job(bad, model=model)


def test_a_yesno_job_with_generate_fields_is_refused():
    j = new_job("tiny", "q?")
    with pytest.raises(ValueError, match="generate"):
        Job(**{**j.__dict__, "max_tokens": 4}).check()


def test_the_verifier_accepts_an_honest_generation(gen, tmp_path):
    job, _, a = gen
    v = verify(job, a.receipt, binding=BIND)
    assert v["verdict"] == "ACCEPT", v


def test_a_skipped_layer_is_caught(gen):
    job, model, a = gen
    L = layers_of(model[0])
    b = run_job(job, "B", SkipLayer(1, L), every=EVERY, model=model, binding=BIND)
    assert b.receipt.fingerprint != a.receipt.fingerprint
    assert verify(job, b.receipt, binding=BIND)["verdict"] == "CHALLENGE"
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, SkipLayer(1, L), out=_quiet,
                      binding=BIND)
    assert d.index < a.token_cps[0]            # in the prompt: an instruction fault
    assert f is not None and f.what == "state" and "mm" in f.honest


def test_an_early_stop_is_caught_and_names_the_step(gen):
    job, model, a = gen
    k = 3
    b = run_job(job, "B", StopEarly(k), every=EVERY, model=model, binding=BIND)
    assert b.tokens == a.tokens[:k]
    v = verify(job, b.receipt, binding=BIND)
    assert v["verdict"] == "CHALLENGE"
    assert v["first_token"] == {"step": k, "re_run": a.tokens[k], "posted": None}
    lines = []
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, StopEarly(k), out=lines.append,
                      binding=BIND, receipt=b.receipt)
    assert d.index == a.token_cps[k]
    assert f.what == "stop" and f"generation step {k}" in f.other
    assert any(f"generation step {k}" in m for m in lines)


def test_a_wrong_token_is_caught_and_names_the_step(gen):
    job, model, a = gen
    k = 2
    b = run_job(job, "B", WrongToken(k), every=EVERY, model=model, binding=BIND)
    assert b.tokens[:k] == a.tokens[:k] and b.tokens[k] == a.tokens[k] + 1
    v = verify(job, b.receipt, binding=BIND)
    assert v["verdict"] == "CHALLENGE" and v["first_token"]["step"] == k
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, WrongToken(k), out=_quiet,
                      binding=BIND)
    assert d.index == a.token_cps[k]
    assert f.what == "token" and f"token {a.tokens[k] + 1}" in f.other


def test_a_forged_answer_on_an_honest_trace_loses(gen):
    job, model, a = gen
    from dataclasses import replace
    forged = replace(a.receipt, answer=gen_answer(a.tokens[:-1] + [a.tokens[-1] + 1]))
    forged.fingerprint = fingerprint(job, forged)
    assert verify(job, forged, binding=BIND)["verdict"] == "CHALLENGE"
    _, d, f = dispute(job, a.log.checkpoints, model, EVERY, out=_quiet, binding=BIND,
                      receipt=forged)
    assert d is None and f.what == "output"


def test_gen_cheats_are_for_generate_jobs():
    job = new_job("tiny", "q?")
    with pytest.raises(ValueError, match="generate"):
        run_job(job, cheat=StopEarly(1), model=tiny_model())
