"""TDCC Exact: the trace log, the receipt's fingerprint and the dispute, on the tiny model."""
from pathlib import Path

import pytest

from opentpu import isa as I
from tdcc_exact.backend import SkipLayer
from tdcc_exact.commit import provider_key
from tdcc_exact.dispute import bisect, first_fault, matches_root
from tdcc_exact.oracle import layers_of, new_job, run_job, tiny_model
from tdcc_exact.settle import accept, slash
from tdcc_exact.trace import Checkpoint, StepRecord, merkle_proof, merkle_root, merkle_verify

EVERY = 512
BIND = provider_key("A")      # A's job (the CLI's default binding for provider A)


@pytest.fixture(scope="module")
def setup():
    model = tiny_model()
    job = new_job("tiny", "Will it rain tomorrow?", "t1", every=EVERY)
    return job, model, run_job(job, "A", every=EVERY, model=model, binding=BIND)


def test_honest_runs_post_the_same_fingerprint(setup):
    job, model, a = setup
    b = run_job(job, "A2", every=EVERY, model=model, binding=BIND)
    assert a.receipt.fingerprint == b.receipt.fingerprint
    assert [c.leaf for c in a.log.checkpoints] == [c.leaf for c in b.log.checkpoints]
    assert (a.logits == b.logits).all()
    assert a.receipt.checkpoints > 4


def test_another_question_changes_the_fingerprint(setup):
    job, model, a = setup
    other = run_job(new_job("tiny", "Will it snow tomorrow?", every=EVERY), model=model)
    assert other.receipt.fingerprint != a.receipt.fingerprint


def test_a_skipped_layer_is_caught_at_the_skipped_instruction(setup):
    job, model, a = setup
    cheat = lambda: SkipLayer(1, layers_of(model[0]))     # noqa: E731
    b = run_job(job, "B", cheat(), every=EVERY, model=model, binding=BIND)
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
    honest = run_job(job, "v", every=EVERY, window=w, model=model, binding=BIND).log.records
    other = run_job(job, "B", cheat(), every=EVERY, window=w, model=model,
                    binding=BIND).log.records
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
    assert d.lo == (mine[index - 1].step if index else 0)       # replay from the agreeing one
    assert d.hi > d.lo
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


COMMIT_VECTOR = {   # the program checks the same hash (programs/tdcc_exact/src/lib.rs, tests)
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
    cheap = run_job(dataclasses.replace(job, wformat="fp4"), "B", every=EVERY, model=model,
                    binding=BIND)
    assert registry.check(job, cheap.receipt.model_hash) is not None
    assert cheap.receipt.fingerprint != a.receipt.fingerprint


def test_a_provider_running_other_weights_is_caught(setup):
    """A smaller or cheaper model in place of the job's: same shape, other weights."""
    from tdcc_exact import registry
    job, _, a = setup
    other = run_job(job, "B", every=EVERY, model=tiny_model(1), binding=BIND,
                    check_registry=False)                # (a cheater skips the check)
    assert other.receipt.model_hash != a.receipt.model_hash
    assert registry.check(job, other.receipt.model_hash) is not None
    assert other.receipt.fingerprint != a.receipt.fingerprint


def test_a_provider_skipping_prompt_tokens_is_caught(setup):
    """Feeding fewer prompt tokens saves work; even with the job's digest forged into the
    fingerprint, the trace root differs."""
    import dataclasses
    job, model, a = setup
    short = run_job(dataclasses.replace(job, prompt_ids=job.prompt_ids[:-4]), "B",
                    every=EVERY, model=model, binding=BIND)
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


def test_the_verdict_names_what_differs(setup):
    import dataclasses
    from tdcc_exact.cli import verify
    from tdcc_exact.commit import commitment, new_salt
    job, model, a = setup
    assert verify(job, a.receipt, EVERY)["verdict"] == "ACCEPT"
    b = run_job(job, "B", SkipLayer(1, layers_of(model[0])), every=EVERY, model=model,
                binding=BIND)
    v = verify(job, b.receipt, EVERY)
    assert v["verdict"] == "CHALLENGE" and "trace_root" in v["differs"]
    salt = new_salt()
    lied = dataclasses.replace(a.receipt, extra={
        "commitment": commitment(bytes(32), "A", salt).hex(), "salt": salt.hex()})
    assert verify(job, lied, EVERY)["verdict"] == "REJECT"   # the reveal does not open it


def test_prove_prints_a_path_to_the_posted_root(setup, tmp_path, capsys):
    import json
    from tdcc_exact.cli import main
    from tdcc_exact.oracle import save_trace
    _, _, a = setup
    save_trace(a.log, tmp_path / "a.trace.json")
    assert main(["prove", "--trace", str(tmp_path / "a.trace.json"), "--index", "1"]) == 0
    p = json.loads(capsys.readouterr().out)
    assert p["root"] == a.receipt.trace_root
    assert merkle_verify(bytes.fromhex(p["leaf"]), 1, p["count"],
                         [bytes.fromhex(x) for x in p["path"]], bytes.fromhex(p["root"]))
    assert main(["prove", "--trace", str(tmp_path / "a.trace.json"), "--index", "99"]) == 1


def test_a_new_keypair_file_is_never_readable_by_others(tmp_path, monkeypatch):
    pytest.importorskip("solders")
    import os
    import stat
    from tdcc_exact import chain
    monkeypatch.setenv("TDCC_EXACT_KEYS", str(tmp_path / "keys"))
    old = os.umask(0o022)                    # a default umask: write_text would make it 0644
    try:
        k = chain.keypair("localnet", "renter")
    finally:
        os.umask(old)
    p = tmp_path / "keys" / "localnet" / "renter.json"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert chain.keypair("localnet", "renter").pubkey() == k.pubkey()   # read back the same


def test_only_tiny_and_tiny_seed_name_the_random_model():
    from tdcc_exact.oracle import is_tiny, model_name
    assert is_tiny("tiny") and is_tiny("tiny:3")
    assert not is_tiny("tinyllama-1.1b") and not is_tiny("models/tiny")
    assert model_name("models/tinyllama-1.1b") == "tinyllama-1.1b"
    with pytest.raises(ValueError):
        is_tiny("tiny:abc")


def test_the_cli_names_a_bad_file_instead_of_crashing(tmp_path, capsys):
    from tdcc_exact.cli import main
    (tmp_path / "half.json").write_text('{"model": "tiny"}')
    (tmp_path / "junk.json").write_text("not json")
    (tmp_path / "t.json").write_text('{"x": 1}')
    for argv, says in [
            (["run", "--job", str(tmp_path / "missing.json")], "No such file"),
            (["run", "--job", str(tmp_path / "half.json")], "not a job file"),
            (["run", "--job", str(tmp_path / "junk.json")], "bad JSON"),
            (["prove", "--trace", str(tmp_path / "t.json"), "--index", "0"], "not a trace")]:
        assert main(argv) == 2
        assert says in capsys.readouterr().err


def test_the_rpc_client_does_not_retry_a_refusal():
    pytest.importorskip("solders")
    import http.server
    import threading
    import time
    from tdcc_exact.chain import ChainError, Rpc

    class Refuse(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_error(403)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), Refuse)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t0 = time.monotonic()
        with pytest.raises(ChainError, match="HTTP 403"):
            Rpc(f"http://127.0.0.1:{srv.server_port}").call("getSlot")
        assert time.monotonic() - t0 < 1          # not 1 + 2 + 4 + 8 s of retries
    finally:
        srv.shutdown()


def test_waiting_for_a_slot_gives_up():
    pytest.importorskip("solders")
    from tdcc_exact.chain import ChainError, Rpc

    class Stalled(Rpc):
        def slot(self):
            return 10
    with pytest.raises(ChainError, match="not reached"):
        Stalled("http://unused").wait_slot(20, timeout=0.5)


def test_the_cli_opens_and_runs_a_job(tmp_path, capsys):
    import json
    from tdcc_exact.cli import main
    job, rec = tmp_path / "job.json", tmp_path / "a.json"
    assert main(["job", "new", "--question", "Will it rain tomorrow?", "--id", "j1",
                 "--out", str(job), "--every", str(EVERY)]) == 0
    assert main(["run", "--job", str(job), "--provider", "A", "--out", str(rec),
                 "--trace", str(tmp_path / "a.trace.json"), "--every", str(EVERY)]) == 0
    r = json.loads(rec.read_text())
    assert r["answer"] in ("YES", "NO") and len(r["fingerprint"]) == 64
    assert {"commitment", "salt"} <= set(r["extra"])           # ready for commit-reveal
    assert "commit " in capsys.readouterr().out


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


# ------------------------------------------------------------------ cross-job replay
def test_the_same_question_twice_gets_different_digests(setup):
    job, model, a = setup
    job2 = new_job("tiny", job.question, "t2", every=EVERY)
    assert job2.prompt_ids == job.prompt_ids and job2.nonce != job.nonce
    assert job2.digest != job.digest
    b = run_job(job2, "A", every=EVERY, model=model)
    assert b.receipt.fingerprint != a.receipt.fingerprint


def test_one_job_under_two_bindings_gets_two_fingerprints(setup):
    """The same Job opened on-chain twice (with A and with B): each run is bound to its job
    account, so B cannot post A's revealed fingerprint."""
    job, model, a = setup
    x = run_job(job, "A", every=EVERY, model=model, binding=b"\x01" * 32)
    y = run_job(job, "A", every=EVERY, model=model, binding=b"\x02" * 32)
    assert x.receipt.fingerprint != y.receipt.fingerprint
    assert x.receipt.trace_root != y.receipt.trace_root
    assert x.log.checkpoints[0].leaf != y.log.checkpoints[0].leaf
    assert x.receipt.binding == "01" * 32
    assert (x.logits == y.logits).all() and x.receipt.answer == y.receipt.answer


def test_a_receipt_for_one_binding_does_not_verify_under_another(setup, tmp_path, capsys):
    from tdcc_exact.cli import main
    job, model, _ = setup
    job.save(tmp_path / "job.json")
    x = run_job(job, "A", every=EVERY, model=model, binding=b"\x01" * 32)
    x.receipt.save(tmp_path / "x.json")
    args = ["verify", "--job", str(tmp_path / "job.json"), "--receipt", str(tmp_path / "x.json"),
            "--every", str(EVERY), "--binding"]
    assert main(args + ["01" * 32]) == 0
    assert main(args + ["02" * 32]) == 1
    assert "CHALLENGE" in capsys.readouterr().out
    # without --binding: the provider name's key, not the binding the receipt claims
    assert main(args[:-1]) == 1


def test_a_job_without_a_nonce_is_refused(setup, tmp_path):
    import json
    from tdcc_exact.oracle import Job
    job, model, _ = setup
    d = dict(job.__dict__)
    d.pop("nonce")
    (tmp_path / "old.json").write_text(json.dumps(d))
    old = Job.load(tmp_path / "old.json")
    with pytest.raises(ValueError, match="nonce"):
        run_job(old, every=EVERY, model=model)


# ------------------------------------------------------------------ the output is in the trace
def test_the_trace_commits_to_the_logits_read_back(setup, monkeypatch):
    """A machine that reads back other logits than it computed has another trace root."""
    from opentpu.llm.qwen3 import IsaBackend
    job, model, a = setup
    real = IsaBackend.read

    def lying(self, s, addr, nbytes):
        out = real(self, s, addr, nbytes)
        out[:4] ^= 0x40
        return out
    monkeypatch.setattr(IsaBackend, "read", lying)
    b = run_job(job, "A", every=EVERY, model=model, binding=BIND)
    assert b.log.step == a.log.step
    assert b.receipt.trace_root != a.receipt.trace_root
    d = bisect(a.log.checkpoints, b.log.checkpoints)
    assert d is not None and d.index == len(a.log.checkpoints) - 1     # the last: the read
    monkeypatch.undo()                                              # the verifier is honest
    from tdcc_exact.cli import dispute
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, out=lambda m: None, binding=BIND)
    # (the provider's replay here reads honestly, so its window does not reach the
    # checkpoint it posted: it loses on the window before the output is ruled on)
    assert f is not None and f.what == "window" and f.step == a.log.step


def _forge(job, rec, **kw):
    import dataclasses
    from tdcc_exact.oracle import fingerprint
    f = dataclasses.replace(rec, **kw)
    f.fingerprint = fingerprint(job, f)
    return f


def test_a_receipt_with_an_honest_trace_and_a_forged_answer_loses(setup, tmp_path, capsys):
    """The honest trace root, a flipped answer and made-up logits hash (fingerprint and
    commitment recomputed to match): the traces agree, but the receipt is not the one the
    trace gives, so the dispute rules an output fault."""
    from tdcc_exact.cli import main
    from tdcc_exact.oracle import save_trace
    job, model, a = setup
    flip = "NO" if a.receipt.answer == "YES" else "YES"
    forged = _forge(job, a.receipt, answer=flip, logits_hash="ab" * 32)
    job.save(tmp_path / "job.json")
    save_trace(a.log, tmp_path / "a.trace.json")
    forged.save(tmp_path / "forged.json")
    a.receipt.save(tmp_path / "honest.json")
    args = ["dispute", "--job", str(tmp_path / "job.json"), "--trace",
            str(tmp_path / "a.trace.json"), "--receipt"]
    assert main(args + [str(tmp_path / "forged.json")]) == 1
    out = capsys.readouterr().out
    assert "the receipt does not" in out and "answer" in out and "logits_hash" in out
    assert main(args + [str(tmp_path / "honest.json")]) == 0
    assert "nothing to dispute" in capsys.readouterr().out


def test_a_receipt_whose_root_is_not_its_trace_loses(setup):
    from tdcc_exact.cli import dispute
    job, model, a = setup
    forged = _forge(job, a.receipt, trace_root="cd" * 32)
    _, d, f = dispute(job, a.log.checkpoints, model, EVERY, out=lambda m: None,
                      receipt=forged, binding=BIND)
    assert d is None and f is not None and f.what == "output" and "trace root" in f.other


# ------------------------------------------------------------------ DRAM stores in the trace
class SkipStore:
    """A provider that leaves out one store (slice 0's n-th ST; None: count them): the
    stale DRAM it leaves is only in what the slice stored, not in TMEM or the registers."""
    ops = frozenset({I.ST})
    skipped = 0

    def __init__(self, n=None):
        self.n, self.count = n, 0

    def start(self):
        pass

    def end(self):
        pass

    def skip(self, s, ins):
        if s.sid:
            return False
        self.count += 1
        if self.count == self.n:
            self.skipped += 1
            return True
        return False


def test_a_skipped_final_store_is_named_by_the_dispute(setup):
    from tdcc_exact.cli import dispute
    job, model, a = setup
    count = SkipStore()
    run_job(job, "B", count, every=EVERY, model=model, binding=BIND)
    last = count.count
    b = run_job(job, "B", SkipStore(last), every=EVERY, model=model, binding=BIND)
    assert b.receipt.extra["skipped_mms"] == 1
    assert b.receipt.trace_root != a.receipt.trace_root
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, SkipStore(last),
                      out=lambda m: None, binding=BIND)
    assert d is not None and d.lo < d.hi            # a step, not only the reads after them
    assert f is not None and f.what == "state" and f.slice == 0
    assert f.honest.startswith(I.OPNAMES[I.ST])


# ------------------------------------------------------------------ revealed windows
def _window(job, model, k, cheat=None):
    return run_job(job, "A", cheat, every=EVERY, model=model, binding=BIND, reveal=k).log.events


def _flip(v: str) -> str:
    return v[:-2] + ("00" if v[-2:] != "00" else "01")


def test_an_honest_revealed_window_verifies(setup):
    import dataclasses
    from tdcc_exact.dispute import verify_window
    from tdcc_exact.trace import Event, chain_start, record_from_json, record_to_json
    job, model, a = setup
    cps = a.log.checkpoints
    for k in (0, 2, len(cps) - 1):                  # the first, one inside, the last (reads)
        ev = _window(job, model, k)
        start = cps[k - 1] if k else chain_start(BIND)
        assert verify_window(ev, start, cps[k]) is None, k
        assert verify_window([record_from_json(record_to_json(r)) for r in ev],
                             start, cps[k]) is None
    kinds = {r.kind for r in ev if isinstance(r, Event)}
    assert {"O", "C"} <= kinds                      # the last window: the reads and the fold
    # one changed byte fails: a step's registers, the closing fold's slice state
    ev = _window(job, model, 2)
    steps = [i for i, r in enumerate(ev) if isinstance(r, StepRecord)]
    bad = list(ev)
    i = steps[len(steps) // 2]
    bad[i] = dataclasses.replace(bad[i], regs=_flip(bad[i].regs))
    assert verify_window(bad, cps[1], cps[2]) is not None
    bad = list(ev)
    bad[-1] = dataclasses.replace(bad[-1], data=[_flip(bad[-1].data[0])] + bad[-1].data[1:])
    assert verify_window(bad, cps[1], cps[2]) is not None
    bad = list(ev)
    i = steps[-1]
    bad[i] = dataclasses.replace(bad[i], state="00" * 32)   # (not in the chain: the fold is)
    assert "state" in verify_window(bad, cps[1], cps[2])


def test_a_truncated_or_padded_window_fails(setup):
    from tdcc_exact.dispute import verify_window
    job, model, a = setup
    cps = a.log.checkpoints
    ev = _window(job, model, 2)
    assert "truncated" in verify_window(ev[:-1], cps[1], cps[2])
    assert verify_window(ev[:len(ev) // 2], cps[1], cps[2]) is not None
    assert verify_window(ev[1:], cps[1], cps[2]) is not None
    assert verify_window(ev + ev[-1:], cps[1], cps[2]) is not None
    assert verify_window(ev, cps[0], cps[2]) is not None           # another start


def test_an_honest_window_does_not_cover_cheating_checkpoints(setup):
    """A provider that posted a cheating trace cannot reveal the honest window for it."""
    from tdcc_exact.dispute import verify_window
    from tdcc_exact.trace import chain_start
    job, model, a = setup
    L = layers_of(model[0])
    b = run_job(job, "B", SkipLayer(1, L), every=EVERY, model=model, binding=BIND)
    k = bisect(a.log.checkpoints, b.log.checkpoints).index
    start = b.log.checkpoints[k - 1] if k else chain_start(BIND)
    end = b.log.checkpoints[k]
    assert verify_window(_window(job, model, k), start, end) is not None
    assert verify_window(_window(job, model, k, SkipLayer(1, L)), start, end) is None


def test_a_provider_whose_window_does_not_chain_loses_the_dispute(setup):
    """The provider replays its window with another shortcut than the one it posted."""
    from tdcc_exact.cli import dispute
    job, model, a = setup
    L = layers_of(model[0])
    b = run_job(job, "B", SkipLayer(1, L), every=EVERY, model=model, binding=BIND)
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, SkipLayer(0, L),
                      out=print, binding=BIND)
    assert d is not None and f is not None and f.what == "window"
    _, d, f = dispute(job, b.log.checkpoints, model, EVERY, SkipLayer(1, L),
                      out=print, binding=BIND)
    assert f is not None and f.what == "state"


# ------------------------------------------------------------------ the checkpoint interval
def test_the_checkpoint_interval_is_part_of_the_job(setup, tmp_path, capsys):
    """A provider at another interval than the verifier's would never match: the interval is
    in the job (and its digest), and a run or a trace at another one is refused."""
    import dataclasses
    import json
    from tdcc_exact.cli import main
    from tdcc_exact.oracle import save_trace
    job, model, a = setup
    assert job.every == EVERY
    assert dataclasses.replace(job, every=1024).digest != job.digest
    with pytest.raises(ValueError, match="every"):
        run_job(job, "A", every=4096, model=model, binding=BIND)
    job.save(tmp_path / "job.json")
    a.receipt.save(tmp_path / "a.json")
    base = ["--job", str(tmp_path / "job.json")]
    assert main(["verify", *base, "--receipt", str(tmp_path / "a.json")]) == 0   # job's own
    assert main(["verify", *base, "--receipt", str(tmp_path / "a.json"),
                 "--every", "4096"]) == 2
    save_trace(a.log, tmp_path / "a.trace.json")
    t = json.loads((tmp_path / "a.trace.json").read_text())
    t["every"] = 4096
    (tmp_path / "a.trace.json").write_text(json.dumps(t))
    assert main(["dispute", *base, "--trace", str(tmp_path / "a.trace.json")]) == 1
    assert "every" in capsys.readouterr().out


# ------------------------------------------------------------------ the build is the registered one
def test_a_build_the_environment_changed_is_refused(setup, monkeypatch):
    """OTPU_FORMATS makes another image than the job's int8 one: run_job refuses before
    running, for providers and verifiers alike."""
    job, model, _ = setup
    with pytest.raises(ValueError, match="registered"):
        run_job(job, "A", model=tiny_model(1), binding=BIND)      # other weights
    monkeypatch.setenv("OTPU_FORMATS", "mlp=fp4")
    with pytest.raises(ValueError, match="OTPU_FORMATS"):
        run_job(job, "A", model=model, binding=BIND)
