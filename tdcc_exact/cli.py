"""tdcc-exact: open, run, verify and dispute oracle jobs on Exact Core.

    tdcc-exact job new --model tiny --question "Did it rain?" --out job.json
    tdcc-exact run --job job.json --provider A --out a.json --trace a.trace.json
    tdcc-exact verify --job job.json --receipt a.json
    tdcc-exact dispute --job job.json --trace b.trace.json [--receipt b.json]
                       [--replay-skip-layer K]
    tdcc-exact prove --trace b.trace.json --index 1
    tdcc-exact demo [--model models/LFM2.5-230M] [--devnet | --localnet]
    tdcc-exact registry add --model tiny [--wformat int8 --cap 256]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import registry
from .backend import SkipLayer
from .commit import check_reveal, commitment, new_salt
from .dispute import bisect, first_fault, matches_root
from .oracle import (TINY, Job, Receipt, build_hash, layers_of, load_model, load_trace,
                     model_name, new_job, run_job, save_trace)
from .settle import accept, slash
from .trace import EVERY, Checkpoint, merkle_proof, merkle_root, merkle_verify


def _cheat(layer, model) -> SkipLayer | None:
    return None if layer is None else SkipLayer(layer, layers_of(model[0]))


def _checkpoints(trace: dict) -> list[Checkpoint]:
    return [Checkpoint.from_json(c) for c in trace["checkpoints"]]


def cmd_job(a) -> int:
    job = new_job(a.model, a.question, a.id)
    job.save(a.out)
    print(f"job {a.id or '-'}: {len(job.prompt_ids)} prompt tokens, yes={job.yes_id} "
          f"no={job.no_id} -> {a.out}")
    return 0


def cmd_run(a) -> int:
    job = Job.load(a.job)
    model = load_model(job.model)
    r = run_job(job, a.provider, _cheat(a.skip_layer, model), a.every, model=model)
    salt = new_salt()
    c = commitment(bytes.fromhex(r.receipt.fingerprint), a.provider, salt)
    r.receipt.extra.update(salt=salt.hex(), commitment=c.hex())   # salt: secret until reveal
    r.receipt.save(a.out)
    if a.trace:
        save_trace(r.log, a.trace)
    print(f"{a.provider}: {r.receipt.answer}  fingerprint {r.receipt.fingerprint}  "
          f"({r.receipt.steps} steps, {r.receipt.checkpoints} checkpoints)")
    print(f"  commit {c.hex()}  (post this first; reveal fingerprint + salt after the window)")
    return 0


def verify(job: Job, rec: Receipt, every: int = EVERY, trace=None) -> dict:
    """A verifier's verdict on a receipt: ACCEPT, CHALLENGE (with the fields that differ) or
    REJECT (the reveal does not open the commitment, or the model build is not the job's)."""
    v = {"provider": rec.provider, "job_id": rec.job_id, "posted": rec.fingerprint}
    if "commitment" in rec.extra and not check_reveal(
            bytes.fromhex(rec.extra["commitment"]), bytes.fromhex(rec.fingerprint),
            rec.provider, bytes.fromhex(rec.extra.get("salt", "00" * 32))):
        return v | {"verdict": "REJECT", "why": "the reveal does not open its commitment"}
    why = registry.check(job, rec.model_hash)
    if why is not None and "not registered" not in why:
        return v | {"verdict": "REJECT", "why": why}
    r = run_job(job, "verifier", every=every)
    if trace:
        save_trace(r.log, trace)
    mine = r.receipt
    diff = {k: {"posted": getattr(rec, k), "re_run": getattr(mine, k)}
            for k in ("answer", "model_hash", "logits_hash", "trace_root", "steps")
            if getattr(mine, k) != getattr(rec, k)}
    ok = mine.fingerprint == rec.fingerprint
    return v | {"verdict": "ACCEPT" if ok else "CHALLENGE", "re_run": mine.fingerprint,
                "differs": diff, "warning": why}


def cmd_verify(a) -> int:
    v = verify(Job.load(a.job), Receipt.load(a.receipt), a.every, a.trace)
    if a.json:
        print(json.dumps(v, indent=1))
    elif v["verdict"] == "REJECT":
        print(f"{v['provider']}: REJECT  ({v['why']})")
    else:
        if v["warning"]:
            print(f"warning: {v['warning']}; the re-run decides alone")
        print(f"{v['provider']}: {v['verdict']}  (posted {v['posted']}, re-run {v['re_run']})")
        for k, d in v["differs"].items():
            print(f"  {k}: posted {d['posted']}, re-run {d['re_run']}")
    return 0 if v["verdict"] == "ACCEPT" else 1


def dispute(job: Job, provider_cps: list[Checkpoint], model, every: int,
            replay_cheat=None, out=print):
    """Bisect the provider's checkpoints against the verifier's own run, then replay the
    window on both sides. (verifier run, divergence, fault)."""
    mine = run_job(job, "verifier", every=every, model=model)
    d = bisect(mine.log.checkpoints, provider_cps)
    if d is None:
        out("traces agree: nothing to dispute")
        return mine, None, None
    out(f"bisection: checkpoint {d.index} of {len(mine.log.checkpoints)} differs "
        f"({d.rounds} rounds), steps {d.lo + 1}..{d.hi}")
    honest = run_job(job, "verifier", every=every, window=(d.lo, d.hi), model=model).log.records
    other = run_job(job, "provider", replay_cheat, every, window=(d.lo, d.hi),
                    model=model).log.records
    f = first_fault(honest, other)
    if f is not None:
        out(f"first fault: step {f.step}, slice {f.slice}, pc {f.pc} ({f.what})")
        out(f"  {f.honest}")
    return mine, d, f


def cmd_dispute(a) -> int:
    job = Job.load(a.job)
    model = load_model(job.model)
    trace = load_trace(a.trace)
    cps = _checkpoints(trace)
    if a.receipt:
        rec = Receipt.load(a.receipt)
        if not matches_root(cps, bytes.fromhex(rec.trace_root)):
            print(f"{rec.provider}: the trace does not match the posted trace root "
                  f"{rec.trace_root}: the provider loses the dispute")
            return 1
    _, d, _ = dispute(job, cps, model, trace.get("every", EVERY),
                      _cheat(a.replay_skip_layer, model))
    return 0 if d is None else 1


def cmd_prove(a) -> int:
    """One checkpoint of a trace with its Merkle path to the trace root: what a bisection
    round shows instead of the whole list."""
    cps = _checkpoints(load_trace(a.trace))
    leaves = [c.leaf for c in cps]
    if not 0 <= a.index < len(cps):
        print(f"the trace has {len(cps)} checkpoints; no index {a.index}", file=sys.stderr)
        return 1
    root, path = merkle_root(leaves), merkle_proof(leaves, a.index)
    assert merkle_verify(leaves[a.index], a.index, len(leaves), path, root)
    print(json.dumps({"index": a.index, "count": len(cps), "root": root.hex(),
                      "checkpoint": cps[a.index].to_json(), "leaf": leaves[a.index].hex(),
                      "path": [x.hex() for x in path]}, indent=1))
    return 0


def cmd_demo(a) -> int:
    if a.devnet or a.localnet:
        from .chain_demo import run
        return run(a)
    t0 = time.time()

    def say(*x):
        print(f"[{time.time() - t0:6.1f}s]", *x)
    question = a.question
    model_id = a.model
    say(f"1. renter opens a yes/no oracle job on {model_id}, locks {a.price / 1e6:.2f} USDC")
    job = new_job(model_id, question, "demo-1")
    say(f"   Q: {question!r} ({len(job.prompt_ids)} tokens)")
    model = load_model(model_id)
    L = layers_of(model[0])
    layer = a.skip_layer if a.skip_layer is not None else L // 2
    say("2. provider A runs it honestly; provider B skips layer", layer, "to save time")
    ra = run_job(job, "A", every=a.every, model=model)
    say(f"   A: {ra.receipt.answer}  {ra.receipt.fingerprint}")
    rb = run_job(job, "B", SkipLayer(layer, L), every=a.every, model=model)
    say(f"   B: {rb.receipt.answer}  {rb.receipt.fingerprint}  "
        f"({rb.receipt.extra['skipped_mms']} matrix multiplies skipped)")
    say("3. a verifier re-runs the job on this laptop")
    rv = run_job(job, "verifier", every=a.every, model=model)
    for r in (ra, rb):
        ok = r.receipt.fingerprint == rv.receipt.fingerprint
        say(f"   {r.receipt.provider}: {'match -> accept' if ok else 'MISMATCH -> challenge'}")
    say("4. searching B's trace for the first instruction that went wrong")
    _, d, f = dispute(job, rb.log.checkpoints, model, a.every, SkipLayer(layer, L),
                      out=lambda m: say("  ", m))
    say("5. settlement (the Solana program executes these transfers)")
    s = {"A": accept(job.job_id, "A", a.price).to_json(),
         "B": slash(job.job_id, "B", "renter", "verifier", a.price, a.stake).to_json()}
    for k, v in s.items():
        for to, amt, why in v["transfers"]:
            say(f"   {k} {v['outcome']}: {to:9s} {amt / 1e6:+9.2f} USDC  {why}")
    if a.out:
        run = {"job": job.__dict__, "receipts": [ra.receipt.__dict__, rb.receipt.__dict__],
               "divergence": d.__dict__ if d else None, "fault": f.__dict__ if f else None,
               "settlement": s}
        with open(a.out, "w") as out:
            json.dump(run, out, indent=1)
        say("   written to", a.out)
    return 0 if f is not None and ra.receipt.fingerprint == rv.receipt.fingerprint else 1


def cmd_registry(a) -> int:
    name = model_name(a.model)
    hh = build_hash(a.model, a.wformat, a.cap)
    registry.add(name, a.wformat, a.cap, hh, a.source or a.model)
    print(f"{registry.key(name, a.wformat, a.cap)} -> {hh}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tdcc-exact", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    j = sub.add_parser("job", help="open an oracle job")
    j.add_argument("action", choices=["new"])
    j.add_argument("--model", default=TINY)
    j.add_argument("--question", required=True)
    j.add_argument("--id", default="")
    j.add_argument("--out", default="job.json")
    j.set_defaults(fn=cmd_job)

    r = sub.add_parser("run", help="run a job as a provider and post a receipt")
    r.add_argument("--job", required=True)
    r.add_argument("--provider", default="A")
    r.add_argument("--out", default="receipt.json")
    r.add_argument("--trace", help="also write the trace's checkpoints here")
    r.add_argument("--skip-layer", type=int, help="cheat: skip this layer's matrix multiplies")
    r.add_argument("--every", type=int, default=EVERY)
    r.set_defaults(fn=cmd_run)

    v = sub.add_parser("verify", help="re-run a job and check a receipt")
    v.add_argument("--job", required=True)
    v.add_argument("--receipt", required=True)
    v.add_argument("--trace", help="also write the verifier's trace here")
    v.add_argument("--every", type=int, default=EVERY)
    v.add_argument("--json", action="store_true", help="print the verdict as JSON")
    v.set_defaults(fn=cmd_verify)

    g = sub.add_parser("registry", help="pin a model build's image hash (tdcc_exact/models.json)")
    g.add_argument("action", choices=["add"])
    g.add_argument("--model", required=True)
    g.add_argument("--wformat", default="int8")
    g.add_argument("--cap", type=int, default=256)
    g.add_argument("--source", default="", help="where the checkpoint came from (revision)")
    g.set_defaults(fn=cmd_registry)

    d = sub.add_parser("dispute", help="find the first instruction a provider's trace got wrong")
    d.add_argument("--job", required=True)
    d.add_argument("--trace", required=True, help="the provider's trace")
    d.add_argument("--receipt", help="the provider's receipt: its trace root must match")
    d.add_argument("--replay-skip-layer", type=int,
                   help="replay the provider's window with this shortcut (local demo)")
    d.set_defaults(fn=cmd_dispute)

    pr = sub.add_parser("prove", help="one checkpoint of a trace and its Merkle path")
    pr.add_argument("--trace", required=True)
    pr.add_argument("--index", type=int, required=True)
    pr.set_defaults(fn=cmd_prove)

    m = sub.add_parser("demo", help="the whole flow: job, runs, verify, dispute, settle")
    m.add_argument("--model", default=TINY, help="tiny, or a checkpoint (models/LFM2.5-230M)")
    m.add_argument("--question", default="Did the Federal Reserve cut rates in September 2026?")
    m.add_argument("--skip-layer", type=int)
    m.add_argument("--price", type=int, default=2_000_000, help="USDC base units")
    m.add_argument("--stake", type=int, default=50_000_000, help="USDC base units")
    m.add_argument("--every", type=int, default=EVERY)
    m.add_argument("--out", help="write the run's JSON here")
    m.add_argument("--devnet", action="store_true",
                   help="every step a Solana devnet transaction (pip install -e '.[chain]')")
    m.add_argument("--localnet", action="store_true", help="the same on solana-test-validator")
    m.add_argument("--rpc", help="RPC URL (default: the cluster's public one)")
    m.add_argument("--commit-window", type=int, default=100,
                   help="slots, for a market this run creates (the providers' run time)")
    m.add_argument("--challenge-window", type=int, default=60,
                   help="slots, for a market this run creates (the verifier's run time)")
    m.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError) as e:     # a missing or malformed file, a bad argument
        print(f"tdcc-exact: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
