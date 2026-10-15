"""The verifier's side as a library: a verdict on a receipt (verify) and a dispute against a
provider's posted checkpoints (dispute). The CLI (tdcc_exact.cli), the on-chain demo and
nodes call these; tdcc_exact.cli re-exports both for older imports.
"""
from __future__ import annotations

from . import registry
from .commit import check_reveal, provider_key
from .dispute import Fault, bisect, first_fault, output_fault, verify_window
from .oracle import Job, Receipt, as_binding, job_every, run_job, save_trace
from .trace import Checkpoint, chain_start


def verify(job: Job, rec: Receipt, every: int | None = None, trace=None,
           binding=None, salt: bytes | None = None, strict: bool = False) -> dict:
    """A verifier's verdict on a receipt: ACCEPT, CHALLENGE (with the fields that differ) or
    REJECT (the reveal does not open the commitment, or the model build is not the job's).
    binding: the on-chain job account's address (never the receipt's own claim); None: the
    receipt's provider name's key (local runs). salt: the revealed salt (else a revealed
    receipt's extra["salt"]); with neither, the commitment is not checked (a warning).
    strict: an unregistered model is REJECT, not a warning (what nodes run)."""
    v = {"provider": rec.provider, "job_id": rec.job_id, "posted": rec.fingerprint}
    notes = []
    if "commitment" in rec.extra:
        s = salt if salt is not None else (
            bytes.fromhex(rec.extra["salt"]) if "salt" in rec.extra else None)
        if s is None:
            notes.append("the commitment is not opened (no salt revealed: --salt)")
        elif not check_reveal(bytes.fromhex(rec.extra["commitment"]),
                              bytes.fromhex(rec.fingerprint), rec.provider, s):
            return v | {"verdict": "REJECT", "why": "the reveal does not open its commitment"}
    why = registry.check(job, rec.model_hash)
    if why is not None and ("not registered" not in why or strict):
        return v | {"verdict": "REJECT", "why": why}
    bind = provider_key(rec.provider) if binding is None else binding
    r = run_job(job, "verifier", every=every, binding=bind)
    if trace:
        save_trace(r.log, trace)
    mine = r.receipt
    diff = {k: {"posted": getattr(rec, k), "re_run": getattr(mine, k)}
            for k in ("answer", "model_hash", "logits_hash", "trace_root", "steps")
            if getattr(mine, k) != getattr(rec, k)}
    ok = mine.fingerprint == rec.fingerprint
    if why is not None:
        notes.append(f"{why}; the re-run decides alone")
    return v | {"verdict": "ACCEPT" if ok else "CHALLENGE", "re_run": mine.fingerprint,
                "differs": diff, "warning": "; ".join(notes) or None}


def dispute(job: Job, provider_cps: list[Checkpoint], model, every: int | None = None,
            replay_cheat=None, out=print, binding=None, receipt: Receipt | None = None):
    """Bisect the provider's checkpoints against the verifier's own run, then replay the
    window on both sides (binding: the disputed on-chain job's). If the traces agree and the
    provider's receipt is given, check the receipt is the one its trace gives (an "output"
    fault, with no divergence). (verifier run, divergence, fault)."""
    every = job_every(job, every)
    mine = run_job(job, "verifier", every=every, model=model, binding=binding)
    d = bisect(mine.log.checkpoints, provider_cps)
    if d is None:
        f = None if receipt is None else output_fault(job, receipt, mine.receipt, provider_cps)
        if f is None:
            out("traces agree: nothing to dispute")
        else:
            out(f"traces agree, the receipt does not: {f.other}")
        return mine, None, f
    out(f"bisection: checkpoint {d.index} of {len(mine.log.checkpoints)} differs "
        f"({d.rounds} rounds), steps {d.lo + 1}..{d.hi}")
    w = (d.lo, d.hi)
    prov = run_job(job, "provider", replay_cheat, every, window=w, model=model,
                   binding=binding, reveal=d.index).log
    if d.index < len(provider_cps):     # the provider's revealed window must chain to its posts
        start = (provider_cps[d.index - 1] if d.index
                 else chain_start(as_binding(binding)))
        why = verify_window(prov.events, start, provider_cps[d.index])
        if why is not None:
            f = Fault(d.lo, -1, -1, "a window that chains to the posted checkpoints", why,
                      "window")
            out(f"the provider's revealed window does not chain to its checkpoints: {why}")
            return mine, d, f
    if d.hi == d.lo:                    # no step between: the host's reads after the last run
        f = Fault(d.lo, -1, -1, "the logits the host read back", "other logits", "output")
        out(f"first fault: the output read back after step {d.lo} ({f.what})")
        return mine, d, f
    honest = run_job(job, "verifier", every=every, window=w, model=model,
                     binding=binding).log.records
    f = first_fault(honest, prov.records)
    if f is not None:
        out(f"first fault: step {f.step}, slice {f.slice}, pc {f.pc} ({f.what})")
        out(f"  {f.honest}")
    return mine, d, f
