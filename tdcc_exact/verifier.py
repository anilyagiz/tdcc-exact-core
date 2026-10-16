"""The verifier's side as a library: a verdict on a receipt (verify) and a dispute against a
provider's posted checkpoints (dispute). The CLI (tdcc_exact.cli), the on-chain demo and
nodes call these; tdcc_exact.cli re-exports both for older imports.
"""
from __future__ import annotations

from . import registry
from .commit import check_reveal, provider_key
from .dispute import Fault, bisect, first_fault, output_fault, verify_window
from .oracle import Job, Receipt, Run, answer_ids, as_binding, job_every, run_job, save_trace
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
    out = v | {"verdict": "ACCEPT" if ok else "CHALLENGE", "re_run": mine.fingerprint,
               "differs": diff, "warning": "; ".join(notes) or None}
    if job.generate and "answer" in diff:
        out["first_token"] = token_diff(r.tokens, answer_ids(rec.answer))
    return out


def token_diff(honest: list[int], posted: list[int] | None) -> dict | None:
    """Where a generate receipt's tokens leave the re-run's: {"step": i, "re_run": token i
    of the re-run (None: it had ended), "posted": the receipt's (None: it had stopped)}.
    None if they are the same; posted None (an answer that is no token list) is step 0."""
    if posted is None:
        return {"step": 0, "re_run": honest[0] if honest else None, "posted": None}
    for i in range(max(len(honest), len(posted))):
        a = honest[i] if i < len(honest) else None
        b = posted[i] if i < len(posted) else None
        if a != b:
            return {"step": i, "re_run": a, "posted": b}
    return None


def generation_fault(job: Job, mine: Run, prov_tokens: list[int] | None, index: int,
                     at_step: int) -> Fault | None:
    """In a generate job, the generation step the first differing checkpoint (`index`)
    belongs to, when the provider's tokens are what differs there: it fed another token than
    the argmax of the logits both traces agree on ("token"), stopped before a stop id or
    max_tokens ("stop"), or went on past them ("overrun"). None: the divergence is in the
    prefill, or in a run's work (an instruction fault decides). at_step: the instruction
    step to report (the window's first)."""
    if not job.generate or prov_tokens is None:
        return None
    honest, cps = mine.tokens, mine.token_cps
    i = max((k for k, c in enumerate(cps) if c <= index), default=None)
    if i is None:
        return None                     # in the prefill: not a token's fault
    td = token_diff(honest, prov_tokens)
    if td is None or td["step"] != i:
        return None
    a, b = td["re_run"], td["posted"]
    if b is None:
        return Fault(at_step, -1, -1, f"generation step {i}: token {a}, the argmax (not a "
                     f"stop id: {job.stop_ids})", f"generation step {i}: stopped after {i} "
                     "tokens", "stop")
    if a is None:
        return Fault(at_step, -1, -1, f"generation step {i}: none (the answer ended at "
                     f"{len(honest)} tokens: a stop id or max_tokens {job.max_tokens})",
                     f"generation step {i}: token {b}", "overrun")
    return Fault(at_step, -1, -1, f"generation step {i}: token {a}, the argmax of the "
                 "logits both traces read", f"generation step {i}: token {b}", "token")


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
    prov_run = run_job(job, "provider", replay_cheat, every, window=w, model=model,
                       binding=binding, reveal=d.index)
    prov = prov_run.log
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
    if job.generate:                    # the provider's tokens: its posted ones, else its
        posted = answer_ids(receipt.answer) if receipt is not None else prov_run.tokens
        g = generation_fault(job, mine, posted, d.index, f.step if f else d.lo + 1)
        if g is not None:
            out(f"first fault: {g.other} ({g.what}); the honest run: {g.honest}")
            f = g
    return mine, d, f
