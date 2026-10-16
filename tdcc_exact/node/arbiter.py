"""The arbiter node: rule on the market's challenged jobs (slash or dismiss).

Each pass (`run_once`) lists the market's Challenged jobs and rules on each one it has not
ruled on yet (a dismissed job challenged again is a new challenge: the state file keys a
ruling by the job and its challenge slot):

    past ruling_deadline   anyone may dismiss now; the node does so itself (dismiss_late)
    the Job                fetched from the store under the on-chain job_digest (the store's
                           check makes it that job)
    the provider's trace   fetched from the store under the on-chain trace_root (checked
                           against the root, so it is the trace the receipt committed to)

then re-runs the job itself, bound to the Job account's address, and decides:

    1. trace missing from the store: slash with divergence_index 0 if `missing_trace_loses`
       (the default: the provider owed the market its trace), else leave the job (it settles
       for the provider once the ruling deadline passes and anyone dismisses it). A trace not
       there yet is waited for `trace_grace` slots after the challenge (default: half the
       ruling window), so a provider whose publish trails its reveal is not slashed for it.
    2. bisection (dispute.bisect) of the arbiter's checkpoints against the provider's finds a
       divergence: slash, divergence_index = the first differing checkpoint, fault_step = its
       window's first step (lo + 1).
    3. the traces agree and the on-chain fingerprint is the arbiter's own run's: dismiss (the
       challenger was wrong).
    4. the traces agree and the fingerprint is not the arbiter's: an output fault (the receipt
       is not the one the trace gives; dispute.output_fault says which field, from the answer
       and logits hash of the ReceiptRevealed event): slash, divergence_index = the checkpoint
       count, fault_step = the last checkpoint's step.

Limit: the arbiter cannot replay the provider's window. In a live market the challenged
provider reveals the disputed window (TraceLog.reveal) and the arbiter checks it with
dispute.verify_window and pins the first faulty instruction with dispute.first_fault
(verifier.dispute does this with a locally replayed provider). No API carries that reveal
yet, so rule 2 slashes on the bisection alone: the provider's posted checkpoint differs from
an honest run's, which only a wrong run (or a wrong post) produces. Once the reveal exists,
rule 2 becomes: slash if the window does not chain to the posts or first_fault finds an
instruction (fault_step = that step), and a provider that never reveals loses as in rule 1.

The node signs with the market's arbiter key (Config.arbiter, which may differ from the
admin's) and refuses to start with any other.
"""
from __future__ import annotations

import time

from ..dispute import bisect, output_fault
from ..oracle import Receipt
from ..trace import Checkpoint
from .common import Models, StateFile, run
from .store import NotFound, StoreError

DONE = {"slashed", "dismissed", "dismissed-late", "no-trace"}


class NotArbiter(RuntimeError):
    pass


class ArbiterNode:
    def __init__(self, chain, owner, store, state_path, models: Models | None = None,
                 missing_trace_loses: bool = True, trace_grace: int | None = None,
                 dismiss_late: bool = True, log=print):
        want = chain.arbiter()
        if bytes(want) != bytes(owner.pubkey()):
            raise NotArbiter(f"this key {owner.pubkey()} is not the market's arbiter {want}")
        self.chain, self.owner, self.store = chain, owner, store
        self.state = StateFile(state_path)
        self.models = models or Models()
        self.missing_trace_loses, self.trace_grace = missing_trace_loses, trace_grace
        self.dismiss_late, self.log = dismiss_late, log

    def run_once(self) -> dict:
        """{job: ruling} of the challenges this pass ruled on."""
        out = {}
        for key, j in self.chain.jobs(states={"Challenged"}):
            k = str(key)
            s = self.state.get(k) or {}
            if s.get("challenge_slot") == j.challenge_slot and s.get("ruling") in DONE:
                continue
            try:
                r = self._rule(key, j)
            except StoreError as e:
                self.log(f"{k[:8]}: store: {e} (retry next pass)")
                continue
            except Exception as e:  # noqa: BLE001 - a node keeps going; the next pass retries
                self.log(f"{k[:8]}: {type(e).__name__}: {e} (retry next pass)")
                continue
            if r:
                out[k] = r
        return out

    def loop(self, poll: float = 2.0) -> None:
        while True:
            try:
                self.run_once()
            except Exception as e:  # noqa: BLE001
                self.log(f"pass failed: {e}")
            time.sleep(poll)

    # ------------------------------------------------------------------ rulings
    def _record(self, k: str, j, ruling: str, **v) -> str:
        self.state.set(k, ruling=ruling, challenge_slot=j.challenge_slot,
                       provider=str(j.provider), verifier=str(j.verifier), **v)
        self.log(f"{k[:8]}: {ruling}" + (f"  ({v['why']})" if "why" in v else ""))
        return ruling

    def _slash(self, key, j, index: int, step: int, why: str, **v) -> str:
        index = max(0, min(int(index), j.checkpoints))     # the program's range
        sig = self.chain.slash(self.owner, key, index, step)
        return self._record(str(key), j, "slashed", sig=sig, divergence_index=index,
                            fault_step=step, why=why, **v)

    def _dismiss(self, key, j, why: str, ruling: str = "dismissed", **v) -> str:
        sig = self.chain.dismiss(self.owner, key)
        return self._record(str(key), j, ruling, sig=sig, why=why, **v)

    def _rule(self, key, j) -> str | None:
        k = str(key)
        slot = self.chain.slot()
        if slot > j.ruling_deadline:
            if not self.dismiss_late:
                return None
            return self._dismiss(key, j, "past the ruling deadline: the receipt stands",
                                 "dismissed-late")
        job = self.store.get_job(j.job_digest.hex())   # NotFound / Tampered: retry
        if job.digest != j.job_digest:
            raise StoreError("the store's job is not the on-chain one")
        try:
            trace = self.store.get_trace(j.trace_root.hex())
        except NotFound:
            grace = (self.trace_grace if self.trace_grace is not None
                     else (j.ruling_deadline - j.challenge_slot) // 2)
            if slot < j.challenge_slot + grace:
                self.log(f"{k[:8]}: the provider's trace is not in the store yet (waiting)")
                return None
            why = (f"the provider's trace {j.trace_root.hex()[:16]}.. is not in the store "
                   f"{slot - j.challenge_slot} slots after the challenge")
            if self.missing_trace_loses:
                return self._slash(key, j, 0, 0, why + ": it loses", trace="missing")
            return self._record(k, j, "no-trace", why=why + ": left to the ruling deadline",
                                trace="missing")
        cps = [Checkpoint.from_json(c) for c in trace["checkpoints"]]
        mine = run(job, "arbiter", self.models, job_key=bytes(key))
        info = dict(trace="available", rerun=mine.receipt.fingerprint,
                    posted=j.fingerprint.hex())
        d = bisect(mine.log.checkpoints, cps)
        if d is not None:
            return self._slash(key, j, d.index, d.lo + 1,
                               f"checkpoint {d.index} differs from an honest run's "
                               f"(steps {d.lo + 1}..{d.hi}, {d.rounds} rounds)", **info)
        if mine.receipt.fingerprint == j.fingerprint.hex():
            return self._dismiss(key, j, "the traces agree and the receipt is the honest "
                                         "run's", **info)
        why = self._output_why(key, j, job, mine.receipt, cps)
        last = cps[-1].step if cps else 0
        return self._slash(key, j, j.checkpoints, last, why, **info)

    def _output_why(self, key, j, job, mine, cps) -> str:
        """Why the receipt is not the one the agreed trace gives (dispute.output_fault, from
        the revealed answer and logits hash when the reveal's event can be read)."""
        why = "the traces agree but the fingerprint is not the honest run's"
        try:
            e = self.chain.revealed(key)
        except Exception as x:  # noqa: BLE001 - the ruling does not depend on it
            self.log(f"{str(key)[:8]}: the reveal's event: {x}")
            e = None
        if not e:
            return why
        posted = Receipt(job.job_id, str(j.provider), "YES" if e["answer"] == 1 else "NO",
                         j.model_hash.hex(), e["logits_hash"], j.trace_root.hex(),
                         0, j.checkpoints, j.fingerprint.hex())
        f = output_fault(job, posted, mine, cps)
        return why if f is None else f"output fault: {f.other}"
