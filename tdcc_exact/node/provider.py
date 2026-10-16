"""The provider node: find the jobs opened for this provider, run them, commit, reveal.

Each pass (`run_once`) lists the market's Job accounts naming this provider and moves each
one step along, as far as the chain's state and the slot allow:

    Open        fetch the Job from the store under the on-chain digest, check it (below), run
                it, save the receipt, its salt and its trace, then commit_receipt
    Committed   once the slot is past commit_deadline, reveal_receipt (from the saved salt)
    Revealed+   publish the trace to the store (data availability for verifiers)
    Challenged  reveal the disputed window: fetch the challenger's signed note
                (store.signed_key("challenge", job, verifier)) and the trace it names, bisect
                it against this node's own checkpoints, re-run the job (bound to the job
                account) recording that window, and publish it as a note this node signs
                under signed_key(window_topic(lo, hi), job, provider): the arbiter's
                bisection names the same (lo, hi) when the challenger's trace is honest
                (the protocol: tdcc_exact/node/__init__.py). Once per challenge.

Before committing the node refuses a job unless the Job it fetched hashes to the on-chain
job_digest and the on-chain model_hash is the registry's pinned hash for the job's
(model, wformat, cap): otherwise a renter could pin a hash no honest run can produce and
have the provider's receipt challenged. A refused job is left alone: it expires back to the
renter at no cost to the provider.

Everything a restart needs (the salt above all) is written to the state file before the
transaction that depends on it, and the node commits only a job the chain shows Open, so it
never commits twice; a commit that landed but was not confirmed is found Committed on the
next pass and revealed.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .. import registry
from ..commit import commitment, new_salt
from ..dispute import bisect
from ..oracle import model_name
from ..trace import Checkpoint, record_to_json
from .common import Models, StateFile, run, window_records, window_topic
from .store import NotFound, StoreError, Tampered, sign_note, signed_key

DONE = {"refused", "missed", "published", "lost"}


class ProviderNode:
    def __init__(self, chain, owner, store, state_path, models: Models | None = None,
                 registry_path=registry.PATH, skip_layer: int | None = None,
                 reveal_windows: bool = True, log=print):
        """skip_layer: tests only, a dishonest provider that skips that layer's work;
        reveal_windows: False, tests only, a provider that withholds its disputed windows."""
        self.chain, self.owner, self.store = chain, owner, store
        self.state = StateFile(state_path)
        self.traces = Path(state_path).parent / "traces"
        self.models = models or Models()
        self.registry_path, self.skip_layer = registry_path, skip_layer
        self.reveal_windows, self.log = reveal_windows, log

    # ------------------------------------------------------------------ one pass
    def run_once(self, wait: bool = False) -> dict:
        """One pass over this provider's jobs; wait: then wait out the commit windows of the
        jobs it committed and reveal them too. {job: status} of the jobs it touched."""
        touched = self._pass()
        if wait:
            pending = [j.commit_deadline for _, j in self._mine({"Committed"})]
            if pending:
                self.chain.rpc.wait_slot(max(pending))
                touched.update(self._pass())
        return touched

    def loop(self, poll: float = 2.0) -> None:
        while True:
            try:
                self._pass()
            except Exception as e:  # noqa: BLE001 - a node keeps going; the next pass retries
                self.log(f"pass failed: {e}")
            time.sleep(poll)

    def _mine(self, states=None):
        return self.chain.jobs(provider=self.owner.pubkey(), states=states)

    def _pass(self) -> dict:
        touched = {}
        for key, j in self._mine():
            k = str(key)
            s = self.state.get(k) or {}
            challenged = j.state == "Challenged" and s.get("status") == "published"
            if s.get("status") in DONE and not challenged:
                continue
            try:
                st = self._answer(key, j, s) if challenged else self._step(key, j, s)
            except StoreError as e:
                st = None
                self.log(f"{k[:8]}: store: {e} (retry next pass)")
            except Exception as e:  # noqa: BLE001
                st = None
                self.log(f"{k[:8]}: {type(e).__name__}: {e} (retry next pass)")
            if st:
                touched[k] = st
        return touched

    def _step(self, key, j, s: dict) -> str | None:
        k = str(key)
        slot = self.chain.slot()
        if j.state == "Open":
            if slot > j.commit_deadline:
                self.state.set(k, status="missed")
                self.log(f"{k[:8]}: commit window closed before this node got to it")
                return "missed"
            if "salt" not in s:
                s = self._prepare(key, j)
                if s.get("status") == "refused":
                    return "refused"
            c = bytes.fromhex(s["commitment"])
            sig = self.chain.commit(self.owner, key, c)
            self.state.set(k, status="committed", commit_sig=sig)
            self.log(f"{k[:8]}: committed ({s['answer']})  {sig}")
            return "committed"
        if j.state == "Committed":
            if "salt" not in s:
                self.state.set(k, status="lost")
                self.log(f"{k[:8]}: committed, but this node has no salt for it")
                return "lost"
            if j.commitment.hex() != s["commitment"]:
                self.state.set(k, status="lost")
                self.log(f"{k[:8]}: the on-chain commitment is not this node's")
                return "lost"
            if slot <= j.commit_deadline:
                return None                    # the window is open: reveal on a later pass
            if slot > j.reveal_deadline:
                self.state.set(k, status="missed")
                self.log(f"{k[:8]}: reveal window closed")
                return "missed"
            sig = self.chain.reveal(self.owner, key, bytes.fromhex(s["fingerprint"]),
                                    bytes.fromhex(s["salt"]), bytes.fromhex(s["model_hash"]),
                                    s["answer"], bytes.fromhex(s["logits_hash"]),
                                    bytes.fromhex(s["tree_root"]), s["checkpoints"])
            self.state.set(k, status="revealed", reveal_sig=sig)
            self.log(f"{k[:8]}: revealed {s['fingerprint'][:16]}..  {sig}")
            return self._publish(k, s) or "revealed"
        if j.state in ("Revealed", "Challenged", "Settled", "Slashed") and "salt" in s:
            return self._publish(k, s)
        return None

    # ------------------------------------------------------------------ the work
    def _refuse(self, k: str, why: str) -> dict:
        self.log(f"{k[:8]}: refused: {why}")
        return self.state.set(k, status="refused", why=why)

    def _prepare(self, key, j) -> dict:
        """Fetch, check and run the job; save what the commit and the reveal need."""
        k = str(key)
        try:
            job = self.store.get_job(j.job_digest.hex())
        except Tampered as e:
            return self._refuse(k, f"the store's job does not match the on-chain digest ({e})")
        except NotFound:
            raise StoreError(f"job {j.job_digest.hex()[:16]}.. is not published yet") from None
        if job.digest != j.job_digest:          # (the store checked; this is the contract)
            return self._refuse(k, "job digest differs from the on-chain one")
        want = registry.expected(model_name(job.model), job.wformat, job.cap,
                                 self.registry_path)
        if want is None:
            return self._refuse(k, f"model {model_name(job.model)} ({job.wformat}, cap "
                                   f"{job.cap}) is not in the registry")
        if want != j.model_hash.hex():
            return self._refuse(k, f"on-chain model hash {j.model_hash.hex()[:16]}.. is not "
                                   f"the registered {want[:16]}..")
        try:
            job.check(getattr(self.models.get(job.model)[0], "vocab", None))
        except ValueError as e:
            return self._refuse(k, f"no run can answer this job: {e}")
        res = run(job, str(self.owner.pubkey()), self.models, self.skip_layer,
                  job_key=bytes(key))
        r = res.receipt
        if r.model_hash != j.model_hash.hex():
            return self._refuse(k, f"this node's build hashes to {r.model_hash[:16]}.., not "
                                   f"the job's {j.model_hash.hex()[:16]}..")
        self.traces.mkdir(parents=True, exist_ok=True)
        tf = self.traces / f"{r.trace_root}.json"
        tf.write_text(json.dumps(res.log.to_json()))
        from ..chain import tree_root
        tree = tree_root([c.leaf for c in res.log.checkpoints])   # what the reveal posts
        salt = new_salt()
        fp = bytes.fromhex(r.fingerprint)
        c = commitment(fp, bytes(self.owner.pubkey()), salt)
        return self.state.set(k, status="prepared", answer=r.answer, fingerprint=r.fingerprint,
                              model_hash=r.model_hash, trace_root=r.trace_root,
                              logits_hash=r.logits_hash, tree_root=tree.hex(),
                              checkpoints=r.checkpoints, salt=salt.hex(), commitment=c.hex(),
                              trace_file=str(tf), job_digest=j.job_digest.hex())

    def _publish(self, k: str, s: dict) -> str | None:
        p = Path(s.get("trace_file", ""))
        if not p.is_file():
            return None
        key = self.store.put_trace(json.loads(p.read_text()))
        if key != s["trace_root"]:
            self.log(f"{k[:8]}: the saved trace's root {key[:16]}.. is not the revealed one")
        self.state.set(k, status="published")
        self.log(f"{k[:8]}: trace {key[:16]}.. published")
        return "published"

    # ------------------------------------------------------------------ a challenge
    def _answer(self, key, j, s: dict) -> str | None:
        """Reveal the window the challenger's trace disputes (once per challenge)."""
        k = str(key)
        if s.get("answered") == j.challenge_slot:
            return None
        mine = json.loads(Path(s["trace_file"]).read_text())
        cps = [Checkpoint.from_json(c) for c in mine["checkpoints"]]
        try:
            note = self.store.get_signed(signed_key("challenge", bytes(key), j.verifier))
            theirs = self.store.get_trace(note["body"]["trace_root"])
        except NotFound:
            self.log(f"{k[:8]}: challenged; the challenger's trace is not in the store yet")
            return None
        d = bisect([Checkpoint.from_json(c) for c in theirs["checkpoints"]], cps)
        if d is None or d.index >= len(cps):
            why = ("the challenger's trace agrees with this node's" if d is None else
                   "the challenger's trace is longer: no posted checkpoint to reveal up to")
            self.state.set(k, answered=j.challenge_slot, window="none", window_why=why)
            self.log(f"{k[:8]}: challenged; no window to reveal ({why})")
            return "no-window"
        if not self.reveal_windows:
            self.state.set(k, answered=j.challenge_slot, window="withheld")
            self.log(f"{k[:8]}: challenged; withholding window {d.lo}..{d.hi}")
            return "withheld"
        job = self.store.get_job(s["job_digest"])
        recs = window_records(job, self.models, bytes(key), d, self.skip_layer)
        body = {"lo": d.lo, "hi": d.hi, "index": d.index,
                "records": [record_to_json(r) for r in recs]}
        self.store.put_signed(sign_note(self.owner, window_topic(d.lo, d.hi), bytes(key),
                                        body))
        self.state.set(k, answered=j.challenge_slot, window=f"{d.lo}..{d.hi}",
                       window_index=d.index)
        self.log(f"{k[:8]}: challenged; window {d.lo}..{d.hi} ({len(recs)} records) "
                 "revealed")
        return "window"
