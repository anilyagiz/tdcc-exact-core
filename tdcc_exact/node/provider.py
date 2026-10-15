"""The provider node: find the jobs opened for this provider, run them, commit, reveal.

Each pass (`run_once`) lists the market's Job accounts naming this provider and moves each
one step along, as far as the chain's state and the slot allow:

    Open        fetch the Job from the store under the on-chain digest, check it (below), run
                it, save the receipt, its salt and its trace, then commit_receipt
    Committed   once the slot is past commit_deadline, reveal_receipt (from the saved salt)
    Revealed+   publish the trace to the store (data availability for verifiers)

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
from ..oracle import model_name
from ..trace import EVERY
from .common import Models, StateFile, run
from .store import NotFound, StoreError, Tampered

DONE = {"refused", "missed", "published", "lost"}


class ProviderNode:
    def __init__(self, chain, owner, store, state_path, models: Models | None = None,
                 every: int = EVERY, registry_path=registry.PATH, skip_layer: int | None = None,
                 log=print):
        """skip_layer: tests only, a dishonest provider that skips that layer's work."""
        self.chain, self.owner, self.store = chain, owner, store
        self.state = StateFile(state_path)
        self.traces = Path(state_path).parent / "traces"
        self.models = models or Models()
        self.every, self.registry_path, self.skip_layer = every, registry_path, skip_layer
        self.log = log

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
            if s.get("status") in DONE:
                continue
            try:
                st = self._step(key, j, s)
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
                                    bytes.fromhex(s["trace_root"]), s["checkpoints"])
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
            raise StoreError(f"job {j.job_digest.hex()[:16]}.. is not published yet")
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
        res = run(job, str(self.owner.pubkey()), self.models, self.every, self.skip_layer,
                  job_key=bytes(key))
        r = res.receipt
        if r.model_hash != j.model_hash.hex():
            return self._refuse(k, f"this node's build hashes to {r.model_hash[:16]}.., not "
                                   f"the job's {j.model_hash.hex()[:16]}..")
        self.traces.mkdir(parents=True, exist_ok=True)
        tf = self.traces / f"{r.trace_root}.json"
        tf.write_text(json.dumps(res.log.to_json()))
        salt = new_salt()
        fp = bytes.fromhex(r.fingerprint)
        c = commitment(fp, bytes(self.owner.pubkey()), salt)
        return self.state.set(k, status="prepared", answer=r.answer, fingerprint=r.fingerprint,
                              model_hash=r.model_hash, trace_root=r.trace_root,
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
