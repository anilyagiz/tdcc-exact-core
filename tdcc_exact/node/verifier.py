"""The verifier node: re-run revealed jobs and challenge the receipts that do not match.

Each pass (`run_once`) lists the market's Revealed jobs and, for a sample of them (`rate`, by
a hash of the job and the verifier's key, so a restart samples the same ones and verifiers
sample different ones), fetches the Job from the store under the on-chain digest, re-runs it
and compares fingerprints: a match is accepted, a mismatch challenged while the challenge
window is open. Each verdict goes into the state file, with whether the provider's trace was
in the store (the arbiter's bisection needs it).
"""
from __future__ import annotations

import hashlib
import time

from .common import Models, StateFile, verdict
from .store import NotFound, StoreError, Tampered


class VerifierNode:
    def __init__(self, chain, owner, store, state_path, models: Models | None = None,
                 rate: float = 1.0, log=print):
        self.chain, self.owner, self.store = chain, owner, store
        self.state = StateFile(state_path)
        self.models = models or Models()
        self.rate, self.log = rate, log

    def sampled(self, key) -> bool:
        x = hashlib.sha256(b"tdcc-exact/sample/v1" + bytes(key)
                           + bytes(self.owner.pubkey())).digest()
        return int.from_bytes(x[:8], "little") < self.rate * 2 ** 64

    def run_once(self) -> dict:
        """{job: verdict} of the jobs this pass decided."""
        out = {}
        for key, j in self.chain.jobs(states={"Revealed"}):
            k = str(key)
            if self.state.get(k):
                continue
            try:
                v = self._check(key, j)
            except StoreError as e:
                self.log(f"{k[:8]}: store: {e} (retry next pass)")
                continue
            except Exception as e:  # noqa: BLE001
                self.log(f"{k[:8]}: {type(e).__name__}: {e} (retry next pass)")
                continue
            if v:
                out[k] = v
        return out

    def loop(self, poll: float = 2.0) -> None:
        while True:
            try:
                self.run_once()
            except Exception as e:  # noqa: BLE001
                self.log(f"pass failed: {e}")
            time.sleep(poll)

    def _record(self, k: str, verdict: str, **v) -> str:
        self.state.set(k, verdict=verdict, **v)
        self.log(f"{k[:8]}: {verdict}" + (f"  ({v['why']})" if "why" in v else ""))
        return verdict

    def _check(self, key, j) -> str | None:
        k = str(key)
        if not self.sampled(key):
            return self._record(k, "skipped", why="not sampled")
        if self.chain.slot() > j.challenge_deadline:
            return self._record(k, "late", why="challenge window closed")
        try:
            job = self.store.get_job(j.job_digest.hex())
        except Tampered as e:
            return self._record(k, "unverifiable", why=f"the store's job is not the "
                                                       f"on-chain one: {e}")
        except NotFound:
            raise StoreError(f"job {j.job_digest.hex()[:16]}.. is not in the store") from None
        v = verdict(job, j, self.models, bytes(key))
        try:
            self.store.get_trace(j.trace_root.hex())
            trace = "available"
        except StoreError:
            trace = "missing"
        info = dict(posted=j.fingerprint.hex(), rerun=v["re_run"], provider=str(j.provider),
                    trace=trace)
        if v["verdict"] == "ACCEPT":
            return self._record(k, "accepted", **info)
        why = v.get("why") or "fingerprint mismatch" + (
            f": {', '.join(v['differs'])} differ" if v["differs"] else "")
        if self.chain.slot() > j.challenge_deadline:
            return self._record(k, "late", why=f"{why}, after the challenge window", **info)
        sig = self.chain.challenge(self.owner, key, bytes.fromhex(v["re_run"]))
        return self._record(k, "challenged", sig=sig, why=why, **info)
