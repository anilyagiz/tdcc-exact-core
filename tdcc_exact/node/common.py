"""What the provider and verifier nodes share: running a job, and a small JSON state file."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from ..oracle import Job, Receipt, is_tiny, layers_of, load_model, run_job


class Models:
    """Loaded models by name (a node runs many jobs on few models). A job names its model by
    the checkpoint directory's last part; `models_dir` is where this node keeps them."""

    def __init__(self, models_dir: str | None = None):
        self.dir = models_dir
        self._cache: dict = {}

    def path(self, model: str) -> str:
        if is_tiny(model) or self.dir is None or Path(model).exists():
            return model
        return str(Path(self.dir) / Path(model).name)

    def get(self, model: str):
        p = self.path(model)
        if p not in self._cache:
            self._cache[p] = load_model(p)
        return self._cache[p]


def run(job: Job, who: str, models: Models, skip_layer: int | None = None, job_key=None,
        window=None, reveal: int | None = None):
    """The one place a node runs a job (oracle.run_job), at the job's own checkpoint interval.
    job_key: the on-chain job account (its 32 bytes): the run's trace is bound to it, so a
    fingerprint revealed on another job cannot be replayed on this one. window, reveal: a
    disputed window's records (run_job's), for a revealed window (window_records)."""
    from ..backend import SkipLayer
    model = models.get(job.model)
    cheat = None if skip_layer is None else SkipLayer(skip_layer, layers_of(model[0]))
    local = Job(**{**job.__dict__, "model": models.path(job.model)})
    return run_job(local, who, cheat, model=model, window=window, reveal=reveal,
                   binding=None if job_key is None else bytes(job_key))


def window_topic(lo: int, hi: int) -> str:
    """The store topic (store.signed_key) of a provider's revealed window of steps (lo, hi]."""
    return f"window/{int(lo)}/{int(hi)}"


def window_records(job: Job, models: Models, job_key, d, skip_layer: int | None = None):
    """What a provider reveals for divergence `d` (dispute.Divergence): every record that
    moved the chain from checkpoint d.index - 1 to its checkpoint d.index (TraceLog.reveal:
    what dispute.verify_window checks), from a re-run with the job's binding. skip_layer:
    the dishonest provider's shortcut, replayed (tests)."""
    return run(job, "provider", models, skip_layer, job_key=job_key, window=(d.lo, d.hi),
               reveal=d.index).log.events


def verdict(job: Job, j, models: Models, job_key, trace=None) -> dict:
    """cli.verify on the receipt a Job account holds (fingerprint, model hash, trace root:
    the chain keeps no answer, logits hash or step count, so only those fields compare).
    {"verdict": ACCEPT | CHALLENGE | REJECT, "re_run": fingerprint, ...}; a REJECT (the
    model build is not the registry's) re-runs here too, for the fingerprint to challenge
    with. trace: a path to save the re-run's trace to (what the verifier publishes when it
    challenges)."""
    from ..cli import verify
    rec = Receipt(job.job_id, str(j.provider), "", j.model_hash.hex(), "", j.trace_root.hex(),
                  0, j.checkpoints, j.fingerprint.hex())
    local = Job(**{**job.__dict__, "model": models.path(job.model)})
    v = verify(local, rec, binding=bytes(job_key), trace=trace)
    v["differs"] = {k: d for k, d in v.get("differs", {}).items()
                    if k in ("model_hash", "trace_root")}
    if v["verdict"] == "REJECT":
        r = run(job, "verifier", models, job_key=job_key)
        v["re_run"] = r.receipt.fingerprint
        if trace:
            from ..oracle import save_trace
            save_trace(r.log, trace)
    return v


class StateFile:
    """A dict persisted as JSON, written atomically after each change (a restart resumes)."""

    def __init__(self, path):
        self.path = Path(path)
        self.data: dict = json.loads(self.path.read_text()) if self.path.exists() else {}

    def get(self, k: str) -> dict | None:
        return self.data.get(k)

    def set(self, k: str, **v) -> dict:
        e = {**self.data.get(k, {}), **v, "updated": time.time()}
        self.data[k] = e
        self.save()
        return e

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)              # the provider's salts are secret until it reveals
        os.replace(tmp, self.path)
