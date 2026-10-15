"""What the provider and verifier nodes share: running a job, and a small JSON state file."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from ..oracle import TINY, Job, layers_of, load_model, run_job
from ..trace import EVERY


class Models:
    """Loaded models by name (a node runs many jobs on few models). A job names its model by
    the checkpoint directory's last part; `models_dir` is where this node keeps them."""

    def __init__(self, models_dir: str | None = None):
        self.dir = models_dir
        self._cache: dict = {}

    def path(self, model: str) -> str:
        if model.startswith(TINY) or self.dir is None or Path(model).exists():
            return model
        return str(Path(self.dir) / Path(model).name)

    def get(self, model: str):
        p = self.path(model)
        if p not in self._cache:
            self._cache[p] = load_model(p)
        return self._cache[p]


def run(job: Job, who: str, models: Models, every: int = EVERY, skip_layer: int | None = None,
        job_key=None):
    """The one place a node runs a job (oracle.run_job). job_key: the on-chain job account
    (its 32 bytes), for when the trace is bound to it."""
    from ..backend import SkipLayer
    model = models.get(job.model)
    cheat = None if skip_layer is None else SkipLayer(skip_layer, layers_of(model[0]))
    local = Job(**{**job.__dict__, "model": models.path(job.model)})
    # (job_key is unused until run_job takes the binding: then binding=bytes(job_key) here)
    return run_job(local, who, cheat, every=every, model=model)


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
