"""The model registry: which DRAM image a job's model must run as.

A receipt's model hash is the hash of the DRAM image the engine builds, and that image depends
on the weights *and* on the build: the weight format, the KV cache's size, the design's
MCOLS / LANES. Two providers with the same checkpoint but another build post different model
hashes, and a provider that quietly runs fp4 instead of int8 (cheaper, a different answer
sometimes) posts a hash that is not the one the job asked for.

So jobs name a registered model, and the registry pins

    (model id, wformat, cap) -> expected image hash

(tdcc_exact/models.json, the packaged pins). A verifier rejects a receipt whose model hash
is not the pinned one before re-running anything; on-chain the job account stores the
expected hash.

A user registry is layered over the packaged one: the file TDCC_EXACT_REGISTRY names, else
$XDG_CONFIG_HOME/tdcc-exact/models.json (~/.config/...). Its entries add to the packaged
pins and take precedence over them. `tdcc-exact registry add` computes an entry and pins it
there (or in the file --path names: the packaged models.json in a source checkout), never
inside an installed package.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

PATH = Path(__file__).with_name("models.json")      # the packaged pins (read-only)
ENV = "TDCC_EXACT_REGISTRY"


def user_path() -> Path:
    """The user registry: $TDCC_EXACT_REGISTRY, else the user's config directory's."""
    if os.environ.get(ENV):
        return Path(os.environ[ENV]).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "tdcc-exact" / "models.json"


def key(model: str, wformat: str, cap: int) -> str:
    return f"{model}|{wformat}|{cap}"


def _read(p: Path) -> dict:
    if not p.exists():
        return {}
    try:
        reg = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"{p}: not a model registry (bad JSON: {e})") from None
    if not isinstance(reg, dict):
        raise ValueError(f"{p}: not a model registry (not an object)")
    return reg


def load(path=None) -> dict:
    """The registry: the file `path` alone, or (None) the packaged pins with the user
    registry over them."""
    if path is not None:
        return _read(Path(path))
    return _read(PATH) | _read(user_path())


def expected(model: str, wformat: str, cap: int, path=None) -> str | None:
    """The pinned image hash (hex) of a model build, or None if it is not registered."""
    e = load(path).get(key(model, wformat, cap))
    return e["image_hash"] if e else None


def add(model: str, wformat: str, cap: int, image_hash: str, source: str = "",
        path=None) -> Path:
    """Pin an entry in `path`, or (None) in the user registry; returns the file written."""
    p = Path(path) if path is not None else user_path()
    reg = _read(p)
    reg[key(model, wformat, cap)] = {"model": model, "wformat": wformat, "cap": cap,
                                     "image_hash": image_hash, "source": source}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(reg, indent=1, sort_keys=True) + "\n")
    return p


def check(job, model_hash: str, path=None) -> str | None:
    """None if the receipt's model hash is the registered one, else why not."""
    from .oracle import model_name
    want = expected(model_name(job.model), job.wformat, job.cap, path)
    if want is None:
        return f"model {model_name(job.model)} ({job.wformat}, cap {job.cap}) is not registered"
    if want != model_hash:
        return f"model hash {model_hash} is not the registered {want}"
    return None
