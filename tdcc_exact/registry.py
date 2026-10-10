"""The model registry: which DRAM image a job's model must run as.

A receipt's model hash is the hash of the DRAM image the engine builds, and that image depends
on the weights *and* on the build: the weight format, the KV cache's size, the design's
MCOLS / LANES. Two providers with the same checkpoint but another build post different model
hashes, and a provider that quietly runs fp4 instead of int8 (cheaper, a different answer
sometimes) posts a hash that is not the one the job asked for.

So jobs name a registered model, and the registry pins

    (model id, wformat, cap) -> expected image hash

(tdcc_exact/models.json). A verifier rejects a receipt whose model hash is not the pinned one
before re-running anything; on-chain the job account stores the expected hash.
`tdcc-exact registry add` computes and pins an entry.
"""
from __future__ import annotations

import json
from pathlib import Path

PATH = Path(__file__).with_name("models.json")


def key(model: str, wformat: str, cap: int) -> str:
    return f"{model}|{wformat}|{cap}"


def load(path=PATH) -> dict:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else {}


def expected(model: str, wformat: str, cap: int, path=PATH) -> str | None:
    """The pinned image hash (hex) of a model build, or None if it is not registered."""
    e = load(path).get(key(model, wformat, cap))
    return e["image_hash"] if e else None


def add(model: str, wformat: str, cap: int, image_hash: str, source: str = "",
        path=PATH) -> None:
    reg = load(path)
    reg[key(model, wformat, cap)] = {"model": model, "wformat": wformat, "cap": cap,
                                     "image_hash": image_hash, "source": source}
    Path(path).write_text(json.dumps(reg, indent=1, sort_keys=True) + "\n")


def check(job, model_hash: str, path=PATH) -> str | None:
    """None if the receipt's model hash is the registered one, else why not."""
    from .oracle import model_name
    want = expected(model_name(job.model), job.wformat, job.cap, path)
    if want is None:
        return f"model {model_name(job.model)} ({job.wformat}, cap {job.cap}) is not registered"
    if want != model_hash:
        return f"model hash {model_hash} is not the registered {want}"
    return None
