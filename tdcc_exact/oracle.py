"""A yes/no oracle job on Exact Core: the job, the run, and the receipt a provider posts.

A job names a model, a prompt (its token ids, so the verifier needs no tokenizer) and the two
answer tokens. Running it feeds the prompt through the engine in device runs of `chunk` tokens
(Engine.prefill) on a traced backend, and the answer is whichever of the two tokens gets the
larger logit after the last one.

The receipt's fingerprint binds everything a verifier re-checks:

    fingerprint = H(job || model image || answer || last logits || trace root)

so two honest runs of a job, on a card or on a laptop, post the same fingerprint, and any
difference in the work changes it.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from .backend import SkipLayer, factory
from .trace import EVERY, TraceLog, h

TINY = "tiny"                    # a small random Qwen3-style model: tests and the quick demo


@dataclass
class Job:
    model: str                   # a Hugging Face checkpoint directory, or "tiny[:seed]"
    prompt_ids: list[int]
    yes_id: int
    no_id: int
    question: str = ""
    wformat: str = "int8"
    cap: int = 256               # the KV cache's positions
    chunk: int = 8               # prompt tokens per device run (Engine.prefill: the trace's shape)
    job_id: str = ""

    @property
    def digest(self) -> bytes:
        d = asdict(self)
        d.pop("job_id")
        d["model"] = model_name(self.model)
        return h(json.dumps(d, sort_keys=True).encode())

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=1))

    @staticmethod
    def load(path) -> "Job":
        return Job(**json.loads(Path(path).read_text()))


def model_name(model: str) -> str:
    """A job's model by name (the directory's last part): the image hash pins the weights."""
    return model if model.startswith(TINY) else Path(model).name


@dataclass
class Receipt:
    job_id: str
    provider: str
    answer: str
    model_hash: str
    logits_hash: str
    trace_root: str
    steps: int
    checkpoints: int
    fingerprint: str
    extra: dict = field(default_factory=dict)

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=1))

    @staticmethod
    def load(path) -> "Receipt":
        return Receipt(**json.loads(Path(path).read_text()))


# ------------------------------------------------------------------------------- models
def tiny_model(seed: int = 0):
    """(spec, weights) of a small random Qwen3-style model (2 layers, 256 wide, 512 tokens):
    every opcode a real model runs, in seconds on the simulator."""
    from opentpu.llm.qwen3 import Spec
    spec = Spec(hidden=256, layers=2, n_q=2, n_kv=2, head_dim=128, ffn=512, vocab=512)
    rng = np.random.default_rng(seed)
    H, d, F_ = spec.hidden, spec.head_dim, spec.ffn

    def r(*shape):
        return (rng.standard_normal(shape, np.float32) * 0.05).astype(np.float32)

    W = {"model.embed_tokens.weight": r(spec.vocab, H),
         "model.norm.weight": np.ones(H, np.float32)}
    for i in range(spec.layers):
        p = f"model.layers.{i}."
        W.update({p + "input_layernorm.weight": np.ones(H, np.float32),
                  p + "post_attention_layernorm.weight": np.ones(H, np.float32),
                  p + "self_attn.q_norm.weight": np.ones(d, np.float32),
                  p + "self_attn.k_norm.weight": np.ones(d, np.float32),
                  p + "self_attn.q_proj.weight": r(spec.n_q * d, H),
                  p + "self_attn.k_proj.weight": r(spec.n_kv * d, H),
                  p + "self_attn.v_proj.weight": r(spec.n_kv * d, H),
                  p + "self_attn.o_proj.weight": r(H, spec.n_q * d),
                  p + "mlp.gate_proj.weight": r(F_, H),
                  p + "mlp.up_proj.weight": r(F_, H),
                  p + "mlp.down_proj.weight": r(H, F_)})
    return spec, W


def load_model(model: str):
    if model.startswith(TINY):
        return tiny_model(int(model.split(":")[1]) if ":" in model else 0)
    from opentpu.llm import load_spec
    from opentpu.llm.qwen3 import load_weights
    return load_spec(model), load_weights(model)


def layers_of(spec) -> int:
    return getattr(spec, "layers", None) or len(getattr(spec, "kinds", ())) or 1


# ------------------------------------------------------------------------------- jobs
def new_job(model: str, question: str, job_id: str = "") -> Job:
    """An oracle job: the question in the model's chat template, answered Yes or No."""
    if model.startswith(TINY):
        ids = [1 + (b % 500) for b in question.encode()][:24] or [1]
        return Job(model, ids, yes_id=3, no_id=4, question=question, job_id=job_id)
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model)
    msg = [{"role": "system", "content": "Answer with exactly one word: Yes or No."},
           {"role": "user", "content": question}]
    ids = tok.apply_chat_template(msg, add_generation_prompt=True, tokenize=True)
    ids = list(ids["input_ids"] if hasattr(ids, "keys") else ids)
    # LFM2.5: "Yes" = 12948 and "No" = 5048, one token each (as the assistant's turn starts,
    # without a leading space). A tokenizer that splits them: their first tokens, which differ
    yes, no = (tok.encode(w, add_special_tokens=False) for w in ("Yes", "No"))
    if yes[0] == no[0]:
        raise ValueError(f"{model}: 'Yes' / 'No' start with the same token ({yes}, {no})")
    return Job(model, ids, yes[0], no[0], question=question, job_id=job_id)


@dataclass
class Run:
    receipt: Receipt
    log: TraceLog
    logits: np.ndarray


def run_job(job: Job, provider: str = "local", cheat: SkipLayer | None = None,
            every: int = EVERY, window=None, model=None) -> Run:
    """Run `job` on a traced Exact Core simulator (cheat: a dishonest provider's shortcut;
    window: (lo, hi], record each step there for a dispute)."""
    from opentpu.llm.qwen3 import Engine    # (every Spec's engine: Qwen3, LFM2, ...)
    spec, W = model if model is not None else load_model(job.model)
    log = TraceLog(every=every, window=window)
    eng = Engine(spec, W, cap=job.cap, backend=factory(log, cheat), wformat=job.wformat,
                 rows=job.chunk, pipeline=False)
    logits = eng.prefill([int(t) for t in job.prompt_ids], chunk=job.chunk)
    logits = np.asarray(logits, np.float32).reshape(-1)
    answer = "YES" if logits[job.yes_id] > logits[job.no_id] else "NO"
    mh, lh, root = eng.backend.model_hash, h(logits.tobytes()), log.root
    fp = h(job.digest, mh, answer.encode(), lh, root)
    extra = {"skipped_mms": cheat.skipped} if cheat is not None else {}
    rec = Receipt(job.job_id, provider, answer, mh.hex(), lh.hex(), root.hex(), log.step,
                  len(log.checkpoints), fp.hex(), extra)
    return Run(rec, log, logits)


def save_trace(log: TraceLog, path) -> None:
    Path(path).write_text(json.dumps(log.to_json()))


def load_trace(path) -> dict:
    return json.loads(Path(path).read_text())
