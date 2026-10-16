"""A yes/no oracle job on Exact Core: the job, the run, and the receipt a provider posts.

A job names a model, a prompt (its token ids, so the verifier needs no tokenizer) and the two
answer tokens. Running it feeds the prompt through the engine in device runs of `chunk` tokens
(Engine.prefill) on a traced backend, and the answer is whichever of the two tokens gets the
larger logit after the last one.

The receipt's fingerprint binds everything a verifier re-checks:

    fingerprint = H(job || model image || answer || last logits || trace root)

so two honest runs of a job, on a card or on a laptop, post the same fingerprint, and any
difference in the work changes it.

A run is bound to the on-chain job account it is for: `binding` (32 bytes, the account's
address; locally the provider's key) is the trace chain's first input, so the same Job opened
twice (with provider A and with provider B, or asked again) has two trace roots and two
fingerprints, and a fingerprint revealed on one is no use on the other. A verifier re-runs
with the binding of the on-chain job, never one a receipt claims. The job also carries a
random nonce (new_job) in its digest, so two jobs' digests differ too.

A job of kind "generate" asks for text instead: the prompt is prefilled, then up to
`max_tokens` tokens are decoded greedily, each one a device run in the same trace, stopping
at a token in `stop_ids`. Greedy means the argmax of the logits the trace committed to
(TraceLog.host_read), ties to the lowest token id, so every honest run picks the same
tokens. The answer is the token ids (answer_bytes: b"GEN" + u32 LE ids in the fingerprint)
and the logits hash covers every step's logits. Sampling is not offered: its host RNG would
have to be seeded from the job and committed to, and the trace would have to cover the
sampler's arithmetic, which runs on the host, not on Exact Core. Generate jobs are off-chain
for now: the Solana program's reveal takes a YES / NO answer.
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from .backend import SkipLayer, factory
from .trace import EVERY, UNBOUND, TraceLog, h

TINY = "tiny"                    # a small random Qwen3-style model: tests and the quick demo
KINDS = ("yesno", "generate")
GEN_TAG = b"GEN"                 # a generate job's answer in the fingerprint: GEN || u32 LE ids


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
    nonce: str = ""              # 32 random bytes (hex), chosen by new_job: in the digest
    every: int = EVERY           # steps between trace checkpoints: the trace's shape, so a
                                 # provider and a verifier must agree on it (in the digest)
    kind: str = "yesno"          # or "generate": greedy decoding of up to max_tokens tokens
    max_tokens: int = 0          # generate: tokens to decode at most (yesno: 0)
    stop_ids: list[int] = field(default_factory=list)   # generate: tokens that end the answer
                                 # (kept, as the answer's last token)

    def __post_init__(self):
        """Integral fields become plain ints (an np.int64 id would not serialize; a 3.0 would
        give another digest than 3), the rest must be strings: a job has one digest."""
        for k in ("yes_id", "no_id", "cap", "chunk", "every", "max_tokens"):
            setattr(self, k, _int(getattr(self, k), k))
        for k in ("prompt_ids", "stop_ids"):
            v = getattr(self, k)
            if isinstance(v, (str, bytes)) or not hasattr(v, "__iter__"):
                raise ValueError(f"{k} must be a list of token ids, not {v!r}")
            setattr(self, k, [_int(t, k) for t in v])
        for k in ("model", "question", "wformat", "job_id", "nonce", "kind"):
            if not isinstance(getattr(self, k), str):
                raise ValueError(f"{k} must be a string, not {getattr(self, k)!r}")
        if self.kind not in KINDS:
            raise ValueError(f"kind {self.kind!r} is not one of {KINDS}")

    @property
    def generate(self) -> bool:
        return self.kind == "generate"

    @property
    def digest(self) -> bytes:
        """H(the job's fields as sorted JSON, without job_id). A yes/no job's digest leaves
        out kind, max_tokens and stop_ids, so it is the digest it had before they existed
        (check() refuses a yes/no job that sets them)."""
        d = asdict(self)
        d.pop("job_id")
        d["model"] = model_name(self.model)
        if not self.generate:
            for k in ("kind", "max_tokens", "stop_ids"):
                d.pop(k)
        return h(json.dumps(d, sort_keys=True).encode())

    def check(self, vocab: int | None = None) -> None:
        """Raise ValueError for a job no run can answer right, before anyone spends a run on
        it: one token for both answers (it would always say NO), a prompt longer than the KV
        cache, token ids outside the model's vocabulary; for a generate job, no tokens to
        decode, or a prompt and answer longer than the KV cache."""
        if self.generate:
            if self.max_tokens < 1:
                raise ValueError(f"max_tokens {self.max_tokens}: a generate job decodes at "
                                 "least one token")
            if len(self.prompt_ids) + self.max_tokens > self.cap:
                raise ValueError(f"{len(self.prompt_ids)} prompt tokens and {self.max_tokens} "
                                 f"to generate do not fit a KV cache of {self.cap}")
        else:
            if self.max_tokens or self.stop_ids:
                raise ValueError("max_tokens and stop_ids are for generate jobs (kind "
                                 "\"generate\"), not yes/no ones")
            if self.yes_id == self.no_id:
                raise ValueError(f"the yes and no tokens are the same ({self.yes_id})")
        if not self.prompt_ids:
            raise ValueError("the prompt is empty")
        if self.chunk < 1:
            raise ValueError(f"chunk {self.chunk} is not a positive token count")
        if self.every < 1:
            raise ValueError(f"every {self.every} is not a positive step count")
        if len(self.prompt_ids) > self.cap:
            raise ValueError(f"{len(self.prompt_ids)} prompt tokens do not fit a KV cache of "
                             f"{self.cap}")
        ids = list(self.prompt_ids) + (list(self.stop_ids) if self.generate
                                       else [self.yes_id, self.no_id])
        bad = [t for t in ids if t < 0 or (vocab is not None and t >= vocab)]
        if bad:
            raise ValueError(f"token ids outside the vocabulary ({vocab}): {bad[:5]}")

    def check_nonce(self) -> bytes:
        """The nonce's bytes. A job without one (a file from before nonces) is refused: two
        such jobs with the same question would share a fingerprint."""
        try:
            n = bytes.fromhex(self.nonce)
        except ValueError:
            n = b""
        if len(n) != NONCE:
            raise ValueError(f"job {self.job_id or '-'} has no {NONCE}-byte nonce (a job file "
                             "from before nonces?): open it again with `tdcc-exact job new`")
        return n

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=1))

    @staticmethod
    def load(path) -> "Job":
        return _load(Job, path)


def _int(v, what: str) -> int:
    """An integral value (int, numpy integer) as int; bool, float and the rest refused."""
    import numbers
    if isinstance(v, (bool, np.bool_)) or not isinstance(v, numbers.Integral):
        raise ValueError(f"{what}: {v!r} is not an integer")
    return int(v)


def is_tiny(model: str) -> bool:
    """The built-in random model: "tiny" or "tiny:<seed>" (not every name starting "tiny")."""
    if model == TINY:
        return True
    if not model.startswith(TINY + ":"):
        return False
    if not model[len(TINY) + 1:].isdigit():
        raise ValueError(f"{model}: the tiny model's seed is a number (tiny:0, tiny:1, ...)")
    return True


NONCE = 32                       # bytes


def new_nonce() -> str:
    return os.urandom(NONCE).hex()


def model_name(model: str) -> str:
    """A job's model by name (the directory's last part): the image hash pins the weights."""
    return model if is_tiny(model) else Path(model).name


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
    binding: str = ""            # the run's binding (hex): informative, a verifier re-runs with
                                 # the on-chain job's own

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=1))

    @staticmethod
    def load(path) -> "Receipt":
        return _load(Receipt, path)


def _read_json(path, what: str):
    try:
        return json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: not a {what} (bad JSON: {e})") from None


def _load(cls, path):
    """A Job or Receipt file, with a message naming the file and the fields when it is not one."""
    d = _read_json(path, cls.__name__.lower())
    try:
        return cls(**d)
    except TypeError:
        names = set(cls.__dataclass_fields__)
        req = {k for k, f in cls.__dataclass_fields__.items()
               if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING}
        got = set(d) if isinstance(d, dict) else set()
        raise ValueError(f"{path}: not a {cls.__name__.lower()} file (missing "
                         f"{sorted(req - got)}, unknown {sorted(got - names)})") from None


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
    if is_tiny(model):
        return tiny_model(int(model.split(":")[1]) if ":" in model else 0)
    from opentpu.llm import load_spec
    from opentpu.llm.qwen3 import load_weights
    return load_spec(model), load_weights(model)


def layers_of(spec) -> int:
    return getattr(spec, "layers", None) or len(getattr(spec, "kinds", ())) or 1


# ------------------------------------------------------------------------------- jobs
def new_job(model: str, question: str, job_id: str = "", every: int = EVERY,
            kind: str = "yesno", max_tokens: int = 16, stop_ids=None) -> Job:
    """An oracle job: the question in the model's chat template, answered Yes or No (every:
    the trace's checkpoint interval). kind "generate": the question in the chat template
    with no system line, answered by up to max_tokens greedily decoded tokens, stopping at
    stop_ids (default: the tokenizer's end-of-sequence tokens; the tiny model: none)."""
    if kind not in KINDS:
        raise ValueError(f"kind {kind!r} is not one of {KINDS}")
    gen = kind == "generate"
    if is_tiny(model):
        ids = [1 + (b % 500) for b in question.encode()][:24] or [1]
        if gen:
            return Job(model, ids, 0, 0, question=question, job_id=job_id,
                       nonce=new_nonce(), every=every, kind=kind, max_tokens=max_tokens,
                       stop_ids=list(stop_ids or []))
        return Job(model, ids, yes_id=3, no_id=4, question=question, job_id=job_id,
                   nonce=new_nonce(), every=every)
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model)
    if gen:
        ids = tok.apply_chat_template([{"role": "user", "content": question}],
                                      add_generation_prompt=True, tokenize=True)
        ids = list(ids["input_ids"] if hasattr(ids, "keys") else ids)
        if stop_ids is None:
            eos = tok.eos_token_id
            stop_ids = [] if eos is None else ([eos] if isinstance(eos, int) else list(eos))
        return Job(model, ids, 0, 0, question=question, job_id=job_id, nonce=new_nonce(),
                   every=every, kind=kind, max_tokens=max_tokens, stop_ids=list(stop_ids))
    msg = [{"role": "system", "content": "Answer with exactly one word: Yes or No."},
           {"role": "user", "content": question}]
    ids = tok.apply_chat_template(msg, add_generation_prompt=True, tokenize=True)
    ids = list(ids["input_ids"] if hasattr(ids, "keys") else ids)
    # LFM2.5: "Yes" = 12948 and "No" = 5048, one token each (as the assistant's turn starts,
    # without a leading space). A tokenizer that splits them: their first tokens, which differ
    yes, no = (tok.encode(w, add_special_tokens=False) for w in ("Yes", "No"))
    if yes[0] == no[0]:
        raise ValueError(f"{model}: 'Yes' / 'No' start with the same token ({yes}, {no})")
    return Job(model, ids, yes[0], no[0], question=question, job_id=job_id, nonce=new_nonce(),
               every=every)


@dataclass
class Run:
    receipt: Receipt
    log: TraceLog
    logits: np.ndarray           # the last logits (a generate job's: its last step's)
    tokens: list = field(default_factory=list)      # a generate job's answer
    token_cps: list = field(default_factory=list)   # a generate job: the checkpoint count
                                 # once token i's logits were read (token i goes to the
                                 # device in the run after that: TraceLog checkpoints)


def greedy(logits, vocab: int | None = None) -> int:
    """The argmax over the model's vocabulary, ties to the lowest token id (np.argmax's
    first maximum)."""
    v = np.asarray(logits, np.float32).reshape(-1)
    return int(np.argmax(v[:vocab] if vocab else v))


def gen_answer(ids) -> str:
    """A generate job's answer as a receipt keeps it: "GEN:" and the ids, comma-separated."""
    return "GEN:" + ",".join(str(int(t)) for t in ids)


def answer_ids(answer: str) -> list[int] | None:
    """The token ids of a generate answer (None: not a canonical gen_answer string)."""
    if not answer.startswith("GEN:"):
        return None
    try:
        ids = [int(t) for t in answer[4:].split(",")] if answer[4:] else []
    except ValueError:
        return None
    if gen_answer(ids) != answer or any(not 0 <= t < 2 ** 32 for t in ids):
        return None
    return ids


def answer_bytes(answer: str) -> bytes:
    """What the fingerprint hashes for an answer: YES / NO as they are; a generate answer as
    b"GEN" + each id as a u32 LE. A string that is neither (a malformed receipt) hashes as
    its own text, which no honest run's fingerprint matches."""
    ids = answer_ids(answer)
    if ids is None:
        return answer.encode()
    return GEN_TAG + np.asarray(ids, "<u4").tobytes()


class StopEarly:
    """A generating provider's shortcut: stop after `after` tokens, as if a stop token came
    (fewer decode runs). Its trace is honest about what it ran, so it ends early."""

    def __init__(self, after: int):
        self.after = int(after)

    def pick(self, i: int, honest: int) -> int | None:
        return None if i >= self.after else honest


class WrongToken:
    """A generating provider's shortcut or slip: at token `at`, emit `token` (default: the
    honest one + 1) instead of the argmax, and go on decoding from it."""

    def __init__(self, at: int, token: int | None = None):
        self.at, self.token = int(at), token

    def pick(self, i: int, honest: int) -> int | None:
        if i != self.at:
            return honest
        return honest + 1 if self.token is None else int(self.token)


GEN_CHEATS = (StopEarly, WrongToken)


def build_hash(model: str, wformat: str = "int8", cap: int = 256, loaded=None) -> str:
    """The image hash a model build gets (what the registry pins), without running anything."""
    from opentpu.llm.qwen3 import Engine
    spec, W = loaded if loaded is not None else load_model(model)
    eng = Engine(spec, W, cap=cap, backend=factory(TraceLog()), wformat=wformat, pipeline=False)
    return eng.backend.model_hash.hex()


def as_binding(binding) -> bytes:
    """32 bytes from bytes, a hex string or None (UNBOUND: a run tied to no job)."""
    if binding is None:
        return UNBOUND
    b = bytes.fromhex(binding) if isinstance(binding, str) else bytes(binding)
    if len(b) != 32:
        raise ValueError(f"a binding is 32 bytes (the job account's address), not {len(b)}")
    return b


def check_build(job: Job, model_hash: str) -> None:
    """Raise if the job's model is registered and this build's image hash is not the pinned
    one: the job says int8, but the environment (OTPU_FORMATS, OTPU_MLP_UNROLL_BODIES, other
    OTPU_* settings) or the weights built another image, whose run no one else would match.
    Providers and verifiers alike check before spending a run."""
    from . import registry
    why = registry.check(job, model_hash)
    if why is not None and "not registered" not in why:
        raise ValueError(f"{why}: this build of {model_name(job.model)} ({job.wformat}, cap "
                         f"{job.cap}) is not the registered one; are OTPU_FORMATS, "
                         "OTPU_MLP_UNROLL_BODIES or other OTPU_* environment variables set?")


def job_every(job: Job, every: int | None) -> int:
    """The job's checkpoint interval; `every`, if given, must be it (a trace at another
    interval has other checkpoints, so it could never match the job's)."""
    if every is not None and int(every) != job.every:
        raise ValueError(f"checkpoints every {every} steps, but the job says every "
                         f"{job.every} (the interval is part of the job)")
    return job.every


def run_job(job: Job, provider: str = "local", cheat: SkipLayer | None = None,
            every: int | None = None, window=None, model=None, binding=None,
            reveal: int | None = None, check_registry: bool = True) -> Run:
    """Run `job` on a traced Exact Core simulator (cheat: a dishonest provider's shortcut;
    every: None, or the job's own checkpoint interval (another is an error); window:
    (lo, hi], record each step there for a dispute; reveal: a checkpoint index, record
    every event up to it in log.events, for dispute.verify_window; binding: the
    on-chain job account's 32-byte address, the trace's first input; None: UNBOUND, for
    local tries only; check_registry: refuse a build whose image hash is not the registered
    one, before running anything; tests of other weights turn it off)."""
    from opentpu.llm.qwen3 import Engine    # (every Spec's engine: Qwen3, LFM2, ...)
    gen_cheat = cheat if isinstance(cheat, GEN_CHEATS) else None
    if gen_cheat is not None:
        if not job.generate:
            raise ValueError(f"{type(cheat).__name__} is a cheat for generate jobs")
        cheat = None
    job.check_nonce()
    every = job_every(job, every)
    bind = as_binding(binding)
    spec, W = model if model is not None else load_model(job.model)
    job.check(getattr(spec, "vocab", None))
    log = TraceLog(every=every, window=window, binding=bind, reveal=reveal)
    eng = Engine(spec, W, cap=job.cap, backend=factory(log, cheat), wformat=job.wformat,
                 rows=job.chunk, pipeline=False)
    if check_registry:
        check_build(job, eng.backend.model_hash.hex())
    logits = eng.prefill([int(t) for t in job.prompt_ids], chunk=job.chunk)
    logits = np.asarray(logits, np.float32).reshape(-1)
    tokens, token_cps = [], []
    if job.generate:
        vocab = getattr(spec, "vocab", None)
        steps = [logits]                    # every step's logits, in the logits hash
        for i in range(job.max_tokens):
            token_cps.append(len(log.checkpoints))
            t = greedy(logits, vocab)
            if gen_cheat is not None:
                t = gen_cheat.pick(i, t)
                if t is None:
                    break
            tokens.append(t)
            if t in job.stop_ids or i == job.max_tokens - 1:
                break
            logits = np.asarray(eng.step(t), np.float32).reshape(-1)
            steps.append(logits)
        answer = gen_answer(tokens)
        lh = h(*[x.tobytes() for x in steps])
    else:
        answer = "YES" if logits[job.yes_id] > logits[job.no_id] else "NO"
        lh = h(logits.tobytes())
    log.finish(eng.backend.machine.slices)  # (after the logits were read back)
    mh, root = eng.backend.model_hash, log.root
    fp = h(job.digest, mh, answer_bytes(answer), lh, root)  # (fingerprint(): the same formula)
    extra = {"skipped_mms": cheat.skipped} if cheat is not None else {}
    rec = Receipt(job.job_id, provider, answer, mh.hex(), lh.hex(), root.hex(), log.step,
                  len(log.checkpoints), fp.hex(), extra, bind.hex())
    return Run(rec, log, logits, tokens, token_cps)


def fingerprint(job: Job, rec: Receipt) -> str:
    """The fingerprint a receipt's own fields give (what the program recomputes)."""
    return h(job.digest, bytes.fromhex(rec.model_hash), answer_bytes(rec.answer),
             bytes.fromhex(rec.logits_hash), bytes.fromhex(rec.trace_root)).hex()


def save_trace(log: TraceLog, path) -> None:
    Path(path).write_text(json.dumps(log.to_json()))


def load_trace(path) -> dict:
    t = _read_json(path, "trace")
    if not isinstance(t, dict) or not isinstance(t.get("checkpoints"), list):
        raise ValueError(f"{path}: not a trace file (no checkpoint list)")
    return t
