"""How good is the yes/no oracle? Decision rules and prompt formats on the fp32 reference.

    python3 tools/oracle_eval.py --model models/LFM2.5-230M [--ref hf|numpy]
                                 [--questions tests/data/oracle_questions.jsonl]
                                 [--formats job,nosys,completion,fewshot] [--seed 0] [--json OUT]
    python3 tools/oracle_eval.py --selftest

For each prompt format, every question is run through the fp32 reference (Hugging Face
transformers by default; --ref numpy uses openTPU's own numpy reference, no torch needed) and
the oracle's margin m = logit[Yes] - logit[No] after the last prompt token is recorded. The
questions are split, seeded and stratified by answer, into a training half and a test half.
Three decision rules, all "Yes iff m - offset > 0" (a tie is No, as in run_job):

    raw     offset 0: today's rule (tdcc_exact.oracle.run_job)
    cf      offset = the margin on a content-free question ("N/A") in the same format
    median  offset = the median margin over the training half (label-free)

Accuracies are on the test half (the offsets never see it); "raw" is also reported on all
questions. AUC is the fraction of (Yes, No) question pairs whose Yes question has the larger
margin: the ceiling of any offset rule, i.e. how much the margin knows at all.

Formats:
    job         exactly the job's token ids (tdcc_exact.oracle.new_job): chat template with
                the system line "Answer with exactly one word: Yes or No." and the question
    nosys       chat template, the question as the only (user) turn
    completion  no chat template: "Question: <q>\\nAnswer (Yes or No):", answer tokens " Yes" /
                " No" (with the leading space a plain-text continuation has)
    fewshot     the job's system line, then two worked turns (one Yes, one No), then the question
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SYSTEM = "Answer with exactly one word: Yes or No."
CONTENT_FREE = "N/A"
SHOTS = [("Is ice frozen water?", "Yes"), ("Is the Moon larger than the Earth?", "No")]
FORMATS = ("job", "nosys", "completion", "fewshot")
RULES = ("raw", "cf", "median")


# ------------------------------------------------------------------------------- rule logic
def load_questions(path) -> list[dict]:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    for r in rows:
        if r.get("a") not in ("Yes", "No") or not r.get("q"):
            raise ValueError(f"bad question row: {r}")
    return rows


def split(labels, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """(train, test) index arrays: each class shuffled with `seed` and halved (train gets the
    smaller half of an odd class), so both halves keep the Yes/No balance."""
    labels = np.asarray(labels, bool)
    rng = np.random.default_rng(seed)
    tr, te = [], []
    for cls in (True, False):
        idx = np.flatnonzero(labels == cls)
        idx = idx[rng.permutation(len(idx))]
        k = len(idx) // 2
        tr += list(idx[:k])
        te += list(idx[k:])
    return np.sort(np.array(tr, int)), np.sort(np.array(te, int))


def decide(margins, offset: float = 0.0) -> np.ndarray:
    """The oracle's answer, True = Yes: margin - offset > 0 (a tie is No, as in run_job)."""
    return np.asarray(margins, np.float64) - offset > 0


def offsets(margins, train, cf_margin: float | None) -> dict[str, float]:
    m = np.asarray(margins, np.float64)
    out = {"raw": 0.0, "median": float(np.median(m[train]))}
    if cf_margin is not None:
        out["cf"] = float(cf_margin)
    return out


def scores(pred, labels) -> dict:
    pred, labels = np.asarray(pred, bool), np.asarray(labels, bool)
    ok = pred == labels
    return {"n": int(len(labels)), "acc": float(ok.mean()),
            "yes_acc": float(ok[labels].mean()) if labels.any() else float("nan"),
            "no_acc": float(ok[~labels].mean()) if (~labels).any() else float("nan"),
            "said_yes": int(pred.sum())}


def auc(margins, labels) -> float:
    """P(margin of a Yes question > margin of a No question), ties counting one half."""
    m, labels = np.asarray(margins, np.float64), np.asarray(labels, bool)
    y, n = m[labels][:, None], m[~labels][None, :]
    return float(((y > n).sum() + 0.5 * (y == n).sum()) / (y.size * n.size))


def margin_stats(margins, labels) -> dict:
    m, labels = np.asarray(margins, np.float64), np.asarray(labels, bool)

    def st(x):
        return {"mean": float(x.mean()), "min": float(x.min()), "median": float(np.median(x)),
                "max": float(x.max())}
    return {"yes": st(m[labels]), "no": st(m[~labels])}


def evaluate(margins, labels, cf_margin: float | None, seed: int = 0) -> dict:
    """Every rule's scores for one format's margins."""
    labels = np.asarray(labels, bool)
    train, test = split(labels, seed)
    offs = offsets(margins, train, cf_margin)
    m = np.asarray(margins, np.float64)
    res = {"offsets": offs, "auc": auc(m, labels), "margins": margin_stats(m, labels),
           "cf_margin": cf_margin, "raw_all": scores(decide(m), labels), "test": {}}
    for rule, off in offs.items():
        res["test"][rule] = scores(decide(m[test], off), labels[test])
    return res


# ------------------------------------------------------------------------------- prompts
class Prompts:
    """Token ids and answer ids of a question in each format, for one checkpoint."""

    def __init__(self, model: str):
        from transformers import AutoTokenizer
        self.model = model
        self.tok = AutoTokenizer.from_pretrained(model)

    def _chat(self, msgs) -> list[int]:
        ids = self.tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=True)
        return list(ids["input_ids"] if hasattr(ids, "keys") else ids)

    def _first(self, word: str) -> int:
        return self.tok.encode(word, add_special_tokens=False)[0]

    def build(self, fmt: str, q: str) -> tuple[list[int], int, int]:
        if fmt == "job":
            from tdcc_exact.oracle import new_job
            job = new_job(self.model, q)
            return list(job.prompt_ids), job.yes_id, job.no_id
        yes, no = self._first("Yes"), self._first("No")
        if fmt == "nosys":
            return self._chat([{"role": "user", "content": q}]), yes, no
        if fmt == "fewshot":
            msgs = [{"role": "system", "content": SYSTEM}]
            for sq, sa in SHOTS:
                msgs += [{"role": "user", "content": sq}, {"role": "assistant", "content": sa}]
            return self._chat(msgs + [{"role": "user", "content": q}]), yes, no
        if fmt == "completion":
            ids = self.tok.encode(f"Question: {q}\nAnswer (Yes or No):", add_special_tokens=True)
            y, n = self._first(" Yes"), self._first(" No")
            if y == n:
                raise ValueError("' Yes' / ' No' start with the same token")
            return list(ids), y, n
        raise ValueError(f"unknown format {fmt!r}")


# ------------------------------------------------------------------------------- references
def hf_ref(model: str):
    import torch
    from transformers import AutoModelForCausalLM
    torch.manual_seed(0)
    m = AutoModelForCausalLM.from_pretrained(model, torch_dtype=torch.float32).eval()

    def last_logits(ids) -> np.ndarray:
        with torch.no_grad():
            out = m(torch.tensor([ids], dtype=torch.long))
        return out.logits[0, -1].float().numpy()
    return last_logits


def numpy_ref(model: str):
    from tdcc_exact.oracle import load_model
    spec, W = load_model(model)
    ref = importlib.import_module(type(spec).__module__).reference_logits

    def last_logits(ids) -> np.ndarray:
        return np.asarray(ref(spec, W, ids), np.float32)[-1]
    return last_logits


def run(model: str, questions, formats, ref: str, seed: int, log=print) -> dict:
    prompts = Prompts(model)
    fwd = hf_ref(model) if ref == "hf" else numpy_ref(model)
    labels = np.array([r["a"] == "Yes" for r in questions])
    out = {"model": model, "ref": ref, "seed": seed, "n": len(questions), "formats": {}}
    for fmt in formats:
        def margin(q):
            ids, y, n = prompts.build(fmt, q)
            lg = fwd(ids)
            return float(lg[y]) - float(lg[n]), len(ids), (y, n)
        cf, _, ans = margin(CONTENT_FREE)
        ms, lens = [], []
        for i, r in enumerate(questions):
            mg, L, _ = margin(r["q"])
            ms.append(mg)
            lens.append(L)
            log(f"  {fmt:10s} {i + 1:3d}/{len(questions)} {r['a']:3s} margin {mg:+7.3f}  {r['q']}")
        res = evaluate(ms, labels, cf, seed)
        res.update({"answer_ids": ans, "prompt_tokens": [min(lens), max(lens)],
                    "per_question": [{"q": r["q"], "a": r["a"], "margin": mg}
                                     for r, mg in zip(questions, ms)]})
        out["formats"][fmt] = res
    return out


def table(out: dict) -> str:
    hdr = (f"{'format':10s} {'rule':6s} {'offset':>7s} {'test acc':>9s} {'Yes acc':>8s} "
           f"{'No acc':>7s} {'AUC':>5s}  {'all raw':>10s}")
    lines = [hdr, "-" * len(hdr)]
    for fmt, r in out["formats"].items():
        for rule in RULES:
            if rule not in r["test"]:
                continue
            s = r["test"][rule]
            lines.append(f"{fmt:10s} {rule:6s} {r['offsets'][rule]:+7.2f} "
                         f"{s['acc']:9.1%} {s['yes_acc']:8.1%} {s['no_acc']:7.1%} "
                         f"{r['auc']:5.2f}  {r['raw_all']['acc']:10.1%}")
    lines += ["", f"{'format':10s} {'class':5s} {'mean':>7s} {'min':>7s} {'median':>7s} "
                  f"{'max':>7s}   (margin = logit Yes - logit No; cf = content-free margin)"]
    for fmt, r in out["formats"].items():
        for cls in ("yes", "no"):
            s = r["margins"][cls]
            lines.append(f"{fmt:10s} {cls:5s} {s['mean']:+7.2f} {s['min']:+7.2f} "
                         f"{s['median']:+7.2f} {s['max']:+7.2f}")
        lines.append(f"{fmt:10s} {'cf':5s} {r['cf_margin']:+7.2f}")
    return "\n".join(lines)


# ------------------------------------------------------------------------------- self-test
def selftest() -> None:
    labels = np.array([True, False] * 10 + [True])          # 11 Yes, 10 No
    tr, te = split(labels, 0)
    assert len(np.intersect1d(tr, te)) == 0 and len(tr) + len(te) == len(labels)
    assert labels[tr].sum() == 5 and labels[te].sum() == 6   # stratified; odd class: test +1
    assert (~labels[tr]).sum() == 5 and (~labels[te]).sum() == 5
    assert all((a == b).all() for a, b in zip(split(labels, 0), (tr, te)))     # deterministic
    assert any((a != b).any() for a, b in zip(split(labels, 1), (tr, te)))     # seed matters

    # A model that always says Yes, but whose margin still ranks the classes (doc section 8)
    m = np.where(labels, 6.0, 5.0) + np.linspace(-0.2, 0.2, len(labels))
    assert decide(m).all()                                    # raw: Yes to everything
    assert decide([0.0, 1e-9, -1e-9]).tolist() == [False, True, False]   # tie is No
    r = evaluate(m, labels, cf_margin=5.5, seed=0)
    assert r["test"]["raw"]["yes_acc"] == 1.0 and r["test"]["raw"]["no_acc"] == 0.0
    assert r["test"]["cf"]["acc"] == 1.0                      # offset 5.5 splits 5±.2 / 6±.2
    assert r["auc"] == 1.0
    assert 5.0 < r["offsets"]["median"] < 6.0
    assert r["test"]["median"]["acc"] >= 0.8
    assert r["raw_all"]["said_yes"] == len(labels)

    assert auc([1, 1], [True, False]) == 0.5 and auc([0, 1], [True, False]) == 0.0
    s = scores([True, True, False, False], [True, False, False, True])
    assert s == {"n": 4, "acc": 0.5, "yes_acc": 0.5, "no_acc": 0.5, "said_yes": 2}
    st = margin_stats([1, 2, 3, 10], [True, True, True, False])
    assert st["yes"]["median"] == 2 and st["no"]["max"] == 10

    # the questions file: balanced, unique, and the few-shot examples are not among them
    qs = load_questions(ROOT / "tests/data/oracle_questions.jsonl")
    ys = sum(q["a"] == "Yes" for q in qs)
    assert len(qs) >= 60 and ys * 2 == len(qs), (len(qs), ys)
    assert len({q["q"] for q in qs}) == len(qs)
    assert not {q for q, _ in SHOTS} & {q["q"] for q in qs}
    print(table({"formats": {"fake": r}}))
    print("selftest ok")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", default=str(ROOT / "models" / "LFM2.5-230M"))
    ap.add_argument("--ref", choices=("hf", "numpy"), default="hf")
    ap.add_argument("--questions", default=str(ROOT / "tests/data/oracle_questions.jsonl"))
    ap.add_argument("--formats", default=",".join(FORMATS))
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--json", help="also write the full results (per-question margins) here")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="test the rule logic on fake margins")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if not (Path(a.model) / "config.json").exists():
        sys.exit(f"{a.model}: no checkpoint (hf download LiquidAI/LFM2.5-230M --local-dir ...)")
    fmts = [f for f in a.formats.split(",") if f]
    bad = set(fmts) - set(FORMATS)
    if bad:
        sys.exit(f"unknown formats {sorted(bad)}; known: {', '.join(FORMATS)}")
    out = run(a.model, load_questions(a.questions), fmts, a.ref, a.seed,
              log=(lambda *_: None) if a.quiet else print)
    print(table(out))
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
