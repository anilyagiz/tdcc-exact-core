"""Choose the trace's checkpoint interval (Job.every) from measurements.

For each interval: one honest run (its time, steps, checkpoints and trace file size), then a
dispute against a provider that skips the last layer's matrix multiplies: the bisection's
rounds, the window it lands on (steps), the provider's revealed window (records, JSON bytes)
and the time of the two window replays (the provider's with every event revealed, the
verifier's with a state hash per step).

    python tools/checkpoint_bench.py                  # the tiny model: a yes/no and a generate job
    python tools/checkpoint_bench.py --every 1024 4096 --tokens 64

LFM2.5-230M is added when models/LFM2.5-230M exists (--no-lfm to leave it out).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tdcc_exact.backend import SkipLayer  # noqa: E402
from tdcc_exact.commit import provider_key  # noqa: E402
from tdcc_exact.dispute import bisect  # noqa: E402
from tdcc_exact.oracle import (Job, layers_of, load_model, new_job, run_job,  # noqa: E402
                               save_trace)
from tdcc_exact.trace import record_to_json  # noqa: E402

EVERYS = (512, 1024, 2048, 4096, 8192, 16384)
LFM = Path(__file__).resolve().parents[1] / "models" / "LFM2.5-230M"
BIND = provider_key("A")
QUESTION = "Is Paris the capital of France?"


def measure(job: Job, model, every: int, pinned: bool = True) -> dict:
    job = Job(**{**job.__dict__, "every": every})
    kw = dict(model=model, binding=BIND, check_registry=pinned)
    t0 = time.perf_counter()
    a = run_job(job, "A", **kw)
    t_run = time.perf_counter() - t0
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "trace.json"
        save_trace(a.log, p)
        trace_bytes = p.stat().st_size
    cheat = lambda: SkipLayer(layers_of(model[0]) - 1, layers_of(model[0]))  # noqa: E731
    b = run_job(job, "B", cheat(), **kw)
    dv = bisect(a.log.checkpoints, b.log.checkpoints)
    w = (dv.lo, dv.hi)
    t0 = time.perf_counter()
    prov = run_job(job, "B", cheat(), window=w, reveal=dv.index, **kw)
    t_prov = time.perf_counter() - t0
    t0 = time.perf_counter()
    run_job(job, "verifier", window=w, **kw)
    t_ver = time.perf_counter() - t0
    reveal = json.dumps([record_to_json(r) for r in prov.log.events])
    return {"every": every, "run_s": t_run, "steps": a.log.step,
            "checkpoints": len(a.log.checkpoints), "trace_bytes": trace_bytes,
            "rounds": dv.rounds, "window_steps": dv.hi - dv.lo,
            "reveal_records": len(prov.log.events), "reveal_bytes": len(reveal),
            "replay_s": t_prov + t_ver}


def table(name: str, rows: list[dict]) -> str:
    out = [f"\n{name}",
           "| every | run (s) | steps | checkpoints | trace (B) | rounds | window (steps) | "
           "reveal (records / KB) | 2 replays (s) |",
           "|--:|--:|--:|--:|--:|--:|--:|--:|--:|"]
    for r in rows:
        out.append(f"| {r['every']} | {r['run_s']:.1f} | {r['steps']} | {r['checkpoints']} | "
                   f"{r['trace_bytes']} | {r['rounds']} | {r['window_steps']} | "
                   f"{r['reveal_records']} / {r['reveal_bytes'] / 1024:.0f} | "
                   f"{r['replay_s']:.1f} |")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--every", type=int, nargs="+", default=list(EVERYS))
    p.add_argument("--tokens", type=int, default=32, help="the generate job's max_tokens")
    p.add_argument("--no-lfm", action="store_true")
    p.add_argument("--json", help="write the rows here too")
    a = p.parse_args(argv)
    tiny = load_model("tiny")
    # the tiny model's prompt runs are short (about 1300 steps in runs of 8 tokens); a long
    # prompt in runs of 64 gives runs of about 9300 steps, so the larger intervals show (an
    # image with 64 rows is not the registered tiny build: unpinned)
    long = Job(**{**new_job("tiny", QUESTION).__dict__,
                  "prompt_ids": [1 + (i * 7) % 500 for i in range(128)], "chunk": 64})
    jobs = [("tiny, yes/no", new_job("tiny", QUESTION), tiny, True),
            (f"tiny, generate {a.tokens} tokens",
             new_job("tiny", QUESTION, kind="generate", max_tokens=a.tokens), tiny, True),
            ("tiny, yes/no, 128 tokens in runs of 64", long, tiny, False)]
    if LFM.is_dir() and not a.no_lfm:
        jobs.append(("LFM2.5-230M, yes/no", new_job(str(LFM), QUESTION), load_model(str(LFM)),
                     True))
    results = {}
    for name, job, model, pinned in jobs:
        rows = []
        for e in a.every:
            rows.append(measure(job, model, e, pinned))
            print(f"{name}: every {e}: {rows[-1]}", file=sys.stderr, flush=True)
        results[name] = rows
        print(table(name, rows), flush=True)
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
