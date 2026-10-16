"""TDCC Exact's trace engine in RTL (rtl/exact/, docs/exact-rtl.md) against tdcc_exact/trace.py.

exact_sha256 on the NIST vectors and on every padding case (lengths 0..200 bytes); exact_trace
fed every event of a tiny-model oracle run (its binding, steps, host writes and reads, run
starts and checkpoint folds, in TraceLog's order) must give TraceLog's chain after every one,
bit for bit. Verilator (--binary) runs the testbenches, Icarus Verilog if Verilator is missing;
the tests skip without either (EXACT_RTL_SIM=iverilog picks Icarus).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest

from tdcc_exact import trace
from tdcc_exact.trace import Event, StepRecord, TraceLog, chain_start

ROOT = Path(__file__).resolve().parents[1]
RTL = ROOT / "rtl" / "exact"
SRC = [RTL / "exact_sha256.sv", RTL / "exact_trace.sv"]


def _simulator() -> str | None:
    want = os.environ.get("EXACT_RTL_SIM")          # "verilator" or "iverilog": only that one
    if want:
        return want if shutil.which(want) else None
    if shutil.which("verilator"):
        return "verilator"
    if shutil.which("iverilog") and shutil.which("vvp"):
        return "iverilog"
    return None


def _build(top: str, srcs: list[Path], out: Path) -> list[str]:
    """Compile testbench `top`; the command that runs it (without +in)."""
    sim = _simulator()
    if sim is None:
        pytest.skip("neither verilator nor iverilog installed")
    out.mkdir(parents=True, exist_ok=True)
    if sim == "verilator":
        cmd = ["verilator", "--binary", "--timing", "-Wno-fatal", "-Wno-lint", "-Wno-style",
               "-O2", "--top-module", top, "-Mdir", str(out), "-o", top, *map(str, srcs)]
        exe = [str(out / top)]
    else:
        vvp = out / f"{top}.vvp"
        cmd = ["iverilog", "-g2012", "-s", top, "-o", str(vvp), *map(str, srcs)]
        exe = ["vvp", "-n", str(vvp)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, f"{sim} build failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}"
    return exe


def _run(exe: list[str], infile: Path) -> list[str]:
    r = subprocess.run([*exe, f"+in={infile}"], capture_output=True, text=True, timeout=900)
    assert r.returncode == 0 and "fatal" not in r.stdout.lower(), r.stdout[-3000:] + r.stderr
    return r.stdout.splitlines()


@pytest.fixture(scope="module")
def sha_tb(tmp_path_factory):
    return _build("exact_sha256_tb", [RTL / "exact_sha256.sv", RTL / "tb" / "exact_sha256_tb.sv"],
                  tmp_path_factory.mktemp("sha"))


@pytest.fixture(scope="module")
def trace_tb(tmp_path_factory):
    return _build("exact_trace_tb", [*SRC, RTL / "tb" / "exact_trace_tb.sv"],
                  tmp_path_factory.mktemp("trace"))


# ----------------------------------------------------------------------------- SHA-256
def _msg_line(m: bytes) -> str:
    pad = m + bytes(-len(m) % 4) if m else bytes(4)
    words = np.frombuffer(pad, ">u4")
    return f"{len(m)} " + " ".join(f"{int(w):08x}" for w in words)


NIST = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",      # 448 bits: 2 blocks
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
     b"klmnopqrlmnopqrsmnopqrstnopqrstu",                               # 896 bits
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
]


def test_sha256_nist_vectors_rtl(sha_tb, tmp_path):
    f = tmp_path / "nist.txt"
    f.write_text("\n".join(_msg_line(m) for m, _ in NIST) + "\n")
    got = [x.split()[1] for x in _run(sha_tb, f) if x.startswith("D ")]
    assert got == [d for _, d in NIST]


def test_sha256_every_padding_case_rtl(sha_tb, tmp_path):
    """Lengths 0..200: the 0x80 in the last data word or a word of its own, the length in the
    same block or the next (55, 56, 63, 64 bytes ...), up to four blocks."""
    rng = np.random.default_rng(5)
    msgs = [rng.integers(0, 256, n, dtype=np.uint8).tobytes() for n in range(201)]
    f = tmp_path / "pad.txt"
    f.write_text("\n".join(_msg_line(m) for m in msgs) + "\n")
    lines = _run(sha_tb, f)
    got = [x.split()[1] for x in lines if x.startswith("D ")]
    assert got == [hashlib.sha256(m).hexdigest() for m in msgs]
    cyc = [int(x.split()[1]) for x in lines if x.startswith("CYCLES ")]
    assert cyc[134] <= 3 * 66 + 24, cyc[134]       # a step's message: 3 blocks


# ----------------------------------------------------------------------------- the trace
def _le_words(b: bytes, n: int) -> list[int]:
    b = b + bytes(4 * n - len(b))
    return [int(w) for w in np.frombuffer(b, "<u4")]


def _hexs(ws) -> str:
    return " ".join(f"{w:x}" for w in ws)


def _payload(r: Event) -> bytes:
    parts = [bytes.fromhex(x) for x in r.data]
    return trace.h(*parts) if r.kind == "C" else b"".join(parts)


def _commands(binding: bytes, every: int, records, late: int = 0) -> str:
    """The testbench's command file for TraceLog records (StepRecords and Events, in order).
    late: post each pause's checkpoint (the C right after a step whose count is a multiple of
    `every`) only after the next `late` steps were pushed (at most the FIFO's depth), so they
    wait in the FIFO: the engine must still hash the C first."""
    out = [f"I {_hexs(_le_words(binding, 8))}", f"E {every:x}"]
    held, wait, prev = None, 0, None
    for r in records:
        if isinstance(r, StepRecord):
            w, g = bytes.fromhex(r.words), bytes.fromhex(r.regs)
            out.append(f"S {r.slice:x} {r.pc:x} {_hexs(_le_words(w, 8))} {_hexs(_le_words(g, 16))}")
            if held is not None:
                wait -= 1
                if wait == 0:
                    out.append(held)
                    held = None
        else:
            p = _payload(r)
            assert len(p) <= 64, (r.kind, len(p))
            line = f"A {ord(r.kind):x} {len(p):x} {_hexs(_le_words(p, 16))}"
            if held is not None:
                out.append(held)
                held = None
            if (late and r.kind == "C" and isinstance(prev, StepRecord)
                    and prev.step % every == 0):
                held, wait = line, late
            else:
                out.append(line)
        prev = r
    if held is not None:
        out.append(held)
    out.append("Q")
    return "\n".join(out) + "\n"


@pytest.fixture(scope="module")
def tiny_run():
    """Every event of a tiny-model oracle job (two slices, 3,666 steps, a checkpoint every 512
    steps and at the runs' ends), recorded as TraceLog reveals a window: here the whole run."""
    from tdcc_exact.oracle import new_job, run_job, tiny_model
    every = 512
    binding = bytes(range(1, 33))
    job = new_job("tiny", "Will it rain tomorrow?", "rtl", every=every)
    old = TraceLog._revealing
    TraceLog._revealing = lambda self: True          # record every event, not one window's
    try:
        run = run_job(job, "A", every=every, model=tiny_model(), binding=binding)
    finally:
        TraceLog._revealing = old
    return binding, every, run.log


def test_trace_engine_matches_tracelog_every_event_rtl(trace_tb, tiny_run, tmp_path):
    binding, every, log = tiny_run
    recs = log.events
    kinds = {r.kind for r in recs if isinstance(r, Event)}
    assert {"W", "O", "R", "C"} <= kinds, kinds           # every event kind is exercised
    f = tmp_path / "cmds.txt"
    f.write_text(_commands(binding, every, recs, late=5))
    lines = _run(trace_tb, f)
    ups = [x.split() for x in lines if x.startswith("U ")]
    want = [chain_start(binding).hex()] + [r.chain for r in recs]
    got = [u[2] for u in ups]
    assert len(got) == len(want), (len(got), len(want))
    bad = next((i for i, (a, b) in enumerate(zip(got, want)) if a != b), None)
    assert bad is None, f"chain differs from event {bad}: {recs[max(bad - 1, 0)]}"
    nsteps = [int(u[1]) for u in ups]
    assert nsteps[-1] == log.step
    # the host's view: the registers after the run
    (res,) = [x.split() for x in lines if x.startswith("R ")]
    steps, events, stall = int(res[1]), int(res[2]), int(res[3])
    chain = np.asarray([int(x, 16) for x in res[4:12]], "<u4").tobytes()
    assert steps == log.step and chain == log.chain
    assert events == sum(isinstance(r, Event) for r in recs)
    assert stall > 0                                      # the FIFO filled and held the pushes
    (cyc,) = [int(x.split()[1]) for x in lines if x.startswith("CYCLES ")]
    assert cyc < 260 * len(recs), cyc / len(recs)


def test_checkpoint_pause_holds_steps_rtl(trace_tb, tmp_path):
    """EVERY = 2, each C posted after the next 3 steps were queued: after every second step
    the engine takes no step until the C, so the chain follows TraceLog's order (step 2, C,
    step 3, ...), not the arrival order."""
    log = TraceLog(every=2, binding=bytes(32))
    recs = []

    def step(pc):
        w = bytes(range(pc, pc + 32))
        log.step += 1
        log.chain = trace.h(log.chain, b"\0\0", pc.to_bytes(4, "little"), w,
                            np.arange(16, dtype="<u4").tobytes())
        recs.append(StepRecord(log.step, 0, pc, w.hex(), "", log.chain.hex(), "",
                               np.arange(16, dtype="<u4").tobytes().hex()))

    step(1)
    step(2)
    st = [bytes([7]) * 32]
    log.chain = trace.h(log.chain, b"C", trace.h(*st))
    recs.append(Event("C", 2, [x.hex() for x in st], log.chain.hex()))
    for pc in range(3, 13):
        step(pc)
        if log.step % 2 == 0:
            log.chain = trace.h(log.chain, b"C", trace.h(*st))
            recs.append(Event("C", log.step, [x.hex() for x in st], log.chain.hex()))
    f = tmp_path / "cmds.txt"
    f.write_text(_commands(bytes(32), 2, recs, late=3))
    got = [x.split()[2] for x in _run(trace_tb, f) if x.startswith("U ")]
    assert got == [chain_start(bytes(32)).hex()] + [r.chain for r in recs]
