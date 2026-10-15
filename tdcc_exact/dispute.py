"""A dispute: find the first instruction where two runs of a job part ways.

1. Bisect the two checkpoint lists (a provider's posted trace and the verifier's own): the
   chain is cumulative, so once a leaf differs every later one does, and a binary search finds
   the first differing checkpoint in log2(checkpoints) rounds. This is the game an on-chain
   referee plays, one round per transaction.
2. Both sides reveal that window, one record per step (where it ran, the chain, a hash of the
   slice's state after it); the first record that differs is the instruction at fault.

In a live market the provider replays its own window when challenged; here (the demo, the
tests) both sides are replayed locally, the provider with the shortcut it took.
"""
from __future__ import annotations

from dataclasses import dataclass

from .trace import Checkpoint, merkle_root


@dataclass
class Divergence:
    index: int                   # the first differing checkpoint
    lo: int                      # its window: steps (lo, hi]
    hi: int
    rounds: int                  # binary-search rounds it took


def matches_root(checkpoints: list[Checkpoint], root: bytes) -> bool:
    """Whether a checkpoint list is the one a receipt committed to: a provider must play the
    bisection on the trace it posted, not on one made up after the challenge."""
    return merkle_root([c.leaf for c in checkpoints]) == root


def bisect(a: list[Checkpoint], b: list[Checkpoint]) -> Divergence | None:
    """A checkpoint where a and b differ while the one before agrees (None: the traces are
    the same). Honest chains are cumulative, so that is the first difference; a posted list
    need not be, so the search starts from the last difference, not from the last leaf."""
    n = min(len(a), len(b))
    if len(a) != len(b):
        hi = n                          # past the shorter list: a difference
    else:
        hi = next((i for i in range(n - 1, -1, -1) if a[i].leaf != b[i].leaf), None)
    if hi is None:
        return None
    lo, rounds = 0, 0                   # a[hi] differs; find lo with a[lo] differing, a[lo-1] not
    while lo < hi:
        mid = (lo + hi) // 2
        rounds += 1
        if a[mid].leaf == b[mid].leaf:
            lo = mid + 1
        else:
            hi = mid
    start = a[lo - 1].step if lo else 0
    end = max(a[lo].step if lo < len(a) else start, b[lo].step if lo < len(b) else start)
    return Divergence(lo, start, end, rounds)


@dataclass
class Fault:
    step: int
    slice: int
    pc: int
    honest: str                  # the instruction the honest run executed there
    other: str                   # and the other run
    what: str                    # "state" (same instruction, different result) or "control"


def first_fault(honest, other) -> Fault | None:
    """The first differing step of two windows of StepRecords."""
    for x, y in zip(honest, other):
        if (x.slice, x.pc, x.words) != (y.slice, y.pc, y.words):
            return Fault(x.step, x.slice, x.pc, x.instr, y.instr, "control")
        if x.state != y.state or x.chain != y.chain:
            return Fault(x.step, x.slice, x.pc, x.instr, y.instr, "state")
    if len(honest) != len(other):        # one side ran a step the other never did
        k = min(len(honest), len(other))
        if len(honest) > k:
            x = honest[k]
            return Fault(x.step, x.slice, x.pc, x.instr, "(ended)", "control")
        y = other[k]
        return Fault(y.step, y.slice, y.pc, "(ended)", y.instr, "control")
    return None
