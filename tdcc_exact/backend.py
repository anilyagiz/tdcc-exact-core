"""Exact Core backends for the engine (opentpu.llm.qwen3.Engine): the bit-exact simulator with
the trace log on, and a dishonest provider's copy that skips work to save time.

The engine takes either one as `backend=` (a factory of (cfg, images)). Both are the ISA
simulator, which the card matches bit for bit (README, "Validating against Hugging Face"), so a
verifier's laptop and a provider's card give the same trace when both are honest.
"""
from __future__ import annotations

import numpy as np

from opentpu import isa as I
from opentpu.isasim import Slice
from opentpu.llm.qwen3 import IsaBackend

from .trace import TraceLog, h


def image_hash(images) -> bytes:
    """The model's commitment: the DRAM images the engine built (weights, tables, layout)."""
    return h(*[h(bytes(memoryview(img))) for img in images])


class TracedBackend(IsaBackend):
    """IsaBackend with every step, host write and run start in `log`."""

    def __init__(self, cfg, images, log: TraceLog):
        self.model_hash = image_hash(images)
        super().__init__(cfg, images)
        self.log = log
        m = self.machine
        m.observer = lambda s, pc: log.observe(s, pc, m.slices)

    def write(self, s, addr, data) -> None:
        v = np.ascontiguousarray(data).view(np.uint8).reshape(-1)
        self.log.host_write(s, addr, v.tobytes())
        super().write(s, addr, data)

    def run(self, programs, args=None) -> dict:
        self.log.run_start(args)
        out = super().run(programs, args)
        self.log.checkpoint(self.machine.slices)
        return out


class _SkippingSlice(Slice):
    """A slice that does not execute the matrix multiplies `skip` picks (cheat.skip)."""
    cheat = None

    def execute(self, ins: I.Instr) -> None:
        if ins.op == I.MM and self.cheat.skip(self, ins):
            return
        super().execute(ins)


class SkipLayer:
    """Provider B's shortcut: in every device run, leave out the matrix multiplies of one
    layer's share of the run (MMs number [layer, layer + 1) * n / layers of the run's n, n
    taken from the first run it watched). The answer often looks the same; its trace does
    not."""

    def __init__(self, layer: int, layers: int):
        self.layer, self.layers = layer, layers
        self.per_run: int | None = None
        self.n = 0
        self.skipped = 0

    def start(self) -> None:
        self.n = 0

    def end(self) -> None:
        if self.per_run is None:
            self.per_run = self.n

    def skip(self, s, ins) -> bool:
        self.n += 1
        if self.per_run is None:
            return False                  # the first run: honest, to learn its size
        per = self.per_run / self.layers
        if self.layer * per <= self.n - 1 < (self.layer + 1) * per:
            self.skipped += 1
            return True
        return False


class CheatingBackend(TracedBackend):
    """TracedBackend whose slices skip work per `cheat` (a provider that cuts corners: its
    log is honest about what it did, so it will not match an honest run)."""

    def __init__(self, cfg, images, log: TraceLog, cheat: SkipLayer):
        super().__init__(cfg, images, log)
        self.cheat = cheat
        for s in self.machine.slices:
            s.__class__ = type("CheatSlice", (_SkippingSlice,), {"cheat": cheat})

    def run(self, programs, args=None) -> dict:
        self.cheat.start()
        out = super().run(programs, args)
        self.cheat.end()
        return out


def factory(log: TraceLog, cheat: SkipLayer | None = None):
    if cheat is None:
        return lambda cfg, images: TracedBackend(cfg, images, log)
    return lambda cfg, images: CheatingBackend(cfg, images, log, cheat)
