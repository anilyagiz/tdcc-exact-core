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


# The kernel functions whose matrix multiplies make up a layer, by the compiler's source
# frames (Instr.src): its token mixer (attention, or LFM2's short convolution), then its MLP.
MIXERS = frozenset({"_attention", "_attention_rows", "_conv", "_conv_rows"})
MLPS = frozenset({"_mlp"})


def layer_part(ins) -> str | None:
    """"mixer", "mlp" or None (the LM head, anything outside a layer): the part of a layer
    that emitted `ins`, by its source frames."""
    names = {f[2] for f in getattr(ins, "src", ())}
    if names & MLPS:
        return "mlp"
    if names & MIXERS:
        return "mixer"
    return None


class SkipLayer:
    """Provider B's shortcut: in every device run, leave out the matrix multiplies of layer
    `layer` (its mixer's and its MLP's). The answer often looks the same; its trace does not.

    The layers repeat inside a hardware LOOP (qwen3 Image.runs, lfm2.plan), so one MM of the
    program runs once per layer of the loop, and a share of a run's MMs is not one layer.
    Instead the layers are counted as they run: per slice and run, a mixer's MM that follows
    an MLP's (or is the run's first) starts the next layer. The parts are told apart by the
    compiler's source frames (Instr.src, layer_part)."""

    def __init__(self, layer: int, layers: int):
        if not 0 <= layer < layers:
            raise ValueError(f"layer {layer} of a {layers}-layer model")
        self.layer, self.layers = layer, layers
        self.skipped = 0
        self._parts: dict = {}           # Instr.src -> layer_part
        self._at: dict = {}              # slice id -> [layer index, last part]

    def start(self) -> None:
        self._at = {}

    def end(self) -> None:
        pass

    def skip(self, s, ins) -> bool:
        src = ins.src
        part = self._parts.get(src, False)
        if part is False:
            part = self._parts[src] = layer_part(ins)
        if part is None:
            return False
        at = self._at.setdefault(s.sid, [-1, None])
        if part == "mixer" and at[1] != "mixer":
            at[0] += 1
        at[1] = part
        if at[0] == self.layer:
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
