"""The trace log: a commitment to every instruction a run executes, cheap enough to keep on.

Every instruction the simulator steps extends a hash chain:

    chain[i] = H(chain[i-1] || slice || pc || the instruction's 8 words || R0..R15 after it)

and every `every` steps, and at the end of each device run, the log takes a checkpoint: a
hash of each slice's working state (TMEM, ACT RAM and its scales, the registers, the pc, and
a running hash of the DRAM words and bytes its stores wrote) is
folded into the chain (chain = H(chain || "C" || state)), and the checkpoint keeps the step
count, that chain and the state hash. A checkpoint's leaf is H(step || chain || state).

The trace root a provider posts is a Merkle tree over the leaves: leaves hashed as
H(0x00 || leaf), nodes as H(0x01 || left || right), an odd level's last node paired with
itself, and the leaf count on top: root = H(0x02 || count || tree root). merkle_proof and
merkle_verify show one checkpoint against that root.

The chain starts from a 32-byte binding: the address of the on-chain job account the run is
for (locally, the provider's key). Two on-chain jobs with the same model, prompt and
parameters (the same Job opened with provider A and with provider B, or a question asked
again) therefore have different traces and fingerprints, and a fingerprint revealed on one is
no use on another.

The host's writes into DRAM between runs (the token, its embedding row) and the start of each
run (its arguments) go into the chain too, so the log covers the inputs as well as the work,
and so do the host's reads back from DRAM (the logits), with a last checkpoint after them
(TraceLog.finish): the trace root commits to the output a receipt's answer comes from.

Two honest runs of the same job give the same leaves. Once a run goes wrong its chain differs
from that step on (the chain is cumulative), so the first differing leaf can be found by a
binary search, and inside its window a replay with a state hash per step names the first
instruction whose result differs (tdcc_exact/dispute.py).
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field

import numpy as np

# The hashes take numpy arrays' bytes as they are in memory (TMEM, the ACT RAM, the
# registers, the logits), so every party must lay them out alike: little-endian, as the
# card, x86 and ARM machines do. A big-endian machine would post other hashes for honest
# work, so it refuses to start instead.
if sys.byteorder != "little":
    raise ImportError("tdcc_exact hashes little-endian memory; this machine is big-endian")


DIGEST = 32                      # bytes per hash (SHA-256: Solana's sol_sha256 syscall, so the
                                 # program can recompute commitments and Merkle paths on-chain)
EVERY = 4096                     # steps between checkpoints
TAG = b"tdcc-exact/trace/v3"
UNBOUND = bytes(32)              # a binding for runs that belong to no job (build_hash)


def h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def chain_start(binding: bytes) -> bytes:
    """The chain before the first event: H(tag || binding), binding the on-chain job account
    (32 bytes: its address), so every job's trace is its own."""
    if len(binding) != 32:
        raise ValueError(f"a binding is 32 bytes, not {len(binding)}")
    return h(TAG, binding)


def state_hash(s) -> bytes:
    """One slice's working state: TMEM, ACT RAM and its scales, the registers and the pc,
    and the running hash of what it stored to DRAM (`stores`, kept by the traced slice:
    the addresses and contents each ST / QST / DSTEP / STREAM wrote). The whole DRAM is not
    hashed (the weights would dominate; the model hash pins them)."""
    regs = np.asarray([s.pc & 0xFFFFFFFF] + [r & 0xFFFFFFFF for r in s.R], np.uint32)
    return h(s.tmem.tobytes(), s.act.tobytes(), s.ascale.tobytes(), regs.tobytes(),
             getattr(s, "stores", b""))


def merkle_root(leaves: list[bytes]) -> bytes:
    """The leaves' Merkle tree, an odd level's last node paired with itself, and the leaf count
    on top: without it [a, b, c] and [a, b, c, c] would share a root."""
    if not leaves:
        return h(b"empty")
    level = [h(b"\x00", x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [h(b"\x01", level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return h(b"\x02", len(leaves).to_bytes(8, "little"), level[0])


def merkle_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """The sibling of leaves[index]'s node on each level, bottom up: with the leaf count, what
    shows one checkpoint belongs to a posted trace root (merkle_verify), so a bisection round
    on-chain needs one leaf and log2(checkpoints) hashes, not the whole list."""
    if not 0 <= index < len(leaves):
        raise IndexError(index)
    level, path = [h(b"\x00", x) for x in leaves], []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        path.append(level[index ^ 1])
        level = [h(b"\x01", level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return path


def merkle_verify(leaf: bytes, index: int, count: int, path: list[bytes], root: bytes) -> bool:
    """Whether `leaf` is leaf number `index` of a trace root over `count` leaves."""
    if not 0 <= index < count:
        return False
    node, n = h(b"\x00", leaf), count
    for sib in path:
        if n <= 1:
            return False
        node = h(b"\x01", node, sib) if index % 2 == 0 else h(b"\x01", sib, node)
        index, n = index // 2, (n + 1) // 2
    return n == 1 and h(b"\x02", count.to_bytes(8, "little"), node) == root


@dataclass
class Checkpoint:
    step: int                    # steps so far (the instruction count across runs and slices)
    chain: bytes
    state: bytes

    @property
    def leaf(self) -> bytes:
        return h(self.step.to_bytes(8, "little"), self.chain, self.state)

    def to_json(self) -> list:
        return [self.step, self.chain.hex(), self.state.hex()]

    @staticmethod
    def from_json(v) -> "Checkpoint":
        return Checkpoint(int(v[0]), bytes.fromhex(v[1]), bytes.fromhex(v[2]))


@dataclass
class StepRecord:
    """One step inside a disputed window: where it ran and what it left behind."""
    step: int
    slice: int
    pc: int
    words: str                   # the instruction's encoding (what the chain hashed)
    instr: str                   # and as text, for people (its comment may differ by compile)
    chain: str
    state: str
    regs: str = ""               # R0..R15 after it (what the chain hashed), for verify_window


@dataclass
class Event:
    """Anything else that moved the chain inside a revealed window (TraceLog.reveal): a host
    write ("W": slice, address, H(data)), a host read ("O": slice, address, length,
    H(data)), a run start ("R": the arguments' bytes) or a checkpoint ("C": each slice's
    state hash). `data` holds those parts in hex, `chain` the chain after the event."""
    kind: str
    step: int
    data: list
    chain: str


def record_to_json(r) -> dict:
    return {"type": "step" if isinstance(r, StepRecord) else "event"} | r.__dict__


def record_from_json(d: dict):
    d = dict(d)
    kind = d.pop("type")
    return StepRecord(**d) if kind == "step" else Event(**d)


def next_chain(chain: bytes, r) -> bytes:
    """The chain after record `r` (a StepRecord or an Event), as TraceLog computed it."""
    if isinstance(r, StepRecord):
        return h(chain, r.slice.to_bytes(2, "little"), r.pc.to_bytes(4, "little"),
                 bytes.fromhex(r.words), bytes.fromhex(r.regs))
    parts = [bytes.fromhex(x) for x in r.data]
    if r.kind == "C":
        return h(chain, b"C", h(*parts))
    if r.kind in ("W", "O", "R"):
        return h(chain, r.kind.encode(), *parts)
    raise ValueError(f"unknown event {r.kind!r}")


@dataclass
class TraceLog:
    every: int = EVERY
    window: tuple[int, int] | None = None     # (lo, hi]: record each step's state here
    binding: bytes = UNBOUND                  # the on-chain job account (see chain_start)
    reveal: int | None = None                 # record every event up to checkpoint `reveal`
    step: int = 0
    chain: bytes = field(init=False)
    checkpoints: list[Checkpoint] = field(default_factory=list)
    records: list[StepRecord] = field(default_factory=list)
    events: list = field(default_factory=list)    # the revealed window: StepRecords, Events
    _words: dict = field(default_factory=dict)    # id(program) -> (program, encoded words)

    def __post_init__(self):
        self.chain = chain_start(self.binding)

    # ------------------------------------------------------------- the machine's events
    def observe(self, s, pc: int, slices) -> None:
        """After slice s stepped the instruction at pc (isasim.Machine.observer); slices: all
        of the machine's, for the checkpoints."""
        prog = s.prog
        ent = self._words.get(id(prog))
        if ent is None or ent[0] is not prog:
            ent = (prog, [None] * len(prog))
            self._words[id(prog)] = ent
        words = ent[1][pc]
        if words is None:
            words = ent[1][pc] = np.asarray(prog[pc].encode(), np.uint32).tobytes()
        regs = np.asarray([r & 0xFFFFFFFF for r in s.R], "<u4").tobytes()
        self.step += 1
        self.chain = h(self.chain, s.sid.to_bytes(2, "little"), pc.to_bytes(4, "little"),
                       words, regs)
        rec = None
        if self.window is not None and self.window[0] < self.step <= self.window[1]:
            rec = StepRecord(self.step, s.sid, pc, words.hex(), str(prog[pc]),
                             self.chain.hex(), state_hash(s).hex(), regs.hex())
            self.records.append(rec)
        if self._revealing():
            self.events.append(rec or StepRecord(self.step, s.sid, pc, words.hex(),
                                                 str(prog[pc]), self.chain.hex(),
                                                 state_hash(s).hex(), regs.hex()))
        if self.step % self.every == 0:
            self.checkpoint(slices)

    def _revealing(self) -> bool:
        return self.reveal is not None and len(self.checkpoints) == self.reveal

    def _event(self, kind: str, *parts: bytes) -> None:
        self.chain = h(self.chain, kind.encode(), *parts)
        if self._revealing():
            self.events.append(Event(kind, self.step, [p.hex() for p in parts],
                                     self.chain.hex()))

    def host_write(self, s: int, addr: int, data: bytes) -> None:
        self._event("W", s.to_bytes(2, "little"), addr.to_bytes(8, "little"), h(data))

    def host_read(self, s: int, addr: int, data: bytes) -> None:
        """What the host read back from DRAM (the logits): the output is in the chain."""
        self._event("O", s.to_bytes(2, "little"), addr.to_bytes(8, "little"),
                    len(data).to_bytes(8, "little"), h(data))

    def run_start(self, args) -> None:
        a = np.asarray([0] if args is None else [int(x) & 0xFFFFFFFF for x in args], "<u4")
        self._event("R", a.tobytes())

    def checkpoint(self, slices) -> None:
        last = self.checkpoints[-1] if self.checkpoints else None
        if last is not None and last.step == self.step and last.chain == self.chain:
            return                              # (nothing happened since)
        states = [state_hash(s) for s in slices]
        st = h(*states)
        rev = self._revealing()
        self.chain = h(self.chain, b"C", st)     # (so a difference in state stays in the chain)
        self.checkpoints.append(Checkpoint(self.step, self.chain, st))
        if rev:
            self.events.append(Event("C", self.step, [x.hex() for x in states],
                                     self.chain.hex()))

    def finish(self, slices) -> None:
        """The last checkpoint, after the host read the output: the root covers the reads."""
        self.checkpoint(slices)

    # ------------------------------------------------------------- the commitment
    @property
    def root(self) -> bytes:
        return merkle_root([c.leaf for c in self.checkpoints])

    def to_json(self) -> dict:
        return {"every": self.every, "steps": self.step, "root": self.root.hex(),
                "checkpoints": [c.to_json() for c in self.checkpoints]}
