"""The trace log: a commitment to every instruction a run executes, cheap enough to keep on.

Every instruction the simulator steps extends a hash chain:

    chain[i] = H(chain[i-1] || slice || pc || the instruction's 8 words || R0..R15 after it)

and every `every` steps, and at the end of each device run, the log takes a checkpoint: a
hash of each slice's working state (TMEM, ACT RAM and its scales, the registers, the pc) is
folded into the chain (chain = H(chain || "C" || state)), and the checkpoint keeps the step
count, that chain and the state hash. A checkpoint's leaf is H(step || chain || state).

The trace root a provider posts is a Merkle tree over the leaves: leaves hashed as
H(0x00 || leaf), nodes as H(0x01 || left || right), an odd level's last node paired with
itself, and the leaf count on top: root = H(0x02 || count || tree root). merkle_proof and
merkle_verify show one checkpoint against that root.

The host's writes into DRAM between runs (the token, its embedding row) and the start of each
run (its arguments) go into the chain too, so the log covers the inputs as well as the work.

Two honest runs of the same job give the same leaves. Once a run goes wrong its chain differs
from that step on (the chain is cumulative), so the first differing leaf can be found by a
binary search, and inside its window a replay with a state hash per step names the first
instruction whose result differs (tdcc_exact/dispute.py).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import numpy as np


DIGEST = 32                      # bytes per hash (SHA-256: Solana's sol_sha256 syscall, so the
                                 # program can recompute commitments and Merkle paths on-chain)
EVERY = 4096                     # steps between checkpoints


def h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def state_hash(s) -> bytes:
    """One slice's working state: TMEM, ACT RAM and its scales, the registers and the pc
    (DRAM is not hashed: what a run stores there it stores from TMEM, and what it loads
    back lands in TMEM, so a wrong value shows up here first)."""
    regs = np.asarray([s.pc & 0xFFFFFFFF] + [r & 0xFFFFFFFF for r in s.R], np.uint32)
    return h(s.tmem.tobytes(), s.act.tobytes(), s.ascale.tobytes(), regs.tobytes())


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


@dataclass
class TraceLog:
    every: int = EVERY
    window: tuple[int, int] | None = None     # (lo, hi]: record each step's state here
    step: int = 0
    chain: bytes = field(default_factory=lambda: h(b"tdcc-exact/trace/v2"))
    checkpoints: list[Checkpoint] = field(default_factory=list)
    records: list[StepRecord] = field(default_factory=list)
    _words: dict = field(default_factory=dict)    # id(program) -> (program, encoded words)

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
        regs = np.asarray([r & 0xFFFFFFFF for r in s.R], np.uint32).tobytes()
        self.step += 1
        self.chain = h(self.chain, s.sid.to_bytes(2, "little"), pc.to_bytes(4, "little"),
                       words, regs)
        if self.window is not None and self.window[0] < self.step <= self.window[1]:
            self.records.append(StepRecord(self.step, s.sid, pc, words.hex(), str(prog[pc]),
                                           self.chain.hex(), state_hash(s).hex()))
        if self.step % self.every == 0:
            self.checkpoint(slices)

    def host_write(self, s: int, addr: int, data: bytes) -> None:
        self.chain = h(self.chain, b"W", s.to_bytes(2, "little"), addr.to_bytes(8, "little"),
                       h(data))

    def run_start(self, args) -> None:
        a = np.asarray([0] if args is None else [int(x) & 0xFFFFFFFF for x in args], np.uint32)
        self.chain = h(self.chain, b"R", a.tobytes())

    def checkpoint(self, slices) -> None:
        if self.checkpoints and self.checkpoints[-1].step == self.step:
            return
        st = h(*[state_hash(s) for s in slices])
        self.chain = h(self.chain, b"C", st)     # (so a difference in state stays in the chain)
        self.checkpoints.append(Checkpoint(self.step, self.chain, st))

    # ------------------------------------------------------------- the commitment
    @property
    def root(self) -> bytes:
        return merkle_root([c.leaf for c in self.checkpoints])

    def to_json(self) -> dict:
        return {"every": self.every, "steps": self.step, "root": self.root.hex(),
                "checkpoints": [c.to_json() for c in self.checkpoints]}
