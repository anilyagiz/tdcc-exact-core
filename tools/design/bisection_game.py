"""A prototype of the on-chain bisection game (docs/design/onchain-dispute.md), off-chain.

The referee below is what the Solana program would do, one `move` per transaction: it holds
only what the program could hold (the two committed trace roots and counts, the range still in
dispute, the round's queries and deadline, the claims posted this round) and checks every
opening with trace.merkle_verify, as `reveal_receipt` checks the fingerprint today. The players
answer from real runs (a TracedBackend's checkpoint list and window records), so the game is
driven by the same lists `dispute.bisect` and `dispute.first_fault` use.

Phases:

    checkpoints   both sides open the leaves the round asks for against their own committed
                  roots (the provider's is the one on the Job; the challenger's comes with its
                  challenge). The search keeps "leaf hi differs" and "every leaf below lo
                  agrees", as dispute.bisect does, and ends on a checkpoint d that differs
                  while d-1 agrees (or d = 0).
    steps         inside the window (steps lo..hi of checkpoint d), both sides post fresh claims
                  H(step || chain || state) at the round's steps; the agreed checkpoint d-1 is
                  the claim at lo. The search ends on one step s: the claims at s-1 agree, at s
                  they differ.
    resolved      the last step is decided by `executor(step, agreed, fold) -> claim`: the
                  one-step proof (or, until it exists, a committee or the arbiter). Whichever
                  side's claim at s is not the executor's loses; both wrong: the provider loses.

Every round has a deadline (`move_window` slots after it opens). A side that has not moved by
then loses by default (`timeout`); if neither moved, the provider loses (its receipt is the one
in question). `k` is the dissection degree: k - 1 queries a round, ceil(log_k(range)) rounds.

The step claims use each StepRecord's `state` (the stepped slice's state hash) as the state;
the design's trace v4 replaces it with the machine's state root. That changes what a claim
hashes, not how the game moves.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tdcc_exact.trace import Checkpoint, h, merkle_proof, merkle_root, merkle_verify

PROVIDER, CHALLENGER = "provider", "challenger"
END = h(b"tdcc-exact/game/v0/end")       # a claim at a step past the end of a side's window


def step_claim(step: int, chain: bytes, state: bytes) -> bytes:
    """A claim about the machine after `step`: the same form as a checkpoint's leaf."""
    return h(step.to_bytes(8, "little"), chain, state)


@dataclass
class Commit:
    """A trace commitment as the program holds it: the trace root and the checkpoint count."""
    root: bytes
    count: int


@dataclass
class Ruling:
    winner: str
    loser: str
    how: str                      # "proof", "timeout", "no-difference", "bad-opening"
    divergence_index: int | None  # the checkpoint d (None: decided before it was found)
    fault_step: int | None        # the step s the executor ruled on
    rounds: int                   # rounds played (both sides moved)
    moves: int                    # transactions sent by the two sides


def _queries(lo: int, hi: int, k: int) -> list[int]:
    """k - 1 points splitting [lo, hi) (fewer when the range is short), strictly increasing."""
    n = hi - lo
    pts = sorted({lo + (n * j) // k for j in range(1, k)} - {hi})
    return [p for p in pts if lo <= p < hi] or [lo]


@dataclass
class BisectionGame:
    provider: Commit
    challenger: Commit
    executor: object                     # (step, agreed claim at step - 1, fold) -> claim
    k: int = 2
    move_window: int = 750               # slots a side has per round (~5 min at 400 ms)
    now: int = 0
    phase: str = "checkpoints"
    lo: int = 0
    hi: int = 0
    queries: list = field(default_factory=list)
    deadline: int = 0
    posted: dict = field(default_factory=dict)
    rounds: int = 0
    moves: int = 0
    divergence: int | None = None
    window: tuple | None = None          # (lo step, hi step) of checkpoint d
    anchor: bytes | None = None          # the agreed claim at self.lo (steps phase)
    hi_claims: tuple = ()                # (provider, challenger) claims at self.hi
    ruling: Ruling | None = None
    _agreed: Checkpoint | None = None    # the opened checkpoint lo - 1 (both sides alike)
    _hi_open: tuple = ()                 # the two openings at hi (checkpoints phase)
    _first_step_round: bool = False

    def __post_init__(self):
        if self.k < 2:
            raise ValueError("the dissection degree is at least 2")
        n = min(self.provider.count, self.challenger.count)
        # the first round shows a difference at hi: the last common index when the counts are
        # equal (a challenger with another hi in mind would name it here), else past the
        # shorter list, where the shorter side has nothing to open
        self.hi = n - 1 if self.provider.count == self.challenger.count else n
        self.queries = [self.hi]
        self.deadline = self.now + self.move_window

    # ------------------------------------------------------------------ the program's checks
    def _commit(self, side: str) -> Commit:
        return self.provider if side == PROVIDER else self.challenger

    def _check_openings(self, side: str, openings) -> list[bytes | None]:
        """openings: [(index, Checkpoint or None, path)] for this round's queries. A None
        checkpoint says the side's list ends before the index (true only past its count)."""
        c = self._commit(side)
        if [o[0] for o in openings] != self.queries:
            raise ValueError("the openings do not answer this round's queries")
        out = []
        for i, cp, path in openings:
            if cp is None:
                if i < c.count:
                    raise ValueError(f"leaf {i} exists (count {c.count}) and was not opened")
                out.append(None)
            elif not merkle_verify(cp.leaf, i, c.count, path, c.root):
                raise ValueError(f"leaf {i} does not open against the committed root")
            else:
                out.append(cp)
        return out

    def move(self, side: str, payload, now: int) -> None:
        """One transaction: a side's openings (checkpoints) or claims (steps) for this round."""
        if self.ruling is not None:
            raise ValueError("the game is over")
        if now > self.deadline:
            raise ValueError("the round's deadline has passed")
        if side in self.posted:
            raise ValueError(f"the {side} already moved this round")
        self.moves += 1
        if self.phase == "checkpoints":
            try:
                payload = self._check_openings(side, payload)
            except ValueError:
                self._end(side, "bad-opening")
                return
        elif len(payload) != len(self.queries):
            self._end(side, "bad-opening")
            return
        self.posted[side] = payload
        if len(self.posted) == 2:
            self._advance(now)

    def timeout(self, now: int) -> Ruling:
        """Anyone, after the deadline: a side that did not move loses by default."""
        if self.ruling is not None:
            return self.ruling
        if now <= self.deadline:
            raise ValueError("the round's deadline has not passed")
        loser = PROVIDER if PROVIDER not in self.posted else CHALLENGER
        return self._end(loser, "timeout")

    # ------------------------------------------------------------------ the search
    def _end(self, loser: str, how: str, step: int | None = None) -> Ruling:
        winner = CHALLENGER if loser == PROVIDER else PROVIDER
        self.ruling = Ruling(winner, loser, how, self.divergence, step, self.rounds, self.moves)
        self.phase = "resolved"
        return self.ruling

    def _open(self, now: int, queries: list[int]) -> None:
        self.queries, self.posted = queries, {}
        self.deadline = now + self.move_window

    def _advance(self, now: int) -> None:
        self.rounds += 1
        a, b = self.posted[PROVIDER], self.posted[CHALLENGER]
        if self.phase == "checkpoints":
            self._advance_checkpoints(now, a, b)
        else:
            self._advance_steps(now, a, b)

    def _advance_checkpoints(self, now: int, a: list, b: list) -> None:
        """As dispute.bisect: keep "leaf hi differs" and "the leaf at lo - 1 agrees"."""
        same = [x is not None and y is not None and x.leaf == y.leaf for x, y in zip(a, b)]
        first = next((j for j, s in enumerate(same) if not s), None)
        if self.rounds == 1:                      # the round that shows a difference at hi
            if first is None:
                self._end(CHALLENGER, "no-difference")
                return
            self._hi_open = (a[0], b[0])
        elif first is None:                       # every query agrees: d is above them
            self.lo, self._agreed = self.queries[-1] + 1, a[-1]
        else:
            if first:
                self.lo, self._agreed = self.queries[first - 1] + 1, a[first - 1]
            self.hi, self._hi_open = self.queries[first], (a[first], b[first])
        if self.lo < self.hi:
            self._open(now, _queries(self.lo, self.hi, self.k))
        else:
            self._to_steps(now)

    def _to_steps(self, now: int) -> None:
        """Checkpoint d found: the window is the steps from checkpoint d-1 to checkpoint d."""
        d = self.divergence = self.hi
        agreed = self._agreed if d else None
        lo_step = agreed.step if agreed is not None else 0
        p, c = self._hi_open
        if p is None:                       # the provider's list ends before d: it loses
            self._end(PROVIDER, "proof", lo_step + 1)
            return
        self.window = (lo_step, max(p.step, c.step if c is not None else lo_step))
        self.phase, self._first_step_round = "steps", True
        self.anchor = agreed.leaf if agreed is not None else None   # (d = 0: the chain start)
        self.lo, self.hi = self.window
        self._open(now, [self.hi])

    def _advance_steps(self, now: int, a: list, b: list) -> None:
        first = next((j for j, (x, y) in enumerate(zip(a, b)) if x != y), None)
        if self._first_step_round:                # both sides' claims at the window's end
            self._first_step_round = False
            if first is None:
                # the last steps agree, so the difference is in what follows them (host
                # reads, the checkpoint fold): the executor rules on the fold
                p, c = self._hi_open
                self._resolve(self.hi, a[0], p.leaf, c.leaf if c is not None else END,
                              fold=True)
                return
            self.hi_claims = (a[0], b[0])
        elif first is None:                       # every query agrees: s is above them
            self.lo, self.anchor = self.queries[-1], a[-1]
        else:
            if first:
                self.lo, self.anchor = self.queries[first - 1], a[first - 1]
            self.hi, self.hi_claims = self.queries[first], (a[first], b[first])
        if self.hi - self.lo > 1:
            self._open(now, _queries(self.lo + 1, self.hi, self.k))
        else:
            self._resolve(self.hi, self.anchor, *self.hi_claims)

    def _resolve(self, step: int, agreed: bytes | None, pc: bytes, cc: bytes,
                 fold: bool = False) -> None:
        right = self.executor(step, agreed, fold)
        if pc == right and cc != right:
            self._end(CHALLENGER, "proof", step)
        else:                                 # the provider's claim is wrong (or both are)
            self._end(PROVIDER, "proof", step)


# ---------------------------------------------------------------------- players
class TracePlayer:
    """A side that plays from its own run: its checkpoint list and, once the window is named,
    its records of that window (window(lo, hi) -> [StepRecord]). `silent_after`: the number of
    moves it makes before it stops answering (None: it always answers)."""

    def __init__(self, checkpoints: list[Checkpoint], window, silent_after: int | None = None):
        self.cps = checkpoints
        self.leaves = [c.leaf for c in checkpoints]
        self.window = window
        self.silent_after = silent_after
        self.made = 0
        self._claims: dict | None = None

    @property
    def commit(self) -> Commit:
        return Commit(merkle_root(self.leaves), len(self.leaves))

    def answer(self, game: BisectionGame):
        if self.silent_after is not None and self.made >= self.silent_after:
            return None
        self.made += 1
        if game.phase == "checkpoints":
            return [(i, self.cps[i], merkle_proof(self.leaves, i)) if i < len(self.cps)
                    else (i, None, []) for i in game.queries]
        if self._claims is None:
            lo, hi = game.window
            self._claims = {r.step: step_claim(r.step, bytes.fromhex(r.chain),
                                               bytes.fromhex(r.state))
                            for r in self.window(lo, hi)}
        return [self._claims.get(s, END) for s in game.queries]


def play(game: BisectionGame, provider: TracePlayer, challenger: TracePlayer,
         slots_per_move: int = 2) -> Ruling:
    """Drive the game: each round both sides answer `slots_per_move` slots apart; a side that
    does not answer is timed out once the round's deadline passes."""
    now = game.now
    while game.ruling is None:
        silent = False
        for side, player in ((PROVIDER, provider), (CHALLENGER, challenger)):
            if game.ruling is not None:
                break
            payload = player.answer(game)
            now += slots_per_move
            if payload is None:
                silent = True
            else:
                game.move(side, payload, now)
        if game.ruling is None and silent:
            now = game.deadline + 1
            game.timeout(now)
    return game.ruling
