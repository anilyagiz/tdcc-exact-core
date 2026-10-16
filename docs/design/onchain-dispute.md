# Design: the dispute on-chain, without the arbiter

Status: a proposal for the owner to decide on. Nothing here is built except the off-chain
prototype of the game ([`tools/design/bisection_game.py`](../../tools/design/bisection_game.py),
tested in [`tests/test_design_proto.py`](../../tests/test_design_proto.py)). It answers
[TODO.md](../../TODO.md) item 6 ("On-chain bisection game", "The last step", "Merkle-ize the
state hash") and the "Arbiter bias" and "Key theft: arbiter or admin" rows of
[threat-model.md](../threat-model.md#attacks). The trace log, the receipt and today's dispute
are in [exact.md](../exact.md); the program is
[`programs/tdcc_exact/src/lib.rs`](../../programs/tdcc_exact/src/lib.rs).

Compute-unit (CU) figures marked "estimate" are worked out from Solana's published limits and
cost schedule, not measured; section 7 lists what to measure before building.

## 1. What the arbiter decides today

A challenge puts the job in `Challenged`. The arbiter node
([`tdcc_exact/node/arbiter.py`](../../tdcc_exact/node/arbiter.py)) re-runs the job, bisects its
checkpoints against the provider's (`dispute.bisect`), checks the provider's revealed window
(`dispute.verify_window`), replays its own window and compares step by step
(`dispute.first_fault`), and signs `slash(divergence_index, fault_step)` or `dismiss`. The
program checks the arbiter's signature, the ruling deadline and `divergence_index <=
checkpoints`. Nothing else: a slash is as good as the arbiter key.

The program already holds what a referee needs to start: the provider's trace root and its
checkpoint count (`Job.trace_root`, `Job.checkpoints`), bound to the fingerprint by
`reveal_receipt`. `trace.merkle_proof` / `merkle_verify` open one checkpoint against it with
`ceil(log2(count))` hashes, and the program has `sol_sha256` (the `hashv` it uses for the
commitment and the fingerprint).

## 2. The bisection game

### 2.1 Commitments

- **The provider**: the trace root and count on the Job, as today.
- **The challenger**: today `challenge` takes only a fingerprint. It also takes the tree root
  and checkpoint count of the challenger's own run (the program rebuilds the trace root with
  `trace_root(tree_root, count)`, as `reveal_receipt` does). With both lists committed, every
  comparison in the search is between two openings the program checks, and the search is
  `dispute.bisect` played one round per transaction.

### 2.2 Phases

| Phase | Range | A move | The program keeps |
|:--|:--|:--|:--|
| 1. checkpoints | checkpoint indices `[lo, hi]` | one opening per side: `(index, step, chain, state, path)`, checked with `merkle_verify` against that side's root | "leaf `hi` differs", "leaf `lo - 1` agrees" |
| 2. steps | steps `(lo, hi]` of checkpoint `d` | `k - 1` claims per side, 32 bytes each | the agreed claim at `lo`, the two claims at `hi` |
| 3. micro-steps (heavy opcodes only, section 3.1) | micro-steps `(0, U]` of the one instruction | `k - 1` claims per side | as phase 2 |
| 4. final | one step or micro-step | the proof inputs (section 3) | the ruling |

Phase 1 starts with both sides opening the last common index (or, when the counts differ, the
shorter side shows its list ends there: an index at or past its count is "nothing", which the
program can check against the committed count). If the leaves there are equal, the challenger
has shown no difference and loses. Then binary search, as `dispute.bisect`: a list need not be a real
chain, so the search keeps a known difference at `hi` and ends on `d` with `d` differing and
`d - 1` agreeing. If the provider's list ends before `d`, the provider loses at once (the
arbiter's rule 2 today).

Phase 2 has no committed per-step data: the chain commits to each step's slice, pc,
instruction words and registers, and the state only at checkpoints. Both sides post fresh
claims `H(step || chain || state)` (the form of a checkpoint leaf) at the round's `k - 1`
steps; the agreed checkpoint `d - 1` anchors `lo`. A claim posted here is binding for the rest
of the game, so neither side can change its story; a side that copies the other's claims only
moves the search to where it must finally disagree. The search ends on step `s`: claims agree
at `s - 1`, differ at `s`. If both sides' claims at the window's last step agree, the
difference is in what follows the steps (the host's reads, the checkpoint fold), and the final
check is the fold (section 3.1, events).

Claims are 32 bytes, so phases 2 and 3 use `k = 16` (15 claims, 480 bytes of a 1,232-byte
transaction). Phase 1 uses `k = 2`: an opening is `72 + 32 * depth` bytes (456 bytes at 4,096
checkpoints), one per transaction.

### 2.3 Who moves, timeouts, loss by default

Both sides move in every round, in either order; the round advances in the transaction of the
second mover. Each round has a deadline, `move_window` slots after it opened. After it,
`timeout` (anyone may send it) ends the game against the side that has not moved; if neither
has, the provider loses (the receipt it was paid for is the one in question). An opening that
does not verify, or a claim list of the wrong length, loses at once.

| Parameter | Proposed | Why |
|:--|--:|:--|
| `move_window` | 1,500 slots (~10 min) | the honest side replays to the window once (about 1 min for LFM2.5-230M, [exact.md](../exact.md#7-overhead-of-the-log)) and then hashes 15 states a round; congestion margin |
| `final_window` | 3,000 slots (~20 min) | staging up to ~40 transactions of proof data (section 3.1) |
| `max_checkpoints` | 4,096 | bounds phase 1 to 13 rounds |
| `max_window` | 65,536 steps | `hi - lo` of checkpoint `d`, read from the opened leaves' `step`; a larger gap loses for its poster (an honest list checkpoints every `job.every` <= 65,536 steps) |
| `max_micro` | 2^20 | bounds phase 3 to 5 rounds |

The longest game is then 13 + 1 + 4 + 5 = 23 rounds: 23 x 1,500 + 3,000 = 37,500 slots
(about 4 h 10 min). `dispute_window = 37,500` replaces `arbiter_window` in the unstake-cooldown
bound `initialize` checks (today's example uses 216,000 slots for the arbiter, a day). A game
between two live sides takes a few slots per round: minutes.

### 2.4 Rounds and transactions

| Job | Checkpoints | Window | Heavy step | Rounds (k = 2 everywhere) | Rounds (k = 2 / 16 / 16) | Transactions |
|:--|--:|--:|:--|--:|--:|--:|
| tiny model, `every` 512 (prototype, measured) | 11 | 512 | (no phase 3) | 15 | 6 at k = 16 everywhere | 12 |
| LFM2.5-230M demo (`every` 4096) | 21 | 4,096 | `mm 8x1024 . 512x1024^T`, 4,096 outputs | 1 + 5 + 1 + 12 + 12 = 31 | 1 + 5 + 1 + 3 + 3 = 13 | 26, plus the final step (4-6) |

A transaction costs 5,000 lamports per signature; a 30-transaction game is about 0.00015 SOL
plus priority fees. The `Dispute` account (about 1.2 KB) and the proof buffer (up to 64 KB)
hold rent while the game runs (about 0.01 and 0.45 SOL) and are closed to their payers at the
end.

The prototype plays phases 1 and 2 on real traces of the tiny model with a cheating provider
(`SkipLayer(1)`): it lands on checkpoint 1 and step 659, the MM `dispute.first_fault` names,
in 15 rounds at `k = 2` and 6 at `k = 16`; a side that stops answering loses at the round's
deadline.

## 3. The last step

Three ways to decide which side is right about one instruction, then a comparison.

### 3.1 (a) A one-step proof on-chain

The program re-executes the step (or one micro-step of it) from the agreed pre-state and
compares the result with the two claims. It needs the pre-state's parts the instruction reads
as Merkle openings, and the post-state root it computes from the parts it writes.

**What the v3 state leaves out.** `trace.state_hash` hashes each slice's TMEM, ACT RAM and
scales, registers, pc and the running hash of its stores, flat. A one-step proof needs more,
all of which an honest run already determines but no hash commits to:

- the loop stack (`Slice.stack`, up to 4 entries of start, end, count), `halted`, `waiting`,
  `polling`: `LOOP` and the back edge in `advance` depend on them;
- the program in IMEM (`HALT CHAIN` loads a new one from DRAM);
- DRAM: `LD`, `MM`, `WAITW`, `DSTEP` and `STREAM` read it. The model hash
  (`backend.image_hash`) is a flat hash of the images, and the stores hash records what was
  written but cannot open one word;
- the machine's schedule: `Machine.run` steps slice 0 until it halts or waits, then slice 1,
  then resolves a collective (`GATHER` copies between slices when every live slice waits), so
  which slice runs next is part of the state.

**Trace v4: a state root.** `TAG = "tdcc-exact/trace/v4"`; a checkpoint's `state` becomes:

    state_root = H("S" || schedule || slice_root[0] || ... || slice_root[S-1])
    slice_root = H(header || imem_root || tmem_root || act_root || dram_root)
    header     = R0..R15, pc, halted, waiting op, polling, loop stack (4 x 3 words): 120 bytes

| Tree | Leaf | Leaves (design config / board) | Depth | Path |
|:--|:--|--:|--:|--:|
| TMEM | 64 words (256 B) | 1,024 (64K words) | 10 | 320 B |
| ACT RAM | one (row, block): 128 int8 + its fp32 scale (132 B) | 512 (8 x 64) / 512 (4 x 128) | 9 | 288 B |
| IMEM | one instruction (32 B) | 8,192 / 4,096 | 13 / 12 | 416 B |
| DRAM | 128 B (one K-block, `D`) | 131,072 (16 MiB) / 2^25 (4 GiB) | 17 / 25 | 544 / 800 B |

The header goes into the transaction in the clear (120 bytes). The model hash becomes the
DRAM root of the initial image, so `Job.model_hash` pins the root the one-step proofs open
weights against (the registry pins move with it). The stores hash is no longer needed: the
DRAM root covers what was written.

Cost to the provider: at each checkpoint, about 1,000 TMEM leaf hashes and 512 ACT leaf hashes
per slice, and the DRAM leaves stored to since the last checkpoint, each a path of 17-25
hashes; the DRAM tree of the image is built once per model (for a 250 MB image, 2 million
leaves, about 4 million hashes). Against a 4,096-step window that takes about a minute on the
simulator, this is small, but it is new work on every run and has to be measured (section 7).

**Solana limits used below.** 1,400,000 CU per transaction; 1,232 bytes per transaction (about
900 bytes left for instruction data with one signer and six accounts); heap 32 KiB, up to
256 KiB on request; an account grows by at most 10 KiB per instruction; `sol_sha256` costs 85
CU plus, per input slice, the larger of 10 CU and half a CU per byte, so a Merkle node
(`H(0x01 || left || right)`) costs about 120 CU and a 13-level path about 1,600 CU. An int8
multiply-accumulate in SBF code is a sign-extending load pair, a multiply and an add: about 8
CU unrolled (estimate). An fp32 add or multiply with openTPU's flush-to-zero and
round-to-nearest-even, in integer code, is about 80 CU (estimate); `exp2` (7 multiply-adds and
the exponent fix-up) about 1,300 CU, `recip` and `rsqrt` about 1,000, `log2` about 1,800.

Proof data larger than one transaction is staged: `write_proof(offset, bytes)` appends to a
proof buffer account (about 900 bytes per transaction), and `prove_step` reads it.

**Heavy opcodes are split into micro-steps.** Re-running a whole `MM` is out of reach: the
LFM2.5-230M step the demo names, `mm 8x1024 . 512x1024^T`, is 4.2 million MACs (about 34
million CU, 24 transactions of compute) and streams 512 KiB of weights (about 580 staging
transactions). Instead each heavy opcode has a fixed micro-step order, both sides run phase 3
over it with claims about the state after each micro-step, and the program re-executes one
micro-step. The order is part of the v4 specification and must match how the simulator
computes (for MM, `isum_P` over K-blocks per output element; isa.md, "Sums").

| Opcode | Micro-step | Reads (openings) | Writes | Proof data | CU (estimate) |
|:--|:--|:--|:--|--:|--:|
| `NOP`, `LI`, `ADDI`, `LOOP`, `BAR`, `HALT` | the step | header, the instruction (IMEM path) | header | ~0.6 KB | < 10k |
| `HALT CHAIN` | one DRAM leaf (4 instructions) into IMEM | DRAM leaf | IMEM leaves | ~1.5 KB | ~10k |
| `RLD` | the step | + one TMEM leaf | header | ~1.2 KB | ~8k |
| `WAITW` | one poll | + one DRAM leaf | one TMEM leaf | ~1.8 KB | ~10k |
| `LD` | one destination TMEM leaf (64 words) | up to 3 DRAM leaves | 1 TMEM leaf | ~3.4 KB | ~20k |
| `ST` | one destination DRAM leaf | up to 2 TMEM leaves | 1 DRAM leaf | ~2.5 KB | ~20k |
| `QACT` | one (row, block): 128 values | up to 3 TMEM leaves (+ CSCALE, RSCALE words) | 1 ACT leaf | ~2.5 KB | ~35k |
| `QACT` ROW mode | as above after one micro-step per block that claims its `amax` (a max is order-free) | | | | ~35k |
| `QST` | one destination DRAM leaf (strided bytes `es` can touch one leaf per byte) | up to 3 TMEM leaves | 1 DRAM leaf | ~2.5 KB | ~40k |
| `MM` | one output element `(j, n)`, all `KB` blocks | `KB` ACT leaves (row `j`), `KB` weight leaves (row `n`), the scale words, the old output word (ACC), alpha (ASCALE) | 1 TMEM word | ~0.3 KB per block + ~1.5 KB | ~1,900 per block + 10k: 25k at K = 1,024; 130k at K = 8,192; 250k at K = 16,384 |
| `MM` RMAX | one per row after its `N` elements (`chain_max` in `n` order, split by 64 columns) | | | | ~15k |
| `VOP` elementwise | one destination TMEM leaf (64 elements) | up to 2 leaves of A, of B (fewer in ROW, COL, SCALAR modes) | 1 TMEM leaf | ~2.5 KB | add / mul: ~10k; exp2: ~90k; log2: ~120k |
| `VOP` RSUM, RSSQ, RDOT | 64 columns of a row: one term into each of `isum_64`'s 64 partials (the partials are part of the micro-state); then the fold tree | 1-2 TMEM leaves | the 64 partials | ~1.5 KB | ~12k, fold ~6k |
| `VOP` RMAX, ARGMAX, OUTER | 64 columns of a row / one destination leaf | | | ~1.5 KB | ~15k |
| `GATHER` | one destination TMEM leaf, across slices | the source slice's TMEM leaves | 1 TMEM leaf | ~2.5 KB | ~20k |
| `DSTEP` | one state row (`cols` <= 256: the row in DRAM, q and k in TMEM) | 8 DRAM leaves, 8 TMEM leaves | 8 DRAM leaves, 1 TMEM word | ~9 KB | ~150k |
| `STREAM` | 64 columns of a row per pass (REDUCE A, then MAP / REDUCE Q), and the scalar ops | | | ~3 KB | ~60k |

Every micro-step fits one 1.4M-CU transaction with a wide margin; the largest proofs (MM at
K = 16,384: 128 blocks, about 36 KB with the paths; DSTEP) take 10-40 staging transactions.
An MM's micro-step count is `M x N` (4,096 for the demo's MM, 8 x 65,535 at most), so phase 3
adds `ceil(log16(M x N))` rounds: 3 for the demo, 5 at most.

The 4-bit weight formats (`W4I`, `W4F`, with `PAIR`) read half the bytes per block and add a
nibble decode and the sub-block multipliers: about 2 CU more per element.

**Events in a window.** A host write (`W`) is checked by hashing the staged data (it must give
the chain's data hash) and updating the DRAM leaves it covers; a run start (`R`) sets the
header (R8..R15 from the arguments, the rest 0, pc 0, empty stack); a host read (`O`) changes
no state, only the chain; the checkpoint fold (`C`) is the state root itself. For the output
fault (the traces agree, the receipt's answer or logits hash does not), v4 makes the logits
hash a Merkle root over the logits in 128-byte leaves (and the `O` event hashes that root), so
the program opens the Yes and No entries (two leaves, depth 11 for a 65,536-token vocabulary)
instead of 256 KB of logits.

**What it costs to build.** A second implementation of the ISA, in Rust for SBF, bit-exact
with `opentpu/isasim.py` and `opentpu/fp32.py` in every micro-step, including the fp32
functions, `isum_P`, `q8` and the NaN rules (isa.md, "Arithmetic"). A wrong bit in it slashes
honest providers. It needs shared test vectors from the simulator per opcode and micro-step,
as `tests/data/exact_settle_vectors.json` does for the payouts, and fuzzing of operands.

### 3.2 (b) A committee of staked verifiers

When phases 1-2 have named the step `s`, the program draws `n` verifiers from a staked
registry (stake-weighted, seeded by a slot hash after the step was named; the registry is the
one [verifier-incentives.md](verifier-incentives.md) proposes). Each re-runs the job to step
`s` and votes, by commit-reveal, on which claim at `s` is right. `t` matching votes decide;
members on the losing side or silent lose part of their committee stake; the winners are paid
from the loser's bond.

A member's work is a re-run up to the window (about 1 min for LFM2.5-230M); 7 members cost
about 7 x 0.008 USDC at the verifier cost used in verifier-incentives.md. Voting takes two
rounds (commit, reveal), about 2 x 1,500 slots.

The chance that an attacker holding a share `x` of the registry's stake draws `t` of `n` seats:

| n, t | x = 10% | x = 20% | x = 33% |
|:--|--:|--:|--:|
| 5, 4 | 4.6e-4 | 6.7e-3 | 4.5e-2 |
| 7, 5 | 1.8e-4 | 4.7e-3 | 4.5e-2 |
| 9, 6 | 6.4e-5 | 3.1e-3 | 4.2e-2 |
| 15, 10 | 1.9e-7 | 1.1e-4 | 8.5e-3 |

Bribery is the weaker point: the draw is public, so an attacker can approach the members after
it. Bribing `t` members costs at least `t x s_c` (what each would lose), which has to exceed
what the dispute is worth to the provider: its stake plus the price. With `min_stake` 1,000
USDC and `t = 5`, each member must stake more than 200 USDC. Liveness needs `t` of `n` honest
and online; a committee that fails to reach `t` falls back to (c)'s rule or to the arbiter.

The committee replaces one trusted key by a stake-weighted majority. It needs no executor, so
it covers every opcode the day it ships.

### 3.3 (c) An optimistic counter-challenge

A ruling, from whoever proposes it (the arbiter, a committee, or a bonded proposer), stands
unless someone counters it within `counter_window` with a bond. A counter escalates: round `r`
needs a bond of `B_0 x 2^r` and gets a longer window; the last round is decided by a backstop.

| Round | Bond | Window |
|:--|--:|--:|
| 0: the ruling | (the proposer's) | 9,000 slots (~1 h) |
| 1: a counter | 10 USDC | 9,000 slots |
| 2: a counter of the counter | 20 USDC | 18,000 slots |
| 3: backstop | 40 USDC | the backstop's own |

One honest watcher with 70 USDC can push a wrong ruling to the backstop; the losing side's
bonds pay the winner. But in TDCC the two sides of the game are already bonded opponents with
opposite claims about one step, so a counter-challenge adds a third party who says the same
thing one of them says. It does not end the game by itself: two parties that disagree about
one instruction can counter each other until the last round, and the last round needs (a), (b)
or the arbiter. What (c) buys is that the backstop is used only when someone pays to use it,
and that its rulings are public and narrow (one step).

### 3.4 Comparison

| | (a) one-step proof | (b) committee | (c) optimistic |
|:--|:--|:--|:--|
| Trust | the program's code (the executor) | `t` of `n` stake-weighted members | the backstop, when invoked |
| Removes the arbiter | yes, for every ported opcode | yes | no, on its own |
| Covers | each opcode once its executor ships | every opcode at once | whatever the backstop covers |
| Final-step time | 1 + staging transactions, minutes | ~2 x 1,500 slots + re-runs | the counter windows: hours |
| Cost per dispute | ~5-45 transactions | ~n re-runs + fees, from the bond | the bonds, if countered |
| Build cost | high: an ISA executor in SBF, bit-exact, with micro-steps | medium: registry, draw, commit-reveal votes, member slashing | low on top of phases 1-2 |
| Failure mode | an executor bug slashes the honest side | collusion or bribery of `t` members | a captured backstop |

## 4. Recommendation

Build (a), in phases, and keep the arbiter only for the opcodes (a) does not cover yet, with
its rulings narrowed to one named step. Every opcode fits one transaction once heavy ones are
split into micro-steps (section 3.1), so the committee is not needed as the end state; it is
the fallback if measurement (section 7) shows an executor does not fit, or if a market wants
the arbiter gone before phase D.

| Phase | What ships | Who decides the last step | Arbiter |
|:--|:--|:--|:--|
| A | The game on-chain (phases 1-2 of section 2.2, today's v3 trace), timeouts and loss by default; `challenge` takes the challenger's root | the arbiter, on the one step the game named: `rule_step(winner)` against the two posted claims | rules on one step; cannot slash outside a game, cannot rule after `final_window` |
| B | Trace v4 (state root, DRAM root as the model hash, Merkle logits); executor for the control, scalar and memory opcodes and the events: `NOP LI ADDI LOOP BAR HALT RLD WAITW LD ST`, `W R O C` | the program for those; the arbiter for the rest | rules on `MM VOP QACT QST GATHER DSTEP STREAM` |
| C | Micro-steps and executors for `MM`, `QACT`, `QST`, `VOP` (elementwise, then the reductions), `GATHER` | the program | rules on `DSTEP`, `STREAM` only: never for the two pinned models, built for the design config, which has neither (the tiny model runs VOP, MM, QACT, LD, GATHER, QST, ADDI, LI, LOOP, HALT, ST) |
| D | `DSTEP`, `STREAM` | the program | retired: `Config.arbiter` set to none, `set_arbiter` refused |

Phase A already removes most of what the arbiter can do wrong today: it can no longer slash a
provider whose list is fine up to the window, or rule on a window or step the game did not
name; a silent arbiter ends the game by the default rule instead of holding the job. Its
ruling names one step that anyone can check by replaying to it.

A market declares which opcodes its executor covers (`Config.proof_ops`, a bitmask); a game
that ends on an opcode outside it goes to the arbiter (phases A-C) or, if the market has no
arbiter, to the committee.

## 5. Program changes

### Accounts

| Account | Seeds | Change |
|:--|:--|:--|
| `Config` | `config, admin` | add `move_window`, `final_window`, `max_checkpoints`, `max_window`, `max_micro`, `proof_ops`, `trace_version`; `arbiter` becomes optional (`Pubkey::default()` = none, from phase D); `arbiter_window` is replaced by `dispute_window` in the cooldown bound |
| `Job` | `job, config, renter, job id` | add `version: u8`, `dispute: Pubkey`; `state` gains `Disputed` (replaces `Challenged` for v2 jobs) |
| `Dispute` (new) | `dispute, job, challenge_slot` | provider, challenger, the challenger's trace root and count, phase, `lo`, `hi`, round, deadline, the round's queries, which sides moved, the agreed claim at `lo`, the two claims at `hi`, the posted claims of the round (2 x 15 x 32 bytes), the instruction under phase 3 and its micro-step count, the bond: about 1.2 KB, rent paid by the challenger, closed at the end |
| `ProofBuf` (new) | `proof, dispute, poster` | up to 64 KB of staged openings; closed by `prove_step` |

### Instructions

| Instruction | Who | What |
|:--|:--|:--|
| `challenge(fingerprint, tree_root, count)` | a verifier, with the bond | as today, plus the challenger's commitment; opens the `Dispute` |
| `open_leaf(round, index, step, chain, state, path)` | either side, phase 1 | checks the opening against that side's root; the second opening of a round advances it |
| `post_claims(round, claims: [[u8; 32]; 15])` | either side, phases 2-3 | the round's claims; the second post advances it; entering phase 3 decodes the instruction from the claims' agreed pre-state |
| `write_proof(offset, bytes)` | anyone | stages proof data |
| `prove_step()` | anyone | phase 4: re-executes the step or micro-step from the staged openings, compares with the two claims, resolves |
| `rule_step(winner)` | the arbiter | phase 4, only when the step's opcode is outside `proof_ops` (phases A-C) |
| `timeout()` | anyone | after a round's deadline: the side that did not move loses |
| `slash`, `dismiss` | — | become internal: the game's resolution pays out as today (renter refunded, `verifier_bps` of the stake and the bond to the challenger, the rest to TDCC; or the bond to the provider and the job back to `Revealed`) |

### Events

- `DisputeOpened { job, provider, challenger, provider_count, challenger_count, deadline }`
- `DisputeRound { job, phase, round, lo, hi, deadline }`
- `WindowNamed { job, divergence_index, lo_step, hi_step }` (end of phase 1)
- `StepNamed { job, step, slice, pc, opcode, micro_steps }` (end of phase 2)
- `StepProven { job, step, micro, opcode, winner }` / `StepRuled { job, step, winner, arbiter }`
- `DisputeTimedOut { job, loser, round }`
- `Slashed` and `Dismissed` gain `how` (proof, timeout, no-difference, bad-opening, arbiter) and
  `fault_micro`.

### Errors

`NotYourTurn`, `RoundClosed`, `BadOpening`, `BadClaims`, `WindowTooLong`, `OpcodeNotProvable`,
`ProofIncomplete`.

## 6. Migration from today's arbiter

1. **A new program version, new markets.** `Config` and `Job` change layout, and the program
   has no migration path for either today. Deploy the new version under the same program id
   (an upgrade); v1 accounts keep their instructions (`challenge` without a root, the arbiter's
   `slash` and `dismiss`) until they close, and `initialize` creates only v2 markets. A
   market's admin stops opening v1 jobs; the last v1 job is ruled by the arbiter within its
   `arbiter_window` (216,000 slots in the example config).
2. **Nodes.** The verifier node sends the new `challenge` with its root and plays the
   challenger's side (it holds its own run); the provider node plays the provider's side (it
   already replays its window for the arbiter, `node/__init__.py`'s protocol). The arbiter
   node shrinks to `rule_step` on named steps in phases A-C. The store is still useful for the
   off-chain look at a trace, but the game no longer depends on it: a side that cannot open a
   leaf loses on-chain.
3. **Trace v4** (phase B) changes every fingerprint, the model hashes and the registry pins
   (`models.json`): v4 jobs carry `trace_version = 4` in their digest, and a market switches
   with a new config. v3 and v4 markets can run side by side.
4. **Docs.** exact.md section 3 and 6, threat-model.md (arbiter rows, "What a slash proves
   today"), architecture.md (the sequence diagram), operations.md (the windows) change with
   each phase.

## 7. Open questions and what to measure first

- **CU of the executor.** Build `MM` one-element and `VOP exp2` one-leaf as an SBF program and
  measure on `solana-test-validator` before committing to phase C; the estimates above have a
  wide margin, but the soft-float cost per operation is a guess.
- **The provider's cost of v4.** The TMEM, ACT and DRAM roots at every checkpoint, measured on
  LFM2.5-230M against the +14% the log costs today.
- **`job.every`.** A shorter interval makes the window and phase 2 shorter but the trace and
  the checkpoint hashing larger (TODO.md item 9).
- **Two slices.** The design config has `S = 2`; the schedule in the state root must reproduce
  `Machine.run`'s order exactly, including `GATHER`'s deferred copy and `WAITW` polling.
- **Card and simulator.** The game decides between two traces of the simulator's semantics; a
  card that drifts from it (threat-model.md, assumption 1) loses games it ran honestly.
