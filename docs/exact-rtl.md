# TDCC Exact's trace engine in RTL

`rtl/exact/` computes the trace log's hash chain (`tdcc_exact/trace.py`, docs/exact.md §1) in
hardware, so a card can post the chain of the run it actually executed instead of re-running it
on the ISA simulator. The engine is standalone: nothing in `rtl/seq`, `rtl/top` or the board
instantiates it yet. The integration plan below says where it goes.

| file | what |
|:--|:--|
| `rtl/exact/exact_sha256.sv` | SHA-256 core: messages of any length streamed in as 32-bit words, padding made inside |
| `rtl/exact/exact_trace.sv` | the trace engine: step FIFO, message formatting, chain, counters, control registers |
| `rtl/exact/tb/*.sv` | file-driven testbenches (the tests write the files) |
| `tests/test_exact_rtl.py` | the RTL against `hashlib` and `TraceLog`, bit for bit |

`make exact-rtl` lints both modules with Verilator (`-Wall`, clean) and runs the tests.

## Verification

Simulated with Verilator 5.020 (`--binary --timing`), and with Icarus Verilog 12 as the
fallback (`EXACT_RTL_SIM=iverilog`); the tests skip when neither is installed.

- **SHA-256:** the NIST vectors (empty, "abc", the 448-bit and 896-bit two-block messages) and
  random messages of every length 0..200 bytes (every padding case: the 0x80 inside the last
  data word or in a word of its own, the length in the same block or the next; up to four
  blocks) equal `hashlib.sha256`.
- **The chain:** a tiny-model oracle job (`run_job`, two slices, a checkpoint every 512 steps)
  recorded with every event revealed: the binding, 3,666 steps, 18 host writes, 2 host reads,
  3 run starts and 11 checkpoint folds, 3,700 events. The testbench plays the sequencer (steps
  pushed back to back under valid/ready, into an 8-entry FIFO) and the host (the control
  registers). The chain after every event equals TraceLog's, as do the step and event counters
  and the chain the host reads through the registers. The checkpoints at the pauses are posted
  five steps late, so those steps wait in the FIFO; the engine still hashes the C first.
  A second test does the same with a pause every 2 steps.
- A mutation check (the pause disabled) fails both chain tests.

Not simulated: the engine inside `otpu_seq` / `otpu_slice` (no hook exists yet), and anything
in Vivado (no synthesis or timing run; the area below is from Yosys).

## The messages

Every event moves the chain to SHA-256(chain || message), exactly as `TraceLog`:

| event | message after the 32-byte chain | bytes with chain | SHA blocks |
|:--|:--|--:|--:|
| step | slice (2, LE), pc (4, LE), the instruction's 8 words (32, each LE), R0..R15 after it (64, each LE) | 134 | 3 |
| W (host write) | "W", slice (2), address (8), H(data) | 75 | 2 |
| O (host read) | "O", slice (2), address (8), length (8), H(data) | 83 | 2 |
| R (run start) | "R", the arguments (4 each, LE; `[0]` without arguments) | 37..65 | 1..2 |
| C (checkpoint) | "C", H(each slice's state hash) | 65 | 2 |
| INIT | (no chain) "tdcc-exact/trace/v3", binding (32) | 51 | 1 |

The engine formats steps itself from the sequencer's signals. For W, O, R and C the host writes
the kind byte and up to 64 payload bytes; the hashes in those payloads (of the data the host
wrote or read, of the slices' states) are the host's. The host has that data anyway; the state
hash is the part a card does not compute yet (below).

## Interface

```
exact_trace #(.DEPTH(16))           // step FIFO entries, a power of two >= 4
  step_valid / step_ready           // valid/ready: a step waits until it is taken
  step_afull                        // flip-flop: at most one FIFO entry free
  step_slice[15:0], step_pc[31:0]
  step_ir[255:0]                    // word k in [32k +: 32]: otpu_seq's ir as it is
  step_regs[511:0]                  // R[k] in [32k +: 32], after the instruction
  reg_we, reg_addr[5:0], reg_wdata, reg_rdata   // rdata: one cycle after the address
  chain[255:0], upd, steps[63:0]    // for a monitor: upd pulses when the chain moved
```

Control registers (word addresses). Byte strings are little-endian words: word k holds bytes
4k..4k+3, byte 4k in bits [7:0], so the host packs and unpacks them with `"<u4"`.

| word | name | | |
|:--|:--|:--|:--|
| 0x00 | CTRL / STATUS | W | bit0 INIT, bit1 POST |
| | | R | bit0 BUSY (hashing, or a step / INIT / POST waiting), bit1 CKPT_WAIT, bit2 POST pending, bit3 INIT pending, bit4 FIFO empty, bit5 FIFO full, bit6 READY (initialized), [23:16] FIFO entries |
| 0x01 | EVERY | RW | steps between checkpoint pauses (0: none) |
| 0x02 | AUX_KIND | RW | [7:0] the event's kind byte ("W" "O" "R" "C") |
| 0x03 | AUX_LEN | RW | payload bytes, 0..64 |
| 0x04, 0x05 | STEP_LO, STEP_HI | RO | steps since INIT |
| 0x06 | EVENTS | RO | posted events since INIT |
| 0x07 | STALL | RO | cycles a step waited on a full FIFO (saturating) |
| 0x08 + k | CHAIN | RO | k = 0..7 |
| 0x10 + k | BINDING | RW | k = 0..7 |
| 0x20 + k | AUX_DATA | RW | k = 0..15 |

**Order.** The engine hashes a posted event only when the FIFO is empty and nothing is being
hashed, or while it is paused at a checkpoint. The host posts W, O and R only while the core is
not running (poll STATUS BUSY = 0 first), as `TraceLog` sees them: writes before a run, the run
start, reads after the halt.

**Checkpoints.** With EVERY = n, after every n-th step (n, 2n, ...: the count since INIT, which
is `TraceLog.step`) the engine stops taking steps (CKPT_WAIT) until the host posts a C. The
FIFO fills behind it and holds the sequencer, which is `TraceLog.observe`'s checkpoint at
`step % every == 0` in hardware order. The other checkpoints (each run's end and `finish`, and
the skip of a checkpoint that would repeat the last one) are the host's ordinary posts.

## Timing

The SHA core runs one round per cycle. A block costs 66 cycles in the compressor (take the
block and load a..h, 64 rounds, add into H); the loader fills the next block meanwhile. A
message of B blocks takes about 66 B + 17 cycles from start to digest (measured: 83, 149 and
215 cycles for 1, 2 and 3 blocks). The chain makes events strictly serial: the next message
starts with this digest.

- **A step: 217 cycles** back to back (215 for the 3-block hash, one to take the next step,
  one to store the chain); a W, O or C event about 150, an R 85 or 150, INIT 85.
- The floor for trace.py's format is three compressions per step (192 rounds); 217 is within
  13% of it at one round per cycle. Going lower takes two rounds per cycle (a longer path, so
  likely not at 133.33 MHz) or a format with fewer blocks per step.
- In the tiny-model test (3,666 steps, the testbench pushing at one step per cycle: the worst
  case) the run took 798,250 cycles, 216 per event.

**Against the sequencer.** The sequencer issues at most one instruction per cycle, so on dense
scalar code (LI, ADDI, LOOP, NOP, back-to-back dispatches) the engine is about 200 times
slower and holds the core once the FIFO is full. Real programs are dominated by long unit
instructions. Estimate for LFM2.5-230M decode, from figures elsewhere in docs: about 4,500
steps per one-token run (docs/exact.md §7, the ISA simulator's step counts) is 0.98 M engine
cycles, against 1.49 M core cycles for the token at 133.33 MHz (11.18 ms, docs/autodecode.md).
So the engine keeps up on average (busy about 65% of the run) and stalls the core only where a
burst of short instructions outruns the FIFO; a 16-entry FIFO absorbs 16 steps, about 3,500
cycles of engine work. The slowdown is therefore expected to be a few percent, not a multiple,
but this is an estimate: the STALL register measures it on the card, and DEPTH can grow
(the FIFO is LUT RAM: up to 32 entries cost the same 136 RAM32M as 16, 64 about twice that). After the halt the host waits for BUSY = 0, at
most DEPTH x 217 cycles (26 us for 16 entries).

**Clock.** Not run through Vivado. The round's long path is a + = hkw + S1(e) + Ch + S0(a) + Maj,
five 32-bit terms (h + K[t] + W[t] is computed a round early to take three terms off it);
single-round SHA-256 cores of this shape usually close above 133 MHz on 7-series, but that has
to be shown at the card's utilization.

## Area (estimate)

Yosys 0.33 `synth_xilinx -family xc7`, flattened (not Vivado, whose counts will differ):

| | LUT (logic) | LUT RAM | FF | CARRY4 |
|:--|--:|--:|--:|--:|
| `exact_sha256` | 1,950 | 0 | 1,680 | 132 |
| `exact_trace`, DEPTH = 16 (with the core) | 3,720 | 136 RAM32M (544 LUTs) | 4,100 | 186 |

About 1.4% of the xc7k480t's 298,600 LUTs and 0.7% of its FFs. The largest parts after the core
are the 136-byte message shift register (1,088 FFs) and the three message sources multiplexed
into it, and the 768 bits of BINDING and AUX_DATA registers (which could move to LUT RAM).

## Integration plan

Into the slice (`otpu_slice` instantiates `exact_trace` next to `otpu_seq`; S = 1 on the card)
and the board's control registers. Nothing below is implemented.

**A step per instruction, from otpu_seq.** `TraceLog.observe` runs after each instruction the
ISA simulator steps, with the registers after it. In `otpu_seq` the R stage executes (in the
`always_ff` case on `op`):

| instruction | when it is a step | R after it |
|:--|:--|:--|
| NOP, LI, ADDI, unit instructions | the cycle `advance()` runs | the next cycle's R (LI / ADDI write at that edge) |
| LOOP | its second cycle (`lp` = 1) | R (unchanged) |
| HALT (and HALT CHAIN) | the cycle it sets `stopping` | R |
| RLD | not at dispatch: the cycle after `rl_v` (R[rd] is written then) | R |
| an illegal instruction | never (the ISA simulator raises) | |

So the hook is a one-cycle stage in `otpu_seq`: a flip-flop `tr_v` with `tr_pc <= pc`,
`tr_ir <= ir` set in those cycles (for RLD: keep its pc and ir at dispatch, raise `tr_v` the
cycle after `rl_v`), and the step is `{tr_v, tr_pc, tr_ir, R}` one cycle later, when R already
holds the instruction's write. `step_slice` is SID. A new output port group on `otpu_seq`, an
`ifdef`-free addition the rest of the design does not see when left open.

**Holding the core.** `otpu_seq` needs one input, `tr_hold` = `step_afull` (a flip-flop, so the
fetch-enable path gains one registered term, as the RLD hold does): `ld` and the R stage's
execute condition (`!halted && ir_v && !rl_wait`) also require `!tr_hold`, and LOOP's first
cycle too. Why it is enough: afull low means at least two free entries at the start of the
cycle; an instruction executed in that cycle pushes one cycle later, and the push from the cycle
before takes at most one of them. An RLD's step cannot be held (the value arrives when it
arrives), but the RLD itself was issued under the same rule and R holds while it is out, so no
other step pushes in that window. `step_valid` is `tr_v`; `step_ready` is never low when it
matters (a debug assertion).

**Control registers.** `otpu_ctrl` (register map version 3, docs/observability.md) decodes 12
address bits; 0x300..0x3BF is free. Map the engine's word w to byte address 0x300 + 4w (CTRL at
0x300, CHAIN at 0x320..0x33C, BINDING at 0x340, AUX_DATA at 0x380), announce it with CAPS bit28
(free), and bump REGMAP to 4. The engine's one-cycle read fits `otpu_ctrl`'s three-cycle read
path. The host side: `TracedBackend`'s `write` / `read` / `run` and `TraceLog.checkpoint` post
their events to the card instead of hashing (the payload hashes as now), INIT with the job's
binding before the first write, EVERY = the job's interval, and the receipt reads CHAIN and
STEP.

**More than one slice.** `TraceLog` interleaves slices in `isasim.Machine.run`'s order (each
slice runs until it blocks on a collective or halts, slice 0 first). The card has one slice. A
multi-slice build needs per-slice step FIFOs and a merger that drains them in that order (the
blocking points are the collective instructions, visible in the steps), or a protocol change
to per-slice chains.

## What is left for the card

- **The state hash.** A checkpoint folds H(each slice's state_hash): TMEM, ACT RAM and its
  scales, R and pc, and `stores`, a running hash of every word ST / QST / DSTEP / STREAM wrote
  (`backend._TracedSlice`: the sorted, de-duplicated word indices and their contents after the
  instruction, per instruction). The engine leaves all of it to the host. On the card this needs
  (a) a state reader at a pause: TMEM (64K words, 256 KB), the ACT RAM and scales through a
  read port while the sequencer is held, into a second SHA core or this one (about 4K blocks
  for TMEM: 270K cycles, 2 ms at 133.33 MHz per checkpoint, every 4,096 steps); (b) the stores
  hash, which in its present definition sorts the addresses an instruction touched, natural in
  numpy and awkward in hardware. Either the host derives it (it has the step's instruction and
  registers, so the footprint, and can read the words back at the pause), or a protocol v4
  defines it in write order.
- **Timing closure at 133.33 MHz** in Vivado with the engine in the slice, and the FIFO depth
  from the STALL register on real models.
- **The hook in `otpu_seq`** and the registers in `otpu_ctrl` (above), with a whole-core test:
  `rtlsim` running a model with the engine on, its chain against `TraceLog` on the ISA
  simulator.
- HALT CHAIN's program reload, WAITW and GATHER need no special case in the engine (they are
  steps like the others), but are covered by no test yet.
