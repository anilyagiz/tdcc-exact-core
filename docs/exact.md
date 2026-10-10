# TDCC Exact: the trace log, the fingerprint and the dispute

Exact Core gives the same bits on the card as on the simulator (README, "Validating against
Hugging Face"), so anyone can re-run a job on a laptop and get the provider's exact answer.
TDCC Exact turns that into a market: a provider posts a fingerprint of its work, a verifier
re-checks it, and a mismatch is settled by finding the one instruction that differs.

The code is in [`tdcc_exact/`](../tdcc_exact). The only change to the openTPU design is an
observer hook in `isasim.Machine.run`, called after each instruction a slice steps.

## 1. The trace log (`tdcc_exact/trace.py`)

Every instruction the simulator steps extends a hash chain (SHA-256, the hash Solana's runtime offers as a syscall):

    chain = H(chain || slice || pc || the instruction's 8 words || R0..R15 after it)

Every 4096 steps, and when each device run ends, the log takes a checkpoint: a hash of each
slice's working state (TMEM, the ACT RAM and its scales, the registers, the pc), folded into
the chain. A checkpoint's leaf is `H(step || chain || state)`, and the trace root is the
Merkle root of the leaves.

The host's writes into DRAM between runs (the token, its embedding row) and each run's
arguments go into the chain too, so the log covers the inputs as well as the work.

DRAM is not hashed at checkpoints: the 4 GiB card's weights would dominate, and they are
pinned by the model hash instead. What a run stores to DRAM it stores from TMEM, and what it
loads back lands in TMEM, so a wrong value is caught there.

## 2. The receipt (`tdcc_exact/oracle.py`)

An oracle job names a model, the prompt's token ids (so the verifier needs no tokenizer) and
the Yes and No tokens. The provider runs the prompt through the engine on the traced backend,
answers with whichever of the two tokens has the larger logit, and posts:

    fingerprint = H(job || model image || answer || last logits || trace root)

Two honest runs give the same fingerprint, on any machine. In the demo the cheating provider
often gives the **same answer** as the honest one; only the fingerprint shows the difference.
That is the case a buyer cannot see on a GPU marketplace.

## 3. The dispute (`tdcc_exact/dispute.py`)

1. **Bisection.** Once a run goes wrong its chain differs at every later checkpoint, so a
   binary search over the two checkpoint lists finds the first differing one in
   log2(checkpoints) rounds. This is the game an on-chain referee plays, one round per
   transaction.
2. **Replay.** Both sides replay that window and record each step: where it ran, its
   encoding, the chain, and a hash of the slice's state. The first record that differs is the
   fault: `control` if a different instruction ran, `state` if the same one gave a different
   result.

On the tiny model, provider B skips one layer's matrix multiplies. The dispute names the
first skipped `MM` in 5 rounds over 26 checkpoints.

In a live market the provider replays its own window when it is challenged, and a provider
that will not reveal it loses by default. In the demo and the tests both sides are replayed
locally, the provider with the shortcut it took (`--replay-skip-layer`).

## 4. Settlement (`tdcc_exact/settle.py`)

- **Accepted:** 80% of the price to the host, 20% to TDCC.
- **Slashed:** the renter's escrow is refunded, the verifier gets half of the provider's
  stake, and TDCC gets the rest.

The Solana program that holds the escrow and the stakes and executes these transfers is a
separate piece; this module only computes them.

## Status

| Piece | State |
|:--|:--|
| Trace log, fingerprint, dispute | on the bit-exact ISA simulator, tested (`tests/test_exact.py`) |
| Trace log in RTL / on the card | not built: the card has a performance trace (`otpu_trace.sv`), not this hash chain |
| Overhead of the log | not measured on LFM2.5-230M yet |
| Solana program | not in this repository |
