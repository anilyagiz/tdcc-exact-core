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

Shares are in basis points, rounded down, with the remainder to TDCC; the Python module and
the program compute the same numbers, and both are tested against
`tests/data/exact_settle_vectors.json` (odd amounts up to `u64::MAX`).

## 5. Receipts people can stake money on

- **The copy attack.** Honest runs post the same fingerprint, so a provider could copy
  another's receipt without running anything. Receipts are posted by commit-reveal
  (`tdcc_exact/commit.py`): first `SHA-256("tdcc-exact/commit/v1" || fingerprint || provider
  key || salt)`, then, after the commit deadline, the fingerprint and the salt. A commitment
  binds its provider's key, and by the time fingerprints are public the commit window is shut.
- **Digest size.** Every hash is SHA-256 (32 bytes): 128-bit collision resistance, and the
  hash Solana's runtime computes as a syscall, so the program can check commitments (and,
  later, Merkle paths of the trace).
- **Model identity.** The model hash is the hash of the DRAM image the engine builds, which
  depends on the build (weight format, KV cache size, design config) as well as the weights.
  `tdcc_exact/models.json` pins `(model, wformat, cap) -> image hash`
  (`tdcc-exact registry add --model ...`); `verify` rejects a receipt with another hash before
  re-running anything, and the program rejects a reveal whose model hash is not the job's. A
  provider that runs fp4 instead of int8 is caught there (`tests/test_exact.py`).

## 6. The Solana program (`programs/tdcc_exact`)

An Anchor program; `tdcc_exact/chain.py` is its client, `tdcc-exact demo --localnet/--devnet`
runs the demo against it.

| Account | Seeds | Holds |
|:--|:--|:--|
| `Config` | `config, admin` | the mint (USDC), the treasury, the vault, 80/20 and 50/50 in bps, the windows (slots), the minimum stake, the unstake cooldown |
| vault | `vault, config` | one token account for every escrow and every stake; its authority is the config |
| `Provider` | `provider, config, owner` | the stake, open jobs, a pending unstake |
| `Job` | `job, config, renter, job id` | the job digest, the expected model hash, the price, the state, the deadlines, the commitment, the revealed fingerprint and trace root, the challenger |

A market is a config, seeded by its admin's key, so anyone can run one (the demo makes its own
test USDC mint). The admin is also the **arbiter**: it signs `slash` (or `dismiss`) after the
off-chain bisection names the faulty step, which goes into the `Slashed` event. Replacing the
arbiter by an on-chain bisection game is TODO.md item 6.

| Instruction | Who | When |
|:--|:--|:--|
| `register_provider`, `stake`, `request_unstake`, `unstake` | provider | unstake after the cooldown and with no open jobs |
| `open_job` | renter | the provider is staked; the price moves into the vault |
| `commit_receipt` | the job's provider | until `commit_deadline` |
| `reveal_receipt` | the job's provider | after `commit_deadline`, until `reveal_deadline`; opens the commitment, model hash must be the job's |
| `challenge` | anyone but the provider | until `challenge_deadline`, with another fingerprint |
| `settle` | anyone | revealed, unchallenged, after `challenge_deadline` |
| `slash`, `dismiss` | the arbiter | challenged |
| `expire` | anyone | no reveal by `reveal_deadline`: the escrow goes back to the renter |

Tests: `cargo test -p tdcc_exact` (the settlement vectors, the commitment vector) and
`tests/test_chain.py` on `solana-test-validator` (honest settle, slash, a copied commitment,
an early reveal, a wrong model hash, a wrong signer, expiry, double settle, a dismissed
challenge; each checks the program's error code). CI runs both.

Not yet: a challenge bond, verifier selection, the on-chain bisection (TODO.md items 6, 7).

## Status

| Piece | State |
|:--|:--|
| Trace log, fingerprint, dispute | on the bit-exact ISA simulator, tested (`tests/test_exact.py`) |
| Trace log in RTL / on the card | not built: the card has a performance trace (`otpu_trace.sv`), not this hash chain |
| Overhead of the log | not measured on LFM2.5-230M yet |
| Receipts: commit-reveal, SHA-256, model registry | done, tested |
| Solana program | `programs/tdcc_exact`, tested on a local validator; challenges decided by an arbiter |
