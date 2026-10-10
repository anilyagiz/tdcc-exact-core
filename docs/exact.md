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

The prompt goes in with `Engine.prefill`: device runs of `job.chunk` tokens (8), each one
program that streams every weight once for its 8 rows. The logits are bit-identical to feeding
the prompt token by token, but the trace is not (other programs run), so the chunk is a field
of the job (in its digest) and the verifier runs the same runs. The same `Engine` runs Qwen3
and LFM2: `opentpu.llm.load_spec` picks the Spec by the checkpoint's `model_type`, and the
Spec's image compiles the model's own kernels (`lfm2_step` / `lfm2_rows` for LFM2).

The job's prompt is the chat template with a system line ("Answer with exactly one word: Yes
or No.") and the question. In LFM2.5's tokenizer "Yes" (12948) and "No" (5048) are one token
each; a tokenizer that splits them would use the first token of each (`new_job`).

## 3. The dispute (`tdcc_exact/dispute.py`)

1. **Bisection.** Once a run goes wrong its chain differs at every later checkpoint, so a
   binary search over the two checkpoint lists finds the first differing one in
   log2(checkpoints) rounds. This is the game an on-chain referee plays, one round per
   transaction.
2. **Replay.** Both sides replay that window and record each step: where it ran, its
   encoding, the chain, and a hash of the slice's state. The first record that differs is the
   fault: `control` if a different instruction ran, `state` if the same one gave a different
   result.

Provider B (`SkipLayer`) skips one layer's matrix multiplies, its mixer's (attention, or
LFM2's short convolution) and its MLP's, in every run. The layers repeat inside a hardware
LOOP (LFM2: layer 0, then the unit (conv, attention) six times, then layer 13), so one MM of
the program runs for several layers. B tells them apart by the compiler's source frames
(`Instr.src`: `_conv*` / `_attention*` / `_mlp`) and counts layers as they run: a mixer MM
after an MLP MM starts the next layer.

On the tiny model the dispute names the first skipped `MM` in 2 rounds over 3 checkpoints. On
LFM2.5-230M (skipping layer 7, a conv layer: 88 MMs a run, 440 over the job's 5 runs) it
names it in 5 rounds over 21 checkpoints: `mm 8x1024 . 512x1024^T`, step 7166 of 66862.

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

## 7. Overhead of the log

Measured on LFM2.5-230M (int8, `cap` 256), on the ISA simulator, one process on a 4-core
cloud VM (Linux, Python 3.13, numpy). The job: "Is Paris the capital of France?" in the chat
template, 31 tokens, prefilled in runs of 8 (4 runs).

| | plain `IsaBackend` (log off) | `TracedBackend` (log on) |
|:--|--:|--:|
| prompt, 31 tokens in 4 runs | 32.5 s (1.05 s / token) | 37.0 s (1.19 s / token, +14%) |
| one decode step (1 token, 1 run) | 3.98 s | 4.05 s |
| the same prompt token by token (31 runs, before this change) | 144 s (4.65 s / token) | |
| engine build (DRAM image) | 10-17 s | 10-17 s |

Logits with the log on and off are bit-identical (checked). Per job, at `EVERY` = 4096:

- **Steps (instructions):** 62,358 for the 31-token prompt, 66,862 for the demo's 36 tokens.
- **Checkpoints:** 20 and 21 (one per 4096 steps, plus one at the end of each run).
- **Trace JSON** (`--trace`): about 150 bytes per checkpoint with the SHA-256 digests
  (2.6 KB for a 17-checkpoint job). The timings above were taken with the earlier
  blake2b-128 chain; a re-run with SHA-256 (55 s for the whole job, engine build included)
  is within the noise of the 37 s + build above.
- **`tdcc-exact demo --model models/LFM2.5-230M`:** 5 min 45 s end to end (36-token
  question): job and tokenizer 6 s, A 58 s, B 52 s, the verifier 58 s, the bisection's
  re-run 54 s, the two window replays 115 s (each a whole run that also hashes the slice's
  state after each of the window's 4096 steps). Every run includes its engine build.
- **`tdcc-exact demo`** (tiny model): 11.6 s, 24 s before the prompt went in with prefill
  (same machine).

So the log costs about 14% on the simulator: hashing each instruction in Python
(`TraceLog.observe`) is small next to simulating it. The window's per-step state hashes
add little to a replay (a few seconds over 4096 steps). The demo's time goes into the six
whole runs; a verifier that only checks a receipt runs once (about 1 min for this job).

## 8. Answer quality (LFM2.5-230M)

Seven questions with known answers, run as oracle jobs on Exact Core (`run_job`), next to the
fp32 numpy reference (`opentpu.llm.lfm2.reference_logits`) on the same token ids:

| Question | Right | Exact Core | logit Yes / No | fp32 reference |
|:--|:--|:--|:--|:--|
| Is Paris the capital of France? | Yes | **Yes** | 27.70 / 21.80 | Yes (28.16 / 22.06) |
| Is 7 an even number? | No | Yes | 29.17 / 23.34 | Yes (29.48 / 23.65) |
| Is the Pacific the largest ocean on Earth? | Yes | **Yes** | 27.20 / 22.88 | Yes (27.52 / 23.07) |
| Do spiders have six legs? | No | Yes | 27.84 / 23.19 | Yes (27.98 / 23.42) |
| Is water made of hydrogen and oxygen? | Yes | **Yes** | 27.36 / 23.11 | Yes (27.45 / 23.24) |
| Is the Sun a planet? | No | Yes | 28.17 / 22.86 | Yes (28.42 / 23.06) |
| Is 2 + 2 equal to 5? | No | Yes | 28.89 / 23.56 | Yes (29.07 / 23.80) |

Exact Core agrees with the fp32 reference on every question (its int8 logits are within
about 0.5 of fp32), so the oracle computes the model faithfully. But **the model answers Yes
to everything**: 3 of 7 right, only the Yes questions. The 230M model is not a yes/no oracle
with this prompt. Other prompts, scored on the fp32 reference over 10 questions (5 Yes, 5 No):
the system line "Answer with exactly one word: Yes or No." 5/10 (all Yes), a question ending
"Answer Yes or No." 5/10 (all Yes), a "careful, truthful assistant" system line 5/10 (all
Yes), no system line 7/10 (but with margins of 0.0-0.4 on three of them). The demo shows that
the work is verifiable, not that this model's answers are right; a real oracle needs a larger
model, or a calibrated threshold (the Yes - No margin against a content-free prompt's).

## Status

| Piece | State |
|:--|:--|
| Trace log, fingerprint, dispute | on the bit-exact ISA simulator, tested (`tests/test_exact.py`; LFM2.5-230M when `models/LFM2.5-230M` exists) |
| Trace log in RTL / on the card | not built: the card has a performance trace (`otpu_trace.sv`), not this hash chain |
| Overhead of the log | measured on LFM2.5-230M (section 7): +14% on the simulator |
| Receipts: commit-reveal, SHA-256, model registry | done, tested |
| Solana program | `programs/tdcc_exact`, tested on a local validator; challenges decided by an arbiter |
