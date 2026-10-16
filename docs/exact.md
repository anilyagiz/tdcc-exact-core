# TDCC Exact: the trace log, the fingerprint and the dispute

Exact Core gives the same bits on the card as on the simulator (README, "Validating against
Hugging Face"), so anyone can re-run a job on a laptop and get the provider's exact answer.
TDCC Exact turns that into a market: a provider posts a fingerprint of its work, a verifier
re-checks it, and a mismatch is settled by finding the one instruction that differs.

The code is in [`tdcc_exact/`](../tdcc_exact). The only change to the openTPU design is an
observer hook in `isasim.Machine.run`, called after each instruction a slice steps.

## 1. The trace log (`tdcc_exact/trace.py`)

The chain starts from `H("tdcc-exact/trace/v3" || binding)`: the binding is the on-chain Job
account's address (locally, the provider's key), so every run is tied to one job and a
fingerprint revealed on one job is worthless on another, even for the same question and model.

Every instruction the simulator steps extends a hash chain (SHA-256, the hash Solana's runtime offers as a syscall):

    chain = H(chain || slice || pc || the instruction's 8 words || R0..R15 after it)

Every `job.every` steps (4096 by default; the interval is part of the job, so provider and
verifier checkpoint alike), and when each device run ends, the log takes a checkpoint: a hash
of each slice's working state (TMEM, the ACT RAM and its scales, the registers, the pc, and a
running hash of what its stores wrote to DRAM), folded into the chain. A checkpoint's leaf is `H(step || chain || state)`, and the trace root is the
Merkle root of the leaves with their count hashed on top (`H(2 || count || root)`), so a list
with its last checkpoint repeated does not share the root.

The host's writes into DRAM between runs (the token, its embedding row), each run's arguments
and what the host reads back (the logits) go into the chain too, so the log covers the inputs,
the work and the output: a receipt whose answer or logits are not the ones its trace read is
an output fault in a dispute.

DRAM itself is not hashed at checkpoints (the card's weights would dominate; the model hash
pins them). What runs store to DRAM is: each slice keeps a running hash of the words and bytes
its ST, QST and DSTEP instructions wrote, and that hash is part of its state, so a run whose
only wrong value is a final store is still caught at the store.

## 2. The receipt (`tdcc_exact/oracle.py`)

An oracle job names a model, the prompt's token ids (so the verifier needs no tokenizer) and
the Yes and No tokens. The provider runs the prompt through the engine on the traced backend,
answers with whichever of the two tokens has the larger logit, and posts:

    fingerprint = H(job || model image || answer || last logits || trace root)

Before anything runs, `Job.check` refuses a job no run could answer right: the same token
for Yes and No, a prompt longer than the KV cache, token ids outside the vocabulary.

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

## 3. The dispute (`tdcc_exact/dispute.py`, `tdcc_exact/verifier.py`)

0. **The posted trace.** The provider plays on the checkpoint list its receipt committed to:
   `tdcc-exact dispute --receipt` checks the list against the posted trace root
   (`matches_root`) and a list that does not match loses at once.
1. **Bisection.** Once a run goes wrong its chain differs at every later checkpoint, so a
   binary search over the two checkpoint lists finds the first differing one in
   log2(checkpoints) rounds. A posted list need not be a real chain (it could differ in the
   middle and copy the last leaf), so the search starts from the last difference and always
   ends on a checkpoint that differs while the one before agrees. This is the game an
   on-chain referee plays, one round per transaction; `trace.merkle_proof` /
   `merkle_verify` let a round show one checkpoint against the trace root instead of the
   whole list.
2. **Replay.** Both sides replay that window and record each step: where it ran, its
   encoding, the chain, and a hash of the slice's state. The first record that differs is the
   fault: `control` if a different instruction ran, `state` if the same one gave a different
   result. A provider's revealed window must chain: `verify_window` replays the chain from the
   agreed checkpoint through every record (steps with their registers, host writes and reads,
   run starts, and the closing checkpoint with each slice's state) and the provider loses if
   it does not reach the checkpoint it posted.
3. **Output.** If the traces agree, the receipt must still be the one the trace gives: the
   answer, the logits hash and the model hash of the verifier's re-run, a trace root that is
   the root of the posted checkpoints, and a fingerprint that is its own fields' hash.
   Otherwise the fault is `output`.

Provider B (`SkipLayer`) skips one layer's matrix multiplies, its mixer's (attention, or
LFM2's short convolution) and its MLP's, in every run. The layers repeat inside a hardware
LOOP (LFM2: layer 0, then the unit (conv, attention) six times, then layer 13), so one MM of
the program runs for several layers. B tells them apart by the compiler's source frames
(`Instr.src`: `_conv*` / `_attention*` / `_mlp`) and counts layers as they run: a mixer MM
after an MLP MM starts the next layer.

On the tiny model the dispute names the first skipped `MM` in 2 rounds over 4 checkpoints. On
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
  `tdcc-exact run` keeps the salt out of the shared receipt, in a private file (`<out>.salt`,
  mode 0600) revealed only with the fingerprint.
- **Replay across jobs.** Commit-reveal protects one job; two jobs with the same question
  would still share a fingerprint. Every job has a random nonce in its digest and every run is
  bound to its on-chain job (section 1), so a fingerprint revealed on one job does not fit
  another, even when a renter opens the same job with several providers.
- **Digest size.** Every hash is SHA-256 (32 bytes): 128-bit collision resistance, and the
  hash Solana's runtime computes as a syscall, so the program can check commitments (and,
  later, Merkle paths of the trace).
- **Model identity.** The model hash is the hash of the DRAM image the engine builds, which
  depends on the build (weight format, KV cache size, design config) as well as the weights.
  `tdcc_exact/models.json` pins `(model, wformat, cap) -> image hash`, and a user registry
  (`tdcc-exact registry add --model ...`, `$TDCC_EXACT_REGISTRY` or
  `~/.config/tdcc-exact/models.json`) adds pins over it; `run_job` refuses a build whose image
  is not the pinned one (an `OTPU_*` setting that changes the formats, say), `verify` rejects
  a receipt with another hash before re-running anything (`--strict`: an unregistered model
  too), and the program rejects a reveal whose model hash is not the job's. A
  provider that runs fp4 instead of int8 is caught there (`tests/test_exact.py`, with the
  other cheats tested: other weights, skipped prompt tokens, an answer with no run).
- **The verdict.** `tdcc-exact verify` gives ACCEPT, CHALLENGE (naming the fields that
  differ) or REJECT (the reveal does not open its commitment, or the build is not the job's);
  `--json` prints it for a verifier node.

## 6. The Solana program (`programs/tdcc_exact`)

An Anchor program; `tdcc_exact/chain.py` is its client, `tdcc-exact demo --localnet/--devnet`
runs the demo against it.

| Account | Seeds | Holds |
|:--|:--|:--|
| `Config` | `config, admin` | the mint (USDC), the treasury, the vault, 80/20 and 50/50 in bps, the windows (slots), the minimum stake, the unstake cooldown, the challenge bond, the arbiter key and its ruling window, the penalty for a withheld reveal |
| vault | `vault, config` | one token account for every escrow, stake and bond; its authority is the config |
| `Provider` | `provider, config, owner` | the stake, open jobs, a pending unstake |
| `Job` | `job, config, renter, job id` | the job digest, the expected model hash, the price, the state, the deadlines, the commitment, the revealed fingerprint, answer and trace root, the challenger, its bond and the ruling deadline |

A market is a config, seeded by its admin's key, so anyone can run one (the demo makes its own
test USDC mint). The **arbiter** signs `slash` (or `dismiss`) after the off-chain bisection
names the faulty step, which goes into the `Slashed` event. It is a key of its own in the
config (the admin's by default), which the admin rotates with `set_arbiter`, so it can be a
multisig and a stolen admin key does not rule on disputes; the arbiter cannot challenge a job
itself. It has `arbiter_window` slots from a challenge to rule; after that anyone may dismiss
and the receipt stands. Replacing the arbiter by an on-chain bisection game is TODO.md item 6.

`initialize` refuses a market with a zero window, stake or bond, and one whose unstake
cooldown does not outlast a job (commit, reveal, challenge and ruling windows together), so a
provider cannot leave before a challenge against it is ruled. The reveal window reuses the
commit window's length: `reveal_deadline = commit_deadline + commit_window`.

| Instruction | Who | When |
|:--|:--|:--|
| `set_arbiter` | the admin | any time |
| `register_provider`, `stake`, `request_unstake`, `unstake` | provider | unstake after the cooldown and with no open jobs |
| `open_job` | renter | the provider is staked and not leaving; the price (above 0) moves into the vault; an optional absolute commit deadline lets one job fanned out to several providers share it |
| `commit_receipt` | the job's provider | until `commit_deadline` |
| `reveal_receipt` | the job's provider, with at least the minimum stake | after `commit_deadline`, until `reveal_deadline`; opens the commitment, and checks on-chain that the fingerprint is `H(job digest, model hash, answer, logits hash, trace root)` and the trace root is `H(2, count, tree root)`, so the answer, the logits and the checkpoint count are bound |
| `challenge` | anyone but the provider and the arbiter, posting `challenge_bond` | until `challenge_deadline`, with another fingerprint; a dismissed challenge does not close the window for other verifiers |
| `settle` | anyone | revealed, unchallenged, after `challenge_deadline` |
| `slash` | the arbiter | challenged, before the ruling deadline; names a checkpoint index of the posted trace (at most its count); the bond goes back to the verifier with its share |
| `dismiss` | the arbiter, or anyone after the ruling deadline | challenged; the bond goes to the provider |
| `expire` | anyone | no reveal by `reveal_deadline`: the escrow goes back to the renter, plus `non_reveal_penalty` from the stake when the provider committed and withheld its reveal |
| `close_job` | anyone | a finished job (settled, slashed, expired): its rent goes back to the renter |

Every payout checks that the token account belongs to the party it pays and holds the market's
mint.

Tests: `cargo test -p tdcc_exact` (the settlement vectors, the commitment and fingerprint
vectors) and `tests/test_chain.py` on `solana-test-validator`, one test or more per rule above,
each checking the program's error code; the unstake, expiry and closing tests read the events
back from the transaction logs. CI runs both.

Every state change emits an event: `Initialized`, `ArbiterChanged`, `ProviderRegistered`,
`Staked`, `UnstakeRequested`, `Unstaked`, `JobOpened`, `ReceiptCommitted`, `ReceiptRevealed`
(with the answer), `Challenged`, `Dismissed`, `Slashed`, `Settled`, `Expired`, `JobClosed`.

Not yet: verifier selection and the on-chain bisection (TODO.md items 6, 7). A renter can open
a job for any staked provider without its consent; the provider's stake is held until the job
expires.

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
