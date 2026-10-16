# TDCC Exact: threat model

What TDCC Exact protects, who could attack it, what it assumes, and each attack we know of
with its mitigation and its state today. The components and the job flow are in
[architecture.md](architecture.md); terms are in [glossary.md](glossary.md). To report a
vulnerability, see [SECURITY.md](../SECURITY.md).

The program is unaudited and runs on devnet with a test USDC mint. Several rows below are
open; a market with real funds needs them closed or accepted in writing first
([operations.md](operations.md#before-mainnet)).

## Assets

| Asset | Where it is | What losing it means |
|:--|:--|:--|
| Escrow | the renters' prices, in the market's vault | a renter pays for work not done, or a provider is not paid for work done |
| Stakes | the providers' USDC, in the same vault | an honest provider is slashed, or a cheater keeps its stake |
| Verdict integrity | the fingerprint, the trace root, the dispute's result, the arbiter's ruling | a wrong answer is paid as right, or a right one is slashed as wrong |
| Liveness | jobs moving to a final state within their windows | escrow and stakes held without end |
| Keys | the admin (arbiter) key, the upgrade authority, provider and renter keys | depends on the key (see the table) |

## Actors

| Actor | Can | Wants |
|:--|:--|:--|
| Renter | open jobs against any staked provider, pick the job's parameters and price, challenge (any key but the provider) | a correct answer, or its money back |
| Provider | run jobs, commit and reveal receipts, post or withhold its checkpoint list, stake and unstake | the price for as little work as it can get away with |
| Verifier | re-run jobs, challenge with another fingerprint, play the dispute | the slashed stake's verifier share |
| Arbiter | sign `slash` or `dismiss` on a challenged job, before its ruling deadline; may not challenge | today: TDCC, assumed honest |
| Admin | seeds the market; rotates the arbiter (`set_arbiter`) | keep the market running |
| Upgrade authority | replace the program's code | must not exist in a careless form on mainnet |
| RPC node | show a client the chain's state, relay its transactions | could lie, delay or censor |
| Observer | read every account, event and transaction | learn fingerprints, prompts' digests, who rents from whom |

## Trust assumptions

1. **The simulator is the card, bit for bit.** A verifier's laptop re-runs a job on the ISA
   simulator and compares fingerprints with a provider that may have run on the card. Upstream
   openTPU checks this (README, "Validating against Hugging Face"). If the card and the
   simulator drift, an honest card provider is challenged. The trace log itself exists only in
   the simulator today ([TODO.md](../TODO.md) item 10).
2. **SHA-256 is collision and preimage resistant.** Every chain step, checkpoint leaf, Merkle
   node, fingerprint and commitment is SHA-256.
3. **The arbiter is honest and live.** Today the market's admin key decides every challenge.
   The program checks the arbiter's signature and that the divergence index is within the
   posted checkpoint count, nothing more. Replacing it is [TODO.md](../TODO.md) item 6.
4. **The model registry is right.** `tdcc_exact/models.json` pins the image hash a correct
   build gives; whoever opens a job copies the expected hash from it.
5. **Solana is live and its slot clock is roughly steady.** Every window is counted in slots.
6. **At least one honest verifier checks each job.** Nothing on-chain forces anyone to.

## Attacks

Status: **done** (mitigated and tested), **partial** (mitigated in part, or only off-chain),
**open** (not mitigated). "In progress" means work on it has started and has not landed on this
branch.

| Attack | How | Mitigation | Status |
|:--|:--|:--|:--|
| Copy attack | Honest runs post the same fingerprint, so a provider posts another's fingerprint without running. | Commit-reveal: the commitment binds the provider's key and a salt; fingerprints are public only after the commit window. | done: [`tdcc_exact/commit.py`](../tdcc_exact/commit.py), `commit_receipt` / `reveal_receipt`; `test_a_copied_commitment_does_not_reveal` |
| Cross-job replay | `job_id` is not in the job digest, so two jobs with the same model, prompt and parameters have the same fingerprint. Once one is revealed, any provider can commit that fingerprint for the other, or run once and be paid for many. | Every job has a random nonce in its digest, and every run is bound to its on-chain Job account: the trace starts from `H(tag, job address)`, so a fingerprint revealed on one job does not fit another, even for the same job opened with several providers (`oracle.run_job(binding=...)`). | done: tests in `tests/test_exact.py`; the nodes and the demo bind each run to its job |
| Skipped work | The provider leaves out part of the computation (a layer's matrix multiplies). | The trace chain covers every instruction and its registers; the checkpoint state hash covers TMEM and ACT RAM. The fingerprint changes even when the answer does not. | done: `SkipLayer`; `test_a_skipped_layer_is_caught_at_the_skipped_instruction` |
| Cheaper model | The provider runs other or smaller weights. | The model image hash is in the fingerprint, the job stores the expected hash, `reveal_receipt` refuses another one, `verify` checks the registry before re-running. | done: [`tdcc_exact/registry.py`](../tdcc_exact/registry.py); `test_a_provider_running_other_weights_is_caught` |
| fp4 for int8 | The provider builds the same weights in a cheaper format. | The format changes the DRAM image, so its hash; `wformat` and `cap` are in the job digest. | done: `test_a_provider_running_fp4_instead_of_int8_is_caught` |
| Skipped tokens | The provider feeds fewer prompt tokens. | The host writes of each token and the run count are in the chain; the trace root differs. | done: `test_a_provider_skipping_prompt_tokens_is_caught` |
| Made-up answer | The provider posts an answer and a fingerprint with no run behind them. | A verifier's re-run gives another fingerprint and challenges. | done: `test_a_receipt_with_no_run_behind_it_is_challenged` |
| Trace substitution in a dispute | After a challenge, the provider plays the bisection on a checkpoint list made up to look honest. | The list must hash to the trace root revealed on-chain before the challenge; a list that does not match loses at once. | done: `matches_root` in [`tdcc_exact/dispute.py`](../tdcc_exact/dispute.py); `test_a_trace_must_match_its_posted_root`, CI |
| Non-cumulative posted checkpoints | A posted list need not be a real chain: it can differ in the middle and copy the honest last leaf, so a plain binary search could land on a window where both sides agree. | The search starts from the last difference and ends on a checkpoint that differs after one that agrees. The leaf count is hashed into the root, so a list with its last leaf repeated has another root. | done: `bisect`, `merkle_root`; `test_bisect_lands_where_the_one_before_agrees`, `test_merkle_root_commits_to_order` |
| Griefing with challenges | Anyone (the renter too) challenges honest receipts with a random fingerprint. It costs a transaction fee, holds the job until the arbiter rules, and loads the arbiter. | A challenge posts `challenge_bond`; a dismissed challenge pays the bond to the provider. | done (program); the bond's size is a market parameter |
| Arbiter withholding | The arbiter never rules: a `Challenged` job holds its escrow and its provider's open-job count (so its whole stake) without end. | A ruling deadline (`arbiter_window` slots after the challenge) after which anyone can dismiss; the receipt then stands and the bond goes to the provider. | done (program) |
| Arbiter bias | The arbiter slashes an honest provider, or dismisses a valid challenge. | None on-chain today. The `Slashed` event names the divergence index and fault step, so anyone can re-run the window and check the ruling after the fact. The on-chain bisection game removes the arbiter. | open ([TODO.md](../TODO.md) item 6) |
| Verifier collusion and selection | A provider runs its own verifier, which never challenges it; a cartel challenges only outsiders. | Anyone may challenge, so one honest verifier is enough. Random verifier selection (VRF or slot hash) is not built. | open ([TODO.md](../TODO.md) item 7) |
| Verifier's dilemma | If nobody cheats, verifying earns nothing, verifiers stop, and then cheating pays. | Random audits paid from the fee, or planted faulty jobs with a reward. Not built. | open ([TODO.md](../TODO.md) item 7) |
| Data withholding | The provider reveals a trace root but will not hand over its checkpoint list or replay a window. | Off-chain, a provider whose list does not match its root loses the dispute, and a revealed window must chain to the posted checkpoints (`dispute.verify_window`). The job and trace store (`tdcc_exact/node/store.py`) holds providers' traces, checked against their roots. Not yet: replication, and a deadline after which a missing trace loses. | partial |
| DRAM-store-only corruption | The checkpoint state hash covers TMEM and ACT RAM, not DRAM. A wrong value stored to DRAM is caught when it is loaded back, but a run's last stores (the logits area) are caught only by the logits hash in the fingerprint, and the dispute cannot name the instruction. | Each slice's state includes a running hash of what its ST, QST and DSTEP instructions wrote to DRAM, and the host's read of the logits is in the chain. | done: `tests/test_exact.py` |
| Job description mismatch | The renter gives the provider a job JSON whose digest is not the one on-chain, and challenges the receipt with a run of the on-chain job. | The provider node refuses to commit unless the job it fetched hashes to the on-chain digest and the on-chain model hash is the registry's pin (`tdcc_exact/node/provider.py`); the job then expires at no cost to it. | done (provider node) |
| Front-running unstake | A provider that expects a challenge withdraws its stake first. | `unstake` needs no open jobs, and `initialize` requires the unstake cooldown to outlast a job (commit, reveal, challenge and ruling windows), so a provider cannot leave before a challenge against it is ruled. | done (program) |
| Free jobs locking stake | A renter opens jobs against a provider to hold its stake (an open job blocks unstaking). | `open_job` refuses a price of 0, and `expire` frees a job after its reveal deadline. A job costs at least one base unit, and the provider does not sign `open_job`, so a renter can still hold a provider's stake for a small price per window. | partial: `test_a_job_must_pay_something` |
| Withheld reveal | A provider commits, then withholds its reveal (it dislikes the answer, or is being watched) and lets the job expire. | `expire` pays the renter `non_reveal_penalty` out of the stake of a provider that committed and did not reveal. | done (program) |
| One stake behind many jobs | `slash` takes the provider's whole stake; a second challenged job of the same provider then slashes 0, and the verifier earns nothing. | `reveal_receipt` requires the provider to hold at least the minimum stake, so after one slash its other jobs cannot be revealed and expire back to their renters. A per-job stake would be stronger. | partial |
| Key theft: arbiter or admin | The arbiter key signs every ruling: with it, an attacker dismisses valid challenges or slashes honest providers (it cannot challenge, so it cannot collect a verifier's share from its own rulings). The admin key seeds the market and can appoint a new arbiter. | The arbiter is a key of its own, rotatable by the admin with `set_arbiter` (a stolen arbiter key is replaced at once), and may be a multisig; keep the admin key offline. The on-chain game removes the arbiter. | partial ([operations.md](operations.md#keys)) |
| Key theft: provider or renter | A stolen provider key can request an unstake and withdraw the stake after the cooldown, or reveal nonsense and be slashed. A stolen renter key can spend the renter's USDC; the refunds of its open jobs still go to token accounts of the renter's key. | None in the program: it cannot tell a thief from the owner. Keep keys out of the repository and out of shared machines. | accepted |
| Upgrade authority | Whoever holds the program's upgrade authority can replace the code and move everything in every vault. | A multisig upgrade authority, or none (immutable) once audited. | open ([TODO.md](../TODO.md) item 11, [operations.md](operations.md#deploy-the-program)) |
| Lying RPC | An RPC node shows a verifier stale state, so it misses the challenge window, or drops its transactions. | Verifiers read at `confirmed` commitment; a verifier node should query more than one RPC and challenge early in the window. | partial ([`tdcc_exact/chain.py`](../tdcc_exact/chain.py) reads one RPC) |
| Observer learns the job | Every account and event is public. The prompt is off-chain, but its digest, the price, the parties and the answer's fingerprint are not secret, and a verifier must see the prompt to re-run it. | None: jobs are public to their verifiers by design. Do not put secrets in prompts. | accepted |

## What a slash proves today

A `Slashed` event says the arbiter signed it. It carries the divergence index (checked to be
within the posted checkpoint count) and the fault step (not checked). Anyone with the job JSON
and the provider's posted list can re-run the dispute and see whether the named step is a real
fault. Until the bisection runs on-chain, a slash is as good as the arbiter.
