# TDCC Exact: glossary

The terms used in [exact.md](exact.md), [architecture.md](architecture.md),
[threat-model.md](threat-model.md) and [operations.md](operations.md), in alphabetical order.
`H` is SHA-256 throughout.

**Arbiter.** The key that decides a challenge by signing `slash` or `dismiss`. Today it is the
market's admin key (TDCC); the on-chain bisection game is meant to replace it
([TODO.md](../TODO.md) item 6).

**Base unit.** The smallest amount of a token. USDC has 6 decimals, so 1 USDC is 1,000,000
base units; every price and stake in the program is in base units.

**Basis points (bps).** Hundredths of a percent: 10,000 bps is the whole amount. The market's
`host_bps` (8,000) and `verifier_bps` (5,000) are in bps; shares are rounded down and the
remainder goes to TDCC.

**Bisection.** A binary search over two checkpoint lists for the first checkpoint that
differs after one that agrees. It takes log2(checkpoints) rounds; in an on-chain game each
round is one transaction.

**Bit-exact.** Two machines give the same bits for the same program and inputs, not just
close numbers. The Exact Core card and the ISA simulator are bit-exact, which is why a
verifier's laptop can reproduce a provider's fingerprint.

**Challenge.** A transaction that disputes a revealed receipt by posting a different
fingerprint, before the job's challenge deadline. Any key but the provider's can send it, once
per job.

**Challenge window.** The number of slots after a reveal during which the receipt can be
challenged. After it closes, an unchallenged job can be settled.

**Checkpoint.** A snapshot the trace log takes every 4096 steps and at the end of each device
run: the step count, the chain so far, and a hash of each slice's working state (TMEM, ACT
RAM and its scales, the registers, the pc).

**Commit-reveal.** Posting a receipt in two phases. First the provider posts a commitment,
`H("tdcc-exact/commit/v1" || fingerprint || provider key || salt)`; after the commit deadline it
posts the fingerprint and the salt, and the program checks they open the commitment. It stops
a provider from copying another's fingerprint.

**Commit window.** The number of slots after `open_job` during which the provider can commit.
The reveal window that follows has the same length.

**Config.** The account that is one market: its admin, its mint, its treasury, its vault, its
shares and its windows. Its address is derived from the admin's key.

**Dismiss.** The arbiter's ruling that a challenge was wrong. The job goes back to
`Revealed` and can be settled from the next slot; it cannot be challenged again.

**Divergence index.** The index of the first checkpoint that differs after one that agrees,
as the bisection finds it. `slash` records it, and the program checks it is within the posted
checkpoint count.

**Escrow.** A job's price, held in the market's vault from `open_job` until the job is
settled (to the provider and the treasury), slashed (back to the renter) or expired (back to
the renter).

**Expire.** Returning a job's escrow to the renter when the provider has not revealed by the
reveal deadline. Anyone can send it.

**Fault.** The first step inside a disputed window where two replays differ. A `control` fault
is a different instruction; a `state` fault is the same instruction with a different result.

**Fingerprint.** The 32-byte hash a provider posts for a job:
`H(job digest || model image hash || answer || logits hash || trace root)`. Two honest runs of
a job give the same fingerprint on any machine.

**Job digest.** The hash of a job's description: the model's name, the prompt's token ids,
the Yes and No tokens, the weight format, the KV cache size and the prefill chunk. The `Job`
account stores it; the job JSON itself stays off-chain.

**Leaf.** One checkpoint's entry in the trace's Merkle tree: `H(step || chain || state)`.

**Merkle proof.** The sibling hashes on the path from one leaf to the trace root. With the
leaf count, it shows one checkpoint belongs to a posted root without the whole list
(`tdcc-exact prove`, `trace.merkle_verify`).

**Model image hash.** The hash of the DRAM image the engine builds for a model. It depends on
the weights and on the build (weight format, KV cache size, design configuration), so it pins
both.

**Open job.** A job that is not yet `Settled`, `Slashed` or `Expired`. A provider with open
jobs cannot unstake.

**Oracle job.** A yes/no question run on a model: the answer is whichever of the Yes and No
tokens gets the larger logit after the prompt.

**Prefill chunk.** The number of prompt tokens fed in one device run (`chunk`, 8). It changes
the trace, so it is part of the job digest.

**Receipt.** What a provider produces for a job: the answer, the model image hash, the logits
hash, the trace root, the step count and the fingerprint.

**Registry.** `tdcc_exact/models.json`: the expected model image hash for each `(model,
wformat, cap)`. A verifier rejects a receipt with another hash before re-running anything.

**Renter.** The party that opens a job and pays its price into escrow.

**Replay.** Re-running a job and recording every step inside one disputed window: where it ran,
its encoding, the chain and the slice's state after it.

**Reveal.** The second phase of commit-reveal: `reveal_receipt` posts the fingerprint, the
salt, the model hash, the trace root and the checkpoint count.

**Settle.** Paying out an accepted job after its challenge window: `host_bps` of the price to
the provider, the rest to the treasury. Anyone can send it.

**SkipLayer.** The dishonest provider of the demo and the tests: in every device run it leaves
out one layer's matrix multiplies, the mixer's and the MLP's. It often gives the same answer
and always a different fingerprint.

**Slash.** The arbiter's ruling that a provider's run was wrong: the renter gets the price back,
the challenger gets `verifier_bps` of the provider's whole stake, and the treasury the rest.

**Slot.** Solana's unit of time, about 400 ms. Every window and deadline in the program is in
slots.

**Stake.** USDC a provider locks in the market's vault. It must be at least `min_stake` to take
jobs, and a slash takes all of it.

**Step.** One instruction executed by one slice of the accelerator. The trace log counts steps
across runs and slices.

**Trace log.** The hash chain the simulator extends at every step:
`chain = H(chain || slice || pc || the instruction's 8 words || R0..R15 after it)`, with the
host's DRAM writes and each run's arguments folded in.

**Trace root.** The Merkle root of a run's checkpoint leaves, with the leaf count hashed on
top. It is part of the fingerprint and is revealed on-chain.

**Treasury.** The market's token account for TDCC's share: the fee on settled jobs and the
rest of slashed stakes.

**Unstake cooldown.** The number of slots between `request_unstake` and the earliest
`unstake`. A pending unstake stops the provider from taking new jobs.

**Vault.** The single token account of a market that holds every escrow and every stake. Its
authority is the market's `Config` account, so only the program can move its tokens.

**Verifier.** Anyone who re-runs a job, compares fingerprints, and challenges a mismatch. It
earns `verifier_bps` of a slashed stake.

**Window (dispute).** The steps between the last agreeing checkpoint and the first differing
one, at most 4096. Both sides replay it to find the fault.
