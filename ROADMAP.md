# Roadmap

Where TDCC Exact is, and what stands between it and a mainnet market. [TODO.md](TODO.md) is
the item-by-item backlog; this page groups it into releases, each with what it must show
before the next one starts. Decisions marked **owner** are not engineering calls.

## Where it is (v0.1)

Done and tested (Python suite, the program on a local validator, CI on Linux, macOS and
Windows):

- **Verification layer.** A trace of every instruction, bound to its on-chain job, covering the
  inputs, the host's read of the logits and each slice's DRAM stores; a trace root that commits
  to its checkpoint count; Merkle proofs; receipts by commit-reveal with the salt kept private;
  a dispute that bisects to a checkpoint, checks a provider's revealed window against its
  posted checkpoints, and rules output faults; a model registry enforced before a run.
- **Program** (devnet): escrow, stakes, a challenge bond, a separate rotatable arbiter with a
  ruling deadline, on-chain checks that the fingerprint and trace root are the hashes of their
  revealed parts, a penalty for a withheld reveal, a cooldown that outlasts a job, closing of
  finished jobs, an event for every state change.
- **Services.** A content-addressed job and trace store, a provider node, a verifier node, an
  indexer and a market status command.
- **Project.** A library API, CI and lint, a release workflow, security policy, architecture,
  threat model, glossary and operations docs.

What it is not yet: trust-minimized (an arbiter rules), economically sound for verifiers (no
pay when nobody cheats), audited, or running on the card.

## v0.2: an honest market on devnet

Goal: outside parties run providers and verifiers on devnet, and a planted cheat is caught and
slashed with no manual step.

- Deploy the current program to devnet as a new market (its accounts changed). **owner**: the
  upgrade authority; if the old deploy's authority is lost, a new program id.
- An arbiter service: watches `Challenged`, fetches the provider's trace from the store, runs
  the dispute, signs `slash` or `dismiss` within `arbiter_window`.
- A reveal API on the provider node (`GET /jobs/{id}/window`) and a deadline after which a
  provider that does not serve its window loses.
- A renter SDK: open a job, publish it to the store, wait for the answer.
- Store replication: **owner** picks where traces live (a TDCC bucket, IPFS, Arweave) and how
  long (the challenge and ruling windows at least).
- A `tdcc-exact demo --devnet` capture with its Explorer pages.

Exit: a week on devnet with two outside providers and one outside verifier; every planted
cheat slashed by the services alone; the indexer shows it.

## v0.3: disputes without a trusted arbiter

Goal: no key can decide a dispute.

- **owner**: the last step's resolution (TODO.md item 6): a one-step proof on-chain (needs a
  Merkle tree over the state, and an on-chain executor for the opcodes), a committee of
  verifiers, or an optimistic counter-challenge.
- The on-chain bisection game: a transaction per round, both sides alternating, timeouts that
  lose by default (the Merkle proofs it needs exist).
- Verifier selection by slot hash or VRF, and pay for verifying when nobody cheats (random
  audits from the fee, or planted faulty jobs).
- A provider's consent to a job (or a per-job stake), so a renter cannot hold any provider's
  stake with jobs it did not accept.

Exit: the arbiter key can be set to an unusable address and every dispute test still passes on
the validator.

## v0.4: the card

Goal: a provider runs jobs on the FPGA card and its trace root equals the simulator's.

- A hash engine next to the sequencer in RTL, the state checkpoints read out from the card,
  timing closed with it in (TODO.md item 10).
- A test that the card's trace root equals the simulator's on LFM2.5-230M.
- **owner**: getting the card.

Exit: the card and the simulator post the same fingerprint for a set of LFM2.5-230M jobs.

## v1.0: mainnet

- An outside audit of the program, its findings fixed or accepted in writing. **owner**.
- The upgrade authority and the arbiter (while there is one) on multisigs. **owner**.
- Mainnet USDC, a parameter review from measured run times, capped stakes at first.
- Monitoring and alerting from the indexer; an incident plan ([docs/operations.md](docs/operations.md)).
- A useful oracle: the evaluation in [docs/oracle-quality.md](docs/oracle-quality.md) run on
  the model, and a decision rule (or a larger model) that is right on held-out questions; the
  rule in the job digest. **owner**: the model, and checking its license for commercial use.

Exit: the audit closed, a mainnet market open with capped stakes, and the oracle's accuracy
published.
