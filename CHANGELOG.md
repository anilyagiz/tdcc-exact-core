# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Changes to the
accelerator itself are upstream's, in [openTPU](https://github.com/FeSens/openTPU).

## [Unreleased]

The first open-source release of TDCC Exact.

### Added

- The trace log: a SHA-256 hash chain over every instruction the bit-exact simulator steps,
  with checkpoints, and a trace root over them that commits to their count; Merkle proofs for
  one checkpoint (`tdcc-exact prove`).
- Yes/no oracle jobs and receipts: a fingerprint binding the job, the model image, the answer,
  the logits and the trace root; a model registry pinning each build's image hash.
- Commit-reveal receipts against copying another provider's fingerprint.
- The dispute: bisection to a checkpoint that differs after one that agrees, then a replay to
  the first instruction at fault; a provider must play on the trace its receipt committed to.
- Settlement arithmetic shared with the program through test vectors.
- The Solana program (Anchor): escrow, provider stakes and unstaking, commit-reveal, one
  challenge per job, slash and dismiss by an arbiter, settle and expire, with an event for every
  state change; deployed on devnet.
- A Python client for it and `tdcc-exact demo --localnet/--devnet`.
- The `tdcc-exact` command: `job`, `run`, `verify` (with `--json`), `dispute`, `prove`,
  `registry`, `demo`.
- LFM2.5-230M runs (prefill, a layer-true dishonest provider for the demo).
- CI: the Python tests, the README's commands, and the program on a local validator.
- Every run bound to its on-chain job and every job given a nonce, so a fingerprint cannot be
  replayed across jobs; the checkpoint interval is part of the job.
- The trace covers the host's read of the logits and each slice's DRAM stores; a dispute checks
  a provider's revealed window against its posted checkpoints, and rules an output fault when
  the traces agree but the receipt does not.
- The program checks the fingerprint and the trace root at reveal, takes a challenge bond, gives
  the arbiter its own rotatable key and a ruling deadline, penalizes a withheld reveal, refuses
  a reveal from a provider below the minimum stake, lets a renter give a fan-out one commit
  deadline, and closes finished jobs (`close_job`).
- Services: a content-addressed job and trace store, a provider node, a verifier node and an
  arbiter node (`tdcc-exact node`), and an indexer (`tdcc-exact market status|events`).
- Provider consent: `open_job` makes a job `Offered` (the escrow in the vault, none of the
  provider's stake locked); the provider takes it on with `accept_job` before the job's
  `accept_deadline`, after which the renter alone can `cancel_job` it (`NotTheRenter`
  otherwise) and get the escrow back with no penalty; a cancelled job ends `Expired`. Events
  `JobAccepted` and `JobCancelled`. The provider node accepts only the offers it has checked.
- A settler node (`tdcc-exact node settler`): settles, expires, closes finished jobs
  (`--no-close` to keep them), and cancels the lapsed offers of its own key (`--name` a
  renter's).
- Generate jobs (`job new --kind generate --max-tokens N`): greedy decoding in the trace, the
  answer in the fingerprint as `b"GEN"` and u32 token ids, verified and disputed off-chain;
  the program still takes yes/no answers.
- `tools/checkpoint_bench.py` measures the checkpoint interval (docs/exact.md section 7; the
  default stays 4096, and the interval is in the job's digest).
- The trace log's hash chain in RTL (`rtl/exact/`, docs/exact-rtl.md, `make exact-rtl`),
  tested against `trace.py` in Verilator or Icarus simulation (skipped when neither is
  installed). It is standalone: not yet in the sequencer, not run through Vivado, and the
  checkpoints' state hash comes from the host.
- A public library API (`tdcc_exact.__all__`, `__version__`, `py.typed`), the commit's salt in
  a private file, `verify --strict`, a user model registry.
- Docs: architecture, threat model, glossary, operations; an oracle evaluation tool.
- CI on Python 3.10 to 3.13, the verifier on macOS and Windows, ruff, rustfmt and clippy,
  Dependabot, and a release workflow.

### Security

- The program is unaudited and runs on devnet only; see [SECURITY.md](SECURITY.md) for its
  known limits.
- The verifier node picks the jobs it re-runs by a hash of the job and its secret key, not
  its public key, so a provider cannot compute in advance which of its jobs go unchecked.
