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

### Security

- The program is unaudited and runs on devnet only; see [SECURITY.md](SECURITY.md) for its
  known limits.
