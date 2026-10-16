# Security

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub: the repository's
**Security** tab, **Report a vulnerability**. We aim to reply within five business days, and
to agree on a disclosure date with you once a fix is ready.

Helpful in a report: what an attacker gains (funds, a wrong verdict, a stuck job), the steps
or a test that shows it, and the commit you looked at.

## Scope

- The Solana program in `programs/tdcc_exact`: escrow, stakes, commit-reveal receipts,
  challenges, slashing and settlement.
- The verification layer in `tdcc_exact/`: the trace log and trace root, Merkle proofs,
  receipts and fingerprints, the bisection dispute, the settlement arithmetic.

Issues in the accelerator design this project builds on (`opentpu/`, `rtl/`, `sim/`,
`boards/`) belong upstream, at [FeSens/openTPU](https://github.com/FeSens/openTPU), unless
they break a guarantee of the verification layer.

## Status

The program is **unaudited** and runs on **devnet only**, with a test USDC mint. Do not use it
with real funds. Its known limits are design decisions not yet made rather than bugs, and are
listed in [TODO.md](TODO.md) (items 6 and 7), [docs/exact.md](docs/exact.md) and
[docs/threat-model.md](docs/threat-model.md):

- challenges are decided by an arbiter key (separate from the admin, rotatable, with a ruling
  deadline after which anyone can dismiss) until the on-chain bisection game replaces it; an
  arbiter that colludes with a provider can still dismiss a valid challenge;
- verifiers are not selected at random, and nothing pays them when nobody cheats (the
  verifier's dilemma);
- a renter can open a job for any staked provider without its consent, holding part of its
  stake until the job expires;
- providers keep their traces themselves; the job store is not yet replicated.

Reports about these are still welcome when they show a concrete path to losing funds.
