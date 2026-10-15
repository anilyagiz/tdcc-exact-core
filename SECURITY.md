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
listed in [TODO.md](TODO.md) (items 6 and 7) and [docs/exact.md](docs/exact.md):

- challenges are decided by an arbiter, the market's admin key, until the on-chain bisection
  game replaces it;
- there is no challenge bond and no random verifier selection yet;
- DRAM stores are not in the trace's state hash; a wrong final store is caught by the logits
  hash only.

Reports about these are still welcome when they show a concrete path to losing funds.
