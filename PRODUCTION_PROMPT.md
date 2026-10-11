# Prompt: take TDCC Exact Core to production readiness

You are working on **anilyagiz/tdcc-exact-core** (branch from `main`), a fork of FeSens/openTPU
that adds **TDCC Exact**: a verifiable-inference market. A provider runs an LLM job on Exact
Core (a bit-exact accelerator; today its ISA simulator), posts a fingerprint of a hash-chained
trace of every instruction, any verifier re-runs it, and a mismatch is settled on Solana by
finding the first instruction that differs.

Your job: **find every remaining gap and close it**, until the software side is production
ready, and produce a precise list of what only a human can do (money, hardware, audits,
legal). Work autonomously; ask only for decisions that are genuinely the owner's.

---

## 0. Read first, then audit before you build

Read, in this order: `TODO.md` (the authoritative backlog, P0/P1/P2), `docs/exact.md`,
`README.md` (top section), `tdcc_exact/*.py`, `programs/tdcc_exact/src/lib.rs`,
`tests/test_exact.py`, `tests/test_chain.py`, `.github/workflows/exact.yml`.

Then **audit** before writing code. Produce `docs/production-readiness.md` with a table:
gap, severity (blocker / high / medium / low), where in the code, fix plan, status. It must
include every open `TODO.md` item plus anything you find. At minimum verify these known gaps:

**Protocol / security (blockers)**
1. **Cross-job replay of fingerprints.** Commit-reveal only stops copying *within* a job's
   commit window. Two jobs with the same digest (same model, prompt, params) have the same
   fingerprint, so a provider can copy a fingerprint revealed on an *earlier* job. Fix: a
   per-job random nonce chosen at `open_job` (e.g. derived from the job PDA + slot hash), fed
   into the trace chain as the first host write and into the fingerprint, and checked on-chain.
   Add Python and on-chain tests for the replay.
2. **Centralized arbiter.** `slash` / `dismiss` are signed by the market admin. Replace with
   the on-chain bisection game (TODO item 6): `bisect` rounds with timeouts, both parties
   alternating, loser-by-default on timeout; decide and implement the last-step resolution
   (pick from TODO 6 options (a)/(b)/(c), write the decision and threat model into
   `docs/exact.md`). If a full one-step proof is out of reach, implement option (c)
   optimistic counter-challenge or (b) a committee, and keep the arbiter only as an
   emergency, time-locked, multisig-held fallback.
3. **Challenge spam / griefing.** No challenge bond. Add a bond (config param), lost to the
   provider on a dismissed / lost challenge, returned on a won one.
4. **Verifier's challenge fingerprint is unverified** and any non-provider can challenge.
   Tie this to the bisection game so a challenger must defend its own trace.
5. **DRAM stores are not in the state hash** (TODO 6, last bullet): hash the regions each run
   stores (ST / QST targets) into the chain; add a test where only the final logits store is
   corrupted and the dispute still names the step.
6. **Data availability:** the provider's checkpoint list must be retrievable for the challenge
   window. Commit its hash on-chain with the reveal; define where it lives (provider-served
   reveal API + optional content-addressed upload); missing data = provider loses.
7. **Verifier incentives** (TODO 7): random audits / planted faulty jobs funded from the fee;
   verifier selection by slot hash so providers cannot pick their verifier.
8. **Stake accounting:** a slashed provider can re-stake and continue. Decide (owner question
   if unclear): permanent ban, cooldown, or allowed. Also check `open_jobs` cannot underflow
   into an unstake-while-jobs-open hole, and that unstake cannot front-run a pending challenge
   (cooldown must exceed commit + reveal + challenge + bisection time; enforce it in
   `initialize`).
9. **Program hardening:** re-derive and check the Job PDA where it is passed in; check every
   token account's mint and owner; support Token-2022 USDC or refuse it explicitly; add
   `close` instructions to reclaim rent for finished jobs; events for every state change;
   pause switch; config update instruction (admin, multisig) with bounds.
10. **Model registry on-chain:** today `models.json` is local. Add an on-chain registry
    account (model id, wformat, cap -> image hash) managed by governance; `open_job` takes
    the model id and copies the pinned hash.

**Product / correctness**
11. **Oracle quality:** LFM2.5-230M answers Yes to every question (docs/exact.md section 8).
    Evaluate prompt formats and a calibrated decision rule (e.g. logit margin threshold
    learned on a labeled set, or an "Answer: Yes/No" completion format) on ≥50 labeled
    questions against the fp32 reference; if 230M cannot reach a useful accuracy, add support
    for a larger model the simulator can run and document the cost. The rule must be part of
    the job digest so it is deterministic.
12. **Jobs beyond yes/no:** greedy generation of N tokens, with the stop rule in the digest.
13. **More cheat scenarios as tests:** smaller model substituted, fp4 for int8, skipped tokens,
    answer with no run, copied receipt (in-window and cross-job), truncated trace, reordered
    checkpoints.
14. **Performance:** `TraceLog.observe` hashes every instruction in Python. Profile on
    LFM2.5-230M; if hashing is >10% of runtime, batch per run or move it to a small C/Rust
    extension with a pure-Python fallback that produces identical bytes (test both). Pick
    `EVERY` from measurements and document it.

**Services (the market does not exist without these)**
15. **Provider node daemon:** watches the chain for jobs assigned to it, runs them, commits,
    reveals, serves the reveal API (`GET /jobs/{id}/checkpoints`, `/window?lo=&hi=`), plays its
    side of the bisection, keeps traces for the challenge window, settles. Idempotent and
    restart-safe (state on disk), structured logs, metrics, config via env/file.
16. **Verifier node:** samples jobs, re-runs, challenges, plays the bisection, claims rewards.
17. **Renter API / SDK:** HTTP endpoint and a Python client: open a job, wait, get the answer
    + receipt + Explorer links.
18. **Chain client hardening (`tdcc_exact/chain.py`):** priority fees, retry with fresh
    blockhash, confirmation timeouts, compute-unit limits, typed errors mapped from the
    program's error codes, no plaintext keys outside dev (support a keypair path or a
    remote signer), devnet/mainnet config profiles.
19. **IDL:** `anchor idl build` crashes with anchor-cli 1.2.1; fix the build (or pin a working
    Anchor version) and publish the IDL so Explorer decodes instructions; generate the
    client from the IDL or test the hand-written encodings against it.

**Engineering hygiene**
20. **CI:** the workflow exists but jobs never start on the private repo (account has no
    Actions minutes). Keep the workflow green-able: add lint (ruff), type check (mypy on
    `tdcc_exact/`), `cargo clippy -D warnings`, `cargo fmt --check`, the program build, the
    validator tests, the demos. Tell the owner CI cannot run until billing is fixed or the
    repo is public.
21. **Packaging:** a pinned lock for the chain/model extras, a Dockerfile for the provider and
    verifier nodes, versioned releases, `CHANGELOG.md`.
22. **Windows / upstream:** keep the only change inside `opentpu/` as the observer hook in
    `isasim.Machine.run` (upstream mergeability); document Linux-only or make the `fcntl`
    imports lazy *outside* `opentpu/` if possible.
23. **Licensing:** check the LFM2.5 model license for commercial use and record the result.
24. **Docs:** an operator runbook (deploy, upgrade, pause, key rotation, incident response),
    a threat model, the protocol spec (state machine, timeouts, economics), API reference.

Do not trust this list blindly; confirm each item against the code, drop what is already
fixed, and add what is missing.

---

## 1. How to work

- Work in prioritized order: blockers → high → medium. One logical change per commit, clear
  messages. Push to your branch and open a **draft PR** per coherent milestone (security
  fixes, bisection game, nodes, etc.), not one giant PR.
- **Never break these invariants:** `tdcc-exact demo` keeps working on the tiny model in
  seconds; two honest runs of a job produce the identical fingerprint; Python
  `tdcc_exact/settle.py` and the program compute identical amounts (shared vectors in
  `tests/data/`); the only change in `opentpu/` is the observer hook.
- Every protocol change gets: a Python test, an on-chain test on `solana-test-validator`
  (`tests/test_chain.py` pattern: assert the program's specific error code), and a docs
  update. Every bug fix starts with a failing test.
- Toolchain: Python venv (`pip install -e '.[chain,model]' pytest`), Agave Solana CLI
  (`sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`), `cargo build-sbf`,
  Anchor 1.2.1. LFM2.5-230M: `hf download LiquidAI/LFM2.5-230M --local-dir models/LFM2.5-230M`
  (gitignored; never commit weights or keys).
- Before each push run: `python -m pytest -q tests/test_exact.py tests/test_isa.py
  tests/test_compiler.py tests/test_chain.py`, `cargo test -p tdcc_exact`, `cargo clippy`,
  `cargo build-sbf`, `tdcc-exact demo`, `tdcc-exact demo --localnet`.
- After the program changes, run an end-to-end localnet scenario with real providers and a
  verifier running as separate node processes, including a cheater caught through the
  on-chain bisection with no arbiter signature.

## 2. Things only the owner can do: ask, do not work around

Collect these in `docs/production-readiness.md` under "Owner actions" and ask the owner
once, with exact steps:
- Devnet SOL for deploy (faucet.solana.com; the airdrop is rate limited), and who holds the
  program upgrade authority (should become a Squads multisig before mainnet).
- GitHub Actions billing, or making the repo public.
- Choice of last-step dispute resolution if the trade-offs are not clear-cut.
- Slashed-provider policy, fee / bond / stake amounts, window lengths for mainnet.
- Security audit of the program (external firm), bug bounty.
- Mainnet USDC, real stakes, RPC provider, monitoring/alerting accounts.
- Hardware (P2): the Kintex-7 card, the RTL hash engine bring-up, timing closure.
- Model license and any legal review for charging for inference.

## 3. Definition of done

- Every blocker and high item in `docs/production-readiness.md` is fixed and tested, or
  explicitly marked as an owner action with the reason.
- The protocol works with **no trusted arbiter** on localnet end to end (renter API → provider
  node → verifier node → on-chain bisection → slash/settle), and on devnet once SOL is
  provided, with Explorer links in the README.
- CI workflow covers lint, types, Rust lint/format, unit, program, validator and demo tests.
- Threat model, protocol spec, operator runbook and API reference are written.
- A final report: what changed, test counts, measured performance, remaining risks, and the
  owner-action list.
