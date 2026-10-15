# TDCC Exact: what is left

What the hackathon deck promises, against what this repository does today. Priorities:
**P0** the devnet demo in the deck, **P1** a market that holds up against real cheaters,
**P2** hardware and mainnet (the deck's 30 / 60 / 90 days).

Done: the trace log, oracle jobs, receipts, the bisection dispute and the settlement
split, all on the bit-exact ISA simulator with a tiny random model (`tdcc-exact demo`,
`tests/test_exact.py`, docs/exact.md).

---

## P0: the demo in the deck (Solana devnet, LFM2.5-230M)

### 1. The Solana program (built, tested on a local validator, deployed to devnet)
- [x] Anchor workspace in `programs/tdcc_exact/` (Rust); program id in the README.
- [x] Deploy to devnet: needs ~2.5 SOL on the deployer key (the devnet airdrop is rate
      limited; https://faucet.solana.com), then
      `solana program deploy -ud target/deploy/tdcc_exact.so --program-id target/deploy/tdcc_exact-keypair.json`.
- [x] Accounts: `Config` (fee 20%, verifier share 50%, challenge window, min stake),
      `Provider` (owner, staked USDC, status), `Job` (renter, model id, job digest, price,
      escrow vault, state), `Receipt` (provider, fingerprint, trace root, checkpoint count,
      posted slot), `Challenge` (verifier, bisection state).
- [x] Instructions (plus commit/reveal, `dismiss`, `expire`): `register_provider` / `stake` / `unstake` (with a cooldown),
      `open_job` (USDC SPL transfer into an escrow PDA), `post_receipt`,
      `challenge`, `settle` (after the window: 80% host / 20% TDCC), `slash` (refund the
      renter, half the stake to the verifier, the rest to TDCC).
- [x] USDC on devnet: a test mint the demo creates (6 decimals), per market.
- [x] Program tests (tests/test_chain.py on solana-test-validator): honest settle, slash, window expiry,
      double settle, wrong signer.
- [x] `tdcc_exact/settle.py` must match the program's arithmetic (rounding of 80/20 and
      50/50 on odd amounts): one shared test vector file.

### 2. A client that connects the CLI to the chain
- [x] `tdcc_exact/chain.py` (solders, or a small TypeScript client): open a job,
      post a receipt, challenge, settle; print Explorer links.
- [x] `tdcc-exact demo --devnet` (and `--localnet`, run end to end): the same 5 steps as today, each step a real devnet
      transaction, with its Explorer link printed.
- [x] Devnet keypairs for renter, provider A, provider B, verifier and TDCC treasury
      (generated, funded by airdrop; never committed).

### 3. The real model (LFM2.5-230M)
Done: LFM2.5-230M runs end to end (`tdcc-exact demo --model models/LFM2.5-230M`, 5 min 45 s
on the simulator); numbers in docs/exact.md sections 5 and 6.
- [x] Install `transformers` and download `LiquidAI/LFM2.5-230M` into `models/`.
- [x] Check that `new_job` works with its tokenizer: chat template, "Yes" / "No" as single
      tokens (if not: take the first token of each, or compare the sums).
- [x] Measure: simulator seconds per token with the trace log on and off, checkpoints per
      job, trace file size. Write the numbers into docs/exact.md ("Overhead of the log").
- [x] Prompt prefill: `run_job` feeds the prompt one token per run (`Engine.step`). Use
      `Engine.prefill` (chunked, far fewer runs) and check it is still deterministic.
- [x] Check `SkipLayer` on LFM2's program: its layers repeat inside a hardware LOOP
      (`plan` loops the repeated unit), so "1/L of the run's MMs" may not be one layer.
      Better: skip by the compiler's source frames (`Instr.src`) or by layer markers.
- [x] Answer quality: a handful of real yes/no questions with known answers, to show the
      oracle is right (not just reproducible).
- [ ] The model answers Yes to every question with this prompt (3 of 7 right, docs/exact.md
      section 8): a larger model, or a calibrated Yes - No threshold, before a real oracle.

### 4. Security fixes before anyone else sees the protocol
- [x] **Copy attack.** (commit-reveal, tdcc_exact/commit.py and the program) Honest runs post the same fingerprint, so a lazy provider can copy
      provider A's receipt without running anything. Fix: commit-reveal (post
      `H(fingerprint || provider pubkey || salt)` first, reveal after the commit window),
      or bind the provider into the trace (its key in the chain's first hash).
- [x] **Digest size.** (SHA-256) `trace.DIGEST = 16` (blake2b-128) gives 64-bit collision
      resistance: too little for a value people stake money on. Use 32 bytes (blake2b-256,
      or SHA-256 to match Solana's syscall).
- [x] **Model identity.** (tdcc_exact/registry.py, models.json; the job stores the hash) The model hash is the hash of the DRAM image the engine builds,
      which depends on the build config (MCOLS, LANES, formats). Pin a model registry:
      model id -> (checkpoint hash, wformat, config) -> expected image hash.
- [x] **Job parameters the provider could change**: `wformat`, `cap`. They are in the job
      digest already; add a test that a provider who runs fp4 instead of int8 is caught.

### 5. Deliverables for the submission
- [x] Demo video: the step-by-step run, recorded (docs/media/tdcc-exact-demo.mp4,
      tools/record_demo.py).
- [ ] A capture of `tdcc-exact demo --devnet` with its Explorer pages.
- [x] The deck's "Code: [GitHub link]" ("Demo: [video link]" waits on the upload).
- [ ] Repo visibility: it is private now; make it public for the judges.
- [x] CI: GitHub Actions on Ubuntu (also builds the program and runs it on a local validator) running `python -m pytest -q tests/test_exact.py
      tests/test_isa.py tests/test_compiler.py` (the upstream suite needs Linux: `fcntl`).

---

## P1: a market that holds up

### 6. The dispute, made real
Today both sides of a dispute are replayed locally, and the provider's replay is told which
shortcut it took (`--replay-skip-layer`). In a market the provider must reveal its own steps.
- [ ] Data availability: the provider stores its full checkpoint list (and can replay any
      window) for the challenge period; upload the checkpoint list to IPFS / Arweave / a
      TDCC bucket, put its hash on-chain with the receipt.
- [ ] Reveal API on the provider node: `GET /jobs/{id}/window?lo=&hi=` returns the step
      records; a provider that does not answer within the deadline loses by default.
- [ ] On-chain bisection game (the Merkle proofs it needs: `trace.merkle_proof` /
      `merkle_verify`): each round a transaction (`bisect_step(index, leaf)`),
      both sides alternate, with timeouts. log2(checkpoints) rounds.
- [ ] The last step: who decides which side is right about one instruction? Options:
      (a) a one-step proof on-chain: needs a Merkle tree over TMEM / ACT RAM instead of
      today's flat state hash, plus an on-chain executor per opcode (MM over 128x8 int8 is
      heavy for Solana compute limits); (b) a committee of verifiers re-runs the window
      (simpler, weaker trust); (c) optimistic: the challenger posts the honest window and
      anyone can counter-challenge. Pick one and write it down in docs/exact.md.
- [ ] Merkle-ize the state hash (TMEM pages, ACT rows) if (a) is chosen.
- [ ] DRAM writes are not in the state hash: stores are caught when the data is loaded
      back. A run whose last stores are wrong (the logits area) is caught only by the
      logits hash. Hash the regions a run stores (ST / QST targets) into the chain.

### 7. Verifier incentives
- [ ] Verifier's dilemma: if nobody cheats, verifiers earn nothing and stop checking.
      Random audits funded from the 20% fee, or deliberately planted faulty jobs with a
      reward for catching them.
- [ ] Verifier selection: random (VRF / slot hash), so a provider cannot collude with "its"
      verifier.
- [ ] Rate limits on challenges: a challenge bond, lost when the challenge is wrong.

### 8. Services
- [ ] Provider node daemon: watches the chain for jobs, runs them on the card or the
      simulator, posts receipts, serves reveals, keeps traces for the challenge window.
- [ ] Verifier node: samples jobs, re-runs on a laptop, challenges, runs the bisection.
- [ ] Renter API: "one API, like any GPU platform": HTTP endpoint that opens a job and
      returns the answer; payment per token in USDC from a wallet or over HTTP with x402.
- [x] More cheat scenarios in tests: a smaller model substituted, fp4 instead of int8,
      tokens skipped, an answer with no run at all, a receipt copied (see 4).
- [ ] Jobs beyond yes/no: generate N tokens (greedy only: sampling uses the host's RNG,
      which would have to be seeded from the job and committed).

### 9. Performance of the verifier
- [x] The trace log hashes every instruction in Python (`TraceLog.observe`). Measure on
      LFM2.5-230M; if it dominates, batch the chain per run or move the hashing into a C /
      Rust extension. (It does not: +14% on LFM2.5-230M, docs/exact.md section 7; about 5%
      of a tiny-model run under the profiler, the rest is the simulator.)
- [ ] Checkpoint interval (`EVERY = 4096`): trade-off between trace size and the window a
      dispute replays. Pick it from the measurements.

---

## P2: hardware and mainnet (deck: 30 / 60 / 90 days)

### 10. The trace log on the card
The card already runs these models bit-exact with the simulator (upstream openTPU measured
it), but the Exact trace log exists only in the simulator. On the card the provider would
have to re-run the job on the simulator to produce a trace, which defeats the card's speed.
- [ ] RTL: a hash engine next to the sequencer (`rtl/seq/otpu_seq.sv`) that folds each
      issued instruction and the register file into a running chain (BLAKE2s or SHA-256 in
      fabric), readable over the control registers.
- [ ] State checkpoints on the card: a TMEM / ACT RAM read-out (or an incremental hash of
      every write) at checkpoint boundaries.
- [ ] The card's chain must equal the simulator's bit for bit: a test like
      `tools/validate.py --backend board --against isa` for the trace root.
- [ ] Timing: the design closes 133.33 MHz with WNS +0.032 ns (README); a hash engine
      must not break timing. Run it through the Vivado tournament.
- [ ] Get a Kintex-7 card (Inspur YPCB-00338), build with `make bit` in
      `boards/ypcb-00338`, bring it up (docs/board.md), first token (deck: 30 days).

### 11. Mainnet (deck: 90 days)
- [ ] Program audit, upgrade authority on a multisig.
- [ ] Mainnet USDC, real stakes, monitoring.
- [ ] Exact cards in the TDCC network; "verified lane" offered to existing TDCC users
      (deck: 60 days), 2-3 paid pilots.

### 12. Housekeeping
- [ ] Licenses: Apache-2.0 NOTICE is in place for openTPU. Check the LFM2.5 model license
      for commercial use before charging for jobs on it.
- [ ] Windows: the upstream package imports `fcntl` (Linux only) in `opentpu/rtlsim.py`,
      `opentpu/host/board.py`, `host/i2c.py`, `host/runstate.py`; the test conftest
      imports them. Either keep Linux-only (and say so) or make those imports lazy.
- [ ] Keep `upstream` (FeSens/openTPU) mergeable: the only change inside `opentpu/` is the
      observer hook in `isasim.Machine.run`.
