# Design: paying verifiers to verify

Status: a proposal for the owner to decide on; nothing here is built. It answers
[TODO.md](../../TODO.md) item 7 ("Verifier's dilemma", "Verifier selection") and the
"Verifier's dilemma" and "Verifier collusion and selection" rows of
[threat-model.md](../threat-model.md#attacks), whose trust assumption 6 is "at least one honest
verifier checks each job. Nothing on-chain forces anyone to." It builds on the on-chain game
of [onchain-dispute.md](onchain-dispute.md).

## 1. Today's parameters

From the example market in [operations.md](../operations.md#choosing-the-windows):

| Parameter | Value |
|:--|:--|
| `host_bps` | 8,000: the provider gets 80% of a settled price, TDCC 20% (`f = 0.2`) |
| `verifier_bps` | 5,000: a winning challenger gets half the slashed stake (`v = 0.5`) |
| `min_stake` | 1,000 USDC (`S`) |
| `challenge_bond` | 10 USDC (`B`), back to a winning challenger, to the provider on a dismissal |
| `challenge_window` | 9,000 slots (about 1 h) |

The cost of one check, `c_v`: a verifier re-runs the job on the simulator. For the
LFM2.5-230M demo job that is 58 s on a 4-core VM, engine build included
([exact.md](../exact.md#7-overhead-of-the-log)): about 0.0024 USDC at 0.15 USDC per VM-hour,
plus a transaction (5,000 lamports, about 0.00075 USDC at 150 USDC per SOL) and fetching the
job. This document uses `c_v = 0.004` USDC for that job and `p = 0.05` USDC as an example
price; neither is a market figure.

## 2. The verifier's dilemma, in numbers

A verifier is paid only when it wins a challenge: `v x S = 500` USDC and its bond back.
Checking a receipt pays if the chance `q` that it is wrong satisfies

    q x v x S >= c_v      ->      q >= 0.004 / 500 = 8e-6

A provider that cheats on a job saves `g` (at most its own run cost; at most `p` if it makes the
answer up) and is caught with probability `rho` (someone checks and challenges), losing `S`
and the price. It cheats when

    g > rho x (S + p)

The two meet at a mixed equilibrium: verifiers check with total probability `rho* = g / (S +
p)`, about 5e-5 for `g = p = 0.05`, and receipts are wrong at `q* = 8e-6`. Three things make it
worse than that:

- **No income without cheating.** At `q* = 8e-6`, a verifier expects one catch in 125,000
  checks: 87 days of back-to-back re-runs at one a minute. A verifier node's fixed cost (a VM
  running all month, about 110 USDC) is never covered in between, so the rational verifier
  stops, and then `rho` falls below `g / S` and cheating pays.
- **Only the first challenger is paid.** With `n` verifiers on the same job each expects
  `1/n` of a catch, so the break-even `q` is `n` times higher.
- **One stake, many jobs.** A slash takes the provider's whole stake once; a provider that
  cheats on all its open jobs pays one verifier once, and the rest of its jobs refund their
  renters and pay nobody ([threat-model.md](../threat-model.md#attacks), "One stake behind many
  jobs").

There is also a hole in how today's verifier node samples. `VerifierNode.sampled`
([`tdcc_exact/node/verifier.py`](../../tdcc_exact/node/verifier.py)) picks a job when
`SHA-256("tdcc-exact/sample/v1" || job address || verifier key) < rate`. Every input is public
when the job is opened, before the provider runs it, so a provider that knows the verifiers'
keys (any verifier that has challenged once is on-chain) knows which jobs nobody will sample
and can cheat on exactly those. Any sampling seed has to come from after the provider has
committed; section 4.3 uses a slot hash after the reveal.

## 3. Options

### 3.1 Random audits paid from the fee

The program picks a fraction `r` of revealed jobs for audit, assigns each an auditor, and pays
it `A` for a re-check whether or not the receipt is wrong. Verifying then pays without
cheating. With `alpha` the share of TDCC's fee that funds audits and `m` the verifier's margin:

    the pool covers the audits:   r x A <= alpha x f x p
    an audit pays:                A >= (1 + m) x c_v
    so:                           alpha >= r x (1 + m) x c_v / (f x p)

| `p / c_v` (price over the cost of a check) | `alpha` needed at `r = 5%`, `m = 1` | at `r = 20%` |
|--:|--:|--:|
| 12.5 (the demo job: 0.05 / 0.004) | 4% | 16% |
| 5 | 10% | 40% |
| 2 | 25% | 100% |
| 1 | 50% | over the whole fee |

The last rows matter: a verifier re-runs on the simulator, which is far slower than a provider's
card. If competition pushes prices toward the card's cost, `c_v` can come close to `p`, and
audits at useful rates cost more than the 20% fee. Then the renter pays an audit fee on top of
the price, or the market raises `f`.

**Proof of work.** An auditor that is paid for "I checked" without showing anything is paid
for nothing. The attestation opens one checkpoint of the provider's trace, chosen after the
auditor is drawn: `index = H(seed || auditor) mod count`, `(step, chain, state)` and its Merkle
path, checked against `Job.trace_root` with `merkle_verify` (about 1,000 CU for 21
checkpoints). An honest re-run produces that leaf and its path from its own list. Without a
re-run, the leaf can come only from the provider's list, so providers keep the list private:
the on-chain game of onchain-dispute.md asks a provider to open leaves when it is challenged,
so the list no longer has to be published to the store for disputes. A provider that hands its
list to auditors so they can skip the work is answered by 3.2.

### 3.2 Planted faulty jobs

TDCC runs decoy providers: keys registered and staked like any other, which also take ordinary
jobs and run them honestly, so a decoy key is not a tell. TDCC opens jobs with them whose
receipts are wrong from the first checkpoint on (`SkipLayer` on every run). A plant tests
auditors and keeps a catch possible when nobody cheats.

- **Paying for a catch.** Slashing a decoy's stake would pay a challenger 500 USDC per plant;
  at any useful plant rate that is more than the audits cost. Instead a plant pays a bounty
  `P_b`. When a game against a decoy job ends against the provider, its payout waits
  `plant_grace` slots; TDCC's `reveal_plant` shows the job's provider is in the decoy set
  committed in `Config` (a Merkle root, one opening) and the plant's salt, and the challenger
  gets `P_b` and its bond while the rest stays with TDCC. Without a reveal the slash pays out as
  any other. A renter cannot mark a third party's job as a plant (its provider is not in the
  set).
- **Punishing a lazy auditor.** An auditor that attested a job which then loses a game by
  proof (not by timeout: TDCC controls both sides of a plant and could let its decoy time out
  on an honest receipt) forfeits its whole verifier stake `s_v` to the audit pool. This holds
  for real cheaters too; plants make sure such jobs exist. It needs the one-step proof for the
  opcode the plant breaks (phase B or C of onchain-dispute.md section 4); a plant that skips an
  MM needs phase C, one that corrupts an `LD` phase B.
- **Rate.** Laziness is deterred when the expected loss per attestation exceeds the work saved,
  `d x s_v >= k x c_v` with `d` plants per audit and `k` a safety factor. The plants cost TDCC
  `d x (P_b + fees)` per audit.

### 3.3 Per-job auditor selection by slot hash or VRF

- **Slot hash.** `select_audit(job)` is sent by anyone once the reveal slot is past. It reads
  the hash of the reveal slot from the `SlotHashes` sysvar (the last 512 slots; after that the
  job is not audited) and derives `seed = H("tdcc-exact/audit/v1" || slot hash || job)`. The
  job is audited if `seed mod 10,000 < audit_bps`; the auditor is a stake-weighted draw from the
  verifier set, excluding the provider's key. No one knows the reveal slot's hash when the
  reveal is sent, except that slot's leader, which can only skip its block to change it (and
  lose the block's rewards). A provider cannot withhold its reveal after seeing the draw: the
  draw comes after the reveal.
- **VRF.** An on-chain VRF (Switchboard, ORAO) removes the leader's one bit of influence, at a
  request fee per job, a few slots of latency and a dependency on an oracle program. Worth it
  when a job's value grows past what a validator would give up a block for.
- **Fee share.** The auditor's pay is `A` from the audit pool; a winning challenge pays as
  today.
- **Front-running.** For the first `audit_priority` slots of the challenge window only the
  drawn auditor may challenge, so a copier that sees its challenge cannot post it first. After
  that anyone may, as today.
- **Collusion.** A provider that controls a share `x` of the verifier set's stake audits its
  own jobs with probability `x`. Its cheating is then caught at rate `r x (1 - x)` from audits,
  plus whatever unpaid watchers catch.

### 3.4 The challenge bond

The bond is what a false challenge costs the challenger, and goes to the provider.

- **Lower bound.** A false challenge costs the provider an on-chain game: about 30
  transactions (0.03 USDC with priority fees), one replay of its own window (`c_v`), and its
  stake and price held for up to `dispute_window` (37,500 slots, about 4 h). So `B >= (1 + m) x
  (0.03 + c_v)`, well under 1 USDC for the demo job.
- **Upper bound.** An honest challenger loses `B` only when it is wrong itself (its own bug, or
  a card that drifts from the simulator); with that at one in a thousand, a 10 USDC bond costs
  it 0.01 USDC a challenge.
- **Today's 10 USDC fits both.** It does not need to change. What changes is that a false
  challenge is decided in hours by the game instead of a day by the arbiter, so it holds the
  provider's stake for less time.

## 4. Recommendation

Paid audits with an opening as proof of work, drawn by slot hash, with plants at a low rate
once the one-step proof covers them.

### 4.1 Formulas

| Symbol | Meaning |
|:--|:--|
| `p`, `f` | the price; TDCC's share (`1 - host_bps / 10,000`) |
| `S`, `v`, `B` | provider stake, the challenger's share of it, the challenge bond |
| `r` | `audit_bps / 10,000`: the share of revealed jobs audited |
| `A` | `audit_pay`: an auditor's pay for an attestation |
| `alpha` | `audit_fee_bps / 10,000`: the share of TDCC's fee paid into the audit pool |
| `s_v` | `verifier_min_stake` |
| `d`, `P_b` | plants per audit, the plant bounty |
| `x` | the largest share of the verifier set's stake one party holds |
| `g`, `c_v`, `k` | a cheat's saving, a check's cost, a safety factor |

    the pool is funded:          r x A <= alpha x f x p
    an audit pays:               A >= (1 + m) x c_v
    cheating does not pay:       r x (1 - x) x S >= k x g
    laziness does not pay:       d x s_v >= k x c_v
    TDCC's cost per job:         r x A + r x d x P_b

### 4.2 Example: the LFM2.5-230M demo job

`p = 0.05`, `c_v = 0.004`, `S = 1,000`, `f = 0.2`, `g <= p`, `x = 0.2`, `k = 10`, `m = 1`.

| Parameter | Value | Check |
|:--|--:|:--|
| `audit_bps` | 500 (5%) | `r x (1 - x) x S = 40 USDC >= k x g = 0.5`: 80 times over; a cheater is audited on average within 25 jobs |
| `audit_pay` | 0.01 USDC | `>= 2 x c_v = 0.008` |
| `audit_fee_bps` | 1,000 (10% of the fee) | the pool takes 0.001 per job, audits draw 0.0005: twice covered; the rest funds plants and misses |
| `verifier_min_stake` | 100 USDC | |
| `miss_penalty` | 0.05 USDC (5 x `A`); deregistered after 3 misses in a row | a drawn auditor that neither attests nor challenges pays for the hole it left |
| plants `d` | 1 per 1,000 audits | `d x s_v = 0.1 >= k x c_v = 0.04` |
| `plant_bounty` | 1 USDC | |
| `audit_priority` | 3,000 slots (the first third of the challenge window) | |
| `challenge_bond` | 10 USDC (unchanged) | section 3.4 |

TDCC's cost: `0.05 x 0.01 + 0.05 x 0.001 x 1 = 0.00055` USDC a job, 5.5% of its 0.01 fee.
An auditor with 10% of the verifier set's stake, in a market of 100,000 jobs a day, is drawn
for 500 audits a day: 500 re-runs, about 8 VM-hours, 2 USDC of compute against 5 USDC of pay,
plus a share of the 5 plants a day.

For a larger model the same formulas give the numbers: `audit_pay` scales with `c_v`, and
`alpha` with `c_v / p` (section 3.1's table). A market whose jobs name several models either
sets `audit_pay` for its most expensive check, or takes it per job: a field of `open_job` the
renter pays into the pool with the price, checked against a per-model floor.

### 4.3 What the program needs

**Accounts**

| Account | Seeds | Holds |
|:--|:--|:--|
| `Verifier` (new) | `verifier, config, owner` | the stake, consecutive misses, a pending unstake, its slot in the set |
| `VerifierSet` (new) | `verifier_set, config` | up to 256 `(key, stake)` entries and the total stake: about 10.3 KB; the draw walks the cumulative stake (a few thousand CU) |
| `Config` | | add `audit_bps`, `audit_pay`, `audit_fee_bps`, `verifier_min_stake`, `verifier_cooldown`, `miss_penalty`, `max_misses`, `audit_priority`, `plant_bounty`, `plant_grace`, `decoy_root`, `plant_authority`, `audit_pool` (a balance kept in the vault) |
| `Job` | | add `audit` (none, drawn, attested, challenged, missed), `auditor`, `audit_index`, `reveal_slot`, `plant` (a renter's 32-byte tag: random, or the plant commitment) |

**Instructions**

| Instruction | Who | What |
|:--|:--|:--|
| `register_verifier`, `stake_verifier`, `request_unstake_verifier`, `unstake_verifier` | a verifier | as the provider's; unstaking waits out `verifier_cooldown` and every job it was drawn for |
| `select_audit` | anyone, after the reveal slot, within 512 slots | the seed from `SlotHashes`, the draw, `audit_index` |
| `attest(step, chain, state, path)` | the drawn auditor, before the challenge deadline | opens leaf `audit_index` against the trace root |
| `challenge` | as today; only the drawn auditor during `audit_priority` | |
| `settle` | anyone | as today, plus `audit_fee_bps` of the fee into the pool, and `audit_pay` from the pool to an auditor that attested |
| `miss_audit` | anyone, after the challenge deadline | `miss_penalty` from the drawn auditor's stake to the pool; deregisters at `max_misses` |
| `reveal_plant(salt, decoy_path)` | the plant authority, within `plant_grace` of a lost game | the decoy's opening against `decoy_root`; pays `plant_bounty` and the bond to the challenger; the decoy's stake stays |
| `forfeit_attester` | anyone, after a job is slashed by proof | the attesting auditor's stake to the pool |

**Events**: `VerifierRegistered`, `VerifierStaked`, `VerifierUnstaked`, `AuditDrawn { job,
auditor, index }`, `Attested { job, auditor }`, `AuditPaid { job, auditor, amount }`,
`AuditMissed { job, auditor, penalty }`, `PlantRevealed { job, challenger, bounty }`,
`AttesterForfeited { job, auditor, amount }`.

### 4.4 Order

1. **Now, no program change.** Seed the verifier node's sampling from a slot hash after the
   reveal instead of `H(job || verifier key)` (section 2).
2. **With phase A of the dispute.** The verifier set, the draw, `attest`, pay and misses.
   Providers stop publishing their checkpoint lists at reveal. This alone makes verifying pay.
3. **With phase B or C.** Plants, `reveal_plant` and `forfeit_attester`, for the opcodes the
   one-step proof covers.

What it leaves open: a party with a large share of the verifier stake audits its own jobs
(`x`); the cost gap between a simulator re-run and a card run caps how low prices can go
before audits need more than the fee; plants trust TDCC's plant authority to reveal only its
own decoys, which `decoy_root` bounds but does not remove.
