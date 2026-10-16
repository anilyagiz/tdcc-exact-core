# TDCC Exact: operations

How to run a TDCC Exact market today: deploy the program, initialize a market and choose its
parameters, keep its keys, watch it, and what has to be done before it holds real money. The
accounts and the job's states are in [architecture.md](architecture.md); the risks behind
each recommendation are in [threat-model.md](threat-model.md).

The program is unaudited and runs on devnet with a test USDC mint. Nothing here makes it safe
for real funds; [Before mainnet](#before-mainnet) lists what does.

## Deploy the program

The build needs the Solana CLI (Agave) with `cargo build-sbf`; CI installs the stable release
([`.github/workflows/exact.yml`](../.github/workflows/exact.yml)).

```sh
cargo build-sbf --manifest-path programs/tdcc_exact/Cargo.toml
# target/deploy/tdcc_exact.so            the program
# target/deploy/tdcc_exact-keypair.json  the program id's keypair (created on the first build)
```

The program id is compiled in (`declare_id!` in
[`programs/tdcc_exact/src/lib.rs`](../programs/tdcc_exact/src/lib.rs)) and repeated in
[`Anchor.toml`](../Anchor.toml) and in `PROGRAM_ID` in
[`tdcc_exact/chain.py`](../tdcc_exact/chain.py). The published id,
`HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A`, belongs to the keypair its deployer holds; it is
not in the repository. A new deployment with its own keypair changes all three places to its
own id:

```sh
solana-keygen pubkey target/deploy/tdcc_exact-keypair.json   # must equal declare_id!
```

Deploy (the deployer's default keypair pays, about 2.5 SOL for this program, and becomes the
upgrade authority):

```sh
solana program deploy -u devnet target/deploy/tdcc_exact.so \
    --program-id target/deploy/tdcc_exact-keypair.json
solana program show -u devnet <PROGRAM_ID>        # the authority and the last deploy slot
```

On a local validator, load the program at start instead (README, "On Solana"):
`solana-test-validator --reset --bpf-program <PROGRAM_ID> target/deploy/tdcc_exact.so`.

### The upgrade authority

Whoever holds the upgrade authority can replace the program and, with it, move every token in
every market's vault. On any cluster with real funds:

- Move the authority to a multisig (for example a Squads vault) right after the first
  deploy, and keep its signers on separate hardware wallets:

  ```sh
  solana program set-upgrade-authority -u <cluster> <PROGRAM_ID> \
      --new-upgrade-authority <MULTISIG_ADDRESS> --skip-new-upgrade-authority-signer-check
  ```

- Upgrade by writing a buffer (`solana program write-buffer`), handing the buffer to the
  multisig (`solana program set-buffer-authority`), and having the multisig sign the upgrade.
- Publish a verifiable build of each deployed version, so anyone can match the deployed
  bytes to a commit.
- Once the program is audited and stable, consider making it immutable
  (`solana program set-upgrade-authority --final`). This cannot be undone, and later fixes
  then need a new program id and a migration.

## Initialize a market

A market is one `Config` account, derived from the admin's key. The arbiter, which signs
every `slash` and `dismiss`, is a key of its own (the admin's unless set), and the admin can
replace it at any time with `set_arbiter`. The admin and the other parameters cannot be
changed after `initialize`; a change means a new market (a new admin key) and moving providers
and renters to it.

From Python ([`tdcc_exact/chain.py`](../tdcc_exact/chain.py)); the client knows `devnet` and
`localnet`, and takes any other RPC with `rpc=` (or `TDCC_EXACT_RPC`):

```python
from solders.pubkey import Pubkey
from tdcc_exact.chain import Params, connect

m = connect("devnet")                    # admin key: ~/.config/tdcc-exact/devnet/admin.json
m.mint = Pubkey.from_string("<USDC mint>")   # leave unset and initialize creates a test mint
m.initialize(Pubkey.from_string("<treasury owner>"), Params(
    host_bps=8_000,             # the provider's share of a settled price
    verifier_bps=5_000,         # the challenger's share of a slashed stake
    commit_window=3_000,        # slots; the reveal window has the same length
    challenge_window=9_000,     # slots after the reveal
    min_stake=1_000_000_000,    # base units (1,000 USDC)
    unstake_cooldown=432_000,   # slots
    challenge_bond=10_000_000,  # a verifier's deposit per challenge (10 USDC)
    arbiter_window=216_000,     # slots the arbiter has to rule (about a day)
    arbiter=Pubkey.from_string("<arbiter multisig>"),
    non_reveal_penalty=20_000_000,  # stake to the renter for a commit never revealed
))
```

`initialize` creates the treasury's associated token account for the treasury owner, and the
vault. It refuses shares above 10,000 bps, a zero window, stake or bond, and an unstake
cooldown that does not outlast a job (below).

### Choosing the windows

A slot is about 400 ms; the numbers above are an example, not a recommendation for every
model.

- **`commit_window`**: long enough for a provider to see the job, run it and land the commit:
  the run time of the slowest model the market takes on the slowest hardware it allows, plus
  margin for congestion. The reveal window (`reveal_deadline = commit_deadline +
  commit_window`) only has to land one transaction, so it is longer than it needs to be.
- **`challenge_window`**: long enough for a verifier to notice the reveal, re-run the job and
  land a challenge. A verifier on the simulator takes about a minute per LFM2.5-230M job
  ([exact.md](exact.md#7-overhead-of-the-log)) and has a queue; the window should cover the
  queue, not one job.
- **`arbiter_window`**: the arbiter's time to rule after a challenge. After it, anyone can
  dismiss and the receipt stands, so it must cover the arbiter's re-run, the bisection and a
  multisig's signing round.
- **`challenge_bond`**: large enough that challenging honest receipts at random costs more than
  it annoys, small enough that an honest verifier risks it; a dismissed challenge pays it to
  the provider.
- **`non_reveal_penalty`**: what a provider pays the renter for committing and then
  withholding its reveal; at least the price of a typical job.
- **`unstake_cooldown`**: longer than the whole life of a job:

      unstake_cooldown > commit_window (commit) + commit_window (reveal)
                         + challenge_window + arbiter_window

  `initialize` enforces it (`Params.job_life`). The program also refuses an unstake while the
  provider has open jobs, so the cooldown is a second guard. With the example: 3,000 + 3,000 +
  9,000 + 216,000 = 231,000 slots, and 432,000 (about two days) leaves margin.

The demo's values (`Params` defaults: 8, 8, cooldown 50; `tdcc-exact demo --localnet`: 100 and
60; CI: 60 and 30) are for a test validator and are far too short for a market.

### Choosing the stake

A slash takes a provider's whole stake once, however many of its jobs are wrong
([threat-model.md](threat-model.md#attacks), "One stake behind many jobs"). The stake has to be
worth more than what a provider saves by cheating on every job it can hold open at once. The
program checks only `min_stake`; renters should check a provider's stake against their price
before `open_job`.

## Keys

No key belongs in the repository. `target/` (with `target/deploy/`) and `.anchor/` are in
[`.gitignore`](../.gitignore); the client keeps its keys under `~/.config/tdcc-exact/<cluster>/`
(or `$TDCC_EXACT_KEYS/<cluster>/`), creating the directory with mode 0700 and each file
readable by its owner only. Do not point `TDCC_EXACT_KEYS` inside the repository.

| Key | Where it lives | What it can do | Keep it |
|:--|:--|:--|:--|
| Program id keypair | `target/deploy/tdcc_exact-keypair.json` | claim the program address at the first deploy | backed up offline until the first deploy, then not needed |
| Upgrade authority | the deployer's `~/.config/solana/id.json` until moved | replace the program, move every vault's tokens | a multisig ([above](#the-upgrade-authority)) |
| Arbiter | wherever its signers keep their keys | slash and dismiss challenged jobs before their ruling deadline | a multisig; rotate it with `set_arbiter` if a signer is lost |
| Admin | `~/.config/tdcc-exact/<cluster>/admin.json` | seeds the market (cannot be rotated); appoints the arbiter | offline |
| Treasury owner | wherever TDCC keeps its funds | spend the fees and slashed stakes | as any treasury |
| Provider, renter, verifier | each party's own machine | that party's stake, escrow, receipts and challenges | each party's concern |

The admin key also pays rent for the config and the vault, and the demo uses it to fund the
other roles with SOL. On devnet it needs about 1 SOL; keep its balance watched.

## Monitoring

Every state change emits an Anchor event, as a `Program data: ` line in the transaction's
logs: the first 8 bytes are `SHA-256("event:<Name>")[:8]`, the rest the fields in Borsh.
`tests/test_chain.py` (`_events`) decodes them; `solana logs -u <cluster> <PROGRAM_ID>` shows
them live.

| Event | Fields | Watch for |
|:--|:--|:--|
| `Initialized` | config, admin, mint | a market you did not create using your program |
| `ProviderRegistered` | provider | |
| `Staked` | provider, amount, stake | |
| `UnstakeRequested` | provider, unlock_slot | a provider leaving with open jobs |
| `Unstaked` | provider, amount | |
| `JobOpened` | job, renter, provider, price, job_digest | many cheap jobs against one provider (stake locking) |
| `ReceiptCommitted` | job, commitment | |
| `ReceiptRevealed` | job, fingerprint, trace_root, checkpoints, answer, logits_hash | verifiers should re-run each one before its challenge deadline |
| `Challenged` | job, verifier, fingerprint, bond, ruling_deadline | every one: the arbiter has to rule before the deadline |
| `Dismissed` | job, verifier, bond | repeated challengers losing bonds |
| `Slashed` | job, provider, verifier, refunded, to_verifier, to_tdcc, divergence_index, fault_step, bond | every one: publish the job and the dispute so others can check it |
| `Settled` | job, provider, host, fee | |
| `Expired` | job, renter, refunded, penalty | providers that let jobs expire, penalties paid |
| `JobClosed` | job, renter, rent | |
| `ArbiterChanged` | config, old, new | every one: only the admin can do it |

Checks to run on a schedule:

- **Challenged jobs waiting for a ruling** longer than the market's ruling policy. Each one
  holds its escrow and its provider's stake.
- **Revealed jobs past their challenge deadline** and not settled. Anyone can settle; the
  operator should run a settler so providers are paid without asking.
- **Open or committed jobs past their reveal deadline** and not expired. Anyone can expire;
  the same settler can.
- **The vault's balance** is at least the sum of the providers' stakes and the prices of open
  jobs. A shortfall is a bug; a surplus is a transfer into the vault from outside the program.
- **The program's last deploy slot and upgrade authority** (`solana program show`): any
  change that was not a planned upgrade is an incident.
- **The admin's SOL balance**, so it can always pay for a ruling.

## Before mainnet

- [ ] An audit of `programs/tdcc_exact` by an outside firm, with its findings fixed or
      accepted in writing.
- [ ] The upgrade authority on a multisig, with a written upgrade procedure; a verifiable
      build of the deployed version.
- [ ] The arbiter on a multisig, with a signing path for `slash` and `dismiss` inside
      `arbiter_window`; the admin key offline (it can only appoint the arbiter).
- [ ] The market on the mainnet USDC mint (set `Market.mint` before `initialize`; check the
      address against Circle's published one), and a treasury token account TDCC controls.
- [ ] A parameter review: windows from measured run times on the hardware the market allows,
      the unstake cooldown from the formula above, the minimum stake against the largest
      open exposure, the shares.
- [ ] The open rows of [threat-model.md](threat-model.md#attacks) closed or accepted in
      writing, at least: arbiter bias (the on-chain game), verifier selection and the
      verifier's dilemma, trace availability.
- [ ] Monitoring and a settler running against the market, with alerts on the checks above.
- [ ] Incident response: a named contact who can be reached at any hour, the reporting
      channel in [SECURITY.md](../SECURITY.md), a written plan for a bad ruling, a stolen
      admin key and a program bug (who decides, how users are told, how an upgrade is
      shipped).
- [ ] The model's license checked for paid jobs ([TODO.md](../TODO.md) item 12).
