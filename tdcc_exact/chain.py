"""The Solana side: a small client for programs/tdcc_exact.

    pip install -e '.[chain]'          (solders; the RPC calls are plain JSON over HTTP)

Market(rpc, admin) is one market instance: the program's config PDA is seeded by the admin's
key, so anyone can start their own (a test USDC mint, a treasury, the windows). Each method
named after an instruction sends one transaction and returns its signature (`open_job` and
`create_mint` also return the account they made); `job`, `provider` and `balance` read
accounts and send nothing. `link(sig)` is a signature's Solana Explorer page
(`link(key, "address")` an account's).

Keypairs live outside the repository, in ~/.config/tdcc-exact/<cluster>/<name>.json, created on
first use. On devnet the admin is funded by an airdrop (or by hand at faucet.solana.com) and
funds the others.

The instruction and account layouts are the program's (Anchor: an 8-byte discriminator, then
the arguments in Borsh); the accounts each instruction takes are in its `#[derive(Accounts)]`
struct, in order.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import (CreateAccountParams, TransferParams, create_account,
                                    transfer)
from solders.transaction import Transaction

PROGRAM_ID = Pubkey.from_string("HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A")
TOKEN_PROGRAM = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSTEM_PROGRAM = Pubkey.from_string("11111111111111111111111111111111")
RENT_SYSVAR = Pubkey.from_string("SysvarRent111111111111111111111111111111111")

RPC = {"devnet": "https://api.devnet.solana.com", "localnet": "http://127.0.0.1:8899"}
DECIMALS = 6
MINT_SIZE = 82

STATES = ["Open", "Committed", "Revealed", "Challenged", "Settled", "Slashed", "Expired"]


class ChainError(RuntimeError):
    def __init__(self, msg: str, logs: list[str] | None = None):
        self.logs = logs or []
        why = [l.split("Error Code: ", 1)[1] for l in self.logs if "Error Code: " in l]
        super().__init__(f"{msg} ({why[0]})" if why else msg)

    @property
    def code(self) -> str:
        """The program's error name (WindowOpen, BadReveal, ...), or ''."""
        for l in self.logs:
            if "Error Code: " in l:
                return l.split("Error Code: ", 1)[1].split(".")[0]
        return ""


# ------------------------------------------------------------------------------- RPC
class Rpc:
    def __init__(self, url: str):
        self.url = url
        self._id = 0

    def call(self, method: str, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": list(params)}).encode()
        for attempt in range(5):
            try:
                req = urllib.request.Request(self.url, body,
                                             {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    out = json.loads(r.read())
                break
            except urllib.error.HTTPError as e:
                if e.code < 500 and e.code != 429:     # a refusal: retrying will not change it
                    raise ChainError(f"{method}: HTTP {e.code} {e.reason} from {self.url}") \
                        from None
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
            except OSError:                             # the network or the node, for now
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
        if "error" in out:
            e = out["error"]
            logs = (e.get("data") or {}).get("logs") if isinstance(e, dict) else None
            raise ChainError(f"{method}: {e.get('message', e) if isinstance(e, dict) else e}",
                             logs)
        return out["result"]

    def slot(self) -> int:
        return self.call("getSlot", {"commitment": "confirmed"})

    def blockhash(self) -> Hash:
        v = self.call("getLatestBlockhash", {"commitment": "confirmed"})["value"]
        return Hash.from_string(v["blockhash"])

    def account(self, key: Pubkey) -> bytes | None:
        v = self.call("getAccountInfo", str(key),
                      {"encoding": "base64", "commitment": "confirmed"})["value"]
        return None if v is None else base64.b64decode(v["data"][0])

    def balance(self, key: Pubkey) -> int:
        return self.call("getBalance", str(key), {"commitment": "confirmed"})["value"]

    def token_balance(self, key: Pubkey) -> int:
        try:
            v = self.call("getTokenAccountBalance", str(key), {"commitment": "confirmed"})
        except ChainError:
            return 0
        return int(v["value"]["amount"])

    def rent(self, size: int) -> int:
        return self.call("getMinimumBalanceForRentExemption", size)

    def send(self, ixs: list[Instruction], payer: Keypair, *signers: Keypair) -> str:
        keys = {bytes(payer.pubkey()): payer}
        for s in signers:
            keys[bytes(s.pubkey())] = s
        msg = Message.new_with_blockhash(ixs, payer.pubkey(), self.blockhash())
        tx = Transaction(list(keys.values()), msg, msg.recent_blockhash)
        raw = base64.b64encode(bytes(tx)).decode()
        sig = self.call("sendTransaction", raw,
                        {"encoding": "base64", "preflightCommitment": "confirmed"})
        self.confirm(sig)
        return sig

    def confirm(self, sig: str, timeout: float = 60.0) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout:
            st = self.call("getSignatureStatuses", [sig])["value"][0]
            if st is not None:
                if st.get("err"):
                    raise ChainError(f"{sig}: {st['err']}")
                if st.get("confirmationStatus") in ("confirmed", "finalized"):
                    return
            time.sleep(0.5)
        raise ChainError(f"{sig}: not confirmed in {timeout:.0f}s")

    def airdrop(self, key: Pubkey, lamports: int) -> str:
        sig = self.call("requestAirdrop", str(key), lamports, {"commitment": "confirmed"})
        self.confirm(sig)
        return sig

    def wait_slot(self, slot: int, timeout: float = 600.0) -> None:
        """Until the cluster is past `slot` (a deadline); ChainError if it is not within
        `timeout` seconds (a stalled validator, or a slot far in the future)."""
        end = time.monotonic() + timeout
        while self.slot() <= slot:
            if time.monotonic() > end:
                raise ChainError(f"slot {slot} not reached within {timeout:.0f} s "
                                 f"(at {self.slot()})")
            time.sleep(0.4)


# ------------------------------------------------------------------------------- keys
def keys_dir(cluster: str) -> Path:
    return Path(os.environ.get("TDCC_EXACT_KEYS", Path.home() / ".config/tdcc-exact")) / cluster


def keypair(cluster: str, name: str) -> Keypair:
    """A named keypair (renter, provider-a, ...), created on first use (never in the repo)."""
    p = keys_dir(cluster) / f"{name}.json"
    if p.exists():
        return Keypair.from_bytes(bytes(json.loads(p.read_text())))
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    k = Keypair()
    # created 0600 from the start: write-then-chmod leaves the secret key readable in between
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(list(bytes(k))))
    return k


# ------------------------------------------------------------------------------- encoding
def ix_disc(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


def acct_disc(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]


def u8(x): return struct.pack("<B", x)
def u16(x): return struct.pack("<H", x)
def u32(x): return struct.pack("<I", x)
def u64(x): return struct.pack("<Q", x)


def b32(x: bytes) -> bytes:
    if len(x) != 32:
        raise ValueError("expected 32 bytes")
    return x


def W(k: Pubkey) -> AccountMeta:
    return AccountMeta(k, is_signer=False, is_writable=True)


def R(k: Pubkey) -> AccountMeta:
    return AccountMeta(k, is_signer=False, is_writable=False)


def S(k: Pubkey, writable: bool = False) -> AccountMeta:
    return AccountMeta(k, is_signer=True, is_writable=writable)


@dataclass
class JobAccount:
    config: Pubkey
    renter: Pubkey
    provider: Pubkey
    job_id: int
    job_digest: bytes
    model_hash: bytes
    price: int
    state: str
    opened_slot: int
    commit_deadline: int
    reveal_deadline: int
    challenge_deadline: int
    commitment: bytes
    fingerprint: bytes
    trace_root: bytes
    checkpoints: int
    verifier: Pubkey
    verifier_fingerprint: bytes
    bond: int
    challenge_slot: int
    ruling_deadline: int

    @staticmethod
    def decode(d: bytes) -> "JobAccount":
        if d[:8] != acct_disc("Job"):
            raise ChainError("not a Job account")
        o = 8
        def take(n):
            nonlocal o
            v = d[o:o + n]
            o += n
            return v
        pk = lambda: Pubkey.from_bytes(take(32))          # noqa: E731
        q = lambda: struct.unpack("<Q", take(8))[0]        # noqa: E731
        config, renter, provider = pk(), pk(), pk()
        job_id, digest, model, price = q(), take(32), take(32), q()
        state = STATES[take(1)[0]]
        opened, cd, rd, chd = q(), q(), q(), q()
        commitment, fp, root = take(32), take(32), take(32)
        cps = struct.unpack("<I", take(4))[0]
        verifier, vfp = pk(), take(32)
        bond, chs, rul = q(), q(), q()
        return JobAccount(config, renter, provider, job_id, digest, model, price, state,
                          opened, cd, rd, chd, commitment, fp, root, cps, verifier, vfp, bond,
                          chs, rul)


@dataclass
class ProviderAccount:
    owner: Pubkey
    stake: int
    open_jobs: int
    unlock_slot: int

    @staticmethod
    def decode(d: bytes) -> "ProviderAccount":
        if d[:8] != acct_disc("Provider"):
            raise ChainError("not a Provider account")
        owner = Pubkey.from_bytes(d[8:40])
        stake, open_jobs, unlock = struct.unpack("<QIQ", d[40:60])
        return ProviderAccount(owner, stake, open_jobs, unlock)


def ata(owner: Pubkey, mint: Pubkey) -> Pubkey:
    return Pubkey.find_program_address([bytes(owner), bytes(TOKEN_PROGRAM), bytes(mint)],
                                       ATA_PROGRAM)[0]


# ------------------------------------------------------------------------------- the market
@dataclass
class Params:
    host_bps: int = 8_000
    verifier_bps: int = 5_000
    commit_window: int = 8           # slots (~3 s on devnet)
    challenge_window: int = 8
    min_stake: int = 10_000_000      # 10 USDC
    unstake_cooldown: int = 50
    challenge_bond: int = 1_000_000  # 1 USDC, a verifier's deposit per challenge
    arbiter_window: int = 16         # slots the arbiter has to rule on a challenge
    arbiter: Pubkey | None = None    # who rules on challenges (None: the admin)

    @property
    def job_life(self) -> int:
        """Slots from open_job to the last moment a challenge can be ruled; the program wants
        unstake_cooldown > this, so no stake leaves before a pending ruling."""
        return 2 * self.commit_window + self.challenge_window + self.arbiter_window


class Market:
    """One market instance of the program, run by `admin`. `arbiter` signs slash and dismiss
    (the config's arbiter key; by default the admin's)."""

    def __init__(self, rpc: Rpc, admin: Keypair, cluster: str = "devnet",
                 program_id: Pubkey = PROGRAM_ID, arbiter: Keypair | None = None):
        self.rpc, self.admin, self.cluster, self.pid = rpc, admin, cluster, program_id
        self.arbiter = arbiter or admin
        self.config = self.pda(b"config", bytes(admin.pubkey()))
        self.vault = self.pda(b"vault", bytes(self.config))
        self.mint: Pubkey | None = None
        self.treasury: Pubkey | None = None
        d = rpc.account(self.config)
        if d is not None:
            self.mint = Pubkey.from_bytes(d[8 + 32:8 + 64])
            self.treasury = Pubkey.from_bytes(d[8 + 64:8 + 96])

    def pda(self, *seeds: bytes) -> Pubkey:
        return Pubkey.find_program_address(list(seeds), self.pid)[0]

    def provider_pda(self, owner: Pubkey) -> Pubkey:
        return self.pda(b"provider", bytes(self.config), bytes(owner))

    def job_pda(self, renter: Pubkey, job_id: int) -> Pubkey:
        return self.pda(b"job", bytes(self.config), bytes(renter), u64(job_id))

    def link(self, what: str, kind: str = "tx") -> str:
        q = ("?cluster=devnet" if self.cluster == "devnet" else
             "?cluster=custom&customUrl=" + self.rpc.url.replace(":", "%3A").replace("/", "%2F"))
        return f"https://explorer.solana.com/{kind}/{what}{q}"

    def _ix(self, name: str, metas: list[AccountMeta], data: bytes = b"") -> Instruction:
        return Instruction(self.pid, ix_disc(name) + data, metas)

    # --------------------------------------------------------------- set-up
    @property
    def ready(self) -> bool:
        return self.mint is not None

    def fund(self, *keys: Pubkey, lamports: int = 50_000_000) -> str | None:
        """Top up each key to `lamports` from the admin (one transfer transaction)."""
        ixs = []
        for k in keys:
            need = lamports - self.rpc.balance(k)
            if need > 0:
                ixs.append(transfer(TransferParams(from_pubkey=self.admin.pubkey(),
                                                   to_pubkey=k, lamports=need)))
        return self.rpc.send(ixs, self.admin) if ixs else None

    def create_mint(self) -> tuple[Pubkey, str]:
        """A test USDC (6 decimals) whose mint authority is the admin."""
        m = Keypair()
        ixs = [create_account(CreateAccountParams(
                   from_pubkey=self.admin.pubkey(), to_pubkey=m.pubkey(),
                   lamports=self.rpc.rent(MINT_SIZE), space=MINT_SIZE, owner=TOKEN_PROGRAM)),
               Instruction(TOKEN_PROGRAM,
                           u8(20) + u8(DECIMALS) + bytes(self.admin.pubkey()) + u8(0),
                           [W(m.pubkey())])]                  # InitializeMint2
        return m.pubkey(), self.rpc.send(ixs, self.admin, m)

    def token_account_ix(self, owner: Pubkey, payer: Pubkey | None = None) -> Instruction:
        mint = self.mint
        return Instruction(ATA_PROGRAM, u8(1),                 # CreateIdempotent
                           [S(payer or self.admin.pubkey(), True), W(ata(owner, mint)), R(owner),
                            R(mint), R(SYSTEM_PROGRAM), R(TOKEN_PROGRAM)])

    def mint_to(self, owner: Pubkey, amount: int) -> str:
        ixs = [self.token_account_ix(owner),
               Instruction(TOKEN_PROGRAM, u8(7) + u64(amount),           # MintTo
                           [W(self.mint), W(ata(owner, self.mint)), S(self.admin.pubkey())])]
        return self.rpc.send(ixs, self.admin)

    def initialize(self, treasury_owner: Pubkey, params: Params = Params()) -> str:
        if self.mint is None:
            self.mint, _ = self.create_mint()
        self.treasury = ata(treasury_owner, self.mint)
        data = (u16(params.host_bps) + u16(params.verifier_bps) + u64(params.commit_window)
                + u64(params.challenge_window) + u64(params.min_stake)
                + u64(params.unstake_cooldown) + u64(params.challenge_bond)
                + u64(params.arbiter_window)
                + bytes(params.arbiter or self.admin.pubkey()))
        ixs = [self.token_account_ix(treasury_owner),
               self._ix("initialize",
                        [S(self.admin.pubkey(), True), W(self.config), R(self.mint),
                         W(self.vault), R(self.treasury), R(TOKEN_PROGRAM),
                         R(SYSTEM_PROGRAM)], data)]
        return self.rpc.send(ixs, self.admin)

    # --------------------------------------------------------------- providers
    def register_provider(self, owner: Keypair) -> str:
        return self.rpc.send([self._ix("register_provider",
                                       [S(owner.pubkey(), True), R(self.config),
                                        W(self.provider_pda(owner.pubkey())),
                                        R(SYSTEM_PROGRAM)])], owner)

    def stake(self, owner: Keypair, amount: int) -> str:
        o = owner.pubkey()
        return self.rpc.send([self._ix("stake",
                                       [S(o), R(self.config), W(self.provider_pda(o)),
                                        R(self.mint), W(ata(o, self.mint)), W(self.vault),
                                        R(TOKEN_PROGRAM)], u64(amount))], owner)

    def request_unstake(self, owner: Keypair) -> str:
        """Start the unstake cooldown; the provider takes no new jobs from now on."""
        o = owner.pubkey()
        return self.rpc.send([self._ix("request_unstake",
                                       [S(o), R(self.config), W(self.provider_pda(o))])], owner)

    def unstake(self, owner: Keypair) -> str:
        """The whole stake back, once the cooldown is over and no job of the provider is open."""
        o = owner.pubkey()
        return self.rpc.send([self._ix("unstake",
                                       [S(o), R(self.config), W(self.provider_pda(o)),
                                        R(self.mint), W(ata(o, self.mint)), W(self.vault),
                                        R(TOKEN_PROGRAM)])], owner)

    def params(self) -> Params:
        """The market's parameters, as its config account holds them."""
        d = self.rpc.account(self.config)
        if d is None:
            raise ChainError(f"no config account {self.config}")
        o = 8 + 5 * 32
        hb, vb = struct.unpack("<HH", d[o:o + 4])
        cw, chw, ms, uc, bond, aw = struct.unpack("<6Q", d[o + 4:o + 52])
        return Params(hb, vb, cw, chw, ms, uc, bond, aw,
                      arbiter=Pubkey.from_bytes(d[8 + 4 * 32:8 + 5 * 32]))

    def provider(self, owner: Pubkey) -> ProviderAccount | None:
        d = self.rpc.account(self.provider_pda(owner))
        return None if d is None else ProviderAccount.decode(d)

    # --------------------------------------------------------------- jobs
    def open_job(self, renter: Keypair, provider: Pubkey, job_id: int, job_digest: bytes,
                 model_hash: bytes, price: int) -> tuple[Pubkey, str]:
        r = renter.pubkey()
        job = self.job_pda(r, job_id)
        data = u64(job_id) + b32(job_digest) + b32(model_hash) + u64(price)
        sig = self.rpc.send([self._ix("open_job",
                                      [S(r, True), R(self.config),
                                       W(self.provider_pda(provider)), W(job), R(self.mint),
                                       W(ata(r, self.mint)), W(self.vault), R(TOKEN_PROGRAM),
                                       R(SYSTEM_PROGRAM)], data)], renter)
        return job, sig

    def job(self, job: Pubkey) -> JobAccount:
        d = self.rpc.account(job)
        if d is None:
            raise ChainError(f"no job account {job}")
        return JobAccount.decode(d)

    def commit_receipt(self, owner: Keypair, job: Pubkey, commitment: bytes) -> str:
        return self.rpc.send([self._ix("commit_receipt",
                                       [S(owner.pubkey()), R(self.config), W(job)],
                                       b32(commitment))], owner)

    def reveal_ix(self, owner: Pubkey, job: Pubkey, fingerprint: bytes, salt: bytes,
                  model_hash: bytes, trace_root: bytes, checkpoints: int) -> Instruction:
        data = b32(fingerprint) + b32(salt) + b32(model_hash) + b32(trace_root) + u32(checkpoints)
        return self._ix("reveal_receipt",
                        [S(owner), R(self.config), W(job), R(self.provider_pda(owner))], data)

    def reveal_receipt(self, owner: Keypair, job: Pubkey, fingerprint: bytes, salt: bytes,
                       model_hash: bytes, trace_root: bytes, checkpoints: int) -> str:
        """Open the commitment (the provider must still hold the minimum stake)."""
        return self.rpc.send([self.reveal_ix(owner.pubkey(), job, fingerprint, salt, model_hash,
                                             trace_root, checkpoints)], owner)

    def challenge_ix(self, verifier: Pubkey, job: Pubkey, fingerprint: bytes) -> Instruction:
        return self._ix("challenge",
                        [S(verifier), R(self.config), W(job), R(self.mint),
                         W(ata(verifier, self.mint)), W(self.vault), R(TOKEN_PROGRAM)],
                        b32(fingerprint))

    def challenge(self, verifier: Keypair, job: Pubkey, fingerprint: bytes) -> str:
        """Dispute a revealed receipt; the config's challenge bond leaves the verifier's USDC."""
        return self.rpc.send([self.challenge_ix(verifier.pubkey(), job, fingerprint)], verifier)

    def settle(self, payer: Keypair | None, job: Pubkey) -> str:
        payer = payer or self.admin
        j = self.job(job)
        return self.rpc.send([self.token_account_ix(j.provider, payer.pubkey()),
                              self._ix("settle",
                                       [R(self.config), W(job),
                                        W(self.provider_pda(j.provider)), R(self.mint),
                                        W(self.vault), W(ata(j.provider, self.mint)),
                                        W(self.treasury), R(TOKEN_PROGRAM)])],
                             payer)

    def set_arbiter(self, arbiter: Pubkey) -> str:
        """The admin hands the arbiter role to `arbiter` (a multisig, a fresh key)."""
        return self.rpc.send([self._ix("set_arbiter",
                                       [S(self.admin.pubkey()), W(self.config)],
                                       bytes(arbiter))], self.admin)

    def slash_ix(self, job: Pubkey, renter: Pubkey, provider: Pubkey, verifier: Pubkey,
                 divergence_index: int, fault_step: int) -> Instruction:
        return self._ix("slash",
                        [S(self.arbiter.pubkey()), R(self.config), W(job),
                         W(self.provider_pda(provider)), R(self.mint), W(self.vault),
                         W(ata(renter, self.mint)), W(ata(verifier, self.mint)),
                         W(self.treasury), R(TOKEN_PROGRAM)],
                        u32(divergence_index) + u64(fault_step))

    def slash(self, job: Pubkey, divergence_index: int, fault_step: int) -> str:
        """The arbiter's ruling for the verifier (the admin pays the fee and the verifier's
        token account if it has none)."""
        j = self.job(job)
        return self.rpc.send([self.token_account_ix(j.verifier),
                              self.slash_ix(job, j.renter, j.provider, j.verifier,
                                            divergence_index, fault_step)],
                             self.admin, self.arbiter)

    def dismiss_ix(self, caller: Pubkey, job: Pubkey, provider: Pubkey) -> Instruction:
        return self._ix("dismiss",
                        [S(caller, True), R(self.config), W(job), R(self.mint), W(self.vault),
                         W(ata(provider, self.mint)), R(TOKEN_PROGRAM)])

    def dismiss(self, job: Pubkey, caller: Keypair | None = None) -> str:
        """The arbiter rejects the challenge (or, after the job's ruling deadline, anyone ends
        it); the bond goes to the provider."""
        caller = caller or self.arbiter
        payer = self.admin if caller is self.arbiter else caller
        j = self.job(job)
        return self.rpc.send([self.token_account_ix(j.provider, payer.pubkey()),
                              self.dismiss_ix(caller.pubkey(), job, j.provider)], payer, caller)

    def expire(self, payer: Keypair, job: Pubkey) -> str:
        j = self.job(job)
        return self.rpc.send([self._ix("expire",
                                       [R(self.config), W(job),
                                        W(self.provider_pda(j.provider)), R(self.mint),
                                        W(self.vault), W(ata(j.renter, self.mint)),
                                        R(TOKEN_PROGRAM)])], payer)

    def close_job(self, job: Pubkey, caller: Keypair | None = None) -> str:
        """Close a Settled, Slashed or Expired job; its rent goes back to the renter."""
        caller = caller or self.admin
        j = self.job(job)
        return self.rpc.send([self._ix("close_job",
                                       [S(caller.pubkey()), R(self.config), W(job),
                                        W(j.renter)])], caller)

    def balance(self, owner: Pubkey) -> int:
        return self.rpc.token_balance(ata(owner, self.mint))


def connect(cluster: str = "devnet", rpc: str | None = None, admin: str = "admin") -> Market:
    url = rpc or os.environ.get("TDCC_EXACT_RPC") or RPC[cluster]
    return Market(Rpc(url), keypair(cluster, admin), cluster)
