"""Every chain call the nodes make, in one place (the program's API is still moving).

Chain wraps a chain.Market: listing Job accounts (getProgramAccounts filtered by the account
discriminator, the market's config and, for a provider, the provider field), the slot, and the
three instructions a node sends (commit_receipt, reveal_receipt, challenge).

The Job account's layout (programs/tdcc_exact, `pub struct Job`): an 8-byte discriminator,
then config, renter, provider (32 bytes each), ... so the memcmp offsets of the fields the
filters use are fixed by the first fields only; the state is filtered here, after decoding,
so a field appended to the account does not move a filter.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

CONFIG_OFFSET = 8                # after the discriminator
PROVIDER_OFFSET = 8 + 32 + 32    # config, renter


class PubOnly:
    """An admin known by its public key only: enough to find a market's config PDA."""

    def __init__(self, key):
        self._key = key

    def pubkey(self):
        return self._key


def load_key(keys_dir, name: str, create: bool = True):
    """DIR/<name>.json (a Solana CLI keypair file: a JSON list of 64 bytes)."""
    from solders.keypair import Keypair
    p = Path(keys_dir) / f"{name}.json"
    if p.exists():
        return Keypair.from_bytes(bytes(json.loads(p.read_text())))
    if not create:
        raise FileNotFoundError(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    k = Keypair()
    p.write_text(json.dumps(list(bytes(k))))
    p.chmod(0o600)
    return k


def market_admin(keys_dir, admin: str | None):
    """The market's admin: a base58 public key, or else DIR/admin.json."""
    from solders.pubkey import Pubkey
    if admin:
        return PubOnly(Pubkey.from_string(admin))
    return load_key(keys_dir, "admin", create=False)


class Chain:
    def __init__(self, market):
        self.m = market
        self.rpc = market.rpc

    @staticmethod
    def connect(rpc_url: str, admin, cluster: str = "localnet") -> "Chain":
        from ..chain import Market, Rpc
        return Chain(Market(Rpc(rpc_url), admin, cluster))

    # ------------------------------------------------------------------ reads
    def slot(self) -> int:
        return self.rpc.slot()

    def jobs(self, provider=None, states=None) -> list:
        """[(job pubkey, JobAccount)] of this market, optionally one provider's, in states."""
        from solders.pubkey import Pubkey

        from ..chain import JobAccount, acct_disc

        def memcmp(offset: int, raw: bytes) -> dict:
            return {"memcmp": {"offset": offset, "bytes": base64.b64encode(raw).decode(),
                               "encoding": "base64"}}
        filters = [memcmp(0, acct_disc("Job")), memcmp(CONFIG_OFFSET, bytes(self.m.config))]
        if provider is not None:
            filters.append(memcmp(PROVIDER_OFFSET, bytes(provider)))
        res = self.rpc.call("getProgramAccounts", str(self.m.pid),
                            {"encoding": "base64", "commitment": "confirmed",
                             "filters": filters})
        out = []
        for a in res:
            j = JobAccount.decode(base64.b64decode(a["account"]["data"][0]))
            if states is None or j.state in states:
                out.append((Pubkey.from_string(a["pubkey"]), j))
        out.sort(key=lambda x: (x[1].opened_slot, str(x[0])))
        return out

    def job(self, key):
        return self.m.job(key)

    # ------------------------------------------------------------------ writes
    def commit(self, owner, job, commitment: bytes) -> str:
        return self.m.commit_receipt(owner, job, commitment)

    def reveal(self, owner, job, fingerprint: bytes, salt: bytes, model_hash: bytes,
               answer: str, logits_hash: bytes, tree_root: bytes, checkpoints: int) -> str:
        """The program checks the fingerprint against these parts (tree_root: the checkpoints'
        Merkle tree below the count, chain.tree_root)."""
        return self.m.reveal_receipt(owner, job, fingerprint, salt, model_hash, answer,
                                     logits_hash, tree_root, checkpoints)

    def challenge(self, verifier, job, fingerprint: bytes) -> str:
        return self.m.challenge(verifier, job, fingerprint)
