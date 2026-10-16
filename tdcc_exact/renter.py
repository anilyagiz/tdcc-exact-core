"""The renter's side of the market: ask a question, wait for the answer, settle, get rent back.

    r = Renter(MarketIO.connect(rpc_url, admin), renter_keypair, store)
    h = r.ask("tiny", "Will it rain tomorrow?", [provider_a, provider_b], price=1_000_000)
    res = r.wait(h, timeout=600)        # answers, fingerprints, agreement across providers
    r.settle_or_expire(h)               # settle (or expire), then close_job: rent back

ask builds the Job (oracle.new_job), publishes it to the store (where providers fetch it by
its digest) and opens one on-chain job per provider, all with one shared commit deadline, so
no provider sees another's reveal before committing its own. The model hash each job pins is
the registry's for the job's (model, wformat, cap): an honest provider refuses any other.

wait polls the job accounts until each is final for the renter: revealed and past its
challenge window (or challenged and ruled on), settled, slashed, or past its reveal deadline
without a reveal (expirable). The answer is the job account's; the logits hash, which the
account does not keep, is the ReceiptRevealed event's. Fingerprints differ between providers
(each run is bound to its own job account), but honest runs agree on the answer and on the
logits hash, which is what `agree` compares.

Every chain call the renter makes goes through MarketIO (one small class, as the nodes'
chainio.Chain), so a change to the program's instructions touches that class only.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field

from . import registry
from .oracle import Job, model_name, new_job
from .trace import EVERY

FINAL = {"Settled", "Slashed", "Expired"}
ANSWERS = {0: "NO", 1: "YES"}


# ------------------------------------------------------------------------------- the chain
class MarketIO:
    """The renter's chain calls on a chain.Market (the admin may be a public key only:
    chainio.PubOnly)."""

    def __init__(self, market):
        self.m = market
        self.rpc = market.rpc

    @staticmethod
    def connect(rpc_url: str, admin, cluster: str = "localnet") -> "MarketIO":
        from .chain import Market, Rpc
        return MarketIO(Market(Rpc(rpc_url), admin, cluster))

    def slot(self) -> int:
        return self.rpc.slot()

    def commit_window(self) -> int:
        return self.m.params().commit_window

    def open(self, renter, provider, job_id: int, digest: bytes, model_hash: bytes,
             price: int, commit_deadline: int):
        """(job account, signature)."""
        return self.m.open_job(renter, provider, job_id, digest, model_hash, price,
                               commit_deadline)

    def job_key(self, renter, job_id: int):
        return self.m.job_pda(renter, job_id)

    def job(self, key):
        """The JobAccount, or None once it is closed (or was never opened)."""
        from .chain import JobAccount
        d = self.rpc.account(key)
        return None if d is None else JobAccount.decode(d)

    def revealed(self, key) -> dict | None:
        from .node.chainio import Chain
        return Chain(self.m).revealed(key)

    def settle(self, payer, key) -> str:
        return self.m.settle(payer, key)

    def expire(self, payer, key) -> str:
        return self.m.expire(payer, key)

    def close(self, caller, key) -> str:
        return self.m.close_job(key, caller)


def _pubkey(k):
    if isinstance(k, str):
        from solders.pubkey import Pubkey
        return Pubkey.from_string(k)
    return k


# ------------------------------------------------------------------------------- handles
@dataclass
class Handle:
    """One question asked of one or more providers (to_json / from_json for a file)."""
    job: Job
    model_hash: str
    price: int
    commit_deadline: int
    jobs: list[dict] = field(default_factory=list)   # {provider, job_id, account, sig}

    def to_json(self) -> dict:
        return {"job": asdict(self.job), "digest": self.job.digest.hex(),
                "model_hash": self.model_hash, "price": self.price,
                "commit_deadline": self.commit_deadline, "jobs": self.jobs}

    @staticmethod
    def from_json(d: dict) -> "Handle":
        return Handle(Job(**d["job"]), d["model_hash"], d["price"], d["commit_deadline"],
                      list(d["jobs"]))


def new_job_id() -> int:
    return int.from_bytes(os.urandom(8), "little") >> 1


class Renter:
    def __init__(self, chain, owner, store, registry_path=None, log=lambda *a: None):
        """chain: a MarketIO (or a stand-in with its methods); owner: the renter's Keypair;
        store: a DirStore / HttpStore."""
        self.chain, self.owner, self.store, self.log = chain, owner, store, log
        self.registry_path = registry_path

    # ------------------------------------------------------------------ ask
    def ask(self, model: str, question: str, providers, price: int, every: int = EVERY,
            job: Job | None = None, commit_deadline: int | None = None) -> Handle:
        """Publish the question's Job and open it with each provider (price each), with one
        commit deadline for all: by default the latest the market allows for the first."""
        if not isinstance(providers, (list, tuple)):
            providers = [providers]
        if not providers:
            raise ValueError("ask at least one provider")
        if len(set(map(str, providers))) != len(providers):
            raise ValueError("a provider is named twice")
        if price <= 0:
            raise ValueError(f"price {price} is not positive")
        job = job or new_job(model, question, every=every)
        job.check_nonce()
        mh = registry.expected(model_name(job.model), job.wformat, job.cap, self.registry_path)
        if mh is None:
            raise ValueError(f"model {model_name(job.model)} ({job.wformat}, cap {job.cap}) is "
                             "not in the registry: no provider would answer it")
        self.store.put_job(job)
        if commit_deadline is None:
            commit_deadline = self.chain.slot() + self.chain.commit_window()
        h = Handle(job, mh, price, commit_deadline)
        for p in providers:
            jid = new_job_id()
            key, sig = self.chain.open(self.owner, _pubkey(p), jid, job.digest,
                                       bytes.fromhex(mh), price, commit_deadline)
            h.jobs.append({"provider": str(p), "job_id": jid, "account": str(key), "sig": sig})
            self.log(f"opened {key} with {p} ({price})  {sig}")
        return h

    # ------------------------------------------------------------------ wait
    def status(self, h: Handle) -> dict:
        """Where each job of the handle stands now (no waiting)."""
        slot = self.chain.slot()
        out = [self._one(e, slot) for e in h.jobs]
        answers = {r["answer"] for r in out if r["answer"] is not None}
        logits = {r["logits_hash"] for r in out if r["logits_hash"] is not None}
        revealed = [r for r in out if r["answer"] is not None]
        agree = len(answers) <= 1 and len(logits) <= 1
        return {"digest": h.job.digest.hex(), "question": h.job.question, "slot": slot,
                "done": all(r["final"] for r in out),
                "answer": answers.pop() if len(answers) == 1 and agree else None,
                "agree": agree, "revealed": len(revealed), "asked": len(out),
                "challenged": any(r["challenged"] for r in out),
                "slashed": any(r["state"] == "Slashed" for r in out),
                "settled": all(r["state"] in ("Settled", "Closed") for r in out),
                "jobs": out}

    def _one(self, e: dict, slot: int) -> dict:
        key = _pubkey(e["account"])
        j = self.chain.job(key)
        r = {"provider": e["provider"], "account": e["account"], "state": "Closed",
             "answer": e.get("answer"), "fingerprint": e.get("fingerprint"),
             "logits_hash": e.get("logits_hash"), "challenged": e.get("challenged", False),
             "final": True}
        if j is None:
            return r
        r["state"] = j.state
        if j.answer in ANSWERS:
            r["answer"] = e["answer"] = ANSWERS[j.answer]
            r["fingerprint"] = e["fingerprint"] = j.fingerprint.hex()
            if e.get("logits_hash") is None:
                ev = self.chain.revealed(key)
                if ev is not None:
                    e["logits_hash"] = ev["logits_hash"]
            r["logits_hash"] = e.get("logits_hash")
        if j.state == "Challenged" or bytes(j.verifier) != bytes(32):
            r["challenged"] = e["challenged"] = True
        r["final"] = (j.state in FINAL
                      or (j.state == "Revealed" and slot > j.challenge_deadline)
                      or (j.state in ("Open", "Committed") and slot > j.reveal_deadline))
        r["deadline"] = {"Open": j.reveal_deadline, "Committed": j.reveal_deadline,
                         "Revealed": j.challenge_deadline,
                         "Challenged": j.ruling_deadline}.get(j.state)
        return r

    def wait(self, h: Handle, timeout: float = 600.0, poll: float = 1.0) -> dict:
        """Poll until every job is final for the renter (status()["done"]) or `timeout`
        seconds pass; the last status either way."""
        end = time.monotonic() + timeout
        while True:
            s = self.status(h)
            if s["done"] or time.monotonic() >= end:
                return s
            time.sleep(poll)

    # ------------------------------------------------------------------ settle
    def settle_or_expire(self, h: Handle) -> dict:
        """settle each job past its challenge window, expire each never revealed past its
        reveal deadline, and close each final one (its rent back to the renter).
        {account: [actions]}."""
        slot = self.chain.slot()
        done = {}
        for e in h.jobs:
            key = _pubkey(e["account"])
            acts = []
            j = self.chain.job(key)
            if j is None:
                done[e["account"]] = ["closed"]
                continue
            if j.state == "Revealed" and slot > j.challenge_deadline:
                self.chain.settle(self.owner, key)
                acts.append("settled")
            elif j.state in ("Open", "Committed") and slot > j.reveal_deadline:
                self.chain.expire(self.owner, key)
                acts.append("expired")
            j = self.chain.job(key)
            if j is not None and j.state in FINAL:
                self.chain.close(self.owner, key)
                acts.append("closed")
            done[e["account"]] = acts or [f"waiting ({j.state})"]
        return done


# ------------------------------------------------------------------------------- the CLI
def cmd_renter(a) -> int:
    from .node.chainio import load_key, market_admin
    from .node.store import open_store
    owner = load_key(a.keys, a.name, create=False)
    chain = MarketIO.connect(a.rpc, market_admin(a.keys, a.admin), a.cluster)
    r = Renter(chain, owner, open_store(a.store))
    if a.action == "ask":
        if not a.provider or not a.question or a.price is None:
            raise ValueError("ask needs --provider, --question and --price")
        h = r.ask(a.model, a.question, a.provider, a.price, every=a.every)
        if a.out:
            with open(a.out, "w") as f:
                json.dump(h.to_json(), f, indent=1)
    else:
        if not a.handle:
            raise ValueError(f"{a.action} needs --handle (the file ask --out wrote)")
        with open(a.handle) as f:
            h = Handle.from_json(json.load(f))
    out = {"handle": h.to_json()}
    if a.wait or a.settle or a.action != "ask":
        out["result"] = r.wait(h, a.timeout) if (a.wait or a.settle) else r.status(h)
    if a.settle or a.action == "settle":
        out["settle"] = r.settle_or_expire(h)
    print(json.dumps(out, indent=1))
    return 0


def add_parser(sub):
    n = sub.add_parser("renter", help="ask providers a question on the market; wait; settle")
    n.add_argument("action", choices=["ask", "status", "settle"])
    n.add_argument("--rpc", default="http://127.0.0.1:8899", help="Solana RPC URL")
    n.add_argument("--cluster", default="localnet", help="for Explorer links only")
    n.add_argument("--keys", required=True, help="keypair directory (the renter's, admin.json)")
    n.add_argument("--name", default="renter", help="the renter's key name in --keys")
    n.add_argument("--admin", help="the market admin's public key (default: KEYS/admin.json)")
    n.add_argument("--store", default="http://127.0.0.1:8787", help="store URL or directory")
    n.add_argument("--provider", action="append", help="a provider's public key (repeat to "
                   "fan out)")
    n.add_argument("--model", default="tiny")
    n.add_argument("--question")
    n.add_argument("--price", type=int, help="USDC base units, per provider")
    n.add_argument("--every", type=int, default=EVERY, help="steps between trace checkpoints")
    n.add_argument("--out", help="ask: write the handle here")
    n.add_argument("--handle", help="status/settle: the handle file")
    n.add_argument("--wait", action="store_true", help="wait until the answers are final")
    n.add_argument("--settle", action="store_true", help="wait, then settle/expire and close")
    n.add_argument("--timeout", type=float, default=600.0, help="seconds to wait")
    n.set_defaults(fn=cmd_renter)
    return n
