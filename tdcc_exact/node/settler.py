"""The settler node: move the market's jobs past their deadlines, so no escrow waits on a person.

Each pass (`run_once`) lists the market's Job accounts and sends, for each one that is due:

    Revealed           past challenge_deadline: settle (the price to the provider and TDCC)
    Open, Committed    past reveal_deadline: expire (the escrow back to the renter, and the
                       non-reveal penalty from the stake for a commit never revealed)
    Offered            past accept_deadline: cancel_job, but only the job's renter may: the
                       node cancels the offers of its own key (a renter runs it under its own
                       key) and logs the others once, skipping them
    Settled, Slashed,  close_job (`close`, on by default): the account's rent goes back to
    Expired            the renter

and then closes, in the same pass, the jobs it just finished. Settle, expire and close are
open to anyone (the program sends every payout to its party whoever signs), so any key with
SOL for the fees can run this; it holds no state of its own: the chain is the state, and a
transaction another settler beat it to fails and is logged, the job is gone or done on the
next pass. Challenged jobs are the arbiter's (its node also dismisses them past the ruling
deadline).
"""
from __future__ import annotations

import time

FINAL = ("Settled", "Slashed", "Expired")


def due(j, slot: int) -> str | None:
    """The action a job in this state is due at `slot` (settle, expire, cancel, close), or
    None."""
    if j.state == "Revealed" and slot > j.challenge_deadline:
        return "settle"
    if j.state in ("Open", "Committed") and slot > j.reveal_deadline:
        return "expire"
    if j.state == "Offered" and slot > j.accept_deadline:
        return "cancel"
    if j.state in FINAL:
        return "close"
    return None


class SettlerNode:
    def __init__(self, chain, owner, close: bool = True, log=print):
        self.chain, self.owner, self.close, self.log = chain, owner, close, log
        self.skipped: set[str] = set()          # others' lapsed offers, logged once

    def run_once(self) -> dict:
        """{job: [actions sent]} of this pass ("settle", "expire", "cancel", "close")."""
        out: dict[str, list[str]] = {}
        slot = self.chain.slot()
        finished = []
        for key, j in self.chain.jobs():
            act = due(j, slot)
            if act is None or (act == "close" and not self.close):
                continue
            k = str(key)
            if act == "cancel" and bytes(j.renter) != bytes(self.owner.pubkey()):
                if k not in self.skipped:
                    self.skipped.add(k)
                    self.log(f"{k[:8]}: offer lapsed at {j.accept_deadline}; only its renter "
                             f"{j.renter} may cancel it (skipped)")
                continue
            if self._send(act, key):
                out.setdefault(k, []).append(act)
                if act != "close":
                    finished.append(key)
        for key in finished if self.close else []:
            if self._send("close", key):
                out[str(key)].append("close")
        return out

    def _send(self, act: str, key) -> bool:
        c, k = self.chain, str(key)
        try:
            sig = {"settle": c.settle, "expire": c.expire, "cancel": c.cancel,
                   "close": c.close}[act](self.owner, key)
        except Exception as e:  # noqa: BLE001 - another settler first, a node hiccup: next pass
            self.log(f"{k[:8]}: {act} failed: {type(e).__name__}: {e}")
            return False
        self.log(f"{k[:8]}: {act}  {sig}")
        return True

    def loop(self, poll: float = 2.0) -> None:
        while True:
            try:
                self.run_once()
            except Exception as e:  # noqa: BLE001 - a node keeps going; the next pass retries
                self.log(f"pass failed: {e}")
            time.sleep(poll)
