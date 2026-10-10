"""Settlement: what the Solana program pays out once a job is accepted or a provider is caught.

The amounts are in USDC base units (6 decimals). This module only computes the transfers; the
program on Solana holds the escrow and the stakes and executes them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

HOST_SHARE = 0.80                # of a settled job's price: the provider (host)
TDCC_SHARE = 0.20                # and TDCC
VERIFIER_SHARE = 0.50            # of a slashed stake: the verifier who caught it (rest: TDCC)


@dataclass
class Settlement:
    job_id: str
    outcome: str                 # "accepted" or "slashed"
    provider: str
    transfers: list              # [to, amount, why]

    def to_json(self) -> dict:
        return asdict(self)


def accept(job_id: str, provider: str, price: int) -> Settlement:
    host = int(price * HOST_SHARE)
    return Settlement(job_id, "accepted", provider,
                      [[provider, host, "job paid"], ["tdcc", price - host, "protocol fee"]])


def slash(job_id: str, provider: str, renter: str, verifier: str, price: int,
          stake: int) -> Settlement:
    v = int(stake * VERIFIER_SHARE)
    return Settlement(job_id, "slashed", provider,
                      [[renter, price, "escrow refunded"],
                       [verifier, v, "share of the slashed stake"],
                       ["tdcc", stake - v, "rest of the slashed stake"],
                       [provider, -stake, "stake slashed"]])
