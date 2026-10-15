"""Settlement: what the Solana program pays out once a job is accepted or a provider is caught.

The amounts are in USDC base units (6 decimals). This module only computes the transfers; the
program on Solana (programs/tdcc_exact) holds the escrow and the stakes and executes them with
the same integer arithmetic: shares in basis points, rounded down, the remainder to TDCC.
tests/data/exact_settle_vectors.json holds cases both sides are tested against.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

BPS = 10_000
HOST_BPS = 8_000                 # of a settled job's price: the provider (host); TDCC the rest
VERIFIER_BPS = 5_000             # of a slashed stake: the verifier who caught it; TDCC the rest


U64 = 2 ** 64


def share(amount: int, bps: int) -> int:
    """amount * bps / 10000, rounded down (u64 * u16 fits in u128 on-chain)."""
    if not (0 <= amount < U64 and 0 <= bps <= BPS):
        raise ValueError(f"amount {amount} is not a u64 or bps {bps} is not in 0..{BPS}")
    return amount * bps // BPS


@dataclass
class Settlement:
    job_id: str
    outcome: str                 # "accepted", "slashed" or "dismissed"
    provider: str
    transfers: list              # [to, amount, why]

    def to_json(self) -> dict:
        return asdict(self)


def accept(job_id: str, provider: str, price: int) -> Settlement:
    host = share(price, HOST_BPS)
    return Settlement(job_id, "accepted", provider,
                      [[provider, host, "job paid"], ["tdcc", price - host, "protocol fee"]])


def slash(job_id: str, provider: str, renter: str, verifier: str, price: int,
          stake: int, bond: int = 0) -> Settlement:
    """The provider is caught: the renter gets the escrow back, the verifier its share of the
    stake and its challenge bond back (one transfer on-chain), TDCC the rest of the stake."""
    v = share(stake, VERIFIER_BPS)
    t = [[renter, price, "escrow refunded"],
         [verifier, v, "share of the slashed stake"],
         ["tdcc", stake - v, "rest of the slashed stake"],
         [provider, -stake, "stake slashed"]]
    if bond:
        t.append([verifier, bond, "challenge bond returned"])
    return Settlement(job_id, "slashed", provider, t)


def expire(job_id: str, provider: str, renter: str, price: int, committed: bool,
           penalty: int, stake: int) -> Settlement:
    """No reveal by the deadline: the escrow back to the renter and, if the provider committed
    (and withheld the reveal), the config's non-reveal penalty from its stake, at most all of
    it."""
    t = [[renter, price, "escrow refunded"]]
    pen = min(penalty, stake) if committed else 0
    if pen:
        t += [[renter, pen, "non-reveal penalty"], [provider, -pen, "stake, non-reveal penalty"]]
    return Settlement(job_id, "expired", provider, t)


def dismiss(job_id: str, provider: str, verifier: str, bond: int) -> Settlement:
    """The challenge is rejected: the verifier's bond pays the provider for the delay (the job
    then settles as accept() says)."""
    return Settlement(job_id, "dismissed", provider,
                      [[provider, bond, "challenge bond (dismissed challenge)"],
                       [verifier, -bond, "challenge bond lost"]])
