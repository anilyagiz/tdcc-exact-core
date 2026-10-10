"""Commit-reveal for receipts: the fix for the copy attack.

Two honest runs of a job post the same fingerprint, so a provider that saw provider A's
receipt could post A's fingerprint without running anything. Receipts are therefore posted in
two phases:

1. commit: while the commit window is open, each provider posts only

       commitment = SHA-256("tdcc-exact/commit/v1" || fingerprint || provider key || salt)

   with its own 32-byte key (its Solana public key) and a fresh random 32-byte salt. The
   commitment shows nothing of the fingerprint, and A's commitment is useless to anyone else
   because it binds A's key.
2. reveal: after the commit window closes, the provider posts the fingerprint and the salt;
   the program recomputes the commitment (sol_sha256 over the same four parts) and accepts the
   reveal only if it matches. Copying a revealed fingerprint is too late: the window is shut.

programs/tdcc_exact computes the same hash (instructions `commit_receipt` and
`reveal_receipt`); tests/test_exact.py and the program's tests share a vector.
"""
from __future__ import annotations

import hashlib
import os

TAG = b"tdcc-exact/commit/v1"


def provider_key(provider: str | bytes) -> bytes:
    """A provider's 32-byte key: its public key's bytes, or (local runs with a name) the
    SHA-256 of the name."""
    if isinstance(provider, bytes):
        if len(provider) != 32:
            raise ValueError("a provider key is 32 bytes")
        return provider
    return hashlib.sha256(provider.encode()).digest()


def new_salt() -> bytes:
    return os.urandom(32)


def commitment(fingerprint: bytes, provider: str | bytes, salt: bytes) -> bytes:
    if len(fingerprint) != 32 or len(salt) != 32:
        raise ValueError("the fingerprint and the salt are 32 bytes each")
    return hashlib.sha256(TAG + fingerprint + provider_key(provider) + salt).digest()


def check_reveal(commit: bytes, fingerprint: bytes, provider: str | bytes, salt: bytes) -> bool:
    return commitment(fingerprint, provider, salt) == commit
