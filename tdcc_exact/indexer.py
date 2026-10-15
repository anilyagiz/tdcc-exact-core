"""Observability for the Solana market: the program's events and a snapshot of its accounts.

    tdcc-exact market status --rpc URL [--admin PUBKEY] [--json]
    tdcc-exact market events --rpc URL [--limit N] [--json]

Events. Anchor's `emit!` logs "Program data: <base64>": an 8-byte discriminator,
sha256("event:<Name>")[:8], then the struct's fields in Borsh (Pubkey 32 bytes, integers
little-endian, [u8; 32] as is). EVENTS below is the program's #[event] structs, in field
order; a new event (or a new field at the end of one) is one line there. An event this table
does not know decodes as {"name": "?", "raw": hex} rather than failing.

Accounts. getProgramAccounts with a discriminator filter, decoded by chain.JobAccount /
chain.ProviderAccount (and CONFIG_FIELDS here), summed into a snapshot: jobs by state, the
escrow still locked, the stakes, the open challenges, and the jobs past a deadline that
anyone may now settle (or the renter expire).

Pubkeys come out as base58 strings and byte arrays as hex, so everything is JSON as is. Only
the RPC and account parts need solders (pip install -e '.[chain]'); the event decoder does
not.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from collections.abc import Iterator

PROGRAM = "HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A"   # chain.PROGRAM_ID

# ------------------------------------------------------------------------------- Borsh
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


# type -> (size, decode)
TYPES = {
    "pubkey": (32, b58),
    "bytes32": (32, lambda b: b.hex()),
    "u64": (8, lambda b: struct.unpack("<Q", b)[0]),
    "i64": (8, lambda b: struct.unpack("<q", b)[0]),
    "u32": (4, lambda b: struct.unpack("<I", b)[0]),
    "u16": (2, lambda b: struct.unpack("<H", b)[0]),
    "u8": (1, lambda b: b[0]),
    "bool": (1, lambda b: b[0] != 0),
}


def decode_fields(fields: list[tuple[str, str]], data: bytes, off: int = 0) -> dict:
    """Borsh fields from data[off:]; ValueError when the data is too short."""
    out = {}
    for name, typ in fields:
        n, dec = TYPES[typ]
        if off + n > len(data):
            raise ValueError(f"short data at {name}")
        out[name] = dec(data[off:off + n])
        off += n
    return out


def encode_fields(fields: list[tuple[str, str]], values: dict) -> bytes:
    """The inverse of decode_fields (for tests and tools): pubkeys as 32 raw bytes or base58."""
    out = b""
    for name, typ in fields:
        v = values[name]
        if typ == "pubkey":
            out += v if isinstance(v, bytes) else _b58_decode(v)
        elif typ == "bytes32":
            out += v if isinstance(v, bytes) else bytes.fromhex(v)
        elif typ == "bool":
            out += bytes([1 if v else 0])
        else:
            out += struct.pack({"u64": "<Q", "i64": "<q", "u32": "<I", "u16": "<H",
                                "u8": "<B"}[typ], v)
    return out


def _b58_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


# ------------------------------------------------------------------------------- events
# programs/tdcc_exact/src/lib.rs, the #[event] structs, fields in order.
EVENTS: dict[str, list[tuple[str, str]]] = {
    "Staked": [("provider", "pubkey"), ("amount", "u64"), ("stake", "u64")],
    "JobOpened": [("job", "pubkey"), ("renter", "pubkey"), ("provider", "pubkey"),
                  ("price", "u64"), ("job_digest", "bytes32")],
    "ReceiptCommitted": [("job", "pubkey"), ("commitment", "bytes32")],
    "ReceiptRevealed": [("job", "pubkey"), ("fingerprint", "bytes32"),
                        ("trace_root", "bytes32"), ("checkpoints", "u32")],
    "Challenged": [("job", "pubkey"), ("verifier", "pubkey"), ("fingerprint", "bytes32")],
    "Settled": [("job", "pubkey"), ("provider", "pubkey"), ("host", "u64"), ("fee", "u64")],
    "Slashed": [("job", "pubkey"), ("provider", "pubkey"), ("verifier", "pubkey"),
                ("refunded", "u64"), ("to_verifier", "u64"), ("to_tdcc", "u64"),
                ("divergence_index", "u32"), ("fault_step", "u64")],
    "Dismissed": [("job", "pubkey"), ("verifier", "pubkey")],
}


def event_disc(name: str) -> bytes:
    return hashlib.sha256(f"event:{name}".encode()).digest()[:8]


def decode_event(data: bytes) -> dict:
    """One event's bytes (discriminator + Borsh) -> {"name": ..., fields...}."""
    for name, fields in EVENTS.items():          # small table: a scan keeps edits one-line
        if data[:8] == event_disc(name):
            try:
                return {"name": name, **decode_fields(fields, data, 8)}
            except ValueError:
                break
    return {"name": "?", "raw": data.hex()}


def encode_event(name: str, values: dict) -> bytes:
    return event_disc(name) + encode_fields(EVENTS[name], values)


def events_from_logs(logs: list[str], program: str = PROGRAM) -> list[dict]:
    """The events `program` emitted in one transaction's log messages, in order.

    "Program data:" lines are attributed to the innermost running program (the invoke /
    success / failed lines are a stack), so another program's data lines are skipped."""
    stack: list[str] = []
    out = []
    for line in logs or []:
        parts = line.split()
        if len(parts) < 3 or parts[0] != "Program" or parts[1].endswith(":"):
            parts = []                                 # "Program log: ..." and the like
        if len(parts) >= 4 and parts[2] == "invoke":
            stack.append(parts[1])
        elif parts and parts[2] in ("success", "failed:", "failed") and stack:
            stack.pop()
        if line.startswith("Program data: ") and stack and stack[-1] == program:
            try:
                data = base64.b64decode(line[len("Program data: "):].strip(), validate=True)
            except ValueError:
                continue
            out.append(decode_event(data))
    return out


# ------------------------------------------------------------------------------- RPC
def signatures(rpc, address: str = PROGRAM, limit: int = 100,
               until: str | None = None) -> list[dict]:
    """getSignaturesForAddress, newest first, paged until `limit` or the `until` signature."""
    out: list[dict] = []
    before = None
    while len(out) < limit:
        opts = {"limit": min(1000, limit - len(out)), "commitment": "confirmed"}
        if before:
            opts["before"] = before
        if until:
            opts["until"] = until
        page = rpc.call("getSignaturesForAddress", address, opts)
        if not page:
            break
        out += page
        before = page[-1]["signature"]
        if len(page) < opts["limit"]:
            break
    return out[:limit]


def events(rpc, program: str = PROGRAM, limit: int = 100, until: str | None = None,
           include_failed: bool = False) -> Iterator[dict]:
    """The decoded events of the program's last `limit` transactions, oldest first (slot
    order); each with its "sig" and "slot". Failed transactions emit nothing that stands and
    are skipped unless include_failed."""
    sigs = signatures(rpc, program, limit, until)
    sigs.reverse()                                     # oldest first, block order kept
    for s in sorted(sigs, key=lambda s: s["slot"]):   # stable: same-slot order stays
        if s.get("err") and not include_failed:
            continue
        tx = rpc.call("getTransaction", s["signature"],
                      {"encoding": "json", "commitment": "confirmed",
                       "maxSupportedTransactionVersion": 0})
        if tx is None:
            continue
        for i, e in enumerate(events_from_logs((tx.get("meta") or {}).get("logMessages"),
                                               program)):
            yield {**e, "sig": s["signature"], "slot": tx.get("slot", s["slot"]),
                   "index": i, "block_time": tx.get("blockTime")}


# ------------------------------------------------------------------------------- accounts
# programs/tdcc_exact/src/lib.rs `Config`, after the discriminator.
CONFIG_FIELDS = [("admin", "pubkey"), ("mint", "pubkey"), ("treasury", "pubkey"),
                 ("vault", "pubkey"), ("host_bps", "u16"), ("verifier_bps", "u16"),
                 ("commit_window", "u64"), ("challenge_window", "u64"), ("min_stake", "u64"),
                 ("unstake_cooldown", "u64"), ("bump", "u8"), ("vault_bump", "u8")]

LIVE = ("Open", "Committed", "Revealed", "Challenged")      # the escrow is still in the vault


def _disc(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]   # chain.acct_disc


def decode_config(d: bytes) -> dict:
    if d[:8] != _disc("Config"):
        raise ValueError("not a Config account")
    return decode_fields(CONFIG_FIELDS, d, 8)


def decode_job(d: bytes) -> dict:
    from .chain import JobAccount
    j = JobAccount.decode(d)
    return {k: (str(v) if type(v).__name__ == "Pubkey" else
                v.hex() if isinstance(v, bytes) else v) for k, v in vars(j).items()}


def decode_provider(d: bytes) -> dict:
    from .chain import ProviderAccount
    p = ProviderAccount.decode(d)
    return {"owner": str(p.owner), "stake": p.stake, "open_jobs": p.open_jobs,
            "unlock_slot": p.unlock_slot}


def program_accounts(rpc, kind: str, program: str = PROGRAM,
                     extra: list[dict] | None = None) -> list[tuple[str, bytes]]:
    """(address, data) of every `kind` account (Job, Provider, Config): a memcmp filter on the
    discriminator, so a layout that grows keeps matching."""
    flt = [{"memcmp": {"offset": 0, "bytes": b58(_disc(kind))}}] + (extra or [])
    res = rpc.call("getProgramAccounts", program,
                   {"encoding": "base64", "commitment": "confirmed", "filters": flt})
    if isinstance(res, dict):                     # withContext responses
        res = res["value"]
    return [(a["pubkey"], base64.b64decode(a["account"]["data"][0])) for a in res]


def config_address(admin: str, program: str = PROGRAM) -> str:
    from solders.pubkey import Pubkey
    pid, a = Pubkey.from_string(program), Pubkey.from_string(admin)
    return str(Pubkey.find_program_address([b"config", bytes(a)], pid)[0])


def provider_address(config: str, owner: str, program: str = PROGRAM) -> str:
    from solders.pubkey import Pubkey
    pid = Pubkey.from_string(program)
    return str(Pubkey.find_program_address(
        [b"provider", bytes(Pubkey.from_string(config)), bytes(Pubkey.from_string(owner))],
        pid)[0])


def build_snapshot(slot: int, configs: dict[str, dict], providers: dict[str, dict],
                   jobs: dict[str, dict]) -> dict:
    """The market's state at `slot` from decoded accounts (address -> dict). Pure."""
    by_state: dict[str, int] = {}
    escrow = 0
    challenges, actions = [], []
    for addr, j in sorted(jobs.items(), key=lambda kv: kv[1]["opened_slot"]):
        st = j["state"]
        by_state[st] = by_state.get(st, 0) + 1
        if st in LIVE:
            escrow += j["price"]
        if st == "Challenged":
            challenges.append({"job": addr, "provider": j["provider"],
                               "verifier": j["verifier"], "price": j["price"]})
        if st == "Revealed" and slot > j["challenge_deadline"]:
            actions.append({"job": addr, "action": "settle", "state": st,
                            "deadline": j["challenge_deadline"],
                            "late": slot - j["challenge_deadline"]})
        elif st in ("Open", "Committed") and slot > j["reveal_deadline"]:
            actions.append({"job": addr, "action": "expire", "state": st,
                            "deadline": j["reveal_deadline"],
                            "late": slot - j["reveal_deadline"]})
    stakes = sorted(({"provider": p["owner"], "account": a, "stake": p["stake"],
                      "open_jobs": p["open_jobs"], "unlock_slot": p["unlock_slot"]}
                     for a, p in providers.items()), key=lambda p: -p["stake"])
    return {"slot": slot, "configs": configs, "jobs": len(jobs), "jobs_by_state": by_state,
            "escrow": escrow, "total_stake": sum(p["stake"] for p in stakes),
            "providers": stakes, "open_challenges": challenges, "actionable": actions}


def snapshot(rpc, admin: str | None = None, program: str = PROGRAM) -> dict:
    """Every Config, Provider and Job account of the program (or of `admin`'s market only)."""
    slot = rpc.slot()
    configs = {a: decode_config(d) for a, d in program_accounts(rpc, "Config", program)}
    job_filter = None
    if admin:
        cfg = config_address(admin, program)
        configs = {a: c for a, c in configs.items() if a == cfg}
        job_filter = [{"memcmp": {"offset": 8, "bytes": cfg}}]          # Job.config
    jobs = {a: decode_job(d) for a, d in program_accounts(rpc, "Job", program, job_filter)}
    providers = {a: decode_provider(d) for a, d in program_accounts(rpc, "Provider", program)}
    if admin:                       # Provider has no config field: its PDA is seeded by one
        providers = {a: p for a, p in providers.items()
                     if a == provider_address(cfg, p["owner"], program)}
    return build_snapshot(slot, configs, providers, jobs)


# ------------------------------------------------------------------------------- CLI
def _usdc(x: int) -> str:
    return f"{x / 1e6:,.2f} USDC"


def _short(k: str) -> str:
    return k if len(k) <= 12 else f"{k[:4]}..{k[-4:]}"


def format_snapshot(s: dict) -> str:
    out = [(f"slot {s['slot']}: {len(s['configs'])} market(s), {s['jobs']} jobs, "
            f"escrow {_usdc(s['escrow'])}, stake {_usdc(s['total_stake'])}")]
    for a, c in s["configs"].items():
        out.append(f"  market {_short(a)}  admin {_short(c['admin'])}  host {c['host_bps']} bps"
                   f"  windows commit {c['commit_window']} / challenge {c['challenge_window']}")
    if s["jobs_by_state"]:
        out.append("  jobs: " + ", ".join(f"{k} {v}" for k, v in s["jobs_by_state"].items()))
    for p in s["providers"]:
        out.append(f"  provider {_short(p['provider'])}  stake {_usdc(p['stake'])}  "
                   f"open jobs {p['open_jobs']}"
                   + (f"  unstaking at {p['unlock_slot']}" if p["unlock_slot"] else ""))
    for c in s["open_challenges"]:
        out.append(f"  CHALLENGED {c['job']}  verifier {_short(c['verifier'])}  "
                   f"(arbiter: slash or dismiss)")
    for x in s["actionable"]:
        out.append(f"  {x['action'].upper():6s} {x['job']}  ({x['state']}, "
                   f"{x['late']} slots past {x['deadline']})")
    return "\n".join(out)


def format_event(e: dict) -> str:
    rest = "  ".join(f"{k}={_short(v) if isinstance(v, str) else v}" for k, v in e.items()
                     if k not in ("name", "sig", "slot", "index", "block_time"))
    return f"{e.get('slot', '-'):>10}  {e['name']:16s} {rest}"


def cmd_market(a) -> int:
    from .chain import RPC, Rpc
    rpc = Rpc(a.rpc or os.environ.get("TDCC_EXACT_RPC") or RPC["devnet"])
    if a.action == "status":
        s = snapshot(rpc, a.admin)
        print(json.dumps(s, indent=1) if a.json else format_snapshot(s))
    else:
        evs = list(events(rpc, limit=a.limit))
        if a.json:
            print(json.dumps(evs, indent=1))
        else:
            for e in evs:
                print(format_event(e))
    return 0

