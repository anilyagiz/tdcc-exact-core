"""tdcc_exact/indexer.py: event and account decoding (no chain), and a validator run.

The validator test needs what tests/test_chain.py needs (skipped otherwise):

    TDCC_EXACT_RPC=http://127.0.0.1:8899 python -m pytest -q tests/test_indexer.py
"""
import base64
import hashlib
import os
import re
from pathlib import Path

import pytest

from tdcc_exact import indexer
from tdcc_exact.indexer import (
    EVENTS,
    b58,
    build_snapshot,
    decode_config,
    decode_event,
    encode_event,
    encode_fields,
    event_disc,
    events_from_logs,
)

LIB = Path(__file__).resolve().parents[1] / "programs/tdcc_exact/src/lib.rs"
PID = indexer.PROGRAM
RUST = {"Pubkey": "pubkey", "u64": "u64", "i64": "i64", "u32": "u32", "u16": "u16",
        "u8": "u8", "bool": "bool", "[u8; 32]": "bytes32", "JobState": "u8"}


def _structs(attr: str) -> dict[str, list[tuple[str, str]]]:
    """lib.rs's structs under `attr` (#[event], #[account]): name -> [(field, type)]."""
    src = LIB.read_text()
    out = {}
    pat = re.escape(attr) + r"\s*(?:#\[[^\]]*\]\s*)*pub struct (\w+) \{(.*?)\n\}"
    for name, body in re.findall(pat, src, re.DOTALL):
        out[name] = [(f, RUST[t.strip()]) for f, t in
                     re.findall(r"pub (\w+): ([^,/\n]+),", body)]
    return out


def _sample(fields, seed: int) -> dict:
    v = {}
    for i, (f, t) in enumerate(fields):
        k = seed * 31 + i + 1
        v[f] = {"pubkey": bytes([k % 256]) * 32, "bytes32": bytes([(k * 7) % 256]) * 32,
                "u64": 2**63 + k, "i64": -k, "u32": 2**31 + k, "u16": 40_000 + k,
                "u8": k % 256, "bool": True}[t]
    return v


def _expect(fields, v: dict) -> dict:
    return {f: (b58(v[f]) if t == "pubkey" else v[f].hex() if t == "bytes32" else v[f])
            for f, t in fields}


def _logs(*events: bytes, program: str = PID) -> list[str]:
    return ([f"Program {program} invoke [1]", "Program log: Instruction: X"]
            + [f"Program data: {base64.b64encode(e).decode()}" for e in events]
            + [f"Program {program} consumed 1000 of 200000 compute units",
               f"Program {program} success"])


# ------------------------------------------------------------------------------- events
def test_the_table_is_the_programs_events():
    """Every #[event] struct in lib.rs, field for field, in order."""
    rs = _structs("#[event]")
    assert rs, "no #[event] structs found in lib.rs"
    assert rs == EVENTS


@pytest.mark.parametrize("name", sorted(_structs("#[event]")))
def test_every_event_decodes_from_hand_built_bytes(name):
    fields = EVENTS[name]
    v = _sample(fields, len(name))
    raw = hashlib.sha256(f"event:{name}".encode()).digest()[:8]
    for f, t in fields:                       # by hand, not through encode_fields
        x = v[f]
        raw += x if isinstance(x, bytes) else x.to_bytes(
            {"u64": 8, "i64": 8, "u32": 4, "u16": 2, "u8": 1}[t], "little",
            signed=(t == "i64"))
    assert raw == encode_event(name, v)
    assert decode_event(raw) == {"name": name, **_expect(fields, v)}


def test_known_values():
    job, renter, prov = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    raw = (event_disc("Slashed") + job + prov + renter + (2_000_001).to_bytes(8, "little")
           + (25_000_000).to_bytes(8, "little") + (25_000_001).to_bytes(8, "little")
           + (4).to_bytes(4, "little") + (1234).to_bytes(8, "little")
           + (1_000_000).to_bytes(8, "little"))
    e = decode_event(raw)
    assert e["name"] == "Slashed" and e["job"] == "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
    assert (e["refunded"], e["to_verifier"], e["to_tdcc"], e["divergence_index"],
            e["fault_step"], e["bond"]) == (2_000_001, 25_000_000, 25_000_001, 4, 1234,
                                           1_000_000)


def test_b58_matches_solders():
    solders = pytest.importorskip("solders.pubkey")
    for b in (bytes(32), b"\x00\x01" + bytes(range(30)), bytes(range(200, 232))):
        assert b58(b) == str(solders.Pubkey.from_bytes(b))
    assert b58(bytes(range(32))) == str(solders.Pubkey.from_bytes(bytes(range(32))))


def test_unknown_and_short_events_do_not_fail():
    raw = event_disc("JobClosed") + b"\x09" * 40
    assert decode_event(raw) == {"name": "?", "raw": raw.hex()}
    short = event_disc("Staked") + b"\x00" * 10
    assert decode_event(short) == {"name": "?", "raw": short.hex()}
    longer = encode_event("Dismissed", _sample(EVENTS["Dismissed"], 1)) + b"\xff" * 8
    assert decode_event(longer)["name"] == "Dismissed"       # a field appended later


def test_a_new_event_is_one_line(monkeypatch):
    monkeypatch.setitem(EVENTS, "JobClosed", [("job", "pubkey"), ("rent", "u64")])
    e = decode_event(event_disc("JobClosed") + b"\x00" * 32 + (5).to_bytes(8, "little"))
    assert e == {"name": "JobClosed", "job": "1" * 32, "rent": 5}


def test_logs_keep_only_this_programs_data():
    a = encode_event("Staked", _sample(EVENTS["Staked"], 2))
    b = encode_event("Dismissed", _sample(EVENTS["Dismissed"], 3))
    other = "Tokenkeg111111111111111111111111111111111111"
    logs = (_logs(a)[:-1]
            + [f"Program {other} invoke [2]", "Program log: success",
               f"Program data: {base64.b64encode(b).decode()}",          # the token program's
               f"Program {other} success",
               f"Program data: {base64.b64encode(b).decode()}",          # ours again
               "Program data: !!not base64!!",
               f"Program {PID} success"]
            + _logs(a, program=other))
    got = events_from_logs(logs)
    assert [e["name"] for e in got] == ["Staked", "Dismissed"]
    assert events_from_logs(None) == []


# ------------------------------------------------------------------------------- accounts
def _acct(name: str, fields, values) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8] + encode_fields(fields,
                                                                                   values)


def test_config_layout_is_lib_rs():
    assert _structs("#[account]\n#[derive(InitSpace)]")["Config"] == indexer.CONFIG_FIELDS
    v = _sample(indexer.CONFIG_FIELDS, 5)
    assert decode_config(_acct("Config", indexer.CONFIG_FIELDS, v)) == _expect(
        indexer.CONFIG_FIELDS, v)
    with pytest.raises(ValueError):
        decode_config(_acct("Job", indexer.CONFIG_FIELDS, v))


JOB = [("config", "pubkey"), ("renter", "pubkey"), ("provider", "pubkey"),
       ("job_id", "u64"), ("job_digest", "bytes32"), ("model_hash", "bytes32"),
       ("price", "u64"), ("state", "u8"), ("opened_slot", "u64"),
       ("commit_deadline", "u64"), ("reveal_deadline", "u64"),
       ("challenge_deadline", "u64"), ("commitment", "bytes32"),
       ("fingerprint", "bytes32"), ("trace_root", "bytes32"),
       ("checkpoints", "u32"), ("verifier", "pubkey"),
       ("verifier_fingerprint", "bytes32"), ("bond", "u64"),
       ("challenge_slot", "u64"), ("ruling_deadline", "u64"), ("bump", "u8")]


def _job(state: int, price: int, opened: int, reveal: int, challenge: int, seed: int) -> bytes:
    v = _sample(JOB, seed)
    v.update(state=state, price=price, opened_slot=opened, commit_deadline=opened + 4,
             reveal_deadline=reveal, challenge_deadline=challenge, checkpoints=3)
    return _acct("Job", JOB, v)


def test_job_and_provider_accounts_decode():
    pytest.importorskip("solders")
    assert _structs("#[account]\n#[derive(InitSpace)]")["Job"] == JOB
    d = indexer.decode_job(_job(2, 7, 100, 108, 0, 1))
    assert (d["state"], d["price"], d["opened_slot"], d["reveal_deadline"],
            d["checkpoints"]) == ("Revealed", 7, 100, 108, 3)
    assert d["renter"] == b58(_sample(JOB, 1)["renter"])
    assert d["model_hash"] == _sample(JOB, 1)["model_hash"].hex()
    prov = [("owner", "pubkey"), ("stake", "u64"), ("open_jobs", "u32"),
            ("unlock_slot", "u64"), ("bump", "u8")]
    assert _structs("#[account]\n#[derive(InitSpace)]")["Provider"] == prov
    p = indexer.decode_provider(_acct("Provider", prov, {
        "owner": b"\x04" * 32, "stake": 50_000_001, "open_jobs": 2, "unlock_slot": 0,
        "bump": 255}))
    assert p == {"owner": b58(b"\x04" * 32), "stake": 50_000_001, "open_jobs": 2,
                 "unlock_slot": 0}


def test_snapshot_sums_escrow_and_finds_late_jobs():
    pytest.importorskip("solders")
    slot = 1000
    raw = {  # address: (state, price, opened, reveal_deadline, challenge_deadline)
        "open-late": (0, 10, 10, 20, 0),          # unrevealed past the reveal deadline
        "open-ok": (0, 20, 990, 1010, 0),
        "committed-late": (1, 30, 30, 40, 0),
        "revealed-late": (2, 40, 40, 60, 900),    # challenge window over: settle
        "revealed-ok": (2, 50, 980, 990, 1005),
        "challenged": (3, 60, 60, 70, 80),
        "settled": (4, 70, 70, 80, 90),
        "slashed": (5, 80, 80, 90, 95),
        "expired": (6, 90, 90, 95, 0),
    }
    jobs = {a: indexer.decode_job(_job(*r, seed=i)) for i, (a, r) in enumerate(raw.items())}
    provs = {"pa": {"owner": "A", "stake": 5, "open_jobs": 1, "unlock_slot": 0},
             "pb": {"owner": "B", "stake": 9, "open_jobs": 0, "unlock_slot": 1200}}
    s = build_snapshot(slot, {}, provs, jobs)
    assert s["jobs"] == 9
    assert s["jobs_by_state"] == {"Open": 2, "Committed": 1, "Revealed": 2, "Challenged": 1,
                                  "Settled": 1, "Slashed": 1, "Expired": 1}
    assert s["escrow"] == 10 + 20 + 30 + 40 + 50 + 60
    assert s["total_stake"] == 14 and s["providers"][0]["provider"] == "B"
    assert [c["job"] for c in s["open_challenges"]] == ["challenged"]
    assert [(x["job"], x["action"], x["late"]) for x in s["actionable"]] == [
        ("open-late", "expire", 980), ("committed-late", "expire", 960),
        ("revealed-late", "settle", 100)]
    text = indexer.format_snapshot(s)
    assert "SETTLE revealed-late" in text and "EXPIRE open-late" in text
    assert "CHALLENGED challenged" in text


def test_cli_parses_market(monkeypatch):
    from tdcc_exact import cli
    seen = []
    monkeypatch.setattr(cli, "cmd_market", lambda a: seen.append(vars(a)) or 0)
    assert cli.main(["market", "events", "--rpc", "http://x", "--limit", "5", "--json"]) == 0
    assert cli.main(["market", "status", "--admin", "K"]) == 0
    assert [(a["action"], a["rpc"], a["limit"], a["json"], a["admin"]) for a in seen] == [
        ("events", "http://x", 5, True, None), ("status", None, 100, False, "K")]


# ------------------------------------------------------------------------------- validator
URL = os.environ.get("TDCC_EXACT_RPC", "http://127.0.0.1:8899")


def _up() -> bool:
    """A quick probe (chain.Rpc retries for ~15 s on a refused connection)."""
    import json
    import urllib.request
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                           "params": [PID, {"encoding": "base64"}]}).encode()
        req = urllib.request.Request(URL, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())["result"]["value"] is not None
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _up(), reason=f"no validator with the program at {URL}")
def test_validator_flow_is_indexed():
    from solders.keypair import Keypair

    from tdcc_exact.chain import Market, Params, Rpc
    from tdcc_exact.commit import commitment

    rpc = Rpc(URL)
    admin, renter, prov, verifier, treasury, leaver = (Keypair() for _ in range(6))
    for k in (admin, renter, prov, verifier, leaver):
        rpc.airdrop(k.pubkey(), 1_000_000_000)
    head = indexer.signatures(rpc, limit=1)
    since = head[0]["signature"] if head else None
    m = Market(rpc, admin, "localnet")
    m.initialize(treasury.pubkey(), Params(commit_window=10, challenge_window=6,
                                           arbiter_window=4, unstake_cooldown=31))
    m.mint_to(prov.pubkey(), 20_000_000)
    m.register_provider(prov)
    m.stake(prov, 20_000_000)
    m.mint_to(renter.pubkey(), 10_000_000)
    m.mint_to(verifier.pubkey(), Params().challenge_bond)
    model = b"\x07" * 32

    def post(job, fp):
        salt = os.urandom(32)
        m.commit_receipt(prov, job, commitment(fp, bytes(prov.pubkey()), salt))
        rpc.wait_slot(m.job(job).commit_deadline)
        m.reveal_receipt(prov, job, fp, salt, model, b"\x0a" * 32, 3)

    j1, _ = m.open_job(renter, prov.pubkey(), 1, b"\x01" * 32, model, 2_000_000)
    post(j1, b"\x11" * 32)
    m.challenge(verifier, j1, b"\x12" * 32)
    m.dismiss(j1)
    rpc.wait_slot(m.job(j1).challenge_deadline)
    m.settle(admin, j1)
    j2, _ = m.open_job(renter, prov.pubkey(), 2, b"\x02" * 32, model, 3_000_000)
    post(j2, b"\x21" * 32)                       # revealed, left to settle
    j3, _ = m.open_job(renter, prov.pubkey(), 3, b"\x03" * 32, model, 1_000_000)
    rpc.wait_slot(max(m.job(j2).challenge_deadline, m.job(j3).reveal_deadline))

    s = indexer.snapshot(rpc, str(admin.pubkey()))
    assert list(s["configs"]) == [str(m.config)]
    assert s["jobs_by_state"] == {"Settled": 1, "Revealed": 1, "Open": 1}
    assert s["escrow"] == 4_000_000
    assert [(p["provider"], p["stake"], p["open_jobs"]) for p in s["providers"]] == [
        (str(prov.pubkey()), 20_000_000, 2)]
    assert {(x["job"], x["action"]) for x in s["actionable"]} == {(str(j2), "settle"),
                                                                  (str(j3), "expire")}
    assert s["open_challenges"] == []
    everything = indexer.snapshot(rpc)
    assert everything["jobs"] >= 3 and str(m.config) in everything["configs"]

    m.expire(renter, j3)
    m.mint_to(leaver.pubkey(), 15_000_000)                 # a provider that leaves
    m.register_provider(leaver)
    m.stake(leaver, 15_000_000)
    m.request_unstake(leaver)
    rpc.wait_slot(m.provider(leaver.pubkey()).unlock_slot)
    m.unstake(leaver)

    evs = list(indexer.events(rpc, limit=200, until=since))
    assert [e["slot"] for e in evs] == sorted(e["slot"] for e in evs)
    assert all(e["name"] != "?" for e in evs)
    init = [e for e in evs if e["name"] == "Initialized" and e["config"] == str(m.config)]
    assert init and init[0]["admin"] == str(admin.pubkey()) and init[0]["mint"] == str(m.mint)
    mine = [e for e in evs if e.get("job") in (str(j1), str(j2), str(j3))
            or e.get("provider") == str(prov.pubkey())]
    assert [e["name"] for e in mine] == [
        "ProviderRegistered", "Staked", "JobOpened", "ReceiptCommitted", "ReceiptRevealed",
        "Challenged", "Dismissed", "Settled", "JobOpened", "ReceiptCommitted",
        "ReceiptRevealed", "JobOpened", "Expired"]
    assert mine[1]["stake"] == 20_000_000 and mine[2]["price"] == 2_000_000
    assert mine[4]["fingerprint"] == "11" * 32 and mine[4]["checkpoints"] == 3
    assert mine[5]["verifier"] == str(verifier.pubkey())
    assert (mine[7]["host"], mine[7]["fee"]) == (1_600_000, 400_000)
    assert (mine[12]["renter"], mine[12]["refunded"]) == (str(renter.pubkey()), 1_000_000)
    gone = [e for e in evs if e.get("provider") == str(leaver.pubkey())]
    assert [e["name"] for e in gone] == ["ProviderRegistered", "Staked", "UnstakeRequested",
                                         "Unstaked"]
    assert gone[2]["unlock_slot"] > 0 and gone[3]["amount"] == 15_000_000
