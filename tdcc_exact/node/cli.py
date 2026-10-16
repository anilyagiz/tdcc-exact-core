"""`tdcc-exact node provider|verifier|arbiter|store|publish`: the market's off-chain services.

    tdcc-exact node store    --dir ~/tdcc-store [--host 0.0.0.0 --port 8787] [--retention 30d]
    tdcc-exact node gc       --dir ~/tdcc-store --retention 30d [--pins FILE] [--dry-run]
    tdcc-exact node publish  --job job.json --store http://host:8787        (a renter)
    tdcc-exact node provider --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node verifier --rpc URL --keys DIR --store http://host:8787 [--rate 0.2] [--once]
    tdcc-exact node arbiter  --rpc URL --keys DIR --store http://host:8787 [--once]

--keys DIR holds Solana keypair files: the node's own (<name>.json, `provider` or `verifier`
by default, created on first use) and, unless --admin names the market's admin public key,
admin.json (the market is the config PDA seeded by the admin's key). The arbiter signs with
KEYS/arbiter.json, or admin.json when there is none; it must be the market's Config.arbiter.
"""
from __future__ import annotations

import argparse
from pathlib import Path



def _limit(v: str) -> tuple[str, int]:
    kind, _, n = v.partition("=")
    kinds = {"job": "jobs", "trace": "traces", "signed": "signed"}
    if kind not in kinds or not n.isdigit():
        raise argparse.ArgumentTypeError(f"{v!r}: want job|trace|signed=BYTES")
    return kinds[kind], int(n)


def _duration(v: str) -> float:
    from .store import parse_duration
    try:
        return parse_duration(v)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def store_opts(a) -> dict:
    """The store server's options from the command line."""
    from .store import AllowList, load_keypair
    return dict(mirrors=a.mirror or (),
                mirror_key=load_keypair(a.store_key) if a.store_key else None,
                max_body=dict(a.max_body or []), timeout=a.timeout,
                writers=AllowList(a.writers) if a.writers else None,
                retention=a.retention, pins=a.pins, gc_every=a.gc_every, log=print)


def cmd_node(a) -> int:
    from .store import DirStore, load_keypair, open_store, serve
    if a.role == "store":
        srv = serve(DirStore(a.dir), a.host, a.port, **store_opts(a))
        print(f"store: {Path(a.dir).resolve()} on http://{a.host}:{srv.server_address[1]}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    if a.role == "gc":
        from .store import load_pins
        r = DirStore(a.dir).gc(a.retention, load_pins(a.pins) if a.pins else (),
                               dry_run=a.dry_run)
        for kind, key in r.deleted:
            print(f"{'would delete' if a.dry_run else 'deleted'} {kind}/{key}")
        print(r if a.retention is not None else f"{r} (no --retention: blobs are kept)")
        return 0
    store = open_store(a.store, key=load_keypair(a.store_key) if a.store_key else None,
                       quorum=a.quorum)
    if a.role == "publish":
        from ..oracle import Job
        print(store.put_job(Job.load(a.job)))
        return 0

    from .chainio import Chain, load_key, market_admin
    from .common import Models
    if not a.keys:
        raise SystemExit("--keys DIR is required")
    name = a.name or a.role
    if a.role == "arbiter":
        try:
            owner = load_key(a.keys, name, create=False)
        except FileNotFoundError:
            name, owner = "admin", load_key(a.keys, "admin", create=False)
        name = "arbiter"                    # the state file's name, whichever key signs
    else:
        owner = load_key(a.keys, name)
    chain = Chain.connect(a.rpc, market_admin(a.keys, a.admin), a.cluster)
    state = a.state or str(Path(a.keys) / f"{name}.state" / "state.json")
    models = Models(a.models)
    print(f"{a.role} {owner.pubkey()} on market {chain.m.config} ({a.rpc}), state {state}")
    if a.role == "provider":
        from .provider import ProviderNode
        node = ProviderNode(chain, owner, store, state, models)
        if a.once:
            print(node.run_once(wait=True))
            return 0
    elif a.role == "arbiter":
        from .arbiter import ArbiterNode, NotArbiter
        try:
            node = ArbiterNode(chain, owner, store, state, models,
                               missing_trace_loses=not a.missing_trace_waits,
                               trace_grace=a.trace_grace,
                               missing_window_loses=not a.missing_window_waits,
                               window_grace=a.window_grace)
        except NotArbiter as e:
            raise SystemExit(str(e)) from None
        if a.once:
            print(node.run_once())
            return 0
    else:
        from .verifier import VerifierNode
        node = VerifierNode(chain, owner, store, state, models, rate=a.rate)
        if a.once:
            print(node.run_once())
            return 0
    try:
        node.loop(a.poll)
    except KeyboardInterrupt:
        pass
    return 0


def add_parser(sub) -> argparse.ArgumentParser:
    n = sub.add_parser("node", help="run a market service: job store, provider, verifier or arbiter",
                       description=__doc__,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    n.add_argument("role", choices=["provider", "verifier", "arbiter", "store", "gc", "publish"])
    n.add_argument("--rpc", default="http://127.0.0.1:8899", help="Solana RPC URL")
    n.add_argument("--cluster", default="localnet", help="for Explorer links only")
    n.add_argument("--keys", help="keypair directory (the node's key, admin.json)")
    n.add_argument("--name", help="the node's key name in --keys (default: the role)")
    n.add_argument("--admin", help="the market admin's public key (default: KEYS/admin.json)")
    n.add_argument("--store", default="http://127.0.0.1:8787",
                   help="store URL or directory; several, comma-separated, are written to a "
                        "quorum of and read from the first with a good copy")
    n.add_argument("--quorum", type=int, help="with several --store: writes that must "
                                              "succeed (default: a majority)")
    n.add_argument("--store-key", help="keypair file that signs the node's PUTs (for a store "
                                       "started with --writers)")
    n.add_argument("--state", help="state file (default: KEYS/<name>.state/state.json)")
    n.add_argument("--models", help="directory holding the models jobs name")
    n.add_argument("--rate", type=float, default=1.0, help="verifier: share of jobs re-run")
    n.add_argument("--missing-trace-waits", action="store_true",
                   help="arbiter: a provider whose trace is not in the store is not slashed "
                        "(default: it loses)")
    n.add_argument("--trace-grace", type=int,
                   help="arbiter: slots after a challenge to wait for a missing trace "
                        "(default: half the ruling window)")
    n.add_argument("--missing-window-waits", action="store_true",
                   help="arbiter: a provider that does not reveal its disputed window is not "
                        "slashed (default: it loses)")
    n.add_argument("--window-grace", type=int,
                   help="arbiter: slots after a challenge to wait for the provider's window "
                        "(default: half the ruling window)")
    n.add_argument("--once", action="store_true", help="one pass, then exit")
    n.add_argument("--poll", type=float, default=2.0, help="seconds between passes")
    n.add_argument("--dir", default="tdcc-store", help="store: where the blobs go")
    n.add_argument("--host", default="127.0.0.1", help="store: address to listen on")
    n.add_argument("--port", type=int, default=8787, help="store: port")
    n.add_argument("--max-body", type=_limit, action="append", metavar="KIND=BYTES",
                   help="store: largest PUT of a kind (job|trace|signed; default 1 MiB, "
                        "64 MiB, 4 MiB); larger ones get 413 unread")
    n.add_argument("--timeout", type=float, default=30.0,
                   help="store: seconds a client may stall a request before it is dropped")
    n.add_argument("--writers", metavar="FILE",
                   help="store: take PUTs only when signed by a key listed in FILE (hex or "
                        "base58, one per line; re-read when it changes). Default: anyone")
    n.add_argument("--retention", type=_duration,
                   help="store, gc: delete blobs last stored longer ago than this (90s, 12h, "
                        "30d, 2w). Default: keep everything")
    n.add_argument("--pins", metavar="FILE",
                   help="store, gc: keys (hex, one per line) never deleted")
    n.add_argument("--gc-every", type=_duration, default=3600.0,
                   help="store: seconds between gc passes (default 1h)")
    n.add_argument("--mirror", action="append", metavar="URL",
                   help="store: push every newly accepted blob to this store too "
                        "(repeatable; signed with --store-key if given)")
    n.add_argument("--dry-run", action="store_true", help="gc: report, delete nothing")
    n.add_argument("--job", help="publish: the Job JSON file")
    n.set_defaults(fn=cmd_node)
    return n
