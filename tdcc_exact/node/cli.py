"""`tdcc-exact node provider|verifier|store|publish`: the market's off-chain services.

    tdcc-exact node store    --dir ~/tdcc-store [--host 0.0.0.0 --port 8787]
    tdcc-exact node publish  --job job.json --store http://host:8787        (a renter)
    tdcc-exact node provider --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node verifier --rpc URL --keys DIR --store http://host:8787 [--rate 0.2] [--once]

--keys DIR holds Solana keypair files: the node's own (<name>.json, `provider` or `verifier`
by default, created on first use) and, unless --admin names the market's admin public key,
admin.json (the market is the config PDA seeded by the admin's key).
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ..trace import EVERY


def cmd_node(a) -> int:
    from .store import DirStore, open_store, serve
    if a.role == "store":
        srv = serve(DirStore(a.dir), a.host, a.port)
        print(f"store: {Path(a.dir).resolve()} on http://{a.host}:{srv.server_address[1]}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    store = open_store(a.store)
    if a.role == "publish":
        from ..oracle import Job
        print(store.put_job(Job.load(a.job)))
        return 0

    from .chainio import Chain, load_key, market_admin
    from .common import Models
    if not a.keys:
        raise SystemExit("--keys DIR is required")
    name = a.name or a.role
    owner = load_key(a.keys, name)
    chain = Chain.connect(a.rpc, market_admin(a.keys, a.admin), a.cluster)
    state = a.state or str(Path(a.keys) / f"{name}.state" / "state.json")
    models = Models(a.models)
    print(f"{a.role} {owner.pubkey()} on market {chain.m.config} ({a.rpc}), state {state}")
    if a.role == "provider":
        from .provider import ProviderNode
        node = ProviderNode(chain, owner, store, state, models, a.every)
        if a.once:
            print(node.run_once(wait=True))
            return 0
    else:
        from .verifier import VerifierNode
        node = VerifierNode(chain, owner, store, state, models, a.every, a.rate)
        if a.once:
            print(node.run_once())
            return 0
    try:
        node.loop(a.poll)
    except KeyboardInterrupt:
        pass
    return 0


def add_parser(sub) -> argparse.ArgumentParser:
    n = sub.add_parser("node", help="run a market service: job store, provider or verifier",
                       description=__doc__,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    n.add_argument("role", choices=["provider", "verifier", "store", "publish"])
    n.add_argument("--rpc", default="http://127.0.0.1:8899", help="Solana RPC URL")
    n.add_argument("--cluster", default="localnet", help="for Explorer links only")
    n.add_argument("--keys", help="keypair directory (the node's key, admin.json)")
    n.add_argument("--name", help="the node's key name in --keys (default: the role)")
    n.add_argument("--admin", help="the market admin's public key (default: KEYS/admin.json)")
    n.add_argument("--store", default="http://127.0.0.1:8787", help="store URL or directory")
    n.add_argument("--state", help="state file (default: KEYS/<name>.state/state.json)")
    n.add_argument("--models", help="directory holding the models jobs name")
    n.add_argument("--every", type=int, default=EVERY)
    n.add_argument("--rate", type=float, default=1.0, help="verifier: share of jobs re-run")
    n.add_argument("--once", action="store_true", help="one pass, then exit")
    n.add_argument("--poll", type=float, default=2.0, help="seconds between passes")
    n.add_argument("--dir", default="tdcc-store", help="store: where the blobs go")
    n.add_argument("--host", default="127.0.0.1", help="store: address to listen on")
    n.add_argument("--port", type=int, default=8787, help="store: port")
    n.add_argument("--job", help="publish: the Job JSON file")
    n.set_defaults(fn=cmd_node)
    return n
