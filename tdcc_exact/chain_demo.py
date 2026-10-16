"""`tdcc-exact demo --devnet` (or --localnet): the demo's five steps, each a Solana transaction.

    1. the renter opens two jobs (offered to provider A and provider B), its USDC into
       escrow; each provider accepts its own (no job binds a provider before it accepts)
    2. A runs honestly, B skips a layer; both commit, then reveal their receipts
    3. a verifier re-runs the job and challenges B's receipt (putting up the challenge bond)
    4. the bisection names B's first wrong instruction; the arbiter slashes B on-chain (the
       verifier gets its bond back with its share of B's stake)
    5. A's job settles after its challenge window: 80% to A, 20% to TDCC

The market (config, test USDC mint, treasury) is created on first use by the admin key in
~/.config/tdcc-exact/<cluster>/admin.json; that key also funds the other roles.
"""
from __future__ import annotations

import time

from . import registry
from .backend import SkipLayer
from .chain import ChainError, Params, connect
from .commit import commitment, new_salt
from .oracle import build_hash, layers_of, load_model, model_name, new_job, run_job

ROLES = ("renter", "provider-a", "provider-b", "verifier", "treasury")


def run(a) -> int:
    from .chain import keypair
    t0 = time.time()

    def say(*x):
        print(f"[{time.time() - t0:6.1f}s]", *x)

    cluster = "devnet" if a.devnet else "localnet"
    m = connect(cluster, a.rpc)
    rpc = m.rpc
    keys = {r: keypair(cluster, r) for r in ROLES}
    renter, pa, pb, verifier = (keys[r] for r in ROLES[:4])
    link = m.link

    # ------------------------------------------------------------------ set-up
    say(f"0. market on {cluster} ({rpc.url}), program {m.pid}")
    if rpc.balance(m.admin.pubkey()) < 500_000_000:
        try:
            rpc.airdrop(m.admin.pubkey(), 2_000_000_000)
        except ChainError as e:
            say(f"   the admin {m.admin.pubkey()} has too little SOL and the airdrop failed "
                f"({e}).\n   Fund it at https://faucet.solana.com and run again.")
            return 2
    if not m.ready:
        p = Params(commit_window=a.commit_window, challenge_window=a.challenge_window)
        p.unstake_cooldown = max(p.unstake_cooldown, p.job_life + 1)
        sig = m.initialize(keys["treasury"].pubkey(), p)
        say(f"   created the market: test USDC mint {m.mint}\n   {link(sig)}")
    m.fund(*(k.pubkey() for k in (renter, pa, pb, verifier)))
    m.mint_to(renter.pubkey(), 2 * a.price)
    bond = m.params().challenge_bond
    if m.balance(verifier.pubkey()) < 2 * bond:             # what each challenge puts up
        m.mint_to(verifier.pubkey(), 2 * bond)
    for p in (pa, pb):
        acct = m.provider(p.pubkey())
        if acct is None:
            m.register_provider(p)
            acct = m.provider(p.pubkey())
        if acct.stake < a.stake:
            m.mint_to(p.pubkey(), a.stake - acct.stake)
            m.stake(p, a.stake - acct.stake)
    say(f"   providers A {pa.pubkey()} and B {pb.pubkey()} staked "
        f"{a.stake / 1e6:.2f} USDC each")

    # ------------------------------------------------------------------ 1. jobs
    question, model_id = a.question, a.model
    job = new_job(model_id, question, "demo", every=a.every)
    model = load_model(model_id)
    want = registry.expected(model_name(model_id), job.wformat, job.cap)
    model_hash = bytes.fromhex(want or build_hash(model_id, job.wformat, job.cap, model))
    say(f"1. renter opens the oracle job on {model_id} with A and with B, "
        f"{a.price / 1e6:.2f} USDC each into escrow")
    say(f"   Q: {question!r} ({len(job.prompt_ids)} tokens)")
    base = int(time.time() * 1000)
    jobs = {}
    deadline = rpc.slot() + m.params().commit_window      # one commit deadline for A and B
    for i, (name, p) in enumerate((("A", pa), ("B", pb))):
        acct, sig = m.open_job(renter, p.pubkey(), base + i, job.digest, model_hash, a.price,
                               deadline)
        jobs[name] = acct
        say(f"   job {name}: {link(str(acct), 'address')}\n   open_job: {link(sig)}")
    for name, p in (("A", pa), ("B", pb)):                # each provider takes its job on
        sig = m.accept_job(p, jobs[name])
        say(f"   {name} accepts: {link(sig)}")

    # ------------------------------------------------------------------ 2. runs, receipts
    L = layers_of(model[0])
    layer = a.skip_layer if a.skip_layer is not None else L // 2
    say(f"2. A runs it honestly; B skips layer {layer} to save time")
    # each run's trace starts from its on-chain job's address (the binding), so B cannot
    # replay A's fingerprint on its own job
    runs = {"A": run_job(job, "A", model=model, binding=bytes(jobs["A"])),
            "B": run_job(job, "B", SkipLayer(layer, L), model=model,
                         binding=bytes(jobs["B"]))}
    salts = {}
    for name, p in (("A", pa), ("B", pb)):
        r = runs[name].receipt
        salts[name] = new_salt()
        c = commitment(bytes.fromhex(r.fingerprint), bytes(p.pubkey()), salts[name])
        sig = m.commit_receipt(p, jobs[name], c)
        say(f"   {name}: {r.answer}  fingerprint {r.fingerprint[:16]}..  commit {link(sig)}")
    rpc.wait_slot(max(m.job(j).commit_deadline for j in jobs.values()))
    for name, p in (("A", pa), ("B", pb)):
        r = runs[name].receipt
        # the program checks the fingerprint against the answer, the logits hash and the
        # trace's tree root and checkpoint count
        sig = m.reveal_run(p, jobs[name], r, [c.leaf for c in runs[name].log.checkpoints],
                           salts[name])
        say(f"   {name} reveals {r.answer}: {link(sig)}")

    # ------------------------------------------------------------------ 3. verify
    say("3. a verifier re-runs each job on this laptop (bound to the job's address)")
    challenged = []
    for name, p in (("A", pa), ("B", pb)):
        mine = run_job(job, "verifier", model=model, binding=bytes(jobs[name]))
        fp = bytes.fromhex(mine.receipt.fingerprint)
        posted = m.job(jobs[name]).fingerprint
        if posted == fp:
            say(f"   {name}: match -> accept")
        else:
            sig = m.challenge(verifier, jobs[name], fp)
            challenged.append(name)
            say(f"   {name}: MISMATCH -> challenge {link(sig)}")

    # ------------------------------------------------------------------ 4. dispute, slash
    from .verifier import dispute
    for name in challenged:
        say(f"4. bisecting {name}'s trace for the first instruction that went wrong")
        _, d, f = dispute(job, runs[name].log.checkpoints, model, replay_cheat=SkipLayer(layer, L),
                          out=lambda s: say("  ", s), binding=bytes(jobs[name]),
                          receipt=runs[name].receipt)
        if d is None or f is None:
            sig = m.dismiss(jobs[name])
            say(f"   no fault found: challenge dismissed {link(sig)}")
            continue
        r0 = {k: m.balance(keys[k].pubkey()) for k in ("renter", "verifier", "treasury")}
        sig = m.slash(jobs[name], d.index, f.step)
        say(f"   the arbiter slashes {name}: {link(sig)}")
        for k, v in r0.items():
            say(f"   {k:9s} {(m.balance(keys[k].pubkey()) - v) / 1e6:+9.2f} USDC")

    # ------------------------------------------------------------------ 5. settle
    say("5. A's challenge window closes; anyone settles A's job")
    for name in ("A", "B"):
        if name in challenged:
            continue
        rpc.wait_slot(m.job(jobs[name]).challenge_deadline)
        p = pa if name == "A" else pb
        b0 = (m.balance(p.pubkey()), m.balance(keys["treasury"].pubkey()))
        sig = m.settle(renter, jobs[name])
        say(f"   settle {link(sig)}")
        say(f"   {name:9s} {(m.balance(p.pubkey()) - b0[0]) / 1e6:+9.2f} USDC  job paid")
        say(f"   {'tdcc':9s} {(m.balance(keys['treasury'].pubkey()) - b0[1]) / 1e6:+9.2f} USDC"
            "  protocol fee")
    states = {n: m.job(j).state for n, j in jobs.items()}
    say(f"   final: {states}")
    return 0 if states.get("A") == "Settled" and states.get("B") == "Slashed" else 1
