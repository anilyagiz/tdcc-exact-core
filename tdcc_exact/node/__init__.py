"""The off-chain half of the market: a job store, a provider node, a verifier node, an
arbiter node and a settler node.

The chain keeps only a job's digest; the job itself (its model, prompt ids, answer tokens)
travels through the store (store.py), keyed by that digest, and each fetch is checked against
the key. Providers publish their traces there too (keyed by trace root) for data availability.

    tdcc-exact node store    --dir DIR --port 8787
    tdcc-exact node provider --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node verifier --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node arbiter  --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node settler  --rpc URL --keys DIR [--name renter] [--no-close] [--once]

The provider accepts (accept_job) only the Offered jobs it will run, after checking them, so
an offer it refuses locks none of its stake. The settler (settler.py) needs no store: it
settles revealed jobs past their challenge deadline, expires jobs past their reveal deadline,
cancels lapsed offers (only the renter's own, so a renter runs it under its key with --name)
and closes finished jobs (unless --no-close). The verifier samples jobs by a hash of the job
and its own secret key, so no provider can tell in advance which of its jobs are re-run.

The nodes reach the chain only through chainio.py, so a change to the program's accounts or
instructions is one file to adapt.

The reveal protocol (a challenged provider shows the arbiter its disputed window):

    1. The verifier challenges (the on-chain fingerprint of its own re-run) and publishes its
       re-run's trace (traces/<root>) and a note it signs, {"trace_root": root}, under
       signed_key("challenge", job, verifier): a key anyone computes from the Job account
       (its verifier field) and only the verifier can fill (store.py: signed notes).
    2. The provider sees its job Challenged, fetches that note and trace, bisects them
       against its own checkpoints (dispute.bisect(theirs, mine): divergence d, steps
       (lo, hi], checkpoint d.index), re-runs the job bound to the Job account recording that
       window (TraceLog.reveal = d.index: every step and host event from its checkpoint
       d.index - 1 to its checkpoint d.index), and publishes the records as a note it signs
       under signed_key(window_topic(lo, hi), job, provider), body {lo, hi, index, records}.
       With no divergence (the challenger's trace agrees with its own), it reveals nothing.
    3. The arbiter bisects its own honest run against the provider's posted trace. An honest
       challenger's trace is the arbiter's, so both name the same (lo, hi); the arbiter
       fetches the provider's window under that key and rules (arbiter.py, rule 2): missing
       after `window_grace` slots: the provider did not reveal (slash); not chaining from
       the agreed checkpoint to the provider's posted one (dispute.verify_window): slash;
       else the first step where it differs from the arbiter's own replay
       (dispute.first_fault) is the fault_step of the slash; no difference: dismiss.

The window's key is fixed by the chain (job, provider) and the bisection (lo, hi), so neither
the verifier nor the arbiter has to ask for it, and a squatter cannot fill it first. Limits:
the provider learns (lo, hi) only from the challenger's trace, so a challenger whose trace is
not honest (or missing) points a dishonest provider at another window than the arbiter's,
and that provider is slashed for not revealing (at lo + 1, not at its first faulty step); an
honest provider never owes a window, since the arbiter's bisection then finds no divergence.
"""
