"""The off-chain half of the market: a job store, a provider node, a verifier node and an
arbiter node.

The chain keeps only a job's digest; the job itself (its model, prompt ids, answer tokens)
travels through the store (store.py), keyed by that digest, and each fetch is checked against
the key. Providers publish their traces there too (keyed by trace root) for data availability.

    tdcc-exact node store    --dir DIR --port 8787
    tdcc-exact node provider --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node verifier --rpc URL --keys DIR --store http://host:8787 [--once]
    tdcc-exact node arbiter  --rpc URL --keys DIR --store http://host:8787 [--once]

The nodes reach the chain only through chainio.py, so a change to the program's accounts or
instructions is one file to adapt.
"""
