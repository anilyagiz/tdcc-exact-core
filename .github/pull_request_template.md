## What changes, and why

## How it was checked

- [ ] `python -m pytest -q tests/test_exact.py tests/test_isa.py tests/test_compiler.py`
- [ ] the program: `cargo test -p tdcc_exact` and `tests/test_chain.py` on a local validator
      (when `programs/` or `tdcc_exact/chain.py` changed)

## Does it change

- [ ] the trace, the trace root or the fingerprint (every receipt changes)
- [ ] the settlement arithmetic (both sides and `tests/data/exact_settle_vectors.json`)
- [ ] the program (devnet needs a redeploy)
- [ ] anything inside `opentpu/` (should it go upstream?)
