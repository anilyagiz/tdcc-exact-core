# Contributing

Issues and pull requests are welcome. Most of the work needs only Python (and Rust for the
Solana program), not an FPGA.

## Where a change goes

- **The verification layer** (`tdcc_exact/`, `programs/tdcc_exact/`, `tests/test_exact.py`,
  `tests/test_chain.py`, `docs/exact.md`): here.
- **The accelerator** (`opentpu/`, `rtl/`, `sim/`, `boards/`): upstream, at
  [FeSens/openTPU](https://github.com/FeSens/openTPU), so the two stay mergeable. The one local
  change inside `opentpu/` is the observer hook in `isasim.Machine.run`.
- **A security problem**: not an issue; see [SECURITY.md](SECURITY.md).

## Setup

```sh
pip install -e '.[chain]' pytest
```

`.[model]` adds what the LFM2.5-230M runs need (the tokenizer, the safetensors reader). The
verifier and the CLI run on any OS; the rest of the upstream suite is Linux-only (`fcntl`).

## Checks

The fast ones, as CI runs them:

```sh
python -m pytest -q tests/test_exact.py tests/test_isa.py tests/test_compiler.py
tdcc-exact demo
```

The Solana program (needs the Solana CLI, Agave):

```sh
cargo test -p tdcc_exact
cargo build-sbf --manifest-path programs/tdcc_exact/Cargo.toml
solana-test-validator --reset --bpf-program \
    HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A target/deploy/tdcc_exact.so &
TDCC_EXACT_REQUIRE_CHAIN=1 python -m pytest -q tests/test_chain.py
```

Changes to the ISA, the simulator or the RTL must keep the full `python -m pytest -q` passing
(it needs Verilator).

## Rules of thumb

- A fix comes with a test that fails without it. For the program, a test on the validator that
  checks the error code.
- The settlement arithmetic lives twice, in `tdcc_exact/settle.py` and in the program's
  `math` module: change both, and `tests/data/exact_settle_vectors.json`, together.
- Anything that changes the trace, the trace root or the fingerprint changes every receipt:
  say so in the commit message and update the README's sample output.
- A program change needs a redeploy before it reaches devnet; say so in the commit message.
- Performance claims say how they were measured.

Contributions are licensed under the Apache License 2.0, as the rest of the repository.
