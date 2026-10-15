"""TDCC Exact's public surface: what `import tdcc_exact` promises (no chain, no board)."""
import re

import tdcc_exact


def test_version_is_a_string():
    assert isinstance(tdcc_exact.__version__, str)
    assert re.match(r"^\d+\.\d+", tdcc_exact.__version__)


def test_all_names_resolve():
    for name in tdcc_exact.__all__:
        assert hasattr(tdcc_exact, name), name


def test_the_entry_points_are_exported():
    for name in ["Job", "Receipt", "new_job", "run_job", "TraceLog", "merkle_root",
                 "merkle_proof", "merkle_verify",
                 "bisect", "first_fault", "commitment", "check_reveal", "accept", "slash"]:
        assert name in tdcc_exact.__all__, name
        assert callable(getattr(tdcc_exact, name)), name


def test_star_import_gives_exactly_all():
    ns: dict = {}
    exec("from tdcc_exact import *", ns)
    ns.pop("__builtins__")
    assert set(ns) == set(tdcc_exact.__all__)


def test_the_package_is_typed():
    from importlib.resources import files
    assert files("tdcc_exact").joinpath("py.typed").is_file()


def test_a_commitment_round_trips_through_the_api():
    c = tdcc_exact.commitment(b"\x01" * 32, "provider", b"\x02" * 32)
    assert tdcc_exact.check_reveal(c, b"\x01" * 32, "provider", b"\x02" * 32)
    assert not tdcc_exact.check_reveal(c, b"\x01" * 32, "other", b"\x02" * 32)


def test_a_merkle_proof_round_trips_through_the_api():
    leaves = [bytes([i]) * 32 for i in range(5)]
    root = tdcc_exact.merkle_root(leaves)
    path = tdcc_exact.merkle_proof(leaves, 3)
    assert tdcc_exact.merkle_verify(leaves[3], 3, len(leaves), path, root)
    assert not tdcc_exact.merkle_verify(leaves[2], 3, len(leaves), path, root)
