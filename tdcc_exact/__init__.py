"""TDCC Exact: verifiable inference on Exact Core (the openTPU design, traced).

The public surface: open a job (new_job), run it and get a receipt (run_job), compare two
traces (bisect, first_fault), prove one checkpoint against a trace root (merkle_proof,
merkle_verify), commit to a fingerprint before revealing it (commitment,
check_reveal), and settle (accept, slash).
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tdcc-exact-core")
except PackageNotFoundError:     # a source checkout that was never installed
    __version__ = "0.0.0"

from .commit import check_reveal, commitment
from .dispute import Divergence, Fault, bisect, first_fault
from .oracle import Job, Receipt, Run, new_job, run_job
from .settle import Settlement, accept, slash
from .trace import Checkpoint, TraceLog, merkle_proof, merkle_root, merkle_verify

__all__ = [
    "__version__",
    "Job", "Receipt", "Run", "new_job", "run_job",
    "TraceLog", "Checkpoint", "merkle_root", "merkle_proof", "merkle_verify",
    "bisect", "first_fault", "Divergence", "Fault",
    "commitment", "check_reveal",
    "accept", "slash", "Settlement",
]
