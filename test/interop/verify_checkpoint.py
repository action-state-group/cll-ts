"""Verify a Go or TypeScript CLL checkpoint with the Python reference."""

import pathlib
import sys

from cll.checkpoint.cose_wire import verify_checkpoint_cose_offline


if len(sys.argv) != 2:
    raise SystemExit("usage: verify_checkpoint.py <checkpoint.cose>")

result = verify_checkpoint_cose_offline(pathlib.Path(sys.argv[1]).read_bytes())
if not result.ok:
    raise SystemExit(f"Python rejected checkpoint: {result.errors}")
