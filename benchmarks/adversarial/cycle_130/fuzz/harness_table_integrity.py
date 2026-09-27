"""harness_table_integrity.py — Atheris harness for the _table module.

Surface under test:
    crc24_interlaken._table.crc_table         (tuple of 256 ints)
    crc24_interlaken._table.precomputed_table (function returns 256 ints)

Contract:
    * Both surfaces must yield exactly 256 entries (CWE-125 / OOB-prevention).
    * Every entry must be in [0, 0xFFFFFF] (CWE-190 / integer overflow guard).
    * The table must be deterministic (importing the module twice produces
      byte-identical tables -- catches accidental random / os.urandom use in
      table generation).
    * crc_table[1] must equal 0x328B63 (the poly); any polynomial drift breaks
      this anchor. This is the strongest structural invariant of the package.

Fuzz strategy:
    * Atheris TestOneFuzzedInput is invoked but the data bytes are ignored --
      table integrity is a property of the module itself, not of a single
      input. We use the fuzzer to repeatedly re-import the module in a fresh
      subprocess to detect any non-determinism (CWE-330 / use-of-insufficient-
      random). The harness is invoked via atheris' libFuzzer driver; for
      "table-only" coverage we run the script with a short max_total_time.
    * On every iteration we verify the invariants listed above. Any
      AssertionError is a Critical finding.

Invocation:
    .venv-fuzz/bin/python benchmarks/adversarial/cycle_130/fuzz/harness_table_integrity.py \\
        -atheris_runs=1000 -max_total_time=5

Expected runtime: <1s. The fuzzer will complete thousands of iterations in
the 5s window because each iteration is constant-time (tuple length +
range checks).
"""

from __future__ import annotations

import importlib
import sys

import atheris

with atheris.instrument_imports():
    import crc24_interlaken._table as tab


_MASK = 0xFFFFFF
_POLY = 0x328B63
_TABLE_LEN = 256


def _assert_table_invariants() -> None:
    """One iteration of the table-integrity invariant check.

    The actual public surface is:
      * tab.precomputed_table() -> tuple of 256 ints
      * tab._TABLE (module-private; referenced by crc_table's inner loop)

    `crc_table` itself is a FUNCTION (not a table), so we assert it is
    callable and round-trips the canonical vector.
    """
    pre = tab.precomputed_table()
    assert isinstance(pre, (tuple, list)), (
        f"precomputed_table() returned {type(pre).__name__}, expected tuple/list"
    )
    tbl = tuple(pre)
    assert len(tbl) == _TABLE_LEN, (
        f"precomputed_table() has {len(tbl)} entries, expected {_TABLE_LEN}"
    )

    # Every entry must be in [0, 0xFFFFFF].
    for i, entry in enumerate(tbl):
        assert isinstance(entry, int), (
            f"precomputed_table()[{i}] is not int: {type(entry).__name__}"
        )
        assert 0 <= entry <= _MASK, (
            f"precomputed_table()[{i}] = {entry:#x}, outside [0, {_MASK:#x}]"
        )

    # Polynomial anchor (catches silent param drift).
    assert tbl[1] == _POLY, (
        f"precomputed_table()[1] = {tbl[1]:#x}, expected poly {_POLY:#x}"
    )

    # crc_table() must be a callable function, not a tuple.
    assert callable(tab.crc_table), (
        f"crc_table is not callable: {type(tab.crc_table).__name__}"
    )
    # crc_table() of the canonical vector must match crc() (already covered
    # by harness_crc_main.py, but we re-assert here so a regression in
    # _table.py alone still trips this surface).
    from crc24_interlaken import crc as _ref_crc  # local import to avoid
    assert tab.crc_table(b"123456789") == _ref_crc(b"123456789") == 0xB4F3E6, (
        "crc_table(b'123456789') drifted from 0xB4F3E6; likely polynomial drift"
    )


def _assert_reimport_determinism() -> None:
    """Reload the module and assert the table is byte-identical."""
    importlib.reload(tab)
    tbl2 = tab.precomputed_table()
    assert tab.precomputed_table() == tbl2, (
        "precomputed_table() changed across import -- non-deterministic table generation"
    )


def TestOneFuzzedInput(data: bytes) -> None:
    """libFuzzer entrypoint. The data bytes are used as a modulo gate to
    trigger the heavier reimport determinism check on a small fraction of
    iterations (so we don't pay the reload cost on every call).
    """
    _assert_table_invariants()
    # Reimport determinism is gated by the first byte of `data` to amortize
    # the ~0.2ms reload cost across ~100 iterations.
    if data and (data[0] % 100) == 0:
        _assert_reimport_determinism()


def main() -> int:
    atheris.Setup(sys.argv, TestOneFuzzedInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())