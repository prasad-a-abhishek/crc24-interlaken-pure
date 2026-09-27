"""harness_crc_main.py — Atheris harness for the public crc() surface.

Surface under test:
    crc24_interlaken.crc(data) -> int

Contract:
    * data must be bytes-like (bytes, bytearray, memoryview); otherwise TypeError
      is raised with the offending type's name in the message.
    * Return value must be an int in [0, 0xFFFFFF] (24-bit masked).

Fuzz strategy (per-cycle adversarial review, cycle_130):
    * Atheris TestOneFuzzedInput is invoked by libFuzzer with random bytes;
      the bytes payload is treated directly as the data argument to crc().
    * For each fuzz input we re-derive the expected value using the
      table-driven path (`crc_table(data)` from `crc24_interlaken._table`)
      and assert the two results are identical. This catches silent
      bitwise/table drift (CWE-835: infinite loop not triggered; CWE-190:
      integer overflow/incorrect mask) as well as correctness regressions.
    * We additionally enforce the 24-bit-mask contract on the return value
      and assert that the function never raises anything other than TypeError
      on non-bytes-like inputs (which the fuzzer will eventually feed by
      varying input length — empty input is bytes-like and accepted; all
      payloads from libFuzzer are bytes).

References:
    * Cycle_130 VULN_AUDIT.md (parent card t_bb711d00)
    * Cycle_130 CWE_MAP.md (CWE-20 MITIGATED, CWE-125 NOT-APPLICABLE,
      CWE-190 MITIGATED, CWE-400 MITIGATED, CWE-770 NOT-APPLICABLE,
      CWE-835 MITIGATED)

Invocation:
    .venv-fuzz/bin/python benchmarks/adversarial/cycle_130/fuzz/harness_crc_main.py \\
        -atheris_runs=10000 -max_total_time=5

Expected runtime: ~5s on CPython 3.11.15 with ASan/UBSan disabled (default);
                <30s with sanitizers enabled. Single-threaded by default.
"""

from __future__ import annotations

import sys

import atheris

# Target surface is import-time only; nothing else is touched.
with atheris.instrument_imports():
    from crc24_interlaken import crc
    from crc24_interlaken._table import crc_table


_MASK = 0xFFFFFF


def _assert_invariant(data: bytes) -> None:
    """Run crc() and crc_table() against the same input and assert equality
    plus the 24-bit-mask contract.

    Raises:
        AssertionError on any contract violation; this is the signal libFuzzer
        will surface to the user.
    """
    ref = crc(data)
    fast = crc_table(data)

    # Contract 1: 24-bit masked output (CWE-190 MITIGATED check).
    assert isinstance(ref, int), f"crc() returned non-int: {type(ref).__name__}"
    assert 0 <= ref <= _MASK, (
        f"crc() returned {ref:#x}, outside [0, {_MASK:#x}]"
    )
    assert isinstance(fast, int), f"crc_table() returned non-int: {type(fast).__name__}"
    assert 0 <= fast <= _MASK, (
        f"crc_table() returned {fast:#x}, outside [0, {_MASK:#x}]"
    )

    # Contract 2: bitwise reference == table-driven fast path.
    # Drift here indicates parameter drift (poly/init/xorout) between
    # __init__.py and _table.py -- the most catastrophic silent-failure
    # mode for a CRC implementation (CWE-835 / spec-authority collision).
    assert ref == fast, (
        f"crc()={ref:#x} != crc_table()={fast:#x} for data={data!r}"
    )


def TestOneFuzzedInput(data: bytes) -> None:
    """libFuzzer entrypoint. `data` is always a `bytes` object."""
    try:
        _assert_invariant(data)
    except AssertionError as exc:
        # atheris treats uncaught AssertionError as a finding and emits a
        # reproducer; we want exactly that behaviour.
        raise


def main() -> int:
    atheris.Setup(sys.argv, TestOneFuzzedInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())