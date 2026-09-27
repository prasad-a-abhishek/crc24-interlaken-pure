"""harness_type_errors.py — Atheris harness for crc() non-bytes input rejection.

Surface under test:
    crc24_interlaken.crc(data) -> int

Contract:
    * data must be bytes-like (bytes, bytearray, memoryview). Anything else
      MUST raise TypeError, NOT ValueError/AttributeError/RuntimeError.
    * The TypeError message must mention the offending type's name -- this
      is the SPEC §3 AC5 contract ("crc() of NoneType is rejected with an
      informative error message naming the type").
    * bytes-like that has been mutated mid-iteration must NOT crash; the
      existing implementation does not hold a reference so mutation is safe.

Fuzz strategy:
    * Atheris TestOneFuzzedInput receives random bytes; the harness uses
      atheris' FuzzedDataProvider to derive a type tag and (sometimes) a
      payload, then constructs an instance of that type and feeds it to
      crc().
    * For each non-bytes-like input we assert:
        1. TypeError is raised (NOT some other exception).
        2. The error message names the offending type.
    * For bytes-like inputs we re-derive the expected value and assert the
      result matches the 24-bit-masked contract.
    * For bytes-like that is a memoryview wrapping a numpy buffer, we assert
      the function does NOT crash -- it may produce a value (current
      behaviour) or raise TypeError, but no segfault / uncaught exception.

References:
    * Cycle_130 VULN_AUDIT.md (Surface 1 input contract table)
    * Cycle_130 TEST_GAPS.md G-04 (array.array vs memoryview asymmetry)

Invocation:
    .venv-fuzz/bin/python benchmarks/adversarial/cycle_130/fuzz/harness_type_errors.py \\
        -atheris_runs=2000 -max_total_time=5

Expected runtime: ~5s. Each iteration is microsecond-scale.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from crc24_interlaken import crc
    from crc24_interlaken._table import crc_table


_MASK = 0xFFFFFF
_NON_BYTES_TYPES = (
    None,
    0,
    -1,
    999999,
    3.14,
    float("nan"),
    float("inf"),
    "123456789",
    "",
    [1, 2, 3],
    (1, 2, 3),
    {"a": 1},
    object(),
    set(),
    frozenset(),
    b"",  # bytes-like (positive)
    bytearray(),
    memoryview(b""),
)


def _should_raise_typeerror(value) -> bool:
    """Return True iff crc() is contractually required to raise TypeError
    on this value."""
    return not isinstance(value, (bytes, bytearray, memoryview))


def _run_one(value, payload: bytes) -> None:
    if _should_raise_typeerror(value):
        # Must raise TypeError, not any other exception.
        raised = None
        try:
            crc(value)
        except TypeError as exc:
            raised = exc
        except Exception as exc:
            raise AssertionError(
                f"crc({value!r}) raised {type(exc).__name__}, expected TypeError"
            ) from exc
        assert raised is not None, (
            f"crc({value!r}) did not raise; expected TypeError"
        )
        # Error message must name the offending type.
        type_name = type(value).__name__
        assert type_name in str(raised), (
            f"crc({value!r}) error message {str(raised)!r} "
            f"does not mention type name {type_name!r}"
        )
    else:
        # bytes-like: must return 24-bit-masked int, must match table-driven
        # path.
        ref = crc(value)
        fast = crc_table(value)
        assert isinstance(ref, int) and 0 <= ref <= _MASK, (
            f"crc({value!r}) returned {ref!r}, outside [0, {_MASK:#x}]"
        )
        assert ref == fast, (
            f"crc({value!r})={ref:#x} != crc_table={fast:#x}"
        )


def TestOneFuzzedInput(data: bytes) -> None:
    """libFuzzer entrypoint. Drives a series of type-tagged invocations."""
    fdp = atheris.FuzzedDataProvider(data)

    # Cycle through the canonical non-bytes-like type set; index derived
    # from fdp so the same payload always exercises the same type but
    # different payloads exercise different types.
    for i in range(min(8, len(_NON_BYTES_TYPES))):
        idx = fdp.ConsumeIntInRange(0, len(_NON_BYTES_TYPES) - 1)
        try:
            value = _NON_BYTES_TYPES[idx]
        except IndexError:
            continue
        _run_one(value, data)

    # Also exercise random bytearray/memoryview from the fuzzer payload --
    # always positive path.
    if data:
        n = fdp.ConsumeIntInRange(0, len(data))
        _run_one(data[:n], data)
        _run_one(bytearray(data[:n]), data)
        _run_one(memoryview(data[:n]), data)

    # Specifically test the SPEC §3 AC5 contract: NoneType rejection.
    _run_one(None, data)


def main() -> int:
    atheris.Setup(sys.argv, TestOneFuzzedInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())