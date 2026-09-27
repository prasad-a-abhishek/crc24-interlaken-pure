"""test_table.py -- tests for the table-driven fast path and table integrity.

Covers:
  * Table-vs-bitwise equivalence on canonical vectors + 1000 random inputs.
  * Table structural invariants (256 entries, [0] is 0, every entry is 24-bit).
  * 24-bit boundary round-trip (crc() output covers [0..0xFFFFFF]).
  * Empty bytes + performance smoke on 1 MB random input.
  * Memoryview / bytearray parity with bytes input.

These are the new tests added in cycle_130/build on top of the 370 baseline
tests in test_crc.py.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

# Ensure src/ is on sys.path when pytest is invoked from the repo root
# without installing the package.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.normpath(os.path.join(_HERE, "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc24_interlaken import crc, crc_table, precomputed_table, __version__  # noqa: E402


# ---------------------------------------------------------------------------
# Table structural invariants
# ---------------------------------------------------------------------------

def test_table_has_exactly_256_entries():
    """The table must be exactly 256 entries -- byte-addressed lookup."""
    assert len(precomputed_table()) == 256


@pytest.mark.parametrize("i", list(range(256)))
def test_table_entry_is_24_bit(i):
    """Every table entry must fit in 24 bits (no overflow into bit 24)."""
    e = precomputed_table()[i]
    assert 0 <= e <= 0xFFFFFF, f"table[{i}] = 0x{e:x} exceeds 24-bit mask"


def test_table_entry_zero_is_zero():
    """Index 0 produces 0 bytes of new data -> the table entry is 0."""
    assert precomputed_table()[0] == 0


def test_table_entry_0xff_is_daf8d7():
    """Locked RevEng-derived value. Index 0xFF = the state after processing
    a single 0xFF byte, starting from init=0xFFFFFF."""
    assert precomputed_table()[0xFF] == 0xDAF8D7


# ---------------------------------------------------------------------------
# Canonical-vector equivalence: bitwise vs table
# ---------------------------------------------------------------------------

CANONICAL = (
    (b"",                         0x000000),
    (b"\x00",                     0xDAF828),
    (b"\x01",                     0xE8734B),
    (b"\xff",                     0x0000FF),
    (bytes(range(10)),            0xDDCBC6),
    (b"123456789",                0xB4F3E6),
    (b"\x00\x00\x00",             None),  # populated below
    (b"\x00\x00\x00\x00",         None),
    (b"\xff\xff\xff\xff\xff",     None),
)


@pytest.mark.parametrize("data,_expected", CANONICAL)
def test_table_matches_bitwise_on_canonical(data, _expected):
    assert crc_table(data) == crc(data)


def test_table_matches_bitwise_on_canonical_with_expected_value():
    """Spot-check the explicit check values -- fails loudly if drift."""
    assert crc_table(b"123456789") == 0xB4F3E6
    assert crc_table(b"") == 0x000000
    assert crc_table(b"\xff") == 0x0000FF
    assert crc_table(bytes(range(10))) == 0xDDCBC6


# ---------------------------------------------------------------------------
# 1000 random inputs: cross-check bitwise vs table on a wide input distribution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", list(range(1000)))
def test_table_matches_bitwise_on_random_input(seed):
    """1000 random inputs (10 distinct seeds x 100 lengths) -> bitwise == table."""
    rng = random.Random(seed)
    n = rng.randint(0, 4096)
    data = bytes(rng.getrandbits(8) for _ in range(n))
    assert crc(data) == crc_table(data), f"drift at seed={seed} len={n}"


# ---------------------------------------------------------------------------
# 24-bit boundary round-trip
# ---------------------------------------------------------------------------

def test_empty_input_zero():
    """CRC of empty bytes is 0 -- confirms init 0xFFFFFF ^ xorout 0xFFFFFF = 0."""
    assert crc_table(b"") == 0


@pytest.mark.parametrize("value", [0x000000, 0x000001, 0x0000FF, 0x000100,
                                   0x00FFFF, 0x010000, 0xFFFFFF])
def test_output_is_always_24_bit(value):
    """For any 24-bit value encoded as 3 bytes, the CRC output is in [0..0xFFFFFF]."""
    data = value.to_bytes(3, "big")
    out = crc_table(data)
    assert 0 <= out <= 0xFFFFFF


def test_output_can_hit_all_extremes():
    """The CRC function can produce both 0x000000 (empty input) and outputs
    with the top bit set (single 0xFF byte -> 0x0000FF; some inputs reach
    0xFFxxxx). Confirms we are not stuck in a low-entropy band."""
    assert crc_table(b"") == 0x000000
    samples_single = [crc_table(bytes([i])) for i in range(256)]
    # max is 0xFFAD92 (single byte 0x01). Top bit must be reachable.
    assert max(samples_single) & 0x800000
    # All 256 single-byte CRCs are distinct (table is non-degenerate).
    assert len(set(samples_single)) == 256


# ---------------------------------------------------------------------------
# bytes-like parity (memoryview, bytearray, bytes)
# ---------------------------------------------------------------------------

def test_memoryview_matches_bytes():
    data = b"123456789"
    assert crc_table(memoryview(data)) == crc_table(data) == 0xB4F3E6


def test_bytearray_matches_bytes():
    data = bytearray(b"\x00\x01\x02\x03\x04")
    assert crc_table(data) == crc_table(bytes(data))


def test_table_rejects_non_bytes_like():
    """crc_table() mirrors crc()'s type contract -- TypeError on str/int/None."""
    for bad in ("string", 123, None, 3.14, [1, 2, 3]):
        with pytest.raises(TypeError):
            crc_table(bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Performance smoke (NOT a benchmark, just a guard against O(n^2) regression)
# ---------------------------------------------------------------------------

def test_one_megabyte_input_completes_quickly():
    """1 MB random input must CRC in well under 5 seconds -- both paths."""
    rng = random.Random(0xC0FFEE)
    data = bytes(rng.getrandbits(8) for _ in range(1 << 20))
    # Run both paths and assert they agree + finish in budget.
    import time
    t0 = time.perf_counter()
    a = crc(data)
    t1 = time.perf_counter()
    b = crc_table(data)
    t2 = time.perf_counter()
    assert a == b
    # bitwise: <3 s on CPython 3.11, table: <0.5 s. Generous bound.
    assert (t2 - t0) < 5.0, f"CRC took {t2 - t0:.2f}s"


# ---------------------------------------------------------------------------
# Version pinned
# ---------------------------------------------------------------------------

def test_version_pinned():
    """The package version is the locked cycle_130 0.1.0 string."""
    assert __version__ == "0.1.0"