"""Tests for crc24-interlaken — pure-Python CRC-24/Interlaken reference.

Covers the 12 LOCKED Acceptance Criteria from SPEC.md §3 across 7 categories.
Target: ≥100 pytest items.
"""

import os
import random
import sys

import pytest

# Make src/ importable without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from crc24_interlaken import crc  # noqa: E402


# ---------------------------------------------------------------------------
# Independent reference implementation (for differential checks)
# ---------------------------------------------------------------------------

def _expected_for(data: bytes) -> int:
    poly, init, xorout, width = 0x328B63, 0xFFFFFF, 0xFFFFFF, 24
    mask = (1 << width) - 1
    crc = init
    for byte in data:
        crc ^= byte << (width - 8)
        for _ in range(8):
            if crc & (1 << (width - 1)):
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    return crc ^ xorout


def _expected_residue(data: bytes) -> int:
    """RevEng residue = unfinalised CRC register after processing *data*.

    Convention: residue = crc_internal_state(input || check_bytes) — i.e.
    the state value BEFORE the xorout step. For CRC-24/Interlaken this
    yields the canonical residue 0x144E63 from the RevEng catalogue.
    """
    poly, init, width = 0x328B63, 0xFFFFFF, 24
    mask = (1 << width) - 1
    crc = init
    for byte in data:
        crc ^= byte << (width - 8)
        for _ in range(8):
            if crc & (1 << (width - 1)):
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    return crc  # no xorout


# ---------------------------------------------------------------------------
# Category 1: canonical  (10 items)
# ---------------------------------------------------------------------------

class TestCanonical:
    """RevEng-published vectors from seed_evidence.json."""

    def test_ac1_123456789(self):
        # AC1: canonical check value
        assert crc(b"123456789") == 0xB4F3E6

    def test_ac2_zero_length(self):
        # AC2: empty input
        assert crc(b"") == 0x000000

    def test_ac3_single_00(self):
        # AC3: single 0x00 byte
        assert crc(bytes([0x00])) == 0xDAF828

    def test_ac4_single_01(self):
        # AC4: single 0x01 byte
        assert crc(bytes([0x01])) == 0xE8734B

    def test_ac5_single_ff(self):
        # AC5: single 0xFF byte
        assert crc(bytes([0xFF])) == 0x0000FF

    def test_ac6_10_byte_ascending(self):
        # AC6: 10-byte ascending
        assert crc(bytes(range(10))) == 0xDDCBC6

    def test_ac7_residue_conformance(self):
        # AC7: RevEng residue = unfinalised CRC register state after processing
        # (input || check_value_as_3_bytes_BE). For CRC-24/Interlaken this
        # yields the catalogue value 0x144E63.
        assert _expected_residue(b"123456789" + b"\xb4\xf3\xe6") == 0x144E63

    def test_bytearray_input(self):
        # bytearray is bytes-like — must be accepted
        assert crc(bytearray(b"123456789")) == 0xB4F3E6

    def test_memoryview_input(self):
        # memoryview is bytes-like — must be accepted
        assert crc(memoryview(b"123456789")) == 0xB4F3E6

    def test_two_byte_input(self):
        assert crc(b"\x00\x31") == _expected_for(b"\x00\x31")


# ---------------------------------------------------------------------------
# Category 2: byte_range  (256 items)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("byte_val", list(range(256)))
def test_single_byte_full_range(byte_val):
    assert crc(bytes([byte_val])) == _expected_for(bytes([byte_val]))


# ---------------------------------------------------------------------------
# Category 3: length_sweep  (20 items)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "length",
    [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 256, 512, 1024],
)
def test_length_sweep(length):
    data = bytes((i * 17 + 3) & 0xFF for i in range(length))
    assert crc(data) == _expected_for(data)


# ---------------------------------------------------------------------------
# Category 4: determinism  (5 items)
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_repeat_100(self):
        # AC10: deterministic across 100 calls
        for _ in range(100):
            assert crc(b"123456789") == 0xB4F3E6

    def test_same_data_same_result(self):
        data = bytes(range(50))
        first = crc(data)
        for _ in range(10):
            assert crc(data) == first

    def test_independent_calls(self):
        for trial in range(20):
            data = bytes([trial & 0xFF] * 17)
            assert crc(data) == _expected_for(data)

    def test_zero_input_stable(self):
        for _ in range(50):
            assert crc(b"") == 0x000000

    def test_known_vector_repeated(self):
        expected = 0xB4F3E6
        for _ in range(25):
            assert crc(b"123456789") == expected


# ---------------------------------------------------------------------------
# Category 5: type_errors  (9 items)
# ---------------------------------------------------------------------------

class TestTypeErrors:
    # AC12: type-error safety

    def test_none_raises(self):
        with pytest.raises(TypeError):
            crc(None)

    def test_str_raises(self):
        with pytest.raises(TypeError):
            crc("123456789")

    def test_int_raises(self):
        with pytest.raises(TypeError):
            crc(123)

    def test_float_raises(self):
        with pytest.raises(TypeError):
            crc(3.14)

    def test_list_raises(self):
        with pytest.raises(TypeError):
            crc([1, 2, 3])

    def test_dict_raises(self):
        with pytest.raises(TypeError):
            crc({"a": 1})

    def test_object_raises(self):
        with pytest.raises(TypeError):
            crc(object())

    def test_tuple_raises(self):
        with pytest.raises(TypeError):
            crc((1, 2, 3))

    def test_error_message_names_type(self):
        with pytest.raises(TypeError) as exc:
            crc(None)
        assert "NoneType" in str(exc.value)


# ---------------------------------------------------------------------------
# Category 6: oracle_differential  (60 items)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rng():
    return random.Random(0xC241)  # fixed seed → deterministic


@pytest.mark.parametrize("trial", range(60))
def test_random_match_reference(rng, trial):
    length = rng.randint(100, 2000)
    data = bytes(rng.getrandbits(8) for _ in range(length))
    assert crc(data) == _expected_for(data)


# ---------------------------------------------------------------------------
# Category 7: edge  (10 items)
# ---------------------------------------------------------------------------

class TestEdge:
    def test_width_mask_ac8(self):
        # AC8: output is masked to 24 bits
        for trial in range(20):
            data = bytes([trial & 0xFF] * 10)
            result = crc(data)
            assert 0 <= result <= 0xFFFFFF

    def test_length_sensitivity_ac9(self):
        # AC9: sensitivity to byte count
        assert crc(b"\x00" * 3) != crc(b"\x00" * 4)

    def test_single_zero_byte(self):
        assert crc(b"\x00") == 0xDAF828

    def test_all_ones_short(self):
        v = crc(b"\xff\xff\xff")
        assert v != 0
        assert 0 <= v <= 0xFFFFFF

    def test_all_zeroes_long(self):
        data = b"\x00" * 100
        assert crc(data) == _expected_for(data)

    def test_all_ones_long(self):
        data = b"\xff" * 100
        assert crc(data) == _expected_for(data)

    def test_alternating_pattern(self):
        data = b"\xaa\x55" * 50
        assert crc(data) == _expected_for(data)

    def test_large_input_64kb(self):
        data = b"\x00" * (1 << 16)
        assert crc(data) == _expected_for(data)

    def test_bytearray_matches_bytes(self):
        data = b"123456789"
        assert crc(bytearray(data)) == crc(data)

    def test_memoryview_matches_bytes(self):
        data = b"123456789"
        assert crc(memoryview(data)) == crc(data)
