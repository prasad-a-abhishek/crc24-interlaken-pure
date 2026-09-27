"""crc24_interlaken._table -- 256-entry precomputed table for CRC-24/Interlaken.

This module exposes a table-driven fast path that is mathematically equivalent
to the bitwise reference in ``crc24_interlaken.crc``. The table is generated
once at import time from the locked CRC-24/Interlaken parameters:

    width  = 24
    poly   = 0x328B63
    init   = 0xFFFFFF
    refIn  = False
    refOut = False
    xorOut = 0xFFFFFF

The constants are duplicated here intentionally -- importing them from
``__init__`` would create a circular import. Any change to the CRC
parameters requires editing *both* this file and ``__init__.py``; the
self-test in ``tests/test_table.py`` cross-checks the two paths on every
test run.

The non-reflected (MSB-first) table-driven form is::

    for byte in data:
        crc = ((crc << 8) ^ TABLE[((crc >> 16) ^ byte) & 0xFF]) & 0xFFFFFF

This matches the standard reference: for each index i in [0..255],
TABLE[i] is the result of starting with ``i << 16`` and iterating 8 bit
clock steps (XOR with poly when MSB is set, shift left otherwise). The
resulting 24-bit word is what ``crc`` would hold if the only byte ever
processed were the index i.

The table is regenerated from the polynomial on every import, so the
parameters cannot drift from the bitwise reference: change one and both
paths will fail self-test. ``precomputed_table()`` returns the live tuple;
``crc_table(data)`` is the fast-path function.
"""

_WIDTH = 24
_POLY = 0x328B63
_MASK = (1 << _WIDTH) - 1  # 0xFFFFFF

_TABLE_SIZE = 256
_TOP_SHIFT = _WIDTH - 8           # 16 -- position where the next input byte is XORed
_MSBMASK = 1 << (_WIDTH - 1)      # 0x800000


def _build_table():
    """Generate the 256-entry table for non-reflected CRC-24/Interlaken."""
    table = [0] * _TABLE_SIZE
    for i in range(_TABLE_SIZE):
        crc = i << _TOP_SHIFT
        for _ in range(8):
            if crc & _MSBMASK:
                crc = ((crc << 1) ^ _POLY) & _MASK
            else:
                crc = (crc << 1) & _MASK
        table[i] = crc
    return tuple(table)


_TABLE = _build_table()


def precomputed_table():
    """Return the 256-entry precomputed table as a tuple of ints.

    Exposed so tests and benchmarks can assert the exact table contents
    (entry 0 must be 0; entry 0xFF is the CRC of a single 0xFF byte
    after the XOR-with-init step is folded in).
    """
    return _TABLE


def crc_table(data) -> int:
    """Table-driven CRC-24/Interlaken of *data* (non-reflected).

    Mathematically equivalent to :func:`crc24_interlaken.crc` -- same init
    (``0xFFFFFF``), same xorout (``0xFFFFFF``), same bit ordering. Used as a
    fast path on platforms where the bitwise inner loop is too slow (e.g.
    PyPy or large streaming workloads).

    Args:
        data: bytes-like object (bytes, bytearray, memoryview).

    Returns:
        int in [0, 0xFFFFFF].

    Raises:
        TypeError: if *data* is not a bytes-like type.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc_table() expected bytes-like (bytes, bytearray, memoryview), "
            f"got {type(data).__name__}"
        )
    crc = 0xFFFFFF
    for byte in data:
        crc = ((crc << 8) ^ _TABLE[((crc >> _TOP_SHIFT) ^ byte) & 0xFF]) & _MASK
    return crc ^ 0xFFFFFF


__all__ = ["precomputed_table", "crc_table"]