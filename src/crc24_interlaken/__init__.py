"""crc24-interlaken -- pure-Python CRC-24/Interlaken reference implementation."""

__version__ = "0.1.0"

_WIDTH = 24
_POLY = 0x328B63
_INIT = 0xFFFFFF
_XOROUT = 0xFFFFFF
_MASK = (1 << _WIDTH) - 1  # 0xFFFFFF


def crc(data) -> int:
    """Compute CRC-24/Interlaken of *data* (non-reflected).

    Returns an integer in [0, 0xFFFFFF].

    Args:
        data: bytes-like object (bytes, bytearray, memoryview).

    Raises:
        TypeError: if *data* is not a bytes-like type.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like (bytes, bytearray, memoryview), "
            f"got {type(data).__name__}"
        )
    crc = _INIT
    for byte in data:
        crc ^= byte << (_WIDTH - 8)
        for _ in range(8):
            if crc & (1 << (_WIDTH - 1)):
                crc = ((crc << 1) ^ _POLY) & _MASK
            else:
                crc = (crc << 1) & _MASK
    return crc ^ _XOROUT
