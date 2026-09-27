"""crc24-interlaken CLI entrypoint.

Run as::

    python3 -m crc24_interlaken --data <hex bytes>
    python3 -m crc24_interlaken --self-test
    python3 -m crc24_interlaken --version

Examples
--------
    $ python3 -m crc24_interlaken --data 31 32 33 34 35 36 37 38 39
    0xb4f3e6

    $ python3 -m crc24_interlaken --self-test
    6/6 vectors passed
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, crc


# 6 canonical RevEng vectors. The 5 in seed_evidence.json plus the
# 10-byte ascending range vector from SPEC §3 AC6. The CLI prints
# "6/6 vectors passed" on success -- this is the spec-mandated
# headline number for the testbench engineer to grep for.
_SELF_TEST_VECTORS = (
    # (label, input bytes, expected CRC)
    ("zero-length",       b"",                  0x000000),
    ("single 0x00",       b"\x00",              0xDAF828),
    ("single 0x01",       b"\x01",              0xE8734B),
    ("single 0xff",       b"\xff",              0x0000FF),
    ("10-byte ascending", bytes(range(10)),    0xDDCBC6),
    ("ASCII '123456789'", b"123456789",        0xB4F3E6),
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crc24-interlaken",
        description="Compute CRC-24/Interlaken (poly=0x328B63, init=0xFFFFFF, xorout=0xFFFFFF) of input bytes.",
    )
    p.add_argument(
        "--data",
        nargs="+",
        metavar="BYTE",
        help="Input bytes as 1- or 2-digit hex tokens (e.g. '31 32 33 34 35 36 37 38 39').",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Run the bundled RevEng-canonical test vectors and print a summary line.",
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="Print 'crc24-interlaken <version>' and exit.",
    )
    return p


def _parse_hex_tokens(tokens) -> bytes:
    """Parse a list of hex strings into bytes. Supports 1- or 2-digit hex tokens."""
    out = bytearray()
    for tok in tokens:
        # tolerate '0x' prefix and any whitespace
        t = tok.lower().removeprefix("0x")
        if len(t) == 0 or len(t) > 2:
            raise ValueError(f"each --data token must be 1 or 2 hex digits, got {tok!r}")
        try:
            out.append(int(t, 16))
        except ValueError as exc:
            raise ValueError(f"invalid hex token {tok!r}") from exc
    return bytes(out)


def _run_self_test() -> int:
    """Run bundled vectors. Returns 0 on success, 1 on any mismatch."""
    passed = 0
    total = 0
    for label, data, expected in _SELF_TEST_VECTORS:
        total += 1
        actual = crc(data)
        if actual != expected:
            print(
                f"FAIL {label}: expected 0x{expected:06x}, got 0x{actual:06x}",
                file=sys.stderr,
            )
            continue
        passed += 1
    if passed == total:
        print(f"{passed}/{total} vectors passed")
        return 0
    print(f"{passed}/{total} vectors passed", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"crc24-interlaken {__version__}")
        return 0

    if args.self_test:
        return _run_self_test()

    if not args.data:
        parser.print_usage(sys.stderr)
        print(
            "crc24-interlaken: error: one of --data, --self-test, or --version is required",
            file=sys.stderr,
        )
        return 2

    try:
        data = _parse_hex_tokens(args.data)
    except ValueError as exc:
        print(f"crc24-interlaken: error: {exc}", file=sys.stderr)
        return 2

    print(f"0x{crc(data):06x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())