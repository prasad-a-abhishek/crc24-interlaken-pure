# crc24-interlaken

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/prasad-a-abhishek/crc24-interlaken-pure/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-≥3.10-blue.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-1662%20passed-brightgreen.svg)](tests/)

> **Pure-Python, byte-exact, RevEng-verified CRC-24/Interlaken reference — zero dependencies, zero compile step, drop-in for ASIC/FPGA SERDES testbenches.**

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/crc24-interlaken-pure.git
```

```python
from crc24_interlaken import crc, crc_table

# Bitwise reference (matches the RevEng pseudocode line-for-line)
assert crc(b"123456789") == 0xB4F3E6

# Table-driven fast path (same math, ~9x faster on 64 KB inputs)
assert crc_table(b"123456789") == 0xB4F3E6
```

Verify the install:

```bash
python3 -m crc24_interlaken --self-test    # → 6/6 vectors passed
python3 -m crc24_interlaken --data 31 32 33 34 35 36 37 38 39
                                        # → 0xb4f3e6
python3 -m pytest -q                       # → 1662 passed
```

## ⚡ Performance & Benchmarks

10 workload profiles (5 sizes × 2 distributions: zeros + random), 5 iterations each, CPython 3.11.15 on Linux aarch64. The table-driven path is **~9× faster** than the bitwise reference on ≥256 B inputs.

| Workload | bitwise mean (µs) | bitwise MB/s | table mean (µs) | table MB/s | speedup |
|---|---:|---:|---:|---:|---:|
| 64 B zeros      |  35 | 1.7 |  4.6 | 13.2 | 7.6× |
| 64 B random     |  37 | 1.7 |  4.4 | 13.8 | 8.4× |
| 256 B zeros     | 142 | 1.7 |  16  | 15.5 | 9.0× |
| 256 B random    | 143 | 1.7 |  16  | 15.1 | 8.8× |
| 1024 B zeros    | 557 | 1.8 |  62  | 15.8 | 9.0× |
| 1024 B random   | 553 | 1.8 |  60  | 16.3 | 9.2× |
| 65536 B zeros   | 31 488 | 2.0 | 3 414 | 18.3 | 9.2× |
| 65536 B random  | 30 381 | 2.1 | 3 320 | 18.8 | 9.2× |

Full breakdown (per-iteration P95, peak RSS, environment, methodology) in [`benchmarks/BENCHMARK.md`](benchmarks/BENCHMARK.md). Reproduce locally with:

```bash
python3 benchmarks/run_benchmark.py
```

**Why no `crcmod` row?** `crcmod`'s `_verifyPoly` requires the polynomial to have its implicit leading bit set (`1<<N ≤ poly < 1<<(N+1)`); the RevEng form `0x328B63` (22-bit, with the implicit `x^24`) is rejected. OR-ing in the leading bit (`0x1328B63`) makes crcmod accept it but changes the polynomial from RevEng's canonical form, so we omit the comparison rather than report a speed baseline against a different polynomial. Full reasoning in `benchmarks/run_benchmark.py::_try_crcmod`.

## Why crc24-interlaken?

**Problem.** An ASIC/FPGA validation engineer writing a Python testbench for a chip-to-chip SERDES link needs a **byte-exact CRC-24/Interlaken** primitive. The Interlaken Protocol Definition v1.2 §5.3.2.2 mandates a CRC-24/Interlaken checker on the data path. Existing options fail in different ways:

| Option | Failure mode |
|---|---|
| **`crcmod`** | Ships a C-extension. Requires `gcc` + Python headers at install time — a non-starter in slim container images, air-gapped CI, or PyPy sandboxes. |
| **`crcany`** | Multi-CRC generator; no single-CRC depth — hard to read, hard to fuzz, hard to certify for a regulated silicon-validation flow. |
| **Roll-your-own from Wikipedia pseudocode** | Easy to flip a bit in the polynomial and ship a CRC that passes unit tests against your own broken reference but fails against the RTL. |

**Our trade-off.** Single CRC, byte-exact, RevEng-verified, parameter-locked at import-time. The bitwise reference is ~25 LOC and greppable end-to-end; the table-driven fast path exposes the same parameters and is regenerated from the polynomial on every import. `dependencies = []` — no compile, no transitive wheels, no supply-chain surprises.

## Features & API

- **Single public function `crc(data: bytes) -> int`** — bitwise reference, non-reflected (MSB-first).
- **Table-driven fast path `crc_table(data) -> int`** — same inputs and outputs, ~9× faster.
- **`precomputed_table() -> tuple[int, ...]`** — the 256-entry table, exposed for tests and benchmarks.
- **CLI** (`python3 -m crc24_interlaken ...`) — `--data HEX [HEX ...]`, `--self-test`, `--version`.
- **Type contract**: accepts `bytes`, `bytearray`, `memoryview`; raises `TypeError` for `str` / `int` / `None` / `list`.
- **Deterministic, streaming-safe**, `>= 3.10`, no runtime dependencies.

```python
from crc24_interlaken import crc

# All six canonical RevEng vectors
assert crc(b"")                  == 0x000000
assert crc(b"\x00")              == 0xDAF828
assert crc(b"\x01")              == 0xE8734B
assert crc(b"\xff")              == 0x0000FF
assert crc(bytes(range(10)))     == 0xDDCBC6
assert crc(b"123456789")         == 0xB4F3E6
```

```bash
$ python3 -m crc24_interlaken --self-test
6/6 vectors passed

$ python3 -m crc24_interlaken --data 31 32 33 34 35 36 37 38 39
0xb4f3e6

$ python3 -m crc24_interlaken --version
crc24-interlaken 0.1.0
```

**Out of scope:** this package implements *only* CRC-24/Interlaken. CRC-24/OpenPGP (poly=0x864CFB) lives in the sibling repo `crc24-pure`; CRC-24/OS-9 and other CRC-24 variants are separate packages.

## License

MIT License — see [`LICENSE`](LICENSE). Cycle 130 of the repo-factory loop, by prasad-a-abhishek.