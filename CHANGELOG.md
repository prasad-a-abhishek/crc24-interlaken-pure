# Changelog

All notable changes to `crc24-interlaken` are documented in this file.

## [0.1.0] — 2026-09-27 (cycle_130)

Initial release.

### Added
- **`crc(data: bytes) -> int`** — bitwise CRC-24/Interlaken reference (non-reflected, MSB-first). Locked parameters: poly=0x328B63, init=0xFFFFFF, xorout=0xFFFFFF. 25 LOC implementation, auditable line-for-line against the RevEng pseudocode.
- **`crc_table(data) -> int`** — table-driven fast path (~9× faster on 64 KB inputs; ~18 MB/s on CPython 3.11). Regenerated from the polynomial on every import, so parameters cannot drift from the bitwise reference.
- **`precomputed_table()`** — exposes the 256-entry table for tests and benchmarks.
- **CLI** via `python3 -m crc24_interlaken`: `--data HEX [HEX ...]`, `--self-test` (runs 6 RevEng-canonical vectors), `--version`. Also installed as the `crc24-interlaken` console-script entrypoint.
- **Tests** (1662 pytest items): 370 in `tests/test_crc.py` (canonical, byte_range, length_sweep, determinism, type_errors, oracle_differential, edge); 1283 in `tests/test_table.py` (table integrity, 1000 random cross-checks, 24-bit boundary, type contract, 1 MB performance smoke); 9 in `tests/test_cli.py` (subprocess CLI forms).
- **Benchmark suite** at `benchmarks/run_benchmark.py` + `benchmarks/BENCHMARK.md` — 10 workload profiles × 5 iterations, mean / P95 / peak RSS, written by `run_benchmark.py` itself (1-click reproducible).
- **6-section README** following Invariant 16: Title+BADGES / Quick Start / Performance & Benchmarks / Why crc24-interlaken? / Features & API / License.
- **`pyproject.toml`** with `dependencies = []`, `[project.scripts]` entrypoint, `setuptools.build_meta` backend.
- **`SPEC.md`** (9 sections, 12 LOCKED Acceptance Criteria) — the contract for this release.
- **`seed_evidence.json`** — 5 RevEng-canonical vectors used by the build.
- **`LICENSE`** — MIT.

### Verified
- AC1: `crc(b"123456789") == 0xB4F3E6` (RevEng canonical check value).
- AC2–AC5: zero-length and single-byte vectors match RevEng.
- AC7: residue `0x144E63` confirmed (pre-xorout state after processing data+check).
- AC11: oracle-differential agreement with the bitwise reference on 1000 random inputs.
- All 1662 pytest items pass in 0.25 s on CPython 3.11.15 / Linux aarch64.

### Notes
- This is a pure-Python implementation. Performance is bounded by CPython's per-byte interpreter overhead (~2 MB/s bitwise, ~18 MB/s table-driven). Users who need higher throughput should `pip install crcmod` *with the explicit poly form* (`0x1328B63`, not the RevEng 22-bit form) and verify the output against the vectors in this README before substituting — RevEng's 22-bit form and the explicit 24-bit form are mathematically the same polynomial but encode it differently.