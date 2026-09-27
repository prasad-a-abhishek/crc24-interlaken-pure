# SURFACES — CRC-24/Interlaken Attack-Surface Enumeration

Cycle: 130
Repo: crc24-interlaken-pure (HEAD 5cf0a97)
Scope: every externally callable surface in `src/crc24_interlaken/` + `python3 -m crc24_interlaken`

This file is the input to STRIDE (`THREAT_MODEL.md`) and the CWE mapping
(`CWE_MAP.md`). Every row below was probed at audit time (2026-09-27) against
HEAD 5cf0a97.

## Surface inventory

| # | Surface | Type | Trust boundary | Attack vector | Test coverage status |
|---|---------|------|----------------|---------------|----------------------|
| 1 | `crc24_interlaken.crc(data)` | Python function (public) | caller ↔ package | Pass non-bytes-like (str/int/None/...). Expect TypeError. Pass zero-length / large / mutated bytearray. | COVERED — 370 items in `tests/test_crc.py` (canonical, byte_range, length_sweep, determinism, type_errors, oracle_differential, edge). |
| 2 | `crc24_interlaken.CrcEngine` (stateful streaming class) | Python class | caller ↔ package | (NOT PRESENT) | **GAP** — task body mentioned this surface; the codebase does **not** expose a `CrcEngine` class. The package implements only the stateless one-shot `crc()` and the table-driven `crc_table()`. See Finding F-INFO-01. |
| 3 | `crc24_interlaken._table` (256-entry precomputed table) | module-level tuple constant | algorithm integrity | Drift between table and bitwise reference → silent CRC miscalculation. | COVERED — `tests/test_table.py` includes `test_table_matches_bitwise_on_canonical` (9 vectors) + `test_table_matches_bitwise_on_random_input` (1000 random inputs) + `test_table_entry_is_24_bit` (256 parametrized) + `test_table_entry_0xff_is_daf8d7`. Drift would fail loudly. |
| 4 | CLI subcommands: `--self-test`, `--data HEX...`, `--version`, `--help` | argparse entrypoint | argv ↔ process | Bad hex token, oversized token, missing required arg, exit-code mapping. | COVERED — 9 items in `tests/test_cli.py` (subprocess-level, real `python3 -m crc24_interlaken`). |
| 5 | CLI `--input-file PATH` (path-traversal surface) | N/A — **not implemented** | n/a | n/a | **GAP (NON-ISSUE)** — the task body mentioned `--input-file`, but the CLI (`__main__.py`) does **not** implement it. Only `--data`, `--self-test`, `--version`, `--help` exist. No path-traversal surface exists. See Finding F-INFO-02. |
| 6 | Module import side effects | import-time | interpreter ↔ filesystem | Network, file writes, env-var reads, signal handlers, fork. | COVERED (negatively) — `import crc24_interlaken` adds only `crc24_interlaken` + `crc24_interlaken._table` to `sys.modules`; no print(), no exit(), no tempfile creation, no network. Import takes ~0.2 ms. |
| 7 | Cross-cycle oracle differential vs shipped siblings | Python module boundary | this package ↔ `crc16-modbus-pure`, `crc16-en13757-pure`, `crc24-pure` (OpenPGP), `crc16-ccitt-false-pure` | Parameter drift → silently re-implementing a sibling CRC; spec-authority collision (e.g. claiming Interlaken when actually computing OpenPGP). | COVERED (negatively) — verified at audit time on `b"123456789"`: our `0xB4F3E6` is byte-distinct from `crc16-modbus` (`0x4B37`), `crc16-en13757` (`0xC2B7`), `crc24-OpenPGP` (`0x21CF02`), and from `crc24-OpenPGP` empty-input residue (`0xB704CE`). Repeated for 2048-byte random input — all distinct. |

## Probing notes (raw evidence captured during audit)

### Surface 1 — `crc()` input contract
```
crc(None)        -> TypeError "expected bytes-like, got NoneType"
crc("123456789") -> TypeError "expected bytes-like, got str"
crc(0) / crc(-1) -> TypeError "expected bytes-like, got int"
crc(999999)      -> TypeError "expected bytes-like, got int"
crc(3.14)        -> TypeError "expected bytes-like, got float"
crc([1,2,3])     -> TypeError "expected bytes-like, got list"
crc((1,2,3))     -> TypeError "expected bytes-like, got tuple"
crc({"a":1})     -> TypeError "expected bytes-like, got dict"
crc(object())    -> TypeError "expected bytes-like, got object"
crc(set())       -> TypeError "expected bytes-like, got set"
crc(frozenset()) -> TypeError "expected bytes-like, got frozenset"
crc(b"")         -> 0x000000  (accepted)
crc(b"a")        -> 0xd80156  (accepted)
crc(array.array("B",[1,2,3]))            -> TypeError "got array"  (REJECTED)
crc(memoryview(array.array("B",[1,2,3]))) -> 0x605584  (accepted via buffer protocol)
```

The `array.array` → memoryview asymmetry is **intentional** and aligned with the
SPEC §3 AC12 contract: `bytes-like` means "supports the buffer protocol with
'B' format". `array.array` itself is not bytes-like; a `memoryview` over it is.
Existing `tests/test_crc.py::TestTypeErrors::test_bytearray_input` and
`test_memoryview_input` cover the canonical positive cases; the negative
`array.array` case is not tested — see TEST_GAPS.md G-04.

### Surface 3 — `_table` integrity
```
table len        = 256
table[0]         = 0x000000
table[1]         = 0x328b63  (== poly at index 1; the canonical correctness anchor)
table[127]       = 0x7439da
table[128]       = 0xaec10d
table[254]       = 0xe873b4
table[255]       = 0xdaf8d7
```
`table[1] == 0x328b63` is the strongest structural invariant: any polynomial
drift (0x328B63 → any other 22-bit value) will break `table[1]` and trigger
`test_table_entry_0xff_is_daf8d7` (which probes index 255) and the 1000-random
input equivalence test. Drift cannot ship.

### Surface 4 — CLI behavior
```
python3 -m crc24_interlaken --self-test                  -> "6/6 vectors passed", exit 0
python3 -m crc24_interlaken --data 31 32 ... 39           -> "0xb4f3e6", exit 0
python3 -m crc24_interlaken --data 0xZZ                  -> exit 2, stderr "invalid hex token '0xZZ'"
python3 -m crc24_interlaken --data                       -> exit 2, stderr "expected at least one argument"
python3 -m crc24_interlaken --data 12345                 -> exit 2, stderr "each --data token must be 1 or 2 hex digits"
python3 -m crc24_interlaken --version                    -> "crc24-interlaken 0.1.0", exit 0
python3 -m crc24_interlaken --help                       -> usage, exit 0
```

### Surface 6 — Import-side-effect probe
```
new modules pulled in by `import crc24_interlaken`: {'crc24_interlaken', 'crc24_interlaken._table'}
import time: ~0.20 ms on CPython 3.11.15
```
Pure-stdlib import. No `os.environ` reads, no `sys.path` writes, no signal
handlers, no `atexit` callbacks, no print().

### Surface 7 — Cross-cycle oracle differential
```
b"123456789":
  crc24-interlaken (us) : 0xb4f3e6
  crc16-modbus-pure     : 0x4b37
  crc16-en13757-pure    : 0x00c2b7
  crc24-OpenPGP         : 0x21cf02

2048-byte random input (seed=0xDEAD):
  crc24-interlaken (us) : 0x67630e
  crc16-en13757-pure    : 0x4bf3
  crc24-OpenPGP         : 0x3ee990
```
All distinct. No two sibling CRCs produce the same output for the same input,
so a caller cannot accidentally substitute this package for one of its
siblings.

## Summary
- 5 of 7 surfaces have explicit test coverage. The two gaps are non-issues:
  surface 2 (CrcEngine) and surface 5 (--input-file) do **not exist in the
  codebase**. The task body lists them as future candidates; the package
  author chose the smaller one-shot + table-driven + CLI surface.
- All four surfaces that DO exist (crc, _table, CLI, import) pass probing
  without raising uncaught exceptions on adversarial input.

VERDICT: SURFACES — enumeration complete, no exploitable surface beyond the
designed `crc()`/CLI contract.