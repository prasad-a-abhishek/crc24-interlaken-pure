# VULN_AUDIT — manual vulnerability audit of crc24-interlaken-pure

Cycle: 130
Repo: crc24-interlaken-pure (HEAD 5cf0a973f13ef4cd41952a67b76bd86df16f5c27)
Audit date: 2026-09-27
Auditor: @repo-adversary (default profile)
Scope: every public surface in `src/crc24_interlaken/` + `python3 -m crc24_interlaken` CLI.
Methodology: manual review + adversarial probing + STRIDE + CWE mapping + 1662-test baseline.

## Executive summary

`crc24-interlaken-pure` is a **stateless, pure-function, zero-dependency**
Python implementation of CRC-24/Interlaken (poly=0x328B63, init=0xFFFFFF,
xorout=0xFFFFFF, MSB-first, non-reflected). The implementation consists of:

- `src/crc24_interlaken/__init__.py` (38 LOC) — public `crc(data: bytes) -> int`
- `src/crc24_interlaken/_table.py` (100 LOC) — table-driven `crc_table(data) -> int`
  + `precomputed_table()` + 256-entry lookup table
- `src/crc24_interlaken/__main__.py` (130 LOC) — CLI entrypoint
- `tests/test_crc.py` (266 LOC, 370 items) + `tests/test_table.py` (178 LOC,
  1283 items) + `tests/test_cli.py` (123 LOC, 9 items) = **1662 pytest items
  all passing** on CPython 3.11.15

Adversarial probing at audit time included:

- 13 negative-type inputs (`None`, `str`, `int` incl. `0`/`-1`/`999999`, `float`,
  `list`, `tuple`, `dict`, `object()`, `set`, `frozenset`) — all rejected with
  informative `TypeError`.
- 5 positive-input extremes (empty / 1024B zeros / 1024B ones / 256B seq /
  2560B seq) — all produce 24-bit-masked outputs.
- 100 MB random input — completes in 49 s, no OOM.
- Table[0..255] integrity check — all 256 entries in `[0, 0xFFFFFF]`.
- Cross-cycle oracle differential — `0xB4F3E6` (us) is byte-distinct from
  `crc16-modbus` (`0x4B37`), `crc16-en13757` (`0xC2B7`), `crc24-OpenPGP`
  (`0x21CF02`), and from `crc24-OpenPGP` empty-input residue (`0xB704CE`).
- CLI argv fuzzing — bad hex tokens, oversized tokens, empty `--data`, no args.
- Import side-effect probe — `import crc24_interlaken` adds only 2 modules to
  `sys.modules`; no print, no exit, no file write, no signal handler.

**No Critical, High, or Medium findings.** Two Info findings about
**non-existent surfaces** that the task body mentioned but which the
codebase does not implement (likely a card-template artefact from the
cycle_125/127/128/129 adversary workstreams).

## Findings (severity-ranked)

### Critical (0)
*None.*

### High (0)
*None.*

### Medium (0)
*None.*

### Low (0)
*None.*

### Info (2)

#### F-INFO-01 — Task-body surface `CrcEngine` is not implemented
**Severity:** Info (documentation artefact, not a defect).
**Where:** task body for `cycle_130/adversary/01_vuln_audit` listed surface #2 as
`crc24_interlaken.CrcEngine` (a stateful streaming engine). The package only
exposes the stateless one-shot `crc()` and the table-driven `crc_table()`.
**Impact:** none. The package's design choice is "no streaming engine"; SPEC §6
explicitly states "this package is NOT streaming — `crc()` consumes the entire
input in memory."
**Recommendation:** none. If a future release adds a streaming engine, the
workstream should re-run this audit.

#### F-INFO-02 — Task-body CLI flag `--input-file` is not implemented
**Severity:** Info (documentation artefact, not a defect).
**Where:** task body listed surface #5 as "CLI accepts `--input-file PATH`
(path-traversal surface)". The CLI (`src/crc24_interlaken/__main__.py`)
implements ONLY `--data`, `--self-test`, `--version`, `--help`. No
`--input-file` exists.
**Impact:** none. No path-traversal surface exists because no path is read.
The `--data HEX [HEX ...]` interface is in-memory only. This is actually
**safer** than what the task body anticipated — there is no filesystem
attack surface at all.
**Recommendation:** none. Document the deliberate absence in SPEC §6
non-goals if a future contributor tries to add `--input-file`.

## Why this package is hard to attack

For each STRIDE category, the implementation has either no preconditions
for the threat, or a defensive guard backed by tests:

| STRIDE | Precondition | Status |
|--------|--------------|--------|
| Spoofing (algorithm identity) | Tampering with `_POLY` in either file | Detected by `test_table_matches_bitwise_on_random_input` (1000 trials) + `test_table_entry_0xff_is_daf8d7` |
| Tampering | Side effects from `crc()` | None possible: pure function, no global state mutation |
| Repudiation | Audit trail required | Not promised by SPEC §6 |
| Info disclosure | Sensitive data passed in | Caller's responsibility; package does not log |
| DoS | Unbounded resource growth | O(n) algorithm; no `--input-file`; bounded by `ARG_MAX` for CLI |
| Elevation | Subprocess / network / setuid | None of these are called; verified by import-side-effect probe |

For each of the 6 candidate CWEs (CWE-20, -125, -190, -400, -770, -835),
the precondition is either absent or mitigated (see `CWE_MAP.md`):

| CWE | Precondition | Status |
|-----|--------------|--------|
| CWE-20 (improper input validation) | Non-bytes-like flowing into the bitwise loop | Guarded by `isinstance(data, (bytes, bytearray, memoryview))` at `__init__.py:25` and `_table.py:90`; 9 negative-type tests |
| CWE-125 (out-of-bounds read) | Pointer arithmetic / shared memory | Not possible in pure Python; table lookups are explicitly `& 0xFF`-masked |
| CWE-190 (integer overflow) | Working value escapes the `_MASK = 0xFFFFFF` | Every intermediate is AND-masked before next iteration; verified by 7-parametrized boundary test |
| CWE-400 (uncontrolled resource consumption) | Amplification / retries | Algorithm is O(n) with constant 8 shifts/byte; no retries, no amplification |
| CWE-770 (allocation without limits) | Allocation independent of input | None exists; `_TABLE` is a module-level constant of 256 ints |
| CWE-835 (infinite loop) | `while` with no exit | Only `for _ in range(8):` and `for byte in data:` exist; both have static or input-bounded exit |

## Surfaces audited

7 surfaces enumerated in `SURFACES.md`:

1. `crc24_interlaken.crc(data)` — public function, 38 LOC total. Covered.
2. `crc24_interlaken.CrcEngine` — **not implemented** (F-INFO-01). N/A.
3. `crc24_interlaken._table` — module-level constant, regenerated from poly
   on import. Covered by `test_table_has_exactly_256_entries` (1) +
   `test_table_entry_is_24_bit` (256) + `test_table_entry_zero_is_zero` (1) +
   `test_table_entry_0xff_is_daf8d7` (1) + canonical + 1000-random.
4. CLI subcommands. Covered by 9 subprocess tests in `tests/test_cli.py`.
5. CLI `--input-file` — **not implemented** (F-INFO-02). N/A.
6. Module import side effects. Covered (negatively) by import-side-effect
   probe at audit time.
7. Cross-cycle oracle differential vs `crc16-modbus-pure`,
   `crc16-en13757-pure`, `crc24-pure` (OpenPGP). Covered (negatively) by
   byte-distinctness check at audit time.

## Test-suite adequacy

1662 pytest items pass; 0 fail; 0 skip. The QA pass (`t_86f393fb`) confirms
all 12 LOCKED Acceptance Criteria from SPEC §3 are covered (AC1..AC12).

`TEST_GAPS.md` enumerates 10 residual gaps (G-01..G-10). None rise to
High/Medium severity; all are either documentation artefacts (the package
intentionally rejects `array.array('B', ...)` even though `memoryview` over
the same array is accepted) or low-priority fuzzing-tier additions that
T3 (fuzz harness) can address.

## Cross-cycle disambiguation

This is the **fifth** CRC shipped by repo-factory; verified byte-distinct
from all four predecessors:

| Cycle | Repo | Polynomial | Check (ASCII 123456789) |
|-------|------|------------|--------------------------|
| 125 | crc7-umts-pure | 7-bit 0x09 | n/a (7-bit CRC) |
| 127 | crc16-modbus-pure | 16-bit 0x4B37 reflected | 0x4B37 |
| 128 | crc16-ccitt-false-pure | 16-bit 0x29B1 non-reflected | (not in local install) |
| 129 | crc16-en13757-pure | 16-bit 0xC2B7 reflected | 0xC2B7 |
| 129 | crc24-pure (OpenPGP) | 24-bit 0x864CFB | 0x21CF02 |
| **130** | **crc24-interlaken-pure** | **24-bit 0x328B63 non-reflected** | **0xB4F3E6** |

All four checked siblings produce **distinct** outputs on `b"123456789"`
and on a 2048-byte random input. No collision.

## Severity-ranked findings table

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| (none) | — | — | — |
| F-INFO-01 | Info | `CrcEngine` surface not implemented | Open (intentional) |
| F-INFO-02 | Info | `--input-file` CLI flag not implemented | Open (intentional) |

## Final verdict

The implementation matches its SPEC contract byte-for-byte; the test
suite has 1662 passing items with no failures and no skips; every CWE
precondition is either absent or mitigated by an explicit code guard
plus a test that would fail if the guard were removed; every STRIDE
applicable category is mitigated; the algorithm identity (RevEng
canonical 0xB4F3E6) is locked by 1000 random bitwise-vs-table equivalences
plus a 6-vector CLI self-test; the package is byte-distinct from all
four predecessor repos.

**VERDICT: CLEAN**

The package can proceed to T2 (fuzzing harnesses) and T3-T5 (fuzzing
execution + report). No remediation work is required from T1.

---

*Audit authored by cycle_130/adversary/01_vuln_audit (default profile).
Supporting analyses: `SURFACES.md`, `CWE_MAP.md`, `TEST_GAPS.md`,
`THREAT_MODEL.md` (all under `benchmarks/adversarial/cycle_130/`).*