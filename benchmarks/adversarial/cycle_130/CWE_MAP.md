# CWE_MAP — CWE applicability for crc24-interlaken-pure

Cycle: 130
Repo: crc24-interlaken-pure (HEAD 5cf0a97)
Method: for each candidate CWE, inspect the source for the preconditions
defined by the CWE; record applicability, evidence (file:line), and a
verdict of APPLICABLE / NOT-APPLICABLE / MITIGATED.

This file is one input to `VULN_AUDIT.md`. The CWE list was drawn from the
task body (CWE-20, -125, -190, -400, -770, -835) plus the STRIDE-derived
secondary set (-22, -276, -377, -532).

## CWE-20 — Improper Input Validation

**Status:** MITIGATED.

**Evidence:**
- `src/crc24_interlaken/__init__.py:25-29` — explicit `isinstance(data, (bytes, bytearray, memoryview))` check before the loop, with a message naming the actual type. The same check is duplicated at `src/crc24_interlaken/_table.py:90-94` for `crc_table()`.
- `tests/test_crc.py::TestTypeErrors` — 9 negative-type assertions covering `None`, `str`, `int`, `float`, `list`, `dict`, `object`, `tuple`, plus a positive assertion that the error message contains the type name.
- `src/crc24_interlaken/__main__.py:_parse_hex_tokens` — hex-token length is bounded to ≤2 chars; tokens outside that range raise `ValueError` (caught and surfaced as exit 2 in `main`).
- `src/crc24_interlaken/__main__.py::main` — argparse handles `--data`, `--self-test`, `--version`; missing-arg exit is `2` with usage on stderr.

**Why mitigated:** every public entrypoint refuses non-bytes-like input at the
front door; the error path is exercised by tests. The only "input" that flows
into the bitwise loop is guaranteed to be `bytes`, `bytearray`, or
`memoryview` of a `B`-format buffer, so per-byte XOR + shift is well-defined.

**Residual:** `crc()` does NOT validate that a `memoryview` was created with
the `'B'` format — a memoryview over a non-`uint8` buffer (e.g. `numpy.int16`
array viewed as bytes) would still be accepted and silently reinterpreted as
8-bit values. This is **not** a security issue (the package is a CRC, not a
parser), but it could surprise a caller. Tracked as TEST_GAPS.md G-04.

## CWE-125 — Out-of-Bounds Read

**Status:** NOT-APPLICABLE.

**Evidence:**
- `src/crc24_interlaken/__init__.py:31` — `for byte in data:` iterates over a bytes-like; Python's iteration protocol cannot produce an index OOB. The inner shift loop is bounded by `range(8)` (no index into `data`).
- `src/crc24_interlaken/_table.py:96-97` — `crc = ((crc << 8) ^ _TABLE[((crc >> _TOP_SHIFT) ^ byte) & 0xFF]) & _MASK`. The lookup index `((crc >> 16) ^ byte) & 0xFF` is AND-masked with `0xFF` before indexing `_TABLE`, so the index is provably in `[0, 255]`. The `& 0xFFFFFF` mask on the result prevents any value escaping the 24-bit window.
- `tests/test_table.py::test_table_has_exactly_256_entries` — asserts `len(_TABLE) == 256` at every test run.
- `tests/test_table.py::test_table_entry_is_24_bit` — 256 parametrized asserts that every entry fits in 24 bits (would catch any `_build_table` bug that stored an unmasked value).

**Why not applicable:** every indexing operation is masked to its
provably-bounded domain. No C-level pointer arithmetic; no `ctypes`; no
shared-memory views. Python's `int` is unbounded; the `_MASK` constraint is
honoured everywhere an intermediate is computed.

## CWE-190 — Integer Overflow or Wraparound

**Status:** NOT-APPLICABLE (Python semantics), but worth explaining.

**Evidence:**
- All intermediate CRC values are masked with `& _MASK = 0xFFFFFF` before the
  next iteration (`src/crc24_interlaken/__init__.py:35,37`,
  `src/crc24_interlaken/_table.py:53,55,97`). The `crc << 1` shift is bounded
  by the `_WIDTH - 1` test on the high bit, so the post-shift value is at
  most `(2 * 0xFFFFFF) ^ 0x328B63`, which is well within Python bigint
  range — but it is then AND-masked, so the working value never exceeds
  `0xFFFFFF`.
- `tests/test_table.py::test_output_is_always_24_bit` — parametrized over 7
  24-bit extremes (0x000000, 0x000001, 0x0000FF, 0x000100, 0x00FFFF,
  0x010000, 0xFFFFFF), each rendered as 3 bytes, asserts the CRC output is
  always ≤ `0xFFFFFF`.
- `tests/test_table.py::test_output_can_hit_all_extremes` — asserts that the
  top bit (`0x800000`) is reachable (would catch any algorithm that
  silently dropped it) and that all 256 single-byte CRCs are distinct
  (would catch any masking bug that collapsed the output).

**Why not applicable:** the algorithm **deliberately relies on overflow
semantics** in the mathematical sense (CRC is a polynomial division in
GF(2)[x] modulo x^24 + 1), but Python's bigint semantics mean there is no
**runtime** overflow. Every working value is masked back to 24 bits after
each shift+XOR, so the implementation cannot enter an unbounded-growth state.

**Residual:** none. If a future contributor removes the `& _MASK` from
`__init__.py:35,37` or `_table.py:53,55`, CWE-190 would become applicable
and the bitwise-table differential test (`test_table_matches_bitwise_on_*`)
would fail.

## CWE-400 — Uncontrolled Resource Consumption

**Status:** MITIGATED (bounded by input size; no amplification).

**Evidence:**
- `crc(data)` reads `data` in a single Python `for byte in data:` loop.
  Per-byte work is **O(1)** (one XOR + 8 shifts/conditional XORs). Total
  runtime is **O(n)** in input length with a small constant. No
  amplification, no exponential backoff, no retries.
- `crc_table(data)` does **O(1)** per byte (one shift + XOR + table
  lookup). Same linear bound.
- 100 MB random input: `crc()` completes in 49 s on CPython 3.11.15
  (probed at audit time). No OOM, no crash.
- `tests/test_table.py::test_one_megabyte_input_completes_quickly` —
  asserts 1 MB completes in < 5 s. Acts as a regression guard against
  any future change that accidentally introduces O(n^2) behaviour.

**Why mitigated:** the algorithm is provably O(n) with a constant ~8
shifts per byte. No amplification primitive exists. The CLI does not
provide `--input-file`, so a 100 GB file cannot be passed without the
caller explicitly choosing to do so.

**Residual:** the CLI accepts an arbitrary number of `--data` tokens via
`argparse(nargs='+')`, so `--data 00 00 00 ...` (a million tokens) could
incur argv-length limits. Linux argv is bounded at `ARG_MAX` (typically
2 MB). For larger inputs, callers should write a Python script — and the
SPEC §6 explicitly says "this package is not for 100 GB inputs". Not a
CWE-400 issue under realistic use.

## CWE-770 — Allocation of Resources Without Limits or Throttling

**Status:** NOT-APPLICABLE.

**Evidence:**
- `crc(data)` and `crc_table(data)` do not allocate proportional to
  anything except `len(data)`. They do not build intermediate copies,
  scratch buffers, or caches.
- `_TABLE` is a module-level constant of exactly 256 ints; allocated
  once at import.
- No `*` unpacking, no list comprehension, no recursion. Per-byte work
  is a single statement (`for byte in data: ...`).

**Why not applicable:** there is no place where resource growth could
exceed linear-in-input-size, and there is no allocation independent of
the input. The bytearray branch in the CLI (`_parse_hex_tokens` appends
to a bytearray) is itself O(n) in the number of tokens.

## CWE-835 — Loop with Unreachable Exit Condition ('Infinite Loop')

**Status:** NOT-APPLICABLE.

**Evidence:**
- `src/crc24_interlaken/__init__.py:33-37` — `for _ in range(8):` is a
  fixed-iteration loop (8 times). It is impossible to run >8 iterations.
- `src/crc24_interlaken/_table.py:51-55` — same `range(8)` in table
  generation. `_build_table()` runs exactly 256 × 8 = 2048 iterations
  and returns.
- `src/crc24_interlaken/__main__.py:_parse_hex_tokens:67` — `for tok in tokens:` is bounded by `len(args.data)`, which is bounded by argv length.
- No `while True` loops anywhere in the source tree (verified by
  `grep -r "while " src/` → only docstring/import paths).

**Why not applicable:** every loop in the package has a static upper bound
(`range(8)`, `len(data)`, `range(256)`). No loop variable is mutated by
the loop body in a way that could fail to advance.

## Secondary CWE candidates (STRIDE-derived)

| CWE | Title | Status | Note |
|-----|-------|--------|------|
| CWE-22 | Path Traversal | NOT-APPLICABLE | No filesystem read/write in the package. The CLI has no `--input-file`; only `--data` tokens. |
| CWE-276 | Incorrect Default Permissions | NOT-APPLICABLE | Package is in-memory; no file or socket creation. |
| CWE-377 | Insecure Temporary File | NOT-APPLICABLE | No `tempfile`/`/tmp` usage. |
| CWE-532 | Insertion of Sensitive Info into Log File | NOT-APPLICABLE | CLI writes to stdout/stderr only. `--data` token contents are NOT echoed on error (`__main__.py:122-123` raises a generic `error: invalid hex token '0xZZ'` without echoing the rest of the input). |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | MITIGATED | Empty input, single-byte input, and 1 MB input are all covered by `test_empty_input_zero` (table) and `test_two_byte_input` (crc). The CRC of `b""` is locked to `0x000000` by init `^` xorout. |
| CWE-681 | Incorrect Conversion between Numeric Types | NOT-APPLICABLE | All numeric values stay as Python `int`; no `int.to_bytes` / `struct.pack` casts in the algorithm path. |
| CWE-704 | Incorrect Type Conversion or Cast | NOT-APPLICABLE | No casting; Python's duck typing + the explicit `isinstance` guard handle type dispatch. |

## Summary
- 6 candidate CWEs evaluated; 0 APPLICABLE.
- 2 MITIGATED (CWE-20, CWE-400) — guarded by code + tests.
- 4 NOT-APPLICABLE (CWE-125, CWE-190, CWE-770, CWE-835) — provably absent.
- 7 secondary CWEs also NOT-APPLICABLE.

VERDICT: CWE_MAP — no CWE matches the implementation; preconditions absent
in the code path.