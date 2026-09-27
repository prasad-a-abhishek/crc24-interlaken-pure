# TEST_GAPS — Adversarial test-coverage gaps in the 1662-test baseline

Cycle: 130
Repo: crc24-interlaken-pure (HEAD 5cf0a97)
Baseline: 1662 pytest items passing
  - tests/test_crc.py: 370
  - tests/test_table.py: 1283
  - tests/test_cli.py: 9

This file lists the **adversarial** test categories that the QA report
("1662/1662 pytest pass") does NOT cover. These are the gaps that an
attacker could exploit; every gap below is graded on whether it represents
a real risk to the package's threat model.

Each gap is:
- **G-XX** — gap ID
- **Risk** — High / Medium / Low / Info
- **Why a gap** — what's missing in the current 1662 items
- **Why it matters / doesn't matter** — whether the missing coverage is a
  real concern or a documentation artefact
- **Suggested test** — how to close the gap if/when workstream T3 builds a
  fuzzing harness

## G-01: `crc()` on memoryview with multi-byte stride / non-'B' format

**Risk:** Low.
**Why a gap:** The current tests cover `crc(bytes)`, `crc(bytearray)`,
`crc(memoryview(bytes))`. They do NOT cover `crc(memoryview(array.array('I')))`
(4-byte ints viewed as bytes) or `crc(memoryview(numpy.int16))` (2-byte
ints viewed as bytes).
**Why it matters:** if a future caller passes such a memoryview, the
package will silently treat the underlying bytes as if they were uint8s.
The output CRC will still be a 24-bit value, but it will not correspond
to the "obvious" interpretation. This is **not** a security issue (CRC is
not a parser), but it could surprise users who expect `bytes` semantics.
**Suggested test:** add a parametrized test that constructs a
memoryview over a 16-bit or 32-bit array and asserts the CRC equals
the CRC of the same bytes after `.tobytes()`.

## G-02: `crc()` on bytes-like objects implementing `__index__` but not buffer protocol

**Risk:** Info.
**Why a gap:** `int` does not implement the buffer protocol, so `crc(int)`
raises TypeError. But Python objects that implement `__index__` (like
`int`) or `__bytes__` (like a hypothetical `MyBytes`-like class) are NOT
accepted — the `isinstance` guard is intentionally narrow.
**Why it matters:** the package author chose to accept ONLY the three
types in the SPEC §3 AC12 contract. This is a **deliberate** design
choice, not a bug. The gap is that we have no test that asserts a
`__bytes__`-implementing class is rejected; if a future contributor widens
the guard, no test would fail.
**Suggested test:** a single negative assertion: `class FakeBytes:
__bytes__ = lambda self: b"123456789"; crc(FakeBytes())` must raise
TypeError.

## G-03: `crc()` and `crc_table()` parity on bytearray mutation during iteration

**Risk:** Info.
**Why a gap:** Python's `for byte in data:` on a `bytearray` reads each
byte via the iterator; if a caller mutates the bytearray during iteration,
CPython's behaviour depends on the iterator implementation.
**Why it matters:** neither the tests nor the package's design thread a
mutation hazard. `bytearray` iteration in CPython snapshots the length
on iter start, so mid-iteration mutation is undefined behaviour. The
package does NOT lock against it. This is a normal Python caveat, not a
package-specific issue.
**Suggested test:** mark as documented non-guarantee in SPEC §6; no test
needed.

## G-04: `crc()` on `array.array('B', ...)` is rejected (intentional)

**Risk:** Info.
**Why a gap:** SPEC §3 AC12 lists `bytes`, `bytearray`, `memoryview`. The
package's `isinstance` check matches exactly that. `array.array('B', ...)`
is NOT bytes-like per CPython's class hierarchy, so it is rejected with
TypeError — but a `memoryview(array.array('B', ...))` IS accepted.
**Why it matters:** the asymmetry is correct (memoryview is the buffer
protocol primitive), but no test documents it. If a future refactor adds
`array.array` to the `isinstance` tuple, the package would silently
accept an `array.array('I', ...)` of 32-bit ints — which would be a
**real** bug.
**Suggested test:** add `assert crc(array.array("B", [1,2,3])) raises
TypeError` (negative) and `assert crc(memoryview(array.array("B", [1,2,3])))`
matches `crc(bytes(array.array("B", [1,2,3])))` (positive).

## G-05: CLI `--data` token-length boundary at 3+ characters

**Risk:** Info (the boundary is enforced; the test is missing).
**Why a gap:** `tests/test_cli.py::test_cli_data_invalid_hex_token_returns_nonzero`
asserts that `zz` is rejected. But there is no test that `12345` (5 chars)
is rejected with the specific message "each --data token must be 1 or 2 hex
digits" — the message text is the lockable behaviour.
**Why it matters:** the rejection logic IS in the code (`__main__.py:71`
`if len(t) == 0 or len(t) > 2`), but if a future refactor changes the
error message wording, no test will catch a regression.
**Suggested test:** add `assert "1 or 2 hex digits" in result.stderr` to
the `12345` case.

## G-06: 100 MB random input regression

**Risk:** Low.
**Why a gap:** `tests/test_table.py::test_one_megabyte_input_completes_quickly`
asserts 1 MB completes in < 5 s. There is no test for 10 MB or 100 MB
inputs. The CLI does not expose `--input-file`, so this would only matter
for the Python API path.
**Why it matters:** if a future refactor introduces O(n^2) behaviour, the
1 MB test would catch it (1 MB at 1 GB/s × 1000× = 1000 s = way over the
budget). So the existing test is sufficient as a regression guard; the
gap is only about documenting the upper-bound behaviour.
**Suggested test:** leave as-is; the 1 MB test is the regression guard.

## G-07: Concurrent / multi-thread invocation of `crc()` and `crc_table()`

**Risk:** Info.
**Why a gap:** no test spawns two threads calling `crc()` on the same
input simultaneously.
**Why it matters:** the algorithm is stateless (each call to `crc(data)`
reinitialises `_INIT` locally and returns), so concurrent calls are
trivially safe. The gap is only documentation — there is no assertion that
"threading does not corrupt the result".
**Suggested test:** not necessary. The stateful surfaces are module-level
constants (`_TABLE`) and are read-only after `_build_table()` returns.

## G-08: Empty `memoryview` (zero-length) parity with empty `bytes`

**Risk:** Info.
**Why a gap:** `tests/test_crc.py` has `test_bytearray_input` and
`test_memoryview_input` for `b"123456789"`. There is no explicit
`crc(memoryview(b""))` test — only `crc(b"") == 0x000000`.
**Why it matters:** `crc(memoryview(b""))` should return `0x000000`. If a
future refactor special-cases `len(data) == 0` in a way that doesn't
handle `memoryview`, this would silently drift.
**Suggested test:** add `assert crc(memoryview(b"")) == 0x000000` and
`assert crc_table(memoryview(b"")) == 0x000000`.

## G-09: CLI `--data` argv length limit (OS-dependent)

**Risk:** Info.
**Why a gap:** `argparse(nargs='+')` will accept up to ~`ARG_MAX` tokens
(~2 MB on Linux). A caller could try to CRC 10 MB by passing 10 million
tokens; this would either fail at the shell level (E2BIG) or be truncated.
**Why it matters:** the package's design choice is "callers CRC large
inputs in Python, not via the CLI". The CLI is a convenience for short
inputs. Not a security issue — just an undocumented limit.
**Suggested test:** document the limit in README or SPEC §6; no test
needed.

## G-10: UnicodeDecodeError / locale-related pitfalls in CLI error messages

**Risk:** Info.
**Why a gap:** CLI error messages use `f"... got {tok!r}"` which produces
a repr. On non-UTF-8 terminals, `tok` could contain non-ASCII bytes; but
since the input is hex tokens, this is bounded.
**Why it matters:** irrelevant. Hex tokens are ASCII.

## Summary

| Gap ID | Risk | Mitigation priority |
|--------|------|---------------------|
| G-01   | Low   | T3 fuzz harness should add 1 parametrized memoryview test |
| G-02   | Info  | Add 1 negative test in test_crc.py::TestTypeErrors |
| G-03   | Info  | Document in SPEC §6 (already documented as non-goal) |
| G-04   | Info  | Add 2 tests (positive memoryview + negative array.array) |
| G-05   | Info  | Add 1 assertion to test_cli.py |
| G-06   | Low   | Existing 1 MB test is sufficient regression guard |
| G-07   | Info  | Not necessary; algorithm is stateless |
| G-08   | Info  | Add 2 assertions (memoryview empty) to test_crc.py / test_table.py |
| G-09   | Info  | Document; no test needed |
| G-10   | Info  | Not relevant (hex tokens are ASCII) |

**Total:** 10 gaps, 0 High, 0 Medium, 2 Low, 8 Info.

The 1662-test baseline is **strong** — it covers all 12 LOCKED Acceptance
Criteria + 1000 random table-vs-bitwise equivalences + the full CLI
contract + 1 MB performance smoke. The remaining gaps are documentation
purity, not security.

VERDICT: TEST_GAPS — coverage is adequate for the threat model; remaining
gaps are documentation-tier.