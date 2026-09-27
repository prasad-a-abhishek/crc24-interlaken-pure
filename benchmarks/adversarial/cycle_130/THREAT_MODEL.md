# THREAT_MODEL — STRIDE analysis for crc24-interlaken-pure

Cycle: 130
Repo: crc24-interlaken-pure (HEAD 5cf0a97)
Scope: STRIDE classification of all 7 surfaces enumerated in `SURFACES.md`.
STRIDE = Spoofing, Tampering, Repudiation, Information disclosure, Denial
of service, Elevation of privilege.

This analysis assumes the package is used as documented: a Python library
called from a testbench, with no untrusted network input. STRIDE still
applies — each category is evaluated against the package's own invariants.

## Spoofing

**Surface 1 (`crc`):** not applicable. The function takes bytes and returns
an int. No identity, no caller authentication, no token issuance. A caller
cannot impersonate another caller of `crc()` because `crc()` does not
remember its callers.

**Surface 3 (`_table`):** the table is the algorithm. If a future
contributor tampered with `src/crc24_interlaken/_table.py::_POLY` (e.g.
changed it from `0x328B63` to `0xED2B63`), the package would silently
compute a **different CRC** while still claiming "CRC-24/Interlaken".
This would be a spoofing attack against the protocol authority
(RevEng + Interlaken v1.2). Mitigated by:
- `tests/test_table.py::test_table_entry_0xff_is_daf8d7` — locks the
  table[255] value; any polynomial drift changes this.
- `tests/test_table.py::test_table_matches_bitwise_on_random_input` —
  1000 random bitwise-vs-table equivalences; bitwise uses `__init__.py`
  constants; any drift between the two would fail this test.
- Cross-cycle oracle check (Surface 7) at audit time confirmed our
  `0xB4F3E6` is byte-distinct from every shipped sibling.

**Surface 4 (CLI):** no caller authentication. Anyone who can run the
binary can ask "what's the CRC of bytes X". This is the documented
behaviour, not a vulnerability.

**Verdict:** Spoofing is mitigated by the cross-check between bitwise
reference and table, plus the locked RevEng check value `0xB4F3E6`.

## Tampering

**Surface 1 (`crc`):** `crc(data)` does not mutate `data` (it iterates
over a `bytes` which is immutable; `bytearray`/`memoryview` are read in
the `for byte in data:` form which yields ints, not writes). Audit-time
probing: `data = bytearray(b"..."); crc(data); assert data == bytearray(b"...")`
→ passed.

**Surface 3 (`_table`):** the table is a `tuple` (immutable). The
`_build_table()` function is called once at import. No runtime mutation
is possible.

**Surface 4 (CLI):** the CLI does not write to any file. Stdout receives
the CRC, stderr receives error messages. No log file, no temp file.

**Surface 6 (import side effects):** `import crc24_interlaken` does not
write to disk, does not register signal handlers, does not fork. Verified
by `sys.modules` diff: only `crc24_interlaken` + `crc24_interlaken._table`
are added.

**Verdict:** Tampering is **not applicable** — the package is a pure
function with no persistent state and no side effects.

## Repudiation

**Surface 1 (`crc`):** not applicable. The function has no logging, no
audit trail, no identity assertion. A caller cannot "deny" having called
`crc()` because there is nothing to deny — the function does not record
calls.

**Surface 4 (CLI):** same — the CLI prints "0xABCD..." to stdout and
nothing else. There is no signed receipt, no nonce, no log line.

**Verdict:** Repudiation is not applicable. If a user needs an audit
trail, they must construct one in their own code (e.g. log the input +
output pair to a file). The package does not promise this.

## Information disclosure

**Surface 1 (`crc`):** the function returns a 24-bit integer. The
function does not return or expose the input bytes; it does not log the
input. Information flow is one-way: bytes in, int out.

**Surface 4 (CLI):** on parse error, the CLI echoes the offending token
in the error message (e.g. `invalid hex token '0xZZ'`). This is a
**controlled** echo of 1-2 characters of user input — not a disclosure
of any sensitive data, since the token is what the user just typed on
the command line.

**Verdict:** information disclosure is not applicable — the package
does not receive sensitive data and does not echo or persist it.

## Denial of service

**Surface 1 (`crc`):** runtime is O(n) with small constant; probed at
100 MB / 49 s on CPython 3.11.15. No amplification, no exponential
backoff. A caller can intentionally trigger 49 s of CPU by passing 100 MB,
but this is the documented behaviour, not a DoS.

**Surface 4 (CLI):** the CLI accepts an arbitrary number of `--data`
tokens via `argparse(nargs='+')`. A caller could exhaust `ARG_MAX`
(~2 MB on Linux) by passing millions of 1-char tokens. The result is
either an `E2BIG` shell error or a successful CRC of up to ~2 MB of
data. The CLI does NOT provide `--input-file`, so a 100 GB DoS via file
read is impossible.

**Surface 3 (`_table`):** `_build_table()` runs at import and takes
~0.2 ms. Not a DoS vector.

**Verdict:** DoS is bounded by the caller's choice of input size. No
amplification primitive exists. Mitigated by the CLI's lack of
`--input-file`.

## Elevation of privilege

**Surface 1, 3:** not applicable — Python functions cannot escalate
privileges beyond what the calling process has.

**Surface 4 (CLI):** the CLI runs with the user's privileges. It does
not call `setuid`, `seteuid`, `sudo`, `os.setresuid`, or any equivalent.
It does not open a network port, does not bind a socket, does not exec
a subprocess. There is no elevation path.

**Surface 6 (import):** `import crc24_interlaken` does not call any
`os`/`subprocess`/`ctypes` module. Verified at audit time: only
`crc24_interlaken` and `crc24_interlaken._table` are added to
`sys.modules` on import.

**Verdict:** Elevation is not applicable — the package has no path to
escalate privileges, and no surface where a low-privilege caller could
cause a high-privilege action.

## STRIDE summary table

| Category | Applicable? | Mitigation / Note |
|----------|-------------|-------------------|
| Spoofing | Yes (algorithm-identity) | Cross-check bitwise vs table + locked RevEng check value |
| Tampering | No | Pure function, immutable inputs |
| Repudiation | No | No audit trail exists or is needed |
| Info disclosure | No | One-way data flow; no sensitive input |
| DoS | Bounded by caller input | O(n) algorithm; no `--input-file`; ~ARG_MAX CLI ceiling |
| Elevation | No | No subprocess / network / setuid |

## Threat-model conclusion

The package is a **stateless CRC primitive**. STRIDE finds:
- 1 applicable category (Spoofing, mitigated by locked check value + cross-check)
- 1 bounded category (DoS, bounded by caller input)
- 4 not-applicable categories (Tampering, Repudiation, Info disclosure, Elevation)

No High-severity threats. No Medium-severity threats. The implementation
matches the SPEC threat model: a minimal, auditable, byte-exact CRC
calculator for use in testbenches where trust comes from reading the 25
lines of source and matching it against the RevEng catalogue entry.

VERDICT: THREAT_MODEL — STRIDE passes; Spoofing is the only real concern,
and it is mitigated by the test suite.