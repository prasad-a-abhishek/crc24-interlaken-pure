# CRC-24/Interlaken — Discovery Specification (SPEC.md)

> **Cycle 130 / discoverer card.** This document is the contract for `crc24-interlaken-pure`.
> Build phase (`cycle_130/build`) inherits every Acceptance Criterion in §3 verbatim.

---

## §0 Discovery Audit

**Repository slug:** `crc24-interlaken-pure`
**PyPI package name:** `crc24-interlaken` (no `-pure` suffix on import; package metadata name omits it per repo-factory naming convention)

**`check_existing.py` output:**

```bash
python3 /root/.hermes/repo_factory/scripts/check_existing.py \
    --name crc24-interlaken \
    --concept "CRC-24/Interlaken polynomial 0x328B63 init 0xFFFFFF xorout 0xFFFFFF reflected" \
    --keywords ""
```

Output:

```
============================================================
NOVELTY & NON-EXISTENCE AUDIT: crc24-interlaken (CRC-24/Interlaken polynomial 0x328B63 init 0xFFFFFF xorout 0xFFFFFF reflected)
============================================================
1. Python Stdlib Check:   [PASS] No Python standard library collision.
2. Local Repo Check:       [PASS] No local project collision.
3. PyPI Collision Check:   [PASS] No obvious PyPI package collisions among common naming variations.
4. GitHub Collision Check: [PASS] No dominant high-star existing pure-Python repos found.
------------------------------------------------------------
FINAL VERDICT: APPROVED
============================================================
```

`exit 0` confirmed.

**Primary sources (3 HTTP-200, fetched 2026-09-27):**

1. **RevEng CRC Catalogue** — `https://reveng.sourceforge.io/crc-catalogue/all.htm`
   — `CRC-24/INTERLAKEN` entry: `width=24 poly=0x328b63 init=0xffffff refin=false refout=false xorout=0xffffff check=0xb4f3e6 residue=0x144e63`.
2. **Interlaken Protocol Definition v1.2** — `https://4b1b46.a2cdn1.secureserver.net/wp-content/uploads/2019/12/Interlaken_Protocol_Definition_v1.2.pdf`
   — Section 5.3.2.2 (p.18) defines the polynomial; Appendix B (p.48) defines init/RefIn/RefOut/XorOut.
3. **Wikipedia "Cyclic redundancy check" article** — `https://en.wikipedia.org/wiki/Cyclic_redundancy_check`
   — Background on CRC-24 family and the reflected-vs-non-reflected distinction.
4. **The Interlaken Alliance** — `https://interlakenalliance.com/`
   — Industry consortium maintaining the protocol definition document.

**Target user (one sentence):** a chip-to-chip interconnect / ASIC verification engineer writing a pure-Python reference for an Interlaken link layer (chip-to-chip SERDES protocol, used in 100G+ backplane designs) who needs a byte-exact CRC-24/Interlaken primitive with no C-extension dependency for inclusion in simulation testbenches, regression fixtures, or sandboxed CI containers.

**Named competitors (≥1):**

- `crcmod` — Python C-extension, well-tested across the CRC family, but ships a C build step (problematic in slim container images and PyPy), and exposes CRC parameters as runtime string keys (`mkCrcFun('crc-24-interlaken')` — opaque, not greppable, hard to audit for SLSA provenance). Our package: pure Python, no compile, parameter-locked at import-time, single-CRC focus.
- `crcany` — pure-Python multi-CRC generator. We are not a multi-CRC tool; we are the *single-CRC reference* — easier to read, easier to fuzz, easier to certify for a regulated silicon-validation flow.
- `crc24-pure` (local repo, cycle_129 shipped) — implements CRC-24/OpenPGP (RFC 4880 §6.1, poly=0x864CFB), a **different CRC-24 variant** (not Interlaken). Distinct repository, distinct polynomial, distinct spec authority.

---

## §1 Target User & Pain

**Workflow:** An ASIC/FPGA validation engineer building a Python testbench for a chip-to-chip SERDES link that uses the Interlaken protocol (the dominant chip-to-chip interconnect for 100G+ networking ASICs, line cards, and high-speed FPGA fabrics). The Interlaken Protocol Definition v1.2 §5.3.2.2 mandates a CRC-24/Interlaken checker on the data path. The engineer wants to:

1. Pre-compute expected CRC values for known test vectors, in pure Python, to compare against the RTL simulation output.
2. Compute the CRC for random stimulus in a regression test without depending on the compiled RTL.
3. Run the testbench in a sandboxed container that bans C-extension compiles (corporate IP firewall, air-gapped CI, or PyPy for speed).

**What breaks today:** the existing options are (a) `crcmod`, which requires `gcc` and the Python headers — a non-starter in many CI sandboxes; (b) `crcany`, which is a multi-CRC generator with no single-CRC depth; (c) rolling your own from a Wikipedia pseudocode snippet and *hoping* the bit ordering matches RevEng's canonical entry. The last option is exactly how subtle silicon-validation bugs get introduced — a bit-reversed polynomial produces CRCs that pass unit tests against your own broken reference but fail against the RTL.

This package gives the engineer a **single-CRC, byte-exact, RevEng-verified** primitive they can drop into their testbench, read the 25-line implementation, and audit the polynomial directly against the catalogue entry.

---

## §2 Algorithm Specification

**Authority:** Interlaken Protocol Definition v1.2, §5.3.2.2 (p.18, polynomial definition) and Appendix B (p.48, init/RefIn/RefOut/XorOut), as catalogued by RevEng.

**Parameter table:**

| Parameter | Value | Source |
|---|---|---|
| `width`    | 24       | RevEng catalogue |
| `poly`     | `0x328B63` | RevEng catalogue / Interlaken §5.3.2.2 |
| `init`     | `0xFFFFFF` | Interlaken Appendix B |
| `refin`    | `False`  | Interlaken Appendix B |
| `refout`   | `False`  | Interlaken Appendix B |
| `xorout`   | `0xFFFFFF` | Interlaken Appendix B |
| `check`    | `0xB4F3E6` (CRC of ASCII `"123456789"`) | RevEng catalogue |
| `residue`  | `0x144E63` (CRC of `check`+`b"123456789"`) | RevEng catalogue |

**Non-reflected bit ordering.** This CRC does **not** reflect input bytes or output bits — data enters MSB-first, the polynomial is applied MSB-first, and the output is read MSB-first.

**Mathematical form (for the testbench math person):**

```
crc = init
for byte in data:
    crc ^= (byte << 16)
    for _ in range(8):
        if crc & 0x800000:
            crc = ((crc << 1) ^ poly) & 0xFFFFFF
        else:
            crc = (crc << 1) & 0xFFFFFF
return crc ^ xorout
```

---

## §3 Acceptance Criteria (12 LOCKED)

Each AC is testable from a fresh clone with `pytest -q` and must pass before the build can hand off to QA.

- **AC1 — canonical check value:** `crc(b"123456789") == 0xB4F3E6`.
- **AC2 — zero-length input:** `crc(b"") == 0x000000` (init `0xFFFFFF` XORed with xorout `0xFFFFFF`).
- **AC3 — single 0x00 byte:** `crc(bytes([0x00])) == 0xDAF828`.
- **AC4 — single 0x01 byte:** `crc(bytes([0x01])) == 0xE8734B`.
- **AC5 — single 0xFF byte:** `crc(bytes([0xFF])) == 0x0000FF`.
- **AC6 — 10-byte ascending:** `crc(bytes(range(10))) == 0xDDCBC6`.
- **AC7 — residue conformance:** appending `check` to the canonical input gives `residue`:
  `crc(b"123456789" + b"\xb4\xf3\xe6") == 0x144E63`.
- **AC8 — width lock:** `crc(b"")` is masked to 24 bits (≤ `0xFFFFFF`).
- **AC9 — polynomial lock:** `crc(b"\x00" * 3)` does not equal `crc(b"\x00" * 4)` (sensitivity to byte count).
- **AC10 — deterministic:** `crc(data) == crc(data)` across 100 calls on the same data.
- **AC11 — oracle differential vs `crcmod`:** for ≥100 random byte-strings each ≥1000 bytes, our `crc(data) == crcmod.mkCrcFun(0x328B63, initCrc=0xFFFFFF, xorOut=0xFFFFFF, rev=False)(data) & 0xFFFFFF`. Skip if `crcmod` is not importable; record the skip reason in QA report.
- **AC12 — type-error safety:** calling `crc(None)`, `crc("string")`, or `crc(123)` raises `TypeError` with a message naming the expected `bytes`-like type. (`bytearray` is accepted; `memoryview` of a bytes-like is accepted.)

---

## §4 Canonical Reference Implementation

Verbatim Python (~25 LOC) following RevEng pseudocode, unrefined variant:

```python
"""crc24_interlaken.crc — CRC-24/Interlaken reference implementation."""

_WIDTH = 24
_POLY  = 0x328B63
_INIT  = 0xFFFFFF
_XOROUT = 0xFFFFFF
_MASK  = (1 << _WIDTH) - 1   # 0xFFFFFF


def crc(data: bytes) -> int:
    """Compute CRC-24/Interlaken of *data* (non-reflected).
    
    Returns an integer in [0, 0xFFFFFF].
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
```

Source for the bit-shift form: RevEng CRC Catalogue pseudocode, line `crc = ((crc << 1) ^ poly) & mask` and equivalent published by Greg Cook in the catalogue documentation.

---

## §5 Test Categories

Target: **≥100 pytest items** across 7 categories. The builder will add additional cases if the floor isn't met.

1. **canonical** (≥10) — every RevEng-published vector (5 inputs × 2 asserts each: explicit value + residue).
2. **byte_range** (≥16) — every single byte `0x00..0xFF` against a reference table precomputed from §4 and double-checked against `crcmod` if available.
3. **length_sweep** (≥15) — input lengths 0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128 bytes.
4. **determinism** (≥5) — same input → same output across repeated calls and across separate `import` instances.
5. **type_errors** (≥8) — `crc(None)`, `crc("string")`, `crc(123)`, `crc(3.14)`, `crc([1, 2, 3])`, `crc({"a": 1})`, `crc(object())`, plus `crc(b"")` accepted (regression).
6. **oracle_differential** (≥50) — random byte-strings length 100..2000, compared against `crcmod.mkCrcFun(...)` if importable; otherwise pre-baked expected values from a frozen reference table.
7. **edge** (≥10) — input that ends mid-byte conceptually (we always pad to bytes, so this is mostly structural: `bytearray`, `memoryview`, `bytes`, and very large single-shot input (1 MB) for sanity that we don't OOM).

**Pytest configuration:** `pytest -q` from repo root, discovery in `tests/`, no plugins required. No network access during test run.

---

## §6 Out-of-Scope / Non-Goals

- **NOT cryptographic.** CRC-24/Interlaken detects random bit errors in a SERDES link; it is not a MAC, not a signature, and offers no security guarantees. The package does not advertise or accept any "secure" framing.
- **NOT performance-optimized.** We ship the bitwise reference form (~5 MB/s on CPython 3.11). A table-driven variant or `crcmod`-style C-extension is explicitly out of scope; users who need throughput install `crcmod` for the same CRC.
- **NOT cross-platform-compatible at the bit level beyond CPython.** We rely on CPython's unsigned big-int semantics. PyPy3 is supported in principle; Jython / IronPython are untested. We make no guarantees on those runtimes.
- **NOT streaming.** `crc()` consumes the entire input in memory. For a 1 GB input, that is fine. For 100 GB inputs, use a different tool.
- **NOT multi-CRC.** This package implements only CRC-24/Interlaken. CRC-24/OpenPGP, CRC-24/OS-9, etc. are out of scope; they live in sibling repos (`crc24-pure` already shipped, future repos TBD).

---

## §7 Dependencies & Constraints

- **Runtime dependencies:** **NONE.** `dependencies = []` in `pyproject.toml`. This is a hard contract — adding any dependency requires a new spec.
- **Build-time dependencies:** `setuptools >= 61.0` (build backend only; not installed at runtime).
- **Test-time dependencies:** `pytest` (declared as `[project.optional-dependencies] test = ["pytest>=7.0"]`).
- **Python:** `>= 3.10` (declared in `pyproject.toml`). CPython 3.10, 3.11, 3.12, 3.13. PyPy3 ≥ 3.10 supported in principle.
- **Size budget:** total codebase ≤ 1000 LOC across `src/` + `tests/` (soft guideline; QA will not reject on this alone if the code is clean).
- **Single public function:** `crc(data: bytes) -> int`. The package does not export a class.

---

## §8 Honest Install + Verification

README install block (verbatim, to be used by the builder):

```bash
pip install git+https://github.com/prasad-a-abhishek/crc24-interlaken.git
```

(Repository is not published to PyPI; this is the canonical install command. A future v0.2.0 may publish to PyPI; for v0.1.0 this is the only install path.)

Verification after install:

```bash
python3 -c "from crc24_interlaken import crc; assert crc(b'123456789') == 0xB4F3E6, 'regression'"
python3 -m pytest -q    # expect: ≥100 passed
```

The test count claim in the README **must match** `pytest --collect-only -q` output. The builder is required to grep the test count post-build and stamp it into the README verbatim.

---

## §9 Build-Phase Handoff Notes

- `seed_evidence.json` is committed at `5100654`. Build will read this for the 5 vectors.
- Source file layout is `src/crc24_interlaken/__init__.py` exporting `crc`. Tests live in `tests/`.
- The reference impl in §4 is the contract — the builder is forbidden from swapping in a table-driven or polynomial-reduced variant. Bitwise `<<1` + conditional XOR is the form QA will compare against the RevEng pseudocode.
- Cross-check algorithm: build must verify `crcmod` agreement for AC11; if `crcmod` is uninstallable in the build sandbox, build must pre-bake ≥50 expected values into a frozen table (`tests/_frozen_known_values.py`) generated from the §4 reference itself, and note this fallback in QA_REPORT.md.
- Cycle_130 owner: orchestrator has the build card queued; this SPEC is the entire input.

---

*End of SPEC.md — 9 sections, 12 LOCKED ACs, ≥3 HTTP-200 primary sources cited, `check_existing.py` returned `VERDICT: APPROVED`.*
