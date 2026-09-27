"""harness_engine_streaming.py — DEFERRED surface harness (placeholder).

Surface under test (proposed):
    crc24_interlaken.CrcEngine
    CrcEngine().update(chunk) -> None
    CrcEngine().digest() -> int

STATUS: **DEFERRED** per cycle_130 VULN_AUDIT.md Finding F-INFO-01.

The current `crc24-interlaken-pure` codebase does **not** implement a
stateful streaming `CrcEngine` class. The package exposes only:

  * `crc24_interlaken.crc(data)` -- stateless one-shot function
  * `crc24_interlaken._table.crc_table(data)` -- stateless table-driven path
  * `crc24_interlaken.precomputed_table()` -- table introspection

SPEC §6 ("Out of Scope") explicitly excludes a streaming engine for v0.1.0.
The cycle_130 task body listed this surface among the harness targets
because the cycle_129+ cycle_130 build specs both reference streaming as a
"what if we ever add it" surface; cycle_129 ships the same stateless
one-shot only.

Why this harness exists:
    1. **Coverage continuity.** If a future cycle adds a streaming engine,
       this file becomes the natural drop-in target -- it is already
       written in the form of a harness and only requires the engine class
       to be added.
    2. **Audit trail.** Without this file the workstream audit cannot
       answer "why is there no streaming harness?"; with it, the answer
       is "F-INFO-01 deferred, see file."

What this file does today:
    It is a no-op libFuzzer harness. Atheris' TestOneFuzzedInput accepts
    the fuzzed payload, runs the invariant check that the engine does
    NOT exist (i.e. `hasattr` is False), and exits cleanly. The wrapper
    `run_all.sh` measures its runtime and reports it as "DEFERRED" in the
    per-surface stats.

What this file WILL do once a streaming engine is added:
    1. Construct a fresh `CrcEngine()` per iteration.
    2. Split the fuzzed payload into N random chunks (1 <= N <= 32).
    3. Feed chunks via `engine.update(chunk)`, then call `engine.digest()`.
    4. Assert that `engine.digest()` equals `crc(full_payload)` -- the
       streaming class must produce the same value as the one-shot call.
    5. Assert that mutation of a chunk after `update()` does not affect
       the digest (the engine must not hold a reference to the input).
    6. Assert that `digest()` returns a 24-bit-masked int.

References:
    * Cycle_130 VULN_AUDIT.md F-INFO-01
    * Cycle_130 SURFACES.md Surface 2
    * SPEC §6 ("Out of Scope")

Invocation (current no-op):
    .venv-fuzz/bin/python benchmarks/adversarial/cycle_130/fuzz/harness_engine_streaming.py \\
        -atheris_runs=10 -max_total_time=1

Expected runtime: <1s.
"""

from __future__ import annotations

import sys

import atheris

import crc24_interlaken


_MASK = 0xFFFFFF
_ENGINE_SYMBOL = "CrcEngine"


def TestOneFuzzedInput(data: bytes) -> None:
    """No-op harness: assert the CrcEngine symbol is absent and the
    package's public surface has not regressed.

    When a future cycle adds a CrcEngine class, this function will be
    extended to exercise it; the assertion below will be replaced with
    streaming-vs-one-shot equivalence checks.
    """
    del data
    assert not hasattr(crc24_interlaken, _ENGINE_SYMBOL), (
        f"crc24_interlaken now exposes {_ENGINE_SYMBOL!r}; "
        f"this harness needs to be updated from DEFERRED to ACTIVE."
    )
    # Sanity: the existing surfaces are still present and well-formed.
    assert hasattr(crc24_interlaken, "crc")
    assert callable(crc24_interlaken.crc)
    # Empty-input invariant.
    assert crc24_interlaken.crc(b"") == 0x000000


def main() -> int:
    atheris.Setup(sys.argv, TestOneFuzzedInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())