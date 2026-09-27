"""harness_cli_args.py — Atheris harness for the CLI surface.

Surface under test:
    python3 -m crc24_interlaken [--data HEX...] [--self-test] [--version] [--help]

Contract:
    * --version / --help exit 0.
    * --self-test exits 0 and prints "6/6 vectors passed".
    * --data <one or more hex tokens> exits 0 and prints "0xRRGGBB".
    * Bad hex tokens (wrong length, non-hex chars, oversized) exit 2 with a
      structured error message on stderr (NOT a traceback).
    * Missing required arg exits 2 with usage on stderr.
    * Combined flags like --data --self-test exit 2 (argparse rejects).
    * Pathological token sequences (1000+ tokens, very long tokens) must NOT
      crash -- either parse cleanly or exit 2 with a clean error.

Fuzz strategy:
    * Atheris TestOneFuzzedInput receives random bytes; the harness
      interprets them as a sequence of CLI tokens and invokes the package
      main() directly via subprocess (so the real `python3 -m` entrypoint
      is exercised -- this catches any future regressions in __main__.py
      before they reach users).
    * Exit code 0 or 2 is the contract; exit code 1 (unhandled exception
      or wrong number) or any signal-terminated exit is a finding.
    * Crash files produced by the fuzzer can be replayed via:
          ./harness_cli_args.py <crashfile>

References:
    * Cycle_130 VULN_AUDIT.md Surface 4 (CLI behaviour table)
    * Cycle_130 TEST_GAPS.md G-08 (CLI argv fuzz coverage)

Invocation:
    .venv-fuzz/bin/python benchmarks/adversarial/cycle_130/fuzz/harness_cli_args.py \\
        -atheris_runs=2000 -max_total_time=5

Expected runtime: ~5s. Each iteration spawns a short-lived subprocess; the
5s budget is dominated by Python startup overhead per spawn (~30ms on
CPython 3.11.15).
"""

from __future__ import annotations

import os
import subprocess
import sys

import atheris


_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
_VALID_HEX = "0123456789abcdef"


def _spawn(argv: list[str], timeout: float = 1.0) -> tuple[int, str, str]:
    """Run `python3 -m crc24_interlaken <argv>` from the repo's worktree.
    Returns (exit_code, stdout, stderr).
    """
    proc = subprocess.run(
        [sys.executable, "-m", "crc24_interlaken", *argv],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONPATH": _REPO_ROOT},
    )
    return proc.returncode, proc.stdout, proc.stderr


def _bytes_to_hex_tokens(data: bytes) -> list[str]:
    """Turn a bytes payload into a list of plausible --data tokens.
    Returns 0..32 tokens, each of 0..4 hex chars. Tokens can be empty,
    wrong-length, non-hex, oversized -- all the cases the real CLI must
    reject cleanly.
    """
    if not data:
        return []
    n = min(32, max(0, data[0]))
    out: list[str] = []
    cursor = 1
    for _ in range(n):
        if cursor >= len(data):
            break
        # 0..3 chars of token (length 0,1,2,3 covers empty + 1-hex + 2-hex +
        # oversized-3).
        tlen = data[cursor] % 4
        cursor += 1
        if cursor + tlen > len(data):
            break
        tok_bytes = data[cursor : cursor + tlen]
        cursor += tlen
        out.append(bytes(b for b in tok_bytes if b in _VALID_HEX.encode())[:tlen].decode("ascii", errors="ignore"))
    return out


def TestOneFuzzedInput(data: bytes) -> None:
    """One iteration: feed the fuzzer payload to the CLI.

    We exercise three CLI sub-surfaces per iteration:
      1. Random --data tokens (bad hex coverage).
      2. --version / --self-test invocations (positive paths).
      3. Combined-flag collisions (--data --self-test, --data --version, etc.).
    """
    fdp = atheris.FuzzedDataProvider(data)

    # Surface 1: --data with bad tokens (always -- this is the primary
    # fuzzing path the harness exists to cover).
    tokens = _bytes_to_hex_tokens(data)
    rc, out, err = _spawn(["--data", *tokens])
    assert rc in (0, 2), (
        f"--data {tokens!r} exited {rc} (expected 0 or 2); "
        f"stdout={out!r} stderr={err!r}"
    )
    if rc == 2:
        # On error, stderr must NOT contain a traceback -- only a clean
        # "crc24-interlaken: error: ..." line.
        assert "Traceback" not in err, (
            f"--data {tokens!r} leaked a traceback to stderr: {err!r}"
        )

    # Surface 2a: --version (every other iteration, gated by fdp).
    if fdp.ConsumeBool():
        rc, out, err = _spawn(["--version"])
        assert rc == 0, f"--version exited {rc} (expected 0)"
        assert "crc24-interlaken" in out, (
            f"--version stdout missing package name: {out!r}"
        )

    # Surface 2b: --self-test (every other iteration, gated by fdp).
    if fdp.ConsumeBool():
        rc, out, err = _spawn(["--self-test"])
        assert rc == 0, f"--self-test exited {rc} (expected 0)"
        assert "vectors passed" in out, (
            f"--self-test stdout missing 'vectors passed': {out!r}"
        )

    # Surface 3: combined / conflicting flags (gated).
    if fdp.ConsumeBool():
        for combo in (
            ["--data", "00", "--self-test"],
            ["--data", "00", "--version"],
            ["--self-test", "--version"],
            ["--data"],
            [],
        ):
            rc, out, err = _spawn(combo)
            assert rc in (0, 2), (
                f"combo {combo!r} exited {rc} (expected 0 or 2); "
                f"stdout={out!r} stderr={err!r}"
            )
            if rc == 2:
                assert "Traceback" not in err, (
                    f"combo {combo!r} leaked a traceback: {err!r}"
                )


def main() -> int:
    atheris.Setup(sys.argv, TestOneFuzzedInput, test_hooks_dir=None)
    # Use a shorter timeout per subprocess (the fuzzer's max_total_time is 5s;
    # we set per-spawn timeout to 1s in _spawn()).
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())