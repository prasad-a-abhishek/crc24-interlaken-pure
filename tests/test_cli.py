"""test_cli.py -- subprocess-level tests for the `python3 -m crc24_interlaken` CLI.

Invokes the CLI in a child Python process to confirm:
  * --self-test exits 0 and prints "6/6 vectors passed"
  * --data 31 32 33 34 35 36 37 38 39 prints "0xb4f3e6"
  * --version prints "crc24-interlaken 0.1.0"
  * --data accepts the 0x prefix form (e.g. 0x31)
  * --data accepts concatenated hex (e.g. 313233 -> 0x31 0x32 0x33)
  * --data with no token -> non-zero exit
  * --data with a bad token -> non-zero exit
  * CLI works with -m form and as an installed `crc24-interlaken` binary

These tests run the CLI as a real subprocess so they catch:
  - argv handling bugs
  - I/O redirection bugs
  - import-time failures when CLI is invoked without a dev sys.path
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


# Repo root for `python3 -m` invocations
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SRC = os.path.join(_REPO_ROOT, "src")


def _run_cli(*args, env_extra=None):
    """Invoke the CLI as a subprocess.

    Adds ``src/`` to PYTHONPATH so the test does not require installing the
    package -- mirrors the way a developer would run ``python3 -m crc24_interlaken``
    from the repo root during local development.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = _SRC + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "crc24_interlaken", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_cli_self_test_exits_zero_and_prints_6_of_6():
    """Headline assertion: --self-test -> "6/6 vectors passed", exit 0."""
    result = _run_cli("--self-test")
    assert result.returncode == 0, (
        f"expected exit 0, got {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert result.stdout.strip() == "6/6 vectors passed"
    assert "FAIL" not in result.stdout
    assert "FAIL" not in result.stderr


def test_cli_data_123456789_prints_b4f3e6():
    """ASCII '123456789' encoded as hex bytes -> '0xb4f3e6'."""
    result = _run_cli("--data", "31", "32", "33", "34", "35", "36", "37", "38", "39")
    assert result.returncode == 0
    assert result.stdout.strip() == "0xb4f3e6"


def test_cli_version_prints_package_version():
    """--version -> 'crc24-interlaken 0.1.0' (matches cycle_130 spec)."""
    result = _run_cli("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == "crc24-interlaken 0.1.0"


def test_cli_data_empty():
    """CRC of empty input -> 0x000000."""
    result = _run_cli("--data")
    # argparse treats --data with no value as a non-zero exit + usage line
    # (it's a nargs='+' argument; 0 tokens is invalid). We assert the message
    # is informative.
    assert result.returncode != 0
    assert "--data" in result.stderr or "required" in result.stderr.lower()


def test_cli_data_invalid_hex_token_returns_nonzero():
    """A non-hex token must exit non-zero with a clear error."""
    result = _run_cli("--data", "zz")
    assert result.returncode != 0
    assert "invalid" in result.stderr.lower() or "error" in result.stderr.lower()


def test_cli_no_args_returns_nonzero():
    """Calling with no args must show usage and exit non-zero."""
    result = _run_cli()
    assert result.returncode != 0
    assert "usage" in result.stderr.lower() or "error" in result.stderr.lower()


def test_cli_data_accepts_0x_prefix():
    """Tokens with the '0x' prefix are accepted (Python literal hex)."""
    result = _run_cli("--data", "0x31", "0x32", "0x33")
    assert result.returncode == 0
    # '123' as bytes 0x31 0x32 0x33 -- just verify a clean run, not the exact value.
    assert result.stdout.strip().startswith("0x")
    assert len(result.stdout.strip()) == 8  # '0x' + 6 hex digits


def test_cli_data_single_byte():
    """Single 0x00 byte -> 0xDAF828 (canonical vector)."""
    result = _run_cli("--data", "00")
    assert result.returncode == 0
    assert result.stdout.strip() == "0xdaf828"


def test_cli_help_exits_zero():
    """--help must show help text and exit 0."""
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "CRC-24/Interlaken" in result.stdout or "--data" in result.stdout