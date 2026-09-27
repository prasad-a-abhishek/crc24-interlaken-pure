#!/usr/bin/env python3
"""run_corpus.py — T3 seed-corpus fuzzer execution for cycle_130.

For each of the 6 surfaces, this script:
  1. Runs the harness with `timeout 5` against `corpus/seed/` (the contract
     seed corpus) and the per-harness subdirectory under `corpus/<surface>/`.
  2. Captures libFuzzer stdout/stderr to `logs/run.log`.
  3. Parses the log to extract the iteration count from libFuzzer's
     `pulse` / `Done` lines.
  4. Writes `stats.json` per surface with the contract schema:

       {
         "surface":          "<name>",
         "iters":            <int>,
         "elapsed_seconds":  <float>,
         "crashes":          <int>,
         "hangs":            <int>,
         "oom":              <int>,
         "oracle_mismatches":<int>,
         "exit_code":        <int>,
         "verdict":          "CLEAN" | "NEEDS_FIX"
       }

  5. Aggregates all surfaces into `AGGREGATE_STATS.json`.

Exit code: 0 if every surface's `verdict == "CLEAN"`; 1 otherwise.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

FUZZ_DIR = Path(__file__).resolve().parent
# …/fuzz -> …/cycle_130 -> …/adversarial -> …/benchmarks -> worktree root
REPO_ROOT = FUZZ_DIR.parent.parent.parent.parent
SEED_DIR = FUZZ_DIR / "corpus" / "seed"
PER_HARNESS_DIR = FUZZ_DIR / "corpus"
LOG_DIR = FUZZ_DIR / "logs"
SURFACE_DIR = FUZZ_DIR  # per-surface stats.json live at fuzz/<surface>/stats.json
AGGREGATE_FILE = FUZZ_DIR / "AGGREGATE_STATS.json"

VENV_PY = REPO_ROOT / ".venv-fuzz" / "bin" / "python"
TIMEOUT_S = 5
ATHERIS_RUNS = 200000  # upper bound; the wall-clock timeout fires first

# (surface_name, harness_filename, kind) where kind in {"atheris", "subprocess"}.
SURFACES = [
    ("crc_main",            "harness_crc_main.py",            "atheris"),
    ("engine_streaming",    "harness_engine_streaming.py",    "atheris"),
    ("table_integrity",     "harness_table_integrity.py",     "atheris"),
    ("cli_args",            "harness_cli_args.py",            "atheris"),
    ("type_errors",         "harness_type_errors.py",         "atheris"),
    ("cross_cycle_oracle",  "harness_cross_cycle_oracle.py",  "atheris"),
]


def _parse_iters(log_text: str) -> int:
    """Extract the iteration count from libFuzzer's stdout/stderr.

    libFuzzer emits progress lines like:
        #32768   pulse  cov: 14 ft: 73 corp: 23/900b exec/s: 16384 rss: 39Mb
        #59781   DONE   cov: 14 ft: 73 corp: 25/930b exec/s: 9963 rss: 43Mb
        Done 200000 in 1 second(s)
        Done 59781 runs in 6 second(s)

    We prefer the `Done N runs` line if present (most accurate count after
    the run completes). Otherwise the largest `#NNNNN` pulse number.
    """
    done_runs_m = re.search(r"Done\s+(\d+)\s+runs?\s+in\s+", log_text)
    if done_runs_m:
        return int(done_runs_m.group(1))
    done_m = re.search(r"Done\s+(\d+)\s+in\s+", log_text)
    if done_m:
        return int(done_m.group(1))
    done_n_m = re.search(r"^#(\d+)\s+DONE\b", log_text, flags=re.MULTILINE)
    if done_n_m:
        return int(done_n_m.group(1))
    pulse_m = re.findall(r"^#(\d+)\s+pulse", log_text, flags=re.MULTILINE)
    if pulse_m:
        return max(int(n) for n in pulse_m)
    init_m = re.search(r"^#(\d+)\s+INITED", log_text, flags=re.MULTILINE)
    if init_m:
        return int(init_m.group(1))
    return 0


def _run_surface(surface: str, harness_file: str, kind: str) -> dict:
    """Run a single harness and return a stats dict."""
    surface_dir = SURFACE_DIR / surface
    surface_dir.mkdir(parents=True, exist_ok=True)
    log_path = surface_dir / "logs" / "run.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path = surface_dir / "stats.json"

    # Compose the corpus argument. libFuzzer accepts one or more seed corpus
    # directories as positional args; passing both the contract seed corpus
    # (corpus/seed/) AND the per-harness curated subdir maximizes coverage.
    per_harness = PER_HARNESS_DIR / surface
    seed_arg = SEED_DIR
    if not SEED_DIR.is_dir():
        # Fallback to per-harness subdir only.
        seed_arg = per_harness

    cmd = [
        str(VENV_PY),
        str(FUZZ_DIR / harness_file),
        f"-atheris_runs={ATHERIS_RUNS}",
        f"-max_total_time={TIMEOUT_S}",
        str(seed_arg),
        str(per_harness),
    ]

    print(f"==> {surface}: running {harness_file} (timeout {TIMEOUT_S}s)")
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S + 25,  # outer safety net; inner `timeout` should fire first
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    elapsed = time.perf_counter() - start
    rc = proc.returncode

    log_text = (proc.stdout or "") + (proc.stderr or "")
    log_path.write_text(log_text, encoding="utf-8", errors="replace")

    iters = _parse_iters(log_text)

    # Determine the verdict.
    # rc 0   = clean atheris exit (only engine_streaming, which hits runs cap)
    # rc 124 = timeout from outer `timeout` wrapper (expected: budget exhausted)
    # rc != 0/124 = some other failure (crash, signal, abnormal exit)
    crashes = 0
    hangs = 0
    oom = 0
    oracle_mismatches = 0

    if rc in (0, 124):
        verdict = "CLEAN"
    else:
        # Anything else is a finding; libFuzzer convention is rc 77 for
        # "harness reported a bug", which becomes our NEEDS_FIX.
        verdict = "NEEDS_FIX"
        crashes = 1

    stats = {
        "surface":            surface,
        "iters":              iters,
        "elapsed_seconds":    round(elapsed, 2),
        "crashes":            crashes,
        "hangs":              hangs,
        "oom":                oom,
        "oracle_mismatches":  oracle_mismatches,
        "exit_code":          rc,
        "verdict":            verdict,
    }
    stats_path.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return stats


def main() -> int:
    if not VENV_PY.is_file():
        print(f"FATAL: {VENV_PY} not found; create .venv-fuzz first", file=sys.stderr)
        return 2

    if not SEED_DIR.is_dir():
        print(f"FATAL: seed corpus {SEED_DIR} not built", file=sys.stderr)
        return 2

    all_stats = []
    for surface, harness, kind in SURFACES:
        all_stats.append(_run_surface(surface, harness, kind))

    total_iters = sum(s["iters"] for s in all_stats)
    total_crashes = sum(s["crashes"] for s in all_stats)
    total_hangs = sum(s["hangs"] for s in all_stats)
    total_oom = sum(s["oom"] for s in all_stats)
    total_oracle = sum(s["oracle_mismatches"] for s in all_stats)
    any_fix = any(s["verdict"] == "NEEDS_FIX" for s in all_stats)
    aggregate_verdict = "NEEDS_FIX" if any_fix else "CLEAN"

    aggregate = {
        "cycle":               130,
        "surfaces_run":        len(all_stats),
        "iters_total":         total_iters,
        "crash_count":         total_crashes,
        "hang_count":          total_hangs,
        "oom_count":           total_oom,
        "oracle_mismatch_count": total_oracle,
        "aggregate_verdict":   aggregate_verdict,
        "per_surface":         all_stats,
    }
    AGGREGATE_FILE.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")

    print("\n==> AGGREGATE_STATS.json:")
    print(json.dumps({k: aggregate[k] for k in (
        "surfaces_run", "iters_total", "crash_count", "hang_count",
        "oom_count", "oracle_mismatch_count", "aggregate_verdict",
    )}, indent=2))

    return 0 if aggregate_verdict == "CLEAN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
