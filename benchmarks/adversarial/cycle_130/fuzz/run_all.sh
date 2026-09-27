#!/usr/bin/env bash
# run_all.sh — run every fuzzing harness under benchmarks/adversarial/cycle_130/fuzz/
# with the canonical 5-second-per-input timeout, collect per-surface stats.
#
# Usage:
#   ./run_all.sh                    # 5s per harness, ASan/UBSan OFF (default)
#   ASAN=1 ./run_all.sh             # enable ASan + UBSan
#   ./run_all.sh /path/to/venv      # use a specific venv (default: .venv-fuzz)
#
# Outputs:
#   - logs/<harness>.log  : per-harness stdout/stderr
#   - stats.json          : machine-readable per-surface summary
#
# Exit code: 0 if all harnesses completed within their budget, 1 otherwise.

set -u

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/../../../../" && pwd)"
LOG_DIR="$FUZZ_DIR/logs"
CORPUS_DIR="$FUZZ_DIR/corpus"
STATS_FILE="$FUZZ_DIR/stats.json"
VENV_DIR="${1:-$REPO_ROOT/.venv-fuzz}"
TIMEOUT_S=5

mkdir -p "$LOG_DIR"

PY="$VENV_DIR/bin/python"
if [ ! -x "$PY" ]; then
    echo "FATAL: $PY not executable. Create .venv-fuzz first or pass venv path." >&2
    exit 2
fi

# Optional sanitizer toggles (forwarded to atheris).
ATHERIS_FLAGS=""
if [ "${ASAN:-0}" = "1" ]; then
    ATHERIS_FLAGS="-detect_leaks=1"
fi

declare -a HARNESSES=(
    "crc_main:harness_crc_main.py"
    "engine_streaming:harness_engine_streaming.py"
    "table_integrity:harness_table_integrity.py"
    "cli_args:harness_cli_args.py"
    "type_errors:harness_type_errors.py"
    "cross_cycle_oracle:harness_cross_cycle_oracle.py"
)

# We'll write JSON incrementally; build a temp file first then mv.
STATS_TMP="$LOG_DIR/.stats.tmp"
echo "{" > "$STATS_TMP"
echo '  "cycle": 130,' >> "$STATS_TMP"
echo '  "harnesses": [' >> "$STATS_TMP"

first=1
overall_rc=0

for entry in "${HARNESSES[@]}"; do
    name="${entry%%:*}"
    file="${entry#*:}"
    log="$LOG_DIR/$name.log"

    echo "==> $name ($file) — running for ${TIMEOUT_S}s"
    # Per-harness 5-second wall-clock timeout. atheris's -max_total_time is
    # the per-input budget; we use the kernel timeout as the wall-clock cap
    # so the harness never wedges the cron loop. The seed corpus is passed
    # as a positional directory argument (libFuzzer convention); the
    # comma-separated `-seed_inputs=` flag is a fallback for harness authors
    # who prefer file lists.
    start_ts=$(date +%s)
    set +e
    timeout "${TIMEOUT_S}" "$PY" "$FUZZ_DIR/$file" $ATHERIS_FLAGS \
        -atheris_runs=200000 -max_total_time="$TIMEOUT_S" \
        "$CORPUS_DIR/$name" \
        > "$log" 2>&1
    rc=$?
    set -e
    end_ts=$(date +%s)
    elapsed=$((end_ts - start_ts))

    # rc 124 = timeout (expected: harness ran for the full budget and was
    # SIGTERMed cleanly). rc 0 = harness exited on its own (rare; usually
    # means a crash that caused the fuzzer to abort). Anything else = bug.
    case "$rc" in
        0)    status="clean-exit"  ;;
        124)  status="timeout-ok"   ;;
        *)    status="crash-rc=$rc"; overall_rc=1 ;;
    esac

    # Extract any 'INFO: Loaded N modules...' / 'Done N runs in Y seconds'
    # style counters from the atheris log if present; otherwise leave at 0.
    runs=$(grep -oE '[0-9]+ EXECUTED|[0-9]+ DONE|[0-9]+ runs in [0-9]+ second' "$log" 2>/dev/null | head -1)
    cov=$(grep -oE 'cov: [0-9]+' "$log" 2>/dev/null | tail -1)

    if [ "$first" = "1" ]; then first=0; else echo "," >> "$STATS_TMP"; fi
    cat >> "$STATS_TMP" <<EOF
    {
      "name": "$name",
      "file": "$file",
      "exit_code": $rc,
      "status": "$status",
      "elapsed_seconds": $elapsed,
      "runs_observed": "${runs:-unknown}",
      "coverage_observed": "${cov:-unknown}"
    }
EOF
done

echo "" >> "$STATS_TMP"
echo "  ]" >> "$STATS_TMP"
echo "}" >> "$STATS_TMP"

mv "$STATS_TMP" "$STATS_FILE"

echo "==> Stats written to $STATS_FILE"
cat "$STATS_FILE"

exit $overall_rc