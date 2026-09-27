# crc24-interlaken -- Benchmark Report

Environment: Python 3.11.15 on Linux aarch64. Timing via `time.perf_counter()`; Peak RSS via `resource.getrusage(RUSAGE_SELF).ru_maxrss`.

Workloads: 10 (5 sizes: 0/64/256/1024/65536 bytes x 2 distributions: zeros + random) x 10 iterations each.

## Headline: bitwise vs table-driven (5 iterations, mean / P95 microseconds, MB/s)

| Workload | bitwise mean (us) | bitwise MB/s | table mean (us) | table MB/s | speedup |
|---|---:|---:|---:|---:|---:|
| 0B zeros | 0.3 | 0.0 | 0.3 | 0.0 | 1.16x |
| 0B random | 0.4 | 0.0 | 0.3 | 0.0 | 1.59x |
| 64B zeros | 32.3 | 1.9 | 4.4 | 14.0 | 7.39x |
| 64B random | 34.3 | 1.8 | 4.1 | 14.9 | 8.40x |
| 256B zeros | 130.3 | 1.9 | 15.0 | 16.2 | 8.66x |
| 256B random | 132.1 | 1.8 | 15.3 | 16.0 | 8.66x |
| 1024B zeros | 506.4 | 1.9 | 58.0 | 16.8 | 8.74x |
| 1024B random | 512.3 | 1.9 | 58.4 | 16.7 | 8.76x |
| 65536B zeros | 29261.9 | 2.1 | 3305.3 | 18.9 | 8.85x |
| 65536B random | 29892.9 | 2.1 | 3356.1 | 18.6 | 8.91x |

## crcmod baseline (NOT INCLUDED)
`crcmod` was importable but its ``_verifyPoly`` rejects the RevEng form
``0x328B63`` (it requires the polynomial to have its implicit leading bit
set: ``1<<24 <= poly < 1<<25``). We could OR in the leading bit
(``0x1328B63``) to make crcmod accept it, but that changes the polynomial
from RevEng's canonical form, so we don't -- comparing against a different
polynomial would not be a fair speed baseline. The pure-Python paths above
are the contract; crcmod is omitted here on purpose, with full reasoning
in ``benchmarks/run_benchmark.py::_try_crcmod``.


## Reproduce

```bash
python3 benchmarks/run_benchmark.py
```

The script writes `benchmarks/BENCHMARK.md` (this file) and prints a summary to stdout.
