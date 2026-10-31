# Benchmark results (aggregates)

These files hold the aggregate results of the benchmarks of an internal
build of SentryTower, before the public release. [docs/benchmarks.md](../docs/benchmarks.md) gives the method, the
conditions and the limits.

The files hold aggregates only: no result of one advisory, no answer key and
no list of repositories.

| File | Content |
| --- | --- |
| `results.json` | All results with their conditions and limits, in one document |
| `confirmation-2026-10.csv` | The confirmation test: detection with its 90% interval, false alarms, mean cost and chance-match rate of each harness |
| `confirmation-2026-10-differences.csv` | The hybrid against Piolium: the differences in percentage points with their 90% intervals |
| `confirmation-2026-10-sensitivity.csv` | The detection rates in the sensitivity views |
| `confirmation-2026-10-size.csv` | The difference against Piolium by repository size |
| `open-harnesses-2026-10.csv` | The open-harness test: each rival with its version, the fixtures it completed, both detection rates with their intervals, the difference, false alarms, cost and the rule's verdict |
| `vulngym-v0.1.4.csv` | The detection rates of each engine and of Piolium on VulnGym v0.1.4 |

Percentages are of the advisories with an answer key. A difference is in
percentage points (pp). An interval is a 90% paired cluster-bootstrap
interval over repositories.
