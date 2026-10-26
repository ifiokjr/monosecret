#!/usr/bin/env bash
#
# Run the hot-path benchmarks with the feature set the `perf` CI job measures.
# Extra arguments go to criterion, for example `--save-baseline base`.
#
#     bash scripts/perf/run-benches.sh
#     bash scripts/perf/run-benches.sh --save-baseline base
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

exec cargo bench -p monosecret --no-default-features --features cli,__bench --bench hot_paths -- "$@"
