#!/usr/bin/env bash
#
# Fail when the workspace dependency graph grows past its budget. Every crate
# is compile time, binary size, and supply-chain surface, so growth has to be
# a decision made in the pull request that needs it: raise `budget` here in
# that same change and say in its description what the new crates buy.
#
# Counts every distinct crate reachable through normal and build dependencies
# on any target, which is what a release build of the whole workspace compiles.
# Dev-dependencies are excluded; they never ship.
#
#     bash scripts/perf/dependency-budget.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

budget=760

count="$(
	cargo tree --workspace --target all -e normal,build --prefix none --locked |
		sed 's/ (\*)$//' |
		sort -u |
		wc -l |
		tr -d ' '
)"

echo "workspace dependency graph: $count distinct crates (budget $budget)"

if ((count > budget)); then
	echo "::error::the dependency graph has $count crates, over the budget of $budget. Raise the budget in scripts/perf/dependency-budget.sh in this change and explain what the new crates buy." >&2
	exit 1
fi
