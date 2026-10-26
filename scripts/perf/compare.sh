#!/usr/bin/env bash
#
# Compare the `head` hot-path benchmark baseline against the `base` baseline
# and fail when a benchmark regressed. A regression is a median that is more
# than THRESHOLD slower (0.25 = 25%) *and* separated from the baseline by more
# than three combined standard errors. Medians rather than means, because a
# shared CI runner's scheduling spikes land in the tail; the two-part test lets
# ordinary runner noise pass while a slowdown of the size that matters cannot
# hide inside it. The gate exists to catch real algorithmic regressions, not
# single-digit drift.
#
# Both sides are saved as named criterion baselines because a plain run
# compares against `base` and then overwrites it:
#
#     bash scripts/perf/run-benches.sh --save-baseline base   # on the base commit
#     bash scripts/perf/run-benches.sh --save-baseline head   # on the change
#     bash scripts/perf/compare.sh
set -euo pipefail

criterion_home="${CRITERION_HOME:-target/criterion}"
threshold="${THRESHOLD:-0.25}"

if [[ ! -d "$criterion_home" ]]; then
	echo "::error::no criterion results under $criterion_home" >&2
	exit 1
fi

rows=()
regressions=()
compared=0

while IFS= read -r head_file; do
	id="${head_file#"$criterion_home"/}"
	id="${id%/head/estimates.json}"
	base_file="$criterion_home/$id/base/estimates.json"

	if [[ ! -f "$base_file" ]]; then
		rows+=("| \`$id\` | new benchmark, no baseline | — | ✅ |")
		continue
	fi

	verdict="$(
		jq -r -n \
			--slurpfile head "$head_file" \
			--slurpfile base "$base_file" \
			--argjson threshold "$threshold" '
			($head[0].median) as $n | ($base[0].median) as $b
			| ($n.point_estimate - $b.point_estimate) as $delta
			| (if $b.point_estimate > 0 then $delta / $b.point_estimate else 0 end) as $relative
			| (($n.standard_error * $n.standard_error) + ($b.standard_error * $b.standard_error) | sqrt) as $se
			| (if $se > 0 then $delta / $se else 0 end) as $z
			| [
				(if $relative > $threshold and $z > 3 then "regression" else "ok" end),
				($relative * 100 | . * 10 | round / 10),
				($z * 10 | round / 10),
				($b.point_estimate / 1000 | . * 100 | round / 100),
				($n.point_estimate / 1000 | . * 100 | round / 100)
			  ] | @tsv'
	)"
	IFS=$'\t' read -r status relative z base_us new_us <<<"$verdict"
	compared=$((compared + 1))

	if [[ "$status" == "regression" ]]; then
		regressions+=("$id")
		rows+=("| \`$id\` | ${base_us} µs → ${new_us} µs | ${relative}% (z ${z}) | ❌ |")
	else
		rows+=("| \`$id\` | ${base_us} µs → ${new_us} µs | ${relative}% (z ${z}) | ✅ |")
	fi
done < <(find "$criterion_home" -path '*/head/estimates.json' | sort)

report="$(
	printf '## Hot-path benchmarks\n\n'
	printf 'Threshold: a median more than %s%% slower with |z| > 3 fails.\n\n' "$(awk -v t="$threshold" 'BEGIN { printf "%g", t * 100 }')"
	printf '| Benchmark | Median (base → change) | Change | Status |\n'
	printf '| --- | --- | --- | --- |\n'
	printf '%s\n' "${rows[@]}"
)"

echo "$report"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	echo "$report" >>"$GITHUB_STEP_SUMMARY"
fi

if ((compared == 0)); then
	echo "::error::no benchmark had both a base and a head measurement" >&2
	exit 1
fi

if ((${#regressions[@]} > 0)); then
	echo "::error::performance regressed in ${#regressions[@]} benchmark(s): ${regressions[*]}" >&2
	exit 1
fi

echo "no regressions across $compared benchmarks"
