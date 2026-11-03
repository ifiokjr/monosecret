---
title: Benchmarks
description: The hot-path benchmarks every pull request is measured against, how the perf gate decides a regression, and how to add a benchmark
---

Every pull request runs the hot-path benchmarks in
`crates/monosecret/benches/hot_paths.rs` twice on one runner — once on the
base commit and once on the change — and fails when a path got meaningfully
slower. The same job keeps the workspace dependency graph under a budget, so
compile time and binary size cannot creep up one crate at a time.

## What is measured

| Benchmark                              | Hot path                                                                   |
| -------------------------------------- | -------------------------------------------------------------------------- |
| `spec_parse/small`, `spec_parse/large` | Parsing and validating `monosecret.toml` (12 and 200 declarations)         |
| `manifest/compose_200`                 | Composing the profile view the CLI prints and the SDKs consume             |
| `codegen/build_ir_200`                 | Building the intermediate representation behind the Rust derive macro      |
| `resolve/env_40`                       | Resolving a 40-secret profile through the `env` provider                   |
| `resolve/json_env_40`                  | The same resolution through `resolve_json`, the SDK entry point            |
| `cache/encode`, `cache/decode_fresh`   | Encoding and classifying a cache envelope, paid on every cached read       |
| `shell_render/*`                       | Rendering `monosecret env` output for bash, GitHub Actions, and PowerShell |

The benchmarks are self-contained: specs are generated in memory, the only
provider touched is `env`, and `HOME` and the XDG directories point at a
scratch directory, so a run never reads or writes a developer's real global
config, cache, or audit log.

## Running locally

```shell-session
$ bash scripts/perf/run-benches.sh
```

The script selects the feature set the CI job uses — `cli` plus the hidden
`__bench` feature that opens the crate-private cache codec — so the build stays
small. To reproduce the CI comparison, save the two sides as named baselines:

```shell-session
$ git switch main && bash scripts/perf/run-benches.sh --save-baseline base
$ git switch my-branch && bash scripts/perf/run-benches.sh --save-baseline head
$ bash scripts/perf/compare.sh
```

Criterion compares a plain run against `base` and then overwrites it, which is
why both sides are saved under their own names.

## How a regression is decided

`scripts/perf/compare.sh` fails a benchmark when its median is more than 25%
slower (`THRESHOLD`, as a fraction) **and** the two medians are separated by
more than three combined standard errors. Medians rather than means, because a
shared runner's scheduling spikes land in the tail; the two-part test lets
ordinary runner noise through while a real slowdown of the size that matters
cannot hide inside it. The gate exists to catch algorithmic regressions, not
single-digit drift. The table it prints also lands in the job summary.

A base commit that predates the benchmarks has nothing to compare against; the
job then only runs the benchmarks on the change.

## The dependency budget

`scripts/perf/dependency-budget.sh` counts every distinct crate reachable
through normal and build dependencies on any target — what a release build of
the whole workspace compiles — and fails above the budget set in the script.
Dev-dependencies are excluded; they never ship. Raise the budget in the same
pull request that needs the new crates and say in its description what they
buy.

## Adding a benchmark

Add a function to `hot_paths.rs`, register it in the `criterion_group!` at the
bottom, and keep it self-contained: no network, no real provider, nothing
outside the scratch home. Name it `group/case` through a benchmark group so
the comparison table stays readable. When a path is `pub(crate)`, add the
smallest possible wrapper to `crates/monosecret/src/bench_support.rs` with a
unit test; that module is the only doorway the benchmarks get, and it is
hidden from documentation.
