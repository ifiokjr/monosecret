---
rust:monosecret: none
---

# Benchmark the hot paths and gate pull requests on them

A criterion suite now covers the paths every invocation pays for: parsing
and validating `monosecret.toml`, composing the manifest, building the
derive macro's intermediate representation, resolving a profile through
the `env` provider both directly and via `resolve_json`, encoding and
classifying cache envelopes, and rendering `monosecret env` output. The
`perf` CI job benchmarks the base commit and the change on one runner and
fails when a median is more than 25% slower with the difference outside
three standard errors, and it keeps the workspace dependency graph under
a budget so compile time and binary size cannot creep up one crate at a
time. The crate gains a hidden `__bench` feature that exposes thin,
tested wrappers over the crate-private cache codec for the benchmarks;
it is not a public API.
