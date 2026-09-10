---
"monosecret": none
---

# Refresh toolchain, dependencies, and CI action pins

Toolchain moves to nightly-2026-09-07 with the clippy fixes its newer lints
require, Rust workspace dependencies are upgraded (base64 0.23, sha2 0.11,
syn 3, reqwest 0.13 with its reworked rustls features, jsonschema 0.55), the
Node native addon moves to napi 3, and GitHub Actions pins advance to their
latest releases. No behavioral changes: the clippy fixes are test-only
assertions, and dead workspace dependency entries are removed.
