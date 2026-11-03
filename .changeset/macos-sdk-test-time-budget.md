---
rust:monosecret: patch
---

# Allow cold macOS SDK validation to finish

The macOS test job has a two-hour budget for environment setup, Rust and
Dart tests, and native language SDK builds and tests. This avoids cancelling
successful cold runs during Swift compilation. Linux keeps its existing
one-hour budget, and every test suite still runs.
