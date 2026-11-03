---
rust:monosecret: patch
---

# Prepare runner disk space for every Ubuntu job

Development-environment setup now frees unused Ubuntu runner SDKs and
Docker images by default. This gives documentation, lint, benchmark, and
feature-check jobs the same disk preparation as builds and coverage, so
installing the shared environment does not exhaust the runner's disk.
Other platforms are unaffected, and callers can still opt out explicitly.
