---
rust:monosecret: docs
---

# Keep the README's provider count pinned to the registry

The README claimed eleven storage backends while the provider registry
ships forty-one, and the repository layout omitted the eight non-Rust
language SDKs, the conformance suite, and the schema directory. The
README now states the real count and describes the real layout, a new
registry test fails whenever the advertised count drifts from the
registered providers, and the one-off agent session reports committed to
the repository root (`context.md`, `PR-CHANGES.md`, `sync-report.txt`)
are gone along with their ignore-list entries. mdt's machine-local index
cache is no longer tracked, so `mdt check` and `dprint` stop rewriting
each other's output.
