---
"@monosecret/cli": fix
"@monosecret/client": fix
---

# Align native npm dependencies with workspace packages

Use workspace references for native npm optional dependencies so local package
resolution stays in sync. pnpm resolves them to matching package versions
when packing. Use monochange 0.21.0 for workspace checks and release planning,
normalize existing changeset
entries and shorten the passbolt test note to satisfy the release-note rules.
Record three historical secret-scan false positives for generated key header
assertions and a public SwiftPM checksum, using exact finding fingerprints.
