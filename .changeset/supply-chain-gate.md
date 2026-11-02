---
rust:monosecret: fix
---

# Gate every pull request on the dependency advisory database

CI now runs `cargo deny` against the whole workspace lockfile: RustSec
advisories, the license allow list in `deny.toml`, duplicate-version and
wildcard policy, and permitted registry sources. The first run surfaced
seventeen live advisories nobody had seen.

The AWS Secrets Manager and Parameter Store providers no longer pull the
end-of-life hyper 0.14 + rustls 0.21 TLS client, which carried four
unpatched certificate-verification and session-secret advisories; they use
the same rustls 0.23 + aws-lc stack as every other HTTP provider. Lockfile
updates clear the remaining fixable advisories in `tokio`, `ctutils`, and a
yanked `yoke-derive` and `async-executor` releases. The PHP extension uses
ext-php-rs 0.16 with ZIP 9 and zstd 0.14, removing the vulnerable archive
build dependencies and their advisory exceptions. Only the `rsa` and
`crypto-bigint` timing advisories during local key generation remain
ignored in `deny.toml`, with an exposure assessment and the condition that
retires each ignore.
