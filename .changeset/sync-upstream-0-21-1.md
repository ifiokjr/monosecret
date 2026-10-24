---
rust:monosecret: feat
rust:monosecret_rpc: fix
---

# Sync upstream 0.21.1 and post-release work

Ports the upstream range accumulated since the 0.4.0 sync, keeping every
fork-specific fix and provider. The headline additions:

- **Credential generators and X.509 identities.** New generation types —
  passphrases and BIP-39 mnemonics, WireGuard and JWK private keys, age
  identities, and self-signed `x509_identity` PKCS#12 archives — plus typed
  conversion targets (`pkcs12`, `pkcs8_private_key`, `x509_certificate`,
  `x509_certificate_chain`, `x509_issuer_chain`) with `from`/`format`/
  `credentials` declarations decoded through the new `typed` module.
- **Transient failure retries.** Provider reads share a bounded exponential
  retry policy across HTTP, SDK, CLI, and external transports; unknown errors
  stay permanent and writes opt in only with a replay-safety guarantee.
  Per-provider hand-rolled retry (Doppler's rate-limit handling) folds into
  the shared policy.
- **Wire compatibility hardening.** The RPC crate accepts additive version 1
  response/result members, bounds JSON integers to the 2^53-1 safe range in
  both directions, and the C resolver mirrors both rules for portable peers.
- **Profile-aware import.** `monosecret import --profile` selects the profile
  both sides of an import resolve against.
- **Unknown-field warnings.** Secret declarations ignore unknown fields with
  a warning instead of silently dropping them.
- **Public provider listing.** `monosecret::providers()` exposes built-in
  provider metadata, including feature-gated entries with their enabling
  feature.

Also ports `monosecret init`'s schema directive on generated manifests,
safer `block_on` for current-thread runtimes, `ResolvedSecret` Debug redaction
(already independently hardened in the fork, whose stronger path redaction is
kept), the fake-provider-CLI test harness that avoids ETXTBSY on Linux, and
removal of the dead root test crate.

Beyond the 50ff51e8 cutoff, the sync also lands the follow-up upstream
fixes: `monosecret check` no longer persists decrypted `as_path` temp
files it never prints (they now drop with the command — verified by
regression tests pinning `get`/`export` persistence), keepass moves to
0.13.21 to fix KDBX DeletionTime serialization, and Proton Pass refs
gain read-only `field` selection (values never travel through pass-cli
arguments, which would expose them in the process list).

Dependency advisories found by `cargo audit` are addressed where a fixed
release exists: rustls 0.23.46 (secret-exposing Debug impls, KEX
downgrade), rustls-webpki 0.103.16 (distrusted-intermediate acceptance),
and webpki-root-certs 1.0.11 (emSign distrust). The legacy rustls 0.21
chain pinned under the AWS SDK stack and the unfixed `rsa` Marvin
advisory remain and are tracked as accepted risk.
