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
