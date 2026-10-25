---
rust:monosecret: patch
rust:monosecret_ipc_resolver: patch
---

# Security hardening from the deep audit

Fixes every actionable finding from a second, line-by-line security audit
of the provider layer, secret lifecycle, CLI surface, C resolver, and
packaging:

- **bws**: `monosecret set` against `bws://` is now opt-in behind
  `MONOSECRET_BWS_ALLOW_ARGV_VALUES=1`. The bws CLI only accepts a secret
  value as a command-line argument, which exposes it in the process list;
  the same reasoning already made Proton Pass field refs read-only.
- **env/export integrity**: `monosecret env` now refuses non-UTF-8 secrets
  with the `as_path` guidance instead of silently emitting lossy
  replacement characters that differ from what `run` injects; non-ASCII
  secret names are rejected at emission (bash cannot source them);
  `env --output` refuses symlinked paths, tightens a pre-existing loose
  file to 0600, and `monosecret init` refuses a symlinked `monosecret.toml`.
- **dotenv/age**: parse errors now report position and kind only — the
  dependency's error Display prints the raw offending line, which in age's
  case is decrypted plaintext. dotenv and age stores refuse symlinked
  paths on read as well as write, and the age store writes atomically
  (staged 0600 + fsync + rename) instead of a world-readable in-place
  truncate.
- **file provider**: entries are read with `O_NOFOLLOW`, closing the
  check-then-read window where a racing writer could swap an entry for a
  symlink.
- **vault/openbao**: `tls=false` is refused for non-loopback hosts — the
  request token would cross the network in cleartext.
- **manifests**: `generate.length`/`generate.bytes` are bounded
  (1..=4096) so a fat-fingered length errors instead of aborting the
  process on an uncatchable allocation failure; case-folded duplicate
  secret names are rejected because the Windows environment collapses
  them nondeterministically; `init --from dotenv://` skips keys that are
  not valid secret names instead of writing a manifest that fails its own
  validation.
- **hygiene**: value-bearing wire structs (Bitwarden items, Cloudflare and
  Setec payloads) print `[REDACTED]` in Debug; the shell export buffer is
  zeroized; `ValidationErrors` Debug no longer carries default values;
  the docker credential helper writes diagnostics to stderr per the
  helper protocol; `monosecret run`'s env is unchanged.
- **C resolver**: returned buffers are defensively NUL-terminated (an
  unterminated allocation let error strings overread adjacent heap);
  `ss_set_error` keeps truncated messages instead of dropping them; the
  server-advertised methods array is capped so the pairwise duplicate
  check cannot be driven quadratically by a hostile endpoint; prompt
  answers reject embedded NUL like every other string field; the header
  now documents that frees must be serialized with in-flight calls on the
  same client.
- **PHP FFI installer**: a failed checksum-sidecar fetch now fails closed
  instead of installing the library unverified.
- **tempfile**: the `getrandom` feature is restored so temp-file names
  reseed from OS entropy in minimal/FFI builds.
