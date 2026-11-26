---
"rust:monosecret": feat
---

# Add ephemeral secrets and 1Password live OTP resolution

- **1Password OTP resolution (`type = "otp"`)**:
  - Resolve live one-time password codes instead of stored `otpauth://` seeds via `op read --no-newline "op://...?attribute=otp"`, `op item get --otp`, and the `totp` field of batched `op item get --format json` responses.
  - Detect non-`OTP` field types and missing OTP fields with clear errors, and never silently fall back to the `otpauth://` seed or `op inject` on batched or single reads.
  - Reject `monosecret set` and `monosecret delete` on `type = "otp"` declarations so OTP seeds stay managed directly in the provider.
- **Ephemeral on-demand secrets (`ephemeral = true`)**:
  - Exclude `ephemeral = true` declarations from default profile resolution (`run`, `export`, `env`, `check`, `validate`, `resolve`, `import`, and typed codegen), resolving them only when explicitly named via `get`, `--include`, a `[scopes]` list, `resolve_named`, or `serve`.
  - Add `--include` and `--group` filtering to `monosecret export` (`Secrets::export_filtered`), matching `run` and `env`.
  - Structurally refuse caching for `ephemeral = true` and `type = "otp"` secrets at the `cache.rs` boundary (`Cacheability`, `CacheEncodeError::EphemeralSecret`, `CacheEntryStatus::RefusedEphemeral`), on `ProviderValue`, during route planning (`plan.rs`), and in cache read/write helpers (`secrets.rs`).
