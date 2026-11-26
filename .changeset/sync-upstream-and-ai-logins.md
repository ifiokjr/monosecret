---
"rust:monosecret": feat
"rust:monosecret_ffi": feat
"rust:monosecret_rpc": fix
"@monosecret/client": feat
"dart": feat
---

# Sync upstream SecretSpec, new providers, and AI logins

- **New & upgraded providers (43 total)**:
  - Add the `sqlite` provider (`sqlite:PATH[?history=true]`) with opt-in append-only SHA-256 hash-chained history and `monosecret verify-history` / `Provider::verify_history()`.
  - Add the hardened, native-async, read-only `bt-pws` (BeyondTrust Password Safe) provider supporting API key + run-as + PAT/MFA and OAuth client credentials, with enforced HTTPS on remote endpoints, disabled redirects, URI credential rejection, and explicit sign-out error reporting.
  - Upgrade the `infisical` provider with Infisical CLI (`>= 0.44.0`) login fallback, `?personal=true` personal overrides, and deferred withheld-value refusal on batch reads.
  - Add Bitwarden (`bw`) `session` provider credential support and SOPS (`sops`) secret deletion support.
- **Core runtime & CLI upgrades**:
  - Add native `AsyncProvider` / `ProviderBase` / `SyncProviderAdapter` / `AsyncProviderAdapter` provider APIs.
  - Add automatic child stdout/stderr output redaction in `monosecret run`, terminal-aware ANSI control preservation (`TerminalRedactionStream`), and `RedactionStream::end_region()`.
  - Add memory-backed `as_path` file delivery (`FileLease`, `FileStorageMode::FileLease`, `Secrets::set_as_path_materializer`) and `file_lease_id` / `release_files` / `read_file` support across FFI and all language SDKs.
  - Add `monosecret config show` (computed configuration with provenance), `monosecret run --config-env <inherit|clear>`, and `monosecret add --optional | --required`.
  - Fix `monosecret check` temp-file cleanup, `monosecret check --json` / `--explain` streaming, and double-wrapped undeclared secret diagnostics.
- **AI coding agent integrations & documentation**:
  - Update `monosecret claude`, add `monosecret codex` (OpenAI Codex CLI native command-backed bearer auth), and add `monosecret pi` (Pi coding agent `!command` auth covering 30+ AI providers).
  - Add comprehensive documentation for AI coding agents (including Google Antigravity CLI, Gemini CLI, and other agents) and a dedicated **Monosecret vs. SecretSpec** comparison guide.
