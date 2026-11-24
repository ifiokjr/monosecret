---
title: Monosecret vs. SecretSpec
description: How Monosecret differs from upstream SecretSpec, what it keeps synced, and whether the original fork features were subsumed upstream
---

Monosecret started as a fork of upstream
[SecretSpec](https://github.com/cachix/secretspec) (`cachix/secretspec`).
Monosecret regularly syncs upstream provider backends, resolver improvements,
and CLI/SDK features while maintaining its own additions for shell/CI loading,
flexible secret filtering, extra cloud/SaaS providers, security hardening, and
AI coding agent integrations.

## Was the original fork feature subsumed by SecretSpec?

**Partially, but not completely.**

Monosecret was originally forked to add targeted secret selection for `run`
(PR #1: `[groups]`, per-secret `groups = [...]`, and
`monosecret run --include` / `--group`), followed shortly after by shell and CI
environment emission (PR #14: `monosecret env` / `load-env`).

Upstream SecretSpec later introduced
[`[scopes]` and `--scope`](/concepts/scopes/), which Monosecret also carries
from upstream. However, `[scopes]` only covers part of what Monosecret's
filtering and shell-loading workflow provides:

| Capability                                                                    | Upstream SecretSpec (`[scopes]`)     | Monosecret (`[scopes]` + `[groups]` + `--include` + `env`)                      |
| ----------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------- |
| Single predefined allowlist per service/task                                  | Yes (`--scope <name>`)               | Yes (`--scope <name>`)                                                          |
| Ad-hoc secret selection on the command line without editing TOML              | No                                   | Yes (`monosecret run --include DB_URL,API_KEY -- ...`)                          |
| Composable multi-group union filtering                                        | No (one `--scope` at a time)         | Yes (`--group db,auth` or repeated `--group`, plus per-secret `groups = [...]`) |
| Combining named groups and ad-hoc keys                                        | No                                   | Yes (`--group db --include EXTRA_KEY`)                                          |
| Shell eval emission (`bash`, `zsh`, `fish`, `powershell`, `nushell`)          | `export --format shell` (POSIX only) | `monosecret env --shell <shell>` across 5 shells + `dotenv`                     |
| Native CI emission (`$GITHUB_ENV` + multi-line `::add-mask::`, GitLab dotenv) | No                                   | Yes (`monosecret env --shell github` / `gitlab`, atomic `0600` `--output`)      |

In short: if you only need a single static per-service allowlist declared in
`monosecret.toml`, `[scopes]` handles it identically in both projects. If you
want ad-hoc `--include` flags, composable multi-group tags, or native
multi-shell and GitHub Actions / GitLab CI loading via `monosecret env`, those
remain unique to Monosecret.

## Feature and architecture comparison

| Area                                 | Upstream SecretSpec                                                                           | Monosecret                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------ | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Manifest & env prefix**            | `secretspec.toml`, `SECRETSPEC_*`                                                             | `monosecret.toml`, `MONOSECRET_*`                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **Storage providers**                | 35 built-in providers on `main`                                                               | **43 built-in providers**: all upstream providers plus fork-exclusive [`convex`](/providers/convex/), [`digitalocean`](/providers/digitalocean/), [`netlify`](/providers/netlify/), [`pulumi`](/providers/pulumi/), [`railway`](/providers/railway/), [`vercel`](/providers/vercel/), `onepassword_env`, and early adoption of [`sqlite`](/providers/sqlite/) (with hash-chained history + `verify-history`), [`bt-pws`](/providers/bt-pws/), and Infisical CLI login + `?personal=true` |
| **Filtering & shell/CI loading**     | `[scopes]` / `--scope`, `export`                                                              | `[scopes]` / `--scope`, `[groups]` / `--group`, `--include`, and `monosecret env` (`bash`, `zsh`, `fish`, `powershell`, `nushell`, `dotenv`, `github`, `gitlab`)                                                                                                                                                                                                                                                                                                                         |
| **AI agent credential helpers**      | `claude` (merged), `codex` (upstream PR #380)                                                 | [`claude`](/integrations/claude-code/), [`codex`](/integrations/codex/), and Monosecret-exclusive [`pi`](/integrations/pi/) (covers 30+ AI providers via Pi's `!command` auth), plus an [AI Agents guide](/integrations/ai-agents/)                                                                                                                                                                                                                                                      |
| **Audit log integrity**              | Local JSONL audit log                                                                         | Local JSONL audit log with **tamper-evident SHA-256 hash chaining** and `monosecret audit --verify`                                                                                                                                                                                                                                                                                                                                                                                      |
| **Cache security defaults**          | Provider cache configurable                                                                   | **Refuses plaintext cache stores by default** unless `allow_plaintext = true` is explicitly opted in                                                                                                                                                                                                                                                                                                                                                                                     |
| **Process hardening**                | Standard process execution                                                                    | Non-dumpable process hardening (`PR_SET_DUMPABLE` on Linux, `PT_DENY_ATTACH` on macOS) and `cargo-deny` supply-chain CI checks                                                                                                                                                                                                                                                                                                                                                           |
| **Output redaction & file delivery** | Automatic `run` output redaction, terminal-aware stream, `file-lease` memory-backed `as_path` | Full parity — automatic `run` output redaction (with ANSI preservation), `Redactor` / `TerminalRedactionStream` / `end_region()`, and `FileLease` memory-backed `as_path` across CLI, Rust, FFI, and SDKs                                                                                                                                                                                                                                                                                |
| **Provider runtime**                 | Native `AsyncProvider` + `ProviderBase` + `SyncProviderAdapter`                               | Full parity, including hardened native-async `bt-pws`                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Language SDKs**                    | Rust, Python, Go, Ruby, Node.js/TypeScript, Haskell, PHP, C#, Swift, JVM, Elixir              | Rust (including `<= 64 KiB` Wasm `client` crate), **Dart** (`monosecret` + typed `monosecret_builder`), Python, Go, Ruby, Node.js/TypeScript, Haskell, PHP, C#, Swift _(note: Monosecret does not currently ship the upstream JVM or Elixir SDKs)_                                                                                                                                                                                                                                       |
| **Distribution & release tooling**   | Cargo, Nix, Homebrew, GHCR                                                                    | Cargo, npm (`@monosecret/cli`, `@monosecret/client`, `@monosecret/skill`), Dart pub, Nix/devenv, managed via `monochange`                                                                                                                                                                                                                                                                                                                                                                |

## Choosing between them

- **Stay on Monosecret** when you rely on `monosecret env` (especially GitHub
  Actions `$GITHUB_ENV` masking or fish/PowerShell/Nushell loading), ad-hoc
  `--include` / multi-group `--group` filtering, any of the platform providers
  (`vercel`, `netlify`, `railway`, `convex`, `digitalocean`, `pulumi`,
  `onepassword_env`), the Dart SDK, the `pi` coding agent integration, or
  Monosecret's tamper-evident audit chain and plaintext-cache refusal defaults.
- **Consider upstream SecretSpec** if you specifically need the JVM or Elixir
  SDKs or want to stay directly on `cachix/secretspec`'s Nix/devenv ecosystem
  conventions (`secretspec.toml` / `SECRETSPEC_*`).

## Keeping manifests portable

Aside from Monosecret-only keys (`[groups]`, per-secret `groups = [...]`,
Monosecret-only providers, and `allow_plaintext` on cache stores), the
`monosecret.toml` schema mirrors upstream `secretspec.toml`: `[project]`,
`[defaults]`, `[providers]`, `[profiles.*]`, `[scopes.*]`, `ref`/`refs`,
`composed`, `from`/`extract`, `encoding`, `as_path`, `generate`, and `prompt`
all follow the same declarative model.
