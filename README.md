<!-- {=projectReadme} -->

<div align="center">
  <a href="https://ifiokjr.github.io/monosecret/">
    <img src="docs/src/assets/logo.png" alt="Monosecret lock logo" width="96" height="96" />
  </a>

<h1>Monosecret</h1>

<p><strong>Declare secrets once. Store them anywhere.</strong></p>

<p>
    A declarative secrets manager for development workflows. Commit the secrets your app
    needs in <code>monosecret.toml</code>; keep the actual values in keyring, 1Password,
    Vault, AWS, GCP, Bitwarden, dotenv, env vars, or another provider.
  </p>

<p>
    <a href="https://github.com/ifiokjr/monosecret/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ifiokjr/monosecret/ci.yml?branch=main&label=ci&style=flat-square" /></a>
    <a href="https://codecov.io/gh/ifiokjr/monosecret"><img alt="Code coverage" src="https://img.shields.io/codecov/c/github/ifiokjr/monosecret?style=flat-square" /></a>
  </p>

<p>
    <a href="https://ifiokjr.github.io/monosecret/"><strong>Documentation</strong></a>
    |
    <a href="https://ifiokjr.github.io/monosecret/quick-start/">Quick Start</a>
    |
    <a href="https://crates.io/crates/monosecret">Crates.io</a>
    |
    <a href="https://docs.rs/monosecret">docs.rs</a>
    |
    <a href="https://discord.gg/naMgvexb6q">Discord</a>
  </p>
</div>

---

## Why Monosecret?

Secrets usually drift into `.env` files, Slack messages, per-machine notes, and CI
settings nobody can audit. Monosecret separates **declaration** from **storage**:

- **Declare** required secrets in versioned `monosecret.toml` files.
- **Store** values in the provider that fits each environment.
- **Run** apps with secrets injected only at runtime.
- **Validate** onboarding, CI, and deploy requirements before they fail later.

## Quick start

```shell-session
$ monosecret init --from .env
$ monosecret config init
$ monosecret check
$ monosecret run -- npm start
```

```toml
[project]
name = "my-app"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
REDIS_URL = { description = "Redis cache", required = false }

[profiles.production]
DATABASE_URL = { providers = ["vault", "keyring", "env"] }
```

## Features

- **Declarative configuration** - define secret names, descriptions, defaults,
  generation rules, scopes, groups, and profile-specific overrides.
- **43 storage backends** - keyring, dotenv, environment variables, SQLite (with
  opt-in hash-chained history and `verify-history`), 1Password, Bitwarden,
  Vault/OpenBao, AWS Secrets Manager and Parameter Store, Google Cloud Secret
  Manager, Azure Key Vault and App Configuration, BeyondTrust Password Safe,
  Kubernetes, SOPS, age, Doppler, Infisical, Vercel, Netlify, Railway, Convex,
  DigitalOcean, Pulumi ESC, and more. See the
  [provider reference](https://ifiokjr.github.io/monosecret/reference/providers/).
- **Safe process execution & CI loading** - `monosecret run` automatically
  redacts resolved secrets from stdout/stderr (with ANSI terminal preservation),
  supports memory-backed `as_path` file delivery, ad-hoc `--include` /
  multi-group `--group` filtering, and `--config-env=clear`; `monosecret env`
  loads bash, zsh, fish, PowerShell, Nushell, dotenv, GitLab CI, and GitHub
  Actions (`$GITHUB_ENV` with multi-line `::add-mask::`).
- **AI coding agent integrations** - native credential helpers for
  [Claude Code](https://ifiokjr.github.io/monosecret/integrations/claude-code/),
  [OpenAI Codex CLI](https://ifiokjr.github.io/monosecret/integrations/codex/),
  and [Pi coding agent](https://ifiokjr.github.io/monosecret/integrations/pi/)
  (30+ AI providers), plus a guide for
  [Google Antigravity, Gemini CLI, and other agents](https://ifiokjr.github.io/monosecret/integrations/ai-agents/).
- **Type-safe Rust SDK** - generate strongly typed Rust structs from
  `monosecret.toml` at compile time, plus a `<= 64 KiB` Wasm client.
- **SDKs for ten languages** - Rust, TypeScript, Python, PHP, Ruby, Go, Dart,
  Swift, C#, and Haskell bindings sit on the same Rust core and pass one shared
  conformance suite.
- **Auditable, hardened access** - require human-readable reasons, keep
  tamper-evident SHA-256 hash-chained local access logs (`monosecret audit --verify`),
  and refuse plaintext caches by default.

## Install

```shell-session
$ npm install --global @monosecret/cli
```

See the [installation guide](https://ifiokjr.github.io/monosecret/quick-start/#installation)
for Nix, devenv, and other options.

## Repository layout

- `crates/` - Rust crates: the `monosecret` library and CLI, the derive macro,
  the FFI layer, and the RPC wire protocol.
- `npm/` - npm packages, including the TypeScript client and CLI wrapper packages.
- Language SDKs: `dart/`, `python/`, `php/`, `ruby/`, `go/`, `swift/`, `dotnet/`,
  and `haskell/`.
- `conformance/` - the cross-SDK conformance suite and its IPC runner.
- `schema/` - JSON Schemas for the resolution report and wire protocols.
- `docs/` - the documentation site.
- `examples/` - examples across supported ecosystems.

## Building from source

```shell-session
$ cargo build --release
```

This builds the CLI crate only. Building the full workspace (FFI, npm, PHP,
Python, and example crates) additionally requires the `php`, `python`, and
`node` toolchains — devenv provides all of them — and is selected explicitly
with `cargo build --workspace`.

## Learn more

- [Monosecret vs. SecretSpec](https://ifiokjr.github.io/monosecret/concepts/monosecret-vs-secretspec/)
- [Configuration reference](https://ifiokjr.github.io/monosecret/reference/configuration/)
- [Provider reference](https://ifiokjr.github.io/monosecret/reference/providers/)
- [AI coding agents & providers](https://ifiokjr.github.io/monosecret/integrations/ai-agents/)
- [CI/CD setup](https://ifiokjr.github.io/monosecret/guides/ci/)
- [Rust SDK](https://ifiokjr.github.io/monosecret/sdk/rust/)

<!-- {/projectReadme} -->
