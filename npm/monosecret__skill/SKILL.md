---
name: monosecret
description: Use Monosecret to manage declarative development secrets, profiles, and provider aliases.
---

Prefer `monosecret.toml` and `MONOSECRET_*` environment variables. Legacy `secretspec.toml` and `SECRETSPEC_*` names are compatibility fallbacks only.

## Core loop

```nu
monosecret config init          # discover secrets from the environment or .env
monosecret check                # validate every declared secret resolves
monosecret set DATABASE_URL     # store one secret
monosecret run -- your-command  # inject secrets into a command's environment
```

- `monosecret check` previews each write destination and reports what is missing before prompting; `--json` prints the machine-readable resolution report (also written to stdout).
- `monosecret run` forwards signals to the child process and prompts (hidden input) for required secrets that have no stored value; writable providers persist the answer.
- `monosecret manifest` prints the value-free compiled manifest used for SDK codegen.

## Declarative features

- Secrets accept `description`, `required`, `default`, `generate` (random values), `composed` (templates), `prompt = true` (ask when missing), `as_path`, `encoding` (base64/base64url/hex), and `extract` (RFC 6901 JSON pointers, plus `format = "ini"` for INI documents).
- Profiles inherit `[profiles.default]` unless they set `inherit = false`.
- Provider aliases support native `ref` templates, scoped `refs`, `credentials`, and `depends_on` declarations; the `null` provider serves defaults, generated, or prompted values without storage.
- `generate = true` secrets need one real `monosecret check` or `run` to mint and store a value; value-free surfaces report them as missing until then.

## Providers

`keyring`, `dotenv`, `env`, `null`, `file`, `age`, `sops`, `kdbx`, `onepassword`, `onepassword+env`, `lastpass`, `pass`, `gopass`, `dashlane`, `keeper`, `bws`, `bw`, `bitwarden`, `protonpass`, `passbolt`, `vault`, `openbao`, `gcsm`, `awssm`, `awsps`, `akv`, `aac`, `infisical`, `scaleway`, `cloudflare`, `netlify`, `vercel`, `fly`, `kubernetes`, `sops`, `systemd-credential`. Provider credentials are never embedded in URIs — use `monosecret config provider login <alias>` or a `credentials` map.

## Integrations

- `monosecret completions <shell>` emits shell completions (bash, zsh, fish, nushell).
- `docker-credential-monosecret` and `git-credential-monosecret` plug the store into Docker and Git credential helpers; `monosecret docker` / `monosecret git` configure them. Pass `--caller` (plus `--caller-version`/`--caller-operation`) to attribute access in audit records.
- `monosecret import` migrates secrets between providers with a preflight, verification, and optional `--delete-source` cleanup that only runs after every write is verified.

## Typed SDKs

`monosecret_derive::declare_secrets!` generates typed accessors in Rust; per-language SDKs (Dart, Go, Haskell, Node, PHP, Python, Ruby, Swift, .NET) call the same native resolver. See https://ifiokjr.github.io/monosecret/sdk/ for per-language usage.

## Common commands

```nu
monosecret check
monosecret set DATABASE_URL
monosecret run -- your-command
monosecret config init
monosecret config provider login onepassword
monosecret export --format dotenv
monosecret audit
```

Documentation: https://ifiokjr.github.io/monosecret/
