---
title: monosecret.toml Reference
description: Complete reference for monosecret.toml configuration options
---

## monosecret.toml Reference

The `monosecret.toml` file defines project-specific secret requirements. This file should be checked into version control.

### Editor autocomplete

:::caution[Version compatibility]
Added in Monosecret 0.4.0.
:::

Add this comment at the top of `monosecret.toml` to enable completion, hover
descriptions, and structural validation in editors using Taplo, including the
Even Better TOML extension for VS Code:

```toml
#:schema https://ifiokjr.github.io/monosecret/schema/monosecret.schema.json
```

For the user configuration, typically `~/.config/monosecret/config.toml`, use:

```toml
#:schema https://ifiokjr.github.io/monosecret/schema/config.schema.json
```

These are [Taplo schema directives](https://taplo.tamasfe.dev/configuration/directives.html#the-schema-directive),
so they remain ordinary comments to Monosecret. The schemas describe the current
`main` branch; fields marked with a minimum version may require a newer release
than your installed CLI. Editor validation catches structural errors and unknown
fields; Monosecret still checks inheritance, references, provider support, and
other semantic constraints when loading the configuration.

You can also download the [project schema](/schema/monosecret.schema.json) or
[user schema](/schema/config.schema.json) and point the directive at a local path
for offline use. Each schema is self-contained.

With Monosecret 0.4.0+, generate the schema from your installed CLI to match its
configuration types:

```bash
monosecret schema --config project --output monosecret.schema.json
monosecret schema --config global --output config.schema.json
```

Then use `#:schema ./monosecret.schema.json` in a project manifest, or point the
user configuration's directive at the generated `config.schema.json`. These
commands need no project or user configuration and never contact a provider.

### [project] Section

<!-- monosecret-test: project -->

```toml
[project]
name = "my-app"           # Project name (required)
revision = "1.0"          # Format version (required, must be "1.0")
extends = ["../shared"]   # Paths to parent configs for inheritance (optional)
require_reason = "agents" # When to require a reason for secret access (optional)
```

| Field            | Type                  | Required | Description                                                                                                                          |
| ---------------- | --------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `name`           | string                | Yes      | Project identifier                                                                                                                   |
| `revision`       | string                | Yes      | Format version (must be "1.0")                                                                                                       |
| `extends`        | array[string]         | No       | Paths to parent configuration files                                                                                                  |
| `require_reason` | `"agents"` \| boolean | No       | When secret access must supply a reason (via `--reason`, `MONOSECRET_REASON`, or the SDK's `with_reason()`). Defaults to `"agents"`. |

The `1.0` revision is backward compatible: newer Monosecret versions continue
to support existing `revision = "1.0"` configurations, although they may add
features to the revision before Monosecret 1.0 is released. With the Monosecret
1.0 release, revision `1.0` will be finalized. Later configuration format
changes may be introduced under new revision numbers.

#### Requiring a reason for secret access

`require_reason` controls when monosecret demands a reason for accessing secrets.
It accepts three values:

| Value                | Behavior                                                                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"agents"` (default) | Require a reason only when Monosecret heuristically classifies the current process as an AI agent. Sessions not classified as agents are unaffected. |
| `true`               | Require a reason from every caller using Monosecret (humans, CI, and agents).                                                                        |
| `false`              | Never require a reason.                                                                                                                              |

The policy is enforced at Monosecret's secret-access entry points and travels
with the checked-in `monosecret.toml`. With `true`, every caller using the
manifest must supply a reason before Monosecret proceeds:

```bash
# In a session Monosecret detects as an agent, with the default "agents" policy:
$ monosecret run -- ./deploy.sh
Error: Accessing secrets requires a reason. Provide one with --reason "<why...>" ...

$ monosecret run --reason "Deploy web frontend" -- ./deploy.sh   # ok
```

:::caution[Agent detection is heuristic]
The default `"agents"` policy depends on detection. It can miss an unknown or
changed agent and can classify a session incorrectly. Use
`require_reason = true` when every Monosecret caller must supply a reason.
:::

**Agent detection.** monosecret delegates heuristic detection of known agents to the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate, which
maintains the per-tool signal list (Claude Code, Cursor, Codex, Gemini CLI,
Copilot, and more). It treats **autonomous and hybrid** environments as agents but
not human-driven interactive editors. In addition, monosecret checks its own
`MONOSECRET_AGENT` environment variable as an explicit opt-in:

```bash
# Mark any harness the detector does not recognize as an agent:
$ export MONOSECRET_AGENT=1
```

Cooperative harnesses that are not auto-detected can set `MONOSECRET_AGENT=1`.
Do not rely on a caller to identify itself when a reason is mandatory; use
`require_reason = true` instead.

The reason is recorded in monosecret's own [audit log](/concepts/audit/) and is
also forwarded to providers that support auditing (e.g. the
[Proton Pass](/providers/protonpass/) provider records it in the agent audit log).

### [defaults] Section (0.4.0+)

Set one project-wide provider chain for provider-backed secrets that do not
choose providers themselves or through their active profile:

```toml title="monosecret.toml"
[defaults]
providers = ["developer"]
```

| Field       | Type          | Required | Description                                                                                                   |
| ----------- | ------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `providers` | array[string] | Yes      | Non-empty default provider chain for every profile. Entries may be aliases, provider names, or provider URIs. |

Project defaults deliberately accept only `providers`: a literal fallback value
or requiredness policy rarely makes sense for every secret in every profile.
The chain may name an alias defined in the project `[providers]` table or only
in the current user's `[defaults.providers]` table. A secret-level chain wins,
followed by `[profiles.<name>.defaults].providers`, this project default, and
finally the user-global default provider.

```toml title="monosecret.toml"
[defaults]
providers = ["developer"]

[profiles.default]
DATABASE_URL = { description = "Development database URL" }
API_TOKEN = { description = "Development API token" }
```

Each developer can define `developer` in their own user configuration:

```toml title="~/.config/monosecret/config.toml"
[defaults.providers]
developer = "keyring://"
```

The project `[defaults].providers` selects a chain; the user
`[defaults.providers]` table defines alias names. Every developer or CI runner
using a user-only alias must define it in their own configuration. A project
`[providers]` entry with the same name takes precedence over that user alias.

### [profiles.*] Section

Defines secret variables for different environments. At least one profile is
required. A `default` profile is optional; when present, other profiles inherit
from it unless they opt out in Monosecret 0.2+.

```toml
[profiles.default] # Optional shared base profile
DATABASE_URL = { description = "PostgreSQL connection", required = true }
API_KEY = { description = "External API key", required = true }
REDIS_URL = { description = "Redis cache", required = false, default = "redis://localhost:6379" }

[profiles.production] # Additional profile (optional)
DATABASE_URL = { required = true } # description inherited from default
```

#### Profile defaults

`[profiles.<name>.defaults]` supplies settings for secrets declared in that
profile:

| Field            | Type          | Required | Description                                                                                                             |
| ---------------- | ------------- | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `inherit` (0.2+) | boolean       | No       | For a non-default profile, whether to inherit declarations and omitted fields from `[profiles.default]` (default: true) |
| `required`       | boolean       | No       | Default requiredness for secrets declared in this profile                                                               |
| `default`        | string        | No       | Default value for secrets declared in this profile                                                                      |
| `providers`      | array[string] | No       | Default provider chain for secrets declared in this profile. Overrides project `[defaults].providers` in 0.4.0+.        |

In Monosecret 0.2+, set `inherit = false` for a standalone profile:

```toml
[profiles.deployment.defaults]
inherit = false

[profiles.deployment]
DEPLOY_TOKEN = { description = "Deployment credential", required = true }
```

This excludes every `[profiles.default]` declaration and prevents explicitly
redeclared secrets from inheriting omitted fields. The setting has no effect on
the `default` profile itself. A standalone profile must declare at least one
secret.

#### Cross-secret presence constraints (0.2+)

:::caution[Version compatibility]
Added in Monosecret 0.2.
:::

A profile can require alternative credentials by assigning secrets to a named
group:

```toml
[profiles.default]
PASSWORD = { description = "Account password", required = { at_least_one = "account_auth" } }
ACCESS_TOKEN = { description = "Personal access token", required = { at_least_one = "account_auth" } }

GITHUB_TOKEN = { description = "GitHub token", required = { exactly_one = "github_auth" } }
GITHUB_APP_KEY = { description = "GitHub App private key", required = { exactly_one = "github_auth" } }
```

`at_least_one` requires one or more group members to resolve; `exactly_one`
requires one. Each field also accepts an array of group names for overlapping
groups. Groups must contain at least two secrets and cannot mix modes. Group
members are individually optional.

Under a [scope](#scopes-section), a group is judged over the members that scope
exposes, so a scoped consumer never inherits a guarantee that rests on a secret
it cannot see.

#### Secret Variable Options

> **Changed in v0.22.**
>
> Unknown fields in secret declarations now produce a warning on standard error
> and are ignored. Earlier versions silently ignored them. The warning suggests
> `composed` when a declaration uses `compose`. Every warning also notes that
> the field may be supported in a newer version of Monosecret.

Each secret variable is defined as a table with the following fields:

| Field             | Type                                  | Required        | Description                                                                                                                                                          |
| ----------------- | ------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `description`     | string                                | Yes (see notes) | Human-readable description of the secret                                                                                                                             |
| `required`        | boolean or table                      | No              | Whether absence is an error; the table form (0.3+) accepts `at_least_one`/`exactly_one` presence groups (defaults to true; false with `default` or a presence group) |
| `default`         | string                                | No              | Default value if not provided                                                                                                                                        |
| `composed` (0.3+) | string                                | No              | Derive a read-only value from other declared secrets using `${UPPERCASE_NAME}` references                                                                            |
| `providers`       | array[string]                         | No              | List of provider aliases to use in fallback order                                                                                                                    |
| `ref`             | table                                 | No              | Coordinates naming an externally managed secret in the provider's store (e.g. `ref = { item = "db", field = "password" }`)                                           |
| `refs` (0.3+)     | table                                 | No              | Provider-alias-scoped coordinates, keyed by leaf alias (e.g. `refs = { source = { item = "old" }, target = { item = "new" } }`); mutually exclusive with `ref`       |
| `as_path`         | boolean                               | No              | Write secret to temp file and return file path (default: false)                                                                                                      |
| `encoding` (0.3+) | `"base64"`, `"base64url"`, or `"hex"` | No              | Encode logical values before storage writes and decode stored values after reads                                                                                     |
| `extract` (0.3+)  | table                                 | No              | Select one logical value from stored JSON (0.3+) or INI (0.3+) data with a pointer                                                                                   |
| `type`            | string                                | No              | Secret type for generation: `password`, `hex`, `base64`, `uuid`, `command`, `rsa_private_key`                                                                        |
| `generate`        | boolean or table                      | No              | Enable auto-generation when secret is missing                                                                                                                        |
| `prompt` (0.3+)   | boolean                               | No              | Securely prompt for a missing value during `monosecret run`; the selected provider controls persistence                                                              |

Field notes:

- `description` is required on the effective secret. An inheriting profile may
  omit it when a matching default declaration supplies it. A standalone
  profile using `inherit = false` (0.2+) must supply its own description.
- `required` defaults to false when `default` is provided. In 0.2+, its table
  form accepts `at_least_one` and `exactly_one` as a group name or array of names.
- `default` is invalid with an explicit `required = true`. A defaulted secret is
  guaranteed to be present in successful resolution and generated types, even
  though the provider does not have to supply it.
- `type` is required when `generate` is enabled.
- `generate` and `default` cannot both be set.
- `prompt = true` (0.2+) is for individually required secrets and cannot be
  combined with `default`, enabled `generate`, `extract`, or `composed`.
- `extract` (0.3+) is read-only and cannot be combined with enabled
  `generate`.
- `from` (0.22+) makes a secret read-only and derived: it needs either
  `extract` or a typed conversion target as its `type`, and cannot declare
  `default`, `providers`, `ref`, `refs`, enabled `generate`, `prompt = true`,
  or `composed`. See [Derived typed secrets](#derived-typed-secrets-050).
- `format` (0.22+) is valid only for types with more than one serialization
  (`pkcs8_private_key` and `x509_certificate`).
- `credentials` (0.22+) is valid only for types that define roles:
  `x509_identity` and `pkcs12` accept `password`. Each value names a declared
  text secret. The `{ provider, ref }` table form is reserved.
- `type = "x509_identity"` (0.22+) is a binary type: it cannot be combined
  with `default` or `prompt = true`, and `encoding` defaults to `base64`.

#### Composed Secrets

:::caution[Version compatibility]
Available since Monosecret 0.2.
:::

:::caution[Version compatibility]
Composition now validates that every inline input is UTF-8. An `as_path`
dependency contributes its path as text.
:::

A composed secret derives a value from other secrets in the effective profile.
See [Composed Secrets](/concepts/composed-secrets/) for the dependency model,
CLI behavior, profile inheritance, and the differences from dotenv expansion:

```toml
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }
DATABASE_URL = { description = "PostgreSQL DSN", composed = "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/app" }
```

References form a static dependency graph. Declaration order does not matter,
and composed secrets may reference other composed secrets. Monosecret rejects
unknown references, cycles, malformed references, and source conflicts while
loading the manifest. A composed secret is read-only and cannot also set
`default`, `providers`, `ref`, `refs` (0.2+), `type`, enabled `generate`,
`encoding` (0.3+), or `extract` (0.3+).

Composition intentionally does **not** implement dotenv or shell expansion:

- only `${UPPERCASE_NAME}` is a reference, and the name must match
  `[A-Z][A-Z0-9_]*` and identify a declared secret;
- ambient environment variables are never consulted;
- fallback operators such as `${NAME:-fallback}`, commands, and recursive
  expansion are unsupported;
- inserted values are opaque and are never scanned again;
- `$$` produces a literal `$` (`$${NAME}` renders `${NAME}`), while ordinary
  braces are literal;
- a missing dependency makes a required composition missing, while a
  `required = false` composition is omitted;
- empty values remain empty and are distinct from missing values.

If a dependency uses `as_path = true`, its exported temporary-file path is the
text inserted into the composed value. Applying `as_path = true` to the
composed secret materializes the final combined value. In Monosecret 0.4.0+,
every other dependency must be valid UTF-8; binary declarations should use
`as_path = true`.

Composition is raw string concatenation. Monosecret cannot know whether a
component occupies a URL username, password, host, path, query, or structured
document position, so it does not URL-encode or JSON-encode components. Store
components in the form required by the target format; use
`monosecret export --format json` when exporting the resolved secret map as
JSON.

### [scopes] Section

:::note[Version compatibility]
Scopes are added in **Monosecret 0.2** and are unavailable in the current 0.2
release. With 0.2, give each service its own profile, or its own
`monosecret.toml`.
:::

See [Scopes](/concepts/scopes/) for the conceptual model and a focused
guide to narrowing services and tasks. This section specifies the complete
configuration and resolution behavior.

Scopes name membership-only subsets of a profile's secrets, so a single service
or task resolves only what it declares instead of the entire profile. They are
**orthogonal to profiles**: a profile decides how each secret resolves
(`required`, `default`, providers, references, generation, prompts (0.2+), `as_path`,
`encoding` (0.3+), `extract` (0.3+), and the storage namespace); a scope only
decides _which_ secrets take part in a given resolution.

```toml
[profiles.default]
DATABASE_URL = { description = "Database", required = true }
API_KEY = { description = "API key", required = true }
QUEUE_TOKEN = { description = "Queue token", required = true }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]

[scopes.worker]
secrets = ["DATABASE_URL", "QUEUE_TOKEN"]
```

```bash
$ monosecret run --scope api    -- ./api      # sees DATABASE_URL, API_KEY

$ monosecret run --scope worker -- ./worker   # sees DATABASE_URL, QUEUE_TOKEN

$ monosecret check  --scope api

$ monosecret export --scope worker --format dotenv
```

Behavior:

- **No scope** resolves the complete profile, exactly as before scopes existed.
- Selecting a scope resolves the **intersection** of the merged profile and the
  scope's `secrets` list — the _visible_ set. A secret the profile does not
  declare is simply absent from that resolution rather than an error, so a scope
  can be reused across profiles that declare different subsets.
- A required secret **excluded** by the active scope does not block resolution —
  it is not part of the scoped set.
- **Composed secrets resolve their inputs without exposing them.** When a visible
  [composed secret](/concepts/composed-secrets/) references secrets the scope
  leaves out (for example `DATABASE_URL` built from `DB_USER` and `DB_PASSWORD`),
  those dependencies are fetched to build the composition and then dropped from
  the output — the child sees `DATABASE_URL`, never `DB_USER`/`DB_PASSWORD`. A
  secret that is neither visible nor a dependency of a visible secret is never
  fetched, so no provider is contacted for it.
- A scope does not change a secret's storage address
  (`{project}/{profile}/{key}`); it only narrows the set.
- **Presence groups are judged over the visible members.** A `required =
  { at_least_one = … }` or `{ exactly_one = … }` group (see
  [Cross-secret presence constraints](#cross-secret-presence-constraints-017))
  is evaluated against the members
  the scope actually exposes. A group with no visible member is not that
  consumer's concern and is not enforced. A group with some visible members is
  enforced over those alone, so a scope never inherits a guarantee that rests on
  a secret it hides — if `at_least_one = "cloud"` is satisfied profile-wide by
  `GCP_KEY`, a scope showing only `AWS_KEY` still fails when `AWS_KEY` is absent.
  `exactly_one` remains enforced whenever two visible members are both present:
  scoping narrows what is judged, never whether it is judged. A secret fetched
  only as a hidden composition input does not count as present, and a violation
  message names only visible members. The reverse case cannot be detected,
  because a secret the scope hides is never fetched: if `exactly_one = "token"`
  is violated profile-wide by both `PRIMARY` and `FALLBACK` being present, a
  scope showing only `PRIMARY` reports success. A scoped check validates the
  scoped consumer, not the profile; run an unscoped `monosecret check` to
  validate the profile as a whole.
- `run --scope` removes **every** manifest-declared secret the scope does not
  admit from the launched command's environment, across _all_ profiles rather
  than only the selected one, **even if the parent shell already exported
  them**, so a value inherited from another profile cannot leak into the child.
  Membership decides this, so a secret the scope lists survives even when the
  selected profile does not declare it (see the admitted rule below). This is
  secret minimization, not an authorization boundary: a process that still holds
  provider credentials could resolve another scope itself.
- `export --scope` **emits** the visible set but unsets nothing, since its
  output formats have no way to express an unset. Narrowing an environment that
  already holds a wider set therefore needs `run --scope`: after
  `eval "$(monosecret export)"`, a later
  `eval "$(monosecret export --scope api)"` leaves the previously exported
  values live in the shell.
- An **empty** scope (or a scope whose intersection with the profile is empty)
  resolves to nothing and contacts no provider.
- **Diagnostics do not name what the scope hides.** A provider warning about a
  hidden composition input calls it `a hidden composition input` rather than
  naming it, matching the way prompting is filtered, so a failing provider
  cannot disclose the very name the output filter removed. A visible secret is
  still named. This covers monosecret's own messages; a provider's error text is
  written by that provider and may still mention the address it searched.
- [Audit](#audit-logging) records what was **read**, not what was exposed: a
  scoped `check` logs the accessed set, including a composition input the scope
  hides, since the point of the log is to capture provider access. A `run` event
  logs what it injected — the visible set. Scoped `check`, `run`, and `export`
  events also carry the selected `scope` name (Monosecret 0.2+).
- An `as_path` secret's resolved value is its temp-file path, so a visible
  composition built from a hidden `as_path` input embeds that path. The file
  stays alive for the duration of the command rather than being cleaned up with
  the hidden secret, so the path resolves. The hidden input is still absent from
  the environment; only its content, in the form the composition derived, is
  reachable — the same contract as a composed DSN that embeds a password.
- A secret the scope **admits** is never scrubbed from `run`, whether it fails
  to resolve (an optional secret with no stored value) or the selected profile
  does not declare it at all. A value the parent exported is inherited exactly
  as it would be without a scope; scoping changes which secrets are in play,
  never the semantics of one it admits. This is what lets a single scope be
  reused across profiles that declare different subsets.
- Under project `extends`, a child `[scopes.<name>]` **replaces** the parent
  scope of the same name outright — the two `secrets` lists are not unioned (see
  [Configuration Inheritance](/concepts/inheritance/)).
- Selecting an undefined scope, or a scope that lists a secret no profile
  declares, is a configuration error.
- A scope's `secrets` list must name at least one secret, with no blank or
  repeated entries. An empty scope is rejected rather than treated as "resolves
  to nothing": it would contact no provider, so `check --scope` would report a
  clean `0 found, 0 missing` while `run --scope` started the command with every
  manifest secret scrubbed and none injected. An empty _intersection_ between a
  valid scope and the selected profile is still fine, since a scope is meant to
  be reused across profiles that declare different subsets.

The `--scope` flag (and the `MONOSECRET_SCOPE` environment variable) apply to
`check`, `run`, and `export`. Scopes are a resolution-time feature of these
untyped paths. The write and copy commands are unaffected: `set` and `import`
ignore an ambient `MONOSECRET_SCOPE` entirely, so a scope neither restricts what
they may write nor narrows the secrets they list. The untyped language SDK
builders also accept an explicit scope and return its name in resolve/report
results, and they honor `MONOSECRET_SCOPE` when given none. The typed SDK
loaders generated by `monosecret_derive` always resolve the **full** profile and
deliberately **ignore** an ambient `MONOSECRET_SCOPE`, since a generated struct
expects every declared field.

A **blank** `--scope` clears an inherited scope rather than being ignored:
`MONOSECRET_SCOPE=api monosecret run --scope "" -- ./job` resolves the whole
profile and scrubs nothing. A blank `MONOSECRET_SCOPE` with no flag means the
same, so a CI template that materializes an unset variable as an empty string
cannot silently narrow a job.

## Complete Example

```toml
# monosecret.toml
[project]
name = "web-api"
revision = "1.0"
extends = ["../shared/monosecret.toml"] # Optional inheritance

# Provider aliases used by profile provider chains
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"

# Default profile - always loaded first
[profiles.default]
APP_NAME = { description = "Application name", required = false, default = "MyApp" }
SESSION_SECRET = { description = "Session signing secret", required = true, providers = [
  "shared_vault",
] }
GITHUB_TOKEN = { description = "GitHub token", required = true, providers = [
  "env",
] }

# Development profile - extends default
[profiles.development]
DATABASE_URL = { description = "Database connection", required = false, default = "sqlite://./dev.db" }
API_URL = { description = "API endpoint", required = false, default = "http://localhost:3000" }
DEBUG = { description = "Debug mode", required = false, default = "true" }

# Production profile - extends default
[profiles.production]
DATABASE_URL = { description = "PostgreSQL cluster connection", required = true, providers = [
  "prod_vault",
  "keyring",
] }
API_URL = { description = "Production API endpoint", required = true }
SENTRY_DSN = { description = "Error tracking service", required = true, providers = [
  "shared_vault",
] }
REDIS_URL = { description = "Redis cache connection", required = true }
```

### Provider Aliases

Provider aliases may be declared in two places:

1. **In `monosecret.toml`** — a top-level `[providers]` table. Check this into version control so every team member and CI runner sees the same mapping out of the box.
2. **In `~/.config/monosecret/config.toml`** — a per-user `[defaults.providers]` table for personal overrides.

On conflict the project-level alias wins, so a stale local config cannot silently shadow the team's mapping.

:::note[Version compatibility]
Provider alias tables with `uri` and `credentials` are available since
Monosecret 0.2. Monosecret 0.1 accepts only bare URI strings; when using
0.1, configure provider credentials through the provider's existing
environment variables, such as `BWS_ACCESS_TOKEN`.
Provider alias `ref` templates are available starting with Monosecret 0.2.
Cached alias tables with `fallback` and `cache` are available since Monosecret
0.2.
:::

<!-- monosecret-test: providers -->

```toml title="monosecret.toml"
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = [
  "prod_vault",
  "keyring",
] }
```

<!-- monosecret-test: global -->

```toml title="~/.config/monosecret/config.toml"
[defaults]
provider = "keyring"

[defaults.providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"
```

Manage user-level aliases via CLI:

```bash
# Monosecret 0.2+: add a provider alias to your user config
$ monosecret config global provider add prod_vault "onepassword://Production"

# Monosecret 0.2+: list all aliases known to your user config
$ monosecret config global provider list

# Monosecret 0.2+: remove an alias from your user config
$ monosecret config global provider remove prod_vault
```

These explicitly scoped CLI commands operate on the user-global config only —
edit `monosecret.toml` by hand to change project-level aliases.

#### Monosecret 0.2 alias values

In Monosecret 0.2 and later, an alias value is either a bare provider URI
string or a table that also declares the credentials the provider needs. Both
forms are accepted in the project `[providers]` and user
`[defaults.providers]` tables.

| Field         | Type   | Required         | Description                                                                                                        |
| ------------- | ------ | ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `uri`         | string | Yes (table form) | The provider URI. A bare-string alias is shorthand for `{ uri = "..." }`.                                          |
| `credentials` | table  | No               | Maps a semantic [provider credential](/reference/provider-credentials/) name to its source.                        |
| `ref` (0.2+)  | table  | No               | Native-address template for this leaf alias. Coordinate strings may contain `{project}`, `{profile}`, and `{key}`. |

Each `credentials` value is either a bare provider spec — read at the convention path for the active project and profile — or a table `{ provider = "...", ref = { ... } }` that pins the exact location with the same `ref` coordinates a secret uses.

```toml title="monosecret.toml"
[providers]
keyring = "keyring://"
# bare string: read access_token from keyring at the convention path
bws = { uri = "bws://project-uuid", credentials = { access_token = "keyring" } }

[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"
credentials = { role_id   = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } },
                secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } } }
```

Configured credentials take precedence over provider environment fallbacks, credential chains are limited to one hop, and a fetched credential is never written to the environment. Store the credentials with [`monosecret config provider login`](/reference/cli/#config-provider-login). See [Provider credentials](/concepts/providers/#provider-credentials) for the full behavior.

For an external provider (0.4.0+), `credentials` is optional and does not need
to enumerate every possible authentication method. The endpoint requests the
semantic names selected by its URI at runtime. A matching table entry overrides
Monosecret's provider-private system-keyring lookup and is fetched lazily; an
entry the endpoint never requests is never read. See the [Secret Provider Protocol](/reference/provider-protocol) and [IPC architecture](/reference/ipc-architecture)
for the external-provider boundary.

Starting with Monosecret 0.2, a leaf alias may also compile logical secret
names into that provider's native coordinates. Templates expand each
placeholder once; text inserted from a project, profile, or key is never
interpreted as another placeholder.

```toml title="monosecret.toml"
[providers]
remote = { uri = "onepassword://Production", ref = { item = "{project}-{profile}", field = "{key}" } }
local = { uri = "dotenv://.env", ref = { item = "{key}" } }

[profiles.production]
API_KEY = { description = "API key", providers = ["remote", "local"] }
```

Templates belong on the leaf aliases in a cached route, not on the cached
alias itself. Bare provider names and literal URIs have no alias identity, so
they use provider convention naming unless the secret declares legacy `ref`.

#### Monosecret 0.2 inline provider cache

:::caution[Version compatibility]
Attaching `cache` directly to an alias with `uri` is available starting with
Monosecret 0.2.
:::

Use `uri` and `cache` when one provider is authoritative. `credentials` remains
optional and configures that same provider:

| Field            | Type   | Required | Description                                                                                                     |
| ---------------- | ------ | -------- | --------------------------------------------------------------------------------------------------------------- |
| `uri`            | string | Yes      | Authoritative provider URI.                                                                                     |
| `credentials`    | table  | No       | Provider-specific credential sources for `uri`.                                                                 |
| `cache`          | table  | Yes      | Local cache policy containing `provider` and `max_age`.                                                         |
| `cache.provider` | string | Yes      | Leaf provider spec used to store cache entries. Must support deletion and address a different store from `uri`. |
| `cache.max_age`  | string | Yes      | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`.                          |

```toml title="monosecret.toml"
[providers]
local = "keyring://monosecret/cache/{project}/{profile}/{key}"
azure = {
  uri = "akv://team-vault",
  credentials = { client_secret = "keyring" },
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["azure"]
```

The alias remains both the selected cached route and the build key for its
authoritative provider, so its configured credentials apply normally.

#### Monosecret 0.2 cached fallback alias values

:::caution[Version compatibility]
Cached provider aliases are available starting with Monosecret 0.2.
:::

A cached fallback alias uses `fallback` and `cache` when more than one provider
can answer:

| Field            | Type          | Required | Description                                                                                                                                                                                                                     |
| ---------------- | ------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fallback`       | array[string] | Yes      | Non-empty authoritative provider route. Reads try entries in order; writes use the first entry.                                                                                                                                 |
| `cache`          | table         | Yes      | Local cache policy containing `provider` and `max_age`.                                                                                                                                                                         |
| `cache.provider` | string        | Yes      | Leaf provider spec used to store cache entries. Must support deletion (keyring, pass, gopass, dotenv, age (0.3+), Azure App Configuration (0.3+), or Vault/OpenBao KV v2) and be a different store from every `fallback` entry. |
| `cache.max_age`  | string        | Yes      | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`.                                                                                                                                          |

```toml title="monosecret.toml"
[providers]
azure = { uri = "akv://team-vault", credentials = { client_secret = "keyring" } }
env = "env://"
local = "keyring://monosecret/cache/{project}/{profile}/{key}"
myprovider = { fallback = [
  "azure",
  "env",
], cache = { provider = "local", max_age = "8h" } }

[profiles.development.defaults]
providers = ["myprovider"]
```

Every cached alias is a complete route and must be the only entry when selected
through `providers`, in any position. Fallback entries and the cache provider
accept aliases, provider names, and URIs, but must resolve to leaf providers;
cached aliases cannot be nested, and the cache must resolve to a different
store than the route's own authoritative providers, since it holds its entries
at the same logical address. The cache provider must also be one Monosecret can
delete from — keyring, pass, gopass, dotenv, age (0.3+), Azure App
Configuration (0.3+), or a Vault/OpenBao KV v2 mount — since every form of
invalidation is a delete. Put credentials on leaf aliases rather than the
cached fallback alias.
See [Provider caching](/concepts/providers/caching/)
for freshness, failure, invalidation, and clearing behavior.

#### Monosecret 0.1 alias values

In Monosecret 0.1, every alias value must be a provider URI string:

```toml title="monosecret.toml"
[providers]
bws = "bws://project-uuid"
```

For example, authenticate the 0.1 BWS provider by setting its environment
variable before running Monosecret:

```bash
$ export BWS_ACCESS_TOKEN="0.your-access-token..."

$ monosecret check
```

Secrets may only reference declared groups. When a profile overrides a secret, omitted `groups` inherit from `[profiles.default]`; explicitly setting `groups = [...]` replaces the default groups rather than merging them.

### Provider References with Path and Key

Per-secret `providers` entries can be either simple alias strings or detailed
reference tables that include a provider-relative `path` and `key`:

```toml
[profiles.default]
# Simple alias — backward compatible.
DATABASE_URL = { description = "Dev DB", providers = ["env"] }

# Detailed provider ref with path and key.
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [
    { provider = "op-dev", path = ["GitHub"], key = "token" }
  ]
}

# Mixed aliases and details in one chain.
API_KEY = {
  description = "External API key",
  providers = ["keyring", { provider = "op-dev", path = ["APIs"] }]
}
```

| Field      | Type          | Required | Description                                                                                     |
| ---------- | ------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `provider` | string        | Yes      | The provider alias name                                                                         |
| `path`     | array[string] | No       | Location path within the provider (e.g. a 1Password section name, or a DigitalOcean key prefix) |
| `key`      | string        | No       | Field key at that path; defaults to the Monosecret secret name                                  |

For 1Password, `onepassword://` keeps the original Monosecret-owned storage behavior. Use `op://` when the provider ref should compose a native 1Password reference:

```toml
[providers]
op = "op://Development/dotfiles"

[profiles.default.GITHUB_TOKEN]
providers = [{ provider = "op", path = ["forges"] }]
# Reads op://Development/dotfiles/forges/GITHUB_TOKEN
```

For DigitalOcean (0.4.4+), the URI pins one secret object and `path` becomes a
key prefix inside it, joined with a double underscore. One request reads the
whole object, however many secrets point into it:

```toml
[providers]
do = "digitalocean://monochange-dev?region=lon1"

[profiles.default.JWT_SECRET]
providers = [{ provider = "do", path = ["auth"] }]
# Reads the key auth__JWT_SECRET in the monochange-dev secret
```

See [Use one DigitalOcean secret per project](/providers/digitalocean/#use-one-digitalocean-secret-per-project).

### as_path Option

:::caution[Version compatibility]
Temporary files now preserve arbitrary secret bytes exactly, including NULs
and trailing newlines.
:::

When `as_path = true`, the secret value is written to a temporary file and the file path is returned instead of the value:

```toml
[profiles.default]
TLS_CERT = { description = "TLS certificate", as_path = true }
GOOGLE_APPLICATION_CREDENTIALS = { description = "GCP service account", as_path = true }
```

In Monosecret 0.4.0+, the file always contains the exact logical bytes. When
combined with `encoding` (0.3+), those are the decoded bytes rather than the
stored representation. When combined with `extract` (0.3+), it contains only
the selected logical value. In 0.4.0+, `get` and Rust's `resolve_bytes()` and
`resolve_named_bytes()` also return binary values inline. `run` preserves
non-UTF-8 inline values on Unix, but environment values cannot contain NULs.
Use `as_path` when an application needs a file. Text SDK responses and text
exports require UTF-8.

| Context             | Behavior                                                                                |
| ------------------- | --------------------------------------------------------------------------------------- |
| CLI `get`, `export` | Files are persisted (not deleted after command exits) because the path is printed       |
| CLI `run`           | Files are deleted after the child process exits                                         |
| CLI `check`         | Files are deleted when the command exits (earlier versions left them behind)            |
| Rust SDK            | Files cleaned up when `ValidatedSecrets` is dropped; use `keep_temp_files()` to persist |
| Rust SDK types      | `PathBuf` or `Option<PathBuf>` instead of `String`                                      |

### Secret Encoding (0.3+)

:::caution[Version compatibility]
Available starting in Monosecret 0.3.
:::

:::caution[Version compatibility]
Encoding now transforms provider bytes rather than Rust strings, so binary
values can be stored through text-only providers. Decoding is strict ASCII:
exactly one trailing LF or CRLF is accepted, and other whitespace is rejected.
:::

`encoding` (0.3+) defines the textual representation stored by providers. It
is independent of the cache envelope and of `as_path`: in 0.4.0+, decoded bytes
can be returned inline by `get` and the Rust byte APIs or materialized to a
file. Text consumers validate UTF-8 separately.

```toml
[profiles.default]
# encoding is available in Monosecret 0.3+
TEXT_CONFIG = { description = "Encoded text", encoding = "base64" }
KEYSTORE = { description = "Binary mTLS keystore", encoding = "base64", as_path = true }
URL_SAFE_KEY = { description = "URL-safe encoded key", encoding = "base64url", as_path = true }
HEX_KEY = { description = "Hex-encoded key", encoding = "hex", as_path = true }
```

| Encoding (0.3+) | Written representation                   | Accepted stored representation             |
| --------------- | ---------------------------------------- | ------------------------------------------ |
| `base64`        | RFC 4648 standard Base64 with padding    | Padded or unpadded standard Base64         |
| `base64url`     | RFC 4648 URL-safe Base64 without padding | Padded or unpadded URL-safe Base64         |
| `hex`           | Lowercase RFC 4648 Base16                | Uppercase, lowercase, or mixed-case Base16 |

In Monosecret 0.4.0+, the stored representation must be ASCII and contain only
the selected encoding's alphabet. Exactly one trailing LF or CRLF is accepted so
command-captured and file-sourced values work without preprocessing; other
whitespace is rejected. Decoded bytes need not be UTF-8 unless the consumer
requires text.

`Secrets::set` and `monosecret set --from-file` (0.4.0+) provide logical bytes;
positional CLI values, interactive prompts, defaults, built-in text generators,
and composed results provide UTF-8 logical bytes. Command generators preserve
arbitrary stdout bytes in 0.4.0+. Monosecret encodes logical bytes before
writing to a provider. The `monosecret import` command copies the stored
representation verbatim, avoiding double encoding.

> **Changed in v0.5.0.**
>
> Binary typed values (`x509_identity` and the `pkcs12` and `der` conversion
> targets) default `encoding` to `base64` and use it wherever their bytes must be
> text: in the provider, in the cache, and inline when `as_path` is not set. With
> `as_path = true` the file holds the raw bytes. `monosecret set` accepts such a
> value in its encoded form. See [Derived typed secrets](#derived-typed-secrets-050).

### Structured Extraction (0.3+)

:::caution[Version compatibility]
Available starting in Monosecret 0.3.
INI extraction with `format = "ini"` is available starting in Monosecret 0.3.
:::

:::caution[Version compatibility]
Extraction rejects non-UTF-8 decoded documents before parsing.
:::

> **Changed in v0.5.0.**
>
> `extract` can now select from the text of another declared secret named by
> `from`. X.509 conversions use `type` and `from` rather than extraction formats;
> see [Derived typed secrets](#derived-typed-secrets-050).

`extract` (0.3+) selects one logical secret from structured text read from a
provider or cache. It supports JSON (0.3+) and INI (0.3+). JSON `pointer`
values are [RFC 6901 JSON Pointers](https://www.rfc-editor.org/rfc/rfc6901):

```toml
[providers]
documents = "file:./secrets"

[profiles.default]
# extract is available in Monosecret 0.3+
DB_USER = {
  description = "Database user",
  providers = ["documents"],
  ref = { item = "application.json" },
  extract = { format = "json", pointer = "/database/user" }
}
DB_PASSWORD = {
  description = "Database password",
  providers = ["documents"],
  ref = { item = "application.json" },
  extract = { format = "json", pointer = "/database/password" }
}
```

Both declarations read the same document. `/database/password` walks nested
objects, `/hosts/0` selects an array element, and `/a~1b/~0key` selects the key
`~key` beneath an `a/b` object. The empty pointer selects the complete document.

JSON strings become their unquoted contents. Numbers, booleans, and `null` use
their JSON spelling; objects and arrays become compact JSON. Invalid JSON or a
pointer that does not match is a decoding error. Once a provider returns a
document, extraction failure is not treated as a provider miss and does not
continue along a fallback chain.

INI extraction (0.3+) uses the same RFC 6901 escaping for pointer segments but
accepts only value selectors. `/key` selects an unsectioned key, while
`/section/key` selects a key in a named section:

```toml
[profiles.default]
# format = "ini" requires Monosecret 0.3+
DB_PASSWORD = {
  description = "Database password",
  providers = ["documents"],
  ref = { item = "application.ini" },
  extract = { format = "ini", pointer = "/database/password" }
}
```

For example, that pointer reads `password` from `[database]`. An explicit
`[DEFAULT]` section is selected as `/DEFAULT/key`; it is distinct from an
unsectioned `/key`. Section and key matching is case-sensitive. `~1` selects a
literal `/` and `~0` selects a literal `~`, just as in JSON Pointer. INI values
always remain strings, and literal backslashes are preserved. Empty pointers,
pointers deeper than `/section/key`, malformed INI, and unmatched pointers are
decoding errors.

In 0.22+, `from` names another declared secret as the document to select from.
The source is resolved first and may itself come from a provider, default,
generator, or another derived declaration. `from` dependencies share composed
secrets' static graph: declaration order does not matter, scoped resolutions
fetch hidden dependencies without exposing them, and unknown names or cycles
are rejected while loading the manifest. JSON and INI continue to use
`pointer`, and the source must be text (a binary typed source is rejected):

```toml
[profiles.default]
# from requires Monosecret 0.22+
GENERATED_DOCUMENT = { description = "Generated JSON", type = "command", generate = { command = "generate-config" } }
DATABASE_PASSWORD = { description = "Database password", from = "GENERATED_DOCUMENT", extract = { format = "json", pointer = "/database/password" } }
```

Stored-value transforms run in this order:

```text
provider or cache → encoding decode → structured extraction → as_path
from source → source resolution → structured extraction → as_path
```

This makes a Base64-encoded JSON document valid input when a declaration sets
both `encoding = "base64"` (0.3+) and `extract` (0.3+). A provider-native
`ref.field` is also resolved first, so a field whose contents are JSON can be
selected further. Without `from`, defaults and composed values are already
logical and are not extracted.

Extracted secrets are read-only. `set`, `delete`, interactive prompting,
generation, and `import` reject them rather than replacing or removing the
containing document and its sibling values. Update the document through its
owning system instead. A `from` selection reports its source as the value to
change.

### Derived typed secrets {/* #derived-typed-secrets-050 */}

_(Available since v0.22)_

A secret with `from` and a typed conversion target as its `type` converts
another declared secret. In 0.22 the source is always an `x509_identity`: a
PKCS#12 archive holding one private key, its leaf certificate, and an optional
issuer chain, whether generated by Monosecret or imported from a provider. Every
target is an ordinary flat secret with its own name, so SDKs and `run` see it
like any other value.

| Type (0.22+)             | Output                                                                                 | `format`                 | Binary     |
| ------------------------ | -------------------------------------------------------------------------------------- | ------------------------ | ---------- |
| `pkcs12`                 | Complete PKCS#12/PFX archive, protected by the `password` credential when one is bound | fixed                    | yes        |
| `pkcs8_private_key`      | Unencrypted PKCS#8 private key                                                         | `pem` (default) or `der` | `der` only |
| `x509_certificate`       | Leaf certificate                                                                       | `pem` (default) or `der` | `der` only |
| `x509_certificate_chain` | Leaf followed by its ordered issuer certificates                                       | `pem`                    | no         |
| `x509_issuer_chain`      | Ordered issuer certificates without the leaf                                           | `pem`                    | no         |

No target is itself an accepted source, so conversions are one level deep. A
composed template may still reference a target.

#### Generated identity and password protected PFX

```toml
[profiles.development]
# type = "x509_identity", from, format, and credentials require Monosecret 0.22+
TLS_IDENTITY = {
  description = "Canonical development TLS identity",
  type = "x509_identity",
  generate = { san = ["dns:localhost", "ip:127.0.0.1"], usages = ["server_auth"], valid_for = "30d" }
}

TLS_PFX_PASSWORD = {
  description = "Password protecting the exported PFX",
  type = "passphrase",
  generate = true
}

TLS_PFX = {
  description = "Password protected Windows TLS identity",
  type = "pkcs12",
  from = "TLS_IDENTITY",
  credentials = { password = "TLS_PFX_PASSWORD" },
  as_path = true
}

TLS_KEY = {
  description = "PKCS#8 private key",
  type = "pkcs8_private_key",
  from = "TLS_IDENTITY",
  as_path = true
}

TLS_CERTIFICATE_DER = {
  description = "Leaf certificate as DER",
  type = "x509_certificate",
  format = "der",
  from = "TLS_IDENTITY",
  as_path = true
}

TLS_CHAIN = {
  description = "Leaf followed by its issuer chain",
  type = "x509_certificate_chain",
  from = "TLS_IDENTITY"
}
```

`TLS_IDENTITY` does not spell `encoding`: binary types default to Base64. One
resolve generates or reads the identity and the password, then materializes
every target. The consumer receives `TLS_PFX` as a `.pfx` path and
`TLS_PFX_PASSWORD` as a value, which is what it needs to load the archive.

#### Importing a protected PFX

The password that opens a stored archive belongs to the source declaration.
Projections do not repeat it:

```toml
[profiles.production]
SERVICE_IDENTITY = {
  description = "Imported service identity",
  type = "x509_identity",
  providers = ["identity_store"],
  credentials = { password = "SERVICE_IDENTITY_PASSWORD" }
}

SERVICE_IDENTITY_PASSWORD = {
  description = "Password protecting the imported PFX",
  providers = ["onepassword"],
  ref = { vault = "Infrastructure", item = "Production TLS", field = "PFX password" }
}

SERVICE_KEY = { description = "Service private key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY", as_path = true }
SERVICE_CERTIFICATE = { description = "Service certificate chain", type = "x509_certificate_chain", from = "SERVICE_IDENTITY", as_path = true }
```

The password is an ordinary declared secret with provider routing, native
coordinates, `monosecret set`, `import`, audit, and scope handling. If it is
missing, the identity and every projection are reported missing under their own
`required` policy. A wrong password, or a protected archive with no password
bound, is a decoding error; Monosecret never falls back to guessing.

To rewrap an archive under a new password, derive a `pkcs12` from the imported
identity with a different `credentials.password`. Omitting the credential on a
`pkcs12` target produces an empty-password archive, an interchange container
rather than a security boundary.

#### Delivery

- `as_path = true` writes the raw bytes to an owner-only file with the type's
  suffix: `.pfx`, `.pem`, or `.der`.
- Without `as_path`, a binary target is exposed inline as text in its
  `encoding` (`base64` by default; `base64url` and `hex` are accepted). This
  suits CI systems that take a Base64 PFX in an environment variable. A text
  target is exposed as is, and `encoding` is rejected on it.
- Stored identities support RSA, P-256, P-384, P-521, and Ed25519 private keys.
  Certificate subjects may contain supplementary Unicode characters even
  though passwords currently require BMP characters. A self-issued leaf with
  matching subject and issuer names may be signed by a distinct issuer key
  when that issuer's certificate is included in its chain.
  They are validated once: the archive must be between 1 byte and
  10 MiB, hold one private key and one matching leaf, carry at most 16 issuer
  certificates that form one unambiguous leaf-to-root chain with verified
  signatures, and be within every validity period. Unordered certificate bags
  are put in order; unrelated, duplicate, or ambiguous bags are rejected.
- Generated `pkcs12` output uses PBES2/PBKDF2 with HMAC-SHA-256, AES-256-CBC
  for key and certificate privacy, and HMAC-SHA-256 integrity, each with
  100,000 iterations. RC2, 3DES, and SHA-1 are never emitted.
- A bound password must be non-empty, contain no NUL, and be at most 1024
  bytes; an empty value is an error rather than "no password". Passwords
  currently support characters in the Unicode Basic Multilingual Plane,
  including accented letters. Supplementary characters, such as most emoji,
  are rejected for both imported identities and derived PKCS#12 archives.

#### Rules

- `from` requires either `extract` (selection) or a conversion target `type`
  (conversion), never both, and cannot set `default`, `providers`, `ref`,
  `refs`, enabled `generate`, `prompt = true`, or `composed`.
- The source's type must be accepted by the target: every target derives from
  `x509_identity`. `x509_identity` itself is stored or generated and cannot be
  derived.
- `format` is accepted only by `pkcs8_private_key` and `x509_certificate`.
- `credentials` roles are defined per type: `x509_identity` and `pkcs12` accept
  `password`; other targets accept none. A credential must name a declared
  text secret, so neither an `as_path` secret nor a binary typed secret
  qualifies. A generated `x509_identity` cannot bind a password; it is stored
  with an empty password and the provider is its security boundary.
- `from` and `credentials` add edges to the same dependency graph as
  `composed`: unknown names, self references, and cycles are rejected when the
  manifest loads, and scopes fetch hidden sources and credentials without
  exposing them.
- Derived secrets are read-only. `set` and `delete` name the source to change
  instead; `import` and generation skip them.
- Profile inheritance merges `from`, `format`, and `credentials` field by
  field like every other field, then validates the merged secret. An override
  may clear inherited credentials with `credentials = {}`.
- `check --explain` labels a conversion `converted from <SOURCE>` and a
  selection `selected from <SOURCE>`; resolve payloads report both with the
  existing `composed` provenance.

### Secret References

The `ref` field names one externally managed secret by the store's own
coordinates instead of Monosecret's `{project}/{profile}/{key}` convention. See
[Secret References](/concepts/references/) for the concept, model, and examples;
this section is the specification.

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = [
  "prod_vault",
] }
INFRA_TOKEN = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" } }
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GITHUB_PAT" }, providers = [
  "env",
] }
```

`ref` is a table of provider-independent coordinates. Unknown keys are rejected
at parse time. Only `item` is universal; it is the secret's complete name in the
store and replaces the whole convention path, including any `folder_prefix` or
format string configured for the provider. A coordinate a store has no equivalent
for is rejected with an error naming it, never silently ignored.

| Coordinate | Required | Meaning                                                                                                                                                                           |
| ---------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `item`     | Yes      | The store's complete name for the secret. Replaces the whole convention path                                                                                                      |
| `field`    | No       | A named component inside the item. Rejected by stores whose secrets hold a single value                                                                                           |
| `vault`    | No       | The container holding the item. 1Password only; other stores take their container from the provider URI                                                                           |
| `section`  | No       | A named group of fields inside the item. 1Password only; requires `field`                                                                                                         |
| `version`  | No       | Which revision of the secret to read. Supported by versioned stores such as Google Secret Manager, AWS Parameter Store (0.3+), and Azure Key Vault (0.3+); defaults to the latest |

Stores fall into two groups for `field`:

| Store                                                                                             | Shape of one secret     | `field`                                                            |
| ------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------ |
| dotenv, file (0.3+), env, pass, LastPass, Bitwarden, AWS Parameter Store (0.3+), Doppler (0.4.0+) | A single value          | Rejected: there is nothing to select                               |
| 1Password, Proton Pass (0.5.0+), Vault KV, AWS Secrets Manager, keyring                           | A record of named parts | Selects the field label, field name, map key, JSON key, or account |

`vault` is the only container coordinate. For every store except 1Password, the
container is part of the provider URI rather than the ref:

```toml
# The mount `kv2` comes from the URI; the ref names the path inside it.
DB = { description = "DB", ref = { item = "myapp/config", field = "pw" }, providers = [
  "vault://vault.example.com:8200/kv2",
] }

# On 1Password, `vault` on the ref overrides the URI's default vault.
TOKEN = { description = "Token", ref = { vault = "Production", item = "infra", field = "token" }, providers = [
  "onepassword://Private",
] }
```

Which provider resolves a `ref` follows the ordinary [provider resolution order](/concepts/providers/). A `ref` composes with the `providers` fallback
chain, and each provider is asked for the same coordinates.

#### How providers interpret the coordinates

| Provider                                                                                     | `item`                                                      | `field`                                                                  | Without `field`                                                                                      | Writes via ref                                                               |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [1Password](/providers/onepassword/#use-existing-secrets)                                    | Item title or UUID                                          | Field label; `vault` and `section` also apply                            | Reads the item like a convention secret (its value or password field); writes edit the `value` field | ✅ via `op item edit` (adds a missing field, never creates items)            |
| [Keeper (0.3+)](/providers/keeper/#use-existing-records)                                     | Record UID or exact title                                   | Standard field type/label or custom field label                          | Reads `password`                                                                                     | ✅ for existing records and fields                                           |
| [keyring](/providers/keyring/#use-existing-secrets)                                          | Service                                                     | Account (defaults to the current system username)                        | Current user's entry                                                                                 | ✅                                                                           |
| [dotenv](/providers/dotenv/#use-existing-secrets)                                            | `.env` key                                                  | Rejected                                                                 | Reads the key                                                                                        | ✅                                                                           |
| [file (0.3+)](/providers/file/#use-existing-files)                                           | Relative file path beneath the configured root              | Rejected                                                                 | Reads the complete file as arbitrary bytes (0.4.0+)                                                  | ✅                                                                           |
| [env](/providers/env/#use-existing-secrets)                                                  | Variable name                                               | Rejected                                                                 | Reads the variable                                                                                   | — (read-only)                                                                |
| [systemd credentials (0.3+)](/providers/systemd-credential/#use-an-existing-credential-name) | Credential filename                                         | Rejected                                                                 | Reads arbitrary credential bytes (0.4.0+)                                                            | — (read-only)                                                                |
| [Fly.io secrets (0.3+)](/providers/fly/#use-existing-secrets)                                | Fly app secret name                                         | Rejected                                                                 | Error: Fly.io does not expose plaintext values                                                       | ✅ write-only via `flyctl secrets set`                                       |
| [Cloudflare Secrets Store (0.3+)](/providers/cloudflare/#use-existing-secrets-020)           | Account-secret name in the selected store                   | Rejected                                                                 | Error: Cloudflare's management API does not expose plaintext values                                  | ✅ write-only via the Cloudflare API                                         |
| [pass](/providers/pass/#use-existing-secrets)                                                | Entry path                                                  | Rejected                                                                 | Reads the entry                                                                                      | ✅                                                                           |
| [Gopass (0.3+)](/providers/gopass/#use-existing-secrets)                                     | Entry path, including any mount-point prefix                | Rejected                                                                 | Reads the entry                                                                                      | ✅                                                                           |
| [LastPass](/providers/lastpass/#use-existing-secrets)                                        | Item name                                                   | Rejected                                                                 | Reads the item                                                                                       | ✅                                                                           |
| [Dashlane (0.3+)](/providers/dashlane/#use-existing-secrets)                                 | Item title or identifier                                    | Field name on the item                                                   | Reads the type's default field (`content`, or `password` for a login)                                | — (read-only)                                                                |
| [Proton Pass](/providers/protonpass/#use-existing-secrets)                                   | Item title                                                  | Any `pass-cli` field name, such as `password` or a custom field (0.5.0+) | Reads the note                                                                                       | ✅ (refs with `field` are read-only, 0.5.0+)                                 |
| [Passbolt (0.3+)](/providers/passbolt/#use-existing-resources)                               | Resource UUID or exact name                                 | `password`, `username`, `uri`, or `description`                          | Reads `password`                                                                                     | ✅ for existing resources; never creates through `ref`                       |
| [Vault](/providers/vault/#use-existing-secrets)                                              | KV path relative to the mount                               | Required (KV entries are maps)                                           | Error                                                                                                | — (read-only)                                                                |
| [OpenBao](/providers/openbao/#use-existing-secrets) (0.3+)                                   | KV path relative to the mount                               | Required (KV entries are maps)                                           | Error                                                                                                | — (read-only)                                                                |
| [AWS Secrets Manager](/providers/awssm/#use-existing-secrets)                                | Secret name or ARN                                          | JSON key (UTF-8 only)                                                    | Whole `SecretString` or `SecretBinary` value (0.4.0+)                                                | — (read-only)                                                                |
| [AWS Parameter Store (0.3+)](/providers/awsps/#use-existing-parameters)                      | Parameter name or ARN; `version` selects a version or label | Rejected                                                                 | Reads the decrypted value                                                                            | ✅ by unversioned parameter name; version, label, and ARN refs are read-only |
| [GCSM](/providers/gcsm/#use-existing-secrets)                                                | Secret id; `version` also applies                           | Rejected                                                                 | Reads latest or the pinned version                                                                   | — (read-only)                                                                |
| [Doppler (0.4.0+)](/providers/doppler/#use-existing-secrets)                                 | `config/NAME`, or a bare `NAME` when the URI pins a config  | Rejected                                                                 | Reads the secret's resolved value                                                                    | ✅                                                                           |
| [Bitwarden (bws)](/providers/bws/#use-existing-secrets)                                      | BWS key name                                                | Rejected                                                                 | Reads the key                                                                                        | ✅                                                                           |
| [Azure Key Vault (0.3+)](/providers/akv/#use-existing-secrets)                               | Secret name; `version` pins a version (0.3+)                | Rejected                                                                 | Reads latest or the pinned version (0.3+)                                                            | — (read-only)                                                                |
| [Azure App Configuration (0.3+)](/providers/aac/#use-existing-key-values)                    | App Configuration key                                       | Rejected                                                                 | Reads the direct value or resolves its canonical Key Vault reference                                 | — (read-only)                                                                |
| [Infisical (0.3+)](/providers/infisical/#use-existing-secrets)                               | Folder and key; `version` also applies                      | Rejected                                                                 | Reads the latest version                                                                             | ✅ unless a version is pinned                                                |
| [Kubernetes (0.3+)](/providers/kubernetes/#use-existing-secrets)                             | Secret key                                                  | Rejected                                                                 | Reads entry                                                                                          | ✅                                                                           |

A provider rejects coordinates it has no equivalent for, with an error naming
the coordinate (for example, `field` on the env provider).

#### Writing through a ref

Writes are symmetric with reads: `monosecret set` and interactive `check`
prompting write through the coordinates in place wherever the table above says
writes are supported. Read-only stores fail with a clear error instead.

#### No string refs

`ref` is always a table. String and URI forms (`ref = "op://vault/item/field"`,
`ref = "env://VAR"`, query-parameter URIs, and similar) are rejected, and the
error spells out the exact table translation. For example, a pasted 1Password
reference `op://Production/infra/token` translates to:

```toml
INFRA_TOKEN = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" }, providers = [
  "onepassword://Production",
] }
```

Provider URIs remain store addresses; the `ref` table provides the complete
native coordinates for the secret.

#### Deduplication, auditing, and reporting

- Secrets sharing identical coordinates and store are fetched once.
- [Audit log](/concepts/audit/) events carry a `ref` field with the coordinates.
- `check --explain` and `check --json` attribute ref secrets to the store URI
  they resolved from.

### Structured Provider Configs with Dependencies

Project-level `[providers]` entries can also be tables with an optional
`depends_on` section to declare that a provider depends on another secret
for authentication:

<!-- monosecret-test: validate -->

```toml
[project]
name = "myapp"
revision = "1.0"

[providers]
keyring = "keyring://" # Simple alias — backward compatible

[providers.op-dev]
uri = "onepassword://Development"
[[providers.op-dev.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"

[profiles.default]
# The dependency secret must itself be declared and resolved from a
# bootstrap provider (one without its own `depends_on`), such as keyring.
OP_SERVICE_ACCOUNT_TOKEN = { providers = [
  "keyring",
], description = "1Password service account token" }
DATABASE_URL = { providers = [
  "op-dev",
], description = "Database connection string" }
```

| Field        | Type   | Required | Description                                    |
| ------------ | ------ | -------- | ---------------------------------------------- |
| `uri`        | string | Yes      | The provider URI                               |
| `depends_on` | table  | No       | Secrets this provider needs for authentication |

Each entry under `depends_on` has:

| Field    | Type   | Required | Description                                                                                                                                      |
| -------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `secret` | string | Yes      | The Monosecret secret name that provides the value                                                                                               |
| `as`     | string | No       | Environment variable name to inject the value as. Defaults to `secret` (e.g. inject a per-account keyring secret as `OP_SERVICE_ACCOUNT_TOKEN`). |

### Prompt on missing during run (0.3+)

:::caution[Version compatibility]
`prompt = true` declarations require Monosecret 0.3 or newer.
:::

Use `prompt = true` when `monosecret run` should ask the operator after every
configured provider has returned missing. Prompting is the value source;
persistence remains a property of the selected provider.

With a writable provider, the answer is saved and reused by later runs. The
write destination and writability are checked before the hidden prompt opens,
just as they are for `monosecret set`. Use the `null` provider when the answer
must exist only for one child invocation:

```toml
[profiles.default]
DEPLOY_PASSWORD = { description = "One-time deployment password", required = true, prompt = true, providers = [
  "null",
] }
```

Here `null` makes the operator the only possible value source and explicitly
declines persistence, so the answer is injected into the child environment and
discarded after it exits. It is not written to a provider or cache. The prompt
uses the controlling terminal rather than the command's stdin, so a pipe or
redirected file remains available to the child:

```bash
$ printf 'deployment input\n' | monosecret run -- ./deploy
? Enter value for DEPLOY_PASSWORD (profile: default):
```

Only `run` interprets `prompt = true` as a missing-value policy. `get`, `export`,
SDK resolution, and value-free reports do not prompt. Interactive `check`
retains its existing setup behavior instead: it offers to store any missing
required secret, independently of `prompt`, and therefore cannot satisfy a
`null`-backed declaration. A `run` without a controlling terminal fails before
starting the child. Explicit `set` and import operations remain governed by the
provider, not by `prompt`.

`prompt = true` is limited to individually required secrets and cannot be
combined with `default`, enabled `generate`, `extract`, or `composed`. Profile
overrides may set `prompt = false` to return to ordinary missing-value behavior.

### Secret Generation

:::note
Secret generation is available since version 0.7.
:::

When `type` and `generate` are set, missing secrets are automatically generated during `check` or `run` and stored via the configured provider:

```toml
[profiles.default]
# Simple: generate with type defaults
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
REQUEST_ID = { description = "Request ID prefix", type = "uuid", generate = true }

# Custom options
API_TOKEN = { description = "API token", type = "hex", generate = { bytes = 32 } }
SESSION_KEY = { description = "Session key", type = "base64", generate = { bytes = 64 } }

# Shell command
MONGO_KEY = { description = "MongoDB keyfile", type = "command", generate = { command = "openssl rand -base64 765" } }

# RSA private key (PKCS1 PEM)
JWT_SIGNING_KEY = { description = "JWT signing key", type = "rsa_private_key", generate = true }

# OpenPGP signing key (0.4.0+)
RELEASE_KEY = { description = "Release signing key", type = "openpgp_private_key", generate = { user_id = "Release Bot <releases@example.com>", capabilities = [
  "sign",
] } }

# OpenSSH Ed25519 private key (0.4.0+)
DEPLOY_KEY = { description = "Deployment SSH key", type = "ssh_private_key", generate = true }

# Private P-256 JSON Web Key (0.22+)
JWT_JWK = { description = "JWT signing JWK", type = "jwk_private_key", generate = { algorithm = "p256", kid = "release-2026" } }

# Native age X25519 identity (0.22+)
BACKUP_IDENTITY = { description = "Backup encryption identity", type = "age_identity", generate = true }

# Self-signed P-256 X.509 identity stored as a Base64 PKCS#12 archive (0.22+)
LOCAL_TLS = { description = "Local TLS identity", type = "x509_identity", generate = { san = [
  "dns:localhost",
  "ip:127.0.0.1",
] } }

# Type without generate: informational only, no auto-generation
MANUAL_SECRET = { description = "Manually managed", type = "password" }
```

#### Generation Types

:::caution[Version compatibility]
The `command` generator preserves stdout exactly, including binary bytes,
whitespace, and final newlines. Only zero-byte output is rejected. Trim inside
the command when needed; use a byte-capable provider or manifest `encoding`
for binary output.
:::

| Type                             | Default Output                                                              | Options                                                                                                                                                        |
| -------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `password`                       | 32 alphanumeric chars                                                       | `length` (int), `charset` (`"alphanumeric"` or `"ascii"`)                                                                                                      |
| `hex`                            | 64 hex chars (32 bytes)                                                     | `bytes` (int)                                                                                                                                                  |
| `base64`                         | 44 chars (32 bytes)                                                         | `bytes` (int)                                                                                                                                                  |
| `uuid`                           | UUID v4 (36 chars)                                                          | none                                                                                                                                                           |
| `command`                        | stdout of command; exact bytes in 0.4.0+                                    | `command` (string, required)                                                                                                                                   |
| `rsa_private_key`                | 2048-bit RSA private key (PKCS1 PEM)                                        | `bits` (int)                                                                                                                                                   |
| `openpgp_private_key` (0.4.0+)   | ASCII-armored OpenPGP v4 transferable secret key                            | `user_id` (required), `algorithm` (`"ed25519"` or `"rsa"`), `bits` (RSA only), `capabilities` (`["sign"]`, `["encrypt"]`, or both)                             |
| `ssh_private_key` (0.4.0+)       | Unencrypted OpenSSH Ed25519 private key                                     | `algorithm` (`"ed25519"` or `"rsa"`), `bits` (RSA only), `comment` (string)                                                                                    |
| `passphrase` (0.5.0+)            | Seven BIP-39 English words joined with `-`                                  | `words` (6–32), `separator` (non-empty string)                                                                                                                 |
| `mnemonic` (0.5.0+)              | 24-word English BIP-39 mnemonic                                             | `algorithm` (`"bip39"`), `words` (12, 15, 18, 21, or 24), `language` (`"english"`)                                                                             |
| `wireguard_private_key` (0.5.0+) | Base64-encoded WireGuard private key                                        | none                                                                                                                                                           |
| `jwk_private_key` (0.5.0+)       | Ed25519 private signing JWK                                                 | `algorithm` (`"ed25519"`, `"p256"`, or `"rsa"`), `bits` (RSA only), `kid` (string)                                                                             |
| `age_identity` (0.5.0+)          | Native X25519 age identity                                                  | none                                                                                                                                                           |
| `x509_identity` (0.5.0+)         | PKCS#12 archive (Base64 at rest) with P-256 key and self-signed certificate | `issuer` (`"self_signed"`), `algorithm` (`"p256"`), `san` (required DNS/IP names), `usages` (`"server_auth"` and/or `"client_auth"`), `valid_for` (1–200 days) |

#### OpenPGP private-key generation {/* #openpgp-private-key-generation-040 */}

:::note[Version compatibility]
Added in Monosecret 0.4.0.
:::

`openpgp_private_key` is generated entirely in Rust and does not invoke GnuPG.
The default `algorithm = "ed25519"` creates an Ed25519 certification-only
primary key plus separate Ed25519 signing and/or Curve25519 encryption subkeys.
For compatibility with RSA-only consumers, `algorithm = "rsa"` uses RSA for the
primary key and all requested subkeys. RSA defaults to 3072 bits;
`bits` accepts 2048 through 8192 and is invalid with `"ed25519"`.

Omitting `capabilities` selects both; the list must otherwise contain `"sign"`,
`"encrypt"`, or both without duplicates. `generate = true` is invalid because
every generated certificate requires an explicit `user_id`.

The ASCII-armored transferable secret key has no OpenPGP passphrase and no
expiration. Store it with an encrypted provider when it needs protection at
rest. Its public certificate and fingerprint can be derived after import by
OpenPGP tooling; Monosecret stores the secret key as one logical value.

#### SSH private-key generation {/* #ssh-private-key-generation-040 */}

:::note[Version compatibility]
Added in Monosecret 0.4.0.
:::

`ssh_private_key` is generated entirely in Rust. `generate = true` creates an
unencrypted Ed25519 OpenSSH private key. Select `algorithm = "rsa"` for
compatibility; RSA defaults to 3072 bits and accepts 2048 through 8192. `bits`
is invalid with Ed25519. An optional `comment` is embedded in the key and must
not contain control characters.

#### Additional credential generation {/* #additional-credential-generation-022 */}

_(Available since v0.22)_

- `passphrase` independently selects seven BIP-39 English words by default
  (77 bits of entropy) and joins them with `-`. It is not a BIP-39 mnemonic.
  `words` accepts 6 through 32; `separator` must be non-empty and contain no
  control characters.
- `mnemonic` (0.22+) emits a checksum-valid BIP-39 mnemonic. It defaults to 24
  English words (256 bits of entropy plus checksum); `words` accepts 12, 15,
  18, 21, or 24. The extensible subtype fields currently accept only
  `algorithm = "bip39"` and `language = "english"`. Monosecret returns the
  mnemonic itself and does not derive a BIP-32 seed, wallet keys, or BIP-39's
  optional mnemonic passphrase.
- `wireguard_private_key` emits the standard Base64-encoded, clamped 32-byte
  scalar accepted by WireGuard and accepts no options.
- `jwk_private_key` emits a compact private signing JWK with public parameters,
  `use = "sig"`, and `key_ops = ["sign"]`. It defaults to Ed25519 with RFC
  9864's fully specified `Ed25519` JOSE algorithm identifier;
  `algorithm = "p256"` selects P-256/`ES256`, and `"rsa"` selects
  RSA/`RS256`. RSA defaults to 3072 bits and accepts 2048 through 8192.
  `kid` adds optional key-identification metadata.
- `age_identity` emits a native X25519 `AGE-SECRET-KEY-1...` identity and
  accepts no options. This is the interoperable classic format supported by
  the Rust age provider. For post-quantum confidentiality, provision an
  externally generated hybrid ML-KEM-768+X25519 `AGE-SECRET-KEY-PQ-1...`
  identity until the Rust age library supports that format.

#### X.509 identity generation {/* #x509-identity-generation-022 */}

_(Available since v0.22)_

`x509_identity` generates a P-256 key and a self-signed X.509 v3 certificate.
`generate.san` is required and accepts `dns:name` and `ip:address` entries;
hostname verification therefore never depends on the deprecated Common Name.
The certificate uses ECDSA with SHA-256, a random 128-bit serial, critical
CA-false basic constraints and digital-signature key usage, plus `server_auth`
extended usage by default. `client_auth` may be selected or combined with it.

Validity defaults to `30d` and accepts `1d` through `200d`, matching the current
CA/Browser Forum maximum for publicly trusted subscriber certificates even
though Monosecret's self-signed development identities are outside that policy.
The start time is backdated five minutes for peer clock skew without extending
the requested total lifetime.

The canonical value is an empty-password PKCS#12 archive. It explicitly uses
AES-256-CBC for key and certificate protection and HMAC-SHA-256 for integrity,
avoiding legacy RC2, 3DES, and SHA-1 profiles. Because the password is empty,
the archive is an interoperable container rather than an independent security
boundary: store it in a provider that protects secrets at rest. `encoding`
defaults to `base64`, so inline exposure is Base64 and `as_path = true` writes
the PFX bytes to an owner-only `.pfx` file. Derive PEM, DER, key, certificate,
chain, and password protected PFX values with `from`; see
[Derived typed secrets](#derived-typed-secrets-050). A provider-backed
`x509_identity` may also be an imported archive, protected or not.

#### Behavior

- Generation only triggers when a secret is **missing** — existing secrets are never overwritten
- Generated values are stored via the secret's configured provider (or the default provider)
- With `providers = ["null"]` (0.3+), a fresh generated value is returned only for the current resolution and is not written to provider storage
- Subsequent runs find the stored value and skip generation (idempotent)
- `generate` and `default` cannot both be set on the same secret
- `type = "command"` requires `generate = { command = "..." }` (not just `generate = true`)
- `type = "openpgp_private_key"` (0.4.0+) requires `generate.user_id`; omitted
  `algorithm` and `capabilities` default to Ed25519/Curve25519 and both
  signing and encryption, respectively
- `type = "ssh_private_key"` (0.4.0+) defaults to Ed25519; RSA generation is
  available with `generate = { algorithm = "rsa", bits = 4096 }`
- `passphrase`, `mnemonic`, `wireguard_private_key`, `jwk_private_key`, `age_identity`, and `x509_identity`
  generation require Monosecret 0.22+
- The value-free preflights — [`check --json` / `check --explain`](/reference/cli/#resolution-report---json----explain)
  and the SDKs' report/no-values resolutions — never mint a value. Since
  Monosecret 0.3 a **required** generatable secret that no provider holds is
  reported as `missing_required` there (and exits non-zero) until a `check` or
  `run` provisions it; an optional one, or one stored in a provider that never
  retains generated values such as `null`, is reported as _will generate_

## Profile Inheritance

- Non-default profiles inherit from `[profiles.default]` when it exists;
  `profiles.<name>.defaults.inherit = false` makes a profile standalone in
  Monosecret 0.3+
- Profile-specific values override default values
- `ref` and `refs` (0.3+) are alternative forms of one setting: declaring
  either in a profile replaces the form inherited from `[profiles.default]`,
  while declaring neither inherits it
- Use the `extends` field in `[project]` to inherit from other monosecret.toml files

## Provider retry policy

_(Available since v0.22)_

The retry policy is an operator setting in `~/.config/monosecret/config.toml`.
It is not a field in the project's `monosecret.toml`.

```toml title="~/.config/monosecret/config.toml"
[defaults.retry]
max_attempts = 3
```

`max_attempts` counts the original attempt and accepts integers from 1 to 10.
The default is 3; use 1 to disable Monosecret-controlled retries. Omitting the
retry table or its `max_attempts` field uses the default.

The delay grows exponentially from 250 ms and is capped at ten seconds. A valid
server retry hint is honored up to that same cap. The delay policy is fixed;
there are no project settings, environment variables, or CLI flags for it.
An explicit Rust `Secrets::with_retry_policy` override takes precedence over
user configuration. See [transient provider failures](/concepts/providers/#transient-failures)
for operation safety and SDK/CLI behavior.
