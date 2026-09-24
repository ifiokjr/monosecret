---
title: Keyring Provider
description: Secure system credential store integration
---

> **Changed in version 0.4.0:** Secret values use the keyring's binary API,
> preserving non-UTF-8 bytes, NULs, whitespace, and line endings. Existing text
> passwords remain readable.

On Windows, text values retain the native UTF-16LE password format used by
earlier releases. Binary values use a Monosecret-specific marker in the same
credential blob and require Monosecret 0.4.0+ to read.

The [Keyring](https://github.com/open-source-cooperative/keyring-rs) provider
stores secrets in your system's native credential store. Recommended for local
development.

## At a glance

|                 |                                        |
| --------------- | -------------------------------------- |
| Provider        | `keyring`                              |
| URI             | `keyring://[folder_prefix]`            |
| Access          | Read and write                         |
| Best for        | Secure local development               |
| Authentication  | Current operating-system user          |
| Default storage | `monosecret/{project}/{profile}/{key}` |

## Quick start

```bash
# Set a secret
$ monosecret set DATABASE_URL --provider keyring
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to keyring

# Get a secret
$ monosecret get DATABASE_URL --provider keyring
postgresql://localhost/mydb

# Run with secrets
$ monosecret run --provider keyring -- npm start
```

## Setup

### Supported platforms

- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service (GNOME Keyring, KWallet)

### macOS keychain prompts

macOS binds every keychain item to the code signature of the program that
created it. Builds that are not signed with an Apple Developer ID, which
includes Monosecret installed through Nix, Homebrew, or `cargo install`, get a
new signature with every release. After an upgrade, macOS therefore asks for
the login keychain password the first time the new build reads each secret.
Choose **Always Allow**: it grants the new build lasting access, and every
later run stays silent. **Allow** grants a single read, so the dialog returns on
the next run.

> **Changed in version 0.4.0:** When a read needs keychain approval, Monosecret
> explains that **Always Allow** prevents repeated prompts for this build.
> Reads leave the keychain item intact. `monosecret set` retries an in-place
> update after asking for access if the first attempt cannot see an item
> written by an earlier build.

Secrets addressed with [`ref`](#use-existing-secrets) belong to the
application that created them. Reading one from Monosecret can prompt until
you grant this build access with **Always Allow**.

### Linux prerequisites

Linux only - install if missing:

```bash
# Debian/Ubuntu
$ sudo apt-get install gnome-keyring

# Fedora
$ sudo dnf install gnome-keyring

# Arch
$ sudo pacman -S gnome-keyring
```

## Configuration

### URI format

```
keyring://[folder_prefix]
```

- `folder_prefix`: Optional path prefix supporting `{project}`, `{profile}`, and `{key}` placeholders. Defaults to `monosecret/{project}/{profile}/{key}`.

### URI examples

```text
keyring
keyring://shared/{profile}/{key}
```

### Project configuration

```toml title="monosecret.toml"
[providers]
local = "keyring://"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["local"] }
```

## Storage model

Each secret is stored under `monosecret/{project}/{profile}/{key}` as the
keyring service, with the current system username as the account. Project and
profile names keep convention secrets isolated.

## Use existing secrets

A secret's
[`ref`](/reference/configuration/#secret-references) field names an exact keyring
entry instead, useful for reading a credential another application already
stored: `item` is the service, and the optional `field` is the account
(defaults to the current system username). Reads and writes target that entry in
place.

```toml
[profiles.default]
API_TOKEN = { description = "Token", ref = { item = "com.example.app", field = "me@example.com" }, providers = [
  "keyring",
] }
```

## Advanced configuration

### Shared secrets

By default, secrets are stored under `monosecret/{project}/{profile}/{key}`, which isolates them per project. To share secrets across projects, use a custom folder prefix via the URI:

```toml
# ~/.config/monosecret/config.toml
[defaults.providers]
shared = "keyring://monosecret/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same keyring entry:

```toml
# monosecret.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from keyring service `monosecret/shared/default/ARTIFACTORY_USER`.
