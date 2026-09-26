---
title: Docker credentials
description: Let Docker retrieve registry credentials through Monosecret providers
---

The Docker credential integration is available in Monosecret 0.3+. It lets
`docker pull`, `docker push`, `docker build`, and Docker Compose retrieve
registry credentials from any Monosecret provider without copying the
password or token into Docker's `config.json`.

## Prerequisites

- Docker
- Monosecret 0.3 or newer, including `docker-credential-monosecret` on `PATH`

## Quick start

These commands are available in Monosecret 0.3+.

Configure the registry with its non-secret username:

::::danger[This changes your Docker configuration]
Docker has no repository-local configuration. `configure` updates
`$DOCKER_CONFIG/config.json` when `DOCKER_CONFIG` is set, or the user-level
`~/.docker/config.json` (`%USERPROFILE%\.docker\config.json` on Windows)
otherwise. The change applies to every Docker command using that configuration.
Monosecret preserves unrelated settings and refuses to replace another helper.
Undo it with `monosecret docker unconfigure --registry ghcr.io`.
::::

```bash
$ monosecret docker configure --registry ghcr.io --username YOUR_USERNAME
```

After confirmation, the command prints the matching login command:

```console
Configured Docker credential for ghcr.io.
Docker configuration: /home/you/.docker/config.json
Store the credential with: monosecret docker login 'ghcr.io'
Undo with: monosecret docker unconfigure --registry 'ghcr.io'
```

Store the password or access token in Monosecret's embedded, registry-isolated
credential store:

```bash
$ monosecret docker login ghcr.io
```

`login` prompts securely on a terminal and reads the password or token from
standard input when piped.

::::caution[Use Monosecret to log in and out]
After configuring the helper, use `monosecret docker login` and
`monosecret docker logout` to manage the stored credential. Docker's own
`docker login` and `docker logout` operations try to write or erase through the
helper, which is intentionally read-only.
::::

Docker now invokes `docker-credential-monosecret get` automatically:

```bash
$ docker pull ghcr.io/OWNER/IMAGE:TAG
$ docker push ghcr.io/OWNER/IMAGE:TAG
```

`configure` does not retrieve or store the credential. It adds the registry's
`credHelpers` entry and records only the registry, Docker configuration path,
username, provider selection, and other value-free metadata. `login` prompts
for the secret and stores it through the selected provider. Each registry and
physical Docker configuration pair has a separate Monosecret project and
secret-key identity, so credentials remain isolated even in flat providers that
do not namespace keys by project or profile. Monosecret's managed state is
owner-readable and owner-writable only; Docker's existing `config.json`
permissions are preserved.

Rerunning `configure` for the same registry and Docker configuration replaces
its Monosecret metadata and reports that replacement. It does not delete the
stored credential.

To use a provider other than your default, pass the same override to both
commands. The follow-up command printed by `configure` includes it automatically:

```bash
$ monosecret docker configure \
  --registry ghcr.io \
  --username YOUR_USERNAME \
  --provider onepassword
$ monosecret docker login ghcr.io --provider onepassword
```

Exported `MONOSECRET_FILE`, `MONOSECRET_PROFILE`, `MONOSECRET_PROVIDER`, and
`MONOSECRET_REASON` values are not saved as durable Docker helper settings.
Pass `--file`, `--profile`, `--provider`, or `--reason` explicitly when the
helper should keep using that selection.

## Docker Hub

Docker uses the historical key `https://index.docker.io/v1/` for Docker Hub.
Monosecret 0.3+ normalizes the familiar Docker Hub hostnames and URL forms to
that key:

```bash
$ monosecret docker configure \
  --registry docker.io \
  --username YOUR_DOCKER_ID
$ monosecret docker login docker.io
```

Registry addresses may contain a port, such as
`registry.example.com:5000`, but not a repository path. Credentials are scoped
to the registry rather than an image namespace.

## Use a project manifest

Custom Docker credential configuration is available in Monosecret 0.3+.

For a credential already declared by a project, pass `--file` to select the
advanced custom-manifest mode. In this mode, `--token-secret` and either
`--username` or `--username-secret` are required:

```toml
[project]
name = "docker-credentials"
revision = "1.0"

[profiles.default]
GHCR_TOKEN = { description = "GitHub Container Registry token" }
```

```bash
$ monosecret set GHCR_TOKEN --file monosecret.toml
$ monosecret --file monosecret.toml docker configure \
  --registry ghcr.io \
  --token-secret GHCR_TOKEN \
  --username YOUR_USERNAME
```

To resolve the username from Monosecret too, declare it and replace
`--username` with `--username-secret GHCR_USERNAME`. Custom-manifest mode also
accepts `--profile` and `--provider`.

The managed state records the manifest's absolute path and, when supplied as
`--profile`, that profile; it never records resolved secret values. Without an
explicit `--profile`, the helper resolves the normal profile each time it runs.
A symlinked manifest retains its logical path, so relative `extends` entries
resolve beside the symlink. If the manifest moves, rerun `configure` for the
affected registry. Manage custom-manifest values with `monosecret set` and
`monosecret delete`; `monosecret docker login` and `logout` intentionally manage
only the embedded store.

## Alternate Docker configuration directory

Per-configuration Docker credential isolation is available in Monosecret 0.3+.
Monosecret and Docker both honor `DOCKER_CONFIG` when selecting `config.json`:

```bash
$ DOCKER_CONFIG="$HOME/.config/docker-work" \
  monosecret docker configure \
    --registry registry.example.com \
    --username YOUR_USERNAME
```

The same registry can use different Monosecret credentials in different Docker
configuration directories. Embedded credentials are isolated by both registry
and the physical Docker configuration path. Equivalent paths through symlinked
directories resolve to the same credential identity. Use the same
`DOCKER_CONFIG` value when logging in, logging out, or unconfiguring entries
from that file.

::::caution[Use DOCKER_CONFIG instead of docker --config]
Docker's `--config <PATH>` flag selects a configuration for the Docker process,
but Docker does not pass that path to credential helpers. Export
`DOCKER_CONFIG=<PATH>` instead so `docker-credential-monosecret` can identify
the matching managed credential. Using only `docker --config <PATH>` can find
the helper registration while leaving the helper unable to select its
credential.
::::

## Remove credentials and configuration

These removal commands are available in Monosecret 0.3+.

Remove an embedded secret without changing Docker's helper configuration:

```bash
$ monosecret docker logout ghcr.io
```

Pass the same `--provider` used for login when it was explicitly overridden.

Remove one helper registration from the active Docker configuration:

```bash
$ monosecret docker unconfigure --registry ghcr.io
```

Remove every Docker credential helper registration that Monosecret owns in
that file:

```bash
$ monosecret docker unconfigure --all
```

Configuration changes prompt with a default of **No**. Pass `--yes` for
non-interactive setup or removal. Monosecret preserves the default credential
store, other registry helpers, existing `auths`, and unrelated Docker options.
If a managed entry changes outside Monosecret, `unconfigure` refuses to modify
another helper's entry. If the Monosecret helper entry is already absent,
`unconfigure` safely removes the stale managed state so an interrupted removal
can be rerun.

`logout` and `unconfigure` are independent: logout deletes the embedded secret,
while unconfigure removes Docker's reference to the helper. This matches the
separation between `login` and `configure`.

## Read-only helper behavior

In Monosecret 0.3+, `docker-credential-monosecret` answers Docker's `get`
operation. It rejects `store`, `erase`, and `list`, so Docker's own
`docker login` and `docker logout` cannot overwrite or delete values in a shared
provider. Use `monosecret docker login` and `monosecret docker logout` for the
embedded store, or normal Monosecret commands for a custom manifest.

Docker may still print `Removing login credentials` and exit successfully after
`docker logout` even though a read-only helper retained the credential. Use
`monosecret docker logout` to remove the stored value, and
`monosecret docker unconfigure` to stop Docker from invoking the helper.

When no matching configuration or stored value exists, the helper returns
Docker's standard credential-not-found response.
