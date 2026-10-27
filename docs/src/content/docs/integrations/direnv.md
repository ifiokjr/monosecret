---
title: direnv
description: Load a profile's secrets into your shell automatically as you enter a project directory
---

[direnv](https://direnv.net) evaluates a `.envrc` when you enter a directory and
unloads it when you leave. Pairing it with Monosecret gives every project
directory its declared secrets, refreshed whenever `monosecret.toml` changes —
no shell plugin, no manual `source`.

```bash title=".envrc"
watch_file monosecret.toml
eval "$(monosecret env --shell bash)"
```

`watch_file` makes direnv re-run the block when the manifest (or the provider
aliases it declares) changes, so editing a profile takes effect the next time
you `cd` in.

Notes that keep this safe:

- The secrets land in environment variables of **every command run in that
  directory**, which is direnv's contract. If that is broader exposure than a
  task needs, run that task with `monosecret run -- <command>` instead and keep
  direnv for the tooling that genuinely wants ambient variables.
- If your global config sets `require_reason`, add one:
  `eval "$(monosecret env --shell bash --reason 'direnv: project environment')"`.
  The reason is recorded in the audit log like any other access.
- Prefer a non-default profile with `--profile`, and check what a manifest
  declares before enabling it: `.envrc` and `monosecret.toml` both come from the
  repository you cloned, so both deserve the same review.

For CI, the same command with `--shell github` appends masked values to
`$GITHUB_ENV` — see the [CI guide](/guides/ci/).
