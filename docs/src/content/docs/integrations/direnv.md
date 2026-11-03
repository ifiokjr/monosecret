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
_monosecret_exports="$(monosecret env --shell bash --reason 'direnv: project environment')" || return
eval "$_monosecret_exports"
unset _monosecret_exports
```

`watch_file` makes direnv re-run the block when the manifest (or the provider
aliases it declares) changes, so editing a profile takes effect the next time
you `cd` in.

Notes that keep this safe:

- The secrets land in environment variables of **every command run in that
  directory**, which is direnv's contract. If that is broader exposure than a
  task needs, run that task with `monosecret run -- <command>` instead and keep
  direnv for the tooling that genuinely wants ambient variables.
- The capture returns immediately if resolution fails, so an error cannot be
  hidden by evaluating empty output. The reason satisfies `require_reason`
  and is recorded in the audit log; adjust it to describe your workflow.
- Prefer a non-default profile with `--profile`, and check what a manifest
  declares before enabling it: `.envrc` and `monosecret.toml` both come from the
  repository you cloned, so both deserve the same review.

For CI, the same command with `--shell github` appends masked values to
`$GITHUB_ENV` — see the [CI guide](/guides/ci/).
