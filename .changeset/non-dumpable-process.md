---
rust:monosecret: fix
---

# Block core dumps and ptrace while the CLI holds secrets

The `monosecret`, `git-credential-monosecret`, and
`docker-credential-monosecret` binaries now disable core dumps on every
Unix and, on Linux, mark the process non-dumpable, so a same-user process
cannot read the resolver's memory or `/proc/<pid>/environ` during the
window secrets are loaded. Working on monosecret itself is still possible
by setting `MONOSECRET_ALLOW_DUMPABLE=1`. The library embedding path (FFI
and the language SDKs) deliberately does not change the dumpability of a
host application's process.
