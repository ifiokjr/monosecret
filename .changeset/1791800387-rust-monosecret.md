---
"rust:monosecret":
  bump: patch
  type: feat
"rust:monosecret_rpc":
  bump: patch
  type: feat
---

# Rename the monosecret-ipc crate to monosecret_rpc

The published crate is monosecret_rpc everywhere: underscore in code and in the Cargo.toml dependency key, matching how the crate is imported. crates.io treats dashes and underscores as one name, so monosecret-ipc and monosecret_ipc are the same occupied crate and a genuinely new name was required. The wire protocol, schema paths, and resolver tooling keep their IPC naming; nothing protocol-level changes. monosecret-ipc 0.4.0 through 0.4.3 remain on crates.io un-yanked so published monosecret releases keep resolving.
