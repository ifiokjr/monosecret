---
"rust:monosecret": fix
"rust:monosecret_rpc": fix
---

# Harden secret handling and clear workspace clippy warnings

Env files and dotenv stores are written owner-only (0600) through staged,
fsynced, atomically renamed temporaries, and symlinked store paths are refused
rather than written through. HTTP redirect refusal moves into the shared
provider client builder, closing the gap for the Railway, Pulumi ESC, Vercel,
and Netlify providers that had none, and the redundant per-provider policies
are dropped. `Debug` renderings of resolved secrets no longer print `value` or
`path` for any payload type, and GitHub `::add-mask::` commands are
percent-encoded and split one per line so multi-line values cannot leak into
job logs. The keyring username lookup is cached per process. The conformance
runner is clippy-clean (indexing/slicing, pass-by-value, unnecessary wraps),
its package renamed to kebab-case `monosecret-rpc-conformance` to silence the
cargo manifest warning, and `cargo clippy` and `cargo check` now emit zero
warnings across the workspace.
