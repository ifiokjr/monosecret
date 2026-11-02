---
rust:monosecret: minor
---

# Add a small Rust client for native and Wasm hosts

The `client` feature with `default-features = false` provides zeroizing access to host-resolved UTF-8 values, or named environment entries injected by `monosecret run` on native targets. Its normal dependency graph is only `secrecy` and `zeroize`; native resolution, process launching, crypto generators, and providers belong to the `runtime` feature. Default CLI/provider builds still include that runtime. Consumers that previously disabled defaults for native resolution must now enable `runtime` explicitly.
