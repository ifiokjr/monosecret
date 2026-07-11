---
monosecret: breaking
---

# Integrate native references and language SDKs

Add provider-independent table-form `ref` coordinates, address-based provider
resolution, batch reads, writable checks, and value-free resolution reports.
Provider implementations must migrate to the new address-oriented APIs.

Integrate the shared native resolver source, local build paths, and tests for
`monosecret_ffi`, `@monosecret/client`, Python, Go, Ruby, and Haskell bindings.
Distribution of the new FFI and native SDK artifacts is explicitly deferred;
this release validates their source integration without publishing them.
