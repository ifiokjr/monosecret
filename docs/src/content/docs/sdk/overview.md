---
title: SDK Overview
description: How the Monosecret language SDKs work
---

Monosecret ships SDKs for Rust, Python, Go, Ruby, Node.js/TypeScript, and
Haskell. They all resolve secrets from the same declarative `monosecret.toml`,
and they all behave identically, because they share one resolver.

## One resolver, thin clients

Resolution (providers, fallback chains, profiles, generation, `as_path`
materialization) lives in a single Rust core. Each SDK is a thin client over
that core rather than a reimplementation:

- **Rust** uses the library directly, with a compile-time derive macro for
  strongly-typed access.
- **Ruby** (a native C extension) statically links the `monosecret_ffi` C ABI
  at build time; **Go** (purego) loads it at runtime with no cgo. Both exchange
  a small JSON request/response with the core.
- **Haskell** links the same C ABI at build time via the GHC FFI.
- **Python** uses a [pyo3](https://pyo3.rs/) native extension, and
  **Node.js/TypeScript** uses a [napi-rs](https://napi.rs/) native addon; both
  embed the same resolver directly and exchange the same JSON request/response
  shape as the C ABI.

Because resolution happens in one place, every provider, chain, profile, and
generator works the same in every language, and a new provider added to the core
is immediately available everywhere with no per-SDK change. A cross-language
conformance suite asserts that all the SDKs reduce the same inputs to the same
result.

## The runtime API

Each SDK mirrors the Rust derive crate's vocabulary: a builder that takes a
provider, profile, and an access reason, and a `load`/`resolve` that returns the
resolved secrets plus the provider and profile used. A missing required secret
is a typed error, distinct from a transport failure (which carries a stable
`kind`). Secrets exposed `as_path` come back as a readable file path.

```python
# Distribution: monosecret_py
from monosecret import Monosecret

resolved = Monosecret.builder().with_provider("keyring://").with_reason("boot").load()
print(resolved.secrets["DATABASE_URL"].get)
```

See each language's page for the idiomatic spelling: [Rust](/sdk/rust),
[Python](/sdk/python), [Go](/sdk/go), [Ruby](/sdk/ruby),
[Node.js](/sdk/nodejs), and [Haskell](/sdk/haskell).

## Typed access

Beyond the Rust derive macro, typed accessors for the other languages are
generated from the manifest. `monosecret schema` emits a JSON Schema for the
secret shape; [quicktype](https://quicktype.io) turns it into an idiomatic type
and deserializer for any language, which you build from the SDK's `fields()`
map:

```bash
monosecret schema | quicktype -s schema --top-level Monosecret --lang <language>
```

This keeps the per-language surface tiny: the SDK only provides `fields()`, and
quicktype owns the type generation.

## Distribution

The resolver ships inside each package, so there is nothing extra to install and
no runtime library path to set:

- **Python** builds the resolver into a pyo3 extension shipped as a `cp39-abi3`
  wheel, and **Ruby** statically links the `monosecret_ffi` archive into a
  native C extension in the gem.
- **Haskell** statically links the same archive at build time via the GHC FFI.
- **Go** loads the `cdylib` at runtime via purego (no cgo); opt-in
  `monosecret_embed` and `monosecret_static` build tags support staged native artifacts.
- **Node.js** loads a platform-specific napi-rs addon lazily from the canonical
  `@monosecret/client` package.

Python, Ruby, Haskell, and Node package the resolver with their native artifact.
Go can use a staged embedded/static artifact or locate `libmonosecret_ffi` through
`MONOSECRET_FFI_LIB`.
