---
monosecret: breaking
---

# Integrate native references and language SDKs

Add provider-independent table-form `ref` coordinates, address-based provider
resolution, batch reads, writable checks, and value-free resolution reports.
Provider implementations must migrate to the new address-oriented APIs.

Ship the shared native resolver through `monosecret_ffi`, `@monosecret/client`,
the `monosecret_py` Python distribution, the
`github.com/ifiokjr/monosecret/go/monosecret_go` Go module, the `monosecret_rb`
Ruby gem, and the Hackage package and module `monosecret` / `Monosecret`.
