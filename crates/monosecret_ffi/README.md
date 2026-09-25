# monosecret_ffi

`monosecret_ffi` is Monosecret's embedded C ABI. It links the Rust resolver and
all enabled in-tree providers into a shared or static native library, exposing
four JSON-in/JSON-out and ownership functions through
[`include/monosecret.h`](include/monosecret.h).

The public name is `monosecret_ffi` starting with Monosecret 0.20. Earlier
releases called this component `monosecret-ffi` and emitted library filenames
containing `monosecret_ffi`; the 0.20 SDK runtime loaders continue to recognize
those older shared-library filenames.

The rename changes packaging, not the exported C symbols or their ownership
rules. Compatibility is intentionally asymmetric:

| Consumer                                                   | Pre-0.20 native library with a 0.20 SDK                                                        | 0.20 native library with a pre-0.20 SDK                            |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Go purego, .NET, PHP FFI                                   | Supported by legacy filename fallback; only pre-0.20 behavior is available                     | Requires the old filename or an explicit `MONOSECRET_FFI_LIB` path |
| Ruby native extension                                      | Upgrade the static archive with the extension source; an already-built extension is unaffected | A pre-0.20 source build still looks for the old archive name       |
| Go cgo/pkg-config and Haskell source builds                | Rebuild against `monosecret_ffi.pc` and the 0.20 archive                                       | Rebuild or provide compatibility pkg-config/archive names          |
| Python, Node, Swift, JVM, packaged .NET/PHP/Ruby artifacts | Native code is bundled or linked by the package; runtime filename discovery does not apply     | Upgrade the package and native artifact together                   |

Filename fallback is not feature emulation: an older library cannot implement
0.20 request fields or behavior such as inline specifications. SDK schema and
symbol checks still decide whether a particular old library is usable.
`MONOSECRET_FFI_LIB` keeps its established environment-variable spelling across
the rename.

Public artifacts are:

- `libmonosecret_ffi.so`, `libmonosecret_ffi.dylib`, or Cargo's `monosecret_ffi.dll`
  (some SDK packages stage the Windows DLL as `libmonosecret_ffi.dll`);
- `libmonosecret_ffi.a`, or the platform-equivalent static library, for static
  embedding;
- `monosecret.h`; and
- `monosecret_ffi.pc` when installed with cargo-c.

Build the native library directly with:

```console
cargo build -p monosecret_ffi --release
```

Or install one library form, its header, and pkg-config metadata:

```console
bash crates/monosecret_ffi/scripts/cinstall.sh "$PREFIX" static
bash crates/monosecret_ffi/scripts/cinstall.sh "$PREFIX" shared
```

This is distinct from
[`libmonosecret-resolver`](../monosecret_ipc_resolver/), the pure-C client for
Monosecret's out-of-process resolution protocol.
