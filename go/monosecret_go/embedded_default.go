//go:build !embed_lib

package monosecret

// Built without the `embed_lib` tag: no embedded library, so the SDK uses
// MONOSECRET_FFI_LIB or a Cargo target directory. Release/distribution builds
// pass `-tags monosecret_embed` (with the per-platform libraries staged into lib/).
var embeddedLib []byte

const embeddedLibName = ""
