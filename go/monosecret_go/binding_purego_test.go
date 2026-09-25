//go:build !monosecret_static && !pkgconfig

package monosecret

import (
	"runtime"
	"testing"
)

// Monosecret keeps the `monosecret_ffi` artifact name as its canonical
// dynamic-library name. Upstream SecretSpec 0.21 renamed its artifact to bare
// `libsecretspec` and dlopen-falls back to the old `libsecretspec_ffi` name;
// the fork never shipped under a different name, so a single canonical entry
// per platform is correct here.
func TestLibraryNamesPreferLibmonosecretFFI(t *testing.T) {
	names := libNames()
	want := []string{"libmonosecret_ffi.so"}
	switch runtime.GOOS {
	case "darwin":
		want = []string{"libmonosecret_ffi.dylib"}

	case "windows":
		// Cargo emits monosecret_ffi.dll into target/, while packaged assets use
		// libmonosecret_ffi.dll.
		want = []string{"monosecret_ffi.dll"}
	}

	if len(names) != len(want) {
		t.Fatalf("library names = %v, want %v", names, want)
	}

	for i, name := range want {
		if names[i] != name {
			t.Fatalf("library names = %v, want %v", names, want)
		}
	}
}