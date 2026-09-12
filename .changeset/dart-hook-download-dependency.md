---
"dart": fix
---

# Record the downloaded FFI payload as a hook build dependency

The Dart build hook downloads the release's `monosecret-ffi-*` payload into a
shared cache and copies it into the build output, but never recorded the
payload as a hook dependency. Hook inputs do not change when a release
changes the downloaded artifact, so runners that cache by input could replay
the previous release's library: a Dart SDK upgrade from 0.3.3 to 0.3.4 kept
loading a cached 0.3.3 dylib and every resolve failed with
`Native ABI version 0.3.3 does not match Dart package version 0.3.4` until
`.dart_tool` was deleted by hand.

The downloaded payload is now recorded through `output.dependencies`, keyed
under `monosecret/<verified-sha256>/` in the shared output directory, so a
changed release artifact (or a cleared cache) re-runs the hook instead of
replaying stale output.

The failure modes of this bug class are now covered by end-to-end hook tests
(`testBuildHook` against a fake release fetcher): the copied asset and its
recorded dependency must track the served payload across runs with identical
hook inputs, a payload that violates its sidecar fails closed, and the
`Native ABI version` mismatch error now tells consumers how to recover
(delete `.dart_tool` and rebuild). Consumers recovering from an
already-cached stale library still need to do that once; the check keeps
failing closed.
