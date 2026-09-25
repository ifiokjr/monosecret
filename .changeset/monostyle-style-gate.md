---
docs: patch
monosecret: patch
monosecret-ipc: patch
monosecret-ipc-conformance: patch
monosecret-php-native: patch
monosecret_client_native: patch
monosecret_derive: patch
monosecret_derive-example: patch
monosecret_ffi: patch
monosecret_py_native: patch
---

# Apply the monostyle style gate

Blank-line layout from `monostyle fix` (padding around control flow, a blank before returns, collapse of stacked blank runs), with `monostyle.toml` configuring the rules and a CI step that reports findings as inline PR annotations.
