---
rust:monosecret_rpc: patch
---

# Release completed IPC request slots before publishing responses

Sequential resolver calls no longer intermittently return `unavailable`
after filling the negotiated request window. A completed handler keeps its
slot until the bounded writer takes its response, then releases the slot
before the client can read that response. Cleanup still observes whether
the response was written, and cancelled or timed-out handlers retain their
slots until they actually stop.
