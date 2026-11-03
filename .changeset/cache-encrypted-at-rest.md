---
rust:monosecret: fix
---

# Refuse caches that would store secrets in plaintext

A cached provider alias whose cache provider does not store values
encrypted at rest is now refused at planning time: the cache envelope
is the secret's value in base64, so a plaintext store would hold a
plaintext copy of every secret it serves. Providers declare encryption
in their registry metadata — keyring, age, sops, and every managed
secret store declare it; env, dotenv, file, and Kubernetes (whose etcd
keeps secrets base64-encoded unless the cluster turns on encryption)
deliberately do not — and an undeclared or external store is refused
rather than assumed safe. An alias that accepts the tradeoff says so
explicitly with `cache.allow_plaintext = true` (0.4.5+), and the error
names the encrypted providers that need no opt-in.
