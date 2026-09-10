---
"rust:monosecret": fix
---

# Cut 1Password service-account reads from one-per-secret to one-per-item

Every secret reference `op inject` resolves is an individually billed read
against the 1Password service-account rate limits. Manifests that pin a whole
profile to one shared item (`op+token://Vault/Item`, with `path`-routed
secrets) paid one request per secret on every resolve, `run`, and devenv
startup — the global dotfiles manifest (17 secrets) spent ~18 reads per run,
nifty's development profile ~20 — which drains the account-wide daily pool.

Field references are now served from batched `op item get` reads: one billed
read per _item_, however many secrets read fields of it, with section and
field matched client-side. The full-resolution budget for a shared-item
manifest is two requests per run (auth preflight + one item read), and `op
inject` plus the per-secret read recovery remain as the correctness fallback
for references the item reads cannot serve (ambiguous titles, unusable
output, fields present but unservable).

`Too many requests` is also classified as a global failure alongside auth
errors. While throttled, every retried or fanned-out attempt is itself a
billed request that extends the lockout, so a rate-limited batch now surfaces
the error after its single failed request instead of cascading.
