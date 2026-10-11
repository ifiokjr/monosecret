---
"rust:monosecret":
  bump: patch
  type: feat
---

# Batch DigitalOcean reads and address keys with `path`

The `digitalocean` provider now overrides `Provider::get_many`: every key a
resolution needs from one secret object is validated first and then served
from a single `GET /v2/security/secrets/{name}?region=…`, however many
declarations point into it. A profile of eight secrets previously cost eight
requests; it now costs one, and `exists_many` reuses the same read.

Provider references with `path` and `key`, and `ref` tables with `section`
and `field`, are now supported. DigitalOcean stores flat string maps, so the
coordinates become a key prefix inside the object selected by the URI, joined
with a double underscore:

```toml
[providers]
do = { uri = "digitalocean://monochange-dev?region=lon1", depends_on = [
  { secret = "DIGITALOCEAN_ACCESS_TOKEN" },
] }

[profiles.production]
JWT_SECRET = { providers = [
  { provider = "do", path = [
    "auth",
  ] },
] } # key auth__JWT_SECRET
GITHUB_TOKEN = { providers = [
  { provider = "do", path = [
    "github",
  ], key = "token" },
] } # key github__token
```

Convention addresses and `ref = { item = "KEY" }` keep reading `KEY`
unchanged. `configured_entry_coordinates` reports the flat key, so two
spellings of one key are recognised as the same entry, and a `version`
coordinate is rejected because secrets are read at their latest version. The
provider guide adds a "use one DigitalOcean secret per project" walkthrough
and a cache example for the inline `cache` form.
