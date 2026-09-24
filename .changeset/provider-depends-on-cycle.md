---
"rust:monosecret": fix
---

# Provider `depends_on` secrets no longer overflow the stack when they resolve through that provider

Forcing a provider that declares `depends_on` (e.g. `monosecret run
--provider op`) applied the session-wide override to the bootstrap secret too,
so building the provider needed the provider: unbounded recursion ending in
`thread 'main' has overflowed its stack` with no error to report or retry
against. The same abort happened for genuine configuration cycles (a
`depends_on` secret routed back at its own provider directly or through
profile defaults).

Bootstrap secrets now resolve from their own declared routes — the
`--provider` flag, the builder override, and `MONOSECRET_PROVIDER` are ignored
while they resolve — so `--provider op` reads `OP_SERVICE_ACCOUNT_TOKEN` from
where it is configured and then queries 1Password. Re-entrant construction is
tracked per thread and fails with a `provider dependency cycle: store ->
TOKEN -> store` error naming the chain, and config loading rejects the direct
form up front (`monosecret check` reports it before anything runs). Six
regression tests cover the flag, the environment variable, both config-cycle
spellings, and static validation.
