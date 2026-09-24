# Configuration schemas

These self-contained JSON Schemas are published verbatim by Astro at
`https://ifiokjr.github.io/monosecret/schema/monosecret.schema.json` and
`https://ifiokjr.github.io/monosecret/schema/config.schema.json`.

These files are generated from the TOML document model in
`monosecret/src/config.rs` using Schemars. Custom wire forms and TOML-specific
transforms live in `monosecret/src/config_schema.rs`. Do not edit the JSON by
hand. Label unreleased fields and enum values with their minimum version in the
Rust doc comments used as completion descriptions.

Regenerate from the repository root (CLI commands available in 0.4+):

```sh
devenv shell cargo run -p monosecret --no-default-features --features cli -- schema --config project --output docs/public/schema/monosecret.schema.json
devenv shell cargo run -p monosecret --no-default-features --features cli -- schema --config global --output docs/public/schema/config.schema.json
```

Run `devenv shell cargo test -p monosecret --no-default-features --features cli --test config_schemas`.
The tests check that both files match CLI output exactly, compile both schemas,
exercise the project TOML deserializer, and check valid and invalid shapes. The schemas
deliberately flag unknown fields to catch editor typos, even where serde ignores
them. They do not replace runtime semantic or provider-specific validation.
