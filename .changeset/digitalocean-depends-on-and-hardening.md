---
"rust:monosecret": fix
---

# Authenticate DigitalOcean from `depends_on` tokens

A `digitalocean` alias declaring
`depends_on = [{ secret = "DIGITALOCEAN_ACCESS_TOKEN" }]` resolved the token
and then dropped it, because the provider did not implement
`configure_dependency_secrets`. It only worked when the same token also
happened to be in the process environment. The provider now accepts a
dependency named `DIGITALOCEAN_ACCESS_TOKEN` or `DIGITALOCEAN_TOKEN`. The
token precedence is the `token` credential, then the `depends_on` token, then
the environment variables.

Hardening in the same provider:

- Secret names made only of dots (`.`, `..`) are rejected when the URI is
  parsed. They would be normalized out of the request path and send the token
  to a different API endpoint.
- A malformed success response reports only the parse error's category and
  position. serde's message can quote the body, which carries plaintext
  values.
- A rejected write replaces every value the request carried with
  `[REDACTED]` in the quoted API error, before the detail is truncated.
- The request and response types that hold values no longer derive `Debug`.
