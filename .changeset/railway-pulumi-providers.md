---
"rust:monosecret":
  bump: patch
  type: feat
"@monosecret/skill":
  bump: patch
  type: feat
---

# Add Railway and Pulumi ESC providers

Two new default-enabled providers: `railway://PROJECT_ID?environment=…`
manages environment variables on one Railway environment and service (or its
shared variables) through the GraphQL API, with name-to-ID resolution,
unrendered reads, sealed-variable reporting, and project-token
authentication; `pulumi://ORG[/PROJECT]/ENVIRONMENT` manages one Pulumi ESC
environment's `values` through the Pulumi Cloud REST API, wrapping writes as
`fn::secret`, reading back through the decrypt endpoint, and retrying
ETag-conflicted read-modify-write cycles. Both support read, write, delete,
discovery, the `token` provider credential with environment fallbacks, and
full documentation.
