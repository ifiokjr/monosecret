---
"rust:monosecret":
  bump: patch
  type: feat
"@monosecret/skill":
  bump: patch
  type: feat
---

# Add DigitalOcean Secrets Manager and Convex providers

Two new default-enabled providers: digitalocean://SECRET_NAME?region=REGION manages the key-value pairs inside one DigitalOcean Secrets Manager secret with merge writes and version-conflict retries, and convex://DEPLOYMENT manages per-deployment environment variables through the Convex deployment API with batch upserts and null-value deletes. Both support read, write, delete, discovery, the token provider credential with environment fallbacks, and full documentation.
