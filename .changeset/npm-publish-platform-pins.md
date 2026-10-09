---
monosecret: fix
---

# Publish npm platform binaries through real version pins

`@monosecret/cli@0.4.1` shipped with `workspace:*` in its
`optionalDependencies`, so `npm install @monosecret/cli` failed with
`No matching version found for @monosecret/cli-darwin-arm64@workspace:*`:
the pnpm workspace protocol means nothing outside this repository, and the
publish pipeline did not rewrite it. Platform binaries and version pins now
follow secretspec's model — exact, always-resolvable version references in
the manifest, bumped by monochange on every release, with a CI gate that
rejects workspace-protocol references outright.

## Also in this change

- **Netlify provider** (`netlify://ACCOUNT_ID`): read, write, delete, and
  discover site or account environment variables through the Netlify API,
  with `NETLIFY_AUTH_TOKEN`/`token` credential auth, deploy-context
  selection, and optional secret-marked write-only values.
- **Vercel provider** (`vercel://PROJECT`): read, write, delete, and
  discover project environment variables through the Vercel API, with
  `VERCEL_TOKEN`/`token` credential auth, team scoping, and target
  selection (`production`, `preview`, `development`).
