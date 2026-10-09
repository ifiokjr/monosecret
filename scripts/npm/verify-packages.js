#!/usr/bin/env node

// Guards the npm manifests against the 0.4.1 publish failure:
// `@monosecret/cli` shipped with `workspace:*` optionalDependencies, which
// `npm publish` passes through verbatim — the pnpm workspace protocol means
// nothing on the registry, so every fresh `npm install @monosecret/cli`
// failed to resolve the platform packages. Runs in CI (packaging job) and
// again in the publish workflow before anything is published.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../..");

export const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

// Registry clients resolve none of these. `file:` is deliberately absent:
// `npm publish` bundles file-referenced packages into the tarball.
export const PROTOCOL_REFERENCES = ["workspace:", "link:", "catalog:"];

/**
 * Collects workspace-protocol dependency references that `npm publish` would
 * ship verbatim. Registry clients cannot resolve any of them outside this
 * repository.
 *
 * @param {Record<string, unknown>} manifest
 * @returns {string[]} offending `field > name > value` descriptions
 */
export function protocolReferenceViolations(manifest) {
  const violations = [];
  for (const field of DEPENDENCY_FIELDS) {
    const dependencies = manifest[field];
    if (typeof dependencies !== "object" || dependencies === null) {
      continue;
    }
    for (const [name, reference] of Object.entries(dependencies)) {
      if (
        typeof reference === "string" &&
        PROTOCOL_REFERENCES.some((prefix) => reference.startsWith(prefix))
      ) {
        violations.push(`${field} > ${name} > ${reference}`);
      }
    }
  }
  return violations;
}

/**
 * Collects optionalDependencies that do not resolve inside the workspace: the
 * referenced package must exist and its manifest version must match the pin
 * exactly. A stale pin installs an older platform binary than the release it
 * ships with.
 *
 * @param {{ name: string, version: string, optionalDependencies?: Record<string, string> }} manifest
 * @param {Map<string, { version: string }>} workspacePackagesByName
 * @returns {string[]} offending `name > pin (workspace has x.y.z)` descriptions
 */
export function unresolvableOptionalDependencies(manifest, workspacePackagesByName) {
  const violations = [];
  for (const [name, pin] of Object.entries(manifest.optionalDependencies ?? {})) {
    const workspacePackage = workspacePackagesByName.get(name);
    if (!workspacePackage) {
      violations.push(`${name} > ${pin} (no such workspace package)`);
      continue;
    }
    if (workspacePackage.version !== pin) {
      violations.push(`${name} > ${pin} (workspace has ${workspacePackage.version})`);
    }
  }
  return violations;
}

/**
 * Validates every npm package manifest in the workspace.
 *
 * @param {string} packagesDir directory containing the npm package folders
 * @returns {string[]} all violations; empty when the manifests publish cleanly
 */
export function collectManifestViolations(packagesDir) {
  const workspacePackagesByName = new Map();
  for (const entry of readdirSync(packagesDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !existsSync(join(packagesDir, entry.name, "package.json"))) {
      continue;
    }
    const manifest = JSON.parse(
      readFileSync(join(packagesDir, entry.name, "package.json"), "utf8"),
    );
    workspacePackagesByName.set(manifest.name, manifest);
  }

  const violations = [];
  for (const [name, manifest] of workspacePackagesByName) {
    for (const violation of protocolReferenceViolations(manifest)) {
      violations.push(`${name}: ${violation} is a workspace-only protocol reference`);
    }
    for (const violation of unresolvableOptionalDependencies(manifest, workspacePackagesByName)) {
      violations.push(`${name}: optional dependency ${violation}`);
    }
  }
  return violations;
}

export function main() {
  const packagesDir = join(repoRoot, "npm");
  const violations = collectManifestViolations(packagesDir);
  if (violations.length > 0) {
    for (const violation of violations) {
      console.error(`::error::${violation}`);
    }
    console.error(
      "npm manifests must reference workspace packages by publishable versions: registry " +
        "clients cannot resolve workspace protocols, and a stale pin installs a mismatched " +
        "platform binary. Pin exact versions — monochange rewrites them on release via the " +
        "versioned_files entries in monochange.toml.",
    );
    process.exitCode = 1;
    return;
  }
  const manifests = readdirSync(packagesDir, { withFileTypes: true }).filter(
    (entry) => entry.isDirectory() && existsSync(join(packagesDir, entry.name, "package.json")),
  );
  console.log(`Verified ${manifests.length} npm package manifests`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
