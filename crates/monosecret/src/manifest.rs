//! Semantic compilation of a parsed manifest.
//!
//! [`Config`](crate::config::Config) is the syntax tree: its `Option` fields
//! record what a particular source/profile wrote. Runtime resolution and
//! generated types instead consume this module's effective view, where profile
//! inheritance and missing-value behavior have already been decided once.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;

use crate::config::Config;
use crate::config::Secret;

/// Secret-value-free manifest for SDK code generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
	/// Project metadata from `[project]`.
	pub project: ManifestProject,
	/// Effective profiles, with inheritance already applied.
	pub profiles: BTreeMap<String, ManifestProfile>,
	/// Declared filtering groups and their descriptions.
	pub groups: BTreeMap<String, String>,
}

/// Project metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestProject {
	pub name: String,
	pub revision: String,
}

/// Effective profile metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestProfile {
	pub secrets: BTreeMap<String, ManifestSecret>,
}

/// Effective secret metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSecret {
	pub required: bool,
	pub has_default: bool,
	pub as_path: bool,
	pub groups: Vec<String>,
}

/// One fully merged secret in an effective profile.
#[derive(Debug, Clone)]
pub(crate) struct CompiledSecret {
	pub(crate) config: Secret,
	/// The effective `required` flag for reporting: a required
	/// generated/defaulted field is still guaranteed on success.
	pub(crate) declared_required: bool,
}

impl CompiledSecret {
	fn new(config: Secret, conditionally_required: bool) -> Self {
		// An inline default makes an omitted `required` behave as false. This
		// preserves the manifest shorthand while keeping an explicit inherited
		// `required = true` visible in reports. Membership in a profile
		// presence constraint likewise replaces the implicit per-secret
		// requirement, while an explicit `required = true` remains independent.
		let declared_required = config
			.required

			.unwrap_or(config.default.is_none() && !conditionally_required);
		Self {
			config,
			declared_required,
		}
	}
}

/// One effective profile, including fields inherited from `default`.
#[derive(Debug, Clone)]
pub(crate) struct CompiledProfile {
	pub(crate) secrets: BTreeMap<String, CompiledSecret>,
}

/// A parsed manifest reduced to the semantics shared by runtime and codegen.
#[derive(Debug, Clone)]
pub(crate) struct CompiledManifest {
	pub(crate) profiles: BTreeMap<String, CompiledProfile>,
}

impl CompiledManifest {
	pub(crate) fn compile(config: &Config) -> Self {
		let default_profile = config.profiles.get("default");
		let mut profiles = BTreeMap::new();

		for (profile_name, profile) in &config.profiles {
			let inherited = (profile_name != "default" && profile.inherits_default())
				.then_some(default_profile)
				.flatten();
			// A `BTreeSet` unions the profile's own names with the inherited
			// ones already deduplicated and sorted, which is the deterministic
			// order every surface consuming the manifest expects.
			let mut names: BTreeSet<&String> = profile.secrets.keys().collect();

			if let Some(default) = inherited {
				names.extend(default.secrets.keys());
			}

			let effective: BTreeMap<String, Secret> = names
				.into_iter()
				.map(|name| {
					let current = profile.secrets.get(name);
					let default = inherited.and_then(|p| p.secrets.get(name));
					let effective = Secret::resolved(
						current,
						default,
						profile.defaults.as_ref(),
						config.defaults.as_ref(),
					)
					.expect("an effective name comes from current or default");
					(name.clone(), effective)
				})
				.collect();

			let secrets = effective
				.into_iter()
				.map(|(name, secret)| {
					let conditionally_required = secret
						.at_least_one
						.as_ref()
						.is_some_and(|groups| !groups.is_empty())
						|| secret
							.exactly_one
							.as_ref()
							.is_some_and(|groups| !groups.is_empty());
					(name, CompiledSecret::new(secret, conditionally_required))
				})
				.collect();

			profiles.insert(profile_name.clone(), CompiledProfile { secrets });
		}

		Self { profiles }
	}

	pub(crate) fn public_manifest(&self, config: &Config) -> Manifest {
		let profiles = self
			.profiles
			.iter()
			.map(|(name, profile)| {
				let secrets = profile
					.secrets
					.iter()
					.map(|(name, secret)| {
						(
							name.clone(),
							ManifestSecret {
								required: secret.declared_required,
								has_default: secret.config.default.is_some(),
								as_path: secret.config.as_path.unwrap_or(false),
								groups: secret.config.groups.clone().unwrap_or_default(),
							},
						)
					})
					.collect();
				(name.clone(), ManifestProfile { secrets })
			})
			.collect();

		Manifest {
			project: ManifestProject {
				name: config.project.name.clone(),
				revision: config.project.revision.clone(),
			},
			profiles,
			groups: config
				.groups
				.clone()
				.unwrap_or_default()
				.into_iter()
				.collect(),
		}
	}
}
