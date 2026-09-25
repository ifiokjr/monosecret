//! Schemas for the TOML document types, including their custom wire forms.

use std::borrow::Cow;

use schemars::JsonSchema;
use schemars::Schema;
use schemars::SchemaGenerator;
use schemars::json_schema;

use super::CredentialSource;
use super::CredentialSourceTable;
use super::ProviderAlias;
use super::ProviderAliasTable;
use super::RequireReason;

impl JsonSchema for CredentialSource {
	fn schema_name() -> Cow<'static, str> {
		"CredentialSource".into()
	}

	fn json_schema(generator: &mut SchemaGenerator) -> Schema {
		json_schema!({
			"description": "Provider supplying a credential, optionally with native coordinates.",
			"anyOf": [String::json_schema(generator), CredentialSourceTable::json_schema(generator)]
		})
	}
}

impl JsonSchema for ProviderAlias {
	fn schema_name() -> Cow<'static, str> {
		"ProviderAlias".into()
	}

	fn json_schema(generator: &mut SchemaGenerator) -> Schema {
		// Derive the fields from the deserializer's table, then express the
		// combinations accepted by its match arms. This keeps field types and
		// documentation in one place without changing parse diagnostics.
		let mut table = ProviderAliasTable::json_schema(generator);
		table.insert(
			"oneOf".into(),
			serde_json::json!([
				{
					"required": ["uri"],
					"not": {"anyOf": [{"required": ["fallback"]}, {"required": ["ref", "cache"]}]}
				},
				{
					"required": ["fallback", "cache"],
					"not": {"anyOf": [{"required": ["uri"]}, {"required": ["credentials"]}, {"required": ["ref"]}]}
				}
			]),
		);
		// A cached route needs at least one non-empty fallback, matching the
		// `ProviderAlias::cached` constructor.
		if let Some(fallback) = table
			.get_mut("properties")
			.and_then(|p| p.get_mut("fallback"))
			.and_then(|f| f.as_object_mut())
		{
			fallback.insert("minItems".into(), 1.into());
			if let Some(items) = fallback.get_mut("items").and_then(|i| i.as_object_mut()) {
				items.insert("minLength".into(), 1.into());
			}
		}
		json_schema!({
			"description": "Provider URI, provider table, or cached fallback chain (0.17+).",
			"anyOf": [String::json_schema(generator), table]
		})
	}
}

impl JsonSchema for RequireReason {
	fn schema_name() -> Cow<'static, str> {
		"RequireReason".into()
	}

	fn json_schema(_: &mut SchemaGenerator) -> Schema {
		json_schema!({
			"description": "When to require an access reason. Defaults to agents.",
			"anyOf": [{"type": "boolean"}, {"type": "string", "enum": ["agents"]}]
		})
	}
}

/// TOML has no null. Keep optional properties optional, but remove the null
/// alternative that derives normally generate for Option<T>. Close fixed
/// tables for typo detection while preserving maps and flattened profiles.
///
/// The project's structured provider form also gets the same combination rules
/// the runtime enforces, so an editor flags a contradictory alias while typing
/// instead of after `monosecret` parses the file. The user-level
/// [`ProviderAlias`] carries these rules through its own `JsonSchema` impl.
#[cfg(feature = "cli")]
fn toml_schema(schema: &mut Schema) {
	if let Some(types) = schema.get_mut("type").and_then(|v| v.as_array_mut()) {
		types.retain(|value| value != "null");
	}
	for keyword in ["anyOf", "oneOf"] {
		if let Some(variants) = schema.get_mut(keyword).and_then(|v| v.as_array_mut()) {
			variants.retain(|value| value.get("type").and_then(|v| v.as_str()) != Some("null"));
		}
	}
	if schema
		.get("default")
		.is_some_and(serde_json::Value::is_null)
	{
		schema.remove("default");
	}
	if schema.get("properties").is_some() && schema.get("additionalProperties").is_none() {
		schema.insert("additionalProperties".into(), false.into());
	}
	if schema.get("title").and_then(|t| t.as_str()) == Some("ProviderConfigStructured") {
		schema.insert(
			"oneOf".into(),
			serde_json::json!([
				{
					"required": ["uri"],
					"not": {"anyOf": [{"required": ["fallback"]}, {"required": ["ref", "cache"]}]}
				},
				{
					"required": ["fallback", "cache"],
					"not": {"anyOf": [{"required": ["uri"]}, {"required": ["credentials"]}, {"required": ["ref"]}]}
				}
			]),
		);
	}
	schemars::transform::transform_subschemas(&mut toml_schema, schema);
	// schemars adds the `title` after the transform pass, so the structured
	// provider form is identified by the fields it declares instead. Only that
	// one form combines `uri` with `fallback` or a `ref` template, so the
	// property set is a stable discriminator.
	let is_structured_provider = schema
		.get("properties")
		.and_then(|p| p.as_object())
		.is_some_and(|properties| {
			properties.contains_key("depends_on")
				&& properties.contains_key("uri")
				&& properties.contains_key("fallback")
		});
	if is_structured_provider {
		schema.insert(
			"oneOf".into(),
			serde_json::json!([
				{
					"required": ["uri"],
					"not": {"anyOf": [{"required": ["fallback"]}, {"required": ["ref", "cache"]}]}
				},
				{
					"required": ["fallback", "cache"],
					"not": {"anyOf": [{"required": ["uri"]}, {"required": ["credentials"]}, {"required": ["ref"]}]}
				}
			]),
		);
		// The runtime requires a cached route to name at least one non-empty
		// fallback, so the editor rejects an empty list too.
		if let Some(fallback) = schema
			.get_mut("properties")
			.and_then(|p| p.get_mut("fallback"))
			.and_then(|f| f.as_object_mut())
		{
			fallback.insert("minItems".into(), 1.into());
			if let Some(items) = fallback.get_mut("items").and_then(|i| i.as_object_mut()) {
				items.insert("minLength".into(), 1.into());
			}
		}
	}
}

/// Generate a self-contained editor schema from this build's document model.
#[cfg(feature = "cli")]
pub(crate) fn generate(global: bool) -> Result<String, serde_json::Error> {
	let generator = schemars::generate::SchemaSettings::draft07()
		.with_transform(toml_schema)
		.into_generator();
	let (mut schema, name, title) = if global {
		(
			generator.into_root_schema_for::<super::GlobalConfig>(),
			"config",
			"Monosecret user configuration",
		)
	} else {
		(
			generator.into_root_schema_for::<super::Config>(),
			"monosecret",
			"Monosecret project configuration",
		)
	};
	schema.insert(
		"$id".into(),
		format!("https://ifiokjr.github.io/monosecret/schema/{name}.schema.json").into(),
	);
	schema.insert("title".into(), title.into());
	schema.insert("$comment".into(), "Generated by monosecret schema --config. Do not edit by hand. Runtime validation also checks cross-field and provider-specific constraints.".into());
	// Other workspace dependencies may enable serde_json's preserve_order
	// feature. Canonicalize keys so the published files do not depend on which
	// provider features were enabled when building the CLI.
	let mut value = serde_json::to_value(schema)?;
	value.sort_all_objects();
	Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
}
