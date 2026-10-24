//! The value-carrying resolve payload: the FFI/SDK boundary.
//!
//! Unlike the value-free [`crate::report::ResolutionReport`] (which powers
//! `check --json` and must never expose a value), this payload **does** carry
//! the resolved secret values. It is the single authoritative output that any
//! other-language SDK consumes over the C ABI. Producing it deliberately exposes
//! secrets, so it is only built at an explicit resolve boundary and its bytes
//! must be treated as sensitive by the caller.
//!
//! On a successful resolution `secrets` holds one entry per declared secret
//! that produced a value; `missing_optional` lists optional secrets with no
//! value. When a required secret is missing, resolution is an error: `secrets`
//! is empty and `missing_required` is populated, mirroring the derive crate's
//! `load()` which fails rather than returning partial secrets.
//!
//! The `no_values` request variant (and [`crate::Secrets::resolve_without_values`])
//! produces the same shape with every `value`/`path` set to `None`, and is
//! additionally side-effect-free: it never mints a generated secret and never
//! writes an `as_path` temp file.
//!
//! The shape is versioned via [`RESOLVE_SCHEMA_VERSION`]. The canonical JSON
//! Schema lives at `schema/resolve-response.schema.json`.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Version of the [`ResolveResponse`] wire format.
pub const RESOLVE_SCHEMA_VERSION: u32 = 2;

/// Formats an `Option`'s presence without its contents.
///
/// `ResolvedSecret::value` carries the secret itself and `path` names the temp
/// file holding it, so neither may reach a `{:?}`/`{:#?}` rendering — a logged
/// error payload, a `dbg!`, an SDK converting errors to strings. The `Some`
/// presence (and its type-independent shape) stays visible for diagnosis.
struct RedactedPresence<T>(Option<T>);

impl<T> fmt::Debug for RedactedPresence<T> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.0.as_ref() {
			Some(_) => formatter.write_str("Some([REDACTED])"),
			None => formatter.write_str("None"),
		}
	}
}

/// Where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedSource {
	/// Returned by a storage provider.
	Provider,
	/// Freshly minted by the secret's `generate` config.
	Generated,
	/// The manifest's committed `default` value.
	Default,
	/// Derived from other declared secrets: a strict `composed` template, or a
	/// `from` conversion or selection. The serialized name remains `composed`
	/// for wire compatibility.
	///
	/// Template composition is available since Monosecret 0.16; `from`
	/// derivation is available since Monosecret 0.5.0.
	Composed,
}

/// One resolved secret. Exactly one of `value` or `path` is set: `path` when
/// the secret is materialized to a temp file (`as_path`), `value` otherwise.
/// The default inline type is `String` for text/JSON APIs. Byte resolution
/// APIs use [`crate::SecretBytes`] starting with 0.4.0.
///
/// `Debug` never renders `value` or `path`, for any payload type: the derived
/// impl would print a `String` payload wholesale (`SecretBytes` already
/// redacts itself, but `T = String` — the wire default — does not).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret<T = String> {
	/// The secret value, when exposed inline.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub value: Option<T>,
	/// Path to the temp file holding the value, when `as_path` is set.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<String>,
	/// Whether this secret is exposed as a file path rather than inline.
	pub as_path: bool,
	/// Whether the value came from a provider, a generator, or a default.
	pub source: ResolvedSource,
	/// Credential-free URI of the provider that answered, when `source` is
	/// `provider`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub source_provider: Option<String>,
}

impl<T> fmt::Debug for ResolvedSecret<T> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ResolvedSecret")
			.field("value", &RedactedPresence(self.value.as_ref()))
			.field("path", &RedactedPresence(self.path.as_ref()))
			.field("as_path", &self.as_path)
			.field("source", &self.source)
			.field("source_provider", &self.source_provider)
			.finish()
	}
}

/// A complete value-carrying resolution result for one profile.
/// The default `String` payload is the JSON wire format; Rust byte resolution
/// uses `ResolveResponse<SecretBytes>` (0.4.0+) without a Serde representation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResponse<T = String> {
	/// Wire-format version; see [`RESOLVE_SCHEMA_VERSION`].
	pub schema_version: u32,
	/// Credential-free URI of the provider the resolution reported against.
	/// Empty when no provider was contacted, which happens when a scope's
	/// intersection with the selected profile is empty and there is nothing to
	/// resolve.
	pub provider: String,
	/// The profile that was resolved.
	pub profile: String,
	/// The active secret scope, when resolution was scoped (`--scope`,
	/// `MONOSECRET_SCOPE`, or the SDK builder). `None` — the whole profile
	/// resolved — is omitted from JSON, so unscoped output is unchanged.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scope: Option<String>,
	/// Resolved secrets by name. Empty when a required secret is missing.
	/// `BTreeMap` keeps the JSON object key order deterministic.
	pub secrets: BTreeMap<String, ResolvedSecret<T>>,
	/// Required secrets that were not found anywhere. Non-empty means the
	/// resolution failed; `secrets` is then empty.
	pub missing_required: Vec<String>,
	/// Optional secrets that were not found.
	pub missing_optional: Vec<String>,
}

impl<T> fmt::Debug for ResolveResponse<T> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ResolveResponse")
			.field("schema_version", &self.schema_version)
			.field("provider", &self.provider)
			.field("profile", &self.profile)
			.field("scope", &self.scope)
			.field("secrets", &self.secrets)
			.field("missing_required", &self.missing_required)
			.field("missing_optional", &self.missing_optional)
			.finish()
	}
}

impl<T> ResolveResponse<T> {
	/// True when no required secret is missing (the resolution succeeded).
	pub fn is_ok(&self) -> bool {
		self.missing_required.is_empty()
	}

	/// Drop every inline value, keeping structure and provenance. Useful for an
	/// inventory/policy consumer that wants the resolve shape without secrets.
	#[must_use]
	pub fn without_values(mut self) -> Self {
		for secret in self.secrets.values_mut() {
			secret.value = None;
			secret.path = None;
		}

		self
	}
}

/// The outcome of resolving one secret by name with
/// [`crate::Secrets::resolve_named`].
///
/// The three variants separate the questions a batch resolve conflates: whether
/// the name exists on the active surface at all, whether it produced a value,
/// and whether its absence is an error. A genuine provider or configuration
/// failure is never one of these variants; it surfaces as `Err` from the call.
///
/// Available since Monosecret 0.19.
/// Byte resolution uses `NamedResolution<SecretBytes>` starting with 0.4.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedResolution<T = String> {
	/// The name is not declared on the active resolution surface: either absent
	/// from the merged profile, or declared but hidden by the active scope. The
	/// caller asked about a secret this configuration does not offer, which is
	/// usually a bug in the caller rather than a missing value.
	Undeclared,
	/// The secret is declared but produced no value.
	Missing {
		/// Whether the profile declares this secret required, which is what
		/// makes the absence an error for a whole-profile resolve. Reported here
		/// rather than decided: a named resolve returns this variant either way
		/// and leaves the policy to the caller.
		required: bool,
	},
	/// The secret produced a value.
	Resolved(ResolvedSecret<T>),
}

/// Which resolution shape a request asks for.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RequestMode {
	/// The value-carrying [`ResolveResponse`] (the default).
	#[default]
	Resolve,
	/// The value-free [`crate::report::ResolutionReport`]: per-secret status and
	/// provenance, never a value, and a missing required secret is reported as a
	/// status rather than failing the call. This is the inventory/preflight view
	/// the CLI exposes as `check --json`.
	Report,
}

#[derive(Debug, Default, Deserialize)]
struct JsonRequest {
	#[serde(default)]
	path: Option<String>,
	#[serde(default)]
	provider: Option<String>,
	#[serde(default)]
	profile: Option<String>,
	#[serde(default)]
	scope: Option<String>,
	#[serde(default)]
	reason: Option<String>,
	/// Structured software-integration identity (Monosecret 0.20+). This is
	/// informational context and does not satisfy `require_reason`.
	#[serde(default)]
	caller: Option<crate::CallerContext>,
	#[serde(default)]
	no_values: bool,
	#[serde(default)]
	mode: RequestMode,
	/// Ephemeral `--include` selection (CLI/SDK). A secret outside the union of
	/// `include` and `groups` is neither resolved nor reported missing.
	#[serde(default)]
	include: Vec<String>,
	/// Ephemeral `--group` selection (CLI/SDK). See [`JsonRequest::include`].
	#[serde(default)]
	groups: Vec<String>,
}

fn error_envelope(kind: &str, message: impl Into<String>) -> serde_json::Value {
	serde_json::json!({
		"ok": false,
		"error": { "kind": kind, "message": message.into() },
	})
}

fn ok_envelope(response: impl Serialize) -> serde_json::Value {
	serde_json::json!({ "ok": true, "response": response })
}

fn dispatch(request_json: &str) -> serde_json::Value {
	let request: JsonRequest = match serde_json::from_str(request_json) {
		Ok(request) => request,
		Err(e) => return error_envelope("invalid_request", format!("invalid request JSON: {e}")),
	};

	let loaded = match &request.path {
		Some(path) => crate::Secrets::load_from(std::path::Path::new(path)),
		None => crate::Secrets::load(),
	};

	let mut app = match loaded {
		Ok(app) => app,
		Err(e) => return error_envelope(e.kind(), crate::error::display_error_chain(&e)),
	};

	if let Some(provider) = request.provider {
		app.set_provider(provider);
	}

	if let Some(profile) = request.profile {
		app.set_profile(profile);
	}

	if let Some(scope) = request.scope {
		app.set_scope(scope);
	}

	if let Some(reason) = request.reason {
		app = app.with_reason(reason);
	}

	if let Some(caller) = request.caller {
		app = app.with_caller(caller);
	}

	match request.mode {
		// Value-free report: never fails on a missing required secret, so an
		// inventory/preflight consumer always gets the shape back.
		RequestMode::Report => {
			let report = if request.include.is_empty() && request.groups.is_empty() {
				app.report()
			} else {
				app.report_filtered(&request.include, &request.groups)
			};
			match report {
				Ok(report) => ok_envelope(report),
				Err(e) => error_envelope(e.kind(), crate::error::display_error_chain(&e)),
			}
		}
		// Value-carrying resolve. `no_values` takes the path that never copies a
		// secret value into the response (and persists no temp file).
		RequestMode::Resolve => {
			let resolved = if request.no_values {
				if request.include.is_empty() && request.groups.is_empty() {
					app.resolve_without_values()
				} else {
					app.resolve_without_values_filtered(&request.include, &request.groups)
				}
			} else if request.include.is_empty() && request.groups.is_empty() {
				app.resolve()
			} else {
				app.resolve_filtered(&request.include, &request.groups)
			};
			match resolved {
				Ok(response) => ok_envelope(response),
				Err(e) => error_envelope(e.kind(), crate::error::display_error_chain(&e)),
			}
		}
	}
}

/// Resolve secrets from a JSON request string and return the JSON response
/// envelope: `{"ok": true, "response": <ResolveResponse | ResolutionReport>}` or
/// `{"ok": false, "error": {"kind", "message"}}`.
///
/// This is the shared JSON boundary used by every native binding (the C ABI in
/// `monosecret_ffi` and the napi-rs Node addon), so the envelope contract is
/// defined in exactly one place. The request accepts optional `path`,
/// `provider`, `profile`, `scope`, `reason`, `caller` (Monosecret 0.20+),
/// `no_values`, and `mode`
/// (`"resolve"` by default, or `"report"` for the value-free
/// [`crate::report::ResolutionReport`]).
/// A `resolve` response carries secret values; treat its bytes as sensitive. A
/// `report` response never does.
pub fn resolve_json(request_json: &str) -> String {
	// Catch panics here, at the one place both native boundaries funnel through
	// (the C ABI in `monosecret_ffi` and the napi-rs Node addon). Unwinding across
	// either is undefined behavior, and turning a panic into the same
	// `{"ok":false,"error":...}` envelope every binding already parses means all
	// bindings behave identically — the C ABI no longer needs to be the only one
	// guarding the boundary.
	let envelope =
		std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(request_json)))
			.unwrap_or_else(|_| error_envelope("internal", "internal panic during resolve"));

	serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"error\":{\"kind\":\"serialize\",\"message\":\"failed to serialize response\"}}".to_string()
    })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn json_caller_context_is_structured_and_separate_from_reason() {
		let request: JsonRequest = serde_json::from_value(serde_json::json!({
			"caller": {
				"name": "git",
				"version": "2.51.0",
				"operation": "credential_get",
				"resource": "github.com"
			}
		}))
		.unwrap();
		assert_eq!(
			request.caller,
			Some(
				crate::CallerContext::new("git")
					.with_version("2.51.0")
					.with_operation("credential_get")
					.with_resource("github.com")
			)
		);
		assert_eq!(request.reason, None);
	}

	#[test]
	fn json_caller_requires_a_name() {
		let response: serde_json::Value = serde_json::from_str(&resolve_json(
			r#"{"caller":{"operation":"credential_get"}}"#,
		))
		.unwrap();
		assert_eq!(response.get("ok"), Some(&serde_json::Value::Bool(false)));
		assert_eq!(
			response
				.get("error")
				.and_then(|error| error.get("kind"))
				.and_then(serde_json::Value::as_str),
			Some("invalid_request")
		);
	}

	#[test]
	fn debug_never_renders_values_or_paths_for_any_payload() {
		let string_payload = ResolveResponse {
			schema_version: RESOLVE_SCHEMA_VERSION,
			provider: "dotenv://.env".to_string(),
			profile: "default".to_string(),
			scope: None,
			secrets: BTreeMap::from([(
				"API_KEY".to_string(),
				ResolvedSecret {
					value: Some("plaintext-secret".to_string()),
					path: None,
					as_path: false,
					source: ResolvedSource::Provider,
					source_provider: Some("dotenv://.env".to_string()),
				},
			)]),
			missing_required: Vec::new(),
			missing_optional: Vec::new(),
		};
		let rendered = format!("{string_payload:?}\n{string_payload:#?}");
		assert!(
			!rendered.contains("plaintext-secret"),
			"a String payload must never survive Debug: {rendered}"
		);
		assert!(
			rendered.contains("Some([REDACTED])"),
			"presence stays visible: {rendered}"
		);

		let bytes_payload = ResolveResponse {
			schema_version: RESOLVE_SCHEMA_VERSION,
			provider: "dotenv://.env".to_string(),
			profile: "default".to_string(),
			scope: None,
			secrets: BTreeMap::from([(
				"BIN".to_string(),
				ResolvedSecret {
					value: Some(crate::SecretBytes::from_slice(b"byte-secret-payload")),
					path: Some("/tmp/monosecret-xyz/BIN".to_string()),
					as_path: true,
					source: ResolvedSource::Provider,
					source_provider: None,
				},
			)]),
			missing_required: Vec::new(),
			missing_optional: Vec::new(),
		};
		let rendered = format!("{bytes_payload:?}");
		assert!(
			!rendered.contains("byte-secret-payload")
				&& !rendered.contains("/tmp/monosecret-xyz/BIN"),
			"a SecretBytes payload and its as_path temp file must never survive Debug: {rendered}"
		);
	}

	#[test]
	fn debug_keeps_none_presence_visible() {
		let secret = ResolvedSecret::<String> {
			value: None,
			path: None,
			as_path: false,
			source: ResolvedSource::Default,
			source_provider: None,
		};
		let rendered = format!("{secret:?}");
		assert!(
			rendered.contains("value: None") && rendered.contains("path: None"),
			"None stays distinguishable from Some: {rendered}"
		);
	}

	#[test]
	fn debug_redacts_inline_values_through_every_wrapper() {
		let secret = ResolvedSecret {
			value: Some("hunter2".to_string()),
			path: None,
			as_path: false,
			source: ResolvedSource::Provider,
			source_provider: Some("keyring://".to_string()),
		};
		let response = ResolveResponse {
			schema_version: RESOLVE_SCHEMA_VERSION,
			provider: "keyring://".to_string(),
			profile: "default".to_string(),
			scope: None,
			secrets: BTreeMap::from([("PASSWORD".to_string(), secret.clone())]),
			missing_required: Vec::new(),
			missing_optional: Vec::new(),
		};

		for rendered in [
			format!("{secret:?}"),
			format!("{secret:#?}"),
			format!("{response:?}"),
			format!("{:?}", NamedResolution::Resolved(secret.clone())),
		] {
			assert!(!rendered.contains("hunter2"), "{rendered}");
			assert!(rendered.contains("[REDACTED]"), "{rendered}");
		}
		assert_eq!(
			format!("{secret:?}"),
			"ResolvedSecret { value: Some([REDACTED]), path: None, as_path: false, \
             source: Provider, source_provider: Some(\"keyring://\") }"
		);
	}

	#[test]
	fn debug_redacts_as_path_file_paths_too() {
		let secret: ResolvedSecret = ResolvedSecret {
			value: None,
			path: Some("/tmp/.tmpABC".to_string()),
			as_path: true,
			source: ResolvedSource::Provider,
			source_provider: None,
		};

		let rendered = format!("{secret:?}");

		assert!(rendered.contains("value: None"), "{rendered}");
		// The fork's hardening redacts `path` as well: a temp-file path names
		// where the secret bytes live, so it stays out of logs too.
		assert!(!rendered.contains("/tmp/.tmpABC"), "{rendered}");
		assert!(rendered.contains("path: Some([REDACTED])"), "{rendered}");
	}
}
