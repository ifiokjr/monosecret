//! Pulumi ESC environment secrets provider.
//!
//! [Pulumi ESC](https://www.pulumi.com/docs/esc/) stores each environment as
//! a versioned YAML definition whose `values` map holds configuration and
//! secrets. Monosecret maps a declaration key to one value under `values`,
//! always wrapped as `fn::secret` so the value is encrypted at rest, and
//! selects the environment through the provider URI. Values are read back
//! in plaintext through the decrypt endpoint.
//!
//! Updates fetch the current definition and write the whole definition back
//! with an `ETag` for optimistic concurrency, mirroring `pulumi env set`; a
//! version conflict is retried against the newer definition. The
//! read-modify-write round-trip normalizes the definition's formatting, so
//! point the alias at an environment whose definition Monosecret may manage.
//!
//! # URI format
//!
//! `pulumi://ORG[/PROJECT]/ENVIRONMENT`
//!
//! The optional project segment defaults to `default`, matching
//! `ORG/ENV` references in the Pulumi CLI. Authentication comes from a
//! `token` provider credential or `PULUMI_ACCESS_TOKEN`.

use std::borrow::Cow;
use std::collections::HashMap;

use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde::Serialize;
use serde_norway::Mapping;
use serde_norway::Value;

use super::Address;
use super::DiscoveryContext;
use super::Provider;
use super::ProviderCredentials;
use super::ProviderUrl;
use crate::MonosecretError;
use crate::Result;
use crate::Secret;
use crate::SecretBytes;
use crate::config::NativeAddress;

const TOKEN: &str = "token";
const TOKEN_ENV: &str = "PULUMI_ACCESS_TOKEN";
const TOKEN_ENVS: &[&str] = &[TOKEN_ENV];
const API_BASE: &str = "https://api.pulumi.com";
const DEFAULT_PROJECT: &str = "default";
const SECRET_KEY: &str = "fn::secret";
/// The `values` keys Pulumi reserves for projections; Monosecret neither
/// reads nor writes them.
const RESERVED_KEYS: &[&str] = &[
	"environmentVariables",
	"pulumiConfig",
	"files",
	"policyConfig",
];
/// How many read-modify-write rounds a write may attempt before an `ETag`
/// conflict is reported instead of retried.
const MAX_WRITE_ATTEMPTS: usize = 3;

/// Configuration for one Pulumi ESC environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PulumiConfig {
	/// Pulumi organization name.
	pub org: String,
	/// ESC project name; the Pulumi CLI's default project is `default`.
	pub project: String,
	/// Environment name within the project.
	pub environment: String,
}

impl TryFrom<&ProviderUrl> for PulumiConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "pulumi" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for pulumi provider; expected 'pulumi'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"pulumi:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let org = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"pulumi provider requires an organization and environment, for example pulumi://my-org/production",
				)
			})?;
		validate_name("organization", &org)?;

		// `ProviderUrl::path` is already percent-decoded.
		let path = url.path();
		let segments: Vec<&str> = path
			.split('/')
			.filter(|segment| !segment.is_empty())
			.collect();

		let (project, environment) = match segments.as_slice() {
			[environment] => (DEFAULT_PROJECT.to_string(), environment.to_string()),
			[project, environment] => (project.to_string(), environment.to_string()),
			_ => {
				return Err(operation_error(
					"pulumi:// takes the environment as a path segment, or PROJECT/ENVIRONMENT: pulumi://my-org/production or pulumi://my-org/payments/production",
				));
			}
		};

		validate_name("project", &project)?;
		validate_name("environment", &environment)?;

		if let Some((key, _)) = url.query_pairs().next() {
			return Err(operation_error(format!(
				"unknown pulumi query parameter '{key}'; pulumi:// takes no query parameters"
			)));
		}

		Ok(Self {
			org,
			project,
			environment,
		})
	}
}

/// Accepts Pulumi organization, project, and environment names: non-empty,
/// at most 100 characters, no control characters or separators.
fn validate_name(label: &str, value: &str) -> Result<()> {
	if value.is_empty()
		|| value.len() > 100
		|| value
			.chars()
			.any(|character| character.is_control() || matches!(character, '/' | ' '))
	{
		return Err(operation_error(format!(
			"Pulumi {label} names are non-empty, at most 100 characters, and contain no spaces, slashes, or control characters"
		)));
	}
	Ok(())
}

#[derive(Debug, Deserialize)]
struct ApiError {
	#[serde(default)]
	code: Option<i64>,
	message: String,
}

#[derive(Debug, Deserialize)]
struct Diagnostics {
	#[serde(default)]
	diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Deserialize)]
struct Diagnostic {
	#[serde(default)]
	severity: String,
	#[serde(default)]
	summary: String,
}

#[derive(Debug, Clone)]
struct Definition {
	/// The `ETag` reported with the fetched definition; PATCH sends it back so
	/// concurrent writers conflict instead of overwriting each other.
	etag: String,
	values: Mapping,
}

/// A Pulumi ESC environment secrets provider.
pub struct PulumiProvider {
	config: PulumiConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: PulumiProvider,
	config: PulumiConfig,
	metadata: &super::catalog::PULUMI,
}

impl PulumiProvider {
	pub fn new(config: PulumiConfig) -> Self {
		Self {
			config,
			credentials: ProviderCredentials::new(),
			api_base: API_BASE.to_string(),
		}
	}

	fn token(&self) -> Option<SecretBytes> {
		super::credential_or_envs(&self.credentials, TOKEN, TOKEN_ENVS)
	}

	fn auth_headers(&self) -> Result<HeaderMap> {
		let token = self.token().ok_or_else(|| {
			operation_error(format!(
				"Pulumi auth requires the `{TOKEN}` provider credential or {TOKEN_ENV}"
			))
		})?;

		let mut headers = HeaderMap::new();
		headers.insert(AUTHORIZATION, pulumi_header(token.expose_secret())?);
		Ok(headers)
	}

	fn client(&self) -> Result<reqwest::Client> {
		super::http::client_builder()
			.default_headers(self.auth_headers()?)
			// Secret-bearing bodies must remain confined to Pulumi Cloud's
			// fixed API origin; a redirect response must never choose where
			// a PATCH body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build Pulumi HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	/// `/api/esc/environments/{org}/{project}/{env}` without a query string.
	fn environment_path(&self) -> String {
		format!(
			"{}/api/esc/environments/{}/{}/{}",
			self.api_base.trim_end_matches('/'),
			self.config.org,
			self.config.project,
			self.config.environment
		)
	}

	fn create_path(&self) -> String {
		format!(
			"{}/api/esc/environments/{}",
			self.api_base.trim_end_matches('/'),
			self.config.org
		)
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if RESERVED_KEYS.contains(&name.as_ref()) {
			return Err(operation_error(format!(
				"'{name}' is a Pulumi-reserved values key: Pulumi projects it into consumers, so Monosecret will not read, write, or delete it"
			)));
		}

		if !is_valid_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid Pulumi ESC key here: keys are ASCII letters, digits, or underscores and start with a letter or underscore"
			)));
		}

		Ok(name)
	}

	/// Fetches the current definition with its `ETag`; `None` on 404. An empty
	/// body is a fresh environment with no values yet.
	async fn get_definition(&self, client: &reqwest::Client) -> Result<Option<Definition>> {
		let action = "reading the environment definition";
		let response = client
			.get(self.environment_path())
			.header("accept", "application/vnd.pulumi+8")
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let status = response.status();
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}

		let etag = response
			.headers()
			.get("etag")
			.and_then(|value| value.to_str().ok())
			.map(str::to_string)
			.ok_or_else(|| operation_error(format!("Pulumi returned no ETag while {action}")))?;

		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;
		check_status(status, &body, action)?;

		let text = std::str::from_utf8(&body).map_err(|_| {
			operation_error(format!("Pulumi returned non-UTF-8 YAML while {action}"))
		})?;

		Ok(Some(Definition {
			etag,
			values: parse_values(text)?,
		}))
	}

	/// Creates the environment, used when `set` finds it missing.
	async fn create_environment(&self, client: &reqwest::Client) -> Result<()> {
		let action = "creating the environment";
		let response = client
			.post(self.create_path())
			.header("accept", "application/vnd.pulumi+8")
			.json(&CreateEnvironment {
				project: &self.config.project,
				name: &self.config.environment,
			})
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;
		check_status(status, &body, action)
	}

	/// Replaces the definition, sending the `ETag` the definition was read
	/// with; `Ok(false)` means the `ETag` no longer matches (a 409 conflict).
	async fn patch_definition(
		&self,
		client: &reqwest::Client,
		definition: &Definition,
	) -> Result<bool> {
		let action = "writing the environment definition";
		let yaml =
			serde_norway::to_string(&values_document(&definition.values)).map_err(|error| {
				operation_error(format!(
					"failed to serialize the Pulumi environment definition: {}",
					crate::error::display_error_chain(&error)
				))
			})?;

		let response = client
			.patch(self.environment_path())
			.header("accept", "application/vnd.pulumi+8")
			.header("content-type", "application/x-yaml")
			.header("etag", &definition.etag)
			.body(yaml)
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		if response.status() == reqwest::StatusCode::CONFLICT {
			return Ok(false);
		}

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;
		check_status(status, &body, action)?;

		let outcome: Diagnostics = serde_json::from_slice(&body).map_err(|error| {
			operation_error(format!(
				"Pulumi returned invalid JSON while {action}: {}",
				crate::error::display_error_chain(&error)
			))
		})?;

		if let Some(error) = outcome
			.diagnostics
			.iter()
			.find(|diagnostic| diagnostic.severity == "error")
		{
			return Err(operation_error(format!(
				"Pulumi reported an error while {action}: {}",
				error.summary
			)));
		}

		Ok(true)
	}

	/// Fetches the decrypted definition; `None` on 404. The decrypt endpoint
	/// resolves `fn::secret` ciphertexts to plaintext.
	async fn get_decrypted(&self, client: &reqwest::Client) -> Result<Option<Mapping>> {
		let action = "decrypting the environment definition";
		let response = client
			.get(format!("{}/decrypt", self.environment_path()))
			.header("accept", "application/vnd.pulumi+8")
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let status = response.status();
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}

		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;
		check_status(status, &body, action)?;

		let text = std::str::from_utf8(&body).map_err(|_| {
			operation_error(format!("Pulumi returned non-UTF-8 YAML while {action}"))
		})?;

		Ok(Some(parse_values(text)?))
	}

	/// The plaintext string stored for `key`, if the key holds a plain or
	/// `fn::secret` string.
	fn stored_string<'a>(values: &'a Mapping, key: &str) -> Result<Option<&'a str>> {
		let Some(value) = values.get(Value::String(key.to_string())) else {
			return Ok(None);
		};

		match value {
			Value::String(value) => Ok(Some(value.as_str())),
			Value::Mapping(secret) if secret.len() == 1 => {
				let Some((name, inner)) = secret.iter().next() else {
					return Err(operation_error(format!(
						"Pulumi ESC key '{key}' holds an empty secret mapping"
					)));
				};
				if name.as_str() != Some(SECRET_KEY) {
					return Err(operation_error(format!(
						"Pulumi ESC key '{key}' holds a structured value Monosecret does not manage"
					)));
				}
				match inner {
					Value::String(value) => Ok(Some(value.as_str())),
					_ => {
						Err(operation_error(format!(
							"Pulumi ESC key '{key}' holds a non-string secret"
						)))
					}
				}
			}
			_ => {
				Err(operation_error(format!(
					"Pulumi ESC key '{key}' holds a non-string value"
				)))
			}
		}
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let Some(values) = self.get_decrypted(client).await? else {
			return Ok(None);
		};

		Ok(Self::stored_string(&values, key)?.map(SecretBytes::from_utf8))
	}

	/// Writes `key` as an `fn::secret` string. The write is a
	/// read-modify-write of the whole definition under an `ETag`, so a
	/// concurrent writer conflicts and the round is retried on top of the
	/// newer definition.
	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		let mut attempts_left = MAX_WRITE_ATTEMPTS;
		let mut created = false;

		loop {
			attempts_left -= 1;

			let Some(mut definition) = self.get_definition(client).await? else {
				if created {
					return Err(operation_error(
						"Pulumi created the environment but it could not be read back",
					));
				}
				self.create_environment(client).await?;
				created = true;
				continue;
			};

			definition
				.values
				.insert(Value::String(key.to_string()), secret_value(value));

			if self.patch_definition(client, &definition).await? {
				return Ok(());
			}

			if attempts_left == 0 {
				return Err(operation_error(
					"Pulumi kept reporting a version conflict while writing the environment definition",
				));
			}
		}
	}

	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		let mut attempts_left = MAX_WRITE_ATTEMPTS;

		loop {
			attempts_left -= 1;

			let Some(mut definition) = self.get_definition(client).await? else {
				return Ok(false);
			};

			if definition
				.values
				.remove(Value::String(key.to_string()))
				.is_none()
			{
				return Ok(false);
			}

			if self.patch_definition(client, &definition).await? {
				return Ok(true);
			}

			if attempts_left == 0 {
				return Err(operation_error(
					"Pulumi kept reporting a version conflict while writing the environment definition",
				));
			}
		}
	}
}

#[derive(Serialize)]
struct CreateEnvironment<'a> {
	project: &'a str,
	name: &'a str,
}

impl Provider for PulumiProvider {
	/// The organization, project, and environment supply isolation;
	/// convention writes use the Monosecret key directly as the `values`
	/// key.
	fn convention_address(
		&self,
		_project: &str,
		_profile: &str,
		key: &str,
	) -> Result<NativeAddress> {
		Ok(NativeAddress {
			item: key.to_string(),
			..Default::default()
		})
	}

	fn with_credentials(&mut self, credentials: ProviderCredentials) {
		self.credentials = credentials;
	}

	fn name(&self) -> &str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		format!(
			"pulumi://{}/{}/{}",
			self.config.org, self.config.project, self.config.environment
		)
	}

	fn storage_identity(&self) -> String {
		format!(
			"pulumi://{}/{}/{}",
			self.config.org, self.config.project, self.config.environment
		)
	}

	fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
		let name = self.secret_name(addr)?;
		let client = self.client()?;
		super::block_on(self.get_async(&client, &name))
	}

	fn check_writable(&self, addr: Address<'_>) -> Result<()> {
		self.secret_name(addr).map(|_| ())
	}

	fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
		self.check_writable(addr)?;
		let name = self.secret_name(addr)?;
		let value = super::require_utf8("pulumi", value)?;
		let client = self.client()?;
		super::block_on(self.set_async(&client, &name, value))
	}

	fn supports_delete(&self) -> bool {
		true
	}

	fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
		self.secret_name(addr).map(|_| ())
	}

	fn delete(&self, addr: Address<'_>) -> Result<bool> {
		self.check_deletable(addr)?;
		let name = self.secret_name(addr)?;
		let client = self.client()?;
		super::block_on(self.delete_async(&client, &name))
	}

	fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
		let name = self.secret_name(addr)?;
		Ok(format!(
			"Pulumi ESC environment '{}/{}/{}' key '{}'",
			self.config.org, self.config.project, self.config.environment, name
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let Some(values) = super::block_on(self.get_decrypted(&client))? else {
			return Ok(HashMap::new());
		};

		Ok(values
			.keys()
			.filter_map(Value::as_str)
			.filter(|key| !RESERVED_KEYS.contains(key))
			.map(|key| {
				let secret = Secret::required(format!("{key} Pulumi ESC value"));
				(key.to_string(), secret)
			})
			.collect())
	}
}

/// Builds the `Authorization: token <token>` header Pulumi Cloud expects,
/// validating the HTTP header syntax without imposing a UTF-8 requirement.
fn pulumi_header(value: &[u8]) -> Result<HeaderValue> {
	let mut header_value = b"token ".to_vec();
	header_value.extend_from_slice(value);
	let header_value = SecretBytes::from_vec(header_value);
	let mut header = HeaderValue::from_bytes(header_value.expose_secret()).map_err(|_| {
		operation_error("provider credential cannot be represented in an HTTP Authorization header")
	})?;
	header.set_sensitive(true);
	Ok(header)
}

/// Parses a definition's `values` mapping; an empty document yields an
/// empty mapping, a top-level mapping yields its `values` table (or an
/// empty one when absent), and anything else is an error.
fn parse_values(text: &str) -> Result<Mapping> {
	let trimmed = text.trim();
	if trimmed.is_empty() || trimmed == "~" {
		return Ok(Mapping::new());
	}

	let document: Value = serde_norway::from_str(trimmed).map_err(|error| {
		operation_error(format!(
			"Pulumi returned invalid YAML: {}",
			crate::error::display_error_chain(&error)
		))
	})?;

	match document {
		Value::Mapping(top) => {
			match top
				.get(Value::String("values".to_string()))
				.cloned()
				.unwrap_or(Value::Mapping(Mapping::new()))
			{
				Value::Mapping(values) => Ok(values),
				_ => {
					Err(operation_error(
						"Pulumi returned a definition whose `values` is not a mapping",
					))
				}
			}
		}
		Value::Null => Ok(Mapping::new()),
		_ => {
			Err(operation_error(
				"Pulumi returned a definition that is not a mapping",
			))
		}
	}
}

/// Wraps `value` the way `pulumi env set --secret` writes it, so the value
/// is encrypted at rest.
fn secret_value(value: &str) -> Value {
	let mut secret = Mapping::new();
	secret.insert(
		Value::String(SECRET_KEY.to_string()),
		Value::String(value.to_string()),
	);
	Value::Mapping(secret)
}

/// Serializes the full definition with the managed `values` mapping.
fn values_document(values: &Mapping) -> Value {
	let mut top = Mapping::new();
	top.insert(
		Value::String("values".to_string()),
		Value::Mapping(values.clone()),
	);
	Value::Mapping(top)
}

fn is_valid_key(name: &str) -> bool {
	!name.is_empty()
		&& name
			.bytes()
			.next()
			.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn check_status(status: reqwest::StatusCode, body: &[u8], action: &str) -> Result<()> {
	if status.is_success() {
		return Ok(());
	}

	Err(api_error(status, body, action))
}

fn api_error(status: reqwest::StatusCode, body: &[u8], action: &str) -> MonosecretError {
	let detail = serde_json::from_slice::<ApiError>(body).map_or_else(
		|_| String::from_utf8_lossy(body).trim().to_string(),
		|error| {
			let code = error
				.code
				.map(|code| format!("{code}: "))
				.unwrap_or_default();
			format!("{code}{}", error.message)
		},
	);
	let detail = detail.chars().take(512).collect::<String>();

	if detail.is_empty() {
		operation_error(format!(
			"Pulumi returned HTTP {} while {action}",
			status.as_u16()
		))
	} else {
		operation_error(format!(
			"Pulumi returned HTTP {} while {action}: {detail}",
			status.as_u16()
		))
	}
}

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach Pulumi while {action}: {}",
		crate::error::display_error_chain(error)
	))
}

fn operation_error(message: impl Into<String>) -> MonosecretError {
	MonosecretError::ProviderOperationFailed(message.into())
}
#[cfg(test)]
#[allow(clippy::indexing_slicing)] // test fixtures: indexing is the assertion
mod tests {
	use std::io::BufRead;
	use std::io::BufReader;
	use std::io::Read;
	use std::io::Write;
	use std::net::SocketAddr;
	use std::net::TcpListener;

	use super::*;

	const ORG: &str = "my-org";
	const PROJECT: &str = "payments";
	const ENVIRONMENT: &str = "production";

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> PulumiConfig {
		PulumiConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> PulumiProvider {
		let mut provider = PulumiProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}");
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.to_string(),
			SecretBytes::from_utf8("pul-token"),
		)]));
		provider
	}

	/// Serves one canned response per request; `etag` becomes a response
	/// header so definition reads carry concurrency state.
	fn response_server(
		responses: Vec<(&'static str, &'static str, Option<&'static str>)>,
	) -> (SocketAddr, std::thread::JoinHandle<Vec<RecordedRequest>>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = listener.local_addr().unwrap();
		let server = std::thread::spawn(move || {
			let mut recorded = Vec::new();

			for (status, body, etag) in responses {
				let (mut stream, _) = listener.accept().unwrap();
				let mut reader = BufReader::new(&mut stream);
				let mut line = String::new();
				reader.read_line(&mut line).unwrap();
				let mut headers = HashMap::new();

				loop {
					let mut header = String::new();
					reader.read_line(&mut header).unwrap();

					if header == "\r\n" || header.is_empty() {
						break;
					}

					if let Some((name, value)) = header.trim_end().split_once(':') {
						headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
					}
				}

				let content_length = headers
					.get("content-length")
					.and_then(|value| value.parse::<usize>().ok())
					.unwrap_or(0);
				let mut request_body = vec![0; content_length];
				reader.read_exact(&mut request_body).unwrap();
				recorded.push(RecordedRequest {
					line: line.trim_end().to_string(),
					headers,
					body: String::from_utf8(request_body).unwrap(),
				});
				let etag = etag
					.map(|etag| format!("ETag: {etag}\r\n"))
					.unwrap_or_default();
				write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/x-yaml\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
				.unwrap();
			}

			recorded
		});
		(endpoint, server)
	}

	#[test]
	fn parses_and_round_trips_configuration() {
		let two_part = format!("pulumi://{ORG}/{ENVIRONMENT}");
		let provider = PulumiProvider::new(config(&two_part));
		assert_eq!(provider.config.project, DEFAULT_PROJECT);
		let canonical = format!("pulumi://{ORG}/{DEFAULT_PROJECT}/{ENVIRONMENT}");
		assert_eq!(provider.uri(), canonical);
		assert_eq!(config(&provider.uri()), provider.config);

		let three_part = format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}");
		let provider = PulumiProvider::new(config(&three_part));
		assert_eq!(provider.uri(), three_part);
		assert_eq!(config(&provider.uri()), provider.config);
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"pulumi://",
			"pulumi:///env",
			&format!("pulumi://{ORG}"),
			&format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}/extra"),
			&format!("pulumi://{ORG}/{ENVIRONMENT}?team=1"),
			"pulumi://has%20space/env",
			&format!("pulumi://{ORG}/has%20space"),
		] {
			assert!(
				PulumiConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "pulumi")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variable() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider = PulumiProvider::new(config(&format!("pulumi://{ORG}/{ENVIRONMENT}")));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("the `token` provider credential or PULUMI_ACCESS_TOKEN"),
			"{error}"
		);
	}

	#[test]
	fn environment_token_uses_the_token_scheme() {
		let _lock = crate::tests::scrub_resolution_env();
		let _env = crate::tests::EnvVarGuard::set(TOKEN_ENV, "env-token");
		let body = Box::leak(
			"values:\n  API_KEY:\n    fn::secret: value\n"
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body, None)]);
		let mut provider = PulumiProvider::new(config(&format!("pulumi://{ORG}/{ENVIRONMENT}")));
		provider.api_base = format!("http://{endpoint}");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"value"
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].headers.get("authorization").map(String::as_str),
			Some("token env-token")
		);
	}

	#[test]
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider = PulumiProvider::new(config(&format!("pulumi://{ORG}/{ENVIRONMENT}")));
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.into(),
			SecretBytes::from_slice(b"token\r\n"),
		)]));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP Authorization header"),
			"{error}"
		);
		assert!(!format!("{error:?}: {error}").contains("token\r\n"));
	}

	#[test]
	fn reads_secret_plain_and_missing_values() {
		let body = Box::leak(
			"values:\n  API_KEY:\n    fn::secret: sk-live\n  PLAIN: direct\n"
				.to_string()
				.into_boxed_str(),
		);
		// Each read performs its own decrypt request.
		let (endpoint, server) = response_server(vec![
			("200 OK", body, None),
			("200 OK", body, None),
			("200 OK", body, None),
		]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"sk-live"
		);
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "PLAIN"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"direct"
		);
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "MISSING"))
				.unwrap(),
			None
		);
		server.join().unwrap();

		let missing_env = Box::leak(String::new().into_boxed_str());
		for _ in 0..3 {
			let (endpoint, server) = response_server(vec![("404 Not Found", missing_env, None)]);
			let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));
			assert_eq!(
				provider
					.get(Address::convention("p", "production", "API_KEY"))
					.unwrap(),
				None
			);
			server.join().unwrap();
		}
	}

	#[test]
	fn non_string_values_are_reported() {
		for yaml in [
			"values:\n  API_KEY:\n    fn::open::aws-login: {}\n",
			"values:\n  API_KEY:\n    fn::secret:\n      nested: value\n",
			"values:\n  API_KEY: 42\n",
		] {
			let body = Box::leak(yaml.to_string().into_boxed_str());
			let (endpoint, server) = response_server(vec![("200 OK", body, None)]);
			let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));
			let error = provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap_err();
			assert!(
				error.to_string().contains("Pulumi ESC key 'API_KEY'"),
				"{error}"
			);
			server.join().unwrap();
		}
	}

	#[test]
	fn writes_secret_values_with_the_read_etag() {
		let definition = Box::leak("values:\n  OTHER: kept\n".to_string().into_boxed_str());
		let updated = Box::leak(r#"{"diagnostics":[]}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![
			("200 OK", definition, Some("etag-one")),
			("200 OK", updated, None),
		]);
		let provider =
			provider_with_token(endpoint, &format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 2);
		assert!(requests[0].line.contains(&format!(
			"GET /api/esc/environments/{ORG}/{PROJECT}/{ENVIRONMENT}"
		)));
		assert!(requests[1].line.contains(&format!(
			"PATCH /api/esc/environments/{ORG}/{PROJECT}/{ENVIRONMENT}"
		)));
		assert_eq!(
			requests[1].headers.get("etag").map(String::as_str),
			Some("etag-one")
		);
		assert!(
			requests[1].headers.get("content-type").map(String::as_str)
				== Some("application/x-yaml"),
			"{}",
			requests[1]
				.headers
				.get("content-type")
				.map(String::as_str)
				.unwrap_or_default()
		);

		let yaml: Value = serde_norway::from_str(&requests[1].body).unwrap();
		let values = yaml.get("values").and_then(Value::as_mapping).unwrap();
		assert_eq!(
			values.get(Value::from("API_KEY")).and_then(|value| {
				value
					.as_mapping()
					.and_then(|secret| secret.get(Value::from("fn::secret")))
					.and_then(Value::as_str)
			}),
			Some("new-value")
		);
		assert_eq!(
			values.get(Value::from("OTHER")).and_then(Value::as_str),
			Some("kept"),
			"the write must preserve the rest of the values"
		);
	}

	#[test]
	fn creates_a_missing_environment_before_the_first_write() {
		let not_found = Box::leak(String::new().into_boxed_str());
		let created = Box::leak("{}".to_string().into_boxed_str());
		let empty_definition = Box::leak(String::new().into_boxed_str());
		let updated = Box::leak(r#"{"diagnostics":[]}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![
			("404 Not Found", not_found, None),
			("201 Created", created, None),
			("200 OK", empty_definition, Some("etag-two")),
			("200 OK", updated, None),
		]);
		let provider =
			provider_with_token(endpoint, &format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("first-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 4);
		assert!(
			requests[1]
				.line
				.contains(&format!("POST /api/esc/environments/{ORG}")),
			"{}",
			requests[1].line
		);
		let create: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(create["project"], PROJECT);
		assert_eq!(create["name"], ENVIRONMENT);
	}

	#[test]
	fn version_conflicts_are_retried_against_the_newer_definition() {
		let stale = Box::leak("values:\n  OTHER: old\n".to_string().into_boxed_str());
		let conflict = Box::leak(
			r#"{"code":409,"message":"the environment was modified"}"#
				.to_string()
				.into_boxed_str(),
		);
		let fresh = Box::leak("values:\n  OTHER: fresh\n".to_string().into_boxed_str());
		let updated = Box::leak(r#"{"diagnostics":[]}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![
			("200 OK", stale, Some("etag-one")),
			("409 Conflict", conflict, None),
			("200 OK", fresh, Some("etag-two")),
			("200 OK", updated, None),
		]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("retry-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 4);
		assert_eq!(
			requests[3].headers.get("etag").map(String::as_str),
			Some("etag-two"),
			"the retry must carry the newer definition's ETag"
		);
		let yaml: Value = serde_norway::from_str(&requests[3].body).unwrap();
		let values = yaml.get("values").and_then(Value::as_mapping).unwrap();
		assert_eq!(
			values.get(Value::from("OTHER")).and_then(Value::as_str),
			Some("fresh"),
			"the retry must apply the change on top of the newer values"
		);
	}

	#[test]
	fn deletes_an_existing_key_and_missing_deletion_is_idempotent() {
		let definition = Box::leak(
			"values:\n  API_KEY:\n    fn::secret: gone\n  OTHER: kept\n"
				.to_string()
				.into_boxed_str(),
		);
		let updated = Box::leak(r#"{"diagnostics":[]}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![
			("200 OK", definition, Some("etag-one")),
			("200 OK", updated, None),
		]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		let yaml: Value = serde_norway::from_str(&requests[1].body).unwrap();
		let values = yaml.get("values").and_then(Value::as_mapping).unwrap();
		assert!(values.get(Value::from("API_KEY")).is_none());
		assert_eq!(
			values.get(Value::from("OTHER")).and_then(Value::as_str),
			Some("kept")
		);

		let missing_key = Box::leak("values:\n  OTHER: kept\n".to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", missing_key, Some("etag-one"))]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);

		let not_found = Box::leak(String::new().into_boxed_str());
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found, None)]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));
		assert!(
			!provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn keys_are_validated_and_reserved_projections_are_refused() {
		let provider = PulumiProvider::new(config(&format!("pulumi://{ORG}/{ENVIRONMENT}")));
		let address = provider
			.convention_address("project", "production", "DATABASE_URL")
			.unwrap();
		assert_eq!(address.item, "DATABASE_URL");

		for key in ["", "1STARTS_WITH_DIGIT", "HAS SPACE", "HAS-DASH"] {
			assert!(
				provider
					.check_writable(Address::convention("project", "production", key))
					.is_err(),
				"{key}"
			);
		}

		for reserved in RESERVED_KEYS {
			let error = provider
				.check_writable(Address::convention("project", "production", reserved))
				.unwrap_err();
			assert!(error.to_string().contains("Pulumi-reserved"), "{error}");
		}
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider = PulumiProvider::new(config(&format!("pulumi://{ORG}/{ENVIRONMENT}")));
		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_slice(b"\xff\xfe"),
			)
			.unwrap_err();
		assert!(
			error.to_string().contains("requires UTF-8 secret values"),
			"{error}"
		);
	}

	#[test]
	fn api_errors_surface_the_code_and_message() {
		let forbidden = Box::leak(
			r#"{"code":403,"message":"you do not have permission"}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("403 Forbidden", forbidden, None)]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 403 while decrypting"),
			"{error}"
		);
		assert!(
			error
				.to_string()
				.contains("403: you do not have permission"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn patch_diagnostics_surface_the_error_summary() {
		let definition = Box::leak(String::new().into_boxed_str());
		let refused = Box::leak(
			r#"{"diagnostics":[{"severity":"error","summary":"invalid definition"}]}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![
			("200 OK", definition, Some("etag-one")),
			("400 Bad Request", refused, None),
		]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("v"),
			)
			.unwrap_err();
		assert!(error.to_string().contains("invalid definition"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn reflection_lists_values_except_reserved_projections() {
		let body = Box::leak(
			"values:\n  API_KEY:\n    fn::secret: a\n  environmentVariables:\n  PULUMI_TOKEN: b\n"
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body, None)]);
		let provider = provider_with_token(endpoint, &format!("pulumi://{ORG}/{ENVIRONMENT}"));

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 2);
		assert!(reflected.contains_key("API_KEY"));
		assert!(reflected.contains_key("PULUMI_TOKEN"));
		assert!(!reflected.contains_key("environmentVariables"));
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_the_environment() {
		let provider =
			PulumiProvider::new(config(&format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}")));
		assert_eq!(
			provider.storage_identity(),
			format!("pulumi://{ORG}/{PROJECT}/{ENVIRONMENT}")
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!("Pulumi ESC environment '{ORG}/{PROJECT}/{ENVIRONMENT}' key 'KEY'")
		);
	}
}
