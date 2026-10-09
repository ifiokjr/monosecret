//! Convex deployment environment variable provider.
//!
//! Convex stores environment variables per deployment, so a dev deployment
//! and a production deployment of the same project hold independent values.
//! Monosecret maps a declaration key directly to an environment variable
//! name and selects the deployment through the provider URI, so one alias
//! per deployment keeps profiles isolated. Values are read back in plaintext
//! through the deployment's API.
//!
//! # URI format
//!
//! `convex://DEPLOYMENT`
//!
//! `DEPLOYMENT` is a deployment name like `happy-otter-123` or its full host
//! like `happy-otter-123.eu-west-1.convex.cloud` for deployments outside
//! US-East. Authentication comes from a `token` provider credential,
//! `CONVEX_DEPLOY_KEY`, or `CONVEX_DEPLOYMENT_TOKEN`.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;

use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde::Serialize;

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
const TOKEN_ENVS: &[&str] = &["CONVEX_DEPLOY_KEY", "CONVEX_DEPLOYMENT_TOKEN"];
const DEPLOYMENT_SUFFIX: &str = ".convex.cloud";
/// Convex caps environment variable names at 256 characters.
const MAX_NAME_LEN: usize = 256;

/// Configuration for one Convex deployment's environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvexConfig {
	/// Convex deployment name or full deployment host.
	pub deployment: String,
}

impl TryFrom<&ProviderUrl> for ConvexConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "convex" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for convex provider; expected 'convex'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"convex:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let deployment = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"convex provider requires a deployment, for example convex://happy-otter-123",
				)
			})?;
		validate_deployment(&deployment)?;

		if !url.path().trim_matches('/').is_empty() {
			return Err(operation_error(
				"convex:// takes no path; put the deployment name or host in the URI authority",
			));
		}

		if let Some((key, _)) = url.query_pairs().next() {
			return Err(operation_error(format!(
				"unknown convex query parameter '{key}'; convex:// takes no query parameters"
			)));
		}

		Ok(Self { deployment })
	}
}

/// Accepts deployment names (`happy-otter-123`) and full deployment hosts
/// (`happy-otter-123.eu-west-1.convex.cloud`); anything else with a dot is
/// rejected so a mistyped host never silently targets another domain.
fn validate_deployment(deployment: &str) -> Result<()> {
	let valid = if deployment.ends_with(DEPLOYMENT_SUFFIX) {
		!deployment.trim_end_matches(DEPLOYMENT_SUFFIX).is_empty()
			&& deployment.len() <= 253
			&& deployment.split('.').all(is_host_label)
	} else {
		!deployment.contains('.')
			&& (3..=63).contains(&deployment.len())
			&& deployment
				.bytes()
				.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
	};

	if valid {
		Ok(())
	} else {
		Err(operation_error(
			"Convex deployments are names like happy-otter-123 or full hosts like happy-otter-123.eu-west-1.convex.cloud (lowercase letters, digits, and hyphens)",
		))
	}
}

fn is_host_label(label: &str) -> bool {
	!label.is_empty()
		&& label
			.bytes()
			.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Debug, Deserialize)]
struct ListEnvVars {
	#[serde(default, rename = "environmentVariables")]
	environment_variables: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Serialize)]
struct EnvChange<'a> {
	name: &'a str,
	/// `None` deletes the named variable.
	value: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct UpdateEnvVars<'a> {
	changes: &'a [EnvChange<'a>],
}

#[derive(Debug, Deserialize)]
struct ApiError {
	#[serde(default)]
	code: Option<String>,
	message: String,
}

/// A Convex deployment environment variable provider.
pub struct ConvexProvider {
	config: ConvexConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: ConvexProvider,
	config: ConvexConfig,
	metadata: &super::catalog::CONVEX,
}

impl ConvexProvider {
	pub fn new(config: ConvexConfig) -> Self {
		let host = deployment_host(&config.deployment);
		Self {
			config,
			credentials: ProviderCredentials::new(),
			api_base: format!("https://{host}"),
		}
	}

	fn token(&self) -> Option<SecretBytes> {
		super::credential_or_envs(&self.credentials, TOKEN, TOKEN_ENVS)
	}

	fn auth_headers(&self) -> Result<HeaderMap> {
		let token = self.token().ok_or_else(|| {
			operation_error(format!(
				"Convex auth requires the `{TOKEN}` provider credential, CONVEX_DEPLOY_KEY, or CONVEX_DEPLOYMENT_TOKEN"
			))
		})?;

		let mut headers = HeaderMap::new();
		headers.insert(AUTHORIZATION, convex_header(token.expose_secret())?);
		Ok(headers)
	}

	fn client(&self) -> Result<reqwest::Client> {
		super::http::client_builder()
			.default_headers(self.auth_headers()?)
			// Secret-bearing bodies must remain confined to the deployment's
			// fixed API origin; a redirect response must never choose where a
			// POST body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build Convex HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	fn list_path(&self) -> String {
		format!(
			"{}/api/v1/list_environment_variables",
			self.api_base.trim_end_matches('/')
		)
	}

	fn update_path(&self) -> String {
		format!(
			"{}/api/v1/update_environment_variables",
			self.api_base.trim_end_matches('/')
		)
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if !is_valid_env_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid Convex environment variable name: names are at most {MAX_NAME_LEN} ASCII letters, digits, or underscores and start with a letter"
			)));
		}

		Ok(name)
	}

	/// Reads the deployment's variables, mapping a `null` value to an absent
	/// entry.
	async fn list_async(&self, client: &reqwest::Client) -> Result<BTreeMap<String, String>> {
		let action = "listing environment variables";
		let response = client
			.get(self.list_path())
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;
		let page: ListEnvVars = decode_response(status, &body, action)?;

		Ok(page
			.environment_variables
			.into_iter()
			.filter_map(|(name, value)| value.map(|value| (name, value)))
			.collect())
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let variables = self.list_async(client).await?;
		Ok(variables.get(key).map(SecretBytes::from_utf8))
	}

	/// Upserts one variable: the deployment API applies `changes` as a batch,
	/// and a change with a value replaces any existing entry.
	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		let response = client
			.post(self.update_path())
			.json(&UpdateEnvVars {
				changes: &[EnvChange {
					name: key,
					value: Some(value),
				}],
			})
			.send()
			.await
			.map_err(|error| reach_error("updating the environment variable", &error))?;
		check_status(response, "updating the environment variable").await
	}

	/// Removes one variable by sending a `null` value; a name that is already
	/// absent is a successful no-op.
	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		if !self.list_async(client).await?.contains_key(key) {
			return Ok(false);
		}

		let response = client
			.post(self.update_path())
			.json(&UpdateEnvVars {
				changes: &[EnvChange {
					name: key,
					value: None,
				}],
			})
			.send()
			.await
			.map_err(|error| reach_error("deleting the environment variable", &error))?;
		check_status(response, "deleting the environment variable").await?;

		Ok(true)
	}
}

impl Provider for ConvexProvider {
	/// The deployment supplies isolation; convention writes use the Monosecret
	/// key directly as the variable name.
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
		format!("convex://{}", self.config.deployment)
	}

	fn storage_identity(&self) -> String {
		format!("convex://{}", self.config.deployment)
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
		let value = super::require_utf8("convex", value)?;
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
			"Convex deployment '{}' environment variable '{}'",
			self.config.deployment, name
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let variables = super::block_on(self.list_async(&client))?;

		Ok(variables
			.into_keys()
			.map(|key| {
				let secret = Secret::required(format!("{key} Convex environment variable"));
				(key, secret)
			})
			.collect())
	}
}

/// Turns a URI deployment into the host serving its deployment API: full
/// hosts are used as written, bare names get the default domain.
fn deployment_host(deployment: &str) -> String {
	if deployment.ends_with(DEPLOYMENT_SUFFIX) {
		deployment.to_string()
	} else {
		format!("{deployment}{DEPLOYMENT_SUFFIX}")
	}
}

/// Builds the deployment API's `Convex` scheme authorization header directly
/// from credential bytes, validating the HTTP header syntax without imposing
/// a UTF-8 requirement.
fn convex_header(value: &[u8]) -> Result<reqwest::header::HeaderValue> {
	let mut header_value = b"Convex ".to_vec();
	header_value.extend_from_slice(value);
	let header_value = SecretBytes::from_vec(header_value);
	let mut header = reqwest::header::HeaderValue::from_bytes(header_value.expose_secret())
		.map_err(|_| {
			operation_error(
				"provider credential cannot be represented in an HTTP Authorization header",
			)
		})?;
	header.set_sensitive(true);
	Ok(header)
}

fn is_valid_env_key(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= MAX_NAME_LEN
		&& name
			.bytes()
			.next()
			.is_some_and(|byte| byte.is_ascii_alphabetic())
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

async fn check_status(response: reqwest::Response, action: &str) -> Result<()> {
	let status = response.status();
	if status.is_success() {
		return Ok(());
	}

	let body = response
		.bytes()
		.await
		.map_err(|error| reach_error(action, &error))?;
	Err(api_error(status, &body, action))
}

fn decode_response<T: serde::de::DeserializeOwned>(
	status: reqwest::StatusCode,
	body: &[u8],
	action: &str,
) -> Result<T> {
	if !status.is_success() {
		return Err(api_error(status, body, action));
	}

	serde_json::from_slice(body).map_err(|error| {
		operation_error(format!(
			"Convex returned invalid JSON while {action} (HTTP {}): {}",
			status.as_u16(),
			crate::error::display_error_chain(&error)
		))
	})
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
			"Convex returned HTTP {} while {action}",
			status.as_u16()
		))
	} else {
		operation_error(format!(
			"Convex returned HTTP {} while {action}: {detail}",
			status.as_u16()
		))
	}
}

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach Convex while {action}: {}",
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

	const DEPLOYMENT: &str = "happy-otter-123";
	const REGIONAL: &str = "happy-otter-123.eu-west-1.convex.cloud";

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> ConvexConfig {
		ConvexConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> ConvexProvider {
		let mut provider = ConvexProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}");
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.to_string(),
			SecretBytes::from_utf8("prod:happy-otter-123|test-key"),
		)]));
		provider
	}

	fn response_server(
		responses: Vec<(&'static str, &'static str)>,
	) -> (SocketAddr, std::thread::JoinHandle<Vec<RecordedRequest>>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = listener.local_addr().unwrap();
		let server = std::thread::spawn(move || {
			let mut recorded = Vec::new();

			for (status, body) in responses {
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
				write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
		let provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		assert_eq!(provider.uri(), format!("convex://{DEPLOYMENT}"));
		assert_eq!(config(&provider.uri()), provider.config);
		assert_eq!(
			provider.api_base,
			format!("https://{DEPLOYMENT}.convex.cloud")
		);

		let regional = ConvexProvider::new(config(&format!("convex://{REGIONAL}")));
		assert_eq!(regional.uri(), format!("convex://{REGIONAL}"));
		assert_eq!(regional.api_base, format!("https://{REGIONAL}"));
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"convex://",
			"convex:///path",
			"convex://an",
			"convex://has%20space",
			"convex://UPPER",
			"convex://happy-otter-123/path",
			"convex://happy-otter-123?team=1",
			"convex://happy-otter-123.example.com",
		] {
			assert!(
				ConvexConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "convex")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variables() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains(
				"the `token` provider credential, CONVEX_DEPLOY_KEY, or CONVEX_DEPLOYMENT_TOKEN"
			),
			"{error}"
		);
	}

	#[test]
	fn environment_token_is_used_when_no_credential_is_configured() {
		let _lock = crate::tests::scrub_resolution_env();
		let _fallback = crate::tests::EnvVarGuard::remove("CONVEX_DEPLOYMENT_TOKEN");
		let _token = crate::tests::EnvVarGuard::set("CONVEX_DEPLOY_KEY", "env-key");
		let empty = Box::leak(r#"{"environmentVariables":{}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let mut provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		provider.api_base = format!("http://{endpoint}");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].headers.get("authorization").map(String::as_str),
			Some("Convex env-key")
		);
	}

	#[test]
	fn second_environment_variable_is_the_fallback() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::remove("CONVEX_DEPLOY_KEY");
		let _second = crate::tests::EnvVarGuard::set("CONVEX_DEPLOYMENT_TOKEN", "deployment-token");
		let empty = Box::leak(r#"{"environmentVariables":{}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let mut provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		provider.api_base = format!("http://{endpoint}");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].headers.get("authorization").map(String::as_str),
			Some("Convex deployment-token")
		);
	}

	#[test]
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.into(),
			SecretBytes::from_slice(b"key\r\n"),
		)]));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP Authorization header"),
			"{error}"
		);
		assert!(!format!("{error:?}: {error}").contains("key\r\n"));
	}

	#[test]
	fn convention_is_flat_and_names_are_validated() {
		let provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		let address = provider
			.convention_address("project", "production", "DATABASE_URL")
			.unwrap();
		assert_eq!(address.item, "DATABASE_URL");

		// Convex names must start with a letter, unlike Netlify or Vercel.
		for key in [
			"",
			"1STARTS_WITH_DIGIT",
			"_LEADING",
			"HAS SPACE",
			"HAS-DASH",
		] {
			assert!(
				provider
					.check_writable(Address::convention("project", "production", key))
					.is_err(),
				"{key}"
			);
		}
	}

	#[test]
	fn reads_the_deployment_value() {
		let body = Box::leak(
			r#"{"environmentVariables":{"API_KEY":"prod-value","OTHER":"untouched"}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"prod-value");

		let requests = server.join().unwrap();
		assert!(
			requests[0]
				.line
				.starts_with("GET /api/v1/list_environment_variables"),
			"{}",
			requests[0].line
		);
	}

	#[test]
	fn missing_and_null_values_resolve_to_none() {
		for body in [
			r#"{"environmentVariables":{"OTHER":"value"}}"#,
			r#"{"environmentVariables":{"API_KEY":null}}"#,
		] {
			let body = Box::leak(body.to_string().into_boxed_str());
			let (endpoint, server) = response_server(vec![("200 OK", body)]);
			let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));
			assert_eq!(
				provider
					.get(Address::convention("p", "production", "API_KEY"))
					.unwrap(),
				None,
				"{body}"
			);
			server.join().unwrap();
		}
	}

	#[test]
	fn writes_a_change_with_a_value() {
		let (endpoint, server) = response_server(vec![("200 OK", "")]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert!(
			requests[0]
				.line
				.starts_with("POST /api/v1/update_environment_variables"),
			"{}",
			requests[0].line
		);
		let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
		assert_eq!(
			body,
			serde_json::json!({"changes": [{"name": "API_KEY", "value": "new-value"}]})
		);
	}

	#[test]
	fn deletes_a_variable_with_a_null_value() {
		let listed = Box::leak(
			r#"{"environmentVariables":{"API_KEY":"value","OTHER":"kept"}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", listed), ("200 OK", "")]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		assert!(
			requests[1]
				.line
				.starts_with("POST /api/v1/update_environment_variables"),
			"{}",
			requests[1].line
		);
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(
			body,
			serde_json::json!({"changes": [{"name": "API_KEY", "value": null}]})
		);
	}

	#[test]
	fn deleting_a_missing_variable_is_idempotent() {
		let listed = Box::leak(r#"{"environmentVariables":{}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", listed)]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
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
		let unauthorized =
			r#"{"code":"AccessTokenInvalid","message":"Access Token could not be decoded"}"#;
		let (endpoint, server) = response_server(vec![("401 Unauthorized", unauthorized)]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 401 while listing"),
			"{error}"
		);
		assert!(
			error
				.to_string()
				.contains("AccessTokenInvalid: Access Token could not be decoded"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn invalid_json_and_bare_error_bodies_are_reported() {
		let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("invalid JSON while listing"),
			"{error}"
		);
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("500 Internal Server Error", "boom")]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 500"), "{error}");
		assert!(error.to_string().contains("boom"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn reflection_lists_the_deployment_variables() {
		let body = Box::leak(
			r#"{"environmentVariables":{"API_KEY":"a","DATABASE_URL":"b","REMOVED":null}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, &format!("convex://{DEPLOYMENT}"));

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 2);
		assert!(reflected.contains_key("API_KEY"));
		assert!(reflected.contains_key("DATABASE_URL"));
		assert!(!reflected.contains_key("REMOVED"));
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_the_deployment() {
		let provider = ConvexProvider::new(config(&format!("convex://{DEPLOYMENT}")));
		assert_eq!(
			provider.storage_identity(),
			format!("convex://{DEPLOYMENT}")
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!("Convex deployment '{DEPLOYMENT}' environment variable 'KEY'")
		);
	}
}
