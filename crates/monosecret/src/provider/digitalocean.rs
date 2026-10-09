//! `DigitalOcean` Secrets Manager provider.
//!
//! `DigitalOcean`'s Secrets Manager stores each secret as a named container in
//! one region holding one or more key-value pairs. Monosecret maps a
//! declaration key to one key inside the configured secret's values and
//! selects the secret and its region through the provider URI, so one alias
//! per secret container keeps configurations isolated. Values are read back
//! in plaintext through the API.
//!
//! Updates replace the whole values map with an optimistic concurrency check
//! on the secret's version, so writes merge the fetched map, and a version
//! conflict is retried before it surfaces.
//!
//! # URI format
//!
//! `digitalocean://SECRET_NAME?region=REGION`
//!
//! Authentication comes from a `token` provider credential,
//! `DIGITALOCEAN_ACCESS_TOKEN`, or `DIGITALOCEAN_TOKEN`.

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
const TOKEN_ENVS: &[&str] = &["DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_TOKEN"];
const API_BASE: &str = "https://api.digitalocean.com/v2";
/// How many read-merge-write rounds a set or delete may attempt before a
/// version conflict is reported instead of retried.
const MAX_WRITE_ATTEMPTS: usize = 3;

/// Configuration for one `DigitalOcean` secret container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigitaloceanConfig {
	/// Name of the `DigitalOcean` secret whose values are managed.
	pub name: String,
	/// Region slug holding the secret, for example `nyc3`.
	pub region: String,
}

impl TryFrom<&ProviderUrl> for DigitaloceanConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "digitalocean" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for digitalocean provider; expected 'digitalocean'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"digitalocean:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let name = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"digitalocean provider requires a secret name, for example digitalocean://my-app-secrets?region=nyc3",
				)
			})?;
		validate_secret_name(&name)?;

		if !url.path().trim_matches('/').is_empty() {
			return Err(operation_error(
				"digitalocean:// takes no path; put the secret name in the URI authority and the region in ?region=",
			));
		}

		let mut region = None;

		for (key, value) in url.query_pairs() {
			let value = value.into_owned();

			let duplicate = match key.as_ref() {
				"region" => set_once(&mut region, value),
				unknown => {
					return Err(operation_error(format!(
						"unknown digitalocean query parameter '{unknown}'; the supported parameter is `region`"
					)));
				}
			};

			if duplicate {
				return Err(operation_error(format!(
					"duplicate digitalocean query parameter '{key}'"
				)));
			}
		}

		let region = region
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"digitalocean provider requires a region slug, for example digitalocean://my-app-secrets?region=nyc3",
				)
			})?;
		validate_region_slug(&region)?;

		Ok(Self { name, region })
	}
}

fn set_once(slot: &mut Option<String>, value: String) -> bool {
	if slot.is_some() {
		true
	} else {
		*slot = Some(value);
		false
	}
}

/// Accepts `DigitalOcean` secret names: up to 255 ASCII letters, digits,
/// hyphens, underscores, or dots.
fn validate_secret_name(name: &str) -> Result<()> {
	if name.is_empty()
		|| name.len() > 255
		|| !name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
	{
		return Err(operation_error(
			"DigitalOcean secret names are at most 255 ASCII letters, digits, hyphens, underscores, or dots",
		));
	}
	Ok(())
}

/// Accepts `DigitalOcean` region slugs: three lowercase letters followed by one
/// or two digits, matching every published slug (`nyc3`, `fra1`, `syd1`, …).
fn validate_region_slug(region: &str) -> Result<()> {
	let valid = matches!(region.len(), 4..=5)
		&& region.bytes().take(3).all(|byte| byte.is_ascii_lowercase())
		&& region.bytes().skip(3).all(|byte| byte.is_ascii_digit());

	if valid {
		Ok(())
	} else {
		Err(operation_error(
			"DigitalOcean regions are slugs like nyc3, fra1, or syd1 (three lowercase letters plus one or two digits)",
		))
	}
}

/// A secret as returned by the API, values included.
#[derive(Debug, Deserialize)]
struct SecretResponse {
	#[serde(default)]
	version: u64,
	#[serde(default)]
	values: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct CreateSecret<'a> {
	name: &'a str,
	region: &'a str,
	values: &'a BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct UpdateSecret<'a> {
	region: &'a str,
	version: u64,
	values: &'a BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
	#[serde(default)]
	id: Option<String>,
	message: String,
}

/// A `DigitalOcean` Secrets Manager provider.
pub struct DigitaloceanProvider {
	config: DigitaloceanConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: DigitaloceanProvider,
	config: DigitaloceanConfig,
	metadata: &super::catalog::DIGITALOCEAN,
}

impl DigitaloceanProvider {
	pub fn new(config: DigitaloceanConfig) -> Self {
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
				"DigitalOcean auth requires the `{TOKEN}` provider credential, DIGITALOCEAN_ACCESS_TOKEN, or DIGITALOCEAN_TOKEN"
			))
		})?;

		let mut headers = HeaderMap::new();
		headers.insert(
			AUTHORIZATION,
			super::credentials::credential_bearer_header(token.expose_secret())?,
		);
		Ok(headers)
	}

	fn client(&self) -> Result<reqwest::Client> {
		super::http::client_builder()
			.default_headers(self.auth_headers()?)
			// Secret-bearing bodies must remain confined to DigitalOcean's
			// fixed API origin; a redirect response must never choose where a
			// POST or PUT body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build DigitalOcean HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	/// `/v2/security/secrets` collection endpoint.
	fn collection_path(&self) -> String {
		format!("{}/security/secrets", self.api_base.trim_end_matches('/'))
	}

	/// `/v2/security/secrets/{name}?region=…` item endpoint.
	fn secret_path(&self) -> String {
		format!(
			"{}/{}?region={}",
			self.collection_path(),
			self.config.name,
			self.config.region
		)
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if !is_valid_value_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid DigitalOcean secret key: keys are ASCII letters, digits, or underscores and start with a letter or underscore"
			)));
		}

		Ok(name)
	}

	/// Fetches the configured secret with its values, or `None` on 404.
	async fn get_secret(&self, client: &reqwest::Client) -> Result<Option<SecretResponse>> {
		let response = client
			.get(self.secret_path())
			.send()
			.await
			.map_err(|error| reach_error("reading the secret", &error))?;

		if response.status() == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error("reading the secret", &error))?;
		decode_response(status, &body, "reading the secret").map(Some)
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let Some(secret) = self.get_secret(client).await? else {
			return Ok(None);
		};

		Ok(secret.values.get(key).map(SecretBytes::from_utf8))
	}

	/// Writes `key` into the secret's values. Updates fetch the current map
	/// first because the API replaces the whole `values` object, and the
	/// version passed with the replacement makes concurrent writes conflict;
	/// a conflict restarts the round so a racing writer's keys survive.
	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		let mut attempts_left = MAX_WRITE_ATTEMPTS;

		loop {
			attempts_left -= 1;

			if let Some(secret) = self.get_secret(client).await? {
				let mut values = secret.values;
				values.insert(key.to_string(), value.to_string());

				let response = client
					.put(self.secret_path())
					.json(&UpdateSecret {
						region: &self.config.region,
						version: secret.version,
						values: &values,
					})
					.send()
					.await
					.map_err(|error| reach_error("updating the secret", &error))?;

				if is_version_conflict(&response) && attempts_left > 0 {
					continue;
				}

				check_status(response, "updating the secret").await?;
				return Ok(());
			}

			let mut values = BTreeMap::new();
			values.insert(key.to_string(), value.to_string());

			let response = client
				.post(self.collection_path())
				.json(&CreateSecret {
					name: &self.config.name,
					region: &self.config.region,
					values: &values,
				})
				.send()
				.await
				.map_err(|error| reach_error("creating the secret", &error))?;

			// A racing creator can claim the name between the fetch and the
			// create; the next round updates instead.
			if is_version_conflict(&response) && attempts_left > 0 {
				continue;
			}

			check_status(response, "creating the secret").await?;
			return Ok(());
		}
	}

	/// Removes `key` from the secret's values. The API requires every secret
	/// to keep at least one pair, so removing the last key is refused rather
	/// than deleting the whole secret container.
	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		let mut attempts_left = MAX_WRITE_ATTEMPTS;

		loop {
			attempts_left -= 1;

			let Some(secret) = self.get_secret(client).await? else {
				return Ok(false);
			};

			let mut values = secret.values;

			if !values.contains_key(key) {
				return Ok(false);
			}

			if values.len() == 1 {
				return Err(operation_error(format!(
					"DigitalOcean secret '{}' must keep at least one key-value pair, so its last key '{key}' cannot be removed here; delete the whole secret with `doctl secrets delete {} --region {}` or the control panel",
					self.config.name, self.config.name, self.config.region
				)));
			}

			values.remove(key);

			let response = client
				.put(self.secret_path())
				.json(&UpdateSecret {
					region: &self.config.region,
					version: secret.version,
					values: &values,
				})
				.send()
				.await
				.map_err(|error| reach_error("deleting the secret key", &error))?;

			// Another writer changed the map in between; the next round
			// removes the key on top of the newer values.
			if is_version_conflict(&response) && attempts_left > 0 {
				continue;
			}

			check_status(response, "deleting the secret key").await?;
			return Ok(true);
		}
	}
}

impl Provider for DigitaloceanProvider {
	/// The secret container plus its region supply isolation; convention
	/// writes use the Monosecret key directly as the value's key.
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
			"digitalocean://{}?region={}",
			self.config.name,
			ProviderUrl::encode_query(&self.config.region)
		)
	}

	fn storage_identity(&self) -> String {
		format!("digitalocean://{}/{}", self.config.region, self.config.name)
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
		let value = super::require_utf8("digitalocean", value)?;
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
			"DigitalOcean secret '{}' (region '{}') key '{}'",
			self.config.name, self.config.region, name
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let Some(secret) = super::block_on(self.get_secret(&client))? else {
			return Ok(HashMap::new());
		};

		Ok(secret
			.values
			.into_keys()
			.map(|key| {
				let secret = Secret::required(format!("{key} DigitalOcean secret value"));
				(key, secret)
			})
			.collect())
	}
}

fn is_valid_value_key(name: &str) -> bool {
	!name.is_empty()
		&& name
			.bytes()
			.next()
			.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Whether a response reports the optimistic-concurrency failure of a values
/// replacement.
fn is_version_conflict(response: &reqwest::Response) -> bool {
	response.status() == reqwest::StatusCode::CONFLICT
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
			"DigitalOcean returned invalid JSON while {action} (HTTP {}): {}",
			status.as_u16(),
			crate::error::display_error_chain(&error)
		))
	})
}

fn api_error(status: reqwest::StatusCode, body: &[u8], action: &str) -> MonosecretError {
	let detail = serde_json::from_slice::<ApiError>(body).map_or_else(
		|_| String::from_utf8_lossy(body).trim().to_string(),
		|error| {
			let id = error.id.map(|id| format!("{id}: ")).unwrap_or_default();
			format!("{id}{}", error.message)
		},
	);
	let detail = detail.chars().take(512).collect::<String>();

	if detail.is_empty() {
		operation_error(format!(
			"DigitalOcean returned HTTP {} while {action}",
			status.as_u16()
		))
	} else {
		operation_error(format!(
			"DigitalOcean returned HTTP {} while {action}: {detail}",
			status.as_u16()
		))
	}
}

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach DigitalOcean while {action}: {}",
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

	const NAME: &str = "my-app-secrets";
	const REGION: &str = "nyc3";

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> DigitaloceanConfig {
		DigitaloceanConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> DigitaloceanProvider {
		let mut provider = DigitaloceanProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}/v2");
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.to_string(),
			SecretBytes::from_utf8("test-token"),
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

	fn secret_body(version: u64, values: &str) -> String {
		format!(
			r#"{{"secret":"{NAME}","region":"{REGION}","version":{version},"values":{values},"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}}"#
		)
	}

	#[test]
	fn parses_and_round_trips_configuration() {
		let encoded = format!("digitalocean://{NAME}?region={REGION}");
		let provider = DigitaloceanProvider::new(config(&encoded));
		assert_eq!(provider.uri(), encoded);
		assert_eq!(config(&provider.uri()), provider.config);
		assert_eq!(provider.config.name, NAME);
		assert_eq!(provider.config.region, REGION);

		let other = DigitaloceanProvider::new(config("digitalocean://prod-secrets?region=fra1"));
		assert_eq!(other.uri(), "digitalocean://prod-secrets?region=fra1");
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"digitalocean://",
			"digitalocean:///path",
			&format!("digitalocean://{NAME}"),
			&format!("digitalocean://{NAME}?region="),
			&format!("digitalocean://{NAME}?region=Nyc3"),
			&format!("digitalocean://{NAME}?region=ny"),
			&format!("digitalocean://{NAME}?region=nyc"),
			&format!("digitalocean://{NAME}?region=nycx"),
			&format!("digitalocean://{NAME}?region={REGION}&region=fra1"),
			&format!("digitalocean://{NAME}?region={REGION}&unknown=true"),
			&format!("digitalocean://{NAME}/path?region={REGION}"),
			"digitalocean://has%20space?region=nyc3",
		] {
			assert!(
				DigitaloceanConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap()))
					.is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "digitalocean")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variables() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains(
				"the `token` provider credential, DIGITALOCEAN_ACCESS_TOKEN, or DIGITALOCEAN_TOKEN"
			),
			"{error}"
		);
	}

	#[test]
	fn environment_token_is_used_when_no_credential_is_configured() {
		let _lock = crate::tests::scrub_resolution_env();
		let _fallback = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
		let _token = crate::tests::EnvVarGuard::set("DIGITALOCEAN_ACCESS_TOKEN", "env-token");
		let not_found =
			r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let mut provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
		provider.api_base = format!("http://{endpoint}/v2");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].headers.get("authorization").map(String::as_str),
			Some("Bearer env-token")
		);
	}

	#[test]
	fn second_environment_variable_is_the_fallback() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
		let _second = crate::tests::EnvVarGuard::set("DIGITALOCEAN_TOKEN", "api-token");
		let not_found =
			r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let mut provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
		provider.api_base = format!("http://{endpoint}/v2");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].headers.get("authorization").map(String::as_str),
			Some("Bearer api-token")
		);
	}

	#[test]
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
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
	fn convention_is_flat_and_names_are_validated() {
		let provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
		let address = provider
			.convention_address("project", "production", "DATABASE_URL")
			.unwrap();
		assert_eq!(address.item, "DATABASE_URL");

		for key in ["", "1STARTS_WITH_DIGIT", "HAS SPACE", "HAS-DASH", "ÜMLAUT"] {
			assert!(
				provider
					.check_writable(Address::convention("project", "production", key))
					.is_err(),
				"{key}"
			);
		}
	}

	#[test]
	fn reads_a_value_from_the_configured_secret() {
		let body = Box::leak(
			secret_body(4, r#"{"API_KEY":"prod-value","OTHER":"untouched"}"#).into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"prod-value");

		let requests = server.join().unwrap();
		assert!(
			requests[0]
				.line
				.contains(&format!("/v2/security/secrets/{NAME}?region={REGION}")),
			"{}",
			requests[0].line
		);
	}

	#[test]
	fn missing_secret_or_key_resolves_to_none() {
		let not_found =
			r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap(),
			None
		);
		assert_eq!(server.join().unwrap().len(), 1);

		let body = Box::leak(secret_body(1, r#"{"OTHER":"value"}"#).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "MISSING"))
				.unwrap(),
			None
		);
		server.join().unwrap();
	}

	#[test]
	fn creates_a_missing_secret_with_the_key() {
		let not_found =
			r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;
		let created = Box::leak(
			format!(r#"{{"name":"{NAME}","region":"{REGION}","version":1}}"#).into_boxed_str(),
		);
		let (endpoint, server) =
			response_server(vec![("404 Not Found", not_found), ("200 OK", created)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 2);
		assert!(requests[1].line.starts_with("POST /v2/security/secrets"));
		assert!(!requests[1].line.contains('?'), "{}", requests[1].line);
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["name"], NAME);
		assert_eq!(body["region"], REGION);
		assert_eq!(body["values"], serde_json::json!({"API_KEY": "new-value"}));
	}

	#[test]
	fn merges_into_an_existing_secret_with_the_current_version() {
		let existing = Box::leak(secret_body(7, r#"{"OTHER":"value"}"#).into_boxed_str());
		let updated = Box::leak(
			format!(r#"{{"name":"{NAME}","region":"{REGION}","version":8}}"#).into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", existing), ("200 OK", updated)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("merged-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert!(requests[1].line.contains("PUT "));
		assert!(
			requests[1]
				.line
				.contains(&format!("/security/secrets/{NAME}?region={REGION}")),
			"{}",
			requests[1].line
		);
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["region"], REGION);
		assert_eq!(body["version"], 7);
		assert_eq!(
			body["values"],
			serde_json::json!({"API_KEY": "merged-value", "OTHER": "value"})
		);
	}

	#[test]
	fn retries_when_the_version_conflicts() {
		let stale = Box::leak(secret_body(1, r#"{"API_KEY":"stale"}"#).into_boxed_str());
		let conflict = r#"{"id":"conflict","message":"The version provided does not match the current version."}"#;
		let fresh =
			Box::leak(secret_body(2, r#"{"API_KEY":"stale","RACED":"added"}"#).into_boxed_str());
		let updated = Box::leak(
			format!(r#"{{"name":"{NAME}","region":"{REGION}","version":3}}"#).into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![
			("200 OK", stale),
			("409 Conflict", conflict),
			("200 OK", fresh),
			("200 OK", updated),
		]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("fresh-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 4);
		let body: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
		assert_eq!(body["version"], 2);
		// The racing writer's key survives the retried replacement.
		assert_eq!(
			body["values"],
			serde_json::json!({"API_KEY": "fresh-value", "RACED": "added"})
		);
	}

	#[test]
	fn deleting_a_missing_key_is_idempotent() {
		let not_found =
			r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		assert!(
			!provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);

		let body = Box::leak(secret_body(1, r#"{"OTHER":"value"}"#).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn deletes_a_key_and_keeps_the_rest() {
		let existing =
			Box::leak(secret_body(5, r#"{"API_KEY":"gone","OTHER":"kept"}"#).into_boxed_str());
		let updated = Box::leak(
			format!(r#"{{"name":"{NAME}","region":"{REGION}","version":6}}"#).into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", existing), ("200 OK", updated)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		assert!(requests[1].line.contains("PUT "));
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["values"], serde_json::json!({"OTHER": "kept"}));
	}

	#[test]
	fn removing_the_last_key_explains_the_constraint_instead_of_deleting() {
		let existing = Box::leak(secret_body(2, r#"{"API_KEY":"only"}"#).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", existing)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		let error = provider
			.delete(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("at least one key-value pair"),
			"{error}"
		);
		assert!(
			error.to_string().contains("doctl secrets delete"),
			"{error}"
		);
		// The secret itself is never deleted through Monosecret.
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn api_errors_surface_the_id_and_message() {
		let unauthorized = r#"{"id":"unauthorized","message":"Unable to authenticate you","request_id":"4d9d8375"}"#;
		let (endpoint, server) = response_server(vec![("401 Unauthorized", unauthorized)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 401 while reading"),
			"{error}"
		);
		assert!(
			error
				.to_string()
				.contains("unauthorized: Unable to authenticate you"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn invalid_json_and_bare_error_bodies_are_reported() {
		let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("invalid JSON while reading"),
			"{error}"
		);
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("500 Internal Server Error", "boom")]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 500"), "{error}");
		assert!(error.to_string().contains("boom"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
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
	fn reflection_lists_the_secret_keys() {
		let body =
			Box::leak(secret_body(3, r#"{"API_KEY":"a","DATABASE_URL":"b"}"#).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider =
			provider_with_token(endpoint, &format!("digitalocean://{NAME}?region={REGION}"));

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 2);
		assert!(reflected.contains_key("API_KEY"));
		assert!(reflected.contains_key("DATABASE_URL"));
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_region_and_secret() {
		let provider =
			DigitaloceanProvider::new(config(&format!("digitalocean://{NAME}?region={REGION}")));
		assert_eq!(
			provider.storage_identity(),
			format!("digitalocean://{REGION}/{NAME}")
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!("DigitalOcean secret '{NAME}' (region '{REGION}') key 'KEY'")
		);
	}
}
