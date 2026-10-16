//! `DigitalOcean` Secrets Manager provider.
//!
//! `DigitalOcean`'s Secrets Manager stores each secret as a named object in
//! one region holding a flat map of key-value pairs. Monosecret maps a
//! declaration to one key inside the secret object selected by the provider
//! URI, so one alias per object keeps configurations isolated. Values are read
//! back in plaintext through the API.
//!
//! # Keys and provider-relative paths
//!
//! A convention address, or a `ref` with only an `item`, names the key
//! directly. A structured reference adds levels: its `item`, every `section`
//! segment, and its `field` are joined with [`KEY_PATH_SEPARATOR`] into one
//! flat key in the same object. A provider reference written as
//! `{ provider = "do", path = ["auth"] }` on `JWT_SECRET` therefore reads the
//! key `auth__JWT_SECRET`. The API stores flat string maps only, so a prefix
//! keeps every value directly editable in the control panel and `doctl`,
//! and one object still serves a whole project.
//!
//! # Batched reads
//!
//! The API returns every key of an object in one response. [`Provider::get_many`]
//! validates every requested key first and then reads the object once, however
//! many declarations point into it.
//!
//! # Writes
//!
//! Updates replace the whole values map with an optimistic concurrency check
//! on the secret's version, so writes merge the fetched map, and a version
//! conflict is retried before it surfaces.
//!
//! # URI format
//!
//! `digitalocean://SECRET_NAME?region=REGION`
//!
//! Authentication comes from a `token` provider credential, a `depends_on`
//! secret named `DIGITALOCEAN_ACCESS_TOKEN` or `DIGITALOCEAN_TOKEN`, or the
//! environment variables of the same names, in that order.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::PoisonError;

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
/// Joins the `item`, `section` segments, and `field` of a structured reference
/// into the one flat key it names inside the secret object.
const KEY_PATH_SEPARATOR: &str = "__";
/// How many read-merge-write rounds a set or delete may attempt before a
/// version conflict is reported instead of retried.
const MAX_WRITE_ATTEMPTS: usize = 3;
/// Upper bound on the API error detail quoted in a Monosecret error.
const MAX_ERROR_DETAIL_CHARS: usize = 512;

/// Configuration for one `DigitalOcean` secret object.
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
/// hyphens, underscores, or dots, and not only dots. The name becomes a URL
/// path segment, where `.` and `..` would be normalized into a different
/// API endpoint.
fn validate_secret_name(name: &str) -> Result<()> {
	let valid = !name.is_empty()
		&& name.len() <= 255
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
		&& !name.bytes().all(|byte| byte == b'.');

	if valid {
		Ok(())
	} else {
		Err(operation_error(
			"DigitalOcean secret names are at most 255 ASCII letters, digits, hyphens, underscores, or dots, and cannot be only dots",
		))
	}
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
///
/// Deliberately not `Debug`: the values are plaintext secrets.
#[derive(Deserialize)]
struct SecretResponse {
	#[serde(default)]
	version: u64,
	#[serde(default)]
	values: BTreeMap<String, String>,
}

/// Request body creating a secret. Not `Debug`: it carries plaintext values.
#[derive(Serialize)]
struct CreateSecret<'a> {
	name: &'a str,
	region: &'a str,
	values: &'a BTreeMap<String, String>,
}

/// Request body replacing a secret's values. Not `Debug`: it carries
/// plaintext values.
#[derive(Serialize)]
struct UpdateSecret<'a> {
	region: &'a str,
	version: u64,
	values: &'a BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ApiError {
	#[serde(default)]
	id: Option<String>,
	message: String,
}

/// A `DigitalOcean` Secrets Manager provider.
pub struct DigitaloceanProvider {
	config: DigitaloceanConfig,
	credentials: ProviderCredentials,
	/// Token delivered by a `depends_on` bootstrap secret. Interior mutability
	/// because [`Provider::configure_dependency_secrets`] takes `&self`.
	dependency_token: Mutex<Option<SecretBytes>>,
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
			dependency_token: Mutex::new(None),
			api_base: API_BASE.to_string(),
		}
	}

	/// The token in effect: an explicit `token` credential, then a
	/// `depends_on` bootstrap secret, then the environment.
	fn token(&self) -> Option<SecretBytes> {
		self.credentials
			.get(TOKEN)
			.cloned()
			.or_else(|| {
				self.dependency_token
					.lock()
					.unwrap_or_else(PoisonError::into_inner)
					.clone()
			})
			.or_else(|| super::credential_or_envs(&self.credentials, TOKEN, TOKEN_ENVS))
	}

	fn auth_headers(&self) -> Result<HeaderMap> {
		let token = self.token().ok_or_else(|| {
			operation_error(format!(
				"DigitalOcean auth requires the `{TOKEN}` provider credential, a DIGITALOCEAN_ACCESS_TOKEN or DIGITALOCEAN_TOKEN depends_on secret, or one of those environment variables"
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
		// Secret-bearing bodies must remain confined to DigitalOcean's fixed
		// API origin; `client_builder` refuses redirects for exactly this reason.
		super::http::client_builder()
			.default_headers(self.auth_headers()?)
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

	/// `/v2/security/secrets/{name}?region=…` item endpoint. Both components
	/// were validated to URL-safe characters when the URI was parsed.
	fn secret_path(&self) -> String {
		format!(
			"{}/{}?region={}",
			self.collection_path(),
			self.config.name,
			self.config.region
		)
	}

	/// The flat key `addr` names inside the secret's values: the `item`, any
	/// `section` segments, and the `field`, joined with
	/// [`KEY_PATH_SEPARATOR`]. Pure, so every operation validates its key
	/// before building a request.
	fn value_key(&self, addr: Address<'_>) -> Result<String> {
		let coords = self.resolve_coords(addr)?;
		let mut segments = vec![coords.item.as_str()];

		if let Some(section) = coords.section.as_deref() {
			segments.extend(section.split('/'));
		}

		if let Some(field) = coords.field.as_deref() {
			segments.push(field);
		}

		let key = segments.join(KEY_PATH_SEPARATOR);

		if !segments.iter().all(|segment| is_key_segment(segment)) || !is_valid_value_key(&key) {
			return Err(operation_error(format!(
				"`{}` does not name a valid DigitalOcean secret key: every path segment and key is ASCII letters, digits, or underscores, and the joined key starts with a letter or underscore",
				coords.render()
			)));
		}

		Ok(key)
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

				check_status(response, "updating the secret", &values).await?;
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

			check_status(response, "creating the secret", &values).await?;
			return Ok(());
		}
	}

	/// Removes `key` from the secret's values. The API requires every secret
	/// to keep at least one pair, so removing the last key is refused rather
	/// than deleting the whole secret object.
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

			check_status(response, "deleting the secret key", &values).await?;
			return Ok(true);
		}
	}
}

impl Provider for DigitaloceanProvider {
	/// The secret object plus its region supply isolation; convention
	/// addresses use the Monosecret key directly as the value's key.
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

	/// `section` and `field` extend the `item` into a prefixed flat key; see
	/// the module documentation. Secrets are read at their latest version.
	fn supported_coords(&self) -> &'static [&'static str] {
		&["section", "field"]
	}

	/// The canonical entry is the flat key itself, so two references that
	/// spell the same key differently (`path = ["auth"]` and
	/// `ref = { item = "auth__JWT_SECRET" }`) are recognised as one entry.
	fn configured_entry_coordinates<'a>(
		&self,
		addr: Address<'a>,
	) -> Result<Cow<'a, NativeAddress>> {
		Ok(Cow::Owned(NativeAddress {
			item: self.value_key(addr)?,
			..Default::default()
		}))
	}

	fn configure_dependency_secrets(&self, dependencies: &[(String, SecretBytes)]) -> Result<()> {
		let token = TOKEN_ENVS.iter().find_map(|env| {
			dependencies
				.iter()
				.find(|(name, value)| name == env && !value.expose_secret().is_empty())
				.map(|(_, value)| value.clone())
		});

		if token.is_some() {
			*self
				.dependency_token
				.lock()
				.unwrap_or_else(PoisonError::into_inner) = token;
		}

		Ok(())
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
		const REQUEST: &str = "value";
		self.get_many(&[(REQUEST, addr)])
			.map(|mut values| values.remove(REQUEST))
	}

	/// Serves every request from one read of the secret object, however many
	/// declarations or keys point into it. Every key is validated before the
	/// request is built, so one malformed reference fails the batch without
	/// contacting `DigitalOcean`.
	fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
		if requests.is_empty() {
			return Ok(HashMap::new());
		}

		let keys = requests
			.iter()
			.map(|(name, addr)| Ok((*name, self.value_key(*addr)?)))
			.collect::<Result<Vec<_>>>()?;
		let client = self.client()?;
		let Some(secret) = super::block_on(self.get_secret(&client))? else {
			return Ok(HashMap::new());
		};

		Ok(keys
			.into_iter()
			.filter_map(|(name, key)| {
				secret
					.values
					.get(&key)
					.map(|value| (name.to_string(), SecretBytes::from_utf8(value)))
			})
			.collect())
	}

	fn check_writable(&self, addr: Address<'_>) -> Result<()> {
		self.value_key(addr).map(|_| ())
	}

	fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
		let key = self.value_key(addr)?;
		let value = super::require_utf8("digitalocean", value)?;
		let client = self.client()?;
		super::block_on(self.set_async(&client, &key, value))
	}

	fn supports_delete(&self) -> bool {
		true
	}

	fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
		self.value_key(addr).map(|_| ())
	}

	fn delete(&self, addr: Address<'_>) -> Result<bool> {
		let key = self.value_key(addr)?;
		let client = self.client()?;
		super::block_on(self.delete_async(&client, &key))
	}

	fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
		let key = self.value_key(addr)?;
		Ok(format!(
			"DigitalOcean secret '{}' (region '{}') key '{key}'",
			self.config.name, self.config.region
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

/// Whether `segment` may appear between separators in a flat key.
fn is_key_segment(segment: &str) -> bool {
	!segment.is_empty()
		&& segment
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_valid_value_key(name: &str) -> bool {
	name.bytes()
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

/// Turns a failed write response into an error. `sent` is the values map the
/// request carried: any of its values echoed in the error body is redacted.
async fn check_status(
	response: reqwest::Response,
	action: &str,
	sent: &BTreeMap<String, String>,
) -> Result<()> {
	let status = response.status();
	if status.is_success() {
		return Ok(());
	}

	let body = response
		.bytes()
		.await
		.map_err(|error| reach_error(action, &error))?;
	Err(api_error(status, &body, action, sent))
}

fn decode_response(
	status: reqwest::StatusCode,
	body: &[u8],
	action: &str,
) -> Result<SecretResponse> {
	if !status.is_success() {
		return Err(api_error(status, body, action, &BTreeMap::new()));
	}

	// The body carries plaintext values, and serde's messages can quote the
	// offending input, so only the error's position is reported.
	serde_json::from_slice(body).map_err(|error| {
		operation_error(format!(
			"DigitalOcean returned invalid JSON while {action} (HTTP {}): {:?} error at line {}, column {}; the body is not shown because it can carry secret values",
			status.as_u16(),
			error.classify(),
			error.line(),
			error.column()
		))
	})
}

fn api_error(
	status: reqwest::StatusCode,
	body: &[u8],
	action: &str,
	sent: &BTreeMap<String, String>,
) -> MonosecretError {
	let detail = serde_json::from_slice::<ApiError>(body).map_or_else(
		|_| String::from_utf8_lossy(body).trim().to_string(),
		|error| {
			let id = error.id.map(|id| format!("{id}: ")).unwrap_or_default();
			format!("{id}{}", error.message)
		},
	);
	// Redact before truncating, so a value cut at the limit cannot leak a
	// prefix of itself; longest first, so a value containing another is
	// redacted whole.
	let mut values: Vec<&str> = sent
		.values()
		.map(String::as_str)
		.filter(|value| !value.is_empty())
		.collect();
	values.sort_unstable_by_key(|value| std::cmp::Reverse(value.len()));
	let detail = values
		.into_iter()
		.fold(detail, |detail, value| detail.replace(value, "[REDACTED]"));
	let detail = detail
		.chars()
		.take(MAX_ERROR_DETAIL_CHARS)
		.collect::<String>();

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
	use std::collections::HashSet;
	use std::io::BufRead;
	use std::io::BufReader;
	use std::io::Read;
	use std::io::Write;
	use std::net::SocketAddr;
	use std::net::TcpListener;

	use super::*;

	const NAME: &str = "my-app-secrets";
	const REGION: &str = "nyc3";
	const NOT_FOUND: &str =
		r#"{"id":"not_found","message":"The resource you requested could not be found."}"#;

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> DigitaloceanConfig {
		DigitaloceanConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn spec() -> String {
		format!("digitalocean://{NAME}?region={REGION}")
	}

	fn provider_at(endpoint: SocketAddr) -> DigitaloceanProvider {
		let mut provider = DigitaloceanProvider::new(config(&spec()));
		provider.api_base = format!("http://{endpoint}/v2");
		provider
	}

	fn provider_with_token(endpoint: SocketAddr) -> DigitaloceanProvider {
		let mut provider = provider_at(endpoint);
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.to_string(),
			SecretBytes::from_utf8("test-token"),
		)]));
		provider
	}

	/// Serves exactly `responses.len()` HTTP exchanges on a loopback port, in
	/// order, and returns what each request carried. Joining the handle after
	/// the operation proves the request count: a missing request blocks the
	/// test, and an extra one finds the port closed.
	fn response_server(
		responses: Vec<(&'static str, String)>,
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

	/// A bound loopback port that must never see a connection.
	fn silent_listener() -> TcpListener {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		listener
	}

	fn assert_untouched(listener: &TcpListener) {
		assert_eq!(
			listener.accept().map(|_| ()).unwrap_err().kind(),
			std::io::ErrorKind::WouldBlock,
			"no request may reach DigitalOcean"
		);
	}

	fn secret_body(version: u64, values: &str) -> String {
		format!(
			r#"{{"secret":"{NAME}","region":"{REGION}","version":{version},"values":{values},"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}}"#
		)
	}

	fn write_result(version: u64) -> String {
		format!(r#"{{"name":"{NAME}","region":"{REGION}","version":{version}}}"#)
	}

	fn native(item: &str, section: Option<&str>, field: Option<&str>) -> NativeAddress {
		NativeAddress {
			item: item.to_string(),
			section: section.map(str::to_string),
			field: field.map(str::to_string),
			..Default::default()
		}
	}

	/// The address a `{ provider = "do", path = [...], key = ... }` reference
	/// compiles to for the declaration `name`.
	fn path_ref(name: &str, path: &[&str], key: Option<&str>) -> NativeAddress {
		crate::config::SecretRequest {
			path: Some(path.iter().map(ToString::to_string).collect()),
			key: key.map(str::to_string),
		}
		.to_native_address(name)
		.unwrap()
	}

	#[test]
	fn parses_and_round_trips_configuration() {
		let encoded = spec();
		let provider = DigitaloceanProvider::new(config(&encoded));
		assert_eq!(provider.uri(), encoded);
		assert_eq!(config(&provider.uri()), provider.config);
		assert_eq!(provider.config.name, NAME);
		assert_eq!(provider.config.region, REGION);

		let other = DigitaloceanProvider::new(config("digitalocean://prod-secrets?region=fra1"));
		assert_eq!(other.uri(), "digitalocean://prod-secrets?region=fra1");

		let dotted = DigitaloceanProvider::new(config("digitalocean://monochange.dev?region=lon1"));
		assert_eq!(dotted.config.name, "monochange.dev");
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
			&format!("digitalocean://user:pass@{NAME}?region={REGION}"),
			&format!("digitalocean://{}?region={REGION}", "a".repeat(256)),
			"digitalocean://has%20space?region=nyc3",
			"onepassword://my-app-secrets?region=nyc3",
		] {
			assert!(
				DigitaloceanConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap()))
					.is_err(),
				"{spec}"
			);
		}
	}

	/// A name of only dots would be normalized out of the request path
	/// (`/v2/security/secrets/..` is `/v2/security`), sending the token and
	/// any write body to a different endpoint.
	#[test]
	fn dot_only_names_are_rejected() {
		for name in [".", "..", "..."] {
			let error = validate_secret_name(name).unwrap_err();
			assert!(error.to_string().contains("only dots"), "{name}: {error}");
		}

		validate_secret_name(".env.production").unwrap();
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
		assert!(bare_provider().supports_delete());
	}

	#[test]
	fn missing_token_names_every_source() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
		let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
		let listener = silent_listener();
		let provider = provider_at(listener.local_addr().unwrap());
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		let message = error.to_string();
		assert!(
			message.contains("the `token` provider credential"),
			"{message}"
		);
		assert!(message.contains("depends_on secret"), "{message}");
		assert!(
			message.contains("DIGITALOCEAN_ACCESS_TOKEN or DIGITALOCEAN_TOKEN"),
			"{message}"
		);
		assert_untouched(&listener);
	}

	/// Reads the `Authorization` header one request carries for `provider`.
	fn authorization_used(mut provider: DigitaloceanProvider) -> String {
		let (endpoint, server) = response_server(vec![("404 Not Found", NOT_FOUND.to_string())]);
		provider.api_base = format!("http://{endpoint}/v2");
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let requests = server.join().unwrap();
		requests[0].headers["authorization"].clone()
	}

	fn bare_provider() -> DigitaloceanProvider {
		DigitaloceanProvider::new(config(&spec()))
	}

	fn dependency(name: &str, value: &str) -> (String, SecretBytes) {
		(name.to_string(), SecretBytes::from_utf8(value))
	}

	#[test]
	fn environment_tokens_are_the_last_fallback_in_order() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::set("DIGITALOCEAN_ACCESS_TOKEN", "access-env");
		let _second = crate::tests::EnvVarGuard::set("DIGITALOCEAN_TOKEN", "legacy-env");
		assert_eq!(authorization_used(bare_provider()), "Bearer access-env");

		let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
		assert_eq!(authorization_used(bare_provider()), "Bearer legacy-env");
	}

	#[test]
	fn depends_on_token_is_delivered_and_beats_the_environment() {
		let _lock = crate::tests::scrub_resolution_env();
		let _env = crate::tests::EnvVarGuard::set("DIGITALOCEAN_ACCESS_TOKEN", "ambient-env");

		let provider = bare_provider();
		provider
			.configure_dependency_secrets(&[
				dependency("UNRELATED", "ignored"),
				dependency("DIGITALOCEAN_TOKEN", "legacy-dependency"),
				dependency("DIGITALOCEAN_ACCESS_TOKEN", "access-dependency"),
			])
			.unwrap();
		assert_eq!(authorization_used(provider), "Bearer access-dependency");

		let provider = bare_provider();
		provider
			.configure_dependency_secrets(&[dependency("DIGITALOCEAN_TOKEN", "legacy-dependency")])
			.unwrap();
		assert_eq!(authorization_used(provider), "Bearer legacy-dependency");
	}

	#[test]
	fn empty_or_unrelated_dependencies_leave_the_environment_in_charge() {
		let _lock = crate::tests::scrub_resolution_env();
		let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
		let _env = crate::tests::EnvVarGuard::set("DIGITALOCEAN_ACCESS_TOKEN", "ambient-env");

		let provider = bare_provider();
		provider
			.configure_dependency_secrets(&[
				dependency("DIGITALOCEAN_ACCESS_TOKEN", ""),
				dependency("OP_SERVICE_ACCOUNT_TOKEN", "not-for-digitalocean"),
			])
			.unwrap();
		assert_eq!(authorization_used(provider), "Bearer ambient-env");
	}

	#[test]
	fn explicit_credential_beats_dependency_and_environment() {
		let _lock = crate::tests::scrub_resolution_env();
		let _env = crate::tests::EnvVarGuard::set("DIGITALOCEAN_ACCESS_TOKEN", "ambient-env");

		let mut provider = bare_provider();
		provider.with_credentials(ProviderCredentials::from([(
			TOKEN.to_string(),
			SecretBytes::from_utf8("explicit-credential"),
		)]));
		provider
			.configure_dependency_secrets(&[dependency(
				"DIGITALOCEAN_ACCESS_TOKEN",
				"access-dependency",
			)])
			.unwrap();
		assert_eq!(authorization_used(provider), "Bearer explicit-credential");
	}

	#[test]
	fn a_poisoned_dependency_slot_still_yields_its_token() {
		let provider = std::sync::Arc::new(bare_provider());
		let poisoner = std::sync::Arc::clone(&provider);
		std::thread::spawn(move || {
			let _guard = poisoner.dependency_token.lock().unwrap();
			panic!("poison the dependency token slot");
		})
		.join()
		.unwrap_err();

		provider
			.configure_dependency_secrets(&[dependency("DIGITALOCEAN_ACCESS_TOKEN", "recovered")])
			.unwrap();
		assert_eq!(
			provider.token().unwrap().expose_secret(),
			b"recovered".as_slice()
		);
	}

	#[test]
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider = bare_provider();
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
		let provider = bare_provider();
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
	fn structured_references_flatten_into_prefixed_keys() {
		let provider = bare_provider();
		let key = |address: &NativeAddress| provider.value_key(Address::Native(address));

		// Convention and item-only refs name the key directly.
		assert_eq!(
			provider
				.value_key(Address::convention("p", "production", "JWT_SECRET"))
				.unwrap(),
			"JWT_SECRET"
		);
		assert_eq!(
			key(&native("PROD_DATABASE_URL", None, None)).unwrap(),
			"PROD_DATABASE_URL"
		);

		// `path = ["auth"]` on JWT_SECRET: item `auth`, field `JWT_SECRET`.
		assert_eq!(
			key(&path_ref("JWT_SECRET", &["auth"], None)).unwrap(),
			"auth__JWT_SECRET"
		);
		// A `key` renames the last segment.
		assert_eq!(
			key(&path_ref("GITHUB_TOKEN", &["github"], Some("token"))).unwrap(),
			"github__token"
		);
		// Deeper paths become sections, joined segment by segment.
		assert_eq!(
			key(&path_ref("KEY", &["app", "auth", "jwt"], None)).unwrap(),
			"app__auth__jwt__KEY"
		);
		// Without a path, `key` is a field of the declaration's own item, as
		// for every other provider.
		assert_eq!(
			key(&crate::config::SecretRequest {
				path: None,
				key: Some("signing".to_string()),
			}
			.to_native_address("JWT_SECRET")
			.unwrap())
			.unwrap(),
			"JWT_SECRET__signing"
		);
		// A raw section without a field is a prefix too.
		assert_eq!(
			key(&native("app", Some("auth"), None)).unwrap(),
			"app__auth"
		);
		// Later segments may start with a digit; only the joined key's
		// first character is restricted.
		assert_eq!(
			key(&native("auth", None, Some("2FA_SEED"))).unwrap(),
			"auth__2FA_SEED"
		);
	}

	#[test]
	fn invalid_reference_segments_are_rejected_with_their_coordinates() {
		let provider = bare_provider();

		for address in [
			native("auth", None, Some("JWT-SECRET")),
			native("auth", Some(""), Some("KEY")),
			native("auth", Some("a//b"), Some("KEY")),
			native("auth", None, Some("")),
			native("1auth", None, Some("KEY")),
			native("aüth", None, Some("KEY")),
		] {
			let error = provider.value_key(Address::Native(&address)).unwrap_err();
			assert!(error.to_string().contains(&address.render()), "{error}");
			assert!(
				error.to_string().contains("valid DigitalOcean secret key"),
				"{error}"
			);
		}

		let versioned = NativeAddress {
			item: "auth".to_string(),
			version: Some("3".to_string()),
			..Default::default()
		};
		let error = provider.value_key(Address::Native(&versioned)).unwrap_err();
		assert!(
			error.to_string().contains("`version` coordinate"),
			"{error}"
		);
		assert_eq!(provider.supported_coords(), &["section", "field"]);
	}

	#[test]
	fn entry_coordinates_are_the_canonical_flat_key() {
		let provider = bare_provider();
		let structured = path_ref("JWT_SECRET", &["auth"], None);
		let flat = native("auth__JWT_SECRET", None, None);

		let canonical = provider
			.configured_entry_coordinates(Address::Native(&structured))
			.unwrap()
			.into_owned();
		assert_eq!(canonical, flat);
		assert_eq!(
			provider
				.configured_entry_coordinates(Address::Native(&flat))
				.unwrap()
				.into_owned(),
			flat
		);
		assert!(
			provider
				.configured_entry_coordinates(Address::Native(&native("a", None, Some("b-c"))))
				.is_err()
		);
	}

	#[test]
	fn reads_a_value_from_the_configured_secret() {
		let (endpoint, server) = response_server(vec![(
			"200 OK",
			secret_body(4, r#"{"API_KEY":"prod-value","OTHER":"untouched"}"#),
		)]);
		let provider = provider_with_token(endpoint);

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"prod-value");

		let requests = server.join().unwrap();
		assert_eq!(
			requests[0].line,
			format!("GET /v2/security/secrets/{NAME}?region={REGION} HTTP/1.1")
		);
		assert_eq!(requests[0].headers["authorization"], "Bearer test-token");
	}

	/// The monochange.dev shape: every declaration reads one object, through
	/// convention keys, `path` refs, a `key` rename, and two declarations
	/// sharing one key. One request serves all of them.
	#[test]
	fn a_batch_reads_the_object_once_for_every_key() {
		let (endpoint, server) = response_server(vec![(
			"200 OK",
			secret_body(
				9,
				r#"{"DATABASE_URL":"sqlite://prod","auth__JWT_SECRET":"jwt","github__GITHUB_CLIENT_ID":"client","github__token":"pat","ai__OPENROUTER_API_KEY":"router"}"#,
			),
		)]);
		let provider = provider_with_token(endpoint);
		let jwt = path_ref("JWT_SECRET", &["auth"], None);
		let client_id = path_ref("GITHUB_CLIENT_ID", &["github"], None);
		let token = path_ref("GITHUB_TOKEN", &["github"], Some("token"));
		let token_alias = path_ref("GH_TOKEN", &["github"], Some("token"));
		let missing = path_ref("MONOCHANGE_TOKEN", &["release"], None);

		let values = provider
			.get_many(&[
				(
					"DATABASE_URL",
					Address::convention("monochange_app", "production", "DATABASE_URL"),
				),
				("JWT_SECRET", Address::Native(&jwt)),
				("GITHUB_CLIENT_ID", Address::Native(&client_id)),
				("GITHUB_TOKEN", Address::Native(&token)),
				("GH_TOKEN", Address::Native(&token_alias)),
				("MONOCHANGE_TOKEN", Address::Native(&missing)),
			])
			.unwrap();

		let text = |name: &str| values[name].try_as_utf8().unwrap().to_string();
		assert_eq!(values.len(), 5, "the missing key is omitted");
		assert_eq!(text("DATABASE_URL"), "sqlite://prod");
		assert_eq!(text("JWT_SECRET"), "jwt");
		assert_eq!(text("GITHUB_CLIENT_ID"), "client");
		assert_eq!(text("GITHUB_TOKEN"), "pat");
		assert_eq!(text("GH_TOKEN"), "pat");
		assert!(!values.contains_key("MONOCHANGE_TOKEN"));

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 1, "one request per secret object");
		assert!(requests[0].line.starts_with("GET "), "{}", requests[0].line);

		// Presence checks reuse the same single read.
		let (endpoint, server) = response_server(vec![(
			"200 OK",
			secret_body(9, r#"{"auth__JWT_SECRET":"jwt"}"#),
		)]);
		let provider = provider_with_token(endpoint);
		let present = provider
			.exists_many(&[
				("JWT_SECRET", Address::Native(&jwt)),
				("GITHUB_CLIENT_ID", Address::Native(&client_id)),
			])
			.unwrap();
		assert_eq!(present, HashSet::from(["JWT_SECRET".to_string()]));
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn an_empty_batch_makes_no_request_and_needs_no_token() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
		let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
		let listener = silent_listener();
		let provider = provider_at(listener.local_addr().unwrap());
		assert!(provider.get_many(&[]).unwrap().is_empty());
		assert_untouched(&listener);
	}

	#[test]
	fn one_invalid_key_fails_the_batch_before_any_request() {
		let listener = silent_listener();
		let provider = {
			let mut provider = provider_at(listener.local_addr().unwrap());
			provider.with_credentials(ProviderCredentials::from([(
				TOKEN.to_string(),
				SecretBytes::from_utf8("test-token"),
			)]));
			provider
		};
		let invalid = native("auth", None, Some("JWT-SECRET"));

		let error = provider
			.get_many(&[
				("VALID", Address::convention("p", "production", "VALID")),
				("INVALID", Address::Native(&invalid)),
			])
			.unwrap_err();
		assert!(error.to_string().contains("field=JWT-SECRET"), "{error}");
		assert_untouched(&listener);

		for result in [
			provider.set(Address::Native(&invalid), &SecretBytes::from_utf8("v")),
			provider.delete(Address::Native(&invalid)).map(|_| ()),
			provider
				.describe_write_target(Address::Native(&invalid))
				.map(|_| ()),
			provider.check_deletable(Address::Native(&invalid)),
		] {
			assert!(result.is_err());
		}
		assert_untouched(&listener);
	}

	#[test]
	fn a_missing_object_resolves_every_key_to_none() {
		let (endpoint, server) = response_server(vec![("404 Not Found", NOT_FOUND.to_string())]);
		let provider = provider_with_token(endpoint);
		let jwt = path_ref("JWT_SECRET", &["auth"], None);
		let values = provider
			.get_many(&[
				("API_KEY", Address::convention("p", "production", "API_KEY")),
				("JWT_SECRET", Address::Native(&jwt)),
			])
			.unwrap();
		assert!(values.is_empty());
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn a_missing_key_resolves_to_none() {
		let (endpoint, server) =
			response_server(vec![("200 OK", secret_body(1, r#"{"OTHER":"value"}"#))]);
		let provider = provider_with_token(endpoint);
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "MISSING"))
				.unwrap(),
			None
		);
		assert_eq!(server.join().unwrap().len(), 1);

		// A response without `values` is an object with no keys.
		let (endpoint, server) = response_server(vec![(
			"200 OK",
			format!(r#"{{"secret":"{NAME}","region":"{REGION}","version":1}}"#),
		)]);
		let provider = provider_with_token(endpoint);
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "ANY"))
				.unwrap(),
			None
		);
		server.join().unwrap();
	}

	#[test]
	fn creates_a_missing_secret_with_the_key() {
		let (endpoint, server) = response_server(vec![
			("404 Not Found", NOT_FOUND.to_string()),
			("200 OK", write_result(1)),
		]);
		let provider = provider_with_token(endpoint);

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 2);
		assert_eq!(requests[1].line, "POST /v2/security/secrets HTTP/1.1");
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["name"], NAME);
		assert_eq!(body["region"], REGION);
		assert_eq!(body["values"], serde_json::json!({"API_KEY": "new-value"}));
	}

	#[test]
	fn a_racing_create_turns_into_an_update() {
		let (endpoint, server) = response_server(vec![
			("404 Not Found", NOT_FOUND.to_string()),
			(
				"409 Conflict",
				r#"{"id":"conflict","message":"a secret with this name already exists"}"#
					.to_string(),
			),
			("200 OK", secret_body(1, r#"{"RACED":"first"}"#)),
			("200 OK", write_result(2)),
		]);
		let provider = provider_with_token(endpoint);

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("mine"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 4);
		assert!(requests[3].line.starts_with("PUT "), "{}", requests[3].line);
		let body: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
		assert_eq!(
			body["values"],
			serde_json::json!({"API_KEY": "mine", "RACED": "first"})
		);
	}

	#[test]
	fn merges_into_an_existing_secret_with_the_current_version() {
		let (endpoint, server) = response_server(vec![
			("200 OK", secret_body(7, r#"{"OTHER":"value"}"#)),
			("200 OK", write_result(8)),
		]);
		let provider = provider_with_token(endpoint);

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("merged-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(
			requests[1].line,
			format!("PUT /v2/security/secrets/{NAME}?region={REGION} HTTP/1.1")
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
	fn writes_and_deletes_through_a_path_reference_use_the_prefixed_key() {
		let jwt = path_ref("JWT_SECRET", &["auth"], None);
		let (endpoint, server) = response_server(vec![
			("200 OK", secret_body(3, r#"{"OTHER":"kept"}"#)),
			("200 OK", write_result(4)),
			(
				"200 OK",
				secret_body(4, r#"{"OTHER":"kept","auth__JWT_SECRET":"rotated"}"#),
			),
			("200 OK", write_result(5)),
		]);
		let provider = provider_with_token(endpoint);

		provider
			.set(Address::Native(&jwt), &SecretBytes::from_utf8("rotated"))
			.unwrap();
		assert!(provider.delete(Address::Native(&jwt)).unwrap());

		let requests = server.join().unwrap();
		let written: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(
			written["values"],
			serde_json::json!({"OTHER": "kept", "auth__JWT_SECRET": "rotated"})
		);
		let deleted: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
		assert_eq!(deleted["values"], serde_json::json!({"OTHER": "kept"}));
		assert_eq!(
			provider
				.describe_write_target(Address::Native(&jwt))
				.unwrap(),
			format!("DigitalOcean secret '{NAME}' (region '{REGION}') key 'auth__JWT_SECRET'")
		);
	}

	#[test]
	fn retries_when_the_version_conflicts() {
		let conflict = r#"{"id":"conflict","message":"The version provided does not match the current version."}"#;
		let (endpoint, server) = response_server(vec![
			("200 OK", secret_body(1, r#"{"API_KEY":"stale"}"#)),
			("409 Conflict", conflict.to_string()),
			(
				"200 OK",
				secret_body(2, r#"{"API_KEY":"stale","RACED":"added"}"#),
			),
			("200 OK", write_result(3)),
		]);
		let provider = provider_with_token(endpoint);

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
	fn persistent_conflicts_surface_after_the_last_attempt() {
		let conflict = r#"{"id":"conflict","message":"The version provided does not match the current version."}"#;
		let mut responses = Vec::new();

		for version in 1..=3 {
			responses.push(("200 OK", secret_body(version, r#"{"API_KEY":"a","B":"b"}"#)));
			responses.push(("409 Conflict", conflict.to_string()));
		}

		let (endpoint, server) = response_server(responses.clone());
		let provider = provider_with_token(endpoint);
		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("never-written"),
			)
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 409 while updating"),
			"{error}"
		);
		assert_eq!(server.join().unwrap().len(), MAX_WRITE_ATTEMPTS * 2);

		let (endpoint, server) = response_server(responses);
		let provider = provider_with_token(endpoint);
		let error = provider
			.delete(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("HTTP 409 while deleting the secret key"),
			"{error}"
		);
		assert_eq!(server.join().unwrap().len(), MAX_WRITE_ATTEMPTS * 2);
	}

	#[test]
	fn deleting_a_missing_key_is_idempotent() {
		let (endpoint, server) = response_server(vec![("404 Not Found", NOT_FOUND.to_string())]);
		let provider = provider_with_token(endpoint);
		assert!(
			!provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);

		let (endpoint, server) =
			response_server(vec![("200 OK", secret_body(1, r#"{"OTHER":"value"}"#))]);
		let provider = provider_with_token(endpoint);
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn deletes_a_key_and_keeps_the_rest() {
		let (endpoint, server) = response_server(vec![
			(
				"200 OK",
				secret_body(5, r#"{"API_KEY":"gone","OTHER":"kept"}"#),
			),
			("200 OK", write_result(6)),
		]);
		let provider = provider_with_token(endpoint);

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		assert!(requests[1].line.starts_with("PUT "));
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["values"], serde_json::json!({"OTHER": "kept"}));
	}

	#[test]
	fn removing_the_last_key_explains_the_constraint_instead_of_deleting() {
		let (endpoint, server) =
			response_server(vec![("200 OK", secret_body(2, r#"{"API_KEY":"only"}"#))]);
		let provider = provider_with_token(endpoint);

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
		let (endpoint, server) =
			response_server(vec![("401 Unauthorized", unauthorized.to_string())]);
		let provider = provider_with_token(endpoint);
		let jwt = path_ref("JWT_SECRET", &["auth"], None);

		let error = provider
			.get_many(&[
				("API_KEY", Address::convention("p", "production", "API_KEY")),
				("JWT_SECRET", Address::Native(&jwt)),
			])
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
		assert!(!error.to_string().contains("test-token"), "{error}");
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn bare_and_empty_error_bodies_are_reported() {
		let (endpoint, server) =
			response_server(vec![("500 Internal Server Error", "boom".to_string())]);
		let provider = provider_with_token(endpoint);
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 500"), "{error}");
		assert!(error.to_string().contains("boom"), "{error}");
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("503 Service Unavailable", String::new())]);
		let provider = provider_with_token(endpoint);
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert_eq!(
			error.to_string(),
			"Provider operation failed: DigitalOcean returned HTTP 503 while reading the secret"
		);
		server.join().unwrap();
	}

	/// A malformed success body can quote secret values in serde's message, so
	/// only the error's category and position are reported.
	#[test]
	fn invalid_json_reports_the_position_without_the_body() {
		for body in [
			"not-json".to_string(),
			r#"{"version":1,"values":"leaked-secret-value"}"#.to_string(),
			r#"{"version":1,"values":{"API_KEY":["leaked-secret-value"]}}"#.to_string(),
		] {
			let (endpoint, server) = response_server(vec![("200 OK", body)]);
			let provider = provider_with_token(endpoint);
			let error = provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap_err();
			let shown = format!("{error} {error:?}");
			assert!(shown.contains("invalid JSON while reading"), "{shown}");
			assert!(shown.contains("line 1, column"), "{shown}");
			assert!(!shown.contains("leaked-secret-value"), "{shown}");
			assert!(!shown.contains("not-json"), "{shown}");
			server.join().unwrap();
		}
	}

	/// A rejected replacement can echo the values it carried; every value sent
	/// with the request, including the object's other keys, is redacted.
	#[test]
	fn write_errors_redact_every_value_the_request_carried() {
		let echo = r#"{"id":"unprocessable_entity","message":"values rejected: new-secret-value then existing-secret-value-long then existing"}"#;
		let (endpoint, server) = response_server(vec![
			(
				"200 OK",
				secret_body(
					1,
					r#"{"OTHER":"existing-secret-value-long","SHORT":"existing","EMPTY":""}"#,
				),
			),
			("422 Unprocessable Entity", echo.to_string()),
		]);
		let provider = provider_with_token(endpoint);

		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-secret-value"),
			)
			.unwrap_err();
		let shown = format!("{error} {error:?}");
		assert!(
			shown.contains("HTTP 422 while updating the secret"),
			"{shown}"
		);
		assert!(shown.contains("unprocessable_entity"), "{shown}");
		assert!(!shown.contains("new-secret-value"), "{shown}");
		// The longer value is redacted whole, not around its `existing` prefix.
		assert!(!shown.contains("secret-value-long"), "{shown}");
		assert!(!shown.contains("existing"), "{shown}");
		assert_eq!(shown.matches("[REDACTED]").count(), 6, "{shown}");
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![
			("404 Not Found", NOT_FOUND.to_string()),
			(
				"400 Bad Request",
				"<html>bad request for created-secret-value</html>".to_string(),
			),
		]);
		let provider = provider_with_token(endpoint);
		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("created-secret-value"),
			)
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("HTTP 400 while creating the secret"),
			"{error}"
		);
		assert!(
			!error.to_string().contains("created-secret-value"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn long_error_details_are_truncated_after_redaction() {
		let value = "v".repeat(MAX_ERROR_DETAIL_CHARS);
		let body = format!("{}{value}", "x".repeat(MAX_ERROR_DETAIL_CHARS - 4));
		let error = api_error(
			reqwest::StatusCode::BAD_REQUEST,
			body.as_bytes(),
			"updating the secret",
			&BTreeMap::from([("KEY".to_string(), value.clone())]),
		);
		let message = error.to_string();
		// Truncating first would have kept the value's first four characters.
		assert!(!message.contains("vvvv"), "{message}");
		assert!(message.ends_with("[RED"), "{message}");
	}

	#[test]
	fn unreachable_endpoints_report_the_action() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = listener.local_addr().unwrap();
		drop(listener);
		let provider = provider_with_token(endpoint);
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("failed to reach DigitalOcean while reading the secret"),
			"{error}"
		);
	}

	#[test]
	fn redirects_are_returned_rather_than_followed() {
		let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
		redirect.set_nonblocking(true).unwrap();
		let target = redirect.local_addr().unwrap();
		let (endpoint, server) = {
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let endpoint = listener.local_addr().unwrap();
			let server = std::thread::spawn(move || {
				let (mut stream, _) = listener.accept().unwrap();
				let mut reader = BufReader::new(&mut stream);
				let mut line = String::new();

				while reader.read_line(&mut line).unwrap() > 2 {
					line.clear();
				}

				write!(
					stream,
					"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
				)
				.unwrap();
			});
			(endpoint, server)
		};
		let provider = provider_with_token(endpoint);

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 307"), "{error}");
		server.join().unwrap();
		assert_untouched(&redirect);
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let listener = silent_listener();
		let provider = provider_at(listener.local_addr().unwrap());
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
		assert_untouched(&listener);
	}

	#[test]
	fn reflection_lists_the_secret_keys() {
		let (endpoint, server) = response_server(vec![(
			"200 OK",
			secret_body(3, r#"{"API_KEY":"a","auth__JWT_SECRET":"b"}"#),
		)]);
		let provider = provider_with_token(endpoint);

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 2);
		assert!(reflected.contains_key("API_KEY"));
		assert!(reflected.contains_key("auth__JWT_SECRET"));
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("404 Not Found", NOT_FOUND.to_string())]);
		let provider = provider_with_token(endpoint);
		assert!(
			provider
				.reflect(DiscoveryContext::new("project", "production"))
				.unwrap()
				.is_empty()
		);
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_region_and_secret() {
		let provider = bare_provider();
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

	/// End-to-end resolution through a manifest, with the real provider
	/// behind a loopback scheme so nothing can reach `DigitalOcean`.
	mod manifest {
		use std::path::Path;

		use super::*;
		use crate::Secrets;
		use crate::config::Config;

		/// `digitalocean-loopback://NAME?region=REGION&port=PORT`: the real
		/// provider with its API base moved to a loopback port.
		struct LoopbackDigitalocean {
			inner: DigitaloceanProvider,
			port: u16,
		}

		struct LoopbackConfig {
			inner: DigitaloceanConfig,
			port: u16,
		}

		impl TryFrom<&ProviderUrl> for LoopbackConfig {
			type Error = MonosecretError;

			fn try_from(url: &ProviderUrl) -> Result<Self> {
				let query = |name: &str| {
					url.query_pairs()
						.find(|(key, _)| key == name)
						.map(|(_, value)| value.into_owned())
						.unwrap()
				};
				let port = query("port").parse().unwrap();
				let inner = DigitaloceanConfig::try_from(&ProviderUrl::new(
					url::Url::parse(&format!(
						"digitalocean://{}?region={}",
						url.host().unwrap(),
						query("region")
					))
					.unwrap(),
				))?;
				Ok(Self { inner, port })
			}
		}

		impl LoopbackDigitalocean {
			fn new(config: LoopbackConfig) -> Self {
				let mut inner = DigitaloceanProvider::new(config.inner);
				inner.api_base = format!("http://127.0.0.1:{}/v2", config.port);
				Self {
					inner,
					port: config.port,
				}
			}
		}

		crate::register_provider! {
			struct: LoopbackDigitalocean,
			config: LoopbackConfig,
			name: "digitalocean-loopback",
			description: "DigitalOcean provider against a loopback test server",
			schemes: ["digitalocean-loopback"],
			examples: ["digitalocean-loopback://my-app-secrets?region=nyc3&port=8080"],
		}

		impl Provider for LoopbackDigitalocean {
			fn convention_address(
				&self,
				project: &str,
				profile: &str,
				key: &str,
			) -> Result<NativeAddress> {
				self.inner.convention_address(project, profile, key)
			}

			fn supported_coords(&self) -> &'static [&'static str] {
				self.inner.supported_coords()
			}

			fn configure_dependency_secrets(
				&self,
				dependencies: &[(String, SecretBytes)],
			) -> Result<()> {
				self.inner.configure_dependency_secrets(dependencies)
			}

			fn with_credentials(&mut self, credentials: ProviderCredentials) {
				self.inner.with_credentials(credentials);
			}

			fn name(&self) -> &str {
				Self::PROVIDER_NAME
			}

			fn uri(&self) -> String {
				format!(
					"digitalocean-loopback://{}?region={}&port={}",
					self.inner.config.name, self.inner.config.region, self.port
				)
			}

			fn storage_identity(&self) -> String {
				self.inner.storage_identity()
			}

			fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
				self.inner.get(addr)
			}

			fn get_many(
				&self,
				requests: &[(&str, Address<'_>)],
			) -> Result<HashMap<String, SecretBytes>> {
				self.inner.get_many(requests)
			}

			fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
				self.inner.set(addr, value)
			}
		}

		#[test]
		fn the_loopback_scheme_wraps_the_real_provider() {
			let (endpoint, server) = response_server(vec![
				("200 OK", secret_body(1, r#"{"KEY":"old"}"#)),
				("200 OK", secret_body(1, r#"{"KEY":"old"}"#)),
				("200 OK", write_result(2)),
			]);
			let mut provider = LoopbackDigitalocean::new(
				LoopbackConfig::try_from(&ProviderUrl::new(
					url::Url::parse(&format!(
						"digitalocean-loopback://{NAME}?region={REGION}&port={}",
						endpoint.port()
					))
					.unwrap(),
				))
				.unwrap(),
			);
			provider.with_credentials(ProviderCredentials::from([(
				TOKEN.to_string(),
				SecretBytes::from_utf8("test-token"),
			)]));
			let address = Address::convention("p", "production", "KEY");

			assert_eq!(provider.name(), "digitalocean-loopback");
			assert_eq!(
				provider
					.convention_address("p", "production", "KEY")
					.unwrap(),
				provider
					.inner
					.convention_address("p", "production", "KEY")
					.unwrap()
			);
			assert_eq!(
				provider.get(address).unwrap().unwrap().expose_secret(),
				b"old"
			);
			provider
				.set(address, &SecretBytes::from_utf8("new"))
				.unwrap();
			assert_eq!(server.join().unwrap().len(), 3);
		}

		/// The production profile monochange.dev uses, with the provider
		/// pointed at `port`, the bootstrap token in `bootstrap`, and `cache`
		/// either `None` or the inline cache policy table.
		fn manifest(port: u16, bootstrap: &Path, cache: Option<&Path>) -> Config {
			let cache_entry = cache.map_or_else(String::new, |path| {
				format!("cache-dotenv = 'dotenv://{}'\n", path.display())
			});
			let cache_policy = cache.map_or(
				"",
				|_| r#", cache = { provider = "cache-dotenv", max_age = "1h" }"#,
			);
			toml::from_str(&format!(
				r#"
[project]
name = "monochange_app"
revision = "1.0"

[providers]
bootstrap = 'dotenv://{bootstrap}'
{cache_entry}do = {{ uri = "digitalocean-loopback://monochange-dev?region=lon1&port={port}", depends_on = [{{ secret = "DIGITALOCEAN_ACCESS_TOKEN" }}]{cache_policy} }}

[profiles.default]
DIGITALOCEAN_ACCESS_TOKEN = {{ description = "DigitalOcean read token", providers = ["bootstrap"] }}
JWT_SECRET = {{ description = "JWT signing secret", providers = [{{ provider = "do", path = ["auth"] }}] }}
GITHUB_CLIENT_ID = {{ description = "GitHub client ID", providers = [{{ provider = "do", path = ["github"] }}] }}
GITHUB_CLIENT_SECRET = {{ description = "GitHub client secret", providers = [{{ provider = "do", path = ["github"] }}] }}
GITHUB_APP_ID = {{ description = "GitHub App ID", required = false, providers = [{{ provider = "do", path = ["github"] }}] }}
OPENROUTER_API_KEY = {{ description = "OpenRouter key", required = false, providers = [{{ provider = "do", path = ["ai"] }}] }}
"#,
				bootstrap = bootstrap.display()
			))
			.expect("valid manifest")
		}

		/// The `monochange-dev` object. `OPENROUTER_API_KEY` is optional and
		/// only provisioned when `with_optional` is set.
		fn object_body(with_optional: bool) -> String {
			let optional = if with_optional {
				r#","ai__OPENROUTER_API_KEY":"router""#
			} else {
				""
			};
			secret_body(
				12,
				&format!(
					r#"{{"auth__JWT_SECRET":"jwt","github__GITHUB_CLIENT_ID":"client","github__GITHUB_CLIENT_SECRET":"secret","github__GITHUB_APP_ID":"42"{optional}}}"#
				),
			)
		}

		fn resolved(secrets: &Secrets) -> crate::ResolveResponse {
			let response = secrets.resolve().unwrap();
			assert!(response.is_ok(), "{:?}", response.missing_required);
			response
		}

		fn value(response: &crate::ResolveResponse, name: &str) -> String {
			response.secrets[name].value.clone().unwrap()
		}

		fn bootstrap_file(directory: &Path) -> std::path::PathBuf {
			let bootstrap = directory.join("bootstrap.env");
			std::fs::write(&bootstrap, "DIGITALOCEAN_ACCESS_TOKEN=bootstrap-token\n").unwrap();
			bootstrap
		}

		#[test]
		fn a_production_profile_costs_one_request_with_the_depends_on_token() {
			let _env = crate::tests::scrub_resolution_env();
			let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
			let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
			let directory = tempfile::TempDir::new().unwrap();
			let bootstrap = bootstrap_file(directory.path());
			let (endpoint, server) = response_server(vec![("200 OK", object_body(false))]);

			let secrets = Secrets::new(
				manifest(endpoint.port(), &bootstrap, None),
				None,
				None,
				Some("default".to_string()),
			);
			let response = resolved(&secrets);

			assert_eq!(value(&response, "JWT_SECRET"), "jwt");
			assert_eq!(value(&response, "GITHUB_CLIENT_ID"), "client");
			assert_eq!(value(&response, "GITHUB_CLIENT_SECRET"), "secret");
			assert_eq!(value(&response, "GITHUB_APP_ID"), "42");
			assert_eq!(response.missing_optional, vec!["OPENROUTER_API_KEY"]);

			let requests = server.join().unwrap();
			assert_eq!(requests.len(), 1, "one request for the whole profile");
			assert_eq!(
				requests[0].line,
				"GET /v2/security/secrets/monochange-dev?region=lon1 HTTP/1.1"
			);
			assert_eq!(
				requests[0].headers["authorization"], "Bearer bootstrap-token",
				"the depends_on secret authenticates, not the environment"
			);
		}

		#[test]
		fn a_cached_route_serves_a_restart_without_contacting_digitalocean() {
			let _env = crate::tests::scrub_resolution_env();
			let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
			let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
			let directory = tempfile::TempDir::new().unwrap();
			let bootstrap = bootstrap_file(directory.path());
			let cache = directory.path().join("cache.env");
			let (endpoint, server) = response_server(vec![("200 OK", object_body(true))]);
			let config = manifest(endpoint.port(), &bootstrap, Some(&cache));

			let first = Secrets::new(config.clone(), None, None, Some("default".to_string()));
			assert_eq!(value(&resolved(&first), "JWT_SECRET"), "jwt");
			assert_eq!(server.join().unwrap().len(), 1, "a cold cache reads once");
			let cached = std::fs::read_to_string(&cache).unwrap();
			assert!(
				cached.contains("JWT_SECRET=") && !cached.contains("auth__JWT_SECRET"),
				"the cache is keyed by logical secret name"
			);
			assert!(!cached.contains("jwt\""), "cached values are encoded");

			// The server is gone: the second resolution succeeds only because
			// every value comes from the cache.
			let second = Secrets::new(config, None, None, Some("default".to_string()));
			let response = resolved(&second);
			assert_eq!(value(&response, "JWT_SECRET"), "jwt");
			assert_eq!(value(&response, "GITHUB_CLIENT_SECRET"), "secret");
			assert_eq!(value(&response, "GITHUB_APP_ID"), "42");
			assert_eq!(value(&response, "OPENROUTER_API_KEY"), "router");
		}

		/// Monosecret caches values, not absence: an optional secret that is not
		/// provisioned misses the cache on every resolution. The miss still
		/// costs a single batched read, and the cached values are not re-read.
		#[test]
		fn an_unprovisioned_optional_secret_costs_one_read_per_resolution() {
			let _env = crate::tests::scrub_resolution_env();
			let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
			let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
			let directory = tempfile::TempDir::new().unwrap();
			let bootstrap = bootstrap_file(directory.path());
			let cache = directory.path().join("cache.env");
			let (endpoint, server) = response_server(vec![
				("200 OK", object_body(false)),
				("200 OK", object_body(false)),
			]);
			let config = manifest(endpoint.port(), &bootstrap, Some(&cache));

			for _ in 0..2 {
				let secrets = Secrets::new(config.clone(), None, None, Some("default".to_string()));
				let response = resolved(&secrets);
				assert_eq!(value(&response, "JWT_SECRET"), "jwt");
				assert_eq!(response.missing_optional, vec!["OPENROUTER_API_KEY"]);
			}

			assert_eq!(
				server.join().unwrap().len(),
				2,
				"one batched read per resolution"
			);
		}

		#[test]
		fn an_unreachable_store_with_a_cold_cache_reports_the_failure() {
			let _env = crate::tests::scrub_resolution_env();
			let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
			let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
			let directory = tempfile::TempDir::new().unwrap();
			let bootstrap = bootstrap_file(directory.path());
			let cache = directory.path().join("cache.env");
			let closed = TcpListener::bind("127.0.0.1:0").unwrap();
			let port = closed.local_addr().unwrap().port();
			drop(closed);

			let secrets = Secrets::new(
				manifest(port, &bootstrap, Some(&cache)),
				None,
				None,
				Some("default".to_string()),
			);
			let error = secrets.resolve().unwrap_err();
			assert!(
				error.to_string().contains("failed to reach DigitalOcean"),
				"{error}"
			);
			assert!(!cache.exists() || std::fs::read_to_string(&cache).unwrap().is_empty());
		}

		/// The dotfiles spelling: a separate cached route alias whose
		/// authoritative source is the `DigitalOcean` alias. Secrets on the route
		/// address their keys with a secret-level `ref` (or convention names);
		/// a provider-reference `path` belongs on the alias that names the URI.
		#[test]
		fn a_fallback_route_alias_caches_ref_and_convention_keys() {
			let _env = crate::tests::scrub_resolution_env();
			let _first = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_ACCESS_TOKEN");
			let _second = crate::tests::EnvVarGuard::remove("DIGITALOCEAN_TOKEN");
			let directory = tempfile::TempDir::new().unwrap();
			let bootstrap = bootstrap_file(directory.path());
			let cache = directory.path().join("cache.env");
			let (endpoint, server) = response_server(vec![(
				"200 OK",
				secret_body(
					3,
					r#"{"DATABASE_URL":"db","auth__JWT_SECRET":"jwt","github__GITHUB_APP_ID":"42"}"#,
				),
			)]);
			let config: Config = toml::from_str(&format!(
				r#"
[project]
name = "monochange_app"
revision = "1.0"

[providers]
bootstrap = 'dotenv://{bootstrap}'
cache-dotenv = 'dotenv://{cache}'
do = {{ uri = "digitalocean-loopback://monochange-dev?region=lon1&port={port}", depends_on = [{{ secret = "DIGITALOCEAN_ACCESS_TOKEN" }}] }}
do-cached = {{ fallback = ["do"], cache = {{ provider = "cache-dotenv", max_age = "1h" }} }}

[profiles.default]
DIGITALOCEAN_ACCESS_TOKEN = {{ description = "DigitalOcean read token", providers = ["bootstrap"] }}
DATABASE_URL = {{ description = "Database URL", providers = ["do-cached"] }}
JWT_SECRET = {{ description = "JWT signing secret", providers = ["do-cached"], ref = {{ item = "auth", field = "JWT_SECRET" }} }}
GITHUB_APP_ID = {{ description = "GitHub App ID", providers = ["do-cached"], ref = {{ item = "github__GITHUB_APP_ID" }} }}
"#,
				bootstrap = bootstrap.display(),
				cache = cache.display(),
				port = endpoint.port()
			))
			.expect("valid manifest");

			let first = Secrets::new(config.clone(), None, None, Some("default".to_string()));
			resolved(&first);
			assert_eq!(server.join().unwrap().len(), 1, "one read serves the route");

			let second = Secrets::new(config, None, None, Some("default".to_string()));
			let response = resolved(&second);
			assert_eq!(value(&response, "DATABASE_URL"), "db");
			assert_eq!(value(&response, "JWT_SECRET"), "jwt");
			assert_eq!(value(&response, "GITHUB_APP_ID"), "42");
		}
	}
}
