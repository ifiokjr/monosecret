//! Vercel project environment variable provider.
//!
//! Vercel stores environment variables per project with one entry per target
//! environment (`production`, `preview`, or `development`). Monosecret maps a
//! declaration key directly to a variable name and selects the target through
//! the provider URI, so one alias per target keeps profiles isolated. Values
//! are read back through the API unless the variable is `sensitive`, which
//! only Vercel's runtime can read.
//!
//! # URI format
//!
//! `vercel://PROJECT[?team_id=TEAM_ID][&target=NAME][&type=KIND]`
//!
//! `PROJECT` is the project ID or name. Authentication comes from a `token`
//! provider credential, `VERCEL_TOKEN`, or `VERCEL_ACCESS_TOKEN`; the team
//! falls back to `VERCEL_ORG_ID`.

use std::borrow::Cow;
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
const TOKEN_ENVS: &[&str] = &["VERCEL_TOKEN", "VERCEL_ACCESS_TOKEN"];
const TEAM_ID_ENV: &str = "VERCEL_ORG_ID";
const API_BASE: &str = "https://api.vercel.com";
const DEFAULT_TARGET: &str = "production";
const DEFAULT_TYPE: &str = "encrypted";
const KNOWN_TARGETS: &[&str] = &["production", "preview", "development"];
const KNOWN_TYPES: &[&str] = &["encrypted", "plain", "sensitive"];
const SENSITIVE_TYPE: &str = "sensitive";

/// Configuration for one Vercel project's environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VercelConfig {
	/// Vercel project ID or name.
	pub project: String,
	/// Optional team ID scoping every request. `None` uses the token's
	/// personal scope.
	pub team_id: Option<String>,
	/// Target environment whose entries are read and written.
	pub target: String,
	/// Variable kind applied on write.
	pub kind: String,
}

impl TryFrom<&ProviderUrl> for VercelConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "vercel" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for vercel provider; expected 'vercel'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"vercel:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let project = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"vercel provider requires a project ID or name, for example vercel://my-project",
				)
			})?;
		validate_project_name(&project)?;

		if !url.path().trim_matches('/').is_empty() {
			return Err(operation_error(
				"vercel:// takes no path; put the project ID or name in the URI authority",
			));
		}

		let mut team_id = None;
		let mut target = None;
		let mut kind = None;

		for (key, value) in url.query_pairs() {
			let value = value.into_owned();

			let duplicate = match key.as_ref() {
				"team_id" => set_once(&mut team_id, value),
				"target" => set_once(&mut target, value),
				"type" => set_once(&mut kind, value),
				unknown => {
					return Err(operation_error(format!(
						"unknown vercel query parameter '{unknown}'; supported parameters are `team_id`, `target`, and `type`"
					)));
				}
			};

			if duplicate {
				return Err(operation_error(format!(
					"duplicate vercel query parameter '{key}'"
				)));
			}
		}

		let team_id = team_id.filter(|value| !value.is_empty());
		if let Some(team_id) = &team_id {
			validate_team_id(team_id)?;
		}

		let target = target.unwrap_or_else(|| DEFAULT_TARGET.to_string());
		if !KNOWN_TARGETS.contains(&target.as_str()) {
			return Err(operation_error(format!(
				"unknown Vercel target '{target}'; supported targets are {}",
				KNOWN_TARGETS.join(", ")
			)));
		}

		let kind = kind.unwrap_or_else(|| DEFAULT_TYPE.to_string());
		if !KNOWN_TYPES.contains(&kind.as_str()) {
			return Err(operation_error(format!(
				"unknown Vercel variable type '{kind}'; supported types are {}",
				KNOWN_TYPES.join(", ")
			)));
		}

		Ok(Self {
			project,
			team_id,
			target,
			kind,
		})
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

fn validate_project_name(project: &str) -> Result<()> {
	if project.is_empty()
		|| project.len() > 100
		|| !project
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
	{
		return Err(operation_error(
			"Vercel project IDs and names are at most 100 ASCII letters, digits, hyphens, or underscores",
		));
	}
	Ok(())
}

fn validate_team_id(team_id: &str) -> Result<()> {
	if team_id.is_empty()
		|| team_id.len() > 100
		|| !team_id
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
	{
		return Err(operation_error(
			"Vercel team IDs are at most 100 ASCII letters, digits, hyphens, or underscores",
		));
	}
	Ok(())
}

/// `target` arrives as a string for single-target entries and as an array
/// when one entry serves several targets.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EnvTargets {
	Many(Vec<String>),
	One(String),
}

impl EnvTargets {
	fn contains(&self, target: &str) -> bool {
		match self {
			Self::Many(targets) => targets.iter().any(|entry| entry == target),
			Self::One(entry) => entry == target,
		}
	}
}

#[derive(Debug, Deserialize)]
struct EnvEntry {
	id: String,
	key: String,
	#[serde(default)]
	value: Option<String>,
	#[serde(default)]
	target: Option<EnvTargets>,
	#[serde(rename = "type", default)]
	var_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Pagination {
	#[allow(dead_code)]
	count: Option<u64>,
	next: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct EnvPage {
	envs: Vec<EnvEntry>,
	pagination: Option<Pagination>,
}

#[derive(Debug, Serialize)]
struct CreateEnv<'a> {
	key: &'a str,
	value: &'a str,
	#[serde(rename = "type")]
	kind: &'a str,
	target: [&'a str; 1],
}

#[derive(Debug, Deserialize)]
struct CreateFailure {
	error: CreateError,
}

#[derive(Debug, Deserialize)]
struct CreateError {
	#[serde(default)]
	code: Option<String>,
	message: String,
}

#[derive(Debug, Deserialize)]
struct CreateOutcome {
	#[serde(default)]
	failed: Vec<CreateFailure>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
	error: ApiError,
}

#[derive(Debug, Deserialize)]
struct ApiError {
	#[serde(default)]
	code: Option<String>,
	message: String,
}

/// A Vercel project environment variable provider.
pub struct VercelProvider {
	config: VercelConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: VercelProvider,
	config: VercelConfig,
	metadata: &super::catalog::VERCEL,
}

impl VercelProvider {
	pub fn new(config: VercelConfig) -> Self {
		Self {
			config,
			credentials: ProviderCredentials::new(),
			api_base: API_BASE.to_string(),
		}
	}

	fn token(&self) -> Option<SecretBytes> {
		super::credential_or_envs(&self.credentials, TOKEN, TOKEN_ENVS)
	}

	fn team_id(&self) -> Option<String> {
		self.config
			.team_id
			.clone()
			.or_else(|| super::preferred_env(&[TEAM_ID_ENV]))
			.filter(|value| !value.is_empty())
	}

	fn auth_headers(&self) -> Result<HeaderMap> {
		let token = self.token().ok_or_else(|| {
			let [primary, fallback, ..] = TOKEN_ENVS else {
				unreachable!("TOKEN_ENVS always names the primary and fallback variables")
			};
			operation_error(format!(
				"Vercel auth requires the `{TOKEN}` provider credential, {primary}, or {fallback}"
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
			// Secret-bearing bodies must remain confined to Vercel's fixed
			// API origin; a redirect response must never choose where a
			// POST body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build Vercel HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	fn envs_path(&self, decrypt: bool) -> String {
		format!(
			"{}/v10/projects/{}/env",
			self.api_base.trim_end_matches('/'),
			self.config.project
		) + if decrypt { "?decrypt=true" } else { "" }
	}

	/// Appends query parameters to a path that may already carry some.
	fn append_query(path: &str, query: &str) -> String {
		let separator = if path.contains('?') { '&' } else { '?' };
		format!("{path}{separator}{query}")
	}

	fn with_team_and_cursor(&self, path: &str, cursor: Option<u64>) -> String {
		let mut path = path.to_string();

		// The resolved team scope (URI parameter or VERCEL_ORG_ID) applies to
		// every request; `uri()` intentionally shows only the configured
		// form, matching how cloudflare renders account_id.
		if let Some(team_id) = self.team_id() {
			path = Self::append_query(&path, &format!("teamId={team_id}"));
		}

		if let Some(cursor) = cursor {
			path = Self::append_query(&path, &format!("next={cursor}"));
		}

		path
	}

	async fn request_page(
		&self,
		client: &reqwest::Client,
		action: &str,
		path: &str,
	) -> Result<(reqwest::StatusCode, Vec<u8>)> {
		let response = client
			.get(path)
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;
		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?
			.to_vec();
		Ok((status, body))
	}

	/// Walks every page of the project's environment variables.
	async fn list_envs(&self, client: &reqwest::Client, decrypt: bool) -> Result<Vec<EnvEntry>> {
		let action = if decrypt {
			"listing decrypted environment variables"
		} else {
			"listing environment variables"
		};
		let base = self.envs_path(decrypt);
		let mut entries = Vec::new();
		let mut cursor = None;

		loop {
			let path = self.with_team_and_cursor(&base, cursor);
			let (status, body) = self.request_page(client, action, &path).await?;
			let page: EnvPage = decode_response(status, &body, action)?;
			entries.extend(page.envs);

			match page.pagination.and_then(|pagination| pagination.next) {
				Some(next_cursor) => cursor = Some(next_cursor),
				None => return Ok(entries),
			}
		}
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if !is_valid_env_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid Vercel environment variable name: names are ASCII letters, digits, or underscores and start with a letter or underscore"
			)));
		}

		Ok(name)
	}

	fn matches_target(entry: &EnvEntry, target: &str) -> bool {
		entry
			.target
			.as_ref()
			.is_some_and(|targets| targets.contains(target))
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let entries = self.list_envs(client, true).await?;
		let Some(entry) = entries
			.iter()
			.find(|entry| entry.key == key && Self::matches_target(entry, &self.config.target))
		else {
			return Ok(None);
		};

		if entry.var_type.as_deref() == Some(SENSITIVE_TYPE) {
			return Err(operation_error(format!(
				"Vercel variable '{key}' is sensitive, so its value is readable only inside Vercel deployments; write it with `type=encrypted` or read it from another provider"
			)));
		}

		let value = entry.value.as_deref().ok_or_else(|| {
			operation_error(format!(
				"Vercel returned no decrypted value for '{key}' (type '{}')",
				entry.var_type.as_deref().unwrap_or("unknown")
			))
		})?;

		Ok(Some(SecretBytes::from_utf8(value)))
	}

	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		let path = self.with_team_and_cursor(
			&Self::append_query(&self.envs_path(false), "upsert=true"),
			None,
		);
		let response = client
			.post(path)
			.json(&CreateEnv {
				key,
				value,
				kind: &self.config.kind,
				target: [&self.config.target],
			})
			.send()
			.await
			.map_err(|error| reach_error("creating the environment variable", &error))?;

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error("creating the environment variable", &error))?
			.to_vec();

		if !status.is_success() {
			return Err(api_error(
				status,
				&body,
				"creating the environment variable",
			));
		}

		let outcome: CreateOutcome = serde_json::from_slice(&body).map_err(|error| {
			operation_error(format!(
				"Vercel returned invalid JSON while creating the environment variable: {}",
				crate::error::display_error_chain(&error)
			))
		})?;

		if let Some(failure) = outcome.failed.first() {
			let code = failure
				.error
				.code
				.as_deref()
				.map(|code| format!("{code}: "))
				.unwrap_or_default();
			return Err(operation_error(format!(
				"Vercel refused to store '{key}': {code}{}",
				failure.error.message
			)));
		}

		Ok(())
	}

	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		let entries = self.list_envs(client, false).await?;
		let matching: Vec<&EnvEntry> = entries
			.iter()
			.filter(|entry| entry.key == key && Self::matches_target(entry, &self.config.target))
			.collect();

		let mut deleted = false;
		for entry in matching {
			let path = self.with_team_and_cursor(
				&format!(
					"{}/v9/projects/{}/env/{}",
					self.api_base.trim_end_matches('/'),
					self.config.project,
					entry.id
				),
				None,
			);
			let response = client
				.delete(path)
				.send()
				.await
				.map_err(|error| reach_error("deleting the environment variable", &error))?;
			check_status(response, "deleting the environment variable").await?;
			deleted = true;
		}

		Ok(deleted)
	}
}

impl Provider for VercelProvider {
	/// The project plus the configured target supply isolation; convention
	/// writes use the Monosecret key directly as the variable name.
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
		let mut query = Vec::new();

		if let Some(team_id) = &self.config.team_id {
			query.push(format!("team_id={}", ProviderUrl::encode_query(team_id)));
		}

		if self.config.target != DEFAULT_TARGET {
			query.push(format!(
				"target={}",
				ProviderUrl::encode_query(&self.config.target)
			));
		}

		if self.config.kind != DEFAULT_TYPE {
			query.push(format!(
				"type={}",
				ProviderUrl::encode_query(&self.config.kind)
			));
		}

		let base = format!("vercel://{}", self.config.project);

		if query.is_empty() {
			base
		} else {
			format!("{base}?{}", query.join("&"))
		}
	}

	fn storage_identity(&self) -> String {
		let scope = self.team_id().unwrap_or_else(|| "personal".to_string());
		format!(
			"vercel://{scope}/{}/{}",
			self.config.project, self.config.target
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
		let value = super::require_utf8("vercel", value)?;
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
		let scope = match &self.config.team_id {
			Some(team_id) => format!("team '{team_id}'"),
			None => "personal scope".to_string(),
		};
		Ok(format!(
			"Vercel {} project '{}' environment variable '{}' for target '{}' (type '{}')",
			scope, self.config.project, name, self.config.target, self.config.kind
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let entries = super::block_on(self.list_envs(&client, false))?;

		Ok(entries
			.into_iter()
			.filter(|entry| Self::matches_target(entry, &self.config.target))
			.map(|entry| {
				let key = entry.key;
				let secret = Secret::required(format!("{key} Vercel environment variable"));
				(key, secret)
			})
			.collect())
	}
}

fn is_valid_env_key(name: &str) -> bool {
	!name.is_empty()
		&& name
			.bytes()
			.next()
			.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
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
			"Vercel returned invalid JSON while {action} (HTTP {}): {}",
			status.as_u16(),
			crate::error::display_error_chain(&error)
		))
	})
}

fn api_error(status: reqwest::StatusCode, body: &[u8], action: &str) -> MonosecretError {
	let detail = serde_json::from_slice::<ApiErrorBody>(body).map_or_else(
		|_| String::from_utf8_lossy(body).trim().to_string(),
		|error| {
			let code = error
				.error
				.code
				.map(|code| format!("{code}: "))
				.unwrap_or_default();
			format!("{code}{}", error.error.message)
		},
	);
	let detail = detail.chars().take(512).collect::<String>();

	if detail.is_empty() {
		operation_error(format!(
			"Vercel returned HTTP {} while {action}",
			status.as_u16()
		))
	} else {
		operation_error(format!(
			"Vercel returned HTTP {} while {action}: {detail}",
			status.as_u16()
		))
	}
}

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach Vercel while {action}: {}",
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

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> VercelConfig {
		VercelConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> VercelProvider {
		let mut provider = VercelProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}");
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

	fn page(envs: &str, next: Option<&str>) -> String {
		let next = match next {
			Some(next) => format!("\"next\":{next}"),
			None => "\"next\":null".to_string(),
		};
		format!(r#"{{"envs":{envs},"pagination":{{"count":1,{next}}}}}"#)
	}

	#[test]
	fn parses_and_round_trips_configuration() {
		let encoded = "vercel://my-project?team_id=team_abc123&target=preview&type=plain";
		let canonical = "vercel://my-project?team_id=team_abc123&target=preview&type=plain";
		let provider = VercelProvider::new(config(encoded));
		assert_eq!(provider.uri(), canonical);
		assert_eq!(config(&provider.uri()), provider.config);

		let defaults = VercelProvider::new(config("vercel://prj_9iVq1vKmTfLw2"));
		assert_eq!(defaults.uri(), "vercel://prj_9iVq1vKmTfLw2");
		assert_eq!(defaults.config.target, "production");
		assert_eq!(defaults.config.kind, "encrypted");
		assert_eq!(defaults.config.team_id, None);
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"vercel://",
			"vercel://my%20project",
			"vercel://my/project",
			"vercel://my-project/path",
			"vercel://my-project?unknown=true",
			"vercel://my-project?target=staging",
			"vercel://my-project?type=secret",
			"vercel://my-project?team_id=has space",
			"vercel://my-project?target=production&target=dev",
		] {
			assert!(
				VercelConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "vercel")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variables() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider = VercelProvider::new(config("vercel://my-project"));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("the `token` provider credential, VERCEL_TOKEN, or VERCEL_ACCESS_TOKEN"),
			"{error}"
		);
	}

	#[test]
	fn environment_token_is_used_when_no_credential_is_configured() {
		let _lock = crate::tests::scrub_resolution_env();
		let _fallback = crate::tests::EnvVarGuard::remove("VERCEL_ACCESS_TOKEN");
		let _token = crate::tests::EnvVarGuard::set("VERCEL_TOKEN", "env-token");
		let empty = Box::leak(page("[]", None).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let mut provider = VercelProvider::new(config("vercel://my-project"));
		provider.api_base = format!("http://{endpoint}");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);

		let expected = "Bearer env-token";
		assert_eq!(
			server.join().unwrap()[0]
				.headers
				.get("authorization")
				.map(String::as_str),
			Some(expected)
		);
	}

	#[test]
	fn second_environment_variable_is_the_fallback() {
		let _lock = crate::tests::scrub_resolution_env();
		let _first = crate::tests::EnvVarGuard::remove("VERCEL_TOKEN");
		let _second = crate::tests::EnvVarGuard::set("VERCEL_ACCESS_TOKEN", "access-token");
		let empty = Box::leak(page("[]", None).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let mut provider = VercelProvider::new(config("vercel://my-project"));
		provider.api_base = format!("http://{endpoint}");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		assert_eq!(
			server.join().unwrap()[0]
				.headers
				.get("authorization")
				.map(String::as_str),
			Some("Bearer access-token")
		);
	}

	#[test]
	fn team_id_falls_back_to_the_environment() {
		let _lock = crate::tests::scrub_resolution_env();
		let _team = crate::tests::EnvVarGuard::set(TEAM_ID_ENV, "team_from_env");
		let empty = Box::leak(page("[]", None).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "KEY"))
				.unwrap(),
			None
		);
		let request = &server.join().unwrap()[0];
		assert!(
			request.line.contains("teamId=team_from_env"),
			"{}",
			request.line
		);
	}

	#[test]
	fn reads_paginated_entries_for_the_configured_target() {
		let first = Box::leak(
			page(
				r#"[{"id":"env_1","key":"OTHER","value":"x","target":["development"],"type":"encrypted"}]"#,
				Some("1700000000"),
			)
			.into_boxed_str(),
		);
		let second = Box::leak(
			page(
				r#"[{"id":"env_2","key":"API_KEY","value":"prod-value","target":"production","type":"encrypted"}]"#,
				None,
			)
			.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", first), ("200 OK", second)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"prod-value");

		let requests = server.join().unwrap();
		assert!(
			requests[0]
				.line
				.starts_with("GET /v10/projects/my-project/env"),
			"{}",
			requests[0].line
		);
		assert!(
			requests[0].line.contains("decrypt=true"),
			"{}",
			requests[0].line
		);
		assert!(
			requests[1].line.contains("next=1700000000"),
			"{}",
			requests[1].line
		);
	}

	#[test]
	fn missing_key_or_target_resolves_to_none() {
		let body = Box::leak(
			page(
				r#"[{"id":"env_1","key":"API_KEY","value":"v","target":["preview"],"type":"encrypted"}]"#,
				None,
			)
			.into_boxed_str(),
		);
		// Both lookups walk the same list; each needs its own response.
		let (endpoint, server) = response_server(vec![("200 OK", body), ("200 OK", body)]);
		let provider = provider_with_token(endpoint, "vercel://my-project?target=production");

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap(),
			None
		);
		assert_eq!(
			provider
				.get(Address::convention("p", "production", "MISSING"))
				.unwrap(),
			None
		);
		server.join().unwrap();
	}

	#[test]
	fn sensitive_values_explain_their_unavailability() {
		let body = Box::leak(
			page(
				r#"[{"id":"env_1","key":"API_KEY","value":"","target":["production"],"type":"sensitive"}]"#,
				None,
			)
			.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("readable only inside Vercel"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn undecryptable_values_are_reported() {
		let body = Box::leak(
			page(
				r#"[{"id":"env_1","key":"API_KEY","target":["production"],"type":"encrypted"}]"#,
				None,
			)
			.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("no decrypted value"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn writes_with_upsert_target_and_type() {
		let created = r#"{"created":{"id":"env_9","key":"API_KEY","value":"v","target":["production"],"type":"encrypted"},"failed":[]}"#;
		let (endpoint, server) = response_server(vec![("201 Created", created)]);
		let provider = provider_with_token(
			endpoint,
			"vercel://my-project?team_id=team_abc123&target=preview&type=plain",
		);

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
				.starts_with("POST /v10/projects/my-project/env"),
			"{}",
			requests[0].line
		);
		assert!(
			requests[0].line.contains("upsert=true"),
			"{}",
			requests[0].line
		);
		assert!(
			requests[0].line.contains("teamId=team_abc123"),
			"{}",
			requests[0].line
		);
		let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
		assert_eq!(body["key"], "API_KEY");
		assert_eq!(body["value"], "new-value");
		assert_eq!(body["type"], "plain");
		assert_eq!(body["target"], serde_json::json!(["preview"]));
	}

	#[test]
	fn refused_writes_surface_the_api_reason() {
		let refused = r#"{"created":null,"failed":[{"error":{"code":"env_already_exists","message":"Environment variable already exists"}}]}"#;
		let (endpoint, server) = response_server(vec![("201 Created", refused)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("v"),
			)
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("env_already_exists: Environment variable already exists"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn write_failures_without_a_code_still_show_the_message() {
		let refused = r#"{"created":null,"failed":[{"error":{"message":"quota exceeded"}}]}"#;
		let (endpoint, server) = response_server(vec![("201 Created", refused)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("v"),
			)
			.unwrap_err();
		assert!(error.to_string().contains("quota exceeded"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn write_http_errors_surface_the_api_reason() {
		let forbidden =
			r#"{"error":{"code":"forbidden","message":"missing Projects: Edit permission"}}"#;
		let (endpoint, server) = response_server(vec![("403 Forbidden", forbidden)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("v"),
			)
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 403 while creating"),
			"{error}"
		);
		assert!(
			error
				.to_string()
				.contains("forbidden: missing Projects: Edit permission"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider = VercelProvider::new(config("vercel://my-project"));
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
	fn convention_is_flat_and_names_are_validated() {
		let provider = VercelProvider::new(config("vercel://my-project"));
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
	}

	#[test]
	fn deletes_every_matching_entry_and_missing_deletion_is_idempotent() {
		let listed = Box::leak(
			page(
				r#"[
					{"id":"env_1","key":"API_KEY","value":"v","target":["production"],"type":"encrypted"},
					{"id":"env_2","key":"API_KEY","value":"v","target":["production","preview"],"type":"encrypted"},
					{"id":"env_3","key":"API_KEY","value":"v","target":["development"],"type":"encrypted"}
				]"#,
				None,
			)
			.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![
			("200 OK", listed),
			("204 No Content", ""),
			("204 No Content", ""),
		]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		assert!(requests[1].line.contains("DELETE "));
		assert!(requests[1].line.contains("/env/env_1"));
		assert!(requests[2].line.contains("/env/env_2"));

		let empty = Box::leak(page("[]", None).into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn reflection_lists_target_entries_once() {
		let body = Box::leak(
			page(
				r#"[
					{"id":"env_1","key":"API_KEY","value":"v","target":["production"],"type":"encrypted"},
					{"id":"env_2","key":"API_KEY","value":"v","target":["production","preview"],"type":"encrypted"},
					{"id":"env_3","key":"PREVIEW_ONLY","value":"v","target":["preview"],"type":"encrypted"}
				]"#,
				None,
			)
			.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 1);
		assert!(reflected.contains_key("API_KEY"));
		assert!(!reflected.contains_key("PREVIEW_ONLY"));
		server.join().unwrap();
	}

	#[test]
	fn api_errors_surface_the_message_and_status() {
		let unauthorized = r#"{"error":{"code":"unauthorized","message":"token is not valid"}}"#;
		let (endpoint, server) = response_server(vec![("401 Unauthorized", unauthorized)]);
		let provider = provider_with_token(endpoint, "vercel://my-project");

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("HTTP 401 while listing"),
			"{error}"
		);
		assert!(error.to_string().contains("token is not valid"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn invalid_json_and_bare_error_bodies_are_reported() {
		let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
		let provider = provider_with_token(endpoint, "vercel://my-project");
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("invalid JSON while listing"),
			"{error}"
		);
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("500 Internal Server Error", "boom")]);
		let provider = provider_with_token(endpoint, "vercel://my-project");
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 500"), "{error}");
		assert!(error.to_string().contains("boom"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_scope_project_and_target() {
		let provider = VercelProvider::new(config(
			"vercel://my-project?team_id=team_abc123&target=preview&type=sensitive",
		));
		assert_eq!(
			provider.storage_identity(),
			"vercel://team_abc123/my-project/preview"
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			"Vercel team 'team_abc123' project 'my-project' environment variable 'KEY' for target 'preview' (type 'sensitive')"
		);
	}
}
