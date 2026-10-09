//! Netlify environment variable provider.
//!
//! Netlify's API stores environment variables per account or site with one
//! value per deploy context. Monosecret maps a declaration key directly to an
//! environment variable name and selects the deploy context through the
//! provider URI, so one alias per context keeps profiles isolated. Values are
//! read back through the API unless the variable is marked secret, which only
//! Netlify's build and runtime systems can read.
//!
//! # URI format
//!
//! `netlify://ACCOUNT_ID[?site_id=SITE_ID][&context=NAME][&scopes=LIST][&secret=true]`
//!
//! Authentication comes from a `token` provider credential or
//! `NETLIFY_AUTH_TOKEN`.

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
const TOKEN_ENV: &str = "NETLIFY_AUTH_TOKEN";
const API_BASE: &str = "https://api.netlify.com/api/v1";
const DEFAULT_CONTEXT: &str = "production";
const GENERIC_CONTEXT: &str = "all";
const KNOWN_CONTEXTS: &[&str] = &[
	"all",
	"production",
	"deploy-preview",
	"branch-deploy",
	"dev",
];
const KNOWN_SCOPES: &[&str] = &["builds", "functions", "runtime", "post-processing"];

/// Configuration for one Netlify account (or site) environment variable set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetlifyConfig {
	/// Netlify account ID or slug owning the environment variables.
	pub account_id: String,
	/// Optional site ID; restricts every operation to that site's variables.
	pub site_id: Option<String>,
	/// Deploy context whose value is read and written.
	pub context: String,
	/// Scopes applied when a variable is created. `None` keeps Netlify's
	/// defaults.
	pub scopes: Option<Vec<String>>,
	/// Whether created variables are marked secret, which hides their values
	/// from the API. Defaults to `false`.
	pub secret: bool,
}

impl TryFrom<&ProviderUrl> for NetlifyConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "netlify" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for netlify provider; expected 'netlify'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"netlify:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let account_id = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"netlify provider requires an account ID or slug, for example netlify://61c7ea67-1f2c-4a3b-9c8d-0e1f2a3b4c5d",
				)
			})?;
		validate_netlify_slug("account ID", &account_id)?;

		if !url.path().trim_matches('/').is_empty() {
			return Err(operation_error(
				"netlify:// takes no path; put the account ID in the URI authority and select a site with ?site_id=",
			));
		}

		let mut site_id = None;
		let mut context = None;
		let mut scopes = None;
		let mut secret = None;

		for (key, value) in url.query_pairs() {
			let value = value.into_owned();

			let duplicate = match key.as_ref() {
				"site_id" => set_once(&mut site_id, value),
				"context" => set_once(&mut context, value),
				"scopes" => set_once(&mut scopes, value),
				"secret" => set_once(&mut secret, value),
				unknown => {
					return Err(operation_error(format!(
						"unknown netlify query parameter '{unknown}'; supported parameters are `site_id`, `context`, `scopes`, and `secret`"
					)));
				}
			};

			if duplicate {
				return Err(operation_error(format!(
					"duplicate netlify query parameter '{key}'"
				)));
			}
		}

		let site_id = site_id.filter(|value| !value.is_empty());
		if let Some(site_id) = &site_id {
			validate_netlify_slug("site ID", site_id)?;
		}

		let context = context.unwrap_or_else(|| DEFAULT_CONTEXT.to_string());
		if !KNOWN_CONTEXTS.contains(&context.as_str()) {
			return Err(operation_error(format!(
				"unknown Netlify context '{context}'; supported contexts are {}",
				KNOWN_CONTEXTS.join(", ")
			)));
		}

		let scopes = match scopes.filter(|value| !value.is_empty()) {
			Some(scopes) => Some(parse_scopes(&scopes)?),
			None => None,
		};

		let secret = match secret.as_deref() {
			None | Some("false") => false,
			Some("true") => true,
			Some(value) => {
				return Err(operation_error(format!(
					"netlify `secret` must be `true` or `false`, not '{value}'"
				)));
			}
		};

		Ok(Self {
			account_id,
			site_id,
			context,
			scopes,
			secret,
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

fn parse_scopes(value: &str) -> Result<Vec<String>> {
	let mut scopes = Vec::new();

	for scope in value.split(',') {
		let scope = scope.trim();

		if scope.is_empty() {
			return Err(operation_error(
				"netlify scopes cannot contain an empty name",
			));
		}

		if !KNOWN_SCOPES.contains(&scope) {
			return Err(operation_error(format!(
				"unknown Netlify scope '{scope}'; supported scopes are {}",
				KNOWN_SCOPES.join(", ")
			)));
		}

		if !scopes.iter().any(|existing| existing == scope) {
			scopes.push(scope.to_string());
		}
	}

	Ok(scopes)
}

/// Accepts Netlify account IDs, slugs, and site IDs: 32-64 characters drawn
/// from letters, digits, hyphens, and underscores.
fn validate_netlify_slug(label: &str, value: &str) -> Result<()> {
	if value.is_empty()
		|| value.len() > 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
	{
		return Err(operation_error(format!(
			"Netlify {label} must be at most 64 ASCII letters, digits, hyphens, or underscores"
		)));
	}
	Ok(())
}

#[derive(Debug, Deserialize)]
struct EnvVarValue {
	#[serde(default)]
	context: String,
	value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnvVar {
	key: String,
	#[serde(default)]
	values: Vec<EnvVarValue>,
	#[serde(default)]
	is_secret: bool,
}

#[derive(Debug, Serialize)]
struct CreateEnvVar<'a> {
	key: &'a str,
	#[serde(skip_serializing_if = "Option::is_none")]
	scopes: Option<&'a [String]>,
	values: &'a [CreateValue<'a>],
	is_secret: bool,
}

#[derive(Debug, Serialize)]
struct CreateValue<'a> {
	context: &'a str,
	value: &'a str,
}

#[derive(Debug, Serialize)]
struct PatchValue<'a> {
	context: &'a str,
	value: &'a str,
}

#[derive(Debug, Deserialize)]
struct ApiError {
	message: String,
}

/// A Netlify account/site environment variable provider.
pub struct NetlifyProvider {
	config: NetlifyConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: NetlifyProvider,
	config: NetlifyConfig,
	metadata: &super::catalog::NETLIFY,
}

impl NetlifyProvider {
	pub fn new(config: NetlifyConfig) -> Self {
		Self {
			config,
			credentials: ProviderCredentials::new(),
			api_base: API_BASE.to_string(),
		}
	}

	fn token(&self) -> Option<SecretBytes> {
		super::credential_or_env(&self.credentials, TOKEN, TOKEN_ENV)
	}

	fn auth_headers(&self) -> Result<HeaderMap> {
		let token = self.token().ok_or_else(|| {
			operation_error(format!(
				"Netlify auth requires the `{TOKEN}` provider credential or {TOKEN_ENV}"
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
			// Secret-bearing bodies must remain confined to Netlify's fixed
			// API origin; a redirect response must never choose where a
			// PATCH or POST body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build Netlify HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	/// `/accounts/{account}/env` without its query string.
	fn base_path(&self) -> String {
		format!(
			"{}/accounts/{}/env",
			self.api_base.trim_end_matches('/'),
			self.config.account_id
		)
	}

	/// Appends `?site_id=` when a site is selected.
	fn with_site_query(&self, path: String) -> String {
		match &self.config.site_id {
			Some(site_id) => format!("{path}?site_id={site_id}"),
			None => path,
		}
	}

	fn var_path(&self, key: &str) -> String {
		self.with_site_query(format!("{}/{}", self.base_path(), key))
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if !is_valid_env_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid Netlify environment variable name: names are ASCII letters, digits, or underscores and start with a letter or underscore"
			)));
		}

		Ok(name)
	}

	/// Fetches the variable behind `key`, or `None` on 404.
	async fn get_var(&self, client: &reqwest::Client, key: &str) -> Result<Option<EnvVar>> {
		let response = client
			.get(self.var_path(key))
			.send()
			.await
			.map_err(|error| reach_error("reading the environment variable", &error))?;

		if response.status() == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error("reading the environment variable", &error))?;
		decode_response(status, &body, "reading the environment variable").map(Some)
	}

	/// Whether the variable carries an entry for the configured context,
	/// regardless of whether that value can be read back.
	fn has_context_entry(var: &EnvVar, context: &str) -> bool {
		var.values
			.iter()
			.any(|value| value.context == context || value.context == GENERIC_CONTEXT)
	}

	/// Resolves the value Netlify would use for the configured context: the
	/// context-specific value wins over a value shared with `all`, matching
	/// Netlify's own resolution order.
	fn context_value<'a>(var: &'a EnvVar, context: &str) -> Option<&'a str> {
		var.values
			.iter()
			.find(|value| value.context == context)
			.or_else(|| {
				var.values
					.iter()
					.find(|value| value.context == GENERIC_CONTEXT)
			})
			.and_then(|value| value.value.as_deref())
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let Some(var) = self.get_var(client, key).await? else {
			return Ok(None);
		};

		if var.is_secret {
			return Err(operation_error(format!(
				"Netlify variable '{key}' is marked secret, so its value is readable only inside Netlify build and runtime systems; use `secret=false` or another provider for readable values"
			)));
		}

		Ok(Self::context_value(&var, &self.config.context).map(SecretBytes::from_utf8))
	}

	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		if self.get_var(client, key).await?.is_some() {
			// PATCH updates or creates just the configured context's value,
			// leaving other contexts' values on the same variable intact.
			let response = client
				.patch(self.var_path(key))
				.json(&PatchValue {
					context: &self.config.context,
					value,
				})
				.send()
				.await
				.map_err(|error| reach_error("updating the environment variable", &error))?;
			check_status(response, "updating the environment variable").await?;
			return Ok(());
		}

		let response = client
			.post(self.with_site_query(self.base_path()))
			.json(&[CreateEnvVar {
				key,
				scopes: self.config.scopes.as_deref(),
				values: &[CreateValue {
					context: &self.config.context,
					value,
				}],
				is_secret: self.config.secret,
			}])
			.send()
			.await
			.map_err(|error| reach_error("creating the environment variable", &error))?;
		check_status(response, "creating the environment variable").await?;
		Ok(())
	}

	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		if self.get_var(client, key).await?.is_none() {
			return Ok(false);
		}

		let response = client
			.delete(self.var_path(key))
			.send()
			.await
			.map_err(|error| reach_error("deleting the environment variable", &error))?;
		check_status(response, "deleting the environment variable").await?;
		Ok(true)
	}

	async fn reflect_async(&self, client: &reqwest::Client) -> Result<Vec<EnvVar>> {
		let response = client
			.get(self.with_site_query(self.base_path()))
			.send()
			.await
			.map_err(|error| reach_error("listing environment variables", &error))?;

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error("listing environment variables", &error))?;
		decode_response(status, &body, "listing environment variables")
	}
}

impl Provider for NetlifyProvider {
	/// The account/site plus the configured context supply isolation;
	/// convention writes use the Monosecret key directly as the variable
	/// name.
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

		if let Some(site_id) = &self.config.site_id {
			query.push(format!("site_id={}", ProviderUrl::encode_query(site_id)));
		}

		if self.config.context != DEFAULT_CONTEXT {
			query.push(format!(
				"context={}",
				ProviderUrl::encode_query(&self.config.context)
			));
		}

		if let Some(scopes) = &self.config.scopes {
			query.push(format!(
				"scopes={}",
				ProviderUrl::encode_query(&scopes.join(","))
			));
		}

		if self.config.secret {
			query.push("secret=true".to_string());
		}

		let base = format!("netlify://{}", self.config.account_id);

		if query.is_empty() {
			base
		} else {
			format!("{base}?{}", query.join("&"))
		}
	}

	fn storage_identity(&self) -> String {
		let site = self.config.site_id.as_deref().unwrap_or("account");
		format!(
			"netlify://{}/{site}/{}",
			self.config.account_id, self.config.context
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
		let value = super::require_utf8("netlify", value)?;
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
		let scope = match &self.config.site_id {
			Some(site_id) => format!("site '{site_id}'"),
			None => "account".to_string(),
		};
		Ok(format!(
			"Netlify {} environment variable '{}' for context '{}'",
			scope, name, self.config.context
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let vars = super::block_on(self.reflect_async(&client))?;

		Ok(vars
			.into_iter()
			.filter(|var| Self::has_context_entry(var, &self.config.context))
			.map(|var| {
				let key = var.key;
				let secret = Secret::required(format!("{key} Netlify environment variable"));
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
			"Netlify returned invalid JSON while {action} (HTTP {}): {}",
			status.as_u16(),
			crate::error::display_error_chain(&error)
		))
	})
}

fn api_error(status: reqwest::StatusCode, body: &[u8], action: &str) -> MonosecretError {
	let detail = serde_json::from_slice::<ApiError>(body).map_or_else(
		|_| String::from_utf8_lossy(body).trim().to_string(),
		|error| error.message,
	);
	let detail = detail.chars().take(512).collect::<String>();

	if detail.is_empty() {
		operation_error(format!(
			"Netlify returned HTTP {} while {action}",
			status.as_u16()
		))
	} else {
		operation_error(format!(
			"Netlify returned HTTP {} while {action}: {detail}",
			status.as_u16()
		))
	}
}

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach Netlify while {action}: {}",
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

	const ACCOUNT: &str = "61c7ea67-1f2c-4a3b-9c8d-0e1f2a3b4c5d";
	const SITE: &str = "b7a6f5e4-d3c2-b1a0-9876-543210fedcba";

	#[derive(Debug)]
	struct RecordedRequest {
		line: String,
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> NetlifyConfig {
		NetlifyConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> NetlifyProvider {
		let mut provider = NetlifyProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}/api/v1");
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

	#[test]
	fn parses_and_round_trips_configuration() {
		let encoded = format!(
			"netlify://{ACCOUNT}?site_id={SITE}&context=deploy-preview&scopes=builds%2Cfunctions&secret=true"
		);
		let canonical = format!(
			"netlify://{ACCOUNT}?site_id={SITE}&context=deploy-preview&scopes=builds,functions&secret=true"
		);
		let provider = NetlifyProvider::new(config(&encoded));
		assert_eq!(provider.uri(), canonical);
		assert_eq!(config(&provider.uri()), provider.config);
		assert_eq!(
			provider.config.scopes,
			Some(vec!["builds".to_string(), "functions".to_string()])
		);
		assert!(provider.config.secret);

		let defaults = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
		assert_eq!(defaults.uri(), format!("netlify://{ACCOUNT}"));
		assert_eq!(defaults.config.context, "production");
		assert_eq!(defaults.config.scopes, None);
		assert!(!defaults.config.secret);
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"netlify://",
			"netlify:///path",
			&format!("netlify://{ACCOUNT}/path"),
			&format!("netlify://{ACCOUNT}?unknown=true"),
			&format!("netlify://{ACCOUNT}?context=staging"),
			&format!("netlify://{ACCOUNT}?scopes=builds,unknown"),
			&format!("netlify://{ACCOUNT}?scopes=builds,,functions"),
			&format!("netlify://{ACCOUNT}?secret=yes"),
			&format!("netlify://{ACCOUNT}?site_id=has space"),
			&format!("netlify://{ACCOUNT}?context=production&context=dev"),
		] {
			assert!(
				NetlifyConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "netlify")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variable() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("the `token` provider credential or NETLIFY_AUTH_TOKEN"),
			"{error}"
		);
	}

	#[test]
	fn environment_token_is_used_when_no_credential_is_configured() {
		let _lock = crate::tests::scrub_resolution_env();
		let _env = crate::tests::EnvVarGuard::set(TOKEN_ENV, "env-token");
		let not_found = r#"{"code":"env_vars_not_found","message":"Env var not found"}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let mut provider = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
		provider.api_base = format!("http://{endpoint}/api/v1");

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
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
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
		let provider = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
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
	fn reads_the_context_value_and_falls_back_to_all() {
		let body = Box::leak(
			r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"all","value":"shared"},{"id":"2","context":"production","value":"prod"}]}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(
			endpoint,
			&format!("netlify://{ACCOUNT}?site_id={SITE}&context=production"),
		);

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"prod");

		let requests = server.join().unwrap();
		assert!(
			requests[0].line.contains(&format!(
				"/api/v1/accounts/{ACCOUNT}/env/API_KEY?site_id={SITE}"
			)),
			"{}",
			requests[0].line
		);
		assert!(
			requests[0].line.contains(&format!("site_id={SITE}")),
			"{}",
			requests[0].line
		);
	}

	#[test]
	fn reads_the_shared_value_when_no_context_value_exists() {
		let body = r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"all","value":"shared"}]}"#;
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		let value = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap()
			.unwrap();
		assert_eq!(value.expose_secret(), b"shared");
		server.join().unwrap();
	}

	#[test]
	fn missing_variable_or_context_resolves_to_none() {
		for body in [
			r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"dev","value":"elsewhere"}]}"#,
			r#"{"key":"API_KEY","is_secret":false,"values":[]}"#,
			r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"all"}]}"#,
		] {
			let (endpoint, server) = response_server(vec![("200 OK", body)]);
			let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));
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
	fn secret_marked_values_explain_their_unavailability() {
		let body = r#"{"key":"API_KEY","is_secret":true,"values":[{"id":"1","context":"production","value":null}]}"#;
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("readable only inside Netlify"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn creates_a_missing_variable_with_context_scopes_and_secret_flag() {
		let not_found = r#"{"code":"env_vars_not_found","message":"Env var not found"}"#;
		let created = r#"[{"key":"API_KEY","is_secret":true,"values":[{"id":"1","context":"production","value":"new"}]}]"#;
		let (endpoint, server) =
			response_server(vec![("404 Not Found", not_found), ("201 Created", created)]);
		let provider = provider_with_token(
			endpoint,
			&format!("netlify://{ACCOUNT}?context=production&scopes=builds,functions&secret=true"),
		);

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 2);
		assert!(requests[1].line.starts_with("POST /api/v1/accounts/"));
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body[0]["key"], "API_KEY");
		assert_eq!(body[0]["is_secret"], true);
		assert_eq!(
			body[0]["scopes"],
			serde_json::json!(["builds", "functions"])
		);
		assert_eq!(body[0]["values"][0]["context"], "production");
		assert_eq!(body[0]["values"][0]["value"], "new-value");
	}

	#[test]
	fn creates_without_optional_scopes_when_none_are_configured() {
		let not_found = r#"{"code":"env_vars_not_found","message":"Env var not found"}"#;
		let created = r#"[{"key":"API_KEY","is_secret":false,"values":[]}]"#;
		let (endpoint, server) =
			response_server(vec![("404 Not Found", not_found), ("201 Created", created)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("v"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert!(body[0].get("scopes").is_none(), "{body}");
	}

	#[test]
	fn patches_only_the_configured_context_of_an_existing_variable() {
		let existing = r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"dev","value":"dev"}]}"#;
		let patched = r#"{"id":"2","context":"production","value":"prod"}"#;
		let (endpoint, server) =
			response_server(vec![("200 OK", existing), ("201 Created", patched)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("prod-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		assert!(requests[1].line.contains("PATCH "));
		assert!(requests[1].line.contains("/env/API_KEY"));
		let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(body["context"], "production");
		assert_eq!(body["value"], "prod-value");
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider = NetlifyProvider::new(config(&format!("netlify://{ACCOUNT}")));
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
	fn api_errors_surface_the_message_and_status() {
		let not_found = r#"{"code":"env_vars_not_found","message":"Env var not found"}"#;
		let forbidden = r#"{"code":"unauthorized","message":"token is not valid"}"#;
		let (endpoint, server) = response_server(vec![
			("404 Not Found", not_found),
			("403 Forbidden", forbidden),
		]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		// set: creation fails with 403 after the 404 lookup.
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
		assert!(error.to_string().contains("token is not valid"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn invalid_json_responses_are_reported_with_the_status() {
		let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("invalid JSON while reading"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn error_bodies_without_a_message_show_the_raw_body() {
		let (endpoint, server) = response_server(vec![("500 Internal Server Error", "boom")]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("HTTP 500"), "{error}");
		assert!(error.to_string().contains("boom"), "{error}");
		server.join().unwrap();
	}

	#[test]
	fn deletes_an_existing_variable_and_missing_deletion_is_idempotent() {
		let existing = r#"{"key":"API_KEY","is_secret":false,"values":[{"id":"1","context":"production","value":"v"}]}"#;
		let deleted = "";
		let (endpoint, server) =
			response_server(vec![("200 OK", existing), ("204 No Content", deleted)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));
		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);
		let requests = server.join().unwrap();
		assert!(requests[1].line.contains("DELETE "));
		assert!(requests[1].line.contains("/env/API_KEY"));

		let not_found = r#"{"code":"env_vars_not_found","message":"Env var not found"}"#;
		let (endpoint, server) = response_server(vec![("404 Not Found", not_found)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn reflection_lists_variables_with_a_value_for_the_context() {
		let body = r#"[
			{"key":"FIRST","is_secret":false,"values":[{"id":"1","context":"production","value":"a"}]},
			{"key":"SHARED","is_secret":false,"values":[{"id":"2","context":"all","value":"b"}]},
			{"key":"DEV_ONLY","is_secret":false,"values":[{"id":"3","context":"dev","value":"c"}]},
			{"key":"SECRET_MARKED","is_secret":true,"values":[{"id":"4","context":"production","value":null}]}
		]"#;
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(endpoint, &format!("netlify://{ACCOUNT}"));

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert!(reflected.contains_key("FIRST"));
		assert!(reflected.contains_key("SHARED"));
		// A dev-only variable would not resolve for this context, so discovery
		// must not declare it; secret-marked variables remain addressable for
		// set and delete even though their values never read back.
		assert!(!reflected.contains_key("DEV_ONLY"));
		assert!(reflected.contains_key("SECRET_MARKED"));
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_separates_sites_and_contexts() {
		let provider = NetlifyProvider::new(config(&format!(
			"netlify://{ACCOUNT}?site_id={SITE}&context=dev"
		)));
		assert_eq!(
			provider.storage_identity(),
			format!("netlify://{ACCOUNT}/{SITE}/dev")
		);
	}

	#[test]
	fn describe_write_target_names_the_scope_and_context() {
		let provider = provider_with_token(
			"127.0.0.1:1".parse().unwrap(),
			&format!("netlify://{ACCOUNT}?site_id={SITE}&context=dev"),
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!("Netlify site '{SITE}' environment variable 'KEY' for context 'dev'")
		);
	}
}
