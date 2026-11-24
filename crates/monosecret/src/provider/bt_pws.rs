//! `BeyondTrust` Password Safe provider (read-only).
//!
//! Retrieves managed account passwords through the `BeyondTrust` Password Safe
//! Public API (`POST /Auth/SignAppin`, `GET /ManagedAccounts`,
//! `POST /Requests`, `GET /Credentials/{requestId}/`, `POST /Auth/Signout`).
//!
//! # Authentication
//!
//! Credentials come from provider alias `[providers.<alias>.credentials]` or
//! environment variables (never from URI query parameters or userinfo):
//!
//! 1. **OAuth client credentials** (`client_id` + `client_secret`, or
//!    `BTPWS_CLIENT_ID` + `BTPWS_CLIENT_SECRET`): exchanges credentials at
//!    `POST {base_url}/auth/connect/token` and signs in with a `Bearer` token.
//! 2. **PS-Auth API key + run-as user** (`auth_key` + `runas`, optionally
//!    `personal_access_token`, or `BTPWS_AUTH_KEY` + `BTPWS_RUNAS` +
//!    `BTPWS_PERSONAL_ACCESS_TOKEN`): sends a `PS-Auth` header and handles
//!    interactive 401 MFA challenges when attached to a terminal.
//!
//! # URI Format
//!
//! `bt-pws://HOST[:PORT][?base_url=URL&system_name=NAME&api_version=VERSION]`
//!
//! Remote endpoints must use HTTPS; plain HTTP is permitted only for loopback
//! addresses (`localhost`, `127.0.0.1`, `::1`). Redirects are disabled so
//! authorization headers and session cookies cannot be forwarded to another
//! host.

use std::collections::BTreeMap;
use std::fmt;
use std::io::IsTerminal;
use std::sync::Mutex;
use std::sync::OnceLock;

use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;
use reqwest::header::COOKIE;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::header::SET_COOKIE;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use super::Address;
use super::ProviderBase as _;
use super::ProviderCredentials;
use super::ProviderUrl;
use super::credential_or_env;
use crate::MonosecretError;
use crate::Result;
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::prompt::CheckedPrompt as _;

const AUTH_KEY: &str = "auth_key";
const RUNAS: &str = "runas";
const PERSONAL_ACCESS_TOKEN: &str = "personal_access_token";
const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";

const AUTH_KEY_ENV: &str = "BTPWS_AUTH_KEY";
const RUNAS_ENV: &str = "BTPWS_RUNAS";
const PERSONAL_ACCESS_TOKEN_ENV: &str = "BTPWS_PERSONAL_ACCESS_TOKEN";
const CLIENT_ID_ENV: &str = "BTPWS_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "BTPWS_CLIENT_SECRET";

const REJECTED_CREDENTIAL_QUERY_KEYS: [&str; 5] = [
	AUTH_KEY,
	RUNAS,
	PERSONAL_ACCESS_TOKEN,
	CLIENT_ID,
	CLIENT_SECRET,
];

/// Configuration for the `BeyondTrust` Password Safe provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BtPwsConfig {
	/// Password Safe host (with optional `:port`) used to derive the default
	/// `https://{host}/BeyondTrust/api/public/v3` base URL.
	pub host: Option<String>,
	/// Optional explicit base URL for the Password Safe REST API.
	pub base_url: Option<String>,
	/// Optional default managed system name used when a secret ref omits `field`.
	pub default_system_name: Option<String>,
	/// Reserved for forward-compatible endpoint configuration.
	pub api_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ManagedAccount {
	system_id: Option<i64>,
	account_id: Option<i64>,
}

#[derive(Deserialize)]
struct OAuthToken {
	access_token: String,
}

impl fmt::Debug for OAuthToken {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("OAuthToken")
			.field("access_token", &"[REDACTED]")
			.finish()
	}
}

enum AuthMethod {
	PsAuth {
		auth_key: SecretBytes,
		runas: SecretBytes,
		personal_access_token: Option<SecretBytes>,
	},
	OAuth {
		client_id: SecretBytes,
		client_secret: SecretBytes,
	},
}

struct Session {
	authorization: HeaderValue,
	cookies: BTreeMap<String, String>,
}

impl Session {
	fn apply_headers(&self, mut headers: HeaderMap) -> Result<HeaderMap> {
		headers.insert(AUTHORIZATION, self.authorization.clone());
		if !self.cookies.is_empty() {
			let cookie_header = self
				.cookies
				.iter()
				.map(|(name, value)| format!("{name}={value}"))
				.collect::<Vec<_>>()
				.join("; ");
			let mut value = HeaderValue::from_str(&cookie_header).map_err(|err| {
				operation_error(format!("invalid BeyondTrust session cookie header: {err}"))
			})?;
			value.set_sensitive(true);
			headers.insert(COOKIE, value);
		}
		Ok(headers)
	}
}

fn validate_endpoint_url(raw: &str) -> Result<String> {
	let parsed = url::Url::parse(raw)
		.map_err(|err| operation_error(format!("invalid BeyondTrust base_url '{raw}': {err}")))?;
	if !parsed.username().is_empty() || parsed.password().is_some() {
		return Err(operation_error(
			"BeyondTrust base_url must not contain embedded credentials; configure provider \
			 credentials or BTPWS_* environment variables instead",
		));
	}
	let Some(host) = parsed.host_str() else {
		return Err(operation_error(format!(
			"invalid BeyondTrust base_url '{raw}': missing host"
		)));
	};
	match parsed.scheme() {
		"https" => {}
		"http" if is_loopback_host(host) => {}
		"http" => {
			return Err(operation_error(format!(
				"refusing insecure BeyondTrust base_url '{raw}': HTTPS is required for non-loopback hosts"
			)));
		}
		scheme => {
			return Err(operation_error(format!(
				"invalid BeyondTrust base_url scheme '{scheme}': expected 'https'"
			)));
		}
	}
	Ok(raw.trim_end_matches('/').to_string())
}

fn is_loopback_host(host: &str) -> bool {
	let trimmed = host.trim_start_matches('[').trim_end_matches(']');
	trimmed.eq_ignore_ascii_case("localhost")
		|| trimmed
			.parse::<std::net::IpAddr>()
			.is_ok_and(|ip| ip.is_loopback())
}

impl TryFrom<&ProviderUrl> for BtPwsConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> Result<Self> {
		if url.scheme() != "bt-pws" {
			return Err(operation_error(format!(
				"Invalid scheme '{}' for BeyondTrust Password Safe provider",
				url.scheme()
			)));
		}

		super::reject_uri_credential(url)?;

		if !url.path().is_empty() && url.path() != "/" {
			return Err(operation_error(format!(
				"BeyondTrust Password Safe secrets are addressed with a secret ref, not via the \
				 provider URI path: {}",
				url.path()
			)));
		}

		for (key, _) in url.query_pairs() {
			if REJECTED_CREDENTIAL_QUERY_KEYS.contains(&key.as_ref()) {
				return Err(operation_error(format!(
					"BeyondTrust credential '{key}' cannot be passed in the provider URI; \
					 configure it under [providers.<alias>.credentials] or via BTPWS_* \
					 environment variables"
				)));
			}
			if !matches!(key.as_ref(), "base_url" | "system_name" | "api_version") {
				return Err(operation_error(format!(
					"Unknown BeyondTrust Password Safe query parameter '{key}'. Supported \
					 parameters are: base_url, system_name, api_version."
				)));
			}
		}

		let host = url.host().filter(|h| !h.is_empty()).map(|host| {
			match url.port() {
				Some(port) => format!("{host}:{port}"),
				None => host,
			}
		});
		let base_url = url
			.query_value("base_url")
			.filter(|v| !v.is_empty())
			.map(|raw| validate_endpoint_url(&raw))
			.transpose()?;

		if host.is_none() && base_url.is_none() {
			return Err(operation_error(
				"No BeyondTrust Password Safe host or base_url given. Use \
				 bt-pws://passwordsafe.example.com or pass ?base_url=https://...",
			));
		}

		Ok(Self {
			host,
			base_url,
			default_system_name: url.query_value("system_name").filter(|v| !v.is_empty()),
			api_version: url.query_value("api_version").filter(|v| !v.is_empty()),
		})
	}
}

/// Read-only provider for `BeyondTrust` Password Safe managed accounts.
pub struct BtPwsProvider {
	config: BtPwsConfig,
	credentials: ProviderCredentials,
	http: OnceLock<reqwest::Client>,
	reason: Mutex<Option<String>>,
	retry_policy: super::RetryPolicy,
}

impl fmt::Debug for BtPwsProvider {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BtPwsProvider")
			.field("config", &self.config)
			.field("credentials", &"[REDACTED]")
			.finish_non_exhaustive()
	}
}

crate::register_provider! {
	struct: BtPwsProvider,
	config: BtPwsConfig,
	metadata: &super::catalog::BT_PWS,
	native_async: true,
}

impl BtPwsProvider {
	#[must_use]
	pub fn new(config: BtPwsConfig) -> Self {
		Self {
			config,
			credentials: ProviderCredentials::new(),
			http: OnceLock::new(),
			reason: Mutex::new(None),
			retry_policy: super::RetryPolicy::default(),
		}
	}

	fn http(&self) -> Result<&reqwest::Client> {
		if let Some(client) = self.http.get() {
			return Ok(client);
		}
		let client = super::http::client_builder().build().map_err(|err| {
			operation_error(format!(
				"failed to build BeyondTrust HTTP client: {}",
				crate::error::display_error_chain(&err)
			))
		})?;
		Ok(self.http.get_or_init(|| client))
	}

	fn base_url(&self) -> Result<String> {
		if let Some(base_url) = self.config.base_url.as_deref() {
			return validate_endpoint_url(base_url);
		}
		if let Some(host) = self.config.host.as_deref() {
			return validate_endpoint_url(&format!("https://{host}/BeyondTrust/api/public/v3"));
		}
		Err(operation_error(
			"BeyondTrust Password Safe host or base_url is not configured",
		))
	}

	fn access_reason(&self) -> String {
		self.reason
			.lock()
			.ok()
			.and_then(|guard| guard.clone())
			.filter(|reason| !reason.trim().is_empty())
			.unwrap_or_else(|| "Monosecret".to_string())
	}

	fn auth_method(&self) -> Result<AuthMethod> {
		let client_id = credential_or_env(&self.credentials, CLIENT_ID, CLIENT_ID_ENV);
		let client_secret = credential_or_env(&self.credentials, CLIENT_SECRET, CLIENT_SECRET_ENV);

		match (client_id, client_secret) {
			(Some(client_id), Some(client_secret)) => {
				return Ok(AuthMethod::OAuth {
					client_id,
					client_secret,
				});
			}
			(Some(_), None) | (None, Some(_)) => {
				return Err(operation_error(
					"BeyondTrust OAuth authentication requires both client_id and client_secret \
					 (or both BTPWS_CLIENT_ID and BTPWS_CLIENT_SECRET)",
				));
			}
			(None, None) => {}
		}

		let auth_key =
			credential_or_env(&self.credentials, AUTH_KEY, AUTH_KEY_ENV).ok_or_else(|| {
				operation_error(
					"BeyondTrust Password Safe auth key missing; configure auth_key or set \
					 BTPWS_AUTH_KEY (or configure OAuth client_id and client_secret)",
				)
			})?;
		let runas = credential_or_env(&self.credentials, RUNAS, RUNAS_ENV).ok_or_else(|| {
			operation_error(
				"BeyondTrust Password Safe runas user missing; configure runas or set BTPWS_RUNAS",
			)
		})?;
		let personal_access_token = credential_or_env(
			&self.credentials,
			PERSONAL_ACCESS_TOKEN,
			PERSONAL_ACCESS_TOKEN_ENV,
		);

		Ok(AuthMethod::PsAuth {
			auth_key,
			runas,
			personal_access_token,
		})
	}

	fn ps_auth_header(
		auth_key: &str,
		runas: &str,
		personal_access_token: Option<&str>,
		challenge: Option<&str>,
	) -> Result<HeaderValue> {
		for (field, val) in [(AUTH_KEY, auth_key), (RUNAS, runas)] {
			if val.contains([';', '\r', '\n']) {
				return Err(operation_error(format!(
					"BeyondTrust {field} contains invalid header delimiter characters"
				)));
			}
		}
		let mut raw = format!("PS-Auth key={auth_key}; runas={runas};");
		if let Some(pat) = personal_access_token.filter(|v| !v.is_empty()) {
			if pat.contains([']', '\r', '\n']) {
				return Err(operation_error(
					"BeyondTrust personal_access_token contains invalid header characters",
				));
			}
			let _ = fmt::Write::write_fmt(&mut raw, format_args!(" pwd=[{pat}];"));
		}
		if let Some(challenge) = challenge.filter(|v| !v.is_empty()) {
			if challenge.contains([';', '\r', '\n']) {
				return Err(operation_error(
					"BeyondTrust MFA challenge contains invalid header characters",
				));
			}
			let _ = fmt::Write::write_fmt(&mut raw, format_args!(" challenge={challenge};"));
		}
		let mut value = HeaderValue::from_str(&raw)
			.map_err(|err| operation_error(format!("invalid BeyondTrust auth header: {err}")))?;
		value.set_sensitive(true);
		Ok(value)
	}

	fn merge_set_cookies(headers: &HeaderMap, cookies: &mut BTreeMap<String, String>) {
		for raw in headers.get_all(SET_COOKIE) {
			let Ok(text) = raw.to_str() else {
				continue;
			};
			let pair = text.split(';').next().unwrap_or_default().trim();
			if let Some((name, value)) = pair.split_once('=') {
				let name = name.trim();
				if !name.is_empty() {
					cookies.insert(name.to_string(), value.trim().to_string());
				}
			}
		}
	}

	async fn oauth_authorization(
		&self,
		base_url: &str,
		client_id: &SecretBytes,
		client_secret: &SecretBytes,
	) -> Result<HeaderValue> {
		let client = self.http()?;
		let body = url::form_urlencoded::Serializer::new(String::new())
			.append_pair("grant_type", "client_credentials")
			.append_pair("client_id", client_id.try_as_utf8()?)
			.append_pair("client_secret", client_secret.try_as_utf8()?)
			.finish();
		let response = client
			.post(format!("{base_url}/auth/connect/token"))
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(body)
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		let status = response.status();
		if !status.is_success() {
			let body = response.text().await.unwrap_or_default();
			return Err(operation_error(format!(
				"BeyondTrust OAuth token request failed with HTTP {status}: {body}"
			)));
		}

		let token: OAuthToken = response.json().await.map_err(|err| {
			operation_error(format!(
				"failed to parse BeyondTrust OAuth token response: {}",
				crate::error::display_error_chain(&err)
			))
		})?;
		super::credentials::credential_bearer_header(token.access_token.as_bytes())
	}

	async fn prompt_mfa_challenge(instruction: String) -> Result<SecretBytes> {
		if !std::io::stdin().is_terminal() {
			return Err(operation_error(
				"BeyondTrust MFA is required, but standard input is not a terminal",
			));
		}
		tokio::task::spawn_blocking(move || {
			let prompt = format!("BeyondTrust MFA required ({instruction})");
			let answer = inquire::Password::new(&prompt)
				.without_confirmation()
				.prompt_checked()
				.map_err(|err| {
					operation_error(format!(
						"failed to read BeyondTrust MFA challenge response: {err}"
					))
				})?;
			Ok(SecretBytes::from_utf8(answer))
		})
		.await
		.map_err(|err| operation_error(format!("BeyondTrust MFA prompt task failed: {err}")))?
	}

	async fn sign_in(&self, base_url: &str) -> Result<Session> {
		let client = self.http()?;
		let auth_method = self.auth_method()?;
		let authorization = match &auth_method {
			AuthMethod::PsAuth {
				auth_key,
				runas,
				personal_access_token,
			} => {
				Self::ps_auth_header(
					auth_key.try_as_utf8()?,
					runas.try_as_utf8()?,
					personal_access_token
						.as_ref()
						.map(SecretBytes::try_as_utf8)
						.transpose()?,
					None,
				)?
			}
			AuthMethod::OAuth {
				client_id,
				client_secret,
			} => {
				self.oauth_authorization(base_url, client_id, client_secret)
					.await?
			}
		};

		let mut cookies = BTreeMap::new();
		let first = client
			.post(format!("{base_url}/Auth/SignAppin"))
			.header(AUTHORIZATION, authorization.clone())
			.json(&json!({}))
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		Self::merge_set_cookies(first.headers(), &mut cookies);

		if first.status().is_success() {
			return Ok(Session {
				authorization,
				cookies,
			});
		}

		let status = first.status();
		if status == StatusCode::UNAUTHORIZED {
			let challenge_instruction = first
				.headers()
				.get("WWW-Authenticate-2FA")
				.and_then(|value| value.to_str().ok())
				.unwrap_or("enter the one-time password")
				.to_string();

			if let AuthMethod::PsAuth {
				auth_key,
				runas,
				personal_access_token,
			} = auth_method
			{
				let challenge = Self::prompt_mfa_challenge(challenge_instruction).await?;
				let mfa_auth = Self::ps_auth_header(
					auth_key.try_as_utf8()?,
					runas.try_as_utf8()?,
					personal_access_token
						.as_ref()
						.map(SecretBytes::try_as_utf8)
						.transpose()?,
					Some(challenge.try_as_utf8()?),
				)?;
				let pending = Session {
					authorization: mfa_auth.clone(),
					cookies: cookies.clone(),
				};
				let headers = pending.apply_headers(HeaderMap::new())?;
				let second = client
					.post(format!("{base_url}/Auth/SignAppin"))
					.headers(headers)
					.json(&json!({}))
					.send()
					.await
					.map_err(|err| {
						super::http::transport_error("BeyondTrust Password Safe", err)
					})?;
				Self::merge_set_cookies(second.headers(), &mut cookies);
				if second.status().is_success() {
					return Ok(Session {
						authorization: mfa_auth,
						cookies,
					});
				}
				let second_status = second.status();
				let body = second.text().await.unwrap_or_default();
				return Err(operation_error(format!(
					"BeyondTrust MFA sign-in failed with HTTP {second_status}: {body}"
				)));
			}
		}

		let body = first.text().await.unwrap_or_default();
		Err(operation_error(format!(
			"BeyondTrust sign-in failed with HTTP {status}: {body}"
		)))
	}

	async fn sign_out(&self, base_url: &str, session: &Session) -> Result<()> {
		let client = self.http()?;
		let headers = session.apply_headers(HeaderMap::new())?;
		let response = client
			.post(format!("{base_url}/Auth/Signout"))
			.headers(headers)
			.json(&json!({}))
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(operation_error(format!(
				"BeyondTrust sign-out failed with HTTP {status}: {body}"
			)));
		}
		Ok(())
	}

	async fn request_password(
		&self,
		base_url: &str,
		session: &Session,
		account_name: &str,
		system_name: &str,
	) -> Result<Option<SecretBytes>> {
		let client = self.http()?;
		let headers = session.apply_headers(HeaderMap::new())?;
		let managed_accounts = client
			.get(format!("{base_url}/ManagedAccounts"))
			.headers(headers.clone())
			.query(&[("accountName", account_name), ("systemName", system_name)])
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		if managed_accounts.status() == StatusCode::NOT_FOUND
			|| managed_accounts.status() == StatusCode::NO_CONTENT
		{
			return Ok(None);
		}
		if !managed_accounts.status().is_success() {
			let status = managed_accounts.status();
			let body = managed_accounts.text().await.unwrap_or_default();
			return Err(operation_error(format!(
				"BeyondTrust managed-account lookup failed with HTTP {status}: {body}"
			)));
		}

		let account_body = managed_accounts.text().await.map_err(|err| {
			operation_error(format!(
				"failed to read BeyondTrust managed-account response: {}",
				crate::error::display_error_chain(&err)
			))
		})?;
		let account: ManagedAccount = if account_body.trim_start().starts_with('[') {
			let accounts: Vec<ManagedAccount> =
				serde_json::from_str(&account_body).map_err(|err| {
					operation_error(format!(
						"failed to parse BeyondTrust managed-account list: {err}"
					))
				})?;
			let Some(first) = accounts.into_iter().next() else {
				return Ok(None);
			};
			first
		} else {
			serde_json::from_str(&account_body).map_err(|err| {
				operation_error(format!(
					"failed to parse BeyondTrust managed-account response: {err}"
				))
			})?
		};

		let (Some(system_id), Some(account_id)) = (account.system_id, account.account_id) else {
			return Err(operation_error(
				"BeyondTrust managed-account response missing SystemId or AccountId",
			));
		};

		let request_body = json!({
			"SystemId": system_id,
			"AccountId": account_id,
			"DurationMinutes": 5,
			"Reason": self.access_reason(),
			"AccessType": "View",
			"ConflictOption": "reuse"
		});

		let request_response = client
			.post(format!("{base_url}/Requests"))
			.headers(headers.clone())
			.json(&request_body)
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		if !request_response.status().is_success() {
			let status = request_response.status();
			let body = request_response.text().await.unwrap_or_default();
			return Err(operation_error(format!(
				"BeyondTrust request creation failed with HTTP {status}: {body}"
			)));
		}

		let raw_request_id = request_response.text().await.map_err(|err| {
			operation_error(format!(
				"failed to read BeyondTrust request id: {}",
				crate::error::display_error_chain(&err)
			))
		})?;
		let request_id = raw_request_id.trim().trim_matches('"').trim();
		if request_id.is_empty()
			|| !request_id
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
		{
			return Err(operation_error(
				"BeyondTrust returned an invalid request identifier",
			));
		}

		let credentials = client
			.get(format!("{base_url}/Credentials/{request_id}/"))
			.headers(headers)
			.send()
			.await
			.map_err(|err| super::http::transport_error("BeyondTrust Password Safe", err))?;

		if !credentials.status().is_success() {
			let status = credentials.status();
			let body = credentials.text().await.unwrap_or_default();
			return Err(operation_error(format!(
				"BeyondTrust credential retrieval failed with HTTP {status}: {body}"
			)));
		}

		let is_json = credentials
			.headers()
			.get(reqwest::header::CONTENT_TYPE)
			.and_then(|value| value.to_str().ok())
			.is_some_and(|ct| ct.to_ascii_lowercase().contains("application/json"));
		let raw_secret = credentials.text().await.map_err(|err| {
			operation_error(format!(
				"failed to read BeyondTrust credential body: {}",
				crate::error::display_error_chain(&err)
			))
		})?;
		let password = if is_json {
			serde_json::from_str::<String>(raw_secret.trim())
				.unwrap_or_else(|_| raw_secret.trim().to_string())
		} else {
			raw_secret.trim().to_string()
		};

		if password.is_empty() {
			Ok(None)
		} else {
			Ok(Some(SecretBytes::from_utf8(password)))
		}
	}
}

impl super::ProviderBase for BtPwsProvider {
	fn retry_ownership(&self) -> super::RetryOwnership {
		super::RetryOwnership::Managed
	}

	fn set_retry_policy(&mut self, policy: super::RetryPolicy) {
		self.retry_policy = policy;
	}

	fn set_reason(&self, reason: Option<String>) {
		if let Ok(mut guard) = self.reason.lock() {
			*guard = reason;
		}
	}

	fn supported_coords(&self) -> &'static [&'static str] {
		&["field"]
	}

	fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
		Ok(NativeAddress {
			item: format!("{project}/{profile}/{key}"),
			..Default::default()
		})
	}

	fn name(&self) -> &str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		let mut uri = match &self.config.host {
			Some(host) => format!("bt-pws://{host}"),
			None => "bt-pws://".to_string(),
		};
		let mut query = Vec::new();
		if let Some(base_url) = &self.config.base_url {
			query.push(format!("base_url={}", ProviderUrl::encode_query(base_url)));
		}
		if let Some(system_name) = &self.config.default_system_name {
			query.push(format!(
				"system_name={}",
				ProviderUrl::encode_query(system_name)
			));
		}
		if let Some(api_version) = &self.config.api_version {
			query.push(format!(
				"api_version={}",
				ProviderUrl::encode_query(api_version)
			));
		}
		if !query.is_empty() {
			uri.push('?');
			uri.push_str(&query.join("&"));
		}
		uri
	}

	fn with_credentials(&mut self, credentials: ProviderCredentials) {
		self.credentials = credentials;
	}
}

#[async_trait::async_trait]
impl super::AsyncProvider for BtPwsProvider {
	async fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
		let coords = self.resolve_coords(addr)?;
		let account_name = coords.item.as_str();
		let system_name = coords
			.field
			.as_deref()
			.or(self.config.default_system_name.as_deref())
			.filter(|name| !name.is_empty())
			.ok_or_else(|| {
				operation_error(
					"BeyondTrust managed system name missing; set ref.field or pass \
					 ?system_name=<NAME> in the provider URI",
				)
			})?;

		let base_url = self.base_url()?;
		let session = self.sign_in(&base_url).await?;
		let password = self
			.request_password(&base_url, &session, account_name, system_name)
			.await;
		let sign_out = self.sign_out(&base_url, &session).await;

		match (password, sign_out) {
			(Ok(password), Ok(())) => Ok(password),
			(Ok(_), Err(sign_out)) => Err(sign_out),
			(Err(password), Ok(())) => Err(password),
			(Err(password), Err(sign_out)) => {
				Err(operation_error(format!(
					"{password}; additionally, BeyondTrust sign-out failed: {sign_out}"
				)))
			}
		}
	}

	async fn set(&self, addr: Address<'_>, _value: &SecretBytes) -> Result<()> {
		super::AsyncProvider::check_writable(self, addr).await
	}

	async fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
		Err(operation_error(
			"BeyondTrust Password Safe provider is read-only",
		))
	}
}

fn operation_error(message: impl Into<String>) -> MonosecretError {
	MonosecretError::ProviderOperationFailed(message.into())
}

#[cfg(test)]
mod tests {
	use std::io::BufRead;
	use std::io::BufReader;
	use std::io::Read;
	use std::io::Write;
	use std::net::SocketAddr;
	use std::net::TcpListener;
	use std::thread;

	use url::Url;

	use super::*;
	use crate::provider::Provider;
	use crate::provider::SyncProviderAdapter;

	fn parse_config(uri: &str) -> Result<BtPwsConfig> {
		let url = ProviderUrl::new(Url::parse(uri).unwrap());
		BtPwsConfig::try_from(&url)
	}

	fn make_provider(uri: &str) -> SyncProviderAdapter<BtPwsProvider> {
		let config = parse_config(uri).unwrap();
		SyncProviderAdapter::from_async(BtPwsProvider::new(config))
	}

	struct RecordedRequest {
		request_line: String,
		headers: BTreeMap<String, String>,
		body: String,
	}

	fn serve_sequence(
		responses: Vec<(&'static str, &'static str, &'static str, &'static str)>,
	) -> (SocketAddr, thread::JoinHandle<Vec<RecordedRequest>>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = listener.local_addr().unwrap();
		let handle = thread::spawn(move || {
			let mut recorded = Vec::new();
			for (status, content_type, extra_headers, body) in responses {
				let (mut stream, _) = listener.accept().unwrap();
				let mut reader = BufReader::new(&mut stream);
				let mut request_line = String::new();
				reader.read_line(&mut request_line).unwrap();
				let mut headers = BTreeMap::new();
				let mut content_length = 0usize;
				loop {
					let mut line = String::new();
					reader.read_line(&mut line).unwrap();
					if line == "\r\n" || line.is_empty() {
						break;
					}
					if let Some((name, value)) = line.split_once(':') {
						let key = name.trim().to_ascii_lowercase();
						let val = value.trim().to_string();
						if key == "content-length" {
							content_length = val.parse().unwrap_or(0);
						}
						headers.insert(key, val);
					}
				}
				let mut body_bytes = vec![0u8; content_length];
				reader.read_exact(&mut body_bytes).unwrap();
				recorded.push(RecordedRequest {
					request_line: request_line.trim_end().to_string(),
					headers,
					body: String::from_utf8(body_bytes).unwrap(),
				});
				write!(
					stream,
					"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
					body.len()
				)
				.unwrap();
			}
			recorded
		});
		(endpoint, handle)
	}

	#[test]
	fn parses_host_system_name_and_api_version_and_round_trips_uri() {
		let uri = "bt-pws://passwordsafe.example.com?system_name=db-01&api_version=v3";
		let config = parse_config(uri).unwrap();
		assert_eq!(config.host.as_deref(), Some("passwordsafe.example.com"));
		assert_eq!(config.default_system_name.as_deref(), Some("db-01"));
		assert_eq!(config.api_version.as_deref(), Some("v3"));

		let provider = make_provider(uri);
		assert_eq!(provider.uri(), uri);
		assert_eq!(
			provider.base_url().unwrap(),
			"https://passwordsafe.example.com/BeyondTrust/api/public/v3"
		);
	}

	#[test]
	fn rejects_credentials_in_uri_query_and_userinfo() {
		for bad in [
			"bt-pws://passwordsafe.example.com?auth_key=secret",
			"bt-pws://passwordsafe.example.com?runas=admin",
			"bt-pws://passwordsafe.example.com?personal_access_token=pat",
			"bt-pws://passwordsafe.example.com?client_id=id",
			"bt-pws://passwordsafe.example.com?client_secret=sec",
			"bt-pws://user:pass@passwordsafe.example.com",
			"bt-pws://passwordsafe.example.com/extra/path",
			"bt-pws://passwordsafe.example.com?unknown=1",
			"bt-pws://",
		] {
			assert!(
				parse_config(bad).is_err(),
				"expected URI to be rejected: {bad}"
			);
		}
	}

	#[test]
	fn enforces_https_for_remote_base_url_and_allows_loopback() {
		let err = parse_config(
			"bt-pws://pws.example.com?base_url=http%3A%2F%2Fpws.example.com%2FBeyondTrust%2Fapi%2Fpublic%2Fv3",
		)
		.unwrap_err();
		assert!(err.to_string().contains("HTTPS is required"), "{err}");

		let loopback = parse_config(
			"bt-pws://127.0.0.1?base_url=http%3A%2F%2F127.0.0.1%3A8443%2FBeyondTrust%2Fapi%2Fpublic%2Fv3",
		)
		.unwrap();
		assert_eq!(
			loopback.base_url.as_deref(),
			Some("http://127.0.0.1:8443/BeyondTrust/api/public/v3")
		);
	}

	#[test]
	fn debug_redacts_credentials() {
		let mut provider = BtPwsProvider::new(parse_config("bt-pws://pws.example.com").unwrap());
		provider.with_credentials(ProviderCredentials::from([
			(
				AUTH_KEY.to_string(),
				SecretBytes::from_utf8("super-secret-key"),
			),
			(RUNAS.to_string(), SecretBytes::from_utf8("svc-account")),
		]));
		let debug = format!("{provider:?}");
		assert!(!debug.contains("super-secret-key"), "{debug}");
		assert!(debug.contains("[REDACTED]"), "{debug}");
	}

	#[test]
	fn ps_auth_header_includes_pat_and_mfa_challenge() {
		let header = BtPwsProvider::ps_auth_header(
			"api-key",
			"user@example.com",
			Some("personal-access-token"),
			Some("123456"),
		)
		.unwrap();

		assert_eq!(
			header.to_str().unwrap(),
			"PS-Auth key=api-key; runas=user@example.com; pwd=[personal-access-token]; challenge=123456;"
		);
		assert!(header.is_sensitive());
	}

	#[test]
	fn ps_auth_retrieves_password_forwards_cookies_and_signs_out() {
		let (endpoint, server) = serve_sequence(vec![
			(
				"200 OK",
				"application/json",
				"Set-Cookie: ASP.NET_SessionId=sess-123; Path=/; HttpOnly\r\n",
				r#"{"UserId":1}"#,
			),
			(
				"200 OK",
				"application/json",
				"",
				r#"{"SystemId":429,"AccountId":75}"#,
			),
			("200 OK", "application/json", "", "9001"),
			("200 OK", "application/json", "", r#""s3cr3t-pw""#),
			("200 OK", "application/json", "", "{}"),
		]);

		let base_url = format!("http://{endpoint}/BeyondTrust/api/public/v3");
		let uri = format!(
			"bt-pws://127.0.0.1?base_url={}",
			ProviderUrl::encode_query(&base_url)
		);
		let mut provider = make_provider(&uri);
		provider.with_credentials(ProviderCredentials::from([
			(AUTH_KEY.to_string(), SecretBytes::from_utf8("k1")),
			(RUNAS.to_string(), SecretBytes::from_utf8("svc@example.com")),
		]));
		provider.set_reason(Some("deploy migration".to_string()));

		let addr = NativeAddress {
			item: "db-user".to_string(),
			field: Some("db-server".to_string()),
			..Default::default()
		};
		let secret = provider
			.get(Address::Native(&addr))
			.unwrap()
			.expect("password should be returned");
		assert_eq!(secret.expose_secret(), b"s3cr3t-pw");

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 5);
		assert!(
			requests
				.first()
				.unwrap()
				.request_line
				.starts_with("POST /BeyondTrust/api/public/v3/Auth/SignAppin ")
		);
		for req in requests.iter().skip(1) {
			assert_eq!(
				req.headers.get("cookie").map(String::as_str),
				Some("ASP.NET_SessionId=sess-123"),
				"missing forwarded cookie on {}",
				req.request_line
			);
		}
		assert!(
			requests
				.get(2)
				.unwrap()
				.body
				.contains(r#""Reason":"deploy migration""#)
		);
		assert!(
			requests
				.get(4)
				.unwrap()
				.request_line
				.starts_with("POST /BeyondTrust/api/public/v3/Auth/Signout ")
		);
	}

	#[test]
	fn oauth_client_credentials_flow_signs_in_and_out() {
		let (endpoint, server) = serve_sequence(vec![
			(
				"200 OK",
				"application/json",
				"",
				r#"{"access_token":"oauth-tok-42"}"#,
			),
			(
				"200 OK",
				"application/json",
				"Set-Cookie: bt=ok; HttpOnly\r\n",
				"{}",
			),
			(
				"200 OK",
				"application/json",
				"",
				r#"[{"SystemId":10,"AccountId":20}]"#,
			),
			("200 OK", "application/json", "", "77"),
			("200 OK", "text/plain", "", "plain-pw\n"),
			("200 OK", "application/json", "", "{}"),
		]);

		let base_url = format!("http://{endpoint}/BeyondTrust/api/public/v3");
		let uri = format!(
			"bt-pws://127.0.0.1?base_url={}&system_name=default-sys",
			ProviderUrl::encode_query(&base_url)
		);
		let mut provider = make_provider(&uri);
		provider.with_credentials(ProviderCredentials::from([
			(CLIENT_ID.to_string(), SecretBytes::from_utf8("cid")),
			(CLIENT_SECRET.to_string(), SecretBytes::from_utf8("csec")),
		]));

		let addr = NativeAddress {
			item: "db-user".to_string(),
			..Default::default()
		};
		let secret = provider.get(Address::Native(&addr)).unwrap().unwrap();
		assert_eq!(secret.expose_secret(), b"plain-pw");

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 6);
		assert!(
			requests
				.first()
				.unwrap()
				.request_line
				.starts_with("POST /BeyondTrust/api/public/v3/auth/connect/token ")
		);
		assert_eq!(
			requests
				.get(1)
				.unwrap()
				.headers
				.get("authorization")
				.map(String::as_str),
			Some("Bearer oauth-tok-42")
		);
	}

	#[test]
	fn missing_managed_account_returns_none_and_still_signs_out() {
		let (endpoint, server) = serve_sequence(vec![
			("200 OK", "application/json", "", "{}"),
			("404 Not Found", "application/json", "", "{}"),
			("200 OK", "application/json", "", "{}"),
		]);
		let base_url = format!("http://{endpoint}/BeyondTrust/api/public/v3");
		let uri = format!(
			"bt-pws://127.0.0.1?base_url={}&system_name=sys",
			ProviderUrl::encode_query(&base_url)
		);
		let mut provider = make_provider(&uri);
		provider.with_credentials(ProviderCredentials::from([
			(AUTH_KEY.to_string(), SecretBytes::from_utf8("k1")),
			(RUNAS.to_string(), SecretBytes::from_utf8("svc")),
		]));

		let found = provider
			.get(Address::convention("app", "prod", "MISSING"))
			.unwrap();
		assert!(found.is_none());

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 3);
		assert!(
			requests
				.get(2)
				.unwrap()
				.request_line
				.starts_with("POST /BeyondTrust/api/public/v3/Auth/Signout ")
		);
	}

	#[test]
	fn sign_out_failure_is_surfaced_not_ignored() {
		let (endpoint, server) = serve_sequence(vec![
			("200 OK", "application/json", "", "{}"),
			(
				"200 OK",
				"application/json",
				"",
				r#"{"SystemId":1,"AccountId":2}"#,
			),
			("200 OK", "application/json", "", "55"),
			("200 OK", "application/json", "", r#""pw""#),
			("500 Internal Server Error", "text/plain", "", "boom"),
		]);
		let base_url = format!("http://{endpoint}/BeyondTrust/api/public/v3");
		let uri = format!(
			"bt-pws://127.0.0.1?base_url={}&system_name=sys",
			ProviderUrl::encode_query(&base_url)
		);
		let mut provider = make_provider(&uri);
		provider.with_credentials(ProviderCredentials::from([
			(AUTH_KEY.to_string(), SecretBytes::from_utf8("k1")),
			(RUNAS.to_string(), SecretBytes::from_utf8("svc")),
		]));

		let err = provider
			.get(Address::convention("app", "prod", "PW"))
			.unwrap_err();
		assert!(
			err.to_string().contains("sign-out failed"),
			"expected sign-out error, got: {err}"
		);
		assert_eq!(server.join().unwrap().len(), 5);
	}

	#[test]
	fn redirects_are_refused() {
		let (endpoint, server) = serve_sequence(vec![(
			"302 Found",
			"text/plain",
			"Location: https://attacker.example.com/steal\r\n",
			"",
		)]);
		let base_url = format!("http://{endpoint}/BeyondTrust/api/public/v3");
		let uri = format!(
			"bt-pws://127.0.0.1?base_url={}&system_name=sys",
			ProviderUrl::encode_query(&base_url)
		);
		let mut provider = make_provider(&uri);
		provider.with_credentials(ProviderCredentials::from([
			(AUTH_KEY.to_string(), SecretBytes::from_utf8("k1")),
			(RUNAS.to_string(), SecretBytes::from_utf8("svc")),
		]));

		let err = provider
			.get(Address::convention("app", "prod", "PW"))
			.unwrap_err();
		assert!(err.to_string().contains("HTTP 302"), "{err}");
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn writes_are_rejected_as_read_only() {
		let provider = make_provider("bt-pws://pws.example.com");
		let addr = Address::convention("app", "prod", "PW");
		let err = provider
			.set(addr, &SecretBytes::from_utf8("val"))
			.unwrap_err();
		assert!(err.to_string().contains("read-only"), "{err}");
	}
}
