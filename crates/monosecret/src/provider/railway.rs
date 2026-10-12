//! Railway project environment variables provider.
//!
//! Railway stores environment variables per project and environment, either
//! on one service or as shared variables available to every service.
//! Monosecret maps a declaration key directly to a variable name and selects
//! the project, environment, and optional service through the provider URI,
//! so one alias per environment keeps profiles isolated. Values are read
//! back in plaintext through the GraphQL API unless a variable is sealed,
//! which only Railway builds and deployments can read.
//!
//! # URI format
//!
//! `railway://PROJECT_ID[?environment_id=ENV_ID][&environment=NAME][&service_id=SERVICE_ID][&service=NAME][&skip_deploys=true]`
//!
//! The environment is selected by ID (`environment_id`) or name
//! (`environment`, like `production`); a service is selected the same way,
//! and omitting both service parameters manages the environment's shared
//! variables. Authentication comes from a `token` provider credential,
//! `RAILWAY_API_TOKEN`, or `RAILWAY_TOKEN` (project token).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;

use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;
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
/// Environment fallbacks in precedence order: an account or workspace token
/// first, then a project token (which Railway sends without a bearer).
const TOKEN_ENVS: &[&str] = &["RAILWAY_API_TOKEN", "RAILWAY_TOKEN"];
const PROJECT_ACCESS_TOKEN_HEADER: &str = "project-access-token";
const API_BASE: &str = "https://backboard.railway.com/graphql/v2";
/// Variables reserved for Railway-provided values; the CLI rejects writes to
/// them and so does Monosecret.
const RESERVED_PREFIX: &str = "RAILWAY_";

/// How the environment is selected: by ID or by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvironmentRef {
	/// Environment ID.
	Id(String),
	/// Environment name, like `production`, resolved per operation.
	Name(String),
}

/// How the service is selected: by ID or by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceRef {
	/// Service ID.
	Id(String),
	/// Service name, resolved per operation.
	Name(String),
}

/// Configuration for one Railway environment's variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailwayConfig {
	/// Railway project ID.
	pub project_id: String,
	/// Environment selection: `environment_id` or `environment` in the URI.
	pub environment: EnvironmentRef,
	/// Service selection; `None` manages the environment's shared variables.
	pub service: Option<ServiceRef>,
	/// Whether writes skip triggering a redeploy of the affected services.
	pub skip_deploys: bool,
}

impl TryFrom<&ProviderUrl> for RailwayConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "railway" {
			return Err(operation_error(format!(
				"invalid scheme '{}' for railway provider; expected 'railway'",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(
				"railway:// does not accept credentials in URI userinfo; use the token provider credential",
			));
		}

		let project_id = url
			.host()
			.filter(|value| !value.is_empty())
			.ok_or_else(|| {
				operation_error(
					"railway provider requires a project ID, for example railway://5dfc2e4b-3a1c-4b2d-8f9a-0e1f2a3b4c5d?environment=production",
				)
			})?;
		validate_railway_id("project ID", &project_id)?;

		if !url.path().trim_matches('/').is_empty() {
			return Err(operation_error(
				"railway:// takes no path; put the project ID in the URI authority and select scope with ?environment=…",
			));
		}

		let mut environment_id = None;
		let mut environment = None;
		let mut service_id = None;
		let mut service = None;
		let mut skip_deploys = None;

		for (key, value) in url.query_pairs() {
			let value = value.into_owned();

			let duplicate = match key.as_ref() {
				"environment_id" => set_once(&mut environment_id, value),
				"environment" => set_once(&mut environment, value),
				"service_id" => set_once(&mut service_id, value),
				"service" => set_once(&mut service, value),
				"skip_deploys" => set_once(&mut skip_deploys, value),
				unknown => {
					return Err(operation_error(format!(
						"unknown railway query parameter '{unknown}'; supported parameters are `environment_id`, `environment`, `service_id`, `service`, and `skip_deploys`"
					)));
				}
			};

			if duplicate {
				return Err(operation_error(format!(
					"duplicate railway query parameter '{key}'"
				)));
			}
		}

		let environment = match (environment_id, environment) {
			(Some(id), None) if !id.is_empty() => {
				validate_railway_id("environment ID", &id)?;
				EnvironmentRef::Id(id)
			}
			(None, Some(name)) if !name.is_empty() => {
				validate_railway_name("environment", &name)?;
				EnvironmentRef::Name(name)
			}
			(Some(_), Some(_)) => {
				return Err(operation_error(
					"railway provider takes either `environment_id` or `environment`, not both",
				));
			}
			_ => {
				return Err(operation_error(
					"railway provider requires an environment: pass ?environment_id=ENV_ID or ?environment=NAME",
				));
			}
		};

		let service = match (service_id, service) {
			(None, None) => None,
			(Some(id), None) if !id.is_empty() => {
				validate_railway_id("service ID", &id)?;
				Some(ServiceRef::Id(id))
			}
			(None, Some(name)) if !name.is_empty() => {
				validate_railway_name("service", &name)?;
				Some(ServiceRef::Name(name))
			}
			(Some(_), Some(_)) => {
				return Err(operation_error(
					"railway provider takes either `service_id` or `service`, not both",
				));
			}
			_ => {
				return Err(operation_error(
					"railway `service_id` and `service` must not be empty",
				));
			}
		};

		let skip_deploys = match skip_deploys.as_deref() {
			None | Some("false") => false,
			Some("true") => true,
			Some(value) => {
				return Err(operation_error(format!(
					"railway `skip_deploys` must be `true` or `false`, not '{value}'"
				)));
			}
		};

		Ok(Self {
			project_id,
			environment,
			service,
			skip_deploys,
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

/// Accepts Railway IDs: up to 64 ASCII letters, digits, and hyphens.
fn validate_railway_id(label: &str, value: &str) -> Result<()> {
	if value.is_empty()
		|| value.len() > 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
	{
		return Err(operation_error(format!(
			"Railway {label} must be at most 64 ASCII letters, digits, or hyphens"
		)));
	}
	Ok(())
}

/// Accepts Railway environment and service names loosely; Railway documents
/// no charset rules, so Monosecret only rejects empties, length abuse, and
/// control characters.
fn validate_railway_name(label: &str, value: &str) -> Result<()> {
	if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
		return Err(operation_error(format!(
			"Railway {label} names are non-empty, at most 255 characters, and contain no control characters"
		)));
	}
	Ok(())
}

#[derive(Debug, Serialize)]
struct GraphqlRequest<'a, T> {
	query: &'a str,
	variables: T,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
	// An `Option` field deserializes as `None` when absent without requiring
	// a `Default` bound on `T`.
	data: Option<T>,
	#[serde(default)]
	errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
struct GraphqlError {
	message: String,
}

#[derive(Debug, Deserialize)]
struct ProjectNode {
	#[serde(default)]
	environments: Connection<NamedNode>,
	#[serde(default)]
	services: Connection<NamedNode>,
}

#[derive(Debug, Deserialize)]
struct Connection<T> {
	edges: Vec<Edge<T>>,
}

// Written by hand because `derive(Default)` would add a `T: Default` bound
// that `ProjectNode`'s defaulted fields do not actually need.
impl<T> Default for Connection<T> {
	fn default() -> Self {
		Self { edges: Vec::new() }
	}
}

#[derive(Debug, Deserialize)]
struct Edge<T> {
	node: T,
}

#[derive(Debug, Deserialize)]
struct NamedNode {
	id: String,
	name: String,
}

#[derive(Debug, Deserialize)]
struct ProjectWrapper {
	project: Option<ProjectNode>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct VariablesQuery<'a> {
	projectId: &'a str,
	environmentId: String,
	serviceId: Option<String>,
	unrendered: bool,
}

#[derive(Deserialize)]
struct VariablesData {
	#[serde(default)]
	variables: Option<BTreeMap<String, Option<String>>>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct ProjectVars<'a> {
	id: &'a str,
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct UpsertData {
	#[serde(default)]
	#[allow(dead_code)]
	variableUpsert: bool,
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct DeleteData {
	#[serde(default)]
	#[allow(dead_code)]
	variableDelete: bool,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct UpsertInput<'a> {
	projectId: &'a str,
	environmentId: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	serviceId: Option<String>,
	name: &'a str,
	value: &'a str,
	skipDeploys: bool,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct UpsertVars<'a> {
	input: UpsertInput<'a>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct DeleteInput<'a> {
	projectId: &'a str,
	environmentId: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	serviceId: Option<String>,
	name: &'a str,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct DeleteVars<'a> {
	input: DeleteInput<'a>,
}

/// A Railway project environment variables provider.
pub struct RailwayProvider {
	config: RailwayConfig,
	credentials: ProviderCredentials,
	api_base: String,
}

crate::register_provider! {
	struct: RailwayProvider,
	config: RailwayConfig,
	metadata: &super::catalog::RAILWAY,
}

impl RailwayProvider {
	pub fn new(config: RailwayConfig) -> Self {
		Self {
			config,
			credentials: ProviderCredentials::new(),
			api_base: API_BASE.to_string(),
		}
	}

	/// An account or workspace token authenticates with a Bearer header; a
	/// project token authenticates with the `Project-Access-Token` header
	/// and no bearer, matching Railway's own CLI.
	fn auth_headers(&self) -> Result<HeaderMap> {
		let mut headers = HeaderMap::new();

		if let Some(token) = self.credentials.get(TOKEN) {
			headers.insert(
				AUTHORIZATION,
				super::credentials::credential_bearer_header(token.expose_secret())?,
			);
			return Ok(headers);
		}

		// The first environment name carries an account or workspace token
		// (bearer); the second carries a project token, which Railway's own
		// CLI sends without a bearer.
		for (index, name) in TOKEN_ENVS.iter().enumerate() {
			let Some(value) = std::env::var_os(name) else {
				continue;
			};
			if value.is_empty() {
				continue;
			}

			let token = SecretBytes::from_vec(value.into_encoded_bytes());
			if index == 0 {
				headers.insert(
					AUTHORIZATION,
					super::credentials::credential_bearer_header(token.expose_secret())?,
				);
			} else {
				let mut header_value = Vec::with_capacity(token.expose_secret().len());
				header_value.extend_from_slice(token.expose_secret());
				let header = HeaderValue::from_bytes(&header_value).map_err(|_| {
					operation_error("provider credential cannot be represented in an HTTP header")
				})?;
				headers.insert(HeaderName::from_static(PROJECT_ACCESS_TOKEN_HEADER), header);
			}

			return Ok(headers);
		}

		Err(operation_error(format!(
			"Railway auth requires the `{TOKEN}` provider credential, RAILWAY_API_TOKEN, or RAILWAY_TOKEN"
		)))
	}

	fn client(&self) -> Result<reqwest::Client> {
		super::http::client_builder()
			.default_headers(self.auth_headers()?)
			// Secret-bearing bodies must remain confined to Railway's fixed
			// API origin; a redirect response must never choose where a
			// mutation body is replayed.
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| {
				operation_error(format!(
					"failed to build Railway HTTP client: {}",
					crate::error::display_error_chain(&error)
				))
			})
	}

	fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
		let name = super::flat_item(self, addr)?;

		if name.starts_with(RESERVED_PREFIX) {
			return Err(operation_error(format!(
				"'{name}' starts with the reserved {RESERVED_PREFIX} prefix: Railway provides those variables itself, so they cannot be written or deleted"
			)));
		}

		if !is_valid_env_key(&name) {
			return Err(operation_error(format!(
				"'{name}' is not a valid Railway variable name: names are ASCII letters, digits, or underscores and start with a letter or underscore"
			)));
		}

		Ok(name)
	}

	/// Runs one GraphQL document against Railway's backboard API.
	async fn graphql<T: serde::de::DeserializeOwned>(
		&self,
		client: &reqwest::Client,
		query: &str,
		variables: &impl Serialize,
		action: &str,
	) -> Result<T> {
		let response = client
			.post(&self.api_base)
			.json(&GraphqlRequest { query, variables })
			.send()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let status = response.status();
		let body = response
			.bytes()
			.await
			.map_err(|error| reach_error(action, &error))?;

		let envelope: Envelope<T> = serde_json::from_slice(&body).map_err(|error| {
			operation_error(format!(
				"Railway returned invalid JSON while {action} (HTTP {}): {}",
				status.as_u16(),
				crate::error::display_error_chain(&error)
			))
		})?;

		if let Some(error) = envelope.errors.first() {
			return Err(operation_error(format!(
				"Railway rejected the request while {action}: {}",
				error.message
			)));
		}

		if !status.is_success() {
			return Err(operation_error(format!(
				"Railway returned HTTP {} while {action}",
				status.as_u16()
			)));
		}

		envelope.data.ok_or_else(|| {
			operation_error(format!(
				"Railway returned no data while {action} (HTTP {})",
				status.as_u16()
			))
		})
	}

	/// Resolves the configured environment and service names to IDs once per
	/// operation; raw IDs skip the lookup.
	async fn resolve_scope(&self, client: &reqwest::Client) -> Result<(String, Option<String>)> {
		let environment_id = match &self.config.environment {
			EnvironmentRef::Id(id) => id.clone(),
			EnvironmentRef::Name(name) => {
				let project = self
					.graphql::<ProjectWrapper>(
						client,
						"query($id: String!) { project(id: $id) { environments(first: 1000) { edges { node { id name } } } } }",
						&ProjectVars {
							id: &self.config.project_id,
						},
						"resolving the environment",
					)
					.await?;
				let project = project.project.ok_or_else(|| {
					operation_error(format!(
						"Railway project '{}' was not found",
						self.config.project_id
					))
				})?;
				find_named(&project.environments, name, "environment")?
			}
		};

		let service_id = match &self.config.service {
			None => None,
			Some(ServiceRef::Id(id)) => Some(id.clone()),
			Some(ServiceRef::Name(name)) => {
				let project = self
					.graphql::<ProjectWrapper>(
						client,
						"query($id: String!) { project(id: $id) { services(first: 1000) { edges { node { id name } } } } }",
						&ProjectVars {
							id: &self.config.project_id,
						},
						"resolving the service",
					)
					.await?;
				let project = project.project.ok_or_else(|| {
					operation_error(format!(
						"Railway project '{}' was not found",
						self.config.project_id
					))
				})?;
				Some(find_named(&project.services, name, "service")?)
			}
		};

		Ok((environment_id, service_id))
	}

	/// Reads the configured scope's variables. Values come back exactly as
	/// stored because the query asks for unrendered values; a sealed variable
	/// appears as a present key with a `null` value.
	async fn list_variables(
		&self,
		client: &reqwest::Client,
		environment_id: &str,
		service_id: Option<&str>,
	) -> Result<BTreeMap<String, Option<String>>> {
		self.graphql::<VariablesData>(
			client,
			"query Variables($projectId: String!, $environmentId: String!, $serviceId: String, $unrendered: Boolean) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: $unrendered) }",
			&VariablesQuery {
				projectId: &self.config.project_id,
				environmentId: environment_id.to_string(),
				serviceId: service_id.map(str::to_string),
				unrendered: true,
			},
			"reading the variables",
		)
		.await
		.map(|data| data.variables.unwrap_or_default())
	}

	async fn get_async(&self, client: &reqwest::Client, key: &str) -> Result<Option<SecretBytes>> {
		let (environment_id, service_id) = self.resolve_scope(client).await?;
		let variables = self
			.list_variables(client, &environment_id, service_id.as_deref())
			.await?;

		match variables.get(key) {
			None => Ok(None),
			Some(None) => {
				Err(operation_error(format!(
					"Railway variable '{key}' is sealed, so its value is readable only inside Railway builds and deployments; unseal it in the Railway dashboard or use another provider for readable values"
				)))
			}
			Some(Some(value)) => Ok(Some(SecretBytes::from_utf8(value))),
		}
	}

	async fn set_async(&self, client: &reqwest::Client, key: &str, value: &str) -> Result<()> {
		let (environment_id, service_id) = self.resolve_scope(client).await?;

		self.graphql::<UpsertData>(
			client,
			"mutation Upsert($input: VariableUpsertInput!) { variableUpsert(input: $input) }",
			&UpsertVars {
				input: UpsertInput {
					projectId: &self.config.project_id,
					environmentId: environment_id,
					serviceId: service_id,
					name: key,
					value,
					skipDeploys: self.config.skip_deploys,
				},
			},
			"writing the variable",
		)
		.await?;

		Ok(())
	}

	async fn delete_async(&self, client: &reqwest::Client, key: &str) -> Result<bool> {
		let (environment_id, service_id) = self.resolve_scope(client).await?;
		let variables = self
			.list_variables(client, &environment_id, service_id.as_deref())
			.await?;

		if !variables.contains_key(key) {
			return Ok(false);
		}

		self.graphql::<DeleteData>(
			client,
			"mutation Delete($input: VariableDeleteInput!) { variableDelete(input: $input) }",
			&DeleteVars {
				input: DeleteInput {
					projectId: &self.config.project_id,
					environmentId: environment_id,
					serviceId: service_id,
					name: key,
				},
			},
			"deleting the variable",
		)
		.await?;

		Ok(true)
	}
}

/// Finds a named environment or service among a connection's edges.
fn find_named(connection: &Connection<NamedNode>, name: &str, label: &str) -> Result<String> {
	connection
		.edges
		.iter()
		.find(|edge| edge.node.name == name)
		.map(|edge| edge.node.id.clone())
		.ok_or_else(|| {
			operation_error(format!(
				"Railway {label} '{name}' was not found in the project"
			))
		})
}

impl Provider for RailwayProvider {
	/// The project, environment, and service supply isolation; convention
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

		match &self.config.environment {
			EnvironmentRef::Id(id) => {
				query.push(format!("environment_id={}", ProviderUrl::encode_query(id)));
			}
			EnvironmentRef::Name(name) => {
				query.push(format!("environment={}", ProviderUrl::encode_query(name)));
			}
		}

		match &self.config.service {
			None => {}
			Some(ServiceRef::Id(id)) => {
				query.push(format!("service_id={}", ProviderUrl::encode_query(id)));
			}
			Some(ServiceRef::Name(name)) => {
				query.push(format!("service={}", ProviderUrl::encode_query(name)));
			}
		}

		if self.config.skip_deploys {
			query.push("skip_deploys=true".to_string());
		}

		format!("railway://{}?{}", self.config.project_id, query.join("&"))
	}

	fn storage_identity(&self) -> String {
		let environment = match &self.config.environment {
			EnvironmentRef::Id(id) => id.clone(),
			EnvironmentRef::Name(name) => name.clone(),
		};
		let service = match &self.config.service {
			None => "shared".to_string(),
			Some(ServiceRef::Id(id)) => id.clone(),
			Some(ServiceRef::Name(name)) => name.clone(),
		};
		format!(
			"railway://{}/{environment}/{service}",
			self.config.project_id
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
		let value = super::require_utf8("railway", value)?;
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
		let environment = match &self.config.environment {
			EnvironmentRef::Id(id) => format!("environment '{id}'"),
			EnvironmentRef::Name(env) => format!("environment '{env}'"),
		};
		let service = match &self.config.service {
			None => "shared variables".to_string(),
			Some(ServiceRef::Id(id)) => format!("service '{id}'"),
			Some(ServiceRef::Name(svc)) => format!("service '{svc}'"),
		};
		Ok(format!(
			"Railway project '{}' {}, {} variable '{}'",
			self.config.project_id, environment, service, name
		))
	}

	fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
		let client = self.client()?;
		let (environment_id, service_id) = super::block_on(self.resolve_scope(&client))?;
		let variables =
			super::block_on(self.list_variables(&client, &environment_id, service_id.as_deref()))?;

		Ok(variables
			.into_keys()
			.filter(|key| !key.starts_with(RESERVED_PREFIX))
			.map(|key| {
				let secret = Secret::required(format!("{key} Railway variable"));
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

fn reach_error(action: &str, error: &reqwest::Error) -> MonosecretError {
	operation_error(format!(
		"failed to reach Railway while {action}: {}",
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

	const PROJECT: &str = "5dfc2e4b-3a1c-4b2d-8f9a-0e1f2a3b4c5d";
	const ENV_ID: &str = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5e";
	const SERVICE_ID: &str = "f6e5d4c3-b2a1-4958-8776-554433221100";

	#[derive(Debug)]
	struct RecordedRequest {
		headers: HashMap<String, String>,
		body: String,
	}

	fn config(spec: &str) -> RailwayConfig {
		RailwayConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
	}

	fn provider_with_token(endpoint: SocketAddr, spec: &str) -> RailwayProvider {
		let mut provider = RailwayProvider::new(config(spec));
		provider.api_base = format!("http://{endpoint}/graphql/v2");
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
		let encoded = format!("railway://{PROJECT}?environment_id={ENV_ID}");
		let provider = RailwayProvider::new(config(&encoded));
		assert_eq!(provider.uri(), encoded);
		assert_eq!(config(&provider.uri()), provider.config);

		let named =
			format!("railway://{PROJECT}?environment=production&service=api&skip_deploys=true");
		let provider = RailwayProvider::new(config(&named));
		assert_eq!(provider.uri(), named);
		assert_eq!(config(&provider.uri()), provider.config);
		assert_eq!(
			provider.config.environment,
			EnvironmentRef::Name("production".to_string())
		);
		assert_eq!(
			provider.config.service,
			Some(ServiceRef::Name("api".to_string()))
		);
		assert!(provider.config.skip_deploys);

		let shared = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
		assert_eq!(shared.config.service, None);
		assert!(!shared.config.skip_deploys);
	}

	#[test]
	fn rejects_invalid_configuration() {
		for spec in [
			"railway://",
			&format!("railway://{PROJECT}"),
			&format!("railway://{PROJECT}?environment="),
			&format!("railway://{PROJECT}?environment_id={ENV_ID}&environment=production"),
			&format!("railway://{PROJECT}?service=api"),
			&format!(
				"railway://{PROJECT}?environment=production&service_id={SERVICE_ID}&service=api"
			),
			&format!("railway://{PROJECT}?environment=production&unknown=true"),
			&format!("railway://{PROJECT}?environment=production&skip_deploys=1"),
			&format!("railway://{PROJECT}?environment=production&environment=staging"),
			"railway://has%20space?environment=production",
			&format!("railway://{PROJECT}/path?environment=production"),
		] {
			assert!(
				RailwayConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).is_err(),
				"{spec}"
			);
		}
	}

	#[test]
	fn registration_declares_read_delete_and_credentials() {
		let registration = crate::provider::PROVIDER_REGISTRY
			.iter()
			.find(|registration| registration.metadata.info.name == "railway")
			.unwrap();
		assert_eq!(registration.metadata.credential_names, &[TOKEN]);
		assert!(registration.metadata.reads);
		assert!(registration.metadata.deletes);
	}

	#[test]
	fn missing_token_names_the_credential_and_environment_variables() {
		let _lock = crate::tests::scrub_resolution_env();
		let provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
		let error = provider
			.get(Address::convention("p", "production", "KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("the `token` provider credential, RAILWAY_API_TOKEN, or RAILWAY_TOKEN"),
			"{error}"
		);
	}

	#[test]
	fn credential_and_api_token_use_the_bearer_header() {
		let _lock = crate::tests::scrub_resolution_env();
		let _api = crate::tests::EnvVarGuard::remove("RAILWAY_TOKEN");
		let _env = crate::tests::EnvVarGuard::set("RAILWAY_API_TOKEN", "env-token");
		let body = Box::leak(
			r#"{"data":{"variables":{"API_KEY":"value"}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let mut provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
		provider.api_base = format!("http://{endpoint}/graphql/v2");

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
			Some("Bearer env-token")
		);
	}

	#[test]
	fn project_token_uses_the_project_access_token_header() {
		let _lock = crate::tests::scrub_resolution_env();
		let _api = crate::tests::EnvVarGuard::remove("RAILWAY_API_TOKEN");
		let _project = crate::tests::EnvVarGuard::set("RAILWAY_TOKEN", "project-token");
		let body = Box::leak(
			r#"{"data":{"variables":{"API_KEY":"value"}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let mut provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
		provider.api_base = format!("http://{endpoint}/graphql/v2");

		assert!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.is_ok()
		);
		let requests = server.join().unwrap();
		assert_eq!(
			requests[0]
				.headers
				.get(PROJECT_ACCESS_TOKEN_HEADER)
				.map(String::as_str),
			Some("project-token")
		);
		assert!(!requests[0].headers.contains_key("authorization"));
	}

	#[test]
	fn invalid_credential_bytes_are_rejected_without_leaking() {
		let _lock = crate::tests::scrub_resolution_env();
		let mut provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
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
	}

	#[test]
	fn environment_names_are_resolved_to_ids_per_operation() {
		let envs = r#"[{"node":{"id":"staging-id","name":"staging"}},{"node":{"id":"prod-id","name":"production"}}]"#;
		let envs_body = Box::leak(
			format!(r#"{{"data":{{"project":{{"environments":{{"edges":{envs}}}}}}}}}"#)
				.into_boxed_str(),
		);
		let variables = Box::leak(
			r#"{"data":{"variables":{"API_KEY":"prod-value"}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) =
			response_server(vec![("200 OK", envs_body), ("200 OK", variables)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment=production"),
		);

		assert_eq!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"prod-value"
		);

		let requests = server.join().unwrap();
		assert_eq!(requests.len(), 2);
		let resolution: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
		assert!(
			resolution["query"]
				.as_str()
				.unwrap()
				.contains("environments"),
			"{}",
			resolution
		);
		let variables_request: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(variables_request["variables"]["environmentId"], "prod-id");
		assert_eq!(variables_request["variables"]["unrendered"], true);
	}

	#[test]
	fn service_names_are_resolved_and_shared_variables_have_no_service() {
		let services =
			r#"[{"node":{"id":"web-id","name":"web"}},{"node":{"id":"api-id","name":"api"}}]"#;
		let services_body = Box::leak(
			format!(r#"{{"data":{{"project":{{"services":{{"edges":{services}}}}}}}}}"#)
				.into_boxed_str(),
		);
		let variables =
			Box::leak(r#"{"data":{"variables":{"API_KEY":"v"}}}"#.to_string().into_boxed_str());
		let (endpoint, server) =
			response_server(vec![("200 OK", services_body), ("200 OK", variables)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}&service=api"),
		);
		assert!(
			provider
				.get(Address::convention("p", "production", "API_KEY"))
				.is_ok()
		);

		let shared = provider_with_token(
			"127.0.0.1:1".parse().unwrap(),
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);
		assert_eq!(shared.config.service, None);

		let requests = server.join().unwrap();
		let variables_request: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert_eq!(variables_request["variables"]["serviceId"], "api-id");
	}

	#[test]
	fn unknown_names_and_missing_projects_are_reported() {
		let envs = r#"[{"node":{"id":"staging-id","name":"staging"}}]"#;
		let envs_body = Box::leak(
			format!(r#"{{"data":{{"project":{{"environments":{{"edges":{envs}}}}}}}}}"#)
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", envs_body)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment=production"),
		);
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("environment 'production' was not found"),
			"{error}"
		);
		server.join().unwrap();

		let missing = Box::leak(r#"{"data":{"project":null}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", missing)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment=production"),
		);
		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("project") && error.to_string().contains("not found"),
			"{error}"
		);
		server.join().unwrap();
	}

	#[test]
	fn sealed_and_missing_variables_resolve_distinctly() {
		let body: &'static str = Box::leak(
			r#"{"data":{"variables":{"API_KEY":null,"OTHER":"value"}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(error.to_string().contains("sealed"), "{error}");
		server.join().unwrap();

		// A sealed variable stays listed, so deleting it probes and mutates.
		let deleted = Box::leak(r#"{"data":{"variableDelete":true}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", body), ("200 OK", deleted)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);
		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);
		server.join().unwrap();

		let empty = Box::leak(r#"{"data":{"variables":{}}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
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
	fn writes_upsert_with_the_configured_scope() {
		let upserted =
			Box::leak(r#"{"data":{"variableUpsert":true}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", upserted)]);
		let provider = provider_with_token(
			endpoint,
			&format!(
				"railway://{PROJECT}?environment_id={ENV_ID}&service_id={SERVICE_ID}&skip_deploys=true"
			),
		);

		provider
			.set(
				Address::convention("p", "production", "API_KEY"),
				&SecretBytes::from_utf8("new-value"),
			)
			.unwrap();

		let requests = server.join().unwrap();
		let request: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
		assert!(
			request["query"]
				.as_str()
				.unwrap()
				.contains("variableUpsert"),
			"{}",
			request
		);
		let input = &request["variables"]["input"];
		assert_eq!(input["projectId"], PROJECT);
		assert_eq!(input["environmentId"], ENV_ID);
		assert_eq!(input["serviceId"], SERVICE_ID);
		assert_eq!(input["name"], "API_KEY");
		assert_eq!(input["value"], "new-value");
		assert_eq!(input["skipDeploys"], true);
	}

	#[test]
	fn deletes_only_an_existing_variable() {
		let listed = Box::leak(
			r#"{"data":{"variables":{"API_KEY":"value","OTHER":"kept"}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let deleted = Box::leak(r#"{"data":{"variableDelete":true}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", listed), ("200 OK", deleted)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);

		assert!(
			provider
				.delete(Address::convention("p", "production", "API_KEY"))
				.unwrap()
		);

		let requests = server.join().unwrap();
		let request: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
		assert!(
			request["query"]
				.as_str()
				.unwrap()
				.contains("variableDelete"),
			"{}",
			request
		);
		assert_eq!(request["variables"]["input"]["name"], "API_KEY");
		assert!(
			request["variables"]["input"]
				.as_object()
				.unwrap()
				.get("serviceId")
				.is_none(),
			"shared variables must omit serviceId"
		);

		let empty = Box::leak(r#"{"data":{"variables":{}}}"#.to_string().into_boxed_str());
		let (endpoint, server) = response_server(vec![("200 OK", empty)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);
		assert!(
			!provider
				.delete(Address::convention("p", "production", "MISSING"))
				.unwrap()
		);
		assert_eq!(server.join().unwrap().len(), 1);
	}

	#[test]
	fn names_are_validated_and_railway_prefix_is_reserved() {
		let provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
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

		let error = provider
			.check_writable(Address::convention(
				"project",
				"production",
				"RAILWAY_API_TOKEN",
			))
			.unwrap_err();
		assert!(
			error.to_string().contains("reserved RAILWAY_ prefix"),
			"{error}"
		);
	}

	#[test]
	fn non_utf8_values_are_rejected_before_any_request() {
		let provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
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
	fn graphql_errors_surface_the_message() {
		let body = Box::leak(
			r#"{"errors":[{"message":"Not Authorized"}],"data":null}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);

		let error = provider
			.get(Address::convention("p", "production", "API_KEY"))
			.unwrap_err();
		assert!(
			error.to_string().contains("Railway rejected the request"),
			"{error}"
		);
		assert!(error.to_string().contains("Not Authorized"), "{error}");
		server.join().unwrap();

		let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);
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
	fn reflection_lists_variables_except_railway_reserved_ones() {
		let body = Box::leak(
			r#"{"data":{"variables":{"API_KEY":"a","RAILWAY_PUBLIC_DOMAIN":"b","SEALED":null}}}"#
				.to_string()
				.into_boxed_str(),
		);
		let (endpoint, server) = response_server(vec![("200 OK", body)]);
		let provider = provider_with_token(
			endpoint,
			&format!("railway://{PROJECT}?environment_id={ENV_ID}"),
		);

		let reflected = provider
			.reflect(DiscoveryContext::new("project", "production"))
			.unwrap();

		assert_eq!(reflected.len(), 2);
		assert!(reflected.contains_key("API_KEY"));
		assert!(reflected.contains_key("SEALED"));
		assert!(!reflected.contains_key("RAILWAY_PUBLIC_DOMAIN"));
		server.join().unwrap();
	}

	#[test]
	fn storage_identity_and_write_target_name_the_scope() {
		let provider = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment=production&service=api"
		)));
		assert_eq!(
			provider.storage_identity(),
			format!("railway://{PROJECT}/production/api")
		);
		assert_eq!(
			provider
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!(
				"Railway project '{PROJECT}' environment 'production', service 'api' variable 'KEY'"
			)
		);

		let shared = RailwayProvider::new(config(&format!(
			"railway://{PROJECT}?environment_id={ENV_ID}"
		)));
		assert_eq!(
			shared.storage_identity(),
			format!("railway://{PROJECT}/{ENV_ID}/shared")
		);
		assert_eq!(
			shared
				.describe_write_target(Address::convention("p", "production", "KEY"))
				.unwrap(),
			format!(
				"Railway project '{PROJECT}' environment '{ENV_ID}', shared variables variable 'KEY'"
			)
		);
	}
}
