use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::MonosecretError;
use crate::Result;
use crate::provider::Address;
use crate::provider::Provider;
use crate::provider::ProviderCredentials;
use crate::provider::ProviderUrl;

/// A section on a `OnePassword` item. Real CLI output emits item-level
/// sections with both `id` and `label`, while a field's `section` back-reference
/// reliably carries only the `id` — the item-level list supplies the
/// id → label mapping for matching sectioned references.
#[derive(Debug, Deserialize)]
struct OnePasswordSection {
	/// Stable section identifier used in `op://` references.
	id: String,
	/// Optional human-readable section label.
	label: Option<String>,
}

/// Represents a `OnePassword` item retrieved from the CLI.
///
/// This struct deserializes the JSON output from the `op item get` command
/// and contains an array of fields that hold the actual secret data.
#[derive(Debug, Deserialize)]
struct OnePasswordItem {
	/// Stable item identifier returned by batched `op item get` calls.
	///
	/// Single-item reads only need the fields, so this remains optional for
	/// compatibility with older CLI output and focused parser fixtures.
	id: Option<String>,
	/// The item title, used to associate batched `op item get` responses with
	/// the name a reference addressed (titles and ids are both legal).
	title: Option<String>,
	/// Collection of fields within the `OnePassword` item.
	/// Each field represents a piece of data stored in the item.
	fields: Vec<OnePasswordField>,
	/// Sections declared on the item, mapping field section ids to labels.
	#[serde(default)]
	sections: Vec<OnePasswordSection>,
}

/// Represents a single field within a `OnePassword` item.
///
/// Fields can contain various types of data such as passwords, strings,
/// or concealed values. The field's label is used to identify specific
/// data within an item.
#[derive(Debug, Deserialize)]
struct OnePasswordField {
	/// Unique identifier for the field within the item.
	id: String,
	/// The type of field (e.g., "STRING", "CONCEALED", "PASSWORD").
	#[serde(rename = "type")]
	field_type: String,
	/// Optional human-readable label for the field.
	/// Used to identify fields like "value", "password", etc.
	label: Option<String>,
	/// The actual value stored in the field.
	/// May be None for certain field types.
	value: Option<String>,
	/// The section the field lives under, by id.
	section: Option<OnePasswordSection>,
}

/// Template for creating new `OnePassword` items via the CLI.
///
/// This struct is serialized to JSON and passed to the `op item create` command
/// using the `--template` flag. It defines the structure and metadata for
/// new secure note items that store secrets.
#[derive(Debug, Serialize)]
struct OnePasswordItemTemplate {
	/// The title of the item, formatted as "monosecret/{project}/{profile}/{key}".
	title: String,
	/// The category of the item. Always "`SECURE_NOTE`" for monosecret items.
	category: String,
	/// Collection of fields to include in the item.
	/// Contains project, key, and value fields.
	fields: Vec<OnePasswordFieldTemplate>,
	/// Tags to help organize and identify monosecret items.
	/// Includes "automated" and the project name.
	tags: Vec<String>,
}

/// Template for individual fields when creating `OnePassword` items.
///
/// Each field represents a piece of data to store in the item.
/// Used within `OnePasswordItemTemplate` to define the item's content.
#[derive(Debug, Serialize)]
struct OnePasswordFieldTemplate {
	/// Human-readable label for the field (e.g., "project", "key", "value").
	label: String,
	/// The type of field. Always "STRING" for monosecret fields.
	#[serde(rename = "type")]
	field_type: String,
	/// The actual value to store in the field.
	value: String,
}

/// The item/field coordinates a native address resolves against 1Password,
/// consumed by the `op read` / `op item edit` command paths. Built from a
/// secret's `ref` table (see [`crate::config::NativeAddress`]); the vault is
/// resolved separately (the address's `vault` key or the store's default).
#[derive(Debug)]
pub struct SecretReference {
	/// The item name or UUID.
	pub item: String,
	/// Optional section the field lives under.
	pub section: Option<String>,
	/// The field label or ID to read and write.
	pub field: String,
}

/// A field reference queued for batched resolution, carrying the vault and
/// item strings the render site already resolved plus the section/field the
/// reference reads. The URI is built from these same strings and is never
/// re-parsed to recover them: item titles may contain `/`, which would make
/// splitting the URI ambiguous. The section/field pair is used only to match
/// values client-side against batched `op item get` reads.
#[derive(Debug, Clone)]
struct BatchRef {
	uri: String,
	vault: String,
	item: String,
	/// Optional section the field lives under.
	section: Option<String>,
	/// The field label or ID to read.
	field: String,
}

/// The outcome of the tiered item reads: per-reference values in slice order,
/// plus the indices the reads could not resolve and that the caller must hand
/// to the inject path.
type RefResolution = (Vec<Option<SecretString>>, Vec<usize>);

/// Collision-resistant framing around each `op inject` expression.
///
/// Inject performs textual replacement, so formats such as JSON cannot safely
/// carry arbitrary secret text without a format-aware escaping guarantee. These
/// per-call markers preserve newlines and punctuation verbatim. Parsing also
/// requires each marker exactly once and in order, preventing shifted values.
#[derive(Debug)]
struct InjectTemplate {
	input: String,
	frames: Vec<(String, String)>,
}

impl InjectTemplate {
	fn new(reference_uris: &[String], nonce: &str) -> Self {
		let mut input = String::new();
		let mut frames = Vec::with_capacity(reference_uris.len());

		for (index, reference_uri) in reference_uris.iter().enumerate() {
			let start = format!("__MONOSECRET_OP_{nonce}_{index}_START__");
			let end = format!("__MONOSECRET_OP_{nonce}_{index}_END__");
			input.push_str(&start);
			input.push_str("{{ ");
			input.push_str(reference_uri);
			input.push_str(" }}");
			input.push_str(&end);
			frames.push((start, end));
		}

		Self { input, frames }
	}

	fn parse(&self, output: &str) -> Result<Vec<String>> {
		for (start, end) in &self.frames {
			if output.matches(start).count() != 1 || output.matches(end).count() != 1 {
				return Err(Self::malformed_output());
			}
		}

		let mut remaining = output;
		let mut values = Vec::with_capacity(self.frames.len());
		for (start, end) in &self.frames {
			let Some(after_start) = remaining.strip_prefix(start) else {
				return Err(Self::malformed_output());
			};
			let Some((value, after_end)) = after_start.split_once(end) else {
				return Err(Self::malformed_output());
			};
			values.push(value.to_string());
			remaining = after_end;
		}

		// `op inject` terminates stdout with one newline even when its input
		// does not. Accept only that exact transport suffix so whitespace in
		// the framed secret values remains untouched.
		if !matches!(remaining, "" | "\n" | "\r\n") {
			return Err(Self::malformed_output());
		}

		Ok(values)
	}

	fn malformed_output() -> MonosecretError {
		MonosecretError::ProviderOperationFailed(
			"1Password CLI returned malformed output from 'op inject'".to_string(),
		)
	}
}

/// Configuration for the `OnePassword` provider.
///
/// This struct contains all the necessary configuration options for
/// interacting with `OnePassword` CLI. It supports both interactive authentication
/// and service account tokens for automated workflows.
///
/// # Examples
///
/// ```ignore
/// # use monosecret::provider::onepassword::OnePasswordConfig;
/// // Using default configuration (interactive auth)
/// let config = OnePasswordConfig::default();
///
/// // With a specific vault
/// let config = OnePasswordConfig {
///     default_vault: Some("Development".to_string()),
///     ..Default::default()
/// };
///
/// // With service account token for CI/CD
/// let config = OnePasswordConfig {
///     service_account_token: Some("ops_eyJzaWduSW...".to_string()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnePasswordConfig {
	/// Optional account shorthand (for multiple accounts).
	///
	/// Used with the `--account` flag when you have multiple `OnePassword`
	/// accounts configured. This should match the shorthand shown in
	/// `op account list`.
	pub account: Option<String>,
	/// Default vault to use when profile is "default".
	///
	/// If not set, defaults to "Private" for the default profile.
	/// For non-default profiles, the profile name is used as the vault name.
	pub default_vault: Option<String>,
	/// Service account token (alternative to interactive auth).
	///
	/// When set, this token is passed via the `OP_SERVICE_ACCOUNT_TOKEN`
	/// environment variable to authenticate without user interaction.
	/// Ideal for CI/CD environments.
	pub service_account_token: Option<String>,
	/// Optional folder prefix format string for organizing secrets in `OnePassword`.
	///
	/// Supports placeholders: {project}, {profile}, and {key}.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not specified.
	pub folder_prefix: Option<String>,
	/// Legacy `op+token://<account>/<basePath>` addressing: these segments are
	/// prepended to a field reference's item path, so a secret's `path` becomes
	/// the *section* within a single shared item. For example
	/// `op+token://Development/Dotfiles` with a secret at `path = ["ai"]` reads
	/// field `ai` of item `Dotfiles` in vault `Development`.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub reference_base_path: Vec<String>,
}

impl TryFrom<&ProviderUrl> for OnePasswordConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		let scheme = url.scheme();

		match scheme {
			"1password" => {
				return Err(MonosecretError::ProviderOperationFailed(
                    "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault)".to_string()
                ));
			}
			"onepassword" | "onepassword+token" | "op" | "op+token" => {}
			_ => {
				return Err(MonosecretError::ProviderOperationFailed(format!(
					"Invalid scheme '{scheme}' for OnePassword provider"
				)));
			}
		}

		// The `onepassword+token://token@vault` form carried a service account
		// token in the URI, which then travelled into committed manifests,
		// shell history, and CI logs. The token now comes from a provider
		// credential or the environment; the scheme itself
		// (`onepassword+token://vault`) still selects service account auth.
		// Checked for both userinfo positions, since the token was accepted in
		// either, and independently of the host so it cannot be reached only
		// through a vault-bearing URI.
		if matches!(scheme, "onepassword+token" | "op+token")
			&& (!url.username().is_empty() || url.password().is_some())
		{
			return Err(MonosecretError::ProviderOperationFailed(
				format!(
					"{scheme}:// no longer accepts the service account token in the URI, \
                     because a URI reaches committed manifests, shell history, and CI \
                     logs. Keep the scheme without the token \
                     (`{scheme}://<vault>`) and supply the token as the \
                     `service_account_token` provider credential (`monosecret config provider \
                     login <alias>`, or `credentials = {{ service_account_token = \"keyring\" }}` \
                     on the alias), or set OP_SERVICE_ACCOUNT_TOKEN. See \
                     https://monosecret.dev/providers/onepassword/#provider-credentials"
				)
				.to_string(),
			));
		}

		let mut config = Self::default();

		// Parse URL components for account@vault format, ignoring dummy localhost
		if let Some(host) = url.host()
			&& host != "localhost"
		{
			let username = url.username();

			// Check if we have username (account) information
			if username.is_empty() {
				// No username, so the host is the vault
				config.default_vault = Some(host);
			} else {
				config.account = Some(username);
				config.default_vault = Some(host);
			}
		}

		// The legacy `op+token://<account>/<basePath>` form treats the URI path
		// as a base path prepended to item references: a secret's `path`
		// becomes a section within a single shared item (see
		// [`OnePasswordConfig::reference_base_path`]). Other schemes reject a
		// path, since items are addressed with a secret's `ref`, not the
		// provider URI.
		if scheme == "op+token" {
			let path = url.path();
			let path = path.trim_matches('/');
			if !path.is_empty() {
				config.reference_base_path = path
					.split('/')
					.filter(|segment| !segment.is_empty())
					.map(str::to_string)
					.collect();
			}
			return Ok(config);
		}

		// Item paths (the `op://vault/item/field` form earlier iterations
		// accepted, including via `onepassword://`) are rejected with the
		// exact `ref` table translation, instead of being silently ignored
		// and reading the conventional layout.
		let path = url.path();
		let path = path.trim_matches('/');
		if !path.is_empty() || scheme == "op" {
			let vault = config.default_vault.as_deref().unwrap_or("<vault>");
			let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
			let hint = match segments.as_slice() {
				[item, field] => {
					crate::config::ref_table_hint(Some(vault), item, None, Some(field))
				}
				[item, section, field] => {
					crate::config::ref_table_hint(Some(vault), item, Some(section), Some(field))
				}
				_ => crate::config::ref_table_hint(Some(vault), "<item>", None, Some("<field>")),
			};
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"1Password items are addressed with a secret's `ref`, not in the provider URI: \
                 use providers = [\"onepassword://{vault}\"] with {hint}"
			)));
		}

		Ok(config)
	}
}

/// Detects if running on Windows Subsystem for Linux 2.
///
/// Checks if the system is running on WSL2 by reading `/proc/sys/kernel/osrelease`
/// and looking for the `-microsoft-standard-WSL2` suffix.
///
/// # Returns
///
/// * `true` - Running on WSL2
/// * `false` - Not running on WSL2 or unable to determine
#[cfg(target_os = "linux")]
fn is_wsl2() -> bool {
	std::fs::read_to_string("/proc/sys/kernel/osrelease")
		.is_ok_and(|content| content.trim().ends_with("-microsoft-standard-WSL2"))
}

#[cfg(not(target_os = "linux"))]
fn is_wsl2() -> bool {
	false
}

/// Removes any `OP_SESSION_*` env vars from a spawned `op` invocation.
///
/// `op` treats `OP_SESSION_<account>` as the authoritative session and will not
/// fall back to the desktop app's biometric flow when those tokens expire,
/// returning `"account is not signed in"` instead. Stripping them lets the
/// desktop integration (Settings → Developer → Integrate with 1Password CLI)
/// handle unlock automatically. See
/// <https://github.com/cachix/monosecret/issues/80>.
const OP_NOT_INSTALLED_HELP: &str = "OnePassword CLI (op) is not installed.\n\n\
    To install it:\n  \
    - macOS: brew install 1password-cli\n  \
    - Linux: Download from https://1password.com/downloads/command-line/\n  \
    - Windows: Download from https://1password.com/downloads/command-line/\n  \
    - NixOS: nix-env -iA nixpkgs.onepassword\n\n\
    Then enable desktop integration in the 1Password app under\n  \
    Settings → Developer → \"Integrate with 1Password CLI\".";

const AUTH_REQUIRED_HELP: &str = "OnePassword authentication required.\n\n\
    Recommended: enable desktop integration in the 1Password app under\n  \
    Settings → Developer → \"Integrate with 1Password CLI\", then unlock the app.\n\n\
    Alternatives:\n  \
    - Service account (CI): set OP_SERVICE_ACCOUNT_TOKEN or use the onepassword+token:// scheme\n  \
    - Manual signin: run 'eval $(op signin)' (session expires after 30 minutes of inactivity)";

fn is_auth_error(error_msg: &str) -> bool {
	error_msg.contains("not currently signed in")
		|| error_msg.contains("no active session")
		|| error_msg.contains("could not find session token")
		|| error_msg.contains("account is not signed in")
}

pub(crate) fn strip_op_session_env(cmd: &mut Command) {
	for (key, _) in std::env::vars_os() {
		if key.to_string_lossy().starts_with("OP_SESSION_") {
			cmd.env_remove(&key);
		}
	}
}

/// Provider implementation for `OnePassword` password manager.
///
/// This provider integrates with `OnePassword` CLI (`op`) to store and retrieve
/// secrets. It organizes secrets in a hierarchical structure within `OnePassword`
/// items using a configurable format string that defaults to: `monosecret/{project}/{profile}/{key}`.
///
/// A secret with native `ref` coordinates instead reads the referenced item
/// field via `op read` and writes it via `op item edit`, ignoring the layout
/// above. See [`SecretReference`].
///
/// # Authentication
///
/// The provider supports three authentication methods, in order of preference:
///
/// 1. **Desktop app integration** (recommended for local dev): enable
///    Settings → Developer → "Integrate with 1Password CLI" in the desktop app.
///    `op` calls are unlocked via biometrics with no shell session needed.
/// 2. **Service Account Tokens**: For CI/CD, configure a token in the config
///    or set `OP_SERVICE_ACCOUNT_TOKEN`.
/// 3. **Manual signin** (legacy): run `eval $(op signin)`. The provider strips
///    `OP_SESSION_*` env vars before spawning `op` so that expired session
///    tokens fall back to desktop integration instead of erroring.
///
/// # Storage Structure
///
/// Secrets are stored as Secure Note items in `OnePassword` with:
/// - Title: formatted according to `folder_prefix` configuration
/// - Category: `SECURE_NOTE`
/// - Fields: project, key, value
/// - Tags: "automated", {project}
///
/// # Example Usage
///
/// ```ignore
/// # Desktop integration (recommended): enable in 1Password app, then:
/// monosecret set MY_SECRET --provider onepassword://Development
///
/// # Service account token
/// export OP_SERVICE_ACCOUNT_TOKEN="ops_eyJzaWduSW..."
/// monosecret get MY_SECRET --provider onepassword+token://Development
/// ```
pub struct OnePasswordProvider {
	/// Configuration for the provider including auth settings and default vault.
	config: OnePasswordConfig,
	/// The `OnePassword` CLI command to use (either "op" or a custom path).
	op_command: String,
	/// Credentials supplied by the provider alias.
	credentials: ProviderCredentials,
	/// Bootstrap secrets handed over via `depends_on`, keyed by the child
	/// environment variable they should be exported as (see
	/// [`Provider::configure_dependency_secrets`]). Interior mutability because
	/// delivery is post-construction and the factory shares the provider as an
	/// `Arc` when it registers an auth preflight.
	dependency_env: Mutex<HashMap<String, SecretString>>,
	#[cfg(test)]
	command_override: Option<std::sync::Arc<TestOpCommandOverride>>,
}

#[cfg(test)]
type TestOpCommandOverride =
	dyn Fn(&Command, Option<&str>) -> Result<String> + Send + Sync + 'static;

const SERVICE_ACCOUNT_TOKEN: &str = "service_account_token";
const OP_SERVICE_ACCOUNT_TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";

crate::register_provider! {
	struct: OnePasswordProvider,
	config: OnePasswordConfig,
	name: "onepassword",
	description: "OnePassword password manager",
	schemes: ["onepassword", "onepassword+token", "op", "op+token"],
	examples: ["onepassword://vault", "onepassword://work@Production", "onepassword+token://vault", "op+token://account/basePath"],
	credential_names: [SERVICE_ACCOUNT_TOKEN],
	preflight: check_auth,
}

impl OnePasswordProvider {
	/// Creates a new `OnePasswordProvider` with the given configuration.
	///
	/// # Arguments
	///
	/// * `config` - The configuration for the provider
	pub fn new(config: OnePasswordConfig) -> Self {
		let op_command = std::env::var("MONOSECRET_OPCLI_PATH").unwrap_or_else(|_| {
			if is_wsl2() {
				"op.exe".to_string()
			} else {
				"op".to_string()
			}
		});
		Self {
			config,
			op_command,
			credentials: ProviderCredentials::new(),
			dependency_env: Mutex::new(HashMap::new()),
			#[cfg(test)]
			command_override: None,
		}
	}

	/// The service account token in effect: the URI-supplied one
	/// (`onepassword+token://`), else an explicitly supplied credential, then
	/// a `depends_on`-delivered bootstrap secret, and only then the
	/// conventional environment variable. When all are absent, `op` falls back
	/// to its own authentication (desktop app or manual signin) exactly as
	/// before. The `depends_on` secret outranks the ambient variable to match
	/// [`OnePasswordEnvProvider`], where the delivered token is exported
	/// explicitly rather than inherited.
	fn effective_service_account_token(&self) -> Option<String> {
		self.config
			.service_account_token
			.clone()
			.or_else(|| {
				self.credentials
					.get(SERVICE_ACCOUNT_TOKEN)
					.map(|secret| secret.expose_secret().to_string())
			})
			.or_else(|| {
				self.dependency_env
					.lock()
					.ok()
					.and_then(|env| env.get(OP_SERVICE_ACCOUNT_TOKEN_ENV).cloned())
					.map(|secret| secret.expose_secret().to_string())
			})
			.or_else(|| std::env::var(OP_SERVICE_ACCOUNT_TOKEN_ENV).ok())
			.filter(|token| !token.is_empty())
	}

	/// Executes a `OnePassword` CLI command with proper error handling.
	///
	/// This method handles:
	/// - Setting up authentication (account, service token)
	/// - Executing the command
	/// - Parsing error messages for common issues
	/// - Providing helpful error messages for missing CLI
	///
	/// # Arguments
	///
	/// * `args` - The command arguments to pass to `op`
	/// * `stdin_data` - Optional data to write to stdin
	///
	/// # Returns
	///
	/// * `Result<String>` - The command output or an error
	///
	/// # Errors
	///
	/// Returns specific errors for:
	/// - Missing `OnePassword` CLI installation
	/// - Authentication required
	/// - Command execution failures
	/// - Stdin write failures
	fn execute_op_command(&self, args: &[&str], stdin_data: Option<&str>) -> Result<String> {
		use std::process::Stdio;

		tracing::debug!(
			command = %self.op_command,
			args = ?args,
			has_stdin = stdin_data.is_some(),
			has_service_token = self.effective_service_account_token().is_some(),
			account = ?self.config.account,
			vault = ?self.config.default_vault,
			"executing 1Password CLI command"
		);

		let mut cmd = Command::new(&self.op_command);
		strip_op_session_env(&mut cmd);

		// Set service account token if provided. Passing an environment-supplied
		// token explicitly is equivalent to `op` inheriting it.
		if let Some(token) = self.effective_service_account_token() {
			cmd.env(OP_SERVICE_ACCOUNT_TOKEN_ENV, token);
		}

		// Add account if specified
		if let Some(account) = &self.config.account {
			cmd.arg("--account").arg(account);
		}

		cmd.args(args);

		#[cfg(test)]
		if let Some(command_override) = &self.command_override {
			return command_override(&cmd, stdin_data);
		}

		// Configure stdio based on whether we have stdin data
		if stdin_data.is_some() {
			cmd.stdin(Stdio::piped());
			cmd.stdout(Stdio::piped());
			cmd.stderr(Stdio::piped());
		}

		let output = if let Some(data) = stdin_data {
			// Spawn process and write to stdin
			let mut child = match cmd.spawn() {
				Ok(child) => child,
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
					return Err(MonosecretError::ProviderOperationFailed(
						OP_NOT_INSTALLED_HELP.to_string(),
					));
				}
				Err(e) => return Err(e.into()),
			};

			// Write to stdin; a child that rejects the batch and exits
			// without draining stdin must surface through its exit status
			// below, not kill us on a broken pipe.
			if let Some(stdin) = child.stdin.take() {
				super::write_child_stdin(stdin, data)?;
			}

			child.wait_with_output()?
		} else {
			// No stdin data, use output() directly
			match cmd.output() {
				Ok(output) => output,
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
					return Err(MonosecretError::ProviderOperationFailed(
						OP_NOT_INSTALLED_HELP.to_string(),
					));
				}
				Err(e) => return Err(e.into()),
			}
		};

		if !output.status.success() {
			let error_msg = String::from_utf8_lossy(&output.stderr);
			if is_auth_error(&error_msg) {
				tracing::error!(
					status = ?output.status.code(),
					stderr = %error_msg,
					args = ?args,
					"1Password CLI command failed due to authentication"
				);
				return Err(MonosecretError::ProviderOperationFailed(
					AUTH_REQUIRED_HELP.to_string(),
				));
			}
			tracing::warn!(
				status = ?output.status.code(),
				stderr = %error_msg,
				args = ?args,
				"1Password CLI command failed"
			);
			return Err(MonosecretError::ProviderOperationFailed(
				error_msg.to_string(),
			));
		}

		String::from_utf8(output.stdout).map_err(|e| {
			MonosecretError::ProviderOperationFailed(format!(
				"1Password CLI returned non-UTF-8 output: {}",
				crate::error::display_error_chain(&e)
			))
		})
	}

	/// Checks if the user is authenticated with `OnePassword` (uncached).
	///
	/// Uses `op vault list` rather than `op whoami` because the latter only
	/// reports the state of an explicit `op signin` session and reports
	/// `account is not signed in` under desktop-app delegated sessions even
	/// when secret reads via `op item ...` work fine. `op vault list` actually
	/// exercises the access path used for real operations.
	///
	/// # Returns
	///
	/// * `Ok(true)` - User is authenticated
	/// * `Ok(false)` - User is not authenticated
	/// * `Err(_)` - Command execution failed
	fn is_authenticated(&self) -> Result<bool> {
		match self.execute_op_command(&["vault", "list", "--format", "json"], None) {
			Ok(_) => Ok(true),
			Err(MonosecretError::ProviderOperationFailed(msg))
				if msg.contains("authentication required") || msg.contains("no account found") =>
			{
				Ok(false)
			}
			Err(e) => Err(e),
		}
	}

	/// Determines the vault name to use.
	///
	/// # Returns
	///
	/// The vault name to use - always returns the configured `default_vault` or "Private"
	fn get_vault_name(&self) -> String {
		self.config
			.default_vault
			.clone()
			.unwrap_or_else(|| "Private".to_string())
	}

	/// Resolves the vault used by operations without turning a whole-item read
	/// into a field read. Entry identity adds the write field separately.
	fn operation_coordinates(&self, addr: Address<'_>) -> Result<crate::config::NativeAddress> {
		let mut coords = self.resolve_coords(addr)?.into_owned();
		if coords.vault.is_none() {
			coords.vault = Some(self.get_vault_name());
		}
		Ok(self.apply_reference_base_path(coords))
	}

	/// Prepends the legacy `op+token://` base path to a field reference's item
	/// path, folding the secret's item into a *section* of the shared base
	/// item. A no-op when no base path is configured (every current scheme
	/// except `op+token`).
	fn apply_reference_base_path(
		&self,
		mut coords: crate::config::NativeAddress,
	) -> crate::config::NativeAddress {
		if self.config.reference_base_path.is_empty() {
			return coords;
		}
		let mut segments = self.config.reference_base_path.clone();
		segments.push(coords.item.clone());
		if let Some(section) = &coords.section {
			segments.extend(section.split('/').map(str::to_string));
		}
		let mut segments = segments.into_iter();
		coords.item = segments.next().expect("base path is non-empty");
		let rest: Vec<String> = segments.collect();
		coords.section = if rest.is_empty() {
			None
		} else {
			Some(rest.join("/"))
		};
		coords
	}

	/// Renders the full `op://` reference string for `op read`.
	///
	/// Names are rendered decoded (spaces and all): the reference is passed to
	/// `op` as a single process argument, so no URL encoding is involved.
	fn reference_uri(vault: &str, reference: &SecretReference) -> String {
		match &reference.section {
			Some(section) => {
				format!(
					"op://{}/{}/{}/{}",
					vault, reference.item, section, reference.field
				)
			}
			None => format!("op://{}/{}/{}", vault, reference.item, reference.field),
		}
	}

	/// Reads the pinned reference via `op read` from the given vault.
	///
	/// Returns `Ok(None)` when the referenced item or field does not exist,
	/// mirroring how the conventional layout reports unprovisioned secrets.
	fn read_reference(
		&self,
		vault: &str,
		reference: &SecretReference,
	) -> Result<Option<SecretString>> {
		self.read_reference_uri(&Self::reference_uri(vault, reference))
	}

	fn read_reference_uri(&self, reference_uri: &str) -> Result<Option<SecretString>> {
		match self.execute_op_command(&["read", "--no-newline", reference_uri], None) {
			Ok(output) => Ok(Some(SecretString::new(output.into()))),
			Err(MonosecretError::ProviderOperationFailed(msg))
				if msg.contains("isn't an item") || msg.contains("doesn't have a field") =>
			{
				Ok(None)
			}
			Err(e) => Err(e),
		}
	}

	/// Resolves unique field references with the fewest possible `op` reads.
	///
	/// Every reference `op inject` resolves is one billed read against the
	/// service-account rate limits
	/// (<https://www.1password.dev/service-accounts/rate-limits>), so
	/// references that share an item are served from batched `op item get`
	/// reads instead — one read per item, with section and field matched
	/// client-side. Only references the item reads cannot serve are deferred
	/// to [`Self::resolve_refs_via_inject`], the original inject-first path
	/// whose recovery semantics stay authoritative: a failed inject is
	/// classified first, an auth/session error surfaces immediately
	/// ([`inject_error_is_recoverable`]), and any other failure is handed to
	/// [`Self::recover_reference_uris`].
	fn read_reference_uris(&self, refs: &[BatchRef]) -> Result<Vec<Option<SecretString>>> {
		if refs.is_empty() {
			return Ok(Vec::new());
		}
		if let [single] = refs {
			return Ok(vec![self.read_reference_uri(&single.uri)?]);
		}

		let (mut values, deferred) = self.read_refs_from_items(refs)?;
		if deferred.is_empty() {
			return Ok(values);
		}

		let deferred_refs: Vec<BatchRef> = deferred
			.iter()
			.map(|&index| {
				refs.get(index)
					.expect("deferred index comes from refs")
					.clone()
			})
			.collect();
		let deferred_values = self.resolve_refs_via_inject(&deferred_refs)?;
		for (index, value) in deferred.into_iter().zip(deferred_values) {
			*values
				.get_mut(index)
				.expect("deferred index comes from the same slice length") = value;
		}
		Ok(values)
	}

	/// Serves field references from batched `op item get` reads.
	///
	/// Tier 1 issues one stdin-batched `op item get` per vault — one child
	/// process and one billed read per referenced item. A single absent or
	/// ambiguous item fails that whole batch, so tier 2 retries each item
	/// individually: healthy items still resolve from their own read, an
	/// absent item's references resolve as `None` exactly the way `op read`
	/// reports them, and anything else (ambiguous titles, unusable output) is
	/// returned as deferred indices for the caller's inject path.
	fn read_refs_from_items(&self, refs: &[BatchRef]) -> Result<RefResolution> {
		use std::collections::BTreeMap;
		use std::collections::HashSet;

		// Reference indices grouped by (vault, item), both BTree-ordered so
		// the child process sequence is deterministic across runs.
		let mut groups: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
		for (index, batch_ref) in refs.iter().enumerate() {
			groups
				.entry((batch_ref.vault.as_str(), batch_ref.item.as_str()))
				.or_default()
				.push(index);
		}
		let mut by_vault: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
		for &(vault, item) in groups.keys() {
			let items = by_vault.entry(vault).or_default();
			if !items.contains(&item) {
				items.push(item);
			}
		}

		let mut values: Vec<Option<SecretString>> = refs.iter().map(|_| None).collect();
		let mut deferred: Vec<usize> = Vec::new();
		// Groups already decided by the per-item retries; the fetched-item
		// pass below must not decide them a second time.
		let mut decided: HashSet<(&str, &str)> = HashSet::new();

		for (vault, items) in by_vault {
			let fetched: Vec<OnePasswordItem> = match self.fetch_items(vault, &items) {
				Ok(fetched) => fetched,
				Err(error) => {
					if !inject_error_is_recoverable(&error) {
						return Err(error);
					}
					let mut fetched = Vec::new();
					for item in items {
						let indices = groups.get(&(vault, item)).expect("group was inserted");
						match self.fetch_item(vault, item) {
							Ok(parsed) => fetched.push(parsed),
							Err(error) => {
								if !inject_error_is_recoverable(&error) {
									return Err(error);
								}
								decided.insert((vault, item));
								if !error_is_missing_item(&error) {
									deferred.extend(indices.iter().copied());
								}
								// A missing item leaves its references `None`,
								// matching the per-ref `op read` outcome for
								// "isn't an item".
							}
						}
					}
					fetched
				}
			};

			for (item, indices) in groups
				.iter()
				.filter(|((group_vault, _), _)| **group_vault == *vault)
				.map(|((_, item), indices)| (*item, indices))
			{
				if decided.contains(&(vault, item)) {
					continue;
				}
				let Some(parsed) = fetched
					.iter()
					.find(|candidate| item_matches_name(candidate, item))
				else {
					// The vault read succeeded but never returned this item;
					// let the inject path decide rather than guessing.
					deferred.extend(indices.iter().copied());
					continue;
				};
				for &index in indices {
					let batch_ref = refs.get(index).expect("group index comes from refs");
					let reference = SecretReference {
						item: item.to_string(),
						section: batch_ref.section.clone(),
						field: batch_ref.field.clone(),
					};
					match Self::resolve_reference_in_item(parsed, &reference) {
						Ok(value) => {
							if let Some(slot) = values.get_mut(index) {
								*slot = value.map(|value| SecretString::new(value.into()));
							}
						}
						Err(()) => deferred.push(index),
					}
				}
			}
		}

		Ok((values, deferred))
	}

	/// Fetches the named items from one vault with one stdin-batched
	/// `op item get` process.
	fn fetch_items(&self, vault: &str, items: &[&str]) -> Result<Vec<OnePasswordItem>> {
		let mut input = items.join("\n");
		input.push('\n');
		let output = self.execute_op_command(
			&["item", "get", "--vault", vault, "--format", "json"],
			Some(&input),
		)?;
		Self::parse_item_documents(&output)
	}

	/// Fetches a single named item from a vault with the item name as the
	/// direct argument, used when the stdin batch cannot be trusted to
	/// attribute a failure to one item.
	fn fetch_item(&self, vault: &str, item: &str) -> Result<OnePasswordItem> {
		let output = self.execute_op_command(
			&["item", "get", item, "--vault", vault, "--format", "json"],
			None,
		)?;
		Self::parse_item_documents(&output)?
			.into_iter()
			.next()
			.ok_or_else(|| {
				MonosecretError::ProviderOperationFailed(
					"1Password CLI returned an empty item document".to_string(),
				)
			})
	}

	/// Parses `op item get --format json` output: current CLI versions emit a
	/// stream of JSON documents (one per item); an array is accepted as well.
	fn parse_item_documents(output: &str) -> Result<Vec<OnePasswordItem>> {
		match serde_json::from_str::<Vec<OnePasswordItem>>(output) {
			// Accept an array as well as the JSON stream emitted by current
			// CLI versions so this remains compatible with output changes.
			Ok(items) => Ok(items),
			Err(_) => {
				serde_json::Deserializer::from_str(output)
					.into_iter::<OnePasswordItem>()
					.collect::<std::result::Result<_, _>>()
					.map_err(|error| {
						MonosecretError::ProviderOperationFailed(format!(
							"1Password CLI returned invalid batched item JSON: {error}"
						))
					})
			}
		}
	}

	/// Matches a reference's section/field grammar against a batch-fetched
	/// item, mirroring `op`'s case-insensitive label resolution.
	///
	/// - `Ok(Some(value))`: the field matched strictly and carries a value.
	/// - `Ok(None)`: no field on the item carries the referenced label or id —
	///   the outcome `op read` reports as "doesn't have a field".
	/// - `Err(())`: a candidate field exists but this item read cannot serve
	///   it (a section shape the strict grammar does not confirm, or no value
	///   in the JSON). Callers defer to `op inject`, whose resolution is
	///   authoritative.
	fn resolve_reference_in_item(
		item: &OnePasswordItem,
		reference: &SecretReference,
	) -> std::result::Result<Option<String>, ()> {
		let same_name = |a: &str, b: &str| a.trim().to_lowercase() == b.trim().to_lowercase();

		// A field's section normally carries only the id; the item-level
		// sections list supplies the id → label candidates to match against.
		let section_candidates = |section: &OnePasswordSection| -> Vec<String> {
			let mut candidates = vec![section.id.clone()];
			if let Some(label) = &section.label {
				candidates.push(label.clone());
			}
			if let Some(listed) = item.sections.iter().find(|listed| listed.id == section.id)
				&& let Some(label) = &listed.label
			{
				candidates.push(label.clone());
			}
			candidates
		};

		let mut label_found = false;
		for field in &item.fields {
			let label_match = field
				.label
				.as_deref()
				.is_some_and(|label| same_name(label, &reference.field))
				|| same_name(&field.id, &reference.field);
			if !label_match {
				continue;
			}
			label_found = true;
			let section_ok = match (&reference.section, &field.section) {
				(None, None) => true,
				(Some(want), Some(have)) => {
					section_candidates(have)
						.iter()
						.any(|candidate| same_name(candidate, want))
				}
				// The reference grammar puts the section in the URI: a ref
				// that omits it must not reach into a sectioned field, and a
				// sectioned ref must not grab an unsectioned one.
				_ => false,
			};
			if !section_ok {
				continue;
			}
			return match field.value.clone() {
				Some(value) => Ok(Some(value)),
				// The matched field carries no value in the item JSON; let
				// `op inject` decide with its authoritative semantics.
				None => Err(()),
			};
		}
		if label_found { Err(()) } else { Ok(None) }
	}

	/// The original inject-first path, retained as the correctness fallback
	/// for references the batched item reads cannot serve.
	fn resolve_refs_via_inject(&self, refs: &[BatchRef]) -> Result<Vec<Option<SecretString>>> {
		if refs.is_empty() {
			return Ok(Vec::new());
		}
		if let [single] = refs {
			return Ok(vec![self.read_reference_uri(&single.uri)?]);
		}

		let uris: Vec<String> = refs.iter().map(|r| r.uri.clone()).collect();
		let nonce = uuid::Uuid::new_v4().simple().to_string();
		let template = InjectTemplate::new(&uris, &nonce);
		match self.execute_op_command(&["inject"], Some(&template.input)) {
			Ok(output) => {
				template.parse(&output).map(|values| {
					values
						.into_iter()
						.map(|value| Some(SecretString::new(value.into())))
						.collect()
				})
			}
			Err(error) => {
				if !inject_error_is_recoverable(&error) {
					return Err(error);
				}
				self.recover_reference_uris(refs)
			}
		}
	}

	/// Identifies refs whose items are absent from their vault (one
	/// `op item list` per distinct vault), resolves those as missing, and
	/// retries the inject batch once with the remainder. Every path that
	/// cannot positively identify-and-retry lands in the per-secret
	/// fallback, preserving the pre-recovery behavior exactly.
	fn recover_reference_uris(&self, refs: &[BatchRef]) -> Result<Vec<Option<SecretString>>> {
		let Some(retained_flags) = self.flag_refs_with_existing_items(refs)? else {
			return self.read_uris_with_fallback(refs);
		};
		if retained_flags.iter().all(|&retained| retained) {
			return self.read_uris_with_fallback(refs);
		}

		let retained: Vec<&BatchRef> = refs
			.iter()
			.zip(&retained_flags)
			.filter_map(|(r, &keep)| keep.then_some(r))
			.collect();

		let retained_values = match retained.as_slice() {
			[] => Vec::new(),
			[single] => vec![self.read_reference_uri(&single.uri)?],
			_ => {
				let uris: Vec<String> = retained.iter().map(|r| r.uri.clone()).collect();
				let nonce = uuid::Uuid::new_v4().simple().to_string();
				let template = InjectTemplate::new(&uris, &nonce);
				match self.execute_op_command(&["inject"], Some(&template.input)) {
					Ok(output) => {
						template
							.parse(&output)?
							.into_iter()
							.map(|value| Some(SecretString::new(value.into())))
							.collect()
					}
					Err(error) => {
						if !inject_error_is_recoverable(&error) {
							return Err(error);
						}
						let retained_refs: Vec<BatchRef> =
							retained.iter().map(|r| (*r).clone()).collect();
						self.read_uris_with_fallback(&retained_refs)?
					}
				}
			}
		};

		let mut retained_iter = retained_values.into_iter();
		Ok(retained_flags
			.into_iter()
			.map(|keep| {
				if keep {
					retained_iter.next().flatten()
				} else {
					None
				}
			})
			.collect())
	}

	/// The pre-existing bounded per-secret fallback, extracted verbatim.
	fn read_uris_with_fallback(&self, refs: &[BatchRef]) -> Result<Vec<Option<SecretString>>> {
		super::map_concurrently(refs, super::get_each_concurrency(), |r| {
			self.read_reference_uri(&r.uri)
		})
		.into_iter()
		.collect()
	}

	/// Returns per-ref "item exists" flags, or `None` when a vault listing
	/// fails for a recoverable reason (caller then treats every ref as retained
	/// via full fallback). Global auth and installation errors are preserved.
	/// A ref is flagged missing ONLY on a successful listing with no match
	/// by id or case-insensitive title — when in doubt, keep it.
	///
	/// Lists with `--include-archive`: archived items are absent from the
	/// default listing but still resolvable by `op read`/`inject`, so
	/// omitting the flag would misclassify their refs as missing.
	fn flag_refs_with_existing_items(&self, refs: &[BatchRef]) -> Result<Option<Vec<bool>>> {
		use std::collections::HashMap;
		use std::collections::HashSet;

		#[derive(Deserialize)]
		struct ListItem {
			id: String,
			title: String,
		}

		let vaults: HashSet<&str> = refs.iter().map(|r| r.vault.as_str()).collect();
		let mut known: HashMap<&str, (HashSet<String>, HashSet<String>)> = HashMap::new();
		for vault in vaults {
			let output = match self.execute_op_command(
				&[
					"item",
					"list",
					"--vault",
					vault,
					"--include-archive",
					"--format",
					"json",
				],
				None,
			) {
				Ok(output) => output,
				Err(error) if inject_error_is_recoverable(&error) => return Ok(None),
				Err(error) => return Err(error),
			};
			let items: Vec<ListItem> = match serde_json::from_str(&output) {
				Ok(items) => items,
				Err(_) => return Ok(None),
			};
			let mut ids = HashSet::new();
			let mut titles = HashSet::new();
			for entry in items {
				ids.insert(entry.id);
				titles.insert(entry.title.trim().to_lowercase());
			}
			known.insert(vault, (ids, titles));
		}

		Ok(Some(
			refs.iter()
				.map(|r| {
					known.get(r.vault.as_str()).is_some_and(|(ids, titles)| {
						ids.contains(&r.item) || titles.contains(&r.item.trim().to_lowercase())
					})
				})
				.collect(),
		))
	}

	/// Writes a value to the pinned reference via `op item edit` in the given
	/// vault.
	///
	/// The referenced item must already exist: references point at externally
	/// managed items, so the provider never creates one. `op item edit` adds
	/// the field to the item if it is missing.
	fn set_reference(
		&self,
		vault: &str,
		reference: &SecretReference,
		value: &SecretString,
	) -> Result<()> {
		let assignment = format!(
			"{}={}",
			Self::assignment_target(reference),
			value.expose_secret()
		);
		let args = vec![
			"item",
			"edit",
			&reference.item,
			"--vault",
			vault,
			&assignment,
		];
		self.execute_op_command(&args, None)?;
		Ok(())
	}

	/// Builds the internal reference a native address's coordinates describe,
	/// resolving the vault (the address's `vault` overrides the store's
	/// default) and rejecting coordinate combinations 1Password cannot honor.
	/// Without a `field`, the address names a whole item, read like a
	/// convention secret and written through its `value` field.
	///
	/// Takes coordinates already resolved (and therefore validated) by
	/// [`Provider::resolve_coords`].
	fn native_reference(
		&self,
		native: &crate::config::NativeAddress,
	) -> Result<(String, Option<SecretReference>)> {
		let vault = native
			.vault
			.clone()
			.unwrap_or_else(|| self.get_vault_name());
		let reference = if let Some(field) = &native.field {
			Some(SecretReference {
				item: native.item.clone(),
				section: native.section.clone(),
				field: field.clone(),
			})
		} else {
			if native.section.is_some() {
				return Err(MonosecretError::ProviderOperationFailed(
					"onepassword references with a `section` also need a `field`".to_string(),
				));
			}
			None
		};
		Ok((vault, reference))
	}

	/// Reads a whole item by title (or ID) from a vault and extracts its value:
	/// the field labeled "value" first, then password/concealed fields. Shared
	/// by convention reads and whole-item native addresses.
	///
	/// If multiple items share the title, falls back to ID-based lookup for
	/// the first match.
	fn read_item(&self, vault: &str, item_name: &str) -> Result<Option<SecretString>> {
		let args = vec![
			"item", "get", item_name, "--vault", vault, "--format", "json",
		];

		match self.execute_op_command(&args, None) {
			Ok(output) => Self::extract_value_from_item(&output),
			Err(MonosecretError::ProviderOperationFailed(msg)) if msg.contains("isn't an item") => {
				Ok(None)
			}
			Err(MonosecretError::ProviderOperationFailed(msg))
				if msg.contains("More than one item") =>
			{
				// Multiple items with same title - fall back to ID-based lookup
				if let Some(item_id) = self.find_item_id(item_name, vault)? {
					let args = vec![
						"item", "get", &item_id, "--vault", vault, "--format", "json",
					];
					match self.execute_op_command(&args, None) {
						Ok(output) => Self::extract_value_from_item(&output),
						Err(e) => Err(e),
					}
				} else {
					Ok(None)
				}
			}
			Err(e) => Err(e),
		}
	}

	/// Builds the `[section.]field` left-hand side of an `op item edit`
	/// assignment. Periods are structural in `op`'s assignment syntax and get
	/// backslash-escaped so they stay part of the name.
	fn assignment_target(reference: &SecretReference) -> String {
		let escape = |s: &str| s.replace('.', "\\.");
		match &reference.section {
			Some(section) => format!("{}.{}", escape(section), escape(&reference.field)),
			None => escape(&reference.field),
		}
	}

	/// Finds an item by title in the vault and returns its ID.
	///
	/// Uses `op item list` to search for items, which is more reliable than
	/// `op item get` for existence checking because it doesn't fail when
	/// an item exists but has no extractable value.
	///
	/// # Arguments
	///
	/// * `item_name` - The item title to search for
	/// * `vault` - The vault to search in
	///
	/// # Returns
	///
	/// * `Ok(Some(id))` - Item found, returns its ID
	/// * `Ok(None)` - Item not found
	/// * `Err(_)` - Search failed
	fn find_item_id(&self, item_name: &str, vault: &str) -> Result<Option<String>> {
		let args = vec!["item", "list", "--vault", vault, "--format", "json"];

		let output = self.execute_op_command(&args, None)?;

		#[derive(Deserialize)]
		struct ListItem {
			id: String,
			title: String,
		}

		let items: Vec<ListItem> = serde_json::from_str(&output).unwrap_or_default();

		Ok(items
			.into_iter()
			.find(|item| item.title == item_name)
			.map(|item| item.id))
	}

	/// Formats the item name for storage in `OnePassword`.
	///
	/// Creates a hierarchical name using the `folder_prefix` format string.
	/// Supports placeholders: {project}, {profile}, and {key}.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not configured.
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key
	/// * `profile` - The profile name
	///
	/// # Returns
	///
	/// A formatted string based on the configured pattern
	fn format_item_name(&self, project: &str, key: &str, profile: &str) -> String {
		let format_string = self
			.config
			.folder_prefix
			.as_deref()
			.unwrap_or("monosecret/{project}/{profile}/{key}");

		format_string
			.replace("{project}", project)
			.replace("{profile}", profile)
			.replace("{key}", key)
	}

	/// Creates a template for a new `OnePassword` item.
	///
	/// This template is serialized to JSON and used with `op item create`.
	/// The item is created as a Secure Note with structured fields.
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key
	/// * `value` - The secret value
	/// * `profile` - The profile name
	///
	/// # Returns
	///
	/// A `OnePasswordItemTemplate` ready for serialization
	fn create_item_template(
		&self,
		project: &str,
		key: &str,
		value: &SecretString,
		profile: &str,
	) -> OnePasswordItemTemplate {
		OnePasswordItemTemplate {
			title: self.format_item_name(project, key, profile),
			category: "SECURE_NOTE".to_string(),
			fields: vec![
				OnePasswordFieldTemplate {
					label: "project".to_string(),
					field_type: "STRING".to_string(),
					value: project.to_string(),
				},
				OnePasswordFieldTemplate {
					label: "key".to_string(),
					field_type: "STRING".to_string(),
					value: key.to_string(),
				},
				OnePasswordFieldTemplate {
					label: "value".to_string(),
					field_type: "STRING".to_string(),
					value: value.expose_secret().to_string(),
				},
			],
			tags: vec!["automated".to_string(), project.to_string()],
		}
	}

	/// Extracts the secret value from a `OnePassword` item JSON.
	///
	/// Looks for a field labeled "value" first, then falls back to
	/// password or concealed fields.
	fn extract_value_from_item(output: &str) -> Result<Option<SecretString>> {
		let item: OnePasswordItem = serde_json::from_str(output)?;
		Ok(Self::extract_value(&item))
	}

	fn extract_value(item: &OnePasswordItem) -> Option<SecretString> {
		// Look for the "value" field
		for field in &item.fields {
			if field.label.as_deref() == Some("value") {
				return field
					.value
					.as_ref()
					.map(|v| SecretString::new(v.clone().into()));
			}
		}

		// Fallback: look for password field or first concealed field
		for field in &item.fields {
			if field.field_type == "CONCEALED" || field.id == "password" {
				return field
					.value
					.as_ref()
					.map(|v| SecretString::new(v.clone().into()));
			}
		}

		None
	}
}

/// Diagnostic prefixes from `op` that indicate the CLI cannot serve ANY
/// request (authentication/session/account problems, or the service-account
/// rate limit). Matching is case-insensitive, after the `[ERROR]` log prefix
/// and optional timestamp. A batch failure matching one of these must surface
/// immediately: retrying or fanning out per-secret reads would repeat the same
/// failure N times — and while throttled, every one of those failed attempts
/// is itself a billed request that extends the lockout.
const AUTH_ERROR_PATTERNS: &[&str] = &[
	// Verbatim fragments pinned in the Findings Log (Task 1, live `op` 2.35.0 probes).
	// execute_op_command's canned AUTH_REQUIRED_HELP is matched exactly below;
	// the pattern also recognizes the equivalent structured `op` diagnostic.
	"authentication required",
	"authorization prompt",
	"error initializing client",
	// Service-account rate limiting: "Too many requests. Your client has
	// been rate-limited. Try again in <duration> seconds."
	"too many requests",
];

fn inject_error_is_recoverable(error: &MonosecretError) -> bool {
	let MonosecretError::ProviderOperationFailed(message) = error else {
		return true;
	};

	if message == OP_NOT_INSTALLED_HELP || message == AUTH_REQUIRED_HELP {
		return false;
	}

	!message.lines().any(|line| {
		let Some(diagnostic) = op_error_diagnostic(line) else {
			return false;
		};
		let diagnostic = diagnostic.to_ascii_lowercase();
		AUTH_ERROR_PATTERNS
			.iter()
			.any(|pattern| diagnostic.starts_with(pattern))
	})
}

/// Extracts the start of an `op` structured diagnostic without scanning its payload,
/// which may contain user-controlled vault, item, section, or field names.
fn op_error_diagnostic(line: &str) -> Option<&str> {
	let line = line.trim_start();
	let diagnostic = line.strip_prefix("[ERROR]")?.trim_start();

	let mut parts = diagnostic.splitn(3, char::is_whitespace);
	let Some(date) = parts.next() else {
		return Some(diagnostic);
	};
	let Some(time) = parts.next() else {
		return Some(diagnostic);
	};
	let Some(message) = parts.next() else {
		return Some(diagnostic);
	};

	let is_date = date.split('/').count() == 3
		&& date.split('/').all(|component| {
			!component.is_empty() && component.chars().all(|c| c.is_ascii_digit())
		});
	let is_time = time.split(':').count() == 3
		&& time.split(':').all(|component| {
			!component.is_empty() && component.chars().all(|c| c.is_ascii_digit())
		});

	if is_date && is_time {
		Some(message.trim_start())
	} else {
		Some(diagnostic)
	}
}

/// Whether an `op item get` failure reports the item as absent — the same
/// outcome `op read` classifies as a missing reference, resolvable as `None`
/// without further round trips.
fn error_is_missing_item(error: &MonosecretError) -> bool {
	let MonosecretError::ProviderOperationFailed(message) = error else {
		return false;
	};
	message.contains("isn't an item")
}

/// Whether a batch-fetched item is the one a reference addressed: references
/// may name the item by id or by title, and titles compare case-insensitively
/// (mirroring [`Self::flag_refs_with_existing_items`] matching).
fn item_matches_name(item: &OnePasswordItem, name: &str) -> bool {
	if item.id.as_deref().is_some_and(|id| id == name) {
		return true;
	}
	item.title
		.as_deref()
		.is_some_and(|title| title.trim().to_lowercase() == name.trim().to_lowercase())
}

impl OnePasswordProvider {
	/// Checks that the user is authenticated with `OnePassword`.
	/// Called by the preflight guard before any provider operations, which
	/// dedupes the probe across instances via [`Provider::auth_scope_key`].
	pub(crate) fn check_auth(&self) -> Result<()> {
		match self.is_authenticated() {
			Ok(true) => Ok(()),
			Ok(false) => {
				Err(MonosecretError::ProviderOperationFailed(
					AUTH_REQUIRED_HELP.to_string(),
				))
			}
			Err(e) => Err(e),
		}
	}
}

impl Provider for OnePasswordProvider {
	/// Receives the provider's `depends_on` bootstrap secrets. The conventional
	/// `OP_SERVICE_ACCOUNT_TOKEN` names the service account token every `op`
	/// child process authenticates with (see
	/// [`Self::effective_service_account_token`]); without it a `depends_on`
	/// provider would run `op` as whichever account the CLI finds signed in —
	/// or fail with "account is not signed in" in CI — instead of the service
	/// account the spec declared.
	fn configure_dependency_secrets(&self, dependencies: &[(String, SecretString)]) -> Result<()> {
		let mut env = self.dependency_env.lock().map_err(|error| {
			MonosecretError::ProviderOperationFailed(format!(
				"provider dependency delivery failed: {error}"
			))
		})?;
		for (name, value) in dependencies {
			if name == OP_SERVICE_ACCOUNT_TOKEN_ENV {
				env.insert(name.clone(), value.clone());
			}
		}
		Ok(())
	}

	/// Convention items are titled by the folder-prefix format string,
	/// `monosecret/{project}/{profile}/{key}` by default, in the store's
	/// default vault, and read like whole-item references: the `value` field
	/// first, then password/concealed fields.
	fn convention_address(
		&self,
		project: &str,
		profile: &str,
		key: &str,
	) -> Result<crate::config::NativeAddress> {
		Ok(crate::config::NativeAddress {
			item: self.format_item_name(project, key, profile),
			vault: Some(self.get_vault_name()),
			..Default::default()
		})
	}

	/// `vault` overrides the store's default vault, `section`/`field` address a
	/// component within the item. 1Password items are not versioned.
	fn supported_coords(&self) -> &'static [&'static str] {
		&["field", "vault", "section"]
	}

	fn entry_coordinates<'a>(
		&self,
		addr: Address<'a>,
	) -> Result<std::borrow::Cow<'a, crate::config::NativeAddress>> {
		let mut coords = self.operation_coordinates(addr)?;
		if coords.field.is_none() && coords.section.is_none() {
			coords.field = Some("value".to_string());
		}
		Ok(std::borrow::Cow::Owned(coords))
	}

	fn with_credentials(&mut self, credentials: ProviderCredentials) {
		// Stored, not folded into the config: the token is resolved where it is
		// consumed (`execute_op_command`, `auth_scope_key`), and `uri()` keeps
		// reporting the scheme the user actually configured rather than
		// flipping to `onepassword+token://`.
		self.credentials = credentials;
	}

	fn name(&self) -> &'static str {
		Self::PROVIDER_NAME
	}

	/// Auth state is per account/token (and `op` binary), not per provider
	/// instance, so the preflight probe is shared across instances with the
	/// same identity. Pinned secret references produce one instance per
	/// referenced secret; without this, N references would run N identical
	/// `op vault list` round-trips.
	fn auth_scope_key(&self) -> Option<String> {
		// The token actually in effect, so two instances supplied with
		// different tokens never share a preflight probe. Hashed rather than
		// embedded: the scope key lives in a process-lifetime cache, and a
		// sourced token is kept as a `SecretString` precisely so its
		// plaintext never sits in long-lived memory.
		use std::hash::Hash;
		use std::hash::Hasher;
		let mut hasher = std::collections::hash_map::DefaultHasher::new();
		self.effective_service_account_token().hash(&mut hasher);
		let token_scope = hasher.finish();
		Some(format!(
			"{:?}",
			(&self.config.account, token_scope, &self.op_command)
		))
	}

	fn uri(&self) -> String {
		// Reconstruct the URI from the config
		// Format: onepassword://[account@]vault or onepassword+token://vault

		let scheme = if self.config.service_account_token.is_some() {
			"onepassword+token"
		} else {
			"onepassword"
		};

		let mut uri = format!("{scheme}://");

		// A configured service account token (from a provider credential or the
		// environment) selects the scheme but is never written into the URI.
		if self.config.service_account_token.is_some() {
			// Just indicate token auth is being used without exposing the token
			if let Some(ref vault) = self.config.default_vault {
				uri.push_str(&ProviderUrl::encode(vault));
			}
		} else {
			// Regular auth: account@vault format
			if let Some(ref account) = self.config.account {
				uri.push_str(&ProviderUrl::encode(account));
				uri.push('@');
			}

			if let Some(ref vault) = self.config.default_vault {
				uri.push_str(&ProviderUrl::encode(vault));
			}
		}

		uri
	}

	/// The vault is part of the resolved entry coordinates, not the account
	/// container identity. Omitting it here lets an explicit `ref.vault`
	/// override two aliases with different URI defaults.
	fn entry_container_identity(&self) -> String {
		match &self.config.account {
			Some(account) => format!("onepassword://{}@", ProviderUrl::encode(account)),
			None => "onepassword://".to_string(),
		}
	}

	/// Retrieves a secret from `OnePassword`.
	///
	/// If multiple items exist with the same title, falls back to ID-based
	/// lookup to retrieve the first matching item.
	///
	/// # Returns
	///
	/// * `Ok(Some(value))` - The secret value if found
	/// * `Ok(None)` - No secret found at the address
	/// * `Err(_)` - Authentication or retrieval error
	fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
		let coords = self.operation_coordinates(addr)?;
		let (vault, reference) = self.native_reference(&coords)?;
		match reference {
			// A field-addressed reference goes through `op read`.
			Some(reference) => self.read_reference(&vault, &reference),
			// A whole-item address (every convention secret, and field-less
			// refs) reads via the value/password field extraction of
			// `op item get`.
			None => self.read_item(&vault, &coords.item),
		}
	}

	/// Stores or updates a secret in `OnePassword`.
	///
	/// If an item with the same title exists, it updates the "value" field.
	/// Otherwise, it creates a new Secure Note item with the secret data.
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key
	/// * `value` - The secret value to store
	/// * `profile` - The profile to use for vault selection
	///
	/// # Returns
	///
	/// * `Ok(())` - Secret stored successfully
	/// * `Err(_)` - Storage or authentication error
	///
	/// # Errors
	///
	/// - Authentication required if not signed in
	/// - Item creation/update failures
	/// - Temporary file creation errors
	fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
		let (project, profile, key) = match addr {
			Address::Native(native) => {
				let coords = self.entry_coordinates(addr)?;
				let (vault, reference) = self.native_reference(&coords)?;
				// Writes through a native address go to the existing item in
				// place (`op item edit` adds a missing field but never creates
				// an item): a whole-item address writes its `value` field, the
				// same field convention reads extract first.
				let reference = reference.unwrap_or_else(|| {
					SecretReference {
						item: native.item.clone(),
						section: None,
						field: "value".to_string(),
					}
				});
				return self.set_reference(&vault, &reference, value);
			}
			Address::Convention {
				project,
				profile,
				key,
			} => (project, profile, key),
		};
		let vault = self.get_vault_name();
		let item_name = self.format_item_name(project, key, profile);

		// Check if item exists by listing items (more reliable than get which requires
		// a readable value). This prevents creating duplicates when an item exists
		// but has no extractable value field.
		if let Some(item_id) = self.find_item_id(&item_name, &vault)? {
			// Item exists, update it by ID to avoid "more than one item" ambiguity
			let field_assignment = format!("value={}", value.expose_secret());
			let args = vec![
				"item",
				"edit",
				&item_id,
				"--vault",
				&vault,
				&field_assignment,
			];

			self.execute_op_command(&args, None)?;
		} else {
			// Item doesn't exist, create it
			let template = self.create_item_template(project, key, value, profile);
			let template_json = serde_json::to_string(&template)?;

			let args = vec!["item", "create", "--vault", &vault, "-"];

			self.execute_op_command(&args, Some(&template_json))?;
		}

		Ok(())
	}

	/// Retrieves multiple secrets from `OnePassword` in a single batch operation.
	///
	/// Whole-item addresses (every convention secret, and field-less refs)
	/// are served from one item listing plus one batched `op item get` call per
	/// vault. Multiple field-addressed refs are served from one batched
	/// `op item get` per vault — one billed read per referenced item, however
	/// many fields it carries — with the original `op inject` path (and
	/// per-secret reads) retained as the correctness fallback.
	fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
		if requests.is_empty() {
			return Ok(HashMap::new());
		}

		// Whole-item requests as (request name, item title), grouped by vault.
		let mut whole_items: HashMap<String, Vec<(String, String)>> = HashMap::new();
		// Field references retain first-seen order while the index deduplicates
		// identical physical addresses and records every request name to fan out.
		let mut field_ref_indices: HashMap<String, usize> = HashMap::new();
		let mut field_refs: Vec<(BatchRef, Vec<String>)> = Vec::new();
		for (name, addr) in requests {
			let coords = self.operation_coordinates(*addr)?;
			let (vault, reference) = self.native_reference(&coords)?;
			match reference {
				Some(reference) => {
					let reference_uri = Self::reference_uri(&vault, &reference);
					if let Some(index) = field_ref_indices.get(&reference_uri) {
						field_refs
							.get_mut(*index)
							.expect("index was inserted for this uri")
							.1
							.push(name.to_string());
					} else {
						field_ref_indices.insert(reference_uri.clone(), field_refs.len());
						let batch_ref = BatchRef {
							uri: reference_uri,
							vault: vault.clone(),
							item: reference.item.clone(),
							section: reference.section.clone(),
							field: reference.field.clone(),
						};
						field_refs.push((batch_ref, vec![name.to_string()]));
					}
				}
				None => {
					whole_items
						.entry(vault)
						.or_default()
						.push((name.to_string(), coords.item.clone()));
				}
			}
		}

		let mut results = HashMap::new();
		for (vault, items) in whole_items {
			results.extend(self.get_items_batch(&vault, items)?);
		}

		let refs: Vec<BatchRef> = field_refs.iter().map(|(r, _)| r.clone()).collect();
		let values = self.read_reference_uris(&refs)?;
		for ((_, names), value) in field_refs.into_iter().zip(values) {
			if let Some(value) = value {
				for name in names {
					results.insert(name, value.clone());
				}
			}
		}

		Ok(results)
	}
}

impl OnePasswordProvider {
	/// Fetches the given `(request name, item title)` pairs from one vault:
	/// lists the vault once to resolve titles to ids, then pipes every matching
	/// id through one `op item get` process and extracts each value/password
	/// field from the returned JSON stream.
	fn get_items_batch(
		&self,
		vault: &str,
		items: Vec<(String, String)>,
	) -> Result<HashMap<String, SecretString>> {
		// List all items in the vault once
		let args = vec!["item", "list", "--vault", vault, "--format", "json"];
		let output = self.execute_op_command(&args, None)?;

		#[derive(Deserialize)]
		struct ListItem {
			id: String,
			title: String,
		}

		let listed: Vec<ListItem> = serde_json::from_str(&output).unwrap_or_default();

		// Build a map of item titles to IDs for quick lookup
		let item_map: HashMap<String, String> = listed
			.into_iter()
			.map(|item| (item.title, item.id))
			.collect();

		// Find which titles exist and need to be fetched. Multiple request names
		// may resolve to one physical item, so fetch each id once and fan its
		// value back out afterwards.
		let mut fetch_indices: HashMap<String, usize> = HashMap::new();
		let mut to_fetch: Vec<(String, Vec<String>)> = Vec::new();
		for (name, title) in items {
			let Some(item_id) = item_map.get(&title) else {
				continue;
			};
			if let Some(index) = fetch_indices.get(item_id) {
				to_fetch
					.get_mut(*index)
					.expect("index was inserted for this item")
					.1
					.push(name);
			} else {
				fetch_indices.insert(item_id.clone(), to_fetch.len());
				to_fetch.push((item_id.clone(), vec![name]));
			}
		}

		if to_fetch.is_empty() {
			return Ok(HashMap::new());
		}

		// `op item get` treats each stdin line as an item specifier and emits
		// one JSON document per item. Do not pass `-`: current CLI versions can
		// interpret it as an additional literal item. This keeps desktop-app
		// authentication to one connection instead of spawning one `op`
		// process per secret.
		let mut input = to_fetch
			.iter()
			.map(|(item_id, _)| item_id.as_str())
			.collect::<Vec<_>>()
			.join("\n");
		input.push('\n');
		let output = self.execute_op_command(
			&["item", "get", "--vault", vault, "--format", "json"],
			Some(&input),
		)?;

		let fetched: Vec<OnePasswordItem> = Self::parse_item_documents(&output)?;

		let expected_count = to_fetch.len();
		let mut names_by_id: HashMap<String, Vec<String>> = to_fetch.into_iter().collect();

		let mut results = HashMap::new();
		for item in fetched {
			let item_id = item.id.as_deref().ok_or_else(|| {
				MonosecretError::ProviderOperationFailed(
					"1Password CLI batch response omitted an item ID".to_string(),
				)
			})?;
			let names = names_by_id.remove(item_id).ok_or_else(|| {
				MonosecretError::ProviderOperationFailed(
					"1Password CLI batch response contained an unexpected item".to_string(),
				)
			})?;
			if let Some(value) = Self::extract_value(&item) {
				for name in names {
					results.insert(name, value.clone());
				}
			}
		}

		if !names_by_id.is_empty() {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"1Password CLI returned {} of {expected_count} requested items",
				expected_count - names_by_id.len()
			)));
		}

		Ok(results)
	}
}

impl Default for OnePasswordProvider {
	/// Creates a `OnePasswordProvider` with default configuration.
	///
	/// Uses interactive authentication and the "Private" vault by default.
	fn default() -> Self {
		Self::new(OnePasswordConfig::default())
	}
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // test fixtures: indexing is the assertion
mod tests {
	use url::Url;

	use super::*;

	fn config(s: &str) -> OnePasswordConfig {
		OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
	}

	#[test]
	fn try_from_parses_account_and_vault() {
		let c = config("onepassword://work@Production");
		assert_eq!(c.account.as_deref(), Some("work"));
		assert_eq!(c.default_vault.as_deref(), Some("Production"));
		assert_eq!(c.service_account_token, None);
	}

	#[test]
	fn try_from_parses_vault_only() {
		let c = config("onepassword://Production");
		assert_eq!(c.account, None);
		assert_eq!(c.default_vault.as_deref(), Some("Production"));
	}

	#[test]
	fn op_token_uri_parses_vault_and_reference_base_path() {
		let c = config("op+token://Development/Dotfiles");
		assert_eq!(c.account, None);
		assert_eq!(c.default_vault.as_deref(), Some("Development"));
		assert_eq!(c.reference_base_path, vec!["Dotfiles"]);
		// A multi-segment base path is preserved as the shared item path.
		let nested = config("op+token://Development/Shared/team");
		assert_eq!(nested.reference_base_path, vec!["Shared", "team"]);
	}

	#[test]
	fn op_token_uri_rejects_a_token_in_the_uri() {
		let err = OnePasswordConfig::try_from(&ProviderUrl::new(
			Url::parse("op+token://acct:ops_tok@Development/Dotfiles").unwrap(),
		))
		.unwrap_err();
		let msg = format!("{err}");
		assert!(
			msg.contains("no longer accepts the service account token in the URI"),
			"expected a token-in-URI refusal, got: {msg}"
		);
	}

	#[test]
	fn op_token_reference_base_path_folds_item_into_section() {
		let provider = OnePasswordProvider::new(config("op+token://Development/Dotfiles"));
		let address = Address::Native(&crate::config::NativeAddress {
			item: "ai".to_string(),
			field: Some("OPENAI_API_KEY".to_string()),
			..Default::default()
		});
		let coords = provider.operation_coordinates(address).unwrap();
		assert_eq!(coords.item, "Dotfiles");
		assert_eq!(coords.section.as_deref(), Some("ai"));
		assert_eq!(coords.field.as_deref(), Some("OPENAI_API_KEY"));
		assert_eq!(coords.vault.as_deref(), Some("Development"));
	}

	#[test]
	fn op_token_reference_base_path_is_a_noop_when_unset() {
		let provider = OnePasswordProvider::new(config("onepassword://Development"));
		let address = Address::Native(&crate::config::NativeAddress {
			item: "ai".to_string(),
			field: Some("OPENAI_API_KEY".to_string()),
			..Default::default()
		});
		let coords = provider.operation_coordinates(address).unwrap();
		assert_eq!(coords.item, "ai");
		assert_eq!(coords.section, None);
		assert_eq!(coords.vault.as_deref(), Some("Development"));
	}

	#[test]
	fn same_entries_treats_an_implicit_vault_as_the_configured_default() {
		let provider = OnePasswordProvider::new(config("onepassword://Production"));
		let implicit = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let explicit = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("credential".to_string()),
			vault: Some("Production".to_string()),
			..Default::default()
		};

		assert!(
			provider
				.same_entries(
					Address::Native(&implicit),
					&provider,
					Address::Native(&explicit),
				)
				.unwrap(),
			"addresses that operations send to one 1Password field must compare equal"
		);
	}

	#[test]
	fn same_entries_treats_an_implicit_field_as_the_value_field() {
		let provider = OnePasswordProvider::new(config("onepassword://Production"));
		let implicit = crate::config::NativeAddress {
			item: "API Key".to_string(),
			..Default::default()
		};
		let explicit = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("value".to_string()),
			..Default::default()
		};

		assert!(
			provider
				.same_entries(
					Address::Native(&implicit),
					&provider,
					Address::Native(&explicit),
				)
				.unwrap()
		);
	}

	#[test]
	fn same_entries_uses_explicit_vaults_instead_of_provider_defaults() {
		let production = OnePasswordProvider::new(config("onepassword://work@Production"));
		let development = OnePasswordProvider::new(config("onepassword://work@Development"));
		let address = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("credential".to_string()),
			vault: Some("Shared".to_string()),
			..Default::default()
		};

		assert!(
			production
				.same_entries(
					Address::Native(&address),
					&development,
					Address::Native(&address),
				)
				.unwrap()
		);
	}

	/// Both userinfo spellings the token scheme used to accept are now refused,
	/// through the real construction path, in an error that says where the token
	/// belongs instead and never repeats the token back.
	///
	/// The two spellings are refused by different checks — the password position
	/// by the shared URI gate, the username position by this provider — so both
	/// are exercised end to end rather than against this module's `try_from`.
	#[test]
	fn try_from_token_scheme_rejects_a_token_in_the_uri() {
		for source in [
			"onepassword+token://ops_tok@Private",
			"onepassword+token://acct:ops_tok@Private",
		] {
			let Err(error) = Box::<dyn Provider>::try_from(source) else {
				panic!("{source} was accepted");
			};
			let message = error.to_string();
			assert!(
				message.contains("service_account_token"),
				"{source}: {message}"
			);
			assert!(!message.contains("ops_tok"), "{source}: {message}");
		}

		// The documented single-token form additionally names the environment
		// fallback and how to keep the scheme.
		let message = config_err("onepassword+token://ops_tok@Private").to_string();
		assert!(message.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{message}");
		assert!(message.contains("onepassword+token://<vault>"), "{message}");
	}

	/// The scheme itself still selects service account authentication; only the
	/// embedded token is gone.
	#[test]
	fn try_from_token_scheme_without_a_token_selects_the_vault() {
		let c = config("onepassword+token://Private");
		assert_eq!(c.default_vault.as_deref(), Some("Private"));
		assert_eq!(c.service_account_token, None);
		assert_eq!(c.account, None);
	}

	#[test]
	fn try_from_ignores_localhost_host() {
		let c = config("onepassword://localhost");
		assert_eq!(c.default_vault, None);
		assert_eq!(c.account, None);
	}

	// Note: the `"1password"` guard arm in `try_from` is effectively unreachable
	// via ProviderUrl, because `Url::parse` rejects schemes that start with a
	// digit (RFC 3986). It therefore cannot be exercised through a real URL.

	#[test]
	fn try_from_rejects_unknown_scheme() {
		let err =
			OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse("keyring://vault").unwrap()))
				.unwrap_err();
		assert!(err.to_string().contains("Invalid scheme"));
	}

	#[test]
	fn get_vault_name_defaults_to_private() {
		let default = OnePasswordProvider::new(OnePasswordConfig::default());
		assert_eq!(default.get_vault_name(), "Private");

		let configured = OnePasswordProvider::new(config("onepassword://Production"));
		assert_eq!(configured.get_vault_name(), "Production");
	}

	#[test]
	fn format_item_name_default_and_custom() {
		let default = OnePasswordProvider::new(OnePasswordConfig::default());
		assert_eq!(
			default.format_item_name("proj", "KEY", "prod"),
			"monosecret/proj/prod/KEY"
		);

		let custom = OnePasswordProvider::new(OnePasswordConfig {
			folder_prefix: Some("{project}-{key}".to_string()),
			..Default::default()
		});
		assert_eq!(custom.format_item_name("proj", "KEY", "prod"), "proj-KEY");
	}

	#[test]
	fn uri_for_account_round_trips() {
		let provider = OnePasswordProvider::new(config("onepassword://work@Production"));
		assert_eq!(provider.uri(), "onepassword://work@Production");
	}

	#[test]
	fn uri_for_token_does_not_leak_secret() {
		// The token now reaches the config from a provider credential or the
		// environment rather than the URI, and still must not resurface in the
		// `uri()` the audit log persists.
		let mut config = config("onepassword+token://Private");
		config.service_account_token = Some("ops_secret_tok".to_string());
		let provider = OnePasswordProvider::new(config);
		let uri = provider.uri();
		assert_eq!(uri, "onepassword+token://Private");
		assert!(!uri.contains("ops_secret_tok"));
	}

	fn config_err(s: &str) -> MonosecretError {
		OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap_err()
	}

	/// Every URI shape that used to be an instance-level reference now errors
	/// with a pointer at the `ref` table.
	#[test]
	fn item_paths_are_rejected_with_ref_hint() {
		// A full reference gets the exact translation.
		let err = config_err("op://Infra/db/password");
		assert!(
			err.to_string()
				.contains("ref = { vault = \"Infra\", item = \"db\", field = \"password\" }"),
			"{err}"
		);

		// A bare op:// with no path still points at `ref`.
		let err = config_err("op://Infra");
		assert!(
			err.to_string().contains("addressed with a secret's `ref`"),
			"{err}"
		);

		// Odd shapes (single segment, too deep) get the generic pointer.
		let err = config_err("onepassword://vault/Production");
		assert!(
			err.to_string().contains("addressed with a secret's `ref`"),
			"{err}"
		);
		let err = config_err("op://Infra/a/b/c/d");
		assert!(
			err.to_string().contains("addressed with a secret's `ref`"),
			"{err}"
		);
	}

	#[test]
	fn assignment_target_escapes_dots() {
		let reference = SecretReference {
			item: "db".to_string(),
			section: Some("api.keys".to_string()),
			field: "connection.url".to_string(),
		};
		assert_eq!(
			OnePasswordProvider::assignment_target(&reference),
			"api\\.keys.connection\\.url"
		);

		let reference = SecretReference {
			section: None,
			..reference
		};
		assert_eq!(
			OnePasswordProvider::assignment_target(&reference),
			"connection\\.url"
		);
	}

	#[test]
	fn pasted_reference_hint_preserves_spaces() {
		// Spaces in vault and item names must survive into the translation
		// hint, since users paste references straight from the 1Password app.
		let Err(err) = Box::<dyn Provider>::try_from("op://Prod Vault/My Item/field") else {
			panic!("op:// provider spec must be rejected");
		};
		assert!(
			err.to_string().contains(
				"ref = { vault = \"Prod Vault\", item = \"My Item\", field = \"field\" }"
			),
			"{err}"
		);
	}

	/// A native address maps its coordinates onto the internal reference: the
	/// `vault` key overrides the store's default vault, `section` and `field`
	/// carry through.
	#[test]
	fn native_address_maps_coordinates_with_vault_override() {
		let provider = OnePasswordProvider::new(config("onepassword://Personal"));
		let addr = crate::config::NativeAddress {
			item: "db".into(),
			field: Some("password".into()),
			section: Some("api".into()),
			vault: Some("Production".into()),
			..Default::default()
		};
		let (vault, reference) = provider.native_reference(&addr).unwrap();
		assert_eq!(vault, "Production");
		let reference = reference.expect("field-addressed reference");
		assert_eq!(
			OnePasswordProvider::reference_uri(&vault, &reference),
			"op://Production/db/api/password"
		);
	}

	/// Without a `vault` key, the store URI's vault applies.
	#[test]
	fn native_address_vault_defaults_to_store_vault() {
		let provider = OnePasswordProvider::new(config("onepassword://Personal"));
		let addr = crate::config::NativeAddress {
			item: "db".into(),
			field: Some("password".into()),
			..Default::default()
		};
		let (vault, _) = provider.native_reference(&addr).unwrap();
		assert_eq!(vault, "Personal");
	}

	/// A whole-item address (no `field`) resolves to no internal reference:
	/// reads go through the convention item extraction.
	#[test]
	fn native_address_without_field_names_the_whole_item() {
		let provider = OnePasswordProvider::new(config("onepassword://Personal"));
		let addr = crate::config::NativeAddress {
			item: "My API Item".into(),
			..Default::default()
		};
		let (_, reference) = provider.native_reference(&addr).unwrap();
		assert!(reference.is_none());
	}

	/// 1Password items are not versioned; the coordinate is rejected.
	#[test]
	fn native_address_rejects_version() {
		let provider = OnePasswordProvider::new(config("onepassword://Personal"));
		let addr = crate::config::NativeAddress {
			item: "db".into(),
			version: Some("3".into()),
			..Default::default()
		};
		let err = provider.resolve_coords(Address::Native(&addr)).unwrap_err();
		assert!(err.to_string().contains("`version`"), "{err}");
	}

	/// A `section` only makes sense when addressing a `field` within it.
	#[test]
	fn native_address_section_requires_field() {
		let provider = OnePasswordProvider::new(config("onepassword://Personal"));
		let addr = crate::config::NativeAddress {
			item: "db".into(),
			section: Some("api".into()),
			..Default::default()
		};
		let err = provider.native_reference(&addr).unwrap_err();
		assert!(err.to_string().contains("need a `field`"), "{err}");
	}

	fn command_args(command: &Command) -> Vec<String> {
		command
			.get_args()
			.map(|arg| arg.to_string_lossy().into_owned())
			.collect()
	}

	fn command_envs(command: &Command) -> Vec<(String, String)> {
		command
			.get_envs()
			.filter_map(|(key, value)| {
				value.map(|value| {
					(
						key.to_string_lossy().into_owned(),
						value.to_string_lossy().into_owned(),
					)
				})
			})
			.collect()
	}

	/// A `depends_on`-delivered `OP_SERVICE_ACCOUNT_TOKEN` must reach every
	/// `op` child process. Dropping it (the pre-0.3.3 behavior) runs `op` as
	/// whichever account the CLI finds signed in, so a service-account setup
	/// fails with "<vault> isn't a vault in this account" or "account is not
	/// signed in" even though resolution itself succeeded.
	#[test]
	fn dependency_token_is_exported_to_op_children() {
		let mut provider = OnePasswordProvider::new(config("op+token://Development/Dotfiles"));
		provider
			.configure_dependency_secrets(&[
				("IGNORED".into(), SecretString::new("ignored".into())),
				(
					"OP_SERVICE_ACCOUNT_TOKEN".into(),
					SecretString::new("dependency-token".into()),
				),
			])
			.unwrap();

		let observed_env = std::sync::Arc::new(Mutex::new(Vec::new()));
		let observed = std::sync::Arc::clone(&observed_env);
		provider.command_override = Some(std::sync::Arc::new(move |command, _stdin| {
			observed.lock().unwrap().extend(command_envs(command));
			let args = command_args(command);
			match args.first().map(String::as_str) {
				// Whole-field reads resolve through `op read op://...`.
				Some("read") => Ok("secret".to_string()),
				_ => Ok(r#"[{"id":"item-id","title":"Dotfiles","fields":[{"id":"password","value":"secret","label":"password"}]}]"#.to_string()),
			}
		}));

		let addr = crate::config::NativeAddress {
			item: "Dotfiles".into(),
			field: Some("password".into()),
			..Default::default()
		};
		let value = provider
			.get(Address::Native(&addr))
			.unwrap()
			.expect("stub returns the item");
		assert_eq!(value.expose_secret(), "secret");

		let envs = observed_env.lock().unwrap();
		assert!(
			envs.iter().any(|(key, value)| {
				key == "OP_SERVICE_ACCOUNT_TOKEN" && value == "dependency-token"
			}),
			"the dependency token must be exported to every op child: {envs:?}"
		);
	}

	/// An explicitly supplied provider credential outranks the `depends_on`
	/// one, so a deliberate configuration can never be silently overridden by
	/// the bootstrap secret.
	#[test]
	fn credential_service_token_outranks_dependency_token() {
		let config = OnePasswordConfig {
			service_account_token: Some("credential-token".to_string()),
			..OnePasswordConfig::default()
		};
		let provider = OnePasswordProvider::new(config);
		provider
			.configure_dependency_secrets(&[(
				"OP_SERVICE_ACCOUNT_TOKEN".into(),
				SecretString::new("dependency-token".into()),
			)])
			.unwrap();

		assert_eq!(
			provider.effective_service_account_token().as_deref(),
			Some("credential-token"),
		);
	}

	#[test]
	fn dependency_token_outranks_ambient_environment() {
		let _guard = crate::tests::EnvVarGuard::set("OP_SERVICE_ACCOUNT_TOKEN", "ambient-token");
		let provider = OnePasswordProvider::new(config("op+token://Development/Dotfiles"));
		provider
			.configure_dependency_secrets(&[(
				"OP_SERVICE_ACCOUNT_TOKEN".into(),
				SecretString::new("dependency-token".into()),
			)])
			.unwrap();

		assert_eq!(
			provider.effective_service_account_token().as_deref(),
			Some("dependency-token"),
		);
	}

	fn framed_output(template: &InjectTemplate, values: &[&str]) -> String {
		let mut output = String::new();
		for ((start, end), value) in template.frames.iter().zip(values) {
			output.push_str(start);
			output.push_str(value);
			output.push_str(end);
		}
		output
	}

	fn secret_matches(results: &HashMap<String, SecretString>, name: &str, expected: &str) -> bool {
		results
			.get(name)
			.is_some_and(|value| value.expose_secret() == expected)
	}

	#[test]
	fn inject_template_round_trips_arbitrary_utf8_values() {
		let references: Vec<String> = (0..7)
			.map(|index| format!("op://vault/item/{index}"))
			.collect();
		let template = InjectTemplate::new(&references, "deterministic-nonce");
		let values = [
			"contains=equals",
			"\"quoted\"",
			r"back\slash",
			"Zażółć gęślą jaźń 🔐",
			"",
			" spaces stay ",
			"first line\nsecond line\nthird line",
		];

		for reference in &references {
			let expression = format!("{{{{ {reference} }}}}");
			assert_eq!(template.input.matches(&expression).count(), 1);
		}
		assert!(
			values
				.iter()
				.filter(|value| !value.is_empty())
				.all(|value| !template.input.contains(value))
		);

		let parsed = template.parse(&framed_output(&template, &values)).unwrap();
		assert!(
			parsed
				.iter()
				.zip(values)
				.all(|(actual, expected)| actual == expected)
		);
	}

	#[test]
	fn inject_parser_accepts_cli_trailing_newline_without_trimming_values() {
		let references = vec!["op://vault/item/one".to_string()];
		let template = InjectTemplate::new(&references, "deterministic-nonce");
		let value = " secret whitespace stays \n";
		let output = format!("{}\n", framed_output(&template, &[value]));

		assert_eq!(template.parse(&output).unwrap(), [value]);
	}

	#[test]
	fn inject_parser_rejects_malformed_output_without_echoing_it() {
		let references = vec![
			"op://vault/item/one".to_string(),
			"op://vault/item/two".to_string(),
		];
		let template = InjectTemplate::new(&references, "deterministic-nonce");
		let valid = framed_output(&template, &["first", "second"]);
		let (first_start, first_end) = &template.frames[0];
		let (second_start, second_end) = &template.frames[1];
		let sensitive = "DO_NOT_ECHO_PLAINTEXT";
		let malformed = [
			valid.trim_end_matches(second_end).to_string(),
			format!("{valid}{first_start}{first_end}"),
			format!("{second_start}second{second_end}{first_start}first{first_end}"),
			format!("unexpected{valid}"),
			format!("{valid}\n\n"),
			format!("{valid} \n"),
			format!(
				"{first_start}{sensitive}{first_end}{first_end}{second_start}second{second_end}"
			),
		];

		for output in malformed {
			let error = template.parse(&output).unwrap_err().to_string();
			assert_eq!(
				error,
				"Provider operation failed: 1Password CLI returned malformed output from 'op inject'"
			);
			assert!(!error.contains(sensitive));
			assert!(!error.contains(&output));
		}
	}

	#[test]
	fn field_refs_resolve_from_one_item_get_per_vault() {
		use std::sync::Arc;
		use std::sync::Mutex;

		#[derive(Debug)]
		struct ObservedCall {
			args: Vec<String>,
			stdin: Option<String>,
			token_is_set: bool,
		}

		let calls = Arc::new(Mutex::new(Vec::<ObservedCall>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(OnePasswordConfig {
			account: Some("work".to_string()),
			default_vault: Some("Personal Vault".to_string()),
			service_account_token: Some("ops_test_token".to_string()),
			..Default::default()
		});
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let token_is_set = command.get_envs().any(|(key, value)| {
				key == OP_SERVICE_ACCOUNT_TOKEN_ENV
					&& value.is_some_and(|value| value == "ops_test_token")
			});
			let stdin = stdin.map(str::to_string);
			observed.lock().unwrap().push(ObservedCall {
				args: args.clone(),
				stdin: stdin.clone(),
				token_is_set,
			});
			let words: Vec<&str> = args.iter().map(String::as_str).collect();
			match words.as_slice() {
				[
					"--account",
					"work",
					"item",
					"get",
					"--vault",
					"Personal Vault",
					"--format",
					"json",
				] => {
					assert_eq!(stdin.as_deref(), Some("API Key\n"));
					Ok(serde_json::json!([{
						"id": "api-key-id",
						"title": "API Key",
						"fields": [{
							"id": "password",
							"type": "STRING",
							"label": "password",
							"value": "first=\"value\"\\with\nlines 🔐",
						}],
					}])
					.to_string())
				}
				[
					"--account",
					"work",
					"item",
					"get",
					"--vault",
					"Prod Vault",
					"--format",
					"json",
				] => {
					assert_eq!(stdin.as_deref(), Some("Database\n"));
					Ok(serde_json::json!([{
						"id": "database-id",
						"title": "Database",
						"sections": [{"id": "s-1", "label": "API Section"}],
						"fields": [{
							"id": "client secret",
							"type": "STRING",
							"label": "client secret",
							"value": "",
							"section": {"id": "s-1"},
						}],
					}])
					.to_string())
				}
				other => unreachable!("unexpected mocked command: {other:?}"),
			}
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let duplicate = first.clone();
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			section: Some("API Section".to_string()),
			field: Some("client secret".to_string()),
			vault: Some("Prod Vault".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("FIRST_COPY", Address::Native(&duplicate)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(
			calls.len(),
			2,
			"one batched item get per vault, however many references share the item"
		);
		assert_eq!(
			calls[0].args,
			[
				"--account",
				"work",
				"item",
				"get",
				"--vault",
				"Personal Vault",
				"--format",
				"json"
			]
		);
		assert!(calls[0].token_is_set);
		assert_eq!(
			calls[0].stdin.as_deref(),
			Some("API Key\n"),
			"the batch carries the item name exactly once"
		);
		assert_eq!(
			calls[1].args,
			[
				"--account",
				"work",
				"item",
				"get",
				"--vault",
				"Prod Vault",
				"--format",
				"json"
			]
		);
		assert!(secret_matches(
			&results,
			"FIRST",
			"first=\"value\"\\with\nlines 🔐"
		));
		assert!(secret_matches(
			&results,
			"FIRST_COPY",
			"first=\"value\"\\with\nlines 🔐"
		));
		assert!(secret_matches(&results, "SECOND", ""));
	}

	/// The dotfiles shape: a whole profile's secrets pinned as sectioned
	/// references to one shared item cost exactly one item read, not one per
	/// secret (`op inject` resolves each reference as an individually billed
	/// read against the service-account rate limits).
	#[test]
	fn shared_item_manifest_costs_one_item_get() {
		use std::sync::Arc;
		use std::sync::Mutex;

		// (secret name, section path, field) mirroring
		// `op+token://Development/Dotfiles` with `path = [...]` providers.
		let manifest: Vec<(&str, &str, &str)> = vec![
			("GITHUB_TOKEN", "forges", "GITHUB_TOKEN"),
			("NIX_GITHUB_TOKEN", "nix", "GITHUB_TOKEN"),
			("GOOGLE_API_KEY", "google", "GOOGLE_API_KEY"),
			("OPENAI_API_KEY", "ai", "OPENAI_API_KEY"),
			("OLLAMA_CLOUD_API_KEY", "ai", "OLLAMA_CLOUD_API_KEY"),
			("HUGGING_FACE_TOKEN", "ai", "HUGGING_FACE_TOKEN"),
			("XIAOMI_MIMO_API_KEY", "ai", "XIAOMI_MIMO_API_KEY"),
			("PULUMI_TOKEN", "infra", "PULUMI_TOKEN"),
			("NPM_TOKEN", "registries", "NPM_TOKEN"),
			("CARGO_REGISTRY_TOKEN", "registries", "CARGO_REGISTRY_TOKEN"),
			("FLAKEHUB_TOKEN", "registries", "FLAKEHUB_TOKEN"),
			("DISCORD_CLIENT_ID", "discord", "DISCORD_CLIENT_ID"),
			("DISCORD_CLIENT_SECRET", "discord", "DISCORD_CLIENT_SECRET"),
			("BACKBLAZE_KEY_ID", "backblaze", "BACKBLAZE_KEY_ID"),
			("BACKBLAZE_KEY_NAME", "backblaze", "BACKBLAZE_KEY_NAME"),
			(
				"BACKBLAZE_APPLICATION_KEY",
				"backblaze",
				"BACKBLAZE_APPLICATION_KEY",
			),
		];

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let stubbed_manifest = manifest.clone();
		let mut provider = OnePasswordProvider::new(config("op+token://Development/Dotfiles"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			observed
				.lock()
				.unwrap()
				.push((args.clone(), stdin.map(str::to_string)));
			assert_eq!(
				args,
				["item", "get", "--vault", "Development", "--format", "json"]
			);
			assert_eq!(stdin.expect("batched item names on stdin"), "Dotfiles\n");
			let section_fields: Vec<serde_json::Value> = stubbed_manifest
				.iter()
				.map(|(_name, section, field)| {
					serde_json::json!({
						"id": field,
						"type": "CONCEALED",
						"label": field,
						"value": format!("value-for-{field}"),
						"section": {"id": section},
					})
				})
				.collect();
			let sections: Vec<serde_json::Value> = stubbed_manifest
				.iter()
				.map(
					|(_name, section, _field)| serde_json::json!({"id": section, "label": section}),
				)
				.collect();
			Ok(serde_json::json!([{
				"id": "dotfiles-id",
				"title": "Dotfiles",
				"sections": sections,
				"fields": section_fields,
			}])
			.to_string())
		}));

		let addresses: Vec<crate::config::NativeAddress> = manifest
			.iter()
			.map(|(_name, section, field)| {
				crate::config::NativeAddress {
					// Under `op+token://Development/Dotfiles`, the address's item
					// is folded into a section of the shared Dotfiles item (see
					// `apply_reference_base_path`).
					item: (*section).to_string(),
					field: Some((*field).to_string()),
					..Default::default()
				}
			})
			.collect();
		let requests: Vec<(&str, Address<'_>)> = manifest
			.iter()
			.zip(&addresses)
			.map(|((name, ..), address)| (*name, Address::Native(address)))
			.collect();

		let results = provider.get_many(&requests).unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(
			calls.len(),
			1,
			"every sectioned reference to one shared item must cost a single item read"
		);
		for (name, _section, field) in &manifest {
			assert!(
				secret_matches(&results, name, &format!("value-for-{field}")),
				"{name} must resolve from the shared item read"
			);
		}
	}

	/// A field the shared item does not carry resolves as absent straight from
	/// the item read — no inject, no vault listing, no per-reference reads.
	#[test]
	fn missing_field_resolves_absent_from_the_item_read() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, _stdin| {
			let args = command_args(command);
			observed.lock().unwrap().push(args.clone());
			let words: Vec<&str> = args.iter().map(String::as_str).collect();
			assert_eq!(
				words,
				["item", "get", "--vault", "Personal", "--format", "json"]
			);
			Ok(
				r#"[{"id":"item-id","title":"Item","fields":[{"id":"present","type":"STRING","label":"present","value":"available"}]}]"#
					.to_string(),
			)
		}));

		let present = crate::config::NativeAddress {
			item: "Item".to_string(),
			field: Some("present".to_string()),
			..Default::default()
		};
		let missing = crate::config::NativeAddress {
			item: "Item".to_string(),
			field: Some("missing".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("PRESENT", Address::Native(&present)),
				("MISSING", Address::Native(&missing)),
				("MISSING_COPY", Address::Native(&missing)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(calls.len(), 1, "one item read serves the whole batch");
		assert!(secret_matches(&results, "PRESENT", "available"));
		assert!(!results.contains_key("MISSING"));
		assert!(!results.contains_key("MISSING_COPY"));
	}

	/// References an absent item points at resolve as `None` from the per-item
	/// reads, without the inject-and-recovery round trips: one read per item,
	/// nothing more.
	#[test]
	fn missing_item_resolves_absent_with_one_read_per_item() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
				0 => {
					// Tier 1: the stdin batch fails because Ghost is absent.
					let words: Vec<&str> = args.iter().map(String::as_str).collect();
					assert_eq!(
						words,
						["item", "get", "--vault", "Personal", "--format", "json"]
					);
					assert_eq!(
						stdin
							.expect("batched item names")
							.lines()
							.collect::<Vec<_>>(),
						["API Key", "Database", "Ghost"]
					);
					Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
				}
				1 => {
					let words: Vec<&str> = args.iter().map(String::as_str).collect();
					assert_eq!(
						words,
						[
							"item", "get", "API Key", "--vault", "Personal", "--format", "json"
						]
					);
					Ok(
						r#"[{"id":"aaa111","title":"API Key","fields":[{"id":"password","type":"STRING","label":"password","value":"alpha"}]}]"#
							.to_string(),
					)
				}
				2 => {
					let words: Vec<&str> = args.iter().map(String::as_str).collect();
					assert_eq!(
						words,
						[
							"item", "get", "Database", "--vault", "Personal", "--format", "json"
						]
					);
					Ok(
						r#"[{"id":"bbb222","title":"Database","fields":[{"id":"secret","type":"STRING","label":"secret","value":"beta"}]}]"#
							.to_string(),
					)
				}
				3 => {
					let words: Vec<&str> = args.iter().map(String::as_str).collect();
					assert_eq!(
						words,
						[
							"item", "get", "Ghost", "--vault", "Personal", "--format", "json"
						]
					);
					Err(MonosecretError::ProviderOperationFailed(
						"[ERROR] \"Ghost\" isn't an item in this vault".to_string(),
					))
				}
				_ => panic!("no inject, vault listing, or per-reference reads expected"),
			}
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		assert_eq!(
			calls.lock().unwrap().len(),
			4,
			"one failed batch read plus one per-item read"
		);
		assert!(secret_matches(&results, "FIRST", "alpha"));
		assert!(secret_matches(&results, "SECOND", "beta"));
		assert!(
			!results.contains_key("GHOST"),
			"missing item resolves as absent"
		);
	}

	/// Titles `op item get` cannot disambiguate defer to the inject path,
	/// which still resolves the values.
	#[test]
	fn ambiguous_titles_fall_back_to_inject() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
				0..=1 => {
					// Tier 1 batch and the per-item retry: the title is
					// ambiguous, so the reads refuse.
					assert!(args.contains(&"item".to_string()));
					Err(MonosecretError::ProviderOperationFailed(
						"More than one item matches the specified item name/version/query. (Item name: 'Item')".to_string(),
					))
				}
				2 => {
					let template = stdin.expect("inject stdin").to_string();
					assert!(args.contains(&"inject".to_string()));
					Ok(template
						.replace("{{ op://Personal/Item/present }}", "injected present")
						.replace("{{ op://Personal/Item/token }}", "injected token"))
				}
				_ => panic!("no further op calls expected"),
			}
		}));

		let first = crate::config::NativeAddress {
			item: "Item".to_string(),
			field: Some("present".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Item".to_string(),
			field: Some("token".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(calls.len(), 3, "two item reads, then the inject batch");
		assert!(secret_matches(&results, "FIRST", "injected present"));
		assert!(secret_matches(&results, "SECOND", "injected token"));
	}

	/// A batch child that exits without draining stdin — how `op item get`
	/// rejects an ambiguous title — must surface through its exit status, not
	/// end resolution on a broken pipe (which, with the CLI's default SIGPIPE
	/// disposition, would kill the process outright).
	#[cfg(unix)]
	#[test]
	fn child_exiting_without_draining_stdin_does_not_break_the_command() {
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.op_command = "/bin/sh".to_string();

		// The child closes its stdin read end at startup and never drains, so
		// the oversized batch is guaranteed to meet the dead pipe regardless
		// of how the spawn-to-write race lands.
		let output = provider
			.execute_op_command(
				&["-c", "exec 0<&-; sleep 0.3"],
				Some(&"x".repeat(128 * 1024)),
			)
			.unwrap();

		assert_eq!(output, "");
	}

	#[test]
	fn one_unique_field_ref_uses_one_read_and_fans_out() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			assert!(stdin.is_none());
			observed.lock().unwrap().push(command_args(command));
			Ok("single value".to_string())
		}));

		let address = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&address)),
				("SECOND", Address::Native(&address)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(calls.len(), 1);
		assert_eq!(
			calls[0],
			["read", "--no-newline", "op://Personal/API Key/password"]
		);
		assert!(secret_matches(&results, "FIRST", "single value"));
		assert!(secret_matches(&results, "SECOND", "single value"));
	}

	#[test]
	fn inject_failure_fallback_preserves_bounded_concurrency() {
		use std::sync::Arc;
		use std::sync::atomic::AtomicUsize;
		use std::sync::atomic::Ordering;
		use std::time::Duration;

		let _lock = crate::tests::scrub_resolution_env();
		let _concurrency =
			crate::tests::EnvVarGuard::set(super::super::GET_EACH_CONCURRENCY_ENV, "3");

		let current = Arc::new(AtomicUsize::new(0));
		let peak = Arc::new(AtomicUsize::new(0));
		let reads = Arc::new(AtomicUsize::new(0));
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new({
			let current = Arc::clone(&current);
			let peak = Arc::clone(&peak);
			let reads = Arc::clone(&reads);
			move |command, _stdin| {
				let args = command_args(command);
				if args.first().is_some_and(|arg| arg == "inject") {
					return Err(MonosecretError::ProviderOperationFailed(
						"one field is missing".to_string(),
					));
				}
				if args.first().is_some_and(|arg| arg == "item") {
					if args.get(1).is_some_and(|arg| arg == "get") {
						// Both batch tiers cannot disambiguate the title, so
						// every reference defers to the inject path.
						return Err(MonosecretError::ProviderOperationFailed(
							"More than one item matches the specified item name/version/query. (Item name: 'Item')".to_string(),
						));
					}
					// Recovery's vault listing: the item exists, so every ref
					// stays retained and falls through to the per-secret reads
					// this test measures the concurrency of.
					return Ok(r#"[{"id":"item-id","title":"Item"}]"#.to_string());
				}

				assert_eq!(args.first().map(String::as_str), Some("read"));
				reads.fetch_add(1, Ordering::SeqCst);
				let active = current.fetch_add(1, Ordering::SeqCst) + 1;
				peak.fetch_max(active, Ordering::SeqCst);
				std::thread::sleep(Duration::from_millis(80));
				current.fetch_sub(1, Ordering::SeqCst);
				Ok(args.last().expect("reference URI").clone())
			}
		}));

		let refs: Vec<BatchRef> = (0..10)
			.map(|index| {
				BatchRef {
					uri: format!("op://Personal/Item/field-{index}"),
					vault: "Personal".to_string(),
					item: "Item".to_string(),
					section: None,
					field: format!("field-{index}"),
				}
			})
			.collect();
		let values = provider.read_reference_uris(&refs).unwrap();

		assert_eq!(reads.load(Ordering::SeqCst), refs.len());
		assert!(
			peak.load(Ordering::SeqCst) <= 3,
			"fallback exceeded the configured concurrency cap"
		);
		assert!(
			peak.load(Ordering::SeqCst) >= 2,
			"fallback unexpectedly processed every reference serially"
		);
		assert!(values.iter().zip(&refs).all(|(value, r)| {
			value
				.as_ref()
				.is_some_and(|value| value.expose_secret() == r.uri)
		}));
	}

	/// An auth failure on the batched item read surfaces immediately, without
	/// retrying either batch tier, injecting, or fanning out per-reference
	/// reads that would each repeat the same failure.
	#[test]
	fn auth_failure_fails_fast_without_fanout() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, _stdin| {
			observed.lock().unwrap().push(command_args(command));
			Err(MonosecretError::ProviderOperationFailed(
                "[ERROR] 2026/08/14 00:00:00 error initializing client: found no accounts for filter \"x\"".to_string(),
            ))
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let error = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap_err();

		assert!(error.to_string().contains("error initializing client"));
		assert_eq!(
			calls.lock().unwrap().len(),
			1,
			"auth failure must not retry or fan out"
		);
	}

	/// A rate-limited batch surfaces after its single failed request: the
	/// throttled tiers, inject, and per-reference reads would each be another
	/// billed request against an already-exhausted pool.
	#[test]
	fn rate_limited_batch_fails_fast_without_fanout() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, _stdin| {
			observed.lock().unwrap().push(command_args(command));
			Err(MonosecretError::ProviderOperationFailed(
				"[ERROR] 2026/09/10 01:42:30 Too many requests. Your client has been rate-limited. Try again in 59 seconds"
					.to_string(),
			))
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let error = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap_err();

		assert!(error.to_string().contains("Too many requests"));
		assert_eq!(
			calls.lock().unwrap().len(),
			1,
			"rate limiting must not trigger retries that extend the lockout"
		);
	}

	#[test]
	fn inject_error_classification_separates_auth_from_data() {
		let auth_authentication_required =
			MonosecretError::ProviderOperationFailed(AUTH_REQUIRED_HELP.to_string());
		let auth_authorization_prompt = MonosecretError::ProviderOperationFailed(
			"[ERROR] 2026/08/14 00:00:00 authorization prompt dismissed, please try again"
				.to_string(),
		);
		let auth_error_initializing_client = MonosecretError::ProviderOperationFailed(
            "[ERROR] 2026/08/14 00:00:00 error initializing client: found no accounts for filter \"x\"".to_string(),
        );
		let cli_not_installed =
			MonosecretError::ProviderOperationFailed(OP_NOT_INSTALLED_HELP.to_string());
		let data = MonosecretError::ProviderOperationFailed(
            "[ERROR] 2026/08/14 00:00:00 could not resolve item UUID for item X: could not find item X in vault abc".to_string(),
        );
		assert!(!inject_error_is_recoverable(&auth_authentication_required));
		assert!(!inject_error_is_recoverable(&auth_authorization_prompt));
		assert!(!inject_error_is_recoverable(
			&auth_error_initializing_client
		));
		assert!(!inject_error_is_recoverable(&cli_not_installed));
		assert!(inject_error_is_recoverable(&data));

		// The service-account rate limit must fail fast: every retried or
		// fanned-out attempt is itself a billed request that extends the
		// lockout.
		let rate_limited = MonosecretError::ProviderOperationFailed(
			"[ERROR] 2026/09/10 01:42:30 Too many requests. Your client has been rate-limited. Try again in 59 seconds"
				.to_string(),
		);
		assert!(!inject_error_is_recoverable(&rate_limited));

		for item in [
			"Authentication Required",
			"Authorization Prompt",
			"Error Initializing Client",
		] {
			let missing_item = MonosecretError::ProviderOperationFailed(format!(
				"[ERROR] 2026/08/14 00:00:00 could not resolve item UUID for item {item}: could not find item {item} in vault abc"
			));
			assert!(
				inject_error_is_recoverable(&missing_item),
				"auth-like item name {item:?} must remain a recoverable data error"
			);
		}
	}

	/// When item reads cannot serve the batch (ambiguous titles) and inject
	/// fails on an absent item, recovery drops that item's reference and
	/// retries the inject batch once without it.
	#[test]
	fn missing_item_drops_ref_and_retries_batch_once() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
				0 => {
					assert!(args.contains(&"item".to_string()));
					Err(MonosecretError::ProviderOperationFailed(
						"More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
					))
				}
				1..=3 => {
					assert_eq!(args[0], "item");
					assert_eq!(args[1], "get");
					Err(MonosecretError::ProviderOperationFailed(
						"More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
					))
				}
				4 => {
					assert!(args.contains(&"inject".to_string()));
					Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
				}
				5 => {
					assert_eq!(
						args,
						[
							"item",
							"list",
							"--vault",
							"Personal",
							"--include-archive",
							"--format",
							"json"
						]
					);
					Ok(
						r#"[{"id":"aaa111","title":"API Key"},{"id":"bbb222","title":"Database"}]"#
							.to_string(),
					)
				}
				6 => {
					let template = stdin.expect("retry inject stdin").to_string();
					assert!(args.contains(&"inject".to_string()));
					assert!(
						!template.contains("Ghost"),
						"dropped ref must not be retried"
					);
					Ok(template
						.replace("{{ op://Personal/API Key/password }}", "alpha")
						.replace("{{ op://Personal/Database/secret }}", "beta"))
				}
				_ => panic!("no further op calls expected"),
			}
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		assert_eq!(calls.lock().unwrap().len(), 7);
		assert!(secret_matches(&results, "FIRST", "alpha"));
		assert!(secret_matches(&results, "SECOND", "beta"));
		assert!(
			!results.contains_key("GHOST"),
			"missing item resolves as absent"
		);
	}

	#[test]
	fn missing_item_check_is_case_insensitive_and_retains_match() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
				0 => {
					assert!(args.contains(&"item".to_string()));
					Err(MonosecretError::ProviderOperationFailed(
						"More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
					))
				}
				1..=3 => {
					assert_eq!(args[0], "item");
					assert_eq!(args[1], "get");
					Err(MonosecretError::ProviderOperationFailed(
						"More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
					))
				}
				4 => {
					assert!(args.contains(&"inject".to_string()));
					Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
				}
				5 => {
					assert_eq!(
						args,
						[
							"item",
							"list",
							"--vault",
							"Personal",
							"--include-archive",
							"--format",
							"json"
						]
					);
					// Listing returns the title lower-cased; the ref uses "API Key".
					// The match must be case-insensitive, so this ref stays retained.
					Ok(
						r#"[{"id":"aaa111","title":"api key"},{"id":"bbb222","title":"Database"}]"#
							.to_string(),
					)
				}
				6 => {
					let template = stdin.expect("retry inject stdin").to_string();
					assert!(args.contains(&"inject".to_string()));
					assert!(
						!template.contains("Ghost"),
						"dropped ref must not be retried"
					);
					assert!(
						template.contains("{{ op://Personal/API Key/password }}"),
						"case-different title match must retain the ref for retry"
					);
					Ok(template
						.replace("{{ op://Personal/API Key/password }}", "alpha")
						.replace("{{ op://Personal/Database/secret }}", "beta"))
				}
				_ => panic!("no further op calls expected"),
			}
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		assert_eq!(calls.lock().unwrap().len(), 7);
		assert!(secret_matches(&results, "FIRST", "alpha"));
		assert!(secret_matches(&results, "SECOND", "beta"));
		assert!(
			!results.contains_key("GHOST"),
			"missing item resolves as absent"
		);
	}

	#[test]
	fn multi_vault_recovery_lists_each_vault_once() {
		use std::collections::HashSet;
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			observed.lock().unwrap().push(args.clone());
			if args.contains(&"get".to_string()) {
				// Both batch tiers cannot disambiguate the item titles.
				return Err(MonosecretError::ProviderOperationFailed(
					"More than one item matches the specified item name/version/query. (Item name: 'x')".to_string(),
				));
			}
			if args.contains(&"inject".to_string()) {
				return Err(MonosecretError::ProviderOperationFailed(
                    "[ERROR] could not resolve item UUID for item X: could not find item X in vault abc".to_string(),
                ));
			}
			if args.first().map(String::as_str) == Some("item") {
				let vault = args.get(3).expect("--vault value").as_str();
				let body = match vault {
					"Personal" => r#"[{"id":"aaa111","title":"API Key"}]"#,
					"Work" => r#"[{"id":"bbb222","title":"Secret"}]"#,
					other => panic!("unexpected vault {other}"),
				};
				return Ok(body.to_string());
			}
			assert_eq!(args.first().map(String::as_str), Some("read"));
			assert!(stdin.is_none());
			Ok(format!("value-for-{}", args.last().expect("reference URI")))
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Secret".to_string(),
			field: Some("value".to_string()),
			vault: Some("Work".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		let list_calls: Vec<&Vec<String>> = calls
			.iter()
			.filter(|args| args.first().map(String::as_str) == Some("item"))
			.filter(|args| args.get(1).map(String::as_str) == Some("list"))
			.collect();
		assert_eq!(
			list_calls.len(),
			2,
			"one `item list` call per distinct vault"
		);
		let listed_vaults: HashSet<&str> = list_calls.iter().map(|args| args[3].as_str()).collect();
		assert!(listed_vaults.contains("Personal"));
		assert!(listed_vaults.contains("Work"));
		assert_eq!(
			calls
				.iter()
				.filter(|args| args.first().map(String::as_str) == Some("inject"))
				.count(),
			1
		);
		assert_eq!(
			calls
				.iter()
				.filter(|args| args.first().map(String::as_str) == Some("read"))
				.count(),
			2
		);
		assert!(secret_matches(
			&results,
			"FIRST",
			"value-for-op://Personal/API Key/password"
		));
		assert!(secret_matches(
			&results,
			"SECOND",
			"value-for-op://Work/Secret/value"
		));
	}

	#[test]
	fn failed_retry_falls_back_to_reads_for_retained_refs_only() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
                0..=3 => Err(MonosecretError::ProviderOperationFailed(
                    "More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
                )),
                4 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
                }
                5 => {
                    assert_eq!(args, ["item", "list", "--vault", "Personal", "--include-archive", "--format", "json"]);
                    Ok(r#"[{"id":"aaa111","title":"API Key"},{"id":"bbb222","title":"Database"}]"#.to_string())
                }
                6 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] item 'Personal/API Key' does not have a field 'password'".to_string(),
                    ))
                }
                index => {
                    assert_eq!(args[0], "read", "post-retry recovery must use per-ref reads");
                    let uri = &args[2];
                    assert!(!uri.contains("Ghost"), "dropped ref must not be individually read");
                    assert!(index <= 8, "exactly one read per retained ref");
                    if uri.contains("API Key") {
                        Err(MonosecretError::ProviderOperationFailed(
                            "[ERROR] item Personal/API Key doesn't have a field password".to_string(),
                        ))
                    } else {
                        Ok("beta".to_string())
                    }
                }
            }
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		assert_eq!(
			calls.lock().unwrap().len(),
			9,
			"batch read, 3 per-item reads, inject, list, retry inject, 2 reads"
		);
		assert!(
			!results.contains_key("GHOST"),
			"listed-missing ref stays absent, never read"
		);
		assert!(
			!results.contains_key("FIRST"),
			"field-miss on read resolves as absent"
		);
		assert!(secret_matches(&results, "SECOND", "beta"));
	}

	#[test]
	fn failed_item_list_falls_back_to_reads_for_all_refs() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
                0..=3 => Err(MonosecretError::ProviderOperationFailed(
                    "More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
                )),
                4 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
                }
                5 => {
                    assert_eq!(args, ["item", "list", "--vault", "Personal", "--include-archive", "--format", "json"]);
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] vault listing unavailable".to_string(),
                    ))
                }
                index => {
                    assert_eq!(args[0], "read", "full fallback must use per-ref reads");
                    let uri = &args[2];
                    assert!(index <= 8, "exactly one read per ref, including the dropped one");
                    if uri.contains("Ghost") {
                        Err(MonosecretError::ProviderOperationFailed(
                            "[ERROR] \"Ghost\" isn't an item in this vault".to_string(),
                        ))
                    } else if uri.contains("API Key") {
                        Ok("alpha".to_string())
                    } else {
                        Ok("beta".to_string())
                    }
                }
            }
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		let observed_calls = calls.lock().unwrap();
		assert_eq!(
			observed_calls.len(),
			9,
			"batch, per-item reads, inject, list, 3 reads"
		);
		assert!(
			observed_calls[6..]
				.iter()
				.any(|(args, _)| args[2].contains("Ghost")),
			"an unresolvable vault listing must still individually read every ref, including Ghost"
		);
		drop(observed_calls);
		assert!(
			!results.contains_key("GHOST"),
			"missing item resolves as absent"
		);
		assert!(secret_matches(&results, "FIRST", "alpha"));
		assert!(secret_matches(&results, "SECOND", "beta"));
	}

	#[test]
	fn auth_error_on_item_list_fails_fast() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, _stdin| {
			let args = command_args(command);
			let mut calls = observed.lock().unwrap();
			let call_index = calls.len();
			calls.push(args.clone());
			drop(calls);
			match call_index {
                0..=2 => Err(MonosecretError::ProviderOperationFailed(
                    "More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
                )),
                3 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
                }
                4 => {
                    assert_eq!(args.first().map(String::as_str), Some("item"));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] error initializing client: found no accounts for filter \"x\""
                            .to_string(),
                    ))
                }
                _ => panic!("no per-reference reads after an auth failure"),
            }
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let error = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
			])
			.unwrap_err();

		assert!(error.to_string().contains("error initializing client"));
		assert_eq!(
			calls.lock().unwrap().len(),
			5,
			"batch, 2 per-item reads, inject, item list"
		);
	}

	#[test]
	fn auth_error_on_retry_inject_fails_fast() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			let mut log = observed.lock().unwrap();
			let call_index = log.len();
			log.push((args.clone(), stdin.map(str::to_string)));
			drop(log);
			match call_index {
                0..=3 => Err(MonosecretError::ProviderOperationFailed(
                    "More than one item matches the specified item name/version/query. (Item name: 'API Key')".to_string(),
                )),
                4 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] could not resolve item UUID for item Ghost: could not find item Ghost in vault abc".to_string(),
                    ))
                }
                5 => {
                    assert_eq!(args, ["item", "list", "--vault", "Personal", "--include-archive", "--format", "json"]);
                    Ok(r#"[{"id":"aaa111","title":"API Key"},{"id":"bbb222","title":"Database"}]"#.to_string())
                }
                6 => {
                    assert!(args.contains(&"inject".to_string()));
                    Err(MonosecretError::ProviderOperationFailed(
                        "[ERROR] error initializing client: found no accounts for filter \"x\"".to_string(),
                    ))
                }
                _ => panic!("no calls after auth failure"),
            }
		}));

		let first = crate::config::NativeAddress {
			item: "API Key".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let ghost = crate::config::NativeAddress {
			item: "Ghost".to_string(),
			field: Some("credential".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Database".to_string(),
			field: Some("secret".to_string()),
			..Default::default()
		};
		let error = provider
			.get_many(&[
				("FIRST", Address::Native(&first)),
				("GHOST", Address::Native(&ghost)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap_err();

		assert!(error.to_string().contains("error initializing client"));
		assert_eq!(calls.lock().unwrap().len(), 7);
	}

	#[test]
	fn missing_item_check_matches_by_id() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, _stdin| {
			let args = command_args(command);
			observed.lock().unwrap().push(args.clone());
			assert_eq!(
				args,
				[
					"item",
					"list",
					"--vault",
					"Personal",
					"--include-archive",
					"--format",
					"json"
				]
			);
			Ok(r#"[{"id":"aaa111","title":"Something Else"}]"#.to_string())
		}));

		let refs = vec![BatchRef {
			uri: "op://Personal/aaa111/password".to_string(),
			vault: "Personal".to_string(),
			item: "aaa111".to_string(),
			section: None,
			field: "password".to_string(),
		}];

		let flags = provider
			.flag_refs_with_existing_items(&refs)
			.unwrap()
			.unwrap();

		assert_eq!(
			flags,
			[true],
			"a ref whose item matches the listing entry's id (not its title) must be retained, not dropped"
		);
		assert_eq!(calls.lock().unwrap().len(), 1);
	}

	#[test]
	fn mixed_whole_items_and_field_refs_keep_both_batch_paths() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			observed.lock().unwrap().push(args.clone());
			match args.as_slice() {
				[command, list, ..] if command == "item" && list == "list" => {
					Ok(r#"[{"id":"whole-id","title":"Whole Item"}]"#.to_string())
				}
				// The whole-items path fetches by id (after the listing); the
				// field-reference path fetches by referenced name.
				[command, get, ..] if command == "item" && get == "get" => {
					match stdin.expect("batched item names").trim() {
						"whole-id" => Ok(
							r#"{"id":"whole-id","fields":[{"id":"value","type":"STRING","label":"value","value":"whole value"}]}"#
								.to_string(),
						),
						"Field One\nField Two" => Ok(
							r#"[{"id":"one-id","title":"Field One","fields":[{"id":"password","type":"STRING","label":"password","value":"field one"}]},{"id":"two-id","title":"Field Two","fields":[{"id":"token","type":"STRING","label":"token","value":"field two"}]}]"#
								.to_string(),
						),
						other => unreachable!("unexpected batched item get: {other:?}"),
					}
				}
				_ => unreachable!("unexpected mocked command"),
			}
		}));

		let whole = crate::config::NativeAddress {
			item: "Whole Item".to_string(),
			..Default::default()
		};
		let first = crate::config::NativeAddress {
			item: "Field One".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let second = crate::config::NativeAddress {
			item: "Field Two".to_string(),
			field: Some("token".to_string()),
			..Default::default()
		};
		let results = provider
			.get_many(&[
				("WHOLE", Address::Native(&whole)),
				("FIRST", Address::Native(&first)),
				("SECOND", Address::Native(&second)),
			])
			.unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(
			calls.iter().filter(|args| args[0] == "inject").count(),
			0,
			"field references resolve from batched item reads, not inject"
		);
		assert_eq!(
			calls
				.iter()
				.filter(|args| args.starts_with(&["item".to_string(), "list".to_string()]))
				.count(),
			1
		);
		assert_eq!(
			calls
				.iter()
				.filter(|args| args.starts_with(&["item".to_string(), "get".to_string()]))
				.count(),
			2,
			"one whole-items get and one field-references get"
		);
		assert!(secret_matches(&results, "WHOLE", "whole value"));
		assert!(secret_matches(&results, "FIRST", "field one"));
		assert!(secret_matches(&results, "SECOND", "field two"));
	}

	#[test]
	fn whole_item_batch_uses_one_get_process_and_maps_results_by_id() {
		use std::sync::Arc;
		use std::sync::Mutex;

		let listed = serde_json::Value::Array(
			(0..10)
				.map(|index| {
					serde_json::json!({
						"id": format!("item-{index}"),
						"title": format!("Secret {index}"),
					})
				})
				.collect(),
		)
		.to_string();
		// `op item get --format json` emits a stream of JSON documents. Use
		// reverse order to prove results are associated by item ID, not by the
		// order in which the CLI returns them.
		let fetched = (0..10)
			.rev()
			.map(|index| {
				serde_json::json!({
					"id": format!("item-{index}"),
					"fields": [{
						"id": "value",
						"type": "STRING",
						"label": "value",
						"value": format!("value-{index}"),
					}],
				})
				.to_string()
			})
			.collect::<String>();

		let calls = Arc::new(Mutex::new(Vec::<(Vec<String>, Option<String>)>::new()));
		let observed = Arc::clone(&calls);
		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(move |command, stdin| {
			let args = command_args(command);
			observed
				.lock()
				.unwrap()
				.push((args.clone(), stdin.map(str::to_string)));
			match args.as_slice() {
				[command, list, ..] if command == "item" && list == "list" => {
					assert!(stdin.is_none());
					Ok(listed.clone())
				}
				[command, get, vault_flag, vault, format_flag, format]
					if command == "item"
						&& get == "get" && vault_flag == "--vault"
						&& vault == "Personal"
						&& format_flag == "--format"
						&& format == "json" =>
				{
					assert!(stdin.is_some());
					Ok(fetched.clone())
				}
				_ => unreachable!("unexpected mocked command"),
			}
		}));

		let names: Vec<String> = (0..10).map(|index| format!("SECRET_{index}")).collect();
		let addresses: Vec<crate::config::NativeAddress> = (0..10)
			.map(|index| {
				crate::config::NativeAddress {
					item: format!("Secret {index}"),
					..Default::default()
				}
			})
			.collect();
		let requests: Vec<(&str, Address<'_>)> = names
			.iter()
			.zip(&addresses)
			.map(|(name, address)| (name.as_str(), Address::Native(address)))
			.collect();

		let results = provider.get_many(&requests).unwrap();

		let calls = calls.lock().unwrap();
		assert_eq!(calls.len(), 2, "one list process and one get process");
		assert_eq!(
			calls[1].0,
			["item", "get", "--vault", "Personal", "--format", "json"]
		);
		let batch_input = calls[1].1.as_deref().expect("batch item IDs on stdin");
		assert_eq!(batch_input.lines().count(), 10);
		for index in 0..10 {
			let item_id = format!("item-{index}");
			assert!(batch_input.lines().any(|line| line == item_id));
			assert!(secret_matches(
				&results,
				&format!("SECRET_{index}"),
				&format!("value-{index}")
			));
		}
	}

	#[test]
	fn empty_batch_does_not_invoke_op() {
		use std::sync::Arc;

		let mut provider = OnePasswordProvider::new(config("onepassword://Personal"));
		provider.command_override = Some(Arc::new(|_, _| {
			panic!("empty batch must not invoke the command seam")
		}));

		assert!(provider.get_many(&[]).unwrap().is_empty());
	}

	/// A field fixture: `(id, label, value, section id, section label)`.
	type FieldFixture<'a> = (
		&'a str,
		&'a str,
		Option<&'a str>,
		Option<&'a str>,
		Option<&'a str>,
	);

	/// Builds an item like `op item get --format json` emits: field sections
	/// carry only the id, the item-level sections list maps ids to labels.
	fn sectioned_item(sections: &[(&str, &str)], fields: &[FieldFixture<'_>]) -> OnePasswordItem {
		serde_json::from_value(serde_json::json!({
			"id": "item-id",
			"title": "Dotfiles",
			"sections": sections
				.iter()
				.map(|(id, label)| serde_json::json!({"id": id, "label": label}))
				.collect::<Vec<_>>(),
			"fields": fields
				.iter()
				.map(|(id, label, value, section_id, section_label)| {
					serde_json::json!({
						"id": id,
						"type": "STRING",
						"label": label,
						"value": value,
						"section": section_id.map(|id| match section_label {
							Some(label) => serde_json::json!({"id": id, "label": label}),
							None => serde_json::json!({"id": id}),
						}),
					})
				})
				.collect::<Vec<_>>(),
		}))
		.unwrap()
	}

	fn resolves_to(
		item: &OnePasswordItem,
		section: Option<&str>,
		field: &str,
	) -> std::result::Result<Option<String>, ()> {
		OnePasswordProvider::resolve_reference_in_item(
			item,
			&SecretReference {
				item: "Dotfiles".to_string(),
				section: section.map(str::to_string),
				field: field.to_string(),
			},
		)
	}

	#[test]
	fn item_matching_resolves_sections_labels_ids_and_case() {
		let item = sectioned_item(
			&[("s-ai", "ai"), ("s-registries", "registries")],
			&[
				("f1", "OPENAI_API_KEY", Some("openai"), Some("s-ai"), None),
				("f2", "NPM_TOKEN", Some("npm"), Some("s-registries"), None),
				("f3", "plain", Some("unsectioned"), None, None),
			],
		);

		// Section by label, resolved through the item-level list.
		assert_eq!(
			resolves_to(&item, Some("ai"), "OPENAI_API_KEY")
				.unwrap()
				.as_deref(),
			Some("openai")
		);
		// Section by id, matching the id the field carries.
		assert_eq!(
			resolves_to(&item, Some("s-ai"), "OPENAI_API_KEY")
				.unwrap()
				.as_deref(),
			Some("openai")
		);
		// Case-insensitive section and field labels, as `op` resolves them.
		assert_eq!(
			resolves_to(&item, Some("AI"), "openai_api_key")
				.unwrap()
				.as_deref(),
			Some("openai")
		);
		// Field matched by its id.
		assert_eq!(
			resolves_to(&item, Some("registries"), "f2")
				.unwrap()
				.as_deref(),
			Some("npm")
		);
		// Unsectioned reference to an unsectioned field.
		assert_eq!(
			resolves_to(&item, None, "plain").unwrap().as_deref(),
			Some("unsectioned")
		);
	}

	#[test]
	fn item_matching_leaves_gray_areas_to_inject() {
		let item = sectioned_item(
			&[("s-ai", "ai")],
			&[
				("f1", "OPENAI_API_KEY", Some("openai"), Some("s-ai"), None),
				("f2", "valueless", None, Some("s-ai"), None),
				("f3", "plain", Some("unsectioned"), None, None),
			],
		);

		// No field with the referenced label: absent, the outcome `op read`
		// reports as "doesn't have a field".
		assert_eq!(resolves_to(&item, Some("ai"), "MISSING"), Ok(None));
		// The grammar puts the section in the URI: an unsectioned reference to
		// a sectioned field is `op inject`'s call.
		assert_eq!(resolves_to(&item, None, "OPENAI_API_KEY"), Err(()));
		// A sectioned reference cannot grab an unsectioned field.
		assert_eq!(resolves_to(&item, Some("ai"), "plain"), Err(()));
		// A matched field whose value the item JSON omits cannot be served
		// from the read; defer.
		assert_eq!(resolves_to(&item, Some("ai"), "valueless"), Err(()));
	}
}
