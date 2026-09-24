mod claude;
mod completion;
mod docker;
mod git;
mod shell;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use clap::ArgMatches;
use clap::CommandFactory;
use clap::FromArgMatches;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use clap::ValueHint;
use clap::parser::ValueSource;
use git::GitAction;

struct LoginCredentialBroker {
	app: Arc<Secrets>,
	alias: String,
	configured: HashMap<String, crate::config::CredentialSource>,
	request_lock: Mutex<()>,
	values:
		Mutex<HashMap<(crate::ProviderCredentialPrincipal, String, String), SecretBytes>>,
	stored: Mutex<Vec<(String, String)>>,
}

impl LoginCredentialBroker {
	fn new(
		app: Arc<Secrets>,
		alias: String,
		credentials: Vec<(String, crate::config::CredentialSource)>,
	) -> Self {
		Self {
			app,
			alias,
			configured: credentials.into_iter().collect(),
			request_lock: Mutex::new(()),
			values: Mutex::new(HashMap::new()),
			stored: Mutex::new(Vec::new()),
		}
	}
}

impl crate::provider::external::ProviderCredentialBroker for LoginCredentialBroker {
	fn get(
		&self,
		principal: &crate::ProviderCredentialPrincipal,
		request: &monosecret_ipc::protocol::callback::CredentialParams,
	) -> crate::Result<Option<SecretBytes>> {
		let _request = self
			.request_lock
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let source = self.configured.get(&request.name);
		let key = (
			principal.clone(),
			if source.is_some() {
				String::new()
			} else {
				request.scope.clone()
			},
			request.name.clone(),
		);
		if let Some(value) = self
			.values
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.get(&key)
			.cloned()
		{
			return Ok(Some(value));
		}
		let Some(value) =
			prompt_provider_credential(&self.alias, principal.scheme(), request, source)?
		else {
			return Ok(None);
		};
		let location = match source {
			Some(source) => self
				.app
				.store_provider_credential(source, &request.name, &value)?,
			None => self.app.store_external_provider_credential(
				principal,
				&request.scope,
				&request.name,
				&value,
			)?,
		};
		self.values
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.insert(key, value.clone());
		self.stored
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.push((request.name.clone(), location));
		Ok(Some(value))
	}

	fn interactive(&self) -> bool {
		true
	}
}

fn prompt_provider_credential(
	alias: &str,
	scheme: &str,
	request: &crate::ProviderCredentialRequest,
	source: Option<&crate::config::CredentialSource>,
) -> crate::Result<Option<SecretBytes>> {
	// A direct provider URI may contain credentials. Show its trusted scheme
	// instead; configured alias names remain useful context for the person.
	let provider = if alias.contains("://") { scheme } else { alias };
	let prompt = match source {
		Some(source) => format!(
			"Enter {} for provider '{}' (source: {}):",
			request.name,
			provider,
			source.display_provider()
		),
		None => format!(
			"Enter {} for provider '{}' ({} credential):",
			request.name, provider, scheme
		),
	};
	let entered = inquire::Password::new(&prompt)
		.without_confirmation()
		.prompt()
		.map_err(|_| {
			crate::MonosecretError::ProviderOperationFailed(
				"provider credential prompt failed".to_string(),
			)
		})?;
	Ok((!entered.is_empty()).then(|| SecretBytes::from_utf8(entered)))
}

use miette::IntoDiagnostic;
use miette::Result;
use miette::WrapErr;
use miette::miette;
use tracing::Event;
use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span::Attributes;
use tracing::span::Id;
use tracing::span::Record;

use crate::CallerContext;
use crate::ExportFormat;
use crate::SecretBytes;
use crate::Secrets;
use crate::Spec;
use crate::config::Config;
use crate::config::GlobalConfig;
use crate::config::GlobalDefaults;
use crate::config::Profile as ConfigProfile;
use crate::config::Project;
use crate::provider::Provider;
#[cfg(feature = "kubernetes")]
use crate::provider::kubernetes::KubernetesKind;
#[cfg(feature = "kubernetes")]
use crate::provider::kubernetes::KubernetesProvider;
use crate::provider::providers;
use crate::provider::spec_names_known_provider;
use crate::spec_edit::add_description as add_secret_to_spec;
use crate::spec_edit::validate_secret_name as validate_add_secret_name;

// `shell.rs` predates the v0.19 error taxonomy. Keep its emission diagnostics
// without widening the public error enum during this compatibility port.
impl crate::MonosecretError {
	#[allow(non_snake_case)]
	pub(crate) fn EnvEmit(message: String) -> Self {
		Self::Io(std::io::Error::other(message))
	}
}
/// Main CLI structure for the monosecret application.
///
/// This is the entry point for the command-line interface, parsing user commands
/// and delegating to the appropriate subcommands for secrets management.
#[derive(Parser)]
#[command(name = "monosecret")]
#[command(about = "A declarative interface for every secret provider. https://monosecret.dev", long_about = None)]
#[command(version)]
struct Cli {
	/// Path to monosecret.toml (default: auto-detect by walking up from current directory)
	#[arg(short = 'f', long, global = true, env = "MONOSECRET_FILE", value_hint = ValueHint::FilePath)]
	file: Option<PathBuf>,

	/// Increase diagnostic logging (`-v` for debug, `-vv` for trace).
	/// Can also use `RUST_LOG=debug` or `RUST_LOG=trace`.
	#[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
	verbose: u8,

	/// Reason for accessing secrets, recorded by providers that support audit
	/// logging (e.g. Proton Pass agent sessions). Takes precedence over the
	/// PROTON_PASS_AGENT_REASON environment variable.
	// The doc comment doubles as clap help text, which snapshots pin verbatim;
	// backtick-wrapping the env name would change user-visible help output.
	#[allow(clippy::doc_markdown)]
	#[arg(long, global = true, env = "MONOSECRET_REASON")]
	reason: Option<String>,

	/// Software integration invoking Monosecret, recorded as caller context
	/// without satisfying the access-reason policy (0.20+)
	#[arg(long, global = true)]
	caller: Option<String>,

	/// Version of the software integration named by --caller (0.20+)
	#[arg(long, global = true)]
	caller_version: Option<String>,

	/// Operation the software integration is performing (0.20+)
	#[arg(long, global = true)]
	caller_operation: Option<String>,

	/// Non-secret resource the software integration is accessing (0.20+)
	#[arg(long, global = true)]
	caller_resource: Option<String>,

	/// The subcommand to execute
	#[command(subcommand)]
	command: Commands,
}

// Four independent "was this option explicitly typed" flags; each tracks a
// separate clap option, so an enum or bitmask would obscure the per-option
// bookkeeping at every use site.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TypedArgs {
	pub(crate) file: bool,
	pub(crate) profile: bool,
	pub(crate) provider: bool,
	pub(crate) reason: bool,
}

impl TypedArgs {
	fn from_matches(matches: &ArgMatches) -> Self {
		let mut typed = Self::default();
		let mut current = Some(matches);
		while let Some(matches) = current {
			for (id, typed) in [
				("file", &mut typed.file),
				("profile", &mut typed.profile),
				("provider", &mut typed.provider),
				("reason", &mut typed.reason),
			] {
				if matches.ids().any(|known| known.as_str() == id)
					&& matches.value_source(id) == Some(ValueSource::CommandLine)
				{
					*typed = true;
				}
			}
			current = matches.subcommand().map(|(_, matches)| matches);
		}
		typed
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompletionShell {
	/// Bourne Again Shell
	Bash,
	/// Elvish shell
	Elvish,
	/// Friendly Interactive Shell
	Fish,
	/// Nushell
	Nushell,
	/// PowerShell
	#[value(name = "powershell")]
	PowerShell,
	/// Z shell
	Zsh,
}

/// Manifest output formats.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ManifestFormat {
	/// Pretty-printed JSON
	Json,
}

/// Available commands for the monosecret CLI.
///
/// This enum defines all the subcommands that can be executed, including
/// initialization, secret management, configuration, and import operations.
#[derive(Subcommand)]
enum Commands {
	/// Initialize a new monosecret.toml (optionally, from a provider)
	Init {
		/// Discover declarations from a provider (additional providers in 0.18+)
		///
		/// Note: no short flag here — `-f` is the global `--file` option.
		#[arg(long, default_value = "dotenv://.env", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		from: String,
		/// Project used to select the provider namespace (0.18+; defaults to directory name)
		#[arg(long)]
		project: Option<String>,
		/// Profile used to select the provider namespace (0.18+)
		#[arg(short = 'P', long, default_value = "default", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: String,
	},
	/// Add a secret declaration to monosecret.toml (0.18+)
	Add {
		/// Name of the secret
		name: String,
		/// Human-readable description (prompts when omitted)
		#[arg(short, long)]
		description: Option<String>,
		/// Profile to add the secret to
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
	},
	/// Set a secret value
	Set {
		/// Name of the secret
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::secrets))]
		name: String,
		/// Value of the secret (will prompt if not provided)
		value: Option<String>,
		/// Read the exact secret bytes from a file, or from stdin with `-` (0.4.0+)
		#[arg(long, value_name = "FILE", conflicts_with = "value", value_hint = ValueHint::FilePath)]
		from_file: Option<PathBuf>,
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
	},
	/// Get a secret value
	Get {
		/// Name of the secret
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::secrets))]
		name: String,
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
	},
	/// Delete stored secret values from a provider (0.18+)
	Delete {
		/// Names of the secrets to delete
		#[arg(required_unless_present = "all", conflicts_with = "all", add = clap_complete::ArgValueCompleter::new(completion::secrets))]
		names: Vec<String>,
		/// Delete every provider-backed secret declared in the active profile
		#[arg(long)]
		all: bool,
		/// Skip the confirmation required by --all
		#[arg(short, long, requires = "all", conflicts_with = "names")]
		yes: bool,
		/// Provider backend to delete from
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
	},
	/// Run a command with secrets injected
	Run {
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
		/// Scope to resolve (a `[scopes]` subset of the profile). Excluded
		/// secrets are removed from the child environment even if inherited.
		#[arg(short = 'S', long, env = "MONOSECRET_SCOPE", add = clap_complete::ArgValueCompleter::new(completion::scopes))]
		scope: Option<String>,
		/// Secret names to inject. Can be repeated or comma-separated.
		#[arg(long = "include")]
		include: Vec<String>,
		/// Secret groups to inject. Can be repeated or comma-separated.
		#[arg(long = "group")]
		group: Vec<String>,
		/// Command and arguments to run
		#[arg(trailing_var_arg = true, value_hint = ValueHint::CommandWithArguments, add = clap_complete::ArgValueCompleter::new(completion::RunCompleter))]
		command: Vec<String>,
	},
	/// Emit a secret-value-free manifest for SDK code generation
	Manifest {
		/// Output format
		#[arg(long, value_enum, default_value_t = ManifestFormat::Json)]
		format: ManifestFormat,
	},
	/// Resolve secrets and print them for another tool to consume
	Export {
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
		/// Scope to resolve (a `[scopes]` subset of the profile)
		#[arg(short = 'S', long, env = "MONOSECRET_SCOPE", add = clap_complete::ArgValueCompleter::new(completion::scopes))]
		scope: Option<String>,
		/// Output format
		#[arg(long, value_enum, default_value = "shell")]
		format: ExportFormat,
	},
	/// Check if all required secrets are in the provider, if not set them
	Check {
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
		/// Scope to check (a `[scopes]` subset of the profile)
		#[arg(short = 'S', long, env = "MONOSECRET_SCOPE", add = clap_complete::ArgValueCompleter::new(completion::scopes))]
		scope: Option<String>,
		/// Don't prompt for missing secrets (exit with error if any are missing)
		#[arg(short = 'n', long)]
		no_prompt: bool,
		/// Print the value-free resolution report as JSON (no secret values).
		/// Never prompts; exits non-zero if a required secret is missing.
		#[arg(long, conflicts_with = "explain")]
		json: bool,
		/// Print a value-free, human-readable resolution trace (no secret
		/// values). Never prompts; exits non-zero if a required secret is missing.
		#[arg(long)]
		explain: bool,
	},
	/// Emit a JSON Schema for the manifest's typed shape.
	///
	/// Feed this to [quicktype](https://quicktype.io) to generate an idiomatic
	/// typed accessor (plus a deserializer) for any language, then hand the
	/// deserializer the flat map from each SDK's `fields()` helper. By default it
	/// describes the union `Monosecret` (safe for any profile); `--profile` gives
	/// that profile's exact fields. Value-free: reads only the manifest.
	///
	/// With --config project or --config global (0.4.0+), emit an editor schema
	/// for the TOML configuration format instead. No configuration files or
	/// providers are accessed in this mode.
	///
	/// Example: `monosecret schema | quicktype -s schema --top-level Monosecret --lang typescript`
	Schema {
		/// Emit the schema for this profile's fields instead of the union
		#[arg(short = 'P', long, conflicts_with = "config", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
		/// Emit an editor schema for project monosecret.toml or global config.toml (0.4.0+)
		#[arg(long, value_enum)]
		config: Option<ConfigSchemaKind>,
		/// Write to this file instead of stdout
		#[arg(short, long, value_hint = ValueHint::FilePath)]
		output: Option<PathBuf>,
	},
	/// Generate shell completion scripts (0.20+)
	Completions {
		/// Shell to generate completions for
		#[arg(value_enum)]
		shell: CompletionShell,
	},
	/// Manage Monosecret configuration
	Config {
		#[command(subcommand)]
		action: ConfigAction,
	},
	/// Manage Docker registry credential integration (0.20+)
	Docker {
		#[command(subcommand)]
		action: docker::DockerAction,
	},
	#[command(about = "Configure Git HTTP(S) or SMTP credentials through Monosecret (0.20+)")]
	Git {
		#[command(subcommand)]
		action: GitAction,
	},
	#[command(about = "Manage Claude Code API credential integration (0.4.0+)")]
	Claude {
		#[command(subcommand)]
		action: claude::ClaudeAction,
	},
	/// Import secrets from a provider to another provider
	Import {
		/// Provider backend to import from (secrets will be imported to the default provider)
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::providers))]
		from_provider: String,
		/// Delete a source value only after the destination contains the same value (0.18+)
		#[arg(long)]
		delete_source: bool,
	},
	/// Manage cached provider values (0.17+)
	Cache {
		#[command(subcommand)]
		action: CacheAction,
	},
	/// Serve one `monosecret.resolver/1` session over stdin and stdout (0.4.0+)
	///
	/// The session is a private child of whoever launched it: it exchanges
	/// framed IPC on the standard streams, never prompts on them, and exits
	/// with its parent. A future daemon mode would instead expose a socket
	/// other local processes can reach, so that mode has to be asked for while
	/// this one does not.
	Serve {
		/// Advertise resolution only, refusing `resolver.set` and
		/// `resolver.delete` (0.4.0+)
		#[arg(long)]
		read_only: bool,
	},
	/// Show the local audit log of secret access
	Audit {
		/// Only show entries for this project
		#[arg(long)]
		project: Option<String>,
		// The doc comment doubles as clap help text, which snapshots pin
		// verbatim; backtick-wrapping `cache_clear` would change help output.
		#[allow(clippy::doc_markdown)]
		/// Only show entries for this action (get, set, delete, check, run, import, export, cache_clear)
		#[arg(long)]
		action: Option<String>,
		/// Show only the last N entries
		#[arg(short = 'n', long)]
		tail: Option<usize>,
		/// Output raw JSON Lines instead of a formatted summary
		#[arg(long)]
		json: bool,
	},
	/// Load resolved secrets into a shell or CI environment.
	#[command(alias = "load-env")]
	Env {
		/// Target shell / format.
		#[arg(short = 's', long, value_enum, default_value_t = shell::Shell::Bash)]
		shell: shell::Shell,
		/// Provider backend to use
		#[arg(short, long, env = "MONOSECRET_PROVIDER")]
		provider: Option<String>,
		/// Profile to use
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE")]
		profile: Option<String>,
		/// Scope to resolve (a `[scopes]` subset of the profile)
		#[arg(short = 'S', long, env = "MONOSECRET_SCOPE")]
		scope: Option<String>,
		/// Write to a file instead of stdout.
		#[arg(short = 'o', long)]
		output: Option<PathBuf>,
		/// Secret names to include. Can be repeated or comma-separated.
		#[arg(long = "include")]
		include: Vec<String>,
		/// Secret groups to include. Can be repeated or comma-separated.
		#[arg(long = "group")]
		group: Vec<String>,
	},
}

fn generate_completions(shell: CompletionShell, output: &mut dyn Write) -> std::io::Result<()> {
	completion::generate(shell, output)
}

/// Cached provider maintenance commands (0.17+).
#[derive(Subcommand)]
enum CacheAction {
	/// Delete cached values for one secret, or all cached secrets (0.17+)
	Clear {
		/// Secret to clear; omit to clear every cached secret in the profile
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::secrets))]
		name: Option<String>,
		/// Profile whose cache entries should be cleared
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles))]
		profile: Option<String>,
	},
}

/// Which TOML document an editor schema describes.
#[derive(Clone, Copy, ValueEnum)]
enum ConfigSchemaKind {
	/// Project monosecret.toml
	Project,
	/// User-global config.toml
	Global,
}

/// Configuration-related subcommands.
///
/// User-global configuration has an explicit `global` namespace. Legacy
/// spellings remain hidden aliases for backwards compatibility.
#[derive(Subcommand)]
enum ConfigAction {
	/// Manage user-global configuration (0.17+)
	Global {
		#[command(subcommand)]
		action: GlobalConfigAction,
	},
	/// Initialize user configuration
	#[command(hide = true)]
	Init {
		/// Provider backend to save without prompting (0.17+)
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Default profile to save without prompting; use "none" to clear it (0.17+)
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles_or_none))]
		profile: Option<String>,
	},
	/// Show current configuration
	#[command(hide = true)]
	Show,
	/// Store project-scoped provider credentials
	#[command(subcommand)]
	Provider(ProviderAction),
}

/// User-global configuration subcommands.
#[derive(Subcommand)]
enum GlobalConfigAction {
	/// Initialize user-global defaults
	Init {
		/// Provider backend to save without prompting
		#[arg(short, long, env = "MONOSECRET_PROVIDER", add = clap_complete::ArgValueCompleter::new(completion::providers))]
		provider: Option<String>,
		/// Default profile to save without prompting; use "none" to clear it
		#[arg(short = 'P', long, env = "MONOSECRET_PROFILE", add = clap_complete::ArgValueCompleter::new(completion::profiles_or_none))]
		profile: Option<String>,
	},
	/// Show user-global configuration
	Show,
	/// Manage user-global provider aliases
	#[command(subcommand)]
	Provider(GlobalProviderAction),
}

/// User-global provider alias management subcommands.
#[derive(Subcommand)]
enum GlobalProviderAction {
	/// Add or update a provider alias
	Add {
		/// Name of the provider alias
		name: String,
		// The doc comment doubles as clap help text, which snapshots pin
		// verbatim; wrapping the bare URIs would change help output.
		#[allow(clippy::doc_markdown)]
		/// Provider URI (e.g., "keyring://", "onepassword://Shared", "dotenv://.env.local")
		uri: String,
		/// Provider credential binding `NAME=PROVIDER` (repeatable). `NAME` is
		/// semantic and provider-specific, such as `access_token` or `role_id`.
		/// Only the bare-string source form is expressible here; add a `ref` by
		/// editing the config.
		#[arg(long = "credential", value_name = "NAME=PROVIDER")]
		credential: Vec<String>,
	},
	/// Remove a provider alias
	Remove {
		/// Name of the provider alias to remove
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::global_provider_aliases))]
		name: String,
	},
	/// List all configured provider aliases
	List,
}

/// Legacy provider alias commands plus project-scoped credential login.
///
/// Alias mutation commands remain hidden for backwards compatibility; new
/// invocations should use `config global provider`.
#[derive(Subcommand)]
enum ProviderAction {
	/// Add or update a provider alias
	#[command(hide = true)]
	Add {
		/// Name of the provider alias
		name: String,
		// The doc comment doubles as clap help text, which snapshots pin
		// verbatim; wrapping the bare URIs would change help output.
		#[allow(clippy::doc_markdown)]
		/// Provider URI (e.g., "keyring://", "onepassword://Shared", "dotenv://.env.local")
		uri: String,
		/// Provider credential binding `NAME=PROVIDER` (repeatable). `NAME` is
		/// semantic and provider-specific, such as `access_token` or `role_id`.
		/// Only the bare-string source form is expressible here; add a `ref` by
		/// editing the config.
		#[arg(long = "credential", value_name = "NAME=PROVIDER")]
		credential: Vec<String>,
	},
	/// Remove a provider alias
	#[command(hide = true)]
	Remove {
		/// Name of the provider alias to remove
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::global_provider_aliases))]
		name: String,
	},
	/// List all configured provider aliases
	#[command(hide = true)]
	List,
	/// Store the credentials declared by a provider alias
	Login {
		/// Name of the provider alias to store credentials for
		#[arg(add = clap_complete::ArgValueCompleter::new(completion::provider_aliases))]
		name: String,
	},
}

impl From<GlobalConfigAction> for ConfigAction {
	fn from(action: GlobalConfigAction) -> Self {
		match action {
			GlobalConfigAction::Init { provider, profile } => Self::Init { provider, profile },
			GlobalConfigAction::Show => Self::Show,
			GlobalConfigAction::Provider(action) => Self::Provider(action.into()),
		}
	}
}

impl From<GlobalProviderAction> for ProviderAction {
	fn from(action: GlobalProviderAction) -> Self {
		match action {
			GlobalProviderAction::Add {
				name,
				uri,
				credential,
			} => {
				Self::Add {
					name,
					uri,
					credential,
				}
			}
			GlobalProviderAction::Remove { name } => Self::Remove { name },
			GlobalProviderAction::List => Self::List,
		}
	}
}

/// Maps the explicit `config global` namespace onto the legacy internal action
/// variants so both CLI spellings share exactly one implementation.
fn normalize_config_action(action: ConfigAction) -> ConfigAction {
	match action {
		ConfigAction::Global { action } => action.into(),
		action => action,
	}
}

/// Returns an example TOML configuration string
///
/// This function provides a template for creating new `monosecret.toml` files,
/// showing the recommended structure and commenting conventions.
///
/// # Returns
///
/// A static string containing an example TOML configuration
fn get_example_toml() -> &'static str {
	r#"# DATABASE_URL = { description = "Database connection string", required = true }

# [profiles.development]
# Development profile inherits all secrets from default profile
# Only define secrets here that need different values or settings than default
# DATABASE_URL = { default = "sqlite:///dev.db" }
#
# New secrets
# REDIS_URL = { description = "Redis connection URL for caching", required = false, default = "redis://localhost:6379" }
"#
}

/// Builds a copyable POSIX-shell command for importing discovered values.
fn migration_command(from: &str, profile: &str) -> String {
	let from = crate::secrets::shell_single_quote(from);
	if profile == "default" {
		format!("monosecret import {from}")
	} else {
		let profile = crate::secrets::shell_single_quote(profile);
		format!("MONOSECRET_PROFILE={profile} monosecret import {from}")
	}
}

/// Generates a `monosecret.toml` document from a [`Config`] with helpful comments.
///
/// String values and keys are serialized through `toml_edit`, so anything that
/// needs quoting or escaping (a description containing a double-quote, a secret
/// name containing a dot, a control character, ...) is emitted as valid,
/// round-trippable TOML rather than hand-interpolated. Secrets are written as
/// inline tables and profiles/secrets are sorted for deterministic output, while
/// instructional comments are preserved for users editing the file by hand.
///
/// # Arguments
///
/// * `config` - The project configuration to serialize
///
/// # Returns
///
/// A TOML string with the configuration and helpful comments
///
/// # Errors
///
/// Returns an error if the configuration cannot be serialized
fn generate_toml_with_comments(config: &Config) -> String {
	use toml_edit::Array;
	use toml_edit::DocumentMut;
	use toml_edit::InlineTable;
	use toml_edit::Item;
	use toml_edit::Table;
	use toml_edit::Value;

	let mut doc = DocumentMut::new();

	// [project]
	let mut project = Table::new();
	project.insert("name", toml_edit::value(config.project.name.as_str()));
	project.insert(
		"revision",
		toml_edit::value(config.project.revision.as_str()),
	);
	if let Some(extends) = &config.project.extends {
		let mut arr = Array::new();
		for entry in extends {
			arr.push(entry.as_str());
		}
		project.insert("extends", toml_edit::value(arr));
	}
	doc.insert("project", Item::Table(project));

	// [profiles.<name>] tables, each secret an inline table. Sorted so the output
	// is deterministic regardless of the source HashMap ordering.
	let mut profiles = Table::new();
	profiles.set_implicit(true);

	let mut profile_names: Vec<&String> = config.profiles.keys().collect();
	profile_names.sort();

	for (index, profile_name) in profile_names.iter().enumerate() {
		// Keys were collected from the same map, so lookups always succeed.
		let profile_config = config
			.profiles
			.get(*profile_name)
			.expect("invariant: key comes from the same map");
		let mut profile_table = Table::new();

		for secret_name in profile_config.sorted_secret_names() {
			let secret_config = profile_config
				.secrets
				.get(&secret_name)
				.expect("invariant: name comes from the same map");
			let mut inline = InlineTable::new();
			inline.insert(
				"description",
				Value::from(secret_config.description.as_deref().unwrap_or("")),
			);
			if let Some(required) = secret_config.required {
				inline.insert("required", Value::from(required));
			} else if secret_config.at_least_one.is_some() || secret_config.exactly_one.is_some() {
				let mut groups = InlineTable::new();
				for (name, memberships) in [
					("at_least_one", &secret_config.at_least_one),
					("exactly_one", &secret_config.exactly_one),
				] {
					let Some(memberships) = memberships else {
						continue;
					};
					let value = match memberships.as_slice() {
						[membership] => Value::from(membership.as_str()),
						memberships => {
							let mut array = Array::new();
							for membership in memberships {
								array.push(membership.as_str());
							}
							Value::Array(array)
						}
					};
					groups.insert(name, value);
				}
				inline.insert("required", Value::InlineTable(groups));
			}
			if let Some(default) = &secret_config.default {
				inline.insert("default", Value::from(default.as_str()));
			}
			if let Some(composed) = &secret_config.composed {
				inline.insert("composed", Value::from(composed.as_str()));
			}
			if let Some(reference) = &secret_config.reference {
				let mut native_address = InlineTable::new();
				for (coordinate, value) in reference.coordinates() {
					if let Some(value) = value {
						native_address.insert(coordinate, Value::from(value));
					}
				}
				inline.insert("ref", Value::InlineTable(native_address));
			}
			profile_table.insert(&secret_name, toml_edit::value(inline));
		}

		// Surface the `extends` option as a comment before the first profile,
		// unless the project already declares an explicit `extends`.
		if index == 0 && config.project.extends.is_none() {
			profile_table.decor_mut().set_prefix(
				"\n# Extend configurations from subdirectories\n# extends = [ \"subdir1\", \"subdir2\" ]\n\n",
			);
		}

		profiles.insert(profile_name.as_str(), Item::Table(profile_table));
	}
	doc.insert("profiles", Item::Table(profiles));

	doc.to_string()
}

/// Ensures `add` will create a new effective declaration in an existing profile.
fn validate_add_target(app: &Secrets, profile: &str, name: &str) -> Result<()> {
	validate_add_secret_name(name)?;

	if !app.config().profiles.contains_key(profile) {
		let mut available: Vec<&str> = app.config().profiles.keys().map(String::as_str).collect();
		available.sort_unstable();
		return Err(miette!(
			"Profile '{}' is not defined in monosecret.toml. Available profiles: {}",
			profile,
			available.join(", ")
		));
	}
	if app.resolve_secret_config(name, Some(profile)).is_some() {
		return Err(miette!(
			"Secret '{}' is already declared for profile '{}'",
			name,
			profile
		));
	}

	Ok(())
}

/// Replaces an existing manifest only after its complete replacement has been
/// written and flushed to a temporary file in the same directory.
fn replace_manifest_atomically(
	path: &Path,
	write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> Result<()> {
	let metadata = fs::metadata(path)
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to read permissions for {}", path.display()))?;
	let parent = path
		.parent()
		.filter(|parent| !parent.as_os_str().is_empty())
		.unwrap_or_else(|| Path::new("."));
	let mut temporary = tempfile::Builder::new()
		.prefix(".monosecret-")
		.tempfile_in(parent)
		.into_diagnostic()
		.wrap_err_with(|| {
			format!(
				"Failed to create a temporary manifest next to {}",
				path.display()
			)
		})?;

	write(temporary.as_file_mut())
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to write temporary manifest for {}", path.display()))?;
	temporary
		.flush()
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to flush temporary manifest for {}", path.display()))?;
	temporary
		.as_file()
		.set_permissions(metadata.permissions())
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to preserve permissions for {}", path.display()))?;
	temporary
		.as_file()
		.sync_all()
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to sync temporary manifest for {}", path.display()))?;
	temporary.persist(path).map_err(|error| {
		miette!(
			"Failed to atomically replace {}: {}",
			path.display(),
			error.error
		)
	})?;

	Ok(())
}

fn write_manifest_atomically(path: &Path, contents: &str) -> Result<()> {
	replace_manifest_atomically(path, |temporary| temporary.write_all(contents.as_bytes()))
}

/// Quotes one argument for copying into a POSIX-compatible shell.
fn shell_quote(value: &str) -> String {
	format!("'{}'", value.replace('\'', "'\\''"))
}

fn add_follow_up_command(name: &str, profile: &str, file: Option<&Path>) -> String {
	let mut command = format!("monosecret set {name} --profile {}", shell_quote(profile));
	if let Some(path) = file {
		command.push_str(" --file ");
		command.push_str(&shell_quote(&path.to_string_lossy()));
	}
	command
}

/// Loads secrets using an explicit path or auto-detection, applying the optional
/// session reason (from `--reason`/`MONOSECRET_REASON`) and structured caller
/// context supplied by an integration.
fn load_secrets(
	file: Option<&Path>,
	reason: Option<&str>,
	caller: Option<&CallerContext>,
) -> Result<Secrets> {
	let mut secrets = match file {
		Some(path) => Secrets::load_from(path),
		None => Secrets::load(),
	}
	.into_diagnostic()
	.wrap_err("Failed to load monosecret configuration")?;

	// Destination previews are CLI presentation. The core computes the
	// provider-specific metadata and invokes this observer only when a CLI
	// caller installs it; SDK/library writes remain free of preview output.
	secrets.set_write_target_reporter(|target| {
		eprintln!(
			"Writing secret '{}' to {} (profile: {})\n  target: {}",
			target.name, target.provider_uri, target.profile, target.target
		);
	});

	let secrets = match reason {
		Some(reason) => secrets.with_reason(reason),
		None => secrets,
	};
	Ok(match caller {
		Some(caller) => secrets.with_caller(caller.clone()),
		None => secrets,
	})
}

/// Loads only the validated declaration model used by value-free commands.
///
/// Unlike [`load_secrets`], this does not initialize global configuration,
/// auditing, or provider state.
fn load_spec(file: Option<&Path>) -> Result<Spec> {
	match file {
		Some(path) => Spec::try_from(path),
		None => crate::secrets::find_config_file().and_then(|path| Spec::try_from(path.as_path())),
	}
	.into_diagnostic()
	.wrap_err("Failed to load monosecret configuration")
}

/// Applies a `--scope` selection to `app`. Clap resolves the flag and its
/// `MONOSECRET_SCOPE` fallback into the same `Option`, so `None` here means
/// neither was given.
///
/// A **blank** value is the caller opting out explicitly, not an absent one: it
/// selects no scope *and* suppresses the library's ambient `MONOSECRET_SCOPE`
/// fallback, so `--scope ""` clears an inherited scope instead of silently
/// deferring to it. Dropping the blank on its own would not be enough — the
/// library would read the environment and narrow the operation anyway, which is
/// the one direction a blank must never take (CI templates and workflow `env:`
/// maps routinely materialize an unset value as an empty string).
fn apply_scope(app: &mut Secrets, scope: Option<String>) {
	let Some(scope) = scope else {
		return;
	};
	if scope.trim().is_empty() {
		app.set_ignore_ambient_scope(true);
	} else {
		app.set_scope(scope);
	}
}

/// Resolves an explicitly supplied config-init provider or prompts for one.
///
/// Explicit values are checked against the same provider registry used for
/// runtime provider construction, without constructing a provider or doing I/O.
fn select_config_init_provider(provider: Option<String>) -> Result<String> {
	if let Some(provider) = provider {
		let provider = provider.trim();
		if provider.is_empty() {
			return Err(miette!("Provider backend cannot be empty"));
		}
		if !spec_names_known_provider(provider).into_diagnostic()? {
			let mut available: Vec<_> = providers().into_iter().map(|info| info.name).collect();
			available.sort_unstable();
			return Err(miette!(
				"Provider backend '{}' not found. Available providers: {}",
				provider,
				available.join(", ")
			));
		}
		if provider.split(':').next() == Some("file") {
			Box::<dyn Provider>::try_from(provider).into_diagnostic()?;
		}
		return Ok(provider.to_string());
	}

	use inquire::Select;

	let provider_choices: Vec<String> = providers()
		.into_iter()
		.map(|info| info.display_with_examples())
		.collect();
	let selected_choice = Select::new("Select your preferred provider backend:", provider_choices)
		.prompt()
		.into_diagnostic()?;

	let selected_provider = selected_choice
		.split(':')
		.next()
		.unwrap_or("keyring")
		.to_string();

	if selected_provider == "file" {
		use inquire::Text;

		let directory = Text::new("File provider root directory:")
			.with_help_message("Use a relative path such as ./.secrets or an absolute path")
			.prompt()
			.into_diagnostic()?;
		let spec = format!("file:{}", directory.trim());
		Box::<dyn Provider>::try_from(spec.as_str())
			.into_diagnostic()
			.wrap_err("Invalid file provider configuration")?;
		Ok(spec)
	} else {
		#[cfg(feature = "kubernetes")]
		{
			if selected_provider == "kubernetes" {
				use inquire::Text;

				let kind_choices = vec![KubernetesKind::ConfigMap, KubernetesKind::Secret];
				let kind = Select::new(
					"Select your preferred kubernetes object kind:",
					kind_choices,
				)
				.prompt()
				.into_diagnostic()?;
				let name = Text::new("Kubernetes object name:")
					.prompt()
					.into_diagnostic()?;
				let namespace = Text::new("Kubernetes namespace:")
					.with_help_message("Leave empty to use the default cluster namespace")
					.prompt()
					.into_diagnostic()?;
				let namespace = if namespace.is_empty() {
					None
				} else {
					Some(namespace)
				};

				let spec = KubernetesProvider::build_uri(&kind, &name, &namespace);
				Box::<dyn Provider>::try_from(spec.as_str())
					.into_diagnostic()
					.wrap_err("Invalid Kubernetes provider configuration")?;
				Ok(spec)
			} else {
				Ok(selected_provider)
			}
		}

		#[cfg(not(feature = "kubernetes"))]
		{
			Ok(selected_provider)
		}
	}
}

/// Resolves an explicitly supplied config-init profile or prompts for one.
fn select_config_init_profile(profile: Option<String>) -> Result<Option<String>> {
	if let Some(profile) = profile {
		let profile = profile.trim();
		if profile.is_empty() {
			return Err(miette!(
				"Default profile cannot be empty; use 'none' to clear it"
			));
		}
		return Ok((profile != "none").then(|| profile.to_string()));
	}

	use inquire::Select;

	let profiles = vec!["development", "default", "none"];
	let profile_choice = Select::new("Select your default profile:", profiles)
		.with_help_message("'development' is recommended for local development environments")
		.prompt()
		.into_diagnostic()?;

	Ok((profile_choice != "none").then(|| profile_choice.to_string()))
}

/// Builds the structured caller context from global CLI flags. Clap global
/// arguments may appear on either side of the subcommand, so dependency
/// validation lives here instead of `requires = "caller"` (which treats a
/// parent and subcommand occurrence as different scopes).
fn caller_context(cli: &Cli) -> Result<Option<CallerContext>> {
	let Some(name) = &cli.caller else {
		if cli.caller_version.is_some()
			|| cli.caller_operation.is_some()
			|| cli.caller_resource.is_some()
		{
			return Err(miette!(
				"--caller-version, --caller-operation, and --caller-resource require --caller"
			));
		}
		return Ok(None);
	};

	let mut context = CallerContext::new(name);
	if let Some(version) = &cli.caller_version {
		context = context.with_version(version);
	}
	if let Some(operation) = &cli.caller_operation {
		context = context.with_operation(operation);
	}
	if let Some(resource) = &cli.caller_resource {
		context = context.with_resource(resource);
	}
	Ok(Some(context))
}

/// A lightweight log level used by the CLI's stderr tracing subscriber.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
enum LogLevel {
	Off,
	Error,
	Warn,
	Info,
	Debug,
	Trace,
}

impl LogLevel {
	fn from_name(name: &str) -> Option<Self> {
		match name.trim().to_ascii_lowercase().as_str() {
			"off" | "quiet" => Some(Self::Off),
			"error" => Some(Self::Error),
			"warn" | "warning" => Some(Self::Warn),
			"info" => Some(Self::Info),
			"debug" => Some(Self::Debug),
			"trace" | "verbose" => Some(Self::Trace),
			_ => None,
		}
	}

	fn from_tracing(level: Level) -> Self {
		match level {
			Level::ERROR => Self::Error,
			Level::WARN => Self::Warn,
			Level::INFO => Self::Info,
			Level::DEBUG => Self::Debug,
			Level::TRACE => Self::Trace,
		}
	}

	fn as_str(self) -> &'static str {
		match self {
			Self::Off => "OFF",
			Self::Error => "ERROR",
			Self::Warn => "WARN",
			Self::Info => "INFO",
			Self::Debug => "DEBUG",
			Self::Trace => "TRACE",
		}
	}
}

struct LogDirective {
	target: Option<String>,
	level: LogLevel,
}

impl LogDirective {
	fn matches(&self, target: &str) -> bool {
		self.target
			.as_deref()
			.is_none_or(|directive_target| target.starts_with(directive_target))
	}

	fn target_len(&self) -> usize {
		self.target.as_deref().map_or(0, str::len)
	}
}

struct StderrLogger {
	directives: Vec<LogDirective>,
}

impl StderrLogger {
	fn for_verbosity(verbosity: u8) -> Self {
		let level = match verbosity {
			0 => LogLevel::Off,
			1 => LogLevel::Debug,
			_ => LogLevel::Trace,
		};

		Self::for_monosecret(level)
	}

	fn from_env(value: &str) -> Self {
		let normalized = value.trim().to_ascii_lowercase();
		if normalized == "verbose" {
			return Self::for_monosecret(LogLevel::Trace);
		}
		if normalized == "quiet" {
			return Self::global(LogLevel::Off);
		}

		let directives: Vec<_> = value
			.split(',')
			.filter_map(|directive| parse_log_directive(directive.trim()))
			.collect();

		if directives.is_empty() {
			Self::for_monosecret(LogLevel::Trace)
		} else {
			Self { directives }
		}
	}

	fn global(level: LogLevel) -> Self {
		Self {
			directives: vec![LogDirective {
				target: None,
				level,
			}],
		}
	}

	fn for_monosecret(level: LogLevel) -> Self {
		Self {
			directives: vec![LogDirective {
				target: Some("monosecret".to_string()),
				level,
			}],
		}
	}

	fn max_level_for(&self, target: &str) -> LogLevel {
		self.directives
			.iter()
			.filter(|directive| directive.matches(target))
			.max_by_key(|directive| directive.target_len())
			.map_or(LogLevel::Off, |directive| directive.level)
	}
}

impl Subscriber for StderrLogger {
	fn enabled(&self, metadata: &Metadata<'_>) -> bool {
		LogLevel::from_tracing(*metadata.level()) <= self.max_level_for(metadata.target())
	}

	fn new_span(&self, _span: &Attributes<'_>) -> Id {
		Id::from_u64(1)
	}

	fn record(&self, _span: &Id, _values: &Record<'_>) {}

	fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

	fn event(&self, event: &Event<'_>) {
		let mut visitor = LogVisitor::default();
		event.record(&mut visitor);

		let level = LogLevel::from_tracing(*event.metadata().level()).as_str();
		let target = event.metadata().target();
		let message = visitor.message.unwrap_or_default();

		if visitor.fields.is_empty() {
			eprintln!("{level} {target}: {message}");
		} else if message.is_empty() {
			eprintln!("{level} {target}: {}", visitor.fields.join(" "));
		} else {
			eprintln!("{level} {target}: {message} {}", visitor.fields.join(" "));
		}
	}

	fn enter(&self, _span: &Id) {}

	fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct LogVisitor {
	message: Option<String>,
	fields: Vec<String>,
}

impl Visit for LogVisitor {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.record_field(field, format_args!("{value:?}"));
	}

	fn record_str(&mut self, field: &Field, value: &str) {
		self.record_field(field, format_args!("{value}"));
	}

	fn record_i64(&mut self, field: &Field, value: i64) {
		self.record_field(field, format_args!("{value}"));
	}

	fn record_u64(&mut self, field: &Field, value: u64) {
		self.record_field(field, format_args!("{value}"));
	}

	fn record_bool(&mut self, field: &Field, value: bool) {
		self.record_field(field, format_args!("{value}"));
	}
}

impl LogVisitor {
	fn record_field(&mut self, field: &Field, value: std::fmt::Arguments<'_>) {
		let value = value.to_string();
		if field.name() == "message" {
			self.message = Some(value);
		} else {
			self.fields.push(format!("{}={value}", field.name()));
		}
	}
}

fn parse_log_directive(value: &str) -> Option<LogDirective> {
	let (target, level) = value
		.split_once('=')
		.map_or((None, value), |(target, level)| {
			(Some(target.trim()), level)
		});
	let level = LogLevel::from_name(level)?;
	let target = target
		.filter(|target| !target.is_empty())
		.map(str::to_string);

	Some(LogDirective { target, level })
}

fn init_tracing(verbosity: u8) {
	let logger = std::env::var("RUST_LOG")
		.or_else(|_| std::env::var("rust_log"))
		.ok()
		.map_or_else(
			|| StderrLogger::for_verbosity(verbosity),
			|value| StderrLogger::from_env(&value),
		);

	let _ = tracing::subscriber::set_global_default(logger);
}

#[cfg(test)]
mod logging_tests {
	use super::*;

	#[test]
	fn log_levels_parse_and_render_all_supported_inputs() {
		let cases = [
			("off", Some(LogLevel::Off), "OFF"),
			("quiet", Some(LogLevel::Off), "OFF"),
			("error", Some(LogLevel::Error), "ERROR"),
			("warn", Some(LogLevel::Warn), "WARN"),
			("warning", Some(LogLevel::Warn), "WARN"),
			("info", Some(LogLevel::Info), "INFO"),
			("debug", Some(LogLevel::Debug), "DEBUG"),
			("trace", Some(LogLevel::Trace), "TRACE"),
			("verbose", Some(LogLevel::Trace), "TRACE"),
			("unknown", None, ""),
		];

		for (name, expected, rendered) in cases {
			let parsed = LogLevel::from_name(name);
			assert_eq!(parsed, expected);
			if let Some(level) = parsed {
				assert_eq!(level.as_str(), rendered);
			}
		}

		assert_eq!(LogLevel::from_tracing(Level::ERROR), LogLevel::Error);
		assert_eq!(LogLevel::from_tracing(Level::WARN), LogLevel::Warn);
		assert_eq!(LogLevel::from_tracing(Level::INFO), LogLevel::Info);
		assert_eq!(LogLevel::from_tracing(Level::DEBUG), LogLevel::Debug);
		assert_eq!(LogLevel::from_tracing(Level::TRACE), LogLevel::Trace);
	}

	#[test]
	fn log_directives_match_targets_and_select_most_specific_level() {
		let global = parse_log_directive("debug").expect("global directive parses");
		assert!(global.matches("anything"));
		assert_eq!(global.target_len(), 0);
		assert_eq!(global.level, LogLevel::Debug);

		let empty_target = parse_log_directive("=info").expect("empty target becomes global");
		assert!(empty_target.matches("monosecret"));
		assert_eq!(empty_target.target_len(), 0);
		assert_eq!(empty_target.level, LogLevel::Info);

		let targeted =
			parse_log_directive("monosecret::provider=warn").expect("targeted directive parses");
		assert!(targeted.matches("monosecret::provider::onepassword"));
		assert!(!targeted.matches("monosecret::secrets"));
		assert_eq!(targeted.target_len(), "monosecret::provider".len());
		assert_eq!(targeted.level, LogLevel::Warn);
		assert!(parse_log_directive("monosecret=nope").is_none());

		let logger =
			StderrLogger::from_env("monosecret=debug,monosecret::provider=trace,other=error");
		assert_eq!(logger.max_level_for("monosecret::secrets"), LogLevel::Debug);
		assert_eq!(
			logger.max_level_for("monosecret::provider::onepassword"),
			LogLevel::Trace
		);
		assert_eq!(logger.max_level_for("other::module"), LogLevel::Error);
		assert_eq!(logger.max_level_for("unmatched"), LogLevel::Off);
	}

	#[test]
	fn stderr_logger_maps_cli_and_environment_filters() {
		assert_eq!(
			StderrLogger::for_verbosity(0).max_level_for("monosecret"),
			LogLevel::Off
		);
		assert_eq!(
			StderrLogger::for_verbosity(1).max_level_for("monosecret"),
			LogLevel::Debug
		);
		assert_eq!(
			StderrLogger::for_verbosity(2).max_level_for("monosecret"),
			LogLevel::Trace
		);
		assert_eq!(
			StderrLogger::from_env("verbose").max_level_for("monosecret"),
			LogLevel::Trace
		);
		assert_eq!(
			StderrLogger::from_env("quiet").max_level_for("anything"),
			LogLevel::Off
		);
		assert_eq!(
			StderrLogger::from_env("not-a-filter").max_level_for("monosecret"),
			LogLevel::Trace
		);
	}

	#[test]
	fn stderr_logger_records_events_and_span_callbacks() {
		tracing::subscriber::with_default(StderrLogger::global(LogLevel::Trace), || {
			tracing::info!("message only");
			tracing::info!(answer = 42_u64);
			tracing::info!(
				signed = -1_i64,
				unsigned = 7_u64,
				flag = true,
				text = "value",
				debug = ?vec![1, 2],
				"message with fields"
			);

			let span = tracing::span!(Level::INFO, "covered_span", field = 1_i64);
			span.record("field", 2_i64);
			let parent = tracing::span!(Level::INFO, "covered_parent");
			span.follows_from(&parent);
			let _entered = span.enter();
		});
	}
}

/// Main entry point for the monosecret CLI application.
///
/// Parses command-line arguments and executes the appropriate command.
/// All commands are delegated to the Monosecret library for processing.
///
/// # Returns
///
/// * `Ok(())` - If the command executed successfully
/// * `Err` - If any error occurred during execution
#[doc(hidden)]
pub fn main() -> Result<()> {
	completion::complete();
	let matches = Cli::command().get_matches();
	let typed = TypedArgs::from_matches(&matches);
	let mut cli = match Cli::from_arg_matches(&matches) {
		Ok(cli) => cli,
		Err(error) => error.exit(),
	};

	// Historical env fallback kept for fork compatibility.
	if cli.file.is_none() {
		cli.file = std::env::var_os("SECRETSPEC_FILE").map(PathBuf::from);
	}
	init_tracing(cli.verbose);
	let caller = caller_context(&cli)?;

	match cli.command {
		Commands::Claude { action } => {
			claude::run(
				action,
				cli.file.as_ref(),
				cli.reason.as_deref(),
				caller.as_ref(),
				typed,
			)
		}
		Commands::Docker { action } => {
			docker::run(
				action,
				cli.file.as_deref(),
				cli.reason.as_deref(),
				caller.as_ref(),
				typed,
			)
		}
		// Initialize a new monosecret.toml configuration file
		Commands::Init {
			from,
			project,
			profile,
		} => {
			// Check if monosecret.toml already exists
			if PathBuf::from("monosecret.toml").exists() {
				use inquire::Confirm;
				let overwrite = Confirm::new("monosecret.toml already exists. Overwrite?")
					.with_default(false)
					.prompt()
					.into_diagnostic()?;

				if !overwrite {
					println!("Cancelled.");
					return Ok(());
				}
			}

			let project_name = match project {
				Some(project) => project,
				None => {
					std::env::current_dir()
						.into_diagnostic()?
						.file_name()
						.unwrap_or_default()
						.to_string_lossy()
						.to_string()
				}
			};
			if project_name.is_empty() {
				return Err(miette!("init project cannot be empty"));
			}
			if profile.is_empty() {
				return Err(miette!("init profile cannot be empty"));
			}

			// Create provider from the specification string.
			let provider: Box<dyn Provider> = from.as_str().try_into().into_diagnostic()?;
			let source_reads = crate::provider::spec_provider_reads(&from);

			// Discover declarations in the namespace the new manifest will use.
			let secrets = provider
				.reflect(crate::DiscoveryContext::new(&project_name, &profile))
				.into_diagnostic()?
				.into_iter()
				.map(|(name, secret)| (name, secret.into_config()))
				.collect();

			// Create a new project config
			let mut profiles = HashMap::new();
			profiles.insert(
				profile.clone(),
				ConfigProfile {
					defaults: None,
					secrets,
				},
			);

			let project_config = Config {
				project: Project {
					name: project_name,
					..Default::default()
				},
				profiles,
				defaults: None,
				providers: None,
				groups: None,
				scopes: None,
			};
			let mut content = generate_toml_with_comments(&project_config);

			// Append comprehensive example
			content.push_str(get_example_toml());

			fs::write("monosecret.toml", content).into_diagnostic()?;

			// Set file permissions to 600 (owner read/write only) on Unix systems
			#[cfg(unix)]
			{
				let metadata = fs::metadata("monosecret.toml").into_diagnostic()?;
				let mut permissions = metadata.permissions();
				permissions.set_mode(0o600);
				fs::set_permissions("monosecret.toml", permissions).into_diagnostic()?;
			}

			let secret_count = project_config
				.profiles
				.values()
				.map(|p| p.secrets.len())
				.sum::<usize>();
			println!("✓ Created monosecret.toml with {secret_count} secrets");

			// If we discovered a populated provider, explain how to copy its
			// values after reviewing the declarations.
			if secret_count > 0 {
				if source_reads {
					println!("\nTo migrate your secrets from {from}:");
					println!("  1. Review monosecret.toml and adjust as needed");
					println!(
						"  2. {}    # Import secret values",
						migration_command(&from, &profile)
					);
				} else {
					println!(
						"\nDiscovered secret names from {from}, but this write-only provider cannot return plaintext values to import."
					);
				}
			}

			println!("\nNext steps:");
			if source_reads {
				println!("  1. monosecret config global init    # Set up user defaults (0.17+)");
				println!("  2. monosecret check          # Verify all secrets and set them");
				println!("  3. monosecret run -- your-command  # Run with secrets");
			} else {
				println!("  1. Review monosecret.toml and adjust the discovered names");
				println!(
					"  2. monosecret config global init    # Set up defaults for readable providers"
				);
				println!(
					"  3. Use monosecret set with an explicit provider to publish secret values"
				);
			}

			Ok(())
		}
		Commands::Add {
			name,
			description,
			profile,
		} => {
			let app = load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			let profile = app.resolve_profile_name(profile.as_deref());
			validate_add_target(&app, &profile, &name)?;

			let description = match description {
				Some(description) => description,
				None => {
					inquire::Text::new(&format!("Description for {name}:"))
						.prompt()
						.into_diagnostic()?
				}
			};
			let description = description.trim();
			if description.is_empty() {
				return Err(miette!("Secret description cannot be empty"));
			}

			let manifest_path = match &cli.file {
				Some(path) => path.clone(),
				None => crate::secrets::find_config_file().into_diagnostic()?,
			};
			let source = fs::read_to_string(&manifest_path)
				.into_diagnostic()
				.wrap_err_with(|| format!("Failed to read {}", manifest_path.display()))?;
			let updated = add_secret_to_spec(&source, &profile, &name, description)?;
			write_manifest_atomically(&manifest_path, &updated)?;

			println!(
				"✓ Added secret '{}' to profile '{}' in {}",
				name,
				profile,
				manifest_path.display()
			);
			println!(
				"Set its value with: {}",
				add_follow_up_command(&name, &profile, cli.file.as_deref())
			);
			Ok(())
		}
		Commands::Git { action } => {
			git::run(
				action,
				cli.file.as_deref(),
				cli.reason.as_deref(),
				caller.as_ref(),
				typed,
			)
		}
		// Handle configuration management commands
		Commands::Config { action } => {
			match normalize_config_action(action) {
				ConfigAction::Global { .. } => unreachable!("global action was normalized"),
				// Initialize user configuration, prompting only for omitted values.
				ConfigAction::Init { provider, profile } => {
					let provider = select_config_init_provider(provider)?;
					let profile = select_config_init_profile(profile)?;

					// Preserve any existing config (audit settings, provider aliases)
					// rather than overwriting the whole file: re-running `config init`
					// must not silently drop a user's `[audit]` table — which would
					// re-enable disabled logging — or their saved provider aliases.
					let mut config = GlobalConfig::load().into_diagnostic()?.unwrap_or_default();
					config.defaults.provider = Some(provider);
					config.defaults.profile = profile;

					config.save().into_diagnostic()?;
					println!(
						"\n✓ Configuration saved to {}",
						GlobalConfig::path().into_diagnostic()?.display()
					);
					Ok(())
				}
				// Display current user configuration
				ConfigAction::Show => {
					match GlobalConfig::load().into_diagnostic()? {
						Some(config) => {
							println!(
								"Configuration file: {}\n",
								GlobalConfig::path().into_diagnostic()?.display()
							);
							match config.defaults.provider {
								Some(provider) => println!("Provider: {provider}"),
								None => println!("Provider: (none)"),
							}
							match config.defaults.profile {
								Some(profile) => println!("Profile:  {profile}"),
								None => println!("Profile:  (none)"),
							}
							if let Some(providers) = &config.defaults.providers {
								println!("\nProvider Aliases:");
								let mut aliases: Vec<_> = providers.iter().collect();
								aliases.sort_by_key(|(a, _)| *a);
								for (alias, uri) in aliases {
									println!("  {alias} = {uri}");
								}
							} else {
								println!("\nProvider Aliases: (none)");
							}
						}
						None => {
							println!(
								"No configuration found. Run 'monosecret config global init' to create one."
							);
						}
					}
					Ok(())
				}
				// Manage provider aliases
				ConfigAction::Provider(action) => {
					match action {
						ProviderAction::Add {
							name,
							uri,
							credential,
						} => {
							// Parse each `NAME=PROVIDER` binding into a credential source.
							let mut credentials = HashMap::new();
							for binding in &credential {
								let (credential_name, spec) =
									binding.split_once('=').ok_or_else(|| {
										miette!(
											"--credential expects NAME=PROVIDER, got '{binding}'"
										)
									})?;
								if credential_name.is_empty() || spec.is_empty() {
									return Err(miette!(
										"--credential expects a non-empty NAME=PROVIDER, got '{binding}'"
									));
								}
								credentials.insert(
									credential_name.to_string(),
									crate::config::CredentialSource::from(spec),
								);
							}
							// An empty map keeps the compact bare-string alias form.
							let alias_value =
								crate::config::ProviderAlias::leaf(uri.clone(), credentials);

							// Load or create config
							let mut config =
								GlobalConfig::load()
									.into_diagnostic()?
									.unwrap_or(GlobalConfig {
										defaults: GlobalDefaults {
											provider: None,
											profile: None,
											providers: None,
										},
										audit: None,
									});

							// Initialize providers map if needed
							if config.defaults.providers.is_none() {
								config.defaults.providers = Some(HashMap::new());
							}

							// Add or update the provider alias
							if let Some(providers) = &mut config.defaults.providers {
								let display = providers
									.insert(name.clone(), alias_value)
									.map_or("added", |_| "updated");
								config.save().into_diagnostic()?;
								println!("✓ Provider alias '{name}' {display}: '{uri}'");
								if !credential.is_empty() {
									println!("  credentials: {}", credential.join(", "));
									println!(
										"  run 'monosecret config provider login {name}' to store the credentials"
									);
								}
							}
							Ok(())
						}
						ProviderAction::Remove { name } => {
							// Load config
							match GlobalConfig::load().into_diagnostic()? {
								Some(mut config) => {
									if let Some(providers) = &mut config.defaults.providers {
										if providers.remove(&name).is_some() {
											config.save().into_diagnostic()?;
											println!("✓ Provider alias '{name}' removed");
										} else {
											println!("✗ Provider alias '{name}' not found");
										}
									} else {
										println!("✗ No provider aliases configured");
									}
								}
								None => {
									println!(
										"✗ No configuration found. Run 'monosecret config global init' first."
									);
								}
							}
							Ok(())
						}
						ProviderAction::List => {
							match GlobalConfig::load().into_diagnostic()? {
								Some(config) => {
									if let Some(providers) = config.defaults.providers {
										if providers.is_empty() {
											println!("No provider aliases configured.");
										} else {
											println!("Provider Aliases:");
											let mut aliases: Vec<_> =
												providers.into_iter().collect();
											// Keys are unique map keys, so the
											// resulting order matches key order.
											aliases.sort_by_key(|(alias, _)| alias.clone());
											for (alias, uri) in aliases {
												println!("  {alias} = {uri}");
											}
										}
									} else {
										println!("No provider aliases configured.");
									}
								}
								None => {
									println!(
										"No configuration found. Run 'monosecret config global init' first."
									);
								}
							}
							Ok(())
						}
						ProviderAction::Login { name } => {
							let app = Arc::new(load_secrets(
								cli.file.as_deref(),
								cli.reason.as_deref(),
								caller.as_ref(),
							)?);
							let credentials =
								app.declared_provider_credentials(&name).into_diagnostic()?;
							let resolved = app.resolve_provider_spec(name.clone());
							if crate::provider::spec_uses_dynamic_credentials(&resolved)
								.into_diagnostic()?
							{
								let broker = Arc::new(LoginCredentialBroker::new(
									app.clone(),
									name.clone(),
									credentials,
								));
								app.initialize_external_provider_with_broker(&name, broker.clone())
									.into_diagnostic()?;
								let stored = broker
									.stored
									.lock()
									.unwrap_or_else(std::sync::PoisonError::into_inner);
								if stored.is_empty() {
									println!(
										"Provider alias '{name}' requested no Monosecret-managed credentials."
									);
								} else {
									for (credential_name, location) in stored.iter() {
										println!("✓ stored {credential_name} in {location}");
									}
								}
								return Ok(());
							}
							let provider_reads = crate::provider::spec_provider_reads(&resolved);
							if credentials.is_empty() {
								println!("Provider alias '{name}' declares no credentials.");
								return Ok(());
							}
							for (credential_name, source) in credentials {
								let entered = inquire::Password::new(&format!(
									"Enter {credential_name} for provider '{name}' (source: {}):",
									source.display_provider()
								))
								.without_confirmation()
								.prompt()
								.into_diagnostic()?;
								if entered.is_empty() {
									println!("✗ Skipped {credential_name} (empty)");
									continue;
								}
								let location = app
									.store_provider_credential(
										&source,
										&credential_name,
									&SecretBytes::from_utf8(entered),
									)
									.into_diagnostic()?;
								println!("✓ stored {credential_name} in {location}");
							}
							if provider_reads {
								println!(
									"\nRun 'monosecret check --provider {name}' to verify authentication."
								);
							} else {
								println!(
									"\nProvider alias '{name}' is write-only; authentication will be verified on its next write."
								);
							}
							Ok(())
						}
					}
				}
			}
		}
		// Set a secret value in the specified provider
		Commands::Set {
			name,
			value,
			from_file,
			provider,
			profile,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(p) = provider {
				app.set_provider(p);
			}
			if let Some(p) = profile {
				app.set_profile(p);
			}
			app.set_provider_credential_prompt(prompt_provider_credential);
			let result = match (value, from_file) {
				(Some(value), None) => app.set_text(&name, &value),
				(None, Some(path)) => app.set_with_input(&name, |_| {
					let bytes = if path == Path::new("-") {
						let mut bytes = Vec::new();
						std::io::stdin().read_to_end(&mut bytes)?;
						bytes
					} else {
						fs::read(&path).map_err(|error| {
							std::io::Error::new(
								error.kind(),
								format!("Failed to read {}: {error}", path.display()),
							)
						})?
					};
					Ok(SecretBytes::from_vec(bytes))
				}),
				(None, None) => app.prompt_and_set(&name),
				(Some(_), Some(_)) => unreachable!("clap rejects conflicting set inputs"),
			};
			result.into_diagnostic().wrap_err("Failed to set secret")?;
			Ok(())
		}
		// Retrieve and display a secret value
		Commands::Get {
			name,
			provider,
			profile,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(p) = provider {
				app.set_provider(p);
			}
			if let Some(p) = profile {
				app.set_profile(p);
			}
			app.get(&name)
				.into_diagnostic()
				.wrap_err("Failed to get secret")?;
			Ok(())
		}
		Commands::Delete {
			mut names,
			all,
			yes,
			provider,
			profile,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(provider) = provider {
				app.set_provider(provider);
			}
			if let Some(profile) = profile {
				app.set_profile(profile);
			}

			if all {
				names = app
					.profile_secret_names_unscoped(None)
					.into_diagnostic()
					.wrap_err("Failed to list secrets for deletion")?;
				// Composed secrets have no stored value. An explicit name gets
				// a useful error from `Secrets::delete`; a whole-profile sweep
				// simply has nothing to do for them.
				names.retain(|name| {
					app.resolve_secret_config(name, None)
						.is_some_and(|secret| secret.composed.is_none())
				});
			} else {
				// Repeating a name should not turn the second occurrence into a
				// confusing "already absent" result.
				let mut seen = HashSet::new();
				names.retain(|name| seen.insert(name.clone()));
			}

			if all && !yes && !names.is_empty() {
				if !std::io::stdin().is_terminal() {
					return Err(miette!(
						"refusing to delete all stored secret values without confirmation; pass --yes for non-interactive use"
					));
				}
				use inquire::Confirm;
				let profile = app.resolve_profile_name(None);
				let confirmed = Confirm::new(&format!(
					"Delete {} stored secret {} from profile '{profile}'?",
					names.len(),
					if names.len() == 1 { "value" } else { "values" }
				))
				.with_default(false)
				.prompt()
				.into_diagnostic()?;
				if !confirmed {
					println!("Cancelled.");
					return Ok(());
				}
			}

			let mut deleted = 0;
			let mut absent = 0;
			let mut failures = Vec::new();
			for name in names {
				match app.delete(&name) {
					Ok(true) => {
						println!("Deleted '{name}'");
						deleted += 1;
					}
					Ok(false) => {
						println!("'{name}' was already absent");
						absent += 1;
					}
					Err(error) => failures.push((name, error.to_string())),
				}
			}

			println!(
				"Deleted {deleted} secret {}; {absent} already absent",
				if deleted == 1 { "value" } else { "values" }
			);
			if !failures.is_empty() {
				return Err(miette!(
					"{} secret {} could not be deleted: {}",
					failures.len(),
					if failures.len() == 1 {
						"value"
					} else {
						"values"
					},
					failures
						.into_iter()
						.map(|(name, error)| format!("'{name}': {error}"))
						.collect::<Vec<_>>()
						.join("; ")
				));
			}
			Ok(())
		}
		// Execute a command with secrets injected as environment variables
		Commands::Run {
			command,
			provider,
			profile,
			scope,
			include,
			group,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(p) = provider {
				app.set_provider(p);
			}
			if let Some(p) = profile {
				app.set_profile(p);
			}
			apply_scope(&mut app, scope);
			app.run_filtered(command, &include, &group)
				.into_diagnostic()
				.wrap_err("Failed to run command")?;
			Ok(())
		}
		// Resolve secrets and print them without running a command
		Commands::Export {
			provider,
			profile,
			scope,
			format,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(p) = provider {
				app.set_provider(p);
			}
			if let Some(p) = profile {
				app.set_profile(p);
			}
			apply_scope(&mut app, scope);
			let mut out = std::io::stdout().lock();
			app.export(format, &mut out)
				.into_diagnostic()
				.wrap_err("Failed to export secrets")?;
			Ok(())
		}
		// Verify all required secrets are available
		Commands::Check {
			provider,
			profile,
			scope,
			no_prompt,
			json,
			explain,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(p) = provider {
				app.set_provider(p);
			}
			if let Some(p) = profile {
				app.set_profile(p);
			}
			apply_scope(&mut app, scope);

			// `--json`/`--explain` surface the value-free resolution report
			// instead of the interactive prompt-for-missing flow. They report
			// on every declared secret (including missing required ones) and
			// exit non-zero when a required secret is missing, so CI can gate.
			if json || explain {
				// Value-free report: never mints, stores, or writes a secret as
				// a side effect of this read-only preflight (unlike `validate()`,
				// which is the value-injecting path).
				let report = app
					.report()
					.into_diagnostic()
					.wrap_err("Failed to resolve secrets")?;

				if json {
					let rendered = serde_json::to_string_pretty(&report)
						.into_diagnostic()
						.wrap_err("Failed to serialize resolution report")?;
					println!("{rendered}");
				} else {
					print!("{}", report.to_explain_string());
				}

				if !report.all_required_present() {
					std::process::exit(1);
				}
				return Ok(());
			}

			let mut out = std::io::stdout();
			let mut validated = app
				.check_with_writer(no_prompt, &mut out)
				.into_diagnostic()
				.wrap_err("Failed to check secrets")?;
			// Persist temp files so they outlive the command
			validated
				.keep_temp_files()
				.into_diagnostic()
				.wrap_err("Failed to persist temporary files")?;
			Ok(())
		}
		// Export typed-accessor or configuration editor schemas (value-free).
		Commands::Schema {
			profile,
			config,
			output,
		} => {
			let schema = match config {
				Some(kind) => {
					crate::config::schema::generate(matches!(kind, ConfigSchemaKind::Global))
						.into_diagnostic()?
				}
				None => load_spec(cli.file.as_deref())?
					.schema_json(profile.as_deref())
					.into_diagnostic()?,
			};
			match output {
				Some(path) => {
					fs::write(&path, schema)
						.into_diagnostic()
						.wrap_err_with(|| format!("Failed to write {}", path.display()))?;
				}
				None => print!("{schema}"),
			}
			Ok(())
		}
		Commands::Completions { shell } => {
			generate_completions(shell, &mut std::io::stdout().lock()).into_diagnostic()?;
			Ok(())
		}
		// Import secrets from one provider to another
		Commands::Import {
			from_provider,
			delete_source,
		} => {
			let app = load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if delete_source {
				app.import_with_delete_source(&from_provider)
					.into_diagnostic()
					.wrap_err("Failed to import and delete source secrets")?;
			} else {
				app.import(&from_provider)
					.into_diagnostic()
					.wrap_err("Failed to import secrets")?;
			}
			Ok(())
		}
		Commands::Cache { action } => {
			match action {
				CacheAction::Clear { name, profile } => {
					let mut app =
						load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
					if let Some(profile) = profile {
						app.set_profile(profile);
					}
					let cleared = app
						.clear_cache(name.as_deref())
						.into_diagnostic()
						.wrap_err("Failed to clear cache")?;
					println!(
						"Cleared {cleared} cache {}",
						if cleared == 1 { "entry" } else { "entries" }
					);
					Ok(())
				}
			}
		}
		Commands::Serve { read_only } => {
			crate::provider::block_on(crate::serve::run_stdio(read_only))
				.into_diagnostic()
				.wrap_err("Monosecret resolver failed")
		}
		// Show the local audit log
		Commands::Audit {
			project,
			action,
			tail,
			json,
		} => show_audit_log(project.as_deref(), action.as_deref(), tail, json),
		// Emit a secret-value-free manifest for SDK code generation
		Commands::Manifest { format } => {
			let app = load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			match format {
				ManifestFormat::Json => {
					let json = serde_json::to_string_pretty(&app.manifest())
						.into_diagnostic()
						.wrap_err("Failed to serialize manifest")?;
					println!("{json}");
				}
			}
			Ok(())
		}
		// Load resolved secrets into a shell or CI environment.
		Commands::Env {
			shell,
			provider,
			profile,
			scope,
			output,
			include,
			group,
		} => {
			let mut app =
				load_secrets(cli.file.as_deref(), cli.reason.as_deref(), caller.as_ref())?;
			if let Some(provider) = provider {
				app.set_provider(provider);
			}
			if let Some(profile) = profile {
				app.set_profile(profile);
			}
			apply_scope(&mut app, scope);
			let pairs = app
				.env_vars(&include, &group)
				.into_diagnostic()
				.wrap_err("Failed to resolve secrets for env export")?;
			shell::emit(shell, &pairs, output.as_deref())
				.into_diagnostic()
				.wrap_err_with(|| format!("Failed to emit {} declarations", shell.as_str()))?;
			Ok(())
		}
	}
}

/// Reads and prints the local audit log, applying optional filters.
fn show_audit_log(
	project: Option<&str>,
	action: Option<&str>,
	tail: Option<usize>,
	json: bool,
) -> Result<()> {
	let audit = GlobalConfig::load()
		.into_diagnostic()
		.wrap_err("Failed to load global configuration")?
		.and_then(|g| g.audit)
		.unwrap_or_default();

	let path = audit.resolved_path().ok_or_else(|| {
		if audit.has_relative_path() {
			miette!(
				"[audit] path {} is not absolute; set an absolute path in ~/.config/monosecret/config.toml",
				audit
					.path
					.as_deref()
					.map(|p| p.display().to_string())
					.unwrap_or_default()
			)
		} else {
			miette!("Could not determine the audit log location")
		}
	})?;

	if !path.exists() {
		eprintln!("No audit log found at {}", path.display());
		return Ok(());
	}

	let content = fs::read_to_string(&path)
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to read audit log at {}", path.display()))?;

	for (line, value) in filter_audit_entries(&content, project, action, tail) {
		if json {
			println!("{line}");
		} else {
			println!("{}", format_audit_line(&value));
		}
	}

	Ok(())
}

/// Parses the audit log, keeps the entries matching the optional `project` and
/// `action` filters, then retains only the last `tail` of them. Each surviving
/// entry is returned as its raw line text (for `--json`) paired with its parsed
/// JSON value (for formatting). A line that is not valid JSON — e.g. a torn write
/// — is dropped, so it never reaches output. Pure (no I/O) so it can be tested.
fn filter_audit_entries<'a>(
	content: &'a str,
	project: Option<&str>,
	action: Option<&str>,
	tail: Option<usize>,
) -> Vec<(&'a str, serde_json::Value)> {
	let mut entries: Vec<(&str, serde_json::Value)> = content
		.lines()
		.filter_map(|line| {
			let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
			let field = |k: &str| v.get(k).and_then(|x| x.as_str());
			if let Some(p) = project
				&& field("project") != Some(p)
			{
				return None;
			}
			// Actions serialize lowercase (`get`/`set`/...); match case-insensitively
			// so `--action Get` is not silently dropped. (`project` stays exact: a
			// project name is an identity, not an enum.)
			if let Some(a) = action
				&& !field("action").is_some_and(|x| x.eq_ignore_ascii_case(a))
			{
				return None;
			}
			Some((line, v))
		})
		.collect();

	if let Some(n) = tail
		&& entries.len() > n
	{
		entries.drain(0..entries.len() - n);
	}

	entries
}

/// Renders control characters in a field harmlessly so caller controlled audit
/// content (reason, command, key, ...) cannot inject escape sequences that
/// erase, overwrite, or forge lines in the formatted `monosecret audit` view.
///
/// ASCII control bytes (0x00..=0x1F) and DEL (0x7F) are replaced with a visible
/// `\xNN` rendering; all other characters pass through unchanged so normal
/// entries look identical.
fn sanitize_field(s: &str) -> String {
	use std::fmt::Write as _;

	if !s.chars().any(char::is_control) {
		return s.to_string();
	}
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		if c.is_control() {
			let _ = write!(out, "\\x{:02x}", c as u32);
		} else {
			out.push(c);
		}
	}
	out
}

/// Renders one parsed JSON Lines audit entry as a readable, colored summary line.
/// The value has already been validated as JSON by `show_audit_log`.
fn format_audit_line(v: &serde_json::Value) -> String {
	use std::fmt::Write as _;

	use colored::Colorize;

	let str_field = |k: &str| v.get(k).and_then(|x| x.as_str());

	let ts = sanitize_field(str_field("ts").unwrap_or(""));
	let action = sanitize_field(str_field("action").unwrap_or("?"));
	let outcome = sanitize_field(str_field("outcome").unwrap_or("?"));
	let project = sanitize_field(str_field("project").unwrap_or(""));
	let profile = sanitize_field(str_field("profile").unwrap_or(""));
	let scope = str_field("scope").map(sanitize_field);

	let target = if let Some(key) = str_field("key") {
		sanitize_field(key)
	} else if let Some(arr) = v.get("keys").and_then(|x| x.as_array()) {
		arr.iter()
			.filter_map(|x| x.as_str())
			.map(sanitize_field)
			.collect::<Vec<_>>()
			.join(",")
	} else {
		String::new()
	};

	let outcome_colored = match outcome.as_str() {
		"found" | "written" | "started" => outcome.green(),
		"missing" | "error" => outcome.red(),
		_ => outcome.yellow(),
	};

	let mut s = format!("{}  {:<6} {}", ts.dimmed(), action.bold(), outcome_colored);
	if let Some(cmd) = str_field("command") {
		let _ = write!(s, "  {}", sanitize_field(cmd).bold());
	}
	if !target.is_empty() {
		let _ = write!(s, "  {target}");
	}
	let _ = write!(s, "  ({project}/{profile}");
	if let Some(scope) = scope {
		let _ = write!(s, " scope:{scope}");
	}
	if let Some(provider) = str_field("provider") {
		let _ = write!(s, " via {}", sanitize_field(provider));
	}
	s += ")";
	if let Some(reason) = str_field("reason") {
		let _ = write!(s, "  reason: {}", sanitize_field(reason).italic());
	}
	if let Some(caller) = v.get("caller").and_then(|value| value.as_object())
		&& let Some(name) = caller.get("name").and_then(|value| value.as_str())
	{
		let mut rendered = sanitize_field(name);
		if let Some(version) = caller.get("version").and_then(|value| value.as_str()) {
			let _ = write!(rendered, "@{}", sanitize_field(version));
		}
		if let Some(operation) = caller.get("operation").and_then(|value| value.as_str()) {
			let _ = write!(rendered, "/{}", sanitize_field(operation));
		}
		if let Some(resource) = caller.get("resource").and_then(|value| value.as_str()) {
			let _ = write!(rendered, " {}", sanitize_field(resource));
		}
		let _ = write!(s, "  caller: {rendered}");
	}
	if let Some(agent) = v
		.get("actor")
		.and_then(|a| a.get("agent"))
		.and_then(|x| x.as_str())
	{
		let _ = write!(s, "  [{}]", sanitize_field(agent));
	}
	s
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::Secret;

	/// Builds a Config with a single secret named `S` under the `default` profile.
	fn config_with_secret(secret: Secret) -> Config {
		let mut secrets = HashMap::new();
		secrets.insert("S".to_string(), secret);
		Config {
			defaults: None,
			project: Project {
				name: "myproj".to_string(),
				..Default::default()
			},
			profiles: HashMap::from([(
				"default".to_string(),
				ConfigProfile {
					defaults: None,
					secrets,
				},
			)]),
			providers: None,
			groups: None,
			scopes: None,
		}
	}

	/// Clap folds `--scope` and its `MONOSECRET_SCOPE` fallback into one
	/// `Option`, so a blank value must mean "no scope" rather than "no opinion".
	/// Dropping it and letting the library re-read the environment would narrow
	/// the operation and scrub the excluded secrets, which is exactly what an
	/// operator writing `--scope ""` is trying to prevent.
	#[test]
	fn a_blank_scope_clears_an_ambient_one() {
		let _env = crate::tests::scrub_resolution_env();
		let _ambient = crate::tests::EnvVarGuard::set("MONOSECRET_SCOPE", "api");
		let config = config_with_secret(Secret::default());

		// Control: nothing applied, so the ambient scope is in force.
		let inherited = Secrets::new(config.clone(), None, None, None);
		assert_eq!(inherited.resolve_scope_name(None).as_deref(), Some("api"));

		// A blank `--scope` (or a blank `MONOSECRET_SCOPE`) selects nothing and
		// suppresses the ambient fallback.
		let mut blank = Secrets::new(config.clone(), None, None, None);
		apply_scope(&mut blank, Some("   ".to_string()));
		assert_eq!(blank.resolve_scope_name(None), None);

		// An absent flag leaves the ambient scope alone, and an explicit one wins.
		let mut absent = Secrets::new(config.clone(), None, None, None);
		apply_scope(&mut absent, None);
		assert_eq!(absent.resolve_scope_name(None).as_deref(), Some("api"));

		let mut explicit = Secrets::new(config, None, None, None);
		apply_scope(&mut explicit, Some("worker".to_string()));
		assert_eq!(explicit.resolve_scope_name(None).as_deref(), Some("worker"));
	}

	#[test]
	fn sanitize_field_neutralizes_control_characters() {
		// A clean string passes through unchanged (and takes the early-return path).
		assert_eq!(sanitize_field("DATABASE_URL"), "DATABASE_URL");
		assert_eq!(sanitize_field(""), "");

		// ASCII control bytes and DEL become a visible `\xNN` rendering so a
		// caller-controlled field (reason, command, key) cannot inject an escape
		// sequence that erases or forges lines in the formatted audit view.
		assert_eq!(sanitize_field("a\nb"), "a\\x0ab");
		assert_eq!(sanitize_field("a\tb"), "a\\x09b");
		assert_eq!(sanitize_field("a\x00b"), "a\\x00b");
		assert_eq!(sanitize_field("a\x7fb"), "a\\x7fb");

		// A real ANSI clear-line sequence is defanged: the ESC byte is escaped,
		// so the literal control character no longer reaches the terminal.
		let injected = sanitize_field("ok\x1b[2Kforged");
		assert_eq!(injected, "ok\\x1b[2Kforged");
		assert!(!injected.contains('\x1b'));
	}

	/// Three audit lines for two projects/actions, used by the filter tests.
	fn sample_log() -> String {
		[
			r#"{"action":"get","project":"alpha","key":"A"}"#,
			r#"{"action":"set","project":"beta","key":"B"}"#,
			r#"{"action":"get","project":"beta","key":"C"}"#,
		]
		.join("\n")
	}

	fn keys_of(entries: &[(&str, serde_json::Value)]) -> Vec<String> {
		entries
			.iter()
			.map(|(_, v)| v["key"].as_str().unwrap().to_string())
			.collect()
	}

	#[test]
	fn filter_audit_entries_filters_by_project_and_action() {
		let log = sample_log();

		// No filters -> every entry, in order.
		assert_eq!(
			keys_of(&filter_audit_entries(&log, None, None, None)),
			vec!["A", "B", "C"]
		);

		// Project is matched exactly.
		assert_eq!(
			keys_of(&filter_audit_entries(&log, Some("beta"), None, None)),
			vec!["B", "C"]
		);

		// Action is matched case-insensitively, so `--action GET` still matches.
		assert_eq!(
			keys_of(&filter_audit_entries(&log, None, Some("GET"), None)),
			vec!["A", "C"]
		);

		// Both filters combine.
		assert_eq!(
			keys_of(&filter_audit_entries(&log, Some("beta"), Some("get"), None)),
			vec!["C"]
		);
	}

	#[test]
	fn filter_audit_entries_applies_tail_and_drops_invalid_lines() {
		let log = sample_log();

		// `tail` keeps only the last N (after filtering).
		assert_eq!(
			keys_of(&filter_audit_entries(&log, None, None, Some(2))),
			vec!["B", "C"]
		);
		// A tail larger than the entry count is a no-op.
		assert_eq!(
			keys_of(&filter_audit_entries(&log, None, None, Some(99))),
			vec!["A", "B", "C"]
		);

		// Non-JSON lines (e.g. a torn write) and blank lines are dropped.
		let torn = format!("{}\nnot json\n\n", sample_log());
		assert_eq!(
			keys_of(&filter_audit_entries(&torn, None, None, None)),
			vec!["A", "B", "C"]
		);
	}

	#[test]
	fn format_audit_line_renders_fields() {
		// Color is disabled so assertions are on stable plain text.
		colored::control::set_override(false);

		let single: serde_json::Value = serde_json::from_str(
			r#"{"ts":"2026-06-07T00:00:00Z","action":"get","outcome":"found",
                "project":"demo","profile":"prod","key":"DB","provider":"dotenv://.env",
                "reason":"deploy","caller":{"name":"git","version":"2.51.0",
                "operation":"credential_get","resource":"github.com"},
                "actor":{"agent":"claude-code"}}"#,
		)
		.unwrap();
		let line = format_audit_line(&single);
		assert!(line.contains("get"));
		assert!(line.contains("found"));
		assert!(line.contains("DB"));
		assert!(line.contains("(demo/prod via dotenv://.env)"));
		assert!(line.contains("reason: deploy"));
		assert!(line.contains("caller: git@2.51.0/credential_get github.com"));
		assert!(line.contains("[claude-code]"));

		// A bulk entry joins `keys[]` and shows the executed command.
		let bulk: serde_json::Value = serde_json::from_str(
			r#"{"ts":"t","action":"run","outcome":"started","project":"demo",
                "profile":"prod","scope":"api","keys":["A","B"],"command":"./deploy.sh"}"#,
		)
		.unwrap();
		let line = format_audit_line(&bulk);
		assert!(line.contains("./deploy.sh"));
		assert!(line.contains("A,B"));
		assert!(line.contains("(demo/prod scope:api)"));

		colored::control::unset_override();
	}

	#[test]
	fn generate_toml_quotes_dotted_secret_name_and_round_trips() {
		// Dotenv accepts keys containing dots (e.g. `FOO.BAR`). A bare TOML key
		// `FOO.BAR` would be parsed as a *dotted* (nested) key, silently losing
		// the secret; toml_edit quotes it so the name round-trips intact.
		let mut secrets = HashMap::new();
		secrets.insert(
			"FOO.BAR".to_string(),
			Secret {
				description: Some("dotted".to_string()),
				..Default::default()
			},
		);
		let mut config = config_with_secret(Secret::default());
		config.profiles.get_mut("default").unwrap().secrets = secrets;

		let generated = generate_toml_with_comments(&config);
		assert!(
			generated.contains("\"FOO.BAR\" = {"),
			"key must be quoted, got: {generated}"
		);
		let parsed: Config = toml::from_str(&generated).expect("must round-trip");
		assert!(
			parsed
				.profiles
				.get("default")
				.is_some_and(|profile| profile.secrets.contains_key("FOO.BAR"))
		);
	}

	#[test]
	fn generate_toml_emits_and_round_trips_extends() {
		let mut config = config_with_secret(Secret {
			description: Some("desc".to_string()),
			..Default::default()
		});
		config.project.extends = Some(vec!["../shared".to_string()]);

		let generated = generate_toml_with_comments(&config);
		let parsed: Config = toml::from_str(&generated).expect("must round-trip");
		assert_eq!(
			parsed.project.extends.as_deref(),
			Some(["../shared".to_string()].as_slice())
		);
	}

	#[test]
	fn generate_toml_round_trips_control_character() {
		// U+007F (DEL) must be escaped: TOML forbids it unescaped in a basic
		// string. toml_edit handles it; a raw byte would fail to re-parse.
		let config = config_with_secret(Secret {
			description: Some("a\u{7f}b".to_string()),
			..Default::default()
		});
		let generated = generate_toml_with_comments(&config);
		let parsed: Config = toml::from_str(&generated).expect("must round-trip");
		assert_eq!(
			parsed
				.profiles
				.get("default")
				.and_then(|profile| profile.secrets.get("S"))
				.and_then(|secret| secret.description.as_deref()),
			Some("a\u{7f}b")
		);
	}

	#[test]
	fn generate_toml_round_trips_values_with_special_chars() {
		// Description and default contain quotes, a backslash and a newline; the
		// project name contains a quote. Before escaping was added these produced
		// malformed TOML that failed to parse back.
		let config = Config {
			defaults: None,
			project: Project {
				name: "weird \"name\"".to_string(),
				..Default::default()
			},
			profiles: HashMap::from([(
				"default".to_string(),
				ConfigProfile {
					defaults: None,
					secrets: HashMap::from([(
						"DATABASE_URL".to_string(),
						Secret {
							description: Some("he said \"hi\"\nthen left\\".to_string()),
							default: Some("a\"b\\c".to_string()),
							..Default::default()
						},
					)]),
				},
			)]),
			providers: None,
			scopes: None,
			groups: None,
		};

		let generated = generate_toml_with_comments(&config);
		let parsed: Config =
			toml::from_str(&generated).expect("generated TOML must be valid and re-parseable");

		assert_eq!(parsed.project.name, "weird \"name\"");
		let secret = parsed
			.profiles
			.get("default")
			.and_then(|profile| profile.secrets.get("DATABASE_URL"))
			.expect("DATABASE_URL declaration present");
		assert_eq!(
			secret.description.as_deref(),
			Some("he said \"hi\"\nthen left\\")
		);
		assert_eq!(secret.default.as_deref(), Some("a\"b\\c"));
	}

	#[test]
	fn generate_toml_none_branch_emits_empty_description_and_omits_fields() {
		let out = generate_toml_with_comments(&config_with_secret(Secret::default()));
		assert!(out.contains("S = { description = \"\" }"), "got: {out}");
		assert!(!out.contains("required = "));
		assert!(!out.contains("default = "));
	}

	#[test]
	fn generate_toml_some_branch_emits_required_and_default() {
		let secret = Secret {
			description: Some("desc".to_string()),
			required: Some(false),
			default: Some("v".to_string()),
			..Default::default()
		};
		let out = generate_toml_with_comments(&config_with_secret(secret));
		assert!(out.contains(", required = false"), "got: {out}");
		assert!(out.contains(", default = \"v\""), "got: {out}");
	}

	#[test]
	fn generate_toml_emits_grouped_requiredness() {
		let secret = Secret {
			description: Some("desc".to_string()),
			at_least_one: Some(vec!["auth".to_string(), "deploy".to_string()]),
			exactly_one: Some(vec!["identity".to_string()]),
			..Default::default()
		};
		let out = generate_toml_with_comments(&config_with_secret(secret));
		assert!(
			out.contains(
				"required = { at_least_one = [\"auth\", \"deploy\"], exactly_one = \"identity\" }"
			),
			"got: {out}"
		);
		let parsed: Config = toml::from_str(&out).expect("must round-trip");
		let secret = parsed
			.profiles
			.get("default")
			.and_then(|profile| profile.secrets.get("S"))
			.expect("S declaration present");
		assert_eq!(
			secret.at_least_one.as_deref(),
			Some(["auth".to_string(), "deploy".to_string()].as_slice())
		);
		assert_eq!(
			secret.exactly_one.as_deref(),
			Some(["identity".to_string()].as_slice())
		);
	}

	#[test]
	fn generate_toml_preserves_composed_templates() {
		let out = generate_toml_with_comments(&config_with_secret(Secret {
			description: Some("dsn".to_string()),
			composed: Some("postgres://${USER}@${HOST}/db".to_string()),
			..Default::default()
		}));
		assert!(
			out.contains(", composed = \"postgres://${USER}@${HOST}/db\""),
			"got: {out}"
		);
	}

	#[test]
	fn generate_toml_preserves_native_references() {
		let out = generate_toml_with_comments(&config_with_secret(Secret {
			description: Some("legacy".to_string()),
			reference: Some(crate::config::NativeAddress {
				item: "LEGACY_TOKEN".to_string(),
				..Default::default()
			}),
			..Default::default()
		}));

		assert!(
			out.contains(", ref = { item = \"LEGACY_TOKEN\" }"),
			"got: {out}"
		);
		let parsed: Config = toml::from_str(&out).expect("must round-trip");
		assert_eq!(
			parsed
				.profiles
				.get("default")
				.and_then(|profile| profile.secrets.get("S"))
				.and_then(|secret| secret.reference.as_ref())
				.map(|reference| reference.item.as_str()),
			Some("LEGACY_TOKEN")
		);
	}

	#[test]
	fn generated_config_with_example_template_is_valid_for_every_profile() {
		for profile in ["default", "development", "production"] {
			let mut config = config_with_secret(Secret {
				description: Some("desc".to_string()),
				..Default::default()
			});
			if profile != "default" {
				let declarations = config.profiles.remove("default").unwrap();
				config.profiles.insert(profile.to_string(), declarations);
			}

			let mut out = generate_toml_with_comments(&config);
			out.push_str(get_example_toml());

			let parsed: Config = toml::from_str(&out)
				.unwrap_or_else(|error| panic!("init output for {profile} must parse: {error}"));
			parsed
				.validate()
				.unwrap_or_else(|error| panic!("init output for {profile} must validate: {error}"));
			assert_eq!(parsed.profiles.len(), 1);
			assert!(parsed.profiles.contains_key(profile));
		}
	}

	#[test]
	fn migration_command_shell_quotes_provider_and_profile() {
		assert_eq!(
			migration_command(
				"awsps://us-east-1?template=/{profile}/{project}/{key}&tier=advanced",
				"default"
			),
			"monosecret import 'awsps://us-east-1?template=/{profile}/{project}/{key}&tier=advanced'"
		);
		assert_eq!(
			migration_command("dotenv://.env production", "team's production"),
			"MONOSECRET_PROFILE='team'\\''s production' monosecret import 'dotenv://.env production'"
		);
	}

	#[test]
	fn cli_command_definition_is_valid() {
		use clap::CommandFactory;
		Cli::command().debug_assert();
	}

	#[test]
	fn completions_accept_every_supported_shell() {
		let cases = [
			("bash", CompletionShell::Bash),
			("elvish", CompletionShell::Elvish),
			("fish", CompletionShell::Fish),
			("nushell", CompletionShell::Nushell),
			("powershell", CompletionShell::PowerShell),
			("zsh", CompletionShell::Zsh),
		];

		for (name, expected) in cases {
			let cli = Cli::try_parse_from(["monosecret", "completions", name]).unwrap();
			match cli.command {
				Commands::Completions { shell } => assert_eq!(shell, expected),
				_ => panic!("expected completions command"),
			}
		}
	}

	#[test]
	fn completions_reject_an_unknown_shell() {
		assert!(Cli::try_parse_from(["monosecret", "completions", "tcsh"]).is_err());
	}

	#[test]
	fn completion_scripts_register_the_dynamic_engine() {
		let shells = [
			CompletionShell::Bash,
			CompletionShell::Elvish,
			CompletionShell::Fish,
			CompletionShell::Nushell,
			CompletionShell::PowerShell,
			CompletionShell::Zsh,
		];

		for shell in shells {
			let mut output = Vec::new();
			generate_completions(shell, &mut output).unwrap();
			let output = String::from_utf8(output).unwrap();
			assert!(
				output.contains("monosecret"),
				"missing binary for {shell:?}"
			);
			assert!(
				output.contains("MONOSECRET_COMPLETE"),
				"missing dynamic completion protocol for {shell:?}"
			);
		}
	}

	#[test]
	fn init_defaults_from_to_dotenv() {
		let cli = Cli::try_parse_from(["monosecret", "init"]).unwrap();
		match cli.command {
			Commands::Init {
				from,
				project,
				profile,
			} => {
				assert_eq!(from, "dotenv://.env");
				assert_eq!(project, None);
				assert_eq!(profile, "default");
			}
			_ => panic!("expected Init command"),
		}
	}

	#[test]
	fn init_accepts_discovery_context() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"init",
			"--from",
			"awsps://us-east-1?template=/{profile}/{project}/{key}",
			"--project",
			"payments",
			"--profile",
			"production",
		])
		.unwrap();
		match cli.command {
			Commands::Init {
				from,
				project,
				profile,
			} => {
				assert_eq!(
					from,
					"awsps://us-east-1?template=/{profile}/{project}/{key}"
				);
				assert_eq!(project.as_deref(), Some("payments"));
				assert_eq!(profile, "production");
			}
			_ => panic!("expected Init command"),
		}
	}

	#[test]
	fn add_parses_description_and_profile() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"add",
			"API_KEY",
			"--description",
			"API access token",
			"--profile",
			"production",
		])
		.unwrap();

		match cli.command {
			Commands::Add {
				name,
				description,
				profile,
			} => {
				assert_eq!(name, "API_KEY");
				assert_eq!(description.as_deref(), Some("API access token"));
				assert_eq!(profile.as_deref(), Some("production"));
			}
			_ => panic!("expected Add command"),
		}
	}

	#[test]
	fn add_secret_to_spec_preserves_comments_and_other_tables() {
		let source = r#"# Project documentation
[project]
name = "demo"
revision = "1.0"

[profiles.default]
# Keep this explanation attached to the existing secret.
DATABASE_URL = { description = "Database connection string" }

[providers]
local = "dotenv://.env"
"#;

		let updated = add_secret_to_spec(source, "default", "API_KEY", "API access token").unwrap();

		assert!(updated.contains("# Project documentation"));
		assert!(updated.contains("# Keep this explanation attached to the existing secret."));
		assert!(updated.contains("local = \"dotenv://.env\""));
		assert!(updated.contains("API_KEY = { description = \"API access token\" }"));

		let config: Config = toml::from_str(&updated).expect("edited manifest must parse");
		config.validate().expect("edited manifest must validate");
		assert_eq!(
			config
				.profiles
				.get("default")
				.and_then(|profile| profile.secrets.get("API_KEY"))
				.and_then(|secret| secret.description.as_deref()),
			Some("API access token")
		);
	}

	#[test]
	fn add_secret_to_spec_can_overlay_an_inherited_profile() {
		let source = r#"[project]
name = "demo"
revision = "1.0"
extends = ["../shared"]

[profiles.default]
LOCAL = { description = "Local secret" }
"#;

		let updated =
			add_secret_to_spec(source, "production", "API_KEY", "API access token").unwrap();

		assert!(updated.contains("[profiles.production]"));
		assert!(updated.contains("API_KEY = { description = \"API access token\" }"));
	}

	#[test]
	fn add_target_rejects_inherited_secrets_and_unknown_profiles() {
		let config: Config = toml::from_str(
			r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
API_KEY = { description = "API access token" }

[profiles.development]
"#,
		)
		.unwrap();
		let app = Secrets::new(config, None, None, None);

		let inherited = validate_add_target(&app, "development", "API_KEY")
			.unwrap_err()
			.to_string();
		assert!(inherited.contains("already declared for profile 'development'"));

		let unknown = validate_add_target(&app, "production", "NEW_KEY")
			.unwrap_err()
			.to_string();
		assert!(unknown.contains("Available profiles: default, development"));

		validate_add_target(&app, "development", "NEW_KEY").unwrap();
	}

	#[test]
	fn add_secret_to_spec_rejects_invalid_or_duplicate_declarations() {
		let source = r#"[profiles.default]
API_KEY = { description = "Existing" }
"#;

		let invalid = add_secret_to_spec(source, "default", "1BAD", "Description")
			.unwrap_err()
			.to_string();
		assert!(invalid.contains("Invalid secret name"));

		let reserved = add_secret_to_spec(source, "default", "defaults", "Description")
			.unwrap_err()
			.to_string();
		assert!(reserved.contains("reserved for profile defaults"));

		let duplicate = add_secret_to_spec(source, "default", "API_KEY", "Description")
			.unwrap_err()
			.to_string();
		assert!(duplicate.contains("already declared"));

		let empty = add_secret_to_spec(source, "default", "NEW_KEY", "   ")
			.unwrap_err()
			.to_string();
		assert!(empty.contains("description cannot be empty"));
	}

	#[test]
	fn atomic_manifest_write_failure_leaves_original_unchanged() {
		let directory = tempfile::tempdir().unwrap();
		let manifest = directory.path().join("monosecret.toml");
		fs::write(&manifest, "original manifest\n").unwrap();

		let error = replace_manifest_atomically(&manifest, |temporary| {
			temporary.write_all(b"partial replacement")?;
			Err(std::io::Error::other("simulated interrupted write"))
		})
		.unwrap_err()
		.to_string();

		assert!(error.contains("Failed to write temporary manifest"));
		assert_eq!(
			fs::read_to_string(&manifest).unwrap(),
			"original manifest\n"
		);
	}

	#[test]
	fn atomic_manifest_write_preserves_permissions() {
		let directory = tempfile::tempdir().unwrap();
		let manifest = directory.path().join("monosecret.toml");
		fs::write(&manifest, "original manifest\n").unwrap();

		#[cfg(unix)]
		fs::set_permissions(&manifest, fs::Permissions::from_mode(0o640)).unwrap();
		let permissions = fs::metadata(&manifest).unwrap().permissions();

		write_manifest_atomically(&manifest, "updated manifest\n").unwrap();

		assert_eq!(fs::read_to_string(&manifest).unwrap(), "updated manifest\n");
		assert_eq!(fs::metadata(&manifest).unwrap().permissions(), permissions);
	}

	#[test]
	fn add_follow_up_command_quotes_profile_and_explicit_file() {
		assert_eq!(
			add_follow_up_command(
				"API_KEY",
				"qa west",
				Some(Path::new("/tmp/project's manifest.toml"))
			),
			"monosecret set API_KEY --profile 'qa west' --file '/tmp/project'\\''s manifest.toml'"
		);
		assert_eq!(
			add_follow_up_command("API_KEY", "default", None),
			"monosecret set API_KEY --profile 'default'"
		);
	}

	#[test]
	fn run_captures_trailing_args() {
		let cli =
			Cli::try_parse_from(["monosecret", "run", "--", "npm", "start", "--flag"]).unwrap();
		match cli.command {
			Commands::Run { command, .. } => {
				assert_eq!(command, vec!["npm", "start", "--flag"]);
			}
			_ => panic!("expected Run command"),
		}
	}

	#[test]
	fn caller_context_flags_are_global_and_details_require_a_name() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"--caller",
			"git",
			"--caller-version",
			"2.51.0",
			"run",
			"--caller-operation",
			"credential_get",
			"--caller-resource",
			"github.com",
			"--",
			"true",
		])
		.unwrap();
		assert_eq!(cli.caller.as_deref(), Some("git"));
		assert_eq!(cli.caller_version.as_deref(), Some("2.51.0"));
		assert_eq!(cli.caller_operation.as_deref(), Some("credential_get"));
		assert_eq!(cli.caller_resource.as_deref(), Some("github.com"));

		let missing_name = Cli::try_parse_from([
			"monosecret",
			"--caller-operation",
			"credential_get",
			"check",
		])
		.unwrap();
		assert!(caller_context(&missing_name).is_err());
	}

	#[test]
	fn check_parses_no_prompt_short_flag() {
		let cli = Cli::try_parse_from(["monosecret", "check", "-n"]).unwrap();
		match cli.command {
			Commands::Check { no_prompt, .. } => assert!(no_prompt),
			_ => panic!("expected Check command"),
		}
	}

	#[test]
	fn delete_requires_names_or_explicit_all() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"delete",
			"API_KEY",
			"DATABASE_URL",
			"--provider",
			"dotenv://.env",
			"--profile",
			"production",
		])
		.unwrap();
		match cli.command {
			Commands::Delete {
				names,
				all,
				yes,
				provider,
				profile,
			} => {
				assert_eq!(names, vec!["API_KEY", "DATABASE_URL"]);
				assert!(!all);
				assert!(!yes);
				assert_eq!(provider.as_deref(), Some("dotenv://.env"));
				assert_eq!(profile.as_deref(), Some("production"));
			}
			_ => panic!("expected delete"),
		}

		assert!(Cli::try_parse_from(["monosecret", "delete"]).is_err());
		let cli = Cli::try_parse_from(["monosecret", "delete", "--all", "--yes"]).unwrap();
		assert!(matches!(
			cli.command,
			Commands::Delete {
				names,
				all: true,
				yes: true,
				..
			} if names.is_empty()
		));
		assert!(
			Cli::try_parse_from(["monosecret", "delete", "API_KEY", "--all"]).is_err(),
			"a named delete and --all must be mutually exclusive"
		);
		assert!(
			Cli::try_parse_from(["monosecret", "delete", "API_KEY", "--yes"]).is_err(),
			"--yes is meaningful only with --all"
		);
	}

	#[test]
	fn import_parses_delete_source() {
		let cli = Cli::try_parse_from(["monosecret", "import", "dotenv://.env", "--delete-source"])
			.unwrap();
		assert!(matches!(
			cli.command,
			Commands::Import {
				from_provider,
				delete_source: true,
			} if from_provider == "dotenv://.env"
		));
	}

	#[test]
	fn cache_clear_parses_optional_name_and_profile() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"cache",
			"clear",
			"API_KEY",
			"--profile",
			"production",
		])
		.unwrap();
		match cli.command {
			Commands::Cache {
				action: CacheAction::Clear { name, profile },
			} => {
				assert_eq!(name.as_deref(), Some("API_KEY"));
				assert_eq!(profile.as_deref(), Some("production"));
			}
			_ => panic!("expected cache clear"),
		}

		let cli = Cli::try_parse_from(["monosecret", "cache", "clear"]).unwrap();
		assert!(matches!(
			cli.command,
			Commands::Cache {
				action: CacheAction::Clear {
					name: None,
					profile: None
				}
			}
		));
	}

	#[test]
	fn config_init_parses_non_interactive_defaults() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"config",
			"global",
			"init",
			"--provider",
			"env",
			"--profile",
			"default",
		])
		.unwrap();

		match cli.command {
			Commands::Config {
				action:
					ConfigAction::Global {
						action: GlobalConfigAction::Init { provider, profile },
					},
			} => {
				assert_eq!(provider.as_deref(), Some("env"));
				assert_eq!(profile.as_deref(), Some("default"));
			}
			_ => panic!("expected config init"),
		}
	}

	#[test]
	fn config_init_explicit_values_skip_selection_and_are_validated() {
		assert_eq!(
			select_config_init_provider(Some(" env:// ".to_string())).unwrap(),
			"env://"
		);
		assert!(
			select_config_init_provider(Some("unknown".to_string()))
				.unwrap_err()
				.to_string()
				.contains("Provider backend 'unknown' not found")
		);
		assert_eq!(
			select_config_init_provider(Some("file:./.secrets".to_string())).unwrap(),
			"file:./.secrets"
		);
		assert!(
			select_config_init_provider(Some("file".to_string()))
				.unwrap_err()
				.to_string()
				.contains("requires an explicit relative or absolute directory path")
		);

		assert_eq!(
			select_config_init_profile(Some(" default ".to_string())).unwrap(),
			Some("default".to_string())
		);
		assert_eq!(
			select_config_init_profile(Some("none".to_string())).unwrap(),
			None
		);
		assert!(select_config_init_profile(Some(" ".to_string())).is_err());
	}

	#[test]
	fn provider_add_parses_repeated_credential_bindings() {
		let cli = Cli::try_parse_from([
			"monosecret",
			"config",
			"global",
			"provider",
			"add",
			"bws",
			"bws://proj",
			"--credential",
			"access_token=keyring",
			"--credential",
			"other=dotenv://.env",
		])
		.unwrap();
		match cli.command {
			Commands::Config {
				action:
					ConfigAction::Global {
						action:
							GlobalConfigAction::Provider(GlobalProviderAction::Add {
								name,
								uri,
								credential,
							}),
					},
			} => {
				assert_eq!(name, "bws");
				assert_eq!(uri, "bws://proj");
				assert_eq!(
					credential,
					vec!["access_token=keyring", "other=dotenv://.env"]
				);
			}
			_ => panic!("expected config provider add"),
		}
	}

	#[test]
	fn provider_add_help_describes_semantic_credentials() {
		let help = Cli::try_parse_from([
			"monosecret",
			"config",
			"global",
			"provider",
			"add",
			"--help",
		])
		.err()
		.expect("--help should stop parsing")
		.to_string();

		assert!(help.contains("semantic and provider-specific"));
		assert!(help.contains("access_token"));
	}

	#[test]
	fn provider_add_rejects_the_environment_shaped_flag() {
		let error = Cli::try_parse_from([
			"monosecret",
			"config",
			"global",
			"provider",
			"add",
			"bws",
			"bws://proj",
			"--env",
			"BWS_ACCESS_TOKEN=keyring",
		])
		.err()
		.expect("--env should be rejected");

		assert!(error.to_string().contains("--env"));
	}

	#[test]
	fn provider_login_parses() {
		let cli =
			Cli::try_parse_from(["monosecret", "config", "provider", "login", "bws"]).unwrap();
		match cli.command {
			Commands::Config {
				action: ConfigAction::Provider(ProviderAction::Login { name }),
			} => {
				assert_eq!(name, "bws");
			}
			_ => panic!("expected config provider login"),
		}
	}

	#[test]
	fn legacy_global_config_spellings_remain_supported() {
		let commands: &[&[&str]] = &[
			&[
				"monosecret",
				"config",
				"init",
				"--provider",
				"env",
				"--profile",
				"default",
			],
			&["monosecret", "config", "show"],
			&[
				"monosecret",
				"config",
				"provider",
				"add",
				"shared",
				"keyring://",
			],
			&["monosecret", "config", "provider", "list"],
			&["monosecret", "config", "provider", "remove", "shared"],
		];

		for command in commands {
			assert!(
				Cli::try_parse_from(*command).is_ok(),
				"legacy command should remain accepted: {command:?}"
			);
		}
	}

	#[test]
	fn global_provider_namespace_rejects_project_scoped_login() {
		let error =
			Cli::try_parse_from(["monosecret", "config", "global", "provider", "login", "bws"])
				.err()
				.expect("global provider namespace must not expose project-scoped login");
		assert!(
			error
				.to_string()
				.contains("unrecognized subcommand 'login'")
		);
	}
}
