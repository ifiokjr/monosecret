//! Pi coding agent (`earendil-works/pi`) command-backed API-key integration.
//!
//! Pi resolves `"key": "!command"` entries in `$PI_CODING_AGENT_DIR/auth.json`
//! (default `~/.pi/agent/auth.json`) by running the shell command and using its
//! trimmed stdout as the API key for that AI provider (e.g. `anthropic`,
//! `openai`, `google`, `openrouter`, `groq`, `mistral`, `deepseek`, `xai`).

use std::path::Path;
use std::path::PathBuf;

use clap::Subcommand;
use miette::IntoDiagnostic;
use miette::Result;
use miette::WrapErr;
use miette::miette;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use uuid::Uuid;

use super::TypedArgs;
use super::credential_integration::confirm;
use super::credential_integration::ensure_unchanged;
use super::credential_integration::manifest_path;
use super::credential_integration::read_credential;
use super::credential_integration::read_optional;
use super::credential_integration::resolve_path;
use super::credential_integration::restore_file;
use super::credential_integration::validate_credential_value;
use super::credential_integration::write_bytes_atomically;
use super::shell_quote;
use crate::CallerContext;
use crate::NamedResolution;
use crate::Secret;
use crate::Secrets;
use crate::Spec;
use crate::config::GlobalConfig;

const STATE_VERSION: u8 = 1;
const DEFAULT_REASON: &str = "Pi model authentication";
const EMBEDDED_SECRET: &str = "PI_API_KEY";

#[derive(Subcommand)]
pub(super) enum PiAction {
	#[command(
		about = "Configure Pi auth.json to retrieve an AI provider API key through Monosecret"
	)]
	Configure {
		#[arg(
			long = "ai-provider",
			value_name = "PROVIDER_ID",
			help = "Pi provider identifier in auth.json (e.g. anthropic, openai, google, openrouter)"
		)]
		ai_provider: String,
		#[arg(long, help = "Custom manifest key containing the API key")]
		token_secret: Option<String>,
		#[arg(
			short = 'P',
			long,
			env = "MONOSECRET_PROFILE",
			help = "Custom manifest profile the credential command should use"
		)]
		profile: Option<String>,
		#[arg(
			short,
			long,
			env = "MONOSECRET_PROVIDER",
			help = "Monosecret storage provider override the credential command should use"
		)]
		provider: Option<String>,
		#[arg(
			long,
			help = "Non-secret audit resource name (defaults to --ai-provider)"
		)]
		resource: Option<String>,
		#[arg(
			short,
			long,
			help = "Confirm the user-level Pi auth.json configuration change non-interactively"
		)]
		yes: bool,
	},
	#[command(about = "Store a Pi AI provider API key in the embedded Monosecret store")]
	Login {
		#[arg(
			long = "ai-provider",
			value_name = "PROVIDER_ID",
			help = "Pi provider identifier configured in auth.json"
		)]
		ai_provider: String,
		#[arg(
			short,
			long,
			env = "MONOSECRET_PROVIDER",
			help = "Override the configured Monosecret storage provider for this operation"
		)]
		provider: Option<String>,
	},
	#[command(about = "Remove a Pi AI provider API key from the embedded Monosecret store")]
	Logout {
		#[arg(
			long = "ai-provider",
			value_name = "PROVIDER_ID",
			help = "Pi provider identifier configured in auth.json"
		)]
		ai_provider: String,
		#[arg(
			short,
			long,
			env = "MONOSECRET_PROVIDER",
			help = "Override the configured Monosecret storage provider for this operation"
		)]
		provider: Option<String>,
	},
	#[command(about = "Remove a Monosecret-managed entry from Pi auth.json")]
	Unconfigure {
		#[arg(
			long = "ai-provider",
			value_name = "PROVIDER_ID",
			help = "Pi provider identifier to remove from auth.json"
		)]
		ai_provider: String,
		#[arg(
			short,
			long,
			help = "Confirm the user-level Pi auth.json configuration change non-interactively"
		)]
		yes: bool,
	},
	#[command(hide = true)]
	Credential {
		#[arg(long)]
		configuration: String,
	},
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedConfig {
	id: String,
	auth_file: PathBuf,
	ai_provider: String,
	provider: Option<String>,
	reason: String,
	resource: String,
	source: CredentialSource,
	configured: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum CredentialSource {
	Embedded,
	Manifest {
		manifest: PathBuf,
		profile: String,
		token_secret: String,
	},
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedState {
	version: u8,
	configs: Vec<ManagedConfig>,
}

impl Default for ManagedState {
	fn default() -> Self {
		Self {
			version: STATE_VERSION,
			configs: Vec::new(),
		}
	}
}

pub(super) fn run(
	action: PiAction,
	file: Option<&PathBuf>,
	reason: Option<&str>,
	caller: Option<&CallerContext>,
	typed: TypedArgs,
) -> Result<()> {
	let file = typed.file.then(|| file.cloned()).flatten();
	match action {
		PiAction::Configure {
			ai_provider,
			token_secret,
			profile,
			provider,
			resource,
			yes,
		} => {
			configure(ConfigureOptions {
				ai_provider,
				token_secret,
				profile,
				provider,
				resource,
				yes,
				file,
				reason,
				typed,
			})
		}
		PiAction::Login {
			ai_provider,
			provider,
		} => {
			login(
				&ai_provider,
				provider.as_deref(),
				file.as_deref(),
				reason,
				caller,
			)
		}
		PiAction::Logout {
			ai_provider,
			provider,
		} => {
			logout(
				&ai_provider,
				provider.as_deref(),
				file.as_deref(),
				reason,
				caller,
			)
		}
		PiAction::Unconfigure { ai_provider, yes } => unconfigure(&ai_provider, yes),
		PiAction::Credential { configuration } => {
			credential(&configuration, file.as_deref(), caller)
		}
	}
}

struct ConfigureOptions<'a> {
	ai_provider: String,
	token_secret: Option<String>,
	profile: Option<String>,
	provider: Option<String>,
	resource: Option<String>,
	yes: bool,
	file: Option<PathBuf>,
	reason: Option<&'a str>,
	typed: TypedArgs,
}

fn configure(options: ConfigureOptions<'_>) -> Result<()> {
	validate_ai_provider(&options.ai_provider)?;
	let resource = match options.resource {
		Some(resource) => {
			validate_resource(&resource)?;
			resource
		}
		None => options.ai_provider.clone(),
	};
	let auth_file = auth_file_path()?;
	let source = if let Some(file) = &options.file {
		let token_secret = options.token_secret.as_deref().ok_or_else(|| {
			miette!("--token-secret is required when --file selects a custom manifest")
		})?;
		let manifest = manifest_path(file)?;
		let mut secrets = Secrets::load_from(&manifest)
			.into_diagnostic()
			.wrap_err("Failed to load custom Pi API-key manifest")?;
		let profile = if options.typed.profile {
			options
				.profile
				.clone()
				.ok_or_else(|| miette!("--profile was selected without a profile value"))?
		} else {
			GlobalConfig::load()
				.into_diagnostic()?
				.and_then(|config| config.defaults.profile)
				.unwrap_or_else(|| "default".to_string())
		};
		secrets.set_profile(&profile);
		validate_secret(&secrets, token_secret, &profile)?;
		CredentialSource::Manifest {
			manifest,
			profile,
			token_secret: token_secret.to_string(),
		}
	} else {
		if options.token_secret.is_some() || options.typed.profile {
			return Err(miette!(
				"--token-secret and --profile require --file; the embedded Pi credential store uses its built-in declaration"
			));
		}
		CredentialSource::Embedded
	};
	let provider = options
		.typed
		.provider
		.then(|| options.provider.clone())
		.flatten();
	let reason = if options.typed.reason {
		options
			.reason
			.filter(|reason| !reason.trim().is_empty())
			.ok_or_else(|| miette!("--reason cannot be empty"))?
			.to_string()
	} else {
		DEFAULT_REASON.to_string()
	};

	let original_auth = read_optional(&auth_file)?;
	let mut auth = parse_auth_file(original_auth.as_deref(), &auth_file)?;
	let state_file = state_path()?;
	let original_state = read_optional(&state_file)?;
	let mut state = parse_state(original_state.as_deref(), &state_file)?;
	let existing_index = state.configs.iter().position(|managed| {
		managed.auth_file == auth_file && managed.ai_provider == options.ai_provider
	});

	let existing = existing_index.and_then(|index| state.configs.get(index));
	let id = existing.map_or_else(
		|| Uuid::new_v4().simple().to_string(),
		|managed| managed.id.clone(),
	);
	if let Some(current_entry) = auth.get(&options.ai_provider) {
		match existing {
			Some(managed) if managed.configured => {
				if *current_entry != expected_auth_entry(&managed.id) {
					return Err(miette!(
						"Pi auth entry for '{}' in {} changed outside Monosecret; refusing to replace it",
						options.ai_provider,
						auth_file.display()
					));
				}
			}
			_ => {
				return Err(miette!(
					"Pi auth.json at {} already contains an unmanaged credential for '{}'; remove it first before letting Monosecret manage it",
					auth_file.display(),
					options.ai_provider
				));
			}
		}
	}

	let desired = ManagedConfig {
		id,
		auth_file: auth_file.clone(),
		ai_provider: options.ai_provider.clone(),
		provider,
		reason,
		resource,
		source,
		configured: true,
	};
	auth.insert(
		desired.ai_provider.clone(),
		expected_auth_entry(&desired.id),
	);
	let mut rendered = serde_json::to_vec_pretty(&Value::Object(auth)).into_diagnostic()?;
	rendered.push(b'\n');
	let auth_changed = original_auth.as_deref() != Some(rendered.as_slice());
	let state_changed = match existing_index.and_then(|index| state.configs.get_mut(index)) {
		Some(slot) if *slot == desired => false,
		Some(slot) => {
			*slot = desired;
			true
		}
		None => {
			state.configs.push(desired);
			true
		}
	};
	validate_state(&state, &state_file)?;
	if !state_changed && !auth_changed {
		println!(
			"Pi API-key integration for '{}' is already configured in {}.",
			options.ai_provider,
			auth_file.display()
		);
		return Ok(());
	}
	if !confirm(
		options.yes,
		&format!(
			"Configure Pi auth.json for AI provider '{}' at {}?",
			options.ai_provider,
			auth_file.display()
		),
	)? {
		return Ok(());
	}

	ensure_unchanged(&auth_file, original_auth.as_deref())?;
	ensure_unchanged(&state_file, original_state.as_deref())?;
	if state_changed {
		write_state(&state_file, &state)?;
	}
	if auth_changed && let Err(error) = write_bytes_atomically(&auth_file, &rendered, true) {
		if state_changed {
			restore_file(&state_file, original_state.as_deref(), true)?;
		}
		return Err(error);
	}

	println!(
		"Configured Pi API-key integration for '{}' in {}.",
		options.ai_provider,
		auth_file.display()
	);
	let configured = state
		.configs
		.iter()
		.find(|managed| {
			managed.auth_file == auth_file && managed.ai_provider == options.ai_provider
		})
		.expect("configured state entry exists");
	match &configured.source {
		CredentialSource::Embedded => {
			println!(
				"Store the API key with: monosecret pi login --ai-provider {}",
				shell_quote(&configured.ai_provider)
			);
		}
		CredentialSource::Manifest {
			manifest,
			profile,
			token_secret,
		} => {
			println!("Monosecret manifest: {}", manifest.display());
			let mut set = format!(
				"monosecret --file {} set {} --profile {}",
				shell_quote(&manifest.to_string_lossy()),
				shell_quote(token_secret),
				shell_quote(profile)
			);
			if let Some(provider) = &configured.provider {
				set.push_str(" --provider ");
				set.push_str(&shell_quote(provider));
			}
			println!("Store the API key with: {set}");
		}
	}
	println!(
		"Undo with: monosecret pi unconfigure --ai-provider {}",
		shell_quote(&configured.ai_provider)
	);
	if !options.typed.provider && options.provider.is_some() {
		println!(
			"Note: MONOSECRET_PROVIDER was not recorded in the Pi credential command; pass --provider to pin it."
		);
	}
	if !options.typed.reason && options.reason.is_some() {
		println!(
			"Note: MONOSECRET_REASON was not recorded in the Pi credential command; pass --reason to pin it."
		);
	}
	Ok(())
}

fn login(
	ai_provider: &str,
	provider: Option<&str>,
	file: Option<&Path>,
	reason: Option<&str>,
	caller: Option<&CallerContext>,
) -> Result<()> {
	validate_ai_provider(ai_provider)?;
	let managed = lifecycle_config(ai_provider, file)?;
	if !managed.configured {
		return Err(miette!(
			"Pi API-key integration for '{ai_provider}' is not active; rerun monosecret pi configure --ai-provider {ai_provider}"
		));
	}
	let (secrets, secret) = embedded_cli_secrets(&managed, provider, reason, caller, "login")?;
	let value = read_credential(&format!("Enter Pi API key for '{ai_provider}':"))?;
	validate_credential_value(&value)?;
	secrets
		.set_text(&secret, &value)
		.into_diagnostic()
		.wrap_err("Failed to store Pi API key")?;
	println!("Stored Pi API key for '{ai_provider}'.");
	Ok(())
}

fn logout(
	ai_provider: &str,
	provider: Option<&str>,
	file: Option<&Path>,
	reason: Option<&str>,
	caller: Option<&CallerContext>,
) -> Result<()> {
	validate_ai_provider(ai_provider)?;
	let managed = lifecycle_config(ai_provider, file)?;
	let (secrets, secret) = embedded_cli_secrets(&managed, provider, reason, caller, "logout")?;
	if secrets
		.delete(&secret)
		.into_diagnostic()
		.wrap_err("Failed to remove Pi API key")?
	{
		println!("Removed stored Pi API key for '{ai_provider}'.");
	} else {
		println!("No stored Pi API key was found for '{ai_provider}'.");
	}
	Ok(())
}

fn credential(
	configuration: &str,
	file: Option<&Path>,
	caller: Option<&CallerContext>,
) -> Result<()> {
	if file.is_some() {
		return Err(miette!(
			"monosecret pi credential uses the manifest recorded by configure; omit --file"
		));
	}
	let state_file = state_path()?;
	let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
	let managed = state
		.configs
		.iter()
		.find(|managed| managed.id == configuration)
		.ok_or_else(|| miette!("Pi API-key configuration was not found"))?;
	if !managed.configured {
		return Err(miette!(
			"Pi API-key configuration for '{}' is not active; rerun monosecret pi configure --ai-provider {}",
			managed.ai_provider,
			managed.ai_provider
		));
	}
	let (mut secrets, secret) = secrets_for_config(managed)?;
	if let Some(provider) = &managed.provider {
		secrets.set_provider(provider);
	}
	secrets = secrets.with_reason(&managed.reason);
	let caller = caller.cloned().unwrap_or_else(|| {
		CallerContext::new("pi")
			.with_operation("credential_get")
			.with_resource(&managed.resource)
	});
	secrets = secrets.with_caller(caller);
	validate_secret(&secrets, &secret, &secrets.resolve_profile_name(None))?;
	match secrets.resolve_named(&secret).into_diagnostic()? {
		NamedResolution::Resolved(resolved) => {
			let value = resolved
				.value
				.ok_or_else(|| miette!("Pi API key cannot be returned as a file path"))?;
			validate_credential_value(&value)?;
			println!("{value}");
			Ok(())
		}
		NamedResolution::Missing { .. } => {
			Err(miette!(
				"Pi API key for '{}' is not stored",
				managed.ai_provider
			))
		}
		NamedResolution::Undeclared => Err(miette!("Pi API-key secret '{secret}' is not declared")),
	}
}

fn unconfigure(ai_provider: &str, yes: bool) -> Result<()> {
	validate_ai_provider(ai_provider)?;
	let auth_file = auth_file_path()?;
	let state_file = state_path()?;
	let original_state = read_optional(&state_file)?;
	let mut state = parse_state(original_state.as_deref(), &state_file)?;
	let Some(index) = state
		.configs
		.iter()
		.position(|managed| managed.auth_file == auth_file && managed.ai_provider == ai_provider)
	else {
		println!("No matching Monosecret-managed Pi integration found for '{ai_provider}'.");
		return Ok(());
	};
	let Some(managed) = state.configs.get(index).cloned() else {
		return Ok(());
	};
	if !managed.configured {
		println!("No matching active Monosecret-managed Pi integration found for '{ai_provider}'.");
		return Ok(());
	}
	let original_auth = read_optional(&auth_file)?;
	let mut auth = parse_auth_file(original_auth.as_deref(), &auth_file)?;
	if auth.get(ai_provider) != Some(&expected_auth_entry(&managed.id)) {
		return Err(miette!(
			"Pi auth entry for '{ai_provider}' in {} changed outside Monosecret; refusing to remove it",
			auth_file.display()
		));
	}
	if !confirm(
		yes,
		&format!(
			"Remove Monosecret-managed Pi credential for '{ai_provider}' from {}?",
			auth_file.display()
		),
	)? {
		return Ok(());
	}

	auth.remove(ai_provider);
	let mut rendered = serde_json::to_vec_pretty(&Value::Object(auth)).into_diagnostic()?;
	rendered.push(b'\n');
	ensure_unchanged(&auth_file, original_auth.as_deref())?;
	ensure_unchanged(&state_file, original_state.as_deref())?;
	write_bytes_atomically(&auth_file, &rendered, true)?;
	if let Some(slot) = state.configs.get_mut(index) {
		slot.configured = false;
	}
	if let Err(error) = write_state(&state_file, &state) {
		restore_file(&auth_file, original_auth.as_deref(), true)?;
		return Err(error);
	}
	println!(
		"Removed Monosecret-managed Pi integration for '{ai_provider}' from {}.",
		auth_file.display()
	);
	Ok(())
}

fn lifecycle_config(ai_provider: &str, file: Option<&Path>) -> Result<ManagedConfig> {
	if file.is_some() {
		return Err(miette!(
			"monosecret pi login and logout use the manifest recorded by configure; omit --file"
		));
	}
	let auth_file = auth_file_path()?;
	let state_file = state_path()?;
	let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
	state
		.configs
		.into_iter()
		.find(|managed| managed.auth_file == auth_file && managed.ai_provider == ai_provider)
		.ok_or_else(|| {
			miette!(
				"Pi API-key integration for '{ai_provider}' is not configured for {}; run monosecret pi configure --ai-provider {ai_provider} first",
				auth_file.display()
			)
		})
}

fn embedded_cli_secrets(
	managed: &ManagedConfig,
	provider: Option<&str>,
	reason: Option<&str>,
	caller: Option<&CallerContext>,
	action: &str,
) -> Result<(Secrets, String)> {
	if !matches!(managed.source, CredentialSource::Embedded) {
		return Err(miette!(
			"this Pi integration uses a custom manifest; use monosecret set or delete with that manifest"
		));
	}
	let (mut secrets, secret) = embedded_secrets(managed)?;
	if let Some(provider) = provider.or(managed.provider.as_deref()) {
		secrets.set_provider(provider);
	}
	secrets = secrets.with_reason(reason.unwrap_or(&managed.reason));
	let caller = caller.cloned().unwrap_or_else(|| {
		CallerContext::new("pi")
			.with_operation(format!("credential_{action}"))
			.with_resource(&managed.resource)
	});
	secrets = secrets.with_caller(caller);
	secrets.set_write_target_reporter(|target| {
		eprintln!(
			"Writing secret '{}' to {} (profile: {})\n  target: {}",
			target.name, target.provider_uri, target.profile, target.target
		);
	});
	Ok((secrets, secret))
}

fn embedded_secrets(managed: &ManagedConfig) -> Result<(Secrets, String)> {
	let mut digest = Sha256::new();
	digest.update(managed.auth_file.as_os_str().as_encoded_bytes());
	digest.update([0]);
	digest.update(managed.ai_provider.as_bytes());
	let identity = data_encoding::HEXLOWER.encode(&digest.finalize());
	let secret = format!("{EMBEDDED_SECRET}_{}", identity.to_ascii_uppercase());
	let spec = Spec::builder(format!("pi-api-key-{identity}"))
		.secret(
			secret.clone(),
			Secret::required(format!(
				"API key used by Pi for AI provider '{}'",
				managed.ai_provider
			)),
		)
		.build()
		.into_diagnostic()?;
	let config = GlobalConfig::path().into_diagnostic()?;
	let base = config
		.parent()
		.ok_or_else(|| miette!("Monosecret config path has no parent directory"))?;
	let mut secrets = Secrets::from_spec_at(spec, base).into_diagnostic()?;
	secrets.set_profile("default");
	secrets.set_ignore_ambient_scope(true);
	Ok((secrets, secret))
}

fn secrets_for_config(managed: &ManagedConfig) -> Result<(Secrets, String)> {
	match &managed.source {
		CredentialSource::Embedded => embedded_secrets(managed),
		CredentialSource::Manifest {
			manifest,
			profile,
			token_secret,
		} => {
			let mut secrets = Secrets::load_from(manifest)
				.into_diagnostic()
				.wrap_err("Failed to load custom Pi API-key manifest")?;
			secrets.set_profile(profile);
			secrets.set_ignore_ambient_scope(true);
			Ok((secrets, token_secret.clone()))
		}
	}
}

fn validate_secret(secrets: &Secrets, name: &str, profile: &str) -> Result<()> {
	if name.is_empty() {
		return Err(miette!("Secret name cannot be empty"));
	}
	let secret = secrets.resolve_secret_config(name, None).ok_or_else(|| {
		miette!("Secret '{name}' is not declared in Monosecret profile '{profile}'")
	})?;
	if secret.as_path == Some(true) {
		return Err(miette!(
			"Secret '{name}' uses as_path and cannot be returned as a Pi API key"
		));
	}
	Ok(())
}

fn validate_ai_provider(ai_provider: &str) -> Result<()> {
	if ai_provider.is_empty()
		|| !ai_provider
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
	{
		return Err(miette!(
			"Pi AI provider identifier '{ai_provider}' must be non-empty and contain only ASCII letters, digits, '-', '_', or '.'"
		));
	}
	Ok(())
}

fn validate_resource(resource: &str) -> Result<()> {
	if resource.trim().is_empty()
		|| resource.trim() != resource
		|| resource
			.chars()
			.any(|character| character.is_ascii_control())
	{
		return Err(miette!(
			"Pi audit resource cannot be empty or contain surrounding whitespace or control characters"
		));
	}
	Ok(())
}

fn auth_file_path() -> Result<PathBuf> {
	let agent_dir = match std::env::var_os("PI_CODING_AGENT_DIR").filter(|value| !value.is_empty())
	{
		Some(path) => PathBuf::from(path),
		None => {
			etcetera::home_dir()
				.into_diagnostic()
				.wrap_err("Failed to locate the user home directory")?
				.join(".pi")
				.join("agent")
		}
	};
	resolve_path(&agent_dir.join("auth.json"))
}

fn state_path() -> Result<PathBuf> {
	let config = GlobalConfig::path().into_diagnostic()?;
	let directory = config
		.parent()
		.ok_or_else(|| miette!("Monosecret config path has no parent directory"))?;
	resolve_path(&directory.join("pi.json"))
}

fn expected_auth_entry(id: &str) -> Value {
	serde_json::json!({
		"type": "api_key",
		"key": format!("!monosecret pi credential --configuration {id}"),
	})
}

fn parse_auth_file(contents: Option<&[u8]>, path: &Path) -> Result<Map<String, Value>> {
	let Some(contents) = contents else {
		return Ok(Map::new());
	};
	let parsed: Value = serde_json::from_slice(contents)
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to parse {}", path.display()))?;
	parsed
		.as_object()
		.cloned()
		.ok_or_else(|| miette!("Pi auth file {} must contain a JSON object", path.display()))
}

fn parse_state(contents: Option<&[u8]>, path: &Path) -> Result<ManagedState> {
	let Some(contents) = contents else {
		return Ok(ManagedState::default());
	};
	let state: ManagedState = serde_json::from_slice(contents)
		.into_diagnostic()
		.wrap_err_with(|| format!("Failed to parse {}", path.display()))?;
	validate_state(&state, path)?;
	Ok(state)
}

fn validate_state(state: &ManagedState, path: &Path) -> Result<()> {
	if state.version != STATE_VERSION {
		return Err(miette!(
			"Unsupported Pi integration state version {} in {}",
			state.version,
			path.display()
		));
	}
	let mut ids = std::collections::HashSet::new();
	let mut keys = std::collections::HashSet::new();
	for managed in &state.configs {
		if Uuid::parse_str(&managed.id).is_err() {
			return Err(miette!(
				"Invalid Pi configuration identifier in {}",
				path.display()
			));
		}
		if !ids.insert(&managed.id) || !keys.insert((&managed.auth_file, &managed.ai_provider)) {
			return Err(miette!(
				"Duplicate Pi integration entry in {}",
				path.display()
			));
		}
		if !managed.auth_file.is_absolute()
			|| validate_ai_provider(&managed.ai_provider).is_err()
			|| managed.reason.trim().is_empty()
			|| validate_resource(&managed.resource).is_err()
		{
			return Err(miette!(
				"Invalid Pi integration entry in {}",
				path.display()
			));
		}
		if let Some(provider) = &managed.provider
			&& (provider.trim().is_empty()
				|| provider
					.chars()
					.any(|character| character.is_ascii_control()))
		{
			return Err(miette!("Invalid Pi provider in {}", path.display()));
		}
		if let CredentialSource::Manifest {
			manifest,
			profile,
			token_secret,
		} = &managed.source
			&& (!manifest.is_absolute()
				|| profile.trim().is_empty()
				|| token_secret.trim().is_empty())
		{
			return Err(miette!(
				"Invalid Pi manifest credential source in {}",
				path.display()
			));
		}
	}
	Ok(())
}

fn write_state(path: &Path, state: &ManagedState) -> Result<()> {
	validate_state(state, path)?;
	let mut contents = serde_json::to_vec_pretty(state).into_diagnostic()?;
	contents.push(b'\n');
	write_bytes_atomically(path, &contents, true)
}
