#![cfg(feature = "cli")]
#![allow(clippy::indexing_slicing)] // test fixtures: missing keys must fail loudly; panic-on-missing is the assertion

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use serde_json::Value;
use tempfile::TempDir;

struct Fixture {
	_temp: TempDir,
	root: PathBuf,
	pi_dir: PathBuf,
	manifest: PathBuf,
	auth_path: PathBuf,
}

impl Fixture {
	fn new() -> Self {
		let temp = TempDir::new().unwrap();
		let root = temp.path().to_path_buf();
		let pi_dir = root.join("pi-agent");
		fs::create_dir(&pi_dir).unwrap();
		let auth_path = pi_dir.join("auth.json");
		fs::write(
			&auth_path,
			r#"{
  "existing-provider": {
    "type": "api_key",
    "key": "EXISTING_ENV_VAR"
  }
}
"#,
		)
		.unwrap();
		let manifest = root.join("monosecret.toml");
		fs::write(
			&manifest,
			r#"
[project]
name = "pi-helper"
revision = "1.0"
require_reason = false

[profiles.default]
ANTHROPIC_TOKEN = { description = "Anthropic API key", default = "fixture-pi-custom-key", providers = ["null"] }
"#,
		)
		.unwrap();
		Self {
			_temp: temp,
			root,
			pi_dir,
			manifest,
			auth_path,
		}
	}

	fn command(&self) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_monosecret"));
		command
			.current_dir(&self.root)
			.env("PI_CODING_AGENT_DIR", &self.pi_dir)
			.env("HOME", self.root.join("home"))
			.env("USERPROFILE", self.root.join("home"))
			.env("XDG_CONFIG_HOME", self.root.join("config"))
			.env("XDG_STATE_HOME", self.root.join("state"))
			.env("APPDATA", self.root.join("config"))
			.env("LOCALAPPDATA", self.root.join("state"))
			.env_remove("MONOSECRET_FILE")
			.env_remove("MONOSECRET_PROFILE")
			.env_remove("MONOSECRET_PROVIDER")
			.env_remove("MONOSECRET_REASON")
			.env_remove("SECRETSPEC_FILE")
			.env_remove("SECRETSPEC_PROFILE")
			.env_remove("SECRETSPEC_PROVIDER")
			.env_remove("SECRETSPEC_REASON");
		command
	}

	fn configure(&self, ai_provider: &str, provider: &str) -> Output {
		self.command()
			.args([
				"pi",
				"configure",
				"--yes",
				"--ai-provider",
				ai_provider,
				"--provider",
				provider,
			])
			.output()
			.unwrap()
	}

	fn state_path(&self) -> PathBuf {
		find_named(&self.root, "pi.json")
			.unwrap_or_else(|| self.root.join("config/monosecret/pi.json"))
	}

	fn state(&self) -> Value {
		serde_json::from_slice(&fs::read(self.state_path()).unwrap()).unwrap()
	}

	fn auth(&self) -> Value {
		serde_json::from_slice(&fs::read(&self.auth_path).unwrap()).unwrap()
	}

	fn configuration_id(&self, ai_provider: &str) -> String {
		self.state()["configs"]
			.as_array()
			.unwrap()
			.iter()
			.find(|entry| entry["ai_provider"].as_str() == Some(ai_provider))
			.unwrap()["id"]
			.as_str()
			.unwrap()
			.to_string()
	}

	fn credential(&self, ai_provider: &str) -> Output {
		self.command()
			.args([
				"pi",
				"credential",
				"--configuration",
				&self.configuration_id(ai_provider),
			])
			.output()
			.unwrap()
	}
}

fn command_with_stdin(mut command: Command, args: &[&str], input: &[u8]) -> Output {
	let mut child = command
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child.stdin.take().unwrap().write_all(input).unwrap();
	child.wait_with_output().unwrap()
}

fn assert_success(context: &str, output: &Output) {
	assert!(
		output.status.success(),
		"{context} failed with {}:\nstdout:\n{}\nstderr:\n{}",
		output.status,
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
}

fn find_named(root: &Path, name: &str) -> Option<PathBuf> {
	let entries = fs::read_dir(root).ok()?;
	for entry in entries.flatten() {
		let path = entry.path();
		if path.file_name().is_some_and(|file| file == name) {
			return Some(path);
		}
		if path.is_dir()
			&& let Some(found) = find_named(&path, name)
		{
			return Some(found);
		}
	}
	None
}

#[test]
fn configure_login_credential_logout_and_unconfigure_multi_provider() {
	let fixture = Fixture::new();
	let store = fixture.root.join("pi.env");
	let provider = format!("dotenv://{}", store.display());

	assert_success(
		"Pi configure anthropic",
		&fixture.configure("anthropic", &provider),
	);
	assert_success(
		"Pi configure openai",
		&fixture.configure("openai", &provider),
	);

	let auth = fixture.auth();
	assert_eq!(auth["existing-provider"]["key"], "EXISTING_ENV_VAR");
	assert_eq!(auth["anthropic"]["type"], "api_key");
	assert_eq!(
		auth["anthropic"]["key"],
		format!(
			"!monosecret pi credential --configuration {}",
			fixture.configuration_id("anthropic")
		)
	);
	assert_eq!(auth["openai"]["type"], "api_key");
	assert_eq!(
		auth["openai"]["key"],
		format!(
			"!monosecret pi credential --configuration {}",
			fixture.configuration_id("openai")
		)
	);

	assert_success(
		"Pi login anthropic",
		&command_with_stdin(
			fixture.command(),
			&["pi", "login", "--ai-provider", "anthropic"],
			b"sk-ant-fixture\n",
		),
	);
	assert_success(
		"Pi login openai",
		&command_with_stdin(
			fixture.command(),
			&["pi", "login", "--ai-provider", "openai"],
			b"sk-openai-fixture\n",
		),
	);

	let ant_out = fixture.credential("anthropic");
	assert_success("Pi credential anthropic", &ant_out);
	assert_eq!(ant_out.stdout, b"sk-ant-fixture\n");

	let openai_out = fixture.credential("openai");
	assert_success("Pi credential openai", &openai_out);
	assert_eq!(openai_out.stdout, b"sk-openai-fixture\n");

	// Unconfiguring one provider leaves the other managed provider and existing entry intact.
	let unconf = fixture
		.command()
		.args(["pi", "unconfigure", "--ai-provider", "anthropic", "--yes"])
		.output()
		.unwrap();
	assert_success("Pi unconfigure anthropic", &unconf);
	let auth_after = fixture.auth();
	assert!(auth_after.get("anthropic").is_none());
	assert!(auth_after.get("openai").is_some());
	assert_eq!(auth_after["existing-provider"]["key"], "EXISTING_ENV_VAR");

	// Credential fetch for unconfigured provider fails, while logout still cleans up the stored secret.
	let inactive = fixture.credential("anthropic");
	assert!(!inactive.status.success());
	assert!(String::from_utf8_lossy(&inactive.stderr).contains("is not active"));
	let logout = fixture
		.command()
		.args(["pi", "logout", "--ai-provider", "anthropic"])
		.output()
		.unwrap();
	assert_success("Pi logout anthropic", &logout);

	// OpenAI credential remains working.
	let openai_still = fixture.credential("openai");
	assert_success("Pi credential openai still works", &openai_still);
	assert_eq!(openai_still.stdout, b"sk-openai-fixture\n");
}

#[test]
fn refuses_to_overwrite_unmanaged_auth_entry() {
	let fixture = Fixture::new();
	let output = fixture.configure("existing-provider", "null");
	assert!(!output.status.success());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("unmanaged credential"),
		"{output:?}"
	);
	assert_eq!(
		fixture.auth()["existing-provider"]["key"],
		"EXISTING_ENV_VAR"
	);
}

#[test]
fn unconfigure_refuses_externally_modified_entry() {
	let fixture = Fixture::new();
	assert_success("Pi configure", &fixture.configure("google", "null"));
	let mut auth = fixture.auth();
	auth["google"]["key"] = Value::String("!other-helper".to_string());
	fs::write(
		&fixture.auth_path,
		serde_json::to_vec_pretty(&auth).unwrap(),
	)
	.unwrap();

	let output = fixture
		.command()
		.args(["pi", "unconfigure", "--ai-provider", "google", "--yes"])
		.output()
		.unwrap();
	assert!(!output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("changed") && stderr.contains("outside Monosecret"),
		"{stderr}"
	);
	assert_eq!(fixture.auth()["google"]["key"], "!other-helper");
}

#[test]
fn custom_manifest_resolves_and_rejects_login_logout() {
	let fixture = Fixture::new();
	let output = fixture
		.command()
		.arg("--file")
		.arg(&fixture.manifest)
		.args([
			"--reason",
			"Use Pi Anthropic key",
			"pi",
			"configure",
			"--yes",
			"--ai-provider",
			"anthropic",
			"--token-secret",
			"ANTHROPIC_TOKEN",
			"--profile",
			"default",
			"--provider",
			"null",
		])
		.output()
		.unwrap();
	assert_success("Pi custom configure", &output);

	let cred = fixture.credential("anthropic");
	assert_success("Pi custom credential", &cred);
	assert_eq!(cred.stdout, b"fixture-pi-custom-key\n");

	for action in ["login", "logout"] {
		let output = fixture
			.command()
			.args(["pi", action, "--ai-provider", "anthropic"])
			.output()
			.unwrap();
		assert!(!output.status.success());
		assert!(String::from_utf8_lossy(&output.stderr).contains("custom manifest"));
	}
}

#[test]
fn configure_requires_confirmation_and_is_idempotent() {
	let fixture = Fixture::new();
	let original = fs::read(&fixture.auth_path).unwrap();
	let rejected = fixture
		.command()
		.args(["pi", "configure", "--ai-provider", "openrouter"])
		.output()
		.unwrap();
	assert!(!rejected.status.success());
	assert!(String::from_utf8_lossy(&rejected.stderr).contains("pass --yes"));
	assert_eq!(fs::read(&fixture.auth_path).unwrap(), original);

	assert_success(
		"Pi first configure",
		&fixture.configure("openrouter", "null"),
	);
	let first_auth = fs::read(&fixture.auth_path).unwrap();
	let first_state = fs::read(fixture.state_path()).unwrap();
	let repeated = fixture.configure("openrouter", "null");
	assert_success("Pi repeated configure", &repeated);
	assert!(String::from_utf8_lossy(&repeated.stdout).contains("already configured"));
	assert_eq!(fs::read(&fixture.auth_path).unwrap(), first_auth);
	assert_eq!(fs::read(fixture.state_path()).unwrap(), first_state);
}

#[cfg(unix)]
#[test]
fn new_auth_and_state_files_are_owner_only() {
	use std::os::unix::fs::PermissionsExt;

	let fixture = Fixture::new();
	fs::remove_file(&fixture.auth_path).unwrap();
	assert_success("Pi configure", &fixture.configure("anthropic", "null"));
	assert_eq!(
		fs::metadata(&fixture.auth_path)
			.unwrap()
			.permissions()
			.mode() & 0o777,
		0o600
	);
	assert_eq!(
		fs::metadata(fixture.state_path())
			.unwrap()
			.permissions()
			.mode() & 0o777,
		0o600
	);
}
