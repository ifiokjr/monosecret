use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use tempfile::TempDir;

#[test]
fn git_credential_fill_uses_the_monosecret_helper() {
	let temp = TempDir::new().unwrap();
	let manifest = temp.path().join("monosecret.toml");
	fs::write(
		&manifest,
		r#"
[project]
name = "git-helper"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_USERNAME = { description = "GitHub username", default = "vimjoyer", providers = ["null"] }
GITHUB_TOKEN = { description = "GitHub token", default = "token=value", providers = ["null"] }
"#,
	)
	.unwrap();

	let binary = Path::new(env!("CARGO_BIN_EXE_git-credential-monosecret"));
	let binary_directory = binary.parent().unwrap();
	let existing_path = env::var_os("PATH").unwrap_or_default();
	let path = env::join_paths(
		std::iter::once(binary_directory.to_path_buf()).chain(env::split_paths(&existing_path)),
	)
	.unwrap();
	let manifest = manifest.to_string_lossy().replace('\'', "'\\''");
	let helper = format!(
		"monosecret --url https://github.com --file '{manifest}' --username-secret GITHUB_USERNAME --password-secret GITHUB_TOKEN"
	);
	let mut child = Command::new("git")
		.args([
			"-c",
			"credential.helper=",
			"-c",
			&format!("credential.https://github.com.helper={helper}"),
			"credential",
			"fill",
		])
		.env("HOME", temp.path())
		.env("XDG_CONFIG_HOME", temp.path().join("config"))
		.env("XDG_STATE_HOME", temp.path().join("state"))
		.env("APPDATA", temp.path().join("config"))
		.env("LOCALAPPDATA", temp.path().join("state"))
		.env("GIT_CONFIG_NOSYSTEM", "1")
		.env("GIT_TERMINAL_PROMPT", "0")
		.env("PATH", path)
		.env_remove("MONOSECRET_FILE")
		.env_remove("MONOSECRET_PROFILE")
		.env_remove("MONOSECRET_PROVIDER")
		.env_remove("MONOSECRET_REASON")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(b"protocol=https\nhost=github.com\n\n")
		.unwrap();

	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"git credential fill failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8(output.stdout).unwrap();
	assert!(stdout.contains("protocol=https\n"));
	assert!(stdout.contains("host=github.com\n"));
	assert!(stdout.contains("username=vimjoyer\n"));
	assert!(stdout.contains("password=token=value\n"));
}
