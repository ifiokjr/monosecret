//! Integration tests that exercise CLI command arms (`set`, `get`, `env`,
//! `audit`) through the compiled `monosecret` binary, covering the `load_secrets`
//! + command dispatch lines in `cli/mod.rs` that were missing patch coverage.

use std::fs;
use std::process::Command;

use insta_cmd::assert_cmd_snapshot;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

/// A deterministic per-test HOME so `assert_cmd_snapshot!`'s `env:` section
/// (which insta filters do not touch) is stable across machines and runs.
/// The directory is wiped first so the audit-log first-run note always prints.
fn test_home(name: &str) -> std::path::PathBuf {
	let home = std::path::PathBuf::from(format!("/tmp/monosecret-cli-arms-{name}"));
	let _ = fs::remove_dir_all(&home);
	home
}

fn snapshot_settings() -> insta::Settings {
	let mut settings = insta::Settings::clone_current();
	settings.add_filter(r"/private/var/folders/\S+", "[TMPDIR]");
	settings.add_filter(r"/var/folders/\S+", "[TMPDIR]");
	settings.add_filter(r"/tmp/\S+", "[TMPDIR]");
	settings.add_filter(r"/home/runner/work/_temp/\S+", "[TMPDIR]");
	// Windows temp dirs (paths are forward-slash normalised in test configs).
	settings.add_filter(r"[A-Z]:/Users/\S+/AppData/Local/Temp/\S+", "[TMPDIR]");
	settings.add_filter(r"[A-Z]:/a/_temp/\S+", "[TMPDIR]");
	// Windows temp dirs with native backslash separators.
	settings.add_filter(r"[A-Z]:\\Users\S+\\AppData\\Local\\Temp\\\S+", "[TMPDIR]");

	settings.add_filter(r"[A-Z]:\\a\\_temp\\\S+", "[TMPDIR]");
	// The audit first-run note is platform-dependent (prints on Unix where
	// HOME is honoured, absent on Windows where etcetera uses USERPROFILE).
	settings.add_filter(r"note: \S+ is now recording \S+ access to \S+[^\n]*\n", "");
	// Strip .exe suffix on Windows so binary names match Unix snapshots.
	settings.add_filter(r"monosecret\.exe", "monosecret");
	settings
}

/// Convert backslashes to forward slashes so Windows paths interpolated into
/// TOML double-quoted strings are not interpreted as escape sequences.
fn forward_slashes(p: &std::path::Path) -> String {
	p.display().to_string().replace('\\', "/")
}

fn base_config(dotenv_path: &str) -> String {
	let dotenv_path = dotenv_path.replace('\\', "/");
	format!(
		r#"
[project]
name = "cli-arms"
revision = "1.0"

[providers]
local = "dotenv://{dotenv_path}"

[profiles.default]
API_KEY = {{ description = "API key", required = true, providers = ["local"] }}
OPTIONAL = {{ description = "Optional", required = false, default = "fallback", providers = ["local"] }}
"#
	)
}

#[test]
fn set_command_writes_secret_to_provider() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&forward_slashes(&dotenv)),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path())
		.env("HOME", test_home("set"))
		.args([
			"-f",
			"monosecret.toml",
			"--reason",
			"test",
			"set",
			"API_KEY",
			"secret-value",
			"--provider",
			"local",
		]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
	insta::assert_snapshot!(fs::read_to_string(&dotenv).unwrap());
}

#[test]
fn get_command_retrieves_secret_from_provider() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "API_KEY=retrieved-value\n").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&forward_slashes(&dotenv)),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path())
		.env("HOME", test_home("get"))
		.args([
			"-f",
			"monosecret.toml",
			"--reason",
			"test",
			"get",
			"API_KEY",
			"--provider",
			"local",
		]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

#[test]
fn env_command_emits_dotenv_to_output_file() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "API_KEY=env-value\n").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&forward_slashes(&dotenv)),
	)
	.unwrap();

	let output_file = dir.path().join("env.out");
	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path())
		.env("HOME", test_home("env"))
		.args([
			"-f",
			"monosecret.toml",
			"--reason",
			"test",
			"env",
			"--shell",
			"dotenv",
			"--provider",
			"local",
			"--output",
			"env.out",
		]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
	insta::assert_snapshot!(fs::read_to_string(&output_file).unwrap());
}

#[test]
#[cfg(not(windows))]
fn audit_command_reads_log_with_filters() {
	let dir = tempfile::tempdir().unwrap();

	// Set up a global config pointing at a temp audit log.
	let audit_log = dir.path().join("audit.jsonl");
	fs::write(
		&audit_log,
		concat!(
			r#"{"action":"get","project":"demo","key":"A","outcome":"found","ts":"2026-01-01T00:00:00Z","profile":"default"}"#,
			"\n",
			r#"{"action":"set","project":"other","key":"B","outcome":"written","ts":"2026-01-02T00:00:00Z","profile":"default"}"#,
			"\n",
			r#"{"action":"get","project":"demo","key":"C","outcome":"found","ts":"2026-01-03T00:00:00Z","profile":"default"}"#,
			"\n",
		),
	)
	.unwrap();

	let xdg_config_home = test_home("audit-config");
	let config_dir = xdg_config_home.join("monosecret");
	fs::create_dir_all(&config_dir).unwrap();
	fs::write(
		config_dir.join("config.toml"),
		format!(
			r"[audit]
path = '{}'
",
			audit_log.display()
		),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("audit"))
		.env("XDG_CONFIG_HOME", &xdg_config_home)
		// etcetera's Windows strategy reads APPDATA (not XDG_CONFIG_HOME) for
		// config_dir, so set both to keep the test cross-platform.
		.env("APPDATA", &xdg_config_home)
		.args([
			"audit",
			"--project",
			"demo",
			"--action",
			"get",
			"--tail",
			"1",
			"--json",
		]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Builds one schema-v2 audit line exactly as the writer does: the entry
/// carries its predecessor's digest (`prev`), and its own `sha` is the SHA-256
/// of the predecessor's digest, a newline, and the entry serialized without
/// the `sha` field. Mirroring the writer here pins the on-disk format.
#[allow(clippy::indexing_slicing)] // test fixture: the object is built right here
fn chained_audit_line(prev: Option<&str>, action: &str) -> String {
	use sha2::Digest as _;

	let mut entry = serde_json::json!({
		"v": 2,
		"action": action,
		"project": "demo",
		"prev": prev,
	});
	let mut hasher = sha2::Sha256::new();
	hasher.update(prev.unwrap_or("genesis").as_bytes());
	hasher.update(b"\n");
	hasher.update(serde_json::to_string(&entry).unwrap().as_bytes());
	let sha = data_encoding::HEXLOWER.encode(&hasher.finalize());
	entry["sha"] = serde_json::Value::String(sha);
	serde_json::to_string(&entry).unwrap()
}

/// The `sha` field of a chained line, for linking the next entry to it.
fn parsed_sha(line: &str) -> Option<String> {
	serde_json::from_str::<serde_json::Value>(line)
		.unwrap()
		.get("sha")
		.and_then(|value| value.as_str())
		.map(str::to_string)
}

fn audit_verify_command(home_name: &str, log_lines: &str) -> Command {
	// `keep` leaves the directory in place after this function returns: the
	// command below runs only after it, and a dropped TempDir would delete
	// the log it needs to read.
	let dir = tempfile::tempdir().unwrap().keep();
	let log = dir.join("audit.jsonl");
	fs::write(&log, log_lines).unwrap();

	// A per-test home: the two verify tests run in parallel, and a shared
	// config location would let one test's command read the other's log.
	let xdg_config_home = test_home(home_name);
	let config_dir = xdg_config_home.join("monosecret");
	fs::create_dir_all(&config_dir).unwrap();
	fs::write(
		config_dir.join("config.toml"),
		format!("[audit]\npath = '{}'\n", forward_slashes(&log)),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.env("HOME", xdg_config_home.clone())
		.env("XDG_CONFIG_HOME", &xdg_config_home)
		.env("APPDATA", &xdg_config_home)
		.args(["audit", "--verify"]);
	cmd
}

#[test]
#[cfg(not(windows))]
fn audit_verify_reports_an_intact_chain() {
	let first = chained_audit_line(None, "get");
	let second = chained_audit_line(parsed_sha(&first).as_deref(), "run");
	let content = format!("{first}\n{second}\n");

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(
			"intact",
			audit_verify_command("audit-verify-intact", &content)
		);
	});
}

#[test]
#[cfg(not(windows))]
fn audit_verify_flags_an_edited_entry() {
	let first = chained_audit_line(None, "get");
	let second = chained_audit_line(parsed_sha(&first).as_deref(), "run");
	// The recorded `run` is edited to `get` without redoing the digest.
	let tampered = second.replace("\"run\"", "\"get\"");
	let content = format!("{first}\n{tampered}\n");

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(
			"tampered",
			audit_verify_command("audit-verify-tampered", &content)
		);
	});
}
