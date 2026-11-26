//! End-to-end integration tests for ephemeral (on-demand) secrets, structural
//! cache refusal, and 1Password live OTP resolution.
//!
//! Uses only local fixtures and a fake `op` CLI stub — never calls real `op` or
//! touches real secrets.

#![cfg(all(unix, feature = "cli"))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use monosecret::Config;
use monosecret::ExportFormat;
use monosecret::NamedResolution;
use monosecret::Secrets;
use monosecret::Spec;
use monosecret::codegen::build_ir;
use monosecret_rpc::lifecycle::Environment;
use monosecret_rpc::lifecycle::LaunchOptions;
use monosecret_rpc::lifecycle::ResolverSession;
use monosecret_rpc::protocol::Limits;
use monosecret_rpc::protocol::Product;
use monosecret_rpc::protocol::resolver::GetParams;
use monosecret_rpc::protocol::resolver::GetResult;
use monosecret_rpc::protocol::resolver::InitializeApplication;
use monosecret_rpc::protocol::resolver::Manifest;
use monosecret_rpc::protocol::resolver::Purpose;
use monosecret_rpc::protocol::resolver::Representation;
use tempfile::TempDir;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

fn forward_slashes(path: &Path) -> String {
	path.display().to_string().replace('\\', "/")
}

/// Writes a stand-in `op` CLI that logs every invocation and serves a dotfiles-shaped
/// `Dotfiles` item containing `NPM_TOKEN` (CONCEALED) and `NPM_OTP` (OTP with an
/// `otpauth://` seed and optional `totp` field).
///
/// Modes via `$OP_STUB_MODE`:
/// - `with_totp`: `item get --format json` includes `"totp": "482910"` on `NPM_OTP`.
/// - `no_totp`: `item get --format json` omits `totp` (only `value: "otpauth://..."`),
///   verifying batched reads fall back to `op read ...?attribute=otp` and NEVER return
///   the seed or invoke `op inject`.
/// - `seed_on_read`: `op read` returns the raw `otpauth://` seed so tests can verify
///   Monosecret refuses it.
fn write_op_stub(dir: &Path, mode: &str) -> (PathBuf, PathBuf) {
	let stub = dir.join("op-stub");
	let log = dir.join("op-calls.log");

	let item_with_totp = serde_json::json!({
		"id": "dotfiles-item-id",
		"title": "Dotfiles",
		"sections": [{"id": "registries", "label": "registries"}],
		"fields": [
			{
				"id": "npm-token-field",
				"type": "CONCEALED",
				"label": "NPM_TOKEN",
				"value": "npm_fixture_token_value",
				"section": {"id": "registries"}
			},
			{
				"id": "npm-otp-field",
				"type": "OTP",
				"label": "NPM_OTP",
				"value": "otpauth://totp/npm:fixture?secret=JBSWY3DPEHPK3PXP",
				"totp": "482910",
				"section": {"id": "registries"}
			},
			{
				"id": "break-glass-field",
				"type": "CONCEALED",
				"label": "BREAK_GLASS",
				"value": "break_glass_live_value",
				"section": {"id": "registries"}
			}
		]
	})
	.to_string();

	let item_no_totp = serde_json::json!({
		"id": "dotfiles-item-id",
		"title": "Dotfiles",
		"sections": [{"id": "registries", "label": "registries"}],
		"fields": [
			{
				"id": "npm-token-field",
				"type": "CONCEALED",
				"label": "NPM_TOKEN",
				"value": "npm_fixture_token_value",
				"section": {"id": "registries"}
			},
			{
				"id": "npm-otp-field",
				"type": "OTP",
				"label": "NPM_OTP",
				"value": "otpauth://totp/npm:fixture?secret=JBSWY3DPEHPK3PXP",
				"section": {"id": "registries"}
			},
			{
				"id": "break-glass-field",
				"type": "CONCEALED",
				"label": "BREAK_GLASS",
				"value": "break_glass_live_value",
				"section": {"id": "registries"}
			}
		]
	})
	.to_string();

	let script = format!(
		r#"#!/bin/sh
OP_STUB_MODE="{mode}"
printf '%s\n' "$*" >> '{log}'

emit_item() {{
	case "$1" in
		Dotfiles)
			if [ "$OP_STUB_MODE" = "no_totp" ]; then
				printf '%s\n' '{item_no_totp}'
			else
				printf '%s\n' '{item_with_totp}'
			fi
			;;
		*)
			printf "error: '%s' isn't an item in this vault\n" "$1" >&2
			exit 1
			;;
	esac
}}

emit_items() {{
	while IFS= read -r name; do
		[ -z "$name" ] && continue
		emit_item "$name"
	done
}}

case "$1" in
	vault) printf '[]\n' ;;
	item)
		case "$2" in
			get)
				for arg in "$@"; do
					if [ "$arg" = "--otp" ]; then
						if [ "$OP_STUB_MODE" = "seed_on_read" ]; then
							printf 'otpauth://totp/npm:fixture?secret=JBSWY3DPEHPK3PXP\n'
						else
							printf '731942\n'
						fi
						exit 0
					fi
				done
				case "$3" in
					""|-*) emit_items ;;
					*) emit_item "$3" ;;
				esac
				;;
			list) printf '[{{"id":"dotfiles-item-id","title":"Dotfiles"}}]\n' ;;
			*) printf 'unexpected op item call: %s\n' "$*" >&2; exit 1 ;;
		esac
		;;
	read)
		uri="$3"
		case "$uri" in
			*"NPM_OTP?attribute=otp")
				if [ "$OP_STUB_MODE" = "seed_on_read" ]; then
					printf 'otpauth://totp/npm:fixture?secret=JBSWY3DPEHPK3PXP'
				else
					printf '482910'
				fi
				;;
			*"NPM_TOKEN?attribute=otp")
				printf "[ERROR] field 'NPM_TOKEN' doesn't have an 'otp' attribute\n" >&2
				exit 1
				;;
			*"NPM_TOKEN")
				printf 'npm_fixture_token_value'
				;;
			*"BREAK_GLASS")
				printf 'break_glass_live_value'
				;;
			*)
				printf "error: '%s' doesn't have a field\n" "$uri" >&2
				exit 1
				;;
		esac
		;;
	inject)
		printf 'ERROR: op inject must never be invoked for OTP reads\n' >&2
		exit 1
		;;
	*)
		printf 'unexpected op call: %s\n' "$*" >&2
		exit 1
		;;
esac
"#,
		log = log.display(),
	);

	fs::write(&stub, script).unwrap();
	let mut perms = fs::metadata(&stub).unwrap().permissions();
	perms.set_mode(0o755);
	fs::set_permissions(&stub, perms).unwrap();
	(log, stub)
}

fn read_op_log(log: &Path) -> Vec<String> {
	fs::read_to_string(log)
		.unwrap_or_default()
		.lines()
		.map(str::to_string)
		.collect()
}

fn write_dotfiles_otp_manifest(
	dir: &Path,
	dotenv_bootstrap: &Path,
	cache_env: Option<&Path>,
) -> PathBuf {
	let manifest = dir.join("monosecret.toml");
	let providers_block = if let Some(cache_path) = cache_env {
		format!(
			r#"[providers]
bootstrap = "dotenv://{bootstrap}"
cache_store = "dotenv://{cache}"
op-leaf = {{ uri = "onepassword+token://Development", depends_on = [{{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }}] }}
op-cached = {{ fallback = ["op-leaf"], cache = {{ provider = "cache_store", max_age = "24h", allow_plaintext = true }} }}
"#,
			bootstrap = forward_slashes(dotenv_bootstrap),
			cache = forward_slashes(cache_path),
		)
	} else {
		format!(
			r#"[providers]
bootstrap = "dotenv://{bootstrap}"
op-cached = {{ uri = "onepassword+token://Development", depends_on = [{{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }}] }}
"#,
			bootstrap = forward_slashes(dotenv_bootstrap),
		)
	};

	let op_provider = if cache_env.is_some() {
		"op-leaf"
	} else {
		"op-cached"
	};

	let content = format!(
		r#"[project]
name = "dotfiles-otp-test"
revision = "1.0"
require_reason = false

[groups]
registries = "Package registry credentials"

{providers_block}

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = {{ description = "bootstrap token", providers = ["bootstrap"] }}
NPM_TOKEN = {{ description = "npm publish token", groups = ["registries"], providers = ["op-cached"], refs = {{ {op_provider} = {{ item = "Dotfiles", section = "registries", field = "NPM_TOKEN" }} }} }}
NPM_OTP = {{ description = "npm 2FA one-time code", type = "otp", ephemeral = true, groups = ["registries"], providers = ["op-cached"], refs = {{ {op_provider} = {{ item = "Dotfiles", section = "registries", field = "NPM_OTP" }} }} }}
BREAK_GLASS = {{ description = "on-demand break-glass token", ephemeral = true, groups = ["registries"], providers = ["op-cached"], refs = {{ {op_provider} = {{ item = "Dotfiles", section = "registries", field = "BREAK_GLASS" }} }} }}

[scopes.npm_publish]
secrets = ["NPM_TOKEN", "NPM_OTP"]

[scopes.web_only]
secrets = ["NPM_TOKEN"]
"#
	);
	fs::write(&manifest, content).unwrap();
	manifest
}

#[test]
fn otp_entry_resolves_six_digit_code_and_ephemeral_is_absent_from_default_resolution() {
	let dir = TempDir::new().unwrap();
	let bootstrap = dir.path().join(".env.bootstrap");
	fs::write(&bootstrap, "OP_SERVICE_ACCOUNT_TOKEN=ops_fixture_token\n").unwrap();
	let (log, op_stub) = write_op_stub(dir.path(), "with_totp");
	let manifest = write_dotfiles_otp_manifest(dir.path(), &bootstrap, None);

	// 1. Default `export` skips ephemeral secrets (NPM_OTP, BREAK_GLASS).
	let export_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		export_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&export_out.stderr)
	);
	let exported = String::from_utf8_lossy(&export_out.stdout);
	assert!(
		exported.contains("NPM_TOKEN=npm_fixture_token_value"),
		"{exported}"
	);
	assert!(
		!exported.contains("NPM_OTP"),
		"default export must exclude ephemeral NPM_OTP: {exported}"
	);
	assert!(
		!exported.contains("BREAK_GLASS"),
		"default export must exclude ephemeral BREAK_GLASS: {exported}"
	);
	assert!(
		!exported.contains("otpauth://"),
		"default export must never expose OTP seed: {exported}"
	);

	// 2. Default `run` skips ephemeral secrets completely.
	let run_file = dir.path().join("default-run.txt");
	let run_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"run",
			"--",
			"sh",
			"-c",
			r#"printf '%s|%s|%s' "$NPM_TOKEN" "${NPM_OTP-unset}" "${BREAK_GLASS-unset}" > "$OUT""#,
		])
		.env("OUT", &run_file)
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		run_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&run_out.stderr)
	);
	assert_eq!(
		fs::read_to_string(&run_file).unwrap(),
		"npm_fixture_token_value|unset|unset"
	);

	// 3. `run --group registries` does NOT implicitly pull in ephemeral secrets.
	let group_file = dir.path().join("group-run.txt");
	let group_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"run",
			"--group",
			"registries",
			"--",
			"sh",
			"-c",
			r#"printf '%s|%s|%s' "$NPM_TOKEN" "${NPM_OTP-unset}" "${BREAK_GLASS-unset}" > "$OUT""#,
		])
		.env("OUT", &group_file)
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		group_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&group_out.stderr)
	);
	assert_eq!(
		fs::read_to_string(&group_file).unwrap(),
		"npm_fixture_token_value|unset|unset"
	);

	// Default resolution and group resolution must never read ephemeral secrets from 1Password.
	let default_calls = read_op_log(&log);
	assert!(
		!default_calls
			.iter()
			.any(|line| line.contains("NPM_OTP") || line.contains("BREAK_GLASS")),
		"default and group resolutions must never read ephemeral secrets: {default_calls:?}"
	);

	// 4. `monosecret get NPM_OTP` resolves the live 6-digit code, never the seed.
	let get_out = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "NPM_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		get_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&get_out.stderr)
	);
	let otp_code = String::from_utf8_lossy(&get_out.stdout);
	assert_eq!(otp_code.len(), 6, "OTP must be 6 digits: {otp_code}");
	assert!(
		otp_code.chars().all(|c| c.is_ascii_digit()),
		"OTP must be ASCII digits: {otp_code}"
	);
	assert_eq!(otp_code, "482910");

	// 5. `monosecret run --include NPM_TOKEN,NPM_OTP` resolves both (live 6-digit code).
	let include_file = dir.path().join("include-run.txt");
	let include_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"run",
			"--include",
			"NPM_TOKEN,NPM_OTP",
			"--",
			"sh",
			"-c",
			r#"printf '%s|%s' "$NPM_TOKEN" "$NPM_OTP" > "$OUT""#,
		])
		.env("OUT", &include_file)
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		include_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&include_out.stderr)
	);
	assert_eq!(
		fs::read_to_string(&include_file).unwrap(),
		"npm_fixture_token_value|482910"
	);

	// 6. `monosecret export --include NPM_OTP --format dotenv` emits the live code.
	let export_inc_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--include",
			"NPM_OTP",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		export_inc_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&export_inc_out.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&export_inc_out.stdout).trim(),
		"NPM_OTP=482910"
	);

	// 7. `monosecret run --scope npm_publish` resolves ephemeral secrets listed in scope.
	let scope_file = dir.path().join("scope-run.txt");
	let scope_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"run",
			"--scope",
			"npm_publish",
			"--",
			"sh",
			"-c",
			r#"printf '%s|%s|%s' "$NPM_TOKEN" "$NPM_OTP" "${OP_SERVICE_ACCOUNT_TOKEN-unset}" > "$OUT""#,
		])
		.env("OUT", &scope_file)
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		scope_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&scope_out.stderr)
	);
	assert_eq!(
		fs::read_to_string(&scope_file).unwrap(),
		"npm_fixture_token_value|482910|unset"
	);

	// 8. Verify `op read ...?attribute=otp` was invoked for single get, and no `op inject` ran.
	let calls = read_op_log(&log);
	assert!(
		calls
			.iter()
			.any(|line| line.contains("NPM_OTP?attribute=otp")),
		"expected ?attribute=otp read call in log: {calls:?}"
	);
	assert!(
		!calls.iter().any(|line| line.starts_with("inject")),
		"OTP reads must never invoke op inject: {calls:?}"
	);
}

#[test]
fn batched_otp_without_totp_field_falls_back_to_attribute_otp_never_seed() {
	let dir = TempDir::new().unwrap();
	let bootstrap = dir.path().join(".env.bootstrap");
	fs::write(&bootstrap, "OP_SERVICE_ACCOUNT_TOKEN=ops_fixture_token\n").unwrap();
	let (log, op_stub) = write_op_stub(dir.path(), "no_totp");
	let manifest = write_dotfiles_otp_manifest(dir.path(), &bootstrap, None);

	let output = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--include",
			"NPM_TOKEN,NPM_OTP",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8_lossy(&output.stdout);
	assert!(
		stdout.contains("NPM_TOKEN=npm_fixture_token_value"),
		"{stdout}"
	);
	assert!(stdout.contains("NPM_OTP=482910"), "{stdout}");
	assert!(
		!stdout.contains("otpauth://"),
		"batched OTP read must never fall back to seed: {stdout}"
	);

	let calls = read_op_log(&log);
	assert!(
		calls.iter().any(|line| line.starts_with("item get")),
		"expected batched item get in log: {calls:?}"
	);
	assert!(
		calls
			.iter()
			.any(|line| line.contains("NPM_OTP?attribute=otp")),
		"expected ?attribute=otp fallback in log: {calls:?}"
	);
	assert!(
		!calls.iter().any(|line| line.starts_with("inject")),
		"OTP fallback must never use op inject: {calls:?}"
	);
}

#[test]
fn cache_never_stores_or_serves_ephemeral_or_otp_secrets_while_caching_ordinary_secrets() {
	let dir = TempDir::new().unwrap();
	let bootstrap = dir.path().join(".env.bootstrap");
	let cache_file = dir.path().join(".env.cache");
	fs::write(&bootstrap, "OP_SERVICE_ACCOUNT_TOKEN=ops_fixture_token\n").unwrap();
	fs::write(&cache_file, "").unwrap();
	let (log, op_stub) = write_op_stub(dir.path(), "with_totp");
	let manifest = write_dotfiles_otp_manifest(dir.path(), &bootstrap, Some(&cache_file));

	// 1. Default export populates the cache for ordinary NPM_TOKEN and skips ephemeral secrets.
	let out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&out.stderr)
	);
	let cache_after_default = fs::read_to_string(&cache_file).unwrap();
	assert!(
		cache_after_default.contains("NPM_TOKEN="),
		"ordinary secret should still be cached: {cache_after_default}"
	);
	assert!(
		!cache_after_default.contains("NPM_OTP"),
		"ephemeral OTP must not be cached: {cache_after_default}"
	);
	assert!(
		!cache_after_default.contains("BREAK_GLASS"),
		"ephemeral secret must not be cached: {cache_after_default}"
	);

	// 2. Second default export is served 100% from cache (zero new `op` calls!).
	let calls_before = read_op_log(&log).len();
	let out2 = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(out2.status.success());
	assert_eq!(
		read_op_log(&log).len(),
		calls_before,
		"ordinary cached secret should hit cache without contacting 1Password"
	);

	// 3. Explicitly resolving NPM_OTP and BREAK_GLASS must NOT write either to the cache.
	let out3 = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"export",
			"--include",
			"NPM_OTP,BREAK_GLASS",
			"--format",
			"dotenv",
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		out3.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&out3.stderr)
	);
	let stdout3 = String::from_utf8_lossy(&out3.stdout);
	assert!(stdout3.contains("NPM_OTP=482910"), "{stdout3}");
	assert!(
		stdout3.contains("BREAK_GLASS=break_glass_live_value"),
		"{stdout3}"
	);
	let cache_after_ephemeral = fs::read_to_string(&cache_file).unwrap();
	assert!(
		!cache_after_ephemeral.contains("NPM_OTP"),
		"NPM_OTP must NEVER be written to cache: {cache_after_ephemeral}"
	);
	assert!(
		!cache_after_ephemeral.contains("482910"),
		"OTP code must NEVER appear in cache: {cache_after_ephemeral}"
	);
	assert!(
		!cache_after_ephemeral.contains("BREAK_GLASS"),
		"BREAK_GLASS must NEVER be written to cache: {cache_after_ephemeral}"
	);

	// 4. Even if someone manually poisons the cache file with fresh entries for
	// BREAK_GLASS and NPM_OTP, Monosecret refuses to serve either and reads live values.
	let npm_token_line = cache_after_ephemeral
		.lines()
		.find(|line| line.starts_with("NPM_TOKEN="))
		.expect("NPM_TOKEN cached line");
	let poisoned_bg = npm_token_line.replacen("NPM_TOKEN=", "BREAK_GLASS=", 1);
	let poisoned_otp = npm_token_line.replacen("NPM_TOKEN=", "NPM_OTP=", 1);
	fs::write(
		&cache_file,
		format!("{cache_after_ephemeral}\n{poisoned_bg}\n{poisoned_otp}\n"),
	)
	.unwrap();

	let calls_before_get = read_op_log(&log).len();
	let get_bg = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "BREAK_GLASS"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		get_bg.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&get_bg.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&get_bg.stdout),
		"break_glass_live_value",
		"ephemeral secret must never be served from a poisoned cache entry"
	);
	assert!(
		read_op_log(&log).len() > calls_before_get,
		"ephemeral read must consult authoritative provider, not cache"
	);

	let calls_before_otp_get = read_op_log(&log).len();
	let get_otp = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "NPM_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		get_otp.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&get_otp.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&get_otp.stdout),
		"482910",
		"OTP secret must never be served from a poisoned cache entry"
	);
	assert!(
		read_op_log(&log).len() > calls_before_otp_get,
		"OTP read must consult authoritative provider, not cache"
	);

	// 5. `monosecret cache clear BREAK_GLASS` explains it is ephemeral and never cached.
	let clear_out = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"-f",
			manifest.to_str().unwrap(),
			"cache",
			"clear",
			"BREAK_GLASS",
		])
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(!clear_out.status.success());
	let clear_err = String::from_utf8_lossy(&clear_out.stderr);
	let normalized_clear_err = clear_err.split_whitespace().collect::<Vec<_>>().join(" ");
	assert!(
		normalized_clear_err.contains("ephemeral and is never cached"),
		"unexpected cache clear error: {clear_err}"
	);
}

#[test]
fn ephemeral_resolution_across_library_apis_check_set_and_codegen() {
	let dir = TempDir::new().unwrap();
	let store = dir.path().join(".env.store");
	let cache = dir.path().join(".env.cache");
	fs::write(
		&store,
		"NORMAL=normal-val\nEPHEMERAL_SECRET=ephemeral-val\n",
	)
	.unwrap();
	fs::write(&cache, "").unwrap();

	let manifest_path = dir.path().join("monosecret.toml");
	fs::write(
		&manifest_path,
		format!(
			r#"[project]
name = "api-test"
revision = "1.0"
require_reason = false

[providers]
store = "dotenv://{store}"
cache = "dotenv://{cache}"
cached = {{ fallback = ["store"], cache = {{ provider = "cache", max_age = "24h", allow_plaintext = true }} }}

[profiles.default]
NORMAL = {{ description = "ordinary secret", providers = ["cached"] }}
EPHEMERAL_SECRET = {{ description = "ephemeral secret", ephemeral = true, providers = ["cached"] }}
MISSING_EPHEMERAL = {{ description = "missing required ephemeral", required = true, ephemeral = true, providers = ["cached"] }}
OTP_CODE = {{ description = "live otp", type = "otp", ephemeral = true, providers = ["cached"] }}

[scopes.on_demand]
secrets = ["EPHEMERAL_SECRET"]

[scopes.normal_only]
secrets = ["NORMAL"]
"#,
			store = forward_slashes(&store),
			cache = forward_slashes(&cache),
		),
	)
	.unwrap();

	let spec = Spec::try_from(manifest_path.as_path()).unwrap();

	// Codegen excludes ephemeral secrets so typed default loaders match default resolution.
	let ir = build_ir(&spec);
	let ir_names: Vec<&str> = ir.union.iter().map(|f| f.name.as_str()).collect();
	assert_eq!(ir_names, vec!["NORMAL"]);

	// Default library resolution skips ephemeral secrets (including missing required ephemeral!).
	let secrets = Secrets::from_spec(spec).unwrap();
	let resolved = secrets.resolve().unwrap();
	assert_eq!(resolved.missing_required, Vec::<String>::new());
	assert!(resolved.secrets.contains_key("NORMAL"));
	assert!(!resolved.secrets.contains_key("EPHEMERAL_SECRET"));
	assert!(!resolved.secrets.contains_key("MISSING_EPHEMERAL"));
	assert!(!resolved.secrets.contains_key("OTP_CODE"));

	// `check --json` / `report()` skips ephemeral secrets by default.
	let report = secrets.report().unwrap();
	let report_names: Vec<&str> = report.secrets.iter().map(|s| s.name.as_str()).collect();
	assert_eq!(report_names, vec!["NORMAL"]);

	// `resolve_named` resolves ephemeral secrets explicitly when unscoped.
	match secrets.resolve_named("EPHEMERAL_SECRET").unwrap() {
		NamedResolution::Resolved(secret) => {
			assert_eq!(secret.value.as_deref(), Some("ephemeral-val"));
		}
		other => panic!("expected Resolved, got {other:?}"),
	}

	// `export_filtered` resolves explicitly included ephemeral secret.
	let mut exported = Vec::new();
	secrets
		.export_filtered(
			ExportFormat::Dotenv,
			&["EPHEMERAL_SECRET".to_string()],
			&[],
			&mut exported,
		)
		.unwrap();
	assert_eq!(
		String::from_utf8(exported).unwrap().trim(),
		"EPHEMERAL_SECRET=ephemeral-val"
	);

	// `set` succeeds for non-OTP ephemeral secret and NEVER writes to cache.
	secrets
		.set_text("EPHEMERAL_SECRET", "updated-ephemeral")
		.unwrap();
	let cache_contents = fs::read_to_string(&cache).unwrap();
	assert!(cache_contents.contains("NORMAL="), "{cache_contents}");
	assert!(
		!cache_contents.contains("EPHEMERAL_SECRET"),
		"set on ephemeral secret must never populate cache: {cache_contents}"
	);

	// `set` rejects `type = "otp"` cleanly.
	let set_otp_err = secrets
		.set_text("OTP_CODE", "123456")
		.expect_err("set must reject type = \"otp\"");
	assert!(
		set_otp_err.to_string().contains("type = \"otp\""),
		"{set_otp_err}"
	);

	// Under a scope that omits EPHEMERAL_SECRET, `resolve_named` treats it as Undeclared.
	let mut scoped = Secrets::from_spec(Spec::try_from(manifest_path.as_path()).unwrap()).unwrap();
	scoped.set_scope("normal_only");
	assert!(matches!(
		scoped.resolve_named("EPHEMERAL_SECRET").unwrap(),
		NamedResolution::Undeclared
	));

	// Under a scope that lists EPHEMERAL_SECRET, it resolves cleanly.
	let mut on_demand =
		Secrets::from_spec(Spec::try_from(manifest_path.as_path()).unwrap()).unwrap();
	on_demand.set_scope("on_demand");
	match on_demand.resolve_named("EPHEMERAL_SECRET").unwrap() {
		NamedResolution::Resolved(secret) => {
			assert_eq!(secret.value.as_deref(), Some("updated-ephemeral"));
		}
		other => panic!("expected Resolved in scope, got {other:?}"),
	}
}

#[test]
fn config_validation_rejects_invalid_ephemeral_and_otp_combinations() {
	let cases = [
		(
			"non-ephemeral depending on ephemeral",
			r#"
[project]
name = "invalid"
revision = "1.0"
[profiles.default]
OTP = { description = "otp", type = "otp", ephemeral = true }
DERIVED = { description = "derived", composed = "code=${OTP}" }
"#,
			"non-ephemeral secret cannot depend on ephemeral secret 'OTP'",
		),
		(
			"ephemeral with presence group",
			r#"
[project]
name = "invalid"
revision = "1.0"
[profiles.default]
A = { description = "a", ephemeral = true, required = { at_least_one = "auth" } }
B = { description = "b", required = { at_least_one = "auth" } }
"#,
			"`ephemeral = true` cannot be combined with `at_least_one` or `exactly_one`",
		),
		(
			"otp with generate",
			r#"
[project]
name = "invalid"
revision = "1.0"
[profiles.default]
OTP = { description = "otp", type = "otp", generate = true }
"#,
			"type = \"otp\" cannot be combined with enabled `generate`",
		),
		(
			"otp with prompt",
			r#"
[project]
name = "invalid"
revision = "1.0"
[profiles.default]
OTP = { description = "otp", type = "otp", prompt = true }
"#,
			"type = \"otp\" cannot be combined with `prompt = true`",
		),
		(
			"otp with extract",
			r#"
[project]
name = "invalid"
revision = "1.0"
[profiles.default]
OTP = { description = "otp", type = "otp", extract = { format = "json", pointer = "/otp" } }
"#,
			"type = \"otp\" cannot be combined with `extract`",
		),
	];

	for (label, toml, expected) in cases {
		let config: Config = toml::from_str(toml).expect(label);
		let err = config.validate().expect_err(label).to_string();
		assert!(
			err.contains(expected),
			"case '{label}': expected '{expected}', got '{err}'"
		);
	}

	// Valid: ephemeral composed secret depending on an ephemeral secret.
	let valid: Config = toml::from_str(
		r#"
[project]
name = "valid"
revision = "1.0"
[profiles.default]
OTP = { description = "otp", type = "otp", ephemeral = true }
HEADER = { description = "header", ephemeral = true, composed = "X-OTP: ${OTP}" }
"#,
	)
	.unwrap();
	valid.validate().unwrap();
}

#[tokio::test]
async fn serve_resolves_ephemeral_otp_on_demand_and_respects_scopes_without_caching() {
	let dir = TempDir::new().unwrap();
	let bootstrap = dir.path().join(".env.bootstrap");
	let cache_file = dir.path().join(".env.cache");
	fs::write(&bootstrap, "OP_SERVICE_ACCOUNT_TOKEN=ops_fixture_token\n").unwrap();
	fs::write(&cache_file, "").unwrap();
	let (_log, op_stub) = write_op_stub(dir.path(), "with_totp");
	let manifest = write_dotfiles_otp_manifest(dir.path(), &bootstrap, Some(&cache_file));

	let deadline = || {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_millis()
			.saturating_add(Duration::from_secs(10).as_millis()) as u64
	};

	let mut env = BTreeMap::new();
	env.insert(
		OsString::from("MONOSECRET_OPCLI_PATH"),
		op_stub.as_os_str().to_os_string(),
	);
	env.insert(
		OsString::from("HOME"),
		dir.path().as_os_str().to_os_string(),
	);

	let session = ResolverSession::launch(
		LaunchOptions {
			executable: PathBuf::from(bin()),
			arguments: vec![OsString::from("serve")],
			environment: Environment::Inherit(env.clone()),
			allow_path_discovery: false,
			max_stderr_bytes: 64 * 1024,
		},
		Product {
			name: "ephemeral-otp-test".into(),
			version: "1".into(),
		},
		Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 4,
		},
		InitializeApplication {
			manifest: Manifest::Path {
				path: manifest.to_string_lossy().into_owned(),
			},
			provider: None,
			profile: Some("default".into()),
			scope: None,
			reason: None,
			requested_authorization_duration_ms: None,
		},
		deadline(),
	)
	.await
	.unwrap();

	let purpose = Purpose {
		consumer: "ephemeral-otp-test".into(),
		operation: "publish".into(),
		host: None,
		path: None,
	};

	let result = session
		.get(
			&GetParams {
				name: "NPM_OTP".into(),
				representation: Representation::Value,
				purpose: purpose.clone(),
			},
			deadline(),
		)
		.await
		.unwrap();
	match result {
		GetResult::Value(resolved) => {
			assert_eq!(resolved.value, "482910");
			assert!(
				resolved.refresh_at_unix_ms.is_none(),
				"ephemeral OTP must never report cache refresh metadata"
			);
		}
		other => panic!("expected live OTP value from serve, got {other:?}"),
	}
	session.close(deadline()).await.unwrap();

	let cache_contents = fs::read_to_string(&cache_file).unwrap();
	assert!(
		!cache_contents.contains("NPM_OTP") && !cache_contents.contains("482910"),
		"serve must never cache ephemeral OTP: {cache_contents}"
	);

	// Scoped serve session (`web_only`) must report `NPM_OTP` as Undeclared.
	let scoped_session = ResolverSession::launch(
		LaunchOptions {
			executable: PathBuf::from(bin()),
			arguments: vec![OsString::from("serve")],
			environment: Environment::Inherit(env),
			allow_path_discovery: false,
			max_stderr_bytes: 64 * 1024,
		},
		Product {
			name: "ephemeral-otp-test".into(),
			version: "1".into(),
		},
		Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 4,
		},
		InitializeApplication {
			manifest: Manifest::Path {
				path: manifest.to_string_lossy().into_owned(),
			},
			provider: None,
			profile: Some("default".into()),
			scope: Some("web_only".into()),
			reason: None,
			requested_authorization_duration_ms: None,
		},
		deadline(),
	)
	.await
	.unwrap();

	let scoped_result = scoped_session
		.get(
			&GetParams {
				name: "NPM_OTP".into(),
				representation: Representation::Value,
				purpose,
			},
			deadline(),
		)
		.await
		.unwrap();
	assert!(
		matches!(scoped_result, GetResult::Undeclared(_)),
		"scoped serve excluding NPM_OTP must report Undeclared, got {scoped_result:?}"
	);
	scoped_session.close(deadline()).await.unwrap();
}

#[test]
fn otp_refuses_raw_seed_and_non_otp_fields_and_supports_whole_item_and_legacy_op_token() {
	let dir = TempDir::new().unwrap();
	let bootstrap = dir.path().join(".env.bootstrap");
	let seed_dotenv = dir.path().join(".env.seed");
	fs::write(&bootstrap, "OP_SERVICE_ACCOUNT_TOKEN=ops_fixture_token\n").unwrap();
	fs::write(
		&seed_dotenv,
		"RAW_SEED_OTP=otpauth://totp/fixture?secret=JBSWY3DPEHPK3PXP\n",
	)
	.unwrap();

	// 1. When 1Password returns a raw `otpauth://` seed, `get` and `run --include`
	// must fail and never emit the seed.
	let seed_dir = TempDir::new().unwrap();
	let (_seed_log, seed_op_stub) = write_op_stub(seed_dir.path(), "seed_on_read");
	let seed_manifest = write_dotfiles_otp_manifest(seed_dir.path(), &bootstrap, None);

	let get_seed = Command::new(bin())
		.current_dir(seed_dir.path())
		.args(["-f", seed_manifest.to_str().unwrap(), "get", "NPM_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &seed_op_stub)
		.env("HOME", seed_dir.path())
		.output()
		.unwrap();
	assert!(
		!get_seed.status.success(),
		"get on raw otpauth:// seed must fail"
	);
	let get_seed_stdout = String::from_utf8_lossy(&get_seed.stdout);
	let get_seed_stderr = String::from_utf8_lossy(&get_seed.stderr);
	assert!(
		!get_seed_stdout.contains("otpauth://") && !get_seed_stdout.contains("JBSWY3DPEHPK3PXP"),
		"stdout must never leak OTP seed: {get_seed_stdout}"
	);
	assert!(
		get_seed_stderr.contains("otpauth://"),
		"stderr must explain seed refusal: {get_seed_stderr}"
	);

	let run_seed = Command::new(bin())
		.current_dir(seed_dir.path())
		.args([
			"-f",
			seed_manifest.to_str().unwrap(),
			"run",
			"--include",
			"NPM_OTP",
			"--",
			"sh",
			"-c",
			"echo should-not-run",
		])
		.env("MONOSECRET_OPCLI_PATH", &seed_op_stub)
		.env("HOME", seed_dir.path())
		.output()
		.unwrap();
	assert!(
		!run_seed.status.success(),
		"run --include on raw otpauth:// seed must fail"
	);
	assert!(
		!String::from_utf8_lossy(&run_seed.stdout).contains("should-not-run"),
		"child command must not run when OTP seed is refused"
	);

	// 2. Non-1Password provider holding a raw `otpauth://` seed also refuses it,
	// non-OTP 1Password fields error cleanly, whole-item OTP uses `--otp`, and
	// legacy `op+token://Development/Dotfiles` folds `item` into section.
	let (log, op_stub) = write_op_stub(dir.path(), "with_totp");
	let manifest = dir.path().join("monosecret.toml");
	fs::write(
		&manifest,
		format!(
			r#"[project]
name = "otp-modes-test"
revision = "1.0"
require_reason = false

[providers]
bootstrap = "dotenv://{bootstrap}"
seed_store = "dotenv://{seed_dotenv}"
op = {{ uri = "onepassword+token://Development", depends_on = [{{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }}] }}
op-legacy = {{ uri = "op+token://Development/Dotfiles", depends_on = [{{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }}] }}

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = {{ description = "bootstrap token", providers = ["bootstrap"] }}
RAW_SEED_OTP = {{ description = "raw seed in dotenv", type = "otp", ephemeral = true, providers = ["seed_store"] }}
BAD_FIELD_OTP = {{ description = "non-OTP field", type = "otp", ephemeral = true, providers = ["op"], ref = {{ item = "Dotfiles", section = "registries", field = "NPM_TOKEN" }} }}
WHOLE_ITEM_OTP = {{ description = "whole-item OTP", type = "otp", ephemeral = true, providers = ["op"], ref = {{ item = "Dotfiles" }} }}
LEGACY_OTP = {{ description = "legacy op+token OTP", type = "otp", ephemeral = true, providers = ["op-legacy"], ref = {{ item = "registries", field = "NPM_OTP" }} }}
"#,
			bootstrap = forward_slashes(&bootstrap),
			seed_dotenv = forward_slashes(&seed_dotenv),
		),
	)
	.unwrap();

	let dotenv_seed_out = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "RAW_SEED_OTP"])
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		!dotenv_seed_out.status.success(),
		"dotenv provider must refuse raw otpauth:// seed for type = \"otp\""
	);
	assert!(
		!String::from_utf8_lossy(&dotenv_seed_out.stdout).contains("JBSWY3DPEHPK3PXP"),
		"stdout must never leak dotenv OTP seed"
	);
	assert!(
		String::from_utf8_lossy(&dotenv_seed_out.stderr).contains("otpauth://"),
		"stderr: {}",
		String::from_utf8_lossy(&dotenv_seed_out.stderr)
	);

	let bad_field_out = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "BAD_FIELD_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		!bad_field_out.status.success(),
		"pointing type = \"otp\" at a non-OTP field must fail"
	);
	assert!(
		!String::from_utf8_lossy(&bad_field_out.stdout).contains("npm_fixture_token_value"),
		"must never return static field value for type = \"otp\""
	);

	let whole_item_out = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "WHOLE_ITEM_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		whole_item_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&whole_item_out.stderr)
	);
	let whole_code = String::from_utf8_lossy(&whole_item_out.stdout);
	assert_eq!(whole_code.len(), 6);
	assert!(whole_code.chars().all(|c| c.is_ascii_digit()));
	assert_eq!(whole_code, "731942");

	let legacy_out = Command::new(bin())
		.current_dir(dir.path())
		.args(["-f", manifest.to_str().unwrap(), "get", "LEGACY_OTP"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		legacy_out.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&legacy_out.stderr)
	);
	let legacy_code = String::from_utf8_lossy(&legacy_out.stdout);
	assert_eq!(legacy_code.len(), 6);
	assert!(legacy_code.chars().all(|c| c.is_ascii_digit()));
	assert_eq!(legacy_code, "482910");

	let calls = read_op_log(&log);
	assert!(
		calls
			.iter()
			.any(|line| line.contains("item get Dotfiles --vault Development --otp")),
		"expected whole-item --otp call in log: {calls:?}"
	);
	assert!(
		calls.iter().any(|line| {
			line.contains("op://Development/Dotfiles/registries/NPM_OTP?attribute=otp")
		}),
		"expected legacy op+token ?attribute=otp call in log: {calls:?}"
	);
}
