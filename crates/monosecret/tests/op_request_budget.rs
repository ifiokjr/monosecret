//! End-to-end service-account request budget tests.
//!
//! Every secret reference `op inject` resolves is one billed read against the
//! 1Password service-account rate limits
//! (<https://www.1password.dev/service-accounts/rate-limits>), and manifests
//! in the wild — the global dotfiles manifest, the nifty manifest — pin a
//! whole profile's secrets as sectioned references to *one shared item* via
//! `op+token://<vault>/<item>`. Resolution must therefore cost a fixed
//! two-read budget (auth preflight + one batched `op item get`) regardless of
//! how many secrets share the item, not one read per secret.
//!
//! A stand-in `op` CLI logs every invocation; the snapshots pin the exact
//! request sequence, so any regression that starts hitting the service account
//! once per secret fails here.

#![cfg(unix)]
// Test fixtures build shell snippets and manifest entries from small string
// tables; the natural idiom trips the format-collect pedantic lint.
#![allow(clippy::format_collect)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

fn forward_slashes(p: &std::path::Path) -> String {
	p.display().to_string().replace('\\', "/")
}

/// The sectioned references the shared `Dotfiles` item carries: sections keyed
/// by path, fields by env name. `([secret name], [section path], [field])`.
const DOTFILES_REFS: [(&str, &str, &str); 16] = [
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

/// The shared `Dotfiles` item in the layout `op item get --format json` emits:
/// a field's section carries only the id, and the item-level sections list
/// maps ids to labels.
fn dotfiles_item_json() -> String {
	let sections: Vec<&str> = DOTFILES_REFS
		.iter()
		.map(|(_, section, _)| *section)
		.collect();
	serde_json::json!([{
		"id": "dotfiles-item-id",
		"title": "Dotfiles",
		"sections": sections
			.iter()
			.map(|section| serde_json::json!({"id": section, "label": section}))
			.collect::<Vec<_>>(),
		"fields": DOTFILES_REFS
			.iter()
			.map(|(_name, section, field)| {
				serde_json::json!({
					"id": field,
					"type": "CONCEALED",
					"label": field,
					"value": format!("{section}/{field}-value"),
					"section": {"id": section},
				})
			})
			.collect::<Vec<_>>(),
	}])
	.to_string()
}

/// A stand-in `op` CLI. Every invocation is appended to the log file, one
/// `<subcommand> <args...>` line per process, so tests can assert the exact
/// request sequence the service account sees.
///
/// Behavior is selected by `$OP_STUB_MODE`:
/// - `serve`: `vault list` succeeds and `item get` serves the shared
///   `Dotfiles` item from stdin batches or direct arguments.
/// - `ambiguous`: `item get` fails the way `op` reports a non-unique title,
///   forcing the batch tiers to defer; the `inject` fallback still resolves.
fn write_op_stub(script: &std::path::Path, log: &std::path::Path, sed: &std::path::Path) {
	let sed_lines: String = DOTFILES_REFS
		.iter()
		.map(|(_name, section, field)| {
			format!(
				"s|{{{{ op://Development/Dotfiles/{section}/{field} }}}}|{section}/{field}-injected|g\n"
			)
		})
		.collect();
	fs::write(sed, sed_lines).unwrap();

	let script_body = format!(
		r#"#!/bin/sh
OP_STUB_MODE="$OP_STUB_MODE"
printf '%s\n' "$*" >> '{log}'

# `item get` emits one JSON document per requested item, from stdin
# (batch form) or the direct argument (single-item form).
emit_items() {{
	while IFS= read -r name; do
		[ -z "$name" ] && continue
		case "$name" in
			Dotfiles) printf '%s' '{dotfiles_json}' ;;
			*)
				printf "error: '%s' isn't an item in this vault\n" "$name" >&2
				exit 1
				;;
		esac
	done
}}

case "$1" in
	vault) printf '[]\n' ;;
	item)
		case "$2" in
			get)
				if [ "$OP_STUB_MODE" = "ambiguous" ]; then
					printf "error: More than one item matches the specified item name/version/query. (Item name: '{name}')\n" >&2
					exit 1
				fi
				case "$3" in
					""|-*) emit_items ;;
					*) printf '%s\n' "$3" | emit_items ;;
				esac
				;;
			list) printf '[{{"id": "dotfiles-item-id", "title": "Dotfiles"}}]\n' ;;
			*) printf 'unexpected op item call: %s\n' "$*" >&2; exit 1 ;;
		esac
		;;
	read) printf 'read-path-unreachable-when-item-get-serves\n' ;;
	inject) sed -f '{sed}' ;;
	*) printf 'unexpected op call: %s\n' "$*" >&2; exit 1 ;;
esac
"#,
		log = log.display(),
		dotfiles_json = dotfiles_item_json(),
		sed = forward_slashes(sed),
		name = "{name}",
	);
	fs::write(script, script_body).unwrap();
	let mut permissions = fs::metadata(script).unwrap().permissions();
	permissions.set_mode(0o755);
	fs::set_permissions(script, permissions).unwrap();
}

/// Reads the stub's invocation log, one line per `op` process.
fn op_calls(log: &std::path::Path) -> Vec<String> {
	fs::read_to_string(log)
		.unwrap()
		.lines()
		.map(str::to_string)
		.collect()
}

/// Writes the global-dotfiles-shaped manifest: a `depends_on` bootstrap token
/// from an ignored dotenv file, and a profile of sectioned references to the
/// single shared `Dotfiles` item.
fn write_dotfiles_manifest(dir: &std::path::Path, dotenv: &std::path::Path) -> std::path::PathBuf {
	let manifest = dir.join("monosecret.toml");
	let entries: String = DOTFILES_REFS
		.iter()
		.map(|(name, path, key)| {
			format!(
				"{name} = {{ description = \"{name}\", providers = [{{ provider = \"op-token\", path = [\"{path}\"], key = \"{key}\" }}] }}\n"
			)
		})
		.collect();
	fs::write(
		&manifest,
		format!(
			r#"
[project]
name = "dotfiles-budget"
revision = "1.0"

[providers]
dotenv = "dotenv://{dotenv}"
op-token = {{ uri = "op+token://Development/Dotfiles", depends_on = [
	{{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }},
] }}

[profiles.default.defaults]
providers = ["op-token"]

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = {{ description = "bootstrap token", providers = ["dotenv"] }}
{entries}
"#,
			dotenv = forward_slashes(dotenv),
			entries = entries,
		),
	)
	.unwrap();
	manifest
}

fn write_stub_with_mode(
	dir: &std::path::Path,
	mode: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
	let op_stub = dir.join("op-stub");
	let log = dir.join("op-calls.log");
	let sed = dir.join("replacements.sed");
	write_op_stub(&op_stub, &log, &sed);
	let script = fs::read_to_string(&op_stub).unwrap().replace(
		"OP_STUB_MODE=\"$OP_STUB_MODE\"",
		&format!("OP_STUB_MODE={mode}"),
	);
	fs::write(&op_stub, script).unwrap();
	(log, op_stub)
}

/// The full-resolution request budget for a dotfiles-shaped manifest: the auth
/// preflight plus exactly one batched item read serve all 16 secrets — the
/// reference count never reaches the service account.
#[test]
fn dotfiles_shaped_manifest_costs_one_item_read() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env.dotfiles");
	fs::write(&dotenv, "OP_SERVICE_ACCOUNT_TOKEN=ops_budget-test-token\n").unwrap();
	let (log, op_stub) = write_stub_with_mode(dir.path(), "serve");
	let manifest = write_dotfiles_manifest(dir.path(), &dotenv);

	let output = Command::new(bin())
		.current_dir(dir.path())
		.arg("-f")
		.arg(&manifest)
		.args(["export", "--format", "dotenv"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let exported = String::from_utf8_lossy(&output.stdout);
	for (section, field) in [
		("forges", "GITHUB_TOKEN"),
		("ai", "OPENAI_API_KEY"),
		("backblaze", "BACKBLAZE_APPLICATION_KEY"),
	] {
		let expected = format!("{field}={section}/{field}-value");
		assert!(
			exported.lines().any(|line| line == expected),
			"export must contain {expected}; got: {exported}"
		);
	}

	let calls = op_calls(&log);
	assert_eq!(
		calls.len(),
		2,
		"one preflight and one batched item read, however many secrets share the item: {calls:?}"
	);
	insta::assert_snapshot!("dotfiles_request_log", calls.join("\n"));
}

/// The `run` path (the devenv / shell entry point) has the same fixed budget,
/// with the `depends_on` token delivered from the bootstrap dotenv store.
#[test]
fn run_command_with_bootstrap_token_costs_one_item_read() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env.dotfiles");
	fs::write(&dotenv, "OP_SERVICE_ACCOUNT_TOKEN=ops_budget-test-token\n").unwrap();
	let (log, op_stub) = write_stub_with_mode(dir.path(), "serve");
	let manifest = write_dotfiles_manifest(dir.path(), &dotenv);

	let output = Command::new(bin())
		.current_dir(dir.path())
		.arg("-f")
		.arg(&manifest)
		.args(["run", "--"])
		.args([
			"sh",
			"-c",
			r#"printf '%s|%s\n' "$OPENAI_API_KEY" "$NPM_TOKEN""#,
		])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout).trim(),
		"ai/OPENAI_API_KEY-value|registries/NPM_TOKEN-value"
	);

	let calls = op_calls(&log);
	assert_eq!(
		calls.len(),
		2,
		"same fixed budget on the run path: {calls:?}"
	);
	insta::assert_snapshot!("run_request_log", calls.join("\n"));
}

/// When item reads cannot disambiguate the title, resolution defers to the
/// inject fallback and still serves every secret — the degraded, more
/// expensive path, pinned here so its extra requests are a conscious choice.
#[test]
fn ambiguous_item_titles_fall_back_to_inject() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env.dotfiles");
	fs::write(&dotenv, "OP_SERVICE_ACCOUNT_TOKEN=ops_budget-test-token\n").unwrap();
	let (log, op_stub) = write_stub_with_mode(dir.path(), "ambiguous");
	let manifest = write_dotfiles_manifest(dir.path(), &dotenv);

	let output = Command::new(bin())
		.current_dir(dir.path())
		.arg("-f")
		.arg(&manifest)
		.args(["export", "--format", "dotenv"])
		.env("MONOSECRET_OPCLI_PATH", &op_stub)
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"the inject fallback must still resolve: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let exported = String::from_utf8_lossy(&output.stdout);
	assert!(
		exported
			.lines()
			.any(|line| line == "OPENAI_API_KEY=ai/OPENAI_API_KEY-injected"),
		"inject fallback values must resolve; got: {exported}"
	);

	let calls = op_calls(&log);
	insta::assert_snapshot!("fallback_request_log", calls.join("\n"));
}
