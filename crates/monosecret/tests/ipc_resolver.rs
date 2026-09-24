#![cfg(feature = "cli")]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use monosecret_ipc::client::Client;
use monosecret_ipc::error::RpcError;
use monosecret_ipc::lifecycle::Environment;
use monosecret_ipc::lifecycle::LaunchOptions;
use monosecret_ipc::lifecycle::PromptResponder;
use monosecret_ipc::lifecycle::ResolverSession;
use monosecret_ipc::protocol::InitializeParams;
use monosecret_ipc::protocol::Limits;
use monosecret_ipc::protocol::Product;
use monosecret_ipc::protocol::callback::PromptParams;
use monosecret_ipc::protocol::callback::PromptResult;
use monosecret_ipc::protocol::resolver::DeleteParams;
use monosecret_ipc::protocol::resolver::GetParams;
use monosecret_ipc::protocol::resolver::GetResult;
use monosecret_ipc::protocol::resolver::InitializeApplication;
use monosecret_ipc::protocol::resolver::Manifest;
use monosecret_ipc::protocol::resolver::Purpose;
use monosecret_ipc::protocol::resolver::ReleaseParams;
use monosecret_ipc::protocol::resolver::Representation;
use monosecret_ipc::protocol::resolver::SetParams;
use monosecret_ipc::protocol::resolver::method;
use serde_json::Value;
use serde_json::json;

fn deadline(after: Duration) -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis()
		.saturating_add(after.as_millis()) as u64
}

fn launch_options() -> LaunchOptions {
	LaunchOptions {
		executable: PathBuf::from(env!("CARGO_BIN_EXE_monosecret")),
		arguments: vec![OsString::from("serve")],
		environment: Environment::Inherit(BTreeMap::new()),
		allow_path_discovery: false,
		max_stderr_bytes: 64 * 1024,
	}
}

fn product() -> Product {
	Product {
		name: "integration-test".into(),
		version: "1".into(),
	}
}

fn limits() -> Limits {
	Limits {
		max_frame_bytes: 32 * 1024,
		max_in_flight: 4,
	}
}

/// The events a case demands. Comparing the observed set against exactly this
/// is what makes a case-driven test fail when it silently stops exercising a
/// branch the case still claims to cover.
fn required_events(case: &Value) -> BTreeSet<&str> {
	let events = case
		.get("required_events")
		.and_then(Value::as_array)
		.expect("a case declares its required events");
	events.iter().filter_map(|event| event.as_str()).collect()
}

/// The action list of a case, or a panic naming the case that lost it.
fn actions_of(case: &Value) -> &[Value] {
	case.get("actions")
		.and_then(Value::as_array)
		.expect("a case declares its actions")
}

#[tokio::test]
async fn checked_in_resolver_case_runs_against_the_real_cli() {
	let case: Value =
		serde_json::from_str(include_str!("fixtures/ipc/resolver-leases.json")).unwrap();
	assert_eq!(case.get("schema_version"), Some(&json!(1)));
	assert_eq!(
		case.get("id").and_then(Value::as_str),
		Some("resolver.path-leases")
	);
	assert!(
		case.get("targets")
			.and_then(Value::as_array)
			.is_some_and(|targets| targets.iter().any(|target| target == "resolver"))
	);
	let actions = actions_of(&case);
	let initialize_action = actions
		.iter()
		.find(|action| action.get("kind") == Some(&json!("initialize")))
		.unwrap();
	assert_eq!(initialize_action["manifest"], "inline");
	assert_eq!(initialize_action["profile"], "default");

	let directory = tempfile::tempdir().unwrap();
	let dotenv = directory.path().join("values.env");
	std::fs::write(&dotenv, "TOKEN=inline-value\nCERT=leased-value\n").unwrap();
	let manifest = r#"
[project]
name = "black-box-ipc"
revision = "1.0"
require_reason = false

[profiles.default]
TOKEN = { description = "token" }
CERT = { description = "certificate", as_path = true }
OPTIONAL = { description = "optional", required = false }
UNRELATED = { description = "named resolution must not read this", required = true }
"#;

	let application = InitializeApplication {
		manifest: Manifest::Inline {
			toml: manifest.into(),
			base_dir: directory.path().to_string_lossy().into_owned(),
		},
		provider: Some(format!("dotenv:{}", dotenv.display())),
		profile: Some("default".into()),
		scope: None,
		reason: None,
		requested_authorization_duration_ms: None,
	};
	let session = ResolverSession::launch(
		LaunchOptions {
			executable: PathBuf::from(env!("CARGO_BIN_EXE_monosecret")),
			arguments: vec![OsString::from("serve")],
			environment: Environment::Inherit(BTreeMap::new()),
			allow_path_discovery: false,
			max_stderr_bytes: 64 * 1024,
		},
		Product {
			name: "integration-test".into(),
			version: "1".into(),
		},
		Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 4,
		},
		application,
		deadline(Duration::from_secs(5)),
	)
	.await
	.unwrap();
	let purpose = Purpose {
		consumer: "integration-test".into(),
		operation: "resolve".into(),
		host: None,
		path: None,
	};
	let mut events = BTreeSet::from(["initialized"]);
	let mut active_lease: Option<(String, String)> = None;

	for action in actions.iter().skip(1) {
		match action.get("kind").and_then(Value::as_str) {
			Some("resolve") => {
				let name = action["name"].as_str().unwrap();
				let representation = match action["representation"].as_str().unwrap() {
					"auto" => Representation::Auto,
					"value" => Representation::Value,
					"path" => Representation::Path,
					other => panic!("unsupported representation {other}"),
				};
				let result = session
					.get(
						&GetParams {
							name: name.into(),
							representation,
							purpose: purpose.clone(),
						},
						deadline(Duration::from_secs(5)),
					)
					.await
					.unwrap();
				match (name, result) {
					("TOKEN", GetResult::Value(value)) => {
						assert_eq!(value.value, "inline-value");
						assert_eq!(value.expires_at_unix_ms, None);
						assert_eq!(value.refresh_at_unix_ms, None);
						events.insert("resolved_value");
					}
					("OPTIONAL", GetResult::Missing(missing)) => {
						assert!(!missing.required);
						events.insert("missing");
					}
					("UNKNOWN", GetResult::Undeclared(_)) => {
						events.insert("undeclared");
					}
					("CERT", GetResult::Path(leased)) => {
						assert_eq!(
							std::fs::read_to_string(&leased.path).unwrap(),
							"leased-value"
						);
						assert_eq!(leased.expires_at_unix_ms, None);
						assert_eq!(leased.refresh_at_unix_ms, None);
						#[cfg(unix)]
						{
							use std::os::unix::fs::PermissionsExt;
							assert_eq!(
								std::fs::metadata(&leased.path)
									.unwrap()
									.permissions()
									.mode()
									& 0o777,
								0o400
							);
						}
						active_lease = Some((leased.path, leased.path_lease_id));
						events.insert("lease_created");
					}
					_ => panic!("resolver returned the wrong result for {name}"),
				}
			}
			Some("release") => {
				assert_eq!(action["duplicates"], true);
				let (path, lease_id) = active_lease.take().unwrap();
				let released = session
					.release(
						&ReleaseParams {
							path_lease_ids: vec![lease_id.clone(), lease_id],
						},
						deadline(Duration::from_secs(5)),
					)
					.await
					.unwrap();
				assert_eq!(released.released, 1);
				assert!(!std::path::Path::new(&path).exists());
				events.insert("lease_removed");
			}
			Some("disconnect") => {
				let (path, _) = active_lease.take().unwrap();
				session
					.close(deadline(Duration::from_secs(5)))
					.await
					.unwrap();
				assert!(!std::path::Path::new(&path).exists());
				events.insert("disconnect_cleanup");
				events.insert("closed");
			}
			None => panic!("resolver case action without a kind"),
			Some(other) => panic!("unsupported resolver case action {other}"),
		}
	}

	assert_eq!(events, required_events(&case));
}

/// The mutation methods against the real CLI, which is what a consumer such as
/// `cargo login` drives: a stored value must be exactly what the same session
/// then resolves, and removing it must be idempotent.
#[tokio::test]
async fn stored_values_round_trip_against_the_real_cli() {
	let directory = tempfile::tempdir().unwrap();
	let dotenv = directory.path().join("values.env");
	std::fs::write(&dotenv, "").unwrap();
	let manifest = r#"
[project]
name = "cargo"
revision = "1.0"
require_reason = false

[profiles.default]
CARGO_REGISTRY_TOKEN = { description = "Cargo registry token", required = false }
"#;

	let session = ResolverSession::launch(
		LaunchOptions {
			executable: PathBuf::from(env!("CARGO_BIN_EXE_monosecret")),
			arguments: vec![OsString::from("serve")],
			environment: Environment::Inherit(BTreeMap::new()),
			allow_path_discovery: false,
			max_stderr_bytes: 64 * 1024,
		},
		Product {
			name: "integration-test".into(),
			version: "1".into(),
		},
		Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 4,
		},
		InitializeApplication {
			manifest: Manifest::Inline {
				toml: manifest.into(),
				base_dir: directory.path().to_string_lossy().into_owned(),
			},
			provider: Some(format!("dotenv:{}", dotenv.display())),
			profile: Some("default".into()),
			scope: None,
			reason: None,
			requested_authorization_duration_ms: None,
		},
		deadline(Duration::from_secs(5)),
	)
	.await
	.unwrap();
	assert!(session.supports(method::SET));
	assert!(session.supports(method::DELETE));

	let purpose = Purpose {
		consumer: "cargo".into(),
		operation: "login".into(),
		host: Some("crates.io".into()),
		path: None,
	};
	let stored = session
		.set(
			&SetParams {
				name: "CARGO_REGISTRY_TOKEN".into(),
				value: "stored-token".into(),
				purpose: purpose.clone(),
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	assert!(stored.target_provider.unwrap().starts_with("dotenv:"));

	let resolved = session
		.get(
			&GetParams {
				name: "CARGO_REGISTRY_TOKEN".into(),
				representation: Representation::Value,
				purpose: purpose.clone(),
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	let GetResult::Value(value) = resolved else {
		panic!("expected the stored value")
	};
	assert_eq!(value.value, "stored-token");

	let removed = session
		.delete(
			&DeleteParams {
				name: "CARGO_REGISTRY_TOKEN".into(),
				purpose: purpose.clone(),
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	assert!(removed.deleted);
	let resolved = session
		.get(
			&GetParams {
				name: "CARGO_REGISTRY_TOKEN".into(),
				representation: Representation::Value,
				purpose: purpose.clone(),
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	assert!(matches!(resolved, GetResult::Missing(_)));

	// Removing what is no longer there is a success, not an error.
	let removed = session
		.delete(
			&DeleteParams {
				name: "CARGO_REGISTRY_TOKEN".into(),
				purpose,
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	assert!(!removed.deleted);
	session
		.close(deadline(Duration::from_secs(5)))
		.await
		.unwrap();
}

/// The checked-in `resolver.prompt` case, against the real CLI.
///
/// The resolver has no terminal of its own, so the question travels back to
/// this process and the answer travels forward. The second session in the case
/// advertises nothing and must resolve to a plain missing result without a
/// prompt ever being sent, which is what keeps a headless consumer from waiting
/// out its deadline.
#[tokio::test]
async fn checked_in_prompt_case_runs_against_the_real_cli() {
	struct Responder {
		asked: Arc<Mutex<Vec<PromptParams>>>,
	}

	#[async_trait::async_trait]
	impl PromptResponder for Responder {
		async fn prompt(&self, params: PromptParams) -> Result<PromptResult, RpcError> {
			self.asked.lock().unwrap().push(params);
			Ok(PromptResult {
				value: "typed-by-a-person".into(),
			})
		}
	}

	let case: Value =
		serde_json::from_str(include_str!("fixtures/ipc/resolver-prompt.json")).unwrap();
	assert_eq!(case.get("schema_version"), Some(&json!(1)));
	assert_eq!(
		case.get("id").and_then(Value::as_str),
		Some("resolver.prompt")
	);
	let actions = actions_of(&case);

	let directory = tempfile::tempdir().unwrap();
	let dotenv = directory.path().join("values.env");
	std::fs::write(&dotenv, "").unwrap();
	let manifest = r#"
[project]
name = "prompted"
revision = "1.0"
require_reason = false

[profiles.default]
DEPLOY_PASSWORD = { description = "deploy password", prompt = true }
"#;
	let application = || {
		InitializeApplication {
			manifest: Manifest::Inline {
				toml: manifest.into(),
				base_dir: directory.path().to_string_lossy().into_owned(),
			},
			provider: Some(format!("dotenv:{}", dotenv.display())),
			profile: Some("default".into()),
			scope: None,
			reason: None,
			requested_authorization_duration_ms: None,
		}
	};
	let purpose = Purpose {
		consumer: "integration-test".into(),
		operation: "resolve".into(),
		host: None,
		path: None,
	};

	let asked = Arc::new(Mutex::new(Vec::new()));
	let mut events = BTreeSet::new();
	let mut session: Option<ResolverSession> = None;

	for action in actions {
		match action.get("kind").and_then(Value::as_str) {
			Some("initialize") => {
				let advertises = !action["client_methods"].as_array().unwrap().is_empty();
				let responder: Option<Arc<dyn PromptResponder>> = advertises.then(|| {
					Arc::new(Responder {
						asked: asked.clone(),
					}) as Arc<dyn PromptResponder>
				});
				session = Some(
					ResolverSession::launch_with_prompt(
						launch_options(),
						product(),
						limits(),
						application(),
						deadline(Duration::from_secs(5)),
						responder,
					)
					.await
					.unwrap(),
				);
				events.insert("initialized");
			}
			Some("resolve") => {
				let before = asked.lock().unwrap().len();
				let result = session
					.as_ref()
					.unwrap()
					.get(
						&GetParams {
							name: action["name"].as_str().unwrap().into(),
							representation: Representation::Value,
							purpose: purpose.clone(),
						},
						deadline(Duration::from_secs(10)),
					)
					.await
					.unwrap();
				let asked_now = asked.lock().unwrap().len();
				match action["expect"].as_str().unwrap() {
					"prompted" => {
						let GetResult::Value(value) = result else {
							panic!("expected the answered value")
						};
						assert_eq!(value.value, "typed-by-a-person");
						assert_eq!(asked_now, before + 1);
						let params = asked.lock().unwrap().last().unwrap().clone();
						assert_eq!(params.name, "DEPLOY_PASSWORD");
						assert_eq!(params.profile, "default");
						// Named because the answer is stored there, and
						// credential-free.
						assert!(params.target_provider.unwrap().starts_with("dotenv:"));
						events.insert("prompt_requested");
						events.insert("prompt_answered");
					}
					"missing" => {
						let GetResult::Missing(missing) = result else {
							panic!("a prompt nobody can answer resolves to no value")
						};
						assert!(missing.required);
						assert_eq!(asked_now, before, "a headless session was still asked");
						events.insert("headless_missing");
						events.insert("no_prompt_requested");
					}
					other => panic!("unsupported prompt expectation {other}"),
				}
			}
			Some("disconnect") => {
				session
					.take()
					.unwrap()
					.close(deadline(Duration::from_secs(5)))
					.await
					.unwrap();
				// The answer was provisioned into the store, so it survives the
				// session that obtained it. Cleared afterwards so the headless
				// session starts from the same empty store.
				if std::fs::read_to_string(&dotenv)
					.unwrap()
					.contains("typed-by-a-person")
				{
					events.insert("answer_persisted");
					std::fs::write(&dotenv, "").unwrap();
				}
				events.insert("closed");
			}
			Some(other) => panic!("unsupported prompt case action {other}"),
			None => panic!("prompt case action without a kind"),
		}
	}

	assert_eq!(events, required_events(&case));
}

#[tokio::test]
async fn resolver_ephemeral_generation_is_silent_on_stderr() {
	use tokio::io::AsyncReadExt;

	let directory = tempfile::tempdir().unwrap();
	let manifest = r#"
[project]
name = "silent-generation"
revision = "1.0"
require_reason = false

[profiles.default]
SESSION_TOKEN = { description = "session token", type = "password", generate = true }
"#;
	let application = InitializeApplication {
		manifest: Manifest::Inline {
			toml: manifest.into(),
			base_dir: directory.path().to_string_lossy().into_owned(),
		},
		provider: Some("null://".into()),
		profile: Some("default".into()),
		scope: None,
		reason: None,
		requested_authorization_duration_ms: None,
	};

	let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_monosecret"))
		.arg("serve")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	let stdin = child.stdin.take().unwrap();
	let stdout = child.stdout.take().unwrap();
	let mut stderr = child.stderr.take().unwrap();
	let initialize = InitializeParams {
		protocol: "monosecret.resolver".into(),
		versions: vec![1],
		client: product(),
		limits: limits(),
		client_methods: Vec::new(),
		application,
	};
	let (client, _): (
		Client,
		monosecret_ipc::protocol::InitializeResult<
			monosecret_ipc::protocol::resolver::InitializedApplication,
		>,
	) = Client::connect(stdout, stdin, initialize, deadline(Duration::from_secs(5)))
		.await
		.unwrap();
	let result: GetResult = client
		.call(
			method::GET,
			&GetParams {
				name: "SESSION_TOKEN".into(),
				representation: Representation::Value,
				purpose: Purpose {
					consumer: "integration-test".into(),
					operation: "resolve".into(),
					host: None,
					path: None,
				},
			},
			deadline(Duration::from_secs(5)),
		)
		.await
		.unwrap();
	assert!(matches!(result, GetResult::Value(_)));
	client
		.close(deadline(Duration::from_secs(5)))
		.await
		.unwrap();

	let status = child.wait().await.unwrap();
	let mut diagnostics = Vec::new();
	stderr.read_to_end(&mut diagnostics).await.unwrap();
	assert!(status.success());
	assert!(
		diagnostics.is_empty(),
		"resolver leaked generation progress: {}",
		String::from_utf8_lossy(&diagnostics)
	);
}
