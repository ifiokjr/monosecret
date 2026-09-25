//! Resolve through SSH without printing secret values (Monosecret 0.4.0+).
//!
//! cargo run -p monosecret-ipc --example `ssh_resolver` -- HOST /remote/monosecret.toml NAME

use std::time::Duration;

use monosecret_ipc::Limits;
use monosecret_ipc::Product;
use monosecret_ipc::connection::SshOptions;
use monosecret_ipc::deadline_unix_ms_after;
use monosecret_ipc::lifecycle::ResolverSession;
use monosecret_ipc::protocol::resolver::GetParams;
use monosecret_ipc::protocol::resolver::GetResult;
use monosecret_ipc::protocol::resolver::InitializeApplication;
use monosecret_ipc::protocol::resolver::Manifest;
use monosecret_ipc::protocol::resolver::Purpose;
use monosecret_ipc::protocol::resolver::Representation;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	let [host, path, name] = args.as_slice() else {
		return Err("usage: ssh_resolver HOST /remote/monosecret.toml NAME".into());
	};
	let session = ResolverSession::launch_ssh(
		SshOptions::new(host),
		Product {
			name: "ssh-example".into(),
			version: "1".into(),
		},
		Limits {
			max_frame_bytes: 32768,
			max_in_flight: 4,
		},
		InitializeApplication {
			manifest: Manifest::Path { path: path.clone() },
			provider: None,
			profile: None,
			scope: None,
			reason: Some("resolve from SSH example".into()),
			requested_authorization_duration_ms: None,
		},
		deadline_unix_ms_after(Duration::from_secs(15)),
	)
	.await?;
	let result = session
		.get(
			&GetParams {
				name: name.clone(),
				representation: Representation::Auto,
				purpose: Purpose {
					consumer: "ssh-example".into(),
					operation: "resolve".into(),
					host: None,
					path: None,
				},
			},
			deadline_unix_ms_after(Duration::from_secs(30)),
		)
		.await;
	// Close even after a failed operation. Neither close nor relaunch replays it.
	let closed = session
		.close(deadline_unix_ms_after(Duration::from_secs(5)))
		.await;
	match result? {
		GetResult::Value(_) => println!("Resolved an inline value."),
		GetResult::Missing(_) => println!("Secret is missing."),
		GetResult::Undeclared(_) => println!("Secret is undeclared in this scope."),
		GetResult::Path(_) => unreachable!("SSH defaults to separate filesystems"),
	}
	closed?;
	Ok(())
}
