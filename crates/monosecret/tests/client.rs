//! Exercise the public lightweight client, including process-injected values.
#![cfg(all(feature = "client", not(target_family = "wasm")))]

use std::process::Command;

use monosecret::client::Client;
use monosecret::client::ExposeSecret as _;

#[test]
fn host_values_are_exposed_only_when_requested() {
	let client = Client::from_values([("TOKEN".into(), "host-supplied-value".into())]);
	assert_eq!(
		client.get("TOKEN").unwrap().expose_secret(),
		"host-supplied-value"
	);
	let debug = format!("{client:?}");
	assert!(debug.contains("TOKEN"));
	assert!(!debug.contains("host-supplied-value"));
	let missing = client.get("ABSENT").unwrap_err();
	assert_eq!(missing.name, "ABSENT");
	assert_eq!(missing.to_string(), "missing UTF-8 secret: ABSENT");
	assert!(Client::default().get("TOKEN").is_err());
}

#[test]
fn injected_environment_is_read_explicitly() {
	const CHILD: &str = "MONOSECRET_CLIENT_TEST_CHILD";
	const PRESENT: &str = "MONOSECRET_CLIENT_TEST_PRESENT";
	const ABSENT: &str = "MONOSECRET_CLIENT_TEST_ABSENT";
	if std::env::var_os(CHILD).is_some() {
		let client = Client::from_env([PRESENT]).unwrap();
		assert_eq!(
			client.get(PRESENT).unwrap().expose_secret(),
			"injected-value"
		);
		assert!(client.get("PATH").is_err());
		assert_eq!(std::env::var(PRESENT).unwrap(), "injected-value");
		assert_eq!(
			Client::from_env([PRESENT, ABSENT]).unwrap_err().name,
			ABSENT
		);
		assert!(
			Client::from_env(std::iter::empty::<&str>())
				.unwrap()
				.get(PRESENT)
				.is_err()
		);
		return;
	}
	// Set the environment only on a child, so tests never mutate shared process
	// state. Inherit profiling variables so this path contributes to coverage.
	let output = Command::new(std::env::current_exe().unwrap())
		.args([
			"--exact",
			"injected_environment_is_read_explicitly",
			"--nocapture",
		])
		.env(CHILD, "1")
		.env(PRESENT, "injected-value")
		.env_remove(ABSENT)
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
}
