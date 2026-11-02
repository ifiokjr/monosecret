//! A small, callable Wasm client fixture. The value is synthetic, not a secret.
use monosecret::client::Client;
use monosecret::client::ExposeSecret as _;

/// Exercise lookup and zeroizing storage using a runtime-selected name.
#[unsafe(no_mangle)]
pub extern "C" fn resolved_value_length(name: u32) -> usize {
	let client = Client::from_values([(name.to_string(), "host-supplied-token".into())]);
	client
		.get(&name.to_string())
		.map_or(0, |value| value.expose_secret().len())
}
