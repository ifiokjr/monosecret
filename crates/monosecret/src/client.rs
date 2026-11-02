//! Access values supplied by `monosecret run` or a trusted embedding host.
//!
//! Enable `client` with `default-features = false` to avoid linking the native
//! resolver, providers, process support, or an async runtime. Wasm hosts supply
//! values explicitly; browser applications must receive only values they are
//! authorized to hold, never server credentials.

use std::collections::BTreeMap;
use std::fmt;

pub use secrecy::ExposeSecret;
use secrecy::SecretString;

/// An owned snapshot of resolved UTF-8 values, wiped when dropped.
#[derive(Default)]
pub struct Client {
	values: BTreeMap<String, SecretString>,
}

/// A requested value was absent or could not be represented as UTF-8.
#[derive(Debug, PartialEq, Eq)]
pub struct MissingSecret {
	/// The requested name; errors never contain the value.
	pub name: String,
}

impl fmt::Display for MissingSecret {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(formatter, "missing UTF-8 secret: {}", self.name)
	}
}

impl std::error::Error for MissingSecret {}

impl Client {
	/// Accept values resolved by a host. Works in browsers and native Wasm guests
	/// without filesystem, environment, network, or process imports.
	pub fn from_values(values: impl IntoIterator<Item = (String, SecretString)>) -> Self {
		Self {
			values: values.into_iter().collect(),
		}
	}

	/// Snapshot only the named environment entries injected by `monosecret run`.
	/// Does not change the process environment. Unavailable on Wasm; its host
	/// supplies values with [`Self::from_values`].
	#[cfg(not(target_family = "wasm"))]
	pub fn from_env(
		names: impl IntoIterator<Item = impl AsRef<str>>,
	) -> Result<Self, MissingSecret> {
		let mut values = BTreeMap::new();
		for name in names {
			let name = name.as_ref();
			let value = std::env::var(name).map_err(|_| MissingSecret { name: name.into() })?;
			values.insert(name.into(), value.into());
		}
		Ok(Self { values })
	}

	/// Borrow a value, exposing its text only when `ExposeSecret` is called.
	pub fn get(&self, name: &str) -> Result<&SecretString, MissingSecret> {
		self.values
			.get(name)
			.ok_or_else(|| MissingSecret { name: name.into() })
	}
}

impl fmt::Debug for Client {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Client")
			.field("names", &self.values.keys())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn host_values_are_readable_but_diagnostics_are_redacted() {
		let client = Client::from_values([("TOKEN".into(), "private-value".into())]);
		assert_eq!(
			client.get("TOKEN").unwrap().expose_secret(),
			"private-value"
		);
		assert!(!format!("{client:?}").contains("private-value"));
		assert_eq!(
			client.get("ABSENT").unwrap_err().to_string(),
			"missing UTF-8 secret: ABSENT"
		);
	}

	#[test]
	#[cfg(not(target_family = "wasm"))]
	fn missing_environment_value_names_only_the_entry() {
		let error = Client::from_env(["MONOSECRET_CLIENT_TEST_ABSENT_9372"]).unwrap_err();
		assert_eq!(error.name, "MONOSECRET_CLIENT_TEST_ABSENT_9372");
	}
}
