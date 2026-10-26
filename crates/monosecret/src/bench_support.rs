//! Thin public entry points for the criterion benchmarks in `benches/`.
//!
//! Benchmarks compile as an external crate, so the hot paths that are
//! `pub(crate)` on purpose — the cache envelope codec — need a doorway. This
//! module is the whole doorway: it exists only behind the `__bench` feature, is
//! hidden from documentation, and promises nothing about stability.

use crate::ProviderValue;
use crate::SecretBytes;
use crate::cache;
use crate::cache::CacheEntryStatus;
/// The shell declaration renderer behind `monosecret env`, which lives in a
/// private CLI module.
#[cfg(feature = "cli")]
pub use crate::cli::shell::Shell;
#[cfg(feature = "cli")]
pub use crate::cli::shell::render as render_shell;

/// Encodes a cache envelope exactly as a cached read stores it, or `None` when
/// the value is already expired or the clock is unusable.
pub fn encode_cache_entry(
	project: &str,
	profile: &str,
	max_age_secs: u64,
	route_fingerprint: &str,
	value: &ProviderValue,
) -> Option<SecretBytes> {
	cache::encode_entry(
		project,
		profile,
		max_age_secs,
		route_fingerprint.to_string(),
		value,
	)
	.ok()
}

/// Decodes a stored envelope and reports whether a read would serve it: owned
/// by this project and profile, written for this route, and still fresh.
pub fn cache_entry_is_fresh(
	stored: &SecretBytes,
	project: &str,
	profile: &str,
	route_fingerprint: &str,
	max_age_secs: u64,
) -> bool {
	matches!(
		cache::inspect_entry(stored, project, profile, route_fingerprint, max_age_secs),
		Ok(CacheEntryStatus::Fresh { .. })
	)
}

#[cfg(test)]
mod tests {
	use super::cache_entry_is_fresh;
	use super::encode_cache_entry;
	use crate::ProviderValue;
	use crate::SecretBytes;

	fn value() -> ProviderValue {
		ProviderValue::new(SecretBytes::from_utf8("hunter2"), None)
	}

	#[test]
	fn fresh_entry_round_trips_through_the_wrappers() {
		let stored = encode_cache_entry("proj", "default", 600, "route-a", &value())
			.expect("a live value encodes");
		assert!(cache_entry_is_fresh(
			&stored, "proj", "default", "route-a", 600
		));
	}

	#[test]
	fn entry_for_another_route_or_owner_is_not_served() {
		let stored = encode_cache_entry("proj", "default", 600, "route-a", &value())
			.expect("a live value encodes");
		assert!(!cache_entry_is_fresh(
			&stored, "proj", "default", "route-b", 600
		));
		assert!(!cache_entry_is_fresh(
			&stored, "other", "default", "route-a", 600
		));
	}

	#[test]
	fn expired_value_does_not_encode() {
		let expired = ProviderValue::new(SecretBytes::from_utf8("stale"), Some(1_000));
		assert!(encode_cache_entry("proj", "default", 600, "route-a", &expired).is_none());
	}

	#[test]
	fn foreign_bytes_are_not_fresh() {
		let stored = SecretBytes::from_utf8("not a monosecret envelope");
		assert!(!cache_entry_is_fresh(
			&stored, "proj", "default", "route-a", 600
		));
	}
}
