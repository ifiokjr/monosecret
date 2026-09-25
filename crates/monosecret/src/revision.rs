//! Revision tokens derived solely from non-secret metadata (0.4.0+).

use monosecret_ipc::Revision;
use sha2::Digest;
use sha2::Sha256;

use crate::plan::PlannedSecret;

/// Every field, including the domain, is UTF-8 with an unsigned 64-bit
/// big-endian byte-length prefix. Output is `ssr1:` plus lowercase SHA-256 hex.
/// Callers must never pass secret bytes or credential-bearing configuration.
pub(crate) fn digest(domain: &str, fields: &[&str]) -> Revision {
	let mut hash = Sha256::new();
	for field in std::iter::once(domain).chain(fields.iter().copied()) {
		hash.update((field.len() as u64).to_be_bytes());
		hash.update(field.as_bytes());
	}
	// sha2 0.11's digest output is a generic-array wrapper without a
	// `LowerHex` impl, so render the bytes explicitly. The wire format is
	// unchanged: lowercase hex over 32 bytes.
	let digest = hash.finalize();
	let mut hex = String::with_capacity(64);
	for byte in &digest {
		use std::fmt::Write;
		let _ = write!(hex, "{byte:02x}");
	}
	Revision::new(format!("ssr1:{hex}")).expect("a digest is a valid revision")
}

pub(crate) fn effective(revision: Option<&Revision>, planned: &PlannedSecret) -> Option<Revision> {
	let revision = revision?;
	let extract = planned.extract();
	Some(digest(
		"monosecret.logical.v1",
		&[
			revision.as_str(),
			extract.map_or("", |e| e.format.as_str()),
			extract.map_or("", |e| e.pointer.as_str()),
			planned.encoding().map_or("", |e| e.as_str()),
		],
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn revision_encoding_has_a_cross_client_test_vector() {
		assert_eq!(
			digest(
				"monosecret.awssm.v1",
				&[
					"arn:aws:secretsmanager:us-east-1:123:secret:db-abcdef",
					"generation-1",
				]
			)
			.as_str(),
			"ssr1:6f16c425c474a408deae1e06436bb93dda2a59666679e87d628a85d3c9034722"
		);
		assert_ne!(digest("test", &["ab", "c"]), digest("test", &["a", "bc"]));
		assert_ne!(digest("test", &["a"]), digest("other", &["a"]));
	}
}
