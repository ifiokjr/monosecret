//! Shared HTTP client configuration for providers that call a REST API.

use std::time::Duration;

/// How long establishing a connection, TLS included, may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may take from sending to its last response byte.
///
/// Without a bound a stalled connection, or a proxy that accepts and never
/// answers, hangs `monosecret run` forever, and retry logic that acts on a
/// timeout can never fire.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// A client builder with Monosecret's connection and request timeouts applied.
///
/// Redirects are refused for every provider. Each provider talks to one
/// endpoint pinned by configuration, and reqwest only strips `Authorization`
/// and `Cookie` on cross-host redirects — custom headers such as
/// `X-Vault-Token` or `X-Auth-Token`, and request bodies replayed across
/// 307/308, reach whatever host a response names. A provider endpoint that
/// answers with a redirect is a misconfiguration or an attacker, so it must
/// surface as an error instead of being followed.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
	reqwest::Client::builder()
		.connect_timeout(CONNECT_TIMEOUT)
		.timeout(REQUEST_TIMEOUT)
		.redirect(reqwest::redirect::Policy::none())
}

/// A client with Monosecret's timeouts and reqwest's other defaults.
#[cfg(any(feature = "infisical", feature = "openbao", feature = "vault"))]
pub(crate) fn default_client() -> reqwest::Client {
	client_builder()
		.build()
		.expect("building an HTTP client without custom TLS settings")
}

/// Asserts that `client` was built by [`client_builder`].
///
/// reqwest exposes no accessor for its timeouts, so this reads them from the
/// client's `Debug` form.
#[cfg(test)]
pub(crate) fn assert_bounded(client: &reqwest::Client) {
	let debug = format!("{client:?}");
	assert!(
		debug.contains(&format!("{REQUEST_TIMEOUT:?}")),
		"client has no request timeout: {debug}"
	);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn builder_bounds_connect_and_request_time() {
		let builder = format!("{:?}", client_builder());
		assert!(
			builder.contains(&format!("connect_timeout: {CONNECT_TIMEOUT:?}")),
			"{builder}"
		);
		assert_bounded(&client_builder().build().unwrap());
	}

	#[test]
	fn builder_refuses_redirects() {
		let builder = format!("{:?}", client_builder());
		assert!(
			builder.contains("redirect_policy: Policy(None)"),
			"providers must never follow redirects: {builder}"
		);
	}
}
