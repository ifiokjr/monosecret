//! The shared synchronous compatibility boundary for native async backends.
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;

use super::Address;
use super::AsyncProvider;
use super::BatchReadRequest;
use super::DiscoveryContext;
use super::ProducedValuePersistence;
use super::Provider;
use super::ProviderCredentials;
use super::ProviderValue;
use super::ReadMode;
use crate::MonosecretError;
use crate::NativeAddress;
use crate::Result;
use crate::SecretBytes;

/// Exposes an async backend through the existing synchronous provider API (0.22+).
///
/// All storage operations run through the shared provider runtime. Configuration,
/// planning, and identity hooks are forwarded without starting backend I/O.
/// Async callers can borrow `as_async()` to bypass the blocking boundary.
pub struct SyncProviderAdapter<P> {
	inner: P,
}

impl<P> SyncProviderAdapter<P> {
	pub fn from_async(provider: P) -> Self {
		Self { inner: provider }
	}

	pub fn as_async(&self) -> &P {
		&self.inner
	}

	pub fn into_async(self) -> P {
		self.inner
	}
}

impl<P> std::ops::Deref for SyncProviderAdapter<P> {
	type Target = P;

	fn deref(&self) -> &P {
		&self.inner
	}
}
impl<P> std::ops::DerefMut for SyncProviderAdapter<P> {
	fn deref_mut(&mut self) -> &mut P {
		&mut self.inner
	}
}

impl<P: AsyncProvider> SyncProviderAdapter<P> {
	fn prepare_capabilities(&self) {
		if self.inner.requires_initialization() {
			let _ = super::block_on(self.inner.initialize());
		}
	}
}

impl<P: AsyncProvider> Provider for SyncProviderAdapter<P> {
	fn set_retry_policy(&mut self, policy: super::RetryPolicy) {
		super::ProviderBase::set_retry_policy(&mut self.inner, policy);
	}

	fn retry_ownership(&self) -> super::RetryOwnership {
		super::ProviderBase::retry_ownership(&self.inner)
	}

	fn retry_safe(&self, operation: super::RetryOperation, addr: Address<'_>) -> bool {
		super::ProviderBase::retry_safe(&self.inner, operation, addr)
	}

	fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
		super::block_on(AsyncProvider::resolve_address(
			&self.inner,
			Address::convention(project, profile, key),
		))
		.map(Cow::into_owned)
	}

	fn supported_coords(&self) -> &'static [&'static str] {
		super::ProviderBase::supported_coords(&self.inner)
	}

	fn supports_coord(&self, name: &str) -> bool {
		self.prepare_capabilities();
		super::ProviderBase::supports_coord(&self.inner, name)
	}

	fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
		super::block_on(AsyncProvider::resolve_address(&self.inner, addr))
	}

	fn configured_entry_coordinates<'a>(
		&self,
		addr: Address<'a>,
	) -> Result<Cow<'a, NativeAddress>> {
		super::ProviderBase::configured_entry_coordinates(&self.inner, addr)
	}

	fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
		super::block_on(AsyncProvider::entry_coordinates(&self.inner, addr))
	}

	fn entry_coordinates_many(&self, addrs: &[Address<'_>]) -> Result<Vec<NativeAddress>> {
		super::block_on(AsyncProvider::entry_coordinates_many(&self.inner, addrs))
	}

	fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
		super::block_on(AsyncProvider::get(&self.inner, addr))
	}

	fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
		super::block_on(AsyncProvider::get_with_metadata(&self.inner, addr))
	}

	fn get_with_mode(&self, addr: Address<'_>, mode: ReadMode) -> Result<Option<ProviderValue>> {
		super::block_on(AsyncProvider::get_with_mode(&self.inner, addr, mode))
	}

	fn supports_read(&self) -> bool {
		self.prepare_capabilities();
		super::ProviderBase::supports_read(&self.inner)
	}

	fn exists(&self, addr: Address<'_>) -> Result<bool> {
		super::block_on(AsyncProvider::exists(&self.inner, addr))
	}

	fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
		super::block_on(AsyncProvider::set(&self.inner, addr, value))
	}

	fn set_expiring(
		&self,
		addr: Address<'_>,
		value: &SecretBytes,
		max_age: std::time::Duration,
	) -> Result<()> {
		super::block_on(AsyncProvider::set_expiring(
			&self.inner,
			addr,
			value,
			max_age,
		))
	}

	fn delete(&self, addr: Address<'_>) -> Result<bool> {
		super::block_on(AsyncProvider::delete(&self.inner, addr))
	}

	fn supports_delete(&self) -> bool {
		self.prepare_capabilities();
		super::ProviderBase::supports_delete(&self.inner)
	}

	fn deletion_unsupported(&self) -> MonosecretError {
		super::ProviderBase::deletion_unsupported(&self.inner)
	}

	fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
		super::block_on(AsyncProvider::check_deletable(&self.inner, addr))
	}

	fn check_writable(&self, addr: Address<'_>) -> Result<()> {
		super::block_on(AsyncProvider::check_writable(&self.inner, addr))
	}

	fn generated_value_persistence(&self) -> ProducedValuePersistence {
		self.prepare_capabilities();
		super::ProviderBase::generated_value_persistence(&self.inner)
	}

	fn prompted_value_persistence(&self) -> ProducedValuePersistence {
		self.prepare_capabilities();
		super::ProviderBase::prompted_value_persistence(&self.inner)
	}

	fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
		super::block_on(AsyncProvider::write_target(&self.inner, addr))
	}

	fn auth_scope_key(&self) -> Option<String> {
		super::ProviderBase::auth_scope_key(&self.inner)
	}

	fn name(&self) -> &str {
		super::ProviderBase::name(&self.inner)
	}

	fn uri(&self) -> String {
		super::ProviderBase::uri(&self.inner)
	}

	fn storage_identity(&self) -> String {
		super::ProviderBase::storage_identity(&self.inner)
	}

	fn entry_container_identity(&self) -> String {
		super::ProviderBase::entry_container_identity(&self.inner)
	}

	fn physical_store_path(&self) -> Option<&std::path::Path> {
		self.prepare_capabilities();
		super::ProviderBase::physical_store_path(&self.inner)
	}

	fn configured_physical_store_path(&self) -> Option<&std::path::Path> {
		super::ProviderBase::configured_physical_store_path(&self.inner)
	}

	fn set_reason(&self, reason: Option<String>) {
		super::ProviderBase::set_reason(&self.inner, reason);
	}

	fn set_requested_authorization_duration(&self, duration: Option<std::time::Duration>) {
		super::ProviderBase::set_requested_authorization_duration(&self.inner, duration);
	}

	fn set_caller(&self, caller: Option<crate::CallerContext>) {
		super::ProviderBase::set_caller(&self.inner, caller);
	}

	fn set_project(&self, project: &str) {
		super::ProviderBase::set_project(&self.inner, project);
	}

	fn set_profile(&self, profile: &str) {
		super::ProviderBase::set_profile(&self.inner, profile);
	}

	fn with_base_dir(&mut self, base_dir: &std::path::Path) {
		super::ProviderBase::with_base_dir(&mut self.inner, base_dir);
	}

	fn with_credentials(&mut self, credentials: ProviderCredentials) {
		super::ProviderBase::with_credentials(&mut self.inner, credentials);
	}

	fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
		super::block_on(AsyncProvider::reflect(&self.inner, context))
	}

	fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
		super::block_on(AsyncProvider::get_many(&self.inner, requests))
	}

	fn get_many_with_metadata(
		&self,
		requests: &[(&str, Address<'_>)],
	) -> Result<HashMap<String, ProviderValue>> {
		super::block_on(AsyncProvider::get_many_with_metadata(&self.inner, requests))
	}

	fn get_many_with_modes(
		&self,
		requests: &[BatchReadRequest<'_>],
	) -> Result<HashMap<String, ProviderValue>> {
		super::block_on(AsyncProvider::get_many_with_modes(&self.inner, requests))
	}

	fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
		super::block_on(AsyncProvider::exists_many(&self.inner, requests))
	}
}

#[cfg(test)]
mod tests {
	use std::path::Path;
	use std::path::PathBuf;
	use std::sync::Mutex;

	use super::*;
	use crate::provider::ProviderBase;
	use crate::provider::RetryPolicy;

	#[derive(Default)]
	struct ConfiguredBackend {
		credentials: ProviderCredentials,
		base: PathBuf,
		policy: RetryPolicy,
		context: Mutex<(Option<String>, String, String)>,
	}

	impl ProviderBase for ConfiguredBackend {
		fn name(&self) -> &'static str {
			"configured"
		}

		fn uri(&self) -> String {
			"configured://account".into()
		}

		fn storage_identity(&self) -> String {
			"shared-store".into()
		}

		fn entry_container_identity(&self) -> String {
			"shared-container".into()
		}

		fn with_credentials(&mut self, credentials: ProviderCredentials) {
			self.credentials = credentials;
		}

		fn with_base_dir(&mut self, base: &Path) {
			self.base = base.into();
		}

		fn set_retry_policy(&mut self, policy: RetryPolicy) {
			self.policy = policy;
		}

		fn set_reason(&self, reason: Option<String>) {
			self.context.lock().unwrap().0 = reason;
		}

		fn set_project(&self, project: &str) {
			self.context.lock().unwrap().1 = project.into();
		}

		fn set_profile(&self, profile: &str) {
			self.context.lock().unwrap().2 = profile.into();
		}

		fn configured_physical_store_path(&self) -> Option<&Path> {
			Some(&self.base)
		}
	}

	#[async_trait::async_trait]
	impl AsyncProvider for ConfiguredBackend {
		async fn get(&self, _addr: Address<'_>) -> Result<Option<SecretBytes>> {
			assert_eq!(self.policy.max_attempts(), 2);
			assert_eq!(
				*self.context.lock().unwrap(),
				(Some("deployment".into()), "app".into(), "prod".into())
			);
			assert!(self.base.is_absolute());
			Ok(self.credentials.get("token").cloned())
		}

		async fn set(&self, _addr: Address<'_>, _value: &SecretBytes) -> Result<()> {
			unreachable!()
		}
	}

	#[test]
	fn forwards_configuration_before_backend_io_and_keeps_planning_pure() {
		let mut provider = SyncProviderAdapter::from_async(ConfiguredBackend::default());
		let base = tempfile::tempdir().unwrap();
		// Identity and planning must work before credentials or session context
		// have been configured. Starting a read here would fail its assertions.
		assert_eq!(provider.storage_identity(), "shared-store");
		assert_eq!(provider.entry_container_identity(), "shared-container");
		let addr = NativeAddress {
			item: "token".into(),
			..Default::default()
		};
		assert_eq!(
			provider
				.configured_entry_coordinates(Address::Native(&addr))
				.unwrap()
				.as_ref(),
			&addr
		);
		provider.with_base_dir(base.path());
		assert_eq!(provider.configured_physical_store_path(), Some(base.path()));
		provider.with_credentials(ProviderCredentials::from([(
			"token".into(),
			"credential".into(),
		)]));
		provider.set_retry_policy(RetryPolicy::new(2).unwrap());
		provider.set_reason(Some("deployment".into()));
		provider.set_project("app");
		provider.set_profile("prod");
		assert_eq!(
			provider
				.get(Address::Native(&addr))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"credential"
		);
	}
}
