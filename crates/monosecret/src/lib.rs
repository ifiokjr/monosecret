//! Monosecret - A declarative secrets manager for development workflows
//!
//! This library provides a type-safe, declarative way to manage secrets and environment
//! variables across different environments and storage backends.
//!
//! # Features
//!
//! - **Declarative Configuration**: Define secrets in `monosecret.toml`
//! - **Rust-first Declarations**: Build a [`Spec`] directly in Rust (0.20+)
//! - **Multiple Providers**: Keyring, dotenv, environment variables, Keeper Secrets Manager (0.18+)
//! - **Profile Support**: Different configurations for development, staging, production
//! - **Type Safety**: Optional compile-time code generation for strongly-typed access
//! - **Validation**: Ensure all required secrets are present before running applications
//!
//! # Example
//!
//! ```ignore
//! // Generate typed structs from monosecret.toml
//! monosecret_derive::declare_secrets!("monosecret.toml");
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load secrets and configure provider/profile
//!     let mut spec = Secrets::load()?;
//!     spec.set_provider("keyring");  // Can use provider name or URI like "dotenv:/path/to/.env"
//!     spec.set_profile("development");
//!
//!     // Validate and get secrets
//!     let secrets = match spec.validate()? {
//!         Ok(validated) => validated,
//!         Err(errors) => return Err(format!("Missing secrets: {}", errors).into()),
//!     };
//!
//!     // Access secrets (field names are lowercased)
//!     println!("Database: {}", secrets.resolved.secrets.get("DATABASE_URL").unwrap());
//!
//!     // Access profile and provider information
//!     println!("Using profile: {}", secrets.resolved.profile);
//!     println!("Using provider: {}", secrets.resolved.provider);
//!
//!     Ok(())
//! }
//! ```

// Internal modules
#[cfg(feature = "runtime")]
mod audit;
/// Doorway for `benches/` into crate-private hot paths. Not a stable API.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench_support;
#[cfg(feature = "runtime")]
mod cache;
#[cfg(feature = "runtime")]
mod caller;
#[cfg(feature = "runtime")]
pub mod codegen;
#[cfg(feature = "runtime")]
mod compiled_spec;
#[cfg(feature = "runtime")]
mod composition;
#[cfg(feature = "runtime")]
mod config;
#[cfg(feature = "runtime")]
mod error;
#[cfg(all(test, unix))]
#[cfg(feature = "runtime")]
pub(crate) mod fake_executable;
#[cfg(feature = "runtime")]
pub(crate) mod generator;
#[cfg(feature = "runtime")]
pub(crate) mod ini_field;
#[cfg(feature = "runtime")]
pub(crate) mod json_field;
#[cfg(feature = "runtime")]
mod manifest;
#[cfg(feature = "runtime")]
mod native;
#[cfg(feature = "runtime")]
mod plan;
#[cfg(feature = "runtime")]
mod report;
#[cfg(feature = "runtime")]
mod resolve;

#[cfg(feature = "runtime")]
mod revision;
#[cfg(feature = "runtime")]
mod secret_value;
#[cfg(feature = "runtime")]
mod secrets;
#[cfg(feature = "cli")]
#[cfg(feature = "runtime")]
mod serve;
#[cfg(feature = "runtime")]
mod spec;
#[cfg(feature = "runtime")]
mod spec_edit;
#[cfg(feature = "runtime")]
pub(crate) mod typed;
#[cfg(feature = "runtime")]
mod validation;
/// Windows ACL helpers. Public only so the IPC conformance harness can build a
/// directory the endpoint trust checks accept; not part of the stable API.
#[cfg(windows)]
#[doc(hidden)]
#[cfg(feature = "runtime")]
pub mod windows_security;
#[cfg(feature = "runtime")]
mod x509_identity;

#[cfg(feature = "runtime")]
pub(crate) mod provider;

// CLI module (feature-gated)
#[cfg(feature = "cli")]
#[cfg(feature = "runtime")]
pub mod cli;

#[cfg(feature = "cli")]
#[doc(hidden)]
#[cfg(feature = "runtime")]
pub mod integration;

#[cfg(feature = "runtime")]
pub use caller::CallerContext;
#[cfg(feature = "runtime")]
pub use config::Resolved;
#[cfg(feature = "runtime")]
pub use secret_value::SecretBytes;

/// Implementation details shared with `monosecret_derive`.
///
/// These document types are not part of the supported Rust SDK. Use [`Spec`]
/// and its builder API instead.
#[doc(hidden)]
#[cfg(feature = "runtime")]
pub mod __private {
	// Generated code uses these re-exports so applications do not need to
	// depend on the implementation crates just to compile the macro output.
	pub use ::secrecy;
	pub use ::serde;

	pub mod codegen {
		pub use crate::codegen::CodegenIr;
		pub use crate::codegen::IrField;
		pub use crate::codegen::IrProfile;
		pub use crate::codegen::build_ir;
		pub use crate::codegen::capitalize;
	}

	pub use crate::config::Config;
	pub use crate::config::GenerateConfig;
	pub use crate::config::GenerateOptions;
	pub use crate::config::Profile;
	pub use crate::config::ProfileDefaults;
	pub use crate::config::Project;
	pub use crate::config::ProjectDefaults;
	pub use crate::config::Secret;
	pub use crate::spec::load_for_codegen;
}

// Public API exports
#[cfg(feature = "runtime")]
pub use config::CredentialBinding;
#[cfg(feature = "runtime")]
pub use config::NativeAddress;
#[cfg(feature = "runtime")]
pub use config::ProjectDefaults;
#[cfg(feature = "runtime")]
pub use config::ProviderConfig;
#[cfg(feature = "runtime")]
pub use config::ProviderConfigStructured;
#[cfg(feature = "runtime")]
pub use config::ProviderDependency;
#[cfg(feature = "runtime")]
pub use config::ProviderRef;
#[cfg(feature = "runtime")]
pub use config::ProviderRefDetail;
#[cfg(feature = "runtime")]
pub use config::SecretRequest;
// Re-export config types for CLI usage only - these are marked #[doc(hidden)]
#[doc(hidden)]
#[cfg(feature = "runtime")]
pub use config::{AuditConfig, Config, GlobalConfig, GlobalDefaults, ProfileDefaults, Project};
// Public API exports
#[cfg(feature = "runtime")]
pub use config::{
	CredentialSource,
	ExtractFormat,
	NativeAddressTemplate,
	ProviderAlias,
	ProviderCache,
	RequireReason,
	SecretEncoding,
	SecretExtract,
};
// Re-export Secret and generation types for monosecret-derive
// (ExtractFormat/SecretEncoding/SecretExtract live in the public API group below.)
#[doc(hidden)]
#[cfg(feature = "runtime")]
pub use config::{GenerateConfig, GenerateOptions};
#[cfg(feature = "runtime")]
pub use error::MonosecretError;
#[cfg(feature = "runtime")]
pub use error::Result;
#[cfg(feature = "runtime")]
pub use manifest::Manifest;
#[cfg(feature = "runtime")]
pub use manifest::ManifestProfile;
#[cfg(feature = "runtime")]
pub use manifest::ManifestProject;
#[cfg(feature = "runtime")]
pub use manifest::ManifestSecret;
#[cfg(feature = "runtime")]
pub use monosecret_rpc::Revision;
#[cfg(feature = "runtime")]
pub use native::INLINE_SPEC_SCHEMA_VERSION;
#[cfg(feature = "runtime")]
pub use native::MIN_INLINE_SPEC_SCHEMA_VERSION;
#[cfg(feature = "runtime")]
pub use native::NATIVE_CALL_REQUEST_VERSION;
#[cfg(feature = "runtime")]
pub use native::call_json;
#[cfg(feature = "runtime")]
pub use provider::Address;
#[cfg(feature = "runtime")]
pub use provider::DiscoveryContext;
#[cfg(feature = "runtime")]
pub use provider::ProducedValuePersistence;
#[cfg(feature = "runtime")]
pub use provider::Provider;
#[cfg(feature = "runtime")]
pub use provider::ProviderInfo;
#[cfg(feature = "runtime")]
pub use provider::ProviderValue;
#[cfg(feature = "runtime")]
pub use provider::RetryPolicy;
#[cfg(feature = "runtime")]
pub use provider::external::BASE_ENDPOINT_ENVIRONMENT;
#[cfg(feature = "runtime")]
pub use provider::external::EndpointSecurity;
#[cfg(feature = "runtime")]
pub use provider::external::ExternalProvider;
#[cfg(feature = "runtime")]
pub use provider::external::PlatformEndpointSecurity;
#[cfg(feature = "runtime")]
pub use provider::external::ProviderCredentialBroker;
#[cfg(feature = "runtime")]
pub use provider::external::ProviderCredentialPrincipal;
#[cfg(feature = "runtime")]
pub use provider::external::ProviderCredentialRequest;
#[cfg(feature = "runtime")]
pub use provider::external::ProviderDiscovery;
#[cfg(feature = "runtime")]
pub use provider::external::ProviderEndpoint;
#[cfg(feature = "runtime")]
pub use provider::external::RegistrationScope;
#[cfg(feature = "runtime")]
pub use provider::external::set_provider_discovery;
#[cfg(feature = "runtime")]
pub use provider::providers;
#[cfg(feature = "runtime")]
pub use report::Derivation;
#[cfg(feature = "runtime")]
pub use report::RESOLUTION_REPORT_SCHEMA_VERSION;
#[cfg(feature = "runtime")]
pub use report::ResolutionReport;
#[cfg(feature = "runtime")]
pub use report::ResolutionStatus;
#[cfg(feature = "runtime")]
pub use report::SecretResolution;
#[cfg(feature = "runtime")]
pub use resolve::NamedResolution;
#[cfg(feature = "runtime")]
pub use resolve::RESOLVE_SCHEMA_VERSION;
#[cfg(feature = "runtime")]
pub use resolve::ResolveResponse;
#[cfg(feature = "runtime")]
pub use resolve::ResolvedSecret;
#[cfg(feature = "runtime")]
pub use resolve::ResolvedSource;
#[cfg(feature = "runtime")]
pub use resolve::resolve_json;
#[cfg(feature = "runtime")]
pub use secrets::ExportFormat;
#[cfg(feature = "runtime")]
pub use secrets::Secrets;
#[cfg(feature = "runtime")]
pub use spec::Generation;
#[cfg(feature = "runtime")]
pub use spec::JwkKeyAlgorithm;
#[cfg(feature = "runtime")]
pub use spec::MnemonicAlgorithm;
#[cfg(feature = "runtime")]
pub use spec::MnemonicLanguage;
#[cfg(feature = "runtime")]
pub use spec::OpenPgpAlgorithm;
#[cfg(feature = "runtime")]
pub use spec::OpenPgpCapability;
#[cfg(feature = "runtime")]
pub use spec::PasswordCharset;
#[cfg(feature = "runtime")]
pub use spec::Profile;
#[cfg(feature = "runtime")]
pub use spec::Secret;
#[cfg(feature = "runtime")]
pub use spec::Spec;
#[cfg(feature = "runtime")]
pub use spec::SpecBuilder;
#[cfg(feature = "runtime")]
pub use spec::SshKeyAlgorithm;
#[cfg(feature = "runtime")]
pub use spec::X509Usage;
#[cfg(feature = "runtime")]
pub use typed::Format;
#[cfg(feature = "runtime")]
pub use validation::ConstraintKind;
#[cfg(feature = "runtime")]
pub use validation::ConstraintViolation;
#[cfg(feature = "runtime")]
pub use validation::ValidatedSecrets;
#[cfg(feature = "runtime")]
pub use validation::ValidationErrors;

#[cfg(test)]
#[cfg(feature = "runtime")]
mod tests;
#[cfg(test)]
#[cfg(feature = "runtime")]
mod typed_tests;

/// Lightweight access to values resolved by Monosecret, on native and Wasm.
#[cfg(feature = "client")]
pub mod client;
