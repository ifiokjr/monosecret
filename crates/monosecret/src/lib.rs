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
mod audit;
mod cache;
mod caller;
pub mod codegen;
mod compiled_spec;
mod composition;
mod config;
mod error;
pub(crate) mod generator;
pub(crate) mod ini_field;
pub(crate) mod json_field;
mod manifest;
mod native;
mod plan;
mod report;
mod resolve;
mod revision;
mod secret_value;
mod secrets;
#[cfg(feature = "cli")]
mod serve;
mod spec;
mod spec_edit;
mod validation;
/// Windows ACL helpers. Public only so the IPC conformance harness can build a
/// directory the endpoint trust checks accept; not part of the stable API.
#[cfg(windows)]
#[doc(hidden)]
pub mod windows_security;

pub(crate) mod provider;

// CLI module (feature-gated)
#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod integration;

pub use caller::CallerContext;
pub use config::Resolved;
pub use secret_value::SecretBytes;

/// Implementation details shared with `monosecret_derive`.
///
/// These document types are not part of the supported Rust SDK. Use [`Spec`]
/// and its builder API instead.
#[doc(hidden)]
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

// Re-export only the types needed by users and generated code
pub use config::NativeAddress;
pub use config::ProjectDefaults;
pub use config::ProviderConfig;
pub use config::ProviderConfigStructured;
pub use config::ProviderDependency;
pub use config::ProviderRef;
pub use config::ProviderRefDetail;
pub use config::SecretRequest;
// Re-export config types for CLI usage only - these are marked #[doc(hidden)]
#[doc(hidden)]
pub use config::{AuditConfig, Config, GlobalConfig, GlobalDefaults, ProfileDefaults, Project};
// Public API exports
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
pub use config::{GenerateConfig, GenerateOptions};
pub use error::MonosecretError;
pub use error::Result;
pub use manifest::Manifest;
pub use manifest::ManifestProfile;
pub use manifest::ManifestProject;
pub use manifest::ManifestSecret;
pub use monosecret_ipc::Revision;
pub use native::INLINE_SPEC_SCHEMA_VERSION;
pub use native::MIN_INLINE_SPEC_SCHEMA_VERSION;
pub use native::NATIVE_CALL_REQUEST_VERSION;
pub use native::call_json;
pub use provider::Address;
pub use provider::DiscoveryContext;
pub use provider::ProducedValuePersistence;
pub use provider::Provider;
pub use provider::ProviderValue;
pub use provider::external::BASE_ENDPOINT_ENVIRONMENT;
pub use provider::external::EndpointSecurity;
pub use provider::external::ExternalProvider;
pub use provider::external::PlatformEndpointSecurity;
pub use provider::external::ProviderCredentialBroker;
pub use provider::external::ProviderCredentialPrincipal;
pub use provider::external::ProviderCredentialRequest;
pub use provider::external::ProviderDiscovery;
pub use provider::external::ProviderEndpoint;
pub use provider::external::RegistrationScope;
pub use provider::external::set_provider_discovery;
pub use report::RESOLUTION_REPORT_SCHEMA_VERSION;
pub use report::ResolutionReport;
pub use report::ResolutionStatus;
pub use report::SecretResolution;
pub use resolve::NamedResolution;
pub use resolve::RESOLVE_SCHEMA_VERSION;
pub use resolve::ResolveResponse;
pub use resolve::ResolvedSecret;
pub use resolve::ResolvedSource;
pub use resolve::resolve_json;
pub use secrets::ExportFormat;
pub use secrets::Secrets;
pub use spec::Generation;
pub use spec::PasswordCharset;
pub use spec::Profile;
pub use spec::Secret;
pub use spec::Spec;
pub use spec::SpecBuilder;
pub use validation::ConstraintKind;
pub use validation::ConstraintViolation;
pub use validation::ValidatedSecrets;
pub use validation::ValidationErrors;

#[cfg(test)]
mod tests;
