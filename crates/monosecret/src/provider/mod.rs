//! # Provider System
//!
//! The provider module implements a trait-based plugin architecture for managing secrets
//! across different storage backends. Providers handle the actual storage and retrieval
//! of secrets, supporting everything from local files to cloud-based secret managers.
//!
//! ## Architecture
//!
//! The provider system is built around the [`Provider`] trait, which defines a common
//! interface for all storage backends. Each provider implementation handles:
//!
//! - Profile-aware storage (e.g., development vs production secrets)
//! - Project isolation (secrets are namespaced by project)
//! - Optional write support (some providers are read-only)
//!
//! ## Available Providers
//!
//! - [`keyring::KeyringProvider`]: System keyring integration (default)
//! - [`kdbx::KdbxProvider`]: `KeePass` KDBX database integration (0.17+)
//! - [`keeper::KeeperProvider`]: Keeper Secrets Manager integration (0.18+)
//! - [`dotenv::DotEnvProvider`]: `.env` file support
//! - [`env::EnvProvider`]: Environment variables (read-only)
//! - [`ejson::EjsonProvider`]: EJSON encrypted files (0.20+)
//! - [`null::NullProvider`]: Defaults, generation, or run prompts without storage (0.19+)
//! - [`file::FileProvider`]: Plaintext file-per-secret storage (0.19+)
//! - [`fly::FlyProvider`]: Fly.io application secrets, write-only (0.20+)
//! - [`cloudflare::CloudflareProvider`]: Cloudflare Secrets Store, write-only (0.20+)
//! - [`pass::PassProvider`]: Pass integration
//! - [`gopass::GoPassProvider`]: Gopass integration
//! - [`systemd_credential::SystemdCredentialProvider`]: systemd service credentials (0.17+)
//! - [`protonpass::ProtonPassProvider`]: Proton Pass integration
//! - [`passbolt::PassboltProvider`]: Passbolt integration through go-passbolt-cli (0.19+)
//! - [`onepassword::OnePasswordProvider`]: 1Password integration
//! - [`onepassword_env::OnePasswordEnvProvider`]: 1Password Environments integration (fork)
//! - [`lastpass::LastPassProvider`]: `LastPass` integration
//! - [`dashlane::DashlaneProvider`]: Dashlane integration, read-only (0.18+)
//! - [`gcsm::GcsmProvider`]: Google Cloud Secret Manager integration
//! - [`awssm::AwssmProvider`]: AWS Secrets Manager integration
//! - [`awsps::AwspsProvider`]: AWS Systems Manager Parameter Store integration (0.18+)
//! - [`vault::VaultProvider`]: `HashiCorp` Vault integration
//! - [`openbao::OpenBaoProvider`]: `OpenBao` integration (0.17+)
//! - [`bws::BwsProvider`]: Bitwarden Secrets Manager integration
//! - [`akv::AkvProvider`]: Azure Key Vault integration
//! - [`aac::AacProvider`]: Azure App Configuration integration (0.20+)
//! - [`infisical::InfisicalProvider`]: Infisical integration (0.16+)
//! - [`bw::BitwardenProvider`]: Bitwarden Password Manager (0.18+)
//! - [`sops::SopsProvider`]: SOPS-encrypted file integration (0.17+)
//! - [`kubernetes::KubernetesProvider`]: Kubernetes integration (0.20+)
//!
//! ## URI-Based Configuration
//!
//! Providers support URI-based configuration for flexibility:
//!
//! ```text
//! keyring://
//! dotenv://.env.production
//! null://  # Use defaults, generation, or run prompts without storage, 0.19+
//! file:./.secrets  # One plaintext file per secret, 0.19+
//! onepassword://vault
//! lastpass://folder
//! keeper://SHARED_FOLDER_UID  # Keeper, 0.18+
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use monosecret::provider::{Address, Provider};
//! use std::convert::TryFrom;
//!
//! // Create a provider from a URI string
//! let provider = Box::<dyn Provider>::try_from("keyring://")?;
//!
//! let addr = Address::convention("myproject", "production", "API_KEY");
//!
//! // Store a secret
//! provider.set(addr, &"secret123".to_string().into())?;
//!
//! // Retrieve a secret
//! if let Some(value) = provider.get(addr)? {
//!     println!("API_KEY retrieved");
//! }
//! ```

mod address;
mod catalog;
mod credentials;
// Every item inside is cfg-gated out in an all-features build.
#[allow(unused_imports, unused_macros)]
mod disabled;
mod factory;
#[macro_use]
pub mod macros;
mod path;
mod preflight;
mod registry;
mod runtime;
mod traits;
mod url;

// Public provider API.
pub use address::Address;
// Shared implementation support used by provider backends and orchestration.
pub(crate) use address::{OwnedAddress, flat_item};
pub(crate) use credentials::ProviderCredentials;
pub(crate) use credentials::credential_or_env;
pub(crate) use credentials::credential_or_envs;
#[cfg(any(
	feature = "cloudflare",
	feature = "openbao",
	feature = "scaleway",
	feature = "vault"
))]
pub(crate) use credentials::preferred_env;
pub(crate) use factory::provider_from_spec;
#[cfg(test)]
pub(crate) use factory::provider_from_url;
pub use macros::PROVIDER_REGISTRY;
pub use macros::ProviderMetadata;
pub use macros::ProviderRegistration;
pub use macros::declared_flag;
pub use macros::declared_read_capability;
#[cfg(any(feature = "awssm", feature = "infisical", feature = "scaleway", test))]
#[cfg(any(feature = "awssm", feature = "infisical", feature = "scaleway", test))]
pub(crate) use path::join_slash_path;
pub(crate) use preflight::ProviderWithPreflight;
pub use registry::ProviderInfo;
pub(crate) use registry::credential_names_for_spec;
pub(crate) use registry::deleting_provider_names;
pub(crate) use registry::provider_display_name_for_spec;
#[cfg(feature = "cli")]
pub use registry::providers;
pub(crate) use registry::spec_names_known_provider;
pub(crate) use registry::spec_provider_deletes;
#[cfg(any(feature = "cli", test))]
pub(crate) use registry::spec_provider_reads;
#[cfg(any(
	feature = "akv",
	feature = "awsps",
	feature = "awssm",
	feature = "cloudflare",
	feature = "gcsm",
	feature = "infisical",
	feature = "scaleway"
))]
pub(crate) use runtime::block_on;
pub(crate) use runtime::write_child_stdin;
pub use traits::DiscoveryContext;
#[cfg(test)]
pub(crate) use traits::GET_EACH_CONCURRENCY_ENV;
pub use traits::ProducedValuePersistence;
pub use traits::Provider;
#[cfg(test)]
pub(crate) use traits::get_each;
pub(crate) use traits::get_each_concurrency;
#[cfg(any(feature = "infisical", feature = "openbao", feature = "vault"))]
pub(crate) use traits::get_each_with;
pub(crate) use traits::map_concurrently;
pub(crate) use traits::same_storage_container;
pub(crate) use url::ProviderUrl;
pub(crate) use url::URI_ENCODE_SET;

// Provider implementations.
#[cfg(feature = "aac")]
pub mod aac;
#[cfg(feature = "age")]
pub mod age;
#[cfg(feature = "akv")]
pub mod akv;
#[cfg(feature = "awsps")]
pub mod awsps;
#[cfg(feature = "awssm")]
pub mod awssm;
#[cfg(feature = "bw")]
pub mod bw;
#[cfg(feature = "bws")]
pub mod bws;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
pub mod dashlane;
pub mod dotenv;
#[cfg(feature = "ejson")]
pub mod ejson;
pub mod env;
pub mod file;
pub mod fly;
#[cfg(feature = "gcsm")]
pub mod gcsm;
pub mod gopass;
#[cfg(feature = "infisical")]
pub mod infisical;
#[cfg(feature = "kdbx")]
pub mod kdbx;
#[cfg(feature = "keeper")]
pub mod keeper;
#[cfg(feature = "keyring")]
pub mod keyring;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
pub mod lastpass;
pub mod null;
pub mod onepassword;
pub mod onepassword_env;
#[cfg(feature = "openbao")]
pub mod openbao;
pub mod pass;
pub mod passbolt;
pub mod protonpass;
#[cfg(feature = "scaleway")]
pub mod scaleway;
#[cfg(feature = "sops")]
pub mod sops;
pub mod systemd_credential;
#[cfg(feature = "vault")]
pub mod vault;
#[cfg(any(feature = "openbao", feature = "vault"))]
mod vault_common;

#[cfg(test)]
pub(crate) mod tests;
