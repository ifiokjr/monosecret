use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use monosecret_ipc::client::CallbackHandler;
use monosecret_ipc::client::Client;
use monosecret_ipc::error::ErrorKind;
use monosecret_ipc::error::RpcError;
use monosecret_ipc::protocol::InitializeParams;
use monosecret_ipc::protocol::Limits;
use monosecret_ipc::protocol::PROTOCOL_VERSION;
use monosecret_ipc::protocol::PROVIDER_PROTOCOL;
use monosecret_ipc::protocol::Product;
use monosecret_ipc::protocol::callback::CredentialParams;
use monosecret_ipc::protocol::callback::CredentialResult;
use monosecret_ipc::protocol::callback::{self};
use monosecret_ipc::protocol::provider::Address;
use monosecret_ipc::protocol::provider::AddressParams;
use monosecret_ipc::protocol::provider::ApplicationContext;
use monosecret_ipc::protocol::provider::GetResult;
use monosecret_ipc::protocol::provider::InitializeApplication;
use monosecret_ipc::protocol::provider::InitializedApplication;
use monosecret_ipc::protocol::provider::Metadata;
use monosecret_ipc::protocol::provider::Persistence;
use monosecret_ipc::protocol::provider::ReflectParams;
use monosecret_ipc::protocol::provider::ReflectResult;
use monosecret_ipc::protocol::provider::ResolveAddressResult;
use monosecret_ipc::protocol::provider::SetParams;
use monosecret_ipc::protocol::provider::{self as wire};
use monosecret_ipc::provider::ProvidedSecret;
use monosecret_ipc::provider::ProviderHandler;
use monosecret_ipc::provider::SecretValue;
use monosecret_ipc::provider::request_credential;
use monosecret_ipc::provider::serve_provider;
use monosecret_ipc::server::RequestContext;
use monosecret_ipc::server::RpcResult;
use monosecret_ipc::server::ServerConfig;

#[derive(Default)]
struct MemoryProvider {
	values: Mutex<HashMap<String, String>>,
	initialized_credential: Arc<Mutex<Option<String>>>,
	write_credential: Arc<Mutex<Option<String>>>,
}

fn key(address: Address) -> String {
	match address {
		Address::Convention {
			project,
			profile,
			key,
		} => format!("{project}/{profile}/{key}"),
		Address::Native { coordinates } => coordinates.item,
	}
}

#[async_trait]
impl ProviderHandler for MemoryProvider {
	fn capabilities(&self) -> Vec<String> {
		wire::CAPABILITIES
			.iter()
			.map(|value| (*value).to_string())
			.collect()
	}

	async fn initialize(
		&self,
		context: &RequestContext,
		application: InitializeApplication,
	) -> RpcResult<Metadata> {
		let credential = request_credential(
			context,
			CredentialParams {
				name: "access_token".into(),
				scope: application.uri.clone(),
				required: false,
			},
		)
		.await?;
		*self.initialized_credential.lock().unwrap() =
			credential.map(|value| value.expose().to_string());
		Ok(Metadata {
			name: application.scheme.clone(),
			display_uri: format!("{}://memory", application.scheme),
			supported_coordinates: Vec::new(),
			generated_value_persistence: Persistence::Persist,
			prompted_value_persistence: Persistence::Ephemeral,
			storage_identity: format!("{}://memory", application.scheme),
			entry_container_identity: format!("{}://memory", application.scheme),
			physical_store_path: None,
		})
	}

	async fn resolve_address(
		&self,
		_context: RequestContext,
		address: Address,
	) -> RpcResult<ResolveAddressResult> {
		Ok(ResolveAddressResult {
			coordinates: wire::Coordinates {
				item: key(address),
				field: None,
				vault: None,
				section: None,
				version: None,
			},
		})
	}

	async fn get(
		&self,
		_context: RequestContext,
		address: Address,
	) -> RpcResult<Option<ProvidedSecret>> {
		Ok(self
			.values
			.lock()
			.unwrap()
			.get(&key(address))
			.cloned()
			.map(|value| {
				ProvidedSecret::new(value, None).with_revision(Some(
					monosecret_ipc::Revision::new("test:version-1".into()).unwrap(),
				))
			}))
	}

	async fn exists(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
		Ok(self.values.lock().unwrap().contains_key(&key(address)))
	}

	async fn set(
		&self,
		context: RequestContext,
		address: Address,
		value: SecretValue,
	) -> RpcResult<()> {
		let credential = request_credential(
			&context,
			CredentialParams {
				name: "access_token".into(),
				scope: "memory://default".into(),
				required: true,
			},
		)
		.await?;
		*self.write_credential.lock().unwrap() = credential.map(|value| value.expose().to_string());
		self.values
			.lock()
			.unwrap()
			.insert(key(address), value.expose().to_string());
		Ok(())
	}

	async fn delete(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
		Ok(self.values.lock().unwrap().remove(&key(address)).is_some())
	}

	async fn check_writable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
		Ok(())
	}

	async fn check_deletable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
		Ok(())
	}

	async fn describe_write_target(
		&self,
		_context: RequestContext,
		address: Address,
	) -> RpcResult<String> {
		Ok(format!("memory {}", key(address)))
	}

	async fn reflect(
		&self,
		_context: RequestContext,
		_params: ReflectParams,
	) -> RpcResult<ReflectResult> {
		Ok(ReflectResult {
			schema_version: 1,
			declarations: BTreeMap::from([(
				"TOKEN".into(),
				wire::ReflectedDeclaration {
					description: "Memory token".into(),
					required: true,
					reference: wire::Coordinates {
						item: "token".into(),
						field: None,
						vault: None,
						section: None,
						version: None,
					},
				},
			)]),
		})
	}
}

struct CredentialAnswer;

#[async_trait]
impl CallbackHandler for CredentialAnswer {
	async fn call(
		&self,
		method: &str,
		params: serde_json::Value,
	) -> Result<serde_json::Value, RpcError> {
		if method != callback::method::CREDENTIAL {
			return Err(RpcError::new(ErrorKind::MethodNotFound));
		}
		let params: CredentialParams =
			serde_json::from_value(params).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
		assert_eq!(params.name, "access_token");
		assert_eq!(params.scope, "memory://default");
		serde_json::to_value(CredentialResult::Found {
			value: "brokered-token".into(),
		})
		.map_err(|_| RpcError::new(ErrorKind::Internal))
	}
}

fn deadline() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis() as u64
		+ Duration::from_secs(2).as_millis() as u64
}

fn address() -> Address {
	Address::Convention {
		project: "payments".into(),
		profile: "production".into(),
		key: "TOKEN".into(),
	}
}

#[tokio::test]
async fn typed_provider_handler_covers_naming_reads_mutations_and_reflection() {
	let (client_io, server_io) = tokio::io::duplex(64 * 1024);
	let (client_read, client_write) = tokio::io::split(client_io);
	let (server_read, server_write) = tokio::io::split(server_io);
	let server = tokio::spawn(serve_provider(
		server_read,
		server_write,
		MemoryProvider::default(),
		ServerConfig::default(),
	));
	let initialize = InitializeParams {
		protocol: PROVIDER_PROTOCOL.into(),
		versions: vec![PROTOCOL_VERSION],
		client: Product {
			name: "provider-test".into(),
			version: "1".into(),
		},
		limits: Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 8,
		},
		client_methods: Vec::new(),
		application: InitializeApplication {
			scheme: "memory".into(),
			uri: "memory://default".into(),
			context: ApplicationContext {
				project: Some("payments".into()),
				profile: Some("production".into()),
				base_dir: None,
				reason: Some("test".into()),
				requested_authorization_duration_ms: None,
			},
		},
	};
	let (raw, initialized) = Client::connect::<_, _, _, InitializedApplication>(
		client_read,
		client_write,
		initialize,
		deadline(),
	)
	.await
	.unwrap();
	assert_eq!(initialized.application.provider.name, "memory");
	let client = raw;

	let resolved: ResolveAddressResult = client
		.call(
			wire::method::RESOLVE_ADDRESS,
			&AddressParams { address: address() },
			deadline(),
		)
		.await
		.unwrap();
	assert_eq!(resolved.coordinates.item, "payments/production/TOKEN");

	let missing: GetResult = client
		.call(
			wire::method::GET,
			&AddressParams { address: address() },
			deadline(),
		)
		.await
		.unwrap();
	assert_eq!(missing, GetResult::Missing);

	let stored: wire::StoredResult = client
		.call(
			wire::method::SET,
			&SetParams {
				address: address(),
				value: "canary-value".into(),
			},
			deadline(),
		)
		.await
		.unwrap();
	assert!(stored.stored);
	let found: GetResult = client
		.call(
			wire::method::GET,
			&AddressParams { address: address() },
			deadline(),
		)
		.await
		.unwrap();
	assert_eq!(
		found,
		GetResult::Found {
			value: "canary-value".into(),
			expires_at_unix_ms: None,
			revision: Some(monosecret_ipc::Revision::new("test:version-1".into()).unwrap()),
		}
	);
	let reflected: ReflectResult = client
		.call(
			wire::method::REFLECT,
			&ReflectParams {
				project: "payments".into(),
				profile: "production".into(),
			},
			deadline(),
		)
		.await
		.unwrap();
	assert_eq!(reflected.declarations.len(), 1);

	let deleted: wire::DeletedResult = client
		.call(
			wire::method::DELETE,
			&AddressParams { address: address() },
			deadline(),
		)
		.await
		.unwrap();
	assert!(deleted.deleted);
	client.close(deadline()).await.unwrap();
	server.await.unwrap().unwrap();
}

#[tokio::test]
async fn provider_can_request_a_credential_during_initialize_and_set() {
	let (client_io, server_io) = tokio::io::duplex(64 * 1024);
	let (client_read, client_write) = tokio::io::split(client_io);
	let (server_read, server_write) = tokio::io::split(server_io);
	let credential = Arc::new(Mutex::new(None));
	let write_credential = Arc::new(Mutex::new(None));
	let provider = MemoryProvider {
		values: Mutex::new(HashMap::new()),
		initialized_credential: credential.clone(),
		write_credential: write_credential.clone(),
	};
	let server = tokio::spawn(serve_provider(
		server_read,
		server_write,
		provider,
		ServerConfig::default(),
	));
	let initialize = InitializeParams {
		protocol: PROVIDER_PROTOCOL.into(),
		versions: vec![PROTOCOL_VERSION],
		client: Product {
			name: "provider-test".into(),
			version: "1".into(),
		},
		limits: Limits {
			max_frame_bytes: 32 * 1024,
			max_in_flight: 8,
		},
		client_methods: vec![callback::method::CREDENTIAL.into()],
		application: InitializeApplication {
			scheme: "memory".into(),
			uri: "memory://default".into(),
			context: ApplicationContext {
				project: Some("payments".into()),
				profile: Some("production".into()),
				base_dir: None,
				reason: Some("test".into()),
				requested_authorization_duration_ms: None,
			},
		},
	};
	let (client, _initialized) = Client::connect_with_callbacks::<_, _, _, InitializedApplication>(
		client_read,
		client_write,
		initialize,
		deadline(),
		Some(Arc::new(CredentialAnswer)),
	)
	.await
	.unwrap();

	assert_eq!(
		credential.lock().unwrap().as_deref(),
		Some("brokered-token")
	);
	assert!(write_credential.lock().unwrap().is_none());
	let stored: wire::StoredResult = client
		.call(
			wire::method::SET,
			&SetParams {
				address: address(),
				value: "secret-to-store".into(),
			},
			deadline(),
		)
		.await
		.unwrap();
	assert!(stored.stored);
	assert_eq!(
		write_credential.lock().unwrap().as_deref(),
		Some("brokered-token")
	);
	client.close(deadline()).await.unwrap();
	server.await.unwrap().unwrap();
}
