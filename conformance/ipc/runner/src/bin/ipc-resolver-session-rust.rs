//! Real transport server for cross-language handshake and ordering tests.
use std::sync::Arc;

use async_trait::async_trait;
use monosecret_ipc::server::ApplicationHandler;
use monosecret_ipc::server::RequestContext;
use monosecret_ipc::server::RpcResult;
use monosecret_ipc::server::ServerConfig;
use monosecret_ipc::server::serve;
use serde_json::Value;
use serde_json::json;

struct Echo;
#[async_trait]
impl ApplicationHandler for Echo {
	fn protocol(&self) -> &'static str {
		"monosecret.resolver"
	}

	fn capabilities(&self) -> Vec<String> {
		vec!["resolver.get".into(), "resolver.release".into()]
	}

	async fn initialize(&self, _: &RequestContext, application: Value) -> RpcResult<Value> {
		Ok(application)
	}

	async fn call(&self, _: RequestContext, _: &str, params: Value) -> RpcResult<Value> {
		Ok(json!({"echo":params["token"]}))
	}
}

#[tokio::main]
async fn main() {
	if serve(
		tokio::io::stdin(),
		tokio::io::stdout(),
		Arc::new(Echo),
		ServerConfig::default(),
	)
	.await
	.is_err()
	{
		std::process::exit(1);
	}
}
