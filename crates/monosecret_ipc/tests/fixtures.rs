use std::fs;
use std::path::Path;
use std::path::PathBuf;

use monosecret_ipc::frame::FrameDecoder;
use monosecret_ipc::frame::encode;
use monosecret_ipc::jsonrpc::Envelope;
use proptest::prelude::*;
use serde_json::Value;
use serde_json::json;

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
	value
		.get(name)
		.unwrap_or_else(|| panic!("missing JSON field {name}"))
}

fn schema_root() -> PathBuf {
	// NOTE (monosecret sync 0.4.0): upstream this crate sits at the repo
	// root, so `../schema` reached the canonical root `schema/ipc/v1/`. This
	// crate lives under `crates/`, so the canonical assets are one level
	// further up. They land with the repo-root schema workstream; the packaged
	// copy under this crate (`packaged_schema_root`) satisfies the build via
	// `include_str!` until then.
	Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/ipc/v1")
}

fn packaged_schema_root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/ipc/v1")
}

#[test]
fn schemas_openrpc_and_fixtures_are_valid_json() {
	let root = schema_root();
	let schemas = [
		"common.schema.json",
		"resolver.schema.json",
		"provider.schema.json",
	]
	.map(|name| {
		let bytes = fs::read(root.join(name)).unwrap();
		let value: Value = serde_json::from_slice(&bytes).unwrap();
		assert!(value.is_object(), "{name}");
		(name, value)
	});
	for name in ["resolver.openrpc.json", "provider.openrpc.json"] {
		let bytes = fs::read(root.join(name)).unwrap();
		let value: Value = serde_json::from_slice(&bytes).unwrap();
		assert!(value.is_object(), "{name}");
	}

	let registry = schemas
		.iter()
		.fold(jsonschema::Registry::new(), |registry, (_, schema)| {
			let uri = field(schema, "$id")
				.as_str()
				.expect("schema has an absolute $id");
			registry.add(uri, schema).expect("schema resource is valid")
		})
		.prepare()
		.expect("schema registry resolves every reference");

	for role in ["wire", "resolver", "provider"] {
		for entry in fs::read_dir(root.join("fixtures").join(role)).unwrap() {
			let path = entry.unwrap().path();
			let bytes = fs::read(&path).unwrap();
			Envelope::parse(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
			let envelope: Value = serde_json::from_slice(&bytes).unwrap();
			if envelope.get("method").is_some() && envelope.get("id").is_some() {
				let request_schema = json!({
					"$ref": concat!(
						"https://ifiokjr.github.io/monosecret/schema/ipc/v1/common.schema.json",
						"#/$defs/RequestEnvelope"
					)
				});
				let validator = jsonschema::options()
					.with_registry(&registry)
					.build(&request_schema)
					.unwrap();
				validator.validate(&envelope).unwrap_or_else(|error| {
					panic!("{} is not a request envelope: {error}", path.display())
				});
			}
			let (schema_ref, instance) = fixture_schema(role, &path, &envelope);
			let root_schema = json!({ "$ref": schema_ref });
			let validator = jsonschema::options()
				.with_registry(&registry)
				.build(&root_schema)
				.unwrap_or_else(|error| panic!("{}: {error}", path.display()));
			if let Err(error) = validator.validate(instance) {
				panic!("{} does not match {schema_ref}: {error}", path.display());
			}
		}
	}
}

#[test]
fn embedded_discovery_documents_match_the_canonical_assets() {
	let canonical = schema_root();
	let packaged = packaged_schema_root();
	for name in [
		"common.schema.json",
		"resolver.schema.json",
		"provider.schema.json",
		"resolver.openrpc.json",
		"provider.openrpc.json",
	] {
		assert_eq!(
			fs::read(canonical.join(name)).unwrap(),
			fs::read(packaged.join(name)).unwrap(),
			"embedded discovery asset drifted: {name}"
		);
	}
}

#[test]
fn method_catalogs_match_openrpc() {
	let root = schema_root();
	let cases = [
		(
			"resolver.openrpc.json",
			"resolver.",
			// The full catalog rather than the advertised set: the document
			// describes the optional mutation methods too.
			monosecret_ipc::protocol::resolver::method::ALL,
		),
		(
			"provider.openrpc.json",
			"provider.",
			monosecret_ipc::protocol::provider::method::ALL,
		),
		(
			"resolver.openrpc.json",
			"rpc.",
			monosecret_ipc::protocol::rpc::ALL,
		),
		(
			"provider.openrpc.json",
			"rpc.",
			monosecret_ipc::protocol::rpc::ALL,
		),
		// The callbacks the endpoint sends the other way. Documented in the
		// resolver's own OpenRPC document because that is the protocol they
		// belong to, and pinned here so the two catalogs cannot drift.
		(
			"resolver.openrpc.json",
			"client.",
			monosecret_ipc::protocol::callback::method::RESOLVER,
		),
		(
			"provider.openrpc.json",
			"client.",
			monosecret_ipc::protocol::callback::method::PROVIDER,
		),
	];
	for (document, prefix, catalog) in cases {
		let value: Value = serde_json::from_slice(&fs::read(root.join(document)).unwrap()).unwrap();
		let mut documented: Vec<_> = field(&value, "methods")
			.as_array()
			.unwrap()
			.iter()
			.filter_map(|method| field(method, "name").as_str())
			.filter(|name| name.starts_with(prefix))
			.collect();
		let mut implemented = catalog.to_vec();
		documented.sort_unstable();
		implemented.sort_unstable();
		assert_eq!(implemented, documented, "{document}");
	}
}

fn fixture_schema<'a>(role: &str, path: &Path, envelope: &'a Value) -> (&'static str, &'a Value) {
	let name = path.file_name().and_then(|name| name.to_str()).unwrap();
	match (role, name) {
		("wire", "error.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/common.schema.json#/$defs/ErrorResponseEnvelope",
				envelope,
			)
		}
		("wire", "discovery-result.json") => {
			(
				concat!(
					"https://ifiokjr.github.io/monosecret/schema/ipc/v1/common.schema.json",
					"#/$defs/DiscoveryDocument"
				),
				field(envelope, "result"),
			)
		}
		("wire", "cancel.json") => {
			(
				concat!(
					"https://ifiokjr.github.io/monosecret/schema/ipc/v1/common.schema.json",
					"#/$defs/CancelParams"
				),
				field(envelope, "params"),
			)
		}
		("wire", "discover.json" | "shutdown.json") => {
			(
				concat!(
					"https://ifiokjr.github.io/monosecret/schema/ipc/v1/common.schema.json",
					"#/$defs/EmptyParams"
				),
				field(envelope, "params"),
			)
		}
		("resolver", "initialize-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/InitializeParams",
				field(envelope, "params"),
			)
		}
		("resolver", "initialize-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/InitializeResult",
				field(envelope, "result"),
			)
		}
		("resolver", "get-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/GetParams",
				field(envelope, "params"),
			)
		}
		("resolver", "get-value-result.json" | "get-revision-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/GetResult",
				field(envelope, "result"),
			)
		}
		("resolver", "release-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/ReleaseParams",
				field(envelope, "params"),
			)
		}
		("resolver", "set-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/SetParams",
				field(envelope, "params"),
			)
		}
		("resolver", "set-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/SetResult",
				field(envelope, "result"),
			)
		}
		("resolver", "prompt-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/PromptParams",
				field(envelope, "params"),
			)
		}
		("resolver", "prompt-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/PromptResult",
				field(envelope, "result"),
			)
		}
		("resolver", "delete-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/DeleteParams",
				field(envelope, "params"),
			)
		}
		("resolver", "delete-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/resolver.schema.json#/$defs/DeleteResult",
				field(envelope, "result"),
			)
		}
		("provider", "initialize-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/InitializeParams",
				field(envelope, "params"),
			)
		}
		("provider", "initialize-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/InitializeResult",
				field(envelope, "result"),
			)
		}
		("provider", "resolve-address-request.json" | "get-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/AddressParams",
				field(envelope, "params"),
			)
		}
		("provider", "get-result.json" | "get-revision-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/GetResult",
				field(envelope, "result"),
			)
		}
		("provider", "credential-request.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/CredentialParams",
				field(envelope, "params"),
			)
		}
		("provider", "credential-result.json") => {
			(
				"https://ifiokjr.github.io/monosecret/schema/ipc/v1/provider.schema.json#/$defs/CredentialResult",
				field(envelope, "result"),
			)
		}
		_ => panic!("fixture {role}/{name} has no schema assertion"),
	}
}

proptest! {
	#[test]
	fn every_chunking_round_trips(payload in "\\{\\\"[a-z]{0,64}\\\":([0-9]{1,6}|true|null)\\}", chunks in prop::collection::vec(1usize..16, 1..32)) {
		let frame = encode(payload.as_bytes(), 4096).unwrap();
		let mut decoder = FrameDecoder::new(4096).unwrap();
		let mut offset = 0;
		let mut output = Vec::new();
		for size in chunks {
			if offset == frame.len() { break; }
			let end = (offset + size).min(frame.len());
			let chunk = frame
				.get(offset..end)
				.expect("chunk boundaries stay within the frame");
			output.extend(decoder.push(chunk).unwrap());
			offset = end;
		}
		if offset < frame.len() {
			let chunk = frame
				.get(offset..)
				.expect("the remaining frame boundary is valid");
			output.extend(decoder.push(chunk).unwrap());
		}
		decoder.finish_eof().unwrap();
		prop_assert_eq!(output.len(), 1);
		let first_frame = output
			.first()
			.expect("the encoded frame produces one decoded frame");
		prop_assert_eq!(first_frame.as_slice(), payload.as_bytes());
	}
}
