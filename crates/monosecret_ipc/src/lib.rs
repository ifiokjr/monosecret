//! Monosecret IPC version 1.
//!
//! The checked-in JSON schemas and protocol documents are canonical. This
//! crate is an independent Rust implementation of their wire, client, server,
//! resolution, and provider state machines.

#[cfg(any(feature = "tokio", feature = "blocking"))]
pub mod connection;
pub mod deadline;
pub mod error;
pub mod frame;
pub mod jsonrpc;
pub mod launch;
pub mod protocol;
pub mod revision;

#[cfg(feature = "tokio")]
mod description;

#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(feature = "tokio")]
pub mod client;
#[cfg(feature = "tokio")]
pub mod lifecycle;
#[cfg(feature = "tokio")]
pub mod provider;
#[cfg(feature = "tokio")]
pub mod resolver;
#[cfg(feature = "tokio")]
pub mod server;

pub use deadline::unix_ms_after as deadline_unix_ms_after;
pub use error::Error;
pub use error::ErrorData;
pub use error::ErrorKind;
pub use error::InteractionKind;
pub use error::InteractionReference;
pub use error::Result;
pub use error::RpcError;
pub use jsonrpc::Envelope;
pub use jsonrpc::Notification;
pub use jsonrpc::Request;
pub use jsonrpc::RequestId;
pub use jsonrpc::Response;
pub use protocol::Limits;
pub use protocol::Product;
pub use revision::Revision;

/// Wire protocol major version implemented by this crate.
pub const WIRE_VERSION: u32 = 1;

/// Absolute pre-negotiation and version 1 frame ceiling.
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 1_048_576;

/// Smallest negotiable frame limit.
pub const MIN_FRAME_BYTES: usize = 4_096;

/// Version 1 in-flight ceiling.
pub const MAX_IN_FLIGHT: usize = 32;

/// Largest request ID that is exactly representable by JSON/JavaScript peers.
pub const MAX_REQUEST_ID: u64 = 9_007_199_254_740_991;
