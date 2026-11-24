//! Local SQLite provider (0.22+).
//!
//! Stores each secret as one row in a local SQLite database. Convention
//! addresses are isolated by project and profile at `{project}/{profile}/{key}`;
//! a native `ref` supplies that key directly as `item`.
//!
//! Confidentiality comes entirely from filesystem permissions on the database
//! file: the schema and connection carry no credential of their own. That is
//! what lets identical code serve both an ordinary user-owned store and a
//! privilege-boundary vault file guarded by a `0600` service-user-owned path;
//! the privilege model stays external to the provider.
//!
//! With `?history=true` every write also appends to a hash-chained,
//! append-only ledger inside the same database (see [`capture_history`]).
//! History is off by default: a plain `sqlite:PATH` store has only the
//! `secrets` table.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::TransactionBehavior;
use rusqlite::params;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::Address;
use super::HistoryFailure;
use super::HistoryFailureReason;
use super::HistoryReport;
use super::Provider;
use super::ProviderUrl;
use crate::MonosecretError;
use crate::Result;
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::config::expand_tilde;

const URI_SHAPE_ERROR: &str =
	"sqlite provider URIs take only a database path and an optional '?history=true' parameter";

/// Configuration for the local SQLite provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteConfig {
	/// Path to the SQLite database file.
	pub path: PathBuf,
	/// Whether history tracking is enabled.
	#[serde(default)]
	pub history: bool,
}

impl TryFrom<&ProviderUrl> for SqliteConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> Result<Self> {
		if url.scheme() != "sqlite" {
			return Err(operation_error(format!(
				"Invalid scheme '{}' for sqlite provider",
				url.scheme()
			)));
		}
		if !url.username().is_empty() || url.password().is_some() {
			return Err(operation_error(URI_SHAPE_ERROR));
		}
		let mut history = false;
		if url.has_query() {
			let pairs: Vec<_> = url.query_pairs().collect();
			let Some((key, value)) = pairs.first() else {
				return Err(operation_error(URI_SHAPE_ERROR));
			};
			if pairs.len() != 1 || key != "history" {
				return Err(operation_error(URI_SHAPE_ERROR));
			}
			match value.as_ref() {
				"true" | "1" | "yes" | "on" => history = true,
				"false" | "0" | "no" | "off" => history = false,
				_ => {
					return Err(operation_error(
						"invalid value for the sqlite provider's 'history' parameter: expected true or false",
					));
				}
			}
		}

		let uri_path = url.path();
		#[cfg(windows)]
		let uri_path = if uri_path.as_bytes().first() == Some(&b'/')
			&& uri_path.as_bytes().get(2) == Some(&b':')
			&& uri_path
				.as_bytes()
				.get(1)
				.is_some_and(u8::is_ascii_alphabetic)
		{
			uri_path.get(1..).unwrap_or(&uri_path).to_string()
		} else {
			uri_path
		};
		let path = match url.host() {
			Some(host) => format!("{host}{uri_path}"),
			None => uri_path,
		};
		if path.is_empty() || path == "/" {
			return Err(operation_error(
				"No SQLite database path given. Use sqlite:./secrets.db or \
				 sqlite:///absolute/path/secrets.db.",
			));
		}

		Ok(Self {
			path: PathBuf::from(path),
			history,
		})
	}
}

/// A provider backed by a local SQLite database, one row per secret.
pub struct SqliteProvider {
	config: SqliteConfig,
}

crate::register_provider! {
	struct: SqliteProvider,
	config: SqliteConfig,
	metadata: &super::catalog::SQLITE,
}

impl SqliteProvider {
	#[must_use]
	pub fn new(mut config: SqliteConfig) -> Self {
		config.path = expand_tilde(config.path);
		Self { config }
	}

	#[cfg(unix)]
	fn create_private_directory(path: &Path) -> std::io::Result<()> {
		use std::os::unix::fs::DirBuilderExt;

		std::fs::DirBuilder::new()
			.recursive(true)
			.mode(0o700)
			.create(path)
	}

	#[cfg(not(unix))]
	fn create_private_directory(path: &Path) -> std::io::Result<()> {
		std::fs::create_dir_all(path)
	}

	#[cfg(unix)]
	fn restrict_file(path: &Path) -> Result<()> {
		use std::os::unix::fs::PermissionsExt;

		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
			operation_error(format!(
				"failed to restrict permissions for sqlite database '{}': {error}",
				path.display()
			))
		})
	}

	#[cfg(not(unix))]
	fn restrict_file(_path: &Path) -> Result<()> {
		Ok(())
	}

	/// Opens the database, creating its parent directory and schema on first
	/// use. Every open re-asserts `0600` permissions on the file, in case it
	/// pre-existed with looser ones.
	fn connection(&self) -> Result<Connection> {
		if let Some(parent) = self.config.path.parent()
			&& !parent.as_os_str().is_empty()
		{
			Self::create_private_directory(parent).map_err(|error| {
				operation_error(format!(
					"failed to create sqlite provider directory '{}': {error}",
					parent.display()
				))
			})?;
		}

		let mut conn = Connection::open(&self.config.path).map_err(|error| {
			operation_error(format!(
				"failed to open sqlite database '{}': {error}",
				self.config.path.display()
			))
		})?;
		conn.busy_timeout(Duration::from_secs(30))
			.map_err(|error| {
				operation_error(format!(
					"failed to configure sqlite database '{}': {error}",
					self.config.path.display()
				))
			})?;
		let mut init_sql = String::from(
			// `foreign_keys` is off by default and is a *per-connection* setting,
			// so without this the REFERENCES clauses on `captured_values` below
			// are documentation rather than a constraint: a tombstone could name
			// a `destroyed_by` sequence no entry has. Every connection this
			// provider hands out comes through here, which is what makes one
			// line sufficient.
			// `secure_delete` is also per-connection and off in most builds of
			// the library. Without it SQLite unlinks a deleted row from the
			// b-tree but leaves its bytes on the freed page, so `delete` leaves
			// the plaintext value recoverable by reading the file. Setting it
			// here makes freed content zeroed on the way out. It is not
			// retroactive: residue already on freelist pages needs a `VACUUM`.
			"PRAGMA foreign_keys=ON;\
			 PRAGMA secure_delete=ON;\
			 PRAGMA journal_mode=DELETE;\
			 PRAGMA synchronous=FULL;\
			 PRAGMA trusted_schema=OFF;\
			 CREATE TABLE IF NOT EXISTS secrets (\
			     item TEXT PRIMARY KEY,\
			     value BLOB NOT NULL\
			 ) STRICT;",
		);
		if self.config.history {
			init_sql.push_str(&history_schema());
		}
		conn.execute_batch(&init_sql).map_err(|error| {
			operation_error(format!(
				"failed to prepare sqlite database '{}': {error}",
				self.config.path.display()
			))
		})?;
		if self.config.history {
			check_history_version(&conn)?;
			// `HISTORY_POST_MIGRATION` drops then recreates triggers so their
			// bodies stay authoritative. Without a reserved write lock, two
			// openers can interleave drop/create and the second create fails
			// with "already exists". BEGIN IMMEDIATE serialises the whole
			// batch behind `busy_timeout`; dropping the transaction without
			// commit rolls back a partial trigger set.
			let tx = conn
				.transaction_with_behavior(TransactionBehavior::Immediate)
				.map_err(|error| {
					operation_error(format!(
						"failed to start history schema transaction on '{}': {error}",
						self.config.path.display()
					))
				})?;
			tx.execute_batch(HISTORY_POST_MIGRATION).map_err(|error| {
				operation_error(format!(
					"failed to finish history schema on '{}': {error}",
					self.config.path.display()
				))
			})?;
			tx.commit().map_err(|error| {
				operation_error(format!(
					"failed to commit history schema on '{}': {error}",
					self.config.path.display()
				))
			})?;
		}
		Self::restrict_file(&self.config.path)?;
		Ok(conn)
	}
}

/// Whether the `secrets.value` column of this database was created as `TEXT`.
///
/// Databases created before values became bytes declared the column `TEXT` in
/// a `STRICT` table, and `CREATE TABLE IF NOT EXISTS` leaves that shape in
/// place. A `STRICT` `TEXT` column refuses a `BLOB`, so such a store has to be
/// written as text or every `set` would fail on an existing vault.
fn stores_values_as_text(conn: &Connection) -> rusqlite::Result<bool> {
	let declared: Option<String> = conn
		.query_row(
			"SELECT type FROM pragma_table_info('secrets') WHERE name = 'value'",
			[],
			|row| row.get(0),
		)
		.optional()?;
	Ok(declared.is_some_and(|declared| declared.eq_ignore_ascii_case("TEXT")))
}

impl Provider for SqliteProvider {
	fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
		Ok(NativeAddress {
			item: format!("{project}/{profile}/{key}"),
			..Default::default()
		})
	}

	fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
		let item = super::flat_item(self, addr)?;
		if !self.config.path.exists() {
			return Ok(None);
		}
		let conn = self.connection()?;
		let value: Option<Vec<u8>> = conn
			.query_row(
				"SELECT value FROM secrets WHERE item = ?1",
				params![item.as_ref()],
				value_bytes,
			)
			.optional()
			.map_err(|error| {
				operation_error(format!(
					"failed to read sqlite provider entry '{item}': {error}"
				))
			})?;
		Ok(value.map(SecretBytes::from_vec))
	}

	fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
		let item = super::flat_item(self, addr)?;
		Ok(format!("{} (item '{item}')", self.config.path.display()))
	}

	fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
		self.check_writable(addr)?;
		let item = super::flat_item(self, addr)?;
		let mut conn = self.connection()?;
		// IMMEDIATE, not deferred: `set` reads the schema before it writes, and
		// a deferred transaction that upgrades a read lock to a write lock
		// fails at once with "database is locked" instead of waiting out
		// `busy_timeout` when another connection holds the write lock.
		let tx = conn
			.transaction_with_behavior(TransactionBehavior::Immediate)
			.map_err(|error| {
				operation_error(format!("failed to start sqlite transaction: {error}"))
			})?;
		let text_column = stores_values_as_text(&tx).map_err(|error| {
			operation_error(format!(
				"failed to inspect sqlite provider schema on '{}': {error}",
				self.config.path.display()
			))
		})?;
		let written = if text_column {
			let text = std::str::from_utf8(value.expose_secret()).map_err(|_| {
				operation_error(format!(
					"sqlite database '{}' stores values as TEXT and cannot hold the \
					 non-UTF-8 value for '{item}'",
					self.config.path.display()
				))
			})?;
			tx.execute(
				"INSERT INTO secrets (item, value) VALUES (?1, ?2) \
				 ON CONFLICT(item) DO UPDATE SET value = excluded.value",
				params![item.as_ref(), text],
			)
		} else {
			tx.execute(
				"INSERT INTO secrets (item, value) VALUES (?1, ?2) \
				 ON CONFLICT(item) DO UPDATE SET value = excluded.value",
				params![item.as_ref(), value.expose_secret()],
			)
		};
		written.map_err(|error| {
			operation_error(format!(
				"failed to write sqlite provider entry '{item}': {error}"
			))
		})?;
		if self.config.history {
			capture_history(&tx, "set")?;
		}
		tx.commit().map_err(|error| {
			operation_error(format!("failed to commit sqlite transaction: {error}"))
		})?;
		Ok(())
	}

	fn delete(&self, addr: Address<'_>) -> Result<bool> {
		let item = super::flat_item(self, addr)?;
		if !self.config.path.exists() {
			return Ok(false);
		}
		let mut conn = self.connection()?;
		let tx = conn
			.transaction_with_behavior(TransactionBehavior::Immediate)
			.map_err(|error| {
				operation_error(format!("failed to start sqlite transaction: {error}"))
			})?;
		let changed = tx
			.execute(
				"DELETE FROM secrets WHERE item = ?1",
				params![item.as_ref()],
			)
			.map_err(|error| {
				operation_error(format!(
					"failed to delete sqlite provider entry '{item}': {error}"
				))
			})?;
		if changed > 0 && self.config.history {
			capture_history(&tx, "delete")?;
		}
		tx.commit().map_err(|error| {
			operation_error(format!("failed to commit sqlite transaction: {error}"))
		})?;
		Ok(changed > 0)
	}

	fn supports_delete(&self) -> bool {
		true
	}

	fn verify_history(&self) -> Result<Option<HistoryReport>> {
		let Some(conn) = self.open_for_verification()? else {
			return Ok(None);
		};
		// The `entries` table, not the URI's `history` flag, is what makes a
		// store auditable: a plain alias and a `?history=true` alias name the
		// same rows, so either may point at a database that carries a ledger.
		if !table_exists(&conn, "entries")? {
			return Ok(None);
		}
		verify_ledger(&conn).map(Some)
	}

	fn name(&self) -> &str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		let path = ProviderUrl::encode(&self.config.path.display().to_string());
		if self.config.history {
			format!("sqlite:{path}?history=true")
		} else {
			format!("sqlite:{path}")
		}
	}

	fn storage_identity(&self) -> String {
		// History is a write-side policy on the same file, not a different
		// store: a `?history=true` alias and a plain alias naming one path
		// read and write the same rows.
		format!(
			"sqlite:{}",
			ProviderUrl::encode(&self.config.path.display().to_string())
		)
	}

	fn physical_store_path(&self) -> Option<&Path> {
		Some(&self.config.path)
	}

	fn with_base_dir(&mut self, base_dir: &Path) {
		if self.config.path.is_relative() {
			self.config.path = base_dir.join(&self.config.path);
		}
	}

	fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
		// Resolve every address up front so an invalid coordinate is rejected
		// the same way whether or not the database file exists yet.
		let mut items = Vec::with_capacity(requests.len());
		for (name, addr) in requests {
			items.push((*name, super::flat_item(self, *addr)?));
		}
		if !self.config.path.exists() {
			return Ok(HashMap::new());
		}
		let conn = self.connection()?;
		let mut statement = conn
			.prepare("SELECT value FROM secrets WHERE item = ?1")
			.map_err(|error| {
				operation_error(format!("failed to query sqlite database: {error}"))
			})?;

		let mut results = HashMap::new();
		for (name, item) in items {
			let value: Option<Vec<u8>> = statement
				.query_row(params![item.as_ref()], value_bytes)
				.optional()
				.map_err(|error| {
					operation_error(format!(
						"failed to read sqlite provider entry '{item}': {error}"
					))
				})?;
			if let Some(value) = value {
				results.insert(name.to_string(), SecretBytes::from_vec(value));
			}
		}
		Ok(results)
	}
}

fn operation_error(message: impl Into<String>) -> MonosecretError {
	MonosecretError::ProviderOperationFailed(message.into())
}

/// Reads the first column as raw bytes whether SQLite holds it as `BLOB` or
/// as `TEXT`, so a row written by another tool as text reads back exactly.
fn value_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<u8>> {
	Ok(row.get_ref(0)?.as_bytes().map(<[u8]>::to_vec)?)
}

// ---------------------------------------------------------------------------
// History capture (opt-in via `?history=true`)
// ---------------------------------------------------------------------------

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Bumped whenever the on-disk history shape changes. Stamped into
/// `PRAGMA user_version`, which starts life at 0 on every SQLite database,
/// so 0 doubles as "pre-versioning": exactly the databases that need
/// migrating.
const SCHEMA_VERSION: i64 = 2;

/// Each distinct value is stored once in `value_blobs` instead of repeating
/// the plaintext in every `captured_values` row.
const VALUE_BLOBS_BODY: &str = "\
     blob_id INTEGER PRIMARY KEY AUTOINCREMENT,\
     item TEXT NOT NULL,\
     value_sha256 TEXT NOT NULL,\
     value_blob BLOB NOT NULL,\
     UNIQUE (item, value_sha256)";

/// Column and constraint body of `captured_values`, shared with any future
/// migration for the same reason as [`VALUE_BLOBS_BODY`].
const CAPTURED_VALUES_BODY: &str = "\
     sequence INTEGER NOT NULL REFERENCES entries(sequence),\
     item TEXT NOT NULL,\
     value_sha256 TEXT NOT NULL,\
     blob_id INTEGER,\
     destroyed_by INTEGER REFERENCES entries(sequence),\
     live_blob_id INTEGER GENERATED ALWAYS AS \
         (CASE WHEN destroyed_by IS NULL THEN blob_id END) VIRTUAL \
         REFERENCES value_blobs(blob_id) ON DELETE RESTRICT,\
     PRIMARY KEY (sequence, item),\
     CHECK (blob_id IS NOT NULL OR destroyed_by IS NOT NULL),\
     CHECK (destroyed_by IS NULL OR destroyed_by > sequence)";

fn history_schema() -> String {
	format!(
		"CREATE TABLE IF NOT EXISTS entries (\
		     sequence INTEGER PRIMARY KEY AUTOINCREMENT,\
		     timestamp_ns INTEGER NOT NULL,\
		     operation TEXT NOT NULL,\
		     previous_hash TEXT NOT NULL,\
		     entry_hash TEXT NOT NULL UNIQUE\
		 ) STRICT;\
		 CREATE TABLE IF NOT EXISTS value_blobs ({VALUE_BLOBS_BODY}) STRICT;\
		 CREATE TABLE IF NOT EXISTS captured_values ({CAPTURED_VALUES_BODY}) STRICT;\
		 CREATE TABLE IF NOT EXISTS head (\
		     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
		     sequence INTEGER NOT NULL,\
		     entry_hash TEXT NOT NULL\
		 ) STRICT;"
	)
}

/// Everything that can only be built once `captured_values` is known to be in
/// its current shape. Applied after [`check_history_version`], never as part
/// of [`history_schema`].
const HISTORY_POST_MIGRATION: &str = "\
     CREATE INDEX IF NOT EXISTS captured_values_blob_id \
         ON captured_values(item, blob_id);\
     DROP TRIGGER IF EXISTS captured_values_destroyed_by_is_write_once;\
     CREATE TRIGGER captured_values_destroyed_by_is_write_once \
         BEFORE UPDATE OF destroyed_by ON captured_values \
         FOR EACH ROW WHEN OLD.destroyed_by IS NOT NULL \
     BEGIN \
         SELECT RAISE(ABORT, 'captured_values.destroyed_by is write-once'); \
     END;\
     DROP TRIGGER IF EXISTS captured_values_is_append_only;\
     CREATE TRIGGER captured_values_is_append_only \
         BEFORE DELETE ON captured_values \
         FOR EACH ROW \
     BEGIN \
         SELECT RAISE(ABORT, 'captured_values is append-only'); \
     END;";

fn sha256_hex(data: &[u8]) -> String {
	data_encoding::HEXLOWER.encode(&Sha256::digest(data))
}

/// Refuses to open a history database that is not already at
/// [`SCHEMA_VERSION`].
fn check_history_version(conn: &Connection) -> Result<()> {
	let version: i64 = conn
		.query_row("PRAGMA user_version", [], |row| row.get(0))
		.map_err(|e| operation_error(e.to_string()))?;

	if version == 0 && !has_current_shape(conn)? {
		return Err(operation_error(
			"this history database predates the current schema and cannot be \
			 upgraded in place. Export its secrets with a build that matches it \
			 and re-import them into a new database.",
		));
	}
	if version > SCHEMA_VERSION {
		return Err(operation_error(format!(
			"this history database was written by a newer version (schema \
			 {version}, this build understands {SCHEMA_VERSION})"
		)));
	}
	if version < SCHEMA_VERSION {
		conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
			.map_err(|e| operation_error(e.to_string()))?;
	}
	Ok(())
}

/// Whether `captured_values` carries the column the current schema depends on.
fn has_current_shape(conn: &Connection) -> Result<bool> {
	let mut stmt = conn
		.prepare("SELECT name FROM pragma_table_info('captured_values')")
		.map_err(|e| operation_error(e.to_string()))?;
	let rows = stmt
		.query_map([], |row| row.get::<_, String>(0))
		.map_err(|e| operation_error(e.to_string()))?;
	for row in rows {
		if row.map_err(|e| operation_error(e.to_string()))? == "blob_id" {
			return Ok(true);
		}
	}
	Ok(false)
}

#[derive(Debug)]
struct CapturedValue {
	item: String,
	value_sha256: String,
}

#[derive(Debug)]
struct Entry {
	sequence: i64,
	timestamp_ns: i64,
	operation: String,
	values: Vec<CapturedValue>,
	previous_hash: String,
	hash: String,
}

fn canonical_entry_json(entry: &Entry) -> String {
	let mut map = BTreeMap::new();
	map.insert("sequence", serde_json::Value::Number(entry.sequence.into()));
	map.insert(
		"timestamp_ns",
		serde_json::Value::Number(entry.timestamp_ns.into()),
	);
	map.insert(
		"operation",
		serde_json::Value::String(entry.operation.clone()),
	);
	let values: Vec<serde_json::Value> = entry
		.values
		.iter()
		.map(|v| {
			let mut pair = serde_json::Map::new();
			pair.insert("item".into(), serde_json::Value::String(v.item.clone()));
			pair.insert(
				"value_sha256".into(),
				serde_json::Value::String(v.value_sha256.clone()),
			);
			serde_json::Value::Object(pair)
		})
		.collect();
	map.insert("values", serde_json::Value::Array(values));
	map.insert(
		"previous_hash",
		serde_json::Value::String(entry.previous_hash.clone()),
	);

	serde_json::to_string(&map).expect("a BTreeMap of JSON values always serializes")
}

fn compute_entry_hash(previous_hash: &str, entry: &Entry) -> String {
	let canonical = canonical_entry_json(entry);
	sha256_hex(format!("{previous_hash}\n{canonical}").as_bytes())
}

/// Appends one entry to the history chain, snapshotting every live secret.
fn capture_history(conn: &Connection, operation: &str) -> Result<()> {
	let mut count: i64 = 0;
	let mut previous_hash = ZERO_HASH.to_string();

	let head_row: Option<(i64, String)> = conn
		.query_row(
			"SELECT sequence, entry_hash FROM head WHERE singleton = 1",
			[],
			|row| Ok((row.get(0)?, row.get(1)?)),
		)
		.optional()
		.map_err(|e| operation_error(e.to_string()))?;

	if let Some((seq, hash)) = head_row {
		count = seq;
		previous_hash = hash;
	}

	let sequence = count + 1;
	let timestamp_ns = {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_err(|e| operation_error(format!("clock error: {e}")))?;
		i64::try_from(now.as_nanos()).unwrap_or(i64::MAX)
	};

	let mut stmt = conn
		.prepare("SELECT item, value FROM secrets ORDER BY item")
		.map_err(|e| operation_error(e.to_string()))?;

	let mut pairs = Vec::new();
	let rows = stmt
		.query_map([], |row| {
			Ok((
				row.get::<_, String>(0)?,
				row.get_ref(1)?.as_bytes().map(<[u8]>::to_vec)?,
			))
		})
		.map_err(|e| operation_error(e.to_string()))?;

	for row in rows {
		pairs.push(row.map_err(|e| operation_error(e.to_string()))?);
	}

	let values: Vec<CapturedValue> = pairs
		.iter()
		.map(|(item, value)| {
			CapturedValue {
				item: item.clone(),
				value_sha256: sha256_hex(value),
			}
		})
		.collect();

	let mut entry = Entry {
		sequence,
		timestamp_ns,
		operation: operation.to_string(),
		values,
		previous_hash: previous_hash.clone(),
		hash: String::new(),
	};
	entry.hash = compute_entry_hash(&previous_hash, &entry);

	conn.execute(
		"INSERT INTO entries (sequence, timestamp_ns, operation, previous_hash, entry_hash) \
		 VALUES (?1, ?2, ?3, ?4, ?5)",
		params![
			entry.sequence,
			entry.timestamp_ns,
			entry.operation,
			entry.previous_hash,
			entry.hash,
		],
	)
	.map_err(|e| operation_error(e.to_string()))?;

	for (val, (_, plain)) in entry.values.iter().zip(pairs.iter()) {
		conn.execute(
			"INSERT OR IGNORE INTO value_blobs (item, value_sha256, value_blob) \
			 VALUES (?1, ?2, ?3)",
			params![val.item, val.value_sha256, plain.as_slice()],
		)
		.map_err(|e| operation_error(e.to_string()))?;

		let blob_id: i64 = conn
			.query_row(
				"SELECT blob_id FROM value_blobs WHERE item = ?1 AND value_sha256 = ?2",
				params![val.item, val.value_sha256],
				|row| row.get(0),
			)
			.map_err(|e| operation_error(e.to_string()))?;

		conn.execute(
			"INSERT INTO captured_values \
			     (sequence, item, value_sha256, blob_id, destroyed_by) \
			 VALUES (?1, ?2, ?3, ?4, NULL)",
			params![entry.sequence, val.item, val.value_sha256, blob_id],
		)
		.map_err(|e| operation_error(e.to_string()))?;
	}

	conn.execute(
		"INSERT INTO head (singleton, sequence, entry_hash) VALUES (1, ?1, ?2) \
		 ON CONFLICT(singleton) DO UPDATE SET \
		 sequence = excluded.sequence, entry_hash = excluded.entry_hash",
		params![entry.sequence, entry.hash],
	)
	.map_err(|e| operation_error(e.to_string()))?;

	Ok(())
}

// ---------------------------------------------------------------------------
// History verification (read-only)
// ---------------------------------------------------------------------------

impl SqliteProvider {
	/// Opens the database with no possibility of writing, or answers `None`
	/// when there is nothing on disk to audit.
	fn open_for_verification(&self) -> Result<Option<Connection>> {
		if !self.config.path.exists() {
			if self.config.history {
				return Err(operation_error(format!(
					"sqlite history database '{}' does not exist",
					self.config.path.display()
				)));
			}
			return Ok(None);
		}
		let conn = Connection::open_with_flags(
			&self.config.path,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
		)
		.map_err(|error| {
			operation_error(format!(
				"failed to open sqlite database '{}' for verification: {error}",
				self.config.path.display()
			))
		})?;
		Ok(Some(conn))
	}
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
	conn.query_row(
		"SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
		params![table],
		|_| Ok(()),
	)
	.optional()
	.map(|found| found.is_some())
	.map_err(|error| operation_error(format!("failed to inspect sqlite schema: {error}")))
}

/// Walks the whole chain in one read-only pass and reports the first break.
fn verify_ledger(conn: &Connection) -> Result<HistoryReport> {
	let schema_version: i64 = conn
		.query_row("PRAGMA user_version", [], |row| row.get(0))
		.map_err(|error| {
			operation_error(format!("failed to read ledger schema version: {error}"))
		})?;

	let mut entries_stmt = conn
		.prepare(
			"SELECT sequence, timestamp_ns, operation, previous_hash, entry_hash \
			 FROM entries ORDER BY sequence",
		)
		.map_err(|error| operation_error(format!("failed to read ledger entries: {error}")))?;
	let stored: Vec<(i64, i64, String, String, String)> = entries_stmt
		.query_map([], |row| {
			Ok((
				row.get(0)?,
				row.get(1)?,
				row.get(2)?,
				row.get(3)?,
				row.get(4)?,
			))
		})
		.and_then(Iterator::collect)
		.map_err(|error| operation_error(format!("failed to read ledger entries: {error}")))?;

	let mut report = HistoryReport {
		entries: stored.len() as u64,
		head_hash: stored
			.last()
			.map_or_else(|| ZERO_HASH.to_string(), |entry| entry.4.clone()),
		schema_version,
		failure: None,
	};

	let mut values_stmt = conn
		.prepare(
			"SELECT item, value_sha256 FROM captured_values \
			 WHERE sequence = ?1 ORDER BY item",
		)
		.map_err(|error| {
			operation_error(format!("failed to read ledger captured values: {error}"))
		})?;

	let mut previous_hash = ZERO_HASH.to_string();
	for (expected_sequence, (sequence, timestamp_ns, operation, entry_previous_hash, entry_hash)) in
		(1i64..).zip(stored.iter())
	{
		if *sequence != expected_sequence {
			report.failure = Some(HistoryFailure {
				sequence: Some(expected_sequence),
				reason: HistoryFailureReason::MissingEntry,
			});
			return Ok(report);
		}
		if entry_previous_hash != &previous_hash {
			report.failure = Some(HistoryFailure {
				sequence: Some(*sequence),
				reason: HistoryFailureReason::PreviousHashMismatch,
			});
			return Ok(report);
		}
		let values: Vec<CapturedValue> = values_stmt
			.query_map(params![sequence], |row| {
				Ok(CapturedValue {
					item: row.get(0)?,
					value_sha256: row.get(1)?,
				})
			})
			.and_then(Iterator::collect)
			.map_err(|error| {
				operation_error(format!(
					"failed to read captured values for entry {sequence}: {error}"
				))
			})?;
		let entry = Entry {
			sequence: *sequence,
			timestamp_ns: *timestamp_ns,
			operation: operation.clone(),
			values,
			previous_hash: entry_previous_hash.clone(),
			hash: String::new(),
		};
		if compute_entry_hash(&previous_hash, &entry) != *entry_hash {
			report.failure = Some(HistoryFailure {
				sequence: Some(*sequence),
				reason: HistoryFailureReason::EntryHashMismatch,
			});
			return Ok(report);
		}
		previous_hash.clone_from(entry_hash);
	}

	let head: Option<(i64, String)> = conn
		.query_row(
			"SELECT sequence, entry_hash FROM head WHERE singleton = 1",
			[],
			|row| Ok((row.get(0)?, row.get(1)?)),
		)
		.optional()
		.map_err(|error| operation_error(format!("failed to read ledger head: {error}")))?;
	let last_sequence = stored.last().map(|entry| entry.0);
	let head_matches = match (&head, last_sequence) {
		(None, None) => true,
		(Some((sequence, hash)), Some(last)) => *sequence == last && *hash == previous_hash,
		_ => false,
	};
	if !head_matches {
		report.failure = Some(HistoryFailure {
			sequence: last_sequence,
			reason: HistoryFailureReason::HeadMismatch,
		});
		return Ok(report);
	}

	if schema_version != SCHEMA_VERSION {
		report.failure = Some(HistoryFailure {
			sequence: None,
			reason: HistoryFailureReason::SchemaVersionMismatch,
		});
	}

	Ok(report)
}

#[cfg(test)]
mod tests {
	use tempfile::TempDir;
	use url::Url;

	use super::*;

	fn provider_url(value: &str) -> ProviderUrl {
		ProviderUrl::new(Url::parse(value).unwrap())
	}

	fn provider(path: PathBuf) -> SqliteProvider {
		SqliteProvider::new(SqliteConfig {
			path,
			history: false,
		})
	}

	fn history_provider(path: PathBuf) -> SqliteProvider {
		SqliteProvider::new(SqliteConfig {
			path,
			history: true,
		})
	}

	fn convention(key: &str) -> Address<'_> {
		Address::convention("project", "production", key)
	}

	#[test]
	fn config_parses_relative_and_absolute_paths() {
		let relative = SqliteConfig::try_from(&provider_url("sqlite://./secrets.db")).unwrap();
		assert_eq!(relative.path, PathBuf::from("./secrets.db"));
		assert!(!relative.history);

		let absolute =
			SqliteConfig::try_from(&provider_url("sqlite:///var/lib/secrets.db")).unwrap();
		assert_eq!(absolute.path, PathBuf::from("/var/lib/secrets.db"));
	}

	#[test]
	fn history_is_off_unless_the_uri_turns_it_on() {
		for (uri, expected) in [
			("sqlite://./secrets.db", false),
			("sqlite://./secrets.db?history=false", false),
			("sqlite://./secrets.db?history=0", false),
			("sqlite://./secrets.db?history=true", true),
			("sqlite://./secrets.db?history=1", true),
			("sqlite://./secrets.db?history=on", true),
		] {
			let config = SqliteConfig::try_from(&provider_url(uri)).unwrap();
			assert_eq!(config.history, expected, "{uri}");
			assert_eq!(config.path, PathBuf::from("./secrets.db"), "{uri}");
		}
	}

	#[test]
	fn config_rejects_missing_path_and_query_options() {
		for uri in [
			"sqlite://",
			"sqlite://./secrets.db?invalid=on",
			"sqlite://./secrets.db?history=true&other=1",
			"sqlite://./secrets.db?history=maybe",
			"sqlite://user:pass@./secrets.db",
		] {
			assert!(SqliteConfig::try_from(&provider_url(uri)).is_err(), "{uri}");
		}
	}

	#[test]
	fn registry_builds_documented_uri() {
		let provider = Box::<dyn Provider>::try_from("sqlite:./secrets.db").unwrap();
		assert_eq!(provider.name(), "sqlite");
		let provider = Box::<dyn Provider>::try_from("sqlite:./secrets.db?history=true").unwrap();
		assert_eq!(provider.name(), "sqlite");
	}

	#[test]
	fn convention_round_trip_is_exact_and_profile_isolated() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		let value = SecretBytes::from_utf8("s3cr3t\nvalue");

		provider
			.set(Address::convention("app", "development", "TOKEN"), &value)
			.unwrap();

		let found = provider
			.get(Address::convention("app", "development", "TOKEN"))
			.unwrap()
			.unwrap();
		assert_eq!(found.expose_secret(), value.expose_secret());
		assert!(
			provider
				.get(Address::convention("app", "production", "TOKEN"))
				.unwrap()
				.is_none()
		);
	}

	#[test]
	fn binary_values_round_trip_exactly() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		let expected = [0x00, 0xff, 0x80, 0x0a, 0x00];
		provider
			.set(
				convention("BLOB"),
				&SecretBytes::from_vec(expected.to_vec()),
			)
			.unwrap();
		let found = provider.get(convention("BLOB")).unwrap().unwrap();
		assert_eq!(found.expose_secret(), expected);

		let batch = provider.get_many(&[("B", convention("BLOB"))]).unwrap();
		assert_eq!(batch.get("B").unwrap().expose_secret(), expected);
	}

	#[test]
	fn value_bytes_reads_text_and_blob_cells_exactly() {
		let conn = Connection::open_in_memory().unwrap();
		conn.execute_batch(
			"CREATE TABLE loose (item TEXT PRIMARY KEY, value ANY) STRICT;\
			 INSERT INTO loose VALUES ('text', 'plain text');\
			 INSERT INTO loose VALUES ('blob', x'00ff80');",
		)
		.unwrap();
		let typed: String = conn
			.query_row(
				"SELECT typeof(value) FROM loose WHERE item = 'text'",
				[],
				|row| row.get(0),
			)
			.unwrap();
		assert_eq!(typed, "text");

		let text = conn
			.query_row(
				"SELECT value FROM loose WHERE item = 'text'",
				[],
				value_bytes,
			)
			.unwrap();
		assert_eq!(text, b"plain text");
		let blob = conn
			.query_row(
				"SELECT value FROM loose WHERE item = 'blob'",
				[],
				value_bytes,
			)
			.unwrap();
		assert_eq!(blob, [0x00, 0xff, 0x80]);
	}

	#[test]
	fn a_legacy_text_value_column_is_still_written_and_read() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		Connection::open(&path)
			.unwrap()
			.execute_batch(
				"CREATE TABLE secrets (item TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;\
				 INSERT INTO secrets VALUES ('project/production/OLD', 'kept');",
			)
			.unwrap();
		let provider = history_provider(path.clone());
		provider
			.set(convention("NEW"), &SecretBytes::from_utf8("fresh"))
			.unwrap();
		assert_eq!(
			provider
				.get(convention("NEW"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"fresh"
		);
		assert_eq!(
			provider
				.get(convention("OLD"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"kept"
		);
		let typed: String = Connection::open(&path)
			.unwrap()
			.query_row(
				"SELECT typeof(value) FROM secrets WHERE item = 'project/production/NEW'",
				[],
				|row| row.get(0),
			)
			.unwrap();
		assert_eq!(typed, "text");

		let error = provider
			.set(convention("BIN"), &SecretBytes::from_vec(vec![0xff, 0xfe]))
			.unwrap_err();
		assert!(error.to_string().contains("non-UTF-8"), "{error}");
	}

	#[test]
	fn set_updates_existing_row() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		provider
			.set(convention("KEY"), &SecretBytes::from_utf8("old"))
			.unwrap();
		provider
			.set(convention("KEY"), &SecretBytes::from_utf8("new"))
			.unwrap();
		assert_eq!(
			provider
				.get(convention("KEY"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"new"
		);
	}

	#[test]
	fn missing_database_and_entry_are_absent_without_creating_a_file() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		assert!(
			provider(path.clone())
				.get(convention("MISSING"))
				.unwrap()
				.is_none()
		);
		assert!(!path.exists());
	}

	#[test]
	fn delete_is_idempotent_and_does_not_create_a_missing_database() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		let provider = provider(path.clone());
		assert!(!provider.delete(convention("KEY")).unwrap());
		assert!(!path.exists());

		provider
			.set(convention("KEY"), &SecretBytes::from_utf8("value"))
			.unwrap();
		assert!(provider.delete(convention("KEY")).unwrap());
		assert!(!provider.delete(convention("KEY")).unwrap());
		assert!(provider.get(convention("KEY")).unwrap().is_none());
	}

	#[test]
	fn delete_leaves_no_plaintext_in_the_database_file() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		let provider = provider(path.clone());
		let plaintext = "PLAINTEXT-CANARY-eb4c1f9a".repeat(8);

		provider
			.set(
				convention("KEY"),
				&SecretBytes::from_utf8(plaintext.clone()),
			)
			.unwrap();

		assert!(
			file_contains(&path, plaintext.as_bytes()),
			"precondition failed: plaintext is not in the file even before delete"
		);

		assert!(provider.delete(convention("KEY")).unwrap());

		assert!(
			!file_contains(&path, plaintext.as_bytes()),
			"deleted plaintext is still readable in {}: PRAGMA secure_delete is not in effect",
			path.display()
		);
	}

	fn file_contains(path: &Path, needle: &[u8]) -> bool {
		let bytes = std::fs::read(path).unwrap();
		bytes.windows(needle.len()).any(|window| window == needle)
	}

	#[test]
	fn uri_round_trips() {
		let provider = provider(PathBuf::from("./my secrets.db"));
		let uri = provider.uri();
		assert_eq!(uri, "sqlite:./my%20secrets.db");
		let reparsed = Box::<dyn Provider>::try_from(uri.as_str()).unwrap();
		assert_eq!(reparsed.uri(), uri);

		let provider = history_provider(PathBuf::from("./my secrets.db"));
		let uri = provider.uri();
		assert_eq!(uri, "sqlite:./my%20secrets.db?history=true");
		let reparsed = Box::<dyn Provider>::try_from(uri.as_str()).unwrap();
		assert_eq!(reparsed.uri(), uri);
	}

	#[test]
	fn history_does_not_change_the_storage_identity() {
		let plain = provider(PathBuf::from("./secrets.db"));
		let with_history = history_provider(PathBuf::from("./secrets.db"));
		assert_ne!(plain.uri(), with_history.uri());
		assert_eq!(plain.storage_identity(), with_history.storage_identity());
	}

	#[test]
	fn relative_path_is_rebased_to_the_manifest() {
		let mut provider = provider(PathBuf::from("data/secrets.db"));
		provider.with_base_dir(Path::new("/project"));
		assert_eq!(
			provider.config.path,
			PathBuf::from("/project/data/secrets.db")
		);
	}

	#[test]
	fn write_target_description_names_the_file_and_item_without_creating_them() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("not-created").join("secrets.db");
		let provider = provider(path.clone());
		let target = provider.describe_write_target(convention("KEY")).unwrap();
		assert!(target.contains(&path.display().to_string()), "{target}");
		assert!(target.contains("project/production/KEY"), "{target}");
		assert!(!path.exists());
	}

	#[cfg(unix)]
	#[test]
	fn database_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt;

		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		provider(path.clone())
			.set(convention("KEY"), &SecretBytes::from_utf8("value"))
			.unwrap();

		let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600);
	}

	#[test]
	fn get_many_reads_multiple_entries_and_omits_missing_ones() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		provider
			.set(convention("ONE"), &SecretBytes::from_utf8("one"))
			.unwrap();
		provider
			.set(convention("TWO"), &SecretBytes::from_utf8("two"))
			.unwrap();

		let results = provider
			.get_many(&[
				("FIRST", convention("ONE")),
				("SECOND", convention("TWO")),
				("MISSING", convention("THREE")),
			])
			.unwrap();
		assert_eq!(results.get("FIRST").unwrap().expose_secret(), b"one");
		assert_eq!(results.get("SECOND").unwrap().expose_secret(), b"two");
		assert!(!results.contains_key("MISSING"));
	}

	#[test]
	fn concurrent_writes_preserve_both_entries() {
		let temp = TempDir::new().unwrap();
		let provider = std::sync::Arc::new(provider(temp.path().join("secrets.db")));
		std::thread::scope(|scope| {
			for (name, value) in [("ONE", "one"), ("TWO", "two")] {
				let provider = std::sync::Arc::clone(&provider);
				scope.spawn(move || {
					provider
						.set(convention(name), &SecretBytes::from_utf8(value))
						.unwrap();
				});
			}
		});
		assert_eq!(
			provider
				.get(convention("ONE"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"one"
		);
		assert_eq!(
			provider
				.get(convention("TWO"))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"two"
		);
	}

	#[test]
	fn concurrent_history_opens_finish_schema_without_trigger_races() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		let provider = std::sync::Arc::new(SqliteProvider::new(SqliteConfig {
			path,
			history: true,
		}));
		provider.connection().expect("seed open");

		let errors = std::sync::Mutex::new(Vec::new());
		std::thread::scope(|scope| {
			for _ in 0..16 {
				let provider = std::sync::Arc::clone(&provider);
				let errors = &errors;
				scope.spawn(move || {
					for _ in 0..20 {
						if let Err(error) = provider.connection() {
							errors.lock().unwrap().push(error.to_string());
						}
					}
				});
			}
		});
		let errors = errors.into_inner().unwrap();
		assert!(
			errors.is_empty(),
			"concurrent history opens failed ({}): {:?}",
			errors.len(),
			errors.into_iter().take(5).collect::<Vec<_>>()
		);

		let conn = provider.connection().expect("final open");
		let trigger_count: i64 = conn
			.query_row(
				"SELECT COUNT(*) FROM sqlite_master \
				 WHERE type = 'trigger' AND name IN ( \
				     'captured_values_destroyed_by_is_write_once', \
				     'captured_values_is_append_only' \
				 )",
				[],
				|row| row.get(0),
			)
			.unwrap();
		assert_eq!(
			trigger_count, 2,
			"both history triggers must exist after concurrent opens"
		);
	}

	#[test]
	fn native_item_addresses_an_arbitrary_row() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		let address = NativeAddress {
			item: "shared/anything".to_string(),
			..Default::default()
		};
		provider
			.set(Address::Native(&address), &SecretBytes::from_utf8("value"))
			.unwrap();
		assert_eq!(
			provider
				.get(Address::Native(&address))
				.unwrap()
				.unwrap()
				.expose_secret(),
			b"value"
		);
	}

	#[test]
	fn unsupported_native_coordinate_is_rejected_even_before_the_database_exists() {
		let temp = TempDir::new().unwrap();
		let provider = provider(temp.path().join("secrets.db"));
		let address = NativeAddress {
			item: "KEY".to_string(),
			field: Some("password".to_string()),
			..Default::default()
		};
		let error = provider.get(Address::Native(&address)).unwrap_err();
		assert!(error.to_string().contains("`field`"), "{error}");
		let error = provider.delete(Address::Native(&address)).unwrap_err();
		assert!(error.to_string().contains("`field`"), "{error}");
		let error = provider
			.get_many(&[("KEY", Address::Native(&address))])
			.unwrap_err();
		assert!(error.to_string().contains("`field`"), "{error}");
	}

	#[test]
	fn a_plain_store_has_no_history_tables() {
		let temp = TempDir::new().unwrap();
		let path = temp.path().join("secrets.db");
		provider(path.clone())
			.set(convention("KEY"), &SecretBytes::from_utf8("v"))
			.unwrap();

		let conn = Connection::open(&path).unwrap();
		let tables: Vec<String> = conn
			.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
			.unwrap()
			.query_map([], |row| row.get(0))
			.unwrap()
			.collect::<std::result::Result<_, _>>()
			.unwrap();
		assert_eq!(tables, ["secrets"]);
	}

	#[test]
	fn foreign_keys_are_enforced_on_every_connection_this_provider_hands_out() {
		let dir = TempDir::new().unwrap();
		let provider = history_provider(dir.path().join("secrets.db"));
		provider
			.set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
			.unwrap();

		let conn = provider.connection().unwrap();
		let enabled: i64 = conn
			.query_row("PRAGMA foreign_keys", [], |row| row.get(0))
			.unwrap();
		assert_eq!(enabled, 1, "foreign key enforcement must be on");

		conn.execute(
			"INSERT INTO value_blobs (item, value_sha256, value_blob) VALUES ('x', 'd', x'00')",
			[],
		)
		.unwrap();
		let blob_id: i64 = conn
			.query_row(
				"SELECT blob_id FROM value_blobs WHERE item = 'x' AND value_sha256 = 'd'",
				[],
				|row| row.get(0),
			)
			.unwrap();

		let orphan = conn.execute(
			"INSERT INTO captured_values (sequence, item, value_sha256, blob_id) \
			 VALUES (99999, 'x', 'd', ?1)",
			params![blob_id],
		);
		let error = orphan.expect_err("a captured value referencing no entry must be refused");
		assert!(
			matches!(
				error.sqlite_error_code(),
				Some(rusqlite::ErrorCode::ConstraintViolation)
			),
			"must be refused by a constraint, got: {error}"
		);
		assert!(
			error.to_string().contains("FOREIGN KEY"),
			"must be refused by the foreign key specifically, got: {error}"
		);
	}

	#[test]
	fn history_is_captured_when_enabled() {
		let dir = TempDir::new().unwrap();
		let db_path = dir.path().join("secrets.db");
		let provider = history_provider(db_path.clone());

		provider
			.set(convention("APP_SECRET"), &SecretBytes::from_utf8("initial"))
			.unwrap();

		let conn = Connection::open(&db_path).unwrap();
		let entries: i64 = conn
			.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
			.unwrap();
		assert_eq!(entries, 1);

		let captured: i64 = conn
			.query_row("SELECT count(*) FROM captured_values", [], |row| row.get(0))
			.unwrap();
		assert_eq!(captured, 1);

		provider.delete(convention("APP_SECRET")).unwrap();

		let entries_after_delete: i64 = conn
			.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
			.unwrap();
		assert_eq!(entries_after_delete, 2);
	}

	#[test]
	fn history_entries_form_a_verifiable_hash_chain() {
		let dir = TempDir::new().unwrap();
		let db_path = dir.path().join("secrets.db");
		let provider = history_provider(db_path.clone());
		provider
			.set(convention("A"), &SecretBytes::from_utf8("one"))
			.unwrap();
		provider
			.set(convention("B"), &SecretBytes::from_utf8("two"))
			.unwrap();
		provider.delete(convention("A")).unwrap();

		let conn = Connection::open(&db_path).unwrap();
		let mut stmt = conn
			.prepare(
				"SELECT sequence, timestamp_ns, operation, previous_hash, entry_hash \
				 FROM entries ORDER BY sequence",
			)
			.unwrap();
		let entries: Vec<(i64, i64, String, String, String)> = stmt
			.query_map([], |row| {
				Ok((
					row.get(0)?,
					row.get(1)?,
					row.get(2)?,
					row.get(3)?,
					row.get(4)?,
				))
			})
			.unwrap()
			.collect::<std::result::Result<_, _>>()
			.unwrap();
		assert_eq!(entries.len(), 3);
		assert_eq!(entries.first().unwrap().3, ZERO_HASH);

		let mut previous = ZERO_HASH.to_string();
		for (sequence, timestamp_ns, operation, previous_hash, entry_hash) in &entries {
			assert_eq!(
				previous_hash, &previous,
				"entry {sequence} breaks the chain"
			);
			let mut captured = conn
				.prepare(
					"SELECT item, value_sha256 FROM captured_values \
					 WHERE sequence = ?1 ORDER BY item",
				)
				.unwrap();
			let values: Vec<CapturedValue> = captured
				.query_map(params![sequence], |row| {
					Ok(CapturedValue {
						item: row.get(0)?,
						value_sha256: row.get(1)?,
					})
				})
				.unwrap()
				.collect::<std::result::Result<_, _>>()
				.unwrap();
			let entry = Entry {
				sequence: *sequence,
				timestamp_ns: *timestamp_ns,
				operation: operation.clone(),
				values,
				previous_hash: previous_hash.clone(),
				hash: String::new(),
			};
			assert_eq!(
				&compute_entry_hash(previous_hash, &entry),
				entry_hash,
				"entry {sequence} does not hash to its stored entry_hash"
			);
			previous = entry_hash.clone();
		}

		let (head_sequence, head_hash): (i64, String) = conn
			.query_row("SELECT sequence, entry_hash FROM head", [], |row| {
				Ok((row.get(0)?, row.get(1)?))
			})
			.unwrap();
		assert_eq!(head_sequence, 3);
		assert_eq!(head_hash, previous);
		assert_eq!(
			entries.get(2).unwrap().2,
			"delete",
			"the last entry records the delete"
		);
	}

	fn ledger_with_three_entries() -> (TempDir, PathBuf, SqliteProvider) {
		let dir = TempDir::new().unwrap();
		let path = dir.path().join("secrets.db");
		let provider = history_provider(path.clone());
		provider
			.set(convention("A"), &SecretBytes::from_utf8("one"))
			.unwrap();
		provider
			.set(convention("B"), &SecretBytes::from_utf8("two"))
			.unwrap();
		provider.delete(convention("A")).unwrap();
		(dir, path, provider)
	}

	fn tamper(path: &Path, sql: &str) {
		let conn = Connection::open(path).unwrap();
		conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
		conn.execute_batch(sql).unwrap();
	}

	fn tamper_delete_entry(path: &Path, sequence: i64) {
		tamper(
			path,
			&format!(
				"DROP TRIGGER IF EXISTS captured_values_is_append_only;\
				 DELETE FROM captured_values WHERE sequence = {sequence};\
				 DELETE FROM entries WHERE sequence = {sequence}"
			),
		);
	}

	#[test]
	fn verify_history_reports_a_clean_chain() {
		let (_dir, path, provider) = ledger_with_three_entries();

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert!(report.is_ok(), "unexpected failure: {:?}", report.failure);
		assert_eq!(report.entries, 3);
		assert_eq!(report.schema_version, SCHEMA_VERSION);
		let expected_head: String = Connection::open(&path)
			.unwrap()
			.query_row(
				"SELECT entry_hash FROM entries ORDER BY sequence DESC LIMIT 1",
				[],
				|row| row.get(0),
			)
			.unwrap();
		assert_eq!(report.head_hash, expected_head);
	}

	#[test]
	fn verify_history_reports_an_empty_ledger_as_verified() {
		let dir = TempDir::new().unwrap();
		let provider = history_provider(dir.path().join("secrets.db"));
		provider.connection().unwrap();

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert!(report.is_ok(), "unexpected failure: {:?}", report.failure);
		assert_eq!(report.entries, 0);
		assert_eq!(report.head_hash, ZERO_HASH);
	}

	#[test]
	fn verify_history_reports_a_mutated_entry_hash() {
		let (_dir, path, provider) = ledger_with_three_entries();
		let forged = "f".repeat(64);
		tamper(
			&path,
			&format!("UPDATE entries SET entry_hash = '{forged}' WHERE sequence = 2"),
		);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert!(!report.is_ok());
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(2),
				reason: HistoryFailureReason::EntryHashMismatch,
			})
		);
	}

	#[test]
	fn verify_history_reports_a_deleted_middle_entry() {
		let (_dir, path, provider) = ledger_with_three_entries();
		tamper_delete_entry(&path, 2);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(report.entries, 2, "the report counts the rows it found");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(2),
				reason: HistoryFailureReason::MissingEntry,
			}),
			"the missing sequence is reported, not the hash break it causes"
		);
	}

	#[test]
	fn verify_history_reports_a_deleted_first_entry() {
		let (_dir, path, provider) = ledger_with_three_entries();
		tamper_delete_entry(&path, 1);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(1),
				reason: HistoryFailureReason::MissingEntry,
			})
		);
	}

	#[test]
	fn verify_history_reports_a_rewritten_backlink() {
		let (_dir, path, provider) = ledger_with_three_entries();
		let forged = "c".repeat(64);
		tamper(
			&path,
			&format!("UPDATE entries SET previous_hash = '{forged}' WHERE sequence = 2"),
		);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(2),
				reason: HistoryFailureReason::PreviousHashMismatch,
			})
		);
	}

	#[test]
	fn verify_history_reports_a_mutated_value_digest() {
		let (_dir, path, provider) = ledger_with_three_entries();
		let forged = "a".repeat(64);
		tamper(
			&path,
			&format!(
				"UPDATE captured_values SET value_sha256 = '{forged}' \
				 WHERE sequence = 1 AND item = 'project/production/A'"
			),
		);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(1),
				reason: HistoryFailureReason::EntryHashMismatch,
			})
		);
	}

	#[test]
	fn verify_history_reports_a_rewritten_head() {
		let (_dir, path, provider) = ledger_with_three_entries();
		let forged = "b".repeat(64);
		tamper(
			&path,
			&format!("UPDATE head SET entry_hash = '{forged}' WHERE singleton = 1"),
		);

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: Some(3),
				reason: HistoryFailureReason::HeadMismatch,
			})
		);
	}

	#[test]
	fn verify_history_reports_a_wrong_schema_version() {
		let (_dir, path, provider) = ledger_with_three_entries();
		tamper(&path, "PRAGMA user_version = 1");

		let report = provider.verify_history().unwrap().expect("a ledger");
		assert_eq!(
			report.failure,
			Some(HistoryFailure {
				sequence: None,
				reason: HistoryFailureReason::SchemaVersionMismatch,
			})
		);
		assert_eq!(report.schema_version, 1);
		assert_eq!(report.entries, 3, "the chain itself still walked cleanly");
	}

	#[test]
	fn verify_history_is_none_without_a_ledger() {
		let dir = TempDir::new().unwrap();
		let path = dir.path().join("secrets.db");
		let plain = provider(path.clone());

		assert_eq!(plain.verify_history().unwrap(), None);
		assert!(!path.exists(), "verification must not create the store");

		plain
			.set(convention("A"), &SecretBytes::from_utf8("one"))
			.unwrap();
		assert_eq!(plain.verify_history().unwrap(), None);
	}

	#[test]
	fn verify_history_rejects_a_missing_history_file() {
		let dir = TempDir::new().unwrap();
		let provider = history_provider(dir.path().join("absent.db"));

		let error = provider.verify_history().unwrap_err().to_string();
		assert!(error.contains("does not exist"), "{error}");
	}

	fn history_with_one_capture(path: &Path) -> (SqliteProvider, Connection, i64) {
		let provider = history_provider(path.to_path_buf());
		provider
			.set(convention("KEY"), &SecretBytes::from_utf8("v"))
			.unwrap();
		let conn = provider.connection().unwrap();
		let blob_id: i64 = conn
			.query_row("SELECT blob_id FROM value_blobs", [], |row| row.get(0))
			.unwrap();
		(provider, conn, blob_id)
	}

	#[test]
	fn a_blob_a_live_snapshot_still_references_cannot_be_deleted() {
		let dir = TempDir::new().unwrap();
		let (_provider, conn, blob_id) = history_with_one_capture(&dir.path().join("secrets.db"));

		let error = conn
			.execute(
				"DELETE FROM value_blobs WHERE blob_id = ?1",
				params![blob_id],
			)
			.expect_err("a blob a live snapshot references must not be deletable");
		assert!(
			error.to_string().contains("FOREIGN KEY"),
			"must be refused by ON DELETE RESTRICT, got: {error}"
		);
	}

	#[test]
	fn a_tombstone_cannot_be_resurrected_even_when_its_value_returns() {
		let dir = TempDir::new().unwrap();
		let path = dir.path().join("secrets.db");
		let (provider, conn, blob_id) = history_with_one_capture(&path);

		conn.execute(
			"INSERT INTO entries (timestamp_ns, operation, previous_hash, entry_hash) \
			 VALUES (0, 'destroy', 'p', 'h')",
			[],
		)
		.unwrap();
		let destroyer: i64 = conn.last_insert_rowid();
		conn.execute(
			"UPDATE head SET sequence = ?1, entry_hash = 'h' WHERE singleton = 1",
			params![destroyer],
		)
		.unwrap();
		conn.execute(
			"UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
			params![destroyer],
		)
		.unwrap();
		conn.execute(
			"DELETE FROM value_blobs WHERE blob_id = ?1",
			params![blob_id],
		)
		.expect("once tombstoned, the blob releases and can be removed");

		provider
			.set(convention("KEY"), &SecretBytes::from_utf8("v"))
			.unwrap();
		let recreated: i64 = conn
			.query_row(
				"SELECT blob_id FROM value_blobs ORDER BY blob_id DESC LIMIT 1",
				[],
				|row| row.get(0),
			)
			.unwrap();
		assert_ne!(
			recreated, blob_id,
			"precondition: AUTOINCREMENT must not reissue the freed id"
		);

		let error = conn
			.execute(
				"UPDATE captured_values SET destroyed_by = NULL WHERE sequence = 1",
				[],
			)
			.expect_err("a tombstone must not be clearable");
		assert!(
			error.to_string().contains("write-once") || error.to_string().contains("FOREIGN KEY"),
			"must be refused by the trigger or the foreign key, got: {error}"
		);
	}

	#[test]
	fn captured_values_rows_cannot_be_deleted_or_their_tombstones_rewritten() {
		let dir = TempDir::new().unwrap();
		let (_provider, conn, _) = history_with_one_capture(&dir.path().join("secrets.db"));

		let deleted = conn
			.execute("DELETE FROM captured_values WHERE sequence = 1", [])
			.expect_err("history rows must not be deletable");
		assert!(
			deleted.to_string().contains("append-only"),
			"must be refused by the append-only trigger, got: {deleted}"
		);

		conn.execute(
			"INSERT INTO entries (timestamp_ns, operation, previous_hash, entry_hash) \
			 VALUES (0, 'destroy', 'p', 'h')",
			[],
		)
		.unwrap();
		let first: i64 = conn.last_insert_rowid();
		conn.execute(
			"UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
			params![first],
		)
		.expect("the first tombstone must be allowed");

		let rewritten = conn
			.execute(
				"UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
				params![first],
			)
			.expect_err("destroyed_by must not be rewritable");
		assert!(
			rewritten.to_string().contains("write-once"),
			"must be refused by the write-once trigger, got: {rewritten}"
		);
	}

	#[test]
	fn a_tombstone_may_not_name_an_entry_at_or_before_its_own_sequence() {
		let dir = TempDir::new().unwrap();
		let (_provider, conn, _) = history_with_one_capture(&dir.path().join("secrets.db"));

		let error = conn
			.execute(
				"UPDATE captured_values SET destroyed_by = 1 WHERE sequence = 1",
				[],
			)
			.expect_err("a value cannot be destroyed by the entry that captured it");
		assert!(
			error.to_string().contains("CHECK"),
			"must be refused by the ordering check, got: {error}"
		);
	}

	#[test]
	fn a_fresh_database_is_created_already_at_the_current_version() {
		let dir = TempDir::new().unwrap();
		let provider = history_provider(dir.path().join("secrets.db"));
		provider
			.set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
			.unwrap();

		let conn = provider.connection().unwrap();
		let version: i64 = conn
			.query_row("PRAGMA user_version", [], |row| row.get(0))
			.unwrap();
		assert_eq!(version, SCHEMA_VERSION);
		assert!(has_current_shape(&conn).unwrap());
	}

	#[test]
	fn a_database_from_an_older_version_is_refused_rather_than_written_to() {
		let dir = TempDir::new().unwrap();
		let db_path = dir.path().join("secrets.db");

		{
			let conn = Connection::open(&db_path).unwrap();
			conn.execute_batch(
				"CREATE TABLE captured_values (\
				     sequence INTEGER NOT NULL,\
				     item TEXT NOT NULL,\
				     value_sha256 TEXT NOT NULL,\
				     destroyed_by INTEGER,\
				     PRIMARY KEY (sequence, item)\
				 ) STRICT;",
			)
			.unwrap();
		}

		let provider = history_provider(db_path.clone());
		let error = provider
			.connection()
			.expect_err("an older database must be refused, not written to");
		let message = error.to_string();
		assert!(
			message.contains("predates the current schema"),
			"the refusal must say what is wrong and what to do, got: {message}"
		);

		let conn = Connection::open(&db_path).unwrap();
		let version: i64 = conn
			.query_row("PRAGMA user_version", [], |row| row.get(0))
			.unwrap();
		assert_eq!(version, 0, "a refused open must not stamp a version");
	}

	#[test]
	fn a_database_from_a_newer_version_is_refused() {
		let dir = TempDir::new().unwrap();
		let db_path = dir.path().join("secrets.db");
		let provider = history_provider(db_path.clone());
		provider
			.set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
			.unwrap();

		Connection::open(&db_path)
			.unwrap()
			.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
			.unwrap();

		let error = provider
			.connection()
			.expect_err("a database from a newer build must be refused");
		assert!(error.to_string().contains("newer version"), "got: {error}");
	}

	#[test]
	fn repeated_captures_of_one_value_store_its_bytes_once() {
		let dir = TempDir::new().unwrap();
		let provider = history_provider(dir.path().join("secrets.db"));

		provider
			.set(convention("APP_SECRET"), &SecretBytes::from_utf8("held"))
			.unwrap();
		for i in 0..4 {
			provider
				.set(
					convention(&format!("OTHER_{i}")),
					&SecretBytes::from_utf8("x"),
				)
				.unwrap();
		}

		let conn = provider.connection().unwrap();
		let captured: i64 = conn
			.query_row(
				"SELECT count(*) FROM captured_values WHERE item = ?1",
				params!["project/production/APP_SECRET"],
				|row| row.get(0),
			)
			.unwrap();
		let blobs: i64 = conn
			.query_row(
				"SELECT count(*) FROM value_blobs WHERE item = ?1",
				params!["project/production/APP_SECRET"],
				|row| row.get(0),
			)
			.unwrap();

		assert!(
			captured > 1,
			"the value should be captured in several snapshots, got {captured}"
		);
		assert_eq!(blobs, 1, "but its bytes should be stored exactly once");
	}
}
