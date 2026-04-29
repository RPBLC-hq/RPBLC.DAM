use dam_core::{EventSink, LogEvent, LogWriteError};
use rusqlite::{Connection, params};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const LEGACY_OPERATION_ID: &str = "legacy";
const LEGACY_EVENT_TYPE: &str = "legacy";
const LEGACY_MESSAGE: &str = "legacy log event migrated without raw preview";
const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum LogStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type LogStoreResult<T> = Result<T, LogStoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub operation_id: String,
    pub level: String,
    pub event_type: String,
    pub kind: Option<String>,
    pub reference: Option<String>,
    pub action: Option<String>,
    pub message: String,
}

pub struct LogStore {
    conn: Mutex<Connection>,
}

impl LogStore {
    pub fn open(path: impl AsRef<Path>) -> LogStoreResult<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        Self::from_connection_with_path(conn, Some(path))
    }

    pub fn open_in_memory() -> LogStoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> LogStoreResult<Self> {
        Self::from_connection_with_path(conn, None)
    }

    fn from_connection_with_path(conn: Connection, path: Option<&Path>) -> LogStoreResult<Self> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                level TEXT NOT NULL,
                event_type TEXT NOT NULL,
                kind TEXT,
                reference TEXT,
                action TEXT,
                message TEXT NOT NULL
            );
            ",
        )?;

        migrate_log_events_schema(&conn, path)?;

        conn.execute_batch(
            "

            CREATE INDEX IF NOT EXISTS idx_log_events_operation_id
                ON log_events(operation_id);

            CREATE INDEX IF NOT EXISTS idx_log_events_event_type
                ON log_events(event_type);
            ",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record(&self, event: &LogEvent) -> LogStoreResult<()> {
        let conn = self.conn.lock().expect("log sqlite mutex poisoned");
        let kind = event.kind.map(|kind| kind.tag().to_string());
        let reference = event.reference.as_ref().map(|reference| reference.key());

        conn.execute(
            "
            INSERT INTO log_events (
                timestamp,
                operation_id,
                level,
                event_type,
                kind,
                reference,
                action,
                message
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ",
            params![
                event.timestamp,
                event.operation_id.as_str(),
                event.level.tag(),
                event.event_type.tag(),
                kind,
                reference,
                event.action.as_deref(),
                event.message.as_str()
            ],
        )?;

        Ok(())
    }

    pub fn list(&self) -> LogStoreResult<Vec<LogEntry>> {
        let conn = self.conn.lock().expect("log sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "
            SELECT id, timestamp, operation_id, level, event_type, kind, reference, action, message
            FROM log_events
            ORDER BY id DESC
            ",
        )?;

        let entries = stmt
            .query_map([], |row| {
                Ok(LogEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    operation_id: row.get(2)?,
                    level: row.get(3)?,
                    event_type: row.get(4)?,
                    kind: row.get(5)?,
                    reference: row.get(6)?,
                    action: row.get(7)?,
                    message: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    pub fn count(&self) -> LogStoreResult<u64> {
        let conn = self.conn.lock().expect("log sqlite mutex poisoned");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM log_events", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

fn migrate_log_events_schema(conn: &Connection, path: Option<&Path>) -> LogStoreResult<()> {
    let columns = table_columns(conn)?;
    if should_rebuild_legacy_schema(&columns) {
        if let Some(path) = path {
            backup_legacy_database(path)?;
        }
        rebuild_legacy_log_events_schema(conn, &columns)?;
        set_schema_version(conn)?;
        return Ok(());
    }

    ensure_column(
        conn,
        &columns,
        "operation_id",
        &format!("operation_id TEXT NOT NULL DEFAULT '{LEGACY_OPERATION_ID}'"),
    )?;
    ensure_column(
        conn,
        &columns,
        "level",
        "level TEXT NOT NULL DEFAULT 'info'",
    )?;
    ensure_column(
        conn,
        &columns,
        "event_type",
        &format!("event_type TEXT NOT NULL DEFAULT '{LEGACY_EVENT_TYPE}'"),
    )?;
    ensure_column(conn, &columns, "kind", "kind TEXT")?;
    ensure_column(conn, &columns, "reference", "reference TEXT")?;
    ensure_column(conn, &columns, "action", "action TEXT")?;
    ensure_column(
        conn,
        &columns,
        "message",
        &format!("message TEXT NOT NULL DEFAULT '{LEGACY_MESSAGE}'"),
    )?;

    set_schema_version(conn)?;
    Ok(())
}

fn should_rebuild_legacy_schema(columns: &[String]) -> bool {
    ["data_type", "destination", "module_name", "value_preview"]
        .iter()
        .any(|column| has_column(columns, column))
}

fn rebuild_legacy_log_events_schema(conn: &Connection, columns: &[String]) -> rusqlite::Result<()> {
    let mut insert_columns = vec![
        "timestamp".to_string(),
        "operation_id".to_string(),
        "level".to_string(),
        "event_type".to_string(),
        "kind".to_string(),
        "reference".to_string(),
        "action".to_string(),
        "message".to_string(),
    ];
    let mut select_values = vec![
        if has_column(columns, "timestamp") {
            "timestamp".to_string()
        } else {
            "0".to_string()
        },
        format!("'{LEGACY_OPERATION_ID}'"),
        "'info'".to_string(),
        format!("'{LEGACY_EVENT_TYPE}'"),
        if has_column(columns, "data_type") {
            "data_type".to_string()
        } else {
            "NULL".to_string()
        },
        "NULL".to_string(),
        if has_column(columns, "action") {
            "action".to_string()
        } else {
            "NULL".to_string()
        },
        legacy_message_expr(columns),
    ];

    if has_column(columns, "id") {
        insert_columns.insert(0, "id".to_string());
        select_values.insert(0, "id".to_string());
    }

    conn.execute_batch(&format!(
        "
        BEGIN IMMEDIATE;

        DROP TABLE IF EXISTS log_events_new;

        CREATE TABLE log_events_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            operation_id TEXT NOT NULL,
            level TEXT NOT NULL,
            event_type TEXT NOT NULL,
            kind TEXT,
            reference TEXT,
            action TEXT,
            message TEXT NOT NULL
        );

        INSERT INTO log_events_new ({insert_columns})
            SELECT {select_values}
            FROM log_events;

        DROP TABLE log_events;

        ALTER TABLE log_events_new RENAME TO log_events;

        COMMIT;
        ",
        insert_columns = insert_columns.join(", "),
        select_values = select_values.join(", "),
    ))
}

fn legacy_message_expr(columns: &[String]) -> String {
    let mut expr = format!("'{LEGACY_MESSAGE}'");
    if has_column(columns, "data_type") {
        expr.push_str(" || '; kind=' || COALESCE(data_type, '')");
    }
    if has_column(columns, "module_name") {
        expr.push_str(" || '; module=' || COALESCE(module_name, '')");
    }
    if has_column(columns, "destination") {
        expr.push_str(" || '; destination=' || COALESCE(destination, '')");
    }
    expr
}

fn backup_legacy_database(path: &Path) -> std::io::Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_secs();
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "log.db".into());
    let backup_path = path.with_file_name(format!("{file_name}.pre-migration-{timestamp}.bak"));
    fs::copy(path, backup_path)?;
    Ok(())
}

fn set_schema_version(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
}

fn table_columns(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(log_events)")?;
    stmt.query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()
}

fn has_column(columns: &[String], name: &str) -> bool {
    columns.iter().any(|column| column == name)
}

fn ensure_column(
    conn: &Connection,
    columns: &[String],
    name: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    if has_column(columns, name) {
        return Ok(());
    }

    conn.execute_batch(&format!("ALTER TABLE log_events ADD COLUMN {definition};"))
}

impl EventSink for LogStore {
    fn record(&self, event: &LogEvent) -> Result<(), LogWriteError> {
        LogStore::record(self, event).map_err(|error| LogWriteError::new(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{LogEventType, LogLevel, Reference, SensitiveType};

    fn event() -> LogEvent {
        LogEvent::new(
            "op-1",
            LogLevel::Info,
            LogEventType::VaultWrite,
            "vault write succeeded",
        )
        .with_kind(SensitiveType::Email)
        .with_reference(Reference {
            kind: SensitiveType::Email,
            id: "7B2HkqFn9xR4mWpD3nYvKt".to_string(),
        })
        .with_action("vault_write_succeeded")
    }

    #[test]
    fn record_then_list_returns_entry() {
        let store = LogStore::open_in_memory().unwrap();

        store.record(&event()).unwrap();

        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation_id, "op-1");
        assert_eq!(entries[0].level, "info");
        assert_eq!(entries[0].event_type, "vault_write");
        assert_eq!(entries[0].kind, Some("email".to_string()));
        assert_eq!(
            entries[0].reference,
            Some("email:7B2HkqFn9xR4mWpD3nYvKt".to_string())
        );
        assert_eq!(entries[0].action, Some("vault_write_succeeded".to_string()));
    }

    #[test]
    fn entries_persist_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("log.db");

        {
            let store = LogStore::open(&db_path).unwrap();
            store.record(&event()).unwrap();
        }

        let store = LogStore::open(&db_path).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn opens_legacy_log_schema_without_exposing_value_preview() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy-log.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "
                CREATE TABLE log_events (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    data_type     TEXT    NOT NULL,
                    destination   TEXT    NOT NULL,
                    action        TEXT    NOT NULL,
                    timestamp     INTEGER NOT NULL,
                    module_name   TEXT    NOT NULL,
                    value_preview TEXT    NOT NULL
                );

                INSERT INTO log_events (
                    data_type,
                    destination,
                    action,
                    timestamp,
                    module_name,
                    value_preview
                )
                VALUES (
                    'email',
                    'stdout',
                    'tokenize',
                    1,
                    'dam-filter',
                    'banana@banana.com'
                );
                ",
            )
            .unwrap();
        }

        let store = LogStore::open(&db_path).unwrap();
        let entries = store.list().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation_id, LEGACY_OPERATION_ID);
        assert_eq!(entries[0].level, "info");
        assert_eq!(entries[0].event_type, LEGACY_EVENT_TYPE);
        assert_eq!(entries[0].kind, Some("email".to_string()));
        assert!(entries[0].message.contains(LEGACY_MESSAGE));
        assert!(entries[0].message.contains("kind=email"));
        assert!(entries[0].message.contains("module=dam-filter"));
        assert!(entries[0].message.contains("destination=stdout"));
        assert!(!format!("{:?}", entries[0]).contains("banana@banana.com"));
        assert_eq!(
            Connection::open(&db_path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        assert!(fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".pre-migration-")
        }));

        store.record(&event()).unwrap();
        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation_id, "op-1");
    }

    #[test]
    fn implements_event_sink_contract() {
        let store = LogStore::open_in_memory().unwrap();
        let sink: &dyn EventSink = &store;

        sink.record(&event()).unwrap();

        assert_eq!(store.count().unwrap(), 1);
    }
}
