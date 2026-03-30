use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

use dam_core::DamError;

/// A single logged detection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub id: i64,
    pub data_type: String,
    pub destination: String,
    pub action: String,
    pub timestamp: i64,
    pub module_name: String,
    pub value_preview: String,
}

/// Aggregate stats for a single data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEntry {
    pub data_type: String,
    pub count: u64,
    pub redacted: u64,
    pub passed: u64,
    pub top_destinations: Vec<String>,
}

/// SQLite-backed storage for detection log events.
pub struct LogStore {
    conn: Mutex<Connection>,
}

impl LogStore {
    /// Open (or create) a log database at `db_path`, apply schema, enable WAL mode.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, DamError> {
        let conn = Connection::open(db_path).map_err(|e| DamError::Db(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DamError::Db(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS log_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                data_type     TEXT    NOT NULL,
                destination   TEXT    NOT NULL,
                action        TEXT    NOT NULL,
                timestamp     INTEGER NOT NULL,
                module_name   TEXT    NOT NULL,
                value_preview TEXT    NOT NULL
            );",
        )
        .map_err(|e| DamError::Db(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a detection event. Timestamp is set to current UNIX epoch seconds.
    pub fn log_event(
        &self,
        data_type: &str,
        destination: &str,
        action: &str,
        module_name: &str,
        value_preview: &str,
    ) -> Result<(), DamError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        conn.execute(
            "INSERT INTO log_events (data_type, destination, action, timestamp, module_name, value_preview)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![data_type, destination, action, now, module_name, value_preview],
        )
        .map_err(|e| DamError::Db(e.to_string()))?;

        Ok(())
    }

    /// Return the most recent events, ordered newest first.
    /// If `limit` is `None`, defaults to 100.
    pub fn query_all(&self, limit: Option<u32>) -> Result<Vec<LogEvent>, DamError> {
        let limit = limit.unwrap_or(100);
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, data_type, destination, action, timestamp, module_name, value_preview
                 FROM log_events
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(LogEvent {
                    id: row.get(0)?,
                    data_type: row.get(1)?,
                    destination: row.get(2)?,
                    action: row.get(3)?,
                    timestamp: row.get(4)?,
                    module_name: row.get(5)?,
                    value_preview: row.get(6)?,
                })
            })
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| DamError::Db(e.to_string()))?);
        }
        Ok(events)
    }

    /// Return events for a specific destination host, ordered newest first.
    pub fn query_by_destination(
        &self,
        host: &str,
        limit: Option<u32>,
    ) -> Result<Vec<LogEvent>, DamError> {
        let limit = limit.unwrap_or(100);
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, data_type, destination, action, timestamp, module_name, value_preview
                 FROM log_events
                 WHERE destination = ?1
                 ORDER BY id DESC
                 LIMIT ?2",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![host, limit], |row| {
                Ok(LogEvent {
                    id: row.get(0)?,
                    data_type: row.get(1)?,
                    destination: row.get(2)?,
                    action: row.get(3)?,
                    timestamp: row.get(4)?,
                    module_name: row.get(5)?,
                    value_preview: row.get(6)?,
                })
            })
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| DamError::Db(e.to_string()))?);
        }
        Ok(events)
    }

    /// Return events for a specific data type, ordered newest first.
    pub fn query_by_type(
        &self,
        data_type: &str,
        limit: Option<u32>,
    ) -> Result<Vec<LogEvent>, DamError> {
        let limit = limit.unwrap_or(100);
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, data_type, destination, action, timestamp, module_name, value_preview
                 FROM log_events
                 WHERE data_type = ?1
                 ORDER BY id DESC
                 LIMIT ?2",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![data_type, limit], |row| {
                Ok(LogEvent {
                    id: row.get(0)?,
                    data_type: row.get(1)?,
                    destination: row.get(2)?,
                    action: row.get(3)?,
                    timestamp: row.get(4)?,
                    module_name: row.get(5)?,
                    value_preview: row.get(6)?,
                })
            })
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| DamError::Db(e.to_string()))?);
        }
        Ok(events)
    }

    /// Aggregate stats: count per data_type, with pass/redact breakdown and top destinations.
    pub fn stats(&self) -> Result<Vec<StatEntry>, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;

        let mut type_stmt = conn
            .prepare(
                "SELECT data_type,
                        COUNT(*) as cnt,
                        SUM(CASE WHEN action = 'redacted' OR action = 'tokenized' THEN 1 ELSE 0 END) as redacted,
                        SUM(CASE WHEN action = 'passed' THEN 1 ELSE 0 END) as passed
                 FROM log_events
                 GROUP BY data_type
                 ORDER BY cnt DESC",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let type_rows: Vec<(String, u64, u64, u64)> = type_stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|e| DamError::Db(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut dest_stmt = conn
            .prepare(
                "SELECT destination, COUNT(*) as cnt
                 FROM log_events
                 WHERE data_type = ?1
                 GROUP BY destination
                 ORDER BY cnt DESC
                 LIMIT 5",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut entries = Vec::with_capacity(type_rows.len());
        for (data_type, count, redacted, passed) in type_rows {
            let top_destinations: Vec<String> = dest_stmt
                .query_map(params![&data_type], |row| row.get(0))
                .map_err(|e| DamError::Db(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| DamError::Db(e.to_string()))?;

            entries.push(StatEntry {
                data_type,
                count,
                redacted,
                passed,
                top_destinations,
            });
        }

        Ok(entries)
    }

    /// Total number of logged events.
    pub fn count(&self) -> Result<usize, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM log_events", [], |row| row.get(0))
            .map_err(|e| DamError::Db(e.to_string()))?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_log.db");
        let store = LogStore::open(&db_path).unwrap();
        (store, dir)
    }

    #[test]
    fn test_open_creates_db() {
        let (store, _dir) = temp_store();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_open_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let _store1 = LogStore::open(&db_path).unwrap();
        // Opening again should not fail (CREATE TABLE IF NOT EXISTS).
        let store2 = LogStore::open(&db_path).unwrap();
        assert_eq!(store2.count().unwrap(), 0);
    }

    #[test]
    fn test_log_and_count() {
        let (store, _dir) = temp_store();
        store
            .log_event(
                "email",
                "api.openai.com",
                "tokenized",
                "detect-pii",
                "test...",
            )
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);

        store
            .log_event("phone", "example.com", "logged", "detect-pii", "555-...")
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_query_all_ordering() {
        let (store, _dir) = temp_store();
        store
            .log_event("email", "a.com", "logged", "mod-a", "a@b...")
            .unwrap();
        store
            .log_event("phone", "b.com", "logged", "mod-b", "555-...")
            .unwrap();
        store
            .log_event("ssn", "c.com", "logged", "mod-c", "123-...")
            .unwrap();

        let events = store.query_all(None).unwrap();
        assert_eq!(events.len(), 3);
        // Newest first (highest id first).
        assert_eq!(events[0].data_type, "ssn");
        assert_eq!(events[1].data_type, "phone");
        assert_eq!(events[2].data_type, "email");
    }

    #[test]
    fn test_query_all_with_limit() {
        let (store, _dir) = temp_store();
        for i in 0..10 {
            store
                .log_event("email", "x.com", "logged", "mod", &format!("{i}..."))
                .unwrap();
        }
        let events = store.query_all(Some(3)).unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_query_by_destination() {
        let (store, _dir) = temp_store();
        store
            .log_event("email", "a.com", "logged", "mod", "a@b...")
            .unwrap();
        store
            .log_event("phone", "b.com", "logged", "mod", "555-...")
            .unwrap();
        store
            .log_event("ssn", "a.com", "logged", "mod", "123-...")
            .unwrap();

        let events = store.query_by_destination("a.com", None).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.destination == "a.com"));
    }

    #[test]
    fn test_query_by_destination_empty() {
        let (store, _dir) = temp_store();
        store
            .log_event("email", "a.com", "logged", "mod", "a@b...")
            .unwrap();

        let events = store.query_by_destination("nonexistent.com", None).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_query_by_type() {
        let (store, _dir) = temp_store();
        store
            .log_event("email", "a.com", "logged", "mod", "a@b...")
            .unwrap();
        store
            .log_event("email", "b.com", "tokenized", "mod", "c@d...")
            .unwrap();
        store
            .log_event("phone", "a.com", "logged", "mod", "555-...")
            .unwrap();

        let events = store.query_by_type("email", None).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.data_type == "email"));
    }

    #[test]
    fn test_query_by_type_with_limit() {
        let (store, _dir) = temp_store();
        for _ in 0..5 {
            store
                .log_event("email", "x.com", "logged", "mod", "a@b...")
                .unwrap();
        }
        let events = store.query_by_type("email", Some(2)).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_stats_empty() {
        let (store, _dir) = temp_store();
        let stats = store.stats().unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn test_stats_aggregation() {
        let (store, _dir) = temp_store();
        store
            .log_event("email", "a.com", "logged", "mod", "a@b...")
            .unwrap();
        store
            .log_event("email", "b.com", "logged", "mod", "c@d...")
            .unwrap();
        store
            .log_event("email", "a.com", "logged", "mod", "e@f...")
            .unwrap();
        store
            .log_event("phone", "a.com", "logged", "mod", "555-...")
            .unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.len(), 2);

        // email has 3 events, phone has 1 — ordered by count descending.
        assert_eq!(stats[0].data_type, "email");
        assert_eq!(stats[0].count, 3);
        // top destinations: a.com (2), b.com (1).
        assert_eq!(stats[0].top_destinations[0], "a.com");
        assert_eq!(stats[0].top_destinations[1], "b.com");

        assert_eq!(stats[1].data_type, "phone");
        assert_eq!(stats[1].count, 1);
        assert_eq!(stats[1].top_destinations, vec!["a.com"]);
    }

    #[test]
    fn test_stats_top_destinations_capped() {
        let (store, _dir) = temp_store();
        for i in 0..8 {
            store
                .log_event("email", &format!("host{i}.com"), "logged", "mod", "x...")
                .unwrap();
        }
        let stats = store.stats().unwrap();
        assert_eq!(stats[0].top_destinations.len(), 5);
    }

    #[test]
    fn test_log_event_fields_roundtrip() {
        let (store, _dir) = temp_store();
        store
            .log_event(
                "cc",
                "payments.example.com",
                "tokenized",
                "detect-pii",
                "4111...",
            )
            .unwrap();

        let events = store.query_all(None).unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.data_type, "cc");
        assert_eq!(e.destination, "payments.example.com");
        assert_eq!(e.action, "tokenized");
        assert_eq!(e.module_name, "detect-pii");
        assert_eq!(e.value_preview, "4111...");
        assert!(e.id > 0);
        assert!(e.timestamp > 0);
    }

    #[test]
    fn test_count_after_multiple_inserts() {
        let (store, _dir) = temp_store();
        for i in 0..25 {
            store
                .log_event("email", "x.com", "logged", "mod", &format!("{i}..."))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 25);
    }
}
