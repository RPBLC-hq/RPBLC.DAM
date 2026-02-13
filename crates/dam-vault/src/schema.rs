use rusqlite::Connection;

/// Apply the vault database schema.
pub fn apply_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS entries (
            ref_id      TEXT PRIMARY KEY,
            pii_type    TEXT NOT NULL,
            ciphertext  BLOB NOT NULL,
            dek_enc     BLOB NOT NULL,
            iv          BLOB NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER,
            source      TEXT,
            label       TEXT
        );

        CREATE TABLE IF NOT EXISTS consent (
            ref_id      TEXT NOT NULL,
            accessor    TEXT NOT NULL,
            purpose     TEXT NOT NULL,
            allowed     INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER,
            PRIMARY KEY (ref_id, accessor, purpose)
        );

        CREATE TABLE IF NOT EXISTS audit (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ref_id      TEXT NOT NULL,
            accessor    TEXT NOT NULL,
            purpose     TEXT NOT NULL,
            action      TEXT NOT NULL,
            granted     INTEGER NOT NULL,
            ts          INTEGER NOT NULL,
            detail      TEXT,
            prev_hash   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(pii_type);
        CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at)
            WHERE expires_at IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_audit_ref ON audit(ref_id);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
        CREATE INDEX IF NOT EXISTS idx_consent_accessor ON consent(accessor);
        ",
    )
}
