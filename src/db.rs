//! SQLite persistence: schema, WAL pragmas, tail-position metadata and
//! batched inserts.

use rusqlite::{params, Connection, Result};

use crate::parser::LogEntry;

/// Run once: pragmas + schema (idempotent). Existing databases are migrated
/// in place: the `source_id` column and `sources` table are added on first
/// open, attributing already-stored rows (and any future default) to 0.
pub fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = OFF;
         CREATE TABLE IF NOT EXISTS requests (
             id        INTEGER PRIMARY KEY,
             source_id INTEGER NOT NULL DEFAULT 0,
             ts        INTEGER NOT NULL,
             ip        TEXT    NOT NULL,
             method    TEXT    NOT NULL DEFAULT '',
             path      TEXT    NOT NULL DEFAULT '',
             protocol  TEXT    NOT NULL DEFAULT '',
             status    INTEGER NOT NULL,
             bytes     INTEGER NOT NULL DEFAULT -1,
             referer   TEXT    NOT NULL DEFAULT '',
             ua        TEXT    NOT NULL DEFAULT ''
         );
         CREATE INDEX IF NOT EXISTS idx_requests_ts     ON requests(ts);
         CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
         CREATE INDEX IF NOT EXISTS idx_requests_path   ON requests(path);
         CREATE INDEX IF NOT EXISTS idx_requests_ip     ON requests(ip);
         CREATE INDEX IF NOT EXISTS idx_requests_ip_ts  ON requests(ip, ts);
         CREATE TABLE IF NOT EXISTS sources (
             id   INTEGER PRIMARY KEY,
             name TEXT UNIQUE NOT NULL
         );
         CREATE TABLE IF NOT EXISTS meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )?;
    let mut st = conn.prepare("PRAGMA table_info(requests)")?;
    let mut rows = st.query([])?;
    let mut has_source = false;
    while let Some(r) = rows.next()? {
        let name: String = r.get(1)?;
        if name == "source_id" {
            has_source = true;
            break;
        }
    }
    if !has_source {
        conn.execute(
            "ALTER TABLE requests ADD COLUMN source_id INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    // Index created after the ALTER so legacy databases migrate cleanly.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_requests_src ON requests(source_id)",
        [],
    )?;
    Ok(())
}

/// Open (or create) the database and apply schema/pragmas.
pub fn open(path: &str) -> Result<Connection> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut st = conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
    let mut rows = st.query(params![key])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Insert a batch inside one transaction; prepared statement is reused
/// across the batch. Each item carries its source id (log file).
pub fn insert_many(conn: &mut Connection, items: &[(i64, LogEntry)]) -> Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    let tx = conn.transaction()?;
    insert_many_tx(&tx, items)?;
    tx.commit()?;
    Ok(items.len())
}

/// Insert a batch inside an existing (import) transaction.
pub fn insert_many_tx(tx: &rusqlite::Transaction, items: &[(i64, LogEntry)]) -> Result<()> {
    let mut st = tx.prepare(
        "INSERT INTO requests (source_id, ts, ip, method, path, protocol, status, bytes, referer, ua)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    for (sid, e) in items {
        st.execute(params![
            sid,
            e.ts,
            e.ip,
            e.method,
            e.path,
            e.protocol,
            e.status,
            e.bytes,
            e.referer,
            e.user_agent
        ])?;
    }
    Ok(())
}

/// Look up (creating if needed) the source id for one configured log path.
pub fn ensure_source(conn: &Connection, name: &str) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO sources (name) VALUES (?1)",
        params![name],
    )?;
    conn.query_row("SELECT id FROM sources WHERE name = ?1", params![name], |r| {
        r.get(0)
    })
}

/// Every configured source with its request count (for the dashboard tabs).
pub fn sources_with_counts(conn: &Connection) -> Result<Vec<(i64, String, i64)>> {
    let mut st = conn.prepare(
        "SELECT s.id, s.name, COUNT(r.id)
         FROM sources s LEFT JOIN requests r ON r.source_id = s.id
         GROUP BY s.id ORDER BY s.name",
    )?;
    let mut rows = st.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?, r.get(2)?));
    }
    Ok(out)
}

pub fn total_requests(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::LogEntry;

    fn entry(ts: i64) -> LogEntry {
        LogEntry {
            ts,
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
            protocol: "HTTP/1.1".into(),
            status: 200,
            bytes: 42,
            referer: String::new(),
            user_agent: String::new(),
        }
    }

    #[test]
    fn schema_and_batch() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        let items: Vec<(i64, LogEntry)> = (0..50).map(|i| (0, entry(i as i64))).collect();
        assert_eq!(insert_many(&mut conn, &items).unwrap(), 50);
        assert_eq!(total_requests(&conn).unwrap(), 50);
        insert_many(&mut conn, &[]).unwrap(); // no-op
        assert_eq!(total_requests(&conn).unwrap(), 50);
    }

    #[test]
    fn source_attribution_and_migration() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        let a = ensure_source(&conn, "/logs/a.log").unwrap();
        let b = ensure_source(&conn, "/logs/b.log").unwrap();
        assert_ne!(a, b);
        // same name → same id
        assert_eq!(ensure_source(&conn, "/logs/a.log").unwrap(), a);
        insert_many(
            &mut conn,
            &[(a, entry(1)), (a, entry(2)), (b, entry(3))],
        )
        .unwrap();
        let rows = sources_with_counts(&conn).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|(id, name, c)| *id == a && name == "/logs/a.log" && *c == 2));
        assert!(rows.iter().any(|(id, name, c)| *id == b && name == "/logs/b.log" && *c == 1));
    }

    #[test]
    fn legacy_schema_migrates() {
        let conn = Connection::open_in_memory().unwrap();
        // Pre-feature schema: no source_id column, no sources table.
        conn.execute_batch(
            "CREATE TABLE requests (
                 id       INTEGER PRIMARY KEY,
                 ts       INTEGER NOT NULL,
                 ip       TEXT    NOT NULL,
                 method   TEXT    NOT NULL DEFAULT '',
                 path     TEXT    NOT NULL DEFAULT '',
                 protocol TEXT    NOT NULL DEFAULT '',
                 status   INTEGER NOT NULL,
                 bytes    INTEGER NOT NULL DEFAULT -1,
                 referer  TEXT    NOT NULL DEFAULT '',
                 ua       TEXT    NOT NULL DEFAULT ''
             );
             INSERT INTO requests (ts, ip, path, status) VALUES (1, '1.1.1.1', '/', 200);
             CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .unwrap();
        init(&conn).unwrap(); // must add source_id + sources, not fail
        assert_eq!(total_requests(&conn).unwrap(), 1);
        // legacy row defaults to source 0; a new insertion with a real
        // source id works after migration
        let sid = ensure_source(&conn, "/logs/new.log").unwrap();
        let e = entry(2);
        let mut conn = conn;
        insert_many(&mut conn, &[(sid, e)]).unwrap();
        assert_eq!(total_requests(&conn).unwrap(), 2);
    }

    #[test]
    fn meta_roundtrip_and_update() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        assert!(meta_get(&conn, "offset").unwrap().is_none());
        meta_set(&conn, "offset", "1234").unwrap();
        assert_eq!(meta_get(&conn, "offset").unwrap().as_deref(), Some("1234"));
        meta_set(&conn, "offset", "5678").unwrap();
        assert_eq!(meta_get(&conn, "offset").unwrap().as_deref(), Some("5678"));
    }

    #[test]
    fn duplicate_insert_allowed() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        let e = entry(1);
        insert_many(&mut conn, &[(0, e.clone())]).unwrap();
        insert_many(&mut conn, &[(0, e)]).unwrap();
        assert_eq!(total_requests(&conn).unwrap(), 2);
    }
}
