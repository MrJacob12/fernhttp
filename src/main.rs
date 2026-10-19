//! fernhttp — Apache log tailer + SQLite history + real-time dashboard.

mod config;
mod db;
mod json;
mod parser;
mod server;
mod signals;
mod stats;
mod tailer;
mod ua;

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::db::{meta_get, meta_set};
use crate::parser::LogEntry;
use crate::server::Shared;
use crate::tailer::{TailMsg, Tailer};

const META_OFFSET: &str = "offset";
const META_FP: &str = "fp";
const BATCH_MAX: usize = 1000;
const FLUSH_EVERY: Duration = Duration::from_secs(1);

/// Meta key scoped to one log file. The legacy bare `offset`/`fp` keys still
/// cover the single-file case (first configured path), so old databases keep
/// working; multi-file setups get one key pair per path.
fn meta_key(prefix: &str, path: &Path) -> String {
    format!("{prefix}:{}", path.display())
}

/// Saved tail position for a path: per-path keys first, legacy single-file
/// keys as fallback for the first configured path. `None` → first-run import.
fn saved_position(conn: &Connection, path: &Path, idx: usize) -> Option<(u64, u64)> {
    let per = (
        meta_get(conn, &meta_key(META_OFFSET, path)).ok().flatten(),
        meta_get(conn, &meta_key(META_FP, path)).ok().flatten(),
    );
    let legacy = (
        meta_get(conn, META_OFFSET).ok().flatten(),
        meta_get(conn, META_FP).ok().flatten(),
    );
    let (o, f) = match per {
        (Some(o), Some(f)) => (o, f),
        _ if idx == 0 => match legacy {
            (Some(o), Some(f)) => (o, f),
            _ => return None,
        },
        _ => return None,
    };
    match (o.parse::<u64>(), f.parse::<u64>()) {
        (Ok(o), Ok(f)) => Some((o, f)),
        _ => None,
    }
}

/// Persist every per-path position plus the legacy keys (from the first
/// path) for downgrade compatibility.
fn persist_positions(conn: &Connection, positions: &HashMap<PathBuf, (u64, u64)>) {
    for (path, (o, f)) in positions {
        let _ = meta_set(conn, &meta_key(META_OFFSET, path), &o.to_string());
        let _ = meta_set(conn, &meta_key(META_FP, path), &f.to_string());
    }
    if let Some((o, f)) = positions.values().next() {
        let _ = meta_set(conn, META_OFFSET, &o.to_string());
        let _ = meta_set(conn, META_FP, &f.to_string());
    }
}

fn main() {
    signals::install();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match config::load(&args) {
        Ok(c) => c,
        Err(e) if e == "help" => {
            println!("{}", config::usage());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{}", config::usage());
            std::process::exit(2);
        }
    };

    // A directory can't be a log file (that's what --logs-dir is for); fail
    // loudly instead of spinning on "read failed: Is a directory" forever.
    for path in &cfg.log {
        if std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false) {
            eprintln!(
                "error: '{}' is a directory, not a log file — use --logs-dir to tail all logs in a directory",
                path.display()
            );
            std::process::exit(2);
        }
    }

    let db_path = cfg.db.to_string_lossy().into_owned();
    let mut conn = match db::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot open database {}: {e}", cfg.db.display());
            std::process::exit(1);
        }
    };

    // Resume stored positions or first-run import per file. Files without a
    // saved position are imported in full; the rest resume at their offset.
    // Each log gets a stable source id for the dashboard tabs.
    let mut resume: Vec<(PathBuf, u64, u64, i64)> = Vec::with_capacity(cfg.log.len());
    let mut positions: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut src_paths: HashMap<i64, PathBuf> = HashMap::new();
    let mut imported_ok: u64 = 0;
    let mut imported_invalid: u64 = 0;
    let mut imported_files: usize = 0;
    for (i, path) in cfg.log.iter().enumerate() {
        let source_id = db::ensure_source(&conn, &path.display().to_string()).unwrap_or(0);
        match saved_position(&conn, path, i) {
            Some((o, f)) => {
                println!("fernhttp: resuming {} at offset {o}", path.display());
                resume.push((path.clone(), o, f, source_id));
                positions.insert(path.clone(), (o, f));
            }
            None => {
                let (ok, invalid, offset, fp) = import_initial(path, &mut conn, source_id);
                println!(
                    "fernhttp: imported {} — {ok} entries, {invalid} unparseable, offset {offset}",
                    path.display()
                );
                imported_ok += ok;
                imported_invalid += invalid;
                imported_files += 1;
                resume.push((path.clone(), offset, fp, source_id));
                positions.insert(path.clone(), (offset, fp));
            }
        }
        src_paths.insert(source_id, path.clone());
    }
    if imported_files > 0 {
        println!(
            "fernhttp: initial import finished — {imported_ok} entries, {imported_invalid} unparseable across {imported_files} file(s)"
        );
    }

    let shared = Shared::new(&db_path);
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    server::start(shared.clone(), &cfg.host, cfg.port, ready_tx);
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: server thread vanished: {e}");
            std::process::exit(1);
        }
    }

    // Tailer thread: polls every configured log, ships parsed chunks.
    let (tx, rx) = mpsc::channel::<TailMsg>();
    let poll_ms = cfg.poll_ms;
    std::thread::spawn(move || {
        let mut tailer = Tailer::resume(resume);
        while !signals::STOP.load(Ordering::SeqCst) {
            tailer.poll(&tx);
            std::thread::sleep(Duration::from_millis(poll_ms));
        }
    });

    let log_list = cfg
        .log
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "fernhttp: dashboard on http://{}:{}/ (db: {}; log: {log_list})",
        cfg.host,
        cfg.port,
        cfg.db.display()
    );

    // Ingest loop (main thread): batch + transaction + per-path meta + SSE notify.
    let mut batch: Vec<(i64, LogEntry)> = Vec::with_capacity(BATCH_MAX);
    // Per-path unparseable-line counters; the dashboard shows their sum.
    let mut file_invalid: HashMap<PathBuf, u64> = HashMap::new();
    let mut last_flush = Instant::now();
    let mut stopping = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(TailMsg::Chunk {
                source_id,
                entries,
                offset,
                fp,
            }) => {
                // The chunk's own tail state already includes these entries:
                // persisting it with the batch guarantees a restart cannot
                // re-read them, even if the Sync for this poll arrives after
                // the flush.
                if let Some(p) = src_paths.get(&source_id) {
                    positions.insert(p.clone(), (offset, fp));
                }
                batch.extend(entries.into_iter().map(|e| (source_id, e)));
            }
            Ok(TailMsg::Sync {
                path,
                offset,
                fp,
                invalid,
            }) => {
                // Sync-only polls carry no entries; only advance the position
                // when it covers more than the last chunk's.
                positions
                    .entry(path.clone())
                    .and_modify(|(o, f)| {
                        if offset > *o {
                            *o = offset;
                            *f = fp;
                        }
                    })
                    .or_insert((offset, fp));
                file_invalid.insert(path, invalid);
                shared
                    .invalid
                    .store(file_invalid.values().sum(), Ordering::Relaxed);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => stopping = true, // tailer exited
        }
        if signals::STOP.load(Ordering::SeqCst) {
            stopping = true;
        }
        let should_flush = stopping
            || batch.len() >= BATCH_MAX
            || (!batch.is_empty() && last_flush.elapsed() >= FLUSH_EVERY);
        if should_flush && !batch.is_empty() {
            flush(&mut conn, &mut batch, &positions, &shared);
            last_flush = Instant::now();
        }
        if stopping && batch.is_empty() {
            // Persist every tail position, even if no batch was flushed after
            // the last Sync — otherwise a restart would re-read those lines
            // and duplicate them.
            persist_positions(&conn, &positions);
            shared.refresh();
            break;
        }
    }
    println!(
        "fernhttp: shutting down cleanly ({} entries flushed)",
        db::total_requests(&conn).unwrap_or(0)
    );
}

/// Commit a batch in one transaction, persist the tail position and wake
/// the dashboard clients.
fn flush(
    conn: &mut Connection,
    batch: &mut Vec<(i64, LogEntry)>,
    positions: &HashMap<PathBuf, (u64, u64)>,
    shared: &Shared,
) {
    match db::insert_many(conn, batch) {
        Ok(n) => {
            let total = db::total_requests(conn).unwrap_or(0);
            eprintln!("fernhttp: +{n} entries (total {total})");
        }
        Err(e) => eprintln!("fernhttp: insert failed: {e}"),
    }
    batch.clear();
    persist_positions(conn, positions);
    shared.refresh();
}

/// First run: stream the whole existing log through the parser in batches.
/// Returns (parsed, unparseable, final_offset, fingerprint). If the file is
/// absent, returns zeros and the tailer will pick it up when it appears.
///
/// Import runs in one transaction with `wal_autocheckpoint` off: measuring on
/// this hardware, per-1000-line commits throttled inserts to ~13k lines/s
/// while the single-transaction + pragma setup reaches ~200k lines/s.
fn import_initial(path: &Path, conn: &mut Connection, source_id: i64) -> (u64, u64, u64, u64) {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return (0, 0, 0, 0),
    };
    let fp = tailer::file_identity(&file);
    conn.execute_batch("PRAGMA cache_size = 20000; PRAGMA wal_autocheckpoint = 0;")
        .ok();
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fernhttp: import transaction failed: {e}");
            return (0, 0, 0, 0);
        }
    };

    let mut buf = vec![0u8; 64 * 1024];
    let mut carry: Vec<u8> = Vec::new(); // bytes after the last '\n'
    let mut batch: Vec<(i64, LogEntry)> = Vec::with_capacity(BATCH_MAX);
    let mut ok: u64 = 0;
    let mut invalid: u64 = 0;
    let mut offset: u64 = 0;
    let mut failed = false;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("fernhttp: import read failed: {e}");
                break;
            }
        };
        match buf[..n].iter().rposition(|&b| b == b'\n') {
            Some(pos) => {
                let carry_len = carry.len() as u64;
                let mut all = std::mem::take(&mut carry);
                all.extend_from_slice(&buf[..=pos]);
                for seg in all.split(|&b| b == b'\n') {
                    let line = std::str::from_utf8(seg).unwrap_or("");
                    let line = line.trim_end_matches('\r');
                    if line.is_empty() {
                        continue; // trailing newline produces an empty segment
                    }
                    match parser::parse_line(line) {
                        Some(e) => batch.push((source_id, e)),
                        None => invalid += 1,
                    }
                }
                offset += carry_len + pos as u64 + 1;
                carry = buf[pos + 1..n].to_vec();
            }
            None => carry.extend_from_slice(&buf[..n]),
        }
        if batch.len() >= BATCH_MAX {
            ok += batch.len() as u64;
            if !import_flush(&tx, &mut batch) {
                failed = true;
                break;
            }
        }
    }
    // Trailing content without a final newline: Apache always newline-terminates,
    // but be lenient and consume it so the tailer never re-reads it.
    if !carry.is_empty() {
        let line = std::str::from_utf8(&carry).unwrap_or("");
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            invalid += 1;
        } else {
            match parser::parse_line(line) {
                Some(e) => batch.push((source_id, e)),
                None => invalid += 1,
            }
        }
        offset += carry.len() as u64;
    }
    ok += batch.len() as u64;
    if !failed {
        failed = !import_flush(&tx, &mut batch);
    }
    match tx.commit() {
        Ok(()) => {}
        Err(e) => eprintln!("fernhttp: import commit failed: {e}"),
    }
    // Restore normal WAL behavior for the live tail.
    conn.execute_batch("PRAGMA wal_autocheckpoint = 1000; PRAGMA wal_checkpoint(TRUNCATE);")
        .ok();
    (ok, invalid, offset, fp)
}

/// Best-effort flush of an import batch into the open import transaction.
fn import_flush(tx: &rusqlite::Transaction, batch: &mut Vec<(i64, LogEntry)>) -> bool {
    if batch.is_empty() {
        return true;
    }
    match db::insert_many_tx(tx, batch) {
        Ok(()) => {
            batch.clear();
            true
        }
        Err(e) => {
            eprintln!("fernhttp: import insert failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: batches flushed during import must not be re-inserted.
    #[test]
    fn import_inserts_each_line_once() {
        let dir = std::env::temp_dir().join(format!("grs-imp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("acc.log");
        let mut lines: Vec<String> = Vec::with_capacity(1050);
        for i in 0..1000 {
            let ts = 1_000_000_000 + i * 60;
            lines.push(format!(
                r#"10.0.0.{} - - [01/Jan/2026:{:02}:{:02}:00 +0000] "GET /p{} HTTP/1.1" 200 42"#,
                i % 200,
                (ts / 3600) % 24,
                (ts / 60) % 60,
                i % 40
            ));
        }
        lines.push("garbage line".to_string());
        let content = lines.join("\n") + "\ntrailing line without newline";
        std::fs::write(&path, &content).unwrap();

        let mut conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();
        let (ok, invalid, offset, _fp) = import_initial(&path, &mut conn, 0);
        assert_eq!(ok, 1000); // all valid generated lines
        assert_eq!(invalid, 2); // "garbage line" + trailing non-newline garbage
        assert_eq!(offset, content.len() as u64);
        assert_eq!(db::total_requests(&conn).unwrap(), 1000);
        std::fs::remove_dir_all(&dir).ok();
    }
}
