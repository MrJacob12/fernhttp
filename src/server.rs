//! Minimal HTTP server on `std::net` (thread per connection, keep-alive).
//! Routes: `/` dashboard, `/api/stats?from=&to=` JSON, `/events` SSE.
//! Shared state: DB path, invalid-line counter, SSE client list, 1s response cache.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::db;
use crate::signals::STOP;
use crate::stats;

const INDEX_HTML: &str = include_str!("index.html");

const MAX_CONN: usize = 32;
const HEAD_MAX: usize = 32 * 1024;
const CACHE_MS: u128 = 1000;
const SSE_HEARTBEAT: Duration = Duration::from_secs(15);
const MAX_WINDOW: i64 = 366 * 86400;

pub struct Cache {
    from: i64,
    to: i64,
    source: Option<i64>,
    at: Instant,
    body: Option<Vec<u8>>,
}

pub struct Shared {
    pub db: String,
    pub invalid: AtomicU64,
    clients: Mutex<Vec<(u64, Sender<()>)>>,
    cache: Mutex<Cache>,
    conns: Arc<AtomicUsize>,
    next_id: AtomicU64,
}

impl Shared {
    pub fn new(db: &str) -> Arc<Shared> {
        Arc::new(Shared {
            db: db.to_string(),
            invalid: AtomicU64::new(0),
            clients: Mutex::new(Vec::new()),
            cache: Mutex::new(Cache {
                from: 0,
                to: 0,
                source: None,
                at: Instant::now(),
                body: None,
            }),
            conns: Arc::new(AtomicUsize::new(0)),
            next_id: AtomicU64::new(1),
        })
    }

    /// Called by the ingest loop after each DB flush: drop the response
    /// cache and poke every SSE client so the dashboard refetches.
    pub fn refresh(&self) {
        *self.cache.lock() = Cache {
            from: 0,
            to: 0,
            source: None,
            at: Instant::now(),
            body: None,
        };
        let mut clients = self.clients.lock();
        clients.retain(|(_, c)| c.send(()).is_ok());
    }
}

/// Bind and spawn the accept loop. `ready` reports bind success/failure to
/// the caller so main can exit early instead of serving nothing.
pub fn start(shared: Arc<Shared>, host: &str, port: u16, ready: Sender<Result<(), String>>) {
    let listener = match TcpListener::bind((host, port)) {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(format!("cannot bind {host}:{port}: {e}")));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let n = shared.conns.fetch_add(1, Ordering::SeqCst);
            if n >= MAX_CONN {
                shared.conns.fetch_sub(1, Ordering::SeqCst);
                let mut s = stream;
                let _ = respond(
                    &mut s,
                    "503 Service Unavailable",
                    "text/plain",
                    b"busy",
                    false,
                );
                continue;
            }
            let shared = shared.clone();
            std::thread::spawn(move || {
                let _guard = ConnGuard(shared.conns.clone());
                handle_conn(stream, &shared);
            });
        }
    });
}

struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_conn(mut stream: TcpStream, shared: &Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let head = match read_head(&mut stream) {
            Ok(Some(h)) => h,
            Ok(None) => return, // client closed
            Err(_) => return,   // timeout / oversized
        };
        let Some(parsed) = parse_head(&head) else {
            let _ = respond(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                b"bad request",
                false,
            );
            return;
        };
        let (method, target, keep_alive) = parsed;
        if method != "GET" {
            let _ = respond(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain",
                b"GET only",
                keep_alive,
            );
            if !keep_alive {
                return;
            }
            continue;
        }
        let (path, query): (&str, &str) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target.as_str(), ""),
        };
        let routed = match path {
            "/" | "/index.html" => respond(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                INDEX_HTML.as_bytes(),
                keep_alive,
            ),
            "/api/stats" => {
                let body = stats_body(shared, query);
                let (code, ctype) = if body.starts_with(b"{") {
                    ("200 OK", "application/json")
                } else {
                    ("500 Internal Server Error", "text/plain")
                };
                respond(&mut stream, code, ctype, &body, keep_alive)
            }
            "/api/sources" => {
                let body = sources_body(shared);
                respond(&mut stream, "200 OK", "application/json", &body, keep_alive)
            }
            "/api/detail" => match detail_body(shared, query) {
                Some(body) => respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &body,
                    keep_alive,
                ),
                None => respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"kind must be path|ua|referer with a value",
                    keep_alive,
                ),
            },
            "/events" => {
                serve_sse(&mut stream, shared);
                return; // stream stays open until disconnect/shutdown
            }
            _ => respond(
                &mut stream,
                "404 Not Found",
                "text/plain",
                b"not found",
                keep_alive,
            ),
        };
        if routed.is_err() || !keep_alive || STOP.load(Ordering::SeqCst) {
            return;
        }
    }
}

/// Read the request head up to "\r\n\r\n". None = clean EOF before any byte.
fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => return Ok(if buf.is_empty() { None } else { Some(buf) }),
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(e); // idle keep-alive timeout
            }
            Err(e) => return Err(e),
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > HEAD_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n") {
            return Ok(Some(buf));
        }
    }
}

/// (method, target, keep_alive)
fn parse_head(head: &[u8]) -> Option<(String, String, bool)> {
    let text = std::str::from_utf8(head).ok()?;
    let first_end = text.find("\r\n").or_else(|| text.find('\n'))?;
    let first = &text[..first_end];
    let mut it = first.split(' ');
    let method = it.next()?.to_string();
    let target = it.next()?.to_string();
    let version = it.next().unwrap_or("HTTP/1.0");
    let http11 = version.eq_ignore_ascii_case("HTTP/1.1");
    let mut close = false;
    for line in text.lines().skip(1) {
        if line.to_ascii_lowercase().starts_with("connection:")
            && line.to_ascii_lowercase().contains("close")
        {
            close = true;
        }
    }
    Some((method, target, http11 && !close))
}

fn stats_body(shared: &Arc<Shared>, query: &str) -> Vec<u8> {
    let (from, to) = parse_window(query);
    let source = parse_source(query);
    // 1s cache, keyed by window + source tab
    {
        let c = shared.cache.lock();
        if let Some(body) = &c.body {
            if c.from == from
                && c.to == to
                && c.source == source
                && c.at.elapsed().as_millis() < CACHE_MS
            {
                return body.clone();
            }
        }
    }
    let conn = match db::open(&shared.db) {
        Ok(c) => c,
        Err(e) => return format!("db error: {e}").into_bytes(),
    };
    let body = match stats::stats_json(
        &conn,
        from,
        to,
        shared.invalid.load(Ordering::Relaxed),
        source,
    ) {
        Ok(s) => s.into_bytes(),
        Err(e) => format!("stats error: {e}").into_bytes(),
    };
    if body.starts_with(b"{") {
        *shared.cache.lock() = Cache {
            from,
            to,
            source,
            at: Instant::now(),
            body: Some(body.clone()),
        };
    }
    body
}

/// Drill-down behind a clicked aggregate row. Returns None (→ 400) when the
/// kind is unknown or the value empty.
fn detail_body(shared: &Arc<Shared>, query: &str) -> Option<Vec<u8>> {
    let (from, to) = parse_window(query);
    let source = parse_source(query);
    let mut kind = String::new();
    let mut value = String::new();
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "kind" => kind = crate::stats::percent_decode(v),
            "value" => value = crate::stats::percent_decode(v),
            _ => {}
        }
    }
    if !matches!(
        kind.as_str(),
        "path"
            | "static"
            | "dir"
            | "ua"
            | "browser"
            | "os"
            | "device"
            | "referer"
            | "phrase"
            | "method"
            | "protocol"
            | "status"
            | "code"
            | "ip"
    ) || value.is_empty()
    {
        return None;
    }
    let conn = match db::open(&shared.db) {
        Ok(c) => c,
        Err(e) => return Some(format!("db error: {e}").into_bytes()),
    };
    let rows = match stats::detail_rows(&conn, from, to, source, &kind, &value) {
        Ok(r) => r,
        Err(e) => return Some(format!("detail error: {e}").into_bytes()),
    };
    let mut j = crate::json::J::new();
    j.obj();
    j.key("rows");
    j.arr();
    for d in rows {
        if d.addr.is_empty() {
            // exact-match drill: [source address, count]
            j.arr();
            j.s(&d.label);
            j.i(d.count);
            j.end();
        } else {
            j.arr();
            j.s(&d.label);
            j.s(&d.addr);
            j.i(d.count);
            j.end();
        }
    }
    j.end();
    j.end();
    Some(j.out().into_bytes())
}

/// `source=` query param: a configured log id for the dashboard tabs.
/// Absent, empty or 0 means "all sources".
fn parse_source(query: &str) -> Option<i64> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == "source" {
            let n = v.parse::<i64>().ok()?;
            return if n > 0 { Some(n) } else { None };
        }
    }
    None
}

/// Configured log files with their request counts, in tab order.
fn sources_body(shared: &Arc<Shared>) -> Vec<u8> {
    let conn = match db::open(&shared.db) {
        Ok(c) => c,
        Err(e) => return format!("db error: {e}").into_bytes(),
    };
    let rows = match db::sources_with_counts(&conn) {
        Ok(r) => r,
        Err(e) => return format!("db error: {e}").into_bytes(),
    };
    let mut j = crate::json::J::new();
    j.obj();
    j.key("sources");
    j.arr();
    for (id, name, count) in rows {
        j.arr();
        j.i(id);
        j.s(&name);
        j.i(count);
        j.end();
    }
    j.end();
    j.end();
    j.out().into_bytes()
}

/// Parse `from`/`to` query params; defaults to the last hour;
/// window is capped to MAX_WINDOW.
fn parse_window(query: &str) -> (i64, i64) {
    let mut from: Option<i64> = None;
    let mut to: Option<i64> = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "from" => from = v.parse::<i64>().ok(),
            "to" => to = v.parse::<i64>().ok(),
            _ => {}
        }
    }
    let now = stats::chrono_now();
    let to = to.unwrap_or(now);
    let default_from = to - 3600;
    let from = from.unwrap_or(default_from);
    if from >= to {
        return (default_from, to);
    }
    let from = from.max(to - MAX_WINDOW);
    (from.max(0), to)
}

fn serve_sse(stream: &mut TcpStream, shared: &Arc<Shared>) {
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
    );
    let _ = stream.flush();
    let (tx, rx) = mpsc::channel::<()>();
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    shared.clients.lock().push((id, tx));
    loop {
        let frame: &[u8] = match rx.recv_timeout(SSE_HEARTBEAT) {
            Ok(()) => b"event: refresh\ndata: ok\n\n",
            Err(RecvTimeoutError::Timeout) => b": ping\n\n",
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if stream.write_all(frame).is_err() || stream.flush().is_err() {
            break;
        }
        if STOP.load(Ordering::SeqCst) {
            break;
        }
    }
    shared.clients.lock().retain(|(k, _)| *k != id);
}

fn respond(
    stream: &mut TcpStream,
    code: &str,
    ctype: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: {conn}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}
