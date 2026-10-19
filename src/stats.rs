//! Aggregations over `requests`, rendered as one JSON document.
//!
//! All queries are parameterized with (`:from`, `:to`) window bounds and
//! run against the `ts` index. Grouping of UA strings and referrer URLs is
//! done in Rust (SQLite has no regex/IP-parsing anyway).

use std::collections::HashMap;

use rusqlite::{params, Connection, Result};

use crate::json::J;
use crate::parser::is_static;
use crate::ua::classify;

const TOP_N: i64 = 10;
/// Referrer/UA grouping sample: unique referers/US that rank in the top 1000.
const GROUP_SAMPLE: i64 = 1000;
/// Window wider than this switches the time series from per-minute to per-hour.
const HOURLY_THRESHOLD: i64 = 3 * 86400;
/// A minute counts as an error spike above this many 4xx/5xx responses.
const SPIKE_MIN: i64 = 5;
/// Scanner: one IP with at least this many 404s in the window.
const SCANNER_MIN: i64 = 10;

// ---------- query helpers ----------

fn scalar(conn: &Connection, sql: &str, from: i64, to: i64) -> Result<i64> {
    conn.query_row(sql, params![from, to], |r| r.get(0))
}

fn sc(conn: &Connection, sql: &str, from: i64, to: i64, extra: i64) -> Result<Vec<(String, i64)>> {
    let mut st = conn.prepare(sql)?;
    let mut rows = st.query(params![from, to, extra])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?));
    }
    Ok(out)
}

fn ii(conn: &Connection, sql: &str, from: i64, to: i64) -> Result<Vec<(i64, i64)>> {
    let mut st = conn.prepare(sql)?;
    let mut rows = st.query(params![from, to])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?));
    }
    Ok(out)
}

fn iii(conn: &Connection, sql: &str, from: i64, to: i64) -> Result<Vec<(i64, i64, i64)>> {
    let mut st = conn.prepare(sql)?;
    let mut rows = st.query(params![from, to])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?, r.get(2)?));
    }
    Ok(out)
}

// ---------- string helpers ----------

/// Extract the bare host from a referer URL ("https://www.Example.com/x" -> "example.com").
pub fn referer_domain(referer: &str) -> Option<String> {
    let s = referer.trim();
    if s.is_empty() || s.contains(' ') {
        return None;
    }
    let after = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("//"))
        .unwrap_or(s);
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    let host = host.strip_prefix("www.").unwrap_or(host);
    Some(host.to_ascii_lowercase())
}

const SEARCH_DOMAINS: &[&str] = &[
    "google.",
    "bing.",
    "duckduckgo.",
    "yandex.",
    "baidu.",
    "ecosia.",
    "startpage.",
    "seznam.",
    "qwant.",
    "sogou.",
    "so.com",
    "brave.com",
    "yahoo.",
];

fn search_param(domain: &str) -> &'static str {
    if domain.contains("baidu.") {
        "wd"
    } else if domain.contains("yandex.") {
        "text"
    } else if domain.contains("sogou.") {
        "query"
    } else if domain.contains("yahoo.") {
        "p"
    } else {
        "q"
    }
}

/// Search phrase from a referrer, if it came from a known search engine.
pub fn search_phrase(referer: &str) -> Option<String> {
    let domain = referer_domain(referer)?;
    let is_search = SEARCH_DOMAINS.iter().any(|d| domain.contains(d));
    if !is_search {
        return None;
    }
    let query = referer.split('?').nth(1)?;
    let param = search_param(&domain);
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=')?;
        if k.eq_ignore_ascii_case(param) {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Decode %XX sequences and '+' -> space (basic URL decoding).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => bytes.push(b' '),
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    bytes.push(h << 4 | l);
                    i += 2;
                }
                _ => bytes.push(b'%'),
            },
            c => bytes.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Top-n entries of a count map, sorted by count desc, then name asc.
fn top_n(map: &HashMap<String, i64>, n: usize) -> Vec<(String, i64)> {
    let mut v: Vec<(String, i64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Fill empty buckets of a (bucket_start, count) series with zeros.
fn fill_series(rows: Vec<(i64, i64)>, from: i64, to: i64, unit: i64) -> Vec<(i64, i64)> {
    let mut map: HashMap<i64, i64> = rows.into_iter().collect();
    let start = from / unit * unit;
    let mut t = start;
    let mut out = Vec::new();
    while t <= to {
        let c = map.remove(&t).unwrap_or(0);
        out.push((t, c));
        t += unit;
    }
    out
}

// ---------- helpers writing into the JSON doc ----------

fn pairs_to_json(j: &mut J, rows: &[(String, i64)]) {
    for (k, v) in rows {
        j.arr();
        j.s(k);
        j.u(*v as u64);
        j.end();
    }
}

// ---------- main entry ----------

/// Full stats document for the [from, to] window. `src` restricts every
/// aggregation to one configured log file (None = all sources).
#[allow(clippy::too_many_lines)]
pub fn stats_json(
    conn: &Connection,
    from: i64,
    to: i64,
    invalid_total: u64,
    src: Option<i64>,
) -> Result<String> {
    // Injected after every ts window; `sf` is a validated integer, so this
    // literal interpolation cannot break out of the SQL string.
    let sf = src
        .map(|s| format!(" AND source_id = {s}"))
        .unwrap_or_default();
    // `{sf}` in the template (no trailing space after ?2) keeps this line out
    // of the global `WHERE ts BETWEEN ?1 AND ?2{sf} ` substitution below.
    let w = format!(" WHERE ts BETWEEN ?1 AND ?2{sf} ");
    let mut j = J::new();
    j.obj();

    j.key("from");
    j.i(from);
    j.key("to");
    j.i(to);
    j.key("generated");
    j.i(chrono_now());

    // ---- general ----
    let requests = scalar(conn, &format!("SELECT COUNT(*) FROM requests{w}"), from, to)?;
    let uniques = scalar(
        conn,
        &format!("SELECT COUNT(DISTINCT ip) FROM requests{w}"),
        from,
        to,
    )?;
    let transfer = scalar(
        conn,
        &format!(
            "SELECT COALESCE(SUM(bytes),0) FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND bytes > 0"
        ),
        from,
        to,
    )?;
    let err4 = scalar(conn, &format!("SELECT COUNT(*) FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status BETWEEN 400 AND 499"), from, to)?;
    let err5 = scalar(
        conn,
        &format!("SELECT COUNT(*) FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status >= 500"),
        from,
        to,
    )?;
    let avg = if requests > 0 {
        transfer as f64 / requests as f64
    } else {
        0.0
    };
    j.key("general");
    j.obj();
    j.key("requests");
    j.i(requests);
    j.key("uniques");
    j.i(uniques);
    j.key("transfer");
    j.i(transfer);
    j.key("errors4xx");
    j.i(err4);
    j.key("errors5xx");
    j.i(err5);
    j.key("avg_size");
    j.f(avg);
    j.key("invalid");
    j.u(invalid_total);
    j.end();

    // ---- time ----
    let unit = if to - from > HOURLY_THRESHOLD {
        3600
    } else {
        60
    };
    let series = fill_series(
        ii(conn, &format!("SELECT (ts/{unit})*{unit}, COUNT(*) FROM requests{w} GROUP BY ts/{unit} ORDER BY 1"), from, to)?,
        from,
        to,
        unit,
    );
    let per_day = fill_series(
        ii(
            conn,
            &format!(
                "SELECT (ts/86400)*86400, COUNT(*) FROM requests{w} GROUP BY ts/86400 ORDER BY 1"
            ),
            from,
            to,
        )?,
        from,
        to,
        86400,
    );
    // heatmap: hour x day-of-week, 7 arrays of 24 counts (UTC)
    let heat_rows = iii(
        conn,
        &format!("SELECT (ts/3600)%24, (ts/86400 + 4) % 7, COUNT(*) FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} GROUP BY 1, 2"),
        from,
        to,
    )?;
    let peak = ii(
        conn,
        &format!("SELECT (ts/60)*60, COUNT(*) FROM requests{w} GROUP BY ts/60 ORDER BY 2 DESC, 1 ASC LIMIT 1"),
        from,
        to,
    )?;

    j.key("time");
    j.obj();
    j.key("unit");
    j.i(unit);
    j.key("series");
    j.arr();
    for (t, c) in &series {
        j.arr();
        j.i(*t);
        j.i(*c);
        j.end();
    }
    j.end();
    j.key("per_day");
    j.arr();
    for (t, c) in &per_day {
        j.arr();
        j.i(*t);
        j.i(*c);
        j.end();
    }
    j.end();
    j.key("heatmap");
    j.arr();
    for dow in 0..7 {
        j.arr();
        for hour in 0..24 {
            let c = heat_rows
                .iter()
                .find(|r| r.0 == hour && r.1 == dow)
                .map(|r| r.2)
                .unwrap_or(0);
            j.i(c);
        }
        j.end();
    }
    j.end();
    j.key("peak");
    match peak.first() {
        Some((t, c)) => {
            j.obj();
            j.key("at");
            j.i(*t);
            j.key("count");
            j.i(*c);
            j.end();
        }
        None => j.n(),
    }
    j.end();

    // ---- resources ----
    let top_paths = sc(
        conn,
        &format!("SELECT path, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND path != '' GROUP BY path ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        GROUP_SAMPLE,
    )?;
    let mut static_map: HashMap<String, i64> = HashMap::new();
    for (p, c) in &top_paths {
        if is_static(p) {
            *static_map.entry(p.clone()).or_insert(0) += c;
        }
    }
    let static_top = top_n(&static_map, TOP_N as usize);
    let top404 = sc(
        conn,
        &format!("SELECT path, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status = 404 AND path != '' GROUP BY path ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    let top5xx = sc(
        conn,
        &format!("SELECT path, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status >= 500 AND path != '' GROUP BY path ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    let top_transfers = sc(
        conn,
        &format!("SELECT path, SUM(bytes) s FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND bytes > 0 AND path != '' GROUP BY path ORDER BY s DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    // first path segment ("/api/v1/x" -> "/api/"), sorted by request count
    let directories = sc(
        conn,
        &format!(
            "SELECT CASE WHEN instr(substr(path,2),'/') = 0 THEN path \
             ELSE substr(path,1,instr(substr(path,2),'/')+1) END AS d, COUNT(*) c \
             FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND path != '' \
             GROUP BY d ORDER BY c DESC LIMIT ?3"
        ),
        from,
        to,
        TOP_N,
    )?;

    j.key("resources");
    j.obj();
    j.key("top_paths");
    j.arr();
    pairs_to_json(
        &mut j,
        &top_paths
            .iter()
            .take(TOP_N as usize)
            .cloned()
            .collect::<Vec<_>>(),
    );
    j.end();
    j.key("top_static");
    j.arr();
    pairs_to_json(&mut j, &static_top);
    j.end();
    j.key("top_404");
    j.arr();
    pairs_to_json(&mut j, &top404);
    j.end();
    j.key("top_5xx");
    j.arr();
    pairs_to_json(&mut j, &top5xx);
    j.end();
    j.key("top_transfers");
    j.arr();
    pairs_to_json(&mut j, &top_transfers);
    j.end();
    j.key("directories");
    j.arr();
    pairs_to_json(&mut j, &directories);
    j.end();
    j.end();

    // ---- visitors ----
    let top_ips = sc(
        conn,
        &format!("SELECT ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} GROUP BY ip ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    let new_visitors = scalar(
        conn,
        &format!(
            "SELECT COUNT(*) FROM (SELECT ip, MIN(ts) m FROM requests WHERE ts <= ?2{sf} GROUP BY ip) WHERE m >= ?1"
        ),
        from,
        to,
    )?;
    let returning = (uniques - new_visitors).max(0);
    j.key("visitors");
    j.obj();
    j.key("top_ips");
    j.arr();
    pairs_to_json(&mut j, &top_ips);
    j.end();
    j.key("new");
    j.i(new_visitors);
    j.key("returning");
    j.i(returning);
    j.end();

    // ---- referrers ----
    let referers = sc(
        conn,
        &format!("SELECT referer, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND referer != '' GROUP BY referer ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        GROUP_SAMPLE,
    )?;
    let mut domain_map: HashMap<String, i64> = HashMap::new();
    let mut search_map: HashMap<String, i64> = HashMap::new();
    for (url, c) in &referers {
        if let Some(d) = referer_domain(url) {
            *domain_map.entry(d.clone()).or_insert(0) += c;
        }
        if let Some(phrase) = search_phrase(url) {
            *search_map.entry(phrase).or_insert(0) += c;
        }
    }
    j.key("referrers");
    j.obj();
    j.key("top");
    j.arr();
    pairs_to_json(
        &mut j,
        &referers
            .iter()
            .take(TOP_N as usize)
            .cloned()
            .collect::<Vec<_>>(),
    );
    j.end();
    j.key("domains");
    j.arr();
    pairs_to_json(&mut j, &top_n(&domain_map, TOP_N as usize));
    j.end();
    j.key("search");
    j.arr();
    pairs_to_json(&mut j, &top_n(&search_map, TOP_N as usize));
    j.end();
    j.end();

    // ---- clients ----
    let ua_rows = sc(
        conn,
        &format!("SELECT ua, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND ua != '' GROUP BY ua ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        GROUP_SAMPLE,
    )?;
    let mut browsers: HashMap<String, i64> = HashMap::new();
    let mut oses: HashMap<String, i64> = HashMap::new();
    let mut devices: HashMap<String, i64> = HashMap::new();
    let mut bots: HashMap<String, i64> = HashMap::new();
    for (ua, c) in &ua_rows {
        let cl = classify(ua);
        if !cl.bot.is_empty() {
            *bots.entry(cl.bot.clone()).or_insert(0) += c;
        } else {
            *browsers.entry(cl.browser.clone()).or_insert(0) += c;
            *oses.entry(cl.os.clone()).or_insert(0) += c;
            *devices.entry(cl.device.clone()).or_insert(0) += c;
        }
    }
    j.key("clients");
    j.obj();
    j.key("browsers");
    j.arr();
    pairs_to_json(&mut j, &top_n(&browsers, TOP_N as usize));
    j.end();
    j.key("oses");
    j.arr();
    pairs_to_json(&mut j, &top_n(&oses, TOP_N as usize));
    j.end();
    j.key("devices");
    j.arr();
    pairs_to_json(&mut j, &top_n(&devices, TOP_N as usize));
    j.end();
    j.key("bots");
    j.arr();
    pairs_to_json(&mut j, &top_n(&bots, TOP_N as usize));
    j.end();
    j.end();

    // ---- protocol / method ----
    let protocols = sc(
        conn,
        &format!("SELECT protocol, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} GROUP BY protocol ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    let methods = sc(
        conn,
        &format!("SELECT method, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} GROUP BY method ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    j.key("protocols");
    j.arr();
    pairs_to_json(&mut j, &protocols);
    j.end();
    j.key("methods");
    j.arr();
    pairs_to_json(&mut j, &methods);
    j.end();

    // ---- statuses ----
    let classes = ii(
        conn,
        &format!("SELECT status/100, COUNT(*) FROM requests{w} GROUP BY status/100 ORDER BY 1"),
        from,
        to,
    )?;
    let codes = ii(
        conn,
        &format!("SELECT status, COUNT(*) FROM requests{w} GROUP BY status ORDER BY 2 DESC, 1 ASC LIMIT 12"),
        from,
        to,
    )?;
    j.key("statuses");
    j.obj();
    j.key("classes");
    j.arr();
    for (k, c) in classes {
        j.arr();
        j.i(k * 100);
        j.i(c);
        j.end();
    }
    j.end();
    j.key("codes");
    j.arr();
    for (k, c) in codes {
        j.arr();
        j.i(k);
        j.i(c);
        j.end();
    }
    j.end();
    j.end();

    // ---- anomalies ----
    let spikes = ii(
        conn,
        &format!("SELECT (ts/60)*60, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status >= 400 GROUP BY ts/60 HAVING c >= {SPIKE_MIN} ORDER BY c DESC, 1 ASC LIMIT 10"),
        from,
        to,
    )?;
    let scanners = sc(
        conn,
        &format!("SELECT ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status = 404 GROUP BY ip HAVING c >= {SCANNER_MIN} ORDER BY c DESC LIMIT ?3"),
        from,
        to,
        TOP_N,
    )?;
    let suspicious = sc(
        conn,
        &format!(
            "SELECT path, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND \
             (path LIKE '%wp-login%' OR path LIKE '%wp-admin%' OR path LIKE '%.env%' OR \
              path LIKE '%/etc/%' OR path LIKE '%phpmyadmin%' OR path LIKE '%adminer%' OR \
              path LIKE '%.git%' OR path LIKE '%../%') \
             GROUP BY path ORDER BY c DESC LIMIT ?3"
        ),
        from,
        to,
        TOP_N,
    )?;
    j.key("anomalies");
    j.obj();
    j.key("spikes");
    j.arr();
    for (t, c) in &spikes {
        j.arr();
        j.i(*t);
        j.i(*c);
        j.end();
    }
    j.end();
    j.key("scanners");
    j.arr();
    pairs_to_json(&mut j, &scanners);
    j.end();
    j.key("suspicious");
    j.arr();
    pairs_to_json(&mut j, &suspicious);
    j.end();
    j.end();

    j.end();
    Ok(j.out())
}

/// One drill-down row. For exact-match kinds `label` is the source address
/// (IP) and `addr` is empty; for fuzzy kinds `label` is the raw matched
/// value and `addr` the source IP; for `ip` kind `label` is the requested
/// path. The modal renders 2 or 3 columns accordingly.
pub struct DetailRow {
    pub label: String,
    pub addr: String,
    pub count: i64,
}

/// Drill-down behind a clicked aggregate: which source addresses (IPs) the
/// requests come from, capped at 50 rows. `kind` selects the column and the
/// match strategy:
/// - exact  ("path"/"static", "method", "protocol", "status"/"code")
/// - fuzzy  ("ua", "referer", "browser", "os", "device", "phrase" — LIKE)
/// - prefix ("dir" — first segment)
/// - "ip"   reverse: the paths requested from one address
pub fn detail_rows(
    conn: &Connection,
    from: i64,
    to: i64,
    src: Option<i64>,
    kind: &str,
    value: &str,
) -> Result<Vec<DetailRow>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let sf = src
        .map(|s| format!(" AND source_id = {s}"))
        .unwrap_or_default();
    // (sql template with ?3, bound value, row shape)
    enum Shape {
        Ipv,             // SELECT ip … → [ip, count]
        PathV,           // SELECT path … → [path, count]
        Both,            // SELECT value, ip … → [value, ip, count]
    }
    let esc = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let (sql, bound, shape): (String, String, Shape) = match kind {
        "path" | "static" | "method" | "protocol" => {
            let col = if kind == "path" || kind == "static" {
                "path"
            } else {
                kind
            };
            (
                format!(
                    "SELECT ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND {col} = ?3 \
                     GROUP BY ip ORDER BY c DESC, ip LIMIT 50"
                ),
                value.to_string(),
                Shape::Ipv,
            )
        }
        "status" | "code" => (
            format!(
                "SELECT ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND status = ?3 \
                 GROUP BY ip ORDER BY c DESC, ip LIMIT 50"
            ),
            value.to_string(),
            Shape::Ipv,
        ),
        "dir" => (
            format!(
                "SELECT path, ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND path LIKE ?3 ESCAPE '\\' \
                 GROUP BY path, ip ORDER BY c DESC LIMIT 50"
            ),
            format!("{esc}%"),
            Shape::Both,
        ),
        "ua" | "referer" | "browser" | "os" | "device" => {
            let col = if kind == "ua" || kind == "browser" || kind == "os" || kind == "device" {
                "ua"
            } else {
                "referer"
            };
            (
                format!(
                    "SELECT {col}, ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND {col} LIKE ?3 ESCAPE '\\' \
                     GROUP BY {col}, ip ORDER BY c DESC LIMIT 50"
                ),
                format!("%{esc}%"),
                Shape::Both,
            )
        }
        "phrase" => (
            format!(
                "SELECT referer, ip, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND referer LIKE ?3 ESCAPE '\\' \
                 GROUP BY referer, ip ORDER BY c DESC LIMIT 50"
            ),
            format!("%{esc}%"),
            Shape::Both,
        ),
        "ip" => (
            format!(
                "SELECT path, COUNT(*) c FROM requests WHERE ts BETWEEN ?1 AND ?2{sf} AND ip = ?3 \
                 GROUP BY path ORDER BY c DESC, path LIMIT 50"
            ),
            value.to_string(),
            Shape::PathV,
        ),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let mut st = conn.prepare(&sql)?;
    let mut rows = st.query(params![from, to, bound])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        match shape {
            Shape::Ipv => out.push(DetailRow {
                label: r.get(0)?,
                addr: String::new(),
                count: r.get(1)?,
            }),
            Shape::PathV => out.push(DetailRow {
                label: r.get(0)?,
                addr: String::new(),
                count: r.get(1)?,
            }),
            Shape::Both => out.push(DetailRow {
                label: r.get(0)?,
                addr: r.get(1)?,
                count: r.get(2)?,
            }),
        }
    }
    Ok(out)
}

/// Wall-clock now. Re-exported so the caller and tests share one clock.
pub fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init, insert_many};
    use crate::parser::LogEntry;
    use rusqlite::Connection;

    const FROM: i64 = 1_000_000_000;

    fn e(
        ts: i64,
        ip: &str,
        path: &str,
        status: i64,
        bytes: i64,
        ua: &str,
        referer: &str,
    ) -> LogEntry {
        LogEntry {
            ts,
            ip: ip.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: status as i32,
            bytes,
            referer: referer.to_string(),
            user_agent: ua.to_string(),
        }
    }

    fn seed() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        // ip details: A=5 requests, B=3, C=2
        let ua_chrome =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118 Safari/537.36";
        let mut rows = vec![
            e(FROM, "10.0.0.1", "/", 200, 100, ua_chrome, "https://www.google.com/search?q=rust+lang"),
            e(FROM + 60, "10.0.0.1", "/", 200, 100, ua_chrome, "https://www.google.com/search?q=rust+lang"),
            e(FROM + 60, "10.0.0.1", "/", 200, 100, ua_chrome, "https://www.example.com/a"),
            e(FROM + 120, "10.0.0.1", "/", 200, 100, ua_chrome, ""),
            e(FROM + 120, "10.0.0.1", "/api/v1/items?id=7", 404, 0, ua_chrome, ""),
            e(FROM + 180, "10.0.0.2", "/style.css", 200, 512, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605 Safari/604.1", ""),
            e(FROM + 180, "10.0.0.2", "/app.js", 200, 2048, "Googlebot/2.1 (+http://www.google.com/bot.html)", ""),
            e(FROM + 240, "10.0.0.2", "/nosuch", 404, 0, "Googlebot/2.1 (+http://www.google.com/bot.html)", ""),
            e(FROM + 240, "10.0.0.3", "/wp-login.php", 500, 0, "curl/7.68.0", ""),
            e(FROM + 300, "10.0.0.3", "/", 200, 10, "curl/7.68.0", "https://bing.com/search?q=linkedin"),
        ];
        // 500 errors from one scanner IP (anomaly)
        for i in 0..12 {
            rows.push(e(
                FROM + 360 + i * 5,
                "203.0.113.66",
                "/.env",
                404,
                0,
                "python-requests/2.31",
                "",
            ));
        }
        let mut conn = conn;
        insert_many(
            &mut conn,
            &rows.iter().map(|e| (0_i64, e.clone())).collect::<Vec<_>>(),
        )
        .unwrap();
        conn
    }

    #[test]
    fn general_counts() {
        let conn = seed();
        let doc = stats_json(&conn, FROM - 100, FROM + 100000, 7, None).unwrap();
        assert!(doc.contains("\"requests\":22"), "{doc}");
        assert!(doc.contains("\"uniques\":4"), "{doc}");
        assert!(doc.contains("\"errors4xx\":14"), "{doc}");
        assert!(doc.contains("\"errors5xx\":1"), "{doc}");
        assert!(doc.contains("\"invalid\":7"), "{doc}");
        // transfer = 100*4 + 512 + 2048 + 10 = 2970
        assert!(doc.contains("\"transfer\":2970"), "{doc}");
    }

    #[test]
    fn source_filter_isolation() {
        let mut conn = seed();
        let a = crate::db::ensure_source(&conn, "/logs/a.log").unwrap();
        insert_many(
            &mut conn,
            &[(
                a,
                e(FROM, "99.99.99.99", "/only-a", 200, 1, "curl/8.0", ""),
            )],
        )
        .unwrap();
        let doc = stats_json(&conn, FROM - 100, FROM + 100000, 0, Some(a)).unwrap();
        assert!(doc.contains("\"requests\":1"), "{doc}");
        assert!(doc.contains("\"/only-a\""), "{doc}");
        assert!(!doc.contains("\"10.0.0.1\""), "{doc}"); // seed rows excluded
        let all = stats_json(&conn, FROM - 100, FROM + 100000, 0, None).unwrap();
        assert!(all.contains("\"requests\":23"), "{all}"); // 22 seed + 1 new
    }

    #[test]
    fn empty_window() {
        let conn = seed();
        // window with no rows: series must still be filled with zeros
        let doc = stats_json(&conn, FROM + 1_000_000, FROM + 1_000_100, 0, None).unwrap();
        assert!(doc.contains("\"requests\":0"), "{doc}");
        assert!(doc.contains("\"peak\":null"), "{doc}");
        assert!(doc.contains("\"series\":[[1000999980,0]"), "{doc}");
    }

    #[test]
    fn resources_and_anomalies() {
        let conn = seed();
        let doc = stats_json(&conn, FROM - 100, FROM + 100000, 0, None).unwrap();
        assert!(doc.contains("\"top_404\""), "{doc}");
        assert!(doc.contains("\"/api/v1/items"), "{doc}");
        assert!(doc.contains("\"/.env\""), "{doc}"); // suspicious
        assert!(doc.contains("\"203.0.113.66\""), "{doc}"); // scanner ip present (pair array)
        assert!(doc.contains("\"top_static\":[[\"/app.js\""), "{doc}"); // static classification, count-sorted
        assert!(doc.contains("\"/style.css\",1]"), "{doc}");
    }

    #[test]
    fn clients_classified() {
        let conn = seed();
        let doc = stats_json(&conn, FROM - 100, FROM + 100000, 0, None).unwrap();
        assert!(doc.contains("\"Chrome\""), "{doc}");
        assert!(doc.contains("\"Googlebot\""), "{doc}");
        assert!(doc.contains("\"iOS\""), "{doc}"); // os bucket
        assert!(doc.contains("\"Mobile\""), "{doc}"); // device bucket
    }

    #[test]
    fn detail_drilldown_kinds() {
        let conn = seed();
        // exact path → source addresses (ip, count)
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "path", "/.env").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "203.0.113.66");
        assert_eq!(rows[0].addr, "");
        assert_eq!(rows[0].count, 12);
        // reverse: what one address requested
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "ip", "203.0.113.66").unwrap();
        assert_eq!(rows[0].label, "/.env");
        assert_eq!(rows[0].count, 12);
        // UA substring (bot label) → raw ua + address
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "ua", "Googlebot").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].addr, "10.0.0.2");
        assert!(rows[0].label.contains("Googlebot"));
        // referrer domain substring
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "referer", "google.com")
            .unwrap();
        assert!(rows.iter().any(|r| r.label.contains("google.com/search")));
        // status code (numeric affinity)
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "status", "404").unwrap();
        assert!(rows.iter().any(|r| r.label == "203.0.113.66" && r.count == 12));
        // directory prefix
        let rows = detail_rows(&conn, FROM - 100, FROM + 100000, None, "dir", "/api").unwrap();
        assert!(rows.iter().any(|r| r.label.contains("/api/v1/items")));
        // unknown kind rejected
        assert!(detail_rows(&conn, FROM - 100, FROM + 100000, None, "bogus", "x").is_err());
    }

    #[test]
    fn directories_resource_present() {
        let conn = seed();
        let doc = stats_json(&conn, FROM - 100, FROM + 100000, 0, None).unwrap();
        assert!(doc.contains("\"directories\":["), "{doc}");
        assert!(doc.contains("\"/\""), "{doc}"); // ""/" -> "/" bucket
        assert!(doc.contains("\"/api/\""), "{doc}");
    }

    #[test]
    fn visitors_new_returning() {
        let conn = seed();
        // window starts at FROM: all ips first request >= FROM -> all new
        let doc = stats_json(&conn, FROM, FROM + 100000, 0, None).unwrap();
        assert!(doc.contains("\"new\":4"), "{doc}");
        assert!(doc.contains("\"returning\":0"), "{doc}");
        // second window: same requests but new ip appeared earlier
        // insert an older request for 10.0.0.3
        let mut conn = conn;
        insert_many(
            &mut conn,
            &[(0, e(
                FROM - 86400,
                "10.0.0.3",
                "/old",
                200,
                1,
                "curl/7.68.0",
                "",
            ))],
        )
        .unwrap();
        let doc = stats_json(&conn, FROM, FROM + 100000, 0, None).unwrap();
        assert!(doc.contains("\"new\":3"), "{doc}");
        assert!(doc.contains("\"returning\":1"), "{doc}");
    }

    #[test]
    fn heatmap_shape() {
        let conn = seed();
        let doc = stats_json(&conn, FROM, FROM + 86400, 0, None).unwrap();
        // 7 rows x 24 cols; the outer '[' is consumed by the split delimiter
        let heat = doc.split("\"heatmap\":[").nth(1).unwrap();
        let until = heat.find("],\"peak\"").unwrap_or(heat.len());
        let block = &heat[..until + 1];
        assert!(block.starts_with("[0,"), "{block}"); // first cell = hour 0
        assert_eq!(block.matches('[').count(), 7, "{block}"); // 7 day rows (outer '[' consumed by split)
        assert_eq!(block.matches(']').count(), 8, "{block}"); // 7 rows + outer close
    }

    #[test]
    fn series_unit_switches_to_hour() {
        let conn = seed();
        let wide = stats_json(&conn, FROM, FROM + 4 * 86400, 0, None).unwrap();
        assert!(wide.contains("\"unit\":3600"), "{wide}");
    }

    #[test]
    fn referer_helpers() {
        assert_eq!(
            referer_domain("https://www.Example.com/path?x=1"),
            Some("example.com".into())
        );
        assert_eq!(referer_domain("http://foo.bar/"), Some("foo.bar".into()));
        assert_eq!(referer_domain("foo"), Some("foo".into())); // scheme-less host still extracted
        assert_eq!(referer_domain(""), None);
        assert_eq!(
            search_phrase("https://www.google.com/search?q=rust+lang"),
            Some("rust lang".into())
        );
        assert_eq!(
            search_phrase("https://google.com/?q=a%20b&hl=en"),
            Some("a b".into())
        );
        assert_eq!(search_phrase("https://example.com/?q=nope"), None);
        assert_eq!(
            search_phrase("https://www.bing.com/search?q=test"),
            Some("test".into())
        );
        assert_eq!(percent_decode("caf%C3%A9+na%C3%AFve"), "café naïve");
        assert_eq!(percent_decode("100%25"), "100%");
    }

    #[test]
    fn top_n_ordering() {
        let mut m = HashMap::new();
        m.insert("a".to_string(), 3);
        m.insert("b".to_string(), 9);
        m.insert("c".to_string(), 3);
        let top = top_n(&m, 2);
        assert_eq!(top, vec![("b".to_string(), 9), ("a".to_string(), 3)]);
    }

    #[test]
    fn fill_series_gaps() {
        let rows = vec![(60, 5), (180, 2)];
        let filled = fill_series(rows, 0, 240, 60);
        assert_eq!(filled, vec![(0, 0), (60, 5), (120, 0), (180, 2), (240, 0)]);
    }
}
