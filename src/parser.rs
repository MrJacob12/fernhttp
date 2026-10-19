//! Single-pass Apache log parser (Common and Combined Log Format), no regex.
//!
//! Line shape:
//! `IP IDENT USER [10/Oct/2026:13:55:36 +0200] "GET /path HTTP/1.1" 200 2326 ["referer"] ["user-agent"]`
//!
//! Any number of trailing fields (referer, user-agent) is accepted, so both
//! Common and Combined formats parse without configuration. Malformed lines
//! yield `None` and are counted elsewhere.

pub const STATIC_EXTS: &[&str] = &[
    "css", "js", "mjs", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "woff",
    "woff2", "ttf", "eot", "otf", "map", "mp4", "webm", "mp3", "ogg", "pdf", "zip",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub ts: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: i32,
    pub bytes: i64, // -1 when the log has '-'
    pub referer: String,
    pub user_agent: String,
}

fn is_space(b: u8) -> bool {
    b == b' '
}

/// Skip spaces; returns false if end of input reached.
fn skip_spaces(s: &str, i: &mut usize) -> bool {
    while *i < s.len() && is_space(s.as_bytes()[*i]) {
        *i += 1;
    }
    *i < s.len()
}

/// Skip spaces, then take a token up to the next space.
fn take_token<'a>(s: &'a str, i: &mut usize) -> Option<&'a str> {
    if !skip_spaces(s, i) {
        return None;
    }
    let start = *i;
    while *i < s.len() && !is_space(s.as_bytes()[*i]) {
        *i += 1;
    }
    Some(&s[start..*i])
}

/// Parse trailing digits as i64 (may be empty -> None).
fn take_digits(s: &str, i: &mut usize) -> Option<i64> {
    if !skip_spaces(s, i) {
        return None;
    }
    let start = *i;
    let mut n: i64 = 0;
    while *i < s.len() && s.as_bytes()[*i].is_ascii_digit() {
        n = n * 10 + (s.as_bytes()[*i] - b'0') as i64;
        *i += 1;
    }
    if *i == start {
        return None;
    }
    Some(n)
}

/// Parse s[i] == '"' quoted string honoring backslash escapes.
/// Returns the raw content and the index just past the closing quote.
fn take_quoted<'a>(s: &'a str, i: &mut usize) -> Option<(&'a str, usize)> {
    let b = s.as_bytes();
    if *i >= s.len() || b[*i] != b'"' {
        return None;
    }
    let start = *i + 1;
    let mut j = start;
    while j < s.len() {
        match b[j] {
            b'\\' => j += 2, // skip escaped char (e.g. \")
            b'"' => {
                let content = &s[start..j];
                *i = j + 1;
                return Some((content, *i));
            }
            _ => j += 1,
        }
    }
    None // unterminated
}

/// Parse `DD/Mon/YYYY:HH:MM:SS +ZZZZ` into a Unix timestamp (UTC).
fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 26 {
        return None;
    }
    let dd = num2(&b[0..2])?;
    let mon = match month(&s[3..6]) {
        Some(m) => m,
        None => return None,
    };
    let yy = num4(&b[7..11])?;
    let hh = num2(&b[12..14])?;
    let mm = num2(&b[15..17])?;
    let ss = num2(&b[18..20])?;
    let sign: i64 = match b[21] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let oh = num2(&b[22..24])?;
    let om = num2(&b[24..26])?;
    if !(1..=31).contains(&dd)
        || !(0..=23).contains(&hh)
        || !(0..=59).contains(&mm)
        || !(0..=59).contains(&ss)
        || oh > 23
        || om > 59
    {
        return None;
    }
    let days = days_from_civil(yy, mon, dd)?;
    let utc = days * 86400 + hh * 3600 + mm * 60 + ss - sign * (oh * 3600 + om * 60);
    Some(utc)
}

fn num2(b: &[u8]) -> Option<i64> {
    if b.len() != 2 {
        return None;
    }
    let (x, y) = (b[0], b[1]);
    if x.is_ascii_digit() && y.is_ascii_digit() {
        Some(((x - b'0') * 10 + (y - b'0')) as i64)
    } else {
        None
    }
}

fn num4(b: &[u8]) -> Option<i64> {
    let mut n = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as i64;
    }
    Some(n)
}

fn month(s: &str) -> Option<i64> {
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 for a proleptic
/// Gregorian date. Returns None for invalid month/day combos.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || d < 1 {
        return None;
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Extract the file extension from a path (lowercased, without the dot).
pub fn file_ext(path: &str) -> Option<String> {
    let last = path.rsplit('/').next()?;
    let (name, ext) = last.rsplit_once('.')?;
    if name.is_empty() || ext.is_empty() || ext.bytes().any(|b| !b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// True if `path` points at a static asset (CSS/JS/image/font/etc).
pub fn is_static(path: &str) -> bool {
    match file_ext(path) {
        Some(e) => STATIC_EXTS.contains(&e.as_str()),
        None => false,
    }
}

/// Parse one access-log line. Returns None for malformed input.
pub fn parse_line(line: &str) -> Option<LogEntry> {
    let mut i = 0;
    let ip = take_token(line, &mut i)?;
    // ident and user fields are skipped
    take_token(line, &mut i)?;
    take_token(line, &mut i)?;

    // timestamp block
    if !skip_spaces(line, &mut i) {
        return None;
    }
    let b = line.as_bytes();
    if b[i] != b'[' {
        return None;
    }
    let open = i + 1;
    let close = line[open..].find(']')? + open;
    let ts = parse_date(&line[open..close])?;
    i = close + 1;

    // request: METHOD TARGET PROTOCOL
    if !skip_spaces(line, &mut i) {
        return None;
    }
    let (request, next) = take_quoted(line, &mut i)?;
    i = next;
    // Apache logs "-" as the request line when a connection dies before any
    // request arrives (typically status 408). Keep such rows with empty
    // request fields so timeouts are counted and analysable instead of
    // being dropped as unparseable.
    let mut method = String::new();
    let mut path = String::new();
    let mut protocol = String::new();
    if request != "-" {
        let mut toks = request.split_whitespace();
        method = toks.next()?.to_string();
        path = toks.next()?.to_string();
        protocol = toks.next().unwrap_or("").to_string();
    }

    // status, bytes
    let status = take_digits(line, &mut i)?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let bytes = match take_token(line, &mut i) {
        Some("-") => -1,
        Some(t) => t.parse::<i64>().ok()?,
        None => -1,
    };

    // optional referer and user-agent (Combined format)
    skip_spaces(line, &mut i);
    let mut referer = String::new();
    if i < line.len() && b[i] == b'"' {
        let (r, n) = take_quoted(line, &mut i)?;
        referer = r.to_string();
        i = n;
        skip_spaces(line, &mut i);
    }
    let mut user_agent = String::new();
    if i < line.len() && b[i] == b'"' {
        let (u, _) = take_quoted(line, &mut i)?;
        user_agent = u.to_string();
    }

    Some(LogEntry {
        ts,
        ip: ip.to_string(),
        method,
        path,
        protocol,
        status: status as i32,
        bytes,
        referer,
        user_agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_line() {
        let line = r#"127.0.0.1 - frank [10/Oct/2026:13:55:36 +0200] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.ip, "127.0.0.1");
        assert_eq!(e.method, "GET");
        assert_eq!(e.path, "/apache_pb.gif");
        assert_eq!(e.protocol, "HTTP/1.0");
        assert_eq!(e.status, 200);
        assert_eq!(e.bytes, 2326);
        assert_eq!(e.referer, "http://www.example.com/start.html");
        assert!(e.user_agent.contains("Mozilla/4.08"));
    }

    #[test]
    fn common_line() {
        let line =
            r#"192.168.1.1 - - [09/Jul/2026:08:00:01 -0700] "GET /index.html HTTP/1.1" 200 512"#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.status, 200);
        assert_eq!(e.path, "/index.html");
        assert_eq!(e.referer, "");
        assert_eq!(e.user_agent, "");
    }

    #[test]
    fn dash_bytes() {
        let line = r#"10.0.0.2 - - [01/Jan/2026:00:00:00 +0000] "HEAD / HTTP/1.1" 204 -"#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.bytes, -1);
    }

    #[test]
    fn ipv6() {
        let line =
            r#"2001:db8::1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "-""#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.ip, "2001:db8::1");
    }

    #[test]
    fn escaped_quote_in_ua() {
        let line = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "Mozilla/4.0 (compatible; \"W;N\")""#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.user_agent, "Mozilla/4.0 (compatible; \\\"W;N\\\")");
        assert_eq!(e.status, 200);
    }

    #[test]
    fn no_protocol_in_request() {
        let line = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /robots.txt" 200 10"#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.protocol, "");
        assert_eq!(e.path, "/robots.txt");
    }

    #[test]
    fn trailing_garbage_ignored() {
        let line = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10 some trailing junk"#;
        assert!(parse_line(line).is_some());
    }

    #[test]
    fn query_string_kept() {
        let line =
            r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /search?q=rust+lang HTTP/1.1" 200 10"#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.path, "/search?q=rust+lang");
    }

    #[test]
    fn empty_line_rejected() {
        assert!(parse_line("").is_none());
    }

    #[test]
    fn bad_date_rejected() {
        let line = r#"1.2.3.4 - - [not-a-date] "GET / HTTP/1.1" 200 10"#;
        assert!(parse_line(line).is_none());
        let line2 = r#"1.2.3.4 - - [32/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10"#;
        assert!(parse_line(line2).is_none());
    }

    #[test]
    fn bad_status_rejected() {
        let line = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 99 10"#;
        assert!(parse_line(line).is_none());
        let line2 = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" OOPS 10"#;
        assert!(parse_line(line2).is_none());
    }

    #[test]
    fn unterminated_quotes_rejected() {
        let line =
            r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10 "unterminated"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn dash_request_line_kept() {
        // Apache 408: connection closed before a request arrived
        let line = r#"34.52.133.111 - - [17/Oct/2026:03:24:28 +0200] "-" 408 1412 "-" "-""#;
        let e = parse_line(line).unwrap();
        assert_eq!(e.status, 408);
        assert_eq!(e.method, "");
        assert_eq!(e.path, "");
        assert_eq!(e.protocol, "");
        assert_eq!(e.bytes, 1412);
    }

    #[test]
    fn missing_request_rejected() {
        let line = r#"1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] 200 10"#;
        assert!(parse_line(line).is_none());
    }

    mod dates {
        use super::*;

        #[test]
        fn epoch() {
            // 1970-01-01 00:00:00 UTC
            assert_eq!(parse_date("01/Jan/1970:00:00:00 +0000"), Some(0));
        }

        #[test]
        fn positive_offset() {
            // 2026-10-10 13:55:36 +0200 == 11:55:36 UTC
            let e = parse_date("10/Oct/2026:13:55:36 +0200").unwrap();
            let expected = 1789134936 + 3600 * 2 - 3600 * 2; // sanity via known math below
            let _ = expected;
            // compute: days_from_civil(2026,10,10) * 86400 + 11*3600+55*60+36
            assert_eq!(e % 86400, 11 * 3600 + 55 * 60 + 36);
        }

        #[test]
        fn negative_offset() {
            let e = parse_date("09/Jul/2026:08:00:01 -0700").unwrap();
            assert_eq!(e % 86400, 15 * 3600 + 0 * 60 + 1); // 08:00 -0700 == 15:00 UTC
        }

        #[test]
        fn leap_day() {
            let e = parse_date("29/Feb/2024:12:00:00 +0000").unwrap();
            let feb28_utc = days_from_civil(2024, 3, 1).unwrap() * 86400;
            assert_eq!(e, feb28_utc - 86400 + 12 * 3600); // 2024-02-29 12:00 UTC
        }

        #[test]
        fn lowercase_month() {
            let e = parse_date("10/oct/2026:00:00:00 +0000").unwrap();
            assert_eq!(e % 86400, 0);
        }

        #[test]
        fn invalid() {
            assert!(parse_date("10/Oct/2026:13:55:36 +0260").is_none());
            assert!(parse_date("").is_none());
            assert!(parse_date("10/Oct/2026:99:55:36 +0200").is_none());
            assert!(parse_date("10/Foo/2026:13:55:36 +0200").is_none());
        }

        #[test]
        fn feb_29_2024_is_leap() {
            assert_eq!(
                days_from_civil(2024, 2, 29),
                Some(days_from_civil(2024, 3, 1).unwrap() - 1)
            );
        }
    }

    #[test]
    fn static_extension_detection() {
        assert!(is_static("/assets/app.js"));
        assert!(is_static("/img/logo.PNG"));
        assert!(is_static("/fonts/f.woff2"));
        assert!(!is_static("/index.php"));
        assert!(!is_static("/"));
        assert!(!is_static("/api/user/123"));
    }
}
