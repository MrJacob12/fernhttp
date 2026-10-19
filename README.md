# fernhttp

Lightweight Apache log analyzer: tails access logs into SQLite (permanent history) and serves a real-time GoAccess-style dashboard over HTTP and Server-Sent Events (SSE).

One static binary. Zero runtime dependencies beyond the filesystem. `rusqlite` (bundled SQLite) is the only native dependency; the HTTP server, JSON writer, log parser, User-Agent classifier, and CLI parsing are implemented using standard library features.

## Build

```sh
cargo build --release
# -> target/release/fernhttp.exe (Windows) / fernhttp (Unix)
```

Release profile: `opt-level=3`, `lto`, `codegen-units=1`, `panic=abort`, `strip` producing a compact standalone binary.

## Quick Start

```sh
./fernhttp --log /var/log/apache2/access.log --db ./logs.db --port 7890
# open http://127.0.0.1:7890/
```

The application imports existing log files on first start, then tails new log entries in real-time.

## Options

```
--config FILE   key=value configuration file
--log PATH      Apache access log to tail (repeatable or comma-separated --log a.log,b.log)
--logs-dir DIR  load every *access.log in a directory (each file becomes a dashboard tab)
--db PATH       SQLite database path (default: fernhttp.db)
--host ADDR     bind address (default: 127.0.0.1)
--port N        HTTP port (default: 7890)
--poll MS       tailer poll interval in milliseconds (default: 500)
```

Configuration file format (`--config`), CLI flags take precedence:

```ini
log = /var/log/apache2/access.log
db  = /srv/fernhttp/logs.db
port = 7890
host = 0.0.0.0
poll = 500
```

## Log Formats

Common and Combined Log Format — auto-detected, no configuration required:

```
IP USER [10/Oct/2026:13:55:36 +0200] "GET /path HTTP/1.1" 200 2326 ["referer"] ["user-agent"]
```

- Single-pass byte parser without regular expressions; malformed lines are skipped and counted.
- Built-in date parser with DST-safe civil to epoch conversion, storing Unix timestamps.
- Handles IPv6, special fields, escaped quotes, and CRLF line endings.

## HTTP API

| Route | Description |
|---|---|
| `GET /` | Dashboard interface (single HTML file, vanilla JavaScript) |
| `GET /api/stats?from=&to=&source=` | Full statistics JSON with response caching |
| `GET /api/sources` | Log files with request counts and tab definitions |
| `GET /api/detail?kind=&value=` | Drill-down data for selected aggregates |
| `GET /events` | Server-Sent Events stream for real-time dashboard updates |

## Analytics Overview

- General statistics: requests, unique IP addresses, total transfer volume, status code distribution, average response size
- Time-based series: per-minute, per-hour, and per-day aggregations, hour by day-of-week heatmap
- Resources: top requested paths, static files, 404 errors, 5xx errors, largest responses, top directories
- Visitors: top IP addresses, new versus returning visitors
- Referrers: top URLs, referrer domains, search engine query phrases
- Clients: browser types, operating systems, devices, search engine bots
- Protocol and method distributions
- Anomalies: error rate spikes, potential scanners, suspicious paths

## Docker Deployment

```sh
mkdir -p logs data
docker compose up -d --build
# dashboard: http://127.0.0.1:7890/
```

Compose maps `./logs` (read-only Apache log directory) and `./data` (SQLite database storage). Configuration is managed through environment variables (`LOG_PATH`, `LOGS_DIR`, `DB_PATH`, `HOST`, `PORT`, `POLL_MS`).

## systemd Service

Copy and adjust `fernhttp.service`:

```sh
sudo cp fernhttp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now fernhttp
```

## License

MIT License.
