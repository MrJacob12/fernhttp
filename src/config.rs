//! Configuration: CLI flags and optional `key = value` config file.
//!
//! Precedence (lowest to highest): built-in defaults, config file, CLI flags.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub log: Vec<PathBuf>, // Apache access logs to tail (repeatable / comma-separated)
    pub logs_dir: Option<PathBuf>, // scan this dir for *access.log files (all hosts)
    pub db: PathBuf,       // SQLite database path
    pub host: String,      // bind address
    pub port: u16,         // HTTP port
    pub poll_ms: u64,      // tailer poll interval
}

/// Built-in default used as a sentinel: the first explicit log assignment
/// replaces it, later assignments append.
const DEFAULT_LOG: &str = "access.log";

impl Default for Config {
    fn default() -> Self {
        Config {
            log: vec![PathBuf::from(DEFAULT_LOG)],
            logs_dir: None,
            db: PathBuf::from("fernhttp.db"),
            host: String::from("127.0.0.1"),
            port: 7890,
            poll_ms: 500,
        }
    }
}

impl Config {
    /// Apply one `key = value` pair. `None` result means "unknown key".
    fn apply(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "log" => {
                // First assignment replaces the built-in default; later ones
                // append, so repeated --log flags, repeated config-file keys
                // and comma-separated values all merge into one list.
                let is_default = self.log.len() == 1
                    && self.log[0].as_os_str() == std::ffi::OsStr::new(DEFAULT_LOG);
                if is_default {
                    self.log.clear();
                }
                for p in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    self.log.push(PathBuf::from(p));
                }
            }
            "db" => self.db = PathBuf::from(value),
            "logs-dir" => self.logs_dir = Some(PathBuf::from(value)),
            "host" => self.host = value.to_string(),
            "port" => self.port = parse_u16("port", value)?,
            "poll" => self.poll_ms = parse_num("poll", value)?,
            _ => return Err(format!("unknown option '{key}'")),
        }
        Ok(())
    }
}

fn parse_u16(name: &str, v: &str) -> Result<u16, String> {
    parse_num::<u64>(name, v).and_then(|n| {
        if n <= 65535 {
            Ok(n as u16)
        } else {
            Err(format!("{name} out of range: {v}"))
        }
    })
}

fn parse_num<T: std::str::FromStr>(name: &str, v: &str) -> Result<T, String> {
    v.trim()
        .parse::<T>()
        .map_err(|_| format!("invalid value for '{name}': '{v}'"))
}

/// Load configuration: defaults <- config file (if any) <- CLI args.
pub fn load(args: &[String]) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            return Err("help".to_string());
        }
        if arg == "--config" {
            i += 1;
            let path = args.get(i).ok_or("--config requires a path")?;
            apply_file(&mut cfg, &PathBuf::from(path))?;
        } else if let Some(stripped) = arg.strip_prefix("--") {
            // --key value or --key=value
            let (key, value) = match stripped.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or(format!("--{stripped} requires a value"))?;
                    (stripped.to_string(), v.clone())
                }
            };
            cfg.apply(&key, &value)?;
        } else if !arg.is_empty() && !arg.starts_with('-') && cfg.log.len() == 1
            && cfg.log[0].as_os_str() == std::ffi::OsStr::new(DEFAULT_LOG)
        {
            // positional shorthand for the log path
            cfg.log = vec![PathBuf::from(arg)];
        } else {
            return Err(format!("unexpected argument '{arg}' (use --help)"));
        }
        i += 1;
    }
    // `--logs-dir`: every file whose name ends in "access.log" becomes a
    // source (Apache's per-vhost convention: <host>-access.log, plus the
    // bare access.log). Explicit --log entries keep their order first;
    // duplicates are dropped.
    if let Some(dir) = &cfg.logs_dir {
        let is_default = cfg.log.len() == 1
            && cfg.log[0].as_os_str() == std::ffi::OsStr::new(DEFAULT_LOG);
        if is_default {
            cfg.log.clear();
        }
        let mut found: Vec<PathBuf> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for en in rd.flatten() {
                let p = en.path();
                let name_ok = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n.ends_with("access.log"));
                if name_ok && p.is_file() {
                    found.push(p);
                }
            }
        }
        found.sort();
        for p in found {
            if !cfg.log.iter().any(|x| x.as_path() == p.as_path()) {
                cfg.log.push(p);
            }
        }
    }
    Ok(cfg)
}

fn apply_file(cfg: &mut Config, path: &PathBuf) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "{}:{}: expected 'key = value'",
                path.display(),
                lineno + 1
            ));
        };
        let (k, v) = (k.trim(), v.trim());
        cfg.apply(k, v)
            .map_err(|e| format!("{}:{}: {e}", path.display(), lineno + 1))?;
    }
    Ok(())
}

pub fn usage() -> String {
    "Usage: fernhttp [--config FILE] [--log PATH]... [--logs-dir DIR] [--db PATH] [--host ADDR] [--port N] [--poll MS]
  positional argument = log path (shorthand)
  --log may be repeated or comma-separated (--log a.log,b.log) to tail several
  logs at once; config-file 'log =' keys merge the same way
  --logs-dir DIR loads every *access.log file in a directory (per-host tabs
  on the dashboard); combined with --log entries are merged and de-duplicated
  options may also be set in a key=value config file; CLI wins".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults() {
        let cfg = load(&args(&[])).unwrap();
        assert_eq!(cfg.port, 7890);
        assert_eq!(cfg.poll_ms, 500);
        assert_eq!(cfg.host, "127.0.0.1");
    }

    #[test]
    fn cli_flags() {
        let cfg = load(&args(&["--log", "a.log", "--db", "x.db", "--port", "9000"])).unwrap();
        assert_eq!(cfg.log, vec![PathBuf::from("a.log")]);
        assert_eq!(cfg.db, PathBuf::from("x.db"));
        assert_eq!(cfg.port, 9000);
    }

    #[test]
    fn multiple_logs_repeat_and_comma() {
        let cfg = load(&args(&[
            "--log", "a.log", "--log", "b.log", "--log", "c.log,d.log",
        ]))
        .unwrap();
        assert_eq!(
            cfg.log,
            vec![
                PathBuf::from("a.log"),
                PathBuf::from("b.log"),
                PathBuf::from("c.log"),
                PathBuf::from("d.log")
            ]
        );
    }

    #[test]
    fn comma_log_replaces_default() {
        let cfg = load(&args(&["--log", "a.log,b.log"])).unwrap();
        assert_eq!(cfg.log, vec![PathBuf::from("a.log"), PathBuf::from("b.log")]);
    }

    #[test]
    fn config_file_logs_merge_with_cli() {
        let dir = std::env::temp_dir().join(format!("grs-test-merge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.conf");
        std::fs::write(
            &path,
            "log = file-a.log\nlog = file-b.log,file-c.log\n",
        )
        .unwrap();
        let cfg = load(&args(&["--config", path.to_str().unwrap(), "--log", "cli.log"])).unwrap();
        assert_eq!(
            cfg.log,
            vec![
                PathBuf::from("file-a.log"),
                PathBuf::from("file-b.log"),
                PathBuf::from("file-c.log"),
                PathBuf::from("cli.log")
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_equals_form() {
        let cfg = load(&args(&["--port=8080", "--poll=250"])).unwrap();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.poll_ms, 250);
    }

    #[test]
    fn positional_log() {
        let cfg = load(&args(&["/var/log/apache/access.log"])).unwrap();
        assert_eq!(cfg.log, vec![PathBuf::from("/var/log/apache/access.log")]);
    }

    #[test]
    fn logs_dir_scans_all_hosts() {
        let dir = std::env::temp_dir().join(format!("grs-test-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("git-access.log"), "").unwrap();
        std::fs::write(dir.join("api-access.log"), "").unwrap();
        std::fs::write(dir.join("other_vhosts_access.log"), "").unwrap();
        std::fs::write(dir.join("access.log"), "").unwrap();
        std::fs::write(dir.join("error.log"), "").unwrap(); // not an access log
        std::fs::write(dir.join("git-access.log.1"), "").unwrap(); // rotated — excluded
        let cfg = load(&args(&["--logs-dir", dir.to_str().unwrap()])).unwrap();
        let names: Vec<String> = cfg
            .log
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "access.log",
                "api-access.log",
                "git-access.log",
                "other_vhosts_access.log"
            ]
        );
        // explicit --log keeps its order and scans are de-duplicated
        let cfg2 =
            load(&args(&["--logs-dir", dir.to_str().unwrap(), "--log", "z.log"])).unwrap();
        assert_eq!(cfg2.log.first().unwrap().file_name().unwrap(), "z.log");
        assert_eq!(cfg2.log.len(), 5); // z.log + 4 from dir
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_key_rejected() {
        assert!(load(&args(&["--bogus", "1"])).is_err());
    }

    #[test]
    fn bad_port_rejected() {
        assert!(load(&args(&["--port", "abc"])).is_err());
        assert!(load(&args(&["--port", "70000"])).is_err());
    }

    #[test]
    fn config_file() {
        let dir = std::env::temp_dir().join(format!("grs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.conf");
        std::fs::write(&path, "# comment\nport = 8123\nhost=0.0.0.0\n").unwrap();
        let cfg = load(&args(&[
            "--config",
            path.to_str().unwrap(),
            "--port",
            "9999",
        ]))
        .unwrap();
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 9999); // CLI wins over file
        std::fs::remove_dir_all(&dir).ok();
    }
}
