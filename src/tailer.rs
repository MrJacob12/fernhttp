//! Tailer: polls a log file, detects rotation/truncation, parses new lines
//! and ships `LogEntry` chunks to the ingest thread over mpsc.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::mpsc::Sender;

use crate::parser::{parse_line, LogEntry};

pub enum TailMsg {
    /// Parsed entries seen since the previous poll, attributed to the
    /// source (log file) they came from, together with the tail state that
    /// includes exactly those entries — flushing with this offset never
    /// leaves a gap that a restart would re-read.
    Chunk {
        source_id: i64,
        entries: Vec<LogEntry>,
        offset: u64,
        fp: u64,
    },
    /// Tail state after a poll: source path, byte offset into the log, file
    /// fingerprint, and running count of unparseable lines.
    Sync {
        path: PathBuf,
        offset: u64,
        fp: u64,
        invalid: u64,
    },
}

/// Stable file identity: survives appends, changes on rotation/replacement.
/// Unix: inode. Windows: (volume serial, file index) via raw FFI, because
/// `std::os::windows::fs::MetadataExt::file_index` is still unstable.
#[cfg(unix)]
pub fn file_identity(file: &fs::File) -> u64 {
    use std::os::unix::fs::MetadataExt;
    file.metadata().map(|m| m.ino()).unwrap_or(0)
}

#[cfg(windows)]
pub fn file_identity(file: &fs::File) -> u64 {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct ByHandleFileInfo {
        file_attributes: u32,
        creation_low: u32,
        creation_high: u32,
        access_low: u32,
        access_high: u32,
        write_low: u32,
        write_high: u32,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            info: *mut ByHandleFileInfo,
        ) -> i32;
    }

    let mut info = std::mem::MaybeUninit::<ByHandleFileInfo>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return 0;
    }
    let info = unsafe { info.assume_init() };
    ((info.volume as u64) << 32) | ((info.index_high as u64) << 32) | info.index_low as u64
}

#[cfg(not(any(unix, windows)))]
pub fn file_identity(_file: &fs::File) -> u64 {
    0
}

pub struct Tailer {
    files: Vec<FileTail>,
}

/// Per-file tail state: one instance per configured log.
struct FileTail {
    path: PathBuf,
    /// Source id in the `sources` table (dashboard tab attribution).
    source_id: i64,
    offset: u64,
    fp: u64,
    /// Bytes after the last complete line, carried between polls.
    pending: Vec<u8>,
    /// Parsed entries for this poll cycle, sent as one chunk.
    entries: Vec<LogEntry>,
    /// Number of lines that failed to parse (grows monotonically).
    invalid: u64,
}

impl Tailer {
    /// Resume from previously stored positions (one
    /// (path, offset, fp, source_id) tuple per log file; first-run files
    /// start at (path, 0, 0, source_id)).
    pub fn resume(files: Vec<(PathBuf, u64, u64, i64)>) -> Tailer {
        Tailer {
            files: files
                .into_iter()
                .map(|(path, offset, fp, source_id)| FileTail {
                    path,
                    source_id,
                    offset,
                    fp,
                    pending: Vec::new(),
                    entries: Vec::new(),
                    invalid: 0,
                })
                .collect(),
        }
    }

    /// One poll cycle over every file: detect rotation/truncation, read new
    /// bytes, parse complete lines, send chunks + syncs tagged per file.
    pub fn poll(&mut self, tx: &Sender<TailMsg>) {
        for f in &mut self.files {
            f.poll(tx);
        }
    }
}

impl FileTail {

    /// One poll cycle: detect rotation/truncation, read new bytes, parse
    /// complete lines, send chunks + sync state.
    pub fn poll(&mut self, tx: &Sender<TailMsg>) {
        let md = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => {
                // File gone (deletion or rename-before-recreate). Wait at 0.
                if self.fp != 0 || self.offset != 0 {
                    eprintln!(
                        "fernhttp: log file missing ({}) — waiting for it",
                        self.path.display()
                    );
                    self.fp = 0;
                    self.offset = 0;
                    self.pending.clear();
                }
                return;
            }
        };
        let mut file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("fernhttp: cannot open log: {e}");
                return;
            }
        };
        let fp = file_identity(&file);
        if fp != self.fp {
            if self.fp != 0 {
                eprintln!(
                    "fernhttp: log rotated ({}) — continuing from new file",
                    self.path.display()
                );
            }
            self.fp = fp;
            self.offset = 0;
            self.pending.clear();
        } else if md.len() < self.offset {
            eprintln!(
                "fernhttp: log truncated ({}) — continuing from offset 0",
                self.path.display()
            );
            self.offset = 0;
            self.pending.clear();
        }

        if let Err(e) = file.seek(SeekFrom::Start(self.offset + self.pending.len() as u64)) {
            eprintln!("fernhttp: seek failed: {e}");
            return;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
        if let Err(e) = file.read_to_end(&mut buf) {
            eprintln!("fernhttp: read failed: {e}");
            return;
        }
        if buf.is_empty() && self.pending.is_empty() {
            let _ = tx.send(TailMsg::Sync {
                path: self.path.clone(),
                offset: self.offset,
                fp: self.fp,
                invalid: self.invalid,
            });
            return;
        }

        let carry_len = self.pending.len() as u64; // bytes already counted in self.offset
        let mut all = std::mem::take(&mut self.pending);
        all.extend_from_slice(&buf);

        match all.iter().rposition(|&b| b == b'\n') {
            Some(pos) => {
                for line in all[..=pos].split(|&b| b == b'\n') {
                    let line = std::str::from_utf8(line).unwrap_or("");
                    let line = line.trim_end_matches('\r');
                    if line.is_empty() {
                        continue; // trailing newline produces an empty segment
                    }
                    match parse_line(line) {
                        Some(e) => self.entries.push(e),
                        None => self.invalid += 1,
                    }
                }
                self.offset += (pos as u64 + 1) - carry_len;
                self.pending = all[pos + 1..].to_vec();
            }
            None => {
                self.pending = all;
            }
        }
        if !self.entries.is_empty() {
            let entries = std::mem::take(&mut self.entries);
            let _ = tx.send(TailMsg::Chunk {
                source_id: self.source_id,
                entries,
                offset: self.offset,
                fp: self.fp,
            });
        }
        let _ = tx.send(TailMsg::Sync {
            path: self.path.clone(),
            offset: self.offset,
            fp: self.fp,
            invalid: self.invalid,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn line(n: i32) -> String {
        format!(
            r#"10.0.0.{} - - [01/Jan/2026:12:00:00 +0000] "GET /p{} HTTP/1.1" 200 42"#,
            n % 100,
            n
        ) + "\n"
    }

    /// The Chunk's offset must cover exactly the entries it carries, so a
    /// flush persisting it can never leave a gap a restart would re-read
    /// (regression: flush fired before the trailing Sync, then hard kill →
    /// duplicated lines).
    #[test]
    fn chunk_carries_offset_of_its_entries() {
        let dir = std::env::temp_dir().join(format!("grs-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.log");
        std::fs::write(&path, line(1) + &line(2) + &line(3)).unwrap();
        let (tx, rx) = mpsc::channel::<TailMsg>();
        let mut t = Tailer::resume(vec![(path.clone(), 0, 0, 7)]);
        t.poll(&tx);
        let mut chunk = None;
        let mut syncs = 0;
        while let Ok(m) = rx.try_recv() {
            match m {
                TailMsg::Chunk {
                    source_id,
                    entries,
                    offset,
                    fp,
                } => {
                    assert_eq!(source_id, 7);
                    assert_eq!(entries.len(), 3);
                    assert_eq!(offset, std::fs::metadata(&path).unwrap().len());
                    assert_ne!(fp, 0);
                    chunk = Some((offset, fp));
                }
                TailMsg::Sync { .. } => syncs += 1,
            }
        }
        assert!(chunk.is_some());
        assert!(syncs >= 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
