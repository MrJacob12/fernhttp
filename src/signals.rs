//! Graceful shutdown: install SIGINT/SIGTERM (Ctrl+C on Windows) handlers
//! with raw FFI so no external crate is needed. The handlers only flip an
//! atomic; the ingest loop observes it, flushes and exits.

use std::sync::atomic::{AtomicBool, Ordering};

pub static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
pub fn install() {
    extern "C" {
        fn signal(sig: i32, handler: unsafe extern "C" fn(i32)) -> usize;
    }
    unsafe extern "C" fn on_signal(_sig: i32) {
        STOP.store(true, Ordering::SeqCst);
    }
    unsafe {
        signal(2, on_signal); // SIGINT
        signal(15, on_signal); // SIGTERM
    }
}

#[cfg(windows)]
pub fn install() {
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    unsafe extern "system" fn on_ctrl(_ctrl_type: u32) -> i32 {
        STOP.store(true, Ordering::SeqCst);
        1 // handled
    }
    unsafe {
        SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

#[cfg(not(any(unix, windows)))]
pub fn install() {
    // No signal support on this platform; relies on process kill.
}
