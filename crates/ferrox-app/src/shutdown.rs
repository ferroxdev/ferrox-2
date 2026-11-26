//! Route restoration for a process that is asked to stop.
//!
//! A `tun_route::Guard` restores the table when it drops, but a signal or a
//! `TerminateProcess` never runs a destructor. The CLI writes a stop file (its
//! portable form) and signals on Unix; both end here, where the live guards are
//! released explicitly before the process exits.

use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
static SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn on_signal(signal: libc::c_int) {
    SIGNAL.store(signal, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signals() {
    let handler = on_signal as *const () as libc::sighandler_t;
    // SAFETY: the handler only stores into an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGHUP, handler);
    }
}

#[cfg(not(unix))]
fn install_signals() {}

#[cfg(unix)]
fn signalled() -> bool {
    SIGNAL.load(std::sync::atomic::Ordering::Relaxed) != 0
}

#[cfg(not(unix))]
fn signalled() -> bool {
    false
}

/// Start the watcher that restores the table and exits. The launcher removes
/// the stop file before spawn, so a restarted lane never sees the old request.
pub(crate) fn watch() {
    install_signals();
    let stop_file = std::env::var_os("FERROX_STOP_FILE").map(std::path::PathBuf::from);
    let spawned = std::thread::Builder::new()
        .name("ferrox-shutdown".to_owned())
        .spawn(move || {
            loop {
                let asked = stop_file.as_deref().is_some_and(Path::exists);
                if asked || signalled() {
                    if let Some(path) = stop_file.as_deref() {
                        let _ = std::fs::remove_file(path);
                    }
                    crate::tun_route::release_all();
                    std::process::exit(0);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    if let Err(error) = spawned {
        eprintln!("ferrox-app: could not start the shutdown watcher: {error}");
    }
}
