//! The matrix's server-side tallies, written only when `FERROX_BENCH_COUNTERS` names a path.
//!
//! A cell's `cell.json` carries the server's CPU, RSS and thread peak, which cannot say where a
//! serving thread spends its time. These counters answer that on a diagnostic dispatch: each is
//! bumped once per batch or per visit, never per byte, so the cost sits below the measurement floor
//! and an unset path costs one relaxed add.

use std::sync::atomic::{AtomicU64, Ordering};

pub const TURNS: usize = 0;
pub const IDLE_WAITS: usize = 1;
pub const CHANNEL_PACKETS: usize = 2;
pub const SERVED_PACKETS: usize = 3;
pub const VISITS: usize = 4;
pub const FLUSHES: usize = 5;
pub const GATHERS: usize = 6;
pub const QUEUED_PACKETS: usize = 7;
pub const QUEUED_BYTES: usize = 8;
pub const FRAMES: usize = 9;
pub const READ_BYTES: usize = 10;
pub const READ_WAITS: usize = 11;
pub const GATHER_FULL: usize = 12;
pub const GATHER_DRY: usize = 13;
pub const FRAMES_QUEUED: usize = 14;

const NAMES: [&str; 15] = [
    "srv_turns",
    "srv_idle_waits",
    "srv_channel_packets",
    "srv_served_packets",
    "h2_visits",
    "h2_flushes",
    "h2_gathers",
    "h2_queued_packets",
    "h2_queued_bytes",
    "h2_frames",
    "h2_read_bytes",
    "h2_read_waits",
    "h2_gather_full",
    "h2_gather_dry",
    "h2_frames_queued",
];

static COUNTERS: [AtomicU64; 15] = [const { AtomicU64::new(0) }; 15];

/// Adds `by` to one counter. A batch-sized bump on a `Relaxed` atomic is a single store.
pub fn add(counter: usize, by: u64) {
    COUNTERS[counter].fetch_add(by, Ordering::Relaxed);
}

pub fn bump(counter: usize) {
    add(counter, 1);
}

/// Every counter as one JSON object, in `NAMES` order.
pub fn dump() -> String {
    let mut out = String::from("{");
    for (index, name) in NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":");
        out.push_str(&COUNTERS[index].load(Ordering::Relaxed).to_string());
    }
    out.push('}');
    out
}

/// Starts the dump clock when `FERROX_BENCH_COUNTERS` names a path. The file is rewritten whole, so
/// the last window survives even a `SIGKILL`ed server; the thread ends with the process.
pub fn install() {
    let Ok(path) = std::env::var("FERROX_BENCH_COUNTERS") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = std::fs::write(&path, dump());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_dump_names_every_bump() {
        bump(READ_BYTES);
        add(QUEUED_BYTES, 4096);
        let dumped = dump();
        for name in NAMES {
            assert!(
                dumped.contains(&format!("\"{name}\":")),
                "{dumped} names {name}"
            );
        }
        assert!(dumped.starts_with(&format!(
            "{{\"srv_turns\":{}",
            COUNTERS[TURNS].load(Ordering::Relaxed)
        )));
        let reads = COUNTERS[READ_BYTES].load(Ordering::Relaxed);
        assert!(dumped.contains(&format!("\"h2_read_bytes\":{reads}")));
        assert!(dumped.contains(&format!(
            "\"h2_queued_bytes\":{}",
            COUNTERS[QUEUED_BYTES].load(Ordering::Relaxed)
        )));
    }
}
