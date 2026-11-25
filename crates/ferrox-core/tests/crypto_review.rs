use std::panic::{AssertUnwindSafe, catch_unwind};

use ferrox_core::alloc_count::{Counts, measure};
use ferrox_core::blake2s::Blake2s;
use ferrox_core::poly1305::Poly1305;

#[test]
fn the_mac_debug_output_redacts_the_accumulator() {
    let mut mac = Poly1305::new(&[0x5a; 32]);
    mac.update(b"a secret that moves the accumulator");
    let shown = format!("{mac:?}");
    assert!(
        !shown.contains("h:"),
        "the one-time accumulator is secret state, not a Debug field: {shown}"
    );
}

#[test]
fn the_keyed_hash_debug_output_redacts_its_state() {
    let mut hash = Blake2s::new(b"a secret key", 32);
    hash.update(b"a secret input");
    let shown = format!("{hash:?}");
    assert!(
        !shown.contains("h:") && !shown.contains("buffer:"),
        "the chaining state and padded key block are secret state, not Debug fields: {shown}"
    );
}

#[test]
fn a_panicking_measurement_does_not_poison_the_next_window() {
    let first = catch_unwind(AssertUnwindSafe(|| {
        measure(|| panic!("a measured closure failed"));
    }));
    assert!(first.is_err(), "the closure must panic");

    let ((), counts) = measure(|| {});
    assert_eq!(
        counts,
        Counts {
            allocs: 0,
            bytes: 0,
            zeroed: 0,
            zeroed_bytes: 0,
        },
        "the next window counts its own closure, not the failed one"
    );
}
