use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

const PACKETS: usize = 65_536;
const ROUNDS: usize = 9;

fn prefix_len(data: &[u8]) -> usize {
    match black_box(ferrox_core::tuic::parse_packet_prefix(data)) {
        Ok((_, used)) => used,
        Err(_) => 0,
    }
}

fn double_parse(data: &[u8]) -> usize {
    match black_box(ferrox_core::tuic::parse_packet_prefix(data)) {
        Ok((_, used)) => match black_box(ferrox_core::tuic::parse_packet(&data[..used])) {
            Ok(packet) => packet.payload.len(),
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

fn elapsed<R>(run: &mut impl FnMut(&[u8]) -> R, frame: &[u8]) -> f64 {
    let start = Instant::now();
    for _ in 0..PACKETS {
        let _ = black_box(run(black_box(frame)));
    }
    start.elapsed().as_nanos() as f64 / PACKETS as f64
}

const BURST: usize = 512;

fn walk_offset(mut buf: Vec<u8>) -> usize {
    let mut at = 0usize;
    let mut frames = 0usize;
    loop {
        match ferrox_core::tuic::parse_packet_prefix(&buf[at..]) {
            Ok((_, used)) if used > 0 => {
                at += used;
                frames += 1;
            }
            _ => break,
        }
    }
    if at > 0 {
        buf.drain(..at);
    }
    frames
}

fn walk_drain(mut buf: Vec<u8>) -> usize {
    let mut frames = 0usize;
    loop {
        match ferrox_core::tuic::parse_packet_prefix(&buf) {
            Ok((_, used)) if used > 0 => {
                buf.drain(..used);
                frames += 1;
            }
            _ => return frames,
        }
    }
}

/// The worker's `MAX_SESSIONS`, so the sweep prices a map that can exist.
const SESSIONS: usize = 1024;

fn sweep_list(ids: &[usize], seen: &mut Vec<usize>) -> usize {
    seen.clear();
    let mut visited = 0;
    for &id in ids {
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        visited += 1;
    }
    visited
}

fn sweep_set(ids: &[usize], seen: &mut std::collections::HashSet<usize>) -> usize {
    seen.clear();
    let mut visited = 0;
    for &id in ids {
        if !seen.insert(id) {
            continue;
        }
        visited += 1;
    }
    visited
}

fn measure<A, B>(
    mut first: impl FnMut(&[u8]) -> A,
    mut second: impl FnMut(&[u8]) -> B,
    frame: &[u8],
) -> (f64, f64) {
    let mut first_best = f64::MAX;
    let mut second_best = f64::MAX;
    for round in 0..ROUNDS {
        let (first_ns, second_ns) = if round % 2 == 0 {
            let first_ns = elapsed(&mut first, frame);
            (first_ns, elapsed(&mut second, frame))
        } else {
            let second_ns = elapsed(&mut second, frame);
            (elapsed(&mut first, frame), second_ns)
        };
        first_best = first_best.min(first_ns);
        second_best = second_best.min(second_ns);
    }
    (first_best, second_best)
}

fn sweep_section(out: &mut String) {
    let ids: Vec<usize> = (0..SESSIONS).map(|n| n * 64 + 1).collect();
    let mut listed_seen: Vec<usize> = Vec::with_capacity(SESSIONS);
    let mut hashed_seen = std::collections::HashSet::with_capacity(SESSIONS);
    let aliases = [65usize, 129, 65, 193, 129];
    assert_eq!(
        sweep_list(&aliases, &mut listed_seen),
        3,
        "an alias is one visit"
    );
    assert_eq!(
        sweep_set(&aliases, &mut hashed_seen),
        3,
        "an alias is one visit"
    );
    let mut list_best = f64::MAX;
    let mut set_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            let start = Instant::now();
            let listed = black_box(sweep_list(black_box(&ids), black_box(&mut listed_seen)));
            list_best = list_best.min(start.elapsed().as_nanos() as f64);
            let start = Instant::now();
            let hashed = black_box(sweep_set(black_box(&ids), black_box(&mut hashed_seen)));
            set_best = set_best.min(start.elapsed().as_nanos() as f64);
            assert_eq!(listed, hashed, "both sweeps visit every session once");
        } else {
            let start = Instant::now();
            let hashed = black_box(sweep_set(black_box(&ids), black_box(&mut hashed_seen)));
            set_best = set_best.min(start.elapsed().as_nanos() as f64);
            let start = Instant::now();
            let listed = black_box(sweep_list(black_box(&ids), black_box(&mut listed_seen)));
            list_best = list_best.min(start.elapsed().as_nanos() as f64);
            assert_eq!(listed, hashed, "both sweeps visit every session once");
        }
    }
    let _ = writeln!(out, "\n## TUIC sweep dedupe\n");
    let _ = writeln!(out, "| path | ms/sweep | ns/session |");
    let _ = writeln!(out, "|---|---:|---:|");
    let _ = writeln!(
        out,
        "| list scan | {:.3} | {:.1} |",
        list_best / 1_000_000.0,
        list_best / SESSIONS as f64
    );
    let _ = writeln!(
        out,
        "| identity set | {:.3} | {:.1} |",
        set_best / 1_000_000.0,
        set_best / SESSIONS as f64
    );
}

/// The tap lookup a received datagram makes, priced at the 256 associations the serving side caps a
/// session at: scanned against a list, or found in a map.
const SINKS: usize = 256;

fn sink_scan(taps: &[(u16, usize)], association: u16) -> Option<usize> {
    for &(tap, at) in taps {
        if tap == association {
            return Some(at);
        }
    }
    None
}

fn time_sink(mut lookup: impl FnMut(usize) -> Option<usize>) -> f64 {
    let start = Instant::now();
    for index in 0..PACKETS {
        let _ = black_box(lookup(black_box(index % SINKS)));
    }
    start.elapsed().as_nanos() as f64 / PACKETS as f64
}

fn sink_section(out: &mut String) {
    let taps: Vec<(u16, usize)> = (0..SINKS)
        .map(|at| (u16::try_from(at).expect("a tap") * 3, at))
        .collect();
    let map: std::collections::HashMap<u16, usize> = taps.iter().copied().collect();
    for at in [0usize, SINKS / 2, SINKS - 1] {
        assert_eq!(
            sink_scan(&taps, taps[at].0),
            map.get(&taps[at].0).copied(),
            "both find the same tap"
        );
    }
    assert_eq!(
        sink_scan(&taps, u16::MAX),
        None,
        "a stray association is not a tap"
    );
    let mut scan_best = f64::MAX;
    let mut map_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            scan_best = scan_best.min(time_sink(|at| sink_scan(&taps, taps[at].0)));
            map_best = map_best.min(time_sink(|at| map.get(&taps[at].0).copied()));
        } else {
            map_best = map_best.min(time_sink(|at| map.get(&taps[at].0).copied()));
            scan_best = scan_best.min(time_sink(|at| sink_scan(&taps, taps[at].0)));
        }
    }
    let _ = writeln!(out, "\n## TUIC sink lookup\n");
    let _ = writeln!(out, "| path | ns/datagram |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| list scan, {SINKS} taps | {scan_best:.1} |");
    let _ = writeln!(out, "| association map | {map_best:.1} |");
}

/// The xHTTP packet-up session's pending-packet map, priced as the session drives it: a push behind
/// the window and the read that takes the head, at the pending depth the session caps itself at.
const PENDING: u64 = 64;

fn btree_cycle(
    map: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    pool: &mut Vec<Vec<u8>>,
    next: &mut u64,
) -> usize {
    for (seq, payload) in (*next..).zip(pool.drain(..)) {
        map.insert(seq, payload);
    }
    for _ in 0..PENDING {
        let payload = map.remove(&*next).expect("the head packet");
        *next += 1;
        pool.push(payload);
    }
    usize::try_from(PENDING).expect("a pending depth")
}

fn hash_cycle(
    map: &mut std::collections::HashMap<u64, Vec<u8>>,
    pool: &mut Vec<Vec<u8>>,
    next: &mut u64,
) -> usize {
    for (seq, payload) in (*next..).zip(pool.drain(..)) {
        map.insert(seq, payload);
    }
    for _ in 0..PENDING {
        let payload = map.remove(&*next).expect("the head packet");
        *next += 1;
        pool.push(payload);
    }
    usize::try_from(PENDING).expect("a pending depth")
}

fn time_packet_map(mut run: impl FnMut() -> usize) -> f64 {
    let start = Instant::now();
    let packets = run();
    start.elapsed().as_nanos() as f64 / packets as f64
}

fn packet_map_section(out: &mut String) {
    let depth = usize::try_from(PENDING).expect("a pending depth");
    let mut btree_pool: Vec<Vec<u8>> = (0..depth)
        .map(|at| vec![u8::try_from(at).expect("a packet tag"); 32])
        .collect();
    let mut hash_pool = btree_pool.clone();
    let mut btree = std::collections::BTreeMap::new();
    let mut hashed = std::collections::HashMap::new();
    let mut btree_next = 0u64;
    let mut hash_next = 0u64;
    let read_btree = btree_cycle(&mut btree, &mut btree_pool, &mut btree_next);
    let read_hash = hash_cycle(&mut hashed, &mut hash_pool, &mut hash_next);
    assert_eq!(read_btree, read_hash, "both drain the round whole");
    assert_eq!(
        btree_pool.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        hash_pool.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        "both hand the same payloads back in sequence order"
    );
    let mut btree_best = f64::MAX;
    let mut hash_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            btree_best = btree_best.min(time_packet_map(|| {
                btree_cycle(&mut btree, &mut btree_pool, &mut btree_next)
            }));
            hash_best = hash_best.min(time_packet_map(|| {
                hash_cycle(&mut hashed, &mut hash_pool, &mut hash_next)
            }));
        } else {
            hash_best = hash_best.min(time_packet_map(|| {
                hash_cycle(&mut hashed, &mut hash_pool, &mut hash_next)
            }));
            btree_best = btree_best.min(time_packet_map(|| {
                btree_cycle(&mut btree, &mut btree_pool, &mut btree_next)
            }));
        }
    }
    let _ = writeln!(out, "\n## xHTTP pending-packet map\n");
    let _ = writeln!(out, "| path | ns/packet |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| BTreeMap, {PENDING} pending | {btree_best:.1} |");
    let _ = writeln!(out, "| HashMap, {PENDING} pending | {hash_best:.1} |");
}

/// The one's-complement checksum the SNI decoy writes over an IPv4 header and a TCP segment: the
/// sixteen-bit word sum taken two bytes at a time, or eight bytes with the big-endian load's two
/// halves added (each weight is 1 modulo 0xffff) and folded at the end.
const CHECKSUM_BYTES: usize = 1500;

fn checksum_pairs(mut sum: u64, bytes: &[u8]) -> u64 {
    let (words, tail) = bytes.as_chunks::<2>();
    for pair in words {
        sum += u64::from(u16::from_be_bytes(*pair));
    }
    if let Some(byte) = tail.first() {
        sum += u64::from(*byte) << 8;
    }
    sum
}

fn checksum_wide(mut sum: u64, bytes: &[u8]) -> u64 {
    let (chunks, tail) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_be_bytes(*chunk);
        sum += (word >> 32) + (word & 0xffff_ffff);
    }
    let (pairs, odd) = tail.as_chunks::<2>();
    for pair in pairs {
        sum += u64::from(u16::from_be_bytes(*pair));
    }
    if let Some(byte) = odd.first() {
        sum += u64::from(*byte) << 8;
    }
    sum
}

fn checksum_fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("the folded sum is sixteen bits")
}

fn checksum_section(out: &mut String) {
    let bytes: Vec<u8> = (0..CHECKSUM_BYTES)
        .map(|at| u8::try_from((at * 37 + 11) & 0xff).expect("a byte"))
        .collect();
    for len in [0usize, 1, 7, 8, 9, 20, 64, CHECKSUM_BYTES] {
        assert_eq!(
            checksum_fold(checksum_wide(0, &bytes[..len])),
            checksum_fold(checksum_pairs(0, &bytes[..len])),
            "length {len}"
        );
    }
    let mut pairs_best = f64::MAX;
    let mut wide_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            let start = Instant::now();
            for _ in 0..PACKETS {
                let _ = black_box(checksum_fold(checksum_pairs(0, black_box(&bytes))));
            }
            pairs_best = pairs_best.min(start.elapsed().as_nanos() as f64 / PACKETS as f64);
            let start = Instant::now();
            for _ in 0..PACKETS {
                let _ = black_box(checksum_fold(checksum_wide(0, black_box(&bytes))));
            }
            wide_best = wide_best.min(start.elapsed().as_nanos() as f64 / PACKETS as f64);
        } else {
            let start = Instant::now();
            for _ in 0..PACKETS {
                let _ = black_box(checksum_fold(checksum_wide(0, black_box(&bytes))));
            }
            wide_best = wide_best.min(start.elapsed().as_nanos() as f64 / PACKETS as f64);
            let start = Instant::now();
            for _ in 0..PACKETS {
                let _ = black_box(checksum_fold(checksum_pairs(0, black_box(&bytes))));
            }
            pairs_best = pairs_best.min(start.elapsed().as_nanos() as f64 / PACKETS as f64);
        }
    }
    let _ = writeln!(out, "\n## SNI decoy checksum\n");
    let _ = writeln!(out, "| path | ns/{CHECKSUM_BYTES}-byte buffer |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| two bytes at a time | {pairs_best:.1} |");
    let _ = writeln!(out, "| eight bytes at a time | {wide_best:.1} |");
}

/// The master key and the SOCKS UDP reply head: both replaced a scratch buffer with a write into
/// a room the caller already holds.
const KEY_BYTES: usize = 64;
const KEY_PASSWORD: &str = "an-example-shared-password";
const REPLY_HEAD: usize = 22;
const REPLY_PAYLOAD: usize = 1200;

fn key_section(out: &mut String) {
    for (password, len) in [(KEY_PASSWORD, KEY_BYTES), ("secret", 32)] {
        assert_eq!(
            ferrox_core::shadowsocks::MasterKey::new(password, len).as_bytes(),
            ferrox_core::shadowsocks::reference_master_key(password, len).as_slice(),
            "{password}/{len}"
        );
    }
    let joined = || {
        let start = Instant::now();
        for _ in 0..PACKETS {
            let key =
                ferrox_core::shadowsocks::reference_master_key(black_box(KEY_PASSWORD), KEY_BYTES);
            let _ = black_box(key.as_slice());
        }
        start.elapsed().as_nanos() as f64 / PACKETS as f64
    };
    let streamed = || {
        let start = Instant::now();
        for _ in 0..PACKETS {
            let key = ferrox_core::shadowsocks::MasterKey::new(black_box(KEY_PASSWORD), KEY_BYTES);
            let _ = black_box(key.as_bytes());
        }
        start.elapsed().as_nanos() as f64 / PACKETS as f64
    };
    let mut joined_best = f64::MAX;
    let mut streamed_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            joined_best = joined_best.min(joined());
            streamed_best = streamed_best.min(streamed());
        } else {
            streamed_best = streamed_best.min(streamed());
            joined_best = joined_best.min(joined());
        }
    }
    let _ = writeln!(out, "\n## shadowsocks master key ({KEY_BYTES} bytes)");
    let _ = writeln!(out, "| path | ns/key |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| joined scratch buffer | {joined_best:.1} |");
    let _ = writeln!(out, "| one hash context | {streamed_best:.1} |");
}

fn reply_section(out: &mut String) {
    let target = ferrox_core::socks::Target::V6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        53,
    );
    let payload = [0x5au8; REPLY_PAYLOAD];
    let head = ferrox_core::socks::datagram_header_len(&target);
    assert_eq!(head, REPLY_HEAD, "the longest head is the fixed room");
    let mut joined = Vec::new();
    ferrox_core::socks::datagram(&target, &payload, &mut joined);
    let mut written = [0u8; REPLY_HEAD];
    written[..3].copy_from_slice(&[0, 0, 0]);
    target.encode_into(&mut written[3..]);
    assert_eq!(
        &written[..head],
        &joined[..head],
        "both shapes write one head"
    );
    let one_buffer = || {
        let start = Instant::now();
        for _ in 0..PACKETS {
            let mut frame = Vec::with_capacity(head + payload.len());
            ferrox_core::socks::datagram(&target, black_box(&payload), &mut frame);
            let _ = black_box(frame.as_slice());
        }
        start.elapsed().as_nanos() as f64 / PACKETS as f64
    };
    let mut room = [0u8; REPLY_HEAD];
    let mut split = || {
        let start = Instant::now();
        for _ in 0..PACKETS {
            room[..3].copy_from_slice(&[0, 0, 0]);
            target.encode_into(&mut room[3..]);
            let _ = black_box((black_box(&room[..head]), black_box(&payload[..])));
        }
        start.elapsed().as_nanos() as f64 / PACKETS as f64
    };
    let mut joined_best = f64::MAX;
    let mut split_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            joined_best = joined_best.min(one_buffer());
            split_best = split_best.min(split());
        } else {
            split_best = split_best.min(split());
            joined_best = joined_best.min(one_buffer());
        }
    }
    let _ = writeln!(out, "\n## SOCKS UDP reply ({REPLY_PAYLOAD}-byte payload)");
    let _ = writeln!(out, "| path | ns/reply |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| head and payload in one buffer | {joined_best:.1} |");
    let _ = writeln!(
        out,
        "| head room, payload where it lies | {split_best:.1} |"
    );
}

pub(crate) fn report() -> String {
    let address = ferrox_core::tuic::address_port("example.com", 443).expect("an address");
    let payload = [7u8; 1200];
    let mut frame = Vec::new();
    ferrox_core::tuic::encode_fragment(1, 2, 1, 0, &address, &payload, &mut frame);
    let start = Instant::now();
    for _ in 0..PACKETS {
        let _ = black_box(ferrox_core::tuic::parse_packet(black_box(&frame)));
    }
    let ns = start.elapsed().as_nanos() as f64 / PACKETS as f64;
    let (once, twice) = measure(prefix_len, double_parse, &frame);
    let mut out = String::new();
    let _ = writeln!(out, "## TUIC packet\n");
    let _ = writeln!(out, "| packets | ns/packet |");
    let _ = writeln!(out, "|---:|---:|");
    let _ = writeln!(out, "| {PACKETS} | {ns:.1} |");
    let _ = writeln!(out, "\n## TUIC stream packet\n");
    let _ = writeln!(out, "| path | ns/packet |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| one parse | {once:.1} |");
    let _ = writeln!(out, "| two parses | {twice:.1} |");
    let _ = writeln!(out, "| saved | {:.1} |", twice - once);
    let mut burst = Vec::with_capacity(frame.len() * BURST);
    for _ in 0..BURST {
        burst.extend_from_slice(&frame);
    }
    let mut drain_best = f64::MAX;
    let mut offset_best = f64::MAX;
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            let fresh = burst.clone();
            let start = Instant::now();
            let drained = black_box(walk_drain(black_box(fresh)));
            drain_best = drain_best.min(start.elapsed().as_nanos() as f64);
            let fresh = burst.clone();
            let start = Instant::now();
            let walked = black_box(walk_offset(black_box(fresh)));
            offset_best = offset_best.min(start.elapsed().as_nanos() as f64);
            assert_eq!(drained, walked, "both walks take every frame");
            assert_eq!(walked, BURST, "the burst is every frame it holds");
        } else {
            let fresh = burst.clone();
            let start = Instant::now();
            let walked = black_box(walk_offset(black_box(fresh)));
            offset_best = offset_best.min(start.elapsed().as_nanos() as f64);
            let fresh = burst.clone();
            let start = Instant::now();
            let drained = black_box(walk_drain(black_box(fresh)));
            drain_best = drain_best.min(start.elapsed().as_nanos() as f64);
            assert_eq!(drained, walked, "both walks take every frame");
            assert_eq!(walked, BURST, "the burst is every frame it holds");
        }
    }
    let _ = writeln!(out, "\n## TUIC burst walk\n");
    let _ = writeln!(out, "| path | us/burst | ns/frame |");
    let _ = writeln!(out, "|---|---:|---:|");
    let _ = writeln!(
        out,
        "| drain per frame | {:.1} | {:.1} |",
        drain_best / 1000.0,
        drain_best / BURST as f64
    );
    let _ = writeln!(
        out,
        "| offset, one drain | {:.1} | {:.1} |",
        offset_best / 1000.0,
        offset_best / BURST as f64
    );
    sweep_section(&mut out);
    sink_section(&mut out);
    packet_map_section(&mut out);
    checksum_section(&mut out);
    key_section(&mut out);
    reply_section(&mut out);
    out
}
