//! TUIC v5 over QUIC: authentication, CONNECT streams, and PACKET datagrams.

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{self, Destination};
use crate::quic::{self, Datagram, QuicStream, QuicheConnection};
use bytes::BufMut as _;
use ferrox_core::tls::Anchors;
use ferrox_core::tuic as wire;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCID_LEN: usize = 16;
const HEARTBEAT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
/// A client driver's idle arm: a local read or stream write is retried within this beat without a packet.
const CLIENT_POLL: Duration = Duration::from_millis(1);
const DIRECT_BUFFER: usize = 256 * 1024;
const UDP_IDLE: Duration = Duration::from_secs(300);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);
const MAX_REASSEMBLIES: usize = 64;
const MAX_REASSEMBLIES_PER_ASSOC: usize = 8;
const MAX_PACKET_PAYLOAD: usize = 65_535;
const MAX_REASSEMBLY_BYTES: usize = MAX_REASSEMBLIES * MAX_PACKET_PAYLOAD;
/// The largest frame a PACKET may carry, header included: the payload limit, the ten-byte packet
/// header, and the first fragment's address (a type byte, a length byte, the name, and a port).
const MAX_UNI_COMMAND: usize = MAX_PACKET_PAYLOAD + 10 + wire::MAX_ADDRESS + 2 + 2;
const MAX_SESSIONS: usize = 1024;
const MAX_PENDING: usize = 64;
const MAX_CLIENT_REPLIES: usize = 64;
const MAX_PREAUTH_COMMANDS: usize = 16;
const MAX_PREAUTH_BYTES: usize = 64 * 1024;
const RETRY_TOKEN_TTL: Duration = Duration::from_secs(60);
const RETRY_TOKEN_TAG: usize = 32;
const MAX_ASSOCIATIONS_PER_SESSION: usize = 256;
const MAX_UDP_SOCKETS: usize = 2048;
const MAX_TUIC_LANES: usize = 64;
const LANES_PER_KEY: usize = 4;
const MAX_RESOLVING_PER_SESSION: usize = 32;
const MAX_RESOLVE_PAYLOADS: usize = 4;
const RESOLVE_QUEUE: usize = 256;
const RESOLVE_WORKERS: usize = 4;
const UDP_BUFFER: usize = 65_535;
const UDP_PACKETS_PER_SWEEP: usize = 256;
const UDP_PACKETS_PER_ASSOC: usize = 32;
const DGRAM_SEND_QUEUE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMode {
    Native,
    Quic,
}

fn quiche_cc(name: &str) -> &str {
    if name == "new_reno" {
        "reno"
    } else {
        name
    }
}

#[derive(Clone)]
struct User {
    uuid: [u8; 16],
    password: String,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("uuid", &self.uuid)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub(crate) struct TuicOut {
    address: String,
    port: u16,
    host: String,
    uuid: [u8; 16],
    password: String,
    mode: RelayMode,
    zero_rtt: bool,
    cc: Option<String>,
    roots: Option<Anchors>,
    cert_pins: Arc<[[u8; 32]]>,
    insecure: bool,
    heartbeat: Duration,
    lanes: Mutex<HashMap<LaneKey, Vec<Arc<Lane>>>>,
    pending: Mutex<HashMap<LaneKey, usize>>,
    session: Arc<Mutex<Option<Vec<u8>>>>,
}

impl std::fmt::Debug for TuicOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicOut")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("host", &self.host)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

type LaneKey = (Option<IpAddr>, Option<Arc<crate::sockopt::SocketOptions>>);

struct LaneLease(Arc<Lane>);

impl std::ops::Deref for LaneLease {
    type Target = Lane;

    fn deref(&self) -> &Lane {
        &self.0
    }
}

impl Drop for LaneLease {
    fn drop(&mut self) {
        self.0.leases.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Expansion<'a> {
    out: &'a TuicOut,
    key: LaneKey,
}

impl Drop for Expansion<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.out.pending.lock() {
            if let Some(n) = pending.get_mut(&self.key) {
                *n -= 1;
            }
            pending.retain(|_, n| *n > 0);
        }
    }
}

struct Lane {
    conn: Arc<Mutex<QuicheConnection>>,
    sock: Arc<Datagram>,
    leases: AtomicUsize,
    local: SocketAddr,
    next_bidi: Mutex<u64>,
    next_uni: AtomicU64,
    next_assoc: AtomicU16,
    stop: Arc<AtomicBool>,
    sinks: Mutex<HashMap<u16, Arc<UdpSink>>>,
    pending: Mutex<Vec<Pending>>,
    session: Arc<Mutex<Option<Vec<u8>>>>,
    direct: Sender<DirectStream>,
    heartbeat: thread::Thread,
    auth: Auth,
    authed: AtomicBool,
    early_since: Option<Instant>,
    establish_by: Option<Instant>,
}

/// One client stream the driver owns end to end: the QUIC id and the local TCP socket, so neither
/// direction needs a relay worker or a second copy through a queue.
struct DirectStream {
    id: u64,
    tcp: Connection,
    out: Vec<u8>,
    inbound: Vec<u8>,
    read_eof: bool,
    fin_sent: bool,
    peer_fin: bool,
    write_shut: bool,
    closed: bool,
    meter: crate::stats::Meter,
    finish: Option<Box<dyn FnOnce() + Send>>,
}

fn lane_established(conn: &QuicheConnection, lane: &Lane) -> bool {
    if conn.is_closed() {
        return false;
    }
    if conn.is_established() {
        return true;
    }
    let Some(since) = lane.early_since else {
        return true;
    };
    Instant::now() < lane.establish_by.unwrap_or(since + quic::HANDSHAKE_TIMEOUT)
        && !(since.elapsed() >= quic::SILENT_HANDSHAKE && conn.stats().recv == 0)
}

struct Auth {
    uuid: [u8; 16],
    password: String,
    frame: OnceLock<Vec<u8>>,
    sent: AtomicUsize,
}

impl Lane {
    /// Finish the handshake once: the exporter token, then resumption. An early lane calls this
    /// from its driver after the flight lands; a cold lane calls it before it is returned, so a
    /// caller never writes into a connection whose trust is still unread.
    fn finish_handshake(&self) -> bool {
        if self.authed.load(Ordering::Relaxed) {
            return true;
        }
        let Ok(mut conn) = self.conn.lock() else {
            return false;
        };
        if !conn.is_established() {
            return !conn.is_closed();
        }
        if self.auth.frame.get().is_none() {
            let Some(token) =
                export_token(&mut conn, &self.auth.uuid, self.auth.password.as_bytes())
            else {
                let _ = conn.close(false, 0, b"authentication");
                quic::flush_egress(&mut conn, &self.sock);
                return false;
            };
            let mut auth = Vec::with_capacity(wire::AUTH_LEN);
            wire::encode_auth(&self.auth.uuid, &token, &mut auth);
            let _ = self.auth.frame.set(auth);
        }
        let Some(auth) = self.auth.frame.get() else {
            return false;
        };
        let mut at = self.auth.sent.load(Ordering::Relaxed);
        while at < auth.len() {
            match conn.stream_send(2, &auth[at..], false) {
                Ok(written) if written > 0 => {
                    at += written;
                    self.auth.sent.store(at, Ordering::Relaxed);
                }
                Ok(_) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                    quic::flush_egress(&mut conn, &self.sock);
                    return !conn.is_closed();
                }
                Err(_) => {
                    let _ = conn.close(false, 0, b"authentication");
                    quic::flush_egress(&mut conn, &self.sock);
                    return false;
                }
            }
        }
        match conn.stream_send(2, &[], true) {
            Ok(_) => {}
            Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                quic::flush_egress(&mut conn, &self.sock);
                return !conn.is_closed();
            }
            Err(_) => {
                let _ = conn.close(false, 0, b"authentication");
                quic::flush_egress(&mut conn, &self.sock);
                return false;
            }
        }
        quic::flush_egress(&mut conn, &self.sock);
        remember_session(&conn, &self.session);
        self.authed.store(true, Ordering::Relaxed);
        true
    }
}

struct UdpSink {
    association: u16,
    reply: UdpSocket,
    /// The relay peer the association is pinned to, stored once so the uplink and the reply path read it without a lock.
    source: OnceLock<SocketAddr>,
    /// The instant the activity stamp counts from, with the last activity in milliseconds after it, so a reply refreshes the stamp with one atomic store.
    born: Instant,
    last: AtomicU64,
}

struct Pending {
    id: Option<u64>,
    data: bytes::Bytes,
    at: usize,
    finish: bool,
}

enum Sent {
    Done,
    Blocked,
    Failed,
}

struct Resolving {
    generation: u64,
    payloads: Vec<Vec<u8>>,
}

struct ResolveJob {
    association: u16,
    host: String,
    port: u16,
    payload: Vec<u8>,
    generation: u64,
    options: Option<Arc<crate::sockopt::SocketOptions>>,
    reply: Sender<ResolveDone>,
}

struct ResolveDone {
    association: u16,
    host: String,
    port: u16,
    target: Option<SocketAddr>,
    payload: Vec<u8>,
    generation: u64,
}

struct ResolverPool {
    jobs: SyncSender<ResolveJob>,
    workers: usize,
}

impl ResolverPool {
    fn get() -> &'static ResolverPool {
        static POOL: OnceLock<ResolverPool> = OnceLock::new();
        POOL.get_or_init(|| {
            let (jobs, pending) = std::sync::mpsc::sync_channel::<ResolveJob>(RESOLVE_QUEUE);
            let pending = Arc::new(Mutex::new(pending));
            let mut workers = 0;
            for index in 0..RESOLVE_WORKERS {
                let pending = Arc::clone(&pending);
                let spawned = thread::Builder::new()
                    .name(format!("tuic-resolve-{index}"))
                    .spawn(move || loop {
                        let job = match pending.lock() {
                            Ok(pending) => match pending.recv() {
                                Ok(job) => job,
                                Err(_) => return,
                            },
                            Err(_) => return,
                        };
                        let target = proxy::resolve_outbound_with(
                            job.options.as_deref(),
                            &job.host,
                            job.port,
                        );
                        let _ = job.reply.send(ResolveDone {
                            association: job.association,
                            host: job.host,
                            port: job.port,
                            target,
                            payload: job.payload,
                            generation: job.generation,
                        });
                    });
                if spawned.is_ok() {
                    workers += 1;
                }
            }
            ResolverPool { jobs, workers }
        })
    }

    fn submit(&self, job: ResolveJob) -> bool {
        if self.workers == 0 {
            return false;
        }
        match self.jobs.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.heartbeat.unpark();
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn.close(true, 0, b"closed");
            quic::flush_egress(&mut conn, &self.sock);
        }
    }
}

#[allow(clippy::mutable_key_type)]
fn prune_lanes(held: &mut HashMap<LaneKey, Vec<Arc<Lane>>>) {
    for pool in held.values_mut() {
        pool.retain(|lane| {
            lane.leases.load(Ordering::Acquire) > 0
                || !(lane.stop.load(Ordering::Relaxed)
                    || lane.conn.lock().is_ok_and(|conn| conn.is_closed()))
        });
    }
    held.retain(|_, pool| !pool.is_empty());
}

#[allow(clippy::mutable_key_type)]
fn make_lane_room(held: &mut HashMap<LaneKey, Vec<Arc<Lane>>>) -> bool {
    while held.values().map(Vec::len).sum::<usize>() >= MAX_TUIC_LANES {
        let Some((key, at)) = held.iter().find_map(|(key, pool)| {
            pool.iter()
                .position(|lane| lane.leases.load(Ordering::Acquire) == 0)
                .map(|at| (key.clone(), at))
        }) else {
            return false;
        };
        if let Some(pool) = held.get_mut(&key) {
            pool.remove(at);
        }
    }
    true
}

impl TuicOut {
    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        proxy::resolve_outbound(&self.address, self.port)
    }

    fn lane(&self) -> Option<LaneLease> {
        let options = proxy::dial_options();
        let source = proxy::flow_source().ok()?;
        let key = (source, options.clone());
        let live = |lane: &Arc<Lane>| {
            !lane.stop.load(Ordering::Relaxed)
                && lane
                    .conn
                    .lock()
                    .is_ok_and(|conn| lane_established(&conn, lane))
        };
        let select = |held: &HashMap<LaneKey, Vec<Arc<Lane>>>, shared: bool| -> Option<LaneLease> {
            if let Some(lane) = held.get(&key).and_then(|pool| {
                pool.iter()
                    .find(|lane| lane.leases.load(Ordering::Acquire) == 0 && live(lane))
            }) {
                lane.leases.fetch_add(1, Ordering::AcqRel);
                return Some(LaneLease(Arc::clone(lane)));
            }
            if !shared {
                return None;
            }
            let lane = held
                .get(&key)?
                .iter()
                .min_by_key(|lane| lane.leases.load(Ordering::Acquire))?;
            lane.leases.fetch_add(1, Ordering::AcqRel);
            Some(LaneLease(Arc::clone(lane)))
        };
        let mut held = self.lanes.lock().ok()?;
        prune_lanes(&mut held);
        if let Some(lease) = select(&held, false) {
            return Some(lease);
        }
        if !self.reserve_expansion(&key, &held) {
            drop(held);
            let deadline = Instant::now() + crate::budgets::dial();
            loop {
                let mut held = self.lanes.lock().ok()?;
                prune_lanes(&mut held);
                if let Some(lease) = select(&held, true) {
                    return Some(lease);
                }
                drop(held);
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        drop(held);
        let expansion = Expansion {
            out: self,
            key: key.clone(),
        };
        let Some(lane) = self.connect_lane(source, options) else {
            drop(expansion);
            let mut held = self.lanes.lock().ok()?;
            prune_lanes(&mut held);
            return select(&held, true);
        };
        let mut held = self.lanes.lock().ok()?;
        prune_lanes(&mut held);
        if held.get(&key).map_or(0, Vec::len) < LANES_PER_KEY && make_lane_room(&mut held) {
            lane.leases.fetch_add(1, Ordering::AcqRel);
            held.entry(key.clone()).or_default().push(Arc::clone(&lane));
            drop(expansion);
            return Some(LaneLease(lane));
        }
        drop(lane);
        drop(expansion);
        select(&held, true)
    }

    #[allow(clippy::mutable_key_type)]
    fn reserve_expansion(&self, key: &LaneKey, held: &HashMap<LaneKey, Vec<Arc<Lane>>>) -> bool {
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        let queued: usize = pending.values().sum();
        let total: usize = held.values().map(Vec::len).sum();
        let mine = held.get(key).map_or(0, Vec::len) + pending.get(key).copied().unwrap_or(0);
        if mine >= LANES_PER_KEY || total + queued >= MAX_TUIC_LANES {
            return false;
        }
        *pending.entry(key.clone()).or_default() += 1;
        true
    }

    fn connect_lane(
        &self,
        source: Option<IpAddr>,
        options: Option<Arc<crate::sockopt::SocketOptions>>,
    ) -> Option<Arc<Lane>> {
        let (socket, peer, local) =
            if let Some(tag) = options.as_deref().and_then(|o| o.dialer_proxy()) {
                let options = options.as_deref()?;
                let peer = options.resolve_addr(&self.address, self.port)?;
                let (sock, stop) = proxy::dial_udp_through_proxy(peer, tag, options)?;
                let local = sock.local_addr().ok()?;
                (quic::Datagram::proxied(sock, peer, stop), peer, local)
            } else {
                let (sock, peer, local) = quic::udp_to_server_with_source(
                    &self.address,
                    self.port,
                    options.as_deref(),
                    source,
                )?;
                (quic::Datagram::plain(sock), peer, local)
            };
        let socket = socket.with_options(options).with_source(source);
        let mut config = self.client_config()?;
        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect_with_buffer_factory::<crate::quic::BytesBufFactory>(
            Some(&self.host),
            &cid,
            local,
            peer,
            &mut config,
        )
        .ok()?;
        if self.zero_rtt {
            if let Ok(session) = self.session.lock() {
                if let Some(blob) = session.as_deref() {
                    let _ = conn.set_session(blob);
                }
            }
        }
        quic::flush_egress(&mut conn, &socket);
        let early = self.zero_rtt && conn.is_in_early_data();
        if !early {
            quic::drive_handshake(&mut conn, &socket, local)?;
        }
        let socket = Arc::new(socket);
        let conn = Arc::new(Mutex::new(conn));
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = heartbeat(&conn, &socket, self.heartbeat, Arc::clone(&stop));
        let (direct, direct_rx) = mpsc::channel::<DirectStream>();
        let lane = Arc::new(Lane {
            conn,
            sock: socket,
            leases: AtomicUsize::new(0),
            local,
            next_bidi: Mutex::new(0),
            next_uni: AtomicU64::new(6),
            next_assoc: AtomicU16::new(0),
            stop,
            sinks: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            session: Arc::clone(&self.session),
            direct,
            heartbeat,
            auth: Auth {
                uuid: self.uuid,
                password: self.password.clone(),
                frame: OnceLock::new(),
                sent: AtomicUsize::new(0),
            },
            authed: AtomicBool::new(false),
            early_since: early.then(Instant::now),
            establish_by: early.then(|| Instant::now() + quic::HANDSHAKE_TIMEOUT),
        });
        if !early && !lane.finish_handshake() {
            return None;
        }
        thread::spawn({
            let lane = Arc::downgrade(&lane);
            move || drive_client(&lane, direct_rx)
        });
        Some(lane)
    }

    fn client_config(&self) -> Option<quiche::Config> {
        let roots = self.roots.as_deref().unwrap_or(&[]);
        let mut config = if !self.cert_pins.is_empty() {
            let mut config = pinned_config(Arc::clone(&self.cert_pins), self.host.clone())?;
            config.set_application_protos(&[wire::ALPN]).ok()?;
            if let Some(name) = self.cc.as_deref() {
                config.set_cc_algorithm_name(name).ok()?;
            }
            config
        } else if self.insecure {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
            config.verify_peer(false);
            config.set_application_protos(&[wire::ALPN]).ok()?;
            if let Some(name) = self.cc.as_deref() {
                config.set_cc_algorithm_name(name).ok()?;
            }
            config
        } else {
            if roots.is_empty() {
                return None;
            }
            quic::quiche_config_alpn(roots, self.cc.as_deref(), &[wire::ALPN])?
        };
        quic::tune_transport(&mut config);
        if self.cc.is_none() {
            let _ = config.set_cc_algorithm_name("bbr");
        }
        config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
        if self.zero_rtt {
            config.enable_early_data();
        }
        Some(config)
    }

    pub(crate) fn dial(&self, client: &Connection, target: &Destination) {
        let Some(lane) = self.lane() else {
            return;
        };
        let (host, port): (Cow<'_, str>, u16) = match target {
            Destination::Name(host, port) => (Cow::Borrowed(host.as_str()), *port),
            Destination::Address(address) => (Cow::Owned(address.ip().to_string()), address.port()),
        };
        let mut header = Vec::with_capacity(host.len() + 5);
        if wire::encode_connect(host.as_ref(), port, &mut header).is_err() {
            return;
        }
        let deadline = Instant::now() + crate::budgets::dial();
        let Ok(mut next) = lane.next_bidi.lock() else {
            return;
        };
        let id = loop {
            if Instant::now() >= deadline {
                return;
            }
            let credit = match lane.conn.lock() {
                Ok(conn) if !conn.is_closed() => conn.peer_streams_left_bidi(),
                _ => return,
            };
            if credit > 0 {
                break *next;
            }
            thread::sleep(Duration::from_millis(5));
        };
        *next = next.wrapping_add(4);
        drop(next);
        let Ok(tcp) = client.try_clone() else {
            return;
        };
        if tcp.set_nonblocking(true).is_err() {
            return;
        }
        header.reserve(DIRECT_BUFFER);
        let direct = lane.direct.clone();
        let _ = direct.send(DirectStream {
            id,
            tcp,
            out: header,
            inbound: Vec::with_capacity(DIRECT_BUFFER),
            read_eof: false,
            fin_sent: false,
            peer_fin: false,
            write_shut: false,
            closed: false,
            meter: proxy::flow_outbound_meter().unwrap_or_default(),
            finish: Some(Box::new(move || drop(lane))),
        });
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn serve_udp(
        &self,
        relay: &UdpSocket,
        associate: Option<&Connection>,
        peer: Option<IpAddr>,
    ) {
        let Some(lane) = self.lane() else {
            return;
        };
        if let Some(associate) = associate {
            let _ = associate.set_read_timeout(Some(POLL));
        }
        let Ok(reply) = relay.try_clone() else {
            return;
        };
        let Ok(mut sinks) = lane.sinks.lock() else {
            return;
        };
        let mut tries = 0usize;
        let association = loop {
            let candidate = lane.next_assoc.fetch_add(1, Ordering::Relaxed);
            if !sinks.contains_key(&candidate) {
                break candidate;
            }
            tries += 1;
            if tries > usize::from(u16::MAX) {
                return;
            }
        };
        let sink = Arc::new(UdpSink {
            association,
            reply,
            source: OnceLock::new(),
            born: Instant::now(),
            last: AtomicU64::new(0),
        });
        sinks.insert(association, Arc::clone(&sink));
        drop(sinks);
        let cancelled = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let watcher = associate.and_then(|associate| {
            let control = associate.try_clone().ok()?;
            let _ = control.set_read_timeout(Some(POLL));
            let cancelled = Arc::clone(&cancelled);
            let finished = Arc::clone(&finished);
            thread::Builder::new()
                .spawn(move || {
                    while !finished.load(Ordering::Relaxed) {
                        if proxy::peer_left(&control) {
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                })
                .ok()
        });
        let watch_started = watcher.is_some();
        let mut buf = vec![0u8; UDP_BUFFER];
        let mut packet = 0u16;
        let mut frame = Vec::new();
        let _ = relay.set_read_timeout(Some(POLL));
        loop {
            if lane.stop.load(Ordering::Relaxed) {
                break;
            }
            if cancelled.load(Ordering::Relaxed)
                || (!watch_started && associate.is_some_and(proxy::peer_left))
            {
                break;
            }
            match relay.recv_from(&mut buf) {
                Ok((n, client)) => {
                    if !proxy::source_ip_ok(peer, client) {
                        continue;
                    }
                    let Some((destination, payload)) = proxy::parse_socks_udp_dest(&buf[..n])
                    else {
                        continue;
                    };
                    match sink.source.get() {
                        None => {
                            let _ = sink.source.set(client);
                        }
                        Some(pinned) if *pinned != client => continue,
                        Some(_) => {}
                    }
                    let Some((address, port)) = destination_wire(&destination) else {
                        continue;
                    };
                    packet = next_packet(packet);
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    if conn.is_closed() {
                        break;
                    }
                    let Ok(mut pending) = lane.pending.lock() else {
                        break;
                    };
                    let max = conn.dgram_max_writable_len();
                    send_message(
                        &mut conn,
                        &lane.sock,
                        self.mode,
                        association,
                        packet,
                        address,
                        port,
                        payload,
                        max,
                        &mut pending,
                        &mut frame,
                    );
                    flush_pending(&mut conn, &lane.sock, &mut pending, &lane.next_uni);
                    touch(&sink);
                }
                Err(error) if is_wait(&error) => {
                    if idle(&sink) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if let Ok(mut sinks) = lane.sinks.lock() {
            sinks.remove(&sink.association);
        }
        finished.store(true, Ordering::Relaxed);
        if let Some(watcher) = watcher {
            let _ = watcher.join();
        }
        if let Ok(mut conn) = lane.conn.lock() {
            if !conn.is_closed() {
                if let Ok(mut pending) = lane.pending.lock() {
                    queue_dissociate(&mut pending, association);
                    flush_pending(&mut conn, &lane.sock, &mut pending, &lane.next_uni);
                }
            }
        };
    }
}

fn destination_wire(destination: &Destination) -> Option<(wire::Address<'_>, u16)> {
    match destination {
        Destination::Name(host, port) => Some((wire::Address::of(host)?, *port)),
        Destination::Address(address) => {
            let port = address.port();
            match address.ip() {
                IpAddr::V4(ip) => Some((wire::Address::V4(ip.octets()), port)),
                IpAddr::V6(ip) => Some((wire::Address::V6(ip.octets()), port)),
            }
        }
    }
}

fn destination_of(address: wire::Address<'_>, port: u16) -> Destination {
    match address {
        wire::Address::V4(octets) => {
            Destination::Address(SocketAddr::new(IpAddr::V4(octets.into()), port))
        }
        wire::Address::V6(octets) => {
            Destination::Address(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        wire::Address::Name(bytes) => {
            Destination::Name(String::from_utf8_lossy(bytes).into_owned(), port)
        }
    }
}

fn next_packet(packet: u16) -> u16 {
    let next = packet.wrapping_add(1);
    if next == u16::MAX {
        0
    } else {
        next
    }
}

/// A pin is the handshake's own verifier, so a chain that does not match never reaches the
/// exporter key or the authentication frame. The callback receives the DER the edge sent, and
/// the same `verify_cert_pinned` rule the other TLS lanes use decides it.
fn pinned_config(pins: Arc<[[u8; 32]]>, name: String) -> Option<quiche::Config> {
    use boring::ssl::{SslAlert, SslMethod, SslVerifyError, SslVerifyMode};
    let mut builder = boring::ssl::SslContextBuilder::new(SslMethod::tls()).ok()?;
    builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let Some(chain) = ssl.peer_cert_chain() else {
            return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
        };
        let mut chain_der = Vec::with_capacity(chain.len());
        for cert in chain {
            let Ok(der) = cert.to_der() else {
                return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
            };
            chain_der.push(der);
        }
        if ferrox_core::tls::verify_cert_pinned(&chain_der, &pins, &name) {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(SslAlert::UNKNOWN_CA))
        }
    });
    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).ok()
}

fn remember_session(conn: &QuicheConnection, session: &Mutex<Option<Vec<u8>>>) -> bool {
    let Some(blob) = conn.session() else {
        return false;
    };
    if let Ok(mut held) = session.lock() {
        *held = Some(blob.to_vec());
    }
    true
}

fn heartbeat(
    conn: &Arc<Mutex<QuicheConnection>>,
    sock: &Arc<Datagram>,
    every: Duration,
    stop: Arc<AtomicBool>,
) -> thread::Thread {
    let conn = Arc::clone(conn);
    let sock = Arc::clone(sock);
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            thread::park_timeout(every.max(POLL));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut conn) = conn.lock() else {
                break;
            };
            if conn.is_closed() {
                break;
            }
            let _ = conn.dgram_send(&[wire::VERSION, wire::HEARTBEAT]);
            quic::flush_egress(&mut conn, &sock);
        }
    });
    handle.thread().clone()
}

fn export_token(
    conn: &mut QuicheConnection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Option<[u8; wire::TOKEN_LEN]> {
    use foreign_types::ForeignTypeRef as _;
    let mut token = [0u8; wire::TOKEN_LEN];
    let ssl = <QuicheConnection as AsMut<boring::ssl::SslRef>>::as_mut(conn);
    let ok = unsafe {
        boring_sys::SSL_export_keying_material(
            ssl.as_ptr(),
            token.as_mut_ptr(),
            token.len(),
            uuid.as_ptr().cast(),
            uuid.len(),
            if password.is_empty() {
                std::ptr::null()
            } else {
                password.as_ptr()
            },
            password.len(),
            i32::from(!password.is_empty()),
        )
    };
    (ok == 1).then_some(token)
}

#[allow(clippy::too_many_arguments)]
fn send_message(
    conn: &mut QuicheConnection,
    sock: &Datagram,
    mode: RelayMode,
    association: u16,
    packet: u16,
    address: wire::Address<'_>,
    port: u16,
    payload: &[u8],
    max: Option<usize>,
    pending: &mut Vec<Pending>,
    frame: &mut Vec<u8>,
) {
    let mut destination = [0u8; wire::MAX_ADDRESS + 4];
    let Some(destination_len) = wire::address_port_into(address, port, &mut destination) else {
        return;
    };
    let address = &destination[..destination_len];
    if mode == RelayMode::Quic {
        queue_stream(pending, association, packet, address, payload);
        return;
    }
    let Some(max) = max else {
        queue_stream(pending, association, packet, address, payload);
        return;
    };
    let Some(plan) = wire::fragment_plan(max, address.len(), payload.len()) else {
        queue_stream(pending, association, packet, address, payload);
        return;
    };
    let fragments = usize::from(plan.total);
    if conn.dgram_send_queue_len() + fragments > DGRAM_SEND_QUEUE {
        quic::flush_egress(conn, sock);
        if conn.dgram_send_queue_len() + fragments > DGRAM_SEND_QUEUE {
            queue_stream(pending, association, packet, address, payload);
            return;
        }
    }
    frame.clear();
    if frame.capacity() < max {
        frame.reserve(max - frame.capacity());
    }
    let mut left = payload;
    for index in 0..plan.total {
        let take = left.len().min(if index == 0 {
            plan.first
        } else {
            plan.continuation
        });
        wire::encode_fragment(
            association,
            packet,
            plan.total,
            index,
            address,
            &left[..take],
            frame,
        );
        if conn.dgram_send(&frame[..]).is_err() {
            quic::flush_egress(conn, sock);
            if conn.dgram_send(&frame[..]).is_err() {
                break;
            }
        }
        left = &left[take..];
    }
}

fn queue_stream(
    pending: &mut Vec<Pending>,
    association: u16,
    packet: u16,
    address: &[u8],
    payload: &[u8],
) {
    if pending.len() >= MAX_PENDING {
        return;
    }
    let mut data = Vec::with_capacity(12 + address.len() + payload.len());
    wire::encode_fragment(association, packet, 1, 0, address, payload, &mut data);
    pending.push(Pending {
        id: None,
        data: data.into(),
        at: 0,
        finish: true,
    });
}

fn queue_dissociate(pending: &mut Vec<Pending>, association: u16) {
    if pending.len() >= MAX_PENDING {
        return;
    }
    let mut data = Vec::with_capacity(4);
    wire::encode_dissociate(association, &mut data);
    pending.push(Pending {
        id: None,
        data: data.into(),
        at: 0,
        finish: true,
    });
}

fn flush_one(conn: &mut QuicheConnection, frame: &mut Pending, next_uni: &AtomicU64) -> Sent {
    if frame.id.is_none() {
        if conn.is_closed() {
            return Sent::Failed;
        }
        if conn.peer_streams_left_uni() == 0 {
            return Sent::Blocked;
        }
        let id = next_uni.load(Ordering::Relaxed);
        match conn.stream_send_zc(id, frame.data.slice(frame.at..), false) {
            Ok((n, _)) if n > 0 => {
                frame.id = Some(id);
                next_uni.store(id.wrapping_add(4), Ordering::Relaxed);
                frame.at += n;
            }
            Err(quiche::Error::Done) => {
                frame.id = Some(id);
                next_uni.store(id.wrapping_add(4), Ordering::Relaxed);
                return Sent::Blocked;
            }
            Err(quiche::Error::StreamLimit) => return Sent::Blocked,
            Ok(_) | Err(_) => return Sent::Failed,
        }
    }
    let Some(id) = frame.id else {
        return Sent::Blocked;
    };
    while frame.at < frame.data.len() {
        match conn.stream_send_zc(id, frame.data.slice(frame.at..), false) {
            Ok((n, _)) if n > 0 => frame.at += n,
            Ok(_) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                return Sent::Blocked;
            }
            Err(_) => return Sent::Failed,
        }
    }
    if frame.finish {
        match conn.stream_send(id, &[], true) {
            Ok(_) => Sent::Done,
            Err(quiche::Error::Done | quiche::Error::StreamLimit) => Sent::Blocked,
            Err(_) => Sent::Failed,
        }
    } else {
        Sent::Done
    }
}

fn flush_pending(
    conn: &mut QuicheConnection,
    sock: &Datagram,
    pending: &mut Vec<Pending>,
    next_uni: &AtomicU64,
) {
    let mut index = 0;
    while index < pending.len() {
        match flush_one(conn, &mut pending[index], next_uni) {
            Sent::Done | Sent::Failed => {
                pending.swap_remove(index);
            }
            Sent::Blocked => index += 1,
        }
    }
    quic::flush_egress(conn, sock);
}

fn is_wait(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn service(conn: &mut QuicheConnection, lane: &Lane) -> bool {
    if conn
        .timeout_instant()
        .is_some_and(|at| at <= Instant::now())
    {
        conn.on_timeout();
    }
    flush_lane(lane, conn);
    !conn.is_closed()
}

fn reply_worker(weak: &std::sync::Weak<Lane>) -> SyncSender<Reply> {
    let (replies, backlog) = std::sync::mpsc::sync_channel::<Reply>(MAX_CLIENT_REPLIES);
    let worker = weak.clone();
    thread::spawn(move || {
        let mut reassembly = HashMap::new();
        let mut head = Vec::with_capacity(22);
        while let Ok(reply) = backlog.recv() {
            let Some(owner) = worker.upgrade() else {
                break;
            };
            if owner.stop.load(Ordering::Relaxed) {
                break;
            }
            dispatch_client(reply.packet(), &owner, &mut reassembly, &mut head);
        }
    });
    replies
}

#[allow(clippy::too_many_lines)]
fn drive_client(weak: &std::sync::Weak<Lane>, direct: Receiver<DirectStream>) {
    if weak.upgrade().is_none() {
        return;
    }
    let replies = reply_worker(weak);
    let mut buf = vec![0u8; 65535];
    let mut ids = Vec::new();
    let mut uni: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut out: Vec<Reply> = Vec::new();
    let mut batch = quic::Batch::new();
    let mut entries: Vec<DirectStream> = Vec::new();
    let mut finished: Vec<DirectStream> = Vec::new();
    while let Some(lane) = weak.upgrade() {
        while let Ok(stream) = direct.try_recv() {
            entries.push(stream);
        }
        if lane.stop.load(Ordering::Relaxed) {
            break;
        }
        if lane.sock.set_read_timeout(Some(CLIENT_POLL)).is_err() {
            break;
        }
        let alive = match quic::recv_batch(&lane.sock, &mut batch) {
            quic::Drain::Read => {
                let taken = batch.len();
                {
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    for at in 0..taken {
                        let Some((bytes, from)) = batch.at(at) else {
                            continue;
                        };
                        let _ = conn.recv(
                            bytes,
                            quiche::RecvInfo {
                                from,
                                to: lane.local,
                            },
                        );
                    }
                }
                lane.finish_handshake() && {
                    let turned = match lane.conn.lock() {
                        Ok(mut conn) => client_turn(
                            &mut conn,
                            &lane,
                            &replies,
                            &mut out,
                            &mut uni,
                            &mut ids,
                            &mut entries,
                            &mut finished,
                        ),
                        Err(_) => false,
                    };
                    finish_direct(&mut finished);
                    turned && hand_off(&mut out, &replies)
                }
            }
            quic::Drain::Empty => {
                if !lane.finish_handshake() {
                    break;
                }
                let alive = {
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    pump_direct(&mut conn, &mut entries, &mut finished);
                    service(&mut conn, &lane)
                };
                finish_direct(&mut finished);
                alive
            }
            quic::Drain::Unbatchable => match lane.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    let _ = conn.recv(
                        &mut buf[..n],
                        quiche::RecvInfo {
                            from,
                            to: lane.local,
                        },
                    );
                    drop(conn);
                    lane.finish_handshake() && {
                        let turned = match lane.conn.lock() {
                            Ok(mut conn) => client_turn(
                                &mut conn,
                                &lane,
                                &replies,
                                &mut out,
                                &mut uni,
                                &mut ids,
                                &mut entries,
                                &mut finished,
                            ),
                            Err(_) => false,
                        };
                        finish_direct(&mut finished);
                        turned && hand_off(&mut out, &replies)
                    }
                }
                Err(error) if is_wait(&error) => {
                    if !lane.finish_handshake() {
                        break;
                    }
                    let alive = {
                        let Ok(mut conn) = lane.conn.lock() else {
                            break;
                        };
                        pump_direct(&mut conn, &mut entries, &mut finished);
                        service(&mut conn, &lane)
                    };
                    finish_direct(&mut finished);
                    alive
                }
                Err(_) => break,
            },
            quic::Drain::Unreadable => break,
        };
        if !alive {
            break;
        }
    }
    entries.clear();
    while direct.try_recv().is_ok() {}
    finish_direct(&mut finished);
    if let Some(lane) = weak.upgrade() {
        lane.stop.store(true, Ordering::Relaxed);
        lane.heartbeat.unpark();
    }
}

/// One packet for the reply worker: a datagram's own buffer, or a slice of a uni stream's read
/// shared with every packet that read carried, so a run of N packets costs one allocation.
enum Reply {
    Whole(Vec<u8>),
    Inside {
        bytes: Arc<Vec<u8>>,
        at: std::ops::Range<usize>,
    },
}

impl Reply {
    fn packet(&self) -> &[u8] {
        match self {
            Self::Whole(bytes) => bytes,
            Self::Inside { bytes, at } => &bytes[at.clone()],
        }
    }
}

/// Queue every complete packet one uni read carried as a slice of that read's single buffer, and
/// return what is left: the partial packet at the tail, or nothing when the read ended on a frame
/// boundary. `true` marks a stream the packets don't parse in, which the caller shuts down.
fn share_uni_packets(data: Vec<u8>, out: &mut Vec<Reply>) -> (Vec<u8>, bool) {
    if data.get(1) != Some(&wire::PACKET) {
        return (data, false);
    }
    let mut known = match wire::parse_packet_prefix(&data) {
        Ok((_, used)) => Some(used),
        Err(wire::FrameError::Short) => return (data, false),
        Err(_) => return (Vec::new(), true),
    };
    let bytes = Arc::new(data);
    let mut at = 0usize;
    loop {
        let used = match known.take() {
            Some(used) => used,
            None => match wire::parse_packet_prefix(&bytes[at..]) {
                Ok((_, used)) => used,
                Err(wire::FrameError::Short) => return (bytes[at..].to_vec(), false),
                Err(_) => return (Vec::new(), true),
            },
        };
        out.push(Reply::Inside {
            bytes: Arc::clone(&bytes),
            at: at..at + used,
        });
        at += used;
    }
}

/// Hand a turn's reliable packets over once the guard is dropped; a full queue waits, never drops.
fn hand_off(out: &mut Vec<Reply>, replies: &SyncSender<Reply>) -> bool {
    for reply in out.drain(..) {
        if replies.send(reply).is_err() {
            return false;
        }
    }
    true
}

/// The work one received batch owes: the datagrams it queued, the streams it made readable, and
/// the timers behind them. The lock, the readable sweep and the egress flush are each paid once
/// per batch instead of once per packet.
fn client_turn(
    conn: &mut QuicheConnection,
    lane: &Lane,
    replies: &SyncSender<Reply>,
    out: &mut Vec<Reply>,
    uni: &mut HashMap<u64, Vec<u8>>,
    ids: &mut Vec<u64>,
    direct: &mut Vec<DirectStream>,
    finished: &mut Vec<DirectStream>,
) -> bool {
    remember_session(conn, &lane.session);
    while let Ok(data) = conn.dgram_recv_buf() {
        let _ = replies.try_send(Reply::Whole(data));
    }
    ids.clear();
    ids.extend(conn.readable());
    for &id in ids.iter() {
        if id % 4 != 3 {
            continue;
        }
        let mut data = uni.remove(&id).unwrap_or_default();
        loop {
            if data.len() > MAX_UNI_COMMAND {
                let (rest, broken) = share_uni_packets(data, out);
                if broken || rest.len() > MAX_UNI_COMMAND {
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                    data = Vec::new();
                    break;
                }
                data = rest;
            }
            // One byte over the cap distinguishes "filled it exactly" from "there is more".
            let room = MAX_UNI_COMMAND - data.len() + 1;
            match conn.stream_recv_buf(id, (&mut data).limit(room)) {
                Ok((0, _)) | Err(_) => break,
                Ok((_, _)) => {}
            }
        }
        let (rest, broken) = share_uni_packets(data, out);
        if broken {
            let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
        }
        data = rest;
        if !conn.stream_finished(id) && !data.is_empty() {
            uni.insert(id, data);
        }
    }
    pump_direct(conn, direct, finished);
    service(conn, lane)
}

/// Move every live client stream both ways while the driver owns the connection. A finished stream
/// is moved out so its lease drops only after the connection guard is gone.
fn pump_direct(
    conn: &mut QuicheConnection,
    streams: &mut Vec<DirectStream>,
    finished: &mut Vec<DirectStream>,
) {
    let mut buf = [0u8; DIRECT_BUFFER];
    let mut at = 0;
    while at < streams.len() {
        if pump_direct_stream(conn, &mut streams[at], &mut buf) {
            finished.push(streams.swap_remove(at));
        } else {
            at += 1;
        }
    }
}

fn pump_direct_stream(
    conn: &mut QuicheConnection,
    stream: &mut DirectStream,
    buf: &mut [u8],
) -> bool {
    if stream.closed {
        return true;
    }
    send_pending(conn, stream);
    if stream.closed {
        return true;
    }
    if stream.out.is_empty() {
        pump_upload(conn, stream, buf);
    }
    if stream.closed {
        return true;
    }
    write_pending(conn, stream);
    if stream.closed {
        return true;
    }
    if stream.inbound.is_empty() && !stream.peer_fin {
        pump_download(conn, stream, buf);
    }
    if stream.closed {
        return true;
    }
    write_pending(conn, stream);
    if stream.closed {
        return true;
    }
    if stream.read_eof && stream.out.is_empty() && !stream.fin_sent {
        match conn.stream_send(stream.id, &[], true) {
            Ok(_) => stream.fin_sent = true,
            Err(quiche::Error::Done) => {}
            Err(_) => {
                abort_direct(conn, stream);
                return true;
            }
        }
    }
    if stream.peer_fin && stream.inbound.is_empty() && !stream.write_shut {
        let _ = stream.tcp.shutdown(Shutdown::Write);
        stream.write_shut = true;
    }
    stream.read_eof
        && stream.fin_sent
        && stream.peer_fin
        && stream.write_shut
        && stream.out.is_empty()
        && stream.inbound.is_empty()
}

fn send_pending(conn: &mut QuicheConnection, stream: &mut DirectStream) {
    while !stream.out.is_empty() {
        let sent = conn.stream_send(stream.id, &stream.out, false);
        match sent {
            Ok(0) | Err(quiche::Error::Done) => break,
            Ok(n) => {
                stream.out.drain(..n);
                stream.meter.write(n);
            }
            Err(_) => {
                abort_direct(conn, stream);
                return;
            }
        }
    }
}

fn pump_upload(conn: &mut QuicheConnection, stream: &mut DirectStream, buf: &mut [u8]) {
    if stream.read_eof {
        return;
    }
    let read = stream.tcp.read(buf);
    match read {
        Ok(0) => stream.read_eof = true,
        Ok(n) => {
            let mut at = 0;
            while at < n {
                let sent = conn.stream_send(stream.id, &buf[at..n], false);
                match sent {
                    Ok(0) | Err(quiche::Error::Done) => {
                        stream.out.extend_from_slice(&buf[at..n]);
                        break;
                    }
                    Ok(sent) => {
                        at += sent;
                        stream.meter.write(sent);
                    }
                    Err(_) => {
                        abort_direct(conn, stream);
                        return;
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
        Err(_) => abort_direct(conn, stream),
    }
}

fn pump_download(conn: &mut QuicheConnection, stream: &mut DirectStream, buf: &mut [u8]) {
    if stream.peer_fin {
        return;
    }
    let received = conn.stream_recv(stream.id, buf);
    match received {
        Ok((0, fin)) => {
            if fin {
                stream.peer_fin = true;
            }
        }
        Ok((n, fin)) => {
            stream.meter.read(n);
            if fin {
                stream.peer_fin = true;
            }
            let mut at = 0;
            while at < n {
                let written = stream.tcp.write(&buf[at..n]);
                match written {
                    Ok(0) => {
                        abort_direct(conn, stream);
                        return;
                    }
                    Ok(written) => at += written,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        stream.inbound.extend_from_slice(&buf[at..n]);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        abort_direct(conn, stream);
                        return;
                    }
                }
            }
        }
        Err(quiche::Error::Done) => {}
        Err(quiche::Error::StreamReset(_)) => abort_direct(conn, stream),
        Err(_) => {
            if conn.is_closed() || conn.is_draining() {
                abort_direct(conn, stream);
            }
        }
    }
}

fn write_pending(conn: &mut QuicheConnection, stream: &mut DirectStream) {
    while !stream.inbound.is_empty() {
        let written = stream.tcp.write(&stream.inbound);
        match written {
            Ok(0) => {
                abort_direct(conn, stream);
                return;
            }
            Ok(n) => {
                stream.inbound.drain(..n);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                abort_direct(conn, stream);
                return;
            }
        }
    }
}

fn abort_direct(conn: &mut QuicheConnection, stream: &mut DirectStream) {
    stream.closed = true;
    stream.out.clear();
    stream.inbound.clear();
    let _ = conn.stream_shutdown(stream.id, quiche::Shutdown::Read, 0);
    let _ = conn.stream_shutdown(stream.id, quiche::Shutdown::Write, 0);
    let _ = stream.tcp.shutdown(Shutdown::Both);
}

fn finish_direct(finished: &mut Vec<DirectStream>) {
    for mut stream in finished.drain(..) {
        if let Some(finish) = stream.finish.take() {
            finish();
        }
    }
}

fn flush_lane(lane: &Lane, conn: &mut QuicheConnection) {
    if let Ok(mut pending) = lane.pending.lock() {
        flush_pending(conn, &lane.sock, &mut pending, &lane.next_uni);
    } else {
        quic::flush_egress(conn, &lane.sock);
    }
}

fn dispatch_client(
    data: &[u8],
    lane: &Lane,
    reassembly: &mut HashMap<(u16, u16), Parts>,
    head: &mut Vec<u8>,
) {
    let Ok(packet) = wire::parse_packet(data) else {
        return;
    };
    let sink = lane
        .sinks
        .lock()
        .ok()
        .and_then(|sinks| sinks.get(&packet.association).cloned());
    let Some(sink) = sink else {
        return;
    };
    client_reply(&packet, reassembly, &sink, head);
}

fn client_reply(
    packet: &wire::Packet<'_>,
    reassembly: &mut HashMap<(u16, u16), Parts>,
    sink: &UdpSink,
    head: &mut Vec<u8>,
) {
    let Some((destination, payload)) = take_packet(reassembly, packet) else {
        return;
    };
    let Some(source) = sink.source.get().copied() else {
        return;
    };
    let target = match destination {
        Destination::Address(target) => target,
        Destination::Name(host, port) => {
            let Some(target) = proxy::resolve_outbound(&host, port) else {
                return;
            };
            target
        }
    };
    let (head, payload) = proxy::socks_udp_parts(head, &target, &payload);
    if proxy::send_to_two(&sink.reply, head, payload, source).is_ok() {
        touch(sink);
    }
}

fn touch(sink: &UdpSink) {
    let stamp = millis(sink.born);
    sink.last.store(stamp, Ordering::Relaxed);
}

fn idle(sink: &UdpSink) -> bool {
    let window = u64::try_from(UDP_IDLE.as_millis()).unwrap_or(u64::MAX);
    millis(sink.born).saturating_sub(sink.last.load(Ordering::Relaxed)) >= window
}

fn millis(born: Instant) -> u64 {
    u64::try_from(born.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn take_packet<'a>(
    reassembly: &mut HashMap<(u16, u16), Parts>,
    packet: &wire::Packet<'a>,
) -> Option<(Destination, Cow<'a, [u8]>)> {
    let size = packet.payload.len();
    if packet.total == 1 {
        let (address, port) = packet.destination?;
        return Some((destination_of(address, port), Cow::Borrowed(packet.payload)));
    }
    if size > MAX_PACKET_PAYLOAD {
        return None;
    }
    let key = (packet.association, packet.packet);
    if reassembly
        .get(&key)
        .is_some_and(|entry| entry.at.elapsed() >= REASSEMBLY_TTL)
    {
        reassembly.remove(&key);
    }
    if !reassembly.contains_key(&key) {
        let mut per_assoc = 0usize;
        let mut retained = 0usize;
        reassembly.retain(|(assoc, _), parts| {
            if parts.at.elapsed() < REASSEMBLY_TTL {
                per_assoc += usize::from(*assoc == packet.association);
                retained += parts.buffer.len();
                true
            } else {
                false
            }
        });
        if reassembly.len() >= MAX_REASSEMBLIES
            || per_assoc >= MAX_REASSEMBLIES_PER_ASSOC
            || retained.saturating_add(size) > MAX_REASSEMBLY_BYTES
        {
            return None;
        }
    }
    let bad = reassembly.get(&key).is_some_and(|entry| {
        entry.total != packet.total
            || entry.slots[usize::from(packet.index)].is_some()
            || entry.buffer.len().saturating_add(size) > MAX_PACKET_PAYLOAD
    });
    if bad {
        reassembly.remove(&key);
        return None;
    }
    let entry = reassembly.entry(key).or_insert_with(|| Parts {
        total: packet.total,
        address: None,
        slots: vec![None; usize::from(packet.total)],
        buffer: Vec::new(),
        received: 0,
        at: Instant::now(),
    });
    if let Some((address, port)) = packet.destination {
        entry.address = Some(destination_of(address, port));
    }
    let at = u32::try_from(entry.buffer.len()).ok()?;
    let len = u16::try_from(size).ok()?;
    entry.slots[usize::from(packet.index)] = Some((at, len));
    entry.buffer.extend_from_slice(packet.payload);
    entry.received += 1;
    if entry.received != entry.total {
        return None;
    }
    let entry = reassembly.remove(&key)?;
    let destination = entry.address?;
    // Fragments that arrived in packet order already sit in that order: the buffer is the datagram.
    let mut next = 0usize;
    let ordered = entry.slots.iter().all(|slot| match *slot {
        Some((at, len)) if at as usize == next => {
            next += usize::from(len);
            true
        }
        _ => false,
    });
    if ordered {
        return Some((destination, Cow::Owned(entry.buffer)));
    }
    let mut payload = Vec::with_capacity(entry.buffer.len());
    for slot in &entry.slots {
        let (at, len) = (*slot)?;
        let at = at as usize;
        payload.extend_from_slice(entry.buffer.get(at..at + usize::from(len))?);
    }
    Some((destination, Cow::Owned(payload)))
}

struct Parts {
    total: u8,
    address: Option<Destination>,
    slots: Vec<Option<(u32, u16)>>,
    buffer: Vec<u8>,
    received: u8,
    at: Instant,
}

pub(crate) fn outbound(root: &Json) -> Result<Option<TuicOut>, String> {
    let Some(first) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|list| list.first())
    else {
        return Ok(None);
    };
    if first.get("protocol").and_then(Json::as_str) != Some("tuic") {
        return Ok(None);
    }
    let settings = first
        .get("settings")
        .ok_or("tuic outbound has no settings")?;
    let server = settings
        .get("servers")
        .and_then(Json::as_arr)
        .and_then(|servers| servers.first())
        .unwrap_or(settings);
    let field = |name: &str| server.get(name).or_else(|| settings.get(name));
    let address = field("address")
        .or_else(|| field("server"))
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("tuic outbound has no server address")?;
    let port = field("port")
        .or_else(|| field("server_port"))
        .and_then(Json::as_port)
        .ok_or("tuic outbound has no server port")?;
    let uuid = field("uuid")
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .ok_or("tuic outbound has no uuid")?;
    let password = field("password")
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("tuic outbound has no password")?;
    let tls = crate::config::outbound_tls(first, address)?;
    if field("udp_over_stream")
        .or_else(|| field("udpOverStream"))
        .is_some_and(|value| matches!(value, Json::Bool(true)))
    {
        return Err("tuic udp_over_stream is not carried".to_owned());
    }
    let mode = match field("udp_relay_mode")
        .or_else(|| field("udpRelayMode"))
        .and_then(Json::as_str)
    {
        Some("native") | None => RelayMode::Native,
        Some("quic") => RelayMode::Quic,
        Some(other) => return Err(format!("tuic udp_relay_mode `{other}` is not carried")),
    };
    let cc = field("congestion_control")
        .or_else(|| field("congestionControl"))
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .map(|name| quiche_cc(name).to_owned());
    if let Some(name) = cc.as_deref() {
        if !matches!(name, "cubic" | "reno" | "bbr") {
            return Err(format!("tuic congestion_control `{name}` is not carried"));
        }
    }
    let heartbeat = field("heartbeat")
        .or_else(|| field("heartbeat_interval"))
        .and_then(Json::as_u32)
        .filter(|seconds| *seconds > 0)
        .map_or(HEARTBEAT, |seconds| Duration::from_secs(u64::from(seconds)));
    Ok(Some(TuicOut {
        address: address.to_owned(),
        port,
        host: if tls.server_name.is_empty() {
            address.to_owned()
        } else {
            tls.server_name.clone()
        },
        uuid,
        password: password.to_owned(),
        mode,
        zero_rtt: bool_field(settings, "zero_rtt_handshake")
            || bool_field(settings, "zeroRttHandshake")
            || bool_field(server, "zero_rtt_handshake")
            || bool_field(server, "zeroRttHandshake"),
        cc,
        roots: Some(tls.roots.clone()),
        cert_pins: Arc::clone(&tls.cert_pins),
        insecure: tls.insecure,
        heartbeat,
        lanes: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        session: Arc::new(Mutex::new(None)),
    }))
}

fn bool_field(node: &Json, name: &str) -> bool {
    matches!(node.get(name), Some(Json::Bool(true)))
}

fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high = None;
    let mut digits = 0;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        digits += 1;
        if digits > 32 {
            return None;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(high) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (high << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    (digits == 32 && high.is_none()).then_some(out)
}

fn users(inbound: &Json) -> Vec<User> {
    let settings = inbound.get("settings");
    let mut users = Vec::new();
    if let Some(listed) = settings
        .and_then(|node| node.get("users").or_else(|| node.get("clients")))
        .and_then(Json::as_arr)
    {
        for user in listed {
            let Some(uuid) = user.get("uuid").and_then(Json::as_str).and_then(uuid_bytes) else {
                continue;
            };
            let Some(password) = user
                .get("password")
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            users.push(User {
                uuid,
                password: password.to_owned(),
            });
        }
    }
    if users.is_empty() {
        if let (Some(uuid), Some(password)) = (
            settings
                .and_then(|node| node.get("uuid"))
                .and_then(Json::as_str)
                .and_then(uuid_bytes),
            settings
                .and_then(|node| node.get("password"))
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty()),
        ) {
            users.push(User {
                uuid,
                password: password.to_owned(),
            });
        }
    }
    users
}

pub(crate) fn serve_inbound(
    address: &str,
    inbound: &Json,
    path: &str,
    freedom: bool,
    stop: Option<Arc<proxy::Stop>>,
) -> bool {
    let users = users(inbound);
    if users.is_empty() {
        eprintln!("tuic inbound in {path} names no user: serves nothing");
        return false;
    }
    let Some(stream) = inbound.get("streamSettings") else {
        eprintln!("tuic inbound in {path} carries no tls settings: serves nothing");
        return false;
    };
    if crate::config::stream_security(inbound) != "tls" {
        eprintln!("tuic inbound in {path} is not on tls: serves nothing");
        return false;
    }
    let Some(identity) = crate::config::tls_identity_from_settings(stream) else {
        eprintln!("unreadable tuic identity in {path}: serves nothing");
        return false;
    };
    let Ok(socket) = quic::bind_datagram(address) else {
        eprintln!("tuic inbound in {path} cannot bind {address}: serves nothing");
        return false;
    };
    let Ok(local) = socket.local_addr() else {
        return false;
    };
    let Some(mut template) = quic::tls_config(&identity) else {
        eprintln!("tuic inbound in {path} cannot build its tls: serves nothing");
        return false;
    };
    if !quic::tune(&mut template, wire::ALPN) {
        return false;
    }
    let setting = |name: &str| {
        inbound
            .get("settings")
            .and_then(|node| node.get(name))
            .and_then(Json::as_u32)
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(u64::from(seconds)))
    };
    let heartbeat = setting("heartbeat").unwrap_or(HEARTBEAT);
    let auth_timeout = setting("auth_timeout").unwrap_or(AUTH_TIMEOUT);
    let udp_timeout = setting("udp_timeout").unwrap_or(UDP_IDLE);
    if let Some(name) = inbound
        .get("settings")
        .and_then(|node| {
            node.get("congestion_control")
                .or_else(|| node.get("congestionControl"))
        })
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
    {
        if !matches!(name, "cubic" | "new_reno" | "reno" | "bbr") {
            eprintln!("tuic congestion_control `{name}` is not carried");
            return false;
        }
        if template.set_cc_algorithm_name(quiche_cc(name)).is_err() {
            eprintln!("tuic congestion_control `{name}` is not carried");
            return false;
        }
    }
    template.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
    if inbound.get("settings").is_some_and(|node| {
        bool_field(node, "zero_rtt_handshake") || bool_field(node, "zeroRttHandshake")
    }) {
        template.enable_early_data();
    }
    let signal = stop.as_ref().map(|stop| stop.shared());
    let meter = proxy::inbound_meter(inbound);
    thread::spawn(move || {
        run(
            Arc::new(Datagram::plain(socket)),
            local,
            users,
            template,
            freedom,
            heartbeat,
            auth_timeout,
            udp_timeout,
            meter,
            signal,
        );
        if let Some(stop) = stop {
            stop.mark_closed();
        }
    });
    true
}

#[allow(clippy::too_many_arguments)]
fn run(
    sock: Arc<Datagram>,
    local: SocketAddr,
    users: Vec<User>,
    template: quiche::Config,
    freedom: bool,
    heartbeat: Duration,
    auth_timeout: Duration,
    udp_timeout: Duration,
    meter: crate::stats::Meter,
    signal: Option<Arc<AtomicBool>>,
) {
    let stop = signal.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let mut retry_secret = [0u8; 32];
    if getrandom::fill(&mut retry_secret).is_err() {
        return;
    }
    let mut server = Server {
        sock,
        local,
        users,
        template,
        freedom,
        heartbeat,
        auth_timeout,
        udp_timeout,
        meter,
        stop: Arc::clone(&stop),
        live: Arc::new(AtomicUsize::new(0)),
        conns: HashMap::new(),
        sessions: 0,
        udp_sockets: Arc::new(AtomicUsize::new(0)),
        retry_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &retry_secret),
        touched: Vec::new(),
        touched_ids: HashSet::new(),
        dead: HashSet::new(),
        seen: HashSet::new(),
    };
    let mut buf = vec![0u8; UDP_BUFFER];
    let mut last_tick = Instant::now();
    if server.sock.set_read_timeout(Some(POLL)).is_err() {
        return;
    }
    let mut batch = quic::Batch::new();
    while !stop.load(Ordering::Relaxed) {
        match quic::recv_batch(&server.sock, &mut batch) {
            quic::Drain::Read => server.route_batch(&mut batch),
            quic::Drain::Empty => {}
            quic::Drain::Unbatchable => match server.sock.recv_from(&mut buf) {
                Ok((n, from)) => server.route(&mut buf[..n], from),
                Err(error)
                    if is_wait(&error) || error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            },
            quic::Drain::Unreadable => break,
        }
        if last_tick.elapsed() >= POLL {
            server.tick();
            last_tick = Instant::now();
        }
    }
    server.close();
}

struct Server {
    sock: Arc<Datagram>,
    local: SocketAddr,
    users: Vec<User>,
    template: quiche::Config,
    freedom: bool,
    heartbeat: Duration,
    auth_timeout: Duration,
    udp_timeout: Duration,
    meter: crate::stats::Meter,
    /// The driver's stop, so every worker leaves and drops its socket before the listener reports closed.
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    conns: HashMap<Vec<u8>, Arc<Session>>,
    sessions: usize,
    udp_sockets: Arc<AtomicUsize>,
    retry_key: ring::hmac::Key,
    /// Sessions this worker owed a turn at the end of a batch, kept so each batch reuses one capacity.
    touched: Vec<Arc<Session>>,
    /// The identities in `touched`, so a burst's repeat visit is one hash, not a walk of the list.
    touched_ids: HashSet<usize>,
    /// The periodic sweep's findings: the dead sessions' identities and the ones it already visited.
    dead: HashSet<usize>,
    seen: HashSet<usize>,
}

/// A worker's claim on the listener's socket, returned even when the flow panics.
struct LiveWorker(Arc<AtomicUsize>);

impl Drop for LiveWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Session {
    conn: Arc<Mutex<QuicheConnection>>,
    born: Instant,
    auth_from: Mutex<Option<Instant>>,
    heartbeat: Mutex<Instant>,
    inner: Mutex<Inner>,
}

struct Inner {
    authed: bool,
    auth: Vec<u8>,
    auth_id: Option<u64>,
    seen: HashSet<u64>,
    uni: HashMap<u64, Vec<u8>>,
    udp: HashMap<u16, UdpAssoc>,
    /// The association the last sweep stopped on, so later ones are serviced next.
    udp_cursor: Option<u16>,
    reassembly: HashMap<(u16, u16), Parts>,
    next_uni: AtomicU64,
    pending: Vec<Pending>,
    resolving: HashMap<(u16, String, u16), Resolving>,
    next_generation: u64,
    resolve_done: Sender<ResolveDone>,
    resolved: Receiver<ResolveDone>,
    udp_sockets: Arc<AtomicUsize>,
    udp_buf: Vec<u8>,
    udp_frame: Vec<u8>,
    readable: Vec<u64>,
    expired: Vec<u16>,
    #[cfg(test)]
    clocks: usize,
    #[cfg(test)]
    expiry_passes: usize,
}

struct UdpAssoc {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    stream: bool,
    last: Instant,
    generation: u64,
    packet: u16,
    /// The socket the next sweep reads first, so a full v4 queue cannot starve v6 forever.
    turn_v6: bool,
    sockets: Arc<AtomicUsize>,
}

impl UdpAssoc {
    fn new(stream: bool, sockets: Arc<AtomicUsize>, generation: u64) -> Self {
        Self {
            v4: None,
            v6: None,
            stream,
            last: Instant::now(),
            generation,
            packet: 0,
            turn_v6: false,
            sockets,
        }
    }
}

impl Drop for UdpAssoc {
    fn drop(&mut self) {
        let held = usize::from(self.v4.is_some()) + usize::from(self.v6.is_some());
        if held > 0 {
            self.sockets.fetch_sub(held, Ordering::Relaxed);
        }
    }
}

fn reserve_socket(sockets: &AtomicUsize) -> bool {
    let mut current = sockets.load(Ordering::Relaxed);
    loop {
        if current >= MAX_UDP_SOCKETS {
            return false;
        }
        match sockets.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

impl UdpAssoc {
    fn socket_for(&mut self, target: SocketAddr) -> Option<&UdpSocket> {
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let slot = if target.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };
        if slot.is_none() {
            if !reserve_socket(&self.sockets) {
                return None;
            }
            if let Ok(socket) = UdpSocket::bind(bind) {
                let _ = socket.set_nonblocking(true);
                *slot = Some(socket);
            } else {
                self.sockets.fetch_sub(1, Ordering::Relaxed);
                return None;
            }
        }
        slot.as_ref()
    }
}

impl Server {
    fn route(&mut self, bytes: &mut [u8], from: SocketAddr) {
        let Some(session) = self.session_for(bytes, from) else {
            return;
        };
        self.feed(&session, bytes, from);
        self.turn(&session);
    }

    /// One received burst: every datagram goes to quiche first, and the session whose packets it
    /// carried takes one turn over them instead of one per datagram.
    fn route_batch(&mut self, batch: &mut quic::Batch) {
        let taken = batch.len();
        let mut touched = std::mem::take(&mut self.touched);
        let mut touched_ids = std::mem::take(&mut self.touched_ids);
        touched.clear();
        touched_ids.clear();
        for at in 0..taken {
            let Some((bytes, from)) = batch.at(at) else {
                continue;
            };
            let Some(session) = self.session_for(bytes, from) else {
                continue;
            };
            self.feed(&session, bytes, from);
            if touched_ids.insert(Arc::as_ptr(&session) as usize) {
                touched.push(session);
            }
        }
        for session in touched.drain(..) {
            self.turn(&session);
        }
        self.touched = touched;
        self.touched_ids = touched_ids;
    }

    fn session_for(&mut self, bytes: &mut [u8], from: SocketAddr) -> Option<Arc<Session>> {
        let header = quiche::Header::from_slice(bytes, SCID_LEN).ok()?;
        if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
            return None;
        }
        let initial = header.ty == quiche::Type::Initial;
        let found = self.conns.get(header.dcid.as_ref()).cloned();
        match found {
            Some(session) => Some(session),
            None if initial => {
                if let Some(token) = header.token.as_deref().filter(|token| !token.is_empty()) {
                    self.accept(from, &header, token)
                } else {
                    self.retry(&header, from);
                    None
                }
            }
            None => None,
        }
    }

    fn retry(&self, header: &quiche::Header, from: SocketAddr) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::fill(&mut scid).is_err() {
            return;
        }
        let token = retry_token(&self.retry_key, from, header.dcid.as_ref(), &scid);
        let mut out = [0u8; 512];
        let Ok(len) = quiche::retry(
            &header.scid,
            &header.dcid,
            &quiche::ConnectionId::from_ref(&scid),
            &token,
            header.version,
            &mut out,
        ) else {
            return;
        };
        let _ = self.sock.send_to(&out[..len], from);
    }

    fn accept(
        &mut self,
        from: SocketAddr,
        header: &quiche::Header,
        token: &[u8],
    ) -> Option<Arc<Session>> {
        if self.sessions >= MAX_SESSIONS {
            return None;
        }
        let (odcid, retry_scid) = retry_token_valid(&self.retry_key, from, token)?;
        if header.dcid.as_ref() != retry_scid.as_slice() {
            return None;
        }
        let odcid = quiche::ConnectionId::from_ref(&odcid);
        let retry_scid = quiche::ConnectionId::from_ref(&retry_scid);
        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let conn: QuicheConnection = quiche::accept_with_retry::<crate::quic::BytesBufFactory>(
            &cid,
            quiche::RetryConnectionIds {
                original_destination_cid: &odcid,
                retry_source_cid: &retry_scid,
            },
            self.local,
            from,
            &mut self.template,
        )
        .ok()?;
        let conn = Arc::new(Mutex::new(conn));
        let now = Instant::now();
        let (resolve_done, resolved) = std::sync::mpsc::channel();
        let session = Arc::new(Session {
            conn: Arc::clone(&conn),
            born: now,
            auth_from: Mutex::new(None),
            heartbeat: Mutex::new(now),
            inner: Mutex::new(Inner {
                authed: false,
                auth: Vec::new(),
                auth_id: None,
                seen: HashSet::new(),
                uni: HashMap::new(),
                udp: HashMap::new(),
                udp_cursor: None,
                reassembly: HashMap::new(),
                next_uni: AtomicU64::new(3),
                pending: Vec::new(),
                resolving: HashMap::new(),
                next_generation: 0,
                resolve_done,
                resolved,
                udp_sockets: Arc::clone(&self.udp_sockets),
                udp_buf: Vec::new(),
                udp_frame: Vec::new(),
                readable: Vec::new(),
                expired: Vec::new(),
                #[cfg(test)]
                clocks: 0,
                #[cfg(test)]
                expiry_passes: 0,
            }),
        });
        self.conns.insert(scid.to_vec(), Arc::clone(&session));
        self.conns
            .entry(retry_scid.as_ref().to_vec())
            .or_insert_with(|| Arc::clone(&session));
        self.sessions += 1;
        Some(session)
    }

    fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let mut seen = std::mem::take(&mut self.seen);
        seen.clear();
        for session in self.conns.values() {
            if !seen.insert(Arc::as_ptr(session) as usize) {
                continue;
            }
            if let Ok(mut conn) = session.conn.lock() {
                let _ = conn.close(true, 0, b"closed");
                quic::flush_egress(&mut conn, &self.sock);
            }
        }
        self.seen = seen;
        self.conns.clear();
        self.sessions = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.live.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let left = self.live.load(Ordering::SeqCst);
        if left != 0 {
            eprintln!("tuic: {left} stream handlers still running at shutdown");
        }
    }

    /// Hand one packet to its connection and register the source ids it named, so the rest of the
    /// batch routes by them.
    fn feed(&mut self, session: &Arc<Session>, bytes: &mut [u8], from: SocketAddr) {
        let Ok(mut conn) = session.conn.lock() else {
            return;
        };
        let _ = conn.recv(
            bytes,
            quiche::RecvInfo {
                from,
                to: self.local,
            },
        );
        for id in conn.source_ids() {
            if !self.conns.contains_key(id.as_ref()) {
                self.conns.insert(id.as_ref().to_vec(), Arc::clone(session));
            }
        }
    }

    /// What a session owes after its packets landed: the timers they advanced, the streams they
    /// made readable, and the egress behind both.
    fn turn(&mut self, session: &Arc<Session>) {
        let Ok(mut conn) = session.conn.lock() else {
            return;
        };
        if conn
            .timeout_instant()
            .is_some_and(|at| at <= Instant::now())
        {
            conn.on_timeout();
        }
        if !conn.is_established() || conn.is_closed() {
            quic::flush_egress(&mut conn, &self.sock);
            return;
        }
        let Ok(mut inner) = session.inner.lock() else {
            return;
        };
        if !inner.authed {
            if let Ok(mut from) = session.auth_from.lock() {
                from.get_or_insert_with(Instant::now);
            }
            if !authenticate(&mut conn, &mut inner, &self.users) {
                quic::flush_egress(&mut conn, &self.sock);
                return;
            }
        }
        let state = &mut *inner;
        state.seen.retain(|id| !conn.stream_closed(*id));
        state.readable.clear();
        state.readable.extend(conn.readable());
        for id in state.uni.keys() {
            if !state.readable.contains(id) {
                state.readable.push(*id);
            }
        }
        let mut ids = std::mem::take(&mut state.readable);
        for &id in &ids {
            match id % 4 {
                0 => {
                    if state.seen.insert(id) {
                        let stream = QuicStream::new(
                            Arc::clone(&session.conn),
                            Arc::clone(&self.sock),
                            id,
                            crate::stats::Meter::default(),
                        )
                        .with_stop(Arc::clone(&self.stop))
                        .with_meter(self.meter.clone());
                        let freedom = self.freedom;
                        self.live.fetch_add(1, Ordering::SeqCst);
                        let worker = LiveWorker(Arc::clone(&self.live));
                        let _ = thread::Builder::new()
                            .spawn(move || serve_tcp(stream, freedom, worker));
                    }
                }
                2 => read_uni(&mut conn, state, id, self.freedom),
                _ => {}
            }
        }
        ids.clear();
        state.readable = ids;
        let now = Instant::now();
        while let Ok(data) = conn.dgram_recv_buf() {
            if self.freedom {
                if let Ok(packet) = wire::parse_packet(&data) {
                    accept_packet(&mut inner, &packet, false, now);
                }
            }
        }
        drain_resolved(&mut inner, now);
        poll_udp(&mut conn, &self.sock, &mut inner, now);
        inner
            .reassembly
            .retain(|_, parts| now.duration_since(parts.at) < REASSEMBLY_TTL);
        expire_udp(&mut inner, now, self.udp_timeout);
        flush_inner(&mut conn, &self.sock, &mut inner);
        self.beat(session, &mut conn, now);
        quic::flush_egress(&mut conn, &self.sock);
    }

    fn beat(&self, session: &Session, conn: &mut QuicheConnection, now: Instant) {
        let due = session
            .heartbeat
            .lock()
            .is_ok_and(|last| now.duration_since(*last) >= self.heartbeat);
        if due {
            let _ = conn.dgram_send(&[wire::VERSION, wire::HEARTBEAT]);
            if let Ok(mut last) = session.heartbeat.lock() {
                *last = now;
            }
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let mut dead = std::mem::take(&mut self.dead);
        let mut seen = std::mem::take(&mut self.seen);
        dead.clear();
        seen.clear();
        for session in self.conns.values() {
            if !seen.insert(Arc::as_ptr(session) as usize) {
                continue;
            }
            let Ok(mut conn) = session.conn.lock() else {
                continue;
            };
            let authed = session.inner.lock().is_ok_and(|inner| inner.authed);
            let auth_at = session
                .auth_from
                .lock()
                .ok()
                .and_then(|from| *from)
                .unwrap_or(session.born);
            if conn.is_closed() || (!authed && now.duration_since(auth_at) >= self.auth_timeout) {
                if !conn.is_closed() {
                    let _ = conn.close(true, 0, b"timeout");
                    quic::flush_egress(&mut conn, &self.sock);
                }
                dead.insert(Arc::as_ptr(session) as usize);
                continue;
            }
            if !conn.is_established() {
                if let Some(at) = conn.timeout_instant() {
                    if at <= now {
                        conn.on_timeout();
                    }
                }
                quic::flush_egress(&mut conn, &self.sock);
                continue;
            }
            self.beat(session, &mut conn, now);
            if let Some(at) = conn.timeout_instant() {
                if at <= now {
                    conn.on_timeout();
                }
            }
            let Ok(mut inner) = session.inner.lock() else {
                continue;
            };
            inner.seen.retain(|id| !conn.stream_closed(*id));
            drain_resolved(&mut inner, now);
            poll_udp(&mut conn, &self.sock, &mut inner, now);
            expire_udp(&mut inner, now, self.udp_timeout);
            inner
                .reassembly
                .retain(|_, parts| now.duration_since(parts.at) < REASSEMBLY_TTL);
            flush_inner(&mut conn, &self.sock, &mut inner);
            quic::flush_egress(&mut conn, &self.sock);
        }
        if !dead.is_empty() {
            self.conns
                .retain(|_, session| !dead.contains(&(Arc::as_ptr(session) as usize)));
            self.sessions = self.sessions.saturating_sub(dead.len());
        }
        dead.clear();
        seen.clear();
        self.dead = dead;
        self.seen = seen;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn retry_token(key: &ring::hmac::Key, from: SocketAddr, odcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let now = unix_now();
    let mut token = Vec::with_capacity(1 + 8 + 17 + 1 + odcid.len() + SCID_LEN + RETRY_TOKEN_TAG);
    token.push(1);
    token.extend_from_slice(&now.to_le_bytes());
    match from.ip() {
        IpAddr::V4(ip) => {
            token.push(4);
            token.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            token.push(6);
            token.extend_from_slice(&ip.octets());
        }
    }
    token.push(odcid.len() as u8);
    token.extend_from_slice(odcid);
    token.extend_from_slice(scid);
    let tag = ring::hmac::sign(key, &token);
    token.extend_from_slice(tag.as_ref());
    token
}

fn retry_token_valid(
    key: &ring::hmac::Key,
    from: SocketAddr,
    token: &[u8],
) -> Option<(Vec<u8>, [u8; SCID_LEN])> {
    let (body, tag) = token.split_at_checked(token.len().checked_sub(RETRY_TOKEN_TAG)?)?;
    if ring::hmac::verify(key, body, tag).is_err() {
        return None;
    }
    let mut at = 0;
    if *body.first()? != 1 {
        return None;
    }
    at += 1;
    let issued = u64::from_le_bytes(body.get(at..at + 8)?.try_into().ok()?);
    at += 8;
    let now = unix_now();
    if issued > now.saturating_add(5) || now.saturating_sub(issued) > RETRY_TOKEN_TTL.as_secs() {
        return None;
    }
    let ip = match body.get(at).copied()? {
        4 => {
            at += 1;
            IpAddr::from(<[u8; 4]>::try_from(body.get(at..at + 4)?).ok()?)
        }
        6 => {
            at += 1;
            IpAddr::from(<[u8; 16]>::try_from(body.get(at..at + 16)?).ok()?)
        }
        _ => return None,
    };
    at += if ip.is_ipv4() { 4 } else { 16 };
    if ip != from.ip() {
        return None;
    }
    let len = *body.get(at)? as usize;
    at += 1;
    if len == 0 || len > quiche::MAX_CONN_ID_LEN {
        return None;
    }
    let odcid = body.get(at..at + len)?.to_vec();
    at += len;
    let scid = <[u8; SCID_LEN]>::try_from(body.get(at..at + SCID_LEN)?).ok()?;
    at += SCID_LEN;
    if at != body.len() {
        return None;
    }
    Some((odcid, scid))
}

fn authenticate(conn: &mut QuicheConnection, inner: &mut Inner, users: &[User]) -> bool {
    if inner.auth.len() < wire::AUTH_LEN {
        if let Some(id) = inner.auth_id {
            if !read_command(conn, id, &mut inner.auth) {
                return false;
            }
        } else {
            let ids: Vec<u64> = conn.readable().filter(|id| id % 4 == 2).collect();
            for id in ids {
                let mut data = inner.uni.remove(&id).unwrap_or_default();
                read_prefix(conn, id, &mut data);
                if data.len() < 2 {
                    if !data.is_empty() {
                        inner.uni.insert(id, data);
                    }
                    continue;
                }
                if data[0] != wire::VERSION {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                if data[1] == wire::AUTHENTICATE {
                    if !read_command(conn, id, &mut data) {
                        return false;
                    }
                    inner.auth_id = Some(id);
                    inner.auth = data;
                    break;
                }
                if !matches!(
                    data[1],
                    wire::CONNECT | wire::PACKET | wire::DISSOCIATE | wire::HEARTBEAT
                ) {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                let held: usize = inner.uni.values().map(Vec::len).sum();
                if inner.uni.len() >= MAX_PREAUTH_COMMANDS
                    || held.saturating_add(data.len()) > MAX_PREAUTH_BYTES
                {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                inner.uni.insert(id, data);
            }
        }
    }
    if inner.auth.len() < wire::AUTH_LEN {
        return false;
    }
    if inner.auth[0] != wire::VERSION || inner.auth[1] != wire::AUTHENTICATE {
        let _ = conn.close(false, 0, b"auth");
        return false;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&inner.auth[2..18]);
    let user = users.iter().find(|user| user.uuid == uuid);
    let password: &[u8] = match user {
        Some(user) => user.password.as_bytes(),
        None => &[],
    };
    let Some(token) = export_token(conn, &uuid, password) else {
        let _ = conn.close(false, 0, b"auth");
        return false;
    };
    if user.is_none() || !constant_eq(&inner.auth[18..50], &token) {
        let _ = conn.close(false, 0, b"auth");
        return false;
    }
    inner.authed = true;
    inner.auth.clear();
    if inner.auth_id.is_some_and(|id| conn.stream_finished(id)) {
        inner.auth_id = None;
    }
    true
}

fn read_prefix(conn: &mut QuicheConnection, id: u64, data: &mut Vec<u8>) {
    while data.len() < 2 {
        let need = 2 - data.len();
        match conn.stream_recv_buf(id, (&mut *data).limit(need)) {
            Ok((0, _)) | Err(_) => break,
            Ok((_, _)) => {}
        }
    }
}

fn read_command(conn: &mut QuicheConnection, id: u64, data: &mut Vec<u8>) -> bool {
    while data.len() < MAX_UNI_COMMAND {
        // One byte over the cap distinguishes "filled it exactly" from "there is more".
        let room = MAX_UNI_COMMAND - data.len() + 1;
        match conn.stream_recv_buf(id, (&mut *data).limit(room)) {
            Ok((0, _)) | Err(_) => break,
            Ok((_, _)) => {
                if data.len() > MAX_UNI_COMMAND {
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                if data.len() >= wire::AUTH_LEN
                    && data.first() == Some(&wire::VERSION)
                    && data.get(1) == Some(&wire::AUTHENTICATE)
                {
                    break;
                }
            }
        }
    }
    true
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn serve_tcp(mut stream: QuicStream, freedom: bool, worker: LiveWorker) {
    if !freedom {
        stream.close();
        drop(stream);
        return;
    }
    let deadline = Instant::now() + CONNECT_HEADER_TIMEOUT;
    let mut head = [0u8; 2];
    if read_exact(&mut stream, &mut head, deadline).is_err()
        || head != [wire::VERSION, wire::CONNECT]
    {
        stream.close();
        drop(stream);
        return;
    }
    let Some((host, port)) = read_stream_address(&mut stream, deadline) else {
        stream.close();
        drop(stream);
        return;
    };
    let Some(upstream) =
        proxy::resolve_outbound(&host, port).and_then(|target| proxy::dial_or_report(&target))
    else {
        stream.close();
        drop(stream);
        return;
    };
    proxy::relay_quic_stream(&upstream, stream, Some(Box::new(move || drop(worker))));
}

fn read_exact(stream: &mut QuicStream, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        match stream.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => at += n,
            Err(error) if is_wait(&error) => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_stream_address(stream: &mut QuicStream, deadline: Instant) -> Option<(String, u16)> {
    let mut kind = [0u8; 1];
    read_exact(stream, &mut kind, deadline).ok()?;
    let host = match kind[0] {
        0 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len, deadline).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name, deadline).ok()?;
            String::from_utf8(name).ok()?
        }
        1 => {
            let mut octets = [0u8; 4];
            read_exact(stream, &mut octets, deadline).ok()?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        2 => {
            let mut octets = [0u8; 16];
            read_exact(stream, &mut octets, deadline).ok()?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    read_exact(stream, &mut port, deadline).ok()?;
    Some((host, u16::from_be_bytes(port)))
}

fn read_uni(conn: &mut QuicheConnection, inner: &mut Inner, id: u64, freedom: bool) {
    if inner.auth_id == Some(id) {
        while let Ok((n, fin)) = conn.stream_discard(id, usize::MAX) {
            if n == 0 || fin {
                break;
            }
        }
        inner.uni.remove(&id);
        if conn.stream_finished(id) {
            inner.auth_id = None;
        }
        return;
    }
    let mut data = inner.uni.remove(&id).unwrap_or_default();
    loop {
        if data.len() > MAX_UNI_COMMAND {
            if freedom && data.get(1) == Some(&wire::PACKET) {
                let Some(at) = read_packets(inner, &data) else {
                    let _ = conn.close(true, 0, b"command");
                    return;
                };
                if at > 0 {
                    data.drain(..at);
                }
                if data.len() <= MAX_UNI_COMMAND {
                    continue;
                }
            }
            let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
            return;
        }
        // One byte over the cap distinguishes "filled it exactly" from "there is more".
        let room = MAX_UNI_COMMAND - data.len() + 1;
        match conn.stream_recv_buf(id, (&mut data).limit(room)) {
            Ok((0, _)) | Err(_) => break,
            Ok((_, _)) => {}
        }
    }
    if freedom && data.get(1) == Some(&wire::PACKET) {
        let Some(at) = read_packets(inner, &data) else {
            let _ = conn.close(true, 0, b"command");
            return;
        };
        if at > 0 {
            data.drain(..at);
        }
    }
    if !conn.stream_finished(id) {
        if !data.is_empty() {
            inner.uni.insert(id, data);
        }
        return;
    }
    if data.len() < 2 || data[0] != wire::VERSION {
        return;
    }
    match data[1] {
        wire::DISSOCIATE if data.len() == 4 => {
            let association = u16::from_be_bytes([data[2], data[3]]);
            inner.udp.remove(&association);
            inner.reassembly.retain(|key, _| key.0 != association);
            inner.resolving.retain(|key, _| key.0 != association);
        }
        wire::HEARTBEAT if data.len() == 2 => {}
        _ => {
            let _ = conn.close(true, 0, b"command");
        }
    }
}

/// Delivers the PACKET frames a uni run carries under one stamp; `None` is a frame past the
/// parser's prefix, which ends the connection, and `Some` is the bytes consumed.
fn read_packets(inner: &mut Inner, data: &[u8]) -> Option<usize> {
    let now = Instant::now();
    #[cfg(test)]
    {
        inner.clocks += 1;
    }
    let mut at = 0usize;
    loop {
        match wire::parse_packet_prefix(&data[at..]) {
            Ok((packet, used)) => {
                accept_packet(inner, &packet, true, now);
                at += used;
            }
            Err(wire::FrameError::Short) => break,
            Err(_) => return None,
        }
    }
    Some(at)
}

fn accept_packet(inner: &mut Inner, packet: &wire::Packet<'_>, stream: bool, now: Instant) {
    let Some(generation) = select_assoc(inner, packet.association, stream) else {
        return;
    };
    let Some((destination, payload)) = take_packet(&mut inner.reassembly, packet) else {
        return;
    };
    match destination {
        Destination::Address(target) => {
            deliver_udp(inner, packet.association, target, &payload, now);
        }
        Destination::Name(host, port) => {
            let job = ResolveJob {
                association: packet.association,
                host,
                port,
                payload: payload.into_owned(),
                generation,
                options: proxy::dial_options(),
                reply: inner.resolve_done.clone(),
            };
            queue_resolve(inner, job);
        }
    }
}

fn queue_resolve(inner: &mut Inner, job: ResolveJob) {
    let key = (job.association, job.host.clone(), job.port);
    if let Some(pending) = inner.resolving.get_mut(&key) {
        if pending.payloads.len() < MAX_RESOLVE_PAYLOADS {
            pending.payloads.push(job.payload);
        }
        return;
    }
    if inner.resolving.len() >= MAX_RESOLVING_PER_SESSION {
        return;
    }
    inner.resolving.insert(
        key.clone(),
        Resolving {
            generation: job.generation,
            payloads: Vec::new(),
        },
    );
    if !ResolverPool::get().submit(job) {
        inner.resolving.remove(&key);
    }
}

fn drain_resolved(inner: &mut Inner, now: Instant) {
    while let Ok(done) = inner.resolved.try_recv() {
        let key = (done.association, done.host.clone(), done.port);
        let Some(held) = inner.resolving.get(&key) else {
            continue;
        };
        if held.generation != done.generation {
            continue;
        }
        if inner
            .udp
            .get(&done.association)
            .is_none_or(|assoc| assoc.generation != done.generation)
        {
            inner.resolving.remove(&key);
            continue;
        }
        let Some(pending) = inner.resolving.remove(&key) else {
            continue;
        };
        if let Some(target) = done.target {
            deliver_udp(inner, done.association, target, &done.payload, now);
            for payload in pending.payloads {
                deliver_udp(inner, done.association, target, &payload, now);
            }
        }
    }
}

/// Record the first PACKET's reply mode before a name waits on DNS: a later numeric PACKET for the
/// same association must not choose the mode the lookup will use. The generation is session-wide, so
/// a recreated association cannot accept a lookup that belonged to an earlier one.
fn select_assoc(inner: &mut Inner, association: u16, stream: bool) -> Option<u64> {
    if let Some(assoc) = inner.udp.get(&association) {
        return Some(assoc.generation);
    }
    if inner.udp.len() >= MAX_ASSOCIATIONS_PER_SESSION {
        return None;
    }
    let generation = inner.next_generation;
    inner.next_generation = generation.wrapping_add(1);
    let sockets = Arc::clone(&inner.udp_sockets);
    inner
        .udp
        .insert(association, UdpAssoc::new(stream, sockets, generation));
    Some(generation)
}

/// Expire idle associations with everything that belonged to them, so a lookup that lands after the
/// expiry cannot recreate the association it was resolved for.
fn expire_udp(inner: &mut Inner, now: Instant, timeout: Duration) {
    let mut expired = std::mem::take(&mut inner.expired);
    expired.clear();
    expired.extend(
        inner
            .udp
            .iter()
            .filter(|(_, assoc)| now.duration_since(assoc.last) >= timeout)
            .map(|(association, _)| *association),
    );
    if expired.is_empty() {
        inner.expired = expired;
        return;
    }
    expired.sort_unstable();
    for association in &expired {
        inner.udp.remove(association);
    }
    #[cfg(test)]
    {
        inner.expiry_passes += 2;
    }
    inner
        .reassembly
        .retain(|key, _| expired.binary_search(&key.0).is_err());
    inner
        .resolving
        .retain(|key, _| expired.binary_search(&key.0).is_err());
    inner.expired = expired;
}

fn deliver_udp(
    inner: &mut Inner,
    association: u16,
    target: SocketAddr,
    payload: &[u8],
    now: Instant,
) {
    let Some(entry) = inner.udp.get_mut(&association) else {
        return;
    };
    entry.last = now;
    let Some(socket) = entry.socket_for(target) else {
        return;
    };
    let _ = socket.send_to(payload, target);
}

fn flush_inner(conn: &mut QuicheConnection, sock: &Arc<Datagram>, inner: &mut Inner) {
    let mut pending = std::mem::take(&mut inner.pending);
    flush_pending(conn, sock, &mut pending, &inner.next_uni);
    inner.pending = pending;
}

fn poll_udp(conn: &mut QuicheConnection, sock: &Datagram, inner: &mut Inner, now: Instant) {
    let max = conn.dgram_max_writable_len();
    let mut buf = std::mem::take(&mut inner.udp_buf);
    buf.resize(UDP_BUFFER, 0);
    let mut pending = std::mem::take(&mut inner.pending);
    let mut frame = std::mem::take(&mut inner.udp_frame);
    let mut swept = 0usize;
    let cursor = inner.udp_cursor;
    let mut after = cursor.is_none_or(|key| !inner.udp.contains_key(&key));
    let mut exhausted = false;
    let mut last_serviced = None;
    'sweep: for (association, assoc) in &mut inner.udp {
        if !after {
            if Some(*association) == cursor {
                after = true;
            }
            continue;
        }
        let UdpAssoc {
            v4,
            v6,
            stream,
            last,
            packet,
            turn_v6,
            ..
        } = assoc;
        let mode = if *stream {
            RelayMode::Quic
        } else {
            RelayMode::Native
        };
        let (first, second) = if *turn_v6 { (v6, v4) } else { (v4, v6) };
        *turn_v6 = !*turn_v6;
        let mut taken = 0usize;
        for socket in [first, second].into_iter().flatten() {
            loop {
                if taken >= UDP_PACKETS_PER_ASSOC || swept >= UDP_PACKETS_PER_SWEEP {
                    break;
                }
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        taken += 1;
                        swept += 1;
                        let address = match from.ip() {
                            IpAddr::V4(ip) => wire::Address::V4(ip.octets()),
                            IpAddr::V6(ip) => wire::Address::V6(ip.octets()),
                        };
                        *last = now;
                        *packet = next_packet(*packet);
                        send_message(
                            conn,
                            sock,
                            mode,
                            *association,
                            *packet,
                            address,
                            from.port(),
                            &buf[..n],
                            max,
                            &mut pending,
                            &mut frame,
                        );
                    }
                    Err(error) if is_wait(&error) => break,
                    Err(_) => break,
                }
            }
        }
        last_serviced = Some(*association);
        if swept >= UDP_PACKETS_PER_SWEEP {
            exhausted = true;
            break 'sweep;
        }
    }
    inner.udp_cursor = if exhausted { last_serviced } else { None };
    inner.pending = pending;
    inner.udp_buf = buf;
    inner.udp_frame = frame;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> (ferrox_core::tls::TlsServerConfig, Vec<Vec<u8>>) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tuic.test".to_owned()]).expect("mints");
        let roots = quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let identity = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: roots.clone(),
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            issuer: None,
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        (identity, roots)
    }

    fn test_out(address: SocketAddr, roots: Vec<Vec<u8>>) -> TuicOut {
        TuicOut {
            address: "127.0.0.1".to_owned(),
            port: address.port(),
            host: "tuic.test".to_owned(),
            uuid: [0x11; 16],
            password: "secret".to_owned(),
            mode: RelayMode::Quic,
            zero_rtt: true,
            cc: None,
            roots: Some(Arc::from(roots)),
            cert_pins: Arc::new([]),
            insecure: false,
            heartbeat: Duration::from_secs(30),
            lanes: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            session: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn a_pin_verifies_the_handshake() {
        let (identity, roots) = test_identity();
        let leaf = identity.certs[0].cert_chain[0].clone();
        let digest = ring::digest::digest(&ring::digest::SHA256, &leaf);
        let pin: [u8; 32] = digest.as_ref().try_into().expect("a sha256 digest");
        let mut config = quic::serve_config(&identity).expect("the server builds");
        let server = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let address = server.local_addr().expect("address");
        let server_thread = thread::spawn(move || {
            let sock = Datagram::plain(server);
            let _ = quic::server_accept(&sock, address, &mut config);
        });
        let mut out = test_out(address, roots);
        out.zero_rtt = false;
        out.cert_pins = Arc::from(vec![pin]);
        let lane = out.lane().expect("a pinned handshake");
        assert!(
            lane.conn.lock().expect("the lane lock").is_established(),
            "the pin did not complete the handshake"
        );
        lane.stop.store(true, Ordering::Relaxed);
        server_thread.join().expect("the server thread");
    }

    #[test]
    fn a_resumed_lane_carries_application_data_before_the_handshake() {
        let (identity, roots) = test_identity();
        let mut config = quic::serve_config(&identity).expect("the server builds");
        config.enable_early_data();
        let server = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let address = server.local_addr().expect("address");
        let (early, observed) = std::sync::mpsc::channel();
        let server_thread = thread::spawn(move || {
            let sock = Datagram::plain(server);
            let mut buf = vec![0u8; 65535];
            let mut out = vec![0u8; 65535];
            let mut first = quic::server_accept(&sock, address, &mut config);
            for _ in 0..20 {
                quic::server_idle(&mut first, &sock, &mut out);
                thread::sleep(Duration::from_millis(10));
            }
            drop(first);
            thread::sleep(Duration::from_millis(100));

            let deadline = Instant::now() + Duration::from_secs(5);
            let (n, from) = loop {
                assert!(Instant::now() < deadline, "no second Initial arrived");
                let Some((n, from)) = quic::server_poll(&sock, &mut buf) else {
                    continue;
                };
                if quiche::Header::from_slice(&mut buf[..n], 20)
                    .is_ok_and(|header| header.ty == quiche::Type::Initial)
                {
                    break (n, from);
                }
            };
            let mut scid = [0u8; 16];
            getrandom::fill(&mut scid).expect("random");
            let cid = quiche::ConnectionId::from_ref(&scid);
            let mut second = quiche::accept_with_buf_factory::<crate::quic::BytesBufFactory>(
                &cid,
                None,
                address,
                from,
                &mut config,
            )
            .expect("accepts");
            second
                .recv(&mut buf[..n], quiche::RecvInfo { from, to: address })
                .expect("drives");
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let mut data = [0u8; 64];
                if let Ok((read, _)) = second.stream_recv(0, &mut data) {
                    if read > 0 {
                        assert!(
                            !second.is_established(),
                            "the server read early data only after the handshake"
                        );
                        early.send(data[..read].to_vec()).expect("reports");
                        break;
                    }
                }
                if let Some((n, from)) = quic::server_poll(&sock, &mut buf) {
                    second
                        .recv(&mut buf[..n], quiche::RecvInfo { from, to: address })
                        .expect("drives");
                }
            }
        });

        let out = test_out(address, roots);
        let first = out.lane().expect("the first lane");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "no session ticket was delivered");
            if out.session.lock().expect("the session lock").is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        first.stop.store(true, Ordering::Relaxed);
        let lane = out.lane().expect("the resumed lane");
        let (established, in_early) = {
            let conn = lane.conn.lock().expect("the lane lock");
            (conn.is_established(), conn.is_in_early_data())
        };
        assert!(in_early, "the lane is not in early data");
        assert!(!established, "the lane waited for the handshake");
        let mut conn = lane.conn.lock().expect("the lane lock");
        assert_eq!(
            conn.stream_send(0, b"early connect", false)
                .expect("queues"),
            13
        );
        quic::flush_egress(&mut conn, &lane.sock);
        drop(conn);
        assert_eq!(
            observed
                .recv_timeout(Duration::from_secs(5))
                .expect("the server reads early data before the handshake"),
            b"early connect"
        );
        server_thread.join().expect("the server thread");
    }

    fn empty_inner() -> (Inner, Sender<ResolveDone>) {
        let (done, resolved) = std::sync::mpsc::channel();
        (
            Inner {
                authed: false,
                auth: Vec::new(),
                auth_id: None,
                seen: HashSet::new(),
                uni: HashMap::new(),
                udp: HashMap::new(),
                udp_cursor: None,
                reassembly: HashMap::new(),
                next_uni: AtomicU64::new(3),
                pending: Vec::new(),
                resolving: HashMap::new(),
                next_generation: 0,
                resolve_done: done.clone(),
                resolved,
                udp_sockets: Arc::new(AtomicUsize::new(0)),
                udp_buf: Vec::new(),
                udp_frame: Vec::new(),
                readable: Vec::new(),
                expired: Vec::new(),
                #[cfg(test)]
                clocks: 0,
                #[cfg(test)]
                expiry_passes: 0,
            },
            done,
        )
    }

    #[test]
    fn a_uuid_is_sixteen_bytes_and_refuses_anything_else() {
        assert_eq!(
            uuid_bytes("00112233-4455-6677-8899-aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert_eq!(uuid_bytes("0011"), None);
        assert_eq!(uuid_bytes("00112233445566778899aabbccddeefg"), None);
    }

    #[test]
    fn a_tuic_outbound_reads_the_reference_spellings() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"servers":[{"address":"tuic.test","server_port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","udp_relay_mode":"quic","congestion_control":"bbr","zero_rtt_handshake":true}]},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!((out.address.as_str(), out.port), ("tuic.test", 443));
        assert_eq!(out.mode, RelayMode::Quic);
        assert!(out.zero_rtt);
    }

    /// A uni read carrying three packets hands them over as three slices of one buffer: one
    /// allocation for the run, no per-packet copy, and the same base under every packet.
    #[test]
    fn a_uni_run_shares_one_buffer_across_its_packets() {
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut run = Vec::new();
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            let mut frame = Vec::new();
            wire::encode_fragment(1, 2, 1, 0, &address, payload, &mut frame);
            run.extend_from_slice(&frame);
        }
        let shared = run.clone();
        let mut replies = Vec::new();
        let (rest, broken) =
            ferrox_core::alloc_count::measure(|| share_uni_packets(shared, &mut replies)).0;
        assert!(!broken, "the run parses whole");
        assert!(rest.is_empty(), "and leaves no tail");
        assert_eq!(replies.len(), 3, "one reply per packet");
        let base = match &replies[0] {
            Reply::Inside { bytes, .. } => bytes.as_ptr(),
            Reply::Whole(_) => panic!("a uni packet is a slice, not its own buffer"),
        };
        let mut at = 0usize;
        for reply in &replies {
            let Reply::Inside { bytes, at: span } = reply else {
                panic!("a uni packet is a slice, not its own buffer");
            };
            assert_eq!(bytes.as_ptr(), base, "every packet reads the same buffer");
            assert_eq!(span.start, at, "and its own span in the run");
            assert_eq!(&bytes[span.clone()], &run[at..span.end]);
            at = span.end;
        }
        assert_eq!(at, run.len(), "the spans cover the read");
    }

    /// The allocator witness for the run above: after the read's buffer is built, handing three
    /// packets over costs the shared cell and nothing per packet.
    #[test]
    fn a_uni_run_is_one_allocation() {
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut frames = Vec::new();
        let mut run = Vec::new();
        for payload in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
            let mut frame = Vec::new();
            wire::encode_fragment(1, 2, 1, 0, &address, payload, &mut frame);
            run.extend_from_slice(&frame);
            frames.push(frame);
        }
        let (before, before_counts) = ferrox_core::alloc_count::measure(|| {
            let mut packets = Vec::with_capacity(3);
            for frame in &frames {
                packets.push(frame.clone());
            }
            packets
        });
        assert_eq!(before_counts.allocs, 4, "a list and a copy per packet");
        let mut out = Vec::with_capacity(4);
        let (_, counts) = ferrox_core::alloc_count::measure(|| share_uni_packets(run, &mut out));
        assert_eq!(
            counts.allocs, 1,
            "the shared cell, not one buffer per packet"
        );
        assert!(counts.allocs < before_counts.allocs, "one cell for the run");
        let replied: Vec<Vec<u8>> = out.iter().map(|reply| reply.packet().to_vec()).collect();
        assert_eq!(replied, before, "the same packets ride the same frames");
    }

    /// A burst of PACKET frames reads one clock for the whole run: every association it delivers
    /// to is stamped from that single instant, and the next run takes its own.
    #[test]
    fn a_packet_run_stamps_its_associations_from_one_clock() {
        let sink = UdpSocket::bind("127.0.0.1:0").expect("a sink");
        sink.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a timeout");
        let port = sink.local_addr().expect("its address").port();
        let address = wire::address_port("127.0.0.1", port).expect("an address");
        let mut run = Vec::new();
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let mut frame = Vec::new();
            wire::encode_fragment(1, 2, 1, 0, &address, payload, &mut frame);
            run.extend_from_slice(&frame);
        }
        let (mut inner, _done) = empty_inner();
        assert_eq!(read_packets(&mut inner, &run), Some(run.len()));
        assert_eq!(
            inner.clocks, 1,
            "a run stamps every association from one instant"
        );
        let mut buf = [0u8; 16];
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let (n, _) = sink.recv_from(&mut buf).expect("the sink reads a packet");
            assert_eq!(&buf[..n], expected, "both packets reach the sink");
        }
        assert_eq!(read_packets(&mut inner, &run), Some(run.len()));
        assert_eq!(inner.clocks, 2, "a second run takes its own stamp");
    }

    /// A full reply queue waits for the forwarder instead of dropping a stream packet: a
    /// dropped one is a reliable byte the peer was promised.
    #[test]
    fn a_full_reply_queue_never_drops_a_stream_packet() {
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut run = Vec::new();
        for payload in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
            let mut frame = Vec::new();
            wire::encode_fragment(1, 2, 1, 0, &address, payload, &mut frame);
            run.extend_from_slice(&frame);
        }
        let mut out = Vec::new();
        let (rest, broken) = share_uni_packets(run, &mut out);
        assert!(!broken, "the run parses whole");
        assert!(rest.is_empty(), "and leaves no tail");
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        let sender = std::thread::spawn(move || hand_off(&mut out, &reply_tx));
        let mut seen = 0;
        while seen < 3 {
            let Ok(reply) = reply_rx.recv_timeout(std::time::Duration::from_secs(5)) else {
                break;
            };
            assert!(matches!(reply, Reply::Inside { .. }), "a stream packet");
            seen += 1;
        }
        assert_eq!(seen, 3, "a full queue never drops a stream packet");
        assert!(
            sender.join().expect("the forwarder's own thread"),
            "and the handoff completes"
        );
    }

    /// A read that ends mid-frame keeps the partial packet as the tail, and nothing else.
    #[test]
    fn a_uni_run_keeps_only_the_partial_tail() {
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut frame = Vec::new();
        wire::encode_fragment(1, 2, 1, 0, &address, b"whole", &mut frame);
        let mut run = frame.clone();
        run.extend_from_slice(&frame[..7]);
        let mut out = Vec::new();
        let (rest, broken) = share_uni_packets(run, &mut out);
        assert!(!broken, "a short tail is not a broken stream");
        assert_eq!(rest, frame[..7], "the partial packet waits for the rest");
        assert_eq!(out.len(), 1, "the whole one went out");

        // A read that ends inside its first frame keeps that read's own buffer.
        let mut short = frame.clone();
        short.truncate(7);
        let base = short.as_ptr();
        let capacity = short.capacity();
        let mut out = Vec::new();
        let ((kept, _), counts) =
            ferrox_core::alloc_count::measure(|| share_uni_packets(short, &mut out));
        assert_eq!(
            kept.as_ptr(),
            base,
            "the first-frame tail is the read's buffer"
        );
        assert_eq!(kept.capacity(), capacity, "and it did not grow");
        assert_eq!(counts.allocs, 0, "and keeping it allocates nothing");
        assert_eq!(kept.len(), 7);
    }

    #[test]
    fn a_full_packet_fits_one_command() {
        let name = "a".repeat(wire::MAX_ADDRESS);
        let address = wire::address_port(&name, 9).expect("an address");
        let payload = vec![7u8; MAX_PACKET_PAYLOAD];
        let mut frame = Vec::new();
        wire::encode_fragment(1, 2, 1, 0, &address, &payload, &mut frame);
        assert!(
            frame.len() <= MAX_UNI_COMMAND,
            "{} > {}",
            frame.len(),
            MAX_UNI_COMMAND
        );
        let packet = wire::parse_packet(&frame).expect("the frame parses");
        assert_eq!(packet.payload.len(), MAX_PACKET_PAYLOAD);
        assert_eq!(packet.destination.expect("a destination").1, 9);
    }

    #[test]
    fn the_first_packets_mode_survives_a_later_numeric_packet() {
        let (mut inner, _done) = empty_inner();
        assert!(
            select_assoc(&mut inner, 4, true).is_some(),
            "the first packet wins"
        );
        assert!(
            select_assoc(&mut inner, 4, false).is_some(),
            "the association stays"
        );
        let assoc = inner.udp.get(&4).expect("the association is recorded");
        assert!(assoc.stream, "a later packet does not restate the mode");
    }

    #[test]
    fn a_late_resolution_does_not_recreate_a_dissociated_association() {
        let (mut inner, done) = empty_inner();
        let generation = select_assoc(&mut inner, 7, false).expect("the association is recorded");
        let key = (7u16, "example.test".to_owned(), 53u16);
        inner.resolving.insert(
            key.clone(),
            Resolving {
                generation,
                payloads: vec![vec![1]],
            },
        );
        inner.udp.remove(&7);
        done.send(ResolveDone {
            association: 7,
            host: "example.test".to_owned(),
            port: 53,
            target: None,
            payload: vec![2],
            generation,
        })
        .expect("the channel is open");
        drain_resolved(&mut inner, Instant::now());
        assert!(!inner.resolving.contains_key(&key));
        assert!(
            inner.udp.is_empty(),
            "a stale result does not recreate the association"
        );
    }

    #[test]
    fn an_idle_association_drops_a_late_resolution() {
        let (mut inner, done) = empty_inner();
        let generation = select_assoc(&mut inner, 9, false).expect("the association is recorded");
        let key = (9u16, "example.test".to_owned(), 53u16);
        inner.resolving.insert(
            key.clone(),
            Resolving {
                generation,
                payloads: vec![vec![1]],
            },
        );
        expire_udp(
            &mut inner,
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(1),
        );
        assert!(inner.udp.is_empty(), "the idle association expires");
        assert!(
            inner.resolving.is_empty(),
            "its pending lookup expires with it"
        );
        done.send(ResolveDone {
            association: 9,
            host: "example.test".to_owned(),
            port: 53,
            target: None,
            payload: vec![2],
            generation,
        })
        .expect("the channel is open");
        drain_resolved(&mut inner, Instant::now());
        assert!(
            inner.udp.is_empty(),
            "an expired lookup does not recreate the association"
        );
    }

    #[test]
    fn every_expired_association_costs_one_pass_per_map() {
        let (mut inner, _done) = empty_inner();
        for association in 0..3u16 {
            select_assoc(&mut inner, association, false).expect("the association is recorded");
            inner.resolving.insert(
                (association, "example.test".to_owned(), 53),
                Resolving {
                    generation: 0,
                    payloads: Vec::new(),
                },
            );
        }
        expire_udp(
            &mut inner,
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(1),
        );
        assert!(inner.udp.is_empty(), "every idle association expires");
        assert!(inner.resolving.is_empty(), "with every lookup it held");
        assert_eq!(
            inner.expiry_passes, 2,
            "one walk of each map, however many associations expired"
        );
    }

    #[test]
    fn a_new_reno_name_is_quiches_reno() {
        assert_eq!(quiche_cc("new_reno"), "reno");
        assert_eq!(quiche_cc("reno"), "reno");
        assert_eq!(quiche_cc("cubic"), "cubic");
        assert_eq!(quiche_cc("bbr"), "bbr");
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","congestion_control":"new_reno"},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!(out.cc.as_deref(), Some("reno"));
        assert!(out.client_config().is_some());
    }

    #[test]
    fn a_single_fragment_packet_payload_is_not_copied() {
        let address = Some((wire::Address::V4([192, 0, 2, 1]), 53));
        let empty = Vec::new();
        let empty_packet = wire::Packet {
            association: 1,
            packet: 2,
            total: 1,
            index: 0,
            destination: address,
            payload: &empty,
        };
        let (_, base) =
            ferrox_core::alloc_count::measure(|| take_packet(&mut HashMap::new(), &empty_packet));
        let payload = vec![7u8; 32];
        let packet = wire::Packet {
            association: 1,
            packet: 3,
            total: 1,
            index: 0,
            destination: address,
            payload: &payload,
        };
        let source = payload.as_ptr();
        let (taken, counts) =
            ferrox_core::alloc_count::measure(|| take_packet(&mut HashMap::new(), &packet));
        let (destination, copied) = taken.expect("one packet");
        assert_eq!(
            destination,
            Destination::Address(SocketAddr::new(IpAddr::V4([192, 0, 2, 1].into()), 53))
        );
        assert_eq!(copied.as_ref(), payload);
        assert_eq!(copied.as_ptr(), source);
        assert_eq!(counts.allocs - base.allocs, 0);
        assert_eq!(counts.bytes - base.bytes, 0);
    }

    #[test]
    fn expired_reassemblies_do_not_hold_the_client_back() {
        let address = Some((wire::Address::V4([192, 0, 2, 1]), 53));
        let payload = vec![7u8; 32];
        let mut reassembly = HashMap::new();
        let stale = Instant::now()
            .checked_sub(REASSEMBLY_TTL + Duration::from_secs(1))
            .expect("the process has run for six seconds");
        for index in 0..MAX_REASSEMBLIES as u16 {
            reassembly.insert(
                (1, index),
                Parts {
                    total: 2,
                    address: None,
                    slots: vec![Some((0, 32)), None],
                    buffer: vec![0u8; 32],
                    received: 1,
                    at: stale,
                },
            );
        }
        let packet = wire::Packet {
            association: 1,
            packet: 700,
            total: 2,
            index: 0,
            destination: address,
            payload: &payload,
        };
        assert!(take_packet(&mut reassembly, &packet).is_none());
        assert_eq!(reassembly.len(), 1, "an expired piece made room");
        assert!(reassembly.contains_key(&(1, 700)));
    }

    /// The sweep a new fragmented packet pays is one walk: it drops the expired parts and counts the
    /// association's live ones in the same pass, so the per-association cap still binds.
    #[test]
    fn a_new_reassembly_sweeps_and_counts_in_one_pass() {
        let address = Some((wire::Address::V4([192, 0, 2, 1]), 53));
        let payload = vec![7u8; 32];
        let mut reassembly = HashMap::new();
        for index in 0..MAX_REASSEMBLIES_PER_ASSOC as u16 {
            reassembly.insert(
                (1, index),
                Parts {
                    total: 2,
                    address: None,
                    slots: vec![Some((0, 32)), None],
                    buffer: vec![0u8; 32],
                    received: 1,
                    at: Instant::now(),
                },
            );
        }
        let packet = wire::Packet {
            association: 1,
            packet: 700,
            total: 2,
            index: 0,
            destination: address,
            payload: &payload,
        };
        assert!(
            take_packet(&mut reassembly, &packet).is_none(),
            "the association's live cap still binds"
        );
        assert_eq!(
            reassembly.len(),
            MAX_REASSEMBLIES_PER_ASSOC,
            "nothing expired, so nothing was dropped"
        );
        let other = wire::Packet {
            association: 2,
            packet: 700,
            total: 2,
            index: 0,
            destination: address,
            payload: &payload,
        };
        assert!(take_packet(&mut reassembly, &other).is_none());
        assert!(
            reassembly.contains_key(&(2, 700)),
            "another association has room"
        );
    }

    #[test]
    fn an_ordered_reassembly_hands_over_the_fragments_own_buffer() {
        let mut buffer = Vec::with_capacity(64);
        buffer.extend_from_slice(&[1u8; 4]);
        let base = buffer.as_ptr();
        let mut reassembly = HashMap::new();
        reassembly.insert(
            (9, 1),
            Parts {
                total: 2,
                address: Some(Destination::Address(SocketAddr::new(
                    IpAddr::V4([192, 0, 2, 1].into()),
                    53,
                ))),
                slots: vec![Some((0, 4)), None],
                buffer,
                received: 1,
                at: Instant::now(),
            },
        );
        let second = [2u8; 4];
        let packet = wire::Packet {
            association: 9,
            packet: 1,
            total: 2,
            index: 1,
            destination: None,
            payload: &second,
        };
        let (taken, counts) =
            ferrox_core::alloc_count::measure(|| take_packet(&mut reassembly, &packet));
        let (_, payload) = taken.expect("both fragments");
        assert_eq!(&*payload, &[1, 1, 1, 1, 2, 2, 2, 2]);
        assert_eq!(counts.allocs, 0, "the fragment's room was already there");
        let Cow::Owned(buffer) = payload else {
            panic!("a reassembled datagram is owned");
        };
        assert_eq!(
            buffer.as_ptr(),
            base,
            "the fragments' buffer is the datagram"
        );
        assert_eq!(buffer.capacity(), 64, "the buffer held its room");
    }

    #[test]
    fn a_reassembly_in_arrival_order_is_put_back_in_packet_order() {
        let mut reassembly = HashMap::new();
        let address = Some((wire::Address::V4([192, 0, 2, 1]), 53));
        let high = [2u8; 4];
        let low = [1u8; 4];
        let second = wire::Packet {
            association: 3,
            packet: 5,
            total: 2,
            index: 1,
            destination: None,
            payload: &high,
        };
        assert!(take_packet(&mut reassembly, &second).is_none());
        let first = wire::Packet {
            association: 3,
            packet: 5,
            total: 2,
            index: 0,
            destination: address,
            payload: &low,
        };
        let (_, payload) = take_packet(&mut reassembly, &first).expect("both fragments");
        assert_eq!(&*payload, &[1, 1, 1, 1, 2, 2, 2, 2]);
    }

    #[test]
    fn a_pin_only_outbound_builds_its_tls() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret"},"streamSettings":{"security":"tls","tlsSettings":{"pinnedPeerCertSha256":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!(out.cert_pins.len(), 1);
        assert!(out.client_config().is_some());
    }

    #[test]
    fn a_tuic_udp_over_stream_is_refused_not_silently_mapped() {
        let base = r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret"%s},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#;
        let config =
            crate::json::parse(&base.replace("%s", r#","udp_over_stream":true"#)).expect("parses");
        assert!(outbound(&config).is_err());
    }

    #[test]
    fn a_tuic_mode_or_congestion_name_outside_the_reference_is_refused() {
        for (field, value) in [
            ("udp_relay_mode", "stream"),
            ("congestion_control", "vegas"),
        ] {
            let config = format!(
                r#"{{"outbounds":[{{"protocol":"tuic","settings":{{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","{field}":"{value}"}},"streamSettings":{{"security":"tls","tlsSettings":{{"allowInsecure":true}}}}}}]}}"#
            );
            let root = crate::json::parse(&config).expect("parses");
            assert!(outbound(&root).is_err(), "{field} accepted {value}");
        }
    }

    #[test]
    fn a_retry_token_binds_the_source_and_both_connection_ids() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"retry");
        let from: SocketAddr = "192.0.2.7:1234".parse().expect("an address");
        let odcid = [7u8; 8];
        let scid = [9u8; SCID_LEN];
        let token = retry_token(&key, from, &odcid, &scid);
        assert_eq!(
            retry_token_valid(&key, from, &token),
            Some((odcid.to_vec(), scid))
        );
        let elsewhere: SocketAddr = "192.0.2.8:1234".parse().expect("an address");
        assert_eq!(retry_token_valid(&key, elsewhere, &token), None);
        let mut tampered = token.clone();
        tampered[0] ^= 1;
        assert_eq!(retry_token_valid(&key, from, &tampered), None);
        let long = [3u8; quiche::MAX_CONN_ID_LEN];
        let token = retry_token(&key, from, &long, &scid);
        assert_eq!(
            retry_token_valid(&key, from, &token),
            Some((long.to_vec(), scid))
        );
    }

    #[test]
    fn an_expired_retry_token_is_refused() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"retry");
        let from: SocketAddr = "192.0.2.7:1234".parse().expect("an address");
        let token = retry_token(&key, from, &[7u8; 8], &[9u8; SCID_LEN]);
        let mut body = token[..token.len() - RETRY_TOKEN_TAG].to_vec();
        let old = unix_now().saturating_sub(RETRY_TOKEN_TTL.as_secs() + 1);
        body[1..9].copy_from_slice(&old.to_le_bytes());
        let tag = ring::hmac::sign(&key, &body);
        body.extend_from_slice(tag.as_ref());
        assert_eq!(retry_token_valid(&key, from, &body), None);
    }

    #[test]
    fn a_delivered_reply_refreshes_the_sink_activity() {
        let client = UdpSocket::bind("127.0.0.1:0").expect("a client");
        let sink = UdpSink {
            association: 1,
            reply: UdpSocket::bind("127.0.0.1:0").expect("a sink"),
            source: OnceLock::new(),
            born: Instant::now()
                .checked_sub(UDP_IDLE + Duration::from_secs(1))
                .expect("an instant"),
            last: AtomicU64::new(0),
        };
        sink.source
            .set(client.local_addr().expect("an address"))
            .expect("the source is pinned once");
        assert!(idle(&sink), "an idle stamp this old is stale");
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut frame = Vec::new();
        wire::encode_fragment(1, 2, 1, 0, &address, b"hello", &mut frame);
        let packet = wire::parse_packet(&frame).expect("a packet");
        let mut head = Vec::new();
        client_reply(&packet, &mut HashMap::new(), &sink, &mut head);
        let mut buf = [0u8; 64];
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a timeout");
        let (n, _) = client.recv_from(&mut buf).expect("the reply arrives");
        assert!(n > 5);
        assert!(!idle(&sink), "the reply refreshed the stamp");
    }
}
