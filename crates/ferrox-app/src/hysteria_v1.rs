//! Hysteria v1 over quiche: the binary control stream, the `host:port` request on each flow, and the datagram lane whose messages carry their own session and address.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::hysteria_v1 as wire;
use ferrox_core::hysteria_v1::{Defrag, UdpMessage, XPlus};

use crate::conn::Connection;
use crate::hysteria::{Dial, Driver, Flow, Session, StreamWake};
use crate::quic::{Mask, Unfilled, MAX_DATAGRAM, RECV_ROOM};

const FIRST_FLOW_STREAM: u64 = 4;

const SCID_LEN: usize = 16;

const STREAM_POLL: Duration = Duration::from_millis(5);

const ROUTE_POLL: Duration = Duration::from_millis(100);

const HEAD_CAP: usize = 16 * 1024;

const UDP_POLL: Duration = Duration::from_secs(1);

const UDP_TARGET_BUF: usize = wire::MAX_UDP_PAYLOAD;

const UDP_RESOLVE_BUDGET: Duration = Duration::from_secs(5);

const MAX_PENDING_DATAGRAMS: usize = 64;

const MAX_UDP_ASSOCIATIONS: usize = 256;

const MAX_PENDING_RESOLVERS: usize = 32;

/// A TCP flow after the server has acknowledged its request: the callback dials the target and writes the response.
pub(crate) type Serve = Arc<dyn Fn(Flow, String, u16) + Send + Sync>;

fn send_all(session: &Session, stream: u64, buf: &[u8]) -> bool {
    crate::hysteria::send_all(session, stream, buf, false)
}

fn read_until(session: &Session, stream: u64, want: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let mut head = Vec::with_capacity(64);
    let mut room = Unfilled::<4096>::new();
    loop {
        if want(&head) {
            return Some(head);
        }
        if head.len() >= HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, _)) => return None,
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        match read {
            Some(n) => head.extend_from_slice(&room.as_mut()[..n]),
            None => {
                if !crate::hysteria::drive_once(session, STREAM_POLL) {
                    return None;
                }
            }
        }
    }
}

fn client_config(dial: &Dial, roots: &[Vec<u8>]) -> Option<quiche::Config> {
    if dial.config.insecure {
        crate::quic::quiche_config_insecure_alpn(None, &[wire::ALPN])
    } else {
        crate::quic::quiche_config_alpn(roots, None, &[wire::ALPN])
    }
}

fn connect(dial: &Dial) -> Option<Session> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = crate::quic::udp_to_server(&dial.address, dial.port)?;
    let cid = crate::quic::hysteria_client_cid(dial.config.quic.as_ref())?;
    let mut config = client_config(dial, roots)?;
    crate::quic::apply_lane_congestion(
        &mut config,
        Some(dial.config.cc),
        dial.config.quic.as_ref(),
    )?;
    if let Some(params) = &dial.config.quic {
        crate::quic::apply_hysteria_quic(&mut config, params, false);
    }
    config.enable_dgram(true, 1024, 1024);
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    let xplus = XPlus::new(&dial.config.obfs_password);
    let sock = match dial
        .config
        .hop
        .as_ref()
        .filter(|hop| !hop.ranges.is_empty())
    {
        Some(hop) => {
            let bind = if peer.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            crate::quic::Datagram::hopped(
                peer,
                hop.ports(),
                hop.interval_ms,
                bind,
                &sock,
                xplus.map(Mask::XPlus),
            )
            .ok()?
        }
        None => match xplus {
            Some(xplus) => crate::quic::Datagram::xplus(sock, xplus),
            None => crate::quic::Datagram::plain(sock),
        },
    };
    let net = crate::quic::network_generation();
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let keep_alive = dial
        .config
        .quic
        .as_ref()
        .map(|params| params.keep_alive)
        .filter(|seconds| *seconds != 0)
        .map(Duration::from_secs);
    let session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
        local_now: Arc::new(Mutex::new(local)),
        peer: Some(peer),
        net: Arc::new(std::sync::atomic::AtomicU64::new(net)),
        migrated: Arc::default(),
        udp_supported: true,
        driver: None,
        send_wake: None,
        keep_alive,
    };
    let mut hello = Vec::with_capacity(20 + dial.config.auth.len());
    wire::encode_client_hello(
        &wire::ClientHello {
            send_bps: 100_000_000,
            recv_bps: 100_000_000,
            auth: dial.config.auth.as_bytes(),
        },
        &mut hello,
    );
    if !send_all(&session, 0, &hello) {
        return None;
    }
    let reply = read_until(&session, 0, |head| wire::decode_server_hello(head).is_ok())?;
    let (server, _) = wire::decode_server_hello(&reply).ok()?;
    if !server.ok || server.recv_bps == 0 {
        return None;
    }
    Some(session)
}

fn read_response(flow: &mut Flow) -> Option<bool> {
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let mut head = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        if let Ok((response, used)) = wire::decode_server_response(&head) {
            flow.backlog = head[used..].to_vec();
            flow.at = 0;
            return Some(response.ok);
        }
        if head.len() > HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        match flow.read_step(&mut buf) {
            Ok(Some(0)) | Err(_) => return None,
            Ok(Some(n)) => head.extend_from_slice(&buf[..n]),
            Ok(None) => {}
        }
    }
}

fn open_flow(session: &Session, stream: u64, host: &str, port: u16) -> Option<Flow> {
    let mut request = Vec::with_capacity(8 + host.len());
    wire::encode_client_request(
        &wire::ClientRequest {
            udp: false,
            host,
            port,
        },
        &[],
        &mut request,
    );
    let (drive, wake) = match session.driver.as_ref() {
        Some(driver) if driver.running() => (false, Some(driver.register(stream))),
        _ => (true, None),
    };
    let mut flow = Flow::from_parts(
        Arc::clone(&session.shared),
        Arc::clone(&session.sock),
        session.local,
        stream,
        Vec::new(),
        drive,
        false,
    )
    .with_wake(wake)
    .with_session(session);
    if !send_all(session, stream, &request) {
        return None;
    }
    if !read_response(&mut flow)? {
        return None;
    }
    Some(flow)
}

struct Pooled {
    session: Session,
    next_stream: u64,
    used: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Server {
    host: String,
    address: String,
    port: u16,
    cc: &'static str,
    auth: String,
    obfs: String,
    hop: Option<ferrox_core::hysteria::Hop>,
    /// A tuned QUIC lane is its own connection: its windows, controller profile and Brutal rates were negotiated, so a dial with another block may not ride it.
    quic: Option<ferrox_core::hysteria::QuicParams>,
    roots: Option<ferrox_core::tls::Anchors>,
    /// A verifying dial may not ride a lane whose peer was accepted without the chain check.
    insecure: bool,
}

const REUSE_WINDOW: Duration = Duration::from_millis(crate::quic::IDLE_TIMEOUT_MS / 2);

static POOL: std::sync::OnceLock<Mutex<HashMap<Server, Vec<Pooled>>>> = std::sync::OnceLock::new();

fn pool() -> &'static Mutex<HashMap<Server, Vec<Pooled>>> {
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn server_of(dial: &Dial) -> Server {
    Server {
        host: dial.host.clone(),
        address: dial.address.clone(),
        port: dial.port,
        cc: dial.config.cc.quiche_name(),
        auth: dial.config.auth.clone(),
        obfs: dial.config.obfs_password.clone(),
        hop: dial.config.hop.clone(),
        quic: dial.config.quic,
        roots: dial.roots.clone(),
        insecure: dial.config.insecure,
    }
}

fn usable(conn: &quiche::Connection) -> bool {
    !conn.is_closed()
        && !conn.is_draining()
        && conn.local_error().is_none()
        && conn.peer_error().is_none()
}

fn candidates(dial: &Dial) -> Vec<(Session, u64)> {
    let Ok(mut pool) = pool().lock() else {
        return Vec::new();
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return Vec::new();
    };
    let now = Instant::now();
    entries.retain(|entry| {
        entry.next_stream / 4 < crate::quic::MAX_STREAMS
            && now.saturating_duration_since(entry.used) < REUSE_WINDOW
            && entry.session.shared.lock().is_ok_and(|conn| usable(&conn))
    });
    entries
        .iter_mut()
        .map(|entry| {
            let stream = entry.next_stream;
            entry.next_stream += 4;
            entry.used = now;
            (entry.session.clone(), stream)
        })
        .collect()
}

fn evict(dial: &Dial, session: &Session) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return;
    };
    entries.retain(|entry| !Arc::ptr_eq(&entry.session.shared, &session.shared));
}

fn keep(dial: &Dial, session: Session, next_stream: u64) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    pool.entry(server_of(dial)).or_default().push(Pooled {
        session,
        next_stream,
        used: Instant::now(),
    });
}

fn open_pooled(dial: &Dial, host: &str, port: u16) -> Option<Flow> {
    for (session, stream) in candidates(dial) {
        if let Some(flow) = open_flow(&session, stream, host, port) {
            return Some(flow);
        }
        if session.shared.lock().is_ok_and(|conn| !usable(&conn)) {
            evict(dial, &session);
        }
    }
    let mut session = connect(dial)?;
    let driver = Driver::new();
    driver.attach(&mut session);
    let Some(flow) = open_flow(&session, FIRST_FLOW_STREAM, host, port) else {
        driver.stop();
        return None;
    };
    keep(dial, session, FIRST_FLOW_STREAM + 4);
    Some(flow)
}

/// Dial one TCP flow through the v1 protocol: the request names the target, the server acknowledges, then bytes relay.
pub(crate) fn dial(client: &Connection, dial: &Dial, target: &crate::proxy::Destination) {
    let (host, port) = match target {
        crate::proxy::Destination::Name(host, port) => (host.clone(), *port),
        crate::proxy::Destination::Address(address) => (address.ip().to_string(), address.port()),
    };
    let Some(flow) = open_pooled(dial, &host, port) else {
        return;
    };
    crate::hysteria::relay(client, &flow);
}

/// One UDP association's live session: the id its datagrams carry, the destination the last socks packet named, and the peer that asked.
struct Lane {
    session: Mutex<Option<u32>>,
    defrag: Mutex<Defrag>,
    source: Mutex<Option<SocketAddr>>,
    client: Mutex<Option<SocketAddr>>,
}

/// The client's UDP uplink over Hysteria v1: one connection and one datagram session per association, with a companion reader driving replies back into the socks frame.
#[allow(clippy::too_many_lines)]
pub(crate) fn serve_udp(relay: &UdpSocket, dial: &Dial, peer: Option<std::net::IpAddr>) {
    let Some(session) = connect(dial) else {
        return;
    };
    let Ok(reply) = relay.try_clone() else {
        return;
    };
    let lane = Arc::new(Lane {
        session: Mutex::new(None),
        defrag: Mutex::new(Defrag::new()),
        source: Mutex::new(None),
        client: Mutex::new(None),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let reader = std::thread::spawn({
        let session = session.clone();
        let lane = Arc::clone(&lane);
        let stop = Arc::clone(&stop);
        move || client_reader(&session, &lane, &stop, &reply)
    });
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    let mut wire = Vec::with_capacity(UDP_TARGET_BUF + 64);
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    let mut host_room = [0u8; HOST_ROOM];
    let mut stream: Option<Flow> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        if !crate::proxy::source_ip_ok(peer, src) {
            continue;
        }
        let pinned = lane.client.lock().ok().and_then(|slot| *slot);
        if pinned.is_some_and(|held| held != src) {
            continue;
        }
        let Some((dest, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
            continue;
        };
        let Ok(mut client) = lane.client.lock() else {
            break;
        };
        match *client {
            None => *client = Some(src),
            Some(peer) if peer != src => continue,
            Some(_) => {}
        }
        drop(client);
        let Some(host) = host_of(dest.ip(), &mut host_room) else {
            continue;
        };
        if stream.is_none() {
            let Some((flow, session_id)) = open_udp_flow(&session, host, dest.port()) else {
                break;
            };
            stream = Some(flow);
            if let Ok(mut slot) = lane.session.lock() {
                *slot = Some(session_id);
            }
            if let Ok(mut reassembly) = lane.defrag.lock() {
                *reassembly = Defrag::new();
            }
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        if let Ok(mut slot) = lane.source.lock() {
            *slot = Some(src);
        }
        let Ok(held) = lane.session.lock() else {
            break;
        };
        let Some(session_id) = *held else {
            continue;
        };
        drop(held);
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session: session_id,
            host,
            port: dest.port(),
            packet,
            frag: 0,
            frags: 1,
            payload,
        };
        let Ok(fragments) = wire::fragments_udp(&message, max) else {
            continue;
        };
        for frag in fragments {
            wire.clear();
            wire::encode_udp_unchecked(&frag, &mut wire);
            let _ = conn.dgram_send(&wire);
        }
        flush(&session.sock, &mut conn, out.as_mut());
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
    if let Some(mut stream) = stream {
        let _ = stream.write_all(&[]);
        stream.close();
    }
}

fn open_udp_flow(session: &Session, host: &str, port: u16) -> Option<(Flow, u32)> {
    let mut request = Vec::with_capacity(5 + host.len());
    wire::encode_client_request(
        &wire::ClientRequest {
            udp: true,
            host,
            port,
        },
        &[],
        &mut request,
    );
    if !send_all(session, FIRST_FLOW_STREAM, &request) {
        return None;
    }
    let head = read_until(session, FIRST_FLOW_STREAM, |head| {
        wire::decode_server_response(head).is_ok()
    })?;
    let (response, used) = wire::decode_server_response(&head).ok()?;
    if !response.ok {
        return None;
    }
    let session_id = response.udp_session_id;
    Some((
        Flow::from_parts(
            Arc::clone(&session.shared),
            Arc::clone(&session.sock),
            session.local,
            FIRST_FLOW_STREAM,
            head.get(used..).unwrap_or_default().to_vec(),
            true,
            false,
        )
        .with_session(session),
        session_id,
    ))
}

fn client_reader(session: &Session, lane: &Lane, stop: &AtomicBool, relay: &UdpSocket) {
    let mut reply = Vec::with_capacity(3 + 25 + UDP_TARGET_BUF);
    loop {
        if stop.load(Ordering::Relaxed) || !crate::hysteria::drive_once(session, UDP_POLL) {
            break;
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        while let Ok(data) = conn.dgram_recv_buf() {
            let Ok(message) = wire::decode_udp(&data) else {
                continue;
            };
            let Ok(held) = lane.session.lock() else {
                break;
            };
            let Some(session_id) = *held else {
                continue;
            };
            drop(held);
            if message.session != session_id {
                continue;
            }
            let Ok(ip) = message.host.parse::<std::net::IpAddr>() else {
                continue;
            };
            let destination = SocketAddr::new(ip, message.port);
            let mut assembled = Vec::new();
            let Some(payload) = lane.defrag.lock().ok().and_then(|mut reassembly| {
                reassembly
                    .feed(&message, &mut assembled)
                    .ok()
                    .flatten()
                    .map(|message| message.payload)
            }) else {
                continue;
            };
            let Some(src) = lane.source.lock().ok().and_then(|slot| *slot) else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            crate::proxy::push_socks_addr(&mut reply, &destination);
            reply.extend_from_slice(payload);
            let _ = relay.send_to(&reply, src);
        }
    }
}

fn flush(sock: &crate::quic::Datagram, conn: &mut quiche::Connection, out: &mut [u8]) {
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

fn server_config(
    identity: &ferrox_core::tls::TlsServerConfig,
    cc: ferrox_core::hysteria::Congestion,
    quic: Option<&ferrox_core::hysteria::QuicParams>,
) -> Option<quiche::Config> {
    let mut config = crate::quic::tls_config(identity)?;
    config.set_application_protos(&[wire::ALPN]).ok()?;
    crate::quic::apply_lane_congestion(&mut config, Some(cc), quic)?;
    config.enable_dgram(true, 1024, 1024);
    config.set_max_idle_timeout(30_000);
    config.set_initial_max_data(20 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(8 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(8 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(8 * 1024 * 1024);
    config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
    config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
    if let Some(params) = quic {
        crate::quic::apply_hysteria_quic(&mut config, params, true);
    }
    Some(config)
}

/// One destination an association carries: the peer it resolved to, the reassembly in flight, the
/// datagrams that arrived before the name resolved, and the stamp eviction reads.
struct Assoc {
    host: String,
    port: u16,
    dest: Option<SocketAddr>,
    defrag: Defrag,
    waiting: Vec<Vec<u8>>,
    resolving: bool,
    used: u64,
}

impl Assoc {
    fn new(host: &str, port: u16, used: u64) -> Self {
        Self {
            host: host.to_owned(),
            port,
            dest: None,
            defrag: Defrag::new(),
            waiting: Vec::new(),
            resolving: false,
            used,
        }
    }

    fn is(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host == host
    }
}

/// Every destination one flow carries, scanned in place so a datagram on a known destination
/// neither builds a key nor inserts one. `waiting` counts the queued payloads across all of them.
#[derive(Default)]
struct Assocs {
    list: Vec<Assoc>,
    waiting: usize,
}

impl Assocs {
    fn find(&self, host: &str, port: u16) -> Option<usize> {
        self.list.iter().position(|assoc| assoc.is(host, port))
    }

    fn insert(&mut self, host: &str, port: u16, used: u64) -> Option<usize> {
        if self.list.len() >= MAX_UDP_ASSOCIATIONS {
            return None;
        }
        self.list.push(Assoc::new(host, port, used));
        Some(self.list.len() - 1)
    }

    fn enqueue(&mut self, at: usize, payload: Vec<u8>) {
        self.list[at].waiting.push(payload);
        self.waiting += 1;
    }

    fn drain(&mut self, at: usize) -> Vec<Vec<u8>> {
        let drained = std::mem::take(&mut self.list[at].waiting);
        self.waiting = self.waiting.saturating_sub(drained.len());
        drained
    }

    fn evict(&mut self, at: usize) {
        let assoc = self.list.swap_remove(at);
        self.waiting = self.waiting.saturating_sub(assoc.waiting.len());
    }

    fn start_waiting(&mut self, room: usize) -> Vec<(String, u16)> {
        let mut keys = Vec::new();
        for assoc in &mut self.list {
            if keys.len() >= room {
                break;
            }
            if assoc.resolving || assoc.waiting.is_empty() {
                continue;
            }
            assoc.resolving = true;
            keys.push((assoc.host.clone(), assoc.port));
        }
        keys
    }
}

/// One clock read per datagram is both the idle stamp and the eviction order.
static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn now_nanos() -> u64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

struct UdpFlow {
    target: Arc<UdpSocket>,
    assocs: Assocs,
    last: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

struct PendingUdp {
    token: u64,
    assocs: Assocs,
}

impl UdpFlow {
    /// The destination this datagram names, stamped and made room for when it is new: `None` when
    /// every association is resolving or holding datagrams and the cap refuses one more.
    fn slot(&mut self, host: &str, port: u16, now: u64) -> Option<usize> {
        if let Some(at) = self.assocs.find(host, port) {
            self.assocs.list[at].used = now;
            return Some(at);
        }
        while self.assocs.list.len() >= MAX_UDP_ASSOCIATIONS {
            let mut victim = None;
            let mut oldest = now;
            for (at, assoc) in self.assocs.list.iter().enumerate() {
                if assoc.resolving || !assoc.waiting.is_empty() {
                    continue;
                }
                if assoc.used <= oldest {
                    oldest = assoc.used;
                    victim = Some(at);
                }
            }
            let Some(at) = victim else {
                break;
            };
            self.assocs.evict(at);
        }
        self.assocs.insert(host, port, now)
    }
}

impl UdpLane {
    fn start_waiting(&mut self, room: usize) -> Vec<(u32, String, u16)> {
        let mut spawn = Vec::new();
        for (session, flow) in &mut self.flows {
            if spawn.len() >= room {
                break;
            }
            for (host, port) in flow.assocs.start_waiting(room - spawn.len()) {
                spawn.push((*session, host, port));
            }
        }
        spawn
    }
}

#[derive(Default)]
struct UdpLane {
    sessions: HashSet<u32>,
    flows: HashMap<u32, UdpFlow>,
    pending: HashMap<u32, PendingUdp>,
    next_token: u64,
    resolving: usize,
}

struct Resolving {
    lane: Arc<Mutex<UdpLane>>,
    released: bool,
}

impl Resolving {
    fn new(lane: Arc<Mutex<UdpLane>>) -> Self {
        Self {
            lane,
            released: false,
        }
    }

    /// Release this resolver's slot once; the guard's drop then has nothing left to give back.
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            if let Ok(mut lane) = self.lane.lock() {
                lane.resolving = lane.resolving.saturating_sub(1);
            }
        }
    }

    /// The same release while the caller already holds the lane lock.
    fn release_in(&mut self, lane: &mut UdpLane) {
        if !self.released {
            self.released = true;
            lane.resolving = lane.resolving.saturating_sub(1);
        }
    }
}

impl Drop for Resolving {
    fn drop(&mut self) {
        self.release();
    }
}

struct Inbound {
    conn: Arc<Mutex<quiche::Connection>>,
    authed: bool,
    auth_buf: Vec<u8>,
    served: HashSet<u64>,
    wakes: HashMap<u64, Arc<StreamWake>>,
    send: Arc<StreamWake>,
    udp: Arc<Mutex<UdpLane>>,
    next_udp: u32,
    client_cid: Vec<u8>,
    initial_dcid: Vec<u8>,
}

fn answer_hello(
    conn: &mut quiche::Connection,
    hello: &wire::ClientHello<'_>,
    auths: &[String],
) -> bool {
    let ok = auths.iter().any(|auth| auth.as_bytes() == hello.auth);
    let mut reply = Vec::with_capacity(20);
    wire::encode_server_hello(
        &wire::ServerHello {
            ok,
            send_bps: hello.recv_bps,
            recv_bps: hello.send_bps,
            message: if ok { b"" } else { b"auth error" },
        },
        &mut reply,
    );
    conn.stream_send(0, &reply, true).is_ok() && ok
}

fn read_request(flow: &mut Flow, deadline: Instant) -> Option<(bool, String, u16)> {
    let prefix = flow.at;
    let mut head = std::mem::take(&mut flow.backlog);
    let mut room = Unfilled::<4096>::new();
    loop {
        match wire::decode_client_request(head.get(prefix..)?) {
            Ok((request, used)) => {
                let request = (request.udp, request.host.to_owned(), request.port);
                flow.backlog = head;
                flow.at = prefix + used;
                return Some(request);
            }
            Err(ferrox_core::hysteria::RequestError::Invalid) => return None,
            Err(ferrox_core::hysteria::RequestError::Incomplete) => {
                if head.len().saturating_sub(prefix) >= HEAD_CAP || Instant::now() >= deadline {
                    return None;
                }
                match flow.read_step(room.as_mut()) {
                    Ok(Some(0)) | Err(_) => return None,
                    Ok(Some(n)) => {
                        head.extend_from_slice(&room.as_mut()[..n]);
                    }
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

fn open_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    session: u32,
    peer: SocketAddr,
) -> Option<UdpFlow> {
    let target = bind_target(peer)?;
    target.set_read_timeout(Some(UDP_POLL)).ok()?;
    let target = Arc::new(target);
    let stop = Arc::new(AtomicBool::new(false));
    let last = Arc::new(AtomicU64::new(now_nanos()));
    std::thread::spawn({
        let shared = Arc::clone(shared);
        let sock = Arc::clone(sock);
        let target = Arc::clone(&target);
        let last = Arc::clone(&last);
        let stop = Arc::clone(&stop);
        move || udp_reader(&shared, &sock, &target, &last, &stop, session)
    });
    Some(UdpFlow {
        target,
        assocs: Assocs::default(),
        last,
        stop,
    })
}

/// A socket that reaches both families, so one association may carry IPv4 and IPv6 destinations.
fn bind_target(peer: SocketAddr) -> Option<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let dual = (|| {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        socket.set_only_v6(false).ok()?;
        let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        socket.bind(&address.into()).ok()?;
        Some(UdpSocket::from(socket))
    })();
    dual.or_else(|| {
        UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .ok()
    })
}

/// The longest text an IP address takes: a mixed IPv6 is 45 bytes.
const HOST_ROOM: usize = 46;

/// The address as the wire spells it, formatted into the caller's room so a datagram's host
/// costs no heap.
fn host_of(ip: IpAddr, room: &mut [u8; HOST_ROOM]) -> Option<&str> {
    let mut cursor = &mut room[..];
    write!(cursor, "{ip}").ok()?;
    let len = HOST_ROOM - cursor.len();
    std::str::from_utf8(&room[..len]).ok()
}

fn target_addr(sock: &UdpSocket, peer: SocketAddr) -> SocketAddr {
    if sock.local_addr().is_ok_and(|local| local.is_ipv6()) {
        if let SocketAddr::V4(v4) = peer {
            return SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port());
        }
    }
    peer
}

fn udp_reader(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    target: &Arc<UdpSocket>,
    last: &Arc<AtomicU64>,
    stop: &AtomicBool,
    session: u32,
) {
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    let mut wire = Vec::new();
    let mut out = Unfilled::<MAX_DATAGRAM>::new();
    let mut packet = 0u16;
    let mut host_room = [0u8; HOST_ROOM];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let (n, from) = match target.recv_from(&mut buf) {
            Ok(found) => found,
            Err(ref error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                let closed = shared.lock().map_or(true, |conn| conn.is_closed());
                if closed || stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        last.store(now_nanos(), Ordering::Relaxed);
        let Ok(mut conn) = shared.lock() else {
            break;
        };
        if stop.load(Ordering::Relaxed) || conn.is_closed() {
            break;
        }
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        packet = packet.wrapping_add(1);
        let Some(host) = host_of(from.ip(), &mut host_room) else {
            continue;
        };
        let message = UdpMessage {
            session,
            host,
            port: from.port(),
            packet,
            frag: 0,
            frags: 1,
            payload: &buf[..n],
        };
        let Ok(fragments) = wire::fragments_udp(&message, max) else {
            break;
        };
        for frag in fragments {
            wire.clear();
            wire::encode_udp_unchecked(&frag, &mut wire);
            let _ = conn.dgram_send(&wire);
        }
        flush(sock, &mut conn, out.as_mut());
    }
}

fn serve_udp_stream(mut flow: Flow, next_udp: u32, lane: &Arc<Mutex<UdpLane>>) {
    let mut response = Vec::with_capacity(8);
    wire::encode_server_response(
        &wire::ServerResponse {
            ok: true,
            udp_session_id: next_udp,
            message: b"",
        },
        &mut response,
    );
    if let Ok(mut lane) = lane.lock() {
        lane.sessions.insert(next_udp);
    } else {
        return;
    }
    if flow.write_all(&response).is_err() {
        if let Ok(mut lane) = lane.lock() {
            lane.sessions.remove(&next_udp);
        }
        return;
    }
    // The stream is the session's lifetime: the server holds it until the client closes it.
    let mut room = [0u8; 1024];
    loop {
        match flow.read(&mut room) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if let Ok(mut lane) = lane.lock() {
        lane.sessions.remove(&next_udp);
        lane.pending.remove(&next_udp);
        if let Some(flow) = lane.flows.remove(&next_udp) {
            flow.stop.store(true, Ordering::Relaxed);
        }
    }
    flow.close();
}

#[allow(clippy::too_many_lines)]
fn relay_datagrams(
    routes: &mut HashMap<Vec<u8>, Inbound>,
    sock: &Arc<crate::quic::Datagram>,
    shared: &Arc<Mutex<quiche::Connection>>,
    dcid: &[u8],
    conn: &mut quiche::Connection,
) {
    while let Ok(data) = conn.dgram_recv_buf() {
        let Ok(message) = wire::decode_udp(&data) else {
            continue;
        };
        let Some(inbound) = routes.get(dcid) else {
            return;
        };
        if !inbound.authed {
            continue;
        }
        let lane_handle = Arc::clone(&inbound.udp);
        let Ok(mut lane) = lane_handle.lock() else {
            return;
        };
        let session = message.session;
        if !lane.sessions.contains(&session) {
            let _ = conn.close(false, 0, b"");
            return;
        }
        let host = message.host;
        let port = message.port;
        let now = now_nanos();
        if lane.flows.contains_key(&session) {
            let literal = host
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port));
            let room = MAX_PENDING_RESOLVERS.saturating_sub(lane.resolving);
            let mut assembled = Vec::new();
            let forged;
            let mut spawn = Vec::new();
            {
                let Some(flow) = lane.flows.get_mut(&session) else {
                    continue;
                };
                flow.last.store(now, Ordering::Relaxed);
                let Some(at) = flow.slot(host, port, now) else {
                    continue;
                };
                let whole = flow.assocs.list[at].defrag.feed(&message, &mut assembled);
                forged = whole.is_err();
                match whole {
                    Ok(Some(message)) => {
                        let assoc = &mut flow.assocs.list[at];
                        let peer = assoc.dest.or(literal);
                        if let Some(peer) = peer {
                            assoc.dest = Some(peer);
                            drop(flow.assocs.drain(at));
                            let _ = flow
                                .target
                                .send_to(message.payload, target_addr(&flow.target, peer));
                        } else if flow.assocs.waiting < MAX_PENDING_DATAGRAMS {
                            flow.assocs.enqueue(at, message.payload.to_vec());
                        }
                    }
                    Ok(None) => {}
                    Err(_) => flow.stop.store(true, Ordering::Relaxed),
                }
            }
            if forged {
                lane.flows.remove(&session);
            } else {
                spawn = lane.start_waiting(room);
            }
            lane.resolving += spawn.len();
            for (session, host, port) in spawn {
                std::thread::spawn({
                    let lane = Arc::clone(&lane_handle);
                    move || resolve_dest(lane, session, host, port)
                });
            }
            continue;
        }
        let UdpLane {
            flows,
            pending,
            next_token,
            resolving,
            ..
        } = &mut *lane;
        let at_cap = flows.len() + pending.len() >= MAX_UDP_ASSOCIATIONS;
        let can_spawn = *resolving < MAX_PENDING_RESOLVERS;
        let token = *next_token;
        let pending = match pending.entry(session) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => {
                if at_cap || !can_spawn {
                    continue;
                }
                *next_token = next_token.wrapping_add(1);
                *resolving += 1;
                let mut assocs = Assocs::default();
                let _ = assocs.insert(host, port, 0);
                let inserted = vacant.insert(PendingUdp { token, assocs });
                let owned = host.to_owned();
                std::thread::spawn({
                    let lane = Arc::clone(&lane_handle);
                    let shared = Arc::clone(shared);
                    let sock = Arc::clone(sock);
                    move || resolve_pending(lane, shared, sock, session, owned, port, token)
                });
                inserted
            }
        };
        let Some(at) = pending
            .assocs
            .find(host, port)
            .or_else(|| pending.assocs.insert(host, port, 0))
        else {
            continue;
        };
        let mut assembled = Vec::new();
        let whole = pending.assocs.list[at]
            .defrag
            .feed(&message, &mut assembled);
        match whole {
            Ok(Some(message)) if pending.assocs.waiting < MAX_PENDING_DATAGRAMS => {
                pending.assocs.enqueue(at, message.payload.to_vec());
            }
            Ok(_) => {}
            Err(_) => {
                lane.pending.remove(&session);
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn resolve_pending(
    lane: Arc<Mutex<UdpLane>>,
    shared: Arc<Mutex<quiche::Connection>>,
    sock: Arc<crate::quic::Datagram>,
    session: u32,
    host: String,
    port: u16,
    token: u64,
) {
    let mut resolving = Resolving::new(Arc::clone(&lane));
    let peer = crate::proxy::resolve_bounded(&host, port, UDP_RESOLVE_BUDGET, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(std::iter::Iterator::collect)
    })
    .and_then(|addrs| addrs.into_iter().next());
    let Some(peer) = peer else {
        if let Ok(mut lane) = lane.lock() {
            if lane.pending.get(&session).is_some_and(|p| p.token == token) {
                lane.pending.remove(&session);
            }
        }
        resolving.release();
        resume_lane(&lane);
        return;
    };
    let Some(mut flow) = open_udp(&shared, &sock, session, peer) else {
        if let Ok(mut lane) = lane.lock() {
            if lane.pending.get(&session).is_some_and(|p| p.token == token) {
                lane.pending.remove(&session);
            }
        }
        resolving.release();
        resume_lane(&lane);
        return;
    };
    let Ok(mut guard) = lane.lock() else {
        flow.stop.store(true, Ordering::Relaxed);
        return;
    };
    if guard.pending.get(&session).is_none_or(|p| p.token != token)
        || !guard.sessions.contains(&session)
    {
        flow.stop.store(true, Ordering::Relaxed);
        drop(guard);
        resolving.release();
        resume_lane(&lane);
        return;
    }
    let Some(pending) = guard.pending.remove(&session) else {
        flow.stop.store(true, Ordering::Relaxed);
        drop(guard);
        resolving.release();
        resume_lane(&lane);
        return;
    };
    flow.assocs = pending.assocs;
    let now = now_nanos();
    for assoc in &mut flow.assocs.list {
        assoc.used = now;
    }
    if !flow.assocs.list.is_empty() {
        flow.assocs.list[0].dest = Some(peer);
        for payload in flow.assocs.drain(0) {
            let _ = flow
                .target
                .send_to(&payload, target_addr(&flow.target, peer));
        }
    }
    guard.flows.insert(session, flow);
    resolving.release_in(&mut guard);
    let room = MAX_PENDING_RESOLVERS.saturating_sub(guard.resolving);
    let spawns = guard.start_waiting(room);
    guard.resolving += spawns.len();
    drop(guard);
    for (session, host, port) in spawns {
        std::thread::spawn({
            let lane = Arc::clone(&lane);
            move || resolve_dest(lane, session, host, port)
        });
    }
}

/// A resolver that ends without installing its flow still releases a slot: start the queued work that slot can now carry.
fn resume_lane(lane: &Arc<Mutex<UdpLane>>) {
    let Ok(mut guard) = lane.lock() else {
        return;
    };
    let room = MAX_PENDING_RESOLVERS.saturating_sub(guard.resolving);
    let spawn = guard.start_waiting(room);
    guard.resolving += spawn.len();
    drop(guard);
    for (session, host, port) in spawn {
        std::thread::spawn({
            let lane = Arc::clone(lane);
            move || resolve_dest(lane, session, host, port)
        });
    }
}

#[allow(clippy::needless_pass_by_value)]
fn resolve_dest(handle: Arc<Mutex<UdpLane>>, session: u32, host: String, port: u16) {
    let mut resolving = Resolving::new(Arc::clone(&handle));
    let peer = crate::proxy::resolve_bounded(&host, port, UDP_RESOLVE_BUDGET, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(std::iter::Iterator::collect)
    })
    .and_then(|addrs| addrs.into_iter().next());
    let Ok(mut lane) = handle.lock() else {
        return;
    };
    if let Some(flow) = lane.flows.get_mut(&session) {
        if let Some(at) = flow.assocs.find(&host, port) {
            flow.assocs.list[at].resolving = false;
            if let Some(peer) = peer {
                flow.assocs.list[at].dest = Some(peer);
                let queued = flow.assocs.drain(at);
                for payload in queued {
                    let _ = flow
                        .target
                        .send_to(&payload, target_addr(&flow.target, peer));
                }
            } else {
                flow.assocs.evict(at);
            }
        }
    }
    resolving.release_in(&mut lane);
    let room = MAX_PENDING_RESOLVERS.saturating_sub(lane.resolving);
    let spawn = lane.start_waiting(room);
    lane.resolving += spawn.len();
    drop(lane);
    for (session, host, port) in spawn {
        std::thread::spawn({
            let handle = Arc::clone(&handle);
            move || resolve_dest(handle, session, host, port)
        });
    }
}

/// Read the binary hello off stream 0 and answer it; `None` when the connection should stop, either to wait for more bytes or because it was refused.
fn authenticate(
    routes: &mut HashMap<Vec<u8>, Inbound>,
    auths: &[String],
    dcid: &[u8],
    conn: &mut quiche::Connection,
    sock: &crate::quic::Datagram,
    out: &mut [u8],
) -> Option<()> {
    if routes.get(dcid).is_some_and(|inbound| inbound.authed) {
        return Some(());
    }
    let mut room = Unfilled::<4096>::new();
    let mut finished = false;
    loop {
        match conn.stream_recv(0, room.as_mut()) {
            Ok((0, _)) => {
                finished = true;
                break;
            }
            Ok((n, _)) => {
                if let Some(inbound) = routes.get_mut(dcid) {
                    inbound.auth_buf.extend_from_slice(&room.as_mut()[..n]);
                }
            }
            Err(_) => break,
        }
    }
    let inbound = routes.get_mut(dcid)?;
    if inbound.auth_buf.len() > HEAD_CAP {
        return None;
    }
    let hello = match wire::decode_client_hello(&inbound.auth_buf) {
        Ok((hello, _)) => hello,
        Err(ferrox_core::hysteria::RequestError::Incomplete) if !finished => return None,
        Err(_) => {
            let _ = conn.close(false, 1, b"protocol error");
            flush(sock, conn, out);
            return None;
        }
    };
    let ok = answer_hello(conn, &hello, auths);
    flush(sock, conn, out);
    inbound.auth_buf.clear();
    inbound.authed = true;
    if !ok {
        let _ = conn.close(false, 2, b"auth error");
        flush(sock, conn, out);
        return None;
    }
    Some(())
}

struct Router<'a> {
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    out: Unfilled<MAX_DATAGRAM>,
    auths: &'a [String],
    serve: &'a Serve,
    udp_idle: Duration,
    routes: HashMap<Vec<u8>, Inbound>,
}

impl Router<'_> {
    fn accept(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        template: &mut quiche::Config,
        client_cid: &[u8],
        initial_dcid: &[u8],
    ) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::fill(&mut scid).is_err() {
            return;
        }
        let cid = quiche::ConnectionId::from_ref(&scid);
        let Ok(mut conn) = quiche::accept(&cid, None, self.local, from, template) else {
            return;
        };
        let info = quiche::RecvInfo {
            from,
            to: self.local,
        };
        if conn.recv(packet, info).is_err() {
            return;
        }
        flush(&self.sock, &mut conn, self.out.as_mut());
        self.routes.insert(
            scid.to_vec(),
            Inbound {
                conn: Arc::new(Mutex::new(conn)),
                authed: false,
                auth_buf: Vec::new(),
                served: HashSet::new(),
                wakes: HashMap::new(),
                send: StreamWake::new(),
                udp: Arc::new(Mutex::new(UdpLane::default())),
                next_udp: 1,
                client_cid: client_cid.to_vec(),
                initial_dcid: initial_dcid.to_vec(),
            },
        );
    }

    fn drive(&mut self, dcid: &[u8], packet: &mut [u8], from: SocketAddr) {
        let Self {
            routes,
            sock,
            out,
            auths,
            serve,
            local,
            ..
        } = self;
        let Some(shared) = routes.get(dcid).map(|i| Arc::clone(&i.conn)) else {
            return;
        };
        let info = quiche::RecvInfo { from, to: *local };
        {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.recv(packet, info).is_err() {
                return;
            }
            flush(sock, &mut conn, out.as_mut());
            if let Some(inbound) = routes.get(dcid) {
                inbound.send.bump();
            }
            if !conn.is_established() || conn.is_closed() {
                return;
            }
            if authenticate(routes, auths, dcid, &mut conn, sock, out.as_mut()).is_none() {
                return;
            }
            let mut streams = Vec::new();
            let mut wakes = Vec::new();
            for id in conn.readable() {
                if id < FIRST_FLOW_STREAM || id % 4 != 0 {
                    continue;
                }
                let Some(inbound) = routes.get_mut(dcid) else {
                    return;
                };
                if let Some(wake) = inbound.wakes.get(&id) {
                    wakes.push(Arc::clone(wake));
                }
                if inbound.served.contains(&id) {
                    continue;
                }
                inbound.served.insert(id);
                let request_udp = inbound.next_udp;
                inbound.next_udp = inbound.next_udp.wrapping_add(1);
                let wake = StreamWake::new();
                inbound.wakes.insert(id, Arc::clone(&wake));
                streams.push((
                    id,
                    request_udp,
                    Arc::clone(&inbound.udp),
                    wake,
                    Arc::clone(&inbound.send),
                ));
            }
            for wake in wakes {
                wake.bump();
            }
            for (id, next_udp, lane, wake, send) in streams {
                let thread_shared = Arc::clone(&shared);
                let thread_sock = Arc::clone(sock);
                let thread_serve = Arc::clone(serve);
                let local = *local;
                std::thread::spawn(move || {
                    serve_tcp_or_udp(
                        &thread_shared,
                        &thread_sock,
                        local,
                        id,
                        &thread_serve,
                        next_udp,
                        &lane,
                        &wake,
                        &send,
                    );
                });
            }
            relay_datagrams(routes, sock, &shared, dcid, &mut conn);
            flush(sock, &mut conn, out.as_mut());
        }
    }

    fn idle(&mut self) {
        self.idle_at(now_nanos());
    }

    fn idle_at(&mut self, now: u64) {
        let Self {
            routes,
            sock,
            out,
            udp_idle,
            ..
        } = self;
        let idle_nanos = u64::try_from(udp_idle.as_nanos()).unwrap_or(u64::MAX);
        routes.retain(|_, inbound| {
            let Ok(mut conn) = inbound.conn.lock() else {
                return true;
            };
            if conn.is_closed() {
                if let Ok(mut lane) = inbound.udp.lock() {
                    for flow in lane.flows.values() {
                        flow.stop.store(true, Ordering::Relaxed);
                    }
                    lane.flows.clear();
                    lane.pending.clear();
                    lane.sessions.clear();
                }
                return false;
            }
            conn.on_timeout();
            flush(sock, &mut conn, out.as_mut());
            inbound.send.bump();
            if let Ok(mut lane) = inbound.udp.lock() {
                lane.flows.retain(|_, flow| {
                    let idle = now.saturating_sub(flow.last.load(Ordering::Relaxed)) > idle_nanos;
                    if idle {
                        flow.stop.store(true, Ordering::Relaxed);
                        false
                    } else {
                        true
                    }
                });
            }
            true
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_tcp_or_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    local: SocketAddr,
    stream: u64,
    serve: &Serve,
    next_udp: u32,
    lane: &Arc<Mutex<UdpLane>>,
    wake: &Arc<StreamWake>,
    send: &Arc<StreamWake>,
) {
    let mut flow = Flow::from_parts(
        Arc::clone(shared),
        Arc::clone(sock),
        local,
        stream,
        Vec::new(),
        false,
        false,
    )
    .with_wake(Some(Arc::clone(wake)))
    .with_send_wake(Arc::clone(send));
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some((udp, host, port)) = read_request(&mut flow, deadline) else {
        return;
    };
    if udp {
        serve_udp_stream(flow, next_udp, lane);
    } else {
        serve(flow, host, port);
    }
}

/// Serve the v1 binary handshake and both flow shapes.
pub(crate) fn serve_loop(
    address: &str,
    auths: &[String],
    identity: &ferrox_core::tls::TlsServerConfig,
    serve: &Serve,
    config: &ferrox_core::hysteria::Config,
) {
    let Some(bound) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        return;
    };
    let Ok(sock) = crate::quic::bind_datagram(address) else {
        return;
    };
    let local = sock.local_addr().unwrap_or(bound);
    let Some(mut template) = server_config(identity, config.cc, config.quic.as_ref()) else {
        eprintln!("hysteria v1 inbound on {address} cannot build its quic tls: serves nothing");
        return;
    };
    let sock = match XPlus::new(&config.obfs_password) {
        Some(obfs) => crate::quic::Datagram::xplus(sock, obfs),
        None => crate::quic::Datagram::plain(sock),
    };
    let mut router = Router {
        sock: Arc::new(sock),
        local,
        out: Unfilled::<MAX_DATAGRAM>::new(),
        auths,
        serve,
        udp_idle: Duration::from_secs(config.udp_idle),
        routes: HashMap::new(),
    };
    let mut buf = Unfilled::<RECV_ROOM>::new();
    if router.sock.set_read_timeout(Some(ROUTE_POLL)).is_err() {
        return;
    }
    #[cfg(target_os = "linux")]
    let mut batch = crate::quic::Batch::new();
    let mut idle_at = Instant::now();
    loop {
        #[cfg(target_os = "linux")]
        match crate::quic::recv_batch(&router.sock, &mut batch) {
            crate::quic::Drain::Read => {
                for at in 0..batch.len() {
                    let Some((packet, from)) = batch.at(at) else {
                        continue;
                    };
                    route_packet(&mut router, &mut template, packet, from);
                }
                if idle_at.elapsed() >= ROUTE_POLL {
                    router.idle();
                    idle_at = Instant::now();
                }
                continue;
            }
            crate::quic::Drain::Empty => {
                router.idle();
                continue;
            }
            crate::quic::Drain::Unbatchable => {}
            // A socket that coalesces must not be read one segment wide.
            crate::quic::Drain::Unreadable => return,
        }
        match router.sock.recv_from(buf.as_mut()) {
            Ok((n, from)) => {
                route_packet(&mut router, &mut template, &mut buf.as_mut()[..n], from);
                if idle_at.elapsed() >= ROUTE_POLL {
                    router.idle();
                    idle_at = Instant::now();
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::InvalidData => {}
            Err(ref error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                router.idle();
            }
            Err(_) => return,
        }
    }
}

fn route_packet(
    router: &mut Router<'_>,
    template: &mut quiche::Config,
    packet: &mut [u8],
    from: SocketAddr,
) {
    let Ok(header) = quiche::Header::from_slice(packet, SCID_LEN) else {
        return;
    };
    if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
        return;
    }
    let initial = header.ty == quiche::Type::Initial;
    let dcid = header.dcid.as_ref();
    let peer_cid = header.scid.as_ref();
    if dcid.len() > 20 || peer_cid.len() > 20 {
        return;
    }
    let mut dcid_buf = [0u8; 20];
    dcid_buf[..dcid.len()].copy_from_slice(dcid);
    let mut peer_buf = [0u8; 20];
    peer_buf[..peer_cid.len()].copy_from_slice(peer_cid);
    let dcid = &dcid_buf[..dcid.len()];
    let peer_cid = &peer_buf[..peer_cid.len()];
    if initial {
        let known = router.routes.contains_key(dcid);
        let retransmit = router.routes.iter().find_map(|(key, inbound)| {
            ((!inbound.initial_dcid.is_empty() && inbound.initial_dcid.as_slice() == dcid)
                || (!peer_cid.is_empty()
                    && !inbound.client_cid.is_empty()
                    && inbound.client_cid.as_slice() == peer_cid))
                .then(|| key.clone())
        });
        if known {
            router.drive(dcid, packet, from);
        } else if let Some(key) = retransmit {
            router.drive(&key, packet, from);
        } else {
            router.accept(packet, from, template, peer_cid, dcid);
        }
    } else {
        router.drive(dcid, packet, from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_v1_session_carries_a_tcp_echo() {
        // Loopback coverage lives with the proxy's dispatch test; this only pins the module's own request framing.
        let mut request = Vec::new();
        wire::encode_client_request(
            &wire::ClientRequest {
                udp: false,
                host: "localhost",
                port: 80,
            },
            &[],
            &mut request,
        );
        assert_eq!(
            wire::decode_client_request(&request)
                .expect("decodes")
                .0
                .port,
            80
        );
    }

    #[test]
    fn an_insecure_v1_dial_accepts_an_untrusted_chain() {
        let dial = |insecure| Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 443,
            config: ferrox_core::hysteria::Config {
                version: 1,
                insecure,
                ..ferrox_core::hysteria::Config::default()
            },
            roots: None,
        };
        assert!(
            client_config(&dial(true), &[]).is_some(),
            "allowInsecure leaves no root to stage"
        );
        assert!(
            client_config(&dial(false), &[]).is_none(),
            "a verifying v1 dial still refuses an empty trust store"
        );
    }

    #[test]
    fn a_v1_tuned_plan_is_its_own_pool_key() {
        // A controller or profile chosen for one lane may not ride a connection negotiated under another.
        let dial = |quic: Option<ferrox_core::hysteria::QuicParams>| Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 443,
            config: ferrox_core::hysteria::Config {
                version: 1,
                auth: "a".to_owned(),
                quic,
                ..ferrox_core::hysteria::Config::default()
            },
            roots: None,
        };
        let bbr = ferrox_core::hysteria::QuicParams {
            bbr_profile: ferrox_core::hysteria::BbrProfile::Aggressive,
            ..ferrox_core::hysteria::QuicParams::default()
        };
        let cubic = ferrox_core::hysteria::QuicParams {
            cc: Some(ferrox_core::hysteria::Congestion::Cubic),
            ..ferrox_core::hysteria::QuicParams::default()
        };
        assert_eq!(
            server_of(&dial(Some(bbr))),
            server_of(&dial(Some(bbr))),
            "a tuned lane reuses itself"
        );
        assert_ne!(
            server_of(&dial(Some(bbr))),
            server_of(&dial(Some(cubic))),
            "a different profile or controller is a different lane"
        );
        assert_ne!(
            server_of(&dial(None)),
            server_of(&dial(Some(cubic))),
            "a tuned lane never rides a plain connection"
        );
        let mut untrusted = dial(None);
        untrusted.config.insecure = true;
        assert_ne!(
            server_of(&untrusted),
            server_of(&dial(None)),
            "an unverified lane is not reused by a verifying dial"
        );
    }

    #[test]
    fn a_v1_datagram_association_reaps_on_the_configured_idle() {
        // The v1 server's reaper takes the stream's `udpIdleTimeout` too: a six-second-old association dies at five and lives at sixty.
        let stamp = now_nanos();
        let reaps = |udp_idle: Duration, age: u64| {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
            config
                .set_application_protos(&[wire::ALPN])
                .expect("negotiates");
            let scid = [7u8; SCID_LEN];
            let cid = quiche::ConnectionId::from_ref(&scid);
            let local: SocketAddr = "127.0.0.1:0".parse().expect("addr");
            let peer: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            let conn = quiche::connect(None, &cid, local, peer, &mut config).expect("connects");
            let stop = Arc::new(AtomicBool::new(false));
            let target = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let mut lane = UdpLane::default();
            lane.sessions.insert(1);
            lane.flows.insert(
                1,
                UdpFlow {
                    target: Arc::new(target),
                    assocs: Assocs::default(),
                    last: Arc::new(AtomicU64::new(stamp)),
                    stop: Arc::clone(&stop),
                },
            );
            let auths: Vec<String> = Vec::new();
            let handler: Serve = Arc::new(|_, _, _| {});
            let mut by_scid = HashMap::new();
            by_scid.insert(
                vec![1u8; SCID_LEN],
                Inbound {
                    conn: Arc::new(Mutex::new(conn)),
                    authed: true,
                    auth_buf: Vec::new(),
                    served: HashSet::new(),
                    wakes: HashMap::new(),
                    send: StreamWake::new(),
                    udp: Arc::new(Mutex::new(lane)),
                    next_udp: 2,
                    client_cid: vec![2u8; 8],
                    initial_dcid: vec![3u8; 8],
                },
            );
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
            let mut router = Router {
                sock: Arc::new(crate::quic::Datagram::plain(sock)),
                local,
                out: Unfilled::new(),
                auths: &auths,
                serve: &handler,
                udp_idle,
                routes: by_scid,
            };
            router.idle_at(stamp + age);
            stop.load(Ordering::Relaxed)
        };
        assert!(
            reaps(Duration::from_secs(5), 6_000_000_000),
            "five seconds reaps a six-second-old association"
        );
        assert!(
            !reaps(Duration::from_secs(5), 4_000_000_000),
            "five seconds keeps a four-second-old association"
        );
        assert!(
            !reaps(Duration::from_secs(60), 6_000_000_000),
            "sixty seconds keeps it"
        );
    }

    #[test]
    fn an_unknown_udp_session_never_reaches_its_destination() {
        let canary = UdpSocket::bind("127.0.0.1:0").expect("binds");
        canary
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let canary_port = canary.local_addr().expect("addr").port();

        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
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
        let address = format!("127.0.0.1:{port}");
        let serve: Serve = Arc::new(|_, _, _| {});
        std::thread::spawn(move || {
            serve_loop(
                &address,
                &["v1-auth".to_owned()],
                &identity,
                &serve,
                &ferrox_core::hysteria::Config {
                    version: 1,
                    cc: ferrox_core::hysteria::Congestion::Bbr,
                    udp_idle: 60,
                    ..ferrox_core::hysteria::Config::default()
                },
            );
        });

        let dial = Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                version: 1,
                auth: "v1-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop: None,
                gecko: None,
                ..ferrox_core::hysteria::Config::default()
            },
            roots: Some(roots.into()),
        };
        let session = connect(&dial).expect("connects");
        let mut datagram = Vec::new();
        wire::encode_udp(
            &UdpMessage {
                session: u32::MAX,
                host: "127.0.0.1",
                port: canary_port,
                packet: 1,
                frag: 0,
                frags: 1,
                payload: b"forged",
            },
            &mut datagram,
        )
        .expect("encodes");
        {
            let mut conn = session.shared.lock().expect("locks");
            conn.dgram_send(&datagram).expect("sends");
            let mut out = Unfilled::<MAX_DATAGRAM>::new();
            flush(&session.sock, &mut conn, out.as_mut());
        }
        let mut buf = [0u8; 64];
        assert!(
            canary.recv_from(&mut buf).is_err(),
            "unknown session reached its destination"
        );
    }

    #[test]
    fn a_stopped_reader_leaves_its_target_queue_alone() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let scid = [7u8; SCID_LEN];
        let cid = quiche::ConnectionId::from_ref(&scid);
        let local = "127.0.0.1:0".parse().expect("addr");
        let peer = "127.0.0.1:1".parse().expect("addr");
        let conn = quiche::connect(None, &cid, local, peer, &mut config).expect("connects");
        let shared = Arc::new(Mutex::new(conn));
        let sock = Arc::new(crate::quic::Datagram::plain(
            UdpSocket::bind("127.0.0.1:0").expect("binds the lane"),
        ));

        let target = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("binds the target"));
        target
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("binds the sender");
        sender
            .send_to(b"late", target.local_addr().expect("target address"))
            .expect("queues a datagram");

        let stop = AtomicBool::new(true);
        let last = Arc::new(AtomicU64::new(now_nanos()));
        let reader = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let sock = Arc::clone(&sock);
            let target = Arc::clone(&target);
            move || udp_reader(&shared, &sock, &target, &last, &stop, 7)
        });
        reader.join().expect("the reader ends");

        let mut buf = [0u8; 8];
        let (n, _) = target
            .recv_from(&mut buf)
            .expect("a stopped reader leaves its target's queue intact");
        assert_eq!(&buf[..n], b"late");
    }

    #[test]
    fn a_stop_while_the_reader_waits_is_not_forwarded() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let scid = [8u8; SCID_LEN];
        let cid = quiche::ConnectionId::from_ref(&scid);
        let local = "127.0.0.1:0".parse().expect("addr");
        let peer = "127.0.0.1:1".parse().expect("addr");
        let conn = quiche::connect(None, &cid, local, peer, &mut config).expect("connects");
        let shared = Arc::new(Mutex::new(conn));
        let sock = Arc::new(crate::quic::Datagram::plain(
            UdpSocket::bind("127.0.0.1:0").expect("binds the lane"),
        ));

        let target = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("binds the target"));
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("binds the sender");

        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(AtomicU64::new(now_nanos()));
        let reader = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let sock = Arc::clone(&sock);
            let target = Arc::clone(&target);
            let last = Arc::clone(&last);
            let stop = Arc::clone(&stop);
            move || udp_reader(&shared, &sock, &target, &last, stop.as_ref(), 7)
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(!reader.is_finished(), "the reader should be waiting");

        let guard = shared.lock().expect("locks");
        stop.store(true, Ordering::Relaxed);
        sender
            .send_to(b"late", target.local_addr().expect("target address"))
            .expect("wakes the reader");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !reader.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let finished = reader.is_finished();
        drop(guard);
        reader.join().expect("the reader ends");
        assert!(
            finished,
            "the reader waited for the connection lock after its flow stopped"
        );
    }
    #[test]
    fn an_idle_destination_is_evicted_at_the_association_cap() {
        let target = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let mut flow = UdpFlow {
            target: Arc::new(target),
            assocs: Assocs::default(),
            last: Arc::new(AtomicU64::new(now_nanos())),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let old = now_nanos().saturating_sub(1_000_000_000);
        for index in 0..MAX_UDP_ASSOCIATIONS {
            let host = format!("old{index}.test");
            let at = flow.assocs.insert(&host, 53, old).expect("room");
            flow.assocs.list[at].dest = Some(SocketAddr::from(([127, 0, 0, 1], 53)));
        }
        let at = flow
            .slot("new.test", 53, now_nanos())
            .expect("an idle slot is evicted");
        assert!(flow.assocs.list[at].is("new.test", 53));
        assert_eq!(flow.assocs.list.len(), MAX_UDP_ASSOCIATIONS);
        let kept = (0..MAX_UDP_ASSOCIATIONS)
            .filter(|index| flow.assocs.find(&format!("old{index}.test"), 53).is_some())
            .count();
        assert_eq!(
            kept,
            MAX_UDP_ASSOCIATIONS - 1,
            "one idle association made room"
        );
        assert_eq!(flow.assocs.start_waiting(1), Vec::new());
    }

    /// A destination holding datagrams is never evicted to make room, so a flow at the cap
    /// refuses the new destination instead of dropping reassembly state.
    #[test]
    fn a_waiting_association_is_not_evicted_for_a_fresh_one() {
        let target = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let mut flow = UdpFlow {
            target: Arc::new(target),
            assocs: Assocs::default(),
            last: Arc::new(AtomicU64::new(now_nanos())),
            stop: Arc::new(AtomicBool::new(false)),
        };
        for index in 0..MAX_UDP_ASSOCIATIONS {
            let host = format!("held{index}.test");
            let at = flow.assocs.insert(&host, 53, 0).expect("room");
            flow.assocs.enqueue(at, vec![1]);
        }
        assert_eq!(flow.assocs.waiting, MAX_UDP_ASSOCIATIONS);
        assert!(
            flow.slot("new.test", 53, now_nanos()).is_none(),
            "a queue no eviction may drop refuses the new destination"
        );
        let waiting = flow.assocs.start_waiting(MAX_UDP_ASSOCIATIONS);
        assert_eq!(waiting.len(), MAX_UDP_ASSOCIATIONS);
        assert_eq!(
            flow.assocs.drain(0).len(),
            1,
            "a resolution takes the queue it waited on"
        );
        assert_eq!(flow.assocs.waiting, MAX_UDP_ASSOCIATIONS - 1);
    }

    /// A datagram on a known association finds its destination in place: no key is cloned and no
    /// table is rewritten.
    #[test]
    fn an_established_destination_costs_no_key_and_no_insert() {
        let host = "example.test";
        let port = 53u16;
        let peer: SocketAddr = "203.0.113.9:53".parse().expect("addr");
        let mut assocs = Assocs::default();
        let at = assocs.insert(host, port, 0).expect("room");
        assocs.list[at].dest = Some(peer);
        let (found, counts) = ferrox_core::alloc_count::measure(|| assocs.find(host, port));
        assert_eq!(found, Some(at));
        assert_eq!(counts.allocs, 0, "the established destination costs no key");
        assert_eq!(counts.bytes, 0);

        let mut used = HashMap::new();
        used.insert((host.to_owned(), port), at);
        let mut defrags = HashMap::new();
        defrags.insert((host.to_owned(), port), Defrag::new());
        let ((), before) = ferrox_core::alloc_count::measure(|| {
            let key = (host.to_owned(), port);
            let _ = used.entry(key.clone()).or_insert(at);
            let _ = defrags.entry(key.clone()).or_insert_with(Defrag::new);
        });
        assert!(
            before.allocs >= 3,
            "the old shape built a key and cloned it per table"
        );

        let payload = [1u8, 2, 3];
        let datagram = UdpMessage {
            session: 1,
            host,
            port,
            packet: 0,
            frag: 0,
            frags: 1,
            payload: &payload,
        };
        let mut assembled = Vec::new();
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..8 {
                let whole = assocs.list[at]
                    .defrag
                    .feed(&datagram, &mut assembled)
                    .expect("a whole datagram")
                    .expect("nothing was missing");
                assert_eq!(whole.payload, &payload[..]);
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "a whole datagram costs no key and no copy"
        );

        let mut waiting: HashMap<(String, u16), Vec<Vec<u8>>> = HashMap::new();
        let ((), before) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..8 {
                let key = (host.to_owned(), port);
                waiting.entry(key.clone()).or_default().push(Vec::new());
            }
        });
        assert!(
            before.allocs >= 8,
            "the old shape cloned the key to queue a datagram"
        );
        assocs.list[at].waiting.reserve(8);
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..8 {
                assocs.enqueue(at, Vec::new());
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "a queued datagram costs its payload, not a key"
        );
        assert_eq!(assocs.waiting, 8);
    }

    /// The host a datagram's message carries is the address's own text, written into a stack
    /// room, so a datagram that names a literal costs no heap.
    #[test]
    fn a_datagram_host_is_the_address_text_without_the_heap() {
        let mut room = [0u8; HOST_ROOM];
        let ip: IpAddr = "2001:db8::1".parse().expect("an address");
        let (mine, counts) = ferrox_core::alloc_count::measure(|| host_of(ip, &mut room));
        assert_eq!(counts.allocs, 0, "the host is written into the room");
        assert_eq!(mine, Some("2001:db8::1"), "and it is the address's text");
        let (text, before) = ferrox_core::alloc_count::measure(|| ip.to_string());
        assert!(
            before.allocs > counts.allocs,
            "the old shape allocated the text"
        );
        assert_eq!(
            &text[..],
            mine.expect("the room's text"),
            "of the same text"
        );
        for text in [
            "10.0.0.2",
            "::1",
            "::ffff:10.0.0.2",
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
        ] {
            let ip: IpAddr = text.parse().expect("an address");
            assert_eq!(
                host_of(ip, &mut room),
                Some(ip.to_string().as_str()),
                "{text}"
            );
        }
    }
}
