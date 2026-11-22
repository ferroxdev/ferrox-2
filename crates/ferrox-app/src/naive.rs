//! `NaiveProxy` over HTTP/2 and HTTP/3: CONNECT with a Basic credential and a padding header,
//! then the reference's eight padded records before the tunnel turns raw.

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{self, Destination};
use crate::xhttp_h2::{
    self, H2Client, H2Conn, H2OpenError, H2Service, H2StreamOut, H2StreamReader,
};
use crate::xhttp_h3::{H3Client, H3OpenError, H3Reader, H3StreamOut, H3Writer, Wire};
use base64::Engine as _;
use ferrox_core::foxy::hpack;
use ferrox_core::hysteria::Congestion;
use ferrox_core::tls::{TlsConfig, TlsProvider as _};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

const PADDING_COUNT: usize = 8;
const MAX_PADDING_CHUNK: usize = 65_535;
const MAX_UOT_LANES: usize = 256;
/// Lane opens run off the receive loop, so each destination queues a bounded burst while dialed.
const MAX_UOT_PENDING: usize = 32;
const MAX_UOT_PENDING_PACKETS: usize = 64;
const MAX_UOT_PENDING_BYTES: usize = 256 * 1024;
const PADDING_ALPHABET: &[u8; 16] = b"!#$()+<>?@[]^`{}";
/// The reference client's defaults: a wide HTTP/2 connection window (each stream gets half), and
/// the QUIC stream and session credit its engine opens with when the config names neither.
const H2_RECEIVE_WINDOW: u64 = if cfg!(target_os = "ios") {
    4 * 1024 * 1024
} else {
    128 * 1024 * 1024
};
const QUIC_STREAM_WINDOW: u64 = 6 * 1024 * 1024;
const QUIC_SESSION_WINDOW: u64 = 15 * 1024 * 1024;

type Reader = Box<dyn Read + Send>;
type Writer = Box<dyn Write + Send>;
type Users = Arc<Vec<(String, String)>>;

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_or(0, |()| u64::from_le_bytes(bytes))
}

fn random_below(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    (random_u64() % limit as u64) as usize
}

fn padding_header() -> String {
    let len = 30 + random_below(32);
    let mut out = Vec::with_capacity(len);
    let mut bits = random_u64();
    for _ in 0..16 {
        out.push(PADDING_ALPHABET[(bits & 15) as usize]);
        bits >>= 4;
    }
    out.resize(len, b'~');
    String::from_utf8(out).expect("the padding alphabet is ASCII")
}

#[derive(Default)]
struct PaddingRead {
    read: usize,
    remaining: usize,
    skip: usize,
    header: [u8; 3],
    have: usize,
}

impl PaddingRead {
    fn read(&mut self, reader: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.remaining > 0 {
                let take = buf.len().min(self.remaining);
                let n = reader.read(&mut buf[..take])?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                self.remaining -= n;
                return Ok(n);
            }
            if self.skip > 0 {
                let mut discard = [0u8; 1024];
                while self.skip > 0 {
                    let take = self.skip.min(discard.len());
                    match reader.read(&mut discard[..take]) {
                        Ok(0) => {
                            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                        }
                        Ok(n) => self.skip -= n,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            if self.read >= PADDING_COUNT {
                return reader.read(buf);
            }
            while self.have < self.header.len() {
                let have = self.have;
                match reader.read(&mut self.header[have..]) {
                    Ok(0) if have == 0 => return Ok(0),
                    Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                    Ok(n) => self.have += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            let original = usize::from(u16::from_be_bytes([self.header[0], self.header[1]]));
            let padding = usize::from(self.header[2]);
            self.have = 0;
            self.read += 1;
            self.remaining = original;
            self.skip = padding;
        }
    }
}

#[derive(Default)]
struct PaddingWrite {
    written: usize,
}

impl PaddingWrite {
    fn write(&mut self, writer: &mut dyn Write, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.written >= PADDING_COUNT {
            return writer.write(data);
        }
        let mut done = 0;
        for chunk in data.chunks(MAX_PADDING_CHUNK) {
            if self.written >= PADDING_COUNT {
                write_all(writer, &data[done..])?;
                return Ok(data.len());
            }
            let padding = random_below(256) as u8;
            let mut header = [0u8; 3];
            header[..2].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            header[2] = padding;
            write_all(writer, &header)?;
            write_all(writer, chunk)?;
            write_zeros(writer, usize::from(padding))?;
            self.written += 1;
            done += chunk.len();
        }
        Ok(data.len())
    }
}

fn read_exact(reader: &mut dyn Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => {
                let (_, rest) = buf.split_at_mut(n);
                buf = rest;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all(writer: &mut dyn Write, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match writer.write(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(n) => buf = &buf[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_zeros(writer: &mut dyn Write, mut left: usize) -> std::io::Result<()> {
    let zeros = [0u8; 255];
    while left > 0 {
        let take = left.min(zeros.len());
        write_all(writer, &zeros[..take])?;
        left -= take;
    }
    Ok(())
}

const UOT_V2: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_V1: &str = "sp.udp-over-tcp.arpa";

/// The version a CONNECT authority names, if it is one of the reference's magic names.
fn uot_magic(target: &Destination) -> Option<u8> {
    let Destination::Name(host, _) = target else {
        return None;
    };
    if host.eq_ignore_ascii_case(UOT_V2) {
        Some(2)
    } else if host.eq_ignore_ascii_case(UOT_V1) {
        Some(1)
    } else {
        None
    }
}

/// The reference's `UoT` address: its own family bytes, not the SOCKS ones this tree uses elsewhere.
fn push_uot_addr(out: &mut Vec<u8>, target: &Destination) {
    match target {
        Destination::Address(address) => match address.ip() {
            IpAddr::V4(ip) => {
                out.push(0);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
        },
        Destination::Name(host, _) => {
            out.push(2);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
}

#[cfg(test)]
fn read_uot_addr(reader: &mut dyn Read) -> std::io::Result<Destination> {
    let mut family = [0u8; 1];
    read_exact(reader, &mut family)?;
    let address = match family[0] {
        0 => {
            let mut octets = [0u8; 4];
            read_exact(reader, &mut octets)?;
            Destination::Address(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 0))
        }
        1 => {
            let mut octets = [0u8; 16];
            read_exact(reader, &mut octets)?;
            Destination::Address(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 0))
        }
        2 => {
            let mut len = [0u8; 1];
            read_exact(reader, &mut len)?;
            let mut host = vec![0u8; usize::from(len[0])];
            read_exact(reader, &mut host)?;
            let host = String::from_utf8(host)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            Destination::Name(host, 0)
        }
        _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    };
    let mut port = [0u8; 2];
    read_exact(reader, &mut port)?;
    let port = u16::from_be_bytes(port);
    Ok(match address {
        Destination::Address(address) => Destination::Address(SocketAddr::new(address.ip(), port)),
        Destination::Name(host, _) => Destination::Name(host, port),
    })
}

fn write_uot_request(
    writer: &mut dyn Write,
    connect: bool,
    target: &Destination,
) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(1 + target.addr_len() + 2);
    head.push(u8::from(connect));
    target.push_addr(&mut head, 4, 3);
    head.extend_from_slice(&target.port().to_be_bytes());
    write_all(writer, &head)
}

fn read_uot_request(reader: &mut dyn Read) -> std::io::Result<(bool, Destination)> {
    let mut connect = [0u8; 1];
    read_exact(reader, &mut connect)?;
    let mut atyp = [0u8; 1];
    read_exact(reader, &mut atyp)?;
    let target = proxy::read_socks_named(reader, atyp[0])
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok((connect[0] != 0, target))
}

fn write_uot_packet(
    writer: &mut dyn Write,
    connect: bool,
    target: &Destination,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut head = Vec::with_capacity(target.addr_len() + 2 + usize::from(!connect));
    if !connect {
        push_uot_addr(&mut head, target);
    }
    head.extend_from_slice(&len.to_be_bytes());
    write_all(writer, &head)?;
    write_all(writer, payload)
}

#[cfg(test)]
fn read_uot_packet(
    reader: &mut dyn Read,
    connect: bool,
    fixed: Option<&Destination>,
) -> std::io::Result<(Destination, Vec<u8>)> {
    let target = if connect {
        fixed
            .cloned()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?
    } else {
        read_uot_addr(reader)?
    };
    let mut len = [0u8; 2];
    read_exact(reader, &mut len)?;
    let mut payload = vec![0u8; usize::from(u16::from_be_bytes(len))];
    read_exact(reader, &mut payload)?;
    Ok((target, payload))
}

/// Parse one `UoT` datagram from a growing buffer: `None` means the buffer ends inside a field,
/// `Some` carries the frame and the bytes it used so the reader can drain exactly those.
fn parse_uot_addr_buf(buf: &[u8]) -> std::io::Result<Option<(Destination, usize)>> {
    let Some(&family) = buf.first() else {
        return Ok(None);
    };
    let (address, mut used) = match family {
        0 => {
            if buf.len() < 5 {
                return Ok(None);
            }
            (
                Destination::Address(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from([buf[1], buf[2], buf[3], buf[4]])),
                    0,
                )),
                5,
            )
        }
        1 => {
            if buf.len() < 17 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            (
                Destination::Address(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 0)),
                17,
            )
        }
        2 => {
            let Some(&len) = buf.get(1) else {
                return Ok(None);
            };
            let len = usize::from(len);
            if buf.len() < 2 + len {
                return Ok(None);
            }
            let host = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            (Destination::Name(host.to_owned(), 0), 2 + len)
        }
        _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    };
    if buf.len() < used + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buf[used], buf[used + 1]]);
    used += 2;
    Ok(Some((
        match address {
            Destination::Address(address) => {
                Destination::Address(SocketAddr::new(address.ip(), port))
            }
            Destination::Name(host, _) => Destination::Name(host, port),
        },
        used,
    )))
}

fn parse_uot_packet(
    buf: &[u8],
    connect: bool,
    fixed: Option<&Destination>,
) -> std::io::Result<Option<(Destination, Vec<u8>, usize)>> {
    let (target, used) = if connect {
        let target = fixed
            .cloned()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        (target, 0)
    } else {
        match parse_uot_addr_buf(buf)? {
            Some((target, used)) => (target, used),
            None => return Ok(None),
        }
    };
    if buf.len() < used + 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([buf[used], buf[used + 1]]));
    let end = used + 2 + len;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((target, buf[used + 2..end].to_vec(), end)))
}

/// A `UoT` reader that keeps the bytes it has already taken: a non-blocking stream may return
/// `WouldBlock` between two fields, and the next call must resume at the same byte.
#[derive(Default)]
struct UotPacketReader {
    buf: Vec<u8>,
}

impl UotPacketReader {
    fn next(
        &mut self,
        stream: &mut NaiveStream,
        connect: bool,
        fixed: Option<&Destination>,
    ) -> std::io::Result<Option<(Destination, Vec<u8>)>> {
        loop {
            if let Some((target, payload, used)) = parse_uot_packet(&self.buf, connect, fixed)? {
                self.buf.drain(..used);
                return Ok(Some((target, payload)));
            }
            if self.buf.len() > 70_000 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) if self.buf.is_empty() => return Ok(None),
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated UoT datagram",
                    ))
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// A `UoT` datagram as the SOCKS5 UDP frame a client on this side expects, address kept as the name it was.
fn uot_socks_frame(target: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + target.addr_len() + payload.len());
    frame.extend_from_slice(&[0, 0, 0]);
    target.push_addr(&mut frame, 4, 3);
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn uot_bind(family: &str) -> Option<UdpSocket> {
    let socket = UdpSocket::bind(family).ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}

#[cfg(unix)]
fn wait_uot_readable(sockets: &[Option<&UdpSocket>], timeout: Duration) -> bool {
    use std::os::fd::AsRawFd as _;
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut rows = [libc::pollfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; 2];
    let mut count = 0;
    for (row, socket) in rows.iter_mut().zip(sockets.iter().flatten()) {
        *row = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        count += 1;
    }
    loop {
        // SAFETY: `count` rows of `rows` are initialised, and the call writes only `revents`.
        let ready = unsafe { libc::poll(rows.as_mut_ptr(), count, millis) };
        if ready >= 0 {
            return ready > 0;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

#[cfg(windows)]
fn wait_uot_readable(sockets: &[Option<&UdpSocket>], timeout: Duration) -> bool {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{WSAPoll, POLLIN, POLLRDNORM, SOCKET, WSAPOLLFD};
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut rows = [WSAPOLLFD {
        fd: 0,
        events: 0,
        revents: 0,
    }; 2];
    let mut count = 0;
    for (row, socket) in rows.iter_mut().zip(sockets.iter().flatten()) {
        *row = WSAPOLLFD {
            fd: socket.as_raw_socket() as SOCKET,
            events: POLLIN | POLLRDNORM,
            revents: 0,
        };
        count += 1;
    }
    // SAFETY: `count` handles of `rows` are initialised, and the call writes only `revents`.
    unsafe { WSAPoll(rows.as_mut_ptr(), count, millis) > 0 }
}

#[cfg(not(any(unix, windows)))]
fn wait_uot_readable(_sockets: &[Option<&UdpSocket>], timeout: Duration) -> bool {
    std::thread::sleep(timeout);
    false
}

fn send_uot_udp(socket: &UdpSocket, payload: &[u8], target: SocketAddr, connected: bool) {
    for _ in 0..8 {
        let sent = if connected {
            socket.send(payload)
        } else {
            socket.send_to(payload, target)
        };
        let retry = match sent {
            Ok(_) => return,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::PermissionDenied
            ),
        };
        if !retry {
            return;
        }
        std::thread::sleep(crate::budgets::RELAY_POLL);
    }
}

/// One `UoT` stream from a client: read its datagrams, carry each to a fresh UDP socket, and frame
/// every reply back on the same stream. A name is resolved here, as the reference's `UoT` router does.
#[allow(clippy::too_many_lines)]
fn serve_uot_stream(stream: &NaiveStream, version: u8) {
    let (connect, fixed) = if version == 2 {
        let mut request = stream.clone();
        let Ok(request) = read_uot_request(&mut request) else {
            stream.abort();
            return;
        };
        request
    } else {
        (false, Destination::Name(String::new(), 0))
    };
    let fixed = (version == 2).then_some(fixed);
    let connected = if connect {
        fixed.as_ref().and_then(|target| match target {
            Destination::Address(address) => Some(*address),
            Destination::Name(host, port) => proxy::resolve_outbound(host, *port),
        })
    } else {
        None
    };
    if connect && connected.is_none() {
        stream.abort();
        return;
    }
    let udp4 = uot_bind("0.0.0.0:0");
    let udp6 = uot_bind("[::]:0");
    if udp4.is_none() && udp6.is_none() {
        stream.abort();
        return;
    }
    if let Some(peer) = connected {
        let socket = if peer.is_ipv4() {
            udp4.as_ref()
        } else {
            udp6.as_ref()
        };
        if socket.is_none_or(|socket| socket.connect(peer).is_err()) {
            stream.abort();
            return;
        }
    }
    let done = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let reader_done = Arc::clone(&done);
    let reader_failed = Arc::clone(&failed);
    let mut reader = stream.clone();
    let mut replies = stream.clone();
    let send4 = udp4.as_ref().and_then(|socket| socket.try_clone().ok());
    let send6 = udp6.as_ref().and_then(|socket| socket.try_clone().ok());
    let send_connected = connected.is_some();
    let fixed_peer = connected;
    let spawned = std::thread::Builder::new()
        .name("ferrox-naive-uot".to_owned())
        .spawn(move || {
            let mut packets = UotPacketReader::default();
            loop {
                if reader_done.load(Ordering::SeqCst) {
                    break;
                }
                let packet = match packets.next(&mut reader, connect, fixed.as_ref()) {
                    Ok(Some(packet)) => packet,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(crate::budgets::RELAY_POLL);
                        continue;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        reader_failed.store(true, Ordering::SeqCst);
                        break;
                    }
                };
                let (target, payload) = packet;
                let Some(target) = fixed_peer.or_else(|| match &target {
                    Destination::Address(address) => Some(*address),
                    Destination::Name(host, port) => proxy::resolve_outbound(host, *port),
                }) else {
                    continue;
                };
                let socket = if target.is_ipv4() {
                    send4.as_ref()
                } else {
                    send6.as_ref()
                };
                if let Some(socket) = socket {
                    send_uot_udp(socket, &payload, target, send_connected);
                }
            }
            reader_done.store(true, Ordering::SeqCst);
        });
    if spawned.is_err() {
        stream.abort();
        return;
    }
    let connected_socket = connected.and_then(|peer| {
        if peer.is_ipv4() {
            udp4.as_ref()
        } else {
            udp6.as_ref()
        }
    });
    let mut buf = proxy::udp_buffer();
    let mut reset = false;
    while !done.load(Ordering::SeqCst) {
        let sockets: [Option<&UdpSocket>; 2] = if connected_socket.is_some() {
            [connected_socket, None]
        } else {
            [udp4.as_ref(), udp6.as_ref()]
        };
        if !wait_uot_readable(&sockets, crate::budgets::RELAY_IDLE) {
            continue;
        }
        for socket in sockets.into_iter().flatten() {
            match socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    if write_uot_packet(
                        &mut replies,
                        connect,
                        &Destination::Address(source),
                        &buf[..n],
                    )
                    .is_err()
                    {
                        reset = true;
                        done.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
    }
    done.store(true, Ordering::SeqCst);
    if reset || failed.load(Ordering::SeqCst) {
        stream.abort();
    } else {
        stream.finish();
    }
}

#[allow(clippy::needless_pass_by_value)]
fn uot_out_reader(
    mut stream: NaiveStream,
    relay: UdpSocket,
    client: SocketAddr,
    target: Destination,
    connect: bool,
    done: Arc<AtomicBool>,
) {
    let mut packets = UotPacketReader::default();
    while !done.load(Ordering::Relaxed) {
        let packet = match packets.next(&mut stream, connect, Some(&target)) {
            Ok(Some(packet)) => packet,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(crate::budgets::RELAY_POLL);
                continue;
            }
            Ok(None) | Err(_) => break,
        };
        let (from, payload) = packet;
        let destination = if connect { target.clone() } else { from };
        let frame = uot_socks_frame(&destination, &payload);
        if let Err(error) = relay.send_to(&frame, client) {
            if !crate::tun_stack::refused(&error) {
                break;
            }
        }
    }
    done.store(true, Ordering::Relaxed);
}

#[derive(Clone)]
enum End {
    H2(H2StreamOut),
    H3(H3StreamOut),
}

struct NaiveInner {
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
    read_padding: Mutex<PaddingRead>,
    write_padding: Mutex<PaddingWrite>,
    end: Mutex<Option<End>>,
    reset_end: Mutex<Option<End>>,
    ended: AtomicBool,
    aborted: AtomicBool,
    padded: bool,
}

impl NaiveInner {
    fn finish(&self) {
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(end) = self
            .end
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        match end {
            End::H2(out) => out.end(),
            End::H3(out) => out.end(),
        }
    }

    fn abort(&self) {
        if self.aborted.swap(true, Ordering::SeqCst) {
            return;
        }
        self.ended.store(true, Ordering::SeqCst);
        let Some(end) = self
            .reset_end
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        match end {
            End::H2(out) => out.reset(),
            End::H3(out) => out.reset(),
        }
    }
}

impl Drop for NaiveInner {
    fn drop(&mut self) {
        self.finish();
    }
}

/// One `NaiveProxy` tunnel. The reader and the writer sit behind their own locks, so a parked read
/// never holds the write half; a clone shares both halves and the one end.
#[derive(Clone)]
pub(crate) struct NaiveStream {
    inner: Arc<NaiveInner>,
}

impl NaiveStream {
    fn new(reader: Reader, writer: Writer, end: End, padded: bool) -> Self {
        Self {
            inner: Arc::new(NaiveInner {
                reader: Mutex::new(reader),
                writer: Mutex::new(writer),
                read_padding: Mutex::new(PaddingRead::default()),
                write_padding: Mutex::new(PaddingWrite::default()),
                end: Mutex::new(Some(end.clone())),
                reset_end: Mutex::new(Some(end)),
                ended: AtomicBool::new(false),
                aborted: AtomicBool::new(false),
                padded,
            }),
        }
    }

    fn finish(&self) {
        self.inner.finish();
    }

    pub(crate) fn abort(&self) {
        self.inner.abort();
    }
}

impl Read for NaiveStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.inner.padded {
            return reader.read(buf);
        }
        let mut padding = self
            .inner
            .read_padding
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        padding.read(&mut **reader, buf)
    }
}

impl Write for NaiveStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.inner.padded {
            return writer.write(buf);
        }
        let mut padding = self
            .inner
            .write_padding
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        padding.write(&mut **writer, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()
    }
}

impl proxy::Duplicate for NaiveStream {
    fn duplicate(&self) -> Option<Self> {
        Some(self.clone())
    }

    fn arm_read(&self) {}
}

impl proxy::HalfShut for NaiveStream {
    fn spill(&self) {
        self.finish();
    }
}

struct H2ClientRead {
    inner: H2StreamReader,
}

impl Read for H2ClientRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        match self.inner.status() {
            Some(200) => Ok(n),
            Some(code) => Err(std::io::Error::other(format!(
                "naive: server answered {code}"
            ))),
            None if n == 0 => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "naive: no response status",
            )),
            None => Ok(n),
        }
    }
}

struct H2OutWrite {
    out: H2StreamOut,
}

impl Write for H2OutWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = std::time::Instant::now() + crate::budgets::relay_stall();
        loop {
            match self.out.data_progress(buf) {
                Ok(sent) => return Ok(sent),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                    }
                    // The wait pumps the transport, so the grant that wakes this lane is read here.
                    self.out.wait_room(crate::budgets::RELAY_POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct H3ClientRead {
    inner: H3Reader,
}

impl Read for H3ClientRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        match self.inner.status() {
            Some(200) => Ok(n),
            Some(code) => Err(std::io::Error::other(format!(
                "naive: server answered {code}"
            ))),
            None if n == 0 => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "naive: no response status",
            )),
            None => Ok(n),
        }
    }
}

struct H3OutWrite {
    out: H3StreamOut,
}

impl Write for H3OutWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.out.data(buf) {
            Ok(buf.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct BoxedWrite(Writer);

impl Write for BoxedWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl proxy::FrameWrite for BoxedWrite {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        parts
            .iter()
            .all(|part| write_all(&mut *self.0, part).is_ok())
    }
}

fn basic_token(user: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
}

fn parse_basic(value: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let space = value.iter().position(|byte| *byte == b' ')?;
    if !value[..space].eq_ignore_ascii_case(b"Basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trim_ascii(&value[space + 1..]))
        .ok()?;
    let colon = decoded.iter().position(|byte| *byte == b':')?;
    Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn verified(value: Option<&[u8]>, users: &Users) -> bool {
    let Some((user, password)) = value.and_then(parse_basic) else {
        return false;
    };
    users.iter().any(|(known_user, known_password)| {
        constant_time_eq(user.as_slice(), known_user.as_bytes())
            && constant_time_eq(password.as_slice(), known_password.as_bytes())
    })
}

fn head_field<'a>(head: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let mut lines = head.split(|byte| *byte == b'\n');
    lines.next()?;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some((field, value)) = line
            .iter()
            .position(|byte| *byte == b':')
            .map(|at| (&line[..at], &line[at + 1..]))
        else {
            continue;
        };
        if field.eq_ignore_ascii_case(name.as_bytes()) {
            return Some(trim_ascii(value));
        }
    }
    None
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn head_method(head: &[u8]) -> Option<&[u8]> {
    let line = head.split(|byte| *byte == b'\n').next()?;
    line.split(|byte| *byte == b' ').next()
}

fn connect_target(authority: &[u8]) -> Option<Destination> {
    let text = std::str::from_utf8(authority).ok()?;
    if text.eq_ignore_ascii_case(UOT_V1) || text.eq_ignore_ascii_case(UOT_V2) {
        return Some(Destination::Name(text.to_owned(), 0));
    }
    if text.parse::<SocketAddr>().is_ok() {
        return proxy::authority_target(authority);
    }
    if text.starts_with('[') {
        return None;
    }
    let (host, port) = text.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    proxy::authority_target(authority)
}

fn head_target(head: &[u8]) -> Option<Destination> {
    let authority = head_field(head, "-connect-authority")
        .filter(|value| !value.is_empty())
        .or_else(|| head_field(head, "host"))
        .filter(|value| !value.is_empty())?;
    connect_target(authority)
}

fn h2_refuse(conn: &Arc<H2Conn>, sid: u32, status: &str, end_stream: bool) {
    let Some((_, _, out)) = conn.open(sid, end_stream) else {
        conn.reset(sid);
        return;
    };
    h2_refuse_open(conn, sid, status, end_stream, &out);
}

fn h2_refuse_open(
    conn: &Arc<H2Conn>,
    sid: u32,
    status: &str,
    end_stream: bool,
    out: &crate::xhttp_h2::H2StreamOut,
) {
    let mut fields = vec![(":status", status)];
    if status == "407" {
        fields.push(("proxy-authenticate", "Basic realm=\"proxy\""));
    }
    if !conn.respond(sid, &fields) {
        out.reset();
        return;
    }
    out.end();
    if !end_stream {
        conn.reset(sid);
    }
}

struct NaiveH2Service {
    users: Users,
    freedom: bool,
}

impl H2Service for NaiveH2Service {
    fn open(&self, conn: &Arc<H2Conn>, sid: u32, block: &[u8], end_stream: bool) -> bool {
        let mut method = None;
        let mut authority = None;
        let mut connect_authority = None;
        let mut authorization = None;
        let mut padding = None;
        let decoded = conn.decode_block(block, |name, value| {
            if name.eq_ignore_ascii_case(b":method") {
                method = Some(value.to_vec());
            } else if name.eq_ignore_ascii_case(b":authority") {
                authority = Some(value.to_vec());
            } else if name.eq_ignore_ascii_case(b"-connect-authority") {
                connect_authority = Some(value.to_vec());
            } else if name.eq_ignore_ascii_case(b"proxy-authorization") {
                authorization = Some(value.to_vec());
            } else if name.eq_ignore_ascii_case(b"padding") {
                padding = Some(value.to_vec());
            }
        });
        if !decoded {
            conn.compression_error();
            return false;
        }
        if method.as_deref() != Some(b"CONNECT") || padding.as_deref().is_none_or(<[u8]>::is_empty)
        {
            h2_refuse(conn, sid, "400", end_stream);
            return false;
        }
        if !verified(authorization.as_deref(), &self.users) {
            h2_refuse(conn, sid, "407", end_stream);
            return false;
        }
        let Some(target) = connect_authority
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(authority.as_deref())
            .and_then(connect_target)
        else {
            h2_refuse(conn, sid, "400", end_stream);
            return false;
        };
        if !self.freedom {
            h2_refuse(conn, sid, "502", end_stream);
            return false;
        }
        let Some((reader, _, out)) = conn.open(sid, end_stream) else {
            conn.reset(sid);
            return false;
        };
        if let Some(version) = uot_magic(&target) {
            let padding = padding_header();
            if !conn.respond(sid, &[(":status", "200"), ("padding", &padding)]) {
                out.reset();
                return false;
            }
            let writer = H2OutWrite { out: out.clone() };
            let stream = NaiveStream::new(Box::new(reader), Box::new(writer), End::H2(out), true);
            let reset = stream.clone();
            let spawned = std::thread::Builder::new()
                .name("ferrox-naive-uot".to_owned())
                .spawn(move || serve_uot_stream(&stream, version));
            if spawned.is_err() {
                reset.abort();
                return false;
            }
            return true;
        }
        // Answer 200 only after the dial succeeds; the dial itself runs off the demux thread.
        let dial_conn = Arc::clone(conn);
        let dial_out = out.clone();
        let spawned = std::thread::Builder::new()
            .name("ferrox-naive-connect".to_owned())
            .spawn(move || {
                let Some(upstream) = dial_naive_target(&target) else {
                    h2_refuse_open(&dial_conn, sid, "502", end_stream, &dial_out);
                    return;
                };
                let padding = padding_header();
                if !dial_conn.respond(sid, &[(":status", "200"), ("padding", &padding)]) {
                    dial_out.reset();
                    return;
                }
                let writer = H2OutWrite {
                    out: dial_out.clone(),
                };
                let stream =
                    NaiveStream::new(Box::new(reader), Box::new(writer), End::H2(dial_out), true);
                proxy::relay_naive_stream(&upstream, stream);
            });
        if spawned.is_err() {
            h2_refuse_open(conn, sid, "502", end_stream, &out);
            return false;
        }
        true
    }
}

fn dial_naive_target(target: &Destination) -> Option<Connection> {
    let resolved = match target {
        Destination::Address(address) => Some(*address),
        Destination::Name(host, port) => proxy::resolve_outbound(host, *port),
    };
    resolved.and_then(|address| proxy::dial_or_report(&address))
}

fn h3_refuse(stream: &crate::quic::QuicStream, status: &str) {
    let mut writer = H3Writer::new(Wire::Server(stream.clone()));
    let head = if status.starts_with("407") {
        format!("HTTP/1.1 {status}\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")
    } else {
        format!("HTTP/1.1 {status}\r\n\r\n")
    };
    if writer.write_all(head.as_bytes()).is_err() || !stream.fin() {
        stream.close();
    } else {
        stream.shutdown_read_h3();
    }
}

fn serve_h3(stream: &crate::quic::QuicStream, users: &Users, freedom: bool) {
    stream.preface_h3();
    let mut reader = H3Reader::new(Wire::Server(stream.clone()));
    let Ok(Some(head)) = reader.read_head() else {
        stream.close();
        return;
    };
    if head_method(&head) != Some(b"CONNECT")
        || head_field(&head, "padding").is_none_or(<[u8]>::is_empty)
    {
        h3_refuse(stream, "400 Bad Request");
        return;
    }
    if !verified(head_field(&head, "proxy-authorization"), users) {
        h3_refuse(stream, "407 Proxy Authentication Required");
        return;
    }
    let Some(target) = head_target(&head) else {
        h3_refuse(stream, "400 Bad Request");
        return;
    };
    if !freedom {
        h3_refuse(stream, "502 Bad Gateway");
        return;
    }
    let uot = uot_magic(&target);
    let upstream = if uot.is_none() {
        let Some(upstream) = dial_naive_target(&target) else {
            h3_refuse(stream, "502 Bad Gateway");
            return;
        };
        Some(upstream)
    } else {
        None
    };
    let padding = padding_header();
    let mut writer = H3Writer::new(Wire::Server(stream.clone()));
    let head = format!("HTTP/1.1 200 OK\r\nPadding: {padding}\r\n\r\n");
    if writer.write_all(head.as_bytes()).is_err() {
        stream.close();
        return;
    }
    let out = H3StreamOut::new(Wire::Server(stream.clone()), stream.owner());
    let stream = NaiveStream::new(Box::new(reader), Box::new(writer), End::H3(out), true);
    if let Some(version) = uot {
        serve_uot_stream(&stream, version);
    } else if let Some(upstream) = upstream {
        proxy::relay_naive_stream(&upstream, stream);
    }
}

fn serve_h2_connection(
    stream: Connection,
    tls: Option<Arc<ferrox_core::tls::TlsServerConfig>>,
    users: Users,
    freedom: bool,
) {
    let Ok(raw) = stream.try_clone() else {
        return;
    };
    if raw
        .set_read_timeout(Some(crate::budgets::handshake()))
        .is_err()
    {
        return;
    }
    let (reader, writer): (Reader, Writer) = if let Some(identity) = tls {
        let Ok(mut session) = ferrox_core::tls::accept(identity.as_ref(), stream) else {
            return;
        };
        if session.handshake().is_err() {
            return;
        }
        if session.alpn() != Some(b"h2") {
            return;
        }
        let Some(halves) = proxy::tls_server_halves(session) else {
            return;
        };
        halves
    } else {
        let Ok(writer) = stream.try_clone() else {
            return;
        };
        (Box::new(stream), Box::new(writer))
    };
    let service = NaiveH2Service { users, freedom };
    xhttp_h2::serve_h2_service_open(reader, BoxedWrite(writer), &service, None, move || {
        let _ = raw.set_read_timeout(None);
    });
}

struct UotCancel {
    stream: NaiveStream,
    done: Arc<AtomicBool>,
    armed: bool,
}

impl UotCancel {
    fn new(stream: &NaiveStream, done: &Arc<AtomicBool>) -> Self {
        Self {
            stream: stream.clone(),
            done: Arc::clone(done),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UotCancel {
    fn drop(&mut self) {
        if self.armed {
            self.done.store(true, Ordering::Relaxed);
            self.stream.abort();
        }
    }
}

type UotOpen = Result<
    (
        (String, SocketAddr),
        NaiveStream,
        Arc<AtomicBool>,
        UotCancel,
    ),
    (String, SocketAddr),
>;

struct PendingUot {
    target: Destination,
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
}

struct UotLane {
    tx: SyncSender<Vec<u8>>,
    done: Arc<AtomicBool>,
    abort: NaiveStream,
    used: u64,
}

/// Writes one lane's packets off the receive loop: a blocked HTTP/2 send parks this lane's writer,
/// never the socket that serves every other lane.
fn uot_writer(
    mut stream: NaiveStream,
    connect: bool,
    target: &Destination,
    initial: VecDeque<Vec<u8>>,
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    done: &AtomicBool,
) {
    for packet in initial {
        if done.load(Ordering::Relaxed) {
            return;
        }
        if write_uot_packet(&mut stream, connect, target, &packet).is_err() {
            done.store(true, Ordering::Relaxed);
            stream.abort();
            return;
        }
    }
    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let Ok(packet) = rx.recv() else {
            break;
        };
        if write_uot_packet(&mut stream, connect, target, &packet).is_err() {
            done.store(true, Ordering::Relaxed);
            stream.abort();
            break;
        }
    }
}

pub(crate) struct NaiveOut {
    address: String,
    port: u16,
    token: Option<String>,
    tls: Arc<TlsConfig>,
    quic: bool,
    uot: Option<u8>,
    stream_window: Option<u64>,
    session_window: Option<u64>,
    congestion: Option<Congestion>,
    extra: Vec<(String, String)>,
    pool_limit: usize,
    h2: Mutex<Vec<Arc<H2Client>>>,
    h3: Mutex<Vec<Arc<H3Client>>>,
    h2_next: AtomicUsize,
    h3_next: AtomicUsize,
    h2_inflight: AtomicUsize,
    h3_inflight: AtomicUsize,
    h2_ready: Condvar,
    h3_ready: Condvar,
}

impl std::fmt::Debug for NaiveOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveOut")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("quic", &self.quic)
            .finish_non_exhaustive()
    }
}

impl NaiveOut {
    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        proxy::resolve_outbound(&self.address, self.port)
    }

    pub(crate) fn dial(self: &Arc<Self>, client: &Connection, target: &Destination) {
        let Some(stream) = self.open(target) else {
            return;
        };
        proxy::relay_naive_stream(client, stream);
    }

    pub(crate) fn udp_over_tcp(&self) -> bool {
        self.uot.is_some()
    }

    /// The outbound's datagram lane: one `UoT` stream per destination, framed as SOCKS5 UDP on the
    /// relay side so a `dialerProxy` hop sees the same shape as every other outbound.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn serve_udp(
        self: &Arc<Self>,
        relay: &UdpSocket,
        associate: Option<&Connection>,
        peer: Option<IpAddr>,
        stop: Option<&AtomicBool>,
    ) {
        let Some(version) = self.uot else {
            return;
        };
        let connect = version == 2;
        // The relay timeout keeps the stop flag observable even with no association to poll.
        let _ = relay.set_read_timeout(Some(crate::budgets::RELAY_POLL));
        let associate = associate.and_then(|associate| {
            associate
                .set_read_timeout(Some(crate::budgets::RELAY_POLL))
                .ok()
                .map(|()| associate)
        });
        let dial = proxy::FlowDial::capture();
        let mut lanes: HashMap<(String, SocketAddr), UotLane> = HashMap::new();
        let mut pending: HashMap<(String, SocketAddr), PendingUot> = HashMap::new();
        let (open_tx, open_rx) = std::sync::mpsc::channel::<UotOpen>();
        let closing = Arc::new(AtomicBool::new(false));
        let mut source_pin: Option<SocketAddr> = None;
        let mut buf = proxy::udp_buffer();
        let mut use_tick = 0u64;
        while stop.is_none_or(|stop| !stop.load(Ordering::Relaxed)) {
            use_tick = use_tick.wrapping_add(1);
            lanes.retain(|_, lane| {
                if lane.done.load(Ordering::Relaxed) {
                    lane.abort.abort();
                    false
                } else {
                    true
                }
            });
            while let Ok(opened) = open_rx.try_recv() {
                match opened {
                    Ok((key, stream, done, mut cancel)) => {
                        let Some(lane) = pending.remove(&key) else {
                            drop(cancel);
                            continue;
                        };
                        if closing.load(Ordering::Relaxed) {
                            drop(cancel);
                            continue;
                        }
                        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_UOT_PENDING_PACKETS);
                        let writer_stream = stream.clone();
                        let writer_done = Arc::clone(&done);
                        if done.load(Ordering::Relaxed) {
                            drop(cancel);
                            continue;
                        }
                        let PendingUot {
                            target, packets, ..
                        } = lane;
                        let writer = std::thread::Builder::new()
                            .name("ferrox-naive-uot-write".to_owned())
                            .spawn(move || {
                                uot_writer(
                                    writer_stream,
                                    connect,
                                    &target,
                                    packets,
                                    &rx,
                                    &writer_done,
                                );
                            });
                        if writer.is_err() {
                            done.store(true, Ordering::Relaxed);
                            stream.abort();
                        } else {
                            if done.load(Ordering::Relaxed) {
                                drop(cancel);
                                continue;
                            }
                            if lanes.len() >= MAX_UOT_LANES {
                                let oldest = lanes
                                    .iter()
                                    .min_by_key(|(_, lane)| lane.used)
                                    .map(|(key, _)| key.clone());
                                if let Some(oldest) = oldest {
                                    if let Some(lane) = lanes.remove(&oldest) {
                                        lane.done.store(true, Ordering::Relaxed);
                                        lane.abort.abort();
                                    }
                                }
                            }
                            lanes.insert(
                                key,
                                UotLane {
                                    tx,
                                    done,
                                    abort: stream,
                                    used: use_tick,
                                },
                            );
                            cancel.disarm();
                        }
                    }
                    Err(key) => {
                        pending.remove(&key);
                    }
                }
            }
            if associate.is_some_and(|control| control.idle_pending() && proxy::peer_left(control))
            {
                break;
            }
            let (n, source) = match relay.recv_from(&mut buf) {
                Ok(packet) => packet,
                Err(error) if proxy::is_timeout(&error) => continue,
                Err(_) => break,
            };
            if let Some(pinned) = source_pin {
                if source != pinned {
                    continue;
                }
            } else if !proxy::source_ip_ok(peer, source) {
                continue;
            }
            let Some((target, payload)) = proxy::parse_socks_udp_dest(&buf[..n]) else {
                continue;
            };
            if source_pin.is_none() {
                source_pin = Some(source);
            }
            let key = (target.authority(), source);
            if lanes
                .get(&key)
                .is_some_and(|lane| lane.done.load(Ordering::Relaxed))
            {
                if let Some(lane) = lanes.remove(&key) {
                    lane.done.store(true, Ordering::Relaxed);
                    lane.abort.abort();
                }
            }
            if !lanes.contains_key(&key) {
                if let Some(lane) = pending.get_mut(&key) {
                    if lane.packets.len() < MAX_UOT_PENDING_PACKETS
                        && lane.bytes + payload.len() <= MAX_UOT_PENDING_BYTES
                    {
                        lane.bytes += payload.len();
                        lane.packets.push_back(payload.to_vec());
                    }
                    continue;
                }
                if pending.len() >= MAX_UOT_PENDING {
                    continue;
                }
                let Ok(reply_relay) = relay.try_clone() else {
                    continue;
                };
                let mut packets = VecDeque::new();
                packets.push_back(payload.to_vec());
                pending.insert(
                    key.clone(),
                    PendingUot {
                        target: target.clone(),
                        packets,
                        bytes: payload.len(),
                    },
                );
                let tx = open_tx.clone();
                let closing = Arc::clone(&closing);
                let this = Arc::clone(self);
                let dial = dial.clone();
                let open_key = key.clone();
                let open_target = target;
                let spawned = std::thread::Builder::new()
                    .name("ferrox-naive-uot-open".to_owned())
                    .spawn(move || {
                        dial.run(|| {
                            if closing.load(Ordering::Relaxed) {
                                let _ = tx.send(Err(open_key));
                                return;
                            }
                            let magic = Destination::Name(
                                if connect { UOT_V2 } else { UOT_V1 }.to_owned(),
                                0,
                            );
                            let Some(stream) = this.open(&magic) else {
                                let _ = tx.send(Err(open_key));
                                return;
                            };
                            if closing.load(Ordering::Relaxed) {
                                stream.abort();
                                let _ = tx.send(Err(open_key));
                                return;
                            }
                            let mut writer = stream.clone();
                            if connect
                                && write_uot_request(&mut writer, true, &open_target).is_err()
                            {
                                stream.abort();
                                let _ = tx.send(Err(open_key));
                                return;
                            }
                            let done = Arc::new(AtomicBool::new(false));
                            let reader_done = Arc::clone(&done);
                            let reader_target = open_target.clone();
                            let reader_stream = writer;
                            let reader = std::thread::Builder::new()
                                .name("ferrox-naive-uot-out".to_owned())
                                .spawn(move || {
                                    uot_out_reader(
                                        reader_stream,
                                        reply_relay,
                                        source,
                                        reader_target,
                                        connect,
                                        reader_done,
                                    );
                                });
                            if reader.is_err() {
                                done.store(true, Ordering::Relaxed);
                                stream.abort();
                                let _ = tx.send(Err(open_key));
                                return;
                            }
                            let cancel = UotCancel::new(&stream, &done);
                            if let Err(error) = tx.send(Ok((open_key, stream, done, cancel))) {
                                if let Ok((_, stream, done, _cancel)) = error.0 {
                                    done.store(true, Ordering::Relaxed);
                                    stream.abort();
                                }
                            }
                        });
                    });
                if spawned.is_err() {
                    pending.remove(&key);
                }
                continue;
            }
            let failed = lanes.get_mut(&key).is_none_or(|lane| {
                lane.used = use_tick;
                if lane.done.load(Ordering::Relaxed) {
                    return true;
                }
                match lane.tx.try_send(payload.to_vec()) {
                    Ok(()) | Err(TrySendError::Full(_)) => false,
                    Err(TrySendError::Disconnected(_)) => true,
                }
            });
            if failed {
                if let Some(lane) = lanes.remove(&key) {
                    lane.done.store(true, Ordering::Relaxed);
                    lane.abort.abort();
                }
            }
        }
        closing.store(true, Ordering::Relaxed);
        for (_, lane) in lanes.drain() {
            lane.done.store(true, Ordering::Relaxed);
            lane.abort.abort();
        }
        drop(open_tx);
        while let Ok(opened) = open_rx.try_recv() {
            if let Ok((_, stream, done, _cancel)) = opened {
                done.store(true, Ordering::Relaxed);
                stream.abort();
            }
        }
        // A result that lands after the last poll must still be aborted, not dropped into `finish`.
        let _ = std::thread::Builder::new()
            .name("ferrox-naive-uot-drain".to_owned())
            .spawn(move || {
                while let Ok(opened) = open_rx.recv() {
                    if let Ok((_, stream, done, _cancel)) = opened {
                        done.store(true, Ordering::Relaxed);
                        stream.abort();
                    }
                }
            });
    }

    fn open(self: &Arc<Self>, target: &Destination) -> Option<NaiveStream> {
        if self.quic {
            return self.open_h3(target);
        }
        self.open_h2(target)
    }

    fn h2_client(self: &Arc<Self>, deadline: Instant) -> Option<Arc<H2Client>> {
        let mut pool = self.h2.lock().ok()?;
        loop {
            pool.retain(|client| {
                client.settle();
                client.reusable()
            });
            let len = pool.len();
            if len > 0 {
                let start = self.h2_next.fetch_add(1, Ordering::Relaxed);
                for offset in 0..len {
                    let at = start.wrapping_add(offset) % len;
                    if pool[at].has_capacity() {
                        return Some(Arc::clone(&pool[at]));
                    }
                }
            }
            let inflight = self.h2_inflight.load(Ordering::Relaxed);
            if pool.len() + inflight < self.pool_limit {
                self.h2_inflight.fetch_add(1, Ordering::Relaxed);
                drop(pool);
                let client = self.connect_h2();
                let mut published = self.h2.lock();
                if let Ok(pool) = published.as_mut() {
                    if let Some(client) = &client {
                        if pool.len() < self.pool_limit {
                            pool.push(Arc::clone(client));
                        }
                    }
                }
                self.h2_inflight.fetch_sub(1, Ordering::Relaxed);
                drop(published);
                self.h2_ready.notify_all();
                return client;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let (next, _) = self
                .h2_ready
                .wait_timeout(pool, left.min(crate::budgets::RELAY_POLL))
                .ok()?;
            pool = next;
        }
    }

    fn connect_h2(self: &Arc<Self>) -> Option<Arc<H2Client>> {
        let server = proxy::resolve_outbound(&self.address, self.port)?;
        let mut tls = (*self.tls).clone();
        tls.alpn = Arc::from(vec![b"h2".to_vec()]);
        let session = proxy::dial_tls_session(&server, &tls, None)?;
        let raw = Arc::new(session.get_ref().try_clone().ok()?);
        let (reader, writer) = proxy::tls_client_halves(session)?;
        H2Client::new_windowed(
            reader,
            BoxedWrite(writer),
            Some(raw),
            Some(self.stream_window.unwrap_or(H2_RECEIVE_WINDOW)),
        )
    }

    fn open_h2(self: &Arc<Self>, target: &Destination) -> Option<NaiveStream> {
        let deadline = Instant::now() + crate::budgets::handshake();
        let mut attempts = 0;
        while attempts < 2 {
            let client = self.h2_client(deadline)?;
            let block = self.h2_block(target);
            match client.open_naive_result(&block, false) {
                Ok((reader, out)) => {
                    let Some((status, padded)) = reader.wait_head() else {
                        out.reset();
                        self.discard_h2(&client);
                        attempts += 1;
                        continue;
                    };
                    if !(200..300).contains(&status) {
                        out.reset();
                        return None;
                    }
                    let reader = H2ClientRead { inner: reader };
                    let writer = H2OutWrite { out: out.clone() };
                    return Some(NaiveStream::new(
                        Box::new(reader),
                        Box::new(writer),
                        End::H2(out),
                        padded,
                    ));
                }
                Err(H2OpenError::Full) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    std::thread::sleep(left.min(crate::budgets::RELAY_POLL));
                }
                Err(_) => {
                    self.discard_h2(&client);
                    attempts += 1;
                }
            }
        }
        None
    }

    fn discard_h2(&self, client: &Arc<H2Client>) {
        if client.reusable() {
            return;
        }
        if let Ok(mut pool) = self.h2.lock() {
            pool.retain(|pooled| !Arc::ptr_eq(pooled, client));
        }
        self.h2_ready.notify_all();
    }

    fn h3_client(self: &Arc<Self>) -> Option<Arc<H3Client>> {
        let deadline = Instant::now() + crate::budgets::handshake();
        let mut pool = self.h3.lock().ok()?;
        loop {
            pool.retain(|client| client.reusable());
            let inflight = self.h3_inflight.load(Ordering::Relaxed);
            if pool.len() + inflight < self.pool_limit {
                self.h3_inflight.fetch_add(1, Ordering::Relaxed);
                drop(pool);
                let client = self.connect_h3();
                let mut published = self.h3.lock();
                if let Ok(pool) = published.as_mut() {
                    if let Some(client) = &client {
                        if pool.len() < self.pool_limit {
                            pool.push(Arc::clone(client));
                        }
                    }
                }
                self.h3_inflight.fetch_sub(1, Ordering::Relaxed);
                drop(published);
                self.h3_ready.notify_all();
                return client;
            }
            if !pool.is_empty() {
                let at = self.h3_next.fetch_add(1, Ordering::Relaxed) % pool.len();
                return Some(Arc::clone(&pool[at]));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let (next, _) = self.h3_ready.wait_timeout(pool, left).ok()?;
            pool = next;
        }
    }

    fn connect_h3(self: &Arc<Self>) -> Option<Arc<H3Client>> {
        let server = proxy::resolve_outbound(&self.address, self.port)?;
        let name = if self.tls.server_name.is_empty() {
            &self.address
        } else {
            &self.tls.server_name
        };
        H3Client::connect_windowed(
            server,
            name,
            &self.tls,
            None,
            false,
            self.congestion,
            Some(self.stream_window.unwrap_or(QUIC_STREAM_WINDOW)),
            Some(self.session_window.unwrap_or(QUIC_SESSION_WINDOW)),
        )
    }

    fn open_h3(self: &Arc<Self>, target: &Destination) -> Option<NaiveStream> {
        let deadline = Instant::now() + crate::budgets::handshake();
        let mut attempts = 0;
        while attempts < 2 {
            let client = self.h3_client()?;
            let block = self.h3_block(target);
            match client.open_block(&block, false) {
                Ok((mut reader, out)) => {
                    attempts += 1;
                    let Ok(Some((status, padded))) = reader.read_response_head() else {
                        out.reset();
                        if !client.reusable() {
                            self.discard_h3(&client);
                        }
                        continue;
                    };
                    if !(200..300).contains(&status) {
                        out.reset();
                        return None;
                    }
                    let reader = H3ClientRead { inner: reader };
                    let writer = H3OutWrite { out: out.clone() };
                    return Some(NaiveStream::new(
                        Box::new(reader),
                        Box::new(writer),
                        End::H3(out),
                        padded,
                    ));
                }
                Err(H3OpenError::Full) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    std::thread::sleep(left.min(crate::budgets::RELAY_POLL));
                }
                Err(H3OpenError::Closed) => {
                    self.discard_h3(&client);
                    attempts += 1;
                }
            }
        }
        None
    }

    fn discard_h3(&self, client: &Arc<H3Client>) {
        if client.reusable() {
            return;
        }
        if let Ok(mut pool) = self.h3.lock() {
            pool.retain(|pooled| !Arc::ptr_eq(pooled, client));
        }
    }

    fn request_fields(&self, target: &Destination) -> Vec<(String, String)> {
        let authority = target.authority();
        let mut fields = Vec::with_capacity(4 + self.extra.len());
        fields.push((":method".to_owned(), "CONNECT".to_owned()));
        fields.push((":authority".to_owned(), authority.clone()));
        if let Some(token) = &self.token {
            fields.push(("proxy-authorization".to_owned(), format!("Basic {token}")));
        }
        fields.push(("padding".to_owned(), padding_header()));
        fields.push(("-connect-authority".to_owned(), authority));
        if self.quic {
            fields.push(("-force-quic".to_owned(), "true".to_owned()));
        }
        for (name, value) in &self.extra {
            fields.push((name.to_ascii_lowercase(), value.clone()));
        }
        fields
    }

    fn h2_block(&self, target: &Destination) -> Vec<u8> {
        let fields = self.request_fields(target);
        let refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        crate::h2::block_encode(&refs)
    }

    fn h3_block(&self, target: &Destination) -> Vec<u8> {
        let fields = self.request_fields(target);
        let refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let mut block = Vec::new();
        hpack::qpack_literal_many(&refs, &mut block);
        block
    }
}

pub(crate) fn outbound(root: &Json) -> Result<Option<NaiveOut>, String> {
    let Some(list) = root.get("outbounds").and_then(Json::as_arr) else {
        return Ok(None);
    };
    let Some(first) = list
        .iter()
        .find(|item| item.get("protocol").and_then(Json::as_str) == Some("naive"))
    else {
        return Ok(None);
    };
    let settings = first.get("settings").unwrap_or(first);
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
        .ok_or("naive outbound has no server address")?;
    let port = field("port")
        .or_else(|| field("server_port"))
        .and_then(Json::as_port)
        .ok_or("naive outbound has no server port")?;
    let username = field("username").and_then(Json::as_str).unwrap_or_default();
    let password = field("password").and_then(Json::as_str).unwrap_or_default();
    let token =
        (!username.is_empty() || !password.is_empty()).then(|| basic_token(username, password));
    let tls = outbound_tls(first, address)?;
    let quic = field("quic").and_then(Json::as_bool).unwrap_or(false);
    let uot = uot_option(field("udp_over_tcp").or_else(|| field("udpOverTcp")));
    let stream_window = memory_bytes(field("stream_receive_window")).filter(|window| *window > 0);
    let session_window =
        memory_bytes(field("quic_session_receive_window")).filter(|window| *window > 0);
    let congestion = congestion_option(field("quic_congestion_control"))?;
    let pool_limit = field("insecure_concurrency")
        .and_then(Json::as_u32)
        .map_or(1, |value| {
            usize::try_from(value).unwrap_or(usize::MAX).max(1)
        });
    let extra = match field("extra_headers").or_else(|| field("extraHeaders")) {
        Some(node) => header_pairs(node)?.unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(Some(NaiveOut {
        address: address.to_owned(),
        port,
        token,
        tls,
        quic,
        uot,
        stream_window,
        session_window,
        congestion,
        extra,
        pool_limit,
        h2: Mutex::new(Vec::new()),
        h3: Mutex::new(Vec::new()),
        h2_next: AtomicUsize::new(0),
        h3_next: AtomicUsize::new(0),
        h2_inflight: AtomicUsize::new(0),
        h3_inflight: AtomicUsize::new(0),
        h2_ready: Condvar::new(),
        h3_ready: Condvar::new(),
    }))
}

fn header_pairs(node: &Json) -> Result<Option<Vec<(String, String)>>, String> {
    let Json::Obj(pairs) = node else {
        return Ok(None);
    };
    let mut headers = Vec::with_capacity(pairs.len());
    for (name, value) in pairs {
        if name.starts_with(':') {
            continue;
        }
        if connection_specific(name) {
            return Err(format!(
                "naive extra_headers `{name}` is connection-specific"
            ));
        }
        let value = match value {
            Json::Str(text) => text.clone(),
            Json::Arr(items) if items.is_empty() => continue,
            Json::Arr(items) => match items.first().and_then(Json::as_str) {
                Some(text) => text.to_owned(),
                None => continue,
            },
            _ => continue,
        };
        if !header_name_ok(name) {
            return Err(format!(
                "naive extra_headers `{name}` is not a valid HTTP field name"
            ));
        }
        if !header_value_ok(&value) {
            return Err(format!(
                "naive extra_headers `{name}` carries a control byte"
            ));
        }
        if name.eq_ignore_ascii_case("te") && !value.eq_ignore_ascii_case("trailers") {
            return Err(format!("naive extra_headers `{name}` must be `trailers`"));
        }
        headers.push((name.to_ascii_lowercase(), value));
    }
    Ok(Some(headers))
}

fn header_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn header_value_ok(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80)
}

fn connection_specific(name: &str) -> bool {
    [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|field| name.eq_ignore_ascii_case(field))
}

fn uot_option(node: Option<&Json>) -> Option<u8> {
    match node? {
        Json::Bool(true) => Some(2),
        Json::Obj(_) => {
            let node = node?;
            if !node.get("enabled").and_then(Json::as_bool).unwrap_or(false) {
                return None;
            }
            match node.get("version").and_then(Json::as_u32) {
                None | Some(0 | 2) => Some(2),
                Some(1) => Some(1),
                Some(_) => None,
            }
        }
        _ => None,
    }
}

/// A `byteformats.MemoryBytes`: a JSON number, or a string whose unit is read the way the reference
/// reads it, with the decimal units also accepted as their binary counterparts.
fn memory_bytes(node: Option<&Json>) -> Option<u64> {
    let text = match node? {
        Json::Num(value) if *value >= 0.0 => return Some(*value as u64),
        Json::Str(text) => text.trim().to_ascii_lowercase(),
        _ => return None,
    };
    let split = text
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: f64 = number.parse().ok()?;
    let multiplier = match unit.trim() {
        "" | "b" => 1.0,
        "k" | "ki" | "kb" | "kib" => 1024.0,
        "m" | "mi" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gi" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "ti" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((number * multiplier) as u64)
}

fn congestion_option(node: Option<&Json>) -> Result<Option<Congestion>, String> {
    let Some(node) = node else {
        return Ok(None);
    };
    let value = node
        .as_str()
        .ok_or("naive quic_congestion_control must be a string")?;
    match value {
        "" => Ok(None),
        "reno" => Ok(Some(Congestion::Reno)),
        "cubic" => Ok(Some(Congestion::Cubic)),
        "bbr" | "bbr2" => Ok(Some(Congestion::Bbr)),
        _ => Err(format!(
            "naive quic_congestion_control `{value}` is not a controller"
        )),
    }
}

fn inbound_congestion_option(node: Option<&Json>) -> Result<Option<Congestion>, String> {
    let Some(node) = node else {
        return Ok(None);
    };
    let value = node
        .as_str()
        .ok_or("naive quic_congestion_control must be a string")?;
    match value {
        "" => Ok(None),
        "reno" => Ok(Some(Congestion::Reno)),
        "cubic" => Ok(Some(Congestion::Cubic)),
        "bbr" => Ok(Some(Congestion::Bbr)),
        "bbr2" => Err("naive inbound does not accept bbr2".to_owned()),
        _ => Err(format!(
            "naive quic_congestion_control `{value}` is not a controller"
        )),
    }
}

fn outbound_tls(outbound: &Json, address: &str) -> Result<Arc<TlsConfig>, String> {
    if outbound.get("streamSettings").is_some() {
        return crate::config::outbound_tls(outbound, address);
    }
    let tls = outbound.get("tls").ok_or("naive outbound has no TLS")?;
    if !tls.get("enabled").and_then(Json::as_bool).unwrap_or(true) {
        return Err("naive outbound requires TLS".to_owned());
    }
    let server_name = tls
        .get("server_name")
        .or_else(|| tls.get("serverName"))
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(address)
        .to_owned();
    let insecure = tls.get("insecure").and_then(Json::as_bool).unwrap_or(false);
    let roots = if insecure {
        Arc::from(Vec::new())
    } else {
        crate::quic::system_roots()
    };
    Ok(Arc::new(TlsConfig {
        server_name,
        insecure,
        roots,
        ..TlsConfig::default()
    }))
}

/// The same listener identity pinned to the one ALPN its transport serves: `h2` on TCP and `h3` on
/// QUIC, whatever list the block carried for the other half.
fn identity_with_alpn(
    identity: &ferrox_core::tls::TlsServerConfig,
    alpn: &[u8],
) -> ferrox_core::tls::TlsServerConfig {
    let mut identity = identity.clone();
    identity.alpn = vec![alpn.to_vec()];
    identity
}

fn inbound_users(inbound: &Json, settings: Option<&Json>) -> Result<Users, String> {
    let mut users = Vec::new();
    for node in [settings, Some(inbound)].into_iter().flatten() {
        let Some(list) = node.get("users").and_then(Json::as_arr) else {
            continue;
        };
        for user in list {
            let username = user
                .get("username")
                .or_else(|| user.get("name"))
                .and_then(Json::as_str)
                .unwrap_or_default();
            let password = user
                .get("password")
                .and_then(Json::as_str)
                .unwrap_or_default();
            if !password.is_empty() {
                if username.contains(':') {
                    return Err(format!(
                        "naive inbound user `{username}` contains `:`, which Basic authentication cannot carry"
                    ));
                }
                users.push((username.to_owned(), password.to_owned()));
            }
        }
    }
    if users.is_empty() {
        if let Some(settings) = settings {
            let username = settings
                .get("username")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let password = settings
                .get("password")
                .and_then(Json::as_str)
                .unwrap_or_default();
            if !password.is_empty() {
                if username.contains(':') {
                    return Err(format!(
                        "naive inbound user `{username}` contains `:`, which Basic authentication cannot carry"
                    ));
                }
                users.push((username.to_owned(), password.to_owned()));
            }
        }
    }
    Ok(Arc::new(users))
}

/// The listeners this inbound opens, for the dynamic path's all-or-nothing bind: QUIC is a UDP
/// listener and only TLS serves it, while a plaintext inbound is the HTTP/2 door alone.
pub(crate) fn inbound_sockets(inbound: &Json) -> (bool, bool) {
    let settings = inbound.get("settings");
    let security = crate::config::stream_security(inbound);
    if security != "tls" && !security.is_empty() && security != "none" {
        return (false, false);
    }
    let (tcp, mut udp) = inbound_networks(inbound, settings).unwrap_or((false, false));
    if security != "tls" {
        if !tcp {
            return (false, false);
        }
        udp = false;
    }
    (tcp, udp)
}

fn inbound_networks(inbound: &Json, settings: Option<&Json>) -> Result<(bool, bool), String> {
    let node = settings
        .and_then(|settings| settings.get("network"))
        .or_else(|| inbound.get("network"));
    let Some(node) = node else {
        return Ok((true, true));
    };
    let mut tcp = false;
    let mut udp = false;
    match node {
        Json::Str(name) => match name.as_str() {
            "tcp" => tcp = true,
            "udp" | "quic" => udp = true,
            _ => {
                return Err(format!(
                    "naive inbound network `{name}` is not tcp, udp, or quic"
                ))
            }
        },
        Json::Arr(items) => {
            for item in items {
                match item.as_str() {
                    Some("tcp") => tcp = true,
                    Some("udp" | "quic") => udp = true,
                    Some(name) => {
                        return Err(format!(
                            "naive inbound network `{name}` is not tcp, udp, or quic"
                        ))
                    }
                    None => {
                        return Err("naive inbound network list must contain strings".to_owned())
                    }
                }
            }
        }
        _ => return Err("naive inbound network must be a string or list".to_owned()),
    }
    if !tcp && !udp {
        return Err("naive inbound network names no listener".to_owned());
    }
    Ok((tcp, udp))
}

fn inbound_config(inbound: &Json) -> Result<(Users, (bool, bool)), String> {
    let settings = inbound.get("settings");
    let users = inbound_users(inbound, settings)?;
    if users.is_empty() {
        return Err("naive inbound names no users".to_owned());
    }
    let security = crate::config::stream_security(inbound);
    if !matches!(security, "" | "none" | "tls") {
        return Err(format!(
            "naive inbound asks for `{security}`: serves nothing"
        ));
    }
    let (tcp, udp) = inbound_networks(inbound, settings)?;
    if udp && !tcp && security != "tls" {
        return Err("naive inbound asks for QUIC without TLS: serves nothing".to_owned());
    }
    Ok((users, (tcp, udp)))
}

pub(crate) fn validate_inbound(inbound: &Json) -> Result<(), String> {
    inbound_config(inbound).map(|_| ())
}

struct ListenerExit {
    left: Arc<AtomicUsize>,
    stop: Option<Arc<proxy::Stop>>,
    committed: Arc<AtomicBool>,
}

impl Drop for ListenerExit {
    fn drop(&mut self) {
        if self.committed.load(Ordering::SeqCst) && self.left.fetch_sub(1, Ordering::SeqCst) == 1 {
            if let Some(stop) = &self.stop {
                stop.mark_closed();
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StartState {
    Waiting,
    Serve,
    Abort,
}

struct StartGate {
    state: Mutex<StartState>,
    ready: Condvar,
}

impl StartGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(StartState::Waiting),
            ready: Condvar::new(),
        }
    }

    fn wait(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while *state == StartState::Waiting {
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *state == StartState::Serve
    }

    fn release(&self, serve: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = if serve {
            StartState::Serve
        } else {
            StartState::Abort
        };
        drop(state);
        self.ready.notify_all();
    }
}

type Start = Box<dyn FnOnce(ListenerExit, Arc<StartGate>) + Send>;

fn tcp_start(
    address: &str,
    path: &str,
    users: Users,
    identity: Option<Arc<ferrox_core::tls::TlsServerConfig>>,
    freedom: bool,
    halted: Arc<AtomicBool>,
    stop: Option<Arc<proxy::Stop>>,
) -> Option<Start> {
    let target = match crate::conn::parse_target(address) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("naive inbound in {path} cannot resolve {address}: {error}");
            return None;
        }
    };
    let listener = match crate::conn::Listener::bind(&target) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("naive inbound in {path} cannot listen on {address}: {error}");
            return None;
        }
    };
    Some(Box::new(move |exit, gate| {
        if !gate.wait() {
            return;
        }
        for stream in listener.incoming() {
            if halted.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else {
                continue;
            };
            let users = Arc::clone(&users);
            let identity = identity.clone();
            let session = stop.as_ref().and_then(|stop| stop.track_session(&stream));
            let _ = std::thread::Builder::new()
                .name("ferrox-naive-h2".to_owned())
                .spawn(move || {
                    let _session = session;
                    serve_h2_connection(stream, identity, users, freedom);
                });
        }
        drop(listener);
        drop(exit);
    }))
}

fn quic_start(
    address: &str,
    path: &str,
    users: Users,
    identity: &ferrox_core::tls::TlsServerConfig,
    freedom: bool,
    congestion: Option<Congestion>,
    halted: Arc<AtomicBool>,
) -> Option<Start> {
    let Some(mut config) = crate::quic::serve_config(identity) else {
        eprintln!("unreadable naive QUIC identity in {path}: serves nothing");
        return None;
    };
    crate::quic::apply_lane_congestion(&mut config, congestion, None)?;
    let sock = match crate::quic::bind_datagram_plain(address) {
        Ok(sock) => sock,
        Err(error) => {
            eprintln!("naive inbound in {path} cannot bind QUIC on {address}: {error}");
            return None;
        }
    };
    Some(Box::new(move |exit, gate| {
        if !gate.wait() {
            return;
        }
        let serve: crate::quic::Serve = Arc::new(move |stream| {
            serve_h3(&stream, &users, freedom);
        });
        crate::quic::serve_loop(
            crate::quic::Datagram::plain(sock),
            &Arc::new(Mutex::new(config)),
            &serve,
            &halted,
        );
        drop(exit);
    }))
}

pub(crate) fn serve_inbound(
    address: &str,
    inbound: &Json,
    path: &str,
    freedom: bool,
    stop: Option<&Arc<proxy::Stop>>,
) -> usize {
    let settings = inbound.get("settings");
    let (users, (tcp, mut udp)) = match inbound_config(inbound) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("naive inbound in {path}: {error}");
            return 0;
        }
    };
    let security = crate::config::stream_security(inbound);
    let identity = if security == "tls" {
        let Some(identity) = crate::config::inbound_tls_identity(inbound) else {
            eprintln!("unreadable naive tls identity in {path}: serves nothing");
            return 0;
        };
        Some(identity)
    } else if security.is_empty() || security == "none" {
        None
    } else {
        eprintln!("naive inbound in {path} asks for `{security}`: serves nothing");
        return 0;
    };
    let tcp_identity = identity
        .as_ref()
        .map(|identity| Arc::new(identity_with_alpn(identity, b"h2")));
    let quic_identity = identity
        .as_ref()
        .map(|identity| Arc::new(identity_with_alpn(identity, b"h3")));
    let congestion = match inbound_congestion_option(
        settings
            .and_then(|settings| settings.get("quic_congestion_control"))
            .or_else(|| inbound.get("quic_congestion_control")),
    ) {
        Ok(congestion) => congestion.or(Some(Congestion::Bbr)),
        Err(error) => {
            eprintln!("naive inbound in {path}: {error}");
            return 0;
        }
    };
    if identity.is_none() {
        if !tcp {
            eprintln!("naive inbound in {path} asks for QUIC without TLS: serves nothing");
            return 0;
        }
        eprintln!("naive inbound in {path} has no TLS: serves plaintext HTTP/2");
        udp = false;
    }
    if !tcp && !udp {
        eprintln!("naive inbound in {path} names no network: serves nothing");
        return 0;
    }
    let halted = stop
        .as_ref()
        .map_or_else(|| Arc::new(AtomicBool::new(false)), |stop| stop.shared());
    let mut starts: Vec<Start> = Vec::new();
    if tcp {
        let Some(start) = tcp_start(
            address,
            path,
            Arc::clone(&users),
            tcp_identity.clone(),
            freedom,
            Arc::clone(&halted),
            stop.cloned(),
        ) else {
            return 0;
        };
        starts.push(start);
    }
    if udp {
        let Some(identity) = quic_identity else {
            eprintln!("naive inbound in {path} asks for QUIC without TLS: serves nothing");
            return 0;
        };
        let Some(start) = quic_start(
            address,
            path,
            Arc::clone(&users),
            identity.as_ref(),
            freedom,
            congestion,
            Arc::clone(&halted),
        ) else {
            return 0;
        };
        starts.push(start);
    }
    if starts.is_empty() {
        return 0;
    }
    start_workers(starts, path, stop)
}

fn start_workers(starts: Vec<Start>, path: &str, stop: Option<&Arc<proxy::Stop>>) -> usize {
    let total = starts.len();
    let left = Arc::new(AtomicUsize::new(0));
    let committed = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(StartGate::new());
    let mut workers = Vec::with_capacity(total);
    for start in starts {
        let exit = ListenerExit {
            left: Arc::clone(&left),
            stop: stop.cloned(),
            committed: Arc::clone(&committed),
        };
        let worker_gate = Arc::clone(&gate);
        match std::thread::Builder::new()
            .name("ferrox-naive-listen".to_owned())
            .spawn(move || start(exit, worker_gate))
        {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                eprintln!("naive inbound in {path} cannot start a listener: {error}");
                gate.release(false);
                for worker in workers {
                    let _ = worker.join();
                }
                return 0;
            }
        }
    }
    left.store(total, Ordering::SeqCst);
    committed.store(true, Ordering::SeqCst);
    gate.release(true);
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_staged_listener_does_not_close_the_shared_stop() {
        let stop = Arc::new(proxy::Stop::new());
        stop.expect_listeners(1);
        let left = Arc::new(AtomicUsize::new(1));
        drop(ListenerExit {
            left: Arc::clone(&left),
            stop: Some(Arc::clone(&stop)),
            committed: Arc::new(AtomicBool::new(false)),
        });
        assert!(!stop.is_closed(), "a worker that never served is not owed");
        assert_eq!(left.load(Ordering::SeqCst), 1);
        drop(ListenerExit {
            left,
            stop: Some(Arc::clone(&stop)),
            committed: Arc::new(AtomicBool::new(true)),
        });
        assert!(stop.is_closed());
    }

    #[test]
    fn a_committed_address_closes_only_after_both_listeners_exit() {
        let stop = Arc::new(proxy::Stop::new());
        stop.expect_listeners(1);
        let left = Arc::new(AtomicUsize::new(2));
        let committed = Arc::new(AtomicBool::new(true));
        drop(ListenerExit {
            left: Arc::clone(&left),
            stop: Some(Arc::clone(&stop)),
            committed: Arc::clone(&committed),
        });
        assert!(!stop.is_closed(), "the tcp listener still holds its socket");
        drop(ListenerExit {
            left,
            stop: Some(Arc::clone(&stop)),
            committed,
        });
        assert!(stop.is_closed());
    }

    fn padded(payload: &[u8], padding: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.push(padding);
        out.extend_from_slice(payload);
        out.extend(std::iter::repeat_n(0, usize::from(padding)));
        out
    }

    #[test]
    fn a_padding_header_is_the_reference_shape() {
        for _ in 0..64 {
            let header = padding_header();
            assert!((30..=61).contains(&header.len()));
            assert!(header.as_bytes()[..16]
                .iter()
                .all(|byte| PADDING_ALPHABET.contains(byte)));
            assert!(header.as_bytes()[16..].iter().all(|byte| *byte == b'~'));
        }
    }

    #[test]
    fn eight_writes_are_framed_then_raw() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&written));
        let mut padding = PaddingWrite::default();
        for _ in 0..8 {
            assert_eq!(padding.write(&mut sink, b"abc").expect("writes"), 3);
        }
        padding.write(&mut sink, b"tail").expect("writes");
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        let mut at = 0;
        for _ in 0..8 {
            assert_eq!(&bytes[at..at + 2], &3u16.to_be_bytes());
            let zeros = usize::from(bytes[at + 2]);
            assert_eq!(&bytes[at + 3..at + 6], b"abc");
            assert!(bytes[at + 6..at + 6 + zeros].iter().all(|byte| *byte == 0));
            at += 6 + zeros;
        }
        assert_eq!(&bytes[at..], b"tail");
    }

    #[test]
    fn a_write_that_spans_record_eight_turns_the_rest_raw() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&written));
        let mut padding = PaddingWrite::default();
        for _ in 0..7 {
            assert_eq!(padding.write(&mut sink, b"abc").expect("writes"), 3);
        }
        let data = vec![7u8; MAX_PADDING_CHUNK + 3];
        assert_eq!(padding.write(&mut sink, &data).expect("writes"), data.len());
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        let mut at = 0;
        for _ in 0..7 {
            at += 6 + usize::from(bytes[at + 2]);
        }
        assert_eq!(
            &bytes[at..at + 2],
            &(MAX_PADDING_CHUNK as u16).to_be_bytes()
        );
        at += 3 + MAX_PADDING_CHUNK + usize::from(bytes[at + 2]);
        assert_eq!(&bytes[at..], &data[MAX_PADDING_CHUNK..]);
    }

    #[test]
    fn a_chunk_over_the_u16_bound_is_split_into_records() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&written));
        let mut padding = PaddingWrite::default();
        let data = vec![7u8; MAX_PADDING_CHUNK + 3];
        assert_eq!(padding.write(&mut sink, &data).expect("writes"), data.len());
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        let first = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(usize::from(first), MAX_PADDING_CHUNK);
        let second = 3 + MAX_PADDING_CHUNK + usize::from(bytes[2]);
        assert_eq!(u16::from_be_bytes([bytes[second], bytes[second + 1]]), 3);
    }

    #[test]
    fn eight_reads_skip_their_padding_then_pass_through() {
        let mut bytes = Vec::new();
        for i in 0..8u8 {
            bytes.extend(padded(&[i, i + 1], i));
        }
        bytes.extend_from_slice(b"tail");
        let mut reader = std::io::Cursor::new(bytes);
        let mut padding = PaddingRead::default();
        let mut got = Vec::new();
        let mut buf = [0u8; 4];
        for i in 0..8u8 {
            let n = padding.read(&mut reader, &mut buf).expect("reads");
            assert_eq!(&buf[..n], &[i, i + 1]);
            got.extend_from_slice(&buf[..n]);
        }
        let n = padding.read(&mut reader, &mut buf).expect("reads");
        assert_eq!(&buf[..n], b"tail");
        assert_eq!(got.len(), 16);
    }

    #[test]
    fn a_zero_length_record_does_not_stall_the_next_one() {
        let mut bytes = padded(&[], 2);
        for _ in 0..7 {
            bytes.extend(padded(b"hi", 0));
        }
        bytes.extend_from_slice(b"tail");
        let mut reader = std::io::Cursor::new(bytes);
        let mut padding = PaddingRead::default();
        let mut buf = [0u8; 4];
        for _ in 0..7 {
            assert_eq!(padding.read(&mut reader, &mut buf).expect("reads"), 2);
            assert_eq!(&buf[..2], b"hi");
        }
        assert_eq!(padding.read(&mut reader, &mut buf).expect("reads"), 4);
        assert_eq!(&buf, b"tail");
    }

    #[test]
    fn an_empty_read_takes_nothing_from_the_padding_stream() {
        let mut reader = std::io::Cursor::new(padded(b"hi", 1));
        let mut padding = PaddingRead::default();
        assert_eq!(padding.read(&mut reader, &mut []).expect("reads"), 0);
        assert_eq!(reader.position(), 0);
    }

    struct Trickle {
        inner: std::io::Cursor<Vec<u8>>,
        block: bool,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.block {
                self.block = false;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.block = true;
            let take = buf.len().min(1);
            self.inner.read(&mut buf[..take])
        }
    }

    #[test]
    fn a_padding_read_resumes_across_would_block() {
        let mut bytes = Vec::new();
        for i in 0..8u8 {
            bytes.extend(padded(&[i], i));
        }
        bytes.extend_from_slice(b"tail");
        let mut reader = Trickle {
            inner: std::io::Cursor::new(bytes),
            block: false,
        };
        let mut padding = PaddingRead::default();
        let mut got = Vec::new();
        let mut buf = [0u8; 4];
        loop {
            match padding.read(&mut reader, &mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("unexpected read error: {error}"),
            }
        }
        assert_eq!(got, b"\x00\x01\x02\x03\x04\x05\x06\x07tail");
    }

    #[test]
    fn a_short_read_leaves_the_rest_of_the_record_for_the_next_call() {
        let mut reader = std::io::Cursor::new(padded(b"abcd", 2));
        let mut padding = PaddingRead::default();
        let mut one = [0u8; 1];
        assert_eq!(padding.read(&mut reader, &mut one).expect("reads"), 1);
        assert_eq!(&one, b"a");
        let mut rest = [0u8; 8];
        let n = padding.read(&mut reader, &mut rest).expect("reads");
        assert_eq!(&rest[..n], b"bcd");
    }

    #[test]
    fn a_truncated_payload_is_not_a_clean_half_close() {
        let mut bytes = padded(b"abcd", 0);
        bytes.truncate(5);
        let mut reader = std::io::Cursor::new(bytes);
        let mut padding = PaddingRead::default();
        let mut buf = [0u8; 8];
        assert_eq!(padding.read(&mut reader, &mut buf).expect("reads"), 2);
        assert_eq!(
            padding
                .read(&mut reader, &mut buf)
                .expect_err("truncated")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn eof_between_records_is_clean() {
        let mut reader = std::io::Cursor::new(padded(b"hi", 1));
        let mut padding = PaddingRead::default();
        let mut buf = [0u8; 8];
        assert_eq!(padding.read(&mut reader, &mut buf).expect("reads"), 2);
        assert_eq!(padding.read(&mut reader, &mut buf).expect("eof"), 0);
    }

    #[test]
    fn basic_auth_accepts_only_the_known_pair() {
        let users = Arc::new(vec![("alice".to_owned(), "s3cret".to_owned())]);
        let token = basic_token("alice", "s3cret");
        assert!(verified(Some(format!("Basic {token}").as_bytes()), &users));
        assert!(verified(Some(format!("basic {token}").as_bytes()), &users));
        assert!(verified(Some(format!("BaSiC {token}").as_bytes()), &users));
        assert!(!verified(
            Some(format!("Basic {}", basic_token("alice", "wrong")).as_bytes()),
            &users
        ));
        assert!(!verified(Some(b"Basic !!!"), &users));
        assert!(!verified(None, &users));
    }

    #[test]
    fn connect_targets_need_an_explicit_port_except_for_uot_magic() {
        assert_eq!(connect_target(b"example.test"), None);
        assert_eq!(
            connect_target(b"example.test:443"),
            Some(Destination::Name("example.test".to_owned(), 443))
        );
        assert_eq!(
            connect_target(b"[2001:db8::1]:443"),
            Some(Destination::Address(
                "[2001:db8::1]:443".parse().expect("addr")
            ))
        );
        assert_eq!(connect_target(b"[2001:db8::1]"), None);
        assert_eq!(
            connect_target(UOT_V2.as_bytes()),
            Some(Destination::Name(UOT_V2.to_owned(), 0))
        );
    }

    #[test]
    fn the_head_keeps_the_connect_authority() {
        let head =
            b"CONNECT example.test:443 HTTP/3\r\nHost: example.test:443\r\nPadding: x\r\n\r\n";
        assert_eq!(head_method(head), Some(b"CONNECT".as_slice()));
        assert_eq!(
            head_target(head),
            Some(Destination::Name("example.test".to_owned(), 443))
        );
        let head =
            b"CONNECT ignored HTTP/3\r\nHost: h.test:80\r\n-connect-authority: a.test:8443\r\n\r\n";
        assert_eq!(
            head_target(head),
            Some(Destination::Name("a.test".to_owned(), 8443))
        );
    }

    #[cfg(unix)]
    #[test]
    fn h2_server_refuses_a_bad_credential_with_407() {
        use std::os::unix::net::UnixStream;

        let (client, server) = UnixStream::pair().expect("pair");
        let users = Arc::new(vec![("alice".to_owned(), "s3cret".to_owned())]);
        let service = NaiveH2Service {
            users,
            freedom: true,
        };
        let server_read = server.try_clone().expect("clone");
        let server_write = server.try_clone().expect("clone");
        std::thread::spawn(move || {
            crate::xhttp_h2::serve_h2_service(
                server_read,
                BoxedWrite(Box::new(server_write)),
                &service,
                None,
            );
        });

        let client_read = client.try_clone().expect("clone");
        let client_write = client.try_clone().expect("clone");
        let h2 =
            H2Client::new(client_read, BoxedWrite(Box::new(client_write)), None).expect("client");
        let block = crate::h2::block_encode(&[
            (":method", "CONNECT"),
            (":authority", "example.test:443"),
            ("-connect-authority", "example.test:443"),
            ("proxy-authorization", "Basic wrong"),
            ("padding", "x"),
        ]);
        let (mut reader, out) = h2.open_naive_result(&block, false).expect("stream");
        let mut one = [0u8; 1];
        let _ = reader.read(&mut one);
        assert_eq!(reader.status(), Some(407));
        out.end();
        h2.close();
    }

    #[test]
    fn uot_names_the_version_it_magic_addresses() {
        assert_eq!(uot_magic(&Destination::Name(UOT_V2.to_owned(), 0)), Some(2));
        assert_eq!(uot_magic(&Destination::Name(UOT_V1.to_owned(), 0)), Some(1));
        assert_eq!(
            uot_magic(&Destination::Name("example.test".to_owned(), 443)),
            None
        );
    }

    #[test]
    fn uot_addresses_round_trip_in_the_reference_families() {
        let targets = [
            Destination::Address("192.0.2.1:53".parse().expect("addr")),
            Destination::Address("[2001:db8::1]:443".parse().expect("addr")),
            Destination::Name("example.test".to_owned(), 8443),
        ];
        for target in targets {
            let mut bytes = Vec::new();
            push_uot_addr(&mut bytes, &target);
            assert_eq!(bytes.len(), target.addr_len() + 2);
            let mut reader = std::io::Cursor::new(bytes);
            assert_eq!(read_uot_addr(&mut reader).expect("reads"), target);
        }
    }

    #[test]
    fn uot_v2_connect_frames_only_the_length_and_payload() {
        let target = Destination::Address("192.0.2.1:53".parse().expect("addr"));
        let mut bytes = Vec::new();
        write_uot_packet(&mut bytes, true, &target, b"hi").expect("writes");
        assert_eq!(bytes, b"\0\x02hi");
        let mut reader = std::io::Cursor::new(bytes);
        assert_eq!(
            read_uot_packet(&mut reader, true, Some(&target)).expect("reads"),
            (target, b"hi".to_vec())
        );
    }

    #[test]
    fn uot_v1_frames_the_address_on_every_datagram() {
        let target = Destination::Address("192.0.2.1:53".parse().expect("addr"));
        let mut bytes = Vec::new();
        write_uot_packet(&mut bytes, false, &target, b"hi").expect("writes");
        assert_eq!(bytes, b"\0\xc0\x00\x02\x01\0\x35\0\x02hi");
        let mut reader = std::io::Cursor::new(bytes);
        assert_eq!(
            read_uot_packet(&mut reader, false, None).expect("reads"),
            (target, b"hi".to_vec())
        );
    }

    #[test]
    fn uot_requests_carry_the_connect_flag_and_socks_destination() {
        let target = Destination::Name("example.test".to_owned(), 443);
        let mut bytes = Vec::new();
        write_uot_request(&mut bytes, true, &target).expect("writes");
        assert_eq!(
            bytes, b"\x01\x03\x0cexample.test\x01\xbb",
            "the request names the destination with SOCKS types, not UoT datagram families"
        );
        let mut reader = std::io::Cursor::new(bytes);
        assert_eq!(
            read_uot_request(&mut reader).expect("reads"),
            (true, target)
        );
    }

    #[test]
    fn congestion_names_are_validated_per_role() {
        let text = |value: &str| Some(Json::Str(value.to_owned()));
        assert_eq!(congestion_option(text("").as_ref()).expect("empty"), None);
        assert_eq!(
            congestion_option(text("bbr2").as_ref()).expect("bbr2"),
            Some(Congestion::Bbr)
        );
        assert!(congestion_option(text("bogus").as_ref()).is_err());
        assert_eq!(
            inbound_congestion_option(text("").as_ref()).expect("empty"),
            None
        );
        assert!(inbound_congestion_option(text("bbr2").as_ref()).is_err());
        assert!(inbound_congestion_option(text("bogus").as_ref()).is_err());
    }

    #[test]
    fn extra_headers_skip_empty_arrays_and_refuse_connection_fields() {
        let empty = crate::json::parse(r#"{"X-Custom": "ok", "Empty": []}"#).expect("parses");
        assert_eq!(
            header_pairs(&empty).expect("reads"),
            Some(vec![("x-custom".to_owned(), "ok".to_owned())])
        );
        let forbidden = crate::json::parse(r#"{"X-Custom": "ok", "Connection": "keep-alive"}"#)
            .expect("parses");
        assert!(header_pairs(&forbidden).is_err());
        let spaced = crate::json::parse(r#"{"X Trace": "enabled"}"#).expect("parses");
        assert!(header_pairs(&spaced).is_err());
        let control = crate::json::parse(r#"{"X-Custom": "ok\r\nInjected: yes"}"#).expect("parses");
        assert!(header_pairs(&control).is_err());
    }

    #[test]
    fn memory_bytes_reads_the_units_the_reference_reads() {
        let value = |text: &str| memory_bytes(Some(&Json::Str(text.to_owned())));
        assert_eq!(value("1024"), Some(1024));
        assert_eq!(value("1k"), Some(1024));
        assert_eq!(value("1.5MiB"), Some(1_572_864));
        assert_eq!(value("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(value("1x"), None);
    }

    #[test]
    fn an_outbound_carries_uot_windows_and_congestion() {
        let tls =
            r#""streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": true}}"#;
        let root = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "naive", "settings": {{"address": "a.test", "port": 443, "username": "u", "password": "p", "quic": true, "udp_over_tcp": true, "stream_receive_window": "6MiB", "quic_session_receive_window": "15MiB", "quic_congestion_control": "bbr2"}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&root).expect("builds").expect("naive");
        assert_eq!(parsed.uot, Some(2));
        assert_eq!(parsed.stream_window, Some(6 * 1024 * 1024));
        assert_eq!(parsed.session_window, Some(15 * 1024 * 1024));
        assert!(matches!(parsed.congestion, Some(Congestion::Bbr)));
        assert!(parsed.udp_over_tcp());
    }

    #[test]
    fn uot_accepts_both_the_boolean_and_the_version_object() {
        assert_eq!(uot_option(Some(&Json::Bool(true))), Some(2));
        assert_eq!(uot_option(Some(&Json::Bool(false))), None);
        let object = |text: &str| uot_option(Some(&crate::json::parse(text).expect("parses")));
        assert_eq!(object(r#"{"enabled": true}"#), Some(2));
        assert_eq!(object(r#"{"enabled": true, "version": 1}"#), Some(1));
        assert_eq!(object(r#"{"enabled": true, "version": 0}"#), Some(2));
        assert_eq!(object(r#"{"version": 1}"#), None);
    }

    #[test]
    fn outbound_spellings_parse() {
        let tls =
            r#""streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": true}}"#;
        let nested = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "naive", "settings": {{"servers": [{{"address": "a.test", "port": 443, "username": "u", "password": "p"}}]}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&nested).expect("builds").expect("naive");
        assert_eq!(parsed.address, "a.test");
        assert_eq!(parsed.port, 443);
        assert_eq!(
            parsed.token.as_deref(),
            Some(basic_token("u", "p").as_str())
        );
        assert!(!parsed.quic);

        let flat = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "naive", "settings": {{"address": "b.test", "port": 8443, "username": "u", "password": "p", "quic": true, "insecure_concurrency": 4}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&flat).expect("builds").expect("naive");
        assert_eq!(parsed.address, "b.test");
        assert_eq!(parsed.port, 8443);
        assert!(parsed.quic);
        assert_eq!(parsed.pool_limit, 4);

        let password_only = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "naive", "settings": {{"address": "c.test", "port": 443, "password": "p"}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&password_only).expect("builds").expect("naive");
        assert_eq!(parsed.token.as_deref(), Some(basic_token("", "p").as_str()));

        let neither = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "naive", "settings": {{"address": "d.test", "port": 443}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&neither).expect("builds").expect("naive");
        assert_eq!(parsed.token, None);
    }

    #[test]
    fn a_naive_outbound_without_tls_is_refused() {
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "naive", "settings": {"address": "a.test", "port": 80}}]}"#,
        )
        .expect("parses");
        assert!(outbound(&plain).is_err());
    }

    #[test]
    fn inbound_sockets_follow_the_network_and_tls() {
        let plain = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}]}}"#,
        )
        .expect("parses");
        assert_eq!(inbound_sockets(&plain), (true, false));
        let tls = crate::json::parse(
            r#"{"protocol": "naive", "streamSettings": {"security": "tls"}, "settings": {"users": [{"username": "u", "password": "p"}]}}"#,
        )
        .expect("parses");
        assert_eq!(inbound_sockets(&tls), (true, true));
        let udp = crate::json::parse(
            r#"{"protocol": "naive", "streamSettings": {"security": "tls"}, "settings": {"network": "udp"}}"#,
        )
        .expect("parses");
        assert_eq!(inbound_sockets(&udp), (false, true));
        let plain_udp = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}], "network": "udp"}}"#,
        )
        .expect("parses");
        assert_eq!(inbound_sockets(&plain_udp), (false, false));
        assert!(validate_inbound(&plain_udp).is_err());
    }

    #[test]
    fn the_tcp_listener_advertises_only_h2() {
        use ferrox_core::tls::{TlsConfig, TlsProvider as _};
        let minted = rcgen::generate_simple_self_signed(vec!["naive.test".to_owned()])
            .expect("mints a certificate");
        let pem = |pem: &str| {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"alpn": ["http/1.1"], "certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            pem(&minted.cert.pem()),
            pem(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        let identity = crate::config::inbound_tls_identity(&config).expect("loads");
        let identity = Arc::new(identity_with_alpn(&identity, b"h2"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = ferrox_core::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert_eq!(server.alpn(), Some(b"h2".as_slice()));
            });
            let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let config = TlsConfig {
                server_name: "naive.test".to_owned(),
                alpn: vec![b"http/1.1".to_vec(), b"h2".to_vec()].into(),
                roots: vec![minted.cert.der().as_ref().to_vec()].into(),
                ..TlsConfig::default()
            };
            let mut client = ferrox_core::tls::connect(&config, stream).expect("configures");
            client.handshake().expect("handshakes");
            assert_eq!(client.alpn(), Some(b"h2".as_slice()));
        });
    }

    #[test]
    fn inbound_users_and_networks_parse() {
        let inbound = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}], "network": "tcp"}}"#,
        )
        .expect("parses");
        let settings = inbound.get("settings");
        let users = inbound_users(&inbound, settings).expect("users");
        assert_eq!(users.len(), 1);
        assert_eq!(
            inbound_networks(&inbound, settings).expect("networks"),
            (true, false)
        );

        let top = crate::json::parse(
            r#"{"protocol": "naive", "users": [{"username": "u", "password": "p"}], "network": ["tcp", "udp"]}"#,
        )
        .expect("parses");
        assert_eq!(inbound_users(&top, None).expect("users").len(), 1);
        assert_eq!(
            inbound_networks(&top, None).expect("networks"),
            (true, true)
        );
    }

    #[test]
    fn invalid_networks_and_colon_usernames_are_refused() {
        let bad = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}], "network": "bogus"}}"#,
        )
        .expect("parses");
        assert!(inbound_networks(&bad, bad.get("settings")).is_err());
        assert!(validate_inbound(&bad).is_err());

        let mixed = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}], "network": ["tcp", "bogus"]}}"#,
        )
        .expect("parses");
        assert!(inbound_networks(&mixed, mixed.get("settings")).is_err());
        assert!(validate_inbound(&mixed).is_err());

        let empty = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u", "password": "p"}], "network": []}}"#,
        )
        .expect("parses");
        assert!(inbound_networks(&empty, empty.get("settings")).is_err());
        assert!(validate_inbound(&empty).is_err());

        let colon = crate::json::parse(
            r#"{"protocol": "naive", "settings": {"users": [{"username": "u:p", "password": "p"}]}}"#,
        )
        .expect("parses");
        assert!(inbound_users(&colon, colon.get("settings")).is_err());
        assert!(validate_inbound(&colon).is_err());
    }

    #[test]
    fn extra_headers_keep_only_the_trailers_te() {
        let trailers = crate::json::parse(r#"{"TE": "trailers"}"#).expect("parses");
        assert_eq!(
            header_pairs(&trailers).expect("headers"),
            Some(vec![("te".to_owned(), "trailers".to_owned())])
        );
        let gzip = crate::json::parse(r#"{"TE": "gzip"}"#).expect("parses");
        assert!(header_pairs(&gzip).is_err());
    }
}
