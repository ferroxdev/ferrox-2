//! The transports a DNS query rides: one datagram, one length-framed stream,
//! that stream under TLS, the same bytes as an HTTP/2 POST, or one QUIC
//! bidirectional stream. The wire message is the caller's; this module only
//! moves it and returns the answer bytes whole.

use crate::conn::Connection;
use crate::h2::{
    block_encode, frame_head, read_head_bounded, Decoder, F_ACK, F_END, F_END_HEADERS, F_PADDED,
    F_PRIORITY, T_CONT, T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS,
};
use crate::sockopt::SocketOptions;
use ferrox_core::tls::TlsProvider as _;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const H2_FRAME_MAX: usize = 16_384;

#[allow(clippy::too_many_arguments)]
pub(crate) fn udp(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    if !local {
        match crate::proxy::dns_udp(host, port, tag, query, timeout) {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    let addr = crate::sockopt::resolve_datagram(options, host, port)?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let routes = crate::tun_route::route_read();
    crate::tun_route::force_underlay();
    let socket = crate::sockopt::datagram_at(options, addr, timeout)?;
    socket
        .send(query)
        .map_err(|error| format!("dns udp send: {error}"))?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    drop(routes);
    let mut response = vec![0u8; ferrox_core::dns::MESSAGE_MAX];
    let read = socket
        .recv(&mut response)
        .map_err(|error| format!("dns udp receive: {error}"))?;
    response.truncate(read);
    Ok(response)
}

pub(crate) fn udp_target(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let routes = crate::tun_route::route_read();
    crate::tun_route::force_underlay();
    let socket = crate::sockopt::datagram_target(target, timeout)?;
    socket
        .send(query)
        .map_err(|error| format!("dns udp send: {error}"))?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    drop(routes);
    let mut response = vec![0u8; ferrox_core::dns::MESSAGE_MAX];
    let read = socket
        .recv(&mut response)
        .map_err(|error| format!("dns udp receive: {error}"))?;
    response.truncate(read);
    Ok(response)
}

pub(crate) fn tcp(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut stream = Timed {
        inner: connect(host, port, tag, options, deadline, local)?,
        deadline,
    };
    write_frame(&mut stream, query)?;
    let reply = read_frame(&mut stream)?;
    if Instant::now() >= deadline {
        return Err("dns deadline".to_owned());
    }
    Ok(reply)
}

pub(crate) fn tls(
    host: &str,
    port: u16,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let stream = Timed {
        inner: connect(host, port, tag, options, deadline, local)?,
        deadline,
    };
    let config = std::sync::Arc::new(ferrox_core::tls::TlsConfig {
        server_name: host.to_owned(),
        alpn: Vec::new().into(),
        roots: crate::quic::system_roots(),
        cert_pins: std::sync::Arc::default(),
        verify_names: std::sync::Arc::default(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: std::sync::Arc::default(),
        curves: std::sync::Arc::default(),
        insecure: false,
        resumption: true,
        fingerprint: None,
        ech_config_list: None,
        websocket: false,
        master_key_log: None,
        client_cert: None,
        client_random: None,
        padding: None,
        ..Default::default()
    });
    let mut stream = ferrox_core::tls::RustlsProvider::connect(&config, stream)
        .map_err(|error| format!("dns tls: {error}"))?;
    stream
        .handshake()
        .map_err(|error| format!("dns tls handshake: {error}"))?;
    write_frame(&mut stream, query)?;
    let reply = read_frame(&mut stream)?;
    if Instant::now() >= deadline {
        return Err("dns deadline".to_owned());
    }
    Ok(reply)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn doh(
    host: &str,
    port: u16,
    path: &str,
    cleartext: bool,
    query: &[u8],
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    timeout: Duration,
    local: bool,
) -> Result<Vec<u8>, String> {
    let default_port = if cleartext { 80 } else { 443 };
    let authority = if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let scheme = if cleartext { "http" } else { "https" };
    let deadline = Instant::now() + timeout;
    let stream = connect(host, port, tag, options, deadline, local)?;
    if cleartext {
        return exchange(
            Timed {
                inner: stream,
                deadline,
            },
            &authority,
            scheme,
            path,
            query,
            deadline,
        );
    }
    let config = std::sync::Arc::new(ferrox_core::tls::TlsConfig {
        server_name: host.to_owned(),
        alpn: vec![b"h2".to_vec()].into(),
        roots: crate::quic::system_roots(),
        cert_pins: std::sync::Arc::default(),
        verify_names: std::sync::Arc::default(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        cipher_suites: std::sync::Arc::default(),
        curves: std::sync::Arc::default(),
        insecure: false,
        resumption: true,
        fingerprint: None,
        ech_config_list: None,
        websocket: false,
        master_key_log: None,
        client_cert: None,
        client_random: None,
        padding: None,
        ..Default::default()
    });
    let mut tls = ferrox_core::tls::RustlsProvider::connect(
        &config,
        Timed {
            inner: stream,
            deadline,
        },
    )
    .map_err(|error| format!("dns doh tls: {error}"))?;
    tls.handshake()
        .map_err(|error| format!("dns doh handshake: {error}"))?;
    exchange(Unbounded(tls), &authority, scheme, path, query, deadline)
}

pub(crate) fn doq(
    host: &str,
    port: u16,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let (socket, peer, local) =
        crate::quic::udp_to_server(host, port).ok_or_else(|| "dns doq: no route".to_owned())?;
    let socket = crate::quic::Datagram::plain(socket);
    let roots = crate::quic::system_roots();
    let mut scid = [0u8; 16];
    getrandom::fill(&mut scid).map_err(|_| "dns doq: no randomness".to_owned())?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = crate::quic::quiche_config_alpn(&roots, None, &[b"doq"])
        .ok_or_else(|| "dns doq: no trust roots".to_owned())?;
    let mut conn = quiche::connect_with_buffer_factory::<crate::quic::BytesBufFactory>(
        Some(host),
        &cid,
        local,
        peer,
        &mut config,
    )
    .map_err(|error| format!("dns doq connect: {error}"))?;
    crate::quic::drive_handshake_by(&mut conn, &socket, local, timeout)
        .ok_or_else(|| "dns doq handshake".to_owned())?;
    let deadline = Instant::now() + timeout;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    if !crate::quic::stream_send_all(&mut conn, &socket, 0, &framed, true, deadline) {
        return Err("dns doq send".to_owned());
    }
    let head = crate::quic::stream_recv_exact(&mut conn, &socket, local, 0, 2, deadline)
        .ok_or_else(|| "dns doq length".to_owned())?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if length > ferrox_core::dns::MESSAGE_MAX {
        return Err("dns doq answer over the message bound".to_owned());
    }
    crate::quic::stream_recv_exact(&mut conn, &socket, local, 0, length, deadline)
        .ok_or_else(|| "dns doq answer".to_owned())
}

fn connect(
    host: &str,
    port: u16,
    tag: Option<&str>,
    options: Option<&SocketOptions>,
    deadline: Instant,
    local: bool,
) -> Result<Connection, String> {
    let left = |deadline: Instant| {
        deadline
            .saturating_duration_since(Instant::now())
            .max(std::time::Duration::from_millis(1))
    };
    let deadline = crate::dnsapp::system_deadline().map_or(deadline, |system| deadline.min(system));
    let timeout = left(deadline);
    if !local {
        match crate::proxy::dns_stream(host, port, tag, timeout) {
            Ok(Some(stream)) => return Ok(stream),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    let timeout = left(deadline);
    crate::tun_route::force_underlay();
    let stream = crate::dnsapp::with_system_deadline(deadline, || {
        crate::sockopt::connect(options, host, port, timeout)
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("dns stream timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("dns stream write timeout: {error}"))?;
    Ok(Connection::Tcp(stream))
}

fn write_frame(stream: &mut impl Write, query: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .and_then(|()| stream.write_all(query))
        .map_err(|error| format!("dns stream send: {error}"))
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("dns stream length: {error}"))?;
    let length = usize::from(u16::from_be_bytes(head));
    if length > ferrox_core::dns::MESSAGE_MAX {
        return Err("dns answer over the message bound".to_owned());
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("dns stream answer: {error}"))?;
    Ok(body)
}

/// Arm a stream's next read with the time left before the exchange deadline.
trait ReadDeadline {
    fn arm(&mut self, remaining: Duration) -> std::io::Result<()>;
}

impl ReadDeadline for Connection {
    fn arm(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(remaining))
    }
}

/// A stream whose transport has no settable read timeout; the exchange still checks the deadline between reads.
struct Unbounded<S>(S);

impl<S> ReadDeadline for Unbounded<S> {
    fn arm(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(())
    }
}

impl<S: Read> Read for Unbounded<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Write> Write for Unbounded<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

struct Bounded<S> {
    inner: S,
    deadline: Instant,
    expired: bool,
}

impl<S: Read + ReadDeadline> Read for Bounded<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            self.expired = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "dns doh deadline",
            ));
        }
        self.inner.arm(left)?;
        match self.inner.read(buf) {
            Ok(read) => Ok(read),
            Err(error) => {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    self.expired = true;
                }
                Err(error)
            }
        }
    }
}

impl<S: Write> Write for Bounded<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn send_doh(
    stream: &mut impl Write,
    authority: &str,
    scheme: &str,
    path: &str,
    query: &[u8],
) -> Result<(), String> {
    let path = if path.is_empty() { "/" } else { path };
    stream
        .write_all(crate::h2::MAGIC)
        .map_err(|error| format!("dns doh preface: {error}"))?;
    frame(stream, T_SETTINGS, 0, 0, &[])?;
    let length = query.len().to_string();
    let headers = [
        (":method", "POST"),
        (":scheme", scheme),
        (":path", path),
        (":authority", authority),
        ("content-type", "application/dns-message"),
        ("accept", "application/dns-message"),
        ("content-length", length.as_str()),
    ];
    frame(stream, T_HEADERS, F_END_HEADERS, 1, &block_encode(&headers))?;
    frame(stream, T_DATA, F_END, 1, query)?;
    stream
        .flush()
        .map_err(|error| format!("dns doh flush: {error}"))
}

fn read_doh_frame<S: Read + ReadDeadline>(
    stream: &mut Bounded<S>,
) -> Result<(u8, u8, Vec<u8>, u32), String> {
    let Some((len, kind, flags, id)) = read_head_bounded(stream) else {
        return Err(if stream.expired {
            "dns doh deadline".to_owned()
        } else {
            "dns doh closed".to_owned()
        });
    };
    if len > H2_FRAME_MAX {
        return Err("dns doh frame over the frame bound".to_owned());
    }
    let mut payload = vec![0u8; len];
    if let Err(error) = stream.read_exact(&mut payload) {
        return Err(if stream.expired {
            "dns doh deadline".to_owned()
        } else {
            format!("dns doh read: {error}")
        });
    }
    Ok((kind, flags, payload, id))
}

/// A connection that re-arms its socket timeout from one absolute deadline before every read and write, so a TLS handshake and the exchange behind it cannot each spend the whole budget.
struct Timed {
    inner: Connection,
    deadline: Instant,
}

impl Timed {
    fn left(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "dns deadline",
            ));
        }
        Ok(left)
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.set_read_timeout(Some(self.left()?))?;
        self.inner.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.set_write_timeout(Some(self.left()?))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.set_write_timeout(Some(self.left()?))?;
        self.inner.flush()
    }
}

impl ReadDeadline for Timed {
    fn arm(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(())
    }
}

fn exchange(
    stream: impl Read + Write + ReadDeadline,
    authority: &str,
    scheme: &str,
    path: &str,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut stream = Bounded {
        inner: stream,
        deadline,
        expired: false,
    };
    send_doh(&mut stream, authority, scheme, path, query)?;
    let mut decoder = Decoder::default();
    let mut block = Vec::new();
    let mut body = Vec::new();
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            return Err("dns doh deadline".to_owned());
        }
        let (kind, flags, payload, id) = read_doh_frame(&mut stream)?;
        match kind {
            T_SETTINGS => {
                if flags & F_ACK == 0 {
                    frame(&mut stream, T_SETTINGS, F_ACK, 0, &[])?;
                }
            }
            T_PING => {
                if flags & F_ACK == 0 {
                    frame(&mut stream, T_PING, F_ACK, 0, &payload)?;
                }
            }
            T_HEADERS | T_CONT => {
                let payload = if kind == T_HEADERS {
                    unframe(flags, &payload, true)?
                } else {
                    &payload
                };
                if block.len() + payload.len() > ferrox_core::dns::MESSAGE_MAX {
                    return Err("dns doh headers over the message bound".to_owned());
                }
                block.extend_from_slice(payload);
                if flags & F_END_HEADERS != 0 {
                    decoder
                        .decode(&block, &mut |name, value| {
                            if name == b":status" {
                                status = Some(String::from_utf8_lossy(value).into_owned());
                            }
                        })
                        .ok_or("dns doh headers")?;
                    block.clear();
                }
                if flags & F_END != 0 {
                    break;
                }
            }
            T_DATA => {
                if id == 1 {
                    let payload = unframe(flags, &payload, false)?;
                    if body.len() + payload.len() > ferrox_core::dns::MESSAGE_MAX {
                        return Err("dns doh answer over the message bound".to_owned());
                    }
                    body.extend_from_slice(payload);
                }
                if flags & F_END != 0 {
                    break;
                }
            }
            T_RST => return Err("dns doh stream reset".to_owned()),
            T_GOAWAY => break,
            _ => {}
        }
    }
    if Instant::now() >= deadline {
        return Err("dns doh deadline".to_owned());
    }
    match status.as_deref() {
        Some("200") => {}
        Some(other) => return Err(format!("dns doh answered {other}")),
        None => return Err("dns doh answered no status".to_owned()),
    }
    Ok(body)
}

/// The payload without the padding and priority fields a frame's flags announce, so a valid
/// padded answer is decoded rather than handed to the DNS reader as damaged bytes.
fn unframe(flags: u8, payload: &[u8], priority: bool) -> Result<&[u8], String> {
    let mut body = payload;
    if flags & F_PADDED != 0 {
        let Some((&padding, rest)) = body.split_first() else {
            return Err("dns doh padded frame is empty".to_owned());
        };
        let padding = usize::from(padding);
        if padding > rest.len() {
            return Err("dns doh padding overruns its frame".to_owned());
        }
        body = &rest[..rest.len() - padding];
    }
    if priority && flags & F_PRIORITY != 0 {
        if body.len() < 5 {
            return Err("dns doh priority field is short".to_owned());
        }
        body = &body[5..];
    }
    Ok(body)
}

fn frame(stream: &mut impl Write, kind: u8, flags: u8, id: u32, body: &[u8]) -> Result<(), String> {
    stream
        .write_all(&frame_head(body.len(), kind, flags, id))
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("dns doh write: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{exchange, read_frame};
    use crate::h2::{
        block_encode, frame_head, F_END, F_END_HEADERS, F_PADDED, T_DATA, T_HEADERS, T_SETTINGS,
    };
    use std::io::{Cursor, Read, Write};

    /// The framed answer's room is zeroed once before the read fills it.
    #[test]
    fn a_dns_frame_read_zeroes_its_target_once() {
        let body = b"answer-bytes";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(body);
        let mut stream = Cursor::new(wire);
        let (frame, counts) = ferrox_core::alloc_count::measure(|| read_frame(&mut stream));
        assert_eq!(
            frame.expect("the frame"),
            body.as_slice(),
            "the bytes are the frame"
        );
        assert_eq!(
            (counts.zeroed, counts.zeroed_bytes),
            (1, 12),
            "the room is zeroed once: {counts:?}"
        );
    }

    #[test]
    fn a_padded_data_frame_uses_the_h2_limit_before_the_dns_bound() {
        let body = vec![0x5a; 8000];
        let padding = 200usize;
        let mut payload = vec![padding as u8];
        payload.extend_from_slice(&body);
        payload.resize(1 + body.len() + padding, 0);
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_head(payload.len(), T_DATA, F_PADDED | F_END, 1));
        wire.extend_from_slice(&payload);
        let mut stream = super::Bounded {
            inner: Wire {
                read: Cursor::new(wire),
            },
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
            expired: false,
        };
        let (kind, flags, payload, _) =
            super::read_doh_frame(&mut stream).expect("a frame inside the H2 limit");
        assert_eq!(kind, T_DATA);
        assert_eq!(
            super::unframe(flags, &payload, false)
                .expect("unframes")
                .len(),
            body.len()
        );
    }

    #[test]
    fn a_priority_flag_does_not_apply_to_data() {
        let data = [0, 0, 0, 0, 1, b'd', b'n', b's'];
        assert_eq!(
            super::unframe(crate::h2::F_PRIORITY, &data, false),
            Ok(&data[..])
        );
        let headers = [0, 0, 0, 0, 1, b':', b' ', b'a'];
        assert_eq!(
            super::unframe(crate::h2::F_PRIORITY, &headers, true),
            Ok(&headers[5..])
        );
    }

    struct Wire {
        read: Cursor<Vec<u8>>,
    }

    struct Endless;

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(0);
            Ok(buf.len())
        }
    }

    impl super::ReadDeadline for Endless {
        fn arm(&mut self, _remaining: std::time::Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for Endless {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Trickle;

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(5));
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = 0;
            Ok(1)
        }
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl super::ReadDeadline for Trickle {
        fn arm(&mut self, _remaining: std::time::Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A one-byte-per-call reader still stops at the absolute deadline, even inside a frame.
    #[test]
    fn a_trickling_doh_stream_ends_at_the_query_deadline() {
        let started = std::time::Instant::now();
        let answer = exchange(
            Trickle,
            "dns.example",
            "https",
            "/dns-query",
            b"query",
            std::time::Instant::now() + std::time::Duration::from_millis(40),
        );
        assert_eq!(answer, Err("dns doh deadline".to_owned()));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    /// A peer that only sends empty data frames cannot stretch the query past its absolute deadline.
    #[test]
    fn an_endless_doh_stream_ends_at_the_query_deadline() {
        let started = std::time::Instant::now();
        let answer = exchange(
            Endless,
            "dns.example",
            "https",
            "/dns-query",
            b"query",
            std::time::Instant::now() + std::time::Duration::from_millis(50),
        );
        assert_eq!(answer, Err("dns doh deadline".to_owned()));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl super::ReadDeadline for Wire {
        fn arm(&mut self, _remaining: std::time::Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Each `DoH` frame body zeroes its room once before the read fills it.
    #[test]
    fn a_doh_frame_read_zeroes_each_target_once() {
        let settings = [0u8, 3, 0, 0, 0, 100];
        let status = block_encode(&[(":status", "200")]);
        let body = b"answer-bytes";
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_head(settings.len(), T_SETTINGS, 0, 0));
        wire.extend_from_slice(&settings);
        wire.extend_from_slice(&frame_head(status.len(), T_HEADERS, F_END_HEADERS, 1));
        wire.extend_from_slice(&status);
        wire.extend_from_slice(&frame_head(body.len(), T_DATA, F_END, 1));
        wire.extend_from_slice(body);
        let expected_zeroed = settings.len() + status.len() + body.len();
        let (answer, counts) = ferrox_core::alloc_count::measure(|| {
            exchange(
                Wire {
                    read: Cursor::new(wire),
                },
                "dns.example",
                "https",
                "/dns-query",
                b"query",
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
        });
        assert_eq!(
            answer.expect("the answer").as_slice(),
            body,
            "the body is the answer"
        );
        assert_eq!(
            (counts.zeroed, counts.zeroed_bytes),
            (3, expected_zeroed),
            "each frame body is zeroed once: {counts:?}"
        );
    }
}
