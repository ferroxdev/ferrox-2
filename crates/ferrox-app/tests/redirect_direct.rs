use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ferrox_core::mux;
use ferrox_core::tls::{TlsConfig, TlsProvider as _};
use ferrox_core::vless::{Command as VlessCommand, VlessLink};
use ferrox_core::vless_encryption::{Client, ClientConfig, generate_pair};

trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

struct App {
    child: Child,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unbound_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

fn connect_until(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("the vless inbound did not open port {port}: {error}"),
        }
    }
}

fn start(tag: &str, body: String) -> App {
    let dir = std::env::temp_dir().join(format!(
        "ferrox-redirect-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("config.json");
    std::fs::write(&config, body).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .arg("-config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ferrox-app");
    App { child, dir }
}

fn client(port: u16, encryption: Option<&str>) -> Box<dyn ReadWrite> {
    let stream = connect_until(port);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    match encryption {
        None => Box::new(stream),
        Some(encryption) => Box::new(
            Client::new(ClientConfig::parse(encryption).expect("client config"))
                .handshake(stream)
                .expect("client handshake"),
        ),
    }
}

fn spawn_tcp_echo(echo: TcpListener) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = echo.accept() {
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).is_ok() {
                let _ = stream.write_all(&buf);
            }
        }
    })
}

fn tcp_echo() -> (u16, std::thread::JoinHandle<()>) {
    let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = echo.local_addr().expect("echo addr").port();
    (port, spawn_tcp_echo(echo))
}

fn tcp_echo_with_udp_watch() -> (u16, std::thread::JoinHandle<()>, UdpEchoWatch) {
    loop {
        let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let port = echo.local_addr().expect("echo addr").port();
        let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) else {
            continue;
        };
        return (port, spawn_tcp_echo(echo), UdpEchoWatch::with_socket(udp));
    }
}

fn tcp_observer() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
    let port = listener.local_addr().expect("redirect target addr").port();
    (port, listener)
}

fn assert_tcp_unreached(listener: &TcpListener, why: &str) {
    listener.set_nonblocking(true).expect("nonblocking target");
    std::thread::sleep(Duration::from_millis(200));
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok(_) => panic!("{why}: the redirect target accepted a connection"),
        Err(error) => panic!("{why}: {error:?}"),
    }
}

struct UdpEchoWatch {
    port: u16,
    stop: Arc<AtomicBool>,
    seen: std::sync::mpsc::Receiver<Vec<u8>>,
    thread: std::thread::JoinHandle<()>,
}

impl UdpEchoWatch {
    fn start() -> Self {
        Self::with_socket(UdpSocket::bind("127.0.0.1:0").expect("bind udp echo"))
    }

    fn with_socket(echo: UdpSocket) -> Self {
        let port = echo.local_addr().expect("udp echo addr").port();
        echo.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("udp echo timeout");
        let (seen, receiver) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match echo.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let _ = echo.send_to(&buf[..n], src);
                        let _ = seen.send(buf[..n].to_vec());
                    }
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                            && stop_thread.load(Ordering::Relaxed) =>
                    {
                        break;
                    }
                    Err(_) => {}
                }
            }
            let _ = echo.set_nonblocking(true);
            while let Ok((n, src)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], src);
                let _ = seen.send(buf[..n].to_vec());
            }
        });
        Self {
            port,
            stop,
            seen: receiver,
            thread,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn finish(self) -> Vec<Vec<u8>> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().expect("udp echo thread");
        self.seen.try_iter().collect()
    }
}

fn pem_lines(pem: &str) -> String {
    pem.trim_end()
        .lines()
        .map(|line| format!("\"{line}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn tls_material() -> (String, Vec<u8>) {
    let minted = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
    let material = format!(
        r#"{{"certificate":[{}],"key":[{}]}}"#,
        pem_lines(&minted.cert.pem()),
        pem_lines(&minted.signing_key.serialize_pem())
    );
    (material, minted.cert.der().to_vec())
}

fn tls_client(port: u16, cert_der: Vec<u8>) -> Box<dyn ReadWrite> {
    let stream = connect_until(port);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let config = TlsConfig {
        server_name: "localhost".to_owned(),
        roots: vec![cert_der].into(),
        ..TlsConfig::default()
    };
    let mut session = ferrox_core::tls::connect(&config, stream).expect("starts tls");
    session.handshake().expect("tls handshake");
    Box::new(session)
}

fn tls_inbound(port: u16, material: &str, outbounds: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
            "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}},
            "streamSettings":{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{material}]}}}}}}],
            "outbounds":[{outbounds}]}}"#
    )
}

fn send_mux(
    stream: &mut dyn ReadWrite,
    id: u16,
    status: mux::Status,
    target: Option<mux::Target<'_>>,
    data: &[u8],
) {
    let frame = mux::Outgoing {
        id,
        status,
        options: mux::DATA,
        target,
        global_id: None,
    };
    let mut bytes = vec![0u8; frame.frame_len(data.len())];
    let len = frame.encode_into(Some(data), &mut bytes);
    stream.write_all(&bytes[..len]).expect("writes mux frame");
}

fn mux_reply(stream: &mut dyn ReadWrite) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 65536];
    loop {
        let n = stream.read(&mut chunk).expect("reads mux reply");
        assert!(n > 0, "mux reply closed");
        buffer.extend_from_slice(&chunk[..n]);
        let mut at = 0;
        while at < buffer.len() {
            match mux::decode(&buffer[at..], mux::NewTail::Forward) {
                Ok((frame, used)) => {
                    at += used;
                    if let Some(data) = frame.data {
                        return data.to_vec();
                    }
                }
                Err(mux::Error::Short { .. }) => break,
                Err(error) => panic!("bad mux reply: {error:?}"),
            }
        }
        buffer.drain(..at);
    }
}

const SMUX_SYN: u8 = 0;
const SMUX_PSH: u8 = 2;

fn smux_send(stream: &mut dyn ReadWrite, command: u8, id: u32, data: &[u8]) {
    let mut frame = Vec::with_capacity(8 + data.len());
    frame.push(1);
    frame.push(command);
    frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
    frame.extend_from_slice(&id.to_le_bytes());
    frame.extend_from_slice(data);
    stream.write_all(&frame).expect("writes smux frame");
}

fn smux_read(stream: &mut dyn ReadWrite) -> (u8, u32, Vec<u8>) {
    let mut head = [0u8; 8];
    stream.read_exact(&mut head).expect("reads smux head");
    assert_eq!(head[0], 1, "smux version");
    let len = usize::from(u16::from_le_bytes([head[2], head[3]]));
    let id = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).expect("reads smux data");
    (head[1], id, data)
}

fn packet_addr_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(&(1u16 | 2u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&[127, 0, 0, 1]);
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn packet_addr_datagram(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let host_len = u8::try_from(host.len()).expect("packet-addr host fits");
    let mut out = Vec::with_capacity(2 + host.len() + 4 + payload.len());
    out.push(3);
    out.push(host_len);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn packet_addr_reply(stream: &mut dyn ReadWrite) -> Vec<u8> {
    let mut data = Vec::new();
    loop {
        let (command, id, chunk) = smux_read(stream);
        assert_eq!(command, SMUX_PSH, "a reply is a smux data frame");
        assert_eq!(id, 2, "the reply rides the stream that asked");
        data.extend_from_slice(&chunk);
        let mut at = 0;
        if data.first() == Some(&0) {
            at = 1;
        }
        if data.len() <= at {
            continue;
        }
        let atyp = data[at];
        at += 1;
        match atyp {
            1 => at += 4,
            3 => {
                if data.len() <= at {
                    continue;
                }
                let len = usize::from(data[at]);
                at += 1 + len;
            }
            4 => at += 16,
            other => panic!("packet-addr reply has address type {other}"),
        }
        at += 2;
        if data.len() < at + 2 {
            continue;
        }
        let len = usize::from(u16::from_be_bytes([data[at], data[at + 1]]));
        at += 2;
        if data.len() < at + len {
            continue;
        }
        return data[at..at + len].to_vec();
    }
}

fn answer(stream: &mut dyn ReadWrite) {
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).expect("the front answers");
    assert_eq!(response, [0, 0]);
}

fn is_closed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

fn assert_closed(stream: &mut dyn ReadWrite, why: &str) {
    let mut back = [0u8; 1];
    match stream.read(&mut back) {
        Ok(0) => {}
        Ok(_) => panic!("{why}: the flow was carried instead of refused"),
        Err(error) if is_closed(&error) => {}
        Err(error) => panic!("{why}: the flow did not terminate: {error:?}"),
    }
}

/// A blocked udp association answers the front, or closes the stream outright, without carrying.
fn assert_udp_refused(stream: &mut dyn ReadWrite, why: &str) {
    let mut response = [0u8; 2];
    match stream.read_exact(&mut response) {
        Ok(()) => {
            assert_eq!(response, [0, 0], "{why}: the front answers");
            assert_closed(stream, why);
        }
        Err(error) if is_closed(&error) => {}
        Err(error) => panic!("{why}: the front did not answer: {error:?}"),
    }
}

fn udp_send(stream: &mut dyn ReadWrite, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u16).to_be_bytes())
        .expect("writes the datagram length");
    stream.write_all(payload).expect("writes the datagram");
}

fn udp(stream: &mut dyn ReadWrite, payload: &[u8]) {
    udp_send(stream, payload);
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .expect("reads the answer length");
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer).expect("reads the answer");
    assert_eq!(answer, payload);
}

/// A direct lane applies its address redirect before the requested name is resolved, so a name
/// that does not resolve still reaches the configured target.
#[test]
fn a_redirect_lane_dials_before_resolving_the_requested_name() {
    let (echo_port, echo) = tcp_echo();
    let port = unbound_port();
    let _app = start(
        "raw",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"redirect","address":"127.0.0.1","port":{echo_port}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut request = link.encode_request_header("missing.invalid", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    answer(stream.as_mut());
    let mut back = [0u8; 4];
    stream
        .read_exact(&mut back)
        .expect("the configured redirect target answers");
    assert_eq!(&back, b"ping", "the redirect target carried the flow");
    echo.join().expect("echo thread");
}

/// The encrypted raw path reaches the same redirect for a name that does not resolve, on both
/// its tcp and udp branches.
#[test]
fn an_encrypted_redirect_lane_dials_before_resolving_the_requested_name() {
    let (echo_port, echo, udp_echo) = tcp_echo_with_udp_watch();
    let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
    let port = unbound_port();
    let _app = start(
        "sealed",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}],"decryption":"{decryption}"}}}}],
                "outbounds":[{{"tag":"direct","protocol":"redirect","address":"127.0.0.1","port":{echo_port}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");

    let mut stream = client(port, Some(&encryption));
    let mut request = link.encode_request_header("missing.invalid", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    answer(stream.as_mut());
    let mut back = [0u8; 4];
    stream
        .read_exact(&mut back)
        .expect("the sealed redirect target answers");
    assert_eq!(
        &back, b"ping",
        "the sealed redirect target carried the flow"
    );

    let mut stream = client(port, Some(&encryption));
    let host = "missing.invalid";
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Udp, host)];
    let len = link.encode_request_into(VlessCommand::Udp, host, 80, &mut header);
    header.truncate(len);
    stream.write_all(&header).expect("writes the udp request");
    answer(stream.as_mut());
    udp(stream.as_mut(), b"ping");
    echo.join().expect("echo thread");
    udp_echo.finish();
}

/// A blackhole default never lets a VLESS flow bypass it for a redirect-only lane.
#[test]
fn a_blackhole_default_does_not_enable_direct_forwarding() {
    let (echo_port, echo) = tcp_observer();
    let port = unbound_port();
    let _app = start(
        "blackhole-default",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"block","protocol":"blackhole"}},
                    {{"tag":"direct","protocol":"redirect","address":"127.0.0.1","port":{echo_port}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut request = link.encode_request_header("127.0.0.1", echo_port);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    assert_closed(
        stream.as_mut(),
        "a blackhole default refuses the direct flow",
    );
    assert_tcp_unreached(&echo, "a blackhole default never reaches the redirect lane");
}

/// A final rule sees the redirected address, not just the requested one, so a blocked redirect
/// target is refused before the dial on both name and address requests.
#[test]
fn a_final_rule_blocks_the_redirect_target() {
    let (echo_port, echo) = tcp_observer();
    let port = unbound_port();
    let _app = start(
        "final-rule",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}",
                    "finalRules":[{{"action":"block","ip":["127.0.0.1"],"blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut request = link.encode_request_header("192.0.2.7", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    let mut response = [0u8; 2];
    stream
        .read_exact(&mut response)
        .expect("a blocked flow still answers");
    assert_closed(
        stream.as_mut(),
        "a final rule that blocks the redirected target",
    );
    assert_tcp_unreached(&echo, "a final rule that blocks the redirected target");
}

/// The encrypted raw path enforces the same final rule before its tcp dial.
#[test]
fn an_encrypted_final_rule_blocks_the_redirect_target() {
    let (echo_port, echo) = tcp_observer();
    let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
    let port = unbound_port();
    let _app = start(
        "sealed-final-rule",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}],"decryption":"{decryption}"}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}",
                    "finalRules":[{{"action":"block","ip":["127.0.0.1"],"blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, Some(&encryption));
    let mut request = link.encode_request_header("192.0.2.7", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    answer(stream.as_mut());
    assert_closed(
        stream.as_mut(),
        "an encrypted final rule that blocks the redirected target",
    );
    assert_tcp_unreached(
        &echo,
        "an encrypted final rule that blocks the redirected target",
    );
}

/// The raw udp association checks the final rule against its redirected target before replying.
#[test]
fn a_final_rule_blocks_the_redirected_udp_target() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let port = unbound_port();
    let _app = start(
        "udp-final-rule",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}",
                    "finalRules":[{{"action":"block","network":"udp","ip":["127.0.0.1"],"blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Udp, "192.0.2.7")];
    let len = link.encode_request_into(VlessCommand::Udp, "192.0.2.7", 80, &mut header);
    header.truncate(len);
    header.extend_from_slice(&(b"blocked".len() as u16).to_be_bytes());
    header.extend_from_slice(b"blocked");
    stream.write_all(&header).expect("writes the udp request");
    assert_udp_refused(
        stream.as_mut(),
        "a final rule that blocks the redirected udp target",
    );
    assert!(
        echo.finish().is_empty(),
        "a blocked udp target never received the datagram"
    );
}

/// The encrypted udp association checks the same final rule before replying.
#[test]
fn an_encrypted_final_rule_blocks_the_redirected_udp_target() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
    let port = unbound_port();
    let _app = start(
        "sealed-udp-final-rule",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}],"decryption":"{decryption}"}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}",
                    "finalRules":[{{"action":"block","network":"udp","ip":["127.0.0.1"],"blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, Some(&encryption));
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Udp, "192.0.2.7")];
    let len = link.encode_request_into(VlessCommand::Udp, "192.0.2.7", 80, &mut header);
    header.truncate(len);
    header.extend_from_slice(&(b"blocked".len() as u16).to_be_bytes());
    header.extend_from_slice(b"blocked");
    stream.write_all(&header).expect("writes the udp request");
    assert_udp_refused(
        stream.as_mut(),
        "an encrypted final rule that blocks the redirected udp target",
    );
    assert!(
        echo.finish().is_empty(),
        "an encrypted blocked udp target never received the datagram"
    );
}

/// A redirected udp association reaches its target when no final rule blocks it.
#[test]
fn a_redirected_udp_association_reaches_the_redirect_target() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let port = unbound_port();
    let _app = start(
        "udp-allowed",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}"}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Udp, "192.0.2.7")];
    let len = link.encode_request_into(VlessCommand::Udp, "192.0.2.7", 80, &mut header);
    header.truncate(len);
    stream.write_all(&header).expect("writes the udp request");
    answer(stream.as_mut());
    udp(stream.as_mut(), b"allowed");
    assert!(
        echo.finish()
            .iter()
            .any(|datagram| datagram.as_slice() == b"allowed"),
        "the redirect target received the allowed datagram"
    );
}

/// An encrypted redirected udp association reaches its target when no final rule blocks it.
#[test]
fn an_encrypted_redirected_udp_association_reaches_the_redirect_target() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
    let port = unbound_port();
    let _app = start(
        "sealed-udp-allowed",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}],"decryption":"{decryption}"}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:{echo_port}"}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, Some(&encryption));
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Udp, "192.0.2.7")];
    let len = link.encode_request_into(VlessCommand::Udp, "192.0.2.7", 80, &mut header);
    header.truncate(len);
    stream.write_all(&header).expect("writes the udp request");
    answer(stream.as_mut());
    udp(stream.as_mut(), b"allowed");
    assert!(
        echo.finish()
            .iter()
            .any(|datagram| datagram.as_slice() == b"allowed"),
        "the encrypted redirect target received the allowed datagram"
    );
}

/// A TLS TCP request applies the direct redirect before the requested name is resolved.
#[test]
fn a_tls_redirect_lane_dials_before_resolving_the_requested_name() {
    let (echo_port, echo) = tcp_echo();
    let (material, cert_der) = tls_material();
    let port = unbound_port();
    let outbounds = format!(
        r#"{{"tag":"direct","protocol":"redirect","address":"127.0.0.1","port":{echo_port}}}"#
    );
    let _app = start("tls-raw", tls_inbound(port, &material, &outbounds));
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = tls_client(port, cert_der);
    let mut request = link.encode_request_header("missing.invalid", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    answer(stream.as_mut());
    let mut back = [0u8; 4];
    stream
        .read_exact(&mut back)
        .expect("the tls redirect target answers");
    assert_eq!(&back, b"ping", "the tls redirect target carried the flow");
    echo.join().expect("echo thread");
}

/// A TLS TCP request whose redirect target a final rule blocks is refused without a fallback.
#[test]
fn a_tls_final_rule_blocks_the_redirect_target() {
    let (echo_port, echo) = tcp_observer();
    let (material, cert_der) = tls_material();
    let port = unbound_port();
    let outbounds = format!(
        r#"{{"tag":"direct","protocol":"freedom","settings":{{
            "redirect":"127.0.0.1:{echo_port}",
            "finalRules":[{{"action":"block","ip":["127.0.0.1"],"blockDelay":"0-0"}}]}}}}"#
    );
    let _app = start("tls-block", tls_inbound(port, &material, &outbounds));
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = tls_client(port, cert_der);
    let mut request = link.encode_request_header("192.0.2.7", 80);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    assert_closed(
        stream.as_mut(),
        "a tls final rule that blocks the redirected target",
    );
    assert_tcp_unreached(&echo, "a tls final rule that blocks the redirected target");
}

/// A TLS TCP request with no redirect still reaches the address the client named.
#[test]
fn a_tls_lane_without_a_redirect_keeps_the_requested_target() {
    let (echo_port, echo) = tcp_echo();
    let (material, cert_der) = tls_material();
    let port = unbound_port();
    let _app = start(
        "tls-direct",
        tls_inbound(port, &material, r#"{"protocol":"freedom","settings":{}}"#),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = tls_client(port, cert_der);
    let mut request = link.encode_request_header("127.0.0.1", echo_port);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).expect("writes the request");
    answer(stream.as_mut());
    let mut back = [0u8; 4];
    stream
        .read_exact(&mut back)
        .expect("the requested target answers");
    assert_eq!(&back, b"ping", "no redirect keeps the requested target");
    echo.join().expect("echo thread");
}

/// A redirected mux Keep target is checked before it sends: a changed name follows the redirect,
/// and a changed address whose redirected port a final rule blocks never reaches that port.
#[test]
fn a_redirected_mux_keep_target_is_checked_before_it_sends() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let blocked = UdpSocket::bind("127.0.0.1:0").expect("bind blocked udp");
    blocked
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("blocked timeout");
    let blocked_port = blocked.local_addr().expect("blocked addr").port();
    let port = unbound_port();
    let _app = start(
        "mux-keep",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:0",
                    "finalRules":[{{"action":"block","network":"udp","ip":["127.0.0.1"],"port":"{blocked_port}","blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let mut header = vec![0u8; link.request_command_len(VlessCommand::Mux, "")];
    let len = link.encode_request_into(VlessCommand::Mux, "", 0, &mut header);
    header.truncate(len);
    stream.write_all(&header).expect("writes the mux request");
    answer(stream.as_mut());

    send_mux(
        stream.as_mut(),
        1,
        mux::Status::New,
        Some(mux::Target::of(mux::Network::Udp, "192.0.2.1", echo_port)),
        b"new",
    );
    assert_eq!(
        mux_reply(stream.as_mut()),
        b"new".to_vec(),
        "the new target answers"
    );

    send_mux(
        stream.as_mut(),
        1,
        mux::Status::Keep,
        Some(mux::Target::of(
            mux::Network::Udp,
            "missing.invalid",
            echo_port,
        )),
        b"keep",
    );
    assert_eq!(
        mux_reply(stream.as_mut()),
        b"keep".to_vec(),
        "a changed keep name follows the redirect"
    );

    send_mux(
        stream.as_mut(),
        1,
        mux::Status::Keep,
        Some(mux::Target::of(
            mux::Network::Udp,
            "192.0.2.1",
            blocked_port,
        )),
        b"blocked",
    );
    let mut back = [0u8; 64];
    assert!(
        blocked.recv_from(&mut back).is_err(),
        "a changed keep target whose redirected port is blocked never sends"
    );
    assert!(
        !echo
            .finish()
            .iter()
            .any(|datagram| datagram.as_slice() == b"blocked"),
        "a blocked keep target never falls back to the previous echo target"
    );
}

/// A sing-mux packet-addr datagram applies its redirect before the name lookup, and a final rule
/// sees the redirected address rather than the one the client named.
#[test]
fn a_packet_addr_redirect_precedes_name_resolution_and_the_block_rule() {
    let echo = UdpEchoWatch::start();
    let echo_port = echo.port();
    let blocked = UdpSocket::bind("127.0.0.1:0").expect("bind blocked udp");
    blocked
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("blocked timeout");
    let blocked_port = blocked.local_addr().expect("blocked addr").port();
    let port = unbound_port();
    let _app = start(
        "packet-addr",
        format!(
            r#"{{"inbounds":[{{"tag":"in","protocol":"vless","listen":"127.0.0.1","port":{port},
                "settings":{{"clients":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}}}],
                "outbounds":[{{"tag":"direct","protocol":"freedom","settings":{{
                    "redirect":"127.0.0.1:0",
                    "finalRules":[{{"action":"block","network":"udp","ip":["127.0.0.1"],"port":"{blocked_port}","blockDelay":"0-0"}}]}}}}]}}"#
        ),
    );
    let link = VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:1")
        .expect("vless link");
    let mut stream = client(port, None);
    let request = link.encode_request_header("0.0.0.0", 444);
    stream
        .write_all(&request)
        .expect("writes the sing-mux request");
    answer(stream.as_mut());
    stream.write_all(&[0, 0]).expect("starts smux");

    smux_send(stream.as_mut(), SMUX_SYN, 2, &[]);
    smux_send(stream.as_mut(), SMUX_PSH, 2, &packet_addr_request());
    smux_send(
        stream.as_mut(),
        SMUX_PSH,
        2,
        &packet_addr_datagram("missing.invalid", echo_port, b"ping"),
    );
    assert_eq!(
        packet_addr_reply(stream.as_mut()),
        b"ping".to_vec(),
        "the redirect answers a name that does not resolve"
    );

    smux_send(
        stream.as_mut(),
        SMUX_PSH,
        2,
        &packet_addr_datagram("192.0.2.1", blocked_port, b"blocked"),
    );
    let mut back = [0u8; 64];
    assert!(
        blocked.recv_from(&mut back).is_err(),
        "the final rule sees the redirected packet-addr destination"
    );
    assert!(
        !echo
            .finish()
            .iter()
            .any(|datagram| datagram.as_slice() == b"blocked"),
        "a blocked packet-addr datagram never falls back to the previous echo target"
    );
}
