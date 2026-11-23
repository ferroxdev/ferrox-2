// xHTTP over HTTP/3: one QUIC connection carries the same request streams the H2 lane does, so stream-one, stream-up and packet-up keep their shapes and only the framing under them changes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::{frames, head_end, hpack};

use crate::quic::{self, Activity, Datagram, QuicheConnection};
use crate::xhttp::{XhttpMode, XhttpSettings};

const TICK: Duration = Duration::from_millis(20);
const POLL: Duration = Duration::from_millis(5);
const READ_ROOM: usize = 16 * 1024;
const H3_WRITE_CHUNK: usize = 16 * 1024;
const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
const H3_FRAME_UNEXPECTED: u64 = 0x0105;
const H3_FRAME_ERROR: u64 = 0x0106;
const H3_ID_ERROR: u64 = 0x0108;
const H3_SETTINGS_ERROR: u64 = 0x0109;
const H3_MISSING_SETTINGS: u64 = 0x010a;

/// One request stream's byte transport: a served stream on the QUIC driver, or one the client
/// opened on its own connection. Both clones share the connection, never the buffered bytes.
#[derive(Clone)]
pub(crate) enum Wire {
    Server(quic::QuicStream),
    Client(ClientStream),
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.read(buf),
            Self::Client(stream) => stream.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.write(buf),
            Self::Client(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Server(stream) => stream.flush(),
            Self::Client(stream) => stream.flush(),
        }
    }
}

impl Wire {
    fn try_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.try_write(buf),
            Self::Client(stream) => stream.try_write(buf),
        }
    }

    fn activity(&self) -> Arc<Activity> {
        match self {
            Self::Server(stream) => stream.activity(),
            Self::Client(stream) => Arc::clone(&stream.activity),
        }
    }

    fn opening_start(&mut self, buf: &[u8], deadline: Option<Instant>) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.write(buf),
            Self::Client(stream) => stream.opening_start(buf, deadline),
        }
    }

    fn opening_rest(
        &mut self,
        buf: &[u8],
        sent: usize,
        deadline: Instant,
    ) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.write(buf),
            Self::Client(stream) => stream.opening_rest(buf, sent, deadline),
        }
    }

    pub(crate) fn fin(&self) {
        match self {
            Self::Server(stream) => {
                stream.fin();
            }
            Self::Client(stream) => stream.fin(),
        }
    }

    pub(crate) fn close(&self) {
        match self {
            Self::Server(stream) => stream.close(),
            Self::Client(stream) => stream.close(),
        }
    }

    /// Closes the whole connection with an HTTP/3 application error, for a frame a request stream may not carry.
    pub(crate) fn abort(&self, code: u64) {
        match self {
            Self::Server(stream) => stream.close_connection(code),
            Self::Client(stream) => stream.close_connection(code),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// A lane is a thread, so the count is the lane's own: a process-wide one sees other tests' lanes.
    static LANE_GRANTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The same lane's empty reads that slept the transport tick instead of handing the lane back.
    static LANE_TICKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn lane_grants() -> usize {
    LANE_GRANTS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn lane_ticks() -> usize {
    LANE_TICKS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn note_lane_grant() {
    LANE_GRANTS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn note_lane_tick() {
    LANE_TICKS.with(|count| count.set(count.get() + 1));
}

#[cfg(not(test))]
#[inline]
fn note_lane_grant() {}

#[cfg(not(test))]
#[inline]
fn note_lane_tick() {}

/// The request stream as the shared dispatch reads it: HEADERS becomes the H1 head `accept_core`
/// parses, and every DATA frame after it is body.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct H3Reader {
    wire: Wire,
    buf: Vec<u8>,
    buf_at: usize,
    head: Option<Vec<u8>>,
    status: Option<u16>,
    padding: bool,
    content_length: Option<usize>,
    frame_left: usize,
    ended: bool,
    head_seen: bool,
    expect_request: bool,
    /// Only a CONNECT reads `Padding`; an ordinary answer leaves the field list unbuilt.
    padding_head: bool,
    /// A CONNECT success ignores `Content-Length`, per RFC 9110 9.3.6.
    connect: bool,
    idle_since: Option<Instant>,
    activity: Arc<Activity>,
    deadline: Option<Instant>,
    /// Bytes of `buf` already initialised for a transport read, so a read lands without the room being zeroed first.
    buf_init: usize,
    #[cfg(test)]
    read_target: usize,
}

impl H3Reader {
    pub(crate) fn new(wire: Wire) -> Self {
        let activity = wire.activity();
        let expect_request = matches!(&wire, Wire::Server(_));
        Self {
            wire,
            buf: Vec::new(),
            buf_at: 0,
            head: None,
            status: None,
            padding: false,
            content_length: None,
            frame_left: 0,
            ended: false,
            head_seen: false,
            expect_request,
            padding_head: false,
            connect: false,
            idle_since: None,
            activity,
            deadline: None,
            buf_init: 0,
            #[cfg(test)]
            read_target: 0,
        }
    }

    pub(crate) fn status(&self) -> Option<u16> {
        self.status
    }

    fn content_length(&self) -> Option<usize> {
        self.content_length
    }

    /// Whether this POST's own response deadline has passed.
    fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Bounds this POST's response wait, independently of the connection's activity clock.
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    /// Drops this request's stream in both directions.
    fn reset(&self) {
        self.wire.close();
    }

    fn idle_expired(&self, since: Instant) -> bool {
        if self.expired() {
            return true;
        }
        let idle = if self.head_seen {
            self.activity.age()
        } else {
            since.elapsed()
        };
        idle >= crate::budgets::relay_stall()
    }

    /// The H1 head the request's HEADERS frame names, with the connection framing the reference's
    /// hub never writes: an H3 stream ends by itself, so the head says chunked and nothing parses it.
    pub(crate) fn read_head(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        while self.head.is_none() && !self.ended {
            self.step()?;
            if self.head_seen && self.head.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 request head is missing",
                ));
            }
        }
        Ok(self.head.take())
    }

    /// Wait for the final response HEADERS on a client stream and report its status and whether it
    /// carried a nonempty `Padding` field, leaving any DATA that followed buffered for the tunnel.
    pub(crate) fn read_response_head(&mut self) -> std::io::Result<Option<(u16, bool)>> {
        self.deadline
            .get_or_insert_with(|| Instant::now() + crate::budgets::relay_stall());
        loop {
            self.parse()?;
            if let Some(status) = self.status {
                self.deadline = None;
                return Ok(Some((status, self.padding)));
            }
            if self.ended {
                self.deadline = None;
                return Ok(None);
            }
            self.fill_room()?;
        }
    }

    /// The buffered bytes an open DATA frame can hand out without a copy.
    fn data_available(&self) -> bool {
        self.frame_left > 0 && self.buf_at < self.buf.len()
    }

    /// Drop the consumed prefix, keeping an incomplete frame's header for the next read.
    fn compact(&mut self) {
        if self.buf_at == 0 {
            return;
        }
        if self.buf_at == self.buf.len() {
            self.buf.clear();
        } else {
            self.buf.drain(..self.buf_at);
        }
        self.buf_at = 0;
    }

    /// Take one transport read into the framing buffer.
    fn fill_room(&mut self) -> std::io::Result<()> {
        self.compact();
        if self.expired() {
            return Err(std::io::Error::other("h3 request stalled"));
        }
        let base = self.buf.len();
        // SAFETY: every byte below the watermark is initialised, and the read fills the room past it before the length counts it.
        unsafe {
            ferrox_core::read::init_room(&mut self.buf, &mut self.buf_init, base + READ_ROOM);
        }
        #[cfg(test)]
        {
            self.read_target = self.buf[base..].as_ptr() as usize;
        }
        match self.wire.read(&mut self.buf[base..]) {
            Ok(0) => {
                self.buf.truncate(base);
                self.ended = true;
            }
            Ok(n) => {
                self.buf.truncate(base + n);
                self.idle_since = None;
            }
            Err(error) if crate::proxy::is_timeout(&error) => {
                self.buf.truncate(base);
                if crate::proxy::body_deadline().is_some_and(|until| Instant::now() >= until) {
                    return Err(error);
                }
                let since = *self.idle_since.get_or_insert_with(Instant::now);
                if self.idle_expired(since) {
                    return Err(std::io::Error::other("h3 request stalled"));
                }
                if crate::proxy::relay_step_owns_poll() {
                    note_lane_grant();
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                note_lane_tick();
                std::thread::sleep(POLL);
            }
            Err(error) => {
                self.buf.truncate(base);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Parse the frames already buffered, then take one datagram's worth when nothing completes.
    fn step(&mut self) -> std::io::Result<()> {
        loop {
            if self.expired() {
                return Err(std::io::Error::other("h3 request stalled"));
            }
            if self.frame_left > 0 {
                self.fill_data()?;
                if self.data_available() {
                    self.idle_since = None;
                    return Ok(());
                }
                if self.ended {
                    return Ok(());
                }
                continue;
            }
            self.parse()?;
            if !self.expect_request {
                status_ok(self.status)?;
            }
            if self.expect_request && self.head.is_some() {
                return Ok(());
            }
            if self.frame_left > 0 {
                self.fill_data()?;
                if self.data_available() {
                    self.idle_since = None;
                    return Ok(());
                }
                if self.ended {
                    return Ok(());
                }
                continue;
            }
            if self.ended || self.head.is_some() {
                return Ok(());
            }
            self.fill_room()?;
        }
    }

    /// Consume every complete frame in the buffer, leaving an incomplete one's header in place.
    fn parse(&mut self) -> std::io::Result<()> {
        let mut at = self.buf_at;
        loop {
            let start = at;
            let Some(frame) = frames::h3_frame(&self.buf, &mut at) else {
                at = start;
                break;
            };
            let Ok(length) = usize::try_from(frame.length) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 frame too long",
                ));
            };
            if frame.kind != frames::H3_DATA && length > crate::xhttp::HEAD_LIMIT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 frame too large",
                ));
            }
            if frame.kind == frames::H3_DATA {
                if !self.head_seen {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "h3 data before headers",
                    ));
                }
                self.frame_left = length;
                self.buf_at = at;
                if length == 0 {
                    continue;
                }
                return Ok(());
            }
            let Some(end) = at.checked_add(length) else {
                at = start;
                break;
            };
            if end > self.buf.len() {
                at = start;
                break;
            }
            let payload = &self.buf[at..end];
            at = end;
            match frame.kind {
                frames::H3_HEADERS => {
                    let status = hpack::qpack_status(payload);
                    if status.is_some_and(|code| (100..200).contains(&code)) {
                        continue;
                    }
                    self.head_seen = true;
                    if self.head.is_none() && self.status.is_none() {
                        let Some((head, status)) = decode_head(payload, self.expect_request) else {
                            let missing = if self.expect_request {
                                "h3 request head is missing"
                            } else {
                                "h3 response head is missing"
                            };
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                missing,
                            ));
                        };
                        if !self.expect_request {
                            let connect_ok = self.connect
                                && status.is_some_and(|code| (200..300).contains(&code));
                            if !connect_ok {
                                self.content_length = hpack::qpack_content_length(payload)
                                    .map_err(|_| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            "h3 content-length is malformed",
                                        )
                                    })?;
                            }
                            if self.padding_head {
                                self.padding = hpack::qpack_fields(payload).is_some_and(|fields| {
                                    fields.iter().any(|(name, value)| {
                                        name.eq_ignore_ascii_case(b"padding") && !value.is_empty()
                                    })
                                });
                            }
                        }
                        self.head = head;
                        self.status = status;
                    }
                }
                frames::H3_CANCEL_PUSH => {
                    // RFC 9114 §7.2.3: `CANCEL_PUSH` belongs to the control stream, so on a request stream it is `H3_FRAME_UNEXPECTED`, a connection error; a request reset is QUIC `RESET_STREAM`, not a frame.
                    self.wire.abort(frames::H3_FRAME_UNEXPECTED);
                    self.ended = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "h3 cancel_push on a request stream",
                    ));
                }
                _ => {}
            }
            self.buf_at = at;
        }
        self.buf_at = at;
        Ok(())
    }

    /// Make the next piece of the open DATA frame available, reading only its remaining bytes.
    fn fill_data(&mut self) -> std::io::Result<()> {
        if self.frame_left == 0 {
            return Ok(());
        }
        loop {
            if self.data_available() {
                return Ok(());
            }
            self.fill_room()?;
            if self.ended {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "h3 data frame ended early",
                ));
            }
        }
    }

    fn advance(&mut self) -> std::io::Result<bool> {
        if self.expired() {
            return Err(std::io::Error::other("h3 request stalled"));
        }
        if self.data_available() {
            return Ok(true);
        }
        if self.ended {
            return self.finish();
        }
        if self.frame_left > 0 {
            self.fill_data()?;
            return Ok(self.data_available());
        }
        self.step()?;
        if self.ended {
            return self.finish();
        }
        Ok(self.data_available())
    }

    /// The stream's own end, checked wherever `step` can reach it: a clean EOF still needs a response head.
    fn finish(&self) -> std::io::Result<bool> {
        if self.frame_left > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "h3 data frame ended early",
            ));
        }
        if self.buf_at < self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "h3 frame ended early",
            ));
        }
        if !self.expect_request && !self.head_seen {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "h3 response head is missing",
            ));
        }
        Ok(false)
    }
}

fn status_ok(status: Option<u16>) -> std::io::Result<()> {
    if status.is_some_and(|code| !(200..300).contains(&code)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "h3 response is not 2xx",
        ));
    }
    Ok(())
}

impl H3Reader {
    /// A response body read that keeps waiting past the head instead of treating it as the end, for a client that cannot hand the status back before the body is drained.
    fn read_answer(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.expired() {
                return Err(std::io::Error::other("h3 request stalled"));
            }
            if self.data_available() {
                let n = self
                    .frame_left
                    .min(self.buf.len() - self.buf_at)
                    .min(buf.len());
                buf[..n].copy_from_slice(&self.buf[self.buf_at..self.buf_at + n]);
                self.buf_at += n;
                self.frame_left -= n;
                return Ok(n);
            }
            if self.frame_left > 0 {
                self.fill_data()?;
                continue;
            }
            if self.ended {
                return Ok(0);
            }
            self.parse()?;
            let _ = self.head.take();
            if self.data_available() || self.frame_left > 0 || self.ended {
                continue;
            }
            self.fill_room()?;
        }
    }
}

impl Read for H3Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let more = self.advance()?;
        status_ok(self.status)?;
        if !more {
            return Ok(0);
        }
        let n = self
            .frame_left
            .min(self.buf.len() - self.buf_at)
            .min(buf.len());
        buf[..n].copy_from_slice(&self.buf[self.buf_at..self.buf_at + n]);
        self.buf_at += n;
        self.frame_left -= n;
        Ok(n)
    }
}

impl crate::proxy::WindowRead for H3Reader {
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        let more = self.advance()?;
        status_ok(self.status)?;
        if !more {
            return Ok(crate::proxy::Window::empty());
        }
        let start = self.buf_at;
        let n = (self.buf.len() - start).min(self.frame_left);
        let end = start + n;
        self.buf_at = end;
        self.frame_left -= n;
        Ok(crate::proxy::Window::one(&self.buf[start..end]))
    }
}

/// The write half: the dispatch's H1 response head becomes HEADERS, everything after it DATA.
pub(crate) struct H3Writer {
    wire: Wire,
    head: Vec<u8>,
    headed: bool,
    pending: Vec<u8>,
    at: usize,
    input: usize,
}

impl H3Writer {
    pub(crate) fn new(wire: Wire) -> Self {
        Self {
            wire,
            head: Vec::new(),
            headed: false,
            pending: Vec::new(),
            at: 0,
            input: 0,
        }
    }
}

impl Write for H3Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.headed {
            self.head.extend_from_slice(buf);
            let Some(at) = head_end(&self.head) else {
                return Ok(buf.len());
            };
            let head = std::mem::take(&mut self.head);
            let text = std::str::from_utf8(&head[..at]).unwrap_or_default();
            if !send_fields(&self.wire, frames::H3_HEADERS, &response_fields(text)) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.headed = true;
            let body = &head[at + 4..];
            if !body.is_empty() && !send_data(&self.wire, body) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            return Ok(buf.len());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if !send_data(&self.wire, buf) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for H3Writer {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        parts.iter().all(|part| self.write_all(part).is_ok())
    }
}

impl crate::proxy::LaneWrite for H3Writer {
    #[allow(clippy::too_many_lines)]
    fn push(&mut self, data: &[u8]) -> crate::proxy::Push {
        if !self.pending.is_empty() {
            match self.wire.try_write(&self.pending[self.at..]) {
                Ok(0) => return crate::proxy::Push::Parked,
                Ok(n) => self.at += n,
                Err(error) if crate::proxy::is_timeout(&error) => {
                    return crate::proxy::Push::Parked
                }
                Err(_) => {
                    self.pending.clear();
                    self.input = 0;
                    return crate::proxy::Push::Lost;
                }
            }
            if self.at < self.pending.len() {
                return crate::proxy::Push::Parked;
            }
            let input = std::mem::take(&mut self.input);
            self.pending.clear();
            self.at = 0;
            if data.len() < input {
                return crate::proxy::Push::Lost;
            }
            return crate::proxy::Push::Took(input);
        }
        if !self.headed {
            self.head.extend_from_slice(data);
            let Some(at) = head_end(&self.head) else {
                return crate::proxy::Push::Took(data.len());
            };
            let head = std::mem::take(&mut self.head);
            let text = std::str::from_utf8(&head[..at]).unwrap_or_default();
            let body = &head[at + 4..];
            let fields = response_fields(text);
            let refs: Vec<(&str, &str)> = fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let mut block = Vec::new();
            hpack::qpack_literal_many(&refs, &mut block);
            let mut pending = Vec::with_capacity(block.len() + body.len() + 18);
            frames::quic_varint(&mut pending, frames::H3_HEADERS);
            frames::quic_varint(&mut pending, block.len() as u64);
            pending.extend_from_slice(&block);
            if !body.is_empty() {
                frames::quic_varint(&mut pending, frames::H3_DATA);
                frames::quic_varint(&mut pending, body.len() as u64);
                pending.extend_from_slice(body);
            }
            self.pending = pending;
            self.input = data.len();
            self.at = 0;
            self.headed = true;
            match self.wire.try_write(&self.pending) {
                Ok(0) => return crate::proxy::Push::Parked,
                Ok(n) => self.at = n,
                Err(error) if crate::proxy::is_timeout(&error) => {
                    return crate::proxy::Push::Parked
                }
                Err(_) => {
                    self.pending.clear();
                    self.input = 0;
                    return crate::proxy::Push::Lost;
                }
            }
            if self.at < self.pending.len() {
                return crate::proxy::Push::Parked;
            }
            self.pending.clear();
            self.at = 0;
            self.input = 0;
            return crate::proxy::Push::Took(data.len());
        }
        if data.is_empty() {
            return crate::proxy::Push::Took(0);
        }
        let take = data.len().min(H3_WRITE_CHUNK);
        let mut pending = Vec::with_capacity(take + 9);
        frames::quic_varint(&mut pending, frames::H3_DATA);
        frames::quic_varint(&mut pending, take as u64);
        pending.extend_from_slice(&data[..take]);
        self.pending = pending;
        self.input = take;
        self.at = 0;
        match self.wire.try_write(&self.pending) {
            Ok(0) => return crate::proxy::Push::Parked,
            Ok(n) => self.at = n,
            Err(error) if crate::proxy::is_timeout(&error) => return crate::proxy::Push::Parked,
            Err(_) => {
                self.pending.clear();
                self.input = 0;
                return crate::proxy::Push::Lost;
            }
        }
        if self.at < self.pending.len() {
            return crate::proxy::Push::Parked;
        }
        self.pending.clear();
        self.at = 0;
        self.input = 0;
        crate::proxy::Push::Took(take)
    }
}

/// The stream a session writes through once its head is out; the dispatch keys on this instead of
/// the H2 stream out, so the body stays raw on both HTTP/2 and HTTP/3.
#[derive(Clone)]
pub(crate) struct H3StreamOut {
    wire: Wire,
    /// The serving connection the session belongs to; a client-side out answers for no listener.
    owner: Option<Arc<quic::ConnectionToken>>,
}

impl std::fmt::Debug for H3StreamOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3StreamOut")
    }
}

impl H3StreamOut {
    pub(crate) fn new(wire: Wire, owner: Option<Arc<quic::ConnectionToken>>) -> Self {
        Self { wire, owner }
    }

    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        payload.is_empty() || send_data(&self.wire, payload)
    }

    pub(crate) fn try_write(&self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut wire = self.wire.clone();
        wire.try_write(bytes)
    }

    /// The serving connection a session binds to; a client-side out answers for no listener.
    pub(crate) fn owner(&self) -> Option<&Arc<quic::ConnectionToken>> {
        self.owner.as_ref()
    }

    pub(crate) fn end(&self) {
        self.wire.fin();
    }

    pub(crate) fn reset(&self) {
        self.wire.close();
    }
}

fn send_data(wire: &Wire, payload: &[u8]) -> bool {
    let mut frame = Vec::with_capacity(payload.len() + 9);
    frames::quic_varint(&mut frame, frames::H3_DATA);
    frames::quic_varint(&mut frame, payload.len() as u64);
    frame.extend_from_slice(payload);
    wire_ready(wire, &frame)
}

fn send_fields(wire: &Wire, kind: u64, fields: &[(String, String)]) -> bool {
    let refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&refs, &mut block);
    let mut frame = Vec::with_capacity(block.len() + 9);
    frames::quic_varint(&mut frame, kind);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    wire_ready(wire, &frame)
}

/// A frame's bytes go down one clone, and the connection keeps pumping the other direction.
fn wire_ready(wire: &Wire, bytes: &[u8]) -> bool {
    let mut wire = wire.clone();
    wire.write_all(bytes).is_ok()
}

fn response_fields(head: &str) -> Vec<(String, String)> {
    let mut fields = Vec::with_capacity(2 + head.matches("\r\n").count());
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .unwrap_or("200");
    fields.push((":status".to_owned(), status.to_owned()));
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        fields.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    fields
}

/// Decode what the receiving side reads: a request side keeps the synthesized head and the status its upload gates on, a response side keeps only the status and never builds a head it would drop.
fn decode_head(payload: &[u8], expect_request: bool) -> Option<(Option<Vec<u8>>, Option<u16>)> {
    if expect_request {
        let fields = hpack::qpack_fields(payload)?;
        let head = synth_head(&fields)?;
        Some((Some(head), hpack::qpack_status(payload)))
    } else {
        Some((None, Some(hpack::qpack_status(payload)?)))
    }
}

/// Whether a field byte can ride an HTTP/1 line: a peer that smuggles `\r\n` through QPACK would write its own headers into the head `accept_core` parses.
pub(crate) fn h1_safe(bytes: &[u8]) -> bool {
    !bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
}

/// Whether a QPACK field can be a request-line token without `accept_core` splitting it on whitespace.
pub(crate) fn h1_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
}

/// The head `accept_core` parses from a request's fields: the same shape the H2 lane synthesises.
fn synth_head(fields: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<u8>> {
    let field = |name: &[u8]| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_slice())
    };
    let method = field(b":method")?;
    let target = if method == b"CONNECT" {
        if field(b":path").is_some() || field(b":scheme").is_some() {
            return None;
        }
        field(b":authority")?
    } else {
        field(b":path")?
    };
    if !h1_token(method) || !h1_token(target) {
        return None;
    }
    let mut head = Vec::with_capacity(method.len() + target.len() + 64);
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(b" HTTP/3\r\n");
    if let Some(authority) = field(b":authority") {
        if !h1_token(authority) {
            return None;
        }
        head.extend_from_slice(b"Host: ");
        head.extend_from_slice(authority);
        head.extend_from_slice(b"\r\n");
    }
    for (name, value) in fields {
        if name.starts_with(b":") {
            continue;
        }
        if name.contains(&b':') || !h1_token(name) || !h1_safe(value) {
            return None;
        }
        head.extend_from_slice(name);
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
    Some(head)
}

/// The dial head as request fields: the pseudo-headers the H2 lane's block carries, with this
/// connection's own framing dropped.
fn block_from_text(head: &str, host: &str, scheme: &str) -> Vec<u8> {
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split_ascii_whitespace();
    let method = request.next().unwrap_or("POST");
    let target = request.next().unwrap_or("/");
    let mut fields = vec![
        (":method".to_owned(), method.to_owned()),
        (":path".to_owned(), target.to_owned()),
        (":scheme".to_owned(), scheme.to_owned()),
        (":authority".to_owned(), host.to_owned()),
    ];
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        fields.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    let refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&refs, &mut block);
    block
}

pub(crate) trait H3Service: Send + Sync {
    fn serve(
        &self,
        reader: Box<dyn crate::proxy::WindowRead + Send>,
        writer: crate::xhttp::XhttpWriter,
    );
}

/// Bind the H3 listener and run its shared QUIC driver; the returned port is the bound one.
pub(crate) fn serve_inbound(
    address: &str,
    identity: &ferrox_core::tls::TlsServerConfig,
    settings: &XhttpSettings,
    service: Arc<dyn H3Service>,
    stop: Option<Arc<crate::proxy::Stop>>,
) -> Result<u16, String> {
    let config = quic::serve_config(identity).ok_or("unreadable xhttp h3 identity")?;
    let sock = quic::bind_datagram_plain(address)
        .map_err(|error| format!("cannot bind xhttp h3 `{address}`: {error}"))?;
    let port = sock
        .local_addr()
        .map_err(|error| format!("xhttp h3 `{address}` has no local address: {error}"))?
        .port();
    let settings = settings.clone();
    let serve: quic::Serve = Arc::new(move |stream| {
        stream.preface_h3();
        serve_one(&stream, &settings, &service);
    });
    let stop_flag = stop
        .as_ref()
        .map_or_else(|| Arc::new(AtomicBool::new(false)), |stop| stop.shared());
    std::thread::Builder::new()
        .name("xhttp-h3".to_owned())
        .spawn(move || {
            quic::serve_loop(
                Datagram::plain(sock),
                &Arc::new(Mutex::new(config)),
                &serve,
                &stop_flag,
            );
            if let Some(stop) = stop {
                stop.mark_closed();
            }
        })
        .map_err(|error| format!("xhttp h3 listener: {error}"))?;
    Ok(port)
}

fn serve_one(stream: &quic::QuicStream, settings: &XhttpSettings, service: &Arc<dyn H3Service>) {
    let mut reader = H3Reader::new(Wire::Server(stream.clone()));
    let Ok(Some(head)) = reader.read_head() else {
        stream.close();
        return;
    };
    let writer = H3Writer::new(Wire::Server(stream.clone()));
    let out = H3StreamOut {
        wire: Wire::Server(stream.clone()),
        owner: stream.owner(),
    };
    let upload: crate::xhttp::Upload<H3Reader> = crate::xhttp::Upload::Window(Box::new(reader));
    match crate::xhttp::accept_core(
        &head,
        Vec::new(),
        upload,
        writer,
        settings,
        Some(crate::xhttp::StreamOut::H3(out.clone())),
        None,
    ) {
        crate::xhttp::Served::Session(reader, writer) => {
            service.serve(reader, writer);
        }
        crate::xhttp::Served::Refused => out.reset(),
        _ => {
            out.end();
        }
    }
}

/// One client request stream on the connection the session dialled.
#[derive(Clone)]
pub(crate) struct ClientStream {
    owner: Arc<H3Client>,
    conn: Arc<Mutex<QuicheConnection>>,
    sock: Arc<Datagram>,
    id: u64,
    peer_fin: Arc<AtomicBool>,
    activity: Arc<Activity>,
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.owner.dead.load(Ordering::Relaxed) {
            return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        }
        if self.peer_fin.load(Ordering::Relaxed) {
            return Ok(0);
        }
        let deadline = Instant::now() + crate::budgets::RELAY_POLL;
        loop {
            let Ok(mut conn) = self.conn.lock() else {
                return Err(std::io::Error::other("h3 connection lock poisoned"));
            };
            if self.owner.dead.load(Ordering::Relaxed) || self.owner.rejected(self.id) {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            match conn.stream_recv(self.id, buf) {
                Ok((0, true)) => {
                    self.peer_fin.store(true, Ordering::Relaxed);
                    return Ok(0);
                }
                Ok((n, fin)) => {
                    if n > 0 {
                        self.peer_fin.store(fin, Ordering::Relaxed);
                        self.activity.touch();
                        quic::flush_egress(&mut conn, &self.sock);
                        return Ok(n);
                    }
                }
                Err(quiche::Error::Done) => {}
                Err(quiche::Error::StreamReset(_)) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!("h3 stream read: {error:?}")));
                }
            }
            if conn.is_closed() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            drop(conn);
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            std::thread::sleep(left.min(POLL));
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.owner.dead.load(Ordering::Relaxed) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let deadline = Instant::now() + crate::budgets::relay_stall();
        let mut rest = bytes::Bytes::copy_from_slice(buf);
        while !rest.is_empty() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("h3 stream send timed out"));
            }
            let Ok(mut conn) = self.conn.lock() else {
                return Err(std::io::Error::other("h3 connection lock poisoned"));
            };
            if self.owner.dead.load(Ordering::Relaxed) || self.owner.rejected(self.id) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            match conn.stream_send_zc(self.id, rest.clone(), false) {
                Ok((0, _)) | Err(quiche::Error::Done) => {
                    drop(conn);
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("h3 stream send timed out"));
                    }
                    std::thread::sleep(POLL);
                }
                Ok((_, remainder)) => {
                    self.activity.touch();
                    quic::flush_egress(&mut conn, &self.sock);
                    rest = remainder.unwrap_or_default();
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!("h3 stream send: {error:?}")));
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("h3 connection lock poisoned"));
        };
        quic::flush_egress(&mut conn, &self.sock);
        Ok(())
    }
}

impl ClientStream {
    /// One non-blocking body send: no room answers zero, so a relay lane parks instead of a worker.
    pub(crate) fn try_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.owner.dead.load(Ordering::Relaxed) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("h3 connection lock poisoned"));
        };
        if self.owner.dead.load(Ordering::Relaxed) || self.owner.rejected(self.id) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        match conn.stream_send_zc(self.id, bytes::Bytes::copy_from_slice(buf), false) {
            Ok((0, _)) | Err(quiche::Error::Done) => Ok(0),
            Ok((n, _)) => {
                self.activity.touch();
                quic::flush_egress(&mut conn, &self.sock);
                Ok(n)
            }
            Err(error) => Err(std::io::Error::other(format!("h3 stream send: {error:?}"))),
        }
    }

    /// One non-blocking opening attempt: `StreamLimit` leaves the id unallocated, while a created
    /// stream may still be waiting for credit after this returns.
    fn opening_start(&mut self, buf: &[u8], deadline: Option<Instant>) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("h3 connection lock poisoned"));
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        if self.owner.dead.load(Ordering::Relaxed)
            || self.owner.rejected(self.id)
            || self.owner.draining.load(Ordering::Relaxed)
        {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        match conn.stream_send(self.id, buf, false) {
            Ok(sent) => {
                self.activity.touch();
                quic::flush_egress(&mut conn, &self.sock);
                Ok(sent)
            }
            Err(quiche::Error::Done) => Ok(0),
            Err(quiche::Error::StreamLimit) => {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            Err(error) => Err(std::io::Error::other(format!("h3 stream send: {error:?}"))),
        }
    }

    /// Finish HEADERS once the stream exists, waiting for credit without the opening lock; the
    /// drain flag only gates the first attempt, so a stream below a GOAWAY cutoff can finish.
    fn opening_rest(
        &mut self,
        buf: &[u8],
        sent: usize,
        deadline: Instant,
    ) -> std::io::Result<usize> {
        let mut rest = buf;
        let mut sent = sent;
        while !rest.is_empty() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("h3 stream send timed out"));
            }
            let Ok(mut conn) = self.conn.lock() else {
                return Err(std::io::Error::other("h3 connection lock poisoned"));
            };
            if self.owner.dead.load(Ordering::Relaxed)
                || self.owner.rejected(self.id)
                || (sent == 0 && self.owner.draining.load(Ordering::Relaxed))
            {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            match conn.stream_send(self.id, rest, false) {
                Ok(0) | Err(quiche::Error::Done) => {
                    drop(conn);
                    #[cfg(test)]
                    self.owner.credit_waits.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(POLL);
                }
                Ok(n) => {
                    sent += n;
                    self.activity.touch();
                    quic::flush_egress(&mut conn, &self.sock);
                    rest = &rest[n..];
                }
                Err(quiche::Error::StreamLimit) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!("h3 stream send: {error:?}")));
                }
            }
        }
        Ok(buf.len())
    }

    fn fin(&self) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let _ = conn.stream_send(self.id, &[], true);
        quic::flush_egress(&mut conn, &self.sock);
    }

    fn close(&self) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Read, 0);
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Write, 0);
        quic::flush_egress(&mut conn, &self.sock);
    }

    /// Closes the whole connection with an HTTP/3 application error.
    fn close_connection(&self, code: u64) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let _ = conn.close(true, code, b"");
        quic::flush_egress(&mut conn, &self.sock);
    }
}

/// Why an H3 stream did not open: the peer's stream limit is temporary, while a dead or draining
/// connection is not.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum H3OpenError {
    Full,
    Closed,
}

/// The client side of one H3 connection: streams open on the shared connection and one pump reads
/// its socket, so an upload waits on credit without stopping the downlink's datagrams.
pub(crate) struct H3Client {
    conn: Arc<Mutex<QuicheConnection>>,
    sock: Arc<Datagram>,
    next: AtomicU64,
    opening: Mutex<()>,
    dead: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
    goaway: Arc<AtomicU64>,
    #[cfg(test)]
    credit_waits: std::sync::atomic::AtomicUsize,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.dead.store(true, Ordering::Relaxed);
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn.close(false, 0, b"");
            quic::flush_egress(&mut conn, &self.sock);
        }
    }
}

impl H3Client {
    /// Whether the shared connection can still open a stream: the pump clears this once the
    /// connection closes, and a pooled client that fails this is dropped rather than reused.
    pub(crate) fn reusable(&self) -> bool {
        !self.dead.load(Ordering::Relaxed) && !self.draining.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn waited_for_credit(&self) -> bool {
        self.credit_waits.load(Ordering::Relaxed) > 0
    }

    fn rejected(&self, id: u64) -> bool {
        id >= self.goaway.load(Ordering::SeqCst)
    }

    pub(crate) fn connect(
        peer: SocketAddr,
        server_name: &str,
        tls: &ferrox_core::tls::TlsConfig,
    ) -> Option<Arc<Self>> {
        Self::connect_tuned(peer, server_name, tls, None, true)
    }

    pub(crate) fn connect_tuned(
        peer: SocketAddr,
        server_name: &str,
        tls: &ferrox_core::tls::TlsConfig,
        quic_params: Option<&ferrox_core::hysteria::QuicParams>,
        default_bbr: bool,
    ) -> Option<Arc<Self>> {
        Self::connect_windowed(
            peer,
            server_name,
            tls,
            quic_params,
            default_bbr,
            None,
            None,
            None,
        )
    }

    /// The reference's `stream_receive_window` and `quic_session_receive_window` on one dial: the
    /// stream window bounds a CONNECT's downlink, the session window bounds the whole connection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connect_windowed(
        peer: SocketAddr,
        server_name: &str,
        tls: &ferrox_core::tls::TlsConfig,
        quic_params: Option<&ferrox_core::hysteria::QuicParams>,
        default_bbr: bool,
        cc: Option<ferrox_core::hysteria::Congestion>,
        stream_window: Option<u64>,
        session_window: Option<u64>,
    ) -> Option<Arc<Self>> {
        Self::connect_windowed_by(
            peer,
            server_name,
            tls,
            quic_params,
            default_bbr,
            cc,
            stream_window,
            session_window,
            crate::budgets::handshake(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connect_windowed_by(
        peer: SocketAddr,
        server_name: &str,
        tls: &ferrox_core::tls::TlsConfig,
        quic_params: Option<&ferrox_core::hysteria::QuicParams>,
        default_bbr: bool,
        cc: Option<ferrox_core::hysteria::Congestion>,
        stream_window: Option<u64>,
        session_window: Option<u64>,
        budget: Duration,
    ) -> Option<Arc<Self>> {
        let mut config = if tls.insecure || !tls.cert_pins.is_empty() {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
            config.verify_peer(false);
            if !quic::tune(&mut config, quic::ALPN) {
                return None;
            }
            config
        } else {
            quic::quiche_config(&tls.roots, None)?
        };
        config.set_initial_max_data(16 * 1024 * 1024);
        if let Some(params) = quic_params {
            if params.cc == Some(ferrox_core::hysteria::Congestion::Brutal) {
                return None;
            }
            quic::apply_hysteria_quic(&mut config, params, false);
        }
        if let Some(window) = stream_window {
            let window = window.max(9);
            config.set_initial_max_stream_data_bidi_local(window);
            config.set_initial_max_stream_data_bidi_remote(window);
            config.set_max_stream_window(window);
        }
        if let Some(window) = session_window {
            let window = window.max(2);
            config.set_initial_max_data(window);
            config.set_max_connection_window(window);
        }
        let cc = cc.or_else(|| {
            quic::lane_controller(quic_params.and_then(|params| params.cc), default_bbr)
        });
        quic::apply_lane_congestion(&mut config, cc, quic_params)?;
        let sock = if peer.is_ipv6() {
            quic::bind_datagram("[::]:0").ok()?
        } else {
            quic::bind_datagram("0.0.0.0:0").ok()?
        };
        let local = sock.local_addr().ok()?;
        let net = quic::network_generation();
        let sock = Arc::new(Datagram::plain(sock));
        sock.remember_source(peer)?;
        let mut scid = [0u8; 16];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect_with_buffer_factory::<crate::quic::BytesBufFactory>(
            Some(server_name),
            &cid,
            local,
            peer,
            &mut config,
        )
        .ok()?;
        if let Some(list) = &tls.ech_config_list {
            conn.as_mut().set_ech_config_list(list).ok()?;
        }
        quic::drive_handshake_by(&mut conn, &sock, local, budget)?;
        if !tls.cert_pins.is_empty() {
            let chain: Vec<Vec<u8>> = match conn.peer_cert_chain() {
                Some(chain) => chain.iter().map(|cert| cert.to_vec()).collect(),
                None => conn
                    .peer_cert()
                    .map(|cert| vec![cert.to_vec()])
                    .unwrap_or_default(),
            };
            if !ferrox_core::tls::verify_cert_pinned(&chain, &tls.cert_pins, server_name) {
                return None;
            }
        }
        quic::send_h3_opening(&mut conn, &sock);
        let conn = Arc::new(Mutex::new(conn));
        let dead = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let goaway = Arc::new(AtomicU64::new(u64::MAX));
        let (pump, pump_sock) = (Arc::clone(&conn), Arc::clone(&sock));
        let (pump_dead, pump_draining) = (Arc::clone(&dead), Arc::clone(&draining));
        let pump_goaway = Arc::clone(&goaway);
        std::thread::Builder::new()
            .name("xhttp-h3-pump".to_owned())
            .spawn(move || {
                pump_connection(
                    &pump,
                    &pump_sock,
                    local,
                    peer,
                    net,
                    &pump_draining,
                    &pump_goaway,
                );
                pump_dead.store(true, Ordering::Relaxed);
            })
            .ok()?;
        Some(Arc::new(Self {
            conn,
            sock,
            next: AtomicU64::new(0),
            opening: Mutex::new(()),
            dead,
            draining,
            goaway,
            #[cfg(test)]
            credit_waits: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    fn open(self: &Arc<Self>, block: &[u8], end_request: bool) -> Option<(H3Reader, H3StreamOut)> {
        self.open_with(block, end_request, Arc::new(Activity::new()), None)
            .ok()
    }

    /// A `NaiveProxy` CONNECT block: the caller frames its own tunnel, so no xHTTP writer is built, and its absolute handshake deadline carries through the opening write and the answer's first head.
    pub(crate) fn open_block_until(
        self: &Arc<Self>,
        block: &[u8],
        end_request: bool,
        deadline: Instant,
    ) -> Result<(H3Reader, H3StreamOut), H3OpenError> {
        let (mut reader, out) = self.open_with(
            block,
            end_request,
            Arc::new(Activity::new()),
            Some(deadline),
        )?;
        reader.padding_head = true;
        reader.connect = true;
        Ok((reader, out))
    }

    fn open_with(
        self: &Arc<Self>,
        block: &[u8],
        end_request: bool,
        activity: Arc<Activity>,
        deadline: Option<Instant>,
    ) -> Result<(H3Reader, H3StreamOut), H3OpenError> {
        let expiry = deadline;
        let deadline = deadline.unwrap_or_else(|| Instant::now() + crate::budgets::relay_stall());
        let Ok(opening) = self.opening.lock() else {
            return Err(H3OpenError::Closed);
        };
        if self.dead.load(Ordering::Relaxed) || self.draining.load(Ordering::Relaxed) {
            return Err(H3OpenError::Closed);
        }
        let id = self.next.load(Ordering::SeqCst);
        if self.rejected(id) {
            return Err(H3OpenError::Closed);
        }
        let wire = Wire::Client(ClientStream {
            owner: Arc::clone(self),
            conn: Arc::clone(&self.conn),
            sock: Arc::clone(&self.sock),
            id,
            peer_fin: Arc::new(AtomicBool::new(false)),
            activity,
        });
        let mut frame = Vec::with_capacity(block.len() + 9);
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(block);
        let mut writer = wire.clone();
        let sent = match writer.opening_start(&frame, expiry) {
            Ok(sent) => {
                self.next.store(id + 4, Ordering::SeqCst);
                sent
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(H3OpenError::Full);
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                wire.close();
                return Err(H3OpenError::Closed);
            }
            Err(_) => {
                self.next.store(id + 4, Ordering::SeqCst);
                wire.close();
                return Err(H3OpenError::Closed);
            }
        };
        drop(opening);
        if sent < frame.len() && writer.opening_rest(&frame[sent..], sent, deadline).is_err() {
            wire.close();
            return Err(H3OpenError::Closed);
        }
        if end_request {
            wire.fin();
        }
        let mut reader = H3Reader::new(wire.clone());
        if expiry.is_some() {
            reader.deadline = Some(deadline);
        }
        Ok((reader, H3StreamOut { wire, owner: None }))
    }

    /// One plain HTTP/3 request and its answer: the head becomes HEADERS, the body DATA, and the reply's status and body come back without the xhttp framing.
    pub(crate) fn ask(
        self: &Arc<Self>,
        head: &str,
        host: &str,
        body: Option<&[u8]>,
        limit: Option<usize>,
    ) -> std::io::Result<(u16, Vec<u8>)> {
        let block = block_from_text(head, host, "https");
        let (mut reader, out) = self
            .open(&block, body.is_none())
            .ok_or_else(|| std::io::Error::other("h3 service lane did not open"))?;
        if let Some(payload) = body {
            if !payload.is_empty() && !out.data(payload) {
                out.reset();
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            out.end();
        }
        reader.set_deadline(Instant::now() + crate::budgets::relay_stall());
        let mut answer = Vec::new();
        let mut buf = [0u8; READ_ROOM];
        loop {
            match reader.read_answer(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if limit.is_some_and(|cap| answer.len().saturating_add(n) > cap) {
                        out.reset();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "h3 service answer is too long",
                        ));
                    }
                    answer.extend_from_slice(&buf[..n]);
                }
                Err(error) => {
                    out.reset();
                    return Err(error);
                }
            }
        }
        let status = reader.status().ok_or_else(|| {
            out.reset();
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "h3 service answer has no status",
            )
        })?;
        if let Some(declared) = reader.content_length() {
            let head_only = head
                .split_ascii_whitespace()
                .next()
                .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
            if !head_only && !matches!(status, 204 | 304) && answer.len() != declared {
                out.reset();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 service answer was truncated",
                ));
            }
        }
        Ok((status, answer))
    }

    fn packet(
        self: &Arc<Self>,
        host: &str,
        settings: &XhttpSettings,
        session: &str,
        seq: u64,
        piece: &[u8],
        activity: Arc<Activity>,
    ) -> bool {
        let (head, body) = crate::xhttp::packet_head(host, settings, session, seq, piece);
        let block = block_from_text(&head, host, "https");
        let deadline = Instant::now() + crate::budgets::relay_stall();
        let Some((mut reader, out)) = self.open_with(&block, false, activity, None).ok() else {
            return false;
        };
        reader.set_deadline(deadline);
        if let Some(body) = body {
            if !out.data(body) {
                out.reset();
                return false;
            }
        }
        out.end();
        let mut sink = [0u8; 64];
        loop {
            match reader.read(&mut sink) {
                Ok(0) => {
                    return reader
                        .status()
                        .is_some_and(|code| (200..300).contains(&code));
                }
                Ok(_) => {}
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(_) => {
                    reader.reset();
                    return false;
                }
            }
        }
    }
}

/// Answer one run of queued datagrams under one connection lock: a burst costs one lock, one timer sweep and
/// one egress sweep for the run rather than one of each per packet.
#[cfg(target_os = "linux")]
fn drain_batch(
    conn: &Arc<Mutex<QuicheConnection>>,
    sock: &Datagram,
    local: SocketAddr,
    batch: &mut quic::Batch,
    moved: bool,
) -> bool {
    let Ok(mut conn) = conn.lock() else {
        return false;
    };
    for at in 0..batch.len() {
        let Some((bytes, from)) = batch.at(at) else {
            continue;
        };
        let _ = conn.recv(bytes, quiche::RecvInfo { from, to: local });
    }
    if conn.is_closed() {
        return false;
    }
    conn.on_timeout();
    quic::flush_egress(&mut conn, sock);
    if moved && quic::path_failed(&mut conn, local) {
        let _ = conn.close(false, 0, b"rebind");
        return false;
    }
    true
}

/// The server control stream's identity and buffered frames, shared by the drain and idle sweeps.
#[derive(Default)]
struct ControlState {
    buf: Vec<u8>,
    id: Option<u64>,
    skipped: Vec<u64>,
    /// Peer QPACK encoder and decoder streams: critical, so their payload is drained but never stopped.
    critical: Vec<u64>,
    encoder: Option<u64>,
    decoder: Option<u64>,
    skip: u64,
    /// Whether the control stream's first frame was SETTINGS, as RFC 9114 requires.
    settings: bool,
    /// The stream-type bytes seen so far per unidirectional stream, so a varint split across reads
    /// is not mistaken for an unknown stream and stopped.
    types: HashMap<u64, Vec<u8>>,
}

/// Run the connection's timers and answer what they queued, once the sock has nothing left to read.
fn sweep(
    conn: &Arc<Mutex<QuicheConnection>>,
    sock: &Datagram,
    local: SocketAddr,
    moved: bool,
    control: &mut ControlState,
    draining: &Arc<AtomicBool>,
    goaway: &AtomicU64,
) -> bool {
    let Ok(mut conn) = conn.lock() else {
        return false;
    };
    if conn.is_closed() {
        return false;
    }
    conn.on_timeout();
    quic::flush_egress(&mut conn, sock);
    if moved && quic::path_failed(&mut conn, local) {
        let _ = conn.close(false, 0, b"rebind");
        return false;
    }
    match h3_control_goaway(&mut conn, control, goaway) {
        Some(true) => draining.store(true, Ordering::Relaxed),
        Some(false) => {}
        None => {
            quic::flush_egress(&mut conn, sock);
            return false;
        }
    }
    true
}

fn drain_stream(conn: &mut QuicheConnection, id: u64) {
    let mut chunk = [0u8; 1024];
    while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
        if n == 0 {
            break;
        }
    }
}

/// The server's HTTP/3 control stream: its type, SETTINGS, then a GOAWAY that ends new requests but
/// not the tunnels already open. The stream is found by its type, and a partial frame stays
/// buffered until the next read completes it.
fn h3_control_goaway(
    conn: &mut QuicheConnection,
    control: &mut ControlState,
    goaway: &AtomicU64,
) -> Option<bool> {
    if control.id.is_some_and(|id| conn.stream_finished(id))
        || control.critical.iter().any(|id| conn.stream_finished(*id))
    {
        let _ = conn.close(true, H3_CLOSED_CRITICAL_STREAM, b"critical stream closed");
        return None;
    }
    let ids: Vec<u64> = conn
        .readable()
        .filter(|id| *id % 4 == 3 && !control.skipped.contains(id))
        .collect();
    for id in ids {
        if Some(id) != control.id {
            if !control.critical.contains(&id) {
                let Some(kind) = read_stream_varint(conn, id, &mut control.types) else {
                    continue;
                };
                match kind {
                    0 => {
                        if control.id.is_some() {
                            let _ = conn.close(
                                true,
                                H3_STREAM_CREATION_ERROR,
                                b"duplicate control stream",
                            );
                            return None;
                        }
                        control.id = Some(id);
                    }
                    2 => {
                        if control.encoder.is_some() {
                            let _ = conn.close(
                                true,
                                H3_STREAM_CREATION_ERROR,
                                b"duplicate qpack encoder",
                            );
                            return None;
                        }
                        // RFC 9204: QPACK encoder and decoder streams are critical; never STOP_SENDING them.
                        control.encoder = Some(id);
                        control.critical.push(id);
                    }
                    3 => {
                        if control.decoder.is_some() {
                            let _ = conn.close(
                                true,
                                H3_STREAM_CREATION_ERROR,
                                b"duplicate qpack decoder",
                            );
                            return None;
                        }
                        control.decoder = Some(id);
                        control.critical.push(id);
                    }
                    _ => {
                        // An unknown stream has no reader here, so stop its payload holding credit.
                        if conn.stream_shutdown(id, quiche::Shutdown::Read, 0).is_err() {
                            control.skipped.push(id);
                        }
                        continue;
                    }
                }
            }
            if Some(id) != control.id {
                drain_stream(conn, id);
                if control.critical.contains(&id) && conn.stream_finished(id) {
                    let _ = conn.close(true, H3_CLOSED_CRITICAL_STREAM, b"critical stream closed");
                    return None;
                }
                continue;
            }
        }
        let mut chunk = [0u8; 1024];
        while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
            control.buf.extend_from_slice(&chunk[..n]);
        }
        if conn.stream_finished(id) {
            let _ = conn.close(true, H3_CLOSED_CRITICAL_STREAM, b"critical stream closed");
            return None;
        }
    }
    match h3_control_frames(
        &mut control.buf,
        &mut control.skip,
        &mut control.settings,
        goaway,
    ) {
        Ok(drain) => Some(drain),
        Err(code) => {
            let _ = conn.close(true, code, b"invalid control frame");
            None
        }
    }
}

/// Consume buffered control frames, skipping an unknown payload as it arrives so the next frame
/// still starts on its own boundary; a GOAWAY after a large frame is not lost with the payload.
fn h3_control_frames(
    control: &mut Vec<u8>,
    skip: &mut u64,
    settings: &mut bool,
    goaway: &AtomicU64,
) -> Result<bool, u64> {
    if *skip > 0 {
        let drop = (*skip).min(control.len() as u64) as usize;
        control.drain(..drop);
        *skip -= drop as u64;
        if *skip > 0 {
            return Ok(false);
        }
    }
    let mut draining = false;
    loop {
        let mut at = 0;
        let Some(kind) = frames::quic_read(&control[..], &mut at) else {
            break;
        };
        let Some(len) = frames::quic_read(&control[..], &mut at) else {
            break;
        };
        let Ok(len) = usize::try_from(len) else {
            control.clear();
            break;
        };
        if kind == 0x7 && !(1..=8).contains(&len) {
            return Err(H3_FRAME_ERROR);
        }
        let Some(end) = at.checked_add(len) else {
            control.clear();
            break;
        };
        if !*settings {
            if kind != 0x4 {
                return Err(H3_MISSING_SETTINGS);
            }
            if end > control.len() {
                break;
            }
            let mut cursor = at;
            while cursor < end {
                let Some(id) = frames::quic_read(&control[..end], &mut cursor) else {
                    return Err(H3_FRAME_ERROR);
                };
                let Some(_value) = frames::quic_read(&control[..end], &mut cursor) else {
                    return Err(H3_FRAME_ERROR);
                };
                // RFC 9114 7.2.4: the HTTP/2 settings identifiers are reserved here, so a peer that sends one has broken SETTINGS, not sent an extension.
                if (0x02..=0x05).contains(&id) {
                    return Err(H3_SETTINGS_ERROR);
                }
            }
            *settings = true;
            control.drain(..end);
            continue;
        }
        // Only GOAWAY belongs on the server control stream; DATA, HEADERS, CANCEL_PUSH, SETTINGS, PUSH_PROMISE, MAX_PUSH_ID, PRIORITY_UPDATE and the HTTP/2 reserved types are H3_FRAME_UNEXPECTED, unassigned types ignored.
        if matches!(
            kind,
            0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x5 | 0x6 | 0x8 | 0x9 | 0xd | 0xF0700 | 0xF0701
        ) {
            return Err(H3_FRAME_UNEXPECTED);
        }
        if end > control.len() {
            if kind != 0x7 {
                let held = control.len().saturating_sub(at);
                control.drain(..control.len());
                *skip = (len - held) as u64;
            }
            break;
        }
        if kind == 0x7 {
            let mut cursor = at;
            let Some(cutoff) = frames::quic_read(&control[..end], &mut cursor) else {
                return Err(H3_FRAME_ERROR);
            };
            if cursor != end {
                return Err(H3_FRAME_ERROR);
            }
            if cutoff % 4 != 0 || cutoff > goaway.load(Ordering::SeqCst) {
                return Err(H3_ID_ERROR);
            }
            goaway.fetch_min(cutoff, Ordering::SeqCst);
            control.drain(..end);
            draining = true;
            continue;
        }
        control.drain(..end);
    }
    if *skip == 0 && control.len() > 64 * 1024 {
        control.clear();
    }
    Ok(draining)
}

/// Read just the stream-type varint from a unidirectional stream, leaving its frames unread and
/// keeping a partial varint until the next read completes it.
fn read_stream_varint(
    conn: &mut QuicheConnection,
    id: u64,
    types: &mut HashMap<u64, Vec<u8>>,
) -> Option<u64> {
    loop {
        let (kind, len) = {
            let bytes = types.entry(id).or_default();
            let mut at = 0;
            (frames::quic_read(bytes, &mut at), bytes.len())
        };
        if let Some(kind) = kind {
            types.remove(&id);
            return Some(kind);
        }
        if len >= 8 {
            types.remove(&id);
            return None;
        }
        let mut byte = [0u8; 1];
        match conn.stream_recv(id, &mut byte) {
            Ok((1, fin)) => {
                types.entry(id).or_default().push(byte[0]);
                if fin {
                    let kind = types.get(&id).and_then(|bytes| {
                        let mut at = 0;
                        frames::quic_read(bytes, &mut at)
                    });
                    types.remove(&id);
                    return kind;
                }
            }
            Ok((_, fin)) => {
                if fin {
                    types.remove(&id);
                }
                return None;
            }
            Err(quiche::Error::Done) => return None,
            Err(_) => {
                types.remove(&id);
                return None;
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn pump_connection(
    conn: &Arc<Mutex<QuicheConnection>>,
    sock: &Arc<Datagram>,
    local: SocketAddr,
    peer: SocketAddr,
    generation: u64,
    draining: &Arc<AtomicBool>,
    goaway: &AtomicU64,
) {
    let mut local = local;
    let mut generation = generation;
    let mut moved = false;
    let mut buf = vec![0u8; 65535];
    let mut control = ControlState::default();
    #[cfg(target_os = "linux")]
    let mut batch = quic::Batch::new();
    loop {
        let now = quic::network_generation();
        if now != generation {
            if let Ok(mut conn) = conn.lock() {
                match quic::rebind_path(&mut conn, sock, peer) {
                    quic::Rebind::Moved(at) => {
                        local = at;
                        moved = true;
                        generation = now;
                    }
                    quic::Rebind::Same | quic::Rebind::Retry | quic::Rebind::Unsupported => {
                        generation = now;
                    }
                    quic::Rebind::Failed => {
                        let _ = conn.close(false, 0, b"rebind");
                        break;
                    }
                }
            }
        }
        let wait = conn
            .lock()
            .ok()
            .and_then(|conn| conn.timeout())
            .map_or(TICK, |left| left.min(TICK))
            .max(Duration::from_millis(1));
        // A Linux lane takes the whole queue per wake, one lock and one timer sweep per burst.
        #[cfg(target_os = "linux")]
        {
            if !sock.refresh_read_timeout(wait) {
                break;
            }
            match quic::recv_batch(sock, &mut batch) {
                quic::Drain::Read => {
                    if drain_batch(conn, sock, local, &mut batch, moved)
                        && sweep(conn, sock, local, moved, &mut control, draining, goaway)
                    {
                        continue;
                    }
                    break;
                }
                quic::Drain::Empty => {
                    if sweep(conn, sock, local, moved, &mut control, draining, goaway) {
                        continue;
                    }
                    break;
                }
                quic::Drain::Unbatchable => {}
                quic::Drain::Unreadable => break,
            }
        }
        let _ = sock.set_read_timeout(Some(wait));
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Ok(mut conn) = conn.lock() {
                    let _ = conn.recv(&mut buf[..n], quiche::RecvInfo { from, to: local });
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
        if !sweep(conn, sock, local, moved, &mut control, draining, goaway) {
            break;
        }
    }
}

struct H3Post {
    client: Arc<H3Client>,
    host: String,
    settings: XhttpSettings,
    session: String,
    activity: Arc<Activity>,
}

impl crate::xhttp::PacketPost for H3Post {
    fn post(&mut self, seq: u64, piece: &[u8]) -> bool {
        self.client.packet(
            &self.host,
            &self.settings,
            &self.session,
            seq,
            piece,
            Arc::clone(&self.activity),
        )
    }
}

struct NullWrite;

impl Write for NullWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for NullWrite {
    fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
        true
    }
}

pub(crate) fn is_h3(alpn: &[Vec<u8>]) -> bool {
    alpn.len() == 1 && alpn[0].as_slice() == b"h3"
}

pub(crate) fn connect_split(
    peer: SocketAddr,
    host: &str,
    settings: &XhttpSettings,
    tls: &ferrox_core::tls::TlsConfig,
) -> Option<(H3Reader, crate::xhttp::XhttpWriter)> {
    let name = if tls.server_name.is_empty() {
        host
    } else {
        &tls.server_name
    };
    let client = H3Client::connect(peer, name, tls)?;
    let head = crate::xhttp::dial_head(host, settings, "", None);
    let block = block_from_text(&head, host, "https");
    let (reader, out) = client.open(&block, false)?;
    let writer = crate::xhttp::XhttpWriter::new(NullWrite);
    writer.set_stream(crate::xhttp::StreamOut::H3(out));
    Some((reader, writer))
}

pub(crate) fn connect_dual_split(
    peer: SocketAddr,
    host: &str,
    settings: &XhttpSettings,
    tls: &ferrox_core::tls::TlsConfig,
) -> Option<(H3Reader, crate::xhttp::XhttpWriter)> {
    let name = if tls.server_name.is_empty() {
        host
    } else {
        &tls.server_name
    };
    let client = H3Client::connect(peer, name, tls)?;
    let session = settings.session_id();
    let down = crate::xhttp::downlink_head(host, settings, &session);
    let block = block_from_text(&down, host, "https");
    let activity = Arc::new(Activity::new());
    let (reader, _) = client
        .open_with(&block, true, Arc::clone(&activity), None)
        .ok()?;
    let writer = if settings.mode == XhttpMode::PacketUp {
        crate::xhttp::XhttpWriter::packets_h3(
            Arc::clone(&client),
            host,
            settings,
            session,
            Arc::clone(&activity),
        )
    } else {
        let up = crate::xhttp::dial_head(host, settings, &session, None);
        let block = block_from_text(&up, host, "https");
        let (_, out) = client.open_with(&block, false, activity, None).ok()?;
        let writer = crate::xhttp::XhttpWriter::new(NullWrite);
        writer.set_stream(crate::xhttp::StreamOut::H3(out));
        writer
    };
    Some((reader, writer))
}

pub(crate) fn packets(
    client: Arc<H3Client>,
    host: &str,
    settings: &XhttpSettings,
    session: String,
    activity: Arc<Activity>,
) -> crate::xhttp::XhttpWriter {
    let post = H3Post {
        client,
        host: host.to_owned(),
        settings: settings.clone(),
        session,
        activity,
    };
    crate::xhttp::XhttpWriter::packets_with(Box::new(post), settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::WindowRead;

    struct Recorder(Arc<std::sync::Mutex<Option<std::io::ErrorKind>>>);

    impl H3Service for Recorder {
        fn serve(
            &self,
            mut reader: Box<dyn WindowRead + Send>,
            _writer: crate::xhttp::XhttpWriter,
        ) {
            let mut buf = [0u8; 16];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) => {
                        *self.0.lock().expect("recorder lock") = Some(error.kind());
                        break;
                    }
                }
            }
        }
    }

    struct Echo;

    impl H3Service for Echo {
        fn serve(&self, mut reader: Box<dyn WindowRead + Send>, writer: crate::xhttp::XhttpWriter) {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !writer.send(&buf[..n]) {
                            break;
                        }
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || crate::proxy::is_timeout(&error) => {}
                    Err(_) => break,
                }
            }
            writer.finish();
        }
    }

    fn minted_identity(name: &str) -> (ferrox_core::tls::TlsServerConfig, Vec<Vec<u8>>) {
        let minted = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("mints");
        let roots = quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let identity = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: roots.clone(),
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: vec![b"h3".to_vec()],
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

    /// Run one scripted answer per request stream, without the xhttp dispatch.
    fn serve_scripted(
        identity: &ferrox_core::tls::TlsServerConfig,
        script: impl Fn(&Wire) + Send + Sync + 'static,
    ) -> u16 {
        serve_scripted_with_streams(identity, None, script)
    }

    fn serve_scripted_with_streams(
        identity: &ferrox_core::tls::TlsServerConfig,
        streams: Option<u64>,
        script: impl Fn(&Wire) + Send + Sync + 'static,
    ) -> u16 {
        let mut config = quic::serve_config(identity).expect("the h3 server config");
        if let Some(streams) = streams {
            config.set_initial_max_streams_bidi(streams);
        }
        let sock = quic::bind_datagram_plain("127.0.0.1:0").expect("the h3 server binds");
        let port = sock.local_addr().expect("the h3 server address").port();
        let serve: quic::Serve = Arc::new(move |stream| {
            stream.preface_h3();
            let wire = Wire::Server(stream);
            let mut reader = H3Reader::new(wire.clone());
            let _ = reader.read_head();
            script(&wire);
            wire.fin();
        });
        std::thread::Builder::new()
            .name("xhttp-h3-answer".to_owned())
            .spawn(move || {
                quic::serve_loop(
                    Datagram::plain(sock),
                    &Arc::new(Mutex::new(config)),
                    &serve,
                    &Arc::new(AtomicBool::new(false)),
                );
            })
            .expect("the h3 answer thread");
        port
    }

    fn serve_ignored_with_streams(
        identity: &ferrox_core::tls::TlsServerConfig,
        streams: u64,
        stream_window: u64,
    ) -> u16 {
        let mut config = quic::serve_config(identity).expect("the h3 server config");
        config.set_initial_max_streams_bidi(streams);
        config.set_initial_max_stream_data_bidi_remote(stream_window);
        config.set_initial_max_data(1 << 20);
        let sock = quic::bind_datagram_plain("127.0.0.1:0").expect("the h3 server binds");
        let port = sock.local_addr().expect("the h3 server address").port();
        let serve: quic::Serve = Arc::new(|_| {});
        std::thread::Builder::new()
            .name("xhttp-h3-ignored".to_owned())
            .spawn(move || {
                quic::serve_loop(
                    Datagram::plain(sock),
                    &Arc::new(Mutex::new(config)),
                    &serve,
                    &Arc::new(AtomicBool::new(false)),
                );
            })
            .expect("the h3 ignored thread");
        port
    }

    /// Answer every request with one status and body, without the xhttp dispatch: the shape a plain store service speaks.
    fn serve_answer(
        identity: &ferrox_core::tls::TlsServerConfig,
        status: &'static str,
        body: &'static [u8],
    ) -> u16 {
        serve_scripted(identity, move |wire| {
            let length = body.len().to_string();
            let fields = [
                (":status".to_owned(), status.to_owned()),
                ("content-length".to_owned(), length),
            ];
            if send_fields(wire, frames::H3_HEADERS, &fields) {
                let _ = send_data(wire, body);
            }
        })
    }

    fn settings() -> XhttpSettings {
        XhttpSettings {
            path: "/x".to_owned(),
            mode: XhttpMode::StreamOne,
            mode_source: crate::xhttp::ModeSource::Stated,
            ..XhttpSettings::stream_one()
        }
    }

    fn dual_settings(mode: XhttpMode) -> XhttpSettings {
        XhttpSettings {
            mode,
            mode_source: crate::xhttp::ModeSource::Stated,
            ..settings()
        }
    }

    fn dial(
        port: u16,
        settings: &XhttpSettings,
        roots: Vec<Vec<u8>>,
    ) -> (H3Reader, crate::xhttp::XhttpWriter) {
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        connect_dual_split(
            SocketAddr::from(([127, 0, 0, 1], port)),
            "localhost",
            settings,
            &tls,
        )
        .expect("the h3 streams open")
    }

    fn client(port: u16, roots: Vec<Vec<u8>>) -> Arc<H3Client> {
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        H3Client::connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost", &tls)
            .expect("the h3 client connects")
    }

    #[test]
    fn a_full_h3_open_does_not_consume_a_stream_id() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_scripted_with_streams(&identity, Some(1), |_| {});
        let client = client(port, roots);
        let head = "POST /o HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let block = block_from_text(head, "localhost", "https");
        let _first = client
            .open_block_until(
                &block,
                false,
                Instant::now() + crate::budgets::relay_stall(),
            )
            .expect("the first h3 stream opens");
        assert!(matches!(
            client.open_block_until(
                &block,
                false,
                Instant::now() + crate::budgets::relay_stall()
            ),
            Err(H3OpenError::Full)
        ));
        assert_eq!(client.next.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn a_second_h3_open_completes_while_the_first_waits_for_credit() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_ignored_with_streams(&identity, 4, 100);
        let client = client(port, roots);
        let large = vec![b'x'; 200];
        let small = vec![b'y'; 20];
        let first_client = Arc::clone(&client);
        let first = std::thread::spawn(move || {
            first_client.open_block_until(
                &large,
                false,
                Instant::now() + crate::budgets::relay_stall(),
            )
        });
        let started = Instant::now();
        while client.next.load(Ordering::SeqCst) == 0 || !client.waited_for_credit() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the first open never waited for credit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let client = Arc::clone(&client);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if !stop.load(Ordering::Relaxed) {
                    client.dead.store(true, Ordering::Relaxed);
                }
            })
        };
        let second = client.open_block_until(
            &small,
            false,
            Instant::now() + crate::budgets::relay_stall(),
        );
        assert!(
            second.is_ok(),
            "the second open completed while the first waited"
        );
        assert!(
            !first.is_finished(),
            "the first open finished instead of waiting for credit"
        );
        stop.store(true, Ordering::Relaxed);
        client.dead.store(true, Ordering::Relaxed);
        let _ = first.join();
        let _ = watchdog.join();
    }

    #[test]
    fn an_h3_alpn_is_case_sensitive() {
        assert!(is_h3(&[b"h3".to_vec()]));
        assert!(!is_h3(&[b"H3".to_vec()]));
        assert!(!is_h3(&[b"h3".to_vec(), b"h2".to_vec()]));
    }

    fn raw_stream(client: &Arc<H3Client>) -> Wire {
        let _opening = client.opening.lock().expect("h3 opening lock");
        let id = client.next.fetch_add(4, Ordering::SeqCst);
        Wire::Client(ClientStream {
            owner: Arc::clone(client),
            conn: Arc::clone(&client.conn),
            sock: Arc::clone(&client.sock),
            id,
            peer_fin: Arc::new(AtomicBool::new(false)),
            activity: Arc::new(Activity::new()),
        })
    }

    #[test]
    fn a_dead_h3_client_fails_its_attached_streams() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_answer(&identity, "200", b"");
        let client = client(port, roots);
        let mut wire = raw_stream(&client);
        client.dead.store(true, Ordering::Relaxed);
        let mut room = [0u8; 1];
        assert_eq!(
            wire.read(&mut room).unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            wire.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    fn send_frame(wire: &Wire, kind: u64, payload: &[u8]) {
        let mut frame = Vec::with_capacity(payload.len() + 9);
        frames::quic_varint(&mut frame, kind);
        frames::quic_varint(&mut frame, payload.len() as u64);
        frame.extend_from_slice(payload);
        wire.clone().write_all(&frame).expect("the frame sends");
    }

    fn refused(reader: &mut H3Reader, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut buf = [0u8; 1];
            match reader.read(&mut buf) {
                Ok(0) => panic!("{what} ended as a clean EOF"),
                Ok(_) => panic!("{what} was answered"),
                Err(error) if crate::proxy::is_timeout(&error) => {
                    assert!(Instant::now() < deadline, "{what} never refused");
                }
                Err(_) => return,
            }
        }
    }

    /// A plain HTTP/3 request keeps its status and body, including a refusal the xhttp framing would treat as a dead stream.
    #[test]
    fn a_plain_h3_request_keeps_its_status_and_body() {
        let (identity, roots) = minted_identity("localhost");
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            alpn: vec![b"h3".to_vec()].into(),
            ..Default::default()
        };
        for (status, body) in [("200", b"world".as_slice()), ("404", b"missing".as_slice())] {
            let port = serve_answer(&identity, status, body);
            let client =
                H3Client::connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost", &tls)
                    .expect("the h3 service lane");
            let head = "POST /o HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n";
            let (got, answer) = client
                .ask(head, "localhost", Some(b"hello"), None)
                .expect("the h3 answer");
            assert_eq!(got.to_string(), status);
            assert_eq!(answer, body);
        }
    }

    #[test]
    fn a_plain_h3_answer_skips_an_informational_status() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_scripted(&identity, |wire| {
            let interim = [(":status".to_owned(), "103".to_owned())];
            let final_head = [
                (":status".to_owned(), "200".to_owned()),
                ("content-length".to_owned(), "5".to_owned()),
            ];
            if send_fields(wire, frames::H3_HEADERS, &interim)
                && send_fields(wire, frames::H3_HEADERS, &final_head)
            {
                let _ = send_data(wire, b"world");
            }
        });
        let client = client(port, roots);
        let head = "POST /o HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n";
        let (status, answer) = client
            .ask(head, "localhost", Some(b"hello"), None)
            .expect("the final h3 answer");
        assert_eq!(status, 200);
        assert_eq!(answer, b"world");
    }

    #[test]
    fn a_plain_h3_answer_refuses_a_truncated_body() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_scripted(&identity, |wire| {
            let fields = [
                (":status".to_owned(), "200".to_owned()),
                ("content-length".to_owned(), "10".to_owned()),
            ];
            if send_fields(wire, frames::H3_HEADERS, &fields) {
                let _ = send_data(wire, b"short");
            }
        });
        let client = client(port, roots);
        let head = "GET /o HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let error = client
            .ask(head, "localhost", None, None)
            .expect_err("a short body is a truncation");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_plain_h3_answer_keeps_a_204_without_a_body() {
        let (identity, roots) = minted_identity("localhost");
        let port = serve_scripted(&identity, |wire| {
            let fields = [
                (":status".to_owned(), "204".to_owned()),
                ("content-length".to_owned(), "10".to_owned()),
            ];
            let _ = send_fields(wire, frames::H3_HEADERS, &fields);
        });
        let client = client(port, roots);
        let head = "GET /o HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (status, answer) = client
            .ask(head, "localhost", None, None)
            .expect("a 204 has no body whatever the header says");
        assert_eq!(status, 204);
        assert_eq!(answer, [0u8; 0]);
    }

    #[test]
    fn a_cancel_push_is_a_frame_error_not_a_reset() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let client = client(port, roots);
        let mut reader = H3Reader::new(raw_stream(&client));
        frames::quic_varint(&mut reader.buf, frames::H3_CANCEL_PUSH);
        frames::quic_varint(&mut reader.buf, 0);
        reader.buf_init = reader.buf.len();
        let mut buf = [0u8; 8];
        assert_eq!(
            reader
                .read(&mut buf)
                .expect_err("cancel_push on a request stream is not EOF")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn a_stream_up_upload_reaches_the_downlink_over_h3() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        assert!(writer.send(b"hello"));
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, b"hello");
    }

    /// A sid names a session only on the connection that opened it: a replay elsewhere is reset before an answer, and the owner keeps carrying data.
    #[test]
    fn a_session_replayed_on_another_connection_is_refused() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let session = settings.session_id();
        let down = block_from_text(
            &crate::xhttp::downlink_head("localhost", &settings, &session),
            "localhost",
            "https",
        );
        let up = block_from_text(
            &crate::xhttp::dial_head("localhost", &settings, &session, None),
            "localhost",
            "https",
        );
        let owner = client(port, roots.clone());
        let replay = client(port, roots);
        let (mut downlink, _) = owner.open(&down, true).expect("the session downlink opens");
        let (_, upload) = owner.open(&up, false).expect("the session upload opens");
        assert!(upload.data(b"one"));
        let mut got = [0u8; 3];
        downlink
            .read_exact(&mut got)
            .expect("the owner's session echoes");
        assert_eq!(&got, b"one");

        let (mut foreign, out) = replay.open(&down, true).expect("the replay opens");
        let mut buf = [0u8; 8];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match foreign.read(&mut buf) {
                Ok(0) => panic!("the replay ended as a clean EOF"),
                Ok(_) => panic!("the replay was answered"),
                Err(error) if crate::proxy::is_timeout(&error) => {
                    assert!(Instant::now() < deadline, "the replay was never refused");
                }
                Err(error) => {
                    assert_eq!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset,
                        "a refusal is a stream reset"
                    );
                    break;
                }
            }
        }
        assert!(foreign.status().is_none(), "a refusal carries no answer");
        out.reset();

        assert!(
            upload.data(b"two"),
            "the owner's session still carries data"
        );
        let mut got = [0u8; 3];
        downlink
            .read_exact(&mut got)
            .expect("the owner's session echoes again");
        assert_eq!(&got, b"two");
    }

    #[test]
    fn a_read_targets_the_framing_buffer() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        let payload: Vec<u8> = (0..96 * 1024).map(|byte| (byte % 251) as u8).collect();
        assert!(writer.send(&payload));
        writer.finish();
        let mut got = Vec::new();
        let mut first = [0u8; 1];
        let n = reader.read(&mut first).expect("the first read");
        assert!(
            reader.read_target >= reader.buf.as_ptr() as usize
                && reader.read_target + READ_ROOM
                    <= reader.buf.as_ptr() as usize + reader.buf.capacity(),
            "the wire read targets the framing buffer"
        );
        got.extend_from_slice(&first[..n]);
        let base = reader.buf.as_ptr();
        let capacity = reader.buf.capacity();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, payload);
        assert_eq!(
            reader.buf.as_ptr(),
            base,
            "the framing buffer does not move"
        );
        assert_eq!(reader.buf.capacity(), capacity, "no reallocation");
    }

    /// A field's value cannot smuggle a second head line into the HTTP/1 head `accept_core` parses.
    #[test]
    fn a_field_with_crlf_is_refused_not_synthesised() {
        let fields = vec![
            (b":method".to_vec(), b"POST".to_vec()),
            (b":path".to_vec(), b"/x".to_vec()),
            (b"host".to_vec(), b"localhost".to_vec()),
            (b"x-a".to_vec(), b"1\r\nContent-Length: 0".to_vec()),
        ];
        assert!(synth_head(&fields).is_none());
        let mut ok = fields.clone();
        ok[3].1 = b"1".to_vec();
        let mut tab = ok.clone();
        tab[1].1 = b"/x\t/evil".to_vec();
        assert!(
            synth_head(&tab).is_none(),
            "a tab cannot start a second target"
        );
        let mut space = ok.clone();
        space[1].1 = b"/x /evil".to_vec();
        assert!(
            synth_head(&space).is_none(),
            "a space cannot start a second target"
        );
        let head = synth_head(&ok).expect("a plain field synthesises");
        assert_eq!(
            head,
            b"POST /x HTTP/3\r\nhost: localhost\r\nx-a: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
    }

    #[test]
    fn a_bulk_upload_crosses_h3_in_one_data_frame() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        let payload: Vec<u8> = (0..96 * 1024).map(|byte| (byte % 251) as u8).collect();
        assert!(writer.send(&payload));
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, payload);
    }

    #[test]
    fn a_data_frame_window_is_the_readers_own_buffer() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        let (mut reader, writer) = connect_split(
            SocketAddr::from(([127, 0, 0, 1], port)),
            "localhost",
            &settings,
            &tls,
        )
        .expect("the h3 stream opens");
        let payload: Vec<u8> = (0..16 * 1024).map(|byte| (byte % 251) as u8).collect();
        assert!(writer.send(&payload));
        writer.finish();
        let (ptr, len) = {
            let window =
                crate::proxy::WindowRead::read_window(&mut reader).expect("the answer window");
            assert!(!window.is_empty(), "the answer has a body");
            (window.bytes().as_ptr() as usize, window.bytes().len())
        };
        let base = reader.buf.as_ptr() as usize;
        let cap = reader.buf.capacity();
        assert!(
            ptr >= base && ptr + len <= base + cap,
            "the window is the reader's own buffer"
        );
    }

    #[test]
    fn an_h3_packet_up_post_gets_a_2xx_and_carries_the_body() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::PacketUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        assert!(writer.send(b"hello"));
        writer.finish();
        let mut got = [0u8; 5];
        let mut at = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while at < got.len() {
            match reader.read(&mut got[at..]) {
                Ok(0) => panic!("the downlink ended after {at} bytes"),
                Ok(n) => at += n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || crate::proxy::is_timeout(&error) => {}
                Err(error) => panic!("the answer reads: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the answer stalls after {at} bytes"
            );
        }
        assert_eq!(&got, b"hello");
    }

    /// A lane's empty h3 read hands the lane back without sleeping the transport tick: the cell's
    /// eight download streams share one connection, and a lane asleep for the tick makes the
    /// receiver's window update late.
    #[test]
    fn a_waiting_h3_stream_read_does_not_sleep_the_transport_tick() {
        if !crate::conn::in_a_quiet_process(
            "xhttp_h3::tests::a_waiting_h3_stream_read_does_not_sleep_the_transport_tick",
        ) {
            return;
        }
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        // The upload stays open, so the echoing server has nothing to answer yet.
        let (mut reader, _writer) = dial(port, &settings, roots);
        let mut room = [0u8; 4096];
        let lane = crate::proxy::RelayStep::enter();
        let began = Instant::now();
        let ticks = lane_ticks();
        let grants = lane_grants();
        loop {
            match reader.read(&mut room) {
                Ok(0) => panic!("the h3 stream ended before it had to wait"),
                Ok(_) => assert!(
                    began.elapsed() < Duration::from_secs(2),
                    "the h3 stream answered for two seconds without ever making a read wait"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("the h3 read fails: {error}"),
            }
        }
        let slept = lane_ticks() - ticks;
        let handed = lane_grants() - grants;
        drop(lane);
        assert_eq!(
            slept, 0,
            "a lane's empty h3 read slept the {POLL:?} transport tick {slept} time(s) instead of \
             handing the lane back"
        );
        assert!(
            handed > 0,
            "a lane's empty h3 read never handed the lane back, so the reader slept a tick"
        );
    }

    #[test]
    fn a_data_frame_before_headers_is_refused() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        send_data(&wire, b"too early");
        let mut reader = H3Reader::new(wire);
        refused(&mut reader, "early DATA");
    }

    #[test]
    fn a_response_head_decodes_only_the_status() {
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("server", "ferrox"),
            ],
            &mut block,
        );
        let (decoded, counts) = ferrox_core::alloc_count::measure(|| decode_head(&block, false));
        assert_eq!(decoded, Some((None, Some(200))));
        assert_eq!(
            counts.allocs, 0,
            "a response reader walks the fields without building them: {counts:?}"
        );
        assert_eq!(hpack::qpack_content_length(&block), Ok(None));

        let mut sized = Vec::new();
        hpack::qpack_literal_many(&[(":status", "200"), ("content-length", "10")], &mut sized);
        assert_eq!(hpack::qpack_content_length(&sized), Ok(Some(10)));
        assert_eq!(
            decode_head(&block, true),
            None,
            "a response block is not a request head"
        );

        let mut request = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "POST"),
                (":path", "/x"),
                (":authority", "localhost"),
            ],
            &mut request,
        );
        let (decoded, counts) = ferrox_core::alloc_count::measure(|| decode_head(&request, true));
        assert!(matches!(
            decoded,
            Some((Some(head), None)) if head.starts_with(b"POST /x HTTP/3\r\n")
        ));
        assert!(
            counts.allocs > 0,
            "the request head is built from its fields: {counts:?}"
        );
        assert_eq!(
            decode_head(&request, false),
            None,
            "a response reader refuses a block that names no status"
        );
        assert_eq!(
            decode_head(&[0x01, 0x00, 0xC0, 0x01], false),
            None,
            "a dynamic-table prefix leaves no status this lane can read"
        );
        assert_eq!(
            decode_head(&[], false),
            None,
            "an empty response head names no status"
        );

        let mut status = Vec::new();
        hpack::qpack_literal_many(
            &[(":method", "POST"), (":path", "/x"), (":status", "500")],
            &mut status,
        );
        assert!(
            matches!(decode_head(&status, true), Some((Some(_), Some(500)))),
            "a request head's status still reaches the upload gate"
        );
    }

    #[test]
    fn a_request_head_without_a_method_is_refused() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        let mut block = Vec::new();
        hpack::qpack_literal_many(&[(":path", "/x")], &mut block);
        send_frame(&wire, frames::H3_HEADERS, &block);
        let mut reader = H3Reader::new(wire);
        refused(&mut reader, "a head without :method");
    }

    #[test]
    fn a_truncated_data_frame_is_an_error() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let port = serve_inbound(
            "127.0.0.1:0",
            &identity,
            &settings,
            Arc::new(Recorder(Arc::clone(&seen))),
            None,
        )
        .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        let mut block = Vec::new();
        let padding = "x".repeat(100);
        let target = format!("/x?x_padding={padding}");
        hpack::qpack_literal_many(
            &[
                (":method", "POST"),
                (":path", target.as_str()),
                (":scheme", "https"),
                (":authority", "localhost"),
            ],
            &mut block,
        );
        let mut frame = Vec::new();
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        frames::quic_varint(&mut frame, frames::H3_DATA);
        frames::quic_varint(&mut frame, 16);
        frame.extend_from_slice(b"cut");
        wire.clone().write_all(&frame).expect("the frame sends");
        wire.fin();
        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.lock().expect("recorder lock").is_none() {
            assert!(Instant::now() < deadline, "the truncation was never seen");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            *seen.lock().expect("recorder lock"),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn a_non_2xx_status_is_an_error() {
        assert!(status_ok(Some(403)).is_err());
        assert!(status_ok(Some(204)).is_ok());
        assert!(status_ok(None).is_ok());
    }

    #[test]
    fn a_stream_one_session_crosses_h3_both_ways() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        let (mut reader, writer) = connect_split(
            SocketAddr::from(([127, 0, 0, 1], port)),
            "localhost",
            &settings,
            &tls,
        )
        .expect("the h3 stream opens");
        assert!(writer.send(b"hello"), "the request body rides DATA");
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, b"hello");
    }
    #[test]
    fn a_brutal_h3_param_is_refused_before_a_socket() {
        let tls = ferrox_core::tls::TlsConfig {
            insecure: true,
            ..Default::default()
        };
        let params = ferrox_core::hysteria::QuicParams {
            cc: Some(ferrox_core::hysteria::Congestion::Brutal),
            ..Default::default()
        };
        assert!(
            H3Client::connect_tuned(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                "localhost",
                &tls,
                Some(&params),
                false,
            )
            .is_none(),
            "brutal is a Hysteria sender, not an h3 service controller"
        );
    }

    fn settings_frame(wire: &mut Vec<u8>) {
        frames::quic_varint(wire, 0x4);
        frames::quic_varint(wire, 0);
    }

    #[test]
    fn a_large_control_frame_keeps_the_goaway_after_it() {
        let mut wire = Vec::new();
        settings_frame(&mut wire);
        frames::quic_varint(&mut wire, 0x21);
        frames::quic_varint(&mut wire, 65_536);
        wire.extend(std::iter::repeat_n(0u8, 65_536));
        frames::quic_varint(&mut wire, 0x7);
        frames::quic_varint(&mut wire, 1);
        frames::quic_varint(&mut wire, 4);
        let split = 50_000;
        let mut control = wire[..split].to_vec();
        let mut skip = 0;
        let mut settings = false;
        let goaway = AtomicU64::new(u64::MAX);
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(false)
        );
        assert!(skip > 0, "the unknown payload is skipped incrementally");
        control.extend_from_slice(&wire[split..]);
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(true)
        );
        assert_eq!(skip, 0);
        assert_eq!(goaway.load(Ordering::SeqCst), 4);
        assert_eq!(control, [] as [u8; 0]);
    }

    #[test]
    fn a_goaway_that_increases_its_cutoff_is_an_error() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 12);
        let goaway = AtomicU64::new(8);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_ID_ERROR),
            "RFC 9114 rejects a cutoff above the one already accepted"
        );
        assert_eq!(goaway.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn a_goaway_must_name_a_client_bidirectional_stream() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 1);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_ID_ERROR),
            "a server stream is not a client request cutoff"
        );
        assert_eq!(goaway.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn a_control_stream_must_start_with_settings() {
        let mut control = Vec::new();
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 4);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_MISSING_SETTINGS)
        );
        assert_eq!(goaway.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn settings_split_across_sweeps_keeps_the_first_frame() {
        let mut control = vec![0x04, 0x02, 0x01];
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(false)
        );
        assert!(
            !settings,
            "the first SETTINGS frame is validated only once its payload is complete"
        );
        control.extend_from_slice(&[0x00, 0x07, 0x01, 0x04]);
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(true)
        );
        assert_eq!(goaway.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn a_goaway_with_trailing_bytes_is_a_frame_error() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 2);
        frames::quic_varint(&mut control, 4);
        control.push(0);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_FRAME_ERROR)
        );
        assert_eq!(goaway.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn a_second_settings_is_a_frame_error() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        settings_frame(&mut control);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_FRAME_UNEXPECTED)
        );
    }

    #[test]
    fn data_on_the_control_stream_is_a_frame_error() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0x0);
        frames::quic_varint(&mut control, 1);
        control.push(0);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_FRAME_UNEXPECTED)
        );
    }

    #[test]
    fn http2_reserved_control_frames_are_unexpected() {
        for kind in [0x2, 0x3, 0x6, 0x8, 0x9, 0xd] {
            let mut control = Vec::new();
            settings_frame(&mut control);
            frames::quic_varint(&mut control, kind);
            frames::quic_varint(&mut control, 0);
            let goaway = AtomicU64::new(u64::MAX);
            let mut skip = 0;
            let mut settings = false;
            assert_eq!(
                h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
                Err(H3_FRAME_UNEXPECTED),
                "frame {kind:#x} is reserved by HTTP/2 and cannot ride a control stream"
            );
        }
    }

    #[test]
    fn priority_update_on_the_server_control_stream_is_unexpected() {
        for kind in [0xf0700, 0xf0701] {
            let mut control = Vec::new();
            settings_frame(&mut control);
            frames::quic_varint(&mut control, kind);
            frames::quic_varint(&mut control, 0);
            let goaway = AtomicU64::new(u64::MAX);
            let mut skip = 0;
            let mut settings = false;
            assert_eq!(
                h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
                Err(H3_FRAME_UNEXPECTED),
                "frame {kind:#x} is server-to-client only"
            );
        }
    }

    #[test]
    fn a_settings_payload_without_a_value_is_a_frame_error() {
        let mut control = Vec::new();
        frames::quic_varint(&mut control, 0x4);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 1);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Err(H3_FRAME_ERROR)
        );
    }

    #[test]
    fn http2_reserved_settings_identifiers_are_settings_errors() {
        for id in [0x2, 0x3, 0x4, 0x5] {
            let mut control = Vec::new();
            frames::quic_varint(&mut control, 0x4);
            frames::quic_varint(&mut control, 2);
            frames::quic_varint(&mut control, id);
            frames::quic_varint(&mut control, 0);
            let goaway = AtomicU64::new(u64::MAX);
            let mut skip = 0;
            let mut settings = false;
            assert_eq!(
                h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
                Err(H3_SETTINGS_ERROR),
                "setting {id:#x} is reserved by HTTP/2"
            );
        }
    }

    #[test]
    fn an_unassigned_control_frame_is_ignored() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0xe);
        frames::quic_varint(&mut control, 0);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(false)
        );
        assert_eq!(control, [] as [u8; 0]);
    }

    #[test]
    fn a_goaway_length_outside_one_to_eight_is_a_frame_error() {
        for len in [0, 9] {
            let mut control = Vec::new();
            settings_frame(&mut control);
            frames::quic_varint(&mut control, 0x7);
            frames::quic_varint(&mut control, len);
            let goaway = AtomicU64::new(u64::MAX);
            let mut skip = 0;
            let mut settings = false;
            assert_eq!(
                h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
                Err(H3_FRAME_ERROR),
                "a GOAWAY payload is one varint, so length {len} cannot be valid"
            );
        }
    }

    #[test]
    fn every_complete_goaway_in_one_sweep_applies() {
        let mut control = Vec::new();
        settings_frame(&mut control);
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 8);
        frames::quic_varint(&mut control, 0x7);
        frames::quic_varint(&mut control, 1);
        frames::quic_varint(&mut control, 4);
        let goaway = AtomicU64::new(u64::MAX);
        let mut skip = 0;
        let mut settings = false;
        assert_eq!(
            h3_control_frames(&mut control, &mut skip, &mut settings, &goaway),
            Ok(true)
        );
        assert_eq!(
            goaway.load(Ordering::SeqCst),
            4,
            "the later complete GOAWAY lowers the cutoff before the lock is released"
        );
        assert_eq!(control, [] as [u8; 0]);
    }
}
