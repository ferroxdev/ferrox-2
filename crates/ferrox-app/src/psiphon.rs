//! The native `Psiphon` lane: a signed server list, the SSH/OSSH transport in
//! [`crate::psiphon_ssh`], and the loopback SOCKS edge the proxy dials.

use crate::json::{self, Json};
use crate::psiphon_broker::Value as Cbor;
use crate::psiphon_ssh::{
    ApiEncoding, Channel, ChannelChunk, Identity, KeepAlive, Proxy, Server, Session, TlsShape,
    MAX_PADDING, MIN_PADDING,
};
use crate::psiphon_webrtc::is_bogon;
use crate::socks::{Credential, Destination, Version};
use crypto_secretbox::aead::{Aead as _, KeyInit as _};
use ferrox_core::tls::shaped::{Body, Ext, Profile};
use ferrox_core::tls::Fingerprint;
use flate2::read::ZlibDecoder;
use ring::signature;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{self, IoSlice, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

const SPONSOR_ID: &str = "07D1ACD69B3AC7A2";
const PROPAGATION_CHANNEL_ID: &str = "EE0B7486ACAE75AA";
const CLIENT_VERSION: &str = "453";
const DSL_REQUEST_NAME: &str = "psiphon-dsl";
const DSL_MAX_PAYLOAD: usize = 65_536;
const DSL_VERSION: u64 = 0;
const DSL_DISCOVER: u64 = 1;
const DSL_GET: u64 = 2;
/// The compartment ID the public Android build embeds for its private conduits.
const PRIVATE_COMPARTMENT_ID: &str = "/TYUL7wjyPuXCGAujuiQuxTRlOFhjMglpDX2kzVo/ks";
/// The regions the Android client rejects when its censored-country switch is on.
const CENSORED_COUNTRY_CODES: &[&str] = &["IR", "CN", "RU", "BY", "TM", "KP"];
const UDPGW_HOST: &str = "127.0.0.1";
const UDPGW_PORT: u16 = 7300;
const UDPGW_FLAG_KEEPALIVE: u8 = 1;
const UDPGW_FLAG_REBIND: u8 = 2;
const UDPGW_FLAG_IPV6: u8 = 8;
const UDPGW_MAX_PAYLOAD: usize = 32_768;
const UDPGW_MAX_MESSAGE: usize = 32_768 + 23;
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const RELAY_BUFFER: usize = 256 * 1024;
const RELAY_BATCH: usize = 64;
/// How long a fetched OSL registry and its files are reused before another attempt.
const OSL_REFRESH: Duration = Duration::from_secs(300);
/// How long one server classification keeps a destination on the direct path.
const SPLIT_TUNNEL_CLASSIFICATION_TTL: Duration = Duration::from_hours(24);
/// The reference's cap on cached split-tunnel classifications.
const SPLIT_TUNNEL_CLASSIFICATION_MAX: usize = 65_536;
const FRONTED_VARIANTS: usize = 256;
const FRONTED_SERVERS: usize = 512;
/// The reference's aggressive queue: three fronted CDN protocols at an
/// eight-way fanout per server entry before the next entry.
const CDN_SCAN_STRIDE: usize = 24;
/// The first tactics entry to try on the next establishment pass.
static TACTICS_CURSOR: AtomicUsize = AtomicUsize::new(0);
/// The least time one tactics entry gets before the pass moves on.
const TACTICS_ATTEMPT_MIN: Duration = Duration::from_secs(10);

const CDN_FRONTING_PROTOCOLS: &[&str] = &[
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const CDN_PROTOCOL_OSSH: u8 = 1;
const CDN_PROTOCOL_HTTP: u8 = 2;
const CDN_PROTOCOL_QUIC: u8 = 4;
const DIRECT_PROTOCOLS: &[&str] = &[
    "SSH",
    "OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "QUIC-OSSH",
    "SHADOWSOCKS-OSSH",
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const CONDUIT_PROTOCOLS: &[&str] = &[
    "INPROXY-WEBRTC-SSH",
    "INPROXY-WEBRTC-OSSH",
    "INPROXY-WEBRTC-TLS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
    "INPROXY-WEBRTC-QUIC-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH",
];
const CDN_FASTLY_VERIFY_NAMES: &[&str] = &[
    "www.python.org",
    "pypi.org",
    "fastly.com",
    "www.fastly.com",
    "developer.fastly.com",
    "githubassets.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
];
const CDN_EDGE_VERIFY_NAMES: &[&str] = &[
    "a248.e.akamai.net",
    "a.akamaized.net",
    "a.akamaized-staging.net",
    "a.akamaihd.net",
    "a.akamaihd-staging.net",
    "www.akamai.com",
];
const CDN_EDGE_ADDRESSES: &[(&str, &str)] = &[
    ("edge-a-1", "23.215.0.206"),
    ("edge-a-2", "23.215.0.203"),
    ("edge-b-1", "23.212.250.91"),
    ("edge-b-2", "23.212.250.78"),
    ("edge-c-1", "23.12.147.13"),
    ("edge-c-2", "23.12.147.29"),
    ("edge-d-1", "23.73.207.8"),
    ("edge-d-2", "23.73.207.15"),
    ("edge-original", "92.123.102.43"),
];
const MAX_REQUEST: usize = 16 * 1024;
const DIAL_ATTEMPTS: usize = 64;
const DIAL_WORKERS: usize = 10;
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const HOLD_OFF_LIMIT: Duration = Duration::from_secs(60);
const FLOW_STACK: usize = 128 * 1024;

static NO_CREDENTIAL: Credential = Credential {
    user: String::new(),
    pass: String::new(),
};

/// The outbound as a flow sees it: a native tunnel and the loopback SOCKS edge over it.
#[derive(Clone)]
pub(crate) struct PsiphonOut {
    inner: Option<Arc<Inner>>,
    endpoint: SocketAddr,
    credential: Arc<Credential>,
    version: Version,
    loopback: bool,
    shutdown: Option<Arc<LaneShutdown>>,
}

struct LaneShutdown {
    stopped: Arc<AtomicBool>,
    channels: Arc<Mutex<Vec<crate::psiphon_ssh::ChannelWaiter>>>,
}

impl LaneShutdown {
    fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            channels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            stopped: Arc::clone(&self.stopped),
            channels: Arc::clone(&self.channels),
        }
    }
}

impl Drop for LaneShutdown {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        for channel in lock(&self.channels).iter() {
            channel.wake();
        }
    }
}

struct ShutdownSignal {
    stopped: Arc<AtomicBool>,
    channels: Arc<Mutex<Vec<crate::psiphon_ssh::ChannelWaiter>>>,
}

impl ShutdownSignal {
    fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stopped)
    }

    fn watch(&self, channel: crate::psiphon_ssh::ChannelWaiter) {
        let mut channels = lock(&self.channels);
        channels.retain(crate::psiphon_ssh::ChannelWaiter::is_live);
        channels.push(channel);
    }
}

struct Inner {
    settings: Settings,
    config_state: u64,
    entries: Mutex<Arc<Vec<Server>>>,
    sloks: Arc<crate::psiphon_osl::SlokStore>,
    requests: Arc<crate::psiphon_osl::ServerEvents>,
    osl_seeded: Arc<AtomicBool>,
    osl_attempt: AtomicUsize,
    last_osl: Mutex<Option<Instant>>,
    last_osl_failure: Mutex<Option<Instant>>,
    upgrade_started: Arc<AtomicBool>,
    last_upgrade_attempt: Mutex<Option<Instant>>,
    dsl_running: AtomicBool,
    dsl_last_fetch: Mutex<Option<Instant>>,
    self_ref: Mutex<Weak<Self>>,
    sessions: Mutex<Vec<Arc<Session>>>,
    next_session: AtomicUsize,
    dial_window: AtomicUsize,
    entry_cursor: AtomicUsize,
    affinity: Mutex<Option<(String, u16)>>,
    moved_to_front: Mutex<HashSet<String>>,
    dsl_placeholders: Arc<Mutex<Vec<DslPlaceholder>>>,
    connecting: Mutex<()>,
    session_id: String,
    stopping: AtomicBool,
    endpoint: SocketAddr,
    http_endpoint: Option<SocketAddr>,
    udpgw: Mutex<Option<Arc<UdpGateway>>>,
    conduit: Mutex<Option<(ConduitMode, Arc<crate::psiphon_webrtc::Conduit>)>>,
    conduit_started: OnceLock<Instant>,
    conduit_fallback: AtomicBool,
    conduit_connected: AtomicBool,
    split_untunneled: Mutex<HashMap<String, Instant>>,
    replay: Arc<crate::psiphon_replay::Cache>,
    light: Option<Arc<crate::psiphon_light::Client>>,
    /// One in-proxy dial bucket for the client's life, as the reference holds it: a bucket built per attempt never throttles a client that reconnects.
    inproxy_limiter: Option<Arc<DialRateLimiter>>,
}

/// The reference's protocol hold-off: a jittered delay before a new tunnel is activated.
#[derive(Clone, Debug, Default)]
struct HoldOff {
    names: Vec<String>,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOff {
    /// The hold-off for a protocol, zero when it is not named.
    fn duration(&self, protocol: &str) -> Duration {
        if self.names.is_empty()
            || !self
                .names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
            || !coin(self.probability)
        {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

/// The reference's provider-scoped hold-off: direct and inproxy key on provider/region,
/// fronting keys on the fronting provider ID.
#[derive(Clone, Debug, Default)]
struct HoldOffClass {
    providers: Vec<(String, Vec<String>)>,
    region_scoped: bool,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOffClass {
    fn delay(&self, provider: Option<&str>, region: Option<&str>) -> Duration {
        if self.providers.is_empty() || !coin(self.probability) {
            return Duration::ZERO;
        }
        let Some(provider) = provider else {
            return Duration::ZERO;
        };
        let matched = self.providers.iter().any(|(id, regions)| {
            id == provider
                && (!self.region_scoped
                    || regions
                        .iter()
                        .any(|allowed| allowed.is_empty() || Some(allowed.as_str()) == region))
        });
        if !matched {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

#[derive(Clone, Debug)]
struct LivenessSpec {
    pattern: String,
    min_upstream: usize,
    max_upstream: usize,
    min_downstream: usize,
    max_downstream: usize,
}

/// The reference's liveness probes, keyed by tunnel-protocol pattern.
#[derive(Clone, Debug, Default)]
struct Liveness {
    initial: Vec<LivenessSpec>,
    periodic: Vec<LivenessSpec>,
}

impl Liveness {
    /// The first probe spec naming this protocol in the given state.
    fn spec(&self, protocol: &str, established: bool) -> Option<LivenessSpec> {
        let probes = if established {
            &self.periodic
        } else {
            &self.initial
        };
        let mut matched: Option<&LivenessSpec> = None;
        let mut fallback = None;
        for probe in probes {
            if probe.pattern.is_empty() {
                fallback = Some(probe);
            } else if wildcard_match(&probe.pattern, protocol)
                && matched.is_none_or(|best| probe.pattern.len() > best.pattern.len())
            {
                matched = Some(probe);
            }
        }
        matched.or(fallback).cloned()
    }
}

/// The reference's protocol wildcard: `*` matches any run of bytes, everything else is literal.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(mut rest) = text.strip_prefix(parts.next().unwrap_or_default()) else {
        return false;
    };
    let mut part = parts.next();
    while let Some(current) = part {
        part = parts.next();
        if part.is_none() {
            return current.is_empty() || rest.ends_with(current);
        }
        if current.is_empty() {
            continue;
        }
        let Some(at) = rest.find(current) else {
            return false;
        };
        rest = &rest[at + current.len()..];
    }
    rest.is_empty()
}

/// The dynamic server list fetcher's window, resolved from the config and the
/// handshake tactics in that order.
#[derive(Clone, Debug)]
struct Dsl {
    enable: bool,
    timeout: Duration,
    retry_count: usize,
    retry_delay: Duration,
    retry_jitter: f64,
    ttl: Duration,
    discover_min: usize,
    discover_max: usize,
    get_min: usize,
    get_max: usize,
    prioritize_new: f64,
    prioritize_existing: f64,
}

impl Default for Dsl {
    fn default() -> Self {
        Self {
            enable: false,
            timeout: Duration::from_secs(5),
            retry_count: 0,
            retry_delay: Duration::from_secs(5),
            retry_jitter: 0.3,
            ttl: Duration::from_hours(1),
            discover_min: 1,
            discover_max: 2,
            get_min: 30,
            get_max: 60,
            prioritize_new: 0.5,
            prioritize_existing: 0.25,
        }
    }
}

struct DslTag {
    tag: Vec<u8>,
    version: i32,
    prioritize: bool,
}

struct DslPlaceholder {
    host: String,
    port: u16,
    created: Instant,
}

fn dsl_placeholder_position(
    placeholders: &[DslPlaceholder],
    host: &str,
    port: u16,
) -> Option<usize> {
    placeholders
        .iter()
        .position(|placeholder| placeholder.host == host && placeholder.port == port)
}

fn expire_dsl_placeholder(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    host: &str,
    port: u16,
    ttl: Duration,
) {
    if ttl.is_zero() {
        return;
    }
    lock(placeholders).retain(|placeholder| {
        !(placeholder.host == host
            && placeholder.port == port
            && placeholder.created.elapsed() >= ttl)
    });
}

fn clear_dsl_placeholder(placeholders: &Mutex<Vec<DslPlaceholder>>, host: &str, port: u16) {
    let mut list = lock(placeholders);
    if let Some(at) = dsl_placeholder_position(&list, host, port) {
        list.remove(at);
    }
}

fn retain_dsl_placeholder(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    host: &str,
    port: u16,
    retain: f64,
) {
    if coin(retain) {
        return;
    }
    clear_dsl_placeholder(placeholders, host, port);
}

fn promote_dsl_placeholders(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    entries: &mut Vec<Server>,
    moved: &mut HashSet<String>,
    max: i64,
) {
    for placeholder in lock(placeholders).iter() {
        if max > 0 && i64::try_from(moved.len()).unwrap_or(i64::MAX) >= max {
            break;
        }
        if move_to_front(entries, &placeholder.host, placeholder.port) {
            moved.insert(format!("{}:{}", placeholder.host, placeholder.port));
        }
    }
}

impl Dsl {
    fn resolved(config: Option<&Json>, tactics: Option<&Json>) -> Self {
        let mut dsl = Self::default();
        dsl.apply(config);
        dsl.apply(tactics);
        if field(config, "DisableDSLFetcher")
            .and_then(Json::as_bool)
            .unwrap_or(false)
        {
            dsl.enable = false;
        }
        dsl
    }

    fn apply(&mut self, fields: Option<&Json>) {
        if let Some(enable) = field(fields, "EnableDSLFetcher").and_then(Json::as_bool) {
            self.enable = enable;
        }
        self.timeout = duration_field(fields, "DSLFetcherTunneledRequestTimeout", self.timeout)
            .min(Duration::from_mins(2));
        self.retry_count = number(fields, "DSLFetcherTunneledRequestRetryCount")
            .map_or(self.retry_count, |count| {
                usize::try_from(count).unwrap_or(usize::MAX)
            });
        self.retry_delay = duration_field(
            fields,
            "DSLFetcherTunneledRequestRetryDelay",
            self.retry_delay,
        )
        .min(Duration::from_mins(1));
        self.retry_jitter = decimal(fields, "DSLFetcherTunneledRequestRetryDelayJitter")
            .unwrap_or(self.retry_jitter)
            .clamp(0.0, 1.0);
        self.ttl = duration_field(fields, "DSLFetcherTunneledFetchTTL", self.ttl)
            .min(Duration::from_hours(24));
        self.discover_min = count_field(
            fields,
            "DSLFetcherTunneledDiscoverServerEntriesMinCount",
            self.discover_min,
        );
        self.discover_max = count_field(
            fields,
            "DSLFetcherTunneledDiscoverServerEntriesMaxCount",
            self.discover_max,
        );
        self.get_min = count_field(
            fields,
            "DSLFetcherTunneledGetServerEntriesMinCount",
            self.get_min,
        );
        self.get_max = count_field(
            fields,
            "DSLFetcherTunneledGetServerEntriesMaxCount",
            self.get_max,
        );
        self.prioritize_new = probability_field(
            fields,
            "DSLPrioritizeDialNewServerEntryProbability",
            self.prioritize_new,
        );
        self.prioritize_existing = probability_field(
            fields,
            "DSLPrioritizeDialExistingServerEntryProbability",
            self.prioritize_existing,
        );
        if self.discover_max < self.discover_min {
            self.discover_max = self.discover_min;
        }
        if self.get_max < self.get_min {
            self.get_max = self.get_min;
        }
    }
}

fn field<'a>(fields: Option<&'a Json>, key: &str) -> Option<&'a Json> {
    fields.and_then(|fields| fields.get(key))
}

fn duration_field(fields: Option<&Json>, key: &str, default: Duration) -> Duration {
    let Some(value) = field(fields, key) else {
        return default;
    };
    if let Some(text) = value.as_str() {
        return go_duration(text).unwrap_or(default);
    }
    value.as_i64().map_or(default, |nanos| {
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(0))
    })
}

fn count_field(fields: Option<&Json>, key: &str, default: usize) -> usize {
    number(fields, key).map_or(default, |count| count.min(256) as usize)
}

/// The reference's token bucket for in-proxy dials; zero disables it.
fn rate_limit(fields: Option<&Json>) -> Option<(usize, Duration)> {
    let quantity = number(fields, "InproxyClientDialRateLimitQuantity").unwrap_or(2);
    if quantity == 0 {
        return None;
    }
    let interval = number(fields, "InproxyClientDialRateLimitIntervalMilliseconds").map_or_else(
        || {
            duration_field(
                fields,
                "InproxyClientDialRateLimitInterval",
                Duration::from_millis(500),
            )
        },
        Duration::from_millis,
    );
    if interval.is_zero() {
        return None;
    }
    Some((usize::try_from(quantity).unwrap_or(usize::MAX), interval))
}

/// A provider-keyed duration map; the reference stores Go duration strings.
fn key_durations(fields: Option<&Json>, key: &str) -> Vec<(String, Duration)> {
    let Some(Json::Obj(pairs)) = fields.and_then(|fields| fields.get(key)) else {
        return Vec::new();
    };
    pairs
        .iter()
        .filter_map(|(provider, value)| {
            let duration = value.as_str().and_then(go_duration).or_else(|| {
                value
                    .as_i64()
                    .map(|nanos| Duration::from_nanos(u64::try_from(nanos).unwrap_or(0)))
            })?;
            Some((provider.clone(), duration))
        })
        .collect()
}

fn probability_field(fields: Option<&Json>, key: &str, default: f64) -> f64 {
    decimal(fields, key).unwrap_or(default).clamp(0.0, 1.0)
}

/// A `golang.org/x/time/rate` bucket over in-proxy dials.
struct DialRateLimiter {
    capacity: f64,
    rate: f64,
    state: std::sync::Mutex<(f64, std::time::Instant)>,
}

impl DialRateLimiter {
    #[allow(clippy::cast_precision_loss)]
    fn new(quantity: usize, interval: Duration) -> Self {
        let capacity = quantity as f64;
        Self {
            capacity,
            rate: capacity / interval.as_secs_f64(),
            state: std::sync::Mutex::new((capacity, std::time::Instant::now())),
        }
    }

    /// Take one token, waiting no later than `deadline`.
    fn wait(&self, deadline: std::time::Instant) -> bool {
        let mut state = lock(&self.state);
        loop {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(state.1).as_secs_f64();
            state.0 = (state.0 + elapsed * self.rate).min(self.capacity);
            state.1 = now;
            if state.0 >= 1.0 {
                state.0 -= 1.0;
                return true;
            }
            let wait = Duration::from_secs_f64((1.0 - state.0) / self.rate);
            let Some(at) = now.checked_add(wait) else {
                return false;
            };
            if at > deadline {
                return false;
            }
            drop(state);
            std::thread::sleep(wait);
            state = lock(&self.state);
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
struct Settings {
    state: PathBuf,
    listen: SocketAddr,
    http_listen: Option<u16>,
    region: Option<String>,
    ready: Duration,
    entries: Option<PathBuf>,
    target: Option<String>,
    protocols: Vec<String>,
    initial_protocols: Vec<String>,
    fronted: bool,
    fronted_fallback: bool,
    cdn_ips: Vec<String>,
    cdn_snis: Vec<String>,
    cdn_scan_user: Option<crate::psiphon_cdn::ScanSpec>,
    cdn_scan_builtin: Vec<crate::psiphon_cdn::ScanSpec>,
    cdn_scan_specs: Vec<crate::psiphon_cdn::ScanSpec>,
    cdn_scan_state: Arc<Mutex<crate::psiphon_cdn::ScanState>>,
    fronted_overrides: Vec<FrontedOverride>,
    fronted_overrides_probability: f64,
    initial_count: usize,
    pool: usize,
    latency: Latency,
    establish: Option<Duration>,
    workers: usize,
    intensive_workers: usize,
    stagger: Duration,
    pause: Duration,
    affinity_grace: Duration,
    keepalive: Option<KeepAlive>,
    propagation: String,
    platform: String,
    client_version: String,
    api_encoding: ApiEncoding,
    api_protocol: crate::psiphon_ssh::ApiProtocol,
    device_region: Option<String>,
    device_location: Option<String>,
    client_features: Vec<String>,
    split_tunnel_own_region: bool,
    split_tunnel_regions: Vec<String>,
    compartment: String,
    personal_pairing: bool,
    conduit: bool,
    conduit_mode: ConduitMode,
    conduit_timeout: Duration,
    conduit_protocols: Vec<String>,
    inproxy_stun: crate::psiphon_tactics::StunServers,
    inproxy_disable_stun: bool,
    inproxy_discover_nat: f64,
    inproxy_discover_nat_timeout: Duration,
    inproxy_dtls_randomization: f64,
    inproxy_media_streams: f64,
    inproxy_media_traffic_shaping: f64,
    inproxy_media_traffic_shaping_parameters: crate::psiphon_webrtc::TrafficShapingParameters,
    inproxy_traffic_shaping: f64,
    inproxy_traffic_shaping_parameters: crate::psiphon_webrtc::TrafficShapingParameters,
    inproxy_offer_timeout: Duration,
    inproxy_offer_personal_timeout: Duration,
    inproxy_offer_retry_delay: Duration,
    inproxy_offer_retry_jitter: f64,
    inproxy_relay_timeout: Duration,
    inproxy_await_ready_timeout: Duration,
    inproxy_no_match_failover: f64,
    inproxy_no_match_failover_personal: f64,
    inproxy_prefer_probability: f64,
    inproxy_force_selection_count: usize,
    inproxy_rate_limit: Option<(usize, Duration)>,
    inproxy_api_timeout: Duration,
    inproxy_debug: bool,
    inproxy_disable_ipv6_ice: bool,
    inproxy_disable_inbound_mobile: bool,
    inproxy_incompatible_networks: Vec<String>,
    inproxy_network_type: String,
    inproxy_front_timeouts: Vec<(String, Duration)>,
    reject_countries: Vec<String>,
    reject_cidrs: Vec<String>,
    geoip_path: Option<String>,
    dns_servers: Vec<SocketAddr>,
    dns: crate::psiphon_dns::Config,
    limit_quic_versions: Vec<String>,
    quic_noise: Option<String>,
    tls_shape: TlsShape,
    meek_padding: (u16, u16),
    limit_meek_buffers: bool,
    relay_buffer: usize,
    rate: Option<crate::psiphon_rate::Rate>,
    holdoff: HoldOff,
    holdoff_direct: HoldOffClass,
    holdoff_fronting: HoldOffClass,
    holdoff_inproxy: HoldOffClass,
    compress_tactics: bool,
    server_entry_max_move_to_front: i64,
    server_entry_reset_probability: f64,
    dsl_retain_failed: f64,
    dsl_placeholder_ttl: Duration,
    restrict_direct_regions: Vec<(String, Vec<String>)>,
    restrict_direct_probability: f64,
    restrict_inproxy_regions: Vec<(String, Vec<String>)>,
    restrict_inproxy_probability: f64,
    restrict_fronting_ids: Vec<String>,
    restrict_fronting_probability: f64,
    liveness: Liveness,
    dial_ports: Vec<(String, PortList)>,
    dial_ports_probability: f64,
    prioritize_protocols: Vec<String>,
    prioritize_count: usize,
    prioritize_probability: f64,
    limit_protocols_probability: f64,
    initial_limit_probability: f64,
    replay: crate::psiphon_replay::Settings,
    disable_tactics: bool,
    meek_headers: Vec<(String, String)>,
    ssh_channel_window: u32,
    packet_tunnel_fd: Option<i32>,
    packet_tunnel_dns: crate::psiphon_packet_tunnel::Dns,
    ssh_packet_tunnel_channel_window: u32,
    server_lists: Vec<String>,
    server_lists_explicit: bool,
    remote_fetch_disabled: bool,
    server_list_key: String,
    signature_key: String,
    osl_roots: Vec<TransferRoot>,
    remote_list_key: String,
    remote_list_retry: Duration,
    enable_upgrade: bool,
    upgrade_roots: Vec<TransferRoot>,
    upgrade_version_header: String,
    upgrade_retry: Duration,
    enable_feedback: bool,
    feedback_roots: Vec<TransferRoot>,
    feedback_key: String,
    feedback_attempts: usize,
    feedback_retry_min: Duration,
    feedback_retry_max: Duration,
    exchange_key: String,
    limit_cpu: bool,
    disable_api: bool,
    ssh_algorithms: Option<[String; 4]>,
    emit_sloks: bool,
    emit_server_alerts: bool,
    headers: Vec<(String, String)>,
    proxy: Option<Proxy>,
    sponsor: String,
    session_id: Option<String>,
    authorizations: Vec<String>,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    burst: Option<crate::psiphon_burst::Config>,
    light: Option<crate::psiphon_light::Config>,
    raw: Option<Json>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConduitMode {
    Auto,
    Public,
    Shirokhorshid,
}

/// One `LimitTunnelDialPortNumbers` entry: the port numbers, as single ports or closed ranges.
#[derive(Clone, Debug, Default)]
struct PortList {
    ranges: Vec<(u16, u16)>,
}

impl PortList {
    fn contains(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|(low, high)| port >= *low && port <= *high)
    }
}

#[derive(Debug, Clone)]
struct FrontedOverride {
    override_id: Option<String>,
    dials: Vec<String>,
    snis: Vec<String>,
    disable_sni: bool,
    alpn: Vec<Vec<u8>>,
    match_providers: Vec<regex::Regex>,
    match_dials: Vec<regex::Regex>,
    match_hosts: Vec<regex::Regex>,
    verify_server_names: Vec<String>,
    verify_pins: Vec<String>,
    tls_profile: Option<String>,
    skip_cert_verify: bool,
}

impl FrontedOverride {
    /// The reference applies an override only when every named match group finds a value.
    fn matches(&self, meek: &crate::psiphon_meek::Meek) -> bool {
        let mut dials = Vec::with_capacity(meek.fronts.len() + 1);
        dials.push(meek.dial.as_str());
        dials.extend(meek.fronts.iter().map(|(dial, _)| dial.as_str()));
        regex_matches_any(
            &self.match_providers,
            &[meek.provider_id.as_deref().unwrap_or("")],
        ) && regex_matches_any(&self.match_dials, &dials)
            && regex_matches_any(&self.match_hosts, &[meek.host.as_str()])
    }
}

/// The Android client's Fastly overrides and its nine Akamai edge addresses.
fn cdn_fronting_overrides(custom_sni: Option<&str>) -> Vec<FrontedOverride> {
    let custom_sni = custom_sni.filter(|sni| !sni.is_empty());
    let alpn = vec![b"http/1.1".to_vec()];
    let fastly_names: Vec<String> = CDN_FASTLY_VERIFY_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut overrides = Vec::with_capacity(2 + CDN_EDGE_ADDRESSES.len());

    let mut provider = cdn_override(
        "fastly-provider",
        "pypi.org",
        Some("pypi.org"),
        fastly_names.clone(),
        alpn.clone(),
    );
    provider.match_providers = static_regex("(?i)fastly");
    overrides.push(provider);

    let mut address = cdn_override(
        "fastly-address",
        "pypi.org",
        Some("pypi.org"),
        fastly_names,
        alpn.clone(),
    );
    address.match_dials = static_regex("(?i)(fastly|pypi|python|github)");
    overrides.push(address);

    for (id, address) in CDN_EDGE_ADDRESSES {
        let mut verify_names = Vec::with_capacity(CDN_EDGE_VERIFY_NAMES.len() + 2);
        if let Some(sni) = custom_sni {
            push_unique(&mut verify_names, sni.to_owned());
        }
        push_unique(&mut verify_names, (*address).to_owned());
        for name in CDN_EDGE_VERIFY_NAMES {
            push_unique(&mut verify_names, (*name).to_owned());
        }
        let mut edge = cdn_override(
            id,
            address,
            custom_sni.or(Some(*address)),
            verify_names,
            alpn.clone(),
        );
        edge.match_dials = static_regex(".*");
        overrides.push(edge);
    }
    overrides
}

fn cdn_override(
    id: &str,
    dial: &str,
    sni: Option<&str>,
    verify_server_names: Vec<String>,
    alpn: Vec<Vec<u8>>,
) -> FrontedOverride {
    FrontedOverride {
        override_id: Some(id.to_owned()),
        dials: vec![dial.to_owned()],
        snis: vec![sni.unwrap_or(dial).to_owned()],
        disable_sni: false,
        alpn,
        match_providers: Vec::new(),
        match_dials: Vec::new(),
        match_hosts: Vec::new(),
        verify_server_names,
        verify_pins: Vec::new(),
        tls_profile: Some("Chrome-83".to_owned()),
        skip_cert_verify: false,
    }
}

fn static_regex(pattern: &str) -> Vec<regex::Regex> {
    vec![regex::Regex::new(pattern).expect("static fronting regex")]
}

/// One `FrontingSpec`: the edge a transfer dials and the origin its `Host` header names.
#[derive(Debug, Clone)]
struct FrontingSpec {
    addresses: Vec<String>,
    disable_sni: bool,
    skip_verify: bool,
    verify_name: String,
    verify_pins: Vec<String>,
    host: String,
}

/// One `ObfuscatedServerListRootURLs` entry: a base URL and its per-URL transfer policy.
#[derive(Debug, Clone)]
struct TransferRoot {
    url: String,
    skip_verify: bool,
    headers: Vec<(String, String)>,
    key: Option<String>,
    only_after: usize,
    fronting: Vec<FrontingSpec>,
}

fn regex_matches_any(patterns: &[regex::Regex], values: &[&str]) -> bool {
    patterns.is_empty()
        || values
            .iter()
            .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for PsiphonOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsiphonOut")
            .field("endpoint", &self.endpoint)
            .field("version", &self.version)
            .field("loopback", &self.loopback)
            .field("connected", &self.inner.is_some())
            .field("shutdown", &self.shutdown.is_some())
            .finish()
    }
}

impl PsiphonOut {
    /// Start the native tunnel and its loopback SOCKS edge.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        if !settings.reject_countries.is_empty() && settings.geoip_path.is_none() {
            eprintln!(
                "psiphon: GeoIPDatabasePath is not set, so proxy-country filtering is skipped"
            );
        }
        if settings.compartment != PRIVATE_COMPARTMENT_ID && !settings.conduit {
            eprintln!(
                "psiphon: a custom compartment is set, but this transport dials SSH/OSSH only"
            );
        }
        let endpoint = settings.listen;
        let listener = TcpListener::bind(endpoint)
            .map_err(|error| format!("psiphon: listen {endpoint}: {error}"))?;
        let endpoint = listener
            .local_addr()
            .map_err(|error| format!("psiphon: listen address: {error}"))?;
        let entries = load_entries(&settings)?;
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let affinity = affinity_host(&settings).map(|host| (host, 0));
        let slok_path = state_is_ours(&settings.state).then(|| settings.state.join("osl-sloks"));
        let sloks = crate::psiphon_osl::SlokStore::open(slok_path);
        let osl_seeded = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(crate::psiphon_osl::ServerEvents {
            sloks: Arc::clone(&sloks),
            seeded: Arc::clone(&osl_seeded),
            emit_alerts: settings.emit_server_alerts,
            emit_sloks: settings.emit_sloks,
        });
        let http = settings
            .http_listen
            .map(|port| {
                TcpListener::bind(SocketAddr::new(endpoint.ip(), port))
                    .map_err(|error| format!("psiphon: http listen {port}: {error}"))
            })
            .transpose()?;
        let http_endpoint = http
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
            .map_err(|error| format!("psiphon: http listen address: {error}"))?;
        let session_id = settings
            .session_id
            .clone()
            .unwrap_or_else(|| hex(&random::<16>()));
        let config_state = settings.config_state();
        let replay = Arc::new(crate::psiphon_replay::Cache::new(settings.replay.clone()));
        let light = settings.light.clone().and_then(|mut config| {
            config.session_id.clone_from(&session_id);
            match crate::psiphon_light::Client::new(config) {
                Ok(client) => Some(Arc::new(client)),
                Err(error) => {
                    eprintln!("psiphon: {error}");
                    None
                }
            }
        });
        let inproxy_limiter = settings
            .inproxy_rate_limit
            .map(|(quantity, interval)| Arc::new(DialRateLimiter::new(quantity, interval)));
        let inner = Arc::new(Inner {
            session_id,
            settings,
            config_state,
            entries: Mutex::new(Arc::new(entries)),
            sloks,
            requests,
            osl_seeded,
            osl_attempt: AtomicUsize::new(0),
            last_osl: Mutex::new(None),
            last_osl_failure: Mutex::new(None),
            upgrade_started: Arc::new(AtomicBool::new(false)),
            last_upgrade_attempt: Mutex::new(None),
            dsl_running: AtomicBool::new(false),
            dsl_last_fetch: Mutex::new(None),
            self_ref: Mutex::new(Weak::new()),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            dial_window: AtomicUsize::new(0),
            entry_cursor: AtomicUsize::new(0),
            affinity: Mutex::new(affinity),
            moved_to_front: Mutex::new(HashSet::new()),
            dsl_placeholders: Arc::new(Mutex::new(Vec::new())),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint,
            http_endpoint,
            udpgw: Mutex::new(None),
            conduit: Mutex::new(None),
            conduit_started: OnceLock::new(),
            conduit_fallback: AtomicBool::new(false),
            conduit_connected: AtomicBool::new(false),
            split_untunneled: Mutex::new(HashMap::new()),
            replay,
            light,
            inproxy_limiter,
        });
        *lock(&inner.self_ref) = Arc::downgrade(&inner);
        let shutdown = Arc::new(LaneShutdown::new());
        if let Some(fd) = inner.settings.packet_tunnel_fd {
            let device = crate::tun::Device::from_inherited(fd, crate::psiphon_packet_tunnel::MTU)
                .map_err(|error| format!("psiphon: PacketTunnelTunFileDescriptor {fd}: {error}"))?;
            let weak = Arc::downgrade(&inner);
            let dns = inner.settings.packet_tunnel_dns;
            let packet_shutdown = shutdown.signal();
            thread::Builder::new()
                .name("psiphon-packet-tunnel".to_owned())
                .spawn(move || packet_tunnel_loop(&weak, device, dns, &packet_shutdown))
                .map_err(|error| format!("psiphon: packet tunnel thread: {error}"))?;
        }
        // The edge binds before a tunnel exists, so a refusal is retried, never a lane that exits.
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-tunnel".to_owned())
            .spawn(move || warm_tunnel(&weak))
            .map_err(|error| format!("psiphon: tunnel thread: {error}"))?;
        if let Some(http) = http {
            let weak = Arc::downgrade(&inner);
            thread::Builder::new()
                .name("psiphon-http".to_owned())
                .spawn(move || accept_http(http, weak))
                .map_err(|error| format!("psiphon: http listener thread: {error}"))?;
        }
        let credential = Arc::new(Credential {
            user: inner.settings.proxy_user.clone().unwrap_or_default(),
            pass: inner.settings.proxy_pass.clone().unwrap_or_default(),
        });
        let loopback = endpoint.ip().is_loopback();
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-socks".to_owned())
            .spawn(move || accept_loop(listener, weak))
            .map_err(|error| format!("psiphon: listener thread: {error}"))?;
        Ok(Self {
            inner: Some(inner),
            endpoint,
            credential,
            version: Version::V5,
            loopback,
            shutdown: Some(shutdown),
        })
    }

    /// Validate the settings without opening a socket or downloading a list.
    pub(crate) fn validate(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        if !settings.reject_countries.is_empty() && settings.geoip_path.is_none() {
            eprintln!(
                "psiphon: GeoIPDatabasePath is not set, so proxy-country filtering is skipped"
            );
        }
        if settings.compartment != PRIVATE_COMPARTMENT_ID && !settings.conduit {
            eprintln!(
                "psiphon: a custom compartment is set, but this transport dials SSH/OSSH only"
            );
        }
        if let Some(config) = settings.light.clone() {
            if let Err(error) = crate::psiphon_light::Client::new(config) {
                eprintln!("psiphon: {error}");
            }
        }
        let endpoint = settings.listen;
        Ok(Self {
            inner: None,
            endpoint,
            credential: Arc::new(Credential {
                user: settings.proxy_user.unwrap_or_default(),
                pass: settings.proxy_pass.unwrap_or_default(),
            }),
            version: Version::V5,
            loopback: endpoint.ip().is_loopback(),
            shutdown: None,
        })
    }

    /// The local SOCKS credential: a loopback edge that names none needs none.
    pub(crate) fn credential(&self) -> &Credential {
        if self.loopback && self.credential.user.is_empty() {
            &NO_CREDENTIAL
        } else {
            &self.credential
        }
    }

    /// The handshake a flow pays: SOCKS4 only where the edge demands nothing and the target fits.
    pub(crate) fn session(&self, target: &Destination<'_>) -> (Version, &Credential) {
        if self.loopback
            && self.credential.user.is_empty()
            && !matches!(target, Destination::V6(..))
        {
            (Version::V4, &NO_CREDENTIAL)
        } else {
            (Version::V5, self.credential())
        }
    }

    #[must_use]
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(wake_address(self.endpoint));
        if let Some(http) = self.http_endpoint {
            let _ = TcpStream::connect(wake_address(http));
        }
        if let Some(gateway) = lock(&self.udpgw).take() {
            gateway.close();
        }
        for session in lock(&self.sessions).drain(..) {
            session.close();
        }
    }
}

/// A listener on the wildcard address is woken through the loopback it also covers.
fn wake_address(endpoint: SocketAddr) -> SocketAddr {
    let ip = match endpoint.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, endpoint.port())
}

impl Inner {
    /// Live sessions, with dead ones retired before any count is read.
    fn live(&self) -> usize {
        let mut sessions = lock(&self.sessions);
        self.replay.promote(sessions.as_slice());
        self.replay.retain_open(&mut sessions);
        sessions.len()
    }

    /// Spread flows over the pool round-robin, so one tunnel's window is not a global cap.
    fn pick(&self) -> Option<Arc<Session>> {
        let mut sessions = lock(&self.sessions);
        self.replay.promote(sessions.as_slice());
        self.replay.retain_open(&mut sessions);
        if sessions.is_empty() {
            return None;
        }
        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
        Some(Arc::clone(&sessions[at]))
    }

    /// Whether a failed pass left a continuation window for this scan.
    fn has_dial_window(&self) -> bool {
        !self.settings.cdn_scan_specs.is_empty() && self.dial_window.load(Ordering::Acquire) != 0
    }

    /// The first entry to dial and the head start its affinity buys, read once per batch.
    fn start(&self) -> (usize, Duration) {
        let window = if self.settings.cdn_scan_specs.is_empty() {
            0
        } else {
            self.dial_window.load(Ordering::Acquire)
        };
        let entries = {
            let mut guard = lock(&self.entries);
            if guard.is_empty() {
                return (0, Duration::ZERO);
            }
            if window == 0 {
                if self.settings.fronted_overrides.is_empty()
                    && coin(self.settings.server_entry_reset_probability)
                {
                    let entries = Arc::make_mut(&mut *guard);
                    shuffle(entries.as_mut_slice());
                    lock(&self.moved_to_front).clear();
                }
                let has_placeholders = { !lock(&self.dsl_placeholders).is_empty() };
                if has_placeholders {
                    let entries = Arc::make_mut(&mut *guard);
                    let mut moved = lock(&self.moved_to_front);
                    promote_dsl_placeholders(
                        &self.dsl_placeholders,
                        entries,
                        &mut moved,
                        self.settings.server_entry_max_move_to_front,
                    );
                }
            }
            Arc::clone(&*guard)
        };
        if let Some(start) = dial_window_start(window, entries.len()) {
            return (start, Duration::ZERO);
        }
        let affinity = lock(&self.affinity);
        match affinity_index(&entries, affinity.as_ref()) {
            Some(base) => (base, self.settings.affinity_grace),
            None if self.settings.fronted_overrides.is_empty() => (0, Duration::ZERO),
            None => (
                self.entry_cursor.fetch_add(1, Ordering::Relaxed) % entries.len(),
                Duration::ZERO,
            ),
        }
    }

    /// Record a live server: it becomes the affinity and, under the cap, the next first entry.
    fn remember(&self, host: &str, protocol: &str) {
        if !self.settings.cdn_scan_specs.is_empty() {
            self.dial_window.store(0, Ordering::Release);
        }
        let affinity = host
            .rsplit_once(':')
            .and_then(|(name, port)| port.parse().ok().map(|port| (name, port)));
        if let Some((name, port)) = affinity {
            *lock(&self.affinity) = Some((name.to_owned(), port));
            save_affinity(&self.settings, name);
            save_dial_parameters(&self.settings, name, protocol);
        }
        let mut guard = lock(&self.entries);
        let max = self.settings.server_entry_max_move_to_front;
        if max == 0 {
            return;
        }
        let mut moved = lock(&self.moved_to_front);
        if max > 0 && i64::try_from(moved.len()).unwrap_or(i64::MAX) >= max {
            return;
        }
        if let Some((name, port)) = affinity {
            if move_to_front(Arc::make_mut(&mut *guard), name, port) {
                moved.insert(host.to_owned());
            }
        }
    }

    /// Dial and add one tunnel; the pool path passes no guard and the single-dial
    /// paths hand over the `connecting` guard so the wait below never holds it.
    #[allow(clippy::too_many_lines)]
    fn connect_locked(
        &self,
        mut start: usize,
        affinity_lead: Duration,
        mut connecting: Option<std::sync::MutexGuard<'_, ()>>,
    ) -> Result<Arc<Session>, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        {
            let sessions = lock(&self.sessions);
            self.replay.promote(sessions.as_slice());
        }
        let entries = Arc::clone(&lock(&self.entries));
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let entries = if !self.has_dial_window() && self.replay.wants_move_to_front() {
            let mut reordered = (*entries).clone();
            self.replay.move_to_front(&mut reordered);
            let affinity = lock(&self.affinity);
            if let (Some(old), Some(new)) = (
                affinity_index(&entries, affinity.as_ref()),
                affinity_index(&reordered, affinity.as_ref()),
            ) {
                let count = reordered.len();
                if count != 0 {
                    let offset = (start + count - old) % count;
                    let preferred = reordered.remove(new);
                    reordered.insert(0, preferred);
                    start = offset % count;
                }
            }
            Arc::new(reordered)
        } else {
            entries
        };
        let deadline = Instant::now() + self.settings.ready;
        let limit = entries.len().min(DIAL_ATTEMPTS);
        let timeout = self.settings.dial_timeout();
        let mut last = String::new();
        let mut offset = 0;
        let mut first_batch = true;
        let inproxy_force_remaining = Arc::new(AtomicUsize::new(
            self.settings.inproxy_force_selection_count,
        ));
        let rate_limiter = self.inproxy_limiter.clone();
        while offset < limit {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let width = self.settings.workers.min(limit - offset);
            if width == 0 {
                break;
            }
            let (batch, taken) = take_dial_batch(
                &entries,
                start,
                offset,
                limit,
                width,
                self.settings.intensive_workers,
                self.settings.conduit,
            );
            offset += taken;
            if taken == 0 {
                break;
            }
            let batch: Vec<Server> = batch
                .into_iter()
                .filter(|server| !self.settings.restricted(server, self.settings.conduit))
                .collect();
            if batch.is_empty() {
                continue;
            }
            let session_id = self.session_id.clone();
            let authorizations = self.settings.authorizations.clone();
            let sponsor = self.settings.sponsor.clone();
            let propagation = self.settings.propagation.clone();
            let platform = self.settings.platform.clone();
            let client_version = self.settings.client_version.clone();
            let api_encoding = self.settings.api_encoding;
            let api_protocol = self.settings.api_protocol;
            let compress_tactics = self.settings.compress_tactics;
            let egress_region = self.settings.region.clone();
            let device_region = self.settings.device_region.clone();
            let device_location = self.settings.device_location.clone();
            let client_features = self.settings.client_features.clone();
            let split_tunnel = self.settings.split_tunnel_own_region;
            let split_tunnel_regions = self.settings.split_tunnel_regions.clone();
            let proxy = self.settings.proxy.clone();
            let dns = self.settings.dns.clone();
            let keepalive = self.settings.keepalive;
            let limit_meek_buffers = self.settings.limit_meek_buffers;
            let tls_shape = self.settings.tls_shape.clone();
            let burst = self.settings.burst;
            let disable_api = self.settings.disable_api;
            let ssh_algorithms = self.settings.ssh_algorithms.clone();
            let config_state = self.config_state;
            let replay = Arc::clone(&self.replay);
            let dsl_placeholders = Arc::clone(&self.dsl_placeholders);
            let dsl_retain_failed = self.settings.dsl_retain_failed;
            let dsl_placeholder_ttl = self.settings.dsl_placeholder_ttl;
            let conduit = if self.settings.conduit
                && batch
                    .iter()
                    .any(|server| server.inproxy.is_some() || server.tls_inproxy.is_some())
            {
                match self.conduit(deadline) {
                    Ok(conduit) => Some(conduit),
                    Err(error) => {
                        eprintln!("psiphon: conduit unavailable: {error}");
                        None
                    }
                }
            } else {
                None
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let lead = if std::mem::take(&mut first_batch) {
                affinity_lead
            } else {
                Duration::ZERO
            };
            let lead = if lead.saturating_add(timeout) <= remaining {
                lead
            } else {
                Duration::ZERO
            };
            let last_delay = lead.saturating_add(
                self.settings
                    .stagger
                    .saturating_mul(u32::try_from(taken.saturating_sub(1)).unwrap_or(u32::MAX)),
            );
            let stagger = if last_delay.saturating_add(timeout) <= remaining {
                self.settings.stagger
            } else {
                Duration::ZERO
            };
            let budget = if stagger.is_zero() {
                remaining.min(timeout.saturating_add(lead))
            } else {
                last_delay.saturating_add(timeout).min(remaining)
            };
            if budget.is_zero() {
                break;
            }
            let inproxy_prefer = self.settings.inproxy_prefer_probability;
            let inproxy_only = !self.settings.protocols.is_empty()
                && self
                    .settings
                    .protocols
                    .iter()
                    .all(|protocol| protocol.starts_with("INPROXY-"));
            let personal_pairing = self.settings.personal_pairing;
            let incompatible = self.settings.inproxy_incompatible();
            let inproxy_api_timeout = self
                .settings
                .inproxy_api_timeout
                .mul_f64(self.settings.latency.multiplier());
            let limiter = rate_limiter.clone();
            let rate_deadline = Instant::now() + budget;
            let force_remaining = Arc::clone(&inproxy_force_remaining);
            let requests =
                Arc::clone(&self.requests) as Arc<dyn crate::psiphon_ssh::ServerRequests>;
            let cdn_scan_specs = self.settings.cdn_scan_specs.clone();
            let cdn_scan_state = Arc::clone(&self.settings.cdn_scan_state);
            let batch_deadline = (Instant::now() + budget).min(deadline);
            let attempt = move |server: &Server| {
                let lease = replay.begin(server, config_state);
                let _scope = crate::psiphon_ssh::dial_seed_scope(lease.seed());
                let mut selected = lease.server().clone();
                let scan_candidate = selected.meek.as_ref().and_then(|meek| {
                    let sni = if meek.disable_sni {
                        ""
                    } else {
                        meek.sni.as_str()
                    };
                    cdn_scan_specs
                        .iter()
                        .any(|spec| spec.contains(&meek.dial, sni))
                        .then(|| crate::psiphon_cdn::ScanCandidate {
                            ip: meek.dial.clone(),
                            sni: sni.to_owned(),
                        })
                });
                let mut use_inproxy = select_inproxy(
                    selected.inproxy.is_some() || selected.tls_inproxy.is_some(),
                    selected.direct && !inproxy_only,
                    conduit.is_some(),
                    inproxy_prefer,
                    &force_remaining,
                );
                if use_inproxy && incompatible && !personal_pairing && !inproxy_only {
                    if !selected.direct {
                        lease.failed();
                        return Err(
                            "psiphon: in-proxy dial skipped on incompatible network".to_owned()
                        );
                    }
                    use_inproxy = false;
                }
                if use_inproxy {
                    if selected.inproxy.is_none() {
                        selected.inproxy = selected.tls_inproxy.take();
                    }
                    if limiter
                        .as_ref()
                        .is_some_and(|limiter| !limiter.wait(rate_deadline))
                    {
                        lease.failed();
                        return Err("psiphon: in-proxy dial rate limit expired".to_owned());
                    }
                } else {
                    selected.inproxy = None;
                    selected.tls_inproxy = None;
                }
                expire_dsl_placeholder(
                    &dsl_placeholders,
                    &server.host,
                    server.port,
                    dsl_placeholder_ttl,
                );
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    lease.failed();
                    return Err("psiphon: dial budget expired before the attempt".to_owned());
                }
                let api_timeout = use_inproxy.then_some(inproxy_api_timeout);
                let identity = Identity {
                    session_id: &session_id,
                    authorizations: &authorizations,
                    sponsor: &sponsor,
                    propagation: &propagation,
                    platform: &platform,
                    version: &client_version,
                    egress_region: egress_region.as_deref(),
                    device_region: device_region.as_deref(),
                    device_location: device_location.as_deref(),
                    client_features: &client_features,
                    split_tunnel,
                    split_tunnel_regions: &split_tunnel_regions,
                    api_encoding,
                    api_protocol,
                    compress_tactics,
                    disable_api,
                    ssh_algorithms: ssh_algorithms.as_ref(),
                };
                match Session::connect(
                    &selected,
                    &identity,
                    batch_deadline,
                    proxy.as_ref(),
                    &dns,
                    conduit.as_deref(),
                    keepalive,
                    &tls_shape,
                    limit_meek_buffers,
                    api_timeout,
                    Some(Arc::clone(&requests)),
                    burst,
                ) {
                    Ok(session) => {
                        if let Some(candidate) = &scan_candidate {
                            lock(&cdn_scan_state).record(candidate, true);
                        }
                        clear_dsl_placeholder(&dsl_placeholders, &server.host, server.port);
                        Ok((session, lease, use_inproxy))
                    }
                    Err(why) => {
                        if let Some(candidate) = &scan_candidate {
                            lock(&cdn_scan_state).record(candidate, false);
                        }
                        retain_dsl_placeholder(
                            &dsl_placeholders,
                            &server.host,
                            server.port,
                            dsl_retain_failed,
                        );
                        lease.failed();
                        Err(why)
                    }
                }
            };
            match race(batch, attempt, budget, stagger, lead) {
                Ok((session, lease, inproxy)) => {
                    drop(connecting.take());
                    if self.stopping.load(Ordering::Acquire) {
                        session.close();
                        return Err("psiphon: the lane is stopping".to_owned());
                    }
                    let protocol = session.protocol();
                    let hold_off =
                        self.settings
                            .holdoff
                            .duration(protocol)
                            .max(self.settings.holdoff_for(
                                protocol,
                                session.provider_id(),
                                session.region(),
                                session.fronting_provider_id(),
                            ));
                    if !hold_off.is_zero() {
                        eprintln!(
                            "psiphon: holding off {protocol} for {} ms",
                            hold_off.as_millis()
                        );
                        let deadline = Instant::now() + hold_off;
                        loop {
                            if self.stopping.load(Ordering::Acquire) {
                                session.close();
                                return Err("psiphon: the lane is stopping".to_owned());
                            }
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
                            thread::sleep(remaining.min(Duration::from_millis(50)));
                        }
                    }
                    self.apply_handshake(&session);
                    self.start_upgrade(&session);
                    let established = !lock(&self.sessions).is_empty();
                    if let Some(probe) = self.settings.liveness.spec(protocol, established) {
                        if let Err(why) = session.liveness_test(
                            probe.min_upstream,
                            probe.max_upstream,
                            probe.min_downstream,
                            probe.max_downstream,
                            self.settings.dial_timeout(),
                        ) {
                            session.close();
                            lease.failed();
                            last = format!("psiphon: liveness test on {protocol}: {why}");
                            continue;
                        }
                    }
                    lease.succeeded(session.id());
                    let session = Arc::new(session);
                    if inproxy && self.settings.conduit {
                        self.conduit_connected.store(true, Ordering::Release);
                    }
                    eprintln!(
                        "psiphon: tunnel up via {} {}",
                        session.server(),
                        session.protocol()
                    );
                    let mut sessions = lock(&self.sessions);
                    self.replay.retain_open(&mut sessions);
                    if sessions.len() >= self.settings.pool {
                        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
                        let existing = Arc::clone(&sessions[at]);
                        drop(sessions);
                        self.replay.promote(std::slice::from_ref(&session));
                        session.close();
                        self.replay.forget_probe(session.id());
                        return Ok(existing);
                    }
                    sessions.push(Arc::clone(&session));
                    return Ok(session);
                }
                Err(why) => last = why,
            }
        }
        if !self.settings.cdn_scan_specs.is_empty() {
            let next = next_dial_start(start, offset, entries.len()).wrapping_add(1);
            self.dial_window.store(next, Ordering::Release);
        }
        Err(format!("psiphon: no server accepted the tunnel: {last}"))
    }

    /// Start a version-gated upgrade download off the handshake, at most one in flight.
    fn start_upgrade(&self, session: &Session) {
        if !self.settings.enable_upgrade || self.settings.upgrade_roots.is_empty() {
            return;
        }
        if self.upgrade_started.load(Ordering::Acquire) {
            return;
        }
        {
            let mut last = lock(&self.last_upgrade_attempt);
            if last.is_some_and(|at| at.elapsed() < self.settings.upgrade_retry) {
                return;
            }
            *last = Some(Instant::now());
        }
        if self.upgrade_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let job = UpgradeJob {
            state: self.settings.state.clone(),
            roots: self.settings.upgrade_roots.clone(),
            version_header: self.settings.upgrade_version_header.clone(),
            client_version: self.settings.client_version.clone(),
            tls_roots: self.settings.tls_shape.roots.clone(),
            disable_system_roots: self.settings.tls_shape.disable_system_root_cas,
        };
        let version = session
            .handshake()
            .upgrade_client_version
            .clone()
            .unwrap_or_default();
        let started = Arc::clone(&self.upgrade_started);
        thread::spawn(move || match download_upgrade(&job, &version) {
            Ok(false) => started.store(false, Ordering::Release),
            Ok(true) => {}
            Err(why) => {
                eprintln!("psiphon: upgrade: {why}");
                started.store(false, Ordering::Release);
            }
        });
    }

    /// Start the dynamic server list fetch off an established tunnel, at most one in flight.
    fn start_dsl(self: &Arc<Self>, session: &Arc<Session>) {
        if self.settings.disable_api {
            return;
        }
        let tactics = session
            .handshake()
            .tactics_payload
            .as_ref()
            .map(crate::psiphon_tactics::Tactics::from_json);
        let dsl = Dsl::resolved(
            self.settings.raw.as_ref(),
            tactics
                .as_ref()
                .and_then(|tactics| tactics.parameters.as_ref()),
        );
        if !dsl.enable {
            return;
        }
        if lock(&self.dsl_last_fetch).is_some_and(|at| at.elapsed() < dsl.ttl) {
            return;
        }
        if self.dsl_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let lane = Arc::clone(self);
        let session = Arc::clone(session);
        if let Err(error) = thread::Builder::new()
            .name("psiphon-dsl".to_owned())
            .spawn(move || {
                match lane.dsl_fetch(&session) {
                    Ok(added) => {
                        if added > 0 {
                            eprintln!("psiphon: DSL added {added} server entries");
                        }
                    }
                    Err(why) => eprintln!("psiphon: DSL fetch: {why}"),
                }
                lane.dsl_running.store(false, Ordering::Release);
            })
        {
            self.dsl_running.store(false, Ordering::Release);
            eprintln!("psiphon: DSL thread: {error}");
        }
    }

    /// Run one discover-then-get pass against the active tunnel's relay.
    #[allow(clippy::too_many_lines)]
    fn dsl_fetch(&self, session: &Session) -> Result<usize, String> {
        if self.settings.disable_api {
            return Ok(0);
        }
        let tactics = session
            .handshake()
            .tactics_payload
            .as_ref()
            .map(crate::psiphon_tactics::Tactics::from_json);
        let dsl = Dsl::resolved(
            self.settings.raw.as_ref(),
            tactics
                .as_ref()
                .and_then(|tactics| tactics.parameters.as_ref()),
        );
        if !dsl.enable {
            return Ok(0);
        }
        if lock(&self.dsl_last_fetch).is_some_and(|at| at.elapsed() < dsl.ttl) {
            return Ok(0);
        }
        let parameters = dsl_base_parameters(
            &self.settings,
            &self.session_id,
            tactics.as_ref().map_or("", |tactics| tactics.tag.as_str()),
        );
        let discover = dsl_discover(
            session,
            &dsl,
            &parameters,
            random_count(dsl.discover_min, dsl.discover_max),
        )?;
        let mut known = HashSet::new();
        {
            let entries = lock(&self.entries);
            for entry in entries.iter() {
                known.insert((entry.dsl_tag(), entry.configuration_version));
            }
        }
        let mut get = Vec::new();
        let mut prioritized = Vec::new();
        for tag in discover {
            let name = ferrox_core::b64::encode(&tag.tag);
            if known.contains(&(name.clone(), tag.version)) {
                if tag.prioritize && coin(dsl.prioritize_existing) {
                    prioritized.push(name);
                }
                continue;
            }
            get.push(tag);
        }
        let mut added = 0usize;
        let mut at = 0usize;
        while at < get.len() {
            let remaining = get.len() - at;
            let mut count = random_count(dsl.get_min.max(1), dsl.get_max).clamp(1, remaining);
            let mut attempt = 0usize;
            loop {
                match dsl_get(
                    session,
                    &dsl,
                    &parameters,
                    &get[at..at + count],
                    &self.settings.conduit_protocols,
                ) {
                    Ok(entries) => {
                        for (tag, server) in get[at..at + count].iter().zip(entries) {
                            let Some(server) = server else {
                                continue;
                            };
                            let mut entries = lock(&self.entries);
                            let region_available =
                                entries_match_region(entries.as_slice(), &self.settings);
                            let Some(server) =
                                runtime_entry(server, &self.settings, region_available)
                            else {
                                continue;
                            };
                            let name = server.dsl_tag();
                            if name.is_empty() {
                                continue;
                            }
                            let list = Arc::make_mut(&mut *entries);
                            if let Some(existing) = list
                                .iter()
                                .position(|known| !name.is_empty() && known.dsl_tag() == name)
                            {
                                if list[existing].configuration_version
                                    < server.configuration_version
                                {
                                    list[existing] = server;
                                }
                                if tag.prioritize && coin(dsl.prioritize_existing) {
                                    prioritized.push(name);
                                }
                                continue;
                            }
                            list.push(server);
                            if tag.prioritize && coin(dsl.prioritize_new) {
                                prioritized.push(name);
                            }
                            added += 1;
                        }
                        at += count;
                        break;
                    }
                    Err(why) if attempt < dsl.retry_count && count > 1 => {
                        pause_dsl(&dsl);
                        count = (count / 2).max(1);
                        attempt += 1;
                        eprintln!("psiphon: DSL get retry after {why}");
                    }
                    Err(why) => return Err(why),
                }
            }
        }
        for name in prioritized {
            self.prioritize_tag(&name);
        }
        *lock(&self.dsl_last_fetch) = Some(Instant::now());
        Ok(added)
    }

    /// Record a DSL-prioritized entry; the next dial round promotes it under the live-server cap.
    fn prioritize_tag(&self, tag: &str) {
        if tag.is_empty() {
            return;
        }
        let max = self.settings.server_entry_max_move_to_front;
        if max == 0 {
            return;
        }
        let entries = lock(&self.entries);
        let Some(entry) = entries.iter().find(|entry| entry.dsl_tag() == tag) else {
            return;
        };
        let host = entry.host.clone();
        let port = entry.port;
        drop(entries);
        let mut placeholders = lock(&self.dsl_placeholders);
        if let Some(at) = dsl_placeholder_position(&placeholders, &host, port) {
            placeholders[at].created = Instant::now();
        } else {
            placeholders.push(DslPlaceholder {
                host,
                port,
                created: Instant::now(),
            });
        }
    }

    /// Apply the server's handshake reply: a steering IP for the fronting provider and new entries.
    fn apply_handshake(&self, session: &Session) {
        let state = session.handshake();
        if let Some(provider) = session.fronting_provider_id() {
            if let Some(address) = state
                .steering_ip
                .as_deref()
                .and_then(|text| text.parse::<IpAddr>().ok())
                .filter(|address| !is_bogon(*address))
            {
                self.settings.dns.remember_steering(provider, address);
            }
        }
        if state.encoded_server_list.is_empty() {
            return;
        }
        let mut entries = lock(&self.entries);
        let list = Arc::make_mut(&mut *entries);
        for encoded in &state.encoded_server_list {
            let Some(server) = decode_entry_with(encoded, true, &self.settings.conduit_protocols)
            else {
                continue;
            };
            let region_available = entries_match_region(list.as_slice(), &self.settings);
            let Some(server) = runtime_entry(server, &self.settings, region_available) else {
                continue;
            };
            if !list
                .iter()
                .any(|known| known.host == server.host && known.port == server.port)
            {
                list.push(server);
            }
        }
    }

    /// Auto keeps personal pairing until the fallback window expires without a tunnel.
    fn conduit_mode(&self) -> ConduitMode {
        if self.settings.conduit_mode != ConduitMode::Auto {
            return self.settings.conduit_mode;
        }
        if self.conduit_fallback.load(Ordering::Acquire) {
            return ConduitMode::Public;
        }
        if self.conduit_connected.load(Ordering::Acquire) {
            return ConduitMode::Auto;
        }
        let started = *self.conduit_started.get_or_init(Instant::now);
        if started.elapsed() >= self.settings.conduit_timeout {
            self.conduit_fallback.store(true, Ordering::Release);
            return ConduitMode::Public;
        }
        ConduitMode::Auto
    }

    /// Build the broker conduit once from the tactics payload and selected compartments.
    #[allow(clippy::too_many_lines)]
    fn conduit(&self, until: Instant) -> Result<Arc<crate::psiphon_webrtc::Conduit>, String> {
        let mode = self.conduit_mode();
        if let Some((cached, conduit)) = lock(&self.conduit).clone() {
            if cached == mode {
                return Ok(conduit);
            }
        }
        let geoip = if self.settings.reject_countries.is_empty() {
            None
        } else if let Some(path) = self.settings.geoip_path.as_deref() {
            match crate::psiphon_geoip::GeoIp::open(path, &self.settings.reject_countries) {
                Ok(geoip) => geoip,
                Err(error) => {
                    eprintln!("{error}; skipping proxy-country filtering");
                    None
                }
            }
        } else {
            None
        };
        let servers = load_tactics_entries(&self.settings)?;
        let session_id = hex(&random::<16>());
        let tactics = fetch_tactics_from(&self.settings, &servers, &session_id, Some(until))?;
        let personal = decode_compartment(&self.settings.compartment)?;
        let configured_compartments = configured_inproxy_compartments(&self.settings);
        let common = if configured_compartments.is_empty() {
            decode_compartments(&tactics.compartments)?
        } else {
            decode_compartments(&configured_compartments)?
        };
        let (common, personal) = match mode {
            ConduitMode::Public => (common, Vec::new()),
            ConduitMode::Shirokhorshid | ConduitMode::Auto => (Vec::new(), vec![personal]),
        };
        // The compartment in the offer is what the proxy pairs on, so it is also what orders and reduces the brokers: a personal ordering under a common offer (or the reverse) picks a broker the other side never selects.
        let configured = configured_inproxy_brokers(&self.settings, mode != ConduitMode::Public);
        let mut brokers = if configured.is_empty() {
            tactics.brokers.clone()
        } else {
            configured
        };
        if let Some(compartment) = personal.first() {
            let max = count_field(
                self.settings.raw.as_ref(),
                "InproxyPersonalPairingMaxBrokerSpecCount",
                3,
            );
            brokers = order_personal_brokers(brokers, compartment, max);
        } else {
            shuffle_brokers(&mut brokers);
        }
        if brokers.is_empty() {
            return Err("psiphon conduit: no broker".to_owned());
        }
        let routes = brokers
            .iter()
            .map(|broker| crate::psiphon_webrtc::BrokerRoute {
                broker: crate::psiphon_broker::Broker {
                    public_key: broker.public_key.clone(),
                    root_secret: broker.root_secret.clone(),
                },
                fronts: broker_fronts(broker),
            })
            .collect();
        if common.is_empty() && personal.is_empty() {
            return Err("psiphon conduit: no compartments".to_owned());
        }
        let conduit = Arc::new(crate::psiphon_webrtc::Conduit::new(
            routes,
            common,
            personal,
            inproxy_stun_servers(&self.settings, &tactics),
            inproxy_stun_servers_rfc5780(&self.settings, &tactics),
            self.settings.inproxy_disable_stun,
            self.settings.inproxy_discover_nat,
            self.settings
                .inproxy_discover_nat_timeout
                .mul_f64(self.settings.latency.multiplier())
                .min(Duration::from_secs(600)),
            self.settings.inproxy_media_streams,
            self.settings.inproxy_media_traffic_shaping,
            self.settings
                .inproxy_media_traffic_shaping_parameters
                .clone(),
            self.settings.inproxy_traffic_shaping,
            self.settings.inproxy_traffic_shaping_parameters.clone(),
            self.settings.inproxy_disable_ipv6_ice,
            self.settings.inproxy_disable_inbound_mobile
                && self.settings.inproxy_network_type == "MOBILE",
            self.settings.inproxy_debug,
            !bool_setting(
                self.settings.raw.as_ref(),
                "InproxyClientDisableWaitToShareSession",
            ),
            self.settings.inproxy_front_timeouts.clone(),
            self.settings.conduit_protocols.clone(),
            self.settings.dial_timeout(),
            self.settings.inproxy_offer_timeout,
            self.settings.inproxy_offer_personal_timeout,
            self.settings.inproxy_offer_retry_delay,
            self.settings.inproxy_offer_retry_jitter,
            self.settings.inproxy_relay_timeout,
            self.settings.inproxy_await_ready_timeout,
            self.settings.inproxy_no_match_failover,
            self.settings.inproxy_no_match_failover_personal,
            self.settings.meek_headers.clone(),
            self.settings.proxy.clone(),
            self.settings.dns.clone(),
            &self.settings.reject_cidrs,
            geoip,
        ));
        *lock(&self.conduit) = Some((mode, Arc::clone(&conduit)));
        Ok(conduit)
    }

    fn udp(&self) -> Result<Arc<UdpGateway>, String> {
        if let Some(gateway) = lock(&self.udpgw).as_ref() {
            if !gateway.is_closed() {
                return Ok(Arc::clone(gateway));
            }
        }
        let channel = self.dial_tunnel(UDPGW_HOST, UDPGW_PORT, self.split_tunnel_enabled())?;
        let mut slot = lock(&self.udpgw);
        if let Some(gateway) = slot.as_ref() {
            if !gateway.is_closed() {
                channel.close();
                return Ok(Arc::clone(gateway));
            }
        }
        let gateway = UdpGateway::start(channel);
        *slot = Some(Arc::clone(&gateway));
        Ok(gateway)
    }

    fn dial(&self, host: &str, port: u16) -> Result<Flow, String> {
        if let Some(light) = self.light.as_ref() {
            if light.routes(host, port) && !self.recent_tunnel(light.inactive()) {
                match light.dial(host, port, self.settings.proxy.as_ref()) {
                    Ok(stream) => {
                        if std::env::var_os("AETHER_PSIPHON_TRACE_FLOWS").is_some() {
                            eprintln!("psiphon: light proxy carried {host}:{port}");
                        }
                        return Ok(Flow::Direct(stream));
                    }
                    Err(error) => eprintln!("psiphon: {error}"),
                }
            }
        }
        if !self.split_tunnel_enabled() {
            return self.dial_tunnel(host, port, false).map(Flow::Tunnel);
        }
        let key = format!("{host}:{port}");
        if self.split_is_untunneled(&key) {
            return self.direct(host, port).map(Flow::Direct);
        }
        self.dial_split(host, port, &key)
    }

    /// A server-tunneled dial: UDP gateways and plain lanes never take the direct path.
    fn dial_tunnel(&self, host: &str, port: u16, always_tunneled: bool) -> Result<Channel, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        for _ in 0..2 {
            let session = self.ensure()?;
            let opened = if always_tunneled {
                session.open_tunneled(host, port)
            } else {
                session.open(host, port)
            };
            match opened {
                Ok(channel) => return Ok(channel),
                // A refused target says nothing about the tunnel; a dead one is replaced and retried.
                Err(why) if !session.is_closed() => return Err(why),
                Err(_) => self.retire(&session),
            }
        }
        Err(format!("psiphon: {host}:{port} was not reachable"))
    }

    /// Ask the server to classify a target, then tunnel it or dial it direct.
    fn dial_split(&self, host: &str, port: u16, key: &str) -> Result<Flow, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        for _ in 0..2 {
            let session = self.ensure()?;
            match session.open_split(host, port) {
                Ok(Some(channel)) => {
                    self.split_forget(key);
                    return Ok(Flow::Tunnel(channel));
                }
                Ok(None) => {
                    self.split_remember(key);
                    return self.direct(host, port).map(Flow::Direct);
                }
                // A refused target says nothing about the tunnel; a dead one is replaced and retried.
                Err(why) if !session.is_closed() => return Err(why),
                Err(_) => self.retire(&session),
            }
        }
        Err(format!("psiphon: {host}:{port} was not reachable"))
    }

    fn retire(&self, session: &Arc<Session>) {
        self.replay.promote(std::slice::from_ref(session));
        session.close();
        lock(&self.sessions).retain(|current| !Arc::ptr_eq(current, session));
        self.replay.forget_probe(session.id());
    }

    fn split_tunnel_enabled(&self) -> bool {
        self.settings.split_tunnel_own_region || !self.settings.split_tunnel_regions.is_empty()
    }

    /// Whether any tunnel read within `threshold`, which keeps the light fallback off.
    fn recent_tunnel(&self, threshold: Duration) -> bool {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        sessions.iter().any(|session| session.idle() < threshold)
    }

    fn split_is_untunneled(&self, key: &str) -> bool {
        let mut cache = lock(&self.split_untunneled);
        match cache.get(key).copied() {
            Some(at) if at.elapsed() < SPLIT_TUNNEL_CLASSIFICATION_TTL => true,
            Some(_) => {
                cache.remove(key);
                false
            }
            None => false,
        }
    }

    fn split_remember(&self, key: &str) {
        let mut cache = lock(&self.split_untunneled);
        if cache.len() >= SPLIT_TUNNEL_CLASSIFICATION_MAX && !cache.contains_key(key) {
            cache.retain(|_, at| at.elapsed() < SPLIT_TUNNEL_CLASSIFICATION_TTL);
            if cache.len() >= SPLIT_TUNNEL_CLASSIFICATION_MAX {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(key.to_owned(), Instant::now());
    }

    fn split_forget(&self, key: &str) {
        lock(&self.split_untunneled).remove(key);
    }

    /// The direct half of split tunnel: the reference's untunneled dial, proxy included.
    fn direct(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        if let Some(proxy) = self.settings.proxy.as_ref() {
            let deadline = Instant::now() + self.settings.dial_timeout();
            let stream = proxy.connect_host(host, port, deadline)?;
            let _ = stream.set_read_timeout(None);
            let _ = stream.set_write_timeout(None);
            return Ok(stream);
        }
        let timeout = self.settings.dial_timeout();
        let addresses = crate::psiphon_dns::resolve_with(&self.settings.dns, host, port)
            .map_err(|error| format!("psiphon: split tunnel could not resolve {host}: {error}"))?;
        let mut last = format!("no address for {host}");
        for address in addresses {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(error) => last = format!("{address}: {error}"),
            }
        }
        Err(format!(
            "psiphon: split tunnel could not dial {host}:{port}: {last}"
        ))
    }

    /// A live tunnel, dialing at most one beside any other caller.
    fn ensure(&self) -> Result<Arc<Session>, String> {
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        let connecting = lock(&self.connecting);
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        self.replay.start_pass();
        let (start, lead) = self.start();
        let session = self.connect_locked(start, lead, Some(connecting))?;
        self.remember(session.server(), session.protocol());
        if let Some(lane) = lock(&self.self_ref).upgrade() {
            lane.start_dsl(&session);
        }
        Ok(session)
    }

    /// Fill the configured pool a batch of tunnels at a time, so a wide pool costs
    /// one handshake window instead of one per tunnel.
    fn fill(self: &Arc<Self>) -> Result<(), String> {
        let fill_workers = if self.settings.limit_cpu { 1 } else { 8 };
        self.replay.start_pass();
        let mut first_round = true;
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return Err("psiphon: the lane is stopping".to_owned());
            }
            let missing = self.settings.pool.saturating_sub(self.live());
            if missing == 0 {
                return Ok(());
            }
            if !std::mem::take(&mut first_round) {
                self.replay.next_round();
            }
            if missing == 1 {
                let connecting = lock(&self.connecting);
                if self.live() >= self.settings.pool {
                    return Ok(());
                }
                let (start, lead) = self.start();
                let session = self.connect_locked(start, lead, Some(connecting))?;
                self.remember(session.server(), session.protocol());
                self.start_dsl(&session);
                continue;
            }
            let width = missing.min(fill_workers);
            let (base, lead) = self.start();
            let count = lock(&self.entries).len();
            if count == 0 {
                return Err("psiphon: the server list holds no SSH entries".to_owned());
            }
            let mut handles = Vec::with_capacity(width);
            for spread in 0..width {
                let lane = Arc::clone(self);
                let start = base.wrapping_add(spread) % count;
                let worker_lead = if spread == 0 { lead } else { Duration::ZERO };
                handles.push(
                    thread::Builder::new()
                        .name("psiphon-pool".to_owned())
                        .spawn(move || {
                            let session = lane.connect_locked(start, worker_lead, None)?;
                            lane.start_dsl(&session);
                            Ok(session)
                        })
                        .map_err(|error| format!("psiphon: pool thread: {error}"))?,
                );
            }
            let mut last = String::new();
            let mut succeeded = 0usize;
            let mut reached = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(session)) => {
                        succeeded += 1;
                        reached = Some((session.server().to_owned(), session.protocol()));
                    }
                    Ok(Err(why)) => last = why,
                    Err(_) => "psiphon: a pool dial panicked".clone_into(&mut last),
                }
            }
            if let Some((host, protocol)) = reached {
                self.remember(&host, protocol);
            }
            if succeeded == 0 {
                return Err(last);
            }
        }
    }

    /// Fetch and import the seeded obfuscated server lists, at most once per interval.
    fn refresh_osl(&self) {
        if self.settings.osl_roots.is_empty()
            || self.settings.remote_fetch_disabled
            || self.settings.target.is_some()
        {
            return;
        }
        let forced = self.osl_seeded.swap(false, Ordering::AcqRel);
        let failed = lock(&self.last_osl_failure);
        let retry = self.settings.remote_list_retry;
        if !forced && failed.is_some_and(|at| retry > Duration::ZERO && at.elapsed() < retry) {
            return;
        }
        drop(failed);
        let mut last = lock(&self.last_osl);
        if !forced && last.is_some_and(|at| at.elapsed() < OSL_REFRESH) {
            return;
        }
        *last = Some(Instant::now());
        drop(last);
        let attempt = self.osl_attempt.load(Ordering::Relaxed);
        match fetch_osl_entries(&self.settings, &self.sloks, attempt) {
            Ok((entries, failure)) => {
                let added = self.add_entries(entries);
                if added > 0 {
                    eprintln!("psiphon: imported {added} obfuscated server entries");
                }
                if let Some(why) = failure {
                    self.osl_attempt.fetch_add(1, Ordering::Relaxed);
                    *lock(&self.last_osl_failure) = Some(Instant::now());
                    eprintln!("psiphon: {why}");
                } else {
                    self.osl_attempt.store(0, Ordering::Relaxed);
                    *lock(&self.last_osl_failure) = None;
                }
            }
            Err(why) => {
                self.osl_attempt.fetch_add(1, Ordering::Relaxed);
                *lock(&self.last_osl_failure) = Some(Instant::now());
                eprintln!("psiphon: {why}");
            }
        }
    }

    /// Append entries the lane does not already dial, keeping the snapshot stable.
    fn add_entries(&self, entries: Vec<Server>) -> usize {
        let mut current = lock(&self.entries);
        let added = new_entries(&current, entries);
        let count = added.len();
        if count > 0 {
            let mut list = (**current).clone();
            list.extend(added);
            *current = Arc::new(list);
        }
        count
    }
}

/// Keep the pool warm beside the edge: a refused dial is a retry, not an exit.
fn warm_tunnel(lane: &Weak<Inner>) {
    let mut logged: Option<Instant> = None;
    loop {
        let Some(inner) = lane.upgrade() else {
            return;
        };
        if inner.stopping.load(Ordering::Acquire) {
            return;
        }
        let pause = inner.settings.pause;
        let outcome = inner.fill();
        if outcome.is_ok() {
            inner.refresh_osl();
        }
        drop(inner);
        match outcome {
            Ok(()) => {
                thread::sleep(pause);
                continue;
            }
            Err(why) => {
                let now = Instant::now();
                // One line per cycle at most, so an instantly refused list cannot flood the log.
                if logged.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10)) {
                    eprintln!("psiphon: {why}; retrying");
                    logged = Some(now);
                }
            }
        }
        thread::sleep(pause);
    }
}

/// One packet tunnel batch: the SSH channel writes in 32 KiB packets, so a
/// batch that size is one channel write.
const PACKET_TUNNEL_BATCH: usize = 32 * 1024;
const PACKET_TUNNEL_POLL_MS: i32 = 100;

/// Keep the tun descriptor across reconnects and swap the SSH channel under it,
/// as the reference's `PacketTunnelTransport` does.
fn packet_tunnel_loop(
    lane: &Weak<Inner>,
    mut device: crate::tun::Device,
    dns: crate::psiphon_packet_tunnel::Dns,
    shutdown: &ShutdownSignal,
) {
    let mut logged: Option<Instant> = None;
    loop {
        if shutdown.stopped.load(Ordering::Acquire) {
            return;
        }
        let outcome = packet_tunnel_once(lane, &mut device, dns, shutdown);
        if shutdown.stopped.load(Ordering::Acquire) {
            return;
        }
        if let Err(why) = outcome {
            let now = Instant::now();
            if logged.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10)) {
                eprintln!("psiphon: packet tunnel: {why}; retrying");
                logged = Some(now);
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn packet_tunnel_once(
    lane: &Weak<Inner>,
    device: &mut crate::tun::Device,
    dns: crate::psiphon_packet_tunnel::Dns,
    shutdown: &ShutdownSignal,
) -> Result<(), String> {
    let session = {
        let Some(inner) = lane.upgrade() else {
            return Ok(());
        };
        if inner.stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        inner.ensure()?
    };
    let mut channel = session.open_packet_tunnel()?;
    channel.watch_shutdown(shutdown.flag());
    shutdown.watch(channel.shutdown_waiter());
    let writer = device
        .clone_writer()
        .map_err(|error| format!("tun descriptor clone: {error}"))?;
    let failed = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let mut upstream = channel.clone();
    let mut downstream = channel.clone();
    let close = channel;
    thread::scope(|scope| {
        let failed_reader = &failed;
        let stop_reader = &stop;
        let shutdown_reader = &shutdown.stopped;
        let reader_lane = lane;
        let handle = scope.spawn(move || {
            packet_tunnel_downstream(
                &mut downstream,
                writer,
                dns,
                failed_reader,
                stop_reader,
                shutdown_reader,
                reader_lane,
            )
        });
        let outcome =
            packet_tunnel_upstream(device, &mut upstream, dns, &failed, &shutdown.stopped);
        stop.store(true, Ordering::Release);
        close.close();
        let read = handle
            .join()
            .map_err(|_| "packet tunnel reader panicked".to_owned())?;
        outcome?;
        read?;
        Ok(())
    })
}

fn packet_tunnel_upstream(
    device: &mut crate::tun::Device,
    channel: &mut crate::psiphon_ssh::Channel,
    dns: crate::psiphon_packet_tunnel::Dns,
    failed: &AtomicBool,
    shutdown: &AtomicBool,
) -> Result<(), String> {
    let fd = device.raw_fd();
    let mut packet = vec![0u8; crate::psiphon_packet_tunnel::MTU + 4];
    let mut batch = Vec::with_capacity(PACKET_TUNNEL_BATCH + crate::psiphon_packet_tunnel::MTU + 2);
    loop {
        if failed.load(Ordering::Acquire) {
            return Err("packet tunnel reader stopped".to_owned());
        }
        if shutdown.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        let ready = crate::psiphon_packet_tunnel::wait_readable(fd, PACKET_TUNNEL_POLL_MS)
            .map_err(|error| format!("tun poll: {error}"))?;
        if !ready {
            continue;
        }
        match device.read_packet(&mut packet) {
            Ok(0) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Ok(read) => {
                let packet = &mut packet[..read];
                if crate::psiphon_packet_tunnel::upstream(packet, &dns) {
                    crate::psiphon_packet_tunnel::append_frame(&mut batch, packet)
                        .map_err(|()| "packet does not fit a frame".to_owned())?;
                }
            }
            Err(error) => return Err(format!("tun read: {error}")),
        }
        while batch.len() < PACKET_TUNNEL_BATCH {
            if failed.load(Ordering::Acquire) {
                return Err("packet tunnel reader stopped".to_owned());
            }
            if shutdown.load(Ordering::Acquire) {
                return Err("psiphon: the lane is stopping".to_owned());
            }
            let ready = crate::psiphon_packet_tunnel::wait_readable(fd, 0)
                .map_err(|error| format!("tun poll: {error}"))?;
            if !ready {
                break;
            }
            let read = match device.read_packet(&mut packet) {
                Ok(0) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Ok(read) => read,
                Err(error) => return Err(format!("tun read: {error}")),
            };
            let packet = &mut packet[..read];
            if crate::psiphon_packet_tunnel::upstream(packet, &dns) {
                crate::psiphon_packet_tunnel::append_frame(&mut batch, packet)
                    .map_err(|()| "packet does not fit a frame".to_owned())?;
            }
        }
        if !batch.is_empty() {
            channel
                .write_all(&batch)
                .map_err(|error| format!("packet tunnel channel write: {error}"))?;
            batch.clear();
        }
    }
}

fn packet_tunnel_downstream(
    channel: &mut crate::psiphon_ssh::Channel,
    mut writer: crate::tun::PacketWriter,
    dns: crate::psiphon_packet_tunnel::Dns,
    failed: &AtomicBool,
    stop: &AtomicBool,
    shutdown: &AtomicBool,
    lane: &Weak<Inner>,
) -> Result<(), String> {
    let mut packet = Vec::with_capacity(crate::psiphon_packet_tunnel::MTU);
    loop {
        if shutdown.load(Ordering::Acquire)
            || lane.strong_count() == 0
            || stop.load(Ordering::Acquire)
        {
            return Ok(());
        }
        let read = match crate::psiphon_packet_tunnel::read_frame(channel, &mut packet) {
            Ok(read) => read,
            Err(error) => {
                if failed.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                failed.store(true, Ordering::Release);
                return Err(format!("packet tunnel channel read: {error}"));
            }
        };
        if read == 0 {
            continue;
        }
        let packet = &mut packet[..read];
        if !crate::psiphon_packet_tunnel::downstream(packet, &dns) {
            continue;
        }
        if let Err(error) = writer.write_packet(packet) {
            failed.store(true, Ordering::Release);
            return Err(format!("tun write: {error}"));
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_loop(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve(stream, &inner));
    }
}

fn serve(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let Some((version, ask)) = read_request(&mut client, inner) else {
        return;
    };
    match ask {
        Ask::Connect(host, port) => match inner.dial(&host, port) {
            Ok(flow) => {
                trace_flow(&flow);
                if !ask_reply(&mut client, version, Ok(())) {
                    flow.close();
                    return;
                }
                let _ = client.set_read_timeout(None);
                let _ = client.set_write_timeout(None);
                let rate = inner
                    .settings
                    .rate
                    .as_ref()
                    .map(|rate| Arc::new(Mutex::new(rate.clone())));
                relay_flow(client, flow, inner.settings.relay_buffer, rate.as_ref());
            }
            Err(why) => {
                eprintln!("psiphon: {why}");
                let _ = ask_reply(&mut client, version, Err(5));
            }
        },
        Ask::Udp => serve_udp(client, inner),
    }
}

