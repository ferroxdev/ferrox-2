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

enum Ask {
    Connect(String, u16),
    Udp,
}

/// One accepted flow: inside the SSH tunnel or directly out when split tunnel says so.
enum Flow {
    Tunnel(Channel),
    Direct(TcpStream),
}

impl Flow {
    fn close(&self) {
        match self {
            Self::Tunnel(channel) => channel.close(),
            Self::Direct(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Write for Flow {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tunnel(channel) => channel.write(buffer),
            Self::Direct(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tunnel(channel) => channel.flush(),
            Self::Direct(stream) => stream.flush(),
        }
    }
}

fn read_request(client: &mut TcpStream, inner: &Inner) -> Option<(Version, Ask)> {
    let mut first = [0u8; 1];
    client.read_exact(&mut first).ok()?;
    match first[0] {
        // SOCKS4 carries no credential exchange, so a credentialed edge refuses it instead of serving it open.
        4 if inner.settings.proxy_user.is_none() => read_v4(client).map(|ask| (Version::V4, ask)),
        4 => {
            let _ = client.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]);
            None
        }
        5 => read_v5(client, inner).map(|ask| (Version::V5, ask)),
        _ => None,
    }
}

fn read_v4(client: &mut TcpStream) -> Option<Ask> {
    let mut head = [0u8; 7];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let port = u16::from_be_bytes([head[1], head[2]]);
    let address = Ipv4Addr::new(head[3], head[4], head[5], head[6]);
    let mut user = Vec::new();
    read_nul(client, &mut user)?;
    let host = if address.octets()[..3] == [0, 0, 0] && address.octets()[3] != 0 {
        let mut name = Vec::new();
        read_nul(client, &mut name)?;
        String::from_utf8(name).ok()?
    } else {
        address.to_string()
    };
    Some(Ask::Connect(host, port))
}

fn read_v5(client: &mut TcpStream, inner: &Inner) -> Option<Ask> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count).ok()?;
    let mut methods = vec![0u8; usize::from(count[0])];
    client.read_exact(&mut methods).ok()?;
    let auth = inner.settings.proxy_user.is_some();
    if auth {
        if !methods.contains(&2) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 2]).ok()?;
        read_auth(client, inner)?;
    } else {
        if !methods.contains(&0) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 0]).ok()?;
    }

    let mut request = [0u8; 4];
    client.read_exact(&mut request).ok()?;
    if request[0] != 5 {
        return None;
    }
    let host = match request[3] {
        1 => {
            let mut address = [0u8; 4];
            client.read_exact(&mut address).ok()?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).ok()?;
            String::from_utf8(name).ok()?
        }
        4 => {
            let mut address = [0u8; 16];
            client.read_exact(&mut address).ok()?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).ok()?;
    let port = u16::from_be_bytes(port);
    match request[1] {
        1 => Some(Ask::Connect(host, port)),
        3 => Some(Ask::Udp),
        _ => None,
    }
}

fn read_auth(client: &mut TcpStream, inner: &Inner) -> Option<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let mut user = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut user).ok()?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).ok()?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    client.read_exact(&mut pass).ok()?;
    let expected_user = inner
        .settings
        .proxy_user
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let expected_pass = inner
        .settings
        .proxy_pass
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let user_ok = constant_time_eq(&user, expected_user);
    let pass_ok = constant_time_eq(&pass, expected_pass);
    if user_ok && pass_ok {
        client.write_all(&[1, 0]).ok()?;
        Some(())
    } else {
        client.write_all(&[1, 1]).ok()?;
        None
    }
}

fn read_nul(client: &mut TcpStream, out: &mut Vec<u8>) -> Option<()> {
    loop {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).ok()?;
        if byte[0] == 0 {
            return Some(());
        }
        if out.len() >= 255 {
            return None;
        }
        out.push(byte[0]);
    }
}

fn ask_reply(client: &mut TcpStream, version: Version, result: Result<(), u8>) -> bool {
    match version {
        Version::V4 => {
            let reply = if result.is_ok() {
                [0, 90, 0, 0, 0, 0, 0, 0]
            } else {
                [0, 91, 0, 0, 0, 0, 0, 0]
            };
            client.write_all(&reply).is_ok()
        }
        Version::V5 => {
            let reply = match result {
                Ok(()) => [5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                Err(code) => [5, code, 0, 1, 0, 0, 0, 0, 0, 0],
            };
            client.write_all(&reply).is_ok()
        }
    }
}

/// Relay one accepted flow through the tunnel, then close it when the tunnel ends.
fn relay_flow(
    client: TcpStream,
    flow: Flow,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    match flow {
        Flow::Tunnel(channel) => relay(client, channel, buffer, rate),
        Flow::Direct(remote) => relay_direct(client, remote, buffer, rate),
    }
}

/// Account bytes against the tunnel's rate limits; false means `CloseAfterExhausted` fired.
fn throttle(
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
    is_read: bool,
    bytes: usize,
) -> bool {
    let Some(rate) = rate else {
        return true;
    };
    let account = {
        let Ok(mut rate) = rate.lock() else {
            return true;
        };
        if is_read {
            rate.read(bytes)
        } else {
            rate.write(bytes)
        }
    };
    crate::psiphon_rate::settle(account)
}

/// Relay a flow directly when split tunneling selects it.
#[allow(clippy::needless_pass_by_value)]
fn relay_direct(
    mut client: TcpStream,
    mut remote: TcpStream,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        return;
    };
    let Ok(mut remote_write) = remote.try_clone() else {
        return;
    };
    let forward_rate = rate.cloned();
    let forward = thread::Builder::new()
        .name("psiphon-direct-forward".to_owned())
        .stack_size(FLOW_STACK)
        .spawn(move || {
            let done = pump_copy(
                &mut client_read,
                &mut remote_write,
                buffer,
                forward_rate.as_ref(),
                false,
            );
            let _ = remote_write.shutdown(if done {
                Shutdown::Write
            } else {
                Shutdown::Both
            });
        })
        .ok();
    let done = pump_copy(&mut remote, &mut client, buffer, rate, true);
    let _ = client.shutdown(if done {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
    if let Some(forward) = forward {
        let _ = forward.join();
    }
    let _ = remote.shutdown(Shutdown::Both);
}

/// Copy one direction until EOF or a terminal error.
fn pump_copy(
    source: &mut impl Read,
    sink: &mut impl Write,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
    is_read: bool,
) -> bool {
    let mut bytes = vec![0u8; buffer];
    loop {
        match source.read(&mut bytes) {
            Ok(0) => return true,
            Ok(read) => {
                if !throttle(rate, is_read, read) {
                    return false;
                }
                if sink.write_all(&bytes[..read]).is_err() {
                    return true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return true,
        }
    }
}

/// Relay both directions of an established stream until either side closes.
#[allow(clippy::needless_pass_by_value)]
fn relay(
    mut client: TcpStream,
    channel: Channel,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        channel.close();
        return;
    };
    let mut channel_write = channel.clone();
    let forward_rate = rate.cloned();
    let forward = thread::Builder::new()
        .name("psiphon-flow-forward".to_owned())
        .stack_size(FLOW_STACK)
        .spawn(move || {
            let done = pump_out(
                &mut client_read,
                &mut channel_write,
                buffer,
                forward_rate.as_ref(),
            );
            if done {
                channel_write.shutdown();
            } else {
                channel_write.close();
            }
        })
        .ok();
    let mut channel_read = channel.clone();
    let done = pump_channel(&mut channel_read, &mut client, rate);
    if !done {
        channel_read.close();
    }
    let _ = client.shutdown(if done {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
    if let Some(forward) = forward {
        let _ = forward.join();
    }
    channel.close();
}

fn trace_flow(flow: &Flow) {
    if std::env::var_os("AETHER_PSIPHON_TRACE_FLOWS").is_some() {
        match flow {
            Flow::Tunnel(channel) => eprintln!(
                "psiphon: flow via session {} {}",
                channel.session_id(),
                channel.server()
            ),
            Flow::Direct(_) => eprintln!("psiphon: flow split-tunneled directly"),
        }
    }
}

/// The download half writes each received packet straight from the SSH buffer,
/// coalescing the packets already queued into one vectored call.
fn pump_channel(
    channel: &mut Channel,
    sink: &mut impl Write,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) -> bool {
    let mut batch: Vec<ChannelChunk> = Vec::with_capacity(RELAY_BATCH);
    loop {
        batch.clear();
        match channel.next_batch(&mut batch, RELAY_BATCH) {
            Ok(true) => {
                let bytes: usize = batch.iter().map(|chunk| chunk.data().len()).sum();
                if !throttle(rate, true, bytes) {
                    channel.recycle_chunks(batch.drain(..));
                    return false;
                }
                if !flush_chunks(channel, sink, &mut batch) {
                    return true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return false,
            _ => return true,
        }
    }
}

fn flush_chunks(channel: &Channel, sink: &mut impl Write, batch: &mut Vec<ChannelChunk>) -> bool {
    let mut slices = [IoSlice::new(&[]); RELAY_BATCH];
    for (slot, chunk) in slices.iter_mut().zip(batch.iter()) {
        *slot = IoSlice::new(chunk.data());
    }
    let wrote = write_all_vectored(sink, &mut slices[..batch.len()]).is_ok();
    channel.recycle_chunks(batch.drain(..));
    wrote
}

fn write_all_vectored(sink: &mut impl Write, mut slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    while !slices.is_empty() {
        let written = match sink.write_vectored(slices) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "psiphon relay write wrote zero bytes",
            ));
        }
        IoSlice::advance_slices(&mut slices, written);
    }
    Ok(())
}

/// The client-to-tunnel side encrypts the read buffer in place, so the payload is not copied into a packet.
fn pump_out(
    source: &mut impl Read,
    sink: &mut Channel,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) -> bool {
    let mut buffer = vec![0u8; buffer];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => return true,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return true,
        };
        if !throttle(rate, false, read) {
            return false;
        }
        // A window or a smaller remote packet can take less than the read, so the remainder leaves next packet.
        let mut at = 0;
        while at < read {
            match sink.write_in_place(&mut buffer[at..read]) {
                Ok(0) => return true,
                Ok(written) => at += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return true,
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_http(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-http-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve_http(stream, &inner));
    }
}

/// `LocalHttpProxyPort` serves CONNECT only: a plain-response request has no tunnel to carry it.
fn serve_http(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let mut head = [0u8; MAX_REQUEST];
    let mut filled = 0;
    let mut scanned = 0;
    let end = loop {
        if filled == head.len() {
            break None;
        }
        match client.read(&mut head[filled..]) {
            Ok(0) => return,
            Ok(read) => {
                filled += read;
                if let Some(at) = ferrox_core::foxy::head_end_grown(&head[..filled], &mut scanned) {
                    break Some(at);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    };
    let Some(end) = end else {
        let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
        return;
    };
    let text = String::from_utf8_lossy(&head[..end]);
    // Bytes a client pipelined behind its CONNECT headers are the stream's first bytes.
    let early = &head[end + 4..filled];
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("");
    let authority = request.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    // A shared edge names a credential, and the HTTP front answers it the way the SOCKS front does.
    if inner.settings.proxy_user.as_deref().is_some_and(|user| {
        let pass = inner.settings.proxy_pass.as_deref().unwrap_or("");
        !http_authorized(&text, user, pass)
    }) {
        let _ = client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"psiphon\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|bare| bare.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(port) = port.parse::<u16>() else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    match inner.dial(host, port) {
        Ok(mut flow) => {
            trace_flow(&flow);
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
                || (!early.is_empty() && flow.write_all(early).is_err())
            {
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
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

/// No early exit, so the compare's time follows the length and not the first differing byte.
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

/// A `Proxy-Authorization: Basic` header carries the same `user:pass` the SOCKS front takes.
fn http_authorized(head: &str, user: &str, pass: &str) -> bool {
    let mut expected = Vec::with_capacity(user.len() + pass.len() + 1);
    expected.extend_from_slice(user.as_bytes());
    expected.push(b':');
    expected.extend_from_slice(pass.as_bytes());
    let expected = ferrox_core::b64::encode(&expected);
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
                return false;
            }
            let Some((scheme, token)) = value.trim().split_once(' ') else {
                return false;
            };
            scheme.eq_ignore_ascii_case("basic")
                && constant_time_eq(token.trim().as_bytes(), expected.as_bytes())
        })
    })
}

impl Settings {
    #[allow(clippy::too_many_lines)]
    /// Read the lane settings, keeping the reference defaults for absent fields.
    fn from_json(settings: Option<&Json>) -> Result<Self, String> {
        let merged = merge_additional_parameters(settings)?;
        let settings = merged.as_ref().or(settings);
        let raw = settings.cloned();
        let listen = listen_address(settings)?;
        let region = match text(settings, "region")
            .or_else(|| text(settings, "egressRegion"))
            .or_else(|| text(settings, "EgressRegion"))
            .or_else(|| env("AETHER_PSIPHON_REGION"))
        {
            Some(code) => Some(ferrox_core::psiphon::region(&code).ok_or_else(|| {
                format!("psiphon: region {code:?} is not a two-letter country code")
            })?),
            None => None,
        };
        let dns_servers: Vec<SocketAddr> = string_list(settings, "DNSResolverAlternateServers")
            .iter()
            .filter_map(|server| {
                let parsed = dns_server(server);
                if parsed.is_none() {
                    eprintln!("psiphon: ignoring invalid DNSResolverAlternateServers {server:?}");
                }
                parsed
            })
            .collect();
        let dns = dns_config(settings, &dns_servers);
        if flag(settings, "disableTunnels", "AETHER_PSIPHON_DISABLE_TUNNELS")
            || flag(settings, "DisableTunnels", "AETHER_PSIPHON_DISABLE_TUNNELS")
        {
            return Err(
                "psiphon: disableTunnels opens no tunnel, so this lane would carry nothing"
                    .to_owned(),
            );
        }
        let ready = text(settings, "readySeconds")
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("readySeconds"))
                    .and_then(Json::as_u32)
                    .map(|value| value.to_string())
            })
            .or_else(|| env("AETHER_PSIPHON_READY_SECS"))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map_or(ferrox_core::psiphon::READY_SECS, |value| value.min(86_400));
        let mut server_lists = json_list(settings, "serverListURLs");
        for key in [
            "remoteServerListURLs",
            "RemoteServerListURLs",
            "RemoteServerListUrl",
            "remoteServerListUrl",
            "serverListUrls",
        ] {
            if server_lists.is_empty() {
                server_lists = json_list(settings, key);
            }
        }
        if server_lists.is_empty() {
            server_lists.extend(text(settings, "serverListURL"));
        }
        if server_lists.is_empty() {
            server_lists = env_list("AETHER_PSIPHON_SERVER_LIST");
        }
        let server_lists_explicit = !server_lists.is_empty();
        if server_lists.is_empty() {
            server_lists.push(ferrox_core::psiphon::SERVER_LIST_URL.to_owned());
        }
        let proxy_user = text(settings, "localProxyUsername")
            .or_else(|| text(settings, "LocalProxyUsername"))
            .or_else(|| text(settings, "shareProxyOnNetworkUsername"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_USER"))
            .filter(|user| !user.is_empty());
        let proxy_pass = text(settings, "localProxyPassword")
            .or_else(|| text(settings, "LocalProxyPassword"))
            .or_else(|| text(settings, "shareProxyOnNetworkPassword"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_PASS"))
            .filter(|pass| !pass.is_empty());
        if proxy_user.is_some() != proxy_pass.is_some() {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must be named together"
                    .to_owned(),
            );
        }
        if proxy_user.as_ref().is_some_and(|user| user.len() > 255)
            || proxy_pass.as_ref().is_some_and(|pass| pass.len() > 255)
        {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must each be at most 255 bytes"
                    .to_owned(),
            );
        }
        let cdn_profile = text(settings, "cdnProfile").map(|profile| profile.to_ascii_lowercase());
        let selection = text(settings, "protocolSelection")
            .map(|selection| selection.to_ascii_lowercase())
            .or_else(|| {
                text(settings, "protocol_selection").map(|value| value.to_ascii_lowercase())
            });
        let mut conduit = selection.as_deref() == Some("conduit");
        let fronted = match selection.as_deref() {
            None => matches!(cdn_profile.as_deref(), Some("fronted")),
            Some("cdn_fronting" | "fronted" | "fronted-meek" | "cdn") => true,
            Some("auto" | "direct" | "conduit") => false,
            Some(other) => {
                eprintln!("psiphon: protocolSelection {other:?} is not a known mode");
                false
            }
        };
        let mut fronted_fallback = !conduit && !fronted;
        let selection_cdn = selection_enables_cdn(selection.as_deref());
        let selection_tactics_disabled = selection_disables_tactics(selection.as_deref());
        // Explicit LimitTunnelProtocols wins; otherwise derive from protocolSelection.
        let mut protocols = protocol_list(settings);
        if protocols.is_empty() {
            protocols = selection_protocols(selection.as_deref());
        }
        let inproxy_named = protocols
            .iter()
            .any(|protocol| protocol.starts_with("INPROXY-"));
        if inproxy_named {
            conduit = true;
            fronted_fallback = false;
        }
        let inproxy_rate_limit = rate_limit(settings);
        let inproxy_api_timeout = millis_setting(
            settings,
            "InproxyPsiphonAPIRequestTimeoutMilliseconds",
            10_000,
            1_000,
        )
        .max(Duration::from_secs(1));
        let inproxy_debug = bool_setting(settings, "InproxyEnableWebRTCDebugLogging");
        let inproxy_disable_ipv6_ice =
            bool_setting(settings, "InproxyClientDisableIPv6ICECandidates")
                || bool_setting(settings, "InproxyDisableIPv6ICECandidates");
        let inproxy_disable_inbound_mobile =
            bool_setting(settings, "InproxyClientDisableInboundForMobileNetworks")
                || bool_setting(settings, "InproxyDisableInboundForMobileNetworks");
        let inproxy_incompatible_networks =
            string_list(settings, "InproxyClientIncompatibleNetworkTypes")
                .into_iter()
                .map(|network| network.to_ascii_uppercase())
                .collect();
        let inproxy_network_type = text(settings, "NetworkType")
            .unwrap_or_default()
            .to_ascii_uppercase();
        let inproxy_front_timeouts =
            key_durations(settings, "InproxyFrontingProviderClientMaxRequestTimeouts");
        let inproxy_prefer_probability = probability_field(
            settings,
            "InproxyTunnelProtocolPreferProbability",
            if selection.as_deref() == Some("conduit") {
                1.0
            } else {
                0.0
            },
        );
        let inproxy_force_selection_count =
            count_field(settings, "InproxyTunnelProtocolForceSelectionCount", 0);
        let conduit_mode = match text(settings, "conduitMode")
            .or_else(|| text(settings, "conduit_mode"))
            .map(|mode| mode.to_ascii_lowercase())
            .as_deref()
        {
            Some("public") => ConduitMode::Public,
            Some("private" | "shirokhorshid") => ConduitMode::Shirokhorshid,
            Some("auto") | None => ConduitMode::Auto,
            Some(other) => {
                eprintln!("psiphon: conduitMode {other:?} is not a known mode");
                ConduitMode::Auto
            }
        };
        let conduit_timeout = Duration::from_secs(
            number(settings, "conduitTimeout")
                .or_else(|| number(settings, "conduit_timeout"))
                .unwrap_or(180)
                .clamp(10, 600),
        );
        let inproxy_stun = crate::psiphon_tactics::StunServers {
            basic: stun_list(
                settings,
                "InproxyClientSTUNServerAddresses",
                "InproxySTUNServerAddresses",
            ),
            rfc5780: stun_list(
                settings,
                "InproxyClientSTUNServerAddressesRFC5780",
                "InproxySTUNServerAddressesRFC5780",
            ),
        };
        let inproxy_disable_stun = bool_setting(settings, "InproxyDisableSTUN")
            || bool_setting(settings, "InproxyClientDisableSTUN");
        let inproxy_discover_nat =
            probability_field(settings, "InproxyClientDiscoverNATProbability", 0.0);
        let inproxy_discover_nat_timeout = Duration::from_millis(
            integer(settings, "InproxyClientDiscoverNATTimeoutMilliseconds")
                .map_or(10_000, |millis| u64::try_from(millis.max(0)).unwrap_or(0)),
        );
        let inproxy_dtls_randomization =
            probability_field(settings, "InproxyDTLSRandomizationProbability", 0.5);
        let inproxy_media_streams =
            probability_field(settings, "InproxyWebRTCMediaStreamsProbability", 0.0);
        let inproxy_media_traffic_shaping = probability_field(
            settings,
            "InproxyWebRTCMediaStreamsTrafficShapingProbability",
            0.5,
        );
        let inproxy_media_traffic_shaping_parameters = traffic_shaping_parameters_with_default(
            settings,
            "InproxyWebRTCMediaStreamsTrafficShapingParameters",
            crate::psiphon_webrtc::TrafficShapingParameters::media_default(),
        );
        let inproxy_traffic_shaping = probability_field(
            settings,
            "InproxyWebRTCDataChannelTrafficShapingProbability",
            0.5,
        );
        let inproxy_traffic_shaping_parameters = traffic_shaping_parameters(
            settings,
            "InproxyWebRTCDataChannelTrafficShapingParameters",
        );
        let inproxy_offer_timeout = millis_setting(
            settings,
            "InproxyClientOfferRequestTimeoutMilliseconds",
            20_000,
            10_000,
        );
        let inproxy_offer_personal_timeout = millis_setting(
            settings,
            "InproxyClientOfferRequestPersonalTimeoutMilliseconds",
            15_000,
            10_000,
        );
        let inproxy_offer_retry_delay = Duration::from_millis(
            number(settings, "InproxyClientOfferRetryDelayMilliseconds")
                .unwrap_or(100)
                .min(60_000),
        );
        let inproxy_offer_retry_jitter = decimal(settings, "InproxyClientOfferRetryJitter")
            .unwrap_or(0.5)
            .clamp(0.0, 1.0);
        let inproxy_relay_timeout = millis_setting(
            settings,
            "InproxyClientRelayedPacketRequestTimeoutMilliseconds",
            35_000,
            10_000,
        );
        let inproxy_await_ready_timeout = millis_setting(
            settings,
            "InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds",
            20_000,
            0,
        );
        let inproxy_no_match_failover =
            decimal(settings, "InproxyClientNoMatchFailoverProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0);
        let inproxy_no_match_failover_personal =
            decimal(settings, "InproxyClientNoMatchFailoverPersonalProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0);
        let mut conduit_protocols = string_list(settings, "ConduitTunnelProtocols");
        if conduit_protocols.is_empty() {
            conduit_protocols = string_list(settings, "conduitTunnelProtocols");
        }
        if conduit_protocols.is_empty() {
            conduit_protocols = string_list(settings, "CONDUIT_TUNNEL_PROTOCOLS");
        }
        let reject_censored = flag(
            settings,
            "rejectCensoredCountryProxies",
            "AETHER_PSIPHON_REJECT_CENSORED_PROXIES",
        );
        let reject_countries = {
            let mut countries = string_list(settings, "InproxyRejectProxyCountryCodes");
            if countries.is_empty() {
                countries = string_list(settings, "rejectProxyCountryCodes");
            }
            if countries.is_empty() && reject_censored {
                countries = CENSORED_COUNTRY_CODES
                    .iter()
                    .map(|code| (*code).to_owned())
                    .collect();
            }
            countries
                .into_iter()
                .map(|code| code.to_ascii_uppercase())
                .collect()
        };
        let geoip_path = text(settings, "GeoIPDatabasePath");
        let reject_cidrs = string_list(settings, "InproxyRejectProxyCIDRs");
        let limit_quic_versions = string_list(settings, "LimitQUICVersions");
        let dial_ports = port_lists(settings);
        let dial_ports_probability = probability(settings, "LimitTunnelDialPortNumbersProbability");
        let prioritize_protocols = protocol_list_named(settings, "PrioritizeTunnelProtocols");
        let prioritize_count =
            number(settings, "PrioritizeTunnelProtocolsCandidateCount").unwrap_or(10) as usize;
        let prioritize_probability = probability(settings, "PrioritizeTunnelProtocolsProbability");
        let limit_protocols_probability = probability(settings, "LimitTunnelProtocolsProbability");
        let initial_limit_probability =
            probability(settings, "InitialLimitTunnelProtocolsProbability");
        let quic_noise = text(settings, "QUICNoiseProfile").filter(|profile| !profile.is_empty());
        let mut sni_names = string_list(settings, "TLSOSSHSNIServerNames");
        if sni_names.is_empty() {
            if let Some(name) = text(settings, "TLSOSSHSNIServerName") {
                sni_names.push(name);
            }
        }
        // Both reference coins must land, so one setting alone never turns a name into a random one.
        let transform_probability = decimal(settings, "TransformHostNameProbability")
            .unwrap_or(0.5)
            .clamp(0.0, 1.0)
            * decimal(settings, "CustomHostNameProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0);
        let meek_padding = (
            u16::try_from(
                number(settings, "MeekMinTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            u16::try_from(
                number(settings, "MeekMaxTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
        );
        let obfuscated_min_padding = ssh_padding(
            settings,
            "ObfuscatedSSHMinPadding",
            MIN_PADDING,
            MIN_PADDING,
        );
        let obfuscated_max_padding = ssh_padding(
            settings,
            "ObfuscatedSSHMaxPadding",
            MAX_PADDING,
            obfuscated_min_padding,
        );
        let meek_limit = |key: &str| {
            let max = crate::psiphon_meek::MAX_REQUEST_PAYLOAD as u64;
            let raw = number(settings, key).unwrap_or(max);
            let value = raw.clamp(1, max) as usize;
            if raw != value as u64 {
                eprintln!("psiphon: {key} clamped to {value}");
            }
            value
        };
        let meek_min_limit_request = meek_limit("MeekMinLimitRequestPayloadLength");
        let meek_max_limit_request = meek_limit("MeekMaxLimitRequestPayloadLength");
        if meek_min_limit_request > meek_max_limit_request {
            eprintln!(
                "psiphon: MeekMinLimitRequestPayloadLength exceeds MeekMaxLimitRequestPayloadLength; using the minimum for both"
            );
        }
        let (tls_roots, disable_system_root_cas) = tls_trust_roots(settings);
        let tls_shape = TlsShape {
            min_padding: u16::try_from(
                number(settings, "TLSTunnelMinTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            max_padding: u16::try_from(
                number(settings, "TLSTunnelMaxTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            sni_names,
            transform_probability,
            hostname_patterns: string_list(settings, "CustomHostNameRegexes"),
            limit_protocols: protocol_list_named(settings, "CustomHostNameLimitProtocols"),
            profiles: tls_profiles(settings),
            custom_profiles: custom_tls_profiles(settings),
            use_only_custom_profiles: settings
                .and_then(|settings| settings.get("UseOnlyCustomTLSProfiles"))
                .and_then(Json::as_bool)
                .unwrap_or(false),
            disable_fronting_profiles: disable_fronting_profiles(settings),
            forced_profile: None,
            randomized_probability: decimal(settings, "SelectRandomizedTLSProfileProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            shadowsocks_prefix: shadowsocks_prefix(settings),
            ossh_prefix: ossh_prefix(settings),
            ossh_seed_transform: protocol_transforms(
                settings,
                "OSSHObfuscatorSeedTransformProbability",
                "OSSHObfuscatorSeedTransformSpecs",
                "OSSHObfuscatorSeedTransformScopedSpecNames",
            ),
            quic_nonce_transform: protocol_transforms(
                settings,
                "ObfuscatedQUICNonceTransformProbability",
                "ObfuscatedQUICNonceTransformSpecs",
                "ObfuscatedQUICNonceTransformScopedSpecNames",
            ),
            direct_http_transform: protocol_transforms(
                settings,
                "DirectHTTPProtocolTransformProbability",
                "DirectHTTPProtocolTransformSpecs",
                "DirectHTTPProtocolTransformScopedSpecNames",
            ),
            fronted_http_transform: protocol_transforms(
                settings,
                "FrontedHTTPProtocolTransformProbability",
                "FrontedHTTPProtocolTransformSpecs",
                "FrontedHTTPProtocolTransformScopedSpecNames",
            ),
            obfuscated_min_padding,
            obfuscated_max_padding,
            meek_alternate_cookie_name: decimal(settings, "MeekAlternateCookieNameProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            meek_alternate_content_type: decimal(settings, "MeekAlternateContentTypeProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            meek_traffic_shaping: decimal(settings, "MeekTrafficShapingProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
            meek_traffic_shaping_protocols: protocol_list_named(
                settings,
                "MeekTrafficShapingLimitProtocols",
            ),
            meek_min_limit_request,
            meek_max_limit_request,
            meek_redial_tls: decimal(settings, "MeekRedialTLSProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding: decimal(settings, "MeekPayloadPaddingProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding_omit: decimal(settings, "MeekPayloadPaddingOmitProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding_min: usize::try_from(
                number(settings, "MeekPayloadPaddingMinSize")
                    .unwrap_or(0)
                    .min(65_533),
            )
            .unwrap_or(0),
            meek_payload_padding_max: usize::try_from(
                number(settings, "MeekPayloadPaddingMaxSize")
                    .unwrap_or(65_533)
                    .min(65_533),
            )
            .unwrap_or(65_533),
            no_default_tls_session_id_probability: decimal(
                settings,
                "NoDefaultTLSSessionIDProbability",
            )
            .unwrap_or(0.5)
            .clamp(0.0, 1.0),
            obfuscated_ticket_probability: decimal(settings, "TLSTunnelObfuscatedPSKProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            roots: tls_roots,
            disable_system_root_cas,
            tls_fragment_client_hello: decimal(settings, "TLSFragmentClientHelloProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            tls_fragment_client_hello_protocols: protocol_list_named(
                settings,
                "TLSFragmentClientHelloLimitProtocols",
            ),
            user_agent_probability: decimal(settings, "PickUserAgentProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            quic_dial_early: decimal(settings, "QUICDialEarlyProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
            quic_disable_path_mtu: decimal(settings, "QUICDisablePathMTUDiscoveryProbability")
                .or_else(|| decimal(settings, "QUICDisableClientPathMTUDiscoveryProbability"))
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            quic_obfuscated_psk: decimal(settings, "QUICObfuscatedPSKProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            fragmentor: crate::psiphon_fragment::Fragmentor::new(
                decimal(settings, "FragmentorProbability").unwrap_or(0.5),
                protocol_list_named(settings, "FragmentorLimitProtocols"),
                number(settings, "FragmentorMinTotalBytes").unwrap_or(0) as usize,
                number(settings, "FragmentorMaxTotalBytes").unwrap_or(0) as usize,
                number(settings, "FragmentorMinWriteBytes").unwrap_or(1) as usize,
                number(settings, "FragmentorMaxWriteBytes").unwrap_or(1500) as usize,
                Duration::from_micros(
                    number(settings, "FragmentorMinDelayMicroseconds").unwrap_or(0),
                ),
                Duration::from_micros(
                    number(settings, "FragmentorMaxDelayMicroseconds").unwrap_or(10_000),
                ),
                flag(
                    settings,
                    "OSSHPrefixEnableFragmentor",
                    "AETHER_PSIPHON_FRAGMENT_OSSHPREFIX",
                ),
            ),
        };
        let mut cdn_ips: Vec<String> = string_list(settings, "cdnIps")
            .into_iter()
            .flat_map(|raw| expand_cidr(&raw))
            .collect();
        let mut cdn_snis = string_list(settings, "cdnSni");
        let mut cdn_scan_user = None;
        let mut fronted_overrides = Vec::new();
        if let Some(items) = settings
            .and_then(|settings| settings.get("FrontedMeekDialOverrides"))
            .and_then(Json::as_arr)
        {
            for item in items {
                let dials = string_list_in(item, "DialAddresses");
                let snis = string_list_in(item, "SNIServerName");
                if dials.is_empty() && snis.is_empty() {
                    continue;
                }
                fronted_overrides.push(FrontedOverride {
                    override_id: text_in(item, "OverrideID"),
                    dials,
                    snis,
                    disable_sni: bool_in(item, "DisableSNI"),
                    alpn: string_list_in(item, "ALPNProtocols")
                        .into_iter()
                        .map(String::into_bytes)
                        .collect(),
                    match_providers: regex_list_in(item, "MatchFrontingProviderIDRegexes"),
                    match_dials: regex_list_in(item, "MatchDialAddressRegexes"),
                    match_hosts: regex_list_in(item, "MatchHostHeaderRegexes"),
                    verify_server_names: string_list_in(item, "VerifyServerNames"),
                    verify_pins: string_list_in(item, "VerifyPins"),
                    tls_profile: text_in(item, "TLSProfile"),
                    skip_cert_verify: bool_in(item, "SkipCertVerify"),
                });
            }
        }
        if let Some(spec) = settings
            .and_then(|settings| settings.get("FrontedMeekCDNScanSpec"))
            .or_else(|| settings.and_then(|settings| settings.get("frontedMeekCDNScanSpec")))
        {
            let ips = string_list_in(spec, "IPCandidates");
            let snis = string_list_in(spec, "SNIServerNames");
            match crate::psiphon_cdn::ScanSpec::from_config(&ips, &snis) {
                Ok(scan) if scan.candidate_count() > 0 => cdn_scan_user = Some(scan),
                Ok(_) => {}
                Err(why) => eprintln!("{why}; keeping the raw candidate list"),
            }
            for ip in ips.into_iter().flat_map(|raw| expand_cidr(&raw)) {
                push_unique(&mut cdn_ips, ip);
            }
            for sni in snis {
                push_unique(&mut cdn_snis, sni);
            }
        }
        let edge_sni = cdn_snis.iter().find(|sni| !sni.is_empty()).cloned();
        let cdn_sets: Vec<String> = string_list(settings, "FrontedMeekCDNScanBuiltInSets")
            .into_iter()
            .chain(string_list(settings, "cdnSets"))
            .collect();
        let use_builtin = flag(
            settings,
            "FrontedMeekCDNScanUseBuiltInSpec",
            "AETHER_PSIPHON_CDN_BUILTIN",
        );
        let selected_sets = crate::psiphon_cdn::select(&cdn_sets);
        let builtin_scan =
            selection_cdn || use_builtin || (!cdn_sets.is_empty() && !selected_sets.is_empty());
        let mut cdn_scan_builtin = Vec::new();
        if builtin_scan {
            let sets = if selection_cdn {
                crate::psiphon_cdn::select(&[])
            } else {
                selected_sets
            };
            let room = FRONTED_VARIANTS
                .saturating_sub(cdn_ips.len())
                .min(FRONTED_VARIANTS / 2);
            for edge in crate::psiphon_cdn::sample_ips(&sets, room) {
                push_unique(&mut cdn_ips, edge);
            }
            for sni in crate::psiphon_cdn::snis(&sets) {
                push_unique(&mut cdn_snis, sni.to_owned());
            }
            cdn_scan_builtin = sets
                .iter()
                .map(|set| crate::psiphon_cdn::ScanSpec::from_builtin(set))
                .collect();
        }
        let mut cdn_scan_specs = Vec::with_capacity(cdn_scan_builtin.len() + 1);
        if let Some(scan) = &cdn_scan_user {
            cdn_scan_specs.push(scan.clone());
        }
        cdn_scan_specs.extend(cdn_scan_builtin.iter().cloned());
        let cdn_scan_state = Arc::new(Mutex::new(crate::psiphon_cdn::ScanState::new()));
        if selection_cdn {
            fronted_overrides.extend(cdn_fronting_overrides(edge_sni.as_deref()));
        } else if cdn_sets
            .iter()
            .any(|set| set.eq_ignore_ascii_case("fastly"))
        {
            fronted_overrides.push(FrontedOverride {
                dials: vec!["pypi.org".to_owned()],
                snis: vec!["pypi.org".to_owned()],
                disable_sni: false,
                alpn: vec![b"http/1.1".to_vec()],
                match_providers: Vec::new(),
                match_dials: Vec::new(),
                match_hosts: Vec::new(),
                override_id: None,
                verify_server_names: Vec::new(),
                verify_pins: Vec::new(),
                tls_profile: None,
                skip_cert_verify: false,
            });
        }
        let fronted_overrides_probability =
            decimal(settings, "FrontedMeekDialOverridesProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0);
        if fronted_overrides_probability <= 0.0 {
            fronted_overrides.clear();
        }
        if cdn_ips.len() > FRONTED_VARIANTS {
            eprintln!(
                "psiphon: {} cdn IP candidates exceed {FRONTED_VARIANTS}; dropping the rest",
                cdn_ips.len()
            );
            cdn_ips.truncate(FRONTED_VARIANTS);
        }
        if cdn_snis.len() > FRONTED_VARIANTS {
            eprintln!(
                "psiphon: {} cdn SNI candidates exceed {FRONTED_VARIANTS}; dropping the rest",
                cdn_snis.len()
            );
            cdn_snis.truncate(FRONTED_VARIANTS);
        }
        let proxy = text(settings, "upstreamProxy")
            .or_else(|| text(settings, "upstream"))
            .or_else(|| text(settings, "UpstreamProxyURL"))
            .or_else(|| text(settings, "UpstreamProxyUrl"))
            .or_else(|| env("AETHER_PSIPHON_UPSTREAM"))
            .map(|url| Proxy::parse(&url, &dns))
            .transpose()?;
        let http_listen = if flag(
            settings,
            "DisableLocalHTTPProxy",
            "AETHER_PSIPHON_DISABLE_HTTP_PROXY",
        ) {
            None
        } else {
            port_number(settings, "LocalHttpProxyPort")
                .or_else(|| port_number(settings, "shareProxyOnNetworkHttpPort"))
                .or_else(|| {
                    env("AETHER_PSIPHON_HTTP_PROXY_PORT")
                        .and_then(|value| value.parse::<u16>().ok())
                })
        };
        let packet_tunnel_fd = number(settings, "PacketTunnelTunFileDescriptor")
            .filter(|fd| *fd > 0)
            .map(|fd| {
                i32::try_from(fd).map_err(|_| {
                    format!("psiphon: PacketTunnelTunFileDescriptor {fd} does not fit an int")
                })
            })
            .transpose()?;
        let packet_tunnel_dns = if packet_tunnel_fd.is_some() {
            crate::psiphon_packet_tunnel::Dns::parse(
                text(settings, "PacketTunnelTransparentDNSIPv4Address")
                    .as_deref()
                    .unwrap_or(""),
                text(settings, "PacketTunnelTransparentDNSIPv6Address")
                    .as_deref()
                    .unwrap_or(""),
            )
            .map_err(|error| format!("psiphon: packet tunnel DNS: {error}"))?
        } else {
            crate::psiphon_packet_tunnel::Dns::default()
        };
        let target =
            text(settings, "TargetServerEntry").or_else(|| env("AETHER_PSIPHON_TARGET_ENTRY"));
        let configured_pool = number(settings, "TunnelPoolSize")
            .or_else(|| number(settings, "tunnelPoolSize"))
            .or_else(|| env("AETHER_PSIPHON_TUNNEL_POOL").and_then(|value| value.parse().ok()))
            .unwrap_or(1);
        if packet_tunnel_fd.is_some() && configured_pool != 1 {
            return Err("psiphon: packet tunnel mode requires TunnelPoolSize to be 1".to_owned());
        }
        // The reference pins a targeted entry to one tunnel, and so does this lane.
        let pool = if target.is_some() || packet_tunnel_fd.is_some() {
            1
        } else {
            configured_pool.clamp(1, 32) as usize
        };
        let disable_timeouts = flag(
            settings,
            "DisableTimeouts",
            "AETHER_PSIPHON_DISABLE_TIMEOUTS",
        );
        let latency = Latency::from_settings(settings, disable_timeouts);
        let establish = number(settings, "TunnelConnectTimeoutSeconds")
            .or_else(|| number(settings, "EstablishTunnelTimeoutSeconds"))
            .map(|seconds| Duration::from_secs(seconds.clamp(1, 600)));
        let initial_protocols = protocol_list_named(settings, "InitialLimitTunnelProtocols");
        let initial_count = number(settings, "InitialLimitTunnelProtocolsCandidateCount")
            .or_else(|| {
                env("AETHER_PSIPHON_INITIAL_PROTOCOL_COUNT").and_then(|value| value.parse().ok())
            })
            .unwrap_or(0) as usize;
        let beast = settings
            .and_then(|settings| settings.get("beastMode"))
            .and_then(Json::as_bool);
        let aggressive_setting = settings
            .and_then(|settings| settings.get("AggressiveEstablishment"))
            .and_then(Json::as_bool)
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("aggressiveEstablishment"))
                    .and_then(Json::as_bool)
            })
            .or(beast);
        // Shirokhorshid's Beast Mode defaults on for every selection mode; a plain reference config keeps it off.
        let aggressive = aggressive_setting.unwrap_or(selection.is_some())
            || env_flag("AETHER_PSIPHON_BEAST")
            || env_flag("AETHER_PSIPHON_AGGRESSIVE");
        let limit_cpu = flag(
            settings,
            "LimitCPUThreads",
            "AETHER_PSIPHON_LIMIT_CPU_THREADS",
        );
        let workers = number(settings, "ConnectionWorkerPoolSize")
            .or_else(|| env("AETHER_PSIPHON_WORKERS").and_then(|value| value.parse().ok()))
            .unwrap_or(DIAL_WORKERS as u64)
            .clamp(1, 32) as usize;
        let worker_cap = number(settings, "ConnectionWorkerPoolMaxSize")
            .unwrap_or(32)
            .clamp(1, 32) as usize;
        let workers = if target.is_some() {
            1
        } else if aggressive {
            workers.max(30).min(worker_cap)
        } else {
            workers.min(worker_cap)
        };
        let workers = if flag(
            settings,
            "DisableConnectionWorkerPool",
            "AETHER_PSIPHON_DISABLE_WORKERS",
        ) {
            1
        } else {
            workers
        };
        let workers = if limit_cpu { 1 } else { workers };
        let intensive_workers = number(settings, "LimitIntensiveConnectionWorkers")
            .unwrap_or(0)
            .min(u64::try_from(workers).unwrap_or(u64::MAX));
        let intensive_workers = if limit_cpu {
            1
        } else {
            intensive_workers as usize
        };
        let stagger = Duration::from_millis(
            number(settings, "StaggerConnectionWorkersMilliseconds")
                .or_else(|| env("AETHER_PSIPHON_STAGGER_MS").and_then(|value| value.parse().ok()))
                .unwrap_or(0)
                .min(60_000),
        );
        let pause = Duration::from_secs(
            number(settings, "EstablishTunnelPausePeriodSeconds")
                .unwrap_or(2)
                .clamp(1, 3600),
        );
        let affinity_grace = Duration::from_millis(
            number(
                settings,
                "EstablishTunnelServerAffinityGracePeriodMilliseconds",
            )
            .unwrap_or(0)
            .min(60_000),
        );
        let propagation = text(settings, "PropagationChannelId")
            .or_else(|| env("AETHER_PSIPHON_PROPAGATION"))
            .unwrap_or_else(|| PROPAGATION_CHANNEL_ID.to_owned());
        let platform = text(settings, "ClientPlatform")
            .or_else(|| env("AETHER_PSIPHON_PLATFORM"))
            .unwrap_or_else(|| "Android".to_owned());
        let client_version = text(settings, "ClientVersion")
            .or_else(|| env("AETHER_PSIPHON_CLIENT_VERSION"))
            .unwrap_or_else(|| CLIENT_VERSION.to_owned());
        let device_region = text(settings, "DeviceRegion")
            .or_else(|| text(settings, "deviceRegion"))
            .or_else(|| env("AETHER_PSIPHON_DEVICE_REGION"))
            .filter(|region| !region.is_empty());
        let device_location = text(settings, "DeviceLocation")
            .or_else(|| text(settings, "deviceLocation"))
            .or_else(|| env("AETHER_PSIPHON_DEVICE_LOCATION"))
            .filter(|location| !location.is_empty());
        let client_features = string_list(settings, "ClientFeatures");
        let split_tunnel_own_region = flag(
            settings,
            "SplitTunnelOwnRegion",
            "AETHER_PSIPHON_SPLIT_TUNNEL_OWN_REGION",
        );
        let split_tunnel_regions = split_tunnel_regions(settings);
        let explicit_compartment = text(settings, "InproxyClientPersonalCompartmentID")
            .or_else(|| text(settings, "inproxyClientPersonalCompartmentID"))
            .or_else(|| text(settings, "inproxyCompartment"))
            .or_else(|| env("AETHER_PSIPHON_COMPARTMENT"))
            .filter(|compartment| !compartment.is_empty());
        let personal_pairing =
            explicit_compartment.is_some() || conduit_mode == ConduitMode::Shirokhorshid;
        let compartment = explicit_compartment.unwrap_or_else(|| PRIVATE_COMPARTMENT_ID.to_owned());
        let limit_meek_buffers = flag(
            settings,
            "LimitMeekBufferSizes",
            "AETHER_PSIPHON_SMALL_MEEK",
        );
        let relay_buffer = if flag(
            settings,
            "LimitRelayBufferSizes",
            "AETHER_PSIPHON_SMALL_RELAY",
        ) {
            4 * 1024
        } else {
            RELAY_BUFFER
        };
        let keepalive = if flag(
            settings,
            "DisablePeriodicSshKeepAlive",
            "AETHER_PSIPHON_DISABLE_KEEPALIVE",
        ) || flag(
            settings,
            "DisableKeepAlive",
            "AETHER_PSIPHON_DISABLE_KEEPALIVE",
        ) {
            None
        } else {
            Some(keepalive(settings))
        };
        let sponsor = text(settings, "sponsorId")
            .or_else(|| text(settings, "SponsorId"))
            .or_else(|| text(settings, "SponsorID"))
            .or_else(|| env("AETHER_PSIPHON_SPONSOR_ID"))
            .unwrap_or_else(|| SPONSOR_ID.to_owned());
        let session_id = client_session_id(settings);
        let burst = crate::psiphon_burst::Config::new(
            number(settings, "ClientBurstUpstreamTargetBytes").unwrap_or(0),
            Duration::from_millis(
                number(settings, "ClientBurstUpstreamDeadlineMilliseconds").unwrap_or(0),
            ),
            number(settings, "ClientBurstDownstreamTargetBytes").unwrap_or(0),
            Duration::from_millis(
                number(settings, "ClientBurstDownstreamDeadlineMilliseconds").unwrap_or(0),
            ),
        );
        let api_encoding = match text(settings, "TargetAPIEncoding").as_deref() {
            None | Some("cbor") => ApiEncoding::Cbor,
            Some("json") => ApiEncoding::Json,
            Some(other) => {
                return Err(format!("psiphon: invalid TargetAPIEncoding {other:?}"));
            }
        };
        let remote_list_retry = Duration::from_millis(
            number(settings, "FetchRemoteServerListRetryPeriodMilliseconds")
                .unwrap_or(0)
                .min(3_600_000),
        );
        let enable_upgrade = flag(
            settings,
            "EnableUpgradeDownload",
            "AETHER_PSIPHON_ENABLE_UPGRADE",
        );
        let upgrade_roots = upgrade_roots(settings);
        let upgrade_version_header =
            text(settings, "UpgradeDownloadClientVersionHeader").unwrap_or_default();
        let upgrade_retry = Duration::from_millis(
            number(settings, "FetchUpgradeRetryPeriodMilliseconds")
                .unwrap_or(30_000)
                .max(1),
        );
        if enable_upgrade && (upgrade_roots.is_empty() || upgrade_version_header.is_empty()) {
            eprintln!(
                "psiphon: EnableUpgradeDownload needs UpgradeDownloadURLs and UpgradeDownloadClientVersionHeader; upgrade checks stay off"
            );
        }
        let enable_upgrade =
            enable_upgrade && !upgrade_roots.is_empty() && !upgrade_version_header.is_empty();
        let enable_feedback = flag(
            settings,
            "EnableFeedbackUpload",
            "AETHER_PSIPHON_ENABLE_FEEDBACK",
        );
        let feedback_roots = feedback_roots(settings);
        let feedback_key = text(settings, "FeedbackEncryptionPublicKey").unwrap_or_default();
        if enable_feedback && (feedback_roots.is_empty() || feedback_key.is_empty()) {
            return Err(
                "psiphon: EnableFeedbackUpload needs FeedbackUploadURLs and FeedbackEncryptionPublicKey"
                    .to_owned(),
            );
        }
        let feedback_attempts =
            usize::try_from(number(settings, "FeedbackUploadMaxAttempts").unwrap_or(5))
                .unwrap_or(5);
        let feedback_retry_min = Duration::from_secs(
            number(settings, "FeedbackUploadRetryMinDelaySeconds").unwrap_or(60),
        );
        let feedback_retry_max = Duration::from_secs(
            number(settings, "FeedbackUploadRetryMaxDelaySeconds")
                .unwrap_or(300)
                .max(1),
        )
        .max(feedback_retry_min);
        let exchange_key = text(settings, "ExchangeObfuscationKey").unwrap_or_default();
        let signature_key = text(settings, "ServerEntrySignaturePublicKey").unwrap_or_default();
        let disable_api = flag(settings, "DisableApi", "AETHER_PSIPHON_DISABLE_API");
        let ssh_algorithms = ssh_algorithms(settings);
        let api_protocol = match text(settings, "TargetAPIProtocol").as_deref() {
            None | Some("ssh") => crate::psiphon_ssh::ApiProtocol::Ssh,
            Some("web") => crate::psiphon_ssh::ApiProtocol::Web,
            Some(other) => {
                return Err(format!("psiphon: invalid TargetAPIProtocol {other:?}"));
            }
        };
        let light = light_settings(
            settings,
            &tls_shape,
            &sponsor,
            &platform,
            device_region.as_deref(),
            session_id.as_deref(),
        );
        Ok(Self {
            state: text(settings, "state")
                .or_else(|| text(settings, "dataRootDirectory"))
                .or_else(|| text(settings, "DataRootDirectory"))
                .or_else(|| text(settings, "dataDirectory"))
                .or_else(|| env("AETHER_PSIPHON_DIR"))
                .or_else(|| env("AETHER_PSIPHON_STATE"))
                .map_or_else(default_state, PathBuf::from),
            listen,
            http_listen,
            region,
            ready: Duration::from_secs(ready),
            entries: server_entries(settings),
            target,
            protocols,
            initial_protocols,
            fronted,
            fronted_fallback,
            cdn_ips,
            cdn_snis,
            cdn_scan_user,
            cdn_scan_builtin,
            cdn_scan_specs,
            cdn_scan_state,
            fronted_overrides,
            fronted_overrides_probability,
            initial_count,
            pool,
            latency,
            establish,
            workers,
            intensive_workers,
            stagger,
            pause,
            affinity_grace,
            propagation,
            platform,
            client_version,
            api_encoding,
            api_protocol,
            device_region,
            device_location,
            client_features,
            split_tunnel_own_region,
            split_tunnel_regions,
            compartment,
            personal_pairing,
            conduit,
            conduit_mode,
            conduit_timeout,
            conduit_protocols,
            inproxy_stun,
            inproxy_disable_stun,
            inproxy_discover_nat,
            inproxy_discover_nat_timeout,
            inproxy_dtls_randomization,
            inproxy_media_streams,
            inproxy_media_traffic_shaping,
            inproxy_media_traffic_shaping_parameters,
            inproxy_traffic_shaping,
            inproxy_traffic_shaping_parameters,
            inproxy_offer_timeout,
            inproxy_offer_personal_timeout,
            inproxy_offer_retry_delay,
            inproxy_offer_retry_jitter,
            inproxy_relay_timeout,
            inproxy_await_ready_timeout,
            inproxy_no_match_failover,
            inproxy_no_match_failover_personal,
            inproxy_prefer_probability,
            inproxy_force_selection_count,
            inproxy_rate_limit,
            inproxy_api_timeout,
            inproxy_debug,
            inproxy_disable_ipv6_ice,
            inproxy_disable_inbound_mobile,
            inproxy_incompatible_networks,
            inproxy_network_type,
            inproxy_front_timeouts,
            reject_countries,
            reject_cidrs,
            geoip_path,
            dns_servers,
            dns,
            limit_quic_versions,
            quic_noise,
            tls_shape,
            meek_padding,
            limit_meek_buffers,
            relay_buffer,
            rate: rate_limits(settings),
            holdoff: holdoff(settings),
            holdoff_direct: holdoff_class(settings, "Direct"),
            holdoff_fronting: holdoff_class(settings, "Fronting"),
            holdoff_inproxy: holdoff_class(settings, "Inproxy"),
            compress_tactics: settings
                .and_then(|settings| settings.get("CompressTactics"))
                .and_then(Json::as_bool)
                .unwrap_or(true),
            server_entry_max_move_to_front: decimal(settings, "ServerEntryIteratorMaxMoveToFront")
                .map_or(-1, |value| value as i64),
            server_entry_reset_probability: decimal(
                settings,
                "ServerEntryIteratorResetProbability",
            )
            .unwrap_or(1.0)
            .clamp(0.0, 1.0),
            dsl_retain_failed: decimal(settings, "DSLPrioritizeDialRetainFailedProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            dsl_placeholder_ttl: number(settings, "DSLPrioritizeDialPlaceholderTTLSeconds")
                .map_or(Duration::from_hours(24), Duration::from_secs),
            restrict_direct_regions: key_strings(settings, "RestrictDirectProviderRegions"),
            restrict_direct_probability: decimal(
                settings,
                "RestrictDirectProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            restrict_inproxy_regions: key_strings(settings, "RestrictInproxyProviderRegions"),
            restrict_inproxy_probability: decimal(
                settings,
                "RestrictInproxyProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            restrict_fronting_ids: string_list(settings, "RestrictFrontingProviderIDs"),
            restrict_fronting_probability: decimal(
                settings,
                "RestrictFrontingProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            liveness: liveness(settings),
            dial_ports,
            dial_ports_probability,
            prioritize_protocols,
            prioritize_count,
            prioritize_probability,
            limit_protocols_probability,
            initial_limit_probability,
            replay: replay_settings(settings),
            keepalive,
            disable_tactics: selection_tactics_disabled
                || flag(settings, "DisableTactics", "AETHER_PSIPHON_DISABLE_TACTICS"),
            meek_headers: dial_headers(settings),
            ssh_channel_window: number(settings, "SSHChannelWindowSize")
                .map_or(crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW, |window| {
                    window.clamp(64 * 1024, u64::from(u32::MAX)) as u32
                }),
            packet_tunnel_fd,
            packet_tunnel_dns,
            ssh_packet_tunnel_channel_window: crate::psiphon_ssh::packet_tunnel_channel_window(
                number(settings, "SSHPacketTunnelChannelWindowSize"),
            ),
            server_lists,
            server_lists_explicit,
            remote_fetch_disabled: flag(
                settings,
                "DisableRemoteServerListFetcher",
                "AETHER_PSIPHON_DISABLE_REMOTE_LIST",
            ),
            server_list_key: text(settings, "serverListSignaturePublicKey")
                .or_else(|| text(settings, "RemoteServerListSignaturePublicKey"))
                .or_else(|| text(settings, "remoteServerListSignaturePublicKey"))
                .or_else(|| env("AETHER_PSIPHON_SERVER_LIST_KEY"))
                .unwrap_or_else(|| ferrox_core::psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
            signature_key,
            osl_roots: osl_roots(settings),
            remote_list_key: text(settings, "RemoteServerListSignaturePublicKey")
                .or_else(|| text(settings, "remoteServerListSignaturePublicKey"))
                .or_else(|| env("AETHER_PSIPHON_REMOTE_LIST_KEY"))
                .unwrap_or_else(|| ferrox_core::psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
            remote_list_retry,
            enable_upgrade,
            upgrade_roots,
            upgrade_version_header,
            upgrade_retry,
            enable_feedback,
            feedback_roots,
            feedback_key,
            feedback_attempts,
            feedback_retry_min,
            feedback_retry_max,
            exchange_key,
            limit_cpu,
            disable_api,
            ssh_algorithms,
            emit_sloks: flag(settings, "EmitSLOKs", "AETHER_PSIPHON_EMIT_SLOKS"),
            emit_server_alerts: flag(
                settings,
                "EmitServerAlerts",
                "AETHER_PSIPHON_EMIT_SERVER_ALERTS",
            ),
            headers: custom_headers(settings),
            proxy,
            sponsor,
            session_id,
            authorizations: string_list(settings, "Authorizations"),
            proxy_user,
            proxy_pass,
            burst,
            light,
            raw,
        })
    }
}

#[derive(Clone, Copy)]
struct Latency {
    direct: f64,
    min: f64,
    max: f64,
    lambda: f64,
}

impl Latency {
    fn from_settings(settings: Option<&Json>, disable_timeouts: bool) -> Self {
        let direct = decimal(settings, "NetworkLatencyMultiplier")
            .or_else(|| env("AETHER_PSIPHON_LATENCY").and_then(|value| value.parse().ok()))
            .filter(|multiplier| *multiplier > 0.0)
            .map(|multiplier| multiplier.min(60.0));
        if let Some(direct) = direct {
            return Self {
                direct,
                min: direct,
                max: direct,
                lambda: 2.0,
            };
        }
        let min = decimal(settings, "NetworkLatencyMultiplierMin")
            .filter(|value| !value.is_nan())
            .map(|value| value.clamp(1.0, 60.0));
        let max = decimal(settings, "NetworkLatencyMultiplierMax")
            .filter(|value| !value.is_nan())
            .map(|value| value.clamp(1.0, 60.0));
        let lambda = decimal(settings, "NetworkLatencyMultiplierLambda")
            .or_else(|| env("AETHER_PSIPHON_LATENCY_LAMBDA").and_then(|value| value.parse().ok()))
            .filter(|value| !value.is_nan())
            .or_else(|| disable_timeouts.then_some(0.1))
            .map(|value| value.clamp(0.001, 1e6));
        if min.is_none() && max.is_none() && lambda.is_none() {
            return Self {
                direct: 1.0,
                min: 1.0,
                max: 1.0,
                lambda: 2.0,
            };
        }
        Self {
            direct: 0.0,
            min: min.unwrap_or(1.0),
            max: max.unwrap_or(3.0),
            lambda: lambda.unwrap_or(2.0),
        }
    }

    fn multiplier(self) -> f64 {
        if self.direct > 0.0 {
            return self.direct;
        }
        if self.max <= self.min || self.lambda <= 0.0 {
            return self.min;
        }
        let span = self.max - self.min;
        for _ in 0..16 {
            let mut bytes = [0u8; 4];
            let _ = getrandom::fill(&mut bytes);
            let uniform = f64::from(u32::from_le_bytes(bytes)) / 4_294_967_296.0;
            let value = self.min - (1.0 - uniform).ln() / self.lambda * span;
            if value <= self.max {
                return value;
            }
        }
        self.max
    }
}

impl Settings {
    /// The reference scales every network budget by `NetworkLatencyMultiplier`.
    fn dial_timeout(&self) -> Duration {
        self.establish
            .unwrap_or(DIAL_TIMEOUT)
            .mul_f64(self.latency.multiplier())
            .min(Duration::from_secs(600))
    }

    /// The longest provider-scoped hold-off that names this tunnel's class.
    fn holdoff_for(
        &self,
        protocol: &str,
        provider: Option<&str>,
        region: Option<&str>,
        fronting: Option<&str>,
    ) -> Duration {
        if protocol.starts_with("FRONTED-MEEK") {
            self.holdoff_fronting.delay(fronting, region)
        } else if protocol.starts_with("INPROXY-") {
            self.holdoff_inproxy.delay(provider, region)
        } else {
            self.holdoff_direct.delay(provider, region)
        }
    }

    /// A hash of the fields that change a dial's selected parameters.
    fn config_state(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.protocols.hash(&mut hasher);
        self.initial_protocols.hash(&mut hasher);
        self.fronted.hash(&mut hasher);
        self.fronted_fallback.hash(&mut hasher);
        self.cdn_ips.hash(&mut hasher);
        self.cdn_snis.hash(&mut hasher);
        for scan in &self.cdn_scan_specs {
            scan.cache_key().hash(&mut hasher);
        }
        format!("{:?}", self.fronted_overrides).hash(&mut hasher);
        self.fronted_overrides_probability
            .to_bits()
            .hash(&mut hasher);
        self.region.hash(&mut hasher);
        self.compartment.hash(&mut hasher);
        self.personal_pairing.hash(&mut hasher);
        self.conduit.hash(&mut hasher);
        self.conduit_protocols.hash(&mut hasher);
        self.inproxy_prefer_probability.to_bits().hash(&mut hasher);
        self.inproxy_force_selection_count.hash(&mut hasher);
        self.inproxy_rate_limit.hash(&mut hasher);
        self.inproxy_api_timeout.hash(&mut hasher);
        self.inproxy_debug.hash(&mut hasher);
        self.inproxy_discover_nat.to_bits().hash(&mut hasher);
        self.inproxy_discover_nat_timeout.hash(&mut hasher);
        self.inproxy_dtls_randomization.to_bits().hash(&mut hasher);
        self.inproxy_media_streams.to_bits().hash(&mut hasher);
        self.inproxy_media_traffic_shaping
            .to_bits()
            .hash(&mut hasher);
        format!("{:?}", self.inproxy_media_traffic_shaping_parameters).hash(&mut hasher);
        self.inproxy_traffic_shaping.to_bits().hash(&mut hasher);
        format!("{:?}", self.inproxy_traffic_shaping_parameters).hash(&mut hasher);
        self.inproxy_disable_ipv6_ice.hash(&mut hasher);
        self.inproxy_disable_inbound_mobile.hash(&mut hasher);
        self.inproxy_incompatible_networks.hash(&mut hasher);
        self.inproxy_network_type.hash(&mut hasher);
        self.inproxy_front_timeouts.hash(&mut hasher);
        for key in [
            "InproxyBrokerSpecs",
            "InproxyClientBrokerSpecs",
            "InproxyPersonalPairingBrokerSpecs",
            "InproxyClientPersonalPairingBrokerSpecs",
            "InproxyPersonalPairingMaxBrokerSpecCount",
            "InproxyCommonCompartmentIDs",
        ] {
            format!("{:?}", self.raw.as_ref().and_then(|raw| raw.get(key))).hash(&mut hasher);
        }
        self.limit_quic_versions.hash(&mut hasher);
        self.quic_noise.hash(&mut hasher);
        self.meek_headers.hash(&mut hasher);
        self.headers.hash(&mut hasher);
        self.authorizations.hash(&mut hasher);
        self.proxy_user.hash(&mut hasher);
        self.proxy_pass.hash(&mut hasher);
        self.device_region.hash(&mut hasher);
        self.client_features.hash(&mut hasher);
        self.prioritize_protocols.hash(&mut hasher);
        self.prioritize_count.hash(&mut hasher);
        self.restrict_direct_regions.hash(&mut hasher);
        self.restrict_inproxy_regions.hash(&mut hasher);
        self.restrict_fronting_ids.hash(&mut hasher);
        format!("{:?}", self.tls_shape).hash(&mut hasher);
        format!("{:?}", self.proxy).hash(&mut hasher);
        format!("{:?}", self.light).hash(&mut hasher);
        format!("{:?}", self.dial_ports).hash(&mut hasher);
        self.dial_ports_probability.to_bits().hash(&mut hasher);
        self.limit_protocols_probability.to_bits().hash(&mut hasher);
        self.initial_limit_probability.to_bits().hash(&mut hasher);
        self.prioritize_probability.to_bits().hash(&mut hasher);
        self.restrict_direct_probability.to_bits().hash(&mut hasher);
        self.restrict_inproxy_probability
            .to_bits()
            .hash(&mut hasher);
        self.restrict_fronting_probability
            .to_bits()
            .hash(&mut hasher);
        hasher.finish()
    }

    /// The reference skips in-proxy dial parameters on a client-disallowed network.
    fn inproxy_incompatible(&self) -> bool {
        self.inproxy_incompatible_networks
            .iter()
            .any(|network| network == &self.inproxy_network_type)
    }

    /// Whether a client restriction skips this candidate; the reference coins per candidate.
    fn restricted(&self, server: &Server, conduit: bool) -> bool {
        if conduit && server.inproxy.is_some() {
            return coin(self.restrict_inproxy_probability)
                && region_restricted(
                    &self.restrict_inproxy_regions,
                    server.provider_id.as_deref(),
                    server.region.as_deref(),
                );
        }
        if server.meek.is_some() {
            return coin(self.restrict_fronting_probability)
                && server
                    .fronting_provider_id
                    .as_deref()
                    .is_some_and(|id| self.restrict_fronting_ids.iter().any(|known| known == id));
        }
        coin(self.restrict_direct_probability)
            && region_restricted(
                &self.restrict_direct_regions,
                server.provider_id.as_deref(),
                server.region.as_deref(),
            )
    }
}

/// Read the named DNS protocol transforms from settings.
fn protocol_transform_specs(
    raw: Option<&Json>,
    field: &str,
) -> Vec<(String, Vec<(String, String)>)> {
    let Some(Json::Obj(specs)) = raw.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    specs
        .iter()
        .filter_map(|(name, value)| {
            let Json::Arr(transforms) = value else {
                return None;
            };
            let pairs: Vec<(String, String)> = transforms
                .iter()
                .filter_map(|transform| {
                    let Json::Arr(parts) = transform else {
                        return None;
                    };
                    if parts.len() != 2 {
                        return None;
                    }
                    Some((parts[0].as_str()?.to_owned(), parts[1].as_str()?.to_owned()))
                })
                .collect();
            (!pairs.is_empty()).then(|| (name.clone(), pairs))
        })
        .collect()
}

/// Read a transform scope-to-spec-name mapping from settings.
fn protocol_transform_scopes(raw: Option<&Json>, field: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(scopes)) = raw.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    scopes
        .iter()
        .map(|(scope, value)| {
            let names = match value {
                Json::Arr(items) => items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            };
            (scope.clone(), names)
        })
        .collect()
}

/// One transform family: its probability, compiled specs and scope map.
fn protocol_transforms(
    settings: Option<&Json>,
    probability: &str,
    specs: &str,
    scopes: &str,
) -> crate::psiphon_dns::ProtocolTransforms {
    crate::psiphon_dns::ProtocolTransforms {
        probability: decimal(settings, probability)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        transforms: std::sync::Arc::new(crate::psiphon_dns::Transforms::new(
            protocol_transform_specs(settings, specs),
            protocol_transform_scopes(settings, scopes),
        )),
    }
}

/// Build the DNS fallback config from the reference's `DNSResolver*` fields.
fn dns_config(raw: Option<&Json>, dns_servers: &[SocketAddr]) -> crate::psiphon_dns::Config {
    let list = |key: &str| -> Vec<String> { string_list(raw, key) };
    let clock = |key: &str, default: u64| {
        Duration::from_millis(number(raw, key).unwrap_or(default).clamp(1, 600_000))
    };
    let mut config = crate::psiphon_dns::Config::from_servers(dns_servers);
    config.preferred = list("DNSResolverPreferredAlternateServers")
        .iter()
        .filter_map(|server| dns_server(server))
        .collect();
    config.attempts_per_server = usize::try_from(
        number(raw, "DNSResolverAttemptsPerServer")
            .unwrap_or(2)
            .clamp(1, 16),
    )
    .unwrap_or(1);
    config.attempts_per_preferred = usize::try_from(
        number(raw, "DNSResolverAttemptsPerPreferredServer")
            .unwrap_or(1)
            .clamp(1, 16),
    )
    .unwrap_or(1);
    config.request_timeout = clock("DNSResolverRequestTimeoutMilliseconds", 5_000);
    config.await_timeout = clock("DNSResolverAwaitTimeoutMilliseconds", 10);
    config.prefer_alternate_probability =
        decimal(raw, "DNSResolverPreferAlternateServerProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
    config.edns0_probability = decimal(raw, "DNSResolverIncludeEDNS0Probability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.qname_casing_probability = decimal(raw, "DNSResolverQNameRandomizeCasingProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.cache_extension = Duration::from_millis(
        number(raw, "DNSResolverCacheExtensionInitialTTLMilliseconds").unwrap_or(0),
    );
    config.cache_extension_verified = Duration::from_millis(
        number(raw, "DNSResolverCacheExtensionVerifiedTTLMilliseconds").unwrap_or(0),
    );
    config.transform_probability = decimal(raw, "DNSResolverProtocolTransformProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.qname_must_match_probability = decimal(raw, "DNSResolverQNameMustMatchProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.transforms = Arc::new(crate::psiphon_dns::Transforms::new(
        protocol_transform_specs(raw, "DNSResolverProtocolTransformSpecs"),
        protocol_transform_scopes(raw, "DNSResolverProtocolTransformScopedSpecNames"),
    ));
    config.preresolved_labels = if let Some(Json::Obj(labels)) =
        raw.and_then(|settings| settings.get("DNSResolverPreresolvedIPAddressCIDRs"))
    {
        labels
            .iter()
            .filter_map(|(label, value)| {
                let texts: Vec<String> = match value {
                    Json::Arr(items) => items
                        .iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect(),
                    Json::Str(text) => vec![text.clone()],
                    _ => return None,
                };
                let networks = crate::psiphon_dns::Config::cidrs(&texts);
                (!networks.is_empty()).then(|| (label.to_ascii_lowercase(), networks))
            })
            .collect()
    } else {
        let networks =
            crate::psiphon_dns::Config::cidrs(&list("DNSResolverPreresolvedIPAddressCIDRs"));
        if networks.is_empty() {
            HashMap::new()
        } else {
            HashMap::from([(String::new(), networks)])
        }
    };
    config.preresolved_probability = decimal(raw, "DNSResolverPreresolvedIPAddressProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.steering_ttl =
        Duration::from_secs(number(raw, "SteeringIPCacheTTLSeconds").unwrap_or(3600));
    config.steering_probability = decimal(raw, "SteeringIPProbability")
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);
    config.steering_max =
        usize::try_from(number(raw, "SteeringIPCacheMaxEntries").unwrap_or(65_536))
            .unwrap_or(65_536);
    config
}

/// The reference's `RateLimits`: a shared token bucket for both directions.
fn rate_limits(settings: Option<&Json>) -> Option<crate::psiphon_rate::Rate> {
    let limits = settings.and_then(|settings| settings.get("RateLimits"))?;
    let amount = |key: &str| {
        limits
            .get(key)
            .and_then(Json::as_u32)
            .map(u64::from)
            .or_else(|| {
                limits
                    .get(key)
                    .and_then(Json::as_i64)
                    .and_then(|value| u64::try_from(value).ok())
            })
            .unwrap_or(0)
    };
    let close = matches!(limits.get("CloseAfterExhausted"), Some(Json::Bool(true)));
    let rate = crate::psiphon_rate::Rate::new(
        amount("ReadBytesPerSecond"),
        amount("ReadUnthrottledBytes"),
        amount("WriteBytesPerSecond"),
        amount("WriteUnthrottledBytes"),
        close,
    );
    rate.active().then_some(rate)
}

/// The reference's tactics timing: how long establishment waits, how it retries, and one dial's deadline.
#[derive(Clone, Copy, Debug, Default)]
struct TacticsTiming {
    wait: Duration,
    retry: Duration,
    jitter: f64,
    timeout: Option<Duration>,
}

/// The reference tactics timing: establishment wait, retry period, jitter, and one dial's deadline.
fn tactics_timing(settings: Option<&Json>) -> TacticsTiming {
    let millis = |key: &str, minimum: u64| {
        number(settings, key)
            .filter(|millis| *millis >= minimum)
            .map(|millis| Duration::from_millis(millis.min(3_600_000)))
    };
    TacticsTiming {
        wait: millis("TacticsWaitPeriodMilliseconds", 0).unwrap_or(Duration::ZERO),
        retry: millis("TacticsRetryPeriodMilliseconds", 1).unwrap_or(Duration::from_secs(2)),
        jitter: decimal(settings, "TacticsRetryPeriodJitter")
            .unwrap_or(0.3)
            .clamp(0.0, 1.0),
        timeout: number(settings, "TacticsTimeoutMilliseconds").and_then(|millis| {
            if millis < 1_000 {
                eprintln!(
                    "psiphon: TacticsTimeoutMilliseconds {millis} is below the 1000 ms floor; using the default"
                );
                None
            } else {
                Some(Duration::from_millis(millis.min(3_600_000)))
            }
        }),
    }
}

/// The reference protocol hold-off, empty when no protocol is named.
fn holdoff(settings: Option<&Json>) -> HoldOff {
    let names = string_list(settings, "HoldOffTunnelProtocolNames");
    if names.is_empty() {
        return HoldOff::default();
    }
    let clock = |key: &str| Duration::from_millis(number(settings, key).unwrap_or(0));
    let min = clock("HoldOffTunnelProtocolMinDurationMilliseconds").min(HOLD_OFF_LIMIT);
    let max = clock("HoldOffTunnelProtocolMaxDurationMilliseconds")
        .min(HOLD_OFF_LIMIT)
        .max(min);
    HoldOff {
        names,
        probability: decimal(settings, "HoldOffTunnelProtocolProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        min,
        max,
    }
}

/// One provider-scoped hold-off class from `HoldOff{Direct,Fronting,Inproxy}Tunnel*`.
fn holdoff_class(settings: Option<&Json>, kind: &str) -> HoldOffClass {
    let clock = |suffix: &str| {
        Duration::from_millis(
            number(settings, &format!("HoldOff{kind}Tunnel{suffix}")).unwrap_or(0),
        )
        .min(HOLD_OFF_LIMIT)
    };
    let min = clock("MinDurationMilliseconds");
    let max = clock("MaxDurationMilliseconds").max(min);
    let region_scoped = kind != "Fronting";
    let providers = if region_scoped {
        key_strings(settings, &format!("HoldOff{kind}TunnelProviderRegions"))
    } else {
        string_list(settings, "HoldOffFrontingTunnelProviderIDs")
            .into_iter()
            .map(|id| (id, Vec::new()))
            .collect()
    };
    HoldOffClass {
        providers,
        region_scoped,
        probability: decimal(settings, &format!("HoldOff{kind}TunnelProbability"))
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        min,
        max,
    }
}

/// A JSON object of provider ID to region list, as the reference's `KeyStrings` fields carry.
fn key_strings(settings: Option<&Json>, key: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(pairs)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    pairs
        .iter()
        .map(|(provider, value)| {
            let regions = match value {
                Json::Arr(items) => items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect(),
                Json::Str(region) => vec![region.clone()],
                _ => Vec::new(),
            };
            (provider.clone(), regions)
        })
        .collect()
}

/// Whether a provider/region map names this provider with `""` or the entry's own region.
fn region_restricted(
    map: &[(String, Vec<String>)],
    provider: Option<&str>,
    region: Option<&str>,
) -> bool {
    let Some(provider) = provider else {
        return false;
    };
    map.iter().any(|(id, regions)| {
        id == provider
            && regions
                .iter()
                .any(|allowed| allowed.is_empty() || Some(allowed.as_str()) == region)
    })
}

/// The reference initial and periodic liveness probes.
fn liveness(settings: Option<&Json>) -> Liveness {
    let flat = LivenessSpec {
        pattern: String::new(),
        min_upstream: usize::try_from(
            number(settings, "LivenessTestMinUpstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        max_upstream: usize::try_from(
            number(settings, "LivenessTestMaxUpstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        min_downstream: usize::try_from(
            number(settings, "LivenessTestMinDownstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        max_downstream: usize::try_from(
            number(settings, "LivenessTestMaxDownstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
    };
    let active = flat.max_upstream > 0 || flat.max_downstream > 0;
    let mut initial = liveness_specs(settings, "InitialLivenessTest");
    let mut periodic = liveness_specs(settings, "LivenessTest");
    if active {
        if initial.is_empty() {
            initial.push(flat.clone());
        }
        if periodic.is_empty() {
            periodic.push(flat);
        }
    }
    Liveness { initial, periodic }
}

/// Read one probe list, keeping only entries with a usable pattern.
fn liveness_specs(settings: Option<&Json>, key: &str) -> Vec<LivenessSpec> {
    let Some(Json::Obj(probes)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    probes
        .iter()
        .map(|(pattern, probe)| {
            let amount = |field: &str| {
                usize::try_from(probe.get(field).and_then(Json::as_u32).unwrap_or(0)).unwrap_or(0)
            };
            LivenessSpec {
                pattern: pattern.clone(),
                min_upstream: amount("MinUpstreamBytes"),
                max_upstream: amount("MaxUpstreamBytes"),
                min_downstream: amount("MinDownstreamBytes"),
                max_downstream: amount("MaxDownstreamBytes"),
            }
        })
        .collect()
}

fn port_number(settings: Option<&Json>, key: &str) -> Option<u16> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_port()
        .or_else(|| value.as_u32().and_then(|port| u16::try_from(port).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        .filter(|port| *port > 0)
}

fn number(settings: Option<&Json>, key: &str) -> Option<u64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_u32()
        .map(u64::from)
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

/// Read an integer field from settings.
fn integer(settings: Option<&Json>, key: &str) -> Option<i64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

fn decimal(settings: Option<&Json>, key: &str) -> Option<f64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    match value {
        Json::Num(number) => Some(*number),
        Json::Str(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// A probability field, clamped to the reference's `[0, 1]`; absent means its default coin lands.
fn probability(settings: Option<&Json>, key: &str) -> f64 {
    decimal(settings, key).unwrap_or(1.0).clamp(0.0, 1.0)
}

/// One weighted coin, with the reference's inclusive endpoints.
fn coin(probability: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 {
        return false;
    }
    f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0 < probability
}

/// The reference's periodic keep-alive window, clamped so a hostile config cannot stall a session.
fn keepalive(settings: Option<&Json>) -> KeepAlive {
    let millis = |key, default: u64| {
        Duration::from_millis(
            number(settings, key)
                .unwrap_or(default)
                .clamp(1_000, 300_000),
        )
    };
    let period_min = millis("SSHKeepAlivePeriodMinMilliseconds", 60_000);
    let period_max = millis("SSHKeepAlivePeriodMaxMilliseconds", 120_000).max(period_min);
    let padding = |key, default: u64| {
        usize::try_from(number(settings, key).unwrap_or(default).min(8_192)).unwrap_or(8_192)
    };
    let padding_min = padding("SSHKeepAlivePaddingMinBytes", 0);
    let padding_max = padding("SSHKeepAlivePaddingMaxBytes", 256).max(padding_min);
    KeepAlive {
        period_min,
        period_max,
        padding_min,
        padding_max,
        inactive: millis("SSHKeepAlivePeriodicInactivePeriodMilliseconds", 10_000),
        timeout: millis("SSHKeepAlivePeriodicTimeoutMilliseconds", 30_000),
    }
}

/// The reference's `Replay*` settings, with its defaults and clamps.
fn replay_settings(settings: Option<&Json>) -> crate::psiphon_replay::Settings {
    let seconds = |key, default| Duration::from_secs(number(settings, key).unwrap_or(default));
    let probability = |key, default| decimal(settings, key).unwrap_or(default).clamp(0.0, 1.0);
    crate::psiphon_replay::Settings {
        disable: flag(settings, "DisableReplay", "AETHER_PSIPHON_DISABLE_REPLAY"),
        candidate_count: integer(settings, "ReplayCandidateCount").unwrap_or(10),
        ttl: seconds("ReplayDialParametersTTLSeconds", 86_400),
        target_upstream: number(settings, "ReplayTargetUpstreamBytes").unwrap_or(0),
        target_downstream: number(settings, "ReplayTargetDownstreamBytes").unwrap_or(0),
        target_duration: seconds("ReplayTargetTunnelDurationSeconds", 1),
        later_round_move_to_front: probability("ReplayLaterRoundMoveToFrontProbability", 0.0),
        retain_failed: probability("ReplayRetainFailedProbability", 0.5),
        ignore_changed_config_state: probability("ReplayIgnoreChangedConfigStateProbability", 0.0),
        fronted_ttl: seconds("FrontedHTTPClientReplayDialParametersTTLSeconds", 86_400),
        fronted_update_frequency: seconds("FrontedHTTPClientReplayUpdateFrequencySeconds", 300),
        fronted_probability: probability("FrontedHTTPClientReplayDialParametersProbability", 1.0),
        fronted_retain_failed: probability("FrontedHTTPClientReplayRetainFailedProbability", 0.5),
        inproxy_broker_ttl: seconds("InproxyReplayBrokerDialParametersTTLSeconds", 86_400),
        inproxy_broker_update_frequency: seconds("InproxyReplayBrokerUpdateFrequencySeconds", 300),
        inproxy_broker_probability: probability(
            "InproxyReplayBrokerDialParametersProbability",
            1.0,
        ),
        inproxy_broker_retain_failed: probability(
            "InproxyReplayBrokerRetainFailedProbability",
            0.5,
        ),
        inproxy_retain_failed: probability("InproxyReplayRetainFailedProbability", 1.0),
    }
}

/// The reference's `LimitTunnelDialPortNumbers`: protocol names (or `All`) to port ranges.
fn port_lists(settings: Option<&Json>) -> Vec<(String, PortList)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| {
        settings
            .get("LimitTunnelDialPortNumbers")
            .or_else(|| settings.get("limitTunnelDialPortNumbers"))
    }) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|(name, value)| {
            let ranges = port_ranges(value)?;
            Some((name.to_ascii_uppercase(), PortList { ranges }))
        })
        .collect()
}

/// A `PortList` value: scalars, closed ranges, or a mix of both, exactly as the reference unmarshals.
fn port_ranges(value: &Json) -> Option<Vec<(u16, u16)>> {
    if let Some(port) = value.as_port() {
        return Some(vec![(port, port)]);
    }
    if let Some(text) = value.as_str() {
        let (low, high) = text.split_once('-').unwrap_or((text, text));
        let low = low.trim().parse::<u16>().ok()?;
        let high = high.trim().parse::<u16>().ok()?;
        return Some(vec![(low.min(high), low.max(high))]);
    }
    let items = value.as_arr()?;
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Json::Arr(pair) => {
                let low = pair.first()?.as_port()?;
                let high = pair.get(1)?.as_port()?;
                ranges.push((low.min(high), low.max(high)));
            }
            Json::Num(_) => {
                let port = item.as_port()?;
                ranges.push((port, port));
            }
            Json::Str(text) => {
                let (low, high) = text
                    .split_once('-')
                    .unwrap_or((text.as_str(), text.as_str()));
                let low = low.trim().parse::<u16>().ok()?;
                let high = high.trim().parse::<u16>().ok()?;
                ranges.push((low.min(high), low.max(high)));
            }
            _ => return None,
        }
    }
    Some(ranges)
}

/// The `ShadowsocksPrefixSpecs` transform, its scope map and its probability.
fn shadowsocks_prefix(settings: Option<&Json>) -> crate::psiphon_ssh::ShadowsocksPrefix {
    crate::psiphon_ssh::ShadowsocksPrefix {
        probability: decimal(settings, "ShadowsocksPrefixProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        specs: transform_specs(settings, "ShadowsocksPrefixSpecs"),
        scoped: transform_scopes(settings, "ShadowsocksPrefixScopedSpecNames"),
    }
}

/// The `OSSHPrefixSpecs` transform, its scope map, probability and split window.
fn ossh_prefix(settings: Option<&Json>) -> crate::psiphon_ssh::OsshPrefix {
    crate::psiphon_ssh::OsshPrefix {
        probability: decimal(settings, "OSSHPrefixProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        specs: transform_specs(settings, "OSSHPrefixSpecs"),
        scoped: transform_scopes(settings, "OSSHPrefixScopedSpecNames"),
        split_min: Duration::from_nanos(duration_nanos(
            settings,
            "OSSHPrefixSplitMinDelayMilliseconds",
            "OSSHPrefixSplitMinDelay",
        )),
        split_max: Duration::from_nanos(duration_nanos(
            settings,
            "OSSHPrefixSplitMaxDelayMilliseconds",
            "OSSHPrefixSplitMaxDelay",
        )),
    }
}

/// One obfuscated-SSH padding bound: the reference only accepts a value in
/// `[prng.SEED_LENGTH, OBFUSCATE_MAX_PADDING]`; anything else leaves the default.
fn ssh_padding(settings: Option<&Json>, key: &str, default: usize, floor: usize) -> usize {
    number(settings, key)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (MIN_PADDING..=MAX_PADDING).contains(value) && *value >= floor)
        .unwrap_or(default)
}

/// A duration in nanoseconds: the `...Milliseconds` spelling is milliseconds, while the
/// reference's `time.Duration` spelling is already nanoseconds.
fn duration_nanos(settings: Option<&Json>, millis: &str, duration: &str) -> u64 {
    if let Some(value) = number(settings, millis) {
        return value.saturating_mul(1_000_000).min(60_000_000_000);
    }
    number(settings, duration).map_or(0, |nanos| nanos.min(60_000_000_000))
}

/// The named byte generators of one prefix transform.
fn transform_specs(settings: Option<&Json>, field: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|(name, spec)| {
            let generator = spec
                .as_arr()
                .and_then(|transforms| transforms.first())
                .and_then(Json::as_arr)
                .and_then(|transform| transform.get(1))
                .and_then(Json::as_str)?;
            Some((name.clone(), generator.to_owned()))
        })
        .collect()
}

/// The scope map of one prefix transform.
fn transform_scopes(settings: Option<&Json>, field: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(scopes)) = settings.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    scopes
        .iter()
        .map(|(scope, names)| {
            (
                scope.clone(),
                names
                    .as_arr()
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Json::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// The anchors a verified Psiphon TLS dial uses, and whether the reference skips verification.
/// A named file is read at dial time so a config with no verified dial keeps working without it.
fn tls_trust_roots(settings: Option<&Json>) -> (crate::psiphon_ssh::TlsRoots, bool) {
    let disabled = flag(
        settings,
        "DisableSystemRootCAs",
        "AETHER_PSIPHON_DISABLE_SYSTEM_ROOT_CAS",
    );
    if disabled {
        return (crate::psiphon_ssh::TlsRoots::Empty, true);
    }
    if let Some(path) = text(settings, "TrustedCACertificatesFilename") {
        return (crate::psiphon_ssh::TlsRoots::File(path), false);
    }
    (crate::psiphon_ssh::TlsRoots::System, false)
}

/// The configured `LimitTLSProfiles` parrots, or the scalar `TLSProfile` when one is named.
fn tls_profiles(settings: Option<&Json>) -> Vec<Fingerprint> {
    let names = if settings
        .and_then(|settings| settings.get("LimitTLSProfiles"))
        .is_some()
    {
        string_list(settings, "LimitTLSProfiles")
    } else {
        text(settings, "TLSProfile").into_iter().collect()
    };
    names
        .iter()
        .filter_map(|name| Fingerprint::resolve(name))
        .collect()
}

/// `CustomTLSProfiles`: an array of named uTLS specs, each accepted profile immutable for the process.
fn custom_tls_profiles(settings: Option<&Json>) -> Vec<Fingerprint> {
    let Some(items) = settings
        .and_then(|settings| settings.get("CustomTLSProfiles"))
        .and_then(Json::as_arr)
    else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut profiles = Vec::new();
    for item in items {
        let Some(name) = text_in(item, "Name") else {
            eprintln!("psiphon: CustomTLSProfiles entry missing Name; ignoring it");
            continue;
        };
        if Fingerprint::resolve(&name).is_some() || !seen.insert(name.clone()) {
            eprintln!("psiphon: invalid or duplicate CustomTLSProfiles name {name:?}; ignoring it");
            continue;
        }
        let Some(spec) = item.get("UTLSSpec") else {
            eprintln!("psiphon: CustomTLSProfiles entry {name:?} missing UTLSSpec; ignoring it");
            continue;
        };
        let ciphers = u16_list(spec.get("CipherSuites"));
        if ciphers.is_empty() {
            eprintln!(
                "psiphon: CustomTLSProfiles entry {name:?} has no cipher suites; ignoring it"
            );
            continue;
        }
        let mut extensions = Vec::new();
        let mut valid = true;
        if let Some(items) = spec.get("Extensions").and_then(Json::as_arr) {
            for item in items {
                if let Some(extension) = custom_extension(item) {
                    extensions.push(extension);
                } else {
                    eprintln!(
                        "psiphon: CustomTLSProfiles entry {name:?} has an unknown extension; ignoring the profile"
                    );
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            continue;
        }
        let name: &'static str = Box::leak(name.into_boxed_str());
        let ciphers: &'static [u16] = Box::leak(ciphers.into_boxed_slice());
        let extensions: Vec<Ext> = extensions
            .into_iter()
            .map(|extension| Ext {
                kind: extension.kind,
                body: extension.body.leak(),
            })
            .collect();
        let extensions: &'static [Ext] = Box::leak(extensions.into_boxed_slice());
        let profile: &'static Profile = Box::leak(Box::new(Profile {
            name,
            ciphers,
            shuffle: false,
            exts: extensions,
        }));
        profiles.push(Fingerprint::custom(profile));
    }
    profiles
}

#[derive(Debug)]
struct CustomExtension {
    kind: u16,
    body: CustomBody,
}

#[derive(Debug)]
enum CustomBody {
    Grease,
    Sni,
    Pad,
    Groups(Vec<u16>),
    Sigalgs(Vec<u16>),
    Alpn(Vec<u8>),
    Versions(Vec<u16>),
    KeyShare(Vec<u16>),
    Raw(Vec<u8>),
}

impl CustomBody {
    fn leak(self) -> Body {
        match self {
            Self::Grease => Body::Grease,
            Self::Sni => Body::Sni,
            Self::Pad => Body::Pad,
            Self::Groups(groups) => Body::Groups(Box::leak(groups.into_boxed_slice())),
            Self::Sigalgs(sigalgs) => Body::Sigalgs(Box::leak(sigalgs.into_boxed_slice())),
            Self::Alpn(alpn) => Body::Alpn(Box::leak(alpn.into_boxed_slice())),
            Self::Versions(versions) => Body::Versions(Box::leak(versions.into_boxed_slice())),
            Self::KeyShare(groups) => Body::KeyShare {
                groups: Box::leak(groups.into_boxed_slice()),
                reuse: false,
            },
            Self::Raw(bytes) => Body::Raw(Box::leak(bytes.into_boxed_slice())),
        }
    }
}

fn custom_extension(item: &Json) -> Option<CustomExtension> {
    let name = item.get("Name")?.as_str()?;
    let data = item.get("Data");
    let (kind, body) = match name {
        "NPN" => (0x3374, CustomBody::Raw(Vec::new())),
        "SNI" => (0x0000, CustomBody::Sni),
        "StatusRequest" => (0x0005, CustomBody::Raw(vec![1, 0, 0, 0, 0])),
        "SupportedCurves" => (0x000a, CustomBody::Groups(u16_list(data?.get("Curves")))),
        "SupportedPoints" => {
            let points = u8_list(data?.get("SupportedPoints"));
            let mut body = Vec::with_capacity(1 + points.len());
            body.push(u8::try_from(points.len()).ok()?);
            body.extend_from_slice(&points);
            (0x000b, CustomBody::Raw(body))
        }
        "SignatureAlgorithms" => (
            0x000d,
            CustomBody::Sigalgs(u16_list(data?.get("SupportedSignatureAlgorithms"))),
        ),
        "RenegotiationInfo" => (0xff01, CustomBody::Raw(vec![0])),
        "ALPN" => (0x0010, CustomBody::Alpn(alpn_body(data?, "AlpnProtocols"))),
        "SCT" => (0x0012, CustomBody::Raw(Vec::new())),
        "SessionTicket" => (0x0023, CustomBody::Raw(Vec::new())),
        "Generic" => (
            u16::try_from(data?.get("Id")?.as_u32()?).ok()?,
            CustomBody::Raw(u8_list(data?.get("Data"))),
        ),
        "ExtendedMasterSecret" => (0x0017, CustomBody::Raw(Vec::new())),
        "GREASE" => (0x0a0a, CustomBody::Grease),
        "BoringPadding" => (0x0015, CustomBody::Pad),
        "KeyShare" => {
            let groups = data?
                .get("KeyShares")?
                .as_arr()?
                .iter()
                .filter_map(|share| share.get("Group").and_then(Json::as_u32))
                .filter_map(|group| u16::try_from(group).ok())
                .collect();
            (0x0033, CustomBody::KeyShare(groups))
        }
        "PSKKeyExchangeModes" => {
            let modes = u8_list(data?.get("Modes"));
            let mut body = Vec::with_capacity(1 + modes.len());
            body.push(u8::try_from(modes.len()).ok()?);
            body.extend_from_slice(&modes);
            (0x002d, CustomBody::Raw(body))
        }
        "SupportedVersions" => (
            0x002b,
            CustomBody::Versions(u16_list(data?.get("Versions"))),
        ),
        "ChannelID" => (
            if data
                .and_then(|data| data.get("OldExtensionID"))
                .and_then(Json::as_bool)
                .unwrap_or(false)
            {
                0x754f
            } else {
                0x7550
            },
            CustomBody::Raw(Vec::new()),
        ),
        "CertCompressionAlgs" => {
            let algorithms = u16_list(data?.get("Algorithms"));
            let mut body = Vec::with_capacity(1 + 2 * algorithms.len());
            body.push(u8::try_from(2 * algorithms.len()).ok()?);
            for algorithm in algorithms {
                body.extend_from_slice(&algorithm.to_be_bytes());
            }
            (0x001b, CustomBody::Raw(body))
        }
        "RecordSizeLimit" => {
            let limit = u16::try_from(data?.get("Limit")?.as_u32()?).ok()?;
            (0x001c, CustomBody::Raw(limit.to_be_bytes().to_vec()))
        }
        "ALPS" => (
            0x4469,
            CustomBody::Alpn(alpn_body_either(
                data?,
                "supported_protocols",
                "SupportedProtocols",
            )),
        ),
        "DelegatedCredentials" => {
            let algorithms = u16_list_either(
                data?,
                "supported_signature_algorithms",
                "SupportedSignatureAlgorithms",
            );
            let mut body = Vec::with_capacity(2 + 2 * algorithms.len());
            body.extend_from_slice(&u16::try_from(2 * algorithms.len()).ok()?.to_be_bytes());
            for algorithm in algorithms {
                body.extend_from_slice(&algorithm.to_be_bytes());
            }
            (0x0022, CustomBody::Raw(body))
        }
        _ => return None,
    };
    Some(CustomExtension { kind, body })
}

fn alpn_body(item: &Json, key: &str) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in string_list_in(item, key) {
        if let Ok(length) = u8::try_from(protocol.len()) {
            list.push(length);
            list.extend_from_slice(protocol.as_bytes());
        }
    }
    let mut body = Vec::with_capacity(2 + list.len());
    body.extend_from_slice(&u16::try_from(list.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&list);
    body
}

fn alpn_body_either(item: &Json, first: &str, second: &str) -> Vec<u8> {
    if item.get(first).is_some() {
        alpn_body(item, first)
    } else {
        alpn_body(item, second)
    }
}

fn u16_list_either(item: &Json, first: &str, second: &str) -> Vec<u16> {
    u16_list(item.get(first).or_else(|| item.get(second)))
}

fn u16_list(value: Option<&Json>) -> Vec<u16> {
    value
        .and_then(Json::as_arr)
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_u32)
        .filter_map(|value| u16::try_from(value).ok())
        .collect()
}

fn u8_list(value: Option<&Json>) -> Vec<u8> {
    value
        .and_then(Json::as_arr)
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_u32)
        .filter_map(|value| u8::try_from(value).ok())
        .collect()
}

fn disable_fronting_profiles(settings: Option<&Json>) -> Vec<(String, Vec<String>)> {
    let Some(block) =
        settings.and_then(|settings| settings.get("DisableFrontingProviderTLSProfiles"))
    else {
        return Vec::new();
    };
    let Json::Obj(pairs) = block else {
        return Vec::new();
    };
    pairs
        .iter()
        .filter_map(|(provider, profiles)| {
            let profiles = profiles
                .as_arr()?
                .iter()
                .filter_map(Json::as_str)
                .map(str::trim)
                .filter(|profile| !profile.is_empty())
                .map(|profile| {
                    Fingerprint::resolve(profile)
                        .and_then(Fingerprint::name)
                        .map_or_else(|| profile.to_owned(), str::to_owned)
                })
                .collect::<Vec<_>>();
            (!profiles.is_empty()).then(|| (provider.clone(), profiles))
        })
        .collect()
}

fn protocol_list_named(settings: Option<&Json>, key: &str) -> Vec<String> {
    string_list(settings, key)
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

/// The protocol limit the Android client derives from its connection mode.
fn selection_protocols(selection: Option<&str>) -> Vec<String> {
    let named = match selection {
        Some("cdn_fronting" | "fronted" | "fronted-meek" | "cdn") => CDN_FRONTING_PROTOCOLS,
        Some("direct") => DIRECT_PROTOCOLS,
        Some("conduit") => CONDUIT_PROTOCOLS,
        _ => return Vec::new(),
    };
    named
        .iter()
        .map(|protocol| (*protocol).to_owned())
        .collect()
}

/// Whether the Android client enables its CDN fronting overrides for this mode.
fn selection_enables_cdn(selection: Option<&str>) -> bool {
    selection_is_cdn(selection) || matches!(selection, Some("auto" | "direct"))
}

/// Whether the Android client's `protocolSelection` names CDN fronting itself.
fn selection_is_cdn(selection: Option<&str>) -> bool {
    matches!(
        selection,
        Some("cdn_fronting" | "fronted" | "fronted-meek" | "cdn")
    )
}

/// Whether the Android client disables tactics for this mode.
fn selection_disables_tactics(selection: Option<&str>) -> bool {
    matches!(
        selection,
        Some("direct" | "cdn_fronting" | "fronted" | "fronted-meek" | "cdn")
    )
}

fn protocol_list(settings: Option<&Json>) -> Vec<String> {
    let mut protocols = string_list(settings, "LimitTunnelProtocols");
    if protocols.is_empty() {
        protocols = string_list(settings, "limitTunnelProtocols");
    }
    if protocols.is_empty() {
        if let Some(single) = text(settings, "TunnelProtocol")
            .or_else(|| text(settings, "tunnelProtocol"))
            .or_else(|| text(settings, "tunnelProtocols"))
        {
            protocols = split_list(&single);
        }
    }
    protocols
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

fn string_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(Json::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text);
    }
    Vec::new()
}

/// The client-specific STUN list wins over the generic one, as in the reference.
fn stun_list(settings: Option<&Json>, client: &str, generic: &str) -> Vec<String> {
    for key in [client, generic] {
        let addresses = string_list(settings, key);
        if !addresses.is_empty() {
            return addresses;
        }
    }
    Vec::new()
}

/// Parse the reference's traffic-shaping parameter object; a present object replaces the default.
fn traffic_shaping_parameters(
    settings: Option<&Json>,
    key: &str,
) -> crate::psiphon_webrtc::TrafficShapingParameters {
    traffic_shaping_parameters_with_default(
        settings,
        key,
        crate::psiphon_webrtc::TrafficShapingParameters::default(),
    )
}

fn traffic_shaping_parameters_with_default(
    settings: Option<&Json>,
    key: &str,
    default: crate::psiphon_webrtc::TrafficShapingParameters,
) -> crate::psiphon_webrtc::TrafficShapingParameters {
    let Some(Json::Obj(pairs)) = settings.and_then(|settings| settings.get(key)) else {
        return default;
    };
    let get = |wanted: &str| {
        pairs
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value)
    };
    let count = |wanted: &str| get(wanted).and_then(Json::as_u32).map_or(0, u64::from);
    let probability = get("DecoyMessageProbability")
        .and_then(|value| match value {
            Json::Num(number) => Some(*number),
            Json::Str(text) => text.trim().parse().ok(),
            _ => None,
        })
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    crate::psiphon_webrtc::TrafficShapingParameters {
        min_padded_messages: count("MinPaddedMessages").min(100),
        max_padded_messages: count("MaxPaddedMessages").min(100),
        min_padding_size: count("MinPaddingSize").min(16_384),
        max_padding_size: count("MaxPaddingSize").min(16_384),
        min_decoy_messages: count("MinDecoyMessages").min(100),
        max_decoy_messages: count("MaxDecoyMessages").min(100),
        min_decoy_size: count("MinDecoySize").min(16_384),
        max_decoy_size: count("MaxDecoySize").min(16_384),
        decoy_message_probability: probability,
    }
}

fn bool_setting(settings: Option<&Json>, key: &str) -> bool {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_bool)
        .unwrap_or(false)
}

/// Read a duration, using the reference's fallback for an explicit non-positive offer or relay.
fn millis_setting(settings: Option<&Json>, key: &str, default: u64, non_positive: u64) -> Duration {
    let millis = match integer(settings, key) {
        None => default,
        Some(value) if value <= 0 => non_positive,
        Some(value) => u64::try_from(value).unwrap_or(u64::MAX),
    };
    Duration::from_millis(millis)
}

/// The OSL roots, preferring the plural list and falling back to the legacy single URL.
fn osl_roots(settings: Option<&Json>) -> Vec<TransferRoot> {
    let global = custom_headers(settings);
    let listed = settings.and_then(|settings| {
        settings
            .get("ObfuscatedServerListRootURLs")
            .or_else(|| settings.get("obfuscatedServerListRootURLs"))
    });
    let mut roots = match listed {
        Some(Json::Arr(items)) => transfer_roots(items, "ObfuscatedServerListRootURLs", &global),
        _ => Vec::new(),
    };
    if roots.is_empty() {
        if let Some(root) = text(settings, "ObfuscatedServerListRootURL") {
            if let Some(url) = transfer_url(root.trim()) {
                roots.push(TransferRoot {
                    url,
                    skip_verify: false,
                    headers: global,
                    key: None,
                    only_after: 0,
                    fronting: Vec::new(),
                });
            }
        }
    }
    if !roots.is_empty() && !roots.iter().any(|root| root.only_after == 0) {
        eprintln!(
            "psiphon: ObfuscatedServerListRootURLs has no OnlyAfterAttempts 0 root; using the first"
        );
        roots[0].only_after = 0;
    }
    roots
}

/// The upgrade roots, preferring the plural list and falling back to the legacy single URL.
fn upgrade_roots(settings: Option<&Json>) -> Vec<TransferRoot> {
    let global = custom_headers(settings);
    let listed = settings.and_then(|settings| settings.get("UpgradeDownloadURLs"));
    let mut roots = match listed {
        Some(Json::Arr(items)) => transfer_roots(items, "UpgradeDownloadURLs", &global),
        _ => Vec::new(),
    };
    if roots.is_empty() {
        if let Some(root) = text(settings, "UpgradeDownloadUrl") {
            if let Some(url) = transfer_url(root.trim()) {
                roots.push(TransferRoot {
                    url,
                    skip_verify: false,
                    headers: global,
                    key: None,
                    only_after: 0,
                    fronting: Vec::new(),
                });
            }
        }
    }
    roots
}

fn feedback_roots(settings: Option<&Json>) -> Vec<TransferRoot> {
    let global = custom_headers(settings);
    settings
        .and_then(|settings| settings.get("FeedbackUploadURLs"))
        .and_then(Json::as_arr)
        .map_or_else(Vec::new, |items| {
            transfer_roots(items, "FeedbackUploadURLs", &global)
        })
}

/// Decode a list of transfer-URL strings or objects, folding global headers under each entry.
fn transfer_roots(items: &[Json], label: &str, global: &[(String, String)]) -> Vec<TransferRoot> {
    let mut roots = Vec::new();
    for item in items {
        match item {
            Json::Str(value) => {
                if let Some(url) = transfer_url(value) {
                    roots.push(TransferRoot {
                        url,
                        skip_verify: false,
                        headers: global.to_vec(),
                        key: None,
                        only_after: 0,
                        fronting: Vec::new(),
                    });
                } else {
                    eprintln!("psiphon: {label} entry names no URL");
                }
            }
            Json::Obj(fields) => {
                let url = fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("URL"))
                    .and_then(|(_, value)| value.as_str())
                    .and_then(transfer_url);
                let Some(url) = url else {
                    eprintln!("psiphon: {label} entry names no URL");
                    continue;
                };
                let skip_verify = fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("SkipVerify"))
                    .and_then(|(_, value)| value.as_bool())
                    .unwrap_or(false);
                let key = fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("B64EncodedPublicKey"))
                    .and_then(|(_, value)| value.as_str())
                    .filter(|key| !key.is_empty())
                    .map(str::to_owned);
                let only_after = fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("OnlyAfterAttempts"))
                    .and_then(|(_, value)| value.as_i64())
                    .unwrap_or(0);
                let local = fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("RequestHeaders"))
                    .map(|(_, value)| header_fields(value))
                    .unwrap_or_default();
                let mut headers = global.to_vec();
                headers.retain(|(name, _)| {
                    !local
                        .iter()
                        .any(|(added, _)| added.eq_ignore_ascii_case(name))
                });
                headers.extend(local);
                roots.push(TransferRoot {
                    url,
                    skip_verify,
                    headers,
                    key,
                    only_after: usize::try_from(only_after).unwrap_or(0),
                    fronting: fronting_specs(fields, label),
                });
            }
            _ => eprintln!("psiphon: {label} entry is not an object"),
        }
    }
    roots
}

/// The transfer-URL `FrontingSpecs`: fronted HTTPS only, as the reference's plaintext round trip.
fn fronting_specs(fields: &[(String, Json)], label: &str) -> Vec<FrontingSpec> {
    let item = Json::Obj(fields.to_vec());
    let Some(Json::Arr(specs)) = field(Some(&item), "FrontingSpecs") else {
        return Vec::new();
    };
    let mut parsed = Vec::new();
    for spec in specs {
        let Json::Obj(fields) = spec else {
            eprintln!("psiphon: {label} FrontingSpecs entry is not an object");
            continue;
        };
        let item = Json::Obj(fields.clone());
        let provider_id = text_in(&item, "FrontingProviderID").unwrap_or_default();
        let addresses = string_list_in(&item, "Addresses");
        let transports = string_list_in(&item, "Transports");
        let disable_sni = bool_in(&item, "DisableSNI");
        let skip_verify = bool_in(&item, "SkipVerify");
        let verify_name = text_in(&item, "VerifyServerName").unwrap_or_default();
        let verify_pins = string_list_in(&item, "VerifyPins");
        let host = text_in(&item, "Host").unwrap_or_default();
        let https = transports.is_empty()
            || transports
                .iter()
                .any(|transport| transport == "FRONTED-HTTPS");
        if provider_id.is_empty()
            || addresses.is_empty()
            || host.is_empty()
            || !https
            || (skip_verify && (!verify_name.is_empty() || !verify_pins.is_empty()))
            || (!skip_verify && verify_name.is_empty())
            || verify_pins.iter().any(String::is_empty)
        {
            eprintln!(
                "psiphon: {label} ignores a FrontingSpec that is incomplete or not fronted HTTPS"
            );
            continue;
        }
        parsed.push(FrontingSpec {
            addresses,
            disable_sni,
            skip_verify,
            verify_name,
            verify_pins,
            host,
        });
    }
    parsed
}

/// A `TransferURL`'s URL is base64 encoded; plain HTTPS URLs are accepted for existing configs.
fn transfer_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with("https://") || value.starts_with("http://") {
        return Some(list_url(value));
    }
    let decoded = ferrox_core::b64::decode(value.as_bytes())?;
    let decoded = String::from_utf8(decoded).ok()?;
    (decoded.starts_with("https://") || decoded.starts_with("http://")).then(|| list_url(&decoded))
}

/// `ObfuscatedSSHAlgorithms` is [kex, cipher, mac, host key]; names this engine cannot carry keep the defaults.
fn ssh_algorithms(settings: Option<&Json>) -> Option<[String; 4]> {
    let names = string_list(settings, "ObfuscatedSSHAlgorithms");
    if names.is_empty() {
        return None;
    }
    let Ok([kex, cipher, mac, host]): Result<[String; 4], _> = names.try_into() else {
        eprintln!("psiphon: ObfuscatedSSHAlgorithms needs four names; using the defaults");
        return None;
    };
    let supported: [&[&str]; 4] = [
        &["curve25519-sha256", "curve25519-sha256@libssh.org"],
        &["aes128-ctr"],
        &["hmac-sha2-256"],
        &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "ssh-ed25519"],
    ];
    for (name, allowed) in [&kex, &cipher, &mac, &host].into_iter().zip(supported) {
        if !allowed.contains(&name.as_str()) {
            eprintln!("psiphon: ObfuscatedSSHAlgorithms {name} is not carried; using the defaults");
            return None;
        }
    }
    Some([kex, cipher, mac, host])
}

fn header_fields(value: &Json) -> Vec<(String, String)> {
    let Json::Obj(fields) = value else {
        return Vec::new();
    };
    fields
        .iter()
        .flat_map(|(name, value)| match value {
            Json::Str(text) => vec![(name.clone(), text.clone())],
            Json::Arr(items) => items
                .iter()
                .filter_map(Json::as_str)
                .map(|text| (name.clone(), text.to_owned()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Split-tunnel regions are ISO 3166-1 alpha-2 codes; accept either case and drop duplicates.
fn split_tunnel_regions(settings: Option<&Json>) -> Vec<String> {
    let mut regions = Vec::new();
    for region in string_list(settings, "SplitTunnelRegions") {
        let region = region.trim().to_ascii_uppercase();
        if region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()) {
            push_unique(&mut regions, region);
        } else {
            eprintln!("psiphon: SplitTunnelRegions ignores {region:?}, not an ISO alpha-2 code");
        }
    }
    regions
}

fn custom_headers(settings: Option<&Json>) -> Vec<(String, String)> {
    let mut headers = header_map(settings, "CustomHeaders");
    if headers.is_empty() {
        headers = header_map(settings, "customHeaders");
    }
    if headers.is_empty() {
        headers = header_map(settings, "UpstreamProxyCustomHeaders");
    }
    merge_headers(headers, header_map(settings, "AdditionalCustomHeaders"))
}

/// The dial headers: `MeekAdditionalHeaders` with `AdditionalCustomHeaders` replacing a same name.
fn dial_headers(settings: Option<&Json>) -> Vec<(String, String)> {
    merge_headers(
        header_map(settings, "MeekAdditionalHeaders"),
        header_map(settings, "AdditionalCustomHeaders"),
    )
}

fn merge_headers(
    mut headers: Vec<(String, String)>,
    additional: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if additional.is_empty() {
        return headers;
    }
    headers.retain(|(name, _)| {
        !additional
            .iter()
            .any(|(added, _)| added.eq_ignore_ascii_case(name))
    });
    headers.extend(additional);
    headers
}

fn header_map(settings: Option<&Json>, key: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    fields
        .iter()
        .flat_map(|(name, value)| match value {
            Json::Str(text) => vec![(name.clone(), text.clone())],
            Json::Arr(items) => items
                .iter()
                .filter_map(Json::as_str)
                .map(|text| (name.clone(), text.to_owned()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// The reference's testing hook: base64 JSON laid over the caller's config.
fn merge_additional_parameters(settings: Option<&Json>) -> Result<Option<Json>, String> {
    let Some(raw) = settings.and_then(|settings| {
        settings
            .get("AdditionalParameters")
            .or_else(|| settings.get("additionalParameters"))
    }) else {
        return Ok(None);
    };
    let over = match raw {
        Json::Obj(_) => raw.clone(),
        Json::Str(text) => {
            let decoded = ferrox_core::b64::decode(text.as_bytes())
                .ok_or_else(|| "psiphon: AdditionalParameters is not base64".to_owned())?;
            let text = String::from_utf8(decoded)
                .map_err(|_| "psiphon: AdditionalParameters is not UTF-8".to_owned())?;
            crate::json::parse(&text)
                .map_err(|error| format!("psiphon: AdditionalParameters: {error}"))?
        }
        _ => return Err("psiphon: AdditionalParameters is not a string or object".to_owned()),
    };
    let Json::Obj(overrides) = over else {
        return Err("psiphon: AdditionalParameters is not a JSON object".to_owned());
    };
    let mut fields = match settings.cloned() {
        Some(Json::Obj(fields)) => fields,
        Some(_) => return Ok(Some(Json::Obj(overrides))),
        None => Vec::new(),
    };
    for (key, value) in overrides {
        if let Some((_, slot)) = fields.iter_mut().find(|(have, _)| *have == key) {
            *slot = value;
        } else {
            fields.push((key, value));
        }
    }
    Ok(Some(Json::Obj(fields)))
}

const KNOWN_SETTINGS: &[&str] = &[
    "listen",
    "shareProxyOnNetwork",
    "shareProxyOnNetworkSocksPort",
    "region",
    "egressRegion",
    "readySeconds",
    "serverList",
    "serverEntries",
    "state",
    "dataRootDirectory",
    "dataDirectory",
    "serverListURL",
    "serverListURLs",
    "serverListUrls",
    "remoteServerListURLs",
    "RemoteServerListURLs",
    "RemoteServerListUrl",
    "remoteServerListUrl",
    "serverListSignaturePublicKey",
    "remoteServerListSignaturePublicKey",
    "RemoteServerListSignaturePublicKey",
    "ServerEntrySignaturePublicKey",
    "FetchRemoteServerListRetryPeriodMilliseconds",
    "EnableUpgradeDownload",
    "UpgradeDownloadURLs",
    "UpgradeDownloadUrl",
    "UpgradeDownloadClientVersionHeader",
    "FetchUpgradeRetryPeriodMilliseconds",
    "EnableFeedbackUpload",
    "FeedbackUploadURLs",
    "FeedbackEncryptionPublicKey",
    "FeedbackUploadMaxAttempts",
    "FeedbackUploadRetryMinDelaySeconds",
    "FeedbackUploadRetryMaxDelaySeconds",
    "ExchangeObfuscationKey",
    "ObfuscatedServerListRootURLs",
    "obfuscatedServerListRootURLs",
    "ObfuscatedServerListRootURL",
    "EmitSLOKs",
    "EmitServerAlerts",
    "DisableRemoteServerListFetcher",
    "DisablePeriodicSshKeepAlive",
    "DisableKeepAlive",
    "SSHKeepAliveSpeedTestSampleProbability",
    "SSHKeepAlivePaddingMinBytes",
    "SSHKeepAlivePaddingMaxBytes",
    "SSHKeepAlivePeriodMinMilliseconds",
    "SSHKeepAlivePeriodMaxMilliseconds",
    "SSHKeepAlivePeriodicTimeoutMilliseconds",
    "SSHKeepAlivePeriodicInactivePeriodMilliseconds",
    "SSHKeepAliveProbeTimeoutMilliseconds",
    "SSHKeepAliveProbeInactivePeriodMilliseconds",
    "SSHKeepAliveNetworkConnectivityPollingPeriodMilliseconds",
    "SSHKeepAliveResetOnFailureProbability",
    "SSHKeepAliveResumeProbeTimeoutMilliseconds",
    "SSHKeepAliveResumeProbeInactivePeriodMilliseconds",
    "SSHKeepAliveResumeReconnectInactivePeriodMilliseconds",
    "LocalSocksProxyPort",
    "ListenInterface",
    "LocalHttpProxyPort",
    "shareProxyOnNetworkHttpPort",
    "DisableLocalSocksProxy",
    "DisableLocalHTTPProxy",
    "EgressRegion",
    "DataRootDirectory",
    "SponsorId",
    "SponsorID",
    "SessionID",
    "Authorizations",
    "sponsorId",
    "localProxyUsername",
    "LocalProxyUsername",
    "shareProxyOnNetworkUsername",
    "localProxyPassword",
    "LocalProxyPassword",
    "shareProxyOnNetworkPassword",
    "DisableTimeouts",
    "disableTunnels",
    "DisableTunnels",
    "upstreamProxy",
    "upstream",
    "UpstreamProxyURL",
    "UpstreamProxyUrl",
    "UpstreamProxyCustomHeaders",
    "UpstreamProxyAllowAllServerEntrySources",
    "protocolSelection",
    "beastMode",
    "AggressiveEstablishment",
    "aggressiveEstablishment",
    "TunnelPoolSize",
    "tunnelPoolSize",
    "ConnectionWorkerPoolSize",
    "ConnectionWorkerPoolMaxSize",
    "LimitIntensiveConnectionWorkers",
    "LimitCPUThreads",
    "DisableConnectionWorkerPool",
    "EstablishTunnelTimeoutSeconds",
    "TunnelConnectTimeoutSeconds",
    "CompressTactics",
    "EnableDSLFetcher",
    "DisableDSLFetcher",
    "DSLPrioritizeDialNewServerEntryProbability",
    "DSLPrioritizeDialExistingServerEntryProbability",
    "DSLPrioritizeDialRetainFailedProbability",
    "DSLPrioritizeDialPlaceholderTTLSeconds",
    "ServerEntryIteratorMaxMoveToFront",
    "ServerEntryIteratorResetProbability",
    "RestrictDirectProviderIDsClientProbability",
    "RestrictDirectProviderRegions",
    "RestrictFrontingProviderIDs",
    "RestrictFrontingProviderIDsClientProbability",
    "RestrictInproxyProviderIDsClientProbability",
    "RestrictInproxyProviderRegions",
    "HoldOffDirectTunnelMinDurationMilliseconds",
    "HoldOffDirectTunnelMaxDurationMilliseconds",
    "HoldOffDirectTunnelProbability",
    "HoldOffDirectTunnelProviderRegions",
    "HoldOffFrontingTunnelMinDurationMilliseconds",
    "HoldOffFrontingTunnelMaxDurationMilliseconds",
    "HoldOffFrontingTunnelProbability",
    "HoldOffFrontingTunnelProviderIDs",
    "HoldOffInproxyTunnelMinDurationMilliseconds",
    "HoldOffInproxyTunnelMaxDurationMilliseconds",
    "HoldOffInproxyTunnelProbability",
    "HoldOffInproxyTunnelProviderRegions",
    "EstablishTunnelPausePeriodSeconds",
    "EstablishTunnelServerAffinityGracePeriodMilliseconds",
    "StaggerConnectionWorkersMilliseconds",
    "PropagationChannelId",
    "ClientPlatform",
    "ClientVersion",
    "DeviceRegion",
    "deviceRegion",
    "DeviceLocation",
    "deviceLocation",
    "ClientFeatures",
    "InproxyClientPersonalCompartmentID",
    "inproxyClientPersonalCompartmentID",
    "InproxySTUNServerAddresses",
    "InproxySTUNServerAddressesRFC5780",
    "InproxyClientSTUNServerAddresses",
    "InproxyClientSTUNServerAddressesRFC5780",
    "InproxyDisableSTUN",
    "InproxyClientDisableSTUN",
    "InproxyClientDiscoverNATProbability",
    "InproxyClientDiscoverNATTimeoutMilliseconds",
    "InproxyDTLSRandomizationProbability",
    "InproxyWebRTCMediaStreamsProbability",
    "InproxyWebRTCMediaStreamsTrafficShapingParameters",
    "InproxyWebRTCMediaStreamsTrafficShapingProbability",
    "InproxyWebRTCDataChannelTrafficShapingProbability",
    "InproxyWebRTCDataChannelTrafficShapingParameters",
    "InproxyClientDisablePortMapping",
    "InproxyDisablePortMapping",
    "InproxyDisableInboundForMobileNetworks",
    "InproxyDisableIPv6ICECandidates",
    "InproxyClientDisableWaitToShareSession",
    "InproxyClientOfferRequestTimeoutMilliseconds",
    "InproxyClientOfferRequestPersonalTimeoutMilliseconds",
    "InproxyClientOfferRetryDelayMilliseconds",
    "InproxyClientOfferRetryJitter",
    "InproxyClientRelayedPacketRequestTimeoutMilliseconds",
    "InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds",
    "InproxyClientNoMatchFailoverProbability",
    "InproxyClientNoMatchFailoverPersonalProbability",
    "InproxyBrokerSpecs",
    "InproxyClientBrokerSpecs",
    "InproxyPersonalPairingBrokerSpecs",
    "InproxyClientPersonalPairingBrokerSpecs",
    "InproxyPersonalPairingMaxBrokerSpecCount",
    "InproxyCommonCompartmentIDs",
    "InproxyAllowClient",
    "InproxyTunnelProtocolPreferProbability",
    "InproxyTunnelProtocolForceSelectionCount",
    "InproxyClientDialRateLimitQuantity",
    "InproxyClientDialRateLimitIntervalMilliseconds",
    "InproxyClientDialRateLimitInterval",
    "InproxyPsiphonAPIRequestTimeoutMilliseconds",
    "InproxyEnableWebRTCDebugLogging",
    "InproxyClientDisableIPv6ICECandidates",
    "InproxyClientDisableInboundForMobileNetworks",
    "InproxyClientIncompatibleNetworkTypes",
    "InproxyFrontingProviderClientMaxRequestTimeouts",
    "NetworkType",
    "InproxyTunnelProtocolSelectionProbability",
    "inproxyCompartment",
    "protocol_selection",
    "conduitMode",
    "conduit_mode",
    "conduitTimeout",
    "conduit_timeout",
    "ConduitTunnelProtocols",
    "conduitTunnelProtocols",
    "CONDUIT_TUNNEL_PROTOCOLS",
    "rejectCensoredCountryProxies",
    "InproxyRejectProxyCountryCodes",
    "rejectProxyCountryCodes",
    "GeoIPDatabasePath",
    "DNSResolverAlternateServers",
    "SteeringIPCacheTTLSeconds",
    "SteeringIPCacheMaxEntries",
    "SteeringIPProbability",
    "cdnProfile",
    "cdnIps",
    "cdnSni",
    "cdnSets",
    "FrontedMeekDialOverrides",
    "FrontedMeekDialOverridesProbability",
    "FrontedMeekCDNScanSpec",
    "frontedMeekCDNScanSpec",
    "FrontedMeekCDNScanUseBuiltInSpec",
    "FrontedMeekCDNScanBuiltInSets",
    "LimitMeekBufferSizes",
    "LimitRelayBufferSizes",
    "NetworkLatencyMultiplier",
    "NetworkLatencyMultiplierMin",
    "NetworkLatencyMultiplierMax",
    "NetworkLatencyMultiplierLambda",
    "InitialLimitTunnelProtocols",
    "InitialLimitTunnelProtocolsCandidateCount",
    "InitialLimitTunnelProtocolsProbability",
    "LimitTunnelProtocols",
    "LimitTunnelProtocolsProbability",
    "LimitTunnelDialPortNumbers",
    "limitTunnelDialPortNumbers",
    "LimitTunnelDialPortNumbersProbability",
    "PrioritizeTunnelProtocols",
    "PrioritizeTunnelProtocolsCandidateCount",
    "PrioritizeTunnelProtocolsProbability",
    "limitTunnelProtocols",
    "TunnelProtocol",
    "tunnelProtocol",
    "tunnelProtocols",
    "TargetServerEntry",
    "CustomHeaders",
    "customHeaders",
    "AdditionalCustomHeaders",
    "AdditionalParameters",
    "additionalParameters",
    "DisableTactics",
    "DisableReplay",
    "FrontedHTTPClientReplayDialParametersProbability",
    "FrontedHTTPClientReplayDialParametersTTLSeconds",
    "FrontedHTTPClientReplayRetainFailedProbability",
    "FrontedHTTPClientReplayUpdateFrequencySeconds",
    "InproxyReplayBrokerDialParametersProbability",
    "InproxyReplayBrokerDialParametersTTLSeconds",
    "InproxyReplayBrokerRetainFailedProbability",
    "InproxyReplayBrokerUpdateFrequencySeconds",
    "InproxyReplayRetainFailedProbability",
    "ReplayCandidateCount",
    "ReplayDialParametersTTLSeconds",
    "ReplayIgnoreChangedConfigStateProbability",
    "ReplayLaterRoundMoveToFrontProbability",
    "ReplayRetainFailedProbability",
    "ReplayTargetDownstreamBytes",
    "ReplayTargetTunnelDurationSeconds",
    "ReplayTargetUpstreamBytes",
    "MeekAdditionalHeaders",
    "SSHChannelWindowSize",
    "SSHPacketTunnelChannelWindowSize",
    "PacketTunnelTunFileDescriptor",
    "PacketTunnelTransparentDNSIPv4Address",
    "PacketTunnelTransparentDNSIPv6Address",
    "ClientBuildRev",
    "NetworkType",
    "ClientBurstUpstreamTargetBytes",
    "ClientBurstUpstreamDeadlineMilliseconds",
    "ClientBurstDownstreamTargetBytes",
    "ClientBurstDownstreamDeadlineMilliseconds",
    "EnableLightProxy",
    "LightProxyEntry",
    "LightProxyEntryTracker",
    "LightProxyDisable",
    "LightProxyTestFetchAddress",
    "LightProxyUseRecommendedSNIProbability",
    "LightProxyCustomHostNameProbability",
    "LightProxyCustomHostNameRegexes",
    "LightProxyTunnelInactiveThresholdMilliseconds",
    "LightProxyTunnelInactiveThreshold",
    "LightProxyDialTimeoutMilliseconds",
    "LightProxyDialTimeout",
    "LimitQUICVersions",
    "LimitTLSProfiles",
    "TLSProfile",
    "CustomTLSProfiles",
    "UseOnlyCustomTLSProfiles",
    "DisableFrontingProviderTLSProfiles",
    "QUICNoiseProfile",
    "InproxyRejectProxyCIDRs",
    "TLSTunnelMinTLSPadding",
    "TLSTunnelMaxTLSPadding",
    "MeekMinTLSPadding",
    "MeekMaxTLSPadding",
    "MeekTrafficShapingProbability",
    "MeekTrafficShapingLimitProtocols",
    "MeekMinLimitRequestPayloadLength",
    "MeekMaxLimitRequestPayloadLength",
    "MeekRedialTLSProbability",
    "MeekAlternateCookieNameProbability",
    "MeekAlternateContentTypeProbability",
    "MeekPayloadPaddingProbability",
    "MeekPayloadPaddingMinSize",
    "MeekPayloadPaddingMaxSize",
    "MeekPayloadPaddingOmitProbability",
    "TLSTunnelTrafficShapingProbability",
    "NoDefaultTLSSessionIDProbability",
    "TLSTunnelObfuscatedPSKProbability",
    "DisableSystemRootCAs",
    "TrustedCACertificatesFilename",
    "TLSFragmentClientHelloProbability",
    "TargetAPIEncoding",
    "TargetAPIProtocol",
    "ClientAPILevel",
    "DisableApi",
    "TLSFragmentClientHelloLimitProtocols",
    "PickUserAgentProbability",
    "QUICDialEarlyProbability",
    "QUICDisablePathMTUDiscoveryProbability",
    "QUICDisableClientPathMTUDiscoveryProbability",
    "QUICObfuscatedPSKProbability",
    "SelectRandomizedTLSProfileProbability",
    "TLSOSSHSNIServerName",
    "TLSOSSHSNIServerNames",
    "TransformHostNameProbability",
    "CustomHostNameRegexes",
    "CustomHostNameProbability",
    "CustomHostNameLimitProtocols",
    "SplitTunnelOwnRegion",
    "SplitTunnelRegions",
    "ShadowsocksPrefixSpecs",
    "ShadowsocksPrefixScopedSpecNames",
    "ShadowsocksPrefixProbability",
    "OSSHPrefixSpecs",
    "OSSHPrefixScopedSpecNames",
    "OSSHPrefixProbability",
    "OSSHPrefixSplitMinDelayMilliseconds",
    "OSSHPrefixSplitMaxDelayMilliseconds",
    "OSSHPrefixSplitMinDelay",
    "OSSHPrefixSplitMaxDelay",
    "OSSHObfuscatorSeedTransformProbability",
    "OSSHObfuscatorSeedTransformScopedSpecNames",
    "OSSHObfuscatorSeedTransformSpecs",
    "ObfuscatedQUICNonceTransformProbability",
    "ObfuscatedQUICNonceTransformScopedSpecNames",
    "ObfuscatedQUICNonceTransformSpecs",
    "DirectHTTPProtocolTransformProbability",
    "DirectHTTPProtocolTransformScopedSpecNames",
    "DirectHTTPProtocolTransformSpecs",
    "FrontedHTTPProtocolTransformProbability",
    "FrontedHTTPProtocolTransformScopedSpecNames",
    "FrontedHTTPProtocolTransformSpecs",
    "ObfuscatedSSHAlgorithms",
    "ObfuscatedSSHMinPadding",
    "ObfuscatedSSHMaxPadding",
    "RateLimits",
    "HoldOffTunnelProtocolMinDurationMilliseconds",
    "HoldOffTunnelProtocolMaxDurationMilliseconds",
    "HoldOffTunnelProtocolNames",
    "HoldOffTunnelProtocolProbability",
    "TacticsWaitPeriodMilliseconds",
    "TacticsRetryPeriodMilliseconds",
    "TacticsRetryPeriodJitter",
    "TacticsTimeoutMilliseconds",
    "InitialLivenessTest",
    "LivenessTest",
    "LivenessTestMinUpstreamBytes",
    "LivenessTestMaxUpstreamBytes",
    "LivenessTestMinDownstreamBytes",
    "LivenessTestMaxDownstreamBytes",
    "FragmentorProbability",
    "FragmentorLimitProtocols",
    "FragmentorMinTotalBytes",
    "FragmentorMaxTotalBytes",
    "FragmentorMinWriteBytes",
    "FragmentorMaxWriteBytes",
    "FragmentorMinDelayMicroseconds",
    "FragmentorMaxDelayMicroseconds",
    "OSSHPrefixEnableFragmentor",
    "DNSResolverAttemptsPerPreferredServer",
    "DNSResolverAttemptsPerServer",
    "DNSResolverAwaitTimeoutMilliseconds",
    "DNSResolverCacheExtensionInitialTTLMilliseconds",
    "DNSResolverCacheExtensionVerifiedTTLMilliseconds",
    "DNSResolverProtocolTransformProbability",
    "DNSResolverProtocolTransformScopedSpecNames",
    "DNSResolverProtocolTransformSpecs",
    "DNSResolverQNameMustMatchProbability",
    "DNSResolverIncludeEDNS0Probability",
    "DNSResolverPreferAlternateServerProbability",
    "DNSResolverPreferredAlternateServers",
    "DNSResolverPreresolvedIPAddressCIDRs",
    "DNSResolverPreresolvedIPAddressProbability",
    "DNSResolverQNameRandomizeCasingProbability",
    "DNSResolverRequestTimeoutMilliseconds",
];

/// Report settings fields this lane does not consume.
fn warn_ignored(settings: Option<&Json>) {
    let Some(Json::Obj(fields)) = settings else {
        return;
    };

    let ignored: Vec<&str> = fields
        .iter()
        .filter(|(key, _)| !KNOWN_SETTINGS.contains(&key.as_str()))
        .map(|(key, _)| key.as_str())
        .collect();
    if !ignored.is_empty() {
        eprintln!("psiphon: native engine ignores {}", ignored.join(", "));
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn dns_server(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    text.parse::<SocketAddr>().ok().or_else(|| {
        text.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The reference's `SessionID`: 32 lowercase hex digits, or one generated per client session.
fn client_session_id(settings: Option<&Json>) -> Option<String> {
    let session = text(settings, "SessionID")?;
    let valid = session.len() == 32
        && session
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        eprintln!("psiphon: SessionID must be 32 lowercase hex digits; generating one");
    }
    valid.then_some(session)
}

/// The `LightProxy` client settings, or `None` when the lane is not enabled.
fn light_settings(
    settings: Option<&Json>,
    tls_shape: &TlsShape,
    sponsor: &str,
    platform: &str,
    device_region: Option<&str>,
    session_id: Option<&str>,
) -> Option<crate::psiphon_light::Config> {
    if !flag(settings, "EnableLightProxy", "AETHER_PSIPHON_LIGHT_PROXY") {
        return None;
    }
    if flag(
        settings,
        "LightProxyDisable",
        "AETHER_PSIPHON_LIGHT_PROXY_DISABLE",
    ) {
        return None;
    }
    let Some(entry) =
        text(settings, "LightProxyEntry").or_else(|| env("AETHER_PSIPHON_LIGHT_PROXY_ENTRY"))
    else {
        eprintln!("psiphon: EnableLightProxy is set but LightProxyEntry is missing");
        return None;
    };
    let build_rev = text(settings, "ClientBuildRev")
        .or_else(|| env("AETHER_PSIPHON_BUILD_REV"))
        .unwrap_or_default();
    let network_type = text(settings, "NetworkType")
        .or_else(|| env("AETHER_PSIPHON_NETWORK_TYPE"))
        .unwrap_or_default();
    let test_fetch_address =
        text(settings, "LightProxyTestFetchAddress").filter(|address| address.contains(':'));
    Some(crate::psiphon_light::Config {
        entry,
        tracker: integer(settings, "LightProxyEntryTracker").unwrap_or(0),
        sponsor: sponsor.to_owned(),
        platform: platform.to_owned(),
        build_rev,
        device_region: device_region.map(str::to_owned),
        session_id: session_id.unwrap_or_default().to_owned(),
        network_type,
        recommended_probability: decimal(settings, "LightProxyUseRecommendedSNIProbability")
            .unwrap_or(0.5)
            .clamp(0.0, 1.0),
        custom_probability: decimal(settings, "LightProxyCustomHostNameProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        custom_hostnames: string_list(settings, "LightProxyCustomHostNameRegexes"),
        inactive: light_duration(
            settings,
            "LightProxyTunnelInactiveThresholdMilliseconds",
            "LightProxyTunnelInactiveThreshold",
            Duration::from_secs(30),
        ),
        dial_timeout: light_duration(
            settings,
            "LightProxyDialTimeoutMilliseconds",
            "LightProxyDialTimeout",
            Duration::from_secs(20),
        )
        .max(Duration::from_secs(1)),
        test_fetch_address,
        tls_shape: tls_shape.clone(),
    })
}

/// Read a millisecond setting, or the older duration spelling.
fn light_duration(
    settings: Option<&Json>,
    millis_key: &str,
    duration_key: &str,
    default: Duration,
) -> Duration {
    if let Some(millis) = number(settings, millis_key) {
        return Duration::from_millis(millis.min(600_000));
    }
    let Some(value) = settings.and_then(|settings| settings.get(duration_key)) else {
        return default;
    };
    if let Some(text) = value.as_str() {
        if let Some(duration) = go_duration(text) {
            return duration.min(Duration::from_secs(600));
        }
    }
    number(settings, duration_key).map_or(default, |nanos| {
        Duration::from_nanos(nanos).min(Duration::from_secs(600))
    })
}

/// The reference's `time.Duration` spellings that tactics use for these two knobs.
fn go_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    for (suffix, scale) in [
        ("ms", 1u64),
        ("ns", 0),
        ("s", 1_000),
        ("m", 60_000),
        ("h", 3_600_000),
    ] {
        if let Some(value) = text.strip_suffix(suffix) {
            let value = value.trim().parse::<u64>().ok()?;
            let millis = value.checked_mul(scale)?;
            return Some(if suffix == "ns" {
                Duration::from_nanos(value)
            } else {
                Duration::from_millis(millis)
            });
        }
    }
    None
}

fn text(settings: Option<&Json>, key: &str) -> Option<String> {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn json_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("URL").and_then(Json::as_str))
                    .or_else(|| item.get("url").and_then(Json::as_str))
            })
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(list_url)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text)
            .into_iter()
            .map(|url| list_url(&url))
            .collect();
    }
    Vec::new()
}

/// A list entry is a plain URL or, as the reference writes it, the base64 of one.
fn list_url(item: &str) -> String {
    if item.starts_with("http://") || item.starts_with("https://") {
        return item.to_owned();
    }
    ferrox_core::b64::decode(item.as_bytes())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .map_or_else(|| item.to_owned(), |url| url.trim().to_owned())
}

fn env_list(environment: &str) -> Vec<String> {
    env(environment)
        .map(|text| split_list(&text))
        .unwrap_or_default()
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', ' ', '\t', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn flag(settings: Option<&Json>, key: &str, environment: &str) -> bool {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_bool)
        .unwrap_or_else(|| env_flag(environment))
}

fn env_flag(environment: &str) -> bool {
    env(environment).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn server_entries(settings: Option<&Json>) -> Option<PathBuf> {
    let path = text(settings, "serverList")
        .or_else(|| text(settings, "serverEntries"))
        .or_else(|| env("AETHER_PSIPHON_SERVER_ENTRIES"))
        .map(PathBuf::from)?;
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("psiphon: server entries {} are not a file", path.display());
        None
    }
}

fn default_state() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("ferrox/psiphon");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state/ferrox/psiphon");
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("ferrox-psiphon-{uid}"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("ferrox-psiphon")
    }
}

fn listen_address(settings: Option<&Json>) -> Result<SocketAddr, String> {
    let share = flag(settings, "shareProxyOnNetwork", "AETHER_PSIPHON_SHARE");
    let private = flag(
        settings,
        "DisableLocalSocksProxy",
        "AETHER_PSIPHON_DISABLE_SOCKS_PROXY",
    );
    let explicit = text(settings, "listen").is_some() || env("AETHER_PSIPHON_BIND").is_some();
    let interface = text(settings, "ListenInterface");
    let text = text(settings, "listen")
        .or_else(|| env("AETHER_PSIPHON_BIND"))
        .or_else(|| {
            text(settings, "shareProxyOnNetworkSocksPort")
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("shareProxyOnNetworkSocksPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("LocalSocksProxyPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .map(|port| {
                    let ip = if share { "0.0.0.0" } else { "127.0.0.1" };
                    format!("{ip}:{port}")
                })
        })
        .unwrap_or_else(|| {
            if share {
                format!(
                    "0.0.0.0:{}",
                    ferrox_core::psiphon::DEFAULT_BIND
                        .rsplit_once(':')
                        .map_or("1821", |(_, port)| port)
                )
            } else {
                ferrox_core::psiphon::DEFAULT_BIND.to_owned()
            }
        });
    let address = if private {
        // The flag removes the reference's local SOCKS listener, but the embedded lane keeps an ephemeral loopback edge for its own outbound.
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    } else {
        let address = text
            .parse::<SocketAddr>()
            .map_err(|_| format!("psiphon: listen {text:?} is not an address and a port"))?;
        if explicit {
            address
        } else if let Some(interface) = interface {
            SocketAddr::new(interface_ip(&interface, address.ip()), address.port())
        } else {
            address
        }
    };
    Ok(if address.port() == 0 {
        SocketAddr::new(address.ip(), free_port(address.ip())?)
    } else {
        address
    })
}

fn interface_ip(interface: &str, fallback: IpAddr) -> IpAddr {
    if interface.eq_ignore_ascii_case("any") {
        return match fallback {
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
    }
    if let Ok(ip) = interface.parse() {
        return ip;
    }
    eprintln!("psiphon: ListenInterface {interface:?} is not an address; using {fallback}");
    fallback
}

fn free_port(ip: IpAddr) -> Result<u16, String> {
    let socket = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("psiphon: no local port on {ip}: {error}"))?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("psiphon: the local port did not read back: {error}"))
}

/// The region codes the signed list publishes and how many entries each carries.
pub(crate) fn regions(settings: Option<&Json>) -> Result<Vec<(String, usize)>, String> {
    let settings = Settings::from_json(settings)?;
    let mut counts: BTreeMap<String, HashSet<IpAddr>> = BTreeMap::new();
    for server in load_all_entries(&settings, false)? {
        if let Some(region) = server.region {
            counts.entry(region).or_default().insert(server.address);
        }
    }
    Ok(counts
        .into_iter()
        .map(|(region, addresses)| (region, addresses.len()))
        .collect())
}

/// Fetch tactics from the first entry that advertises the untunneled capability.
pub(crate) fn tactics(settings: Option<&Json>) -> Result<crate::psiphon_tactics::Tactics, String> {
    let settings = Settings::from_json(settings)?;
    fetch_tactics(&settings)
}

fn compartment32(text: &str, what: &str) -> Result<[u8; 32], String> {
    ferrox_core::b64::decode(text.as_bytes())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("psiphon broker: {what} is not 32 base64 bytes"))
}

/// Create the local offer unless the caller supplied SDP.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn webrtc_offer(
    address: IpAddr,
    stun_servers: &[String],
    disable_stun: bool,
    disable_ipv6_ice: bool,
    disable_inbound: bool,
    debug: bool,
    sdp: Option<&str>,
    timeout: std::time::Duration,
    dns_config: &crate::psiphon_dns::Config,
    unreliable: bool,
    media_secret: Option<[u8; 32]>,
) -> Result<(Option<crate::psiphon_webrtc::WebRtc>, String), String> {
    if let Some(sdp) = sdp {
        return Ok((None, sdp.to_owned()));
    }
    let (webrtc, sdp) = crate::psiphon_webrtc::WebRtc::offer(
        address,
        stun_servers,
        disable_stun,
        disable_ipv6_ice,
        disable_inbound,
        debug,
        timeout,
        dns_config,
        unreliable,
        media_secret,
    )?;
    Ok((Some(webrtc), sdp))
}

/// Apply the broker's answer and open the channel.
fn webrtc_conduit(
    webrtc: &mut crate::psiphon_webrtc::WebRtc,
    offer: &crate::psiphon_broker::Offer,
    timeout: std::time::Duration,
) -> Result<(), String> {
    if offer.answer_sdp.is_empty() {
        return Ok(());
    }
    webrtc.answer(&offer.answer_sdp)?;
    webrtc.await_channel(timeout)
}

/// Send a client offer to the first broker the tactics payload names.
#[allow(clippy::too_many_lines)]
pub(crate) fn broker_offer(
    settings: Option<&Json>,
    sdp: Option<&str>,
) -> Result<crate::psiphon_broker::Offer, String> {
    let settings = Settings::from_json(settings)?;
    if settings.disable_tactics {
        return Err(
            "psiphon: DisableTactics is set and no embedded tactics are bundled".to_owned(),
        );
    }
    if settings.proxy.is_some() && sdp.is_none() {
        eprintln!("psiphon broker: generated WebRTC uses direct UDP; the proxy carries only broker requests");
    }
    let servers = load_tactics_entries(&settings)?;
    let session_id = hex(&random::<16>());
    let tactics = fetch_tactics_from(&settings, &servers, &session_id, None)?;
    let personal: [u8; 32] = compartment32(&settings.compartment, "personal compartment")?;
    let server = servers
        .iter()
        .find(|server| server.inproxy.is_some())
        .ok_or_else(|| "psiphon broker: no in-proxy destination".to_owned())?;
    let destination = server
        .inproxy
        .as_ref()
        .ok_or_else(|| "psiphon broker: no in-proxy destination".to_owned())?;
    let configured_compartments = configured_inproxy_compartments(&settings);
    let compartments: Vec<[u8; 32]> = if configured_compartments.is_empty() {
        tactics
            .compartments
            .iter()
            .map(|compartment| compartment32(compartment, "tactics compartment"))
            .collect::<Result<_, _>>()?
    } else {
        configured_compartments
            .iter()
            .map(|compartment| compartment32(compartment, "configured compartment"))
            .collect::<Result<_, _>>()?
    };
    let (compartments, personal) = match settings.conduit_mode {
        ConduitMode::Public => (compartments, Vec::new()),
        ConduitMode::Shirokhorshid | ConduitMode::Auto => (Vec::new(), vec![personal]),
    };
    // The offer's own compartment picks the broker order, so the pair the proxy derives is the one this dial used.
    let configured =
        configured_inproxy_brokers(&settings, settings.conduit_mode != ConduitMode::Public);
    let mut brokers = if configured.is_empty() {
        tactics.brokers.clone()
    } else {
        configured
    };
    if let Some(compartment) = personal.first() {
        let max = count_field(
            settings.raw.as_ref(),
            "InproxyPersonalPairingMaxBrokerSpecCount",
            3,
        );
        brokers = order_personal_brokers(brokers, compartment, max);
    } else {
        shuffle_brokers(&mut brokers);
    }
    let broker = brokers
        .first()
        .ok_or_else(|| "psiphon broker: no broker".to_owned())?;
    let identity = Identity {
        session_id: &session_id,
        authorizations: &settings.authorizations,
        sponsor: &settings.sponsor,
        propagation: &settings.propagation,
        platform: &settings.platform,
        version: &settings.client_version,
        egress_region: settings.region.as_deref(),
        device_region: settings.device_region.as_deref(),
        device_location: settings.device_location.as_deref(),
        client_features: &settings.client_features,
        split_tunnel: settings.split_tunnel_own_region,
        split_tunnel_regions: &settings.split_tunnel_regions,
        api_encoding: settings.api_encoding,
        api_protocol: settings.api_protocol,
        compress_tactics: settings.compress_tactics,
        disable_api: settings.disable_api,
        ssh_algorithms: settings.ssh_algorithms.as_ref(),
    };
    let fronts = broker_fronts(broker);
    if fronts.is_empty() {
        return Err("psiphon broker: no fronting host".to_owned());
    }
    let mut why = String::new();
    for front in &fronts {
        let timeout = settings.ready.max(std::time::Duration::from_secs(20));
        let provider = front.provider_id.as_deref().unwrap_or("");
        let max_request = settings
            .inproxy_front_timeouts
            .iter()
            .find(|(known, _)| known == provider)
            .map(|(_, timeout)| *timeout)
            .filter(|timeout| !timeout.is_zero());
        let offer_timeout = max_request.map_or(settings.inproxy_offer_timeout, |max| {
            settings.inproxy_offer_timeout.min(max)
        });
        let offer_personal_timeout = max_request
            .map_or(settings.inproxy_offer_personal_timeout, |max| {
                settings.inproxy_offer_personal_timeout.min(max)
            });
        let mut client = match crate::psiphon_broker::Client::connect(
            crate::psiphon_broker::Broker {
                public_key: broker.public_key.clone(),
                root_secret: broker.root_secret.clone(),
            },
            front,
            settings.ready,
            settings.proxy.as_ref(),
            &settings.meek_headers,
            &settings.dns,
            offer_timeout,
            offer_personal_timeout,
            settings.inproxy_relay_timeout,
        ) {
            Ok(client) => client,
            Err(error) => {
                why = error;
                continue;
            }
        };
        let offer_secret = crate::psiphon_ssh::random::<32>();
        let media_secret = coin(settings.inproxy_media_streams).then_some(offer_secret);
        let (mut webrtc, generated) = webrtc_offer(
            server.address,
            &inproxy_stun_servers(&settings, &tactics),
            settings.inproxy_disable_stun,
            settings.inproxy_disable_ipv6_ice,
            settings.inproxy_disable_inbound_mobile && settings.inproxy_network_type == "MOBILE",
            settings.inproxy_debug,
            sdp,
            timeout,
            &settings.dns,
            server.inproxy.as_ref().is_some_and(inproxy_uses_quic),
            media_secret,
        )?;
        let nat_deadline = Instant::now()
            + settings
                .inproxy_discover_nat_timeout
                .mul_f64(settings.latency.multiplier())
                .min(Duration::from_secs(600))
                .min(timeout);
        if coin(settings.inproxy_discover_nat) {
            if let Some(nat) = crate::psiphon_webrtc::discover_nat_type(
                &inproxy_stun_servers_rfc5780(&settings, &tactics),
                server.address,
                nat_deadline,
                &settings.dns,
            ) {
                client.set_nat_type(nat);
            }
        }
        let shaping = if media_secret.is_some() {
            coin(settings.inproxy_media_traffic_shaping)
                .then(|| settings.inproxy_media_traffic_shaping_parameters.clone())
        } else {
            coin(settings.inproxy_traffic_shaping)
                .then(|| settings.inproxy_traffic_shaping_parameters.clone())
        };
        if let Some(parameters) = shaping.as_ref() {
            if let Some(webrtc) = webrtc.as_mut() {
                webrtc.set_traffic_shaping(parameters.clone(), offer_secret);
            }
        }
        let offer_settings = crate::psiphon_broker::OfferSettings {
            secret: offer_secret,
            traffic_shaping: shaping,
            use_media_streams: crate::psiphon_webrtc::offers_media(&generated),
        };
        match client.client_offer(
            destination,
            &compartments,
            &personal,
            &generated,
            &crate::psiphon_broker::Metrics::from_identity(&identity),
            &offer_settings,
        ) {
            Ok(offer) => {
                if let Some(webrtc) = webrtc.as_mut() {
                    if let Err(error) =
                        webrtc_conduit(webrtc, &offer, settings.inproxy_await_ready_timeout)
                    {
                        why = error;
                        continue;
                    }
                }
                return Ok(offer);
            }
            Err(error) => why = error,
        }
    }
    Err(why)
}

/// Configuration overrides win over tactics, and the client list over the generic one.
fn inproxy_stun_servers(
    settings: &Settings,
    tactics: &crate::psiphon_tactics::Tactics,
) -> Vec<String> {
    let mut stun = tactics.stun_servers.clone();
    if !settings.inproxy_stun.basic.is_empty() {
        stun.basic.clone_from(&settings.inproxy_stun.basic);
    }
    if !settings.inproxy_stun.rfc5780.is_empty() {
        stun.rfc5780.clone_from(&settings.inproxy_stun.rfc5780);
    }
    if stun.basic.is_empty() {
        stun.basic = stun.rfc5780;
    }
    stun.basic
}

/// The RFC 5780 list used only for NAT discovery, never for ICE.
fn inproxy_stun_servers_rfc5780(
    settings: &Settings,
    tactics: &crate::psiphon_tactics::Tactics,
) -> Vec<String> {
    let mut stun = tactics.stun_servers.clone();
    if !settings.inproxy_stun.rfc5780.is_empty() {
        stun.rfc5780.clone_from(&settings.inproxy_stun.rfc5780);
    }
    stun.rfc5780
}

/// Configured broker specs win over tactics; the personal-pairing list wins in that mode.
fn configured_inproxy_brokers(
    settings: &Settings,
    personal_pairing: bool,
) -> Vec<crate::psiphon_tactics::Broker> {
    let raw = settings.raw.as_ref();
    let keys: &[&str] = if personal_pairing {
        &[
            "InproxyClientPersonalPairingBrokerSpecs",
            "InproxyPersonalPairingBrokerSpecs",
            "InproxyClientBrokerSpecs",
            "InproxyBrokerSpecs",
        ]
    } else {
        &["InproxyClientBrokerSpecs", "InproxyBrokerSpecs"]
    };
    keys.iter()
        .find_map(|key| {
            let brokers = crate::psiphon_tactics::brokers_from(raw.and_then(|raw| raw.get(key)));
            (!brokers.is_empty()).then_some(brokers)
        })
        .unwrap_or_default()
}

/// The configured common compartment IDs win over tactics.
fn configured_inproxy_compartments(settings: &Settings) -> Vec<String> {
    crate::psiphon_tactics::compartments_from(
        settings
            .raw
            .as_ref()
            .and_then(|raw| raw.get("InproxyCommonCompartmentIDs")),
    )
}

/// The reference's seeded stream: `ChaCha20` keyed with the whole compartment ID at counter zero, read eight bytes big-endian per `math/rand` draw.
