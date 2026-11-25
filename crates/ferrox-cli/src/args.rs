//! The command line the release package documents. Parsing is deliberately
//! separate from doing: a bad invocation must refuse before a running lane is
//! touched, and it must say what is missing.

use std::process::exit;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Serve,
    Down,
    Status,
    Ports,
    Tun,
    Login,
    Logout,
    Locations,
    Location,
    Version,
    Supervise,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outbound {
    Foxy,
    Veepn,
    Psiphon,
    Vless,
    Vmess,
    Trojan,
    Ss,
    Config,
}

#[derive(Debug, Default)]
pub struct Psiphon {
    pub bin: String,
    pub dir: String,
    pub listen: String,
    pub http: String,
    pub region: String,
    pub shape: String,
    pub ready: String,
    pub base: String,
    pub entries: String,
    pub split: bool,
    pub split_regions: String,
    pub user: String,
    pub pass: String,
    pub pool: String,
    pub workers: String,
    pub aggressive: Option<bool>,
    pub features: String,
    pub latency: String,
    pub cdn_profile: String,
    pub geoip: String,
    pub reject_censored: bool,
    pub reject_countries: String,
    pub compartment: String,
    pub disable_timeouts: bool,
    pub dns_alternate: String,
    pub device_location: String,
    pub device_region: String,
    pub network_id: String,
    pub additional_params: String,
    pub establish_timeout: String,
    pub emit_bytes: bool,
    pub conduit_mode: String,
    pub conduit_timeout: String,
    pub share: bool,
    pub server_lists: String,
    pub osl: String,
    pub entry_key: String,
    pub list_key: String,
    pub exchange_key: String,
    pub cdn_ips: String,
    pub cdn_sni: String,
    pub cdn_sets: String,
    pub unsafe_alerts: bool,
    pub location_precision: String,
    pub share_port: String,
    pub share_http: String,
}

#[derive(Debug)]
pub struct Options {
    pub action: Action,
    pub outbound: Option<Outbound>,
    pub config_file: String,
    pub vless: String,
    pub vmess: String,
    pub vmess_id: String,
    pub vmess_network: String,
    pub trojan: String,
    pub ss: String,
    pub ss_method: String,
    pub email: String,
    pub password: String,
    pub code: String,
    pub country: String,
    pub country_set: bool,
    pub city: String,
    pub city_set: bool,
    pub carrier: String,
    pub carrier_set: bool,
    pub fxa_user_agent: String,
    pub upstream: String,
    pub exclude_domains: String,
    pub exclude_ports: String,
    pub region: String,
    pub veepn_domains: String,
    pub veepn_udid: String,
    pub psiphon: Psiphon,
    pub fronts: String,
    pub fronts_set: bool,
    pub socks: u16,
    pub http: u16,
    pub mixed: u16,
    pub socks_set: bool,
    pub http_set: bool,
    pub mixed_set: bool,
    pub instance: Option<String>,
    pub all: bool,
    pub vpn: bool,
    pub vpn_proxy: bool,
    pub vpn_engine: String,
    pub vpn_engine_set: bool,
    pub vpn_ipv6: bool,
    pub vpn_mtu: u16,
    pub vpn_name: String,
    pub vpn_dns: String,
    pub vpn_tuned: bool,
    pub warp: bool,
    pub warp_mode: String,
    pub warp_mode_set: bool,
    pub warp_identity: String,
    pub udp_via: String,
    pub browser: bool,
    pub debug: bool,
    pub ping: bool,
    pub loc_filter: String,
    pub loc_country: String,
    pub loc_city: String,
    pub supervise_pid: Option<u32>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            action: Action::Up,
            outbound: None,
            config_file: String::new(),
            vless: String::new(),
            vmess: String::new(),
            vmess_id: String::new(),
            vmess_network: "tcp".to_owned(),
            trojan: String::new(),
            ss: String::new(),
            ss_method: "aes-256-gcm".to_owned(),
            email: String::new(),
            password: String::new(),
            code: String::new(),
            country: "US".to_owned(),
            country_set: false,
            city: String::new(),
            city_set: false,
            carrier: "auto".to_owned(),
            carrier_set: false,
            fxa_user_agent: String::new(),
            upstream: String::new(),
            exclude_domains: String::new(),
            exclude_ports: String::new(),
            region: String::new(),
            veepn_domains: String::new(),
            veepn_udid: String::new(),
            psiphon: Psiphon::default(),
            fronts: "socks,http,mixed".to_owned(),
            fronts_set: false,
            socks: 10808,
            http: 8080,
            mixed: 10809,
            socks_set: false,
            http_set: false,
            mixed_set: false,
            instance: None,
            all: false,
            vpn: false,
            vpn_proxy: false,
            vpn_engine: "native".to_owned(),
            vpn_engine_set: false,
            vpn_ipv6: false,
            vpn_mtu: 1500,
            vpn_name: String::new(),
            vpn_dns: "1.1.1.1".to_owned(),
            vpn_tuned: false,
            warp: false,
            warp_mode: "auto".to_owned(),
            warp_mode_set: false,
            warp_identity: String::new(),
            udp_via: String::new(),
            browser: false,
            debug: false,
            ping: false,
            loc_filter: String::new(),
            loc_country: String::new(),
            loc_city: String::new(),
            supervise_pid: None,
        }
    }
}

fn env_port(name: &str, strict: bool) -> Option<u16> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => None,
        Err(error) if strict => die(&format!(
            "{name} is not readable as a port: {error}; nothing was started."
        )),
        Err(_) => None,
        Ok(value) => match value.parse::<u16>() {
            Ok(port) if port != 0 => Some(port),
            _ if strict => die(&format!(
                "{name} wants a port between 1 and 65535, got '{value}'; nothing was started."
            )),
            _ => None,
        },
    }
}

fn apply_env_port(name: &str, strict: bool, value: &mut u16, set: &mut bool) {
    if *set {
        return;
    }
    if let Some(port) = env_port(name, strict) {
        *value = port;
        *set = true;
    }
}

fn apply_env_ports(options: &mut Options) {
    let strict = matches!(
        options.action,
        Action::Up | Action::Serve | Action::Tun | Action::Supervise
    );
    apply_env_port(
        "FOXY_SOCKS_PORT",
        strict,
        &mut options.socks,
        &mut options.socks_set,
    );
    apply_env_port(
        "FOXY_HTTP_PORT",
        strict,
        &mut options.http,
        &mut options.http_set,
    );
    apply_env_port(
        "FOXY_MIXED_PORT",
        strict,
        &mut options.mixed,
        &mut options.mixed_set,
    );
}

pub fn die(message: &str) -> ! {
    eprintln!("ferrox-cli: {message}");
    exit(1)
}

fn need<'a>(args: &'a [String], index: usize, flag: &str, hint: &str) -> &'a str {
    args.get(index + 1).map_or_else(
        || die(&format!("--{flag} wants {hint}; nothing was started.")),
        String::as_str,
    )
}

fn digits(args: &[String], index: usize, flag: &str, hint: &str, minimum: u64) -> String {
    let value = need(args, index, flag, hint);
    match value.parse::<u64>() {
        Ok(number) if number >= minimum => value.to_owned(),
        _ => die(&format!(
            "--{flag} wants {hint}, got '{value}'; nothing was started."
        )),
    }
}

fn port(flag: &str, value: &str) -> u16 {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => port,
        Ok(_) => die(&format!(
            "--{flag} wants a port between 1 and 65535, got '{value}'; nothing was started."
        )),
        Err(_) => die(&format!(
            "--{flag} wants a port number between 1 and 65535, got '{value}'; nothing was started."
        )),
    }
}

/// The engine names the app understands, with the reference's aliases folded onto
/// the four stacks it serves.
fn vpn_engine(flag: &str, value: &str) -> String {
    match value {
        "native" | "hev" | "tun2socks" | "loopback" => "native",
        "userspace" | "smoltcp" | "gvisor" => "userspace",
        "system" => "system",
        "hybrid" | "mixed" => "hybrid",
        _ => die(&format!(
            "--{flag} wants native, userspace, system or hybrid (aliases: hev, tun2socks, smoltcp, gvisor, mixed), got '{value}'; nothing was started."
        )),
    }
    .to_owned()
}

fn vpn_mtu(value: &str) -> u16 {
    match value.parse::<u16>() {
        Ok(mtu) if (576..=9000).contains(&mtu) => mtu,
        _ => die(&format!(
            "--vpn-mtu wants an MTU between 576 and 9000, got '{value}'; nothing was started."
        )),
    }
}

fn vpn_name(value: &str) -> String {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        die(&format!(
            "--vpn-name wants 1-32 letters, digits, - _ or ., got '{value}'; nothing was started."
        ));
    }
    value.to_owned()
}

fn vpn_dns(value: &str) -> String {
    if value == "none" {
        return value.to_owned();
    }
    if value.parse::<std::net::IpAddr>().is_err() {
        die(&format!(
            "--vpn-dns wants an address or 'none', got '{value}'; nothing was started."
        ));
    }
    value.to_owned()
}

/// The WARP carrier modes the app serves, with the aliases its own reader accepts.
fn warp_mode(value: &str) -> String {
    match value {
        "auto" | "wireguard" | "wg" | "masque" | "gool" | "wg-over-masque" | "gool-classic"
        | "wiw" | "warp-in-warp" | "mim" | "masque-in-masque" => value,
        _ => die(&format!(
            "--warp-mode wants auto, wireguard, masque, gool (wg-over-masque), gool-classic (warp-in-warp) or mim (masque-in-masque), got '{value}'; nothing was started."
        )),
    }
    .to_owned()
}

fn udp_via(value: &str) -> String {
    match value {
        "foxy" | "warp" | "direct" | "block" => value,
        "psiphon" | "psiphon-cdn" => value,
        _ => die(&format!(
            "--udp-via wants foxy, warp, psiphon, psiphon-cdn, direct or block, got '{value}'; nothing was started."
        )),
    }
    .to_owned()
}

pub fn parse() -> Options {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "up" => {
                options.action = Action::Up;
                index += 1;
            }
            "serve" => {
                options.action = Action::Serve;
                index += 1;
            }
            "down" => {
                options.action = Action::Down;
                index += 1;
            }
            "status" => {
                options.action = Action::Status;
                index += 1;
            }
            "ports" => {
                options.action = Action::Ports;
                index += 1;
            }
            "tun" => {
                options.action = Action::Tun;
                index += 1;
            }
            "login" => {
                options.action = Action::Login;
                index += 1;
            }
            "logout" => {
                options.action = Action::Logout;
                index += 1;
            }
            "locations" => {
                options.action = Action::Locations;
                index += 1;
                if index < args.len() && args[index] == "--ping" {
                    options.ping = true;
                    index += 1;
                }
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_filter = args[index].clone();
                    index += 1;
                }
            }
            "location" => {
                options.action = Action::Location;
                index += 1;
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_country = args[index].clone();
                    index += 1;
                }
                if index < args.len() && !args[index].starts_with('-') {
                    options.loc_city = args[index].clone();
                    index += 1;
                }
            }
            "version" => {
                options.action = Action::Version;
                index += 1;
            }
            "__supervise" => {
                options.action = Action::Supervise;
                index += 1;
                if index < args.len() {
                    options.supervise_pid = args[index].parse().ok();
                    index += 1;
                }
            }
            "--foxy" => {
                options.outbound = Some(Outbound::Foxy);
                index += 1;
            }
            "--veepn" => {
                options.outbound = Some(Outbound::Veepn);
                index += 1;
            }
            "--psiphon" => {
                options.outbound = Some(Outbound::Psiphon);
                index += 1;
            }
            "--psiphon-cdn" | "--psiphon-fronted" => {
                options.outbound = Some(Outbound::Psiphon);
                options.psiphon.cdn_profile = "fronted".to_owned();
                options.psiphon.aggressive = Some(true);
                options.psiphon.shape = "cdn".to_owned();
                index += 1;
            }
            "--psiphon-bin" => {
                options.psiphon.bin =
                    need(&args, index, "psiphon-bin", "the psiphon-tunnel-core path").to_owned();
                index += 2;
            }
            "--psiphon-region" => {
                options.psiphon.region =
                    need(&args, index, "psiphon-region", "a two-letter region").to_owned();
                index += 2;
            }
            "--psiphon-mode" => {
                let value = need(&args, index, "psiphon-mode", "auto, cdn, conduit or direct");
                if !matches!(value, "auto" | "cdn" | "conduit" | "direct") {
                    die(&format!(
                        "--psiphon-mode wants auto, cdn, conduit or direct, got '{value}'; nothing was started."
                    ));
                }
                options.psiphon.shape = value.to_owned();
                index += 2;
            }
            "--psiphon-listen" => {
                options.psiphon.listen =
                    need(&args, index, "psiphon-listen", "an address and port").to_owned();
                index += 2;
            }
            "--psiphon-http" => {
                options.psiphon.http =
                    need(&args, index, "psiphon-http", "an address and port, or off").to_owned();
                index += 2;
            }
            "--psiphon-dir" => {
                options.psiphon.dir =
                    need(&args, index, "psiphon-dir", "a data directory").to_owned();
                index += 2;
            }
            "--psiphon-ready" => {
                options.psiphon.ready =
                    digits(&args, index, "psiphon-ready", "a number of seconds", 0);
                index += 2;
            }
            "--psiphon-base" => {
                options.psiphon.base =
                    need(&args, index, "psiphon-base", "a JSON config path").to_owned();
                index += 2;
            }
            "--psiphon-entries" => {
                options.psiphon.entries =
                    need(&args, index, "psiphon-entries", "a server-entry file").to_owned();
                index += 2;
            }
            "--psiphon-split" => {
                options.psiphon.split = true;
                index += 1;
            }
            "--psiphon-split-region" => {
                options.psiphon.split_regions =
                    need(&args, index, "psiphon-split-region", "country codes").to_owned();
                index += 2;
            }
            "--psiphon-user" => {
                options.psiphon.user = need(&args, index, "psiphon-user", "a username").to_owned();
                index += 2;
            }
            "--psiphon-pass" => {
                options.psiphon.pass = need(&args, index, "psiphon-pass", "a password").to_owned();
                index += 2;
            }
            "--psiphon-pool" => {
                options.psiphon.pool = digits(&args, index, "psiphon-pool", "a tunnel count", 0);
                index += 2;
            }
            "--psiphon-workers" => {
                options.psiphon.workers =
                    digits(&args, index, "psiphon-workers", "a worker count", 0);
                index += 2;
            }
            "--psiphon-aggressive" => {
                options.psiphon.aggressive = Some(true);
                index += 1;
            }
            "--psiphon-no-aggressive" => {
                options.psiphon.aggressive = Some(false);
                index += 1;
            }
            "--psiphon-conduit-mode" => {
                let value = need(
                    &args,
                    index,
                    "psiphon-conduit-mode",
                    "auto, private or public",
                );
                if !matches!(value, "auto" | "public" | "private") {
                    die(&format!(
                        "--psiphon-conduit-mode wants auto, private or public, got '{value}'; nothing was started."
                    ));
                }
                options.psiphon.conduit_mode = value.to_owned();
                index += 2;
            }
            "--psiphon-conduit-timeout" => {
                options.psiphon.conduit_timeout = digits(
                    &args,
                    index,
                    "psiphon-conduit-timeout",
                    "seconds, at least 1",
                    1,
                );
                index += 2;
            }
            "--psiphon-share" => {
                options.psiphon.share = true;
                index += 1;
            }
            "--psiphon-server-list" => {
                options.psiphon.server_lists =
                    need(&args, index, "psiphon-server-list", "server-list URLs").to_owned();
                index += 2;
            }
            "--psiphon-osl" => {
                options.psiphon.osl = need(
                    &args,
                    index,
                    "psiphon-osl",
                    "obfuscated server-list root URLs",
                )
                .to_owned();
                index += 2;
            }
            "--psiphon-entry-key" => {
                options.psiphon.entry_key = need(
                    &args,
                    index,
                    "psiphon-entry-key",
                    "a server-entry public key",
                )
                .to_owned();
                index += 2;
            }
            "--psiphon-list-key" => {
                options.psiphon.list_key =
                    need(&args, index, "psiphon-list-key", "a list publisher key").to_owned();
                index += 2;
            }
            "--psiphon-exchange-key" => {
                options.psiphon.exchange_key = need(
                    &args,
                    index,
                    "psiphon-exchange-key",
                    "an exchange obfuscation key",
                )
                .to_owned();
                index += 2;
            }
            "--psiphon-feature" => {
                options.psiphon.features =
                    need(&args, index, "psiphon-feature", "client features").to_owned();
                index += 2;
            }
            "--psiphon-latency" => {
                options.psiphon.latency = need(
                    &args,
                    index,
                    "psiphon-latency",
                    "a multiplier of at least 1",
                )
                .to_owned();
                index += 2;
            }
            "--psiphon-disable-timeouts" => {
                options.psiphon.disable_timeouts = true;
                index += 1;
            }
            "--psiphon-cdn-profile" => {
                let value = need(
                    &args,
                    index,
                    "psiphon-cdn-profile",
                    "fronted, legacy, android or off",
                );
                if !matches!(value, "fronted" | "legacy" | "android" | "off") {
                    die(&format!(
                        "--psiphon-cdn-profile wants fronted, legacy, android or off, got '{value}'; nothing was started."
                    ));
                }
                options.psiphon.cdn_profile = value.to_owned();
                index += 2;
            }
            "--psiphon-cdn-ip" => {
                options.psiphon.cdn_ips =
                    need(&args, index, "psiphon-cdn-ip", "CDN edge addresses").to_owned();
                index += 2;
            }
            "--psiphon-cdn-sni" => {
                options.psiphon.cdn_sni =
                    need(&args, index, "psiphon-cdn-sni", "CDN edge names").to_owned();
                index += 2;
            }
            "--psiphon-cdn-set" => {
                options.psiphon.cdn_sets =
                    need(&args, index, "psiphon-cdn-set", "built-in CDN set names").to_owned();
                index += 2;
            }
            "--psiphon-unsafe-alerts" => {
                options.psiphon.unsafe_alerts = true;
                index += 1;
            }
            "--psiphon-location-precision" => {
                options.psiphon.location_precision = digits(
                    &args,
                    index,
                    "psiphon-location-precision",
                    "a precision above zero",
                    1,
                );
                index += 2;
            }
            "--psiphon-share-port" => {
                options.psiphon.share_port =
                    digits(&args, index, "psiphon-share-port", "a port", 1);
                options.psiphon.share = true;
                index += 2;
            }
            "--psiphon-share-http" => {
                options.psiphon.share_http =
                    digits(&args, index, "psiphon-share-http", "a port", 1);
                options.psiphon.share = true;
                index += 2;
            }
            "--psiphon-geoip" => {
                options.psiphon.geoip =
                    need(&args, index, "psiphon-geoip", "a MaxMind database").to_owned();
                index += 2;
            }
            "--psiphon-reject-censored" => {
                options.psiphon.reject_censored = true;
                index += 1;
            }
            "--psiphon-reject-country" => {
                options.psiphon.reject_countries =
                    need(&args, index, "psiphon-reject-country", "country codes").to_owned();
                index += 2;
            }
            "--psiphon-compartment" => {
                options.psiphon.compartment =
                    need(&args, index, "psiphon-compartment", "a compartment id").to_owned();
                index += 2;
            }
            "--psiphon-dns" => {
                options.psiphon.dns_alternate =
                    need(&args, index, "psiphon-dns", "resolver addresses").to_owned();
                index += 2;
            }
            "--psiphon-device-location" => {
                options.psiphon.device_location =
                    need(&args, index, "psiphon-device-location", "a geohash").to_owned();
                index += 2;
            }
            "--psiphon-device-region" => {
                options.psiphon.device_region =
                    need(&args, index, "psiphon-device-region", "a two-letter region").to_owned();
                index += 2;
            }
            "--psiphon-network-id" => {
                options.psiphon.network_id =
                    need(&args, index, "psiphon-network-id", "a network id").to_owned();
                index += 2;
            }
            "--psiphon-additional-params" => {
                options.psiphon.additional_params = need(
                    &args,
                    index,
                    "psiphon-additional-params",
                    "base64 parameters",
                )
                .to_owned();
                index += 2;
            }
            "--psiphon-establish-timeout" => {
                options.psiphon.establish_timeout = digits(
                    &args,
                    index,
                    "psiphon-establish-timeout",
                    "seconds, at least 1",
                    1,
                );
                index += 2;
            }
            "--psiphon-emit-bytes" => {
                options.psiphon.emit_bytes = true;
                index += 1;
            }
            "--vless" => {
                options.outbound = Some(Outbound::Vless);
                options.vless = need(&args, index, "vless", "a vless:// share link").to_owned();
                index += 2;
            }
            "--vmess" => {
                options.outbound = Some(Outbound::Vmess);
                options.vmess = need(&args, index, "vmess", "HOST:PORT").to_owned();
                index += 2;
            }
            "--uuid" => {
                options.vmess_id = need(&args, index, "uuid", "the VMess user id").to_owned();
                index += 2;
            }
            "--network" => {
                options.vmess_network = need(&args, index, "network", "tcp or ws").to_owned();
                index += 2;
            }
            "--trojan" => {
                options.outbound = Some(Outbound::Trojan);
                options.trojan = need(&args, index, "trojan", "HOST:PORT").to_owned();
                index += 2;
            }
            "--ss" => {
                options.outbound = Some(Outbound::Ss);
                options.ss = need(&args, index, "ss", "HOST:PORT").to_owned();
                index += 2;
            }
            "--method" => {
                options.ss_method = need(&args, index, "method", "a shadowsocks method").to_owned();
                index += 2;
            }
            "--config" => {
                options.outbound = Some(Outbound::Config);
                options.config_file = need(&args, index, "config", "a JSON config path").to_owned();
                index += 2;
            }
            "--email" => {
                options.email = need(&args, index, "email", "an email address").to_owned();
                index += 2;
            }
            "--browser" => {
                options.browser = true;
                index += 1;
            }
            "--password" => {
                options.password = need(&args, index, "password", "a password").to_owned();
                index += 2;
            }
            "--code" => {
                options.code = need(&args, index, "code", "a two-factor code").to_owned();
                index += 2;
            }
            "--country" => {
                options.country = need(&args, index, "country", "a country code").to_owned();
                options.country_set = true;
                index += 2;
            }
            "--region" => {
                options.region = need(&args, index, "region", "a region id").to_owned();
                index += 2;
            }
            "--domains" => {
                options.veepn_domains =
                    need(&args, index, "domains", "comma-separated origins").to_owned();
                index += 2;
            }
            "--udid" => {
                options.veepn_udid = need(&args, index, "udid", "a device id").to_owned();
                index += 2;
            }
            "--city" => {
                options.city = need(&args, index, "city", "a city code").to_owned();
                options.city_set = true;
                index += 2;
            }
            "--carrier" => {
                let value = need(&args, index, "carrier", "auto, h1, h2 or h3");
                match value {
                    "auto" | "h1" | "h2" | "h3" => options.carrier = value.to_owned(),
                    _ => die(&format!(
                        "--carrier wants auto, h1, h2 or h3, got '{value}'; nothing was started."
                    )),
                }
                options.carrier_set = true;
                index += 2;
            }
            "--fxa-user-agent" => {
                let value = need(
                    &args,
                    index,
                    "fxa-user-agent",
                    "a printable ASCII User-Agent",
                );
                if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
                    die("--fxa-user-agent wants printable ASCII only; nothing was started.");
                }
                let value = value.trim();
                value.clone_into(&mut options.fxa_user_agent);
                index += 2;
            }
            "--upstream" => {
                options.upstream =
                    need(&args, index, "upstream", "an http:// or socks5:// URL").to_owned();
                index += 2;
            }
            "--exclude-domains" => {
                options.exclude_domains = need(
                    &args,
                    index,
                    "exclude-domains",
                    "comma-separated domain suffixes",
                )
                .to_owned();
                index += 2;
            }
            "--exclude-ports" => {
                options.exclude_ports =
                    need(&args, index, "exclude-ports", "comma-separated ports").to_owned();
                index += 2;
            }
            "--fronts" => {
                options.fronts =
                    need(&args, index, "fronts", "a comma-separated front list").to_owned();
                options.fronts_set = true;
                index += 2;
            }
            "--socks" => {
                options.socks = port("socks", need(&args, index, "socks", "a port"));
                options.socks_set = true;
                index += 2;
            }
            "--http" => {
                options.http = port("http", need(&args, index, "http", "a port"));
                options.http_set = true;
                index += 2;
            }
            "--mixed" => {
                options.mixed = port("mixed", need(&args, index, "mixed", "a port"));
                options.mixed_set = true;
                index += 2;
            }
            "--instance" => {
                let value = need(
                    &args,
                    index,
                    "instance",
                    "a name of letters, digits, - or _",
                );
                if !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    die(&format!(
                        "--instance wants letters, digits, - or _, got '{value}'; nothing was started."
                    ));
                }
                if value.len() > 32 {
                    die("an --instance name is at most 32 characters; nothing was started.");
                }
                options.instance = Some(value.to_owned());
                index += 2;
            }
            "--all" => {
                options.all = true;
                index += 1;
            }
            "--vpn" => {
                options.vpn = true;
                index += 1;
            }
            "--vpn-proxy" => {
                options.vpn_proxy = true;
                index += 1;
            }
            "--vpn-engine" | "--tun-engine" => {
                options.vpn_engine = vpn_engine(
                    arg.trim_start_matches('-'),
                    need(
                        &args,
                        index,
                        "vpn-engine",
                        "native, userspace, system or hybrid",
                    ),
                );
                options.vpn_engine_set = true;
                index += 2;
            }
            "--vpn-ipv6" => {
                options.vpn_ipv6 = true;
                options.vpn_tuned = true;
                index += 1;
            }
            "--vpn-mtu" => {
                options.vpn_mtu =
                    vpn_mtu(need(&args, index, "vpn-mtu", "an MTU between 576 and 9000"));
                options.vpn_tuned = true;
                index += 2;
            }
            "--vpn-name" => {
                options.vpn_name = vpn_name(need(&args, index, "vpn-name", "a device name"));
                options.vpn_tuned = true;
                index += 2;
            }
            "--vpn-dns" => {
                options.vpn_dns = vpn_dns(need(&args, index, "vpn-dns", "an address or 'none'"));
                options.vpn_tuned = true;
                index += 2;
            }
            "--warp" => {
                options.warp = true;
                index += 1;
            }
            "--warp-mode" => {
                options.warp_mode = warp_mode(need(
                    &args,
                    index,
                    "warp-mode",
                    "auto, wireguard, masque, gool, gool-classic or mim",
                ));
                options.warp_mode_set = true;
                index += 2;
            }
            "--warp-identity" => {
                options.warp_identity = need(
                    &args,
                    index,
                    "warp-identity",
                    "a path for the WARP identity",
                )
                .to_owned();
                index += 2;
            }
            "--udp-via" => {
                options.udp_via = udp_via(need(
                    &args,
                    index,
                    "udp-via",
                    "foxy, warp, psiphon, psiphon-cdn, direct or block",
                ));
                index += 2;
            }
            "--debug" => {
                options.debug = true;
                index += 1;
            }
            "--ping" => {
                options.ping = true;
                index += 1;
            }
            "--tun" => {
                options.vpn = true;
                index += 1;
            }
            "-h" | "--help" => {
                usage();
            }
            "-V" | "--version" => {
                options.action = Action::Version;
                index += 1;
            }
            other if !other.starts_with('-') && options.action == Action::Locations => {
                options.loc_filter = other.to_owned();
                index += 1;
            }
            other if !other.starts_with('-') && options.action == Action::Location => {
                if options.loc_country.is_empty() {
                    options.loc_country = other.to_owned();
                } else if options.loc_city.is_empty() {
                    options.loc_city = other.to_owned();
                } else {
                    die(&format!("unknown argument: {other} (see --help)"));
                }
                index += 1;
            }
            other => die(&format!("unknown argument: {other} (see --help)")),
        }
    }

    if options.ping && options.action != Action::Locations {
        die("--ping belongs to 'locations' (ferrox-cli locations --ping); nothing was started.");
    }
    if options.browser && options.action != Action::Login {
        die("--browser belongs to 'login' (ferrox-cli login --browser); nothing was started.");
    }
    if (!options.exclude_domains.is_empty() || !options.exclude_ports.is_empty())
        && options.outbound != Some(Outbound::Foxy)
    {
        die("--exclude-domains and --exclude-ports belong to the foxy lane; nothing was started.");
    }
    if !options.fxa_user_agent.is_empty() && options.outbound != Some(Outbound::Foxy) {
        die("--fxa-user-agent belongs to the foxy lane; nothing was started.");
    }
    if options.all {
        if options.action != Action::Down {
            die("--all belongs to 'down' (ferrox-cli down --all); nothing was started.");
        }
        if options.instance.is_some() {
            die("--all stops every lane, so it takes no --instance; nothing was started.");
        }
    }
    if options.vpn && options.vpn_proxy {
        die("--vpn opens a TUN device and captures the whole host; --vpn-proxy arms the Windows system proxy. Pick one; nothing was started.");
    }
    if options.vpn_engine_set && !options.vpn {
        die("--vpn-engine belongs to --vpn; nothing was started.");
    }
    if options.vpn_tuned && !options.vpn {
        die(
            "--vpn-ipv6, --vpn-mtu, --vpn-name and --vpn-dns belong to --vpn; nothing was started.",
        );
    }
    if options.outbound == Some(Outbound::Psiphon) {
        if options.psiphon.region.is_empty() {
            if !options.region.is_empty() {
                options.psiphon.region = options.region.clone();
            } else if options.country_set {
                options.psiphon.region = options.country.clone();
            }
        }
        if options.psiphon.shape.is_empty() {
            options.psiphon.shape = "auto".to_owned();
        }
        if options.psiphon.aggressive.is_none() {
            options.psiphon.aggressive = Some(true);
        }
        if options.psiphon.dns_alternate.is_empty() {
            options.psiphon.dns_alternate = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4".to_owned();
        }
    }
    if options.udp_via == "psiphon" || options.udp_via == "psiphon-cdn" {
        if options.psiphon.shape.is_empty() {
            options.psiphon.shape = "auto".to_owned();
        }
        if options.udp_via == "psiphon-cdn" {
            if options.psiphon.shape == "auto" {
                options.psiphon.shape = "cdn".to_owned();
            }
            if options.psiphon.cdn_profile.is_empty() {
                options.psiphon.cdn_profile = "fronted".to_owned();
            }
            if options.psiphon.aggressive.is_none() {
                options.psiphon.aggressive = Some(true);
            }
        }
        if options.psiphon.aggressive.is_none() {
            options.psiphon.aggressive = Some(true);
        }
        if options.psiphon.dns_alternate.is_empty() {
            options.psiphon.dns_alternate = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4".to_owned();
        }
    }
    if options.warp && !matches!(options.outbound, Some(Outbound::Foxy | Outbound::Psiphon)) {
        die("--warp chains the foxy or psiphon lane through WARP (up --foxy --warp, up --psiphon --warp); nothing was started.");
    }
    if !options.udp_via.is_empty()
        && options.udp_via != "foxy"
        && options.outbound != Some(Outbound::Foxy)
    {
        die("--udp-via splits the foxy lane (up --foxy --udp-via ...); nothing was started.");
    }
    if (options.warp_mode_set || !options.warp_identity.is_empty())
        && !options.warp
        && options.udp_via != "warp"
    {
        die("--warp-mode and --warp-identity belong to --warp or --udp-via warp; nothing was started.");
    }
    if options.warp_identity.contains(['\n', '\r']) {
        die("--warp-identity wants a single path; nothing was started.");
    }
    if options.instance.is_some() && (options.vpn || options.vpn_proxy) {
        die(
            "the TUN device and the system proxy are machine-wide: run the instance without --vpn or --vpn-proxy and point the app at its fronts, or capture the host on the unnamed lane; nothing was started.",
        );
    }
    apply_env_ports(&mut options);
    options
}

/// Windows reserves the TUN device for an Administrator and cannot re-execute
/// itself with a usable terminal, so the remedy is named. Unix starts only the
/// app through `sudo` (in `lane::start`), keeping this process and every state
/// file owned by the invoking user.
pub fn require_vpn_admin() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
        // SAFETY: the call reads the current token and allocates nothing the caller owns.
        if unsafe { IsUserAnAdmin() } != 0 {
            return;
        }
        die("--vpn opens a TUN device and needs Administrator: start ferrox-cli from an elevated Windows Terminal (or right-click > Run as administrator); nothing was started.");
    }
    #[cfg(not(windows))]
    {}
}

pub fn usage() -> ! {
    println!(
        "usage: ferrox-cli <command> [options]

commands
  login      save the foxy account once (prompts for the password; --browser
             signs in through a real browser instead)
  logout     stop the lane, then forget the account and its stored session
  locations  list the countries and cities the catalogue publishes
             (--ping measures the handshake to each edge, fastest first);
             --psiphon lists the signed Psiphon server-list regions
  location   remember an exit: location [--foxy|--veepn|--psiphon] CC [CITY]
  up         start the lane in the background, print the port map (default)
  serve      start the lane in this terminal, until Ctrl-C
  down       stop the lane and clear the system proxy it set (--all: every lane)
  status     show the lane (--instance NAME for one of several), then its exit
  ports      print the port map and the settings to type
  tun        the TUN engines and what each one needs
  version    print the release binary's version

first run, then every run:
  ferrox-cli up --foxy --vpn
  ferrox-cli status
  ferrox-cli down

outbound (choose one)
  --foxy                 Foxy lane; account from the credentials file
  --veepn                VeePN lane; anonymous, no account and no server
  --psiphon              native OSSH/SSH lane; no account and no client binary
  --psiphon-cdn          the same lane with CDN fronting and beast mode
  --vless LINK           a vless:// share link (tcp, ws, grpc, httpupgrade, xhttp)
  --vmess HOST:PORT --uuid ID
  --trojan HOST:PORT --password PW
  --ss HOST:PORT --method METHOD --password PW
  --config FILE          any JSON config this binary serves, used verbatim

foxy options
  --email ADDR           Firefox account, else FOXY_EMAIL, else the credentials file
  --password PW          password, else FOXY_PASS
  --browser              with login: sign in through the system browser (no password sent here)
  --code CODE            two-factor code
  --country CC           exit country; default is the remembered one, else US
  --city CODE            city tier inside the country
  --carrier NAME         auto|h1|h2|h3, default auto
  --fxa-user-agent UA    override the pinned desktop Firefox identity for FxA
  --upstream URL         http:// or socks5(h):// hop to reach the edge through
  --warp                 chain the foxy or psiphon carrier through Cloudflare WARP
  --warp-mode MODE       auto (default), wireguard, masque, gool (wg-over-masque),
                         gool-classic (warp-in-warp) or mim (masque-in-masque)
  --warp-identity FILE   the WARP device identity to reuse (default beside the lane)
  --udp-via LANE         foxy (default), warp, psiphon, psiphon-cdn, direct or
                         block; datagrams take a second outbound while TCP stays
                         on foxy
  --exclude-domains LIST domain suffixes that leave the tunnel
  --exclude-ports LIST   destination ports that leave the tunnel

veepn options
  --region CC            exit region id, else the plane picks
  --domains URLS         comma-separated https origins to ask
  --udid ID              the device identity the plane sees

psiphon options (nothing is required: the signed list names the servers)
  --psiphon-region CC    exit region, default the remembered one
  --country CC / --region CC   aliases for --psiphon-region on this lane
  --psiphon-dir DIR      lane state, default $CONF_DIR/psiphon
  --psiphon-listen ADDR  local SOCKS address, default 127.0.0.1:1821
  --psiphon-http ADDR    local HTTP address, or off
  --psiphon-mode MODE    auto, cdn, conduit or direct
  --psiphon-cdn-profile NAME  fronted, legacy, android or off
  --psiphon-aggressive / --psiphon-no-aggressive  the wider establishment race
  --psiphon-conduit-mode MODE  auto, private or public
  --psiphon-compartment ID  the private conduit compartment
  --psiphon-share / --psiphon-share-port N / --psiphon-share-http N
  --psiphon-server-list URLS / --psiphon-osl URLS  remote server-list sources
  --psiphon-list-key KEY / --psiphon-entry-key KEY  signature publishers
  --psiphon-base FILE / --psiphon-entries FILE  a base config and entry list
  --psiphon-ready SECS / --psiphon-establish-timeout SECS
  --psiphon-split / --psiphon-split-region CODES  split-tunnel own or listed regions
  --psiphon-user USER / --psiphon-pass PW  local proxy credentials
  --psiphon-pool N / --psiphon-workers N  tunnel and worker pool sizes
  --psiphon-feature LIST / --psiphon-latency N / --psiphon-disable-timeouts
  --psiphon-cdn-ip LIST / --psiphon-cdn-sni LIST / --psiphon-cdn-set LIST
  --psiphon-unsafe-alerts / --psiphon-location-precision N
  --psiphon-geoip FILE / --psiphon-reject-censored / --psiphon-reject-country LIST
  --psiphon-dns LIST / --psiphon-device-location ID / --psiphon-device-region CC
  --psiphon-network-id ID / --psiphon-additional-params B64 / --psiphon-emit-bytes
  --psiphon-bin FILE     a psiphon-tunnel-core path, if one is used
  --psiphon-exchange-key KEY / --psiphon-conduit-timeout SECS

fronts
  --fronts LIST          socks,http,mixed (default all three)
  --socks PORT           default 10808
  --http PORT            default 8080
  --mixed PORT           default 10809
  --instance NAME        another lane beside the unnamed one
  --all                  with down: stop every lane

vpn (whole-device capture; needs root or Administrator)
  --vpn                  open a TUN device and route the host through the lane
  --tun                  alias for --vpn
  --vpn-engine ENGINE    native (default), userspace, system or hybrid
                         aliases: hev, tun2socks, smoltcp, gvisor, mixed
  --vpn-ipv6             also carry IPv6
  --vpn-mtu N            device MTU, default 1500
  --vpn-name NAME        device name (default ferrox0, or the system utun on macOS)
  --vpn-dns ADDR         resolver that port 53 is sent to, default 1.1.1.1; 'none' leaves it
  --vpn-proxy            the old behaviour: point the Windows system proxy at the fronts
  --debug                keep the lane's dial trace in the log
  -h, --help             this text
  -V, --version          print the release binary's version"
    );
    exit(0)
}
