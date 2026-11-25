//! The lane config the binary is handed. One writer for every outbound, so a
//! share link, an account and a verbatim file all reach the engine the same way.

use std::net::TcpListener;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::args::{Options, Outbound};
use crate::paths::{read_trim, read_trim_checked, write_private, Paths};

#[derive(Clone, Copy, Debug)]
pub struct Ports {
    pub socks: u16,
    pub http: u16,
    pub mixed: u16,
}

/// The TUN inbound `--vpn` adds to a generated config. A user config is served
/// verbatim, so it must carry its own.
#[derive(Clone, Debug)]
pub struct Vpn {
    pub engine: String,
    pub ipv6: bool,
    pub mtu: u16,
    pub name: String,
    pub dns: String,
}

impl Vpn {
    pub fn from_options(options: &Options) -> Self {
        Self {
            engine: options.vpn_engine.clone(),
            ipv6: options.vpn_ipv6,
            mtu: options.vpn_mtu,
            name: options.vpn_name.clone(),
            dns: options.vpn_dns.clone(),
        }
    }

    fn inbound(&self) -> Value {
        let mut inbound = json!({
            "protocol": "tun",
            "tag": "tun-in",
            "stack": self.engine,
            "auto_route": true,
            "mtu": self.mtu,
            "address": if self.ipv6 {
                vec!["198.18.0.1/15", "fdfe:dcba:9876::1/64"]
            } else {
                vec!["198.18.0.1/15"]
            },
        });
        if !self.name.is_empty() {
            inbound["name"] = Value::String(self.name.clone());
        }
        if self.dns != "none" {
            inbound["dns_mode"] = Value::String("hijack".to_owned());
            inbound["dns_address"] = json!([self.dns]);
        }
        inbound
    }
}

/// The hidden loopback front a WARP-chained foxy lane dials; the router sends
/// its flows to the tagged `warp` outbound, so the lane keeps one process and
/// the TUN route guard can pin the WARP edge.
pub const WARP_HOP_TAG: &str = "ferrox-warp-hop";

#[derive(Clone, Debug, Default)]
pub struct Generated {
    pub hidden_socks: Option<u16>,
    pub extra: Vec<(String, Value)>,
    pub rules: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct FoxyAccount {
    pub email: String,
    pub password: String,
}

pub fn fronts(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|front| !front.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn port_of(front: &str, ports: Ports) -> u16 {
    match front {
        "socks" => ports.socks,
        "mixed" => ports.mixed,
        _ => ports.http,
    }
}

fn split_host_port(value: &str, flag: &str) -> Result<(String, u64), String> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(format!("--{flag} wants HOST:PORT, got '{value}'"));
    };
    if host.is_empty() || port.is_empty() {
        return Err(format!("--{flag} wants HOST:PORT, got '{value}'"));
    }
    let port: u64 = port
        .parse()
        .map_err(|_| format!("--{flag} wants HOST:PORT, got '{value}'"))?;
    if port == 0 || port > 65535 {
        return Err(format!(
            "--{flag} wants a port between 1 and 65535, got '{value}'"
        ));
    }
    Ok((host.to_owned(), port))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_domains(raw: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for item in raw.split(',') {
        let mut name = item.trim().to_lowercase().trim_end_matches('.').to_owned();
        if let Some(stripped) = name.strip_prefix("*.") {
            name = stripped.to_owned();
        }
        if let Some(stripped) = name.strip_prefix('.') {
            name = stripped.to_owned();
        }
        if name.is_empty() {
            continue;
        }
        if name.contains('/')
            || name.contains(':')
            || name.contains('*')
            || name.contains("..")
            || name.starts_with('.')
            || name.chars().any(char::is_whitespace)
        {
            return Err(format!(
                "--exclude-domains wants domain suffixes like example.com, got '{}'; nothing was started.",
                item.trim()
            ));
        }
        names.push(name);
    }
    if names.is_empty() {
        return Err(
            "--exclude-domains wants at least one domain suffix; nothing was started.".to_owned(),
        );
    }
    Ok(names)
}

fn split_ports(raw: &str) -> Result<Vec<u16>, String> {
    let mut numbers = Vec::new();
    for item in raw.split(',') {
        let value = item.trim();
        if value.is_empty() {
            continue;
        }
        let Ok(port) = value.parse::<u32>() else {
            return Err(format!(
                "--exclude-ports wants ports 1-65535, got '{value}'; nothing was started."
            ));
        };
        if port == 0 || port > 65535 {
            return Err(format!(
                "--exclude-ports wants ports 1-65535, got '{value}'; nothing was started."
            ));
        }
        numbers.push(port as u16);
    }
    if numbers.is_empty() {
        return Err("--exclude-ports wants at least one port; nothing was started.".to_owned());
    }
    Ok(numbers)
}

pub fn validate_exclusions(options: &Options) -> Result<(), String> {
    if !options.exclude_domains.is_empty() {
        split_domains(&options.exclude_domains)?;
    }
    if !options.exclude_ports.is_empty() {
        split_ports(&options.exclude_ports)?;
    }
    Ok(())
}

pub fn effective_region(options: &Options) -> String {
    let region = if options.region.is_empty() && options.country_set {
        options.country.clone()
    } else {
        options.region.clone()
    };
    region.to_lowercase()
}

pub fn stable_udid(options: &Options, paths: &Paths) -> Result<String, String> {
    if !options.veepn_udid.is_empty() {
        return Ok(options.veepn_udid.clone());
    }
    let file = paths.conf_dir.join("veepn.udid");
    if let Some(value) = read_trim(&file).filter(|value| !value.is_empty()) {
        return Ok(value);
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| format!("cannot mint a device id: {error}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    );
    write_private(&file, &format!("{value}\n"))
        .map_err(|error| format!("cannot save the device id: {error}"))?;
    Ok(value)
}

pub fn load_foxy_location(options: &mut Options, paths: &Paths) {
    if options.country_set {
        return;
    }
    let Some(line) = read_trim(&paths.location_file) else {
        return;
    };
    let mut parts = line.split_whitespace();
    let Some(country) = parts.next() else {
        return;
    };
    options.country = country.to_uppercase();
    if !options.city_set {
        if let Some(city) = parts.next() {
            options.city = city.to_uppercase();
        }
    }
}

pub fn load_veepn_location(options: &mut Options, paths: &Paths) {
    if !options.region.is_empty() || options.country_set {
        return;
    }
    if let Some(line) = read_trim(&paths.veepn_location) {
        options.region = line.trim().to_lowercase();
    }
}

pub fn save_veepn_location(options: &Options, paths: &Paths) -> Result<(), String> {
    let region = effective_region(options);
    if region.is_empty() {
        return Ok(());
    }
    write_private(
        &paths.veepn_location,
        &format!("{}\n", region.to_lowercase()),
    )
    .map_err(|error| format!("cannot remember the exit: {error}"))
}

pub fn load_psiphon_location(options: &mut Options, paths: &Paths) {
    if !options.psiphon.region.is_empty() {
        return;
    }
    if let Some(line) = read_trim(&paths.psiphon_location) {
        if let Some(country) = line.split_whitespace().next() {
            options.psiphon.region = country.to_uppercase();
        }
    }
}

pub fn save_psiphon_location(options: &Options, paths: &Paths) -> Result<(), String> {
    if options.psiphon.region.is_empty() {
        return Ok(());
    }
    write_private(
        &paths.psiphon_location,
        &format!("{} \n", options.psiphon.region.to_uppercase()),
    )
    .map_err(|error| format!("cannot remember the exit: {error}"))
}

pub fn save_foxy_location(options: &Options, paths: &Paths) -> Result<(), String> {
    if options.country.is_empty() {
        return Ok(());
    }
    write_private(
        &paths.location_file,
        &format!(
            "{} {}\n",
            options.country.to_uppercase(),
            options.city.to_uppercase()
        ),
    )
    .map_err(|error| format!("cannot remember the exit: {error}"))
}

pub fn remembered_country(paths: &Paths) -> String {
    read_trim(&paths.location_file)
        .and_then(|line| line.split_whitespace().next().map(str::to_owned))
        .unwrap_or_default()
}

pub fn remembered_city(paths: &Paths) -> String {
    read_trim(&paths.location_file)
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .unwrap_or_default()
}

pub fn build_outbound(
    options: &Options,
    paths: &Paths,
    account: Option<&FoxyAccount>,
) -> Result<Value, String> {
    match options.outbound {
        Some(Outbound::Foxy) => foxy_outbound(options, paths, account),
        Some(Outbound::Veepn) => veepn_outbound(options, paths),
        Some(Outbound::Psiphon) => psiphon_outbound(options, paths, false),
        Some(Outbound::Vless) => vless_outbound(&options.vless),
        Some(Outbound::Vmess) => vmess_outbound(options),
        Some(Outbound::Trojan) => trojan_outbound(options),
        Some(Outbound::Ss) => ss_outbound(options),
        Some(Outbound::Config) | None => Err("no outbound chosen".to_owned()),
    }
}

/// The extra outbounds and routing `--warp` and `--udp-via` add to a generated
/// foxy or psiphon config. The carrier outbound itself is built after this runs,
/// so `options.upstream` already names the hidden front it must dial.
pub fn lane_plan(options: &mut Options, paths: &Paths) -> Result<Generated, String> {
    let mut generated = Generated::default();
    if !matches!(options.outbound, Some(Outbound::Foxy | Outbound::Psiphon)) {
        return Ok(generated);
    }
    let warp_chain = options.warp && options.upstream.is_empty();
    if warp_chain {
        let port = free_loopback_port()?;
        options.upstream = format!("socks5://127.0.0.1:{port}");
        generated.hidden_socks = Some(port);
        generated
            .extra
            .push(("warp".to_owned(), warp_outbound(options, paths)));
        generated.rules.push(json!({
            "type": "field",
            "inboundTag": [WARP_HOP_TAG],
            "outboundTag": "warp",
        }));
    }
    if options.outbound != Some(Outbound::Foxy) {
        return Ok(generated);
    }
    match options.udp_via.as_str() {
        "" | "foxy" => {}
        "warp" => {
            if !warp_chain {
                generated
                    .extra
                    .push(("warp".to_owned(), warp_outbound(options, paths)));
            }
            generated.rules.insert(
                0,
                json!({"type": "field", "network": "udp", "outboundTag": "warp"}),
            );
        }
        "psiphon" | "psiphon-cdn" => {
            let tag = format!("udp-{}", options.udp_via);
            generated
                .extra
                .push((tag.clone(), psiphon_outbound(options, paths, true)?));
            generated.rules.insert(
                0,
                json!({"type": "field", "network": "udp", "outboundTag": tag}),
            );
        }
        "direct" => {
            generated
                .extra
                .push(("udp-direct".to_owned(), json!({"protocol": "freedom"})));
            generated.rules.insert(
                0,
                json!({"type": "field", "network": "udp", "outboundTag": "udp-direct"}),
            );
        }
        "block" => {
            generated
                .extra
                .push(("udp-block".to_owned(), json!({"protocol": "blackhole"})));
            generated.rules.insert(
                0,
                json!({"type": "field", "network": "udp", "outboundTag": "udp-block"}),
            );
        }
        other => return Err(format!("unknown --udp-via lane `{other}`")),
    }
    Ok(generated)
}

fn warp_outbound(options: &Options, paths: &Paths) -> Value {
    let identity = if options.warp_identity.is_empty() {
        paths.warp_identity.to_string_lossy().into_owned()
    } else {
        options.warp_identity.clone()
    };
    json!({
        "protocol": "warp",
        "settings": {
            "identityFile": identity,
            "register": true,
            "mode": options.warp_mode,
        },
    })
}

fn free_loopback_port() -> Result<u16, String> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| format!("cannot reserve a loopback port for the WARP hop: {error}"))
}

fn hidden_inbound(inbound: &Value) -> bool {
    inbound.get("tag").and_then(Value::as_str) == Some(WARP_HOP_TAG)
}

fn foxy_outbound(
    options: &Options,
    paths: &Paths,
    account: Option<&FoxyAccount>,
) -> Result<Value, String> {
    let Some(account) = account else {
        return Err("no foxy account: run 'ferrox-cli login' first".to_owned());
    };
    let mut settings = Map::new();
    settings.insert("email".to_owned(), json!(account.email));
    settings.insert("password".to_owned(), json!(account.password));
    settings.insert("country".to_owned(), json!(options.country.to_uppercase()));
    settings.insert("carrier".to_owned(), json!(options.carrier));
    if !options.fxa_user_agent.is_empty() {
        settings.insert("fxaUserAgent".to_owned(), json!(options.fxa_user_agent));
    }
    if !paths.token_file.as_os_str().is_empty() {
        settings.insert(
            "tokenFile".to_owned(),
            json!(paths.token_file.to_string_lossy()),
        );
    }
    if !options.city.is_empty() {
        settings.insert("city".to_owned(), json!(options.city.to_uppercase()));
    }
    if !options.upstream.is_empty() {
        settings.insert("upstreamProxy".to_owned(), json!(options.upstream));
    }
    if !options.code.is_empty() {
        settings.insert("code".to_owned(), json!(options.code));
    }
    if !options.exclude_domains.is_empty() {
        settings.insert(
            "directDomains".to_owned(),
            json!(split_domains(&options.exclude_domains)?),
        );
    }
    if !options.exclude_ports.is_empty() {
        settings.insert(
            "directPorts".to_owned(),
            json!(split_ports(&options.exclude_ports)?),
        );
    }
    Ok(json!({"protocol": "foxy", "settings": settings}))
}

fn veepn_outbound(options: &Options, paths: &Paths) -> Result<Value, String> {
    let mut settings = Map::new();
    let region = effective_region(options);
    if !region.is_empty() {
        settings.insert("region".to_owned(), json!(region));
    }
    let listed: Vec<String> = options
        .veepn_domains
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect();
    if !listed.is_empty() {
        settings.insert("domains".to_owned(), json!(listed));
    }
    let udid = stable_udid(options, paths)?;
    if !udid.is_empty() {
        settings.insert("udid".to_owned(), json!(udid));
    }
    Ok(json!({"protocol": "veepn", "settings": settings}))
}

fn listed(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn psiphon_outbound(options: &Options, paths: &Paths, udp: bool) -> Result<Value, String> {
    let p = &options.psiphon;
    let mut settings = Map::new();
    let state = if p.dir.is_empty() {
        paths.psiphon_dir.to_string_lossy().into_owned()
    } else {
        p.dir.clone()
    };
    settings.insert("dataRootDirectory".to_owned(), json!(state));
    if !p.bin.is_empty() {
        settings.insert("binary".to_owned(), json!(p.bin));
    }
    if !p.listen.is_empty() {
        settings.insert("listen".to_owned(), json!(p.listen));
    } else if udp {
        settings.insert("listen".to_owned(), json!("127.0.0.1:0"));
    }
    if !p.http.is_empty() {
        settings.insert("httpListen".to_owned(), json!(p.http));
    }
    if !p.region.is_empty() {
        settings.insert("region".to_owned(), json!(p.region));
    }
    match p.shape.as_str() {
        "conduit" => {
            settings.insert("protocolSelection".to_owned(), json!("conduit"));
        }
        "cdn" => {
            settings.insert("protocolSelection".to_owned(), json!("cdn_fronting"));
        }
        "auto" => {
            settings.insert("protocolSelection".to_owned(), json!("auto"));
        }
        _ => {}
    }
    if !p.ready.is_empty() {
        settings.insert(
            "readySeconds".to_owned(),
            json!(p.ready.parse::<u64>().unwrap_or(0)),
        );
    }
    if !p.base.is_empty() {
        settings.insert("baseConfig".to_owned(), json!(p.base));
    }
    if !p.entries.is_empty() {
        settings.insert("serverList".to_owned(), json!(p.entries));
    }
    if !options.upstream.is_empty() {
        settings.insert("upstreamProxy".to_owned(), json!(options.upstream));
    }
    if p.split {
        settings.insert("splitTunnelOwnRegion".to_owned(), json!(true));
    }
    let split_regions = listed(&p.split_regions);
    if !split_regions.is_empty() {
        settings.insert("splitTunnelRegions".to_owned(), json!(split_regions));
    }
    if !p.user.is_empty() {
        settings.insert("localProxyUsername".to_owned(), json!(p.user));
    }
    if !p.pass.is_empty() {
        settings.insert("localProxyPassword".to_owned(), json!(p.pass));
    }
    if !p.pool.is_empty() {
        settings.insert(
            "tunnelPoolSize".to_owned(),
            json!(p.pool.parse::<u64>().unwrap_or(0)),
        );
    }
    if !p.workers.is_empty() {
        settings.insert(
            "ConnectionWorkerPoolSize".to_owned(),
            json!(p.workers.parse::<u64>().unwrap_or(0)),
        );
    }
    if let Some(aggressive) = p.aggressive {
        settings.insert("aggressiveEstablishment".to_owned(), json!(aggressive));
    }
    let mut features = listed(&p.features);
    if p.unsafe_alerts && !features.iter().any(|item| item == "unsafe-traffic-alerts") {
        features.push("unsafe-traffic-alerts".to_owned());
    }
    if !p.location_precision.is_empty()
        && p.location_precision != "0"
        && !features.iter().any(|item| item == "coarse-location")
    {
        features.push("coarse-location".to_owned());
    }
    if !features.is_empty() {
        settings.insert("ClientFeatures".to_owned(), json!(features));
    }
    if !p.latency.is_empty() {
        let latency = p.latency.parse::<f64>().map_err(|_| {
            format!(
                "--psiphon-latency wants a multiplier of at least 1, got '{}'; nothing was started.",
                p.latency
            )
        })?;
        settings.insert("NetworkLatencyMultiplier".to_owned(), json!(latency));
    }
    if !p.cdn_profile.is_empty() {
        settings.insert("cdnProfile".to_owned(), json!(p.cdn_profile));
    }
    for (key, value) in [
        ("cdnIps", &p.cdn_ips),
        ("cdnSni", &p.cdn_sni),
        ("cdnSets", &p.cdn_sets),
    ] {
        let items = listed(value);
        if !items.is_empty() {
            settings.insert(key.to_owned(), json!(items));
        }
    }
    if !p.share_port.is_empty() {
        settings.insert(
            "shareProxyOnNetworkSocksPort".to_owned(),
            json!(p.share_port.parse::<u64>().unwrap_or(0)),
        );
    }
    if !p.share_http.is_empty() {
        settings.insert(
            "shareProxyOnNetworkHttpPort".to_owned(),
            json!(p.share_http.parse::<u64>().unwrap_or(0)),
        );
    }
    if !p.geoip.is_empty() {
        settings.insert("GeoIPDatabasePath".to_owned(), json!(p.geoip));
    }
    if p.reject_censored {
        settings.insert("rejectCensoredProxies".to_owned(), json!(true));
    }
    let reject_countries = listed(&p.reject_countries);
    if !reject_countries.is_empty() {
        settings.insert("rejectProxyCountries".to_owned(), json!(reject_countries));
    }
    if !p.compartment.is_empty() {
        settings.insert("inproxyCompartment".to_owned(), json!(p.compartment));
    }
    if p.disable_timeouts {
        settings.insert("DisableTimeouts".to_owned(), json!(true));
    }
    let dns = listed(&p.dns_alternate);
    if !dns.is_empty() {
        settings.insert("DNSResolverAlternateServers".to_owned(), json!(dns));
    }
    if !p.device_location.is_empty() {
        settings.insert("deviceLocation".to_owned(), json!(p.device_location));
    }
    if !p.device_region.is_empty() {
        settings.insert("deviceRegion".to_owned(), json!(p.device_region));
    }
    if !p.network_id.is_empty() {
        settings.insert("networkId".to_owned(), json!(p.network_id));
    }
    if !p.additional_params.is_empty() {
        settings.insert(
            "additionalParameters".to_owned(),
            json!(p.additional_params),
        );
    }
    if !p.establish_timeout.is_empty() {
        settings.insert(
            "EstablishTunnelTimeoutSeconds".to_owned(),
            json!(p.establish_timeout.parse::<u64>().unwrap_or(0)),
        );
    }
    if p.emit_bytes {
        settings.insert("emitBytesTransferred".to_owned(), json!(true));
    }
    if !p.conduit_mode.is_empty() {
        settings.insert("conduitMode".to_owned(), json!(p.conduit_mode));
    }
    if !p.conduit_timeout.is_empty() {
        settings.insert(
            "conduitTimeout".to_owned(),
            json!(p.conduit_timeout.parse::<u64>().unwrap_or(0)),
        );
    }
    if p.share {
        settings.insert("shareProxyOnNetwork".to_owned(), json!(true));
    }
    for (key, value) in [
        ("serverListURLs", &p.server_lists),
        ("ObfuscatedServerListRootURLs", &p.osl),
    ] {
        let items = listed(value);
        if !items.is_empty() {
            settings.insert(key.to_owned(), json!(items));
        }
    }
    if !p.entry_key.is_empty() {
        settings.insert(
            "ServerEntrySignaturePublicKey".to_owned(),
            json!(p.entry_key),
        );
    }
    if !p.list_key.is_empty() {
        settings.insert("serverListSignaturePublicKey".to_owned(), json!(p.list_key));
    }
    if !p.exchange_key.is_empty() {
        settings.insert("ExchangeObfuscationKey".to_owned(), json!(p.exchange_key));
    }
    Ok(json!({"protocol": "psiphon", "settings": settings}))
}

fn vless_outbound(link: &str) -> Result<Value, String> {
    if !link.starts_with("vless://") {
        return Err(format!(
            "--vless wants a vless:// share link, got '{link}'; nothing was started.\n  example: ferrox-cli up --vless 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=/ws'"
        ));
    }
    let body = &link["vless://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    let (body, query) = body.split_once('?').unwrap_or((body, ""));
    let (uuid, hostport) = body
        .rsplit_once('@')
        .ok_or_else(|| "a vless link is vless://{uuid}@{host}:{port}?{query}".to_owned())?;
    if uuid.is_empty() || hostport.is_empty() {
        return Err("a vless link is vless://{uuid}@{host}:{port}?{query}".to_owned());
    }
    let (host, port) = split_host_port(hostport, "vless")?;

    let mut params: Map<String, Value> = Map::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(percent_decode(key), json!(percent_decode(value)));
    }
    let get = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    let kind = {
        let value = get("type").to_lowercase();
        if value.is_empty() {
            "tcp".to_owned()
        } else {
            value
        }
    };
    let security = {
        let value = get("security").to_lowercase();
        if value.is_empty() {
            "none".to_owned()
        } else {
            value
        }
    };
    let sni = if get("sni").is_empty() {
        get("peer")
    } else {
        get("sni")
    };
    let host_header = get("host");
    let path = get("path");
    let service = get("serviceName");
    let mode = get("mode");
    let flow = get("flow");
    let header_type = get("headerType").to_lowercase();

    let network = match kind.as_str() {
        "raw" => "tcp",
        "websocket" => "ws",
        other => other,
    };
    let mut stream = Map::new();
    stream.insert("network".to_owned(), json!(network));
    match kind.as_str() {
        "ws" | "websocket" => {
            let mut ws = Map::new();
            ws.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                ws.insert("headers".to_owned(), json!({"Host": host_header}));
            }
            stream.insert("wsSettings".to_owned(), Value::Object(ws));
        }
        "grpc" => {
            stream.insert("grpcSettings".to_owned(), json!({"serviceName": service}));
        }
        "httpupgrade" => {
            let mut settings = Map::new();
            settings.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                settings.insert("host".to_owned(), json!(host_header));
            }
            stream.insert("httpupgradeSettings".to_owned(), Value::Object(settings));
        }
        "xhttp" => {
            let mut settings = Map::new();
            settings.insert(
                "path".to_owned(),
                json!(if path.is_empty() { "/" } else { path.as_str() }),
            );
            if !host_header.is_empty() {
                settings.insert("host".to_owned(), json!(host_header));
            }
            if !mode.is_empty() {
                settings.insert("mode".to_owned(), json!(mode));
            }
            stream.insert("xhttpSettings".to_owned(), Value::Object(settings));
        }
        "tcp" | "raw" => match header_type.as_str() {
            "" | "none" => {}
            "http" => {
                let paths: Vec<&str> = path
                    .split(',')
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .collect();
                let path_values: Vec<&str> = if paths.is_empty() { vec!["/"] } else { paths };
                let mut request = Map::new();
                request.insert("version".to_owned(), json!("1.1"));
                request.insert("method".to_owned(), json!("GET"));
                request.insert("path".to_owned(), json!(path_values));
                if !host_header.is_empty() {
                    let hosts: Vec<&str> = host_header
                        .split(',')
                        .map(str::trim)
                        .filter(|host| !host.is_empty())
                        .collect();
                    if !hosts.is_empty() {
                        request.insert("headers".to_owned(), json!({"Host": hosts}));
                    }
                }
                stream.insert(
                    "tcpSettings".to_owned(),
                    json!({"header": {"type": "http", "request": Value::Object(request)}}),
                );
            }
            other => {
                return Err(format!(
                    "`headerType={other}` needs --config: this converter writes none and http"
                ));
            }
        },
        other => {
            return Err(format!(
                "`{other}` needs --config: this converter writes tcp, ws, grpc, httpupgrade and xhttp"
            ));
        }
    }

    match security.as_str() {
        "tls" => {
            let mut tls = Map::new();
            tls.insert(
                "serverName".to_owned(),
                json!(if sni.is_empty() {
                    host.as_str()
                } else {
                    sni.as_str()
                }),
            );
            let mut allow_insecure = false;
            for name in ["allowInsecure", "insecure"] {
                match get(name).to_lowercase().as_str() {
                    "" | "0" | "false" => {}
                    "1" | "true" => allow_insecure = true,
                    other => {
                        return Err(format!(
                            "`{name}={other}` wants 0 or 1; nothing was started."
                        ));
                    }
                }
            }
            tls.insert("allowInsecure".to_owned(), json!(allow_insecure));
            if !get("fp").is_empty() {
                tls.insert("fingerprint".to_owned(), json!(get("fp")));
            }
            if !get("alpn").is_empty() {
                tls.insert(
                    "alpn".to_owned(),
                    json!(get("alpn").split(',').collect::<Vec<_>>()),
                );
            }
            stream.insert("security".to_owned(), json!("tls"));
            stream.insert("tlsSettings".to_owned(), Value::Object(tls));
        }
        "reality" => {
            if get("pbk").is_empty() {
                return Err("a reality link without `pbk` names no server key".to_owned());
            }
            let mut reality = Map::new();
            reality.insert(
                "serverName".to_owned(),
                json!(if sni.is_empty() {
                    host.as_str()
                } else {
                    sni.as_str()
                }),
            );
            reality.insert("publicKey".to_owned(), json!(get("pbk")));
            if !get("sid").is_empty() {
                reality.insert("shortId".to_owned(), json!(get("sid")));
            }
            if !get("fp").is_empty() {
                reality.insert("fingerprint".to_owned(), json!(get("fp")));
            }
            if !get("spx").is_empty() {
                reality.insert("spiderX".to_owned(), json!(get("spx")));
            }
            stream.insert("security".to_owned(), json!("reality"));
            stream.insert("realitySettings".to_owned(), Value::Object(reality));
        }
        "none" | "" => {
            stream.insert("security".to_owned(), json!("none"));
        }
        other => {
            return Err(format!("security `{other}` needs --config"));
        }
    }

    let mut user = Map::new();
    user.insert("id".to_owned(), json!(uuid));
    user.insert("encryption".to_owned(), json!("none"));
    if !flow.is_empty() && flow != "none" {
        user.insert("flow".to_owned(), json!(flow));
    }
    Ok(json!({
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [Value::Object(user)]}]},
        "streamSettings": Value::Object(stream),
    }))
}

fn vmess_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.vmess, "vmess")?;
    if options.vmess_id.is_empty() {
        return Err(
            "--vmess needs --uuid ID as well, e.g. ferrox-cli up --vmess host:443 --uuid UUID"
                .to_owned(),
        );
    }
    let network = match options.vmess_network.as_str() {
        "" | "tcp" | "raw" => "tcp",
        "ws" | "websocket" => "ws",
        other => {
            return Err(format!(
                "`{other}` is not a VMess network here: use tcp or ws, or --config"
            ));
        }
    };
    Ok(json!({
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
            "users": [{"id": options.vmess_id, "security": "auto"}]}]},
        "streamSettings": {"network": network},
    }))
}

fn trojan_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.trojan, "trojan")?;
    if options.password.is_empty() {
        return Err(
            "--trojan needs --password PW as well, e.g. ferrox-cli up --trojan host:443 --password PW"
                .to_owned(),
        );
    }
    Ok(json!({
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": options.password}]},
    }))
}

fn ss_outbound(options: &Options) -> Result<Value, String> {
    let (host, port) = split_host_port(&options.ss, "ss")?;
    if options.password.is_empty() {
        return Err(
            "--ss needs --password PW as well, e.g. ferrox-cli up --ss host:8388 --password PW"
                .to_owned(),
        );
    }
    Ok(json!({
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
            "method": options.ss_method, "password": options.password}]},
    }))
}

pub fn write_config(
    path: &Path,
    outbound: &Value,
    fronts: &str,
    ports: Ports,
    vpn: Option<&Vpn>,
    generated: Option<&Generated>,
) -> Result<(), String> {
    let mut inbounds = Vec::new();
    if let Some(vpn) = vpn {
        inbounds.push(vpn.inbound());
    }
    for front in self::fronts(fronts) {
        let port = match front.as_str() {
            "socks" => ports.socks,
            "http" => ports.http,
            "mixed" => ports.mixed,
            other => return Err(format!("unknown front `{other}`: socks, http, mixed")),
        };
        inbounds.push(json!({"protocol": front, "listen": "127.0.0.1", "port": port}));
    }
    let mut outbounds = vec![outbound.clone()];
    let mut routing = Vec::new();
    if let Some(generated) = generated {
        if let Some(port) = generated.hidden_socks {
            inbounds.push(json!({
                "protocol": "socks",
                "tag": WARP_HOP_TAG,
                "listen": "127.0.0.1",
                "port": port,
            }));
        }
        for (tag, outbound) in &generated.extra {
            let mut outbound = outbound.clone();
            outbound["tag"] = Value::String(tag.clone());
            outbounds.push(outbound);
        }
        routing.extend(generated.rules.iter().cloned());
    }
    let mut document = json!({"inbounds": inbounds, "outbounds": outbounds});
    if !routing.is_empty() {
        document["routing"] = json!({"rules": routing});
    }
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("cannot encode the config: {error}"))?;
    write_private(path, &format!("{text}\n"))
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn adopted_ports(path: &Path, fronts: &[String], fixed: &mut [bool], ports: &mut Ports) {
    let Some(text) = read_trim(path) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) else {
        return;
    };
    let names = ["socks", "http", "mixed"];
    let mut adopted: Vec<&str> = Vec::new();
    for inbound in inbounds {
        if hidden_inbound(inbound) {
            continue;
        }
        let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
            continue;
        };
        let Some(index) = names.iter().position(|candidate| *candidate == name) else {
            continue;
        };
        if !fronts.iter().any(|front| front == name)
            || fixed[index]
            || adopted.contains(&names[index])
        {
            continue;
        }
        let Some(port) = inbound.get("port").and_then(Value::as_u64) else {
            continue;
        };
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        match index {
            0 => ports.socks = port,
            1 => ports.http = port,
            _ => ports.mixed = port,
        }
        fixed[index] = true;
        adopted.push(names[index]);
    }
}

fn free_port(start: u16, taken: &[u16]) -> u16 {
    for port in start..=u16::MAX {
        if !taken.contains(&port) && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    start
}

pub fn plan_ports(options: &Options, paths: &Paths, scan: bool) -> Ports {
    let mut ports = Ports {
        socks: options.socks,
        http: options.http,
        mixed: options.mixed,
    };
    let fronts = fronts(&options.fronts);
    let mut fixed = [options.socks_set, options.http_set, options.mixed_set];
    if paths.cfg.exists() {
        adopted_ports(&paths.cfg, &fronts, &mut fixed, &mut ports);
    }
    let mut taken: Vec<u16> = Vec::new();
    let names = ["socks", "http", "mixed"];
    let values = [ports.socks, ports.http, ports.mixed];
    for (index, name) in names.iter().enumerate() {
        if fronts.iter().any(|front| front == name) && fixed[index] {
            taken.push(values[index]);
        }
    }
    if scan {
        for (index, name) in names.iter().enumerate() {
            if !fronts.iter().any(|front| front == name) || fixed[index] {
                continue;
            }
            let value = match index {
                0 => ports.socks,
                1 => ports.http,
                _ => ports.mixed,
            };
            let port = free_port(value, &taken);
            match index {
                0 => ports.socks = port,
                1 => ports.http = port,
                _ => ports.mixed = port,
            }
            taken.push(port);
        }
    }
    ports
}

pub fn front_listeners(path: &Path, list: &str) -> Vec<(String, String)> {
    let document = read_trim_checked(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let inbounds = document
        .as_ref()
        .and_then(|document| document.get("inbounds"))
        .and_then(Value::as_array);
    fronts(list)
        .into_iter()
        .map(|front| {
            let listen = inbounds
                .and_then(|inbounds| {
                    inbounds.iter().find(|inbound| {
                        !hidden_inbound(inbound)
                            && inbound.get("protocol").and_then(Value::as_str)
                                == Some(front.as_str())
                    })
                })
                .and_then(|inbound| inbound.get("listen"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            (front, listen)
        })
        .collect()
}

pub fn config_fronts(
    path: &str,
    proxy: bool,
    fronts_set: bool,
    asked: &str,
) -> Result<String, String> {
    let text = read_trim_checked(Path::new(path))
        .map_err(|error| format!("cannot read config {path}: {error}"))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("cannot read config {path}: {error}"))?;
    let mut order: Vec<String> = Vec::new();
    if let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) {
        for inbound in inbounds {
            if hidden_inbound(inbound) {
                continue;
            }
            let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
                continue;
            };
            if !matches!(name, "socks" | "http" | "mixed") {
                continue;
            }
            let Some(port) = inbound.get("port").and_then(Value::as_u64) else {
                return Err(format!("inbound `{name}` has no port in 1-65535"));
            };
            if port == 0 || port > 65535 {
                return Err(format!("inbound `{name}` has no port in 1-65535"));
            }
            if !order.iter().any(|front| front == name) {
                order.push(name.to_owned());
            }
        }
    }
    if fronts_set {
        let wanted = fronts(asked);
        for front in &wanted {
            if !order.contains(front) {
                return Err(format!(
                    "the config serves no {front} inbound; --fronts names it"
                ));
            }
        }
        order.retain(|front| wanted.contains(front));
    }
    if proxy {
        if order.is_empty() {
            return Err(
                "the config serves no socks, http or mixed inbound; --vpn-proxy needs one"
                    .to_owned(),
            );
        }
        if let Some(inbounds) = document.get("inbounds").and_then(Value::as_array) {
            for inbound in inbounds {
                if hidden_inbound(inbound) {
                    continue;
                }
                let Some(name) = inbound.get("protocol").and_then(Value::as_str) else {
                    continue;
                };
                if !order.iter().any(|front| front == name) {
                    continue;
                }
                let listen = inbound.get("listen").and_then(Value::as_str);
                if listen == Some("::1") {
                    return Err(format!(
                        "inbound `{name}` listens on ::1; --vpn-proxy points the Windows proxy at 127.0.0.1, so use 127.0.0.1"
                    ));
                }
                let loopback =
                    listen.is_some_and(|listen| listen == "localhost" || listen == "127.0.0.1");
                if !loopback {
                    return Err(format!(
                        "inbound `{name}` listens on {}, not loopback; --vpn-proxy needs 127.0.0.1",
                        listen.unwrap_or("all interfaces")
                    ));
                }
            }
        }
    }
    Ok(order.join(","))
}

/// Whether a verbatim config already carries the device `--vpn` would otherwise add.
pub fn config_has_tun(path: &str) -> Result<bool, String> {
    let text = read_trim_checked(Path::new(path))
        .map_err(|error| format!("cannot read config {path}: {error}"))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("cannot read config {path}: {error}"))?;
    Ok(document
        .get("inbounds")
        .and_then(Value::as_array)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                matches!(
                    inbound.get("protocol").and_then(Value::as_str),
                    Some("tun" | "utun" | "wintun" | "tun2socks")
                )
            })
        }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrox-cli-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |span| span.subsec_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn options() -> Options {
        Options {
            fronts: "socks,http,mixed".to_owned(),
            fronts_set: false,
            socks: 10808,
            http: 8080,
            mixed: 10809,
            socks_set: false,
            http_set: false,
            mixed_set: false,
            ..Options::default()
        }
    }

    #[test]
    fn fronts_trims_and_drops_empty_entries() {
        assert_eq!(fronts(" socks, ,http , mixed"), ["socks", "http", "mixed"]);
        assert_eq!(fronts(" , "), Vec::<String>::new());
    }

    #[test]
    fn ports_follow_the_front_name() {
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        assert_eq!(port_of("socks", ports), 1);
        assert_eq!(port_of("http", ports), 2);
        assert_eq!(port_of("mixed", ports), 3);
    }

    #[test]
    fn exclude_domains_normalize_star_and_dot() {
        assert_eq!(
            split_domains("*.Example.COM., .lan, printer").unwrap(),
            ["example.com", "lan", "printer"]
        );
    }

    #[test]
    fn exclude_domains_refuse_the_shapes_a_suffix_cannot_be() {
        assert!(split_domains("a/b").is_err());
        assert!(split_domains("a:1").is_err());
        assert!(split_domains("*.example..com").is_err());
        assert!(split_domains(" , ").is_err());
    }

    #[test]
    fn exclude_ports_refuse_zero_and_overflow() {
        assert_eq!(split_ports("22, 443").unwrap(), [22, 443]);
        assert!(split_ports("0").is_err());
        assert!(split_ports("65536").is_err());
        assert!(split_ports("http").is_err());
        assert!(split_ports(" ").is_err());
    }

    #[test]
    fn vless_ws_tls_matches_the_reference_shape() {
        let outbound = vless_outbound(
            "vless://uuid@host.test:443?type=ws&security=tls&sni=edge.example&host=cdn.example&path=%2Fws#name",
        )
        .unwrap();
        assert_eq!(outbound["protocol"], "vless");
        assert_eq!(outbound["settings"]["vnext"][0]["address"], "host.test");
        assert_eq!(outbound["settings"]["vnext"][0]["port"], 443);
        assert_eq!(outbound["settings"]["vnext"][0]["users"][0]["id"], "uuid");
        assert_eq!(outbound["streamSettings"]["network"], "ws");
        assert_eq!(outbound["streamSettings"]["security"], "tls");
        assert_eq!(
            outbound["streamSettings"]["tlsSettings"]["serverName"],
            "edge.example"
        );
        assert_eq!(outbound["streamSettings"]["wsSettings"]["path"], "/ws");
        assert_eq!(
            outbound["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example"
        );
    }

    #[test]
    fn vmess_network_names_a_transport_this_cli_can_build() {
        let mut options = options();
        options.vmess = "host:443".to_owned();
        options.vmess_id = "uuid".to_owned();
        options.vmess_network = "websocket".to_owned();
        let outbound = vmess_outbound(&options).unwrap();
        assert_eq!(outbound["streamSettings"]["network"], "ws");
        options.vmess_network = "quic".to_owned();
        let error = vmess_outbound(&options).unwrap_err();
        assert!(error.contains("use tcp or ws"));
    }

    #[test]
    fn vless_tls_reads_allow_insecure_from_either_spelling() {
        let permissive =
            vless_outbound("vless://uuid@host.test:443?type=tcp&security=tls&allowInsecure=1")
                .unwrap();
        assert_eq!(
            permissive["streamSettings"]["tlsSettings"]["allowInsecure"],
            true
        );
        let legacy =
            vless_outbound("vless://uuid@host.test:443?type=tcp&security=tls&insecure=true")
                .unwrap();
        assert_eq!(
            legacy["streamSettings"]["tlsSettings"]["allowInsecure"],
            true
        );
        let strict = vless_outbound("vless://uuid@host.test:443?type=tcp&security=tls").unwrap();
        assert_eq!(
            strict["streamSettings"]["tlsSettings"]["allowInsecure"],
            false
        );
        assert!(vless_outbound(
            "vless://uuid@host.test:443?type=tcp&security=tls&allowInsecure=maybe"
        )
        .is_err());
    }

    #[test]
    fn vless_tcp_carries_the_http_header_type() {
        let outbound = vless_outbound(
            "vless://uuid@host.test:443?type=tcp&headerType=http&host=cdn.example&path=%2Fa",
        )
        .unwrap();
        let header = &outbound["streamSettings"]["tcpSettings"]["header"];
        assert_eq!(header["type"], "http");
        assert_eq!(header["request"]["path"][0], "/a");
        assert_eq!(header["request"]["headers"]["Host"][0], "cdn.example");
        assert!(vless_outbound("vless://uuid@host.test:443?type=tcp&headerType=srtp").is_err());
    }

    #[test]
    fn exclusions_are_validated_before_any_account_is_resolved() {
        let mut options = options();
        options.exclude_domains = "*.Example.COM, .lan".to_owned();
        options.exclude_ports = "22,443".to_owned();
        assert_eq!(validate_exclusions(&options), Ok(()));
        options.exclude_domains = "a/b".to_owned();
        assert!(validate_exclusions(&options).is_err());
        options.exclude_domains.clear();
        options.exclude_ports = "65536".to_owned();
        assert!(validate_exclusions(&options).is_err());
    }

    #[test]
    fn vless_reality_without_a_key_is_refused() {
        let error = vless_outbound("vless://uuid@host:443?security=reality").unwrap_err();
        assert!(error.contains("pbk"));
    }

    #[test]
    fn vless_unknown_carrier_needs_a_config() {
        let error = vless_outbound("vless://uuid@host:443?type=kcp").unwrap_err();
        assert!(error.contains("--config"));
    }

    #[test]
    fn plan_ports_adopts_the_config_ports_but_a_named_flag_wins() {
        let dir = scratch("ports");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        std::fs::write(
            &paths.cfg,
            r#"{"inbounds":[{"protocol":"socks","port":19080},{"protocol":"http","port":19081}]}"#,
        )
        .unwrap();
        let mut options = options();
        options.fronts = "socks,http".to_owned();
        assert_eq!(plan_ports(&options, &paths, false).socks, 19080);
        assert_eq!(plan_ports(&options, &paths, false).http, 19081);
        options.http_set = true;
        options.http = 28080;
        assert_eq!(plan_ports(&options, &paths, false).http, 28080);
    }

    #[test]
    fn plan_ports_scans_when_asked() {
        let dir = scratch("scan");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), Some("work"));
        let mut options = options();
        options.fronts = "socks".to_owned();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        options.socks = taken;
        let ports = plan_ports(&options, &paths, true);
        assert_ne!(ports.socks, taken);
        drop(listener);
    }

    #[test]
    fn write_config_writes_every_named_front_and_no_other() {
        let dir = scratch("write");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let outbound = serde_json::json!({"protocol": "freedom"});
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        write_config(&paths.cfg, &outbound, "socks,mixed", ports, None, None).unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        assert_eq!(document["inbounds"][0]["protocol"], "socks");
        assert_eq!(document["inbounds"][0]["port"], 1);
        assert_eq!(document["inbounds"][1]["protocol"], "mixed");
        assert_eq!(document["inbounds"][1]["port"], 3);
        assert_eq!(document["outbounds"][0]["protocol"], "freedom");
    }

    #[test]
    fn write_config_puts_the_tun_inbound_first_with_the_selected_engine() {
        let dir = scratch("tun");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let outbound = serde_json::json!({"protocol": "freedom"});
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        let vpn = Vpn {
            engine: "userspace".to_owned(),
            ipv6: true,
            mtu: 1400,
            name: "ferrox9".to_owned(),
            dns: "192.0.2.53".to_owned(),
        };
        write_config(&paths.cfg, &outbound, "socks", ports, Some(&vpn), None).unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        assert_eq!(document["inbounds"][0]["protocol"], "tun");
        assert_eq!(document["inbounds"][0]["stack"], "userspace");
        assert_eq!(document["inbounds"][0]["auto_route"], true);
        assert_eq!(document["inbounds"][0]["mtu"], 1400);
        assert_eq!(document["inbounds"][0]["name"], "ferrox9");
        assert_eq!(document["inbounds"][0]["dns_mode"], "hijack");
        assert_eq!(document["inbounds"][0]["dns_address"][0], "192.0.2.53");
        assert_eq!(
            document["inbounds"][0]["address"][1],
            "fdfe:dcba:9876::1/64"
        );
        assert_eq!(document["inbounds"][1]["protocol"], "socks");
    }

    #[test]
    fn psiphon_settings_carry_the_native_engine_options() {
        let dir = scratch("psiphon");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let mut options = options();
        options.outbound = Some(Outbound::Psiphon);
        options.psiphon.region = "NL".to_owned();
        options.psiphon.shape = "cdn".to_owned();
        options.psiphon.aggressive = Some(true);
        options.psiphon.split = true;
        options.psiphon.split_regions = "US, CA".to_owned();
        options.psiphon.cdn_ips = "192.0.2.1".to_owned();
        let outbound = build_outbound(&options, &paths, None).unwrap();
        assert_eq!(outbound["protocol"], "psiphon");
        assert_eq!(outbound["settings"]["region"], "NL");
        assert_eq!(outbound["settings"]["protocolSelection"], "cdn_fronting");
        assert_eq!(outbound["settings"]["aggressiveEstablishment"], true);
        assert_eq!(outbound["settings"]["splitTunnelOwnRegion"], true);
        assert_eq!(outbound["settings"]["splitTunnelRegions"][1], "CA");
        assert_eq!(outbound["settings"]["cdnIps"][0], "192.0.2.1");
        assert_eq!(
            outbound["settings"]["dataRootDirectory"],
            paths.psiphon_dir.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn a_split_psiphon_lane_keeps_the_shell_tag_and_an_ephemeral_port() {
        let dir = scratch("psiphon-udp");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let mut options = options();
        options.outbound = Some(Outbound::Foxy);
        options.udp_via = "psiphon-cdn".to_owned();
        options.psiphon.shape = "cdn".to_owned();
        options.psiphon.aggressive = Some(true);
        options.psiphon.cdn_profile = "fronted".to_owned();
        let generated = lane_plan(&mut options, &paths).unwrap();
        let (tag, outbound) = &generated.extra[0];
        assert_eq!(tag, "udp-psiphon-cdn");
        assert_eq!(outbound["settings"]["listen"], "127.0.0.1:0");
        assert_eq!(outbound["settings"]["cdnProfile"], "fronted");
        assert_eq!(generated.rules[0]["outboundTag"], "udp-psiphon-cdn");
    }

    #[test]
    fn write_config_chains_a_psiphon_lane_through_warp() {
        let dir = scratch("psiphon-warp");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let mut options = options();
        options.outbound = Some(Outbound::Psiphon);
        options.warp = true;
        let generated = lane_plan(&mut options, &paths).unwrap();
        let hidden = generated.hidden_socks.expect("warp needs a hidden front");
        let outbound = build_outbound(&options, &paths, None).unwrap();
        assert_eq!(
            outbound["settings"]["upstreamProxy"],
            format!("socks5://127.0.0.1:{hidden}")
        );
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        write_config(
            &paths.cfg,
            &outbound,
            "socks",
            ports,
            None,
            Some(&generated),
        )
        .unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        assert_eq!(document["outbounds"][0]["protocol"], "psiphon");
        assert_eq!(document["outbounds"][1]["protocol"], "warp");
        assert_eq!(
            document["routing"]["rules"][0]["inboundTag"][0],
            WARP_HOP_TAG
        );
    }

    #[test]
    fn write_config_chains_warp_through_a_hidden_front_and_tags_udp() {
        let dir = scratch("warp");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let mut options = Options {
            outbound: Some(Outbound::Foxy),
            warp: true,
            warp_mode: "gool".to_owned(),
            udp_via: "warp".to_owned(),
            ..Options::default()
        };
        let generated = lane_plan(&mut options, &paths).unwrap();
        let hidden = generated.hidden_socks.expect("warp needs a hidden front");
        assert!(options.upstream.starts_with("socks5://127.0.0.1:"));
        let outbound = serde_json::json!({"protocol": "foxy", "settings": {"upstreamProxy": options.upstream}});
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        write_config(
            &paths.cfg,
            &outbound,
            "socks",
            ports,
            None,
            Some(&generated),
        )
        .unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        let hidden_inbound = document["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["tag"] == WARP_HOP_TAG)
            .expect("hidden front");
        assert_eq!(hidden_inbound["protocol"], "socks");
        assert_eq!(hidden_inbound["port"], hidden);
        assert_eq!(document["outbounds"][1]["protocol"], "warp");
        assert_eq!(document["outbounds"][1]["tag"], "warp");
        assert_eq!(document["outbounds"][1]["settings"]["mode"], "gool");
        assert_eq!(
            document["outbounds"][1]["settings"]["identityFile"],
            paths.warp_identity.to_string_lossy().as_ref()
        );
        assert_eq!(document["routing"]["rules"][0]["network"], "udp");
        assert_eq!(document["routing"]["rules"][0]["outboundTag"], "warp");
        assert_eq!(
            document["routing"]["rules"][1]["inboundTag"][0],
            WARP_HOP_TAG
        );
        assert_eq!(
            config_fronts(paths.cfg.to_str().unwrap(), false, false, "").unwrap(),
            "socks"
        );
    }

    #[test]
    fn write_config_udp_direct_adds_a_second_tagged_outbound() {
        let dir = scratch("udp-direct");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let mut options = Options {
            outbound: Some(Outbound::Foxy),
            udp_via: "direct".to_owned(),
            ..Options::default()
        };
        let generated = lane_plan(&mut options, &paths).unwrap();
        assert_eq!(generated.hidden_socks, None);
        let outbound = serde_json::json!({"protocol": "foxy"});
        let ports = Ports {
            socks: 1,
            http: 2,
            mixed: 3,
        };
        write_config(
            &paths.cfg,
            &outbound,
            "socks",
            ports,
            None,
            Some(&generated),
        )
        .unwrap();
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.cfg).unwrap()).unwrap();
        assert_eq!(document["outbounds"][1]["protocol"], "freedom");
        assert_eq!(document["outbounds"][1]["tag"], "udp-direct");
        assert_eq!(document["routing"]["rules"][0]["outboundTag"], "udp-direct");
    }

    #[test]
    fn config_fronts_refuses_a_vpn_route_that_is_not_loopback() {
        let dir = scratch("fronts");
        let file = dir.join("mine.json");
        std::fs::write(
            &file,
            r#"{"inbounds":[{"protocol":"socks","listen":"0.0.0.0","port":1080}]}"#,
        )
        .unwrap();
        let error = config_fronts(file.to_str().unwrap(), true, false, "").unwrap_err();
        assert!(error.contains("not loopback"));
    }

    #[test]
    fn config_fronts_refuses_a_loopback_the_system_proxy_does_not_target() {
        let dir = scratch("fronts-alias");
        let file = dir.join("mine.json");
        std::fs::write(
            &file,
            r#"{"inbounds":[{"protocol":"socks","listen":"127.0.0.2","port":1080}]}"#,
        )
        .unwrap();
        let error = config_fronts(file.to_str().unwrap(), true, false, "").unwrap_err();
        assert!(error.contains("not loopback"));
    }

    #[test]
    fn front_listeners_keep_a_configured_loopback_alias() {
        let dir = scratch("listeners-alias");
        let file = dir.join("mine.json");
        std::fs::write(
            &file,
            r#"{"inbounds":[{"protocol":"socks","listen":"127.0.0.2","port":1080}]}"#,
        )
        .unwrap();
        assert_eq!(
            front_listeners(&file, "socks,http"),
            [
                ("socks".to_owned(), "127.0.0.2".to_owned()),
                ("http".to_owned(), String::new())
            ]
        );
    }

    #[test]
    fn effective_region_lowers_the_country_alias() {
        let mut options = options();
        options.country = "US".to_owned();
        options.country_set = true;
        assert_eq!(effective_region(&options), "us");
        options.region = "US-VA".to_owned();
        assert_eq!(effective_region(&options), "us-va");
    }

    #[test]
    fn stable_udid_is_kept_across_calls() {
        let dir = scratch("udid");
        let paths = Paths::with_dirs(dir.clone(), dir.join("state"), None);
        let options = options();
        let first = stable_udid(&options, &paths).unwrap();
        let second = stable_udid(&options, &paths).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
    }
}
