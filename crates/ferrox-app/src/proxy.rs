use crate::conn::{parse_target, Connection, Listener};
use std::collections::{HashMap, HashSet};
#[cfg(windows)]
use std::io::IoSliceMut;
use std::io::{IoSlice, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use lane_pool::Next;

use crate::budgets::{
    self, ACCOUNT_ATTEMPTS, CARRIER_DEAD_SECS, RELAY_HANDOFF_SPINS, RELAY_IDLE, RELAY_LOCK_TRIES,
    RELAY_MOVING_READS, RELAY_POLL, SESSION_POLL,
};
use crate::config::{
    inbound_carrier, inbound_reality_config, inbound_tls_identity, outbound_carrier,
    outbound_reality, outbound_tls, server_fallbacks, stream_security, tls_ca_roots, trojan_key,
    uuid_bytes, vless_security_supported, Carrier, Fallback, FallbackNetwork,
};
use crate::json::Json;
use ferrox_core::failure::{Failure, Kind, Ladder, Rung, Stage};
#[cfg(test)]
use ferrox_core::tls::RecordAlignment as _;
use ferrox_core::tls::{Edges, Stream, TlsProvider as _};
use ferrox_core::vless::{Flow, Target};

pub(crate) fn print_version() {
    println!("ferrox-app {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

/// Published edges as JSON rows on stdout: the catalogue is public, so the list needs no config, account or lane. `--ping` adds the handshake time, and a null is an edge that did not answer.
pub(crate) fn print_foxy_edges(ping: bool) {
    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let readings = ping.then(|| crate::foxy_latency::readings(&edges));
    for (index, edge) in edges.iter().enumerate() {
        if let Some(readings) = &readings {
            println!(
                "{}",
                foxy_edge_row(edge, readings.get(index).copied().flatten())
            );
        } else {
            println!(
                "{{\"host\":\"{}\",\"port\":{},\"city\":\"{}\",\"country\":\"{}\"}}",
                edge.host, edge.port, edge.city, edge.country
            );
        }
    }
}

/// The measured row a pinged listing prints: a number of milliseconds, or the null an unanswered edge earns.
fn foxy_edge_row(edge: &ferrox_core::foxy::Candidate, reading: Option<u64>) -> String {
    let ms = reading.map_or_else(|| "null".to_owned(), |ms| ms.to_string());
    format!(
        "{{\"host\":\"{}\",\"port\":{},\"city\":\"{}\",\"country\":\"{}\",\"ms\":{ms}}}",
        edge.host, edge.port, edge.city, edge.country
    )
}

pub(crate) fn serve_json(label: &str, body: &str, test: bool) -> ! {
    let root = crate::json::parse(body)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root, None, test)
}

/// Xray's own wire form; the pinned scenario suite spawns this binary with `-config=stdin: -format=pb`.
pub(crate) fn serve_protobuf(label: &str, bytes: &[u8], test: bool) -> ! {
    let (root, seed) = crate::xray_pb::to_json_seeded(bytes)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root, Some(&seed), test)
}

/// The listen addresses an inbound names: every port its `port` field expands, on the
/// `listen` host, or the `unix` path standing in for both. An empty answer is an inbound
/// naming no socket, which the caller skips; a datagram carrier keeps the IP address by
/// the same rule.
fn inbound_addresses(inbound: &Json) -> Vec<String> {
    #[cfg(unix)]
    {
        let unix_path = inbound
            .get("unix")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty());
        if let Some(path) = unix_path {
            return vec![format!("unix:{path}")];
        }
    }
    let Some(field) = inbound.get("port") else {
        return Vec::new();
    };
    let ports = inbound_ports(field);
    if ports.is_empty() {
        return Vec::new();
    }
    let host = inbound
        .get("listen")
        .and_then(Json::as_str)
        .filter(|listen| !listen.is_empty())
        .unwrap_or("0.0.0.0");
    ports
        .into_iter()
        .map(|port| format!("{host}:{port}"))
        .collect()
}

/// The ports a `port` field names, in the forms the reference `PortList` accepts: a JSON
/// number, a plain or `"env:NAME"`-sourced decimal string, an `"a-b"` range expanded to
/// every port in it, and comma-separated combinations of those.
fn inbound_ports(field: &Json) -> Vec<u16> {
    if let Some(port) = field.as_port() {
        return vec![port];
    }
    let Some(spec) = field.as_str() else {
        return Vec::new();
    };
    let mut ports = Vec::new();
    for piece in spec.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let env_value = piece
            .strip_prefix("env:")
            .and_then(|name| std::env::var(name).ok());
        if piece.starts_with("env:") && env_value.is_none() {
            eprintln!(
                "env `{}` in the port list is unset, so its piece names no port",
                &piece[4..]
            );
            continue;
        }
        let piece = env_value.as_deref().unwrap_or(piece);
        let (from, to) = piece.split_once('-').unwrap_or((piece, piece));
        let (Ok(from), Ok(to)) = (from.parse::<u16>(), to.parse::<u16>()) else {
            eprintln!("port piece `{piece}` is not a port the reference names; piece skipped");
            continue;
        };
        if from > to {
            eprintln!("port range `{piece}` descends, piece skipped");
            continue;
        }
        ports.extend(from..=to);
    }
    ports
}

/// The address and port dokodemo-door rewrites every flow to, each half optional so the
/// flow's own local address can fill what the config omits.
#[derive(Clone, Debug, Default)]
struct DokodemoRewrite {
    host: Option<String>,
    port: Option<u16>,
}

impl DokodemoRewrite {
    fn from_config(inbound: &Json) -> Self {
        let Some(settings) = inbound.get("settings") else {
            return Self::default();
        };
        let host = settings
            .get("address")
            .or_else(|| settings.get("rewriteAddress"))
            .and_then(Json::as_str)
            .map(str::to_owned);
        let port = settings
            .get("port")
            .and_then(Json::as_port)
            .filter(|port| *port != 0)
            .or_else(|| settings.get("rewritePort").and_then(Json::as_port))
            .filter(|port| *port != 0);
        Self { host, port }
    }

    /// The target a followed flow falls back to: only what the config spelled, with no
    /// local address to complete it, because the reference fills from the flow alone.
    fn configured(&self) -> Option<Destination> {
        let host = self.host.as_deref()?;
        Some(dokodemo_destination(host, self.port.unwrap_or(0)))
    }

    /// The target a non-followed flow asks for: the config's half, or the flow's own
    /// address half, completed by a `portMap` entry for the flow's local port.
    fn resolved(
        &self,
        local: Option<SocketAddr>,
        port_map: &HashMap<String, DokodemoPortMapEntry>,
    ) -> Destination {
        let host = self
            .host
            .as_deref()
            .unwrap_or_else(|| dokodemo_default_host(local));
        let port = self
            .port
            .or_else(|| local.map(|local| local.port()))
            .unwrap_or(0);
        let mut dest = dokodemo_destination(host, port);
        let key = local
            .map(|local| local.port().to_string())
            .unwrap_or_default();
        if let Some(entry) = port_map.get(&key) {
            if let Some(host) = entry.host.as_deref() {
                dest = dokodemo_destination(host, dest.port());
            }
            if let Some(port) = entry.port {
                dest = dokodemo_with_port(&dest, port);
            }
        }
        dest
    }
}

/// xray's fallback when the config names no address: the loopback of the flow's family,
/// or `localhost` when the local address did not parse.
fn dokodemo_default_host(local: Option<SocketAddr>) -> &'static str {
    match local {
        Some(local) if local.ip().to_canonical().is_ipv4() => "127.0.0.1",
        Some(_) => "::1",
        None => "localhost",
    }
}

/// One host and port in xray's own spelling, with a bracketed IPv6 literal unwrapped.
fn dokodemo_destination(host: &str, port: u16) -> Destination {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => Destination::Address(SocketAddr::new(ip, port)),
        Err(_) => Destination::Name(host.to_owned(), port),
    }
}

fn dokodemo_with_port(dest: &Destination, port: u16) -> Destination {
    match dest {
        Destination::Name(host, _) => Destination::Name(host.clone(), port),
        Destination::Address(address) => Destination::Address(SocketAddr::new(address.ip(), port)),
    }
}

/// The networks dokodemo-door is told to carry; the reference defaults an absent list to
/// tcp and lets `network` alone override its older `allowedNetwork` spelling.
fn dokodemo_networks(inbound: &Json) -> Vec<&str> {
    let Some(settings) = inbound.get("settings") else {
        return vec!["tcp"];
    };
    let named = match settings.get("network") {
        Some(Json::Null) | None => settings.get("allowedNetwork"),
        named => named,
    };
    match named {
        Some(Json::Arr(items)) => items.iter().filter_map(Json::as_str).collect(),
        Some(Json::Str(network)) => network.split(',').collect(),
        _ => vec!["tcp"],
    }
}

fn dokodemo_has(networks: &[&str], network: &str) -> bool {
    networks
        .iter()
        .any(|named| named.eq_ignore_ascii_case(network))
}

/// The reference carries `userLevel` on the inbound's user; the door applies it as the
/// accepted stream's policy level.
fn dokodemo_user_level(inbound: &Json) -> u32 {
    inbound
        .get("settings")
        .and_then(|settings| settings.get("userLevel"))
        .and_then(Json::as_u32)
        .unwrap_or(0)
}

#[allow(clippy::too_many_lines)]
fn serve_root(label: &str, root: &Json, seed: Option<&crate::xray_pb::Seed>, test: bool) -> ! {
    // Sized before the first lane, so every flow from here reads the ceiling its role named.
    if dials_a_proxy(root) {
        lane_pool::mark_proxy_peer();
    }
    // Armed before the first inbound opens, so every flow from here reads the budget the operator named.
    crate::budgets::apply_config(
        &crate::config::budgets(root)
            .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}"))),
    );
    crate::dnsapp::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    crate::policy::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    if let Some(policy) = seed.and_then(|seed| seed.policy.clone()) {
        crate::policy::install_config(policy);
    }
    crate::stats::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    let geodata = install_file_apps(root, test)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    install_default_outbound_tag(root);
    let freedom = has_protocol(root, "outbounds", "freedom");
    let configured = find_outbound_with(root, test)
        .unwrap_or_else(|reason| exit(&format!("bad config {label}: {reason}")));
    // A loopback outbound names its inbound by tag, so it resolves only when no concrete dial won.
    let loopback = find_loopback_outbound(root);
    let outbound = match configured.clone() {
        Some(Outbound::Freedom(_)) | None if loopback.is_some() => {
            let tag = loopback.expect("guarded by is_some");
            Some(
                resolve_loopback(root, &tag, freedom).unwrap_or_else(|reason| {
                    exit(&format!("bad config {label}: loopback {reason}"))
                }),
            )
        }
        selected => selected,
    };
    if let Some(Outbound::Freedom(freedom)) = &outbound {
        let _ = DIRECT_FREEDOM.set(Arc::clone(freedom));
    }
    // Named only when no outbound was built, so the reason behind an exit that names nothing is on its own line first.
    let refused = outbound.is_none().then(|| diagnose_outbounds(root));
    let portals =
        reverse_portals(root).unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    let routing = routing_for(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")))
        .or_else(|| {
            geodata
                .as_ref()
                .filter(|geodata| !geodata.outbound().is_empty())
                .map(|_| crate::router::Routing::empty())
        });
    let observatory = start_observatory(root, test)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    crate::metrics::set_observatory(observatory.clone());
    let api_config = match seed.and_then(|seed| seed.api.clone()) {
        Some(config) => Some(config),
        None => crate::commander::ApiConfig::from_json(root),
    };
    let api = api_config.map(crate::commander::Api::new);
    if let Some(api) = api.as_ref() {
        match seed {
            Some(seed) => api.seed_outbounds(&seed.outbounds),
            None => api.seed_json_outbounds(root),
        }
    }
    let route = routing.map(|routing| {
        route_shared_with_api(
            root,
            routing,
            &portals,
            observatory.clone(),
            api.as_ref(),
            configured.as_ref(),
            geodata.as_ref().map(crate::geodata::Config::outbound),
        )
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")))
    });
    if let Some(observatory) = &observatory {
        crate::observatory::spawn(root, observatory, route.as_ref())
            .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    }
    if let Some(api) = api.as_ref() {
        wire_api(
            api,
            observatory,
            Runtime::new(
                outbound.clone(),
                route.clone(),
                freedom,
                Arc::clone(&portals),
            ),
            test,
        )
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    }
    if !test {
        if let Some(geodata) = geodata {
            crate::geodata::start(geodata, route.clone(), outbound.clone(), root.clone());
        }
        install_dns_route(route.clone(), outbound.as_ref());
        start_bridges(root, outbound.as_ref(), route.as_ref());
    }
    let inbounds = serve_inbounds_counted(
        label,
        root,
        outbound.as_ref(),
        route.as_ref(),
        true,
        freedom,
        &portals,
        api.as_deref(),
        seed,
        test,
        false,
    );
    if inbounds == 0 {
        match refused.as_deref().unwrap_or(&[]).first() {
            Some(reason) => exit(&format!("bad config {label}: {reason}")),
            None => exit(&format!("no servable inbound in {label}")),
        }
    }
    if test {
        println!("Configuration OK.");
        std::process::exit(0);
    }
    if ["XRAY_VLESS_FULL_BINARY", "XRAY_HYSTERIA_BINARY"]
        .iter()
        .any(|seam| std::env::var_os(seam).is_some())
    {
        // The startup record both pinned interop harnesses scan the server log for; not this binary's name.
        println!("ferrox-app serving; harness readiness token: core: Xray 26.11.9 started");
    }
    loop {
        thread::park();
        report_dial_failures();
    }
}

/// The observatory a config names; `-test` proves both blocks parse without starting either probe loop.
fn start_observatory(
    root: &Json,
    test: bool,
) -> Result<Option<Arc<crate::observatory::Observatory>>, String> {
    if test {
        crate::observatory::validate(root).map(|()| None)
    } else {
        crate::observatory::configure(root)
    }
}

/// The file-backed apps and the `geodata` block: `-test` parses them without opening or creating anything the reference also leaves alone.
fn install_file_apps(root: &Json, test: bool) -> Result<Option<crate::geodata::Config>, String> {
    let geodata = crate::geodata::parse(root, &crate::router::asset_dirs())?;
    if test {
        crate::metrics::parse(root)?;
        crate::accesslog::parse(root)?;
    } else {
        crate::metrics::install(root)?;
        crate::accesslog::install(root)?;
    }
    Ok(geodata)
}

/// Attach the runtime a management call drives, then listen for it; `-test` skips the listener.
fn wire_api(
    api: &Arc<crate::commander::Api>,
    observatory: Option<Arc<crate::observatory::Observatory>>,
    runtime: Runtime,
    test: bool,
) -> Result<(), String> {
    api.set_observatory(observatory);
    api.set_runtime(Arc::new(runtime));
    if !test {
        api.serve_listen()?;
    }
    Ok(())
}

/// One inbound's lane: a route plan when the config carries rules, else the single configured outbound.
fn routed_out(
    outbound: Option<&Outbound>,
    route: Option<&Arc<RouteShared>>,
    inbound: &Json,
    source_known: bool,
) -> Option<Outbound> {
    match route {
        Some(shared) => Some(Outbound::Route(Arc::new(RoutePlan::new(
            Arc::clone(shared),
            inbound_tag(inbound),
            inbound_name(inbound),
            source_known,
        )))),
        None => outbound.cloned(),
    }
}

/// Opens every inbound the config names, proving each server inbound's rules at startup, and reports
/// how many opened and whether a hysteria inbound wants the readiness token.
fn inbound_sniffing(inbound: &Json, label: &str) -> Option<Arc<crate::sniff::Sniffing>> {
    crate::sniff::parse(inbound.get("sniffing")).unwrap_or_else(|error| {
        exit(&format!(
            "bad config {label}: inbound {} sniffing {error}",
            inbound_tag(inbound).as_deref().unwrap_or("<untagged>")
        ))
    })
}

fn refuse_source(
    route: Option<&Arc<RouteShared>>,
    inbound: &Json,
    label: &str,
    kind: &str,
    prove: bool,
) -> bool {
    let Some(shared) = route else {
        return false;
    };
    let tag = inbound_tag(inbound);
    let Some(selector) = shared
        .routing
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .source_refusal(tag.as_deref())
    else {
        return false;
    };
    let message = format!(
        "bad config {label}: {} inbound {} names `{selector}`, which a {kind} flow cannot answer",
        canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or("")),
        tag.as_deref().unwrap_or("<untagged>")
    );
    if prove {
        exit(&message);
    }
    eprintln!("{message}");
    true
}

/// Whether this inbound's xHTTP carrier is the QUIC one, decided the way the listener decides it:
/// xHTTP, TLS with a loadable identity, and an ALPN list of exactly `h3`. Only then does the
/// dispatcher register a stop the listener will actually signal.
fn inbound_is_xhttp_h3(inbound: &Json) -> bool {
    if !matches!(inbound_carrier(inbound), Carrier::Xhttp { .. })
        || crate::config::stream_security(inbound) != "tls"
        || crate::config::inbound_tls_identity(inbound).is_none()
    {
        return false;
    }
    let alpn = inbound
        .get("streamSettings")
        .and_then(|stream| stream.get("tlsSettings"))
        .and_then(|tls| tls.get("alpn"));
    let names: Vec<&str> = match alpn {
        Some(Json::Str(single)) if !single.is_empty() => vec![single],
        Some(Json::Arr(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .filter(|name| !name.is_empty())
            .collect(),
        _ => return false,
    };
    names.as_slice() == ["h3"]
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn serve_inbounds_counted(
    label: &str,
    root: &Json,
    outbound: Option<&Outbound>,
    route: Option<&Arc<RouteShared>>,
    prove: bool,
    freedom: bool,
    portals: &crate::reverse::Portals,
    api: Option<&crate::commander::Api>,
    seed: Option<&crate::xray_pb::Seed>,
    test: bool,
    fallible: bool,
) -> usize {
    let routed =
        |inbound: &Json, source_known: bool| routed_out(outbound, route, inbound, source_known);
    let mut inbounds = 0;
    let configured = configured_emails(root);
    if let Some(list) = root.get("inbounds").and_then(Json::as_arr) {
        for inbound in list {
            let protocol =
                canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or(""));
            // The reference expands a port list and datagram carrier to one listener per port.
            let Some(addresses) = serve_addresses(inbound, protocol) else {
                continue;
            };
            // `-test` takes an ephemeral loopback port so the one a running instance holds is never touched.
            let listening = test.then(|| {
                addresses
                    .iter()
                    .map(|address| {
                        if address.is_empty() {
                            String::new()
                        } else {
                            "127.0.0.1:0".to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
            });
            let bind = listening.as_ref().unwrap_or(&addresses);
            if !inbound_served(protocol) {
                refuse_inbound(protocol, label, inbound);
                continue;
            }
            if prove {
                if let Some(shared) = route {
                    prove_server_route(shared, inbound, label);
                }
            }
            register_inbound_sniffing(inbound, label, &addresses);
            let handler_stop = api.map(|_| Arc::new(Stop::new()));
            let handler_tag = inbound_tag(inbound);
            let handler_raw = seed.and_then(|seed| {
                let tag = handler_tag.as_deref().unwrap_or_default();
                seed.inbounds
                    .iter()
                    .find(|(candidate, _)| candidate == tag)
                    .map(|(_, raw)| raw.clone())
            });
            let mut handler_stops: Vec<(Arc<Stop>, String)> = Vec::new();
            let vmess_users = (protocol == "vmess").then(|| {
                let make = || inbound_vmess_users(inbound);
                let users = match (route, handler_tag.as_deref()) {
                    (Some(shared), Some(tag)) => shared.vmess_users(tag, make),
                    _ => make(),
                };
                if let Some(shared) = route {
                    shared.restrict_user_portals(handler_tag.as_deref(), &users);
                }
                users
            });
            let before = inbounds;
            let h3_stop = if inbound_is_xhttp_h3(inbound) {
                handler_stop.as_ref()
            } else {
                None
            };
            for address in bind {
                match protocol {
                    "vless" => {
                        if serve_vless_inbound(
                            address,
                            inbound,
                            freedom,
                            label,
                            portals,
                            handler_stop.as_ref(),
                        ) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "trojan" => {
                        if serve_trojan_inbound(address, inbound, freedom, handler_stop.as_ref()) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "vmess" => {
                        let users = vmess_users.as_ref().expect("a vmess table");
                        if serve_vmess_inbound_users(
                            address,
                            inbound,
                            freedom,
                            handler_stop.as_ref().map(Arc::clone),
                            users,
                        ) {
                            if let Some(stop) = &handler_stop {
                                if !matches!(
                                    inbound_carrier(inbound),
                                    Carrier::Kcp(_)
                                        | Carrier::Xdrive { .. }
                                        | Carrier::Quic
                                        | Carrier::Hysteria(_)
                                ) {
                                    handler_stops.push((Arc::clone(stop), address.clone()));
                                }
                            }
                            inbounds += 1;
                        }
                    }
                    "shadowsocks" => {
                        if serve_shadowsocks_inbound(
                            address,
                            inbound,
                            freedom,
                            &configured,
                            handler_stop.as_ref(),
                        ) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "hysteria" => {
                        if serve_hysteria_inbound(address, inbound, freedom, label) {
                            inbounds += 1;
                        }
                    }
                    "tuic" => {
                        if crate::tuic::serve_inbound(
                            address,
                            inbound,
                            label,
                            freedom,
                            handler_stop.clone(),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "anytls" => {
                        if crate::anytls::serve_inbound(
                            address,
                            inbound,
                            label,
                            freedom,
                            handler_stop.clone(),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "socks" | "http" | "mixed" => {
                        let Some(out) = routed(inbound, true) else {
                            eprintln!(
                                "inbound `{protocol}` in {label} names no outbound to carry it"
                            );
                            continue;
                        };
                        // A front with no tcp carrier has no chain to arm, so the inbound is refused rather than served unmasked.
                        if crate::config::has_tcp_mask(inbound.get("streamSettings")) {
                            eprintln!("inbound `{protocol}` in {label} asks for a finalmask tcp chain it cannot arm");
                            continue;
                        }
                        let accounts = Arc::new(if protocol == "http" {
                            http_accounts(inbound)
                        } else {
                            socks_accounts(inbound)
                        });
                        let role = match protocol {
                            "http" => Role::Http { out, accounts },
                            "socks" => Role::Socks { out, accounts },
                            _ => Role::Mixed { out, accounts },
                        };
                        spawn_role(address, inbound_role(inbound, role), inbound_tag(inbound));
                        inbounds += 1;
                    }
                    "dokodemo-door" => {
                        if let Some(out) = routed(inbound, true) {
                            let (armed, tcp) = serve_dokodemo(
                                address,
                                inbound,
                                &out,
                                label,
                                handler_stop.as_ref(),
                                fallible,
                            );
                            inbounds += armed;
                            if tcp && !dokodemo_has(&dokodemo_networks(inbound), "udp") {
                                if let Some(stop) = &handler_stop {
                                    handler_stops.push((Arc::clone(stop), address.clone()));
                                }
                            }
                        }
                    }
                    "hc" => {
                        if serve_hc_inbound(address, inbound) {
                            inbounds += 1;
                        }
                    }
                    "blackhole" => {
                        if serve_blackhole_inbound(
                            address,
                            inbound,
                            label,
                            handler_stop.as_ref().map(Arc::clone),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "tun" => {
                        // A tun flow has no source or local address, so a reaching rule that names one is refused here.
                        if refuse_source(route, inbound, label, "tun", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        let spec = match tun_spec(inbound) {
                            Ok(spec) => spec,
                            Err(error) => {
                                eprintln!("tun inbound: {error}");
                                continue;
                            }
                        };
                        // `-test` proves the device spec without opening an interface the reference also leaves closed.
                        if test {
                            #[cfg(not(target_os = "linux"))]
                            if tun_stack(inbound) == "system" {
                                eprintln!("tun inbound: the system tun stack is Linux-only");
                                continue;
                            }
                            inbounds += 1;
                        } else if serve_tun_inbound(&spec, inbound, &out, address) {
                            inbounds += 1;
                        }
                    }
                    "wireguard" => {
                        if refuse_source(route, inbound, label, "tunnel", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        match crate::wg::serve_inbound(inbound, &out, address) {
                            Ok(_) => inbounds += 1,
                            Err(reason) => eprintln!("wireguard inbound {address}: {reason}"),
                        }
                    }
                    "masque" => {
                        if refuse_source(route, inbound, label, "MASQUE", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        match crate::masque::serve_inbound(inbound, &out, address) {
                            Ok(_) => inbounds += 1,
                            Err(reason) => eprintln!("masque inbound {address}: {reason}"),
                        }
                    }
                    _ => eprintln!("unsupported inbound protocol `{protocol}` in {label}"),
                }
            }
            if !prove && inbounds > before {
                if let Some(networks) = server_networks(inbound) {
                    if let Some(shared) = route {
                        shared.record_server_inbound(
                            handler_tag.clone(),
                            &networks,
                            portal_inbound(protocol),
                        );
                    }
                }
            }
            let handler_users = vmess_users;
            if let Some(stop) = &handler_stop {
                stop.expect_listeners(handler_stops.len());
            }
            if let Some(api) = api {
                if inbounds > before {
                    api.register_inbound(
                        handler_tag.as_deref().unwrap_or_default(),
                        handler_raw,
                        protocol,
                        handler_users,
                        handler_stops,
                    );
                }
            }
        }
    }
    inbounds
}

fn register_inbound_sniffing(inbound: &Json, label: &str, addresses: &[String]) {
    let sniffing = inbound_sniffing(inbound, label);
    for address in addresses {
        crate::sniff::register(address, sniffing.clone());
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn serve_inbounds(
    label: &str,
    root: &Json,
    outbound: Option<&Outbound>,
    route: Option<&Arc<RouteShared>>,
    freedom: bool,
    portals: &crate::reverse::Portals,
    api: Option<&std::sync::Arc<crate::commander::Api>>,
    seed: Option<&crate::xray_pb::Seed>,
) -> usize {
    serve_inbounds_counted(
        label,
        root,
        outbound,
        route,
        true,
        freedom,
        portals,
        api.map(std::sync::Arc::as_ref),
        seed,
        false,
        false,
    )
}

/// The listener lanes an inbound opens: the device's own (a tun names no socket), else one
/// address per port the reference expands. `None` is an inbound that bound nothing, skipped.
fn serve_addresses(inbound: &Json, protocol: &str) -> Option<Vec<String>> {
    if crate::tun::is_device(protocol) {
        return Some(vec![String::new()]);
    }
    let addresses = inbound_addresses(inbound);
    (!addresses.is_empty()).then_some(addresses)
}

/// A device inbound is refused with the reason the device layer computes from the config; any other unserved inbound is refused by name.
fn refuse_inbound(protocol: &str, label: &str, inbound: &Json) {
    if crate::tun::is_device(protocol) {
        let settings = inbound.get("settings");
        let field = |key| {
            settings
                .as_ref()
                .and_then(|s| s.get(key))
                .or_else(|| inbound.get(key))
        };
        let spec = crate::tun::Spec::new(
            field("name").and_then(Json::as_str),
            field("mtu").and_then(Json::as_u32).map(|m| m as usize),
        );
        eprintln!(
            "device inbound `{protocol}` in {label}: {}",
            crate::tun::refusal_reason(&spec)
        );
    } else {
        eprintln!("unsupported inbound protocol `{protocol}` in {label}: refused, not served");
    }
}

/// Served inbounds; the `tun` device inbound opens a native interface and relays TCP flows.
const SERVED_INBOUNDS: [&str; 16] = [
    "vless",
    "trojan",
    "vmess",
    "shadowsocks",
    "hysteria",
    "tuic",
    "anytls",
    "socks",
    "http",
    "mixed",
    "tun",
    "wireguard",
    "masque",
    "dokodemo-door",
    "hc",
    "blackhole",
];

/// Whether this protocol is an inbound this binary serves.
fn inbound_served(protocol: &str) -> bool {
    SERVED_INBOUNDS.contains(&protocol)
}

/// A listener's stop flag: removal sets it and dials the address, so a blocked accept wakes, sees
/// the flag, and drops the socket instead of waiting for a flow that will never come.
#[derive(Debug, Default)]
pub(crate) struct Stop {
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    listeners: std::sync::atomic::AtomicUsize,
    closed: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

impl Stop {
    pub(crate) fn new() -> Self {
        Self {
            listeners: std::sync::atomic::AtomicUsize::new(1),
            ..Self::default()
        }
    }

    /// The number of listener threads that must drop their sockets before the stop is closed.
    pub(crate) fn expect_listeners(&self, count: usize) {
        self.listeners
            .store(count.max(1), std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The same flag as an owned handle the QUIC driver can poll.
    pub(crate) fn shared(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.stopped)
    }

    fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn mark_closed(&self) {
        if self
            .listeners
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            > 1
        {
            return;
        }
        if let Ok(mut closed) = self.closed.lock() {
            *closed = true;
            self.wake.notify_all();
        }
    }

    /// Wait for the listener thread to drop its socket, so a caller that removes a handler does not
    /// report success while the port still accepts.
    pub(crate) fn wait_closed(&self) -> bool {
        let Ok(mut closed) = self.closed.lock() else {
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !*closed {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            let Ok(next) = self.wake.wait_timeout(closed, left) else {
                return false;
            };
            closed = next.0;
        }
        true
    }
}

/// Wake a listener the stop flag already named; the accepted connection carries no flow.
pub(crate) fn wake_listener(stop: &Stop, address: &str) {
    if !stop.stopped() {
        return;
    }
    if let Ok(target) = parse_target(address) {
        let _ = crate::conn::connect(&target, std::time::Duration::from_millis(500));
    }
}

fn spawn_role(address: &str, role: Role, tag: Option<String>) {
    spawn_role_stopped(address, role, tag, None);
}

fn spawn_role_stopped(
    address: &str,
    role: Role,
    tag: Option<String>,
    stop: Option<std::sync::Arc<Stop>>,
) {
    let listener = bind_listener(address, &role)
        .unwrap_or_else(|error| exit(&format!("cannot listen on {address}: {error}")));
    let address = address.to_owned();
    thread::spawn(move || accept_listener(listener, &address, &role, tag.as_deref(), stop));
}

fn try_spawn_role_stopped(
    address: &str,
    role: Role,
    tag: Option<String>,
    stop: Option<std::sync::Arc<Stop>>,
) -> std::io::Result<()> {
    let listener = bind_listener(address, &role)?;
    let address = address.to_owned();
    thread::spawn(move || accept_listener(listener, &address, &role, tag.as_deref(), stop));
    Ok(())
}

/// The role a listener serves, wrapped when its config says the first bytes are a PROXY header.
fn inbound_role(inbound: &Json, role: Role) -> Role {
    if crate::config::accept_proxy_protocol(inbound.get("streamSettings")) {
        Role::Proxied(Box::new(role))
    } else {
        role
    }
}

fn serve_vless_inbound(
    address: &str,
    inbound: &Json,
    freedom: bool,
    path: &str,
    portals: &crate::reverse::Portals,
    stop: Option<&Arc<Stop>>,
) -> bool {
    let users = inbound_users(inbound, portals);
    let carrier = inbound_carrier(inbound);
    let sec = stream_security(inbound);
    // QUIC arrives on UDP with its own handshake, so it never reaches the TCP accept loop.
    if matches!(carrier, Carrier::Quic) {
        return serve_vless_quic_inbound(address, inbound, &users, freedom, path);
    }
    if let Carrier::Unknown { network } = &carrier {
        eprintln!("unsupported network `{network}` in {path}: refused, not served");
        return false;
    }
    // An xdrive inbound has no socket: its `security` belongs to the store's lanes, so the stream is served as it arrives from the log.
    if let Carrier::Xdrive { settings } = &carrier {
        serve_vless_xdrive_inbound(address, inbound, &users, settings, freedom);
        return true;
    }
    match sec {
        // Hysteria carries its own QUIC TLS, so xray's `security: tls` names that handshake rather than a second layer above it.
        _ if matches!(carrier, Carrier::Hysteria(_)) => {
            let Carrier::Hysteria(config) = carrier else {
                return false;
            };
            if config.version != 2 {
                eprintln!(
                    "hysteria v{} carrier in {path} is not the v2 serve `hysteria` names: serves nothing",
                    config.version
                );
                return false;
            }
            let owned = address.to_owned();
            let Some(settings) = inbound.get("streamSettings") else {
                eprintln!("unreadable hysteria identity in {path}: serves nothing");
                return false;
            };
            let Some(identity) = crate::config::tls_identity_from_settings(settings) else {
                eprintln!("unreadable hysteria identity in {path}: serves nothing");
                return false;
            };
            let masq = crate::config::masquerade_from_stream(Some(settings));
            let users = Arc::clone(&users);
            let meter = crate::stats::inbound(inbound_tag(inbound).as_deref());
            let serve: crate::hysteria::Serve = Arc::new(move |flow| {
                serve_vless_hysteria(flow.with_meter(meter.clone()), &users, freedom);
            });
            serve_hysteria_thread(&owned, &config, &identity, &masq, &serve)
        }
        "tls" => serve_vless_tls_inbound(address, inbound, &users, &carrier, freedom, path, stop),
        "reality" => serve_vless_reality_inbound(address, inbound, &users, &carrier, freedom, path),
        _ if !vless_security_supported(sec) => {
            eprintln!("unsupported vless security `{sec}` in {path}: serves raw TCP only");
            false
        }
        _ => {
            let owned = address.to_owned();
            if let Carrier::Kcp(config) = carrier {
                let users = Arc::clone(&users);
                let meter = crate::stats::inbound(inbound_tag(inbound).as_deref());
                let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
                    let _flow = crate::accesslog::flow(Some(conn.remote_addr()), "", 0);
                    serve_vless_kcp(conn, &users, freedom, meter.clone());
                });
                return serve_kcp_bound(&owned, config, &serve, inbound);
            }
            let fallbacks = match server_fallbacks(inbound) {
                Ok(fallbacks) => fallbacks.map(Arc::from),
                Err(error) => {
                    eprintln!("{error} in {path}: inbound refused");
                    return false;
                }
            };
            let decryption = match crate::config::server_decryption(inbound) {
                Ok(decryption) => decryption,
                Err(error) => {
                    eprintln!("{error} in {path}: inbound refused");
                    return false;
                }
            };
            if decryption.is_some() && fallbacks.is_some() {
                eprintln!(
                    r#"VLESS settings: "fallbacks" can not be used together with "decryption" in {path}: inbound refused"#
                );
                return false;
            }
            let role = inbound_role(
                inbound,
                Role::Vless {
                    users,
                    carrier,
                    freedom,
                    fallbacks,
                    decryption,
                },
            );
            spawn_role_stopped(&owned, role, inbound_tag(inbound), None);
            true
        }
    }
}

/// The hysteria listener a vless inbound's carrier hands off to, carrying the same `udpIdleTimeout` and `quicParams` the stream named.
fn serve_hysteria_thread(
    address: &str,
    config: &ferrox_core::hysteria::Config,
    identity: &ferrox_core::tls::TlsServerConfig,
    masq: &ferrox_core::hysteria::Masquerade,
    serve: &crate::hysteria::Serve,
) -> bool {
    let Some(prepared) = crate::hysteria::prepare(
        address,
        identity,
        config.cc,
        &config.obfs_password,
        config.quic.as_ref(),
    ) else {
        return false;
    };
    let auth = config.auth.clone();
    let udp_idle = std::time::Duration::from_secs(config.udp_idle);
    let quic = config.quic;
    let realm = config.realm.clone();
    let masq = masq.clone();
    let serve = Arc::clone(serve);
    thread::spawn(move || {
        crate::hysteria::serve_prepared(
            prepared,
            std::slice::from_ref(&auth),
            &masq,
            &serve,
            udp_idle,
            quic.as_ref(),
            realm.as_deref(),
        );
    });
    true
}

thread_local! {
    /// The lane the flow on this thread resolved to; a dial under it carries that lane's counters.
    static OUTBOUND_TAG: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    /// The last dial this thread attempted: `Some(false)` refused, `Some(true)` connected, `None` never needed one.
    static DIAL_REPORT: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Run one front's dial and report the last attempt it made, so a caller can tell a
/// refused proxy leg from a clean close without threading a result through every lane.
pub(crate) fn observe_dial<T>(f: impl FnOnce() -> T) -> (T, Option<bool>) {
    DIAL_REPORT.with(|slot| slot.set(None));
    let value = f();
    (value, DIAL_REPORT.with(std::cell::Cell::get))
}

/// The tag of the one outbound a config without routing uses, which is what its counters key on.
static DEFAULT_OUTBOUND_TAG: Mutex<Option<String>> = Mutex::new(None);

fn install_default_outbound_tag(root: &Json) {
    let tag = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("tag"))
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned);
    *DEFAULT_OUTBOUND_TAG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = tag;
}

fn default_outbound_tag() -> Option<String> {
    DEFAULT_OUTBOUND_TAG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The counters a carrier that builds its own stream handles charges, for a flow on this thread.
pub(crate) fn flow_outbound_meter() -> Option<crate::stats::Meter> {
    OUTBOUND_TAG.with(|cell| {
        cell.borrow()
            .as_deref()
            .map(|tag| crate::stats::outbound(Some(tag)))
    })
}

/// The counters an inbound listener charges, for a carrier whose streams carry their own handles.
pub(crate) fn inbound_meter(inbound: &Json) -> crate::stats::Meter {
    crate::stats::inbound(inbound_tag(inbound).as_deref())
}

struct OutboundTag;

impl OutboundTag {
    fn enter(tag: Option<&str>) -> Self {
        OUTBOUND_TAG.with(|cell| *cell.borrow_mut() = tag.map(str::to_owned));
        Self
    }
}

impl Drop for OutboundTag {
    fn drop(&mut self) {
        OUTBOUND_TAG.with(|cell| *cell.borrow_mut() = None);
    }
}

/// xray's `sendThrough`: the source a flow leaves from, one address or a fresh host in a CIDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendThrough {
    Address(IpAddr),
    Cidr { base: IpAddr, prefix: u8 },
}

impl SendThrough {
    /// The source one dial binds; a CIDR rolls a host in its subnet as `ParseRandomIP` does.
    fn address(self) -> Result<IpAddr, std::io::Error> {
        let (base, prefix) = match self {
            Self::Address(address) => return Ok(address),
            Self::Cidr { base, prefix } => (base, prefix),
        };
        let bits = if base.is_ipv4() { 32 } else { 128 };
        if prefix == bits {
            return Ok(base);
        }
        let mut raw = [0u8; 16];
        #[cfg(test)]
        if FAIL_ENTROPY.with(std::cell::Cell::get) {
            return Err(std::io::Error::other("no entropy"));
        }
        getrandom::fill(&mut raw).map_err(std::io::Error::other)?;
        Ok(match base {
            IpAddr::V4(base) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                let base = u32::from(base) & mask;
                let roll = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) & !mask;
                IpAddr::V4(std::net::Ipv4Addr::from(base | roll))
            }
            IpAddr::V6(base) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                let base = u128::from(base) & mask;
                let roll = u128::from_le_bytes(raw) & !mask;
                IpAddr::V6(std::net::Ipv6Addr::from(base | roll))
            }
        })
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn resolve_source(send: Option<SendThrough>) -> Result<Option<IpAddr>, std::io::Error> {
    send.map(SendThrough::address).transpose()
}

thread_local! {
    /// The source the outbound a flow entered names, read by the one dial seam.
    static SEND_THROUGH: std::cell::Cell<Option<SendThrough>> = const { std::cell::Cell::new(None) };
    /// The `streamSettings.sockopt` that outbound names, read by the same seam.
    static DIAL_SOCKOPTS: std::cell::RefCell<Option<Arc<crate::sockopt::SocketOptions>>> = const { std::cell::RefCell::new(None) };
    /// The family the outbound a flow entered resolves a named target to before the request carries it.
    static TARGET_STRATEGY: std::cell::Cell<Option<FreedomDomain>> = const { std::cell::Cell::new(None) };
}

struct SendThroughGuard;

impl SendThroughGuard {
    fn enter(source: Option<SendThrough>) -> Self {
        SEND_THROUGH.with(|cell| cell.set(source));
        Self
    }
}

impl Drop for SendThroughGuard {
    fn drop(&mut self) {
        SEND_THROUGH.with(|cell| cell.set(None));
    }
}

/// The options the flow on this thread dials with, for a carrier that binds its own datagram socket.
pub(crate) fn flow_sockopts() -> Option<Arc<crate::sockopt::SocketOptions>> {
    DIAL_SOCKOPTS.with(|cell| cell.borrow().clone())
}

/// The source the flow on this thread leaves from, for a carrier that binds its own datagram socket.
pub(crate) fn flow_source() -> std::io::Result<Option<IpAddr>> {
    resolve_source(SEND_THROUGH.with(std::cell::Cell::get))
}

/// The options one flow's dial carries, cleared on drop so a pooled lane thread's next flow starts on the bare socket.
struct DialSockoptsGuard;

impl DialSockoptsGuard {
    fn enter(sockopts: Option<Arc<crate::sockopt::SocketOptions>>) -> Self {
        DIAL_SOCKOPTS.with(|cell| *cell.borrow_mut() = sockopts);
        Self
    }
}

impl Drop for DialSockoptsGuard {
    fn drop(&mut self) {
        DIAL_SOCKOPTS.with(|cell| *cell.borrow_mut() = None);
    }
}

/// The `targetStrategy` one flow's outbound names, cleared on drop so a lane that answers before the
/// request is built cannot leave it for the next flow on the thread.
struct TargetStrategyGuard;

impl TargetStrategyGuard {
    fn enter(strategy: Option<FreedomDomain>) -> Self {
        TARGET_STRATEGY.with(|cell| cell.set(strategy));
        Self
    }
}

impl Drop for TargetStrategyGuard {
    fn drop(&mut self) {
        TARGET_STRATEGY.with(|cell| cell.set(None));
    }
}

/// The outbound-level `sendThrough`: an address or a CIDR, while xray's two names for the inbound's
/// own addresses warn and leave the dial unbound.
fn parse_send_through(outbound: &Json) -> Result<Option<SendThrough>, String> {
    let Some(value) = outbound.get("sendThrough") else {
        return Ok(None);
    };
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let Some(text) = value.as_str() else {
        return Err("sendThrough is not a string".to_owned());
    };
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let refuse = || format!("unable to send through: {text}");
    if let Some((address, prefix)) = text.split_once('/') {
        let base = address.parse::<IpAddr>().map_err(|_| refuse())?;
        let prefix = prefix.parse::<u8>().map_err(|_| refuse())?;
        let bits = if base.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err(refuse());
        }
        return Ok(Some(SendThrough::Cidr { base, prefix }));
    }
    if text.eq_ignore_ascii_case("origin") || text.eq_ignore_ascii_case("srcip") {
        eprintln!(
            "outbound sendThrough `{text}` is not wired; the dial uses the OS source address"
        );
        return Ok(None);
    }
    text.parse::<IpAddr>()
        .map(|address| Some(SendThrough::Address(address)))
        .map_err(|_| refuse())
}

/// Whether any outbound names a dial setting, so a config with no `routing` block still builds the
/// plan that carries it.
fn dial_settings_present(root: &Json) -> Result<bool, String> {
    let outbounds = root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]);
    let mut present = false;
    for outbound in outbounds {
        present |= is_chain_config(outbound);
        present |= parse_send_through(outbound)?.is_some();
        present |= parse_outbound_sockopt(outbound)?.is_some();
        present |= parse_target_strategy(outbound)?.is_some();
    }
    Ok(present)
}

/// The outbound-level `targetStrategy`: the family the handler resolves a named target to before
/// the protocol sends it, and the reference's own refusal for a name it does not know.
fn parse_target_strategy(outbound: &Json) -> Result<Option<FreedomDomain>, String> {
    let Some(text) = outbound.get("targetStrategy").and_then(Json::as_str) else {
        return Ok(None);
    };
    let strategy = FreedomDomain::parse(text)
        .ok_or_else(|| format!("unsupported target domain strategy: {text}"))?;
    Ok((strategy != FreedomDomain::AsIs).then_some(strategy))
}

/// The socket options an outbound's `streamSettings.sockopt` names: the mark, interface and TCP
/// options its transport dial carries.
fn parse_outbound_sockopt(
    outbound: &Json,
) -> Result<Option<crate::sockopt::SocketOptions>, String> {
    let mut options = crate::sockopt::parse_outbound(
        outbound
            .get("streamSettings")
            .and_then(|s| s.get("sockopt")),
    )?;
    if let Some(tag) = detour_tag(outbound) {
        if let Some(named) = options
            .as_ref()
            .and_then(crate::sockopt::SocketOptions::dialer_proxy)
        {
            if named != tag {
                return Err(format!(
                    "outbound names both dialerProxy `{named}` and detour `{tag}`"
                ));
            }
        }
        options
            .get_or_insert_with(crate::sockopt::SocketOptions::default)
            .set_dialer_proxy(Some(tag));
    }
    let Some(options) = options else {
        return Ok(None);
    };
    if options.address_port_strategy() != crate::sockopt::AddressPortStrategy::None
        && outbound
            .get("protocol")
            .and_then(Json::as_str)
            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("freedom"))
    {
        return Err("freedom outbound does not support \"sockopt.addressPortStrategy\"".to_owned());
    }
    Ok(Some(options))
}

/// The routing table a config runs with: its own block, or an empty one when an outbound names a
/// dial setting the plan must carry.
fn routing_for(root: &Json) -> Result<Option<crate::router::Routing>, String> {
    match crate::router::Routing::parse(root)? {
        Some(routing) => Ok(Some(routing)),
        None if dial_settings_present(root)? => Ok(Some(crate::router::Routing::empty())),
        None => Ok(None),
    }
}

/// One dial that leaves from the source `sendThrough` names and carries the options `sockopt`
/// took; the plain dial stays the same.
fn dial_from(
    target: &SocketAddr,
    source: Option<IpAddr>,
    sockopts: Option<&crate::sockopt::SocketOptions>,
    fast: bool,
    timeout: std::time::Duration,
) -> std::io::Result<(std::net::TcpStream, bool)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    if timeout.is_zero() {
        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
    }
    let domain = if target.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if let Some(sockopts) = sockopts {
        sockopts.apply_to(&socket, *target)?;
    }
    if let Some(source) = source {
        socket.bind(&SockAddr::from(SocketAddr::new(source, 0)))?;
    }
    let armed = fast && crate::fastopen::arm(&socket).is_ok();
    crate::conn::connect_bounded(&socket, &SockAddr::from(*target), timeout)?;
    Ok((std::net::TcpStream::from(socket), armed))
}

/// Hand the target to the outbound a `dialerProxy` names over a loopback pipe, then return the
/// other end to the dialer. The hop owns its own source, options and strategy; the pipe owns none.
pub(crate) fn dial_through_proxy(
    target: SocketAddr,
    tag: &str,
    options: &crate::sockopt::SocketOptions,
) -> std::io::Result<Connection> {
    let Some(shared) = options.route() else {
        return Err(std::io::Error::other(
            "there is no outbound handler for dialerProxy",
        ));
    };
    if OUTBOUND_TAG.with(|cell| cell.borrow().as_deref() == Some(tag)) {
        return Err(std::io::Error::other(format!(
            "dialerProxy loops through `{tag}`"
        )));
    }
    if shared.outbound_ref(tag).is_none() {
        return Err(std::io::Error::other(
            "there is no outbound handler for dialerProxy",
        ));
    }
    let (source, sockopts, strategy) = if shared.default_tag.as_deref() == Some(tag) {
        (
            shared.default_source,
            shared.default_sockopts.clone(),
            shared.default_strategy,
        )
    } else {
        (
            shared.sources.get(tag).copied(),
            shared.sockopts.get(tag).cloned(),
            shared.strategies.get(tag).copied(),
        )
    };
    let (client, server) = crate::reverse::loopback_pair()
        .ok_or_else(|| std::io::Error::other("dialerProxy: no loopback pipe"))?;
    let name = tag.to_owned();
    thread::Builder::new()
        .name("ferrox-dialer-proxy".to_owned())
        .spawn(move || {
            let Some(out) = shared.outbound_ref(&name) else {
                return;
            };
            let _source = SendThroughGuard::enter(source);
            let _sockopts = DialSockoptsGuard::enter(sockopts);
            let _target = TargetStrategyGuard::enter(strategy);
            serve_connect(
                server,
                out,
                &Destination::Address(target),
                Front::Probe,
                &[],
                Some(&name),
                FlowFacts::default(),
            );
        })
        .map_err(|error| std::io::Error::other(format!("dialerProxy: {error}")))?;
    Ok(client)
}

/// The outbounds `serve_udp_lane_with` gives a datagram lane; a tagged dial refuses a hop
/// without one instead of handing its caller a socket no reply can reach.
fn udp_lane_supported(out: &Outbound) -> bool {
    match out {
        Outbound::Loopback(loopback) => loopback.dial.as_ref().is_some_and(udp_lane_supported),
        Outbound::Vless(vless) => match &vless.carrier {
            Carrier::Quic => true,
            Carrier::Raw(_) => vless.tls.is_none(),
            Carrier::Kcp(_) => vless.mux.tcp.is_some(),
            Carrier::Hysteria(_) => {
                vless.mux.tcp.is_none() && hysteria_dial_session(vless).is_some()
            }
            _ => false,
        },
        Outbound::Trojan(trojan) => {
            (matches!(trojan.carrier, Carrier::Hysteria(_))
                && trojan_hysteria_dial(trojan).is_some())
                || trojan_udp_carried(&trojan.carrier)
        }
        Outbound::Vmess(_)
        | Outbound::Hysteria(_)
        | Outbound::Tuic(_)
        | Outbound::Foxy(_)
        | Outbound::WireGuard(_)
        | Outbound::Masque(_)
        | Outbound::Warp(_)
        | Outbound::Freedom(_)
        | Outbound::Psiphon(_)
        | Outbound::Dns(_)
        | Outbound::ReversePortal(_) => true,
        Outbound::Shadowsocks(ss) => matches!(ss.carrier, Carrier::Raw(_)),
        Outbound::Socks(socks) => socks.version != crate::socks::Version::V4,
        Outbound::Http(_)
        | Outbound::AnyTls(_)
        | Outbound::Veepn(_)
        | Outbound::Route(_)
        | Outbound::Block(_)
        | Outbound::Metrics { .. }
        | Outbound::Api(_) => false,
    }
}

/// Hand a datagram destination to the outbound a `dialerProxy` names. The caller gets a socket
/// connected to a shim that frames each datagram into the hop's own UDP lane, so the hop owns the
/// carrier and its source, options and strategy, and the pipe owns none.
#[allow(clippy::too_many_lines)]
pub(crate) fn dial_udp_through_proxy(
    target: SocketAddr,
    tag: &str,
    options: &crate::sockopt::SocketOptions,
) -> Option<(UdpSocket, Arc<AtomicBool>)> {
    let shared = options.route()?;
    if OUTBOUND_TAG.with(|cell| cell.borrow().as_deref() == Some(tag)) {
        return None;
    }
    let out = shared.outbound_ref(tag)?.clone();
    if !udp_lane_supported(&out) {
        return None;
    }
    let (source, sockopts, strategy) = if shared.default_tag.as_deref() == Some(tag) {
        (
            shared.default_source,
            shared.default_sockopts.clone(),
            shared.default_strategy,
        )
    } else {
        (
            shared.sources.get(tag).copied(),
            shared.sockopts.get(tag).cloned(),
            shared.strategies.get(tag).copied(),
        )
    };
    let relay = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).ok()?;
    let relay_addr = relay.local_addr().ok()?;
    relay.set_read_timeout(Some(budgets::udp_idle())).ok()?;
    let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).ok()?;
    let client_addr = client.local_addr().ok()?;
    let request_in = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).ok()?;
    let request_out = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).ok()?;
    request_in.connect(client_addr).ok()?;
    request_out.connect(relay_addr).ok()?;
    client.connect(request_in.local_addr().ok()?).ok()?;
    request_in.set_read_timeout(Some(UDP_POLL)).ok()?;
    request_out.set_read_timeout(Some(UDP_POLL)).ok()?;
    client.set_read_timeout(Some(budgets::udp_idle())).ok()?;
    let reply_in = request_out.try_clone().ok()?;
    let reply_out = request_in.try_clone().ok()?;
    let stop = Arc::new(AtomicBool::new(false));
    let request_stop = Arc::clone(&stop);
    if thread::Builder::new()
        .name("ferrox-tagged-udp-in".to_owned())
        .spawn(move || {
            let mut buf = udp_buffer();
            let mut frame = Vec::with_capacity(HEAD + UDP_BUF);
            while !request_stop.load(Ordering::Relaxed) {
                match request_in.recv(&mut buf) {
                    Ok(n) => {
                        let frame = socks_udp_frame(&mut frame, &target, &buf[..n]);
                        if request_out.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(error) if is_timeout(&error) => {}
                    Err(_) => break,
                }
            }
        })
        .is_err()
    {
        return None;
    }
    let reply_stop = Arc::clone(&stop);
    if thread::Builder::new()
        .name("ferrox-tagged-udp-out".to_owned())
        .spawn(move || {
            let mut buf = udp_buffer();
            while !reply_stop.load(Ordering::Relaxed) {
                match reply_in.recv(&mut buf) {
                    Ok(n) => {
                        let Some((_, payload)) = parse_socks_udp(&buf[..n]) else {
                            continue;
                        };
                        if reply_out.send(payload).is_err() {
                            break;
                        }
                    }
                    Err(error) if is_timeout(&error) => {}
                    Err(_) => break,
                }
            }
        })
        .is_err()
    {
        stop.store(true, Ordering::Relaxed);
        return None;
    }
    let name = tag.to_owned();
    let relay_stop = Arc::clone(&stop);
    if thread::Builder::new()
        .name("ferrox-tagged-udp".to_owned())
        .spawn(move || {
            let _source = SendThroughGuard::enter(source);
            let _target = TargetStrategyGuard::enter(strategy);
            let _tag = OutboundTag::enter(Some(&name));
            serve_udp_lane_with(&relay, &out, None, None, source, sockopts.as_ref());
            relay_stop.store(true, Ordering::Relaxed);
        })
        .is_err()
    {
        stop.store(true, Ordering::Relaxed);
        return None;
    }
    Some((client, stop))
}

fn dial(target: &SocketAddr) -> Result<Connection, Failure> {
    dial_kind(target, false).map(|(stream, _)| stream)
}

/// What the kernel did with the SYN on a direct leg, so the caller knows whether the first write
/// rides it and whether the reference's rewrite is still needed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fast {
    /// A `dialerProxy` hop owns the hello, so this leg never asked for it.
    Off,
    /// A direct leg that could not ask: the kernel lacks `TCP_FASTOPEN_CONNECT`.
    Absent,
    /// The kernel held the SYN back: establishment starts at the first write, whose bytes ride the
    /// SYN as far as its payload room allows.
    Deferred,
    /// The handshake completed outright: this server sent no cookie, so the record is rewritten.
    Refused,
}

/// The same dial, with Fast Open wanted on a direct leg. A second round fetches the cookie the
/// first handshake did not carry; a failed second round keeps the first socket, and a server that
/// still answers directly leaves the first-record rewrite in place.
fn dial_kind(target: &SocketAddr, fast: bool) -> Result<(Connection, Fast), Failure> {
    // The seam's one dial entry: a named source or option builds the socket before the same budget, and neither is the TCP dial unchanged.
    let sockopts = DIAL_SOCKOPTS.with(|cell| cell.borrow().clone());
    if let Some(options) = sockopts.as_deref() {
        if let Some(tag) = options.dialer_proxy() {
            let stream = dial_through_proxy(*target, tag, options)
                .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?;
            no_delay(&stream);
            return Ok((outbound_metered(stream), Fast::Off));
        }
    }
    let source = resolve_source(SEND_THROUGH.with(std::cell::Cell::get))
        .map_err(|_| Failure::new(Stage::SocketConnected, Kind::Local))?;
    if fast && crate::fastopen::supported() {
        let mut kept = None;
        let mut outcome = Fast::Refused;
        let budget = budgets::dial();
        let started = std::time::Instant::now();
        for round in 0..2 {
            let left = budget.saturating_sub(started.elapsed());
            match dial_from(target, source, sockopts.as_deref(), true, left) {
                Ok((stream, armed)) => {
                    let deferred = armed && crate::fastopen::deferred(&stream);
                    kept = Some(stream);
                    if deferred {
                        outcome = Fast::Deferred;
                        break;
                    }
                    if !armed {
                        outcome = Fast::Absent;
                        break;
                    }
                }
                Err(_) if round == 0 => {
                    let plain = sockopts.map(|options| options.without_fast_open());
                    let left = budget.saturating_sub(started.elapsed());
                    match dial_from(target, source, plain.as_ref(), false, left) {
                        Ok((stream, _)) => {
                            kept = Some(stream);
                            outcome = Fast::Absent;
                            break;
                        }
                        Err(plain) => {
                            return Err(Failure::new(Stage::SocketConnected, Kind::of(&plain)));
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let stream =
            Connection::Tcp(kept.expect("the first round either returns or keeps a socket"));
        no_delay(&stream);
        return Ok((outbound_metered(stream), outcome));
    }
    let outcome = if fast { Fast::Absent } else { Fast::Off };
    let stream = match (source, sockopts) {
        (None, None) => crate::conn::connect(&crate::conn::Target::Ip(*target), budgets::dial())
            .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?,
        (source, sockopts) => Connection::Tcp(
            dial_from(target, source, sockopts.as_deref(), false, budgets::dial())
                .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?
                .0,
        ),
    };
    no_delay(&stream);
    Ok((outbound_metered(stream), outcome))
}

fn outbound_metered(stream: Connection) -> Connection {
    let meter = OUTBOUND_TAG.with(|cell| {
        cell.borrow()
            .as_deref()
            .map(|tag| crate::stats::outbound(Some(tag)))
    });
    match meter {
        Some(meter) => stream.with_meter(meter),
        None => stream,
    }
}

pub(crate) fn dial_or_report(target: &SocketAddr) -> Option<Connection> {
    match dial(target) {
        Ok(stream) => {
            DIAL_REPORT.with(|slot| slot.set(Some(true)));
            Some(stream)
        }
        Err(failure) => {
            DIAL_REPORT.with(|slot| slot.set(Some(false)));
            note_dial_failure(target, failure);
            None
        }
    }
}

fn note_dial_failure(target: &SocketAddr, failure: Failure) {
    if failure.worth_retrying() {
        RETRYABLE_DIALS.fetch_add(1, Ordering::Relaxed);
    } else {
        FATAL_DIALS.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(mut last) = LAST_DIAL.lock() {
        *last = Some((*target, failure));
    }
    #[cfg(test)]
    if let Ok(mut by_target) = LAST_DIAL_BY_TARGET.lock() {
        by_target.push((*target, failure));
    }
    echo_trace(&format!("dial {target} failed: {failure}"));
    eprintln!("dial {target} failed: {failure}");
}

/// The dial-failure report a lazy answer owes when the peer refuses it: the answer is read
/// after the relay starts, so the dial can no longer climb and the flow closes instead.
fn answer_refused(server: Option<SocketAddr>) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        if let Some(server) = server {
            note_dial_failure(&server, Failure::new(Stage::RequestSent, Kind::Dropped));
        }
    })
}

#[cfg(test)]
pub(crate) fn last_dial_failure() -> Option<(SocketAddr, Failure)> {
    LAST_DIAL.lock().ok().and_then(|last| *last)
}

#[cfg(test)]
pub(crate) fn last_dial_failure_at(target: SocketAddr) -> Option<Failure> {
    LAST_DIAL_BY_TARGET.lock().ok().and_then(|all| {
        all.iter()
            .rev()
            .find(|(at, _)| *at == target)
            .map(|(_, failure)| *failure)
    })
}

// The ladder rung a configured carrier answers, if it is on the ladder.
fn rung_of(carrier: &Carrier) -> Option<Rung> {
    match carrier {
        Carrier::Raw(_) => Some(Rung::Raw),
        Carrier::Ws { .. } => Some(Rung::Ws),
        Carrier::Xhttp { .. } => Some(Rung::Xhttp),
        Carrier::Grpc(_) => Some(Rung::Grpc),
        Carrier::HttpUpgrade { .. } => Some(Rung::HttpUpgrade),
        _ => None,
    }
}

// The (path, early-data budget) a non-raw rung reuses from the configured carrier.
fn stream_params(carrier: &Carrier) -> Option<(&str, u32)> {
    match carrier {
        Carrier::Ws { path, ed } => Some((path, *ed)),
        Carrier::Grpc(settings) => Some((settings.path.as_str(), 0)),
        Carrier::HttpUpgrade { path, .. } | Carrier::HttpHeader { path, .. } => Some((path, 0)),
        Carrier::Xhttp { settings, .. } => Some((settings.path.as_str(), 0)),
        _ => None,
    }
}

// The rung a dial starts at: the carrier this server was configured for, or Raw when it is off the ladder.
fn ladder_start(carrier: &Carrier) -> Rung {
    rung_of(carrier).unwrap_or(Rung::Raw)
}

static FATAL_DIALS: AtomicU64 = AtomicU64::new(0);

static RETRYABLE_DIALS: AtomicU64 = AtomicU64::new(0);
// The last dial failure, so a test that outlives its dial names the stage instead of timing out in silence.
static LAST_DIAL: std::sync::Mutex<Option<(SocketAddr, Failure)>> = std::sync::Mutex::new(None);

#[cfg(test)]
static LAST_DIAL_BY_TARGET: std::sync::Mutex<Vec<(SocketAddr, Failure)>> =
    std::sync::Mutex::new(Vec::new());

// Echo stage tracing behind one env flag, on stdout because the harness captures stdout per test.
static ECHO_TRACE_ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn echo_trace_on() -> bool {
    *ECHO_TRACE_ON.get_or_init(|| std::env::var("FERROX_ECHO_TRACE").is_ok())
}

static ECHO_T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub(crate) fn echo_trace(stage: &str) {
    if echo_trace_on() {
        let at = ECHO_T0
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis();
        println!("echo-trace: t={at} {stage}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DialFailures {
    pub fatal: u64,
    pub retryable: u64,
}

pub(crate) fn dial_failures() -> DialFailures {
    DialFailures {
        fatal: FATAL_DIALS.load(Ordering::Relaxed),
        retryable: RETRYABLE_DIALS.load(Ordering::Relaxed),
    }
}

fn report_dial_failures() {
    let failures = dial_failures();
    if failures.fatal + failures.retryable == 0 {
        return;
    }
    eprintln!(
        "dials: {} fatal, {} retryable",
        failures.fatal, failures.retryable
    );
    report_ladder_rates();
}

fn report_ladder_rates() {
    let ladder = Ladder::global();
    for rung in Rung::ALL {
        eprintln!(
            "ladder: {rung}: {} attempts, {} useful",
            ladder.attempts(rung),
            ladder.useful(rung)
        );
    }
    eprintln!(
        "ladder: {} climbs, {} descents",
        ladder.climbs(),
        ladder.descents()
    );
}

fn no_delay(stream: &Connection) {
    let _ = stream.set_nodelay(true);
}

/// Startup ends here: xray answers a config error with `Failed to start:` on stdout and status 23,
/// so a `-test` run reports the same verdict systemd's restart policy keys on.
pub(crate) fn exit(message: &str) -> ! {
    if crate::test_only() {
        println!("Failed to start: {message}");
        std::process::exit(23);
    }
    eprintln!("{message}");
    std::process::exit(1);
}

/// The RFC 1929 accounts a SOCKS5 front accepts: the name and the password the
/// credential exchange carries.
///
/// A front with no accounts asks for no authentication, the one this tree has always
/// served. A front that asks for the exchange and names no account refuses every
/// credential, which is what a config that asks for password authentication without
/// saying who may use it means.
#[derive(Debug, Clone, Default)]
struct SocksAccounts {
    /// Whether the front asks for the credential exchange at all.
    password: bool,
    /// The accounts the front accepts, each with the email and level its counters key on.
    pairs: Vec<SocksAccount>,
}

#[derive(Debug, Clone, Default)]
struct SocksAccount {
    user: String,
    pass: String,
    email: String,
    level: u32,
}

impl SocksAccounts {
    /// Whether the front wants the credential exchange, which is what decides the
    /// method the greeting must offer.
    fn wants_credential(&self) -> bool {
        self.password
    }

    /// The account the credential names, if this front knows it.
    fn account(&self, user: &[u8], pass: &[u8]) -> Option<&SocksAccount> {
        self.pairs
            .iter()
            .find(|account| account.user.as_bytes() == user && account.pass.as_bytes() == pass)
    }

    /// Whether the front has an account at all, which is what xray's HTTP side gates its 407 on.
    fn names_accounts(&self) -> bool {
        !self.pairs.is_empty()
    }
}

/// The no-authentication front: the account list a config that names none carries.
fn no_accounts() -> SocksAccounts {
    SocksAccounts::default()
}

/// The accounts a SOCKS front accepts, read from the inbound's own settings.
///
/// The shape is xray's: an `auth` of `password` and a list of `accounts` (or its `users` alias), each a `user` and a `pass`. A front that names no `auth` asks for no authentication.
fn socks_accounts(inbound: &Json) -> SocksAccounts {
    let settings = inbound.get("settings");
    let auth = settings
        .and_then(|s| s.get("auth"))
        .and_then(Json::as_str)
        .unwrap_or("");
    if !auth.eq_ignore_ascii_case("password") {
        return SocksAccounts::default();
    }
    let empty = Vec::new();
    let accounts = settings
        .and_then(|s| s.get("accounts").or_else(|| s.get("users")))
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    let mut pairs = Vec::new();
    for account in accounts {
        let Some(user) = account.get("user").and_then(Json::as_str) else {
            continue;
        };
        let Some(pass) = account.get("pass").and_then(Json::as_str) else {
            continue;
        };
        pairs.push(SocksAccount {
            user: user.to_owned(),
            pass: pass.to_owned(),
            email: account
                .get("email")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            level: account.get("level").and_then(Json::as_u32).unwrap_or(0),
        });
    }
    SocksAccounts {
        password: true,
        pairs,
    }
}

/// The accounts an HTTP front accepts: xray reads `accounts` when the key is there, else `users`, and asks for a credential only when the list names one.
fn http_accounts(inbound: &Json) -> SocksAccounts {
    let listed = inbound
        .get("settings")
        .and_then(|settings| settings.get("accounts").or_else(|| settings.get("users")))
        .and_then(Json::as_arr)
        .unwrap_or(&[]);
    let pairs = listed
        .iter()
        .map(|account| SocksAccount {
            user: account
                .get("user")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            pass: account
                .get("pass")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            email: account
                .get("email")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            level: account.get("level").and_then(Json::as_u32).unwrap_or(0),
        })
        .collect::<Vec<_>>();
    SocksAccounts {
        password: !pairs.is_empty(),
        pairs,
    }
}

#[derive(Debug, Clone)]
enum Role {
    Vless {
        users: VlessUsers,
        carrier: Carrier,
        freedom: bool,
        fallbacks: Option<Arc<[Fallback]>>,
        decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    },
    VlessTls {
        users: VlessUsers,
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
        fallbacks: Option<Arc<[Fallback]>>,
        decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    },
    VlessReality {
        users: VlessUsers,
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
        fallbacks: Option<Arc<[Fallback]>>,
        decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    },
    Trojan {
        keys: std::sync::Arc<[[u8; 56]]>,
        carrier: Carrier,
        freedom: bool,
        account: InboundAccount,
    },
    TrojanTls {
        keys: std::sync::Arc<[[u8; 56]]>,
        carrier: Carrier,
        freedom: bool,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
        fallbacks: Option<Arc<[Fallback]>>,
        account: InboundAccount,
    },
    TrojanReality {
        keys: std::sync::Arc<[[u8; 56]]>,
        carrier: Carrier,
        freedom: bool,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
        fallbacks: Option<Arc<[Fallback]>>,
        account: InboundAccount,
    },
    Vmess {
        users: crate::vmess::UsersRef,
        carrier: Carrier,
        freedom: bool,
        account: InboundAccount,
    },
    VmessTls {
        users: crate::vmess::UsersRef,
        carrier: Carrier,
        freedom: bool,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
        account: InboundAccount,
    },
    VmessReality {
        users: crate::vmess::UsersRef,
        carrier: Carrier,
        freedom: bool,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
        account: InboundAccount,
    },
    Shadowsocks {
        accounts: Arc<crate::shadowsocks::SsAccounts>,
        carrier: Carrier,
        freedom: bool,
        tls: Option<Arc<ferrox_core::tls::TlsServerConfig>>,
    },
    Socks {
        out: Outbound,
        accounts: Arc<SocksAccounts>,
    },
    Http {
        out: Outbound,
        accounts: Arc<SocksAccounts>,
    },
    Mixed {
        out: Outbound,
        accounts: Arc<SocksAccounts>,
    },
    /// dokodemo-door: a raw stream to the address its config rewrites every flow to,
    /// where a `portMap` entry for the flow's own port replaces the address. A
    /// `followRedirect` flow asks the kernel where it was really going instead.
    Dokodemo {
        out: Outbound,
        dest: DokodemoRewrite,
        port_map: HashMap<String, DokodemoPortMapEntry>,
        follow_redirect: bool,
        receive_original_destination: bool,
        transparent: Option<crate::sockopt::Tproxy>,
        mask: Option<ferrox_core::finalmask::Chain>,
        listen: Option<SocketAddr>,
        account: Box<InboundAccount>,
    },
    /// The role's first bytes are a PROXY protocol header, read before the carrier handshake.
    Proxied(Box<Role>),
}

impl Role {
    /// The post-TLS write chain an accepted stream of this role carries, from its tcp carrier.
    fn tcp_mask(&self) -> Option<&ferrox_core::finalmask::Chain> {
        match self {
            Role::Vless { carrier, .. }
            | Role::VlessTls { carrier, .. }
            | Role::VlessReality { carrier, .. }
            | Role::Trojan { carrier, .. }
            | Role::TrojanTls { carrier, .. }
            | Role::TrojanReality { carrier, .. }
            | Role::Vmess { carrier, .. }
            | Role::VmessTls { carrier, .. }
            | Role::VmessReality { carrier, .. }
            | Role::Shadowsocks { carrier, .. } => carrier.tcp_mask(),
            Role::Dokodemo { mask, .. } => mask.as_ref(),
            // A front with no tcp carrier has nowhere to arm a chain, so its inbound refuses one.
            Role::Socks { .. } | Role::Http { .. } | Role::Mixed { .. } => None,
            Role::Proxied(inner) => inner.tcp_mask(),
        }
    }

    /// The source-address filters an accepted stream of this role carries, from its tcp carrier.
    fn tcp_filter(&self) -> Option<&[ferrox_core::finalmask::SourceFilter]> {
        match self {
            Role::Vless { carrier, .. }
            | Role::VlessTls { carrier, .. }
            | Role::VlessReality { carrier, .. }
            | Role::Trojan { carrier, .. }
            | Role::TrojanTls { carrier, .. }
            | Role::TrojanReality { carrier, .. }
            | Role::Vmess { carrier, .. }
            | Role::VmessTls { carrier, .. }
            | Role::VmessReality { carrier, .. }
            | Role::Shadowsocks { carrier, .. } => carrier.tcp_filter(),
            Role::Dokodemo { mask, .. } => mask.as_ref().and_then(|chain| {
                let filters = chain.filters();
                (!filters.is_empty()).then_some(filters)
            }),
            Role::Socks { .. } | Role::Http { .. } | Role::Mixed { .. } => None,
            Role::Proxied(inner) => inner.tcp_filter(),
        }
    }

    /// The transparent spelling an accepted connection asks the kernel for.
    fn transparent(&self) -> Option<crate::sockopt::Tproxy> {
        match self {
            Role::Dokodemo { transparent, .. } => *transparent,
            Role::Proxied(inner) => inner.transparent(),
            _ => None,
        }
    }

    /// Whether this role's serve path ends in the pooled relay instead of pinning a thread for the flow.
    fn tcp_stream(&self) -> bool {
        match self {
            Role::Vless { carrier, .. }
            | Role::VlessTls { carrier, .. }
            | Role::VlessReality { carrier, .. }
            | Role::Trojan { carrier, .. }
            | Role::TrojanTls { carrier, .. }
            | Role::TrojanReality { carrier, .. }
            | Role::Vmess { carrier, .. }
            | Role::VmessTls { carrier, .. }
            | Role::VmessReality { carrier, .. }
            | Role::Shadowsocks { carrier, .. } => carrier.tcp_stream(),
            Role::Proxied(inner) => inner.tcp_stream(),
            Role::Socks { .. } | Role::Http { .. } | Role::Mixed { .. } | Role::Dokodemo { .. } => {
                false
            }
        }
    }

    /// The account a protocol's front authenticated, when the config names one.
    fn account(&self) -> Option<&InboundAccount> {
        match self {
            Role::Trojan { account, .. }
            | Role::TrojanTls { account, .. }
            | Role::TrojanReality { account, .. }
            | Role::Vmess { account, .. }
            | Role::VmessTls { account, .. }
            | Role::VmessReality { account, .. } => Some(account),
            Role::Vless { .. }
            | Role::VlessTls { .. }
            | Role::VlessReality { .. }
            | Role::Shadowsocks { .. }
            | Role::Socks { .. }
            | Role::Http { .. }
            | Role::Mixed { .. } => None,
            Role::Dokodemo { account, .. } => Some(account.as_ref()),
            Role::Proxied(inner) => inner.account(),
        }
    }

    /// Whether this role's TLS handshake can run on a lane instead of the accept thread.
    fn serves_polled_tls(&self) -> bool {
        matches!(self, Role::TrojanTls { .. })
    }

    /// Accepts the TLS session and hands it to the lanes, so the caller returns before the
    /// peer's first byte and the handshake parks off the workers.
    #[allow(clippy::too_many_lines)]
    fn serve_polled_tls(self, stream: Connection, sniffing: Option<Arc<crate::sniff::Sniffing>>) {
        let Role::TrojanTls {
            keys,
            carrier,
            freedom,
            server,
            fallbacks,
            account,
        } = self
        else {
            return;
        };
        if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
        let source = stream.peer_addr().ok();
        let email = account.email;
        let level = account.level;
        match carrier {
            Carrier::Raw(_) => {
                let Ok(raw) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let front = FrontNames::of(&session);
                    relay_trojan_with_fallbacks(
                        session,
                        Some(raw),
                        None,
                        keys.as_ref(),
                        &[],
                        freedom,
                        fallbacks.as_deref(),
                        crate::stats::Meter::default(),
                        &front,
                        &prefix,
                    );
                });
            }
            Carrier::Ws { path, .. } => {
                let Ok(out) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let (reader, writer) = session_halves(session, out);
                    let reader = crate::xhttp::ChainReader::new(prefix, reader);
                    serve_session_trojan_ws(reader, writer, &path, keys.as_ref(), freedom);
                });
            }
            Carrier::Xhttp { settings } => {
                let Ok(out) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let (reader, writer) = session_halves(session, out);
                    let reader = crate::xhttp::ChainReader::new(prefix, reader);
                    serve_trojan_xhttp_carrier(
                        reader,
                        writer,
                        &settings,
                        keys.as_ref(),
                        freedom,
                        |_, _| true,
                    );
                });
            }
            Carrier::HttpUpgrade { path, host, .. } => {
                let Ok(raw) = stream.try_clone() else {
                    return;
                };
                let Ok(out) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let (reader, writer) = session_halves(session, out);
                    let reader = crate::xhttp::ChainReader::new(prefix, reader);
                    serve_session_trojan_httpupgrade(
                        reader,
                        writer,
                        raw,
                        &path,
                        &host,
                        keys.as_ref(),
                        freedom,
                    );
                });
            }
            Carrier::HttpHeader {
                paths, response, ..
            } => {
                let Ok(raw) = stream.try_clone() else {
                    return;
                };
                let Ok(out) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let (reader, writer) = session_halves(session, out);
                    let reader = crate::xhttp::ChainReader::new(prefix, reader);
                    serve_session_trojan_httpheader(
                        reader,
                        writer,
                        raw,
                        &paths,
                        keys.as_ref(),
                        freedom,
                        response.as_deref(),
                    );
                });
            }
            Carrier::Grpc(settings) => {
                let Ok(out) = stream.try_clone() else {
                    return;
                };
                let Ok(session) = ferrox_core::tls::accept(&server, stream) else {
                    return;
                };
                run_tls_handshake(session, move |session, prefix| {
                    let _flow = lane_flow(sniffing, source, &email, level);
                    let (reader, writer) = session_halves(session, out);
                    let reader = crate::xhttp::ChainReader::new(prefix, reader);
                    serve_session_trojan_grpc(reader, writer, &settings, keys.as_ref(), freedom);
                });
            }
            Carrier::Quic
            | Carrier::Kcp(_)
            | Carrier::Hysteria(_)
            | Carrier::Masque
            | Carrier::Xdrive { .. }
            | Carrier::Http
            | Carrier::Unknown { .. } => {}
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Outbound {
    Vless(VlessOut),
    Trojan(TrojanOut),
    Vmess(VmessOut),
    Shadowsocks(ShadowsocksOut),
    Hysteria(Box<HysteriaOut>),
    Tuic(Arc<crate::tuic::TuicOut>),
    AnyTls(Arc<crate::anytls::AnyTlsOut>),
    Socks(SocksOut),
    Foxy(Box<FoxyOut>),
    Veepn(crate::veepn::VeepnOut),
    Psiphon(crate::psiphon::PsiphonOut),
    Freedom(Arc<FreedomOut>),
    Http(HttpOut),
    /// The rules choose the outbound per flow; the plan holds the registry and the fallback.
    Route(Arc<RoutePlan>),
    /// A re-inject through a named inbound, with its own sniffer applied before the dial.
    Loopback(Box<LoopbackOut>),
    /// The rules drop the flow after the front has granted it.
    Block(ferrox_core::blackhole::Response),
    /// The wire carries DNS queries; the lane answers, drops, and forwards them.
    Dns(DnsOut),
    /// A reverse portal, named by an inbound user's tag: its flows ride a mux session the bridge
    /// opened, and the portal answers them from its own side.
    ReversePortal(Arc<crate::reverse::Portal>),
    /// The flow rides a `WireGuard` tunnel: the userspace stack dials the
    /// destination the rules chose and encrypts every inner packet.
    WireGuard(Arc<crate::wg::WireGuardOut>),
    /// The flow rides a MASQUE CONNECT-IP tunnel: one HTTP/3 conversation carries
    /// every destination as inner IP packets over QUIC datagrams.
    Masque(Arc<crate::masque::MasqueOut>),
    /// WARP's two halves: `WireGuard` and MASQUE, with the first data-plane answer
    /// in auto mode deciding which one carries the flows.
    Warp(Arc<crate::warp::WarpOut>),
    /// The metrics app's tag: a flow routed here reaches its own HTTP handler on a loopback lane.
    Metrics {
        address: SocketAddr,
    },
    /// The flow is the management API's own gRPC transport.
    Api(std::sync::Arc<crate::commander::Api>),
}

impl Outbound {
    /// The edge this outbound dials, borrowed straight from the configured parts — no address `String` is cloned and no `host:port` is re-serialised per flow to be taken apart again by the same read.
    fn edge(&self) -> Option<SocketAddr> {
        match self {
            Self::Vless(vless) => resolve_outbound(&vless.address, vless.port),
            Self::Trojan(trojan) => resolve_outbound(&trojan.address, trojan.port),
            Self::Vmess(vmess) => resolve_outbound(&vmess.address, vmess.port),
            Self::Shadowsocks(ss) => resolve_outbound(&ss.address, ss.port),
            Self::Hysteria(hy) => resolve_outbound(&hy.address, hy.port),
            Self::Tuic(tuic) => tuic.edge(),
            Self::AnyTls(anytls) => anytls.edge(),
            Self::Socks(socks) => resolve_outbound(&socks.address, socks.port),
            Self::Http(http) => resolve_outbound(&http.address, http.port),
            Self::WireGuard(wireguard) => wireguard.edge(),
            Self::Masque(masque) => masque.edge(),
            Self::Warp(warp) => warp.edge(),
            Self::Psiphon(lane) => Some(lane.endpoint()),
            Self::Metrics { address } => Some(*address),
            Self::Foxy(_)
            | Self::Veepn(_)
            | Self::Freedom(_)
            | Self::Route(_)
            | Self::Loopback(_)
            | Self::Block(_)
            | Self::Dns(_)
            | Self::ReversePortal(_)
            | Self::Api(_) => None,
        }
    }

    fn resolved_lane_with_protocol(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        facts: FlowFacts<'_>,
    ) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        let Self::Route(plan) = self else {
            return (Picked::Static(self), None);
        };
        let owner = plan.process_owner(network, client);
        let facts = FlowFacts {
            source: None,
            local: None,
            process: owner.as_ref(),
            ..facts
        };
        plan.lane_with_protocol(asked, network, client, facts)
    }

    /// Whether any rule reads the HTTP attributes a front would have to parse off the request head.
    fn wants_attrs(&self) -> bool {
        matches!(
            self,
            Self::Route(plan)
                if plan
                    .shared
                    .routing
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .wants_attrs()
        )
    }
}

/// A routing answer: a configured outbound borrowed from the startup table, or an outbound the
/// management API added after startup and keeps alive for as long as a flow holds it.
pub(crate) enum Picked<'a> {
    Static(&'a Outbound),
    Dynamic(Arc<Outbound>),
}

impl std::ops::Deref for Picked<'_> {
    type Target = Outbound;

    fn deref(&self) -> &Outbound {
        match self {
            Self::Static(out) => out,
            Self::Dynamic(out) => out,
        }
    }
}

impl Picked<'_> {
    /// The answer as an owned outbound, for a lane that outlives the plan's borrow.
    pub(crate) fn into_owned(self) -> Outbound {
        match self {
            Self::Static(out) => out.clone(),
            Self::Dynamic(out) => (*out).clone(),
        }
    }
}

/// The lane `device_dial` resolved for a flow that still needs the front's own relay: the outbound
/// and its tag travel with the verdict, so the relay does not pick a second time off a balancer.
pub(crate) struct Lane {
    pub(crate) out: Arc<Outbound>,
    pub(crate) tag: Option<String>,
    /// The dial settings routing left for this lane. The fallback relay runs on a thread a
    /// `budgets::spawn` started, where the thread-locals `device_dial` set are not visible, so
    /// they travel with the lane and are reinstalled before the dial.
    source: Option<SendThrough>,
    sockopts: Option<Arc<crate::sockopt::SocketOptions>>,
    strategy: Option<FreedomDomain>,
}

impl Lane {
    /// Reinstall the captured settings on the thread that dials this lane.
    fn enter(&self) -> (SendThroughGuard, DialSockoptsGuard, TargetStrategyGuard) {
        (
            SendThroughGuard::enter(self.source),
            DialSockoptsGuard::enter(self.sockopts.clone()),
            TargetStrategyGuard::enter(self.strategy),
        )
    }
}

/// The outbounds the management API added or removed after startup. `changed` keeps the routing
/// fast path free of the lock until the first mutation; `closed` answers a removed tag the way a
/// blackhole outbound does.
#[derive(Debug, Default)]
struct Dynamic {
    added: HashMap<String, Arc<Outbound>>,
    removed: HashSet<String>,
}

/// One direct-dial server inbound remembered for a later rule proof.
#[derive(Debug, Clone)]
struct ServerInbound {
    tag: Option<String>,
    networks: Vec<crate::router::Network>,
    portal: bool,
}

/// Routing once its assets are read: the rules, every outbound a rule names, and the first
/// configured outbound as the fallback the reference calls its default handler.
#[derive(Debug)]
pub(crate) struct RouteShared {
    routing: Arc<RwLock<crate::router::Routing>>,
    tagged: HashMap<String, Outbound>,
    /// Each balancer's candidate tags, ordered by tag. Built once so a flow picks from a slice.
    balancers: Arc<HashMap<String, Vec<String>>>,
    /// Each balancer's fallback, so the server-route proof resolves every tag it can pick without the table's lock.
    balancer_fallbacks: HashMap<String, String>,
    /// Every server inbound's tag and target networks, including one the management API added,
    /// so an `AddRule` proves the same direct dial the start did.
    server_inbounds: Mutex<Vec<ServerInbound>>,
    /// The `VMess` users each inbound serves, so a rule change can refresh their portal restriction.
    vmess_users: Mutex<HashMap<String, crate::vmess::UsersRef>>,
    observatory: Option<Arc<crate::observatory::Observatory>>,
    /// The script router, kept outside the routing lock: a script callback re-enters the table.
    script_router: Option<Arc<crate::router_script::ScriptRouter>>,
    script: Option<crate::router_script::ScriptCallbacks>,
    default: Outbound,
    default_tag: Option<String>,
    /// The source each outbound's `sendThrough` names, and the default outbound's own.
    sources: HashMap<String, SendThrough>,
    default_source: Option<SendThrough>,
    /// The socket options each outbound's `streamSettings.sockopt` names, and the default's own.
    sockopts: HashMap<String, Arc<crate::sockopt::SocketOptions>>,
    default_sockopts: Option<Arc<crate::sockopt::SocketOptions>>,
    /// The `targetStrategy` each outbound names, and the default's own.
    strategies: HashMap<String, FreedomDomain>,
    default_strategy: Option<FreedomDomain>,
    has_dial_settings: bool,
    dynamic: Arc<RwLock<Dynamic>>,
    changed: AtomicBool,
    closed: Outbound,
    /// The table's own weak handle, so an outbound the management API adds later can bind a
    /// loopback's second routing pass without the table keeping itself alive.
    self_weak: OnceLock<Weak<RouteShared>>,
}

impl RouteShared {
    /// Rebuild the rule table from the config after a geodata download, keeping the balancer state
    /// a reparse cannot recreate. A script owns its own matchers and reads the files per call.
    pub(crate) fn reload_routing(&self, root: &Json) -> Result<(), String> {
        if self
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .carries_script()
        {
            return Ok(());
        }
        let Some(mut next) = crate::router::Routing::parse_in(root, crate::router::asset_dirs())?
        else {
            return Ok(());
        };
        let mut current = self
            .routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        next.adopt_added_rules(&mut current)?;
        next.adopt_balancer_state(&mut current);
        *current = next;
        Ok(())
    }

    /// Give every loopback outbound in this table a weak handle to the table, so its second
    /// routing pass resolves against the same live rules and tags the start built.
    fn bind_loopbacks(self: &Arc<Self>) {
        for out in self.tagged.values() {
            if let Outbound::Loopback(loopback) = out {
                loopback.bind(self);
            }
        }
        if let Outbound::Loopback(loopback) = &self.default {
            loopback.bind(self);
        }
    }

    /// The outbound a `geodata.outbound` tag names, borrowed from the registry rather than copied.
    fn outbound_ref(&self, tag: &str) -> Option<&Outbound> {
        if tag.is_empty() {
            return Some(&self.default);
        }
        self.tagged.get(tag)
    }

    /// The probe target a health check reaches by tag, with the same source, options and target
    /// strategy the route gives a flow; the chain tag resolves to its exit lane.
    pub(crate) fn probe_target(self: &Arc<Self>, tag: &str) -> Option<ProbeTarget> {
        let out = if self.default_tag.as_deref() == Some(tag) {
            self.default.clone()
        } else {
            self.tagged.get(tag)?.clone()
        };
        Some(self.probe_target_with(tag, out))
    }

    /// A target for a configured tag no rule selected: the route never built it, but its dial
    /// settings are still in the table, so a probe reads the same hop a flow would.
    pub(crate) fn probe_target_with(self: &Arc<Self>, tag: &str, out: Outbound) -> ProbeTarget {
        if let Outbound::Loopback(loopback) = &out {
            loopback.bind(self);
        }
        if let Outbound::Masque(masque) = &out {
            masque.install_route(self);
        }
        let (source, sockopts, strategy) = if self.default_tag.as_deref() == Some(tag) {
            (
                self.default_source,
                self.default_sockopts.clone(),
                self.default_strategy,
            )
        } else {
            (
                self.sources.get(tag).copied(),
                self.sockopts.get(tag).cloned(),
                self.strategies.get(tag).copied(),
            )
        };
        ProbeTarget {
            out,
            source,
            sockopts,
            strategy,
            tag: Some(tag.to_owned()),
        }
    }

    /// The outbound a `geodata.outbound` tag names, or the default when the tag is empty, which is
    /// what the reference's forced-tag dispatch falls back to.
    pub(crate) fn outbound_for(&self, tag: &str) -> Option<Outbound> {
        self.outbound_ref(tag)
            .cloned()
            .or_else(|| crate::reverse::portal_for_tag(tag).map(Outbound::ReversePortal))
    }

    /// Remember a direct-dial server inbound the management API added, so a later rule that can
    /// reach it is proved against the lane it really serves.
    fn record_server_inbound(
        &self,
        tag: Option<String>,
        networks: &[crate::router::Network],
        portal: bool,
    ) {
        let mut inbounds = self
            .server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inbounds
            .iter()
            .any(|inbound| inbound.tag == tag && inbound.networks.as_slice() == networks)
        {
            inbounds.push(ServerInbound {
                tag,
                networks: networks.to_vec(),
                portal,
            });
        }
    }

    fn vmess_users(
        &self,
        tag: &str,
        make: impl FnOnce() -> crate::vmess::UsersRef,
    ) -> crate::vmess::UsersRef {
        let mut users = self
            .vmess_users
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::sync::Arc::clone(users.entry(tag.to_owned()).or_insert_with(make))
    }

    fn restrict_user_portals(&self, tag: Option<&str>, users: &crate::vmess::UsersRef) {
        let routing = self
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        users.restrict_portals(routing.portal_targets(
            tag,
            &|named| portal_tag(self, named),
            &|named| portal_domain(self, named),
        ));
    }

    fn forget_vmess_users(&self, tag: &str) {
        self.vmess_users
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tag);
    }

    fn refresh_portal_rules(&self) {
        let users: Vec<(String, crate::vmess::UsersRef)> = self
            .vmess_users
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(tag, users)| (tag.clone(), std::sync::Arc::clone(users)))
            .collect();
        for (tag, users) in users {
            self.restrict_user_portals(Some(&tag), &users);
        }
    }

    /// Forget a server inbound whose listener the management API stopped.
    fn forget_server_inbound(&self, tag: &str) {
        self.server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|inbound| inbound.tag.as_deref() != Some(tag));
    }

    /// Register an outbound the management API added. A tag a rule already names, or the default,
    /// is a duplicate until it was removed; a removed tag can be added again, as in the reference.
    fn add_outbound(&self, tag: &str, out: Outbound) -> Result<(), String> {
        let server_inbounds = self
            .server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        {
            let routing = self
                .routing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for inbound in &server_inbounds {
                routing.server_routes(&server_proof_for_candidate(
                    self,
                    inbound.tag.as_deref(),
                    &inbound.networks,
                    tag,
                    &out,
                    inbound.portal,
                ))?;
            }
        }
        let mut dynamic = self
            .dynamic
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let static_tag = (self.tagged.contains_key(tag)
            || Some(tag) == self.default_tag.as_deref())
            && !dynamic.removed.contains(tag);
        if static_tag || dynamic.added.contains_key(tag) {
            return Err(format!("existing tag found: {tag}"));
        }
        dynamic.removed.remove(tag);
        if let Some(shared) = self.self_weak.get().and_then(Weak::upgrade) {
            if let Outbound::Loopback(loopback) = &out {
                loopback.bind(&shared);
            }
            if let Outbound::Masque(masque) = &out {
                masque.install_route(&shared);
            }
        }
        dynamic.added.insert(tag.to_owned(), Arc::new(out));
        self.changed.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Drop a tag from routing. A flow that still names it is blocked rather than served by a lane
    /// the operator removed; a tag nobody knows is a no-op, as in the reference.
    fn remove_outbound(&self, tag: &str) {
        let mut dynamic = self
            .dynamic
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let was_added = dynamic.added.remove(tag).is_some();
        let was_static = self.tagged.contains_key(tag) || Some(tag) == self.default_tag.as_deref();
        if was_static {
            dynamic.removed.insert(tag.to_owned());
        }
        if was_added || was_static {
            self.changed.store(true, Ordering::Relaxed);
        }
    }

    /// The tag a tested context routes to: the same table, the same balancer pick and the same
    /// script a live flow would get, without the default outbound the reference leaves to the caller.
    /// A matched rule's webhook fires here too, as the reference's `PickRoute` fires it.
    fn routed_tag(&self, probe: &crate::router::Probe<'_>) -> Result<Option<String>, String> {
        if let Some(script) = self.script_router.as_deref() {
            let Some(callbacks) = self.script.as_ref() else {
                return Ok(None);
            };
            let first = probe.flow(probe.targets[0], probe.sources[0], probe.locals[0]);
            if let Some(tag) = script.route(&first, callbacks)? {
                return Ok(Some(tag));
            }
        }
        let (target, webhook) = {
            let routing = self
                .routing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(hit) = routing.probe_rule(probe) else {
                return Ok(None);
            };
            let target = match hit.target {
                crate::router::RouteTarget::Outbound(tag) => Ok(tag.to_owned()),
                crate::router::RouteTarget::Balancer(tag) => Err(tag.to_owned()),
            };
            (target, hit.webhook.cloned())
        };
        let tag = match target {
            Ok(tag) => tag,
            Err(tag) => {
                let routing = self
                    .routing
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(balancer) = routing.balancer(&tag) else {
                    return Ok(None);
                };
                let candidates = self
                    .balancers
                    .get(&tag)
                    .expect("startup built every balancer's candidates");
                let observed = self
                    .observatory
                    .as_deref()
                    .map(crate::observatory::Observatory::snapshot);
                if let Some(picked) = balancer.pick(candidates, observed.as_deref()) {
                    picked.into_owned()
                } else if let Some(fallback) = balancer.fallback() {
                    fallback.to_owned()
                } else {
                    return Err("balancing strategy returns empty tag".to_owned());
                }
            }
        };
        if let Some(webhook) = webhook {
            let destination = destination_of(probe);
            webhook.fire(&crate::webhook::Event {
                email: probe.user,
                level: None,
                protocol: probe.protocol,
                network: probe.network,
                source: event_address(probe.sources.first().copied().flatten(), probe.source_port),
                destination: destination.as_ref(),
                original: None,
                route: None,
                inbound_tag: probe.inbound_tag,
                inbound_name: None,
                local: event_address(probe.locals.first().copied().flatten(), probe.local_port),
                outbound_tag: &tag,
            });
        }
        Ok(Some(tag))
    }
}

/// An event address: the reference joins a named address with its port, whether or not it is named.
fn event_address(ip: Option<std::net::IpAddr>, port: u16) -> Option<std::net::SocketAddr> {
    ip.map(|ip| std::net::SocketAddr::new(ip, port))
}

/// The destination a tested context names: a domain first, then its first target address, and none
/// when it names neither, which the reference's event renders as null.
fn destination_of(probe: &crate::router::Probe<'_>) -> Option<Destination> {
    let port = probe.port.unwrap_or(0);
    match (probe.domain, probe.targets.first().copied().flatten()) {
        (Some(domain), _) => Some(Destination::Name(domain.to_owned(), port)),
        (None, Some(ip)) => Some(Destination::Address(std::net::SocketAddr::new(ip, port))),
        (None, None) => None,
    }
}

/// What an inbound added after startup needs to open: the same lanes, portals, counters and policy
/// the configured inbounds got, kept alive for the management API's lifetime.
#[derive(Debug)]
pub(crate) struct Runtime {
    outbound: Option<Outbound>,
    route: Option<Arc<RouteShared>>,
    freedom: bool,
    portals: Arc<crate::reverse::Portals>,
}

impl Runtime {
    fn new(
        outbound: Option<Outbound>,
        route: Option<Arc<RouteShared>>,
        freedom: bool,
        portals: Arc<crate::reverse::Portals>,
    ) -> Self {
        Self {
            outbound,
            route,
            freedom,
            portals,
        }
    }

    /// Build the handler the request carries and put it in the routing table. Without routing the
    /// handler is built and dropped, which is the reference's unused manager entry.
    pub(crate) fn add_outbound(&self, tag: &str, raw: &[u8]) -> Result<(), String> {
        let config = crate::xray_pb::outbound(raw)?;
        let out = build_outbound(&config, tag)?;
        if let Some(route) = &self.route {
            route.add_outbound(tag, out)?;
        }
        Ok(())
    }

    pub(crate) fn remove_outbound(&self, tag: &str) {
        if let Some(route) = &self.route {
            route.remove_outbound(tag);
        }
    }

    /// Every rule in table order, for `RoutingService.ListRule`; an unconfigured table lists none.
    pub(crate) fn listed_rules(&self) -> Vec<crate::router::ListedRule> {
        let Some(route) = &self.route else {
            return Vec::new();
        };
        route
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .listed_rules()
            .collect()
    }

    /// Append or replace the rule table, for `RoutingService.AddRule`; a table-less config has
    /// nowhere to put a rule and answers the reference's "routing not configured". Every server
    /// inbound proves the candidate table first, so a rule it would silently never evaluate is refused.
    pub(crate) fn add_rules(
        &self,
        rules: &[crate::json::Json],
        append: bool,
    ) -> Result<(), String> {
        let Some(route) = &self.route else {
            return Err("routing not configured".to_owned());
        };
        let known = |tag: &str| {
            route.tagged.contains_key(tag)
                || Some(tag) == route.default_tag.as_deref()
                || crate::reverse::portal_for_tag(tag).is_some()
        };
        let direct = |named: &str| direct_tag(route, named);
        let server_inbounds = route
            .server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let proofs: Vec<crate::router::ServerProof<'_>> = server_inbounds
            .iter()
            .map(|inbound| {
                server_proof(
                    route,
                    inbound.tag.as_deref(),
                    &inbound.networks,
                    &direct,
                    inbound.portal,
                )
            })
            .collect();
        route
            .routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .add_rules(rules, append, known, &proofs)?;
        route.refresh_portal_rules();
        Ok(())
    }

    /// Drop a server inbound the management API stopped, so a later rule is not proved against a
    /// lane nothing serves any more.
    pub(crate) fn forget_server_inbound(&self, tag: &str) {
        if let Some(route) = &self.route {
            route.forget_server_inbound(tag);
            route.forget_vmess_users(tag);
        }
    }

    /// Drop every rule carrying `tag`, for `RoutingService.RemoveRule`.
    pub(crate) fn remove_rules(&self, tag: &str) -> Result<(), String> {
        let Some(route) = &self.route else {
            return Err("routing not configured".to_owned());
        };
        let server_inbounds = route
            .server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let direct = |named: &str| direct_tag(route, named);
        let proofs: Vec<crate::router::ServerProof<'_>> = server_inbounds
            .iter()
            .map(|inbound| {
                server_proof(
                    route,
                    inbound.tag.as_deref(),
                    &inbound.networks,
                    &direct,
                    inbound.portal,
                )
            })
            .collect();
        route
            .routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove_rules(tag, &proofs)?;
        route.refresh_portal_rules();
        Ok(())
    }

    /// The tag a `RoutingService.TestRoute` context routes to, or `None` for xray's no-clue.
    pub(crate) fn tested_route(
        &self,
        probe: &crate::router::Probe<'_>,
    ) -> Result<Option<String>, String> {
        let Some(route) = &self.route else {
            return Ok(None);
        };
        route.routed_tag(probe)
    }

    /// A balancer's forced tag and its strategy's principle target; an unknown tag is the
    /// reference's `cannot find tag`.
    pub(crate) fn balancer_info(&self, tag: &str) -> Result<(String, Vec<String>), &'static str> {
        let Some(route) = &self.route else {
            return Err("cannot find tag");
        };
        let routing = route
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(balancer) = routing.balancer(tag) else {
            return Err("cannot find tag");
        };
        let candidates = route.balancers.get(tag).map_or(&[][..], Vec::as_slice);
        let observed = route
            .observatory
            .as_deref()
            .map(crate::observatory::Observatory::snapshot);
        Ok((
            balancer.forced(),
            balancer
                .principle(candidates, observed.as_deref())
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ))
    }

    /// Force a balancer's pick; an empty target hands it back to the strategy. A forced target,
    /// and the strategy's own picks once the target is cleared, must still dial direct for every
    /// server inbound, so a non-direct pick is refused and the previous one restored rather than
    /// leaving a proven table pointing elsewhere. The write lock serializes overrides and keeps a
    /// pick from seeing a target before its proof.
    pub(crate) fn override_balancer(&self, tag: &str, target: &str) -> Result<(), String> {
        let Some(route) = &self.route else {
            return Err("cannot find tag".to_owned());
        };
        let routing = route
            .routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(balancer) = routing.balancer(tag) else {
            return Err("cannot find tag".to_owned());
        };
        let previous = balancer.forced();
        balancer.force(target);
        let direct = |named: &str| direct_tag(route, named);
        let server_inbounds = route
            .server_inbounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for inbound in &server_inbounds {
            if let Err(reason) = routing.server_routes(&server_proof(
                route,
                inbound.tag.as_deref(),
                &inbound.networks,
                &direct,
                inbound.portal,
            )) {
                balancer.force(&previous);
                return Err(reason);
            }
        }
        Ok(())
    }
}

/// The runtime a management test starts from: the same route and outbound the config names.
#[cfg(test)]
pub(crate) fn test_runtime(root: &Json) -> Runtime {
    let routing = crate::router::Routing::parse_in(root, Vec::new()).expect("routing parses");
    let portals = Arc::new(crate::reverse::Portals::default());
    let route = routing.map(|routing| route_shared(root, routing, &portals, None).expect("shared"));
    let outbound = find_outbound(root).expect("outbound builds");
    Runtime::new(outbound, route, true, portals)
}

/// Serve the handlers one management call added, through the same inbound path the startup config
/// used; the route proof is skipped because the reference does not prove routes on an add.
pub(crate) fn serve_dynamic_inbounds(
    runtime: &Runtime,
    root: &Json,
    seed: &crate::xray_pb::Seed,
    api: &crate::commander::Api,
) -> usize {
    serve_inbounds_counted(
        "commander",
        root,
        runtime.outbound.as_ref(),
        runtime.route.as_ref(),
        false,
        runtime.freedom,
        &runtime.portals,
        Some(api),
        Some(seed),
        false,
        true,
    )
}

