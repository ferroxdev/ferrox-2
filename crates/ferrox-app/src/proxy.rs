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

/// What an inbound already resolved about a flow besides its destination: the protocol it read, the
/// authenticated account, the HTTP head, and the process that owns the client socket.
#[derive(Clone, Copy, Default)]
struct FlowFacts<'a> {
    protocol: Option<&'a str>,
    user: Option<&'a str>,
    level: Option<u32>,
    attrs: Option<&'a crate::router::Attributes<'a>>,
    process: Option<&'a crate::process::Owner>,
    /// The destination before the sniffer rewrote it, and the rewrite a `routeOnly` sniffer routes
    /// by but does not dial.
    original: Option<&'a Destination>,
    route: Option<&'a Destination>,
    /// The UDP datagram's own endpoints, which replace the TCP control connection's for a split association.
    source: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

/// One inbound's view of the routes: its tag decides which rules may see a flow, and whether the
/// transport can answer the selectors that name source and local addresses.
#[derive(Debug, Clone)]
pub(crate) struct RoutePlan {
    shared: Arc<RouteShared>,
    inbound_tag: Option<String>,
    inbound_name: Option<String>,
    source_known: bool,
    skip_dns: bool,
}

/// The one decision a SOCKS association can carry, or `Split` when each datagram names its own.
#[derive(Debug, Clone)]
pub(crate) enum Association {
    Default,
    Tag(String),
    Split,
}

impl RoutePlan {
    fn new(
        shared: Arc<RouteShared>,
        inbound_tag: Option<String>,
        inbound_name: Option<String>,
        source_known: bool,
    ) -> Self {
        Self {
            shared,
            inbound_tag,
            inbound_name,
            source_known,
            skip_dns: false,
        }
    }

    /// A loopback re-inject keeps the named tag's domain rules but does not resolve a name, the
    /// reference's `SkipDNSResolve`.
    fn without_dns(mut self) -> Self {
        self.skip_dns = true;
        self
    }

    fn wants_attrs(&self) -> bool {
        self.shared
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .wants_attrs()
    }

    /// The lane a SOCKS association picks, read from the live table so a rule the management API
    /// added or removed after startup reaches the UDP path.
    fn association(&self) -> Association {
        match self
            .shared
            .routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .udp_tag(
                self.inbound_tag.as_deref(),
                self.shared.default_tag.as_deref(),
            ) {
            Ok(None) => Association::Default,
            Ok(Some(tag)) => Association::Tag(tag.to_owned()),
            Err(()) => Association::Split,
        }
    }

    fn target(&self, tag: &str) -> Picked<'_> {
        if self.shared.changed.load(Ordering::Relaxed) {
            let dynamic = self
                .shared
                .dynamic
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if dynamic.removed.contains(tag) {
                return Picked::Static(&self.shared.closed);
            }
            if let Some(out) = dynamic.added.get(tag) {
                return Picked::Dynamic(Arc::clone(out));
            }
        }
        if Some(tag) == self.shared.default_tag.as_deref() {
            return Picked::Static(&self.shared.default);
        }
        match self.shared.tagged.get(tag) {
            Some(out) => Picked::Static(out),
            None => Picked::Static(&self.shared.closed),
        }
    }

    /// The fallback lane, resolved through the same dynamic table so removing the default tag
    /// blocks it instead of serving a handler the operator dropped.
    fn default_lane(&self) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        match self.shared.default_tag.as_deref() {
            Some(tag) => (self.target(tag), Some(std::borrow::Cow::Borrowed(tag))),
            None => (Picked::Static(&self.shared.default), None),
        }
    }

    pub(crate) fn pick(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        user: Option<&str>,
    ) -> Picked<'_> {
        let facts = FlowFacts {
            source: None,
            local: None,
            user,
            ..FlowFacts::default()
        };
        self.pick_with_protocol(asked, network, client, facts)
    }

    fn pick_with_protocol(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        facts: FlowFacts<'_>,
    ) -> Picked<'_> {
        let owner = self.process_owner(network, client);
        let facts = FlowFacts {
            source: None,
            local: None,
            process: owner.as_ref(),
            ..facts
        };
        self.lane_with_protocol(asked, network, client, facts).0
    }

    /// The outbound one flow takes and the tag that names its lane, or the default when no rule
    /// matched. A balancer picks per flow; its fallback, then the default handler, covers no pick.
    #[cfg(test)]
    fn lane(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        user: Option<&str>,
    ) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        let facts = FlowFacts {
            source: None,
            local: None,
            user,
            ..FlowFacts::default()
        };
        self.lane_with_protocol(asked, network, client, facts)
    }

    /// The process that owns the client socket, looked up once per flow and only when a rule names
    /// it. A PROXY header's reported peer is skipped: it can name another local process.
    fn process_owner(
        &self,
        network: crate::router::Network,
        client: Option<&Connection>,
    ) -> Option<crate::process::Owner> {
        self.process_owner_from(network, client?.socket_peer().ok()?)
    }

    fn process_owner_from(
        &self,
        network: crate::router::Network,
        source: SocketAddr,
    ) -> Option<crate::process::Owner> {
        if !self.source_known
            || !self
                .shared
                .routing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .wants_process()
        {
            return None;
        }
        crate::process::owner(network, source)
    }

    fn lane_with_protocol(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        facts: FlowFacts<'_>,
    ) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        let answer = self.lane_with_protocol_untracked(asked, network, client, facts);
        if self.shared.has_dial_settings {
            self.carry_dial_settings(answer.1.as_deref());
        }
        answer
    }

    /// The source and options the picked lane's tag names, left for the one dial seam.
    fn carry_dial_settings(&self, tag: Option<&str>) {
        let source = match tag {
            Some(tag) => self.shared.sources.get(tag).copied(),
            None => self.shared.default_source,
        };
        SEND_THROUGH.with(|cell| cell.set(source));
        let sockopts = match tag {
            Some(tag) => self.shared.sockopts.get(tag).cloned(),
            None => self.shared.default_sockopts.clone(),
        };
        DIAL_SOCKOPTS.with(|cell| *cell.borrow_mut() = sockopts);
        let strategy = match tag {
            Some(tag) => self.shared.strategies.get(tag).copied(),
            None => self.shared.default_strategy,
        };
        TARGET_STRATEGY.with(|cell| cell.set(strategy));
    }

    fn lane_with_protocol_untracked(
        &self,
        asked: &Destination,
        network: crate::router::Network,
        client: Option<&Connection>,
        facts: FlowFacts<'_>,
    ) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        let (domain, ip) = match asked {
            Destination::Name(host, _) => (Some(host.as_str()), None),
            Destination::Address(address) => (None, Some(address.ip())),
        };
        let (source, local) = if self.source_known {
            (
                facts
                    .source
                    .or_else(|| client.and_then(|client| client.peer_addr().ok())),
                facts
                    .local
                    .or_else(|| client.and_then(|client| client.local_addr().ok())),
            )
        } else {
            (facts.source, facts.local)
        };
        let (source, source_port) = source.map_or((None, 0), |addr| (Some(addr.ip()), addr.port()));
        let (local, local_port) = local.map_or((None, 0), |addr| (Some(addr.ip()), addr.port()));
        let flow = crate::router::Flow {
            network,
            domain,
            ip,
            port: Some(asked.port()),
            source,
            source_port,
            local,
            local_port,
            vless_route: 0,
            inbound_tag: self.inbound_tag.as_deref(),
            protocol: facts.protocol,
            user: facts.user,
            attrs: facts.attrs,
            process: facts.process,
        };
        if let Some(script) = self.shared.script_router.as_deref() {
            let Some(callbacks) = self.shared.script.as_ref() else {
                return self.default_lane();
            };
            match script.route(&flow, callbacks) {
                Ok(Some(tag)) => {
                    let out = self.target(&tag);
                    return (out, Some(std::borrow::Cow::Owned(tag)));
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("routing script: {error}");
                    return (Picked::Static(&self.shared.closed), None);
                }
            }
        }
        let (lane, tag, webhook) = {
            let routing = self
                .shared
                .routing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let hit = if self.skip_dns {
                routing.route_target_without_resolve(&flow)
            } else {
                routing.route_target(&flow)
            };
            let Some(hit) = hit else {
                return self.default_lane();
            };
            let webhook = hit.webhook.cloned();
            let (lane, tag) = match hit.target {
                crate::router::RouteTarget::Outbound(tag) => {
                    let lane = self.target(tag);
                    (lane, self.stable_tag(tag).map(std::borrow::Cow::Borrowed))
                }
                crate::router::RouteTarget::Balancer(tag) => self.pick_balanced(&routing, tag),
            };
            (lane, tag, webhook)
        };
        if let Some(webhook) = webhook {
            webhook.fire(&crate::webhook::Event {
                email: flow.user,
                level: facts.level,
                protocol: flow.protocol,
                network: flow.network,
                source: event_address(flow.source, flow.source_port),
                destination: Some(asked),
                original: Some(facts.original.unwrap_or(asked)),
                route: facts.route,
                inbound_tag: flow.inbound_tag,
                inbound_name: self.inbound_name.as_deref(),
                local: event_address(flow.local, flow.local_port),
                outbound_tag: tag.as_deref().unwrap_or(""),
            });
        }
        (lane, tag)
    }

    /// The tag's own key in the startup table, so a decision names it without copying.
    fn stable_tag(&self, tag: &str) -> Option<&str> {
        if let Some((key, _)) = self.shared.tagged.get_key_value(tag) {
            return Some(key);
        }
        self.shared
            .default_tag
            .as_deref()
            .filter(|default| *default == tag)
    }

    /// The lane a balancer picks for one flow; the event names the picked tag, as the reference's
    /// `GetTag` resolves a balancer before it fires.
    fn pick_balanced(
        &self,
        routing: &crate::router::Routing,
        tag: &str,
    ) -> (Picked<'_>, Option<std::borrow::Cow<'_, str>>) {
        let Some(balancer) = routing.balancer(tag) else {
            return self.default_lane();
        };
        let candidates = self
            .shared
            .balancers
            .get(tag)
            .expect("startup built every balancer's candidates");
        let observed = self
            .shared
            .observatory
            .as_deref()
            .map(crate::observatory::Observatory::snapshot);
        if let Some(picked) = balancer.pick(candidates, observed.as_deref()) {
            let out = self.target(&picked);
            return (out, Some(picked));
        }
        if let Some(fallback) = balancer.fallback() {
            let out = self.target(fallback);
            return (
                out,
                self.stable_tag(fallback).map(std::borrow::Cow::Borrowed),
            );
        }
        self.default_lane()
    }

    /// The lane one association picks without leaving that lane's dial settings for this thread.
    fn udp_lane(
        &self,
        association: &Association,
    ) -> Result<(Picked<'_>, Option<std::borrow::Cow<'_, str>>), ()> {
        match association {
            Association::Default => Ok(self.default_lane()),
            Association::Tag(tag) => {
                let lane = self.target(tag);
                Ok((lane, self.stable_tag(tag).map(std::borrow::Cow::Borrowed)))
            }
            Association::Split => Err(()),
        }
    }

    fn udp_out(&self, association: &Association) -> Result<Picked<'_>, ()> {
        let (lane, tag) = self.udp_lane(association)?;
        if self.shared.has_dial_settings {
            self.carry_dial_settings(tag.as_deref());
        }
        Ok(lane)
    }
}

/// The tag an inbound answers to, or nothing when the config leaves it unnamed.
fn inbound_tag(inbound: &Json) -> Option<String> {
    inbound
        .get("tag")
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
}

/// The handler an event names for an inbound: the reference's proxy name, which the `mixed`
/// spelling shares with `socks`.
fn inbound_name(inbound: &Json) -> Option<String> {
    let protocol = canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or(""));
    match protocol {
        "" => None,
        "mixed" => Some("socks".to_owned()),
        other => Some(other.to_owned()),
    }
}

/// The outbound one configured entry names, with the reason when this tree cannot dial it: a tag a
/// rule can reach is built at startup, so a missing or unbuildable one stops the process, not a flow.
pub(crate) fn build_outbound(config: &Json, tag: &str) -> Result<Outbound, String> {
    if is_chain_config(config) {
        return Err(format!(
            "outbound `{tag}` is a chain; add chains in the startup config"
        ));
    }
    let protocol = canonical_protocol(config.get("protocol").and_then(Json::as_str).unwrap_or(""));
    if protocol == "loopback" {
        // A management-API handler has no config root; its named tag is all the second pass needs.
        let settings = config.get("settings");
        let inbound_tag = settings
            .and_then(|settings| settings.get("inboundTag"))
            .and_then(Json::as_str)
            .unwrap_or("");
        let sniffing = crate::sniff::parse(settings.and_then(|settings| settings.get("sniffing")))
            .map_err(|error| format!("loopback `{inbound_tag}` sniffing {error}"))?
            .filter(|sniffing| sniffing.enabled());
        return Ok(loopback_out(inbound_tag, None, true, None, sniffing));
    }
    if protocol == "blackhole" {
        let answer = crate::blackhole::answer(config.get("settings"))
            .map_err(|reason| format!("outbound `{tag}` {reason}"))?;
        return Ok(Outbound::Block(answer));
    }
    let single = Json::Obj(vec![(
        "outbounds".to_owned(),
        Json::Arr(vec![config.clone()]),
    )]);
    find_outbound(&single)
        .map_err(|reason| format!("outbound `{tag}` {reason}"))?
        .ok_or_else(|| format!("outbound `{tag}` protocol `{protocol}` is not carried"))
}

/// The routing table the inbounds share: the default is the first configured outbound, and every tag
/// a rule names is built once here rather than per flow.
/// The portals the config names: one per reverse tag an inbound user carries. The same registry
/// both builds the users and answers the routes that name a portal tag.
fn reverse_portals(root: &Json) -> Result<Arc<crate::reverse::Portals>, String> {
    let mut portals = crate::reverse::Portals::default();
    for inbound in root.get("inbounds").and_then(Json::as_arr).unwrap_or(&[]) {
        if canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or(""))
            != "vless"
        {
            continue;
        }
        for client in inbound
            .get("settings")
            .and_then(|settings| settings.get("clients"))
            .and_then(Json::as_arr)
            .unwrap_or(&[])
        {
            let Some(tag) = client
                .get("reverse")
                .and_then(|reverse| reverse.get("tag"))
                .and_then(Json::as_str)
            else {
                continue;
            };
            if tag.is_empty() {
                eprintln!("vless: an inbound reverse tag is empty, so the user forwards nothing");
                continue;
            }
            if client
                .get("flow")
                .and_then(Json::as_str)
                .is_some_and(|flow| flow == ferrox_core::vless::VISION_FLOW)
            {
                eprintln!(
                    "vless: reverse user `{tag}` names the vision flow; a reverse session carries the unframed stream only"
                );
            }
            portals.insert(tag);
        }
    }
    for portal in root
        .get("reverse")
        .and_then(|reverse| reverse.get("portals"))
        .and_then(Json::as_arr)
        .unwrap_or(&[])
    {
        let Some(tag) = portal.get("tag").and_then(Json::as_str) else {
            continue;
        };
        let Some(domain) = portal.get("domain").and_then(Json::as_str) else {
            continue;
        };
        if !tag.is_empty() && !domain.is_empty() {
            portals.insert_domain(tag, domain)?;
        }
    }
    let portals = Arc::new(portals);
    crate::reverse::install_portals(Arc::clone(&portals));
    Ok(portals)
}

/// One routing target, with loopback built as the named tag's second pass instead of refused.
fn routed_outbound(root: &Json, config: &Json, tag: &str) -> Result<Outbound, String> {
    if canonical_protocol(config.get("protocol").and_then(Json::as_str).unwrap_or("")) != "loopback"
    {
        return build_outbound(config, tag);
    }
    resolve_routed_loopback(root, config)
}

#[cfg(test)]
fn route_shared(
    root: &Json,
    routing: crate::router::Routing,
    portals: &crate::reverse::Portals,
    observatory: Option<Arc<crate::observatory::Observatory>>,
) -> Result<Arc<RouteShared>, String> {
    route_shared_with_api(root, routing, portals, observatory, None, None, None)
}

/// The tag an outbound's `streamSettings.sockopt.dialerProxy` names, with the empty string the
/// reference reads as a direct dial.
fn dialer_proxy_tag(config: &Json) -> Option<&str> {
    config
        .get("streamSettings")
        .and_then(|settings| settings.get("sockopt"))
        .and_then(|sockopt| sockopt.get("dialerProxy"))
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
}

/// The tag a sing-box-shaped outbound's top-level `detour` names.
fn detour_tag(config: &Json) -> Option<&str> {
    config
        .get("detour")
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
}

/// The one hop an outbound dials through. `dialerProxy` and `detour` are the same edge; naming
/// both differently is a config error rather than a silent preference.
fn next_hop_tag(config: &Json) -> Result<Option<&str>, String> {
    match (dialer_proxy_tag(config), detour_tag(config)) {
        (Some(dialer), Some(detour)) if dialer != detour => Err(format!(
            "names both dialerProxy `{dialer}` and detour `{detour}`"
        )),
        (Some(tag), _) | (_, Some(tag)) => Ok(Some(tag)),
        (None, None) => Ok(None),
    }
}

/// The `LxBox` chain outbound: `type` or `protocol` is `chain`, and its `outbounds` are ordered
/// from the client's first hop to the exit.
fn is_chain_config(config: &Json) -> bool {
    config
        .get("protocol")
        .and_then(Json::as_str)
        .or_else(|| config.get("type").and_then(Json::as_str))
        .is_some_and(|name| name.eq_ignore_ascii_case("chain"))
}

/// Ordered hop tags a chain entry names, from the top-level `LxBox` field or its `settings` twin.
fn chain_hops(config: &Json) -> Result<Vec<String>, String> {
    let listed = config
        .get("outbounds")
        .or_else(|| {
            config
                .get("settings")
                .and_then(|settings| settings.get("outbounds"))
        })
        .ok_or_else(|| "chain has no outbounds list".to_owned())?
        .as_arr()
        .ok_or_else(|| "chain outbounds is not an array".to_owned())?;
    let mut hops = Vec::with_capacity(listed.len());
    for hop in listed {
        let tag = hop
            .as_str()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| "chain outbounds carries a non-string or empty hop".to_owned())?;
        hops.push(tag.to_owned());
    }
    Ok(hops)
}

/// Flatten a chain whose first position names another chain, which `LxBox` allows only there. The
/// result is the ordered leaf hops; a nested chain anywhere else, a self-reference, a missing hop,
/// a duplicate and a cycle are startup refusals.
fn flatten_chain<'a>(
    tag: &str,
    configs: &HashMap<&'a str, &'a Json>,
    visiting: &mut HashSet<String>,
) -> Result<Vec<String>, String> {
    if !visiting.insert(tag.to_owned()) {
        return Err(format!("chain `{tag}` loops through itself"));
    }
    let config = configs
        .get(tag)
        .ok_or_else(|| format!("chain `{tag}` names no outbound"))?;
    let mut flat = Vec::new();
    for (index, hop) in chain_hops(config)?.into_iter().enumerate() {
        let Some(hop_config) = configs.get(hop.as_str()).copied() else {
            return Err(format!(
                "chain `{tag}` names `{hop}`, which no outbound names"
            ));
        };
        if is_chain_config(hop_config) {
            if index != 0 {
                return Err(format!(
                    "chain `{tag}` nests chain `{hop}` at position {index}; only the first position may nest"
                ));
            }
            flat.extend(flatten_chain(&hop, configs, visiting)?);
        } else {
            flat.push(hop);
        }
    }
    visiting.remove(tag);
    if flat.len() < 2 {
        return Err(format!("chain `{tag}` has fewer than two hops"));
    }
    let mut seen = HashSet::new();
    for hop in &flat {
        if !seen.insert(hop.clone()) {
            return Err(format!("chain `{tag}` names `{hop}` twice"));
        }
        if hop == tag {
            return Err(format!("chain `{tag}` names itself"));
        }
    }
    Ok(flat)
}

/// One outbound's chain: every named hop exists, none names itself, and the walk terminates. A
/// missing handler, a self-reference and a cycle are startup refusals, as they are in xray.
fn check_dialer_proxy<'a>(
    configs: &HashMap<&'a str, &'a Json>,
    label: &'a str,
    config: &'a Json,
) -> Result<(), String> {
    if is_chain_config(config) {
        if let Some(hop) = next_hop_tag(config)? {
            return Err(format!(
                "chain `{label}` names detour `{hop}`; its outbounds list is its route"
            ));
        }
        return Ok(());
    }
    let mut cursor = next_hop_tag(config)?;
    if cursor == Some(label) {
        return Err(format!("outbound `{label}` dialerProxy names itself"));
    }
    let mut seen = HashSet::new();
    seen.insert(label);
    while let Some(hop) = cursor {
        if !seen.insert(hop) {
            return Err(format!("dialerProxy/detour loop through `{hop}`"));
        }
        let Some(next) = configs.get(hop) else {
            return Err(format!(
                "outbound `{label}` dialerProxy/detour names `{hop}`, which no outbound names"
            ));
        };
        cursor = next_hop_tag(next)?;
    }
    Ok(())
}

fn check_dialer_proxies<'a>(
    configs: &HashMap<&'a str, &'a Json>,
    default_tag: Option<&str>,
    first: &'a Json,
) -> Result<(), String> {
    for (&tag, &config) in configs {
        check_dialer_proxy(configs, tag, config)?;
    }
    if default_tag.is_none() {
        check_dialer_proxy(configs, "<default>", first)?;
    }
    Ok(())
}

/// Every hop a `dialerProxy` or `detour` names is a route target the dial seam must reach, even
/// when no rule names it directly.
fn add_dialer_proxy_targets<'a>(
    configs: &HashMap<&'a str, &'a Json>,
    default_tag: Option<&str>,
    first: &'a Json,
    targets: &mut Vec<&'a str>,
) -> Result<(), String> {
    let default = default_tag.is_none().then_some(first);
    for config in configs.values().copied().chain(default) {
        if is_chain_config(config) {
            continue;
        }
        let mut cursor = next_hop_tag(config)?;
        while let Some(hop) = cursor {
            targets.push(hop);
            cursor = match configs.get(hop) {
                Some(config) if !is_chain_config(config) => next_hop_tag(config)?,
                _ => None,
            };
        }
    }
    Ok(())
}

/// Whether a hop's own dial seam reads the predecessor's `dialerProxy`; a carrier that binds its
/// own socket instead would reach the peer from this machine and skip every earlier hop.
fn chain_hop_can_dial_through(out: &Outbound) -> bool {
    match out {
        Outbound::Vless(vless) => vless.carrier.tcp_stream(),
        Outbound::Vmess(vmess) => vmess.carrier.tcp_stream(),
        Outbound::Trojan(trojan) => trojan.carrier.tcp_stream(),
        // A raw Shadowsocks datagram lane opens its own socket, so a hop above it would be lost.
        Outbound::Shadowsocks(shadowsocks) => {
            shadowsocks.carrier.tcp_stream() && shadowsocks.mux.udp_manager().is_some()
        }
        Outbound::Socks(_)
        | Outbound::Http(_)
        | Outbound::Psiphon(_)
        | Outbound::Freedom(_)
        | Outbound::Masque(_)
        | Outbound::AnyTls(_) => true,
        Outbound::WireGuard(_)
        | Outbound::Warp(_)
        | Outbound::Hysteria(_)
        | Outbound::Tuic(_)
        | Outbound::Foxy(_)
        | Outbound::Veepn(_)
        | Outbound::Loopback(_)
        | Outbound::Route(_)
        | Outbound::Block(_)
        | Outbound::Dns(_)
        | Outbound::ReversePortal(_)
        | Outbound::Metrics { .. }
        | Outbound::Api(_) => false,
    }
}

/// One lane in a chain: the tag the dial seam reaches, the outbound built for it, and the dial
/// settings that lane carries. The innermost lane is the chain's route entry.
struct ChainLane {
    tag: String,
    out: Outbound,
    source: Option<SendThrough>,
    sockopts: Option<Arc<crate::sockopt::SocketOptions>>,
    strategy: Option<FreedomDomain>,
}

fn chain_lane_tag(tag: &str, index: usize) -> String {
    format!("\u{1}chain\u{1}{tag}\u{1}{index}")
}

/// Build the lanes an ordered chain names: the exit keeps the route entry's tag, every earlier
/// hop gets a private tag, and each dials through the hop before it. The chain list is the route,
/// so a hop's own `detour` is not carried inside it.
fn build_chain_lanes(
    root: &Json,
    configs: &HashMap<&str, &Json>,
    tag: &str,
    hops: &[String],
) -> Result<Vec<ChainLane>, String> {
    let mut lanes = Vec::with_capacity(hops.len());
    for (index, hop) in hops.iter().enumerate() {
        let Some(config) = configs.get(hop.as_str()).copied() else {
            return Err(format!(
                "chain `{tag}` names `{hop}`, which no outbound names"
            ));
        };
        if next_hop_tag(config)?.is_some() {
            eprintln!(
                "chain `{tag}` hop `{hop}` names its own detour; the chain position is used instead"
            );
        }
        let lane_tag = chain_lane_tag(tag, index);
        if configs.contains_key(lane_tag.as_str()) {
            return Err(format!(
                "chain `{tag}` needs private tag `{lane_tag}`, which an outbound already names"
            ));
        }
        let mut out = routed_outbound(root, config, &lane_tag)?;
        // MASQUE's spec owns its carrier hop; the first position clears any hop the config named.
        let upstream = (index > 0).then(|| chain_lane_tag(tag, index - 1));
        if let Outbound::Masque(masque) = &mut out {
            let Some(masque) = Arc::get_mut(masque) else {
                return Err(format!("chain `{tag}` hop `{hop}` MASQUE lane is shared"));
            };
            masque.set_dialer_proxy(upstream.as_deref());
        }
        if index > 0 && !chain_hop_can_dial_through(&out) {
            return Err(format!(
                "chain `{tag}` hop `{hop}` cannot dial through `{}`; only the first position dials the machine directly",
                hops[index - 1]
            ));
        }
        if index + 1 < hops.len()
            && matches!(
                out,
                Outbound::Freedom(_)
                    | Outbound::Block(_)
                    | Outbound::Dns(_)
                    | Outbound::Loopback(_)
                    | Outbound::Route(_)
                    | Outbound::Metrics { .. }
                    | Outbound::Api(_)
            )
        {
            return Err(format!(
                "chain `{tag}` hop `{hop}` cannot relay to `{}`",
                hops[index + 1]
            ));
        }
        let source = parse_send_through(config)?;
        let mut sockopts = parse_outbound_sockopt(config)?;
        match index {
            0 => {
                if let Some(options) = sockopts.as_mut() {
                    options.set_dialer_proxy(None);
                }
            }
            _ => {
                sockopts
                    .get_or_insert_with(crate::sockopt::SocketOptions::default)
                    .set_dialer_proxy(Some(&chain_lane_tag(tag, index - 1)));
            }
        }
        lanes.push(ChainLane {
            tag: lane_tag,
            out,
            source,
            sockopts: sockopts.map(Arc::new),
            strategy: parse_target_strategy(config)?,
        });
    }
    Ok(lanes)
}

/// The same table with the commander's tag reachable: a rule naming it hands the flow to the
/// in-process API rather than to a configured outbound.
#[allow(clippy::too_many_lines)]
fn route_shared_with_api(
    root: &Json,
    routing: crate::router::Routing,
    portals: &crate::reverse::Portals,
    observatory: Option<Arc<crate::observatory::Observatory>>,
    api: Option<&Arc<crate::commander::Api>>,
    default: Option<&Outbound>,
    geodata_outbound: Option<&str>,
) -> Result<Arc<RouteShared>, String> {
    let list = root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]);
    let Some(first) = list.first() else {
        return Err("routing has no outbound to fall back to".into());
    };
    let server_inbounds: Vec<ServerInbound> = root
        .get("inbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(|inbound| {
            let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
            serve_addresses(inbound, canonical_protocol(protocol))?;
            server_networks(inbound).map(|networks| ServerInbound {
                tag: inbound_tag(inbound),
                networks,
                portal: portal_inbound(protocol),
            })
        })
        .collect();
    let default_tag = first
        .get("tag")
        .and_then(Json::as_str)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned);
    let mut configs: HashMap<&str, &Json> = HashMap::new();
    for outbound in list {
        let tag = outbound.get("tag").and_then(Json::as_str).unwrap_or("");
        if tag.is_empty() {
            continue;
        }
        if configs.insert(tag, outbound).is_some() {
            return Err(format!("outbound tag `{tag}` is named twice"));
        }
    }
    check_dialer_proxies(&configs, default_tag.as_deref(), first)?;
    let mut chain_specs: HashMap<String, Vec<String>> = HashMap::new();
    for (&tag, &config) in &configs {
        if is_chain_config(config) {
            let hops = flatten_chain(tag, &configs, &mut HashSet::new())?;
            chain_specs.insert(tag.to_owned(), hops);
        }
    }
    let mut chain_lanes: HashMap<String, Vec<ChainLane>> = HashMap::new();
    for (tag, hops) in &chain_specs {
        chain_lanes.insert(tag.clone(), build_chain_lanes(root, &configs, tag, hops)?);
    }
    let build = |config: &Json, tag: &str| -> Result<Outbound, String> {
        if is_chain_config(config) {
            return chain_lanes
                .get(tag)
                .and_then(|lanes| lanes.last())
                .map(|lane| lane.out.clone())
                .ok_or_else(|| format!("chain `{tag}` has no built lanes"));
        }
        routed_outbound(root, config, tag)
    };
    let default = match default {
        Some(outbound) => outbound.clone(),
        None => {
            if is_chain_config(first) {
                let tag = default_tag
                    .as_deref()
                    .ok_or_else(|| "the default chain outbound needs a tag".to_owned())?;
                build(first, tag)?
            } else {
                build(first, default_tag.as_deref().unwrap_or("<default>"))?
            }
        }
    };
    let default_lane = if is_chain_config(first) {
        default_tag
            .as_deref()
            .and_then(|tag| chain_lanes.get(tag))
            .and_then(|lanes| lanes.last())
    } else {
        None
    };
    let default_source = match default_lane {
        Some(lane) => lane.source,
        None => parse_send_through(first)?,
    };
    let mut sources = HashMap::new();
    for (&tag, &config) in &configs {
        if !is_chain_config(config) {
            if let Some(source) = parse_send_through(config)? {
                sources.insert(tag.to_owned(), source);
            }
        }
    }
    let default_sockopts = match default_lane {
        Some(lane) => lane.sockopts.clone(),
        None => parse_outbound_sockopt(first)?.map(Arc::new),
    };
    let mut sockopts = HashMap::new();
    for (&tag, &config) in &configs {
        if !is_chain_config(config) {
            if let Some(options) = parse_outbound_sockopt(config)? {
                sockopts.insert(tag.to_owned(), Arc::new(options));
            }
        }
    }
    let default_strategy = match default_lane {
        Some(lane) => lane.strategy,
        None => parse_target_strategy(first)?,
    };
    let mut strategies = HashMap::new();
    for (&tag, &config) in &configs {
        if !is_chain_config(config) {
            if let Some(strategy) = parse_target_strategy(config)? {
                strategies.insert(tag.to_owned(), strategy);
            }
        }
    }
    let mut tagged = HashMap::new();
    for (tag, lanes) in &chain_lanes {
        for lane in lanes {
            tagged.insert(lane.tag.clone(), lane.out.clone());
            if let Some(source) = lane.source {
                sources.insert(lane.tag.clone(), source);
            }
            if let Some(options) = &lane.sockopts {
                sockopts.insert(lane.tag.clone(), Arc::clone(options));
            }
            if let Some(strategy) = lane.strategy {
                strategies.insert(lane.tag.clone(), strategy);
            }
        }
        let exit = lanes.last().expect("a chain has at least two lanes");
        tagged.insert(tag.clone(), exit.out.clone());
        if let Some(source) = exit.source {
            sources.insert(tag.clone(), source);
        }
        if let Some(options) = &exit.sockopts {
            sockopts.insert(tag.clone(), Arc::clone(options));
        }
        if let Some(strategy) = exit.strategy {
            strategies.insert(tag.clone(), strategy);
        }
    }
    let has_dial_settings = default_source.is_some()
        || !sources.is_empty()
        || default_sockopts.is_some()
        || !sockopts.is_empty()
        || default_strategy.is_some()
        || !strategies.is_empty();
    let mut targets: Vec<&str> = if routing.script().is_some() {
        configs.keys().copied().collect()
    } else {
        routing
            .targets()
            .filter_map(|target| match target {
                crate::router::RouteTarget::Outbound(tag) => Some(tag),
                crate::router::RouteTarget::Balancer(_) => None,
            })
            .collect()
    };
    if let Some(tag) = geodata_outbound.filter(|tag| !tag.is_empty()) {
        if configs.contains_key(tag) {
            targets.push(tag);
        }
    }
    add_dialer_proxy_targets(&configs, default_tag.as_deref(), first, &mut targets)?;
    for target in targets {
        if tagged.contains_key(target) {
            continue;
        }
        if let Some(api) = api {
            if api.routed() && target == api.tag() {
                tagged.insert(target.to_owned(), Outbound::Api(std::sync::Arc::clone(api)));
                continue;
            }
        }
        if Some(target) == default_tag.as_deref() {
            tagged.insert(target.to_owned(), default.clone());
            continue;
        }
        // A portal tag is not an outbound entry: the inbound user's reverse tag registers it at start.
        if let Some(portal) = portals.get(target) {
            tagged.insert(target.to_owned(), Outbound::ReversePortal(portal));
            continue;
        }
        if crate::metrics::tag().as_deref() == Some(target) {
            if let Some(address) = crate::metrics::tagged_address() {
                tagged.insert(target.to_owned(), Outbound::Metrics { address });
                continue;
            }
        }
        let Some(config) = configs.get(target) else {
            return Err(format!(
                "routing targets `{target}`, which no outbound names"
            ));
        };
        let out = build(config, target)?;
        tagged.insert(target.to_owned(), out);
    }
    let mut balancers = HashMap::new();
    for balancer in routing.balancers() {
        let mut candidates: Vec<String> = list
            .iter()
            .filter_map(|outbound| {
                let tag = outbound.get("tag").and_then(Json::as_str).unwrap_or("");
                (!tag.is_empty() && balancer.selects(tag)).then(|| tag.to_owned())
            })
            .collect();
        candidates.sort_unstable();
        for candidate in &candidates {
            if tagged.contains_key(candidate) || Some(candidate.as_str()) == default_tag.as_deref()
            {
                continue;
            }
            let Some(config) = configs.get(candidate.as_str()) else {
                return Err(format!(
                    "balancer `{}` selects `{candidate}`, which no outbound names",
                    balancer.tag()
                ));
            };
            tagged.insert(candidate.clone(), build(config, candidate)?);
        }
        if let Some(fallback) = balancer.fallback() {
            if !tagged.contains_key(fallback) && Some(fallback) != default_tag.as_deref() {
                let Some(config) = configs.get(fallback) else {
                    return Err(format!(
                        "balancer `{}` falls back to `{fallback}`, which no outbound names",
                        balancer.tag()
                    ));
                };
                tagged.insert(fallback.to_owned(), build(config, fallback)?);
            }
        }
        balancers.insert(balancer.tag().to_owned(), candidates);
    }
    let balancer_fallbacks: HashMap<String, String> = routing
        .balancers()
        .filter_map(|balancer| {
            balancer
                .fallback()
                .map(|fallback| (balancer.tag().to_owned(), fallback.to_owned()))
        })
        .collect();
    let script_router = routing.script_shared();
    let routing = Arc::new(RwLock::new(routing));
    let balancers = Arc::new(balancers);
    let dynamic = Arc::new(RwLock::new(Dynamic::default()));
    let script = if script_router.is_some() {
        let routing = Arc::clone(&routing);
        let balancers = Arc::clone(&balancers);
        let tags: Arc<HashSet<String>> = Arc::new(tagged.keys().cloned().collect());
        let dynamic = Arc::clone(&dynamic);
        let observatory = observatory.clone();
        Some(crate::router_script::ScriptCallbacks {
            resolve: Arc::new(crate::router::resolve_ips_script),
            pick: Arc::new(move |tag| {
                pick_script_outbound(
                    &routing,
                    &balancers,
                    &tags,
                    &dynamic,
                    observatory.as_deref(),
                    tag,
                )
            }),
        })
    } else {
        None
    };
    let shared = Arc::new(RouteShared {
        routing,
        tagged,
        balancers,
        balancer_fallbacks,
        server_inbounds: Mutex::new(server_inbounds),
        vmess_users: Mutex::new(HashMap::new()),
        observatory,
        script_router,
        script,
        default,
        default_tag,
        sources,
        default_source,
        sockopts,
        default_sockopts,
        strategies,
        default_strategy,
        has_dial_settings,
        dynamic,
        changed: AtomicBool::new(false),
        closed: Outbound::Block(ferrox_core::blackhole::Response::None),
        self_weak: OnceLock::new(),
    });
    for options in shared.sockopts.values() {
        options.install_route(&shared);
    }
    if let Some(options) = &shared.default_sockopts {
        options.install_route(&shared);
    }
    for outbound in shared
        .tagged
        .values()
        .chain(std::iter::once(&shared.default))
    {
        if let Outbound::Masque(masque) = outbound {
            masque.install_route(&shared);
        }
    }
    let _ = shared.self_weak.set(Arc::downgrade(&shared));
    shared.bind_loopbacks();
    Ok(shared)
}

/// `xray.router.PickOutbound`: a balancer tag picks one candidate (its fallback when a strategy
/// names none), any other tag has to be an outbound this table built.
fn pick_script_outbound(
    routing: &RwLock<crate::router::Routing>,
    balancers: &HashMap<String, Vec<String>>,
    tags: &HashSet<String>,
    dynamic: &RwLock<Dynamic>,
    observatory: Option<&crate::observatory::Observatory>,
    tag: &str,
) -> Result<String, String> {
    let routing = routing
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(balancer) = routing.balancer(tag) {
        let candidates = balancers.get(tag).map_or(&[][..], Vec::as_slice);
        let observed = observatory.map(crate::observatory::Observatory::snapshot);
        if let Some(picked) = balancer.pick(candidates, observed.as_deref()) {
            return Ok(picked.into_owned());
        }
        if let Some(fallback) = balancer.fallback() {
            return Ok(fallback.to_owned());
        }
        return Err(format!("balancer `{tag}` has no outbound"));
    }
    let dynamic = dynamic
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if dynamic.removed.contains(tag) {
        return Err(format!("outbound `{tag}` not found"));
    }
    if dynamic.added.contains_key(tag) || tags.contains(tag) {
        Ok(tag.to_owned())
    } else {
        Err(format!("outbound `{tag}` not found"))
    }
}

/// The target networks a direct-dial server inbound serves; `None` when this tree routes it
/// through an outbound instead. `AnyTLS` carries streams only, so a datagram rule never reaches it.
fn server_networks(inbound: &Json) -> Option<Vec<crate::router::Network>> {
    let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
    match canonical_protocol(protocol) {
        "shadowsocks" => {
            let (tcp, udp) = inbound_ss_networks(inbound);
            let carrier = inbound_carrier(inbound);
            let served = !matches!(
                carrier,
                Carrier::Quic
                    | Carrier::Hysteria(_)
                    | Carrier::Masque
                    | Carrier::Http
                    | Carrier::Unknown { .. }
            );
            let udp = (udp && matches!(carrier, Carrier::Raw(_))) || (tcp && served);
            let mut networks = Vec::with_capacity(2);
            if tcp {
                networks.push(crate::router::Network::Tcp);
            }
            if udp {
                networks.push(crate::router::Network::Udp);
            }
            (!networks.is_empty()).then_some(networks)
        }
        "vless" | "trojan" | "vmess" | "hysteria" | "tuic" => Some(vec![
            crate::router::Network::Tcp,
            crate::router::Network::Udp,
        ]),
        "anytls" => Some(vec![crate::router::Network::Tcp]),
        _ => None,
    }
}

/// A server inbound dials direct, so every rule that can reach it must name a freedom outbound and
/// the fallback must be one too; anything else refuses the start rather than serving the wrong lane.
fn prove_server_route(shared: &RouteShared, inbound: &Json, label: &str) {
    let Some(networks) = server_networks(inbound) else {
        return;
    };
    let tag = inbound_tag(inbound);
    let portal = portal_inbound(inbound.get("protocol").and_then(Json::as_str).unwrap_or(""));
    let direct = |named: &str| direct_tag(shared, named);
    let routing = shared
        .routing
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(error) = routing.server_routes(&server_proof(
        shared,
        tag.as_deref(),
        &networks,
        &direct,
        portal,
    )) {
        exit(&format!("bad config {label}: {error}"));
    };
}

/// A server inbound's fixed direct dial, as the rules that reach it must see it.
fn server_proof<'a>(
    shared: &'a RouteShared,
    inbound: Option<&'a str>,
    networks: &'a [crate::router::Network],
    direct: &'a dyn Fn(&str) -> bool,
    portal: bool,
) -> crate::router::ServerProof<'a> {
    let default_direct = match shared.default_tag.as_deref() {
        Some(tag) => {
            direct_tag(shared, tag)
                || (portal
                    && matches!(&shared.default, Outbound::Block(_))
                    && !shared.has_freedom())
        }
        None => {
            matches!(&shared.default, Outbound::Freedom(_))
                || (portal
                    && matches!(&shared.default, Outbound::Block(_))
                    && !shared.has_freedom())
        }
    };
    let blocks = matches!(&shared.default, Outbound::Freedom(lane) if lane.blocks_any());
    let default_tag = shared.default_tag.clone();
    crate::router::ServerProof {
        inbound,
        default_direct,
        networks,
        direct: Box::new(move |named| direct(named)),
        direct_policy: Box::new(move |named| {
            !portal || !blocks || default_tag.as_deref() == Some(named)
        }),
        portal_rule: Box::new(move |rule| {
            portal
                && portal_tag(shared, rule.target())
                && portal_domain(shared, rule.target())
                    .is_some_and(|domain| rule.only_matches_domain(&domain))
        }),
        candidates: &shared.balancers,
        fallbacks: &shared.balancer_fallbacks,
    }
}

/// Whether a candidate outbound dials direct, by the same rule the dynamic table applies: a
/// freedom lane with no final block rules.
fn candidate_direct(out: &Outbound) -> bool {
    matches!(out, Outbound::Freedom(freedom) if !freedom.has_final_rules())
}

/// One server inbound's proof against a candidate outbound that is not published yet, so an
/// `AddOutbound` cannot replace a proven direct lane with a blocked one.
fn server_proof_for_candidate<'a>(
    shared: &'a RouteShared,
    inbound: Option<&'a str>,
    networks: &'a [crate::router::Network],
    tag: &'a str,
    candidate: &'a Outbound,
    portal: bool,
) -> crate::router::ServerProof<'a> {
    let direct = move |named: &str| {
        if named == tag {
            candidate_direct(candidate)
        } else {
            direct_tag(shared, named)
        }
    };
    let candidate_is_default = shared.default_tag.as_deref() == Some(tag);
    let has_freedom = shared.has_freedom() || matches!(candidate, Outbound::Freedom(_));
    let default_direct = if candidate_is_default {
        candidate_direct(candidate)
            || (portal && matches!(&shared.default, Outbound::Block(_)) && !has_freedom)
    } else {
        match shared.default_tag.as_deref() {
            Some(default) => {
                direct_tag(shared, default)
                    || (portal && matches!(&shared.default, Outbound::Block(_)) && !has_freedom)
            }
            None => {
                matches!(&shared.default, Outbound::Freedom(_))
                    || (portal && matches!(&shared.default, Outbound::Block(_)) && !has_freedom)
            }
        }
    };
    let blocks = matches!(&shared.default, Outbound::Freedom(lane) if lane.blocks_any());
    let default_tag = shared.default_tag.clone();
    crate::router::ServerProof {
        inbound,
        default_direct,
        networks,
        direct: Box::new(direct),
        direct_policy: Box::new(move |named| {
            !portal || !blocks || default_tag.as_deref() == Some(named)
        }),
        portal_rule: Box::new(move |rule| {
            portal
                && portal_tag(shared, rule.target())
                && portal_domain(shared, rule.target())
                    .is_some_and(|domain| rule.only_matches_domain(&domain))
        }),
        candidates: &shared.balancers,
        fallbacks: &shared.balancer_fallbacks,
    }
}

impl RouteShared {
    fn has_freedom(&self) -> bool {
        if matches!(&self.default, Outbound::Freedom(_))
            || self
                .tagged
                .values()
                .any(|out| matches!(out, Outbound::Freedom(_)))
        {
            return true;
        }
        self.dynamic
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .added
            .values()
            .any(|out| matches!(out.as_ref(), Outbound::Freedom(_)))
    }
}

/// Whether an outbound tag dials direct: a freedom outbound, or the default tag when the default
/// outbound is freedom. The dynamic table wins, so a removed or replaced tag reads its live lane.
fn direct_tag(shared: &RouteShared, tag: &str) -> bool {
    if shared.changed.load(Ordering::Relaxed) {
        let dynamic = shared
            .dynamic
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if dynamic.removed.contains(tag) {
            return false;
        }
        if let Some(out) = dynamic.added.get(tag) {
            return match out.as_ref() {
                Outbound::Freedom(freedom) => !freedom.has_final_rules(),
                _ => false,
            };
        }
    }
    // A direct-only inbound dials its own target, so a lane naming a hop is not a direct route.
    let options = if Some(tag) == shared.default_tag.as_deref() {
        shared.default_sockopts.as_deref()
    } else {
        shared.sockopts.get(tag).map(Arc::as_ref)
    };
    if options.is_some_and(|options| options.dialer_proxy().is_some()) {
        return false;
    }
    let default_tag = Some(tag) == shared.default_tag.as_deref();
    (default_tag && matches!(&shared.default, Outbound::Freedom(_)))
        || matches!(shared.tagged.get(tag), Some(Outbound::Freedom(lane))
            if default_tag || !lane.has_final_rules())
}

/// Whether an inbound protocol attaches reverse portals, so a rule naming one is served rather than dialed.
fn portal_inbound(protocol: &str) -> bool {
    matches!(canonical_protocol(protocol), "vless" | "vmess")
}

/// Whether a tag names a reverse portal the inbound carries.
fn portal_tag(shared: &RouteShared, tag: &str) -> bool {
    if shared.changed.load(Ordering::Relaxed) {
        let dynamic = shared
            .dynamic
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if dynamic.removed.contains(tag) {
            return false;
        }
        if let Some(out) = dynamic.added.get(tag) {
            return matches!(out.as_ref(), Outbound::ReversePortal(_));
        }
    }
    matches!(shared.tagged.get(tag), Some(Outbound::ReversePortal(_)))
        || crate::reverse::portal_for_tag(tag).is_some()
}

/// The domain a portal target serves, from the startup table or the live registry.
fn portal_domain(shared: &RouteShared, tag: &str) -> Option<String> {
    if let Some(Outbound::ReversePortal(portal)) = shared.tagged.get(tag) {
        return Some(portal.domain().to_owned());
    }
    crate::reverse::portal_for_tag(tag).map(|portal| portal.domain().to_owned())
}

/// The Foxy lane: an account's pass over an edge in one pinned country, plus the split-tunnel list.
#[derive(Debug, Clone)]
pub(crate) struct FoxyOut {
    account: Option<std::sync::Arc<crate::foxy_account::Account>>,
    country: String,
    carrier: crate::foxy::Carrier,
    /// The configured upstream; dialing past it leaks, so a value that does not parse refuses the outbound.
    upstream: Option<crate::foxy::UpstreamProxy>,
    /// The ladder this lane walks, tiered once: the country's edges in tier order, the order every flow reads rather than rebuilds.
    ladder: Vec<ferrox_core::foxy::Candidate>,
    stored: Option<std::sync::Arc<ferrox_core::foxy::Candidate>>,
    /// Set when an edge refuses the pass: later flows answer locally instead of paying that round trip again.
    unauthenticated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Strikes and the earliest next dial: one attempt answers a 429, the rest wait out the refusal curve.
    limited_strikes: std::sync::Arc<std::sync::atomic::AtomicU32>,
    limited_until: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Silent carriers and until when: otherwise an `auto` walk repays the whole handshake budget per flow.
    carrier_dead: std::sync::Arc<std::sync::Mutex<ferrox_core::foxy::Refusals>>,
    /// Edges whose TCP tunnels kept ending soon and the ones rested for a while: an edge that answers the probe yet drops the traffic is otherwise dialed by every flow.
    edge_strikes: std::sync::Arc<std::sync::Mutex<ferrox_core::foxy::EdgeStrikes>>,
    roots: ferrox_core::tls::Anchors,
    pins: ferrox_core::foxy::pin::Pins,
    pass: ferrox_core::foxy::Pass,
    edge_address: Option<SocketAddr>,
    direct_ports: Vec<u16>,
    direct_suffixes: Vec<String>,
    exit_probe: Option<String>,
    /// The pinned-country edge whose real exit the pre-flight confirmed, tried before the label order; empty until one agrees.
    verified:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<ferrox_core::foxy::Candidate>>>>,
    /// Set when no edge could carry a probe tunnel here: the pre-flight then stops rather than costing every flow a dead dial.
    probe_unavailable: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set while the sweep runs on its own thread: one lane probes once, and a flow that arrives mid-sweep rides the label order rather than waiting.
    exit_probe_running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Until when the probes are known to answer a country other than the pin: a sweep that reached an edge and agreed with none is the answer, and re-asking it per flow buys the same refusal again.
    exit_refuted_until: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// The carrier each flow kind (TCP, UDP, CONNECT-IP) last opened, so `auto` can report the rung it actually used.
    selected: std::sync::Arc<std::sync::Mutex<[u8; 3]>>,
}

fn carrier_slots() -> std::sync::Arc<std::sync::Mutex<[u8; 3]>> {
    std::sync::Arc::new(std::sync::Mutex::new([u8::MAX; 3]))
}

impl FoxyOut {
    /// Whether this edge is already known not to answer this carrier, inside the window.
    fn carrier_unanswered(
        &self,
        edge: &ferrox_core::foxy::Candidate,
        carrier: crate::foxy::Carrier,
    ) -> bool {
        self.carrier_dead
            .lock()
            .is_ok_and(|cache| cache.blocked(carrier.key(), &edge.host, edge.port, now_secs()))
    }

    /// Only silence is cached: a status means the edge answered, so it never marks a carrier dead.
    fn remember_unanswered(
        &self,
        edge: &ferrox_core::foxy::Candidate,
        carrier: crate::foxy::Carrier,
        failure: ferrox_core::foxy::Failure,
    ) {
        if !matches!(
            failure,
            ferrox_core::foxy::Failure::Io
                | ferrox_core::foxy::Failure::Stream
                | ferrox_core::foxy::Failure::Frame
        ) {
            return;
        }
        if let Ok(mut cache) = self.carrier_dead.lock() {
            cache.remember(
                carrier.key(),
                &edge.host,
                edge.port,
                now_secs() + CARRIER_DEAD_SECS,
            );
        }
    }

    /// The edge answered this carrier: the remembered silence was wrong, so it is found again at once.
    fn carrier_answered(&self, edge: &ferrox_core::foxy::Candidate, carrier: crate::foxy::Carrier) {
        if let Ok(mut cache) = self.carrier_dead.lock() {
            cache.clear(carrier.key(), &edge.host, edge.port);
        }
    }

    /// Records the carrier a flow kind last opened, once per change, so `status` can name the rung `auto` chose.
    fn note_carrier(&self, kind: &str, carrier: crate::foxy::Carrier) {
        let slot = match kind {
            "tcp" => 0,
            "udp" => 1,
            "ip" => 2,
            _ => return,
        };
        if let Ok(mut selected) = self.selected.lock() {
            if selected[slot] != carrier.key() {
                selected[slot] = carrier.key();
                eprintln!("foxy: carrier {kind} {}", carrier.name());
            }
        }
    }

    /// The edge every carrier should try first: the pre-flight's verified exit, else the configured stored edge. The edge is held, not copied: a flow that cloned it paid four strings to name an edge the lane already holds, and the mutex is not held across the dial.
    fn preferred_edge(&self) -> Option<std::sync::Arc<ferrox_core::foxy::Candidate>> {
        if let Ok(kept) = self.verified.lock() {
            if let Some(edge) = kept.clone() {
                return Some(edge);
            }
        }
        self.stored.clone()
    }

    /// Whether this edge's TCP tunnels kept ending soon enough to rest it right now.
    fn edge_resting(&self, edge: &ferrox_core::foxy::Candidate) -> bool {
        self.edge_strikes
            .lock()
            .is_ok_and(|cache| cache.resting(&edge.host, edge.port, now_secs()))
    }

    /// The dial order with rested edges left out, or the whole order when every edge rests, so a full rest cannot black-hole a flow. The survivors are held in the order's own array: a flow that collected them into a vector paid a heap buffer for a list of four it walks once.
    fn live_dials<'a>(
        &'a self,
        order: &ferrox_core::foxy::DialOrder<'a>,
    ) -> ferrox_core::foxy::DialOrder<'a> {
        order.filtered(|edge| !self.edge_resting(edge))
    }

    /// A TCP tunnel through this edge ended after lasting this long: two quick ends in a row rest the edge, a tunnel that carried traffic frees it.
    fn note_edge_end(&self, edge: &ferrox_core::foxy::Candidate, lasted: Duration) {
        if let Ok(mut cache) = self.edge_strikes.lock() {
            cache.note_end(&edge.host, edge.port, lasted, now_secs());
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VlessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    carrier: Carrier,
    host: String,
    headers: Vec<(String, String)>,
    heartbeat: u32,
    mux: Mux,
    pool: Pools,
    quic_roots: Option<ferrox_core::tls::Anchors>,
    quic_ech: Option<Arc<[u8]>>,
    hysteria_roots: Option<ferrox_core::tls::Anchors>,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    flow: String,
    reality: Option<Arc<ferrox_core::tls::RealityClientConfig>>,
    encryption: Option<Arc<ferrox_core::vless_encryption::Client>>,
}

impl VlessOut {
    fn is_vision(&self) -> bool {
        ferrox_core::vless::is_vision_name(&self.flow)
    }

    fn allows_udp443(&self) -> bool {
        self.flow == ferrox_core::vless::VISION_UDP443_FLOW
    }

    /// The spec a carrier opener dials: a clone whose pools are fresh, so the manager the closure
    /// is stored in is not itself reachable from the spec it holds.
    fn carrier_spec(&self) -> Self {
        Self {
            pool: Pools::default(),
            ..self.clone()
        }
    }

    fn tcp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.tcp?;
        let open = {
            let spec = self.carrier_spec();
            move || open_vless_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
        })
    }

    fn udp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.udp_manager()?;
        let open = {
            let spec = self.carrier_spec();
            move || open_vless_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => match self.mux.xudp {
                Xudp::Shared => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
                _ => MuxPool::Cool(self.pool.udp(cap, open)).into(),
            },
        })
    }
}

/// The freedom lane's own settings: where it redirects, how it resolves a name, whether it
/// prefixes the dial with a PROXY header, the fragment stage its carrier writes through, the
/// decoy datagrams a UDP flow opens with, and the final rules that refuse a destination.
#[derive(Debug, Clone, Default)]
pub(crate) struct FreedomOut {
    redirect: Option<FreedomRedirect>,
    domain: FreedomDomain,
    proxy_protocol: u8,
    fragment: Option<Arc<ferrox_core::finalmask::Chain>>,
    noises: Vec<FreedomNoise>,
    final_rules: Vec<FreedomFinalRule>,
}

static DIRECT_FREEDOM: OnceLock<Arc<FreedomOut>> = OnceLock::new();

fn direct_freedom() -> Option<&'static Arc<FreedomOut>> {
    DIRECT_FREEDOM.get()
}

impl FreedomOut {
    fn is_plain(&self) -> bool {
        self.redirect.is_none()
            && self.domain == FreedomDomain::AsIs
            && self.proxy_protocol == 0
            && self.fragment.is_none()
            && self.noises.is_empty()
            && self.final_rules.is_empty()
    }

    /// Whether this lane carries block or allow rules a direct handler that reads only the default
    /// lane would silently skip.
    fn has_final_rules(&self) -> bool {
        !self.final_rules.is_empty()
    }

    fn blocks_any(&self) -> bool {
        self.final_rules
            .iter()
            .any(|rule| rule.action == FreedomRuleAction::Block)
    }

    /// The first final rule the destination matches; `Allow` and `Block` both stop the search.
    fn final_rule(
        &self,
        network: crate::router::Network,
        ip: IpAddr,
        port: u16,
    ) -> Option<&FreedomFinalRule> {
        self.final_rules
            .iter()
            .find(|rule| rule.matches(network, ip, port))
    }

    fn blocks(&self, network: crate::router::Network, ip: IpAddr, port: u16) -> bool {
        self.final_rule(network, ip, port)
            .is_some_and(|rule| rule.action == FreedomRuleAction::Block)
    }

    /// The port a redirect rewrites to, or zero when it names none; the noise writer skips DNS on it.
    fn override_port(&self) -> u16 {
        match &self.redirect {
            Some(FreedomRedirect::Address(_, port) | FreedomRedirect::Port(port)) if *port != 0 => {
                *port
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreedomRuleAction {
    Allow,
    Block,
}

/// One `finalRules` entry, scoped the way the reference scopes it: a network mask, port ranges,
/// address rules, and the wait a blocked connection is held for before it closes.
#[derive(Debug, Clone)]
struct FreedomFinalRule {
    action: FreedomRuleAction,
    /// `None` matches both networks; `Some` is `[tcp, udp]`.
    networks: Option<[bool; 2]>,
    ports: Option<Vec<(u16, u16)>>,
    ips: Option<Arc<crate::router::IpMatcher>>,
    block_delay: Option<(u64, u64)>,
}

impl FreedomFinalRule {
    fn matches(&self, network: crate::router::Network, ip: IpAddr, port: u16) -> bool {
        if let Some(networks) = self.networks {
            let selected = match network {
                crate::router::Network::Tcp => networks[0],
                crate::router::Network::Udp => networks[1],
                crate::router::Network::Other(_) => false,
            };
            if !selected {
                return false;
            }
        }
        if let Some(ports) = &self.ports {
            if !ports.iter().any(|&(from, to)| from <= port && port <= to) {
                return false;
            }
        }
        self.ips.as_ref().is_none_or(|ips| ips.matches(ip))
    }

    fn delay(&self) -> Duration {
        let (min, max) = self.block_delay.unwrap_or((30, 90));
        let (min, max) = if min <= max { (min, max) } else { (max, min) };
        let span = max.saturating_sub(min);
        let seconds = if span == 0 {
            min
        } else {
            min.saturating_add(freedom_roll(span.saturating_add(1)))
        };
        Duration::from_secs(seconds)
    }
}

const UDP_NOISE_MAX_V4: u64 = 65_507;
const UDP_NOISE_MAX_V6: u64 = 65_527;

/// One `noises` entry: a fixed packet, a drawn one, or a QUIC-shaped one, sent before the first
/// datagram of a UDP flow and followed by the configured wait.
#[derive(Debug, Clone)]
struct FreedomNoise {
    noise: ferrox_core::evasion::Noise,
    apply_to: FreedomNoiseApply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreedomNoiseApply {
    Ip,
    Ipv4,
    Ipv6,
}

impl FreedomNoise {
    fn applies_to(&self, ip: IpAddr) -> bool {
        match self.apply_to {
            FreedomNoiseApply::Ip => true,
            FreedomNoiseApply::Ipv4 => ip.is_ipv4(),
            FreedomNoiseApply::Ipv6 => ip.is_ipv6(),
        }
    }
}

/// A uniform value in `[0, bound)`, drawn from the OS with rejection so no modulo bias remains.
fn freedom_roll(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let limit = u64::MAX - (u64::MAX % bound);
    loop {
        let mut raw = [0u8; 8];
        if getrandom::fill(&mut raw).is_err() {
            return 0;
        }
        let value = u64::from_le_bytes(raw);
        if value < limit {
            return value % bound;
        }
    }
}

/// `redirect` replaces the requested address, or only its port when the host is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FreedomRedirect {
    Address(String, u16),
    Port(u16),
}

impl FreedomRedirect {
    fn apply(&self, asked: &Destination) -> Destination {
        match (self, asked) {
            (Self::Address(host, port), _) => {
                let port = if *port == 0 { asked.port() } else { *port };
                match host.parse() {
                    Ok(ip) => Destination::Address(SocketAddr::new(ip, port)),
                    Err(_) => Destination::Name(host.clone(), port),
                }
            }
            (Self::Port(0), _) => asked.clone(),
            (Self::Port(port), Destination::Address(address)) => {
                Destination::Address(SocketAddr::new(address.ip(), *port))
            }
            (Self::Port(port), Destination::Name(host, _)) => {
                Destination::Name(host.clone(), *port)
            }
        }
    }
}

/// The family preference the reference's `domainStrategy` names. `AsIs` leaves a name to the
/// system dial; every other value resolves it here first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FreedomDomain {
    #[default]
    AsIs,
    UseIp,
    UseIp4,
    UseIp6,
    UseIp46,
    UseIp64,
    ForceIp,
    ForceIp4,
    ForceIp6,
    ForceIp46,
    ForceIp64,
}

impl FreedomDomain {
    fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "" | "asis" => Some(Self::AsIs),
            "useip" => Some(Self::UseIp),
            "useipv4" => Some(Self::UseIp4),
            "useipv6" => Some(Self::UseIp6),
            "useipv4v6" => Some(Self::UseIp46),
            "useipv6v4" => Some(Self::UseIp64),
            "forceip" => Some(Self::ForceIp),
            "forceipv4" => Some(Self::ForceIp4),
            "forceipv6" => Some(Self::ForceIp6),
            "forceipv4v6" => Some(Self::ForceIp46),
            "forceipv6v4" => Some(Self::ForceIp64),
            _ => None,
        }
    }

    fn forces(self) -> bool {
        matches!(
            self,
            Self::ForceIp | Self::ForceIp4 | Self::ForceIp6 | Self::ForceIp46 | Self::ForceIp64
        )
    }

    /// The first address in the order this strategy asks for, from the resolver's whole answer.
    fn pick(self, ips: &[std::net::IpAddr]) -> Option<std::net::IpAddr> {
        let v4 = || ips.iter().copied().find(std::net::IpAddr::is_ipv4);
        let v6 = || ips.iter().copied().find(std::net::IpAddr::is_ipv6);
        match self {
            Self::AsIs | Self::UseIp | Self::ForceIp => ips.first().copied(),
            Self::UseIp4 | Self::ForceIp4 => v4(),
            Self::UseIp6 | Self::ForceIp6 => v6(),
            Self::UseIp46 | Self::ForceIp46 => v4().or_else(v6),
            Self::UseIp64 | Self::ForceIp64 => v6().or_else(v4),
        }
    }
}

/// A direct Hysteria v1 outbound: the QUIC edge, the credential and the trust bundle it dials with.
#[derive(Debug, Clone)]
pub(crate) struct HysteriaOut {
    address: String,
    port: u16,
    host: String,
    config: ferrox_core::hysteria::Config,
    roots: Option<ferrox_core::tls::Anchors>,
}

impl HysteriaOut {
    fn dial(&self) -> crate::hysteria::Dial {
        crate::hysteria::Dial {
            host: self.host.clone(),
            address: self.address.clone(),
            port: self.port,
            config: self.config.clone(),
            roots: self.roots.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpOut {
    address: String,
    port: u16,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    /// The carrier the TLS rides when the config names one; the plain dial stays raw.
    carrier: Carrier,
    host: String,
    carrier_headers: Vec<(String, String)>,
    heartbeat: u32,
    headers: Vec<(String, String)>,
    user: Option<String>,
    pass: Option<String>,
}

/// The SOCKS5 client lane: the server this outbound dials, and the credential it offers.
///
/// The credential is the RFC 1929 one, and it is offered only when it is spelled whole:
/// a half-written credential refuses the lane rather than downgrading it to no
/// authentication.
#[derive(Debug, Clone)]
pub(crate) struct SocksOut {
    address: String,
    port: u16,
    credential: crate::socks::Credential,
    version: crate::socks::Version,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    /// The carrier the TLS rides when the config names one; the plain dial stays raw.
    carrier: Carrier,
    host: String,
    carrier_headers: Vec<(String, String)>,
    heartbeat: u32,
}

impl SocksOut {
    /// The lane a config names: the server's address, the credential it offers, and the
    /// version it speaks.
    pub(crate) fn new(
        address: &str,
        port: u16,
        user: &str,
        pass: &str,
        version: crate::socks::Version,
    ) -> Self {
        Self {
            address: address.to_owned(),
            port,
            credential: crate::socks::Credential {
                user: user.to_owned(),
                pass: pass.to_owned(),
            },
            version,
            tls: None,
            carrier: Carrier::Raw(ferrox_core::finalmask::Chain::default()),
            host: address.to_owned(),
            carrier_headers: Vec::new(),
            heartbeat: 0,
        }
    }
}

macro_rules! refused_carriers {
    () => {
        Carrier::Quic
            | Carrier::Kcp(_)
            | Carrier::Hysteria(_)
            | Carrier::Masque
            | Carrier::Xdrive { .. }
            | Carrier::Http
            | Carrier::Unknown { .. }
    };
}

#[derive(Debug, Clone)]
pub(crate) struct VmessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    cipher: crate::vmess::Cipher,
    auth_len: bool,
    no_termination: bool,
    carrier: Carrier,
    host: String,
    headers: Vec<(String, String)>,
    heartbeat: u32,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    reality: Option<Arc<ferrox_core::tls::RealityClientConfig>>,
    quic_roots: Option<ferrox_core::tls::Anchors>,
    quic_ech: Option<Arc<[u8]>>,
    hysteria_roots: Option<ferrox_core::tls::Anchors>,
    mux: Mux,
    pool: Pools,
}

#[derive(Debug, Clone)]
pub(crate) struct TrojanOut {
    address: String,
    port: u16,
    key: [u8; 56],
    carrier: Carrier,
    host: String,
    headers: Vec<(String, String)>,
    heartbeat: u32,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    quic_roots: Option<ferrox_core::tls::Anchors>,
    quic_ech: Option<Arc<[u8]>>,
    hysteria_roots: Option<ferrox_core::tls::Anchors>,
    mux: Mux,
    pool: Pools,
    reality: Option<Arc<ferrox_core::tls::RealityClientConfig>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ShadowsocksOut {
    address: String,
    port: u16,
    method: String,
    password: String,
    carrier: Carrier,
    host: String,
    headers: Vec<(String, String)>,
    heartbeat: u32,
    mux: Mux,
    pool: Pools,
    tls: Option<Arc<ferrox_core::tls::TlsConfig>>,
    reality: Option<Arc<ferrox_core::tls::RealityClientConfig>>,
    hysteria_roots: Option<ferrox_core::tls::Anchors>,
}

impl VmessOut {
    /// A spec whose pools are fresh, as for every carrier opener, so no manager holds itself.
    fn carrier_spec(&self) -> Self {
        Self {
            pool: Pools::default(),
            ..self.clone()
        }
    }

    fn tcp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.tcp?;
        let open = {
            let spec = self.carrier_spec();
            move || open_vmess_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
        })
    }

    fn udp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.udp_manager()?;
        let open = {
            let spec = self.carrier_spec();
            move || open_vmess_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => match self.mux.xudp {
                Xudp::Shared => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
                _ => MuxPool::Cool(self.pool.udp(cap, open)).into(),
            },
        })
    }
}

impl TrojanOut {
    fn carrier_spec(&self) -> Self {
        Self {
            pool: Pools::default(),
            ..self.clone()
        }
    }

    fn tcp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.tcp?;
        let open = {
            let spec = self.carrier_spec();
            move || open_trojan_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
        })
    }

    fn udp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.udp_manager()?;
        let open = {
            let spec = self.carrier_spec();
            move || open_trojan_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => match self.mux.xudp {
                Xudp::Shared => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
                _ => MuxPool::Cool(self.pool.udp(cap, open)).into(),
            },
        })
    }
}

impl ShadowsocksOut {
    fn carrier_spec(&self) -> Self {
        Self {
            pool: Pools::default(),
            ..self.clone()
        }
    }

    fn tcp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.tcp?;
        let open = {
            let spec = self.carrier_spec();
            move || open_ss_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
        })
    }

    fn udp_pool(&self) -> Option<Arc<MuxPool>> {
        let cap = self.mux.udp_manager()?;
        let open = {
            let spec = self.carrier_spec();
            move || open_ss_mux(&spec).map(Into::into)
        };
        Some(match self.mux.protocol {
            Some(protocol) => {
                MuxPool::Sing(self.pool.sing(protocol, self.mux.padding, cap, open)).into()
            }
            None => match self.mux.xudp {
                Xudp::Shared => MuxPool::Cool(self.pool.tcp(cap, open)).into(),
                _ => MuxPool::Cool(self.pool.udp(cap, open)).into(),
            },
        })
    }
}

/// xray's `MultiplexSettings`: the TCP carrier's cap, the datagram manager's own cap, and `xudpProxyUDP443`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mux {
    /// `enabled`: the object turns the whole mux on, the 443 policy included.
    enabled: bool,
    /// Flows a carrier takes before a second is dialed, at the reference's 128 floor; `None` is `concurrency < 0`.
    tcp: Option<usize>,
    /// `xudpConcurrency`: `Off` is negative, `Shared` is zero (the TCP carrier carries datagrams too), `Own` is the datagram manager's cap.
    xudp: Xudp,
    /// What a datagram to port 443 does while the mux is on.
    udp443: Udp443,
    /// `mux.protocol`: `None` is xray's Mux.Cool, `Some` is sing-mux's session under a rendezvous target.
    protocol: Option<crate::singmux::Protocol>,
    /// `mux.padding`: sing-mux's first sixteen writes and reads carry a length-prefixed pad.
    padding: bool,
}

impl Default for Mux {
    fn default() -> Self {
        Mux {
            enabled: false,
            tcp: None,
            xudp: Xudp::Off,
            udp443: Udp443::Reject,
            protocol: None,
            padding: false,
        }
    }
}

impl Mux {
    /// The datagram carrier's cap: `Shared` rides the TCP carrier, `Own` gets its own, and `Off` dials directly.
    fn udp_manager(&self) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        if self.protocol.is_some() {
            return self.tcp;
        }
        match self.xudp {
            Xudp::Off => None,
            Xudp::Shared => self.tcp,
            Xudp::Own(cap) => Some(cap),
        }
    }

    /// xray's `xudpProxyUDP443`, read only while the xray session is on; every other datagram is allowed.
    fn udp_443(&self, dest: SocketAddr) -> Udp443 {
        if self.enabled && self.protocol.is_none() && dest.port() == 443 {
            self.udp443
        } else {
            Udp443::Allow
        }
    }
}

/// xray's `xudpConcurrency` fold: a negative count dials datagrams directly, zero keeps the TCP carrier, a positive count gets its own manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Xudp {
    Off,
    Shared,
    Own(usize),
}

/// The carrier a `mux.enabled` outbound dials: xray's Mux.Cool, or sing-mux's own session.
enum MuxPool {
    Cool(Arc<crate::muxpool::Manager>),
    Sing(Arc<crate::singmux::Pool>),
}

impl MuxPool {
    fn dial(&self, target: &Destination) -> Option<PooledFlow> {
        match self {
            Self::Cool(manager) => manager.dial(&mux_target(target)).map(PooledFlow::Cool),
            Self::Sing(pool) => pool.dial(target).map(PooledFlow::Sing),
        }
    }

    fn udp(
        &self,
        target: SocketAddr,
        global_id: Option<&[u8; ferrox_core::mux::GLOBAL_ID]>,
        payload: &[u8],
        deliver: &crate::muxpool::Deliver,
    ) -> Option<PooledUdpFlow> {
        match self {
            Self::Cool(manager) => manager
                .udp(&mux_target_of(target), global_id, payload, deliver)
                .map(PooledUdpFlow::Cool),
            Self::Sing(pool) => {
                let flow = pool.dial_udp(&Destination::Address(target), deliver)?;
                if !payload.is_empty() && !flow.send(payload) {
                    flow.close();
                    return None;
                }
                Some(PooledUdpFlow::Sing(flow))
            }
        }
    }
}

enum PooledFlow {
    Cool(crate::muxpool::Flow),
    Sing(crate::singmux::Flow),
}

enum PooledReplies {
    Cool(Receiver<crate::muxpool::Msg>),
    Sing(crate::singmux::Replies),
}

struct PooledReply {
    data: Vec<u8>,
    end: bool,
    credit: usize,
}

impl PooledReplies {
    fn recv(&self) -> Result<PooledReply, std::sync::mpsc::RecvError> {
        match self {
            Self::Cool(replies) => replies.recv().map(|msg| PooledReply {
                data: msg.data,
                end: msg.end,
                credit: 0,
            }),
            Self::Sing(replies) => replies.recv().map(|msg| PooledReply {
                data: msg.data,
                end: msg.end,
                credit: msg.credit,
            }),
        }
    }

    fn try_recv(&self) -> Option<PooledReply> {
        match self {
            Self::Cool(replies) => replies.try_recv().ok().map(|msg| PooledReply {
                data: msg.data,
                end: msg.end,
                credit: 0,
            }),
            Self::Sing(replies) => replies.try_recv().map(|msg| PooledReply {
                data: msg.data,
                end: msg.end,
                credit: msg.credit,
            }),
        }
    }

    /// Hands a written reply's window back to the peer; the Cool carrier has no window to return.
    fn settle(&self, credit: usize) {
        if let Self::Sing(replies) = self {
            replies.settle(credit);
        }
    }
}

enum PooledUdpFlow {
    Cool(crate::muxpool::UdpFlow),
    Sing(crate::singmux::UdpFlow),
}

impl PooledUdpFlow {
    fn send(&self, target: &ferrox_core::mux::Target<'_>, data: &[u8]) -> bool {
        match self {
            Self::Cool(flow) => flow.send(target, data),
            Self::Sing(flow) => flow.send(data),
        }
    }

    fn close(self) {
        match self {
            Self::Cool(flow) => flow.close(),
            Self::Sing(flow) => flow.close(),
        }
    }
}

impl PooledFlow {
    fn send(&self, data: &[u8]) -> bool {
        match self {
            Self::Cool(flow) => flow.send(data),
            Self::Sing(flow) => flow.send(data),
        }
    }

    fn take_replies(&mut self) -> Option<PooledReplies> {
        match self {
            Self::Cool(flow) => flow.take_replies().map(PooledReplies::Cool),
            Self::Sing(flow) => flow.take_replies().map(PooledReplies::Sing),
        }
    }

    fn end_upload(&self) {
        match self {
            Self::Cool(flow) => flow.end_upload(),
            Self::Sing(flow) => flow.end_upload(),
        }
    }

    fn close(self) {
        match self {
            Self::Cool(flow) => flow.close(),
            Self::Sing(flow) => flow.close(),
        }
    }
}

/// The carrier pools an outbound's mux settings build, one for TCP and one for its own datagram
/// manager; `Shared` datagrams ride the TCP carrier, so both lanes name the same pool then.
#[derive(Debug, Clone, Default)]
struct Pools(Arc<PoolsInner>);

impl Pools {
    fn tcp(
        &self,
        cap: usize,
        open: impl Fn() -> Option<crate::muxpool::Uplink> + Send + Sync + 'static,
    ) -> Arc<crate::muxpool::Manager> {
        Arc::clone(
            self.0
                .tcp
                .get_or_init(|| crate::muxpool::Manager::new(cap, open)),
        )
    }

    fn udp(
        &self,
        cap: usize,
        open: impl Fn() -> Option<crate::muxpool::Uplink> + Send + Sync + 'static,
    ) -> Arc<crate::muxpool::Manager> {
        Arc::clone(
            self.0
                .udp
                .get_or_init(|| crate::muxpool::Manager::new(cap, open)),
        )
    }

    fn sing(
        &self,
        protocol: crate::singmux::Protocol,
        padding: bool,
        cap: usize,
        open: impl Fn() -> Option<crate::muxpool::Uplink> + Send + Sync + 'static,
    ) -> Arc<crate::singmux::Pool> {
        Arc::clone(
            self.0
                .sing
                .get_or_init(|| crate::singmux::Pool::new(protocol, padding, cap, open)),
        )
    }
}

#[derive(Debug, Default)]
struct PoolsInner {
    tcp: std::sync::OnceLock<Arc<crate::muxpool::Manager>>,
    udp: std::sync::OnceLock<Arc<crate::muxpool::Manager>>,
    sing: std::sync::OnceLock<Arc<crate::singmux::Pool>>,
}

/// What a UDP datagram to port 443 does under a mux: it is refused, rides the mux, or skips it for the direct dial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Udp443 {
    #[default]
    Reject,
    Allow,
    Skip,
}

fn bind_listener(address: &str, role: &Role) -> std::io::Result<Listener> {
    let target = parse_target(address)?;
    match role.transparent() {
        Some(_) => Listener::bind_transparent(&target),
        None => Listener::bind(&target),
    }
}

fn accept_listener(
    listener: Listener,
    address: &str,
    role: &Role,
    tag: Option<&str>,
    stop: Option<std::sync::Arc<Stop>>,
) {
    let sniffing = crate::sniff::for_listener(listener.local_addr().ok(), address);
    for stream in listener.incoming() {
        if stop.as_ref().is_some_and(|stop| stop.stopped()) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let source = stream.peer_addr().ok().map(|peer| peer.ip());
        if !matches!(role, Role::Proxied(_))
            && role
                .tcp_filter()
                .is_some_and(|filters| filters.iter().any(|filter| filter.rejects(source)))
        {
            continue;
        }
        no_delay(&stream);
        let role = role.clone();
        let sniffing = sniffing.clone();
        if role.serves_polled_tls() {
            let stream = stream
                .with_mask_role(role.tcp_mask(), ferrox_core::finalmask::MaskRole::Server)
                .with_meter(crate::stats::inbound(tag))
                .with_policy(Some(crate::policy::flow(0)));
            let stream = with_account(stream, role.account(), false);
            // The ClientHello peek runs on a setup lane, so a stalled hello cannot hold the accept loop.
            let accepted_at = Instant::now();
            let mut work = Some((role, stream, sniffing));
            lane_pool::submit_setup(
                Box::new(move || {
                    if let Some((role, stream, sniffing)) = work.take() {
                        // The header handshake reads the peer's first bytes; the lane spends what is left of the handshake budget, queue time included.
                        let budget = budgets::handshake();
                        let waited = accepted_at.elapsed();
                        if waited >= budget {
                            return lane_pool::Next::Done;
                        }
                        let _cap = budgets::cap_handshake(budget.saturating_sub(waited));
                        if stream.start_mask().is_ok() && stream.complete_xmc().is_ok() {
                            role.serve_polled_tls(stream, sniffing);
                        }
                    }
                    lane_pool::Next::Done
                }),
                Box::new(|| {}),
            );
            continue;
        }
        let tag = tag.map(str::to_owned);
        let accepted_at = Instant::now();
        if role.tcp_stream() {
            let mut work = Some((stream, role, tag, sniffing));
            lane_pool::submit_setup(
                Box::new(move || {
                    if let Some((stream, role, tag, sniffing)) = work.take() {
                        serve_accepted(stream, role, tag.as_deref(), sniffing, accepted_at);
                    }
                    lane_pool::Next::Done
                }),
                Box::new(|| {}),
            );
        } else {
            thread::spawn(move || {
                serve_accepted(stream, role, tag.as_deref(), sniffing, accepted_at);
            });
        }
    }
    drop(listener);
    if let Some(stop) = stop {
        stop.mark_closed();
    }
}

fn serve_accepted(
    mut stream: Connection,
    role: Role,
    tag: Option<&str>,
    sniffing: Option<std::sync::Arc<crate::sniff::Sniffing>>,
    accepted_at: Instant,
) {
    let budget = budgets::handshake();
    let waited = accepted_at.elapsed();
    if waited >= budget {
        return;
    }
    let _cap = budgets::cap_handshake(budget.saturating_sub(waited));
    crate::sniff::install_current(sniffing);
    let (stream, role) = match role {
        Role::Proxied(inner) => {
            let source = crate::conn::read_proxy_header(&mut stream, budgets::handshake());
            let _ = stream.set_read_timeout(None);
            let Ok(source) = source else { return };
            let stream = match source {
                Some(source) => stream.with_peer(source),
                None => stream,
            };
            (stream, *inner)
        }
        role => (stream, role),
    };
    if role.tcp_filter().is_some_and(|filters| {
        filters
            .iter()
            .any(|filter| filter.rejects(stream.peer_addr().ok().map(|peer| peer.ip())))
    }) {
        return;
    }
    // Armed once per accepted stream, as the reference wraps its listener's conn.
    let stream = stream
        .with_mask_role(role.tcp_mask(), ferrox_core::finalmask::MaskRole::Server)
        .with_meter(crate::stats::inbound(tag))
        .with_policy(Some(crate::policy::flow(0)));
    // A server's handshakes read the peer's first bytes here, before the relay arms a one-millisecond poll clock.
    if stream.start_mask().is_err() || stream.complete_xmc().is_err() {
        return;
    }
    front_dispatch(stream, role);
}

pub(crate) fn spawn_carried<F: FnOnce() + Send + 'static>(body: F) {
    let sniffing = crate::sniff::current();
    let access = crate::accesslog::snapshot();
    // The carried flow reads the waits its caller armed, not the constants a new thread defaults to.
    crate::budgets::spawn(move || {
        crate::sniff::install_current(sniffing);
        let _flow = crate::accesslog::install_snapshot(access);
        body();
    });
}

fn spawn_trojan_udp<R, W, C>(reader: R, writer: W, close: C)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    C: FnOnce() + Send + 'static,
{
    spawn_carried(move || serve_trojan_udp_halves(reader, writer, close));
}

fn spawn_trojan_mux<R, W>(
    reader: R,
    writer: W,
    close: Arc<dyn Fn() + Send + Sync>,
    carried: Vec<u8>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    spawn_carried(move || serve_trojan_mux(reader, writer, close, &carried));
}

fn spawn_vless_mux<R, W>(reader: R, writer: W, close: Arc<dyn Fn() + Send + Sync>)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    spawn_carried(move || serve_mux_tunnel(Box::new(reader), Box::new(writer), close, &[]));
}

fn is_singmux_request(cmd: u8, target: &SocketAddr) -> bool {
    cmd == 1 && *target == singmux_sentinel()
}

fn spawn_singmux_halves<R, W>(
    reader: R,
    writer: W,
    close: Arc<dyn Fn() + Send + Sync>,
    carried: Vec<u8>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    spawn_carried(move || serve_singmux_tunnel(reader, writer, close, &carried));
}

fn spawn_singmux_connection(stream: Connection, carried: Vec<u8>) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let closer = stream.try_clone().ok();
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Some(closer) = &closer {
            let _ = closer.shutdown(Shutdown::Both);
        }
    });
    spawn_singmux_halves(reader, stream, close, carried);
}

fn serve_shadowsocks(
    stream: Connection,
    accounts: &crate::shadowsocks::SsAccounts,
    carrier: &Carrier,
    freedom: bool,
    tls: Option<&ferrox_core::tls::TlsServerConfig>,
) {
    if let Some(server) = tls {
        serve_shadowsocks_tls(stream, accounts, carrier, freedom, server);
        return;
    }
    if accounts.is_2022 {
        let (password, method) = (accounts.password.as_str(), accounts.method.as_str());
        let identities = accounts.identities.as_slice();
        match carrier {
            Carrier::Raw(_) => {
                crate::shadowsocks2022::serve(stream, password, method, identities, freedom);
            }
            Carrier::Ws { path, .. } => {
                crate::shadowsocks2022::serve_ws(
                    stream,
                    password,
                    method,
                    identities,
                    path.as_str(),
                    freedom,
                );
            }
            Carrier::HttpUpgrade { path, host, .. } => {
                crate::shadowsocks2022::serve_httpupgrade(
                    stream,
                    password,
                    method,
                    identities,
                    path.as_str(),
                    host,
                    freedom,
                );
            }
            Carrier::Grpc(settings) => {
                crate::shadowsocks2022::serve_grpc_with(
                    stream, password, method, identities, settings, freedom,
                );
            }
            Carrier::Xhttp { settings, .. } => {
                crate::shadowsocks2022::serve_xhttp(
                    stream, password, method, identities, settings, freedom,
                );
            }
            Carrier::HttpHeader {
                paths, response, ..
            } => {
                crate::shadowsocks2022::serve_httpheader_with(
                    stream,
                    password,
                    method,
                    identities,
                    paths,
                    freedom,
                    response.as_deref(),
                );
            }
            refused_carriers!() => {}
        }
        return;
    }
    let users = &accounts.users;
    match carrier {
        Carrier::Raw(_) => crate::shadowsocks::serve(stream, users, freedom),
        Carrier::Ws { path, .. } => {
            crate::shadowsocks::serve_ws(stream, users, path.as_str(), freedom);
        }
        Carrier::HttpUpgrade { path, host, .. } => {
            crate::shadowsocks::serve_httpupgrade(stream, users, path.as_str(), host, freedom);
        }
        Carrier::Grpc(settings) => {
            crate::shadowsocks::serve_grpc_with(stream, users, settings, freedom);
        }
        Carrier::Xhttp { settings, .. } => {
            crate::shadowsocks::serve_xhttp(stream, users, settings, freedom);
        }
        Carrier::HttpHeader {
            paths, response, ..
        } => {
            crate::shadowsocks::serve_httpheader_with(
                stream,
                users,
                paths,
                freedom,
                response.as_deref(),
            );
        }
        refused_carriers!() => {}
    }
}

/// The h2 preface uses the demux the Trojan and `VMess` TLS carriers answer; an H1 peer keeps its session.
fn serve_ss_xhttp_carrier<
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    settings: &crate::xhttp::XhttpSettings,
    accounts: crate::shadowsocks::SsAccounts,
    freedom: bool,
) {
    let settings = settings.clone();
    let sniffing = crate::sniff::current();
    let mut access = Some(crate::accesslog::snapshot());
    let mut read = Some(read);
    let mut write = Some(write);
    let mut accounts = Some(accounts);
    lane_pool::submit_setup(
        Box::new(move || {
            crate::sniff::install_current(sniffing.clone());
            let access = access.take().expect("one xhttp preface");
            let _flow = crate::accesslog::install_snapshot(access);
            let read = read.take().expect("one xhttp preface");
            let write = write.take().expect("one xhttp preface");
            let accounts = accounts.take().expect("one xhttp preface");
            let Some((chained, h2)) = sniff_xhttp(read, false, |_, _| true) else {
                return lane_pool::Next::Done;
            };
            if !h2 {
                let Some((reader, writer)) =
                    crate::xhttp::accept_split_with_settings(chained, write, &settings, None)
                else {
                    return lane_pool::Next::Done;
                };
                let closer = writer.clone();
                let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.finish());
                serve_ss_tls_session(reader, writer, &accounts, freedom, &close);
                return lane_pool::Next::Done;
            }
            #[cfg(test)]
            if let Ok(mut paths) = H2_DIAL_WITNESS.lock() {
                paths.push(settings.path.clone());
            }
            let service = ss_xhttp_service(&settings, accounts, freedom);
            let until = Instant::now() + crate::budgets::handshake();
            let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut step =
                crate::xhttp_h2::h2_lane(chained, write, service, None, Some((until, opened)));
            let sniffing = crate::sniff::current();
            let access = crate::accesslog::snapshot();
            lane_pool::submit_demux(
                Box::new(move || {
                    crate::sniff::install_current(sniffing.clone());
                    let _flow = crate::accesslog::install_snapshot(access.clone());
                    step()
                }),
                Box::new(|| {}),
            );
            lane_pool::Next::Done
        }),
        Box::new(|| {}),
    );
}

fn ss_xhttp_service(
    settings: &crate::xhttp::XhttpSettings,
    accounts: crate::shadowsocks::SsAccounts,
    freedom: bool,
) -> crate::xhttp_h2::XhttpSessionService {
    crate::xhttp_h2::XhttpSessionService::new(
        settings.clone(),
        Arc::new(move |reader, writer, _decryption| {
            if accounts.is_2022 {
                crate::shadowsocks2022::serve_xhttp_accepted(
                    reader,
                    writer,
                    &accounts.password,
                    &accounts.method,
                    &accounts.identities,
                    freedom,
                );
            } else {
                crate::shadowsocks::serve_xhttp_accepted(reader, writer, &accounts.users, freedom);
            }
        }),
    )
}

fn serve_shadowsocks_tls(
    stream: Connection,
    accounts: &crate::shadowsocks::SsAccounts,
    carrier: &Carrier,
    freedom: bool,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match carrier {
        Carrier::Raw(_) => {
            let Ok(raw) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let Ok(transport) = raw.try_clone() else {
                return;
            };
            let (reader, writer) = session_halves(session, transport);
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let _ = raw.shutdown(Shutdown::Both);
            });
            serve_ss_tls_session(reader, writer, accounts, freedom, &close);
        }
        Carrier::Ws { path, .. } => {
            let Ok(out) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session, out);
            let Some((reader, writer)) = crate::ws::accept_split(reader, writer, path) else {
                return;
            };
            let closer = writer.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            serve_ss_tls_session(reader, writer, accounts, freedom, &close);
        }
        Carrier::HttpUpgrade { path, host, .. } => {
            let Ok(raw) = stream.try_clone() else { return };
            let Ok(out) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session, out);
            let Some((reader, writer)) =
                crate::httpupgrade::accept_split(reader, writer, path, host)
            else {
                crate::httpupgrade::quiet(&raw);
                return;
            };
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let _ = raw.shutdown(Shutdown::Both);
            });
            serve_ss_tls_session(reader, writer, accounts, freedom, &close);
        }
        Carrier::Grpc(settings) => {
            let Ok(out) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session, out);
            let Some((reader, writer)) = crate::grpc::accept_split_with(reader, writer, settings)
            else {
                return;
            };
            let closer = writer.clone();
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
            serve_ss_tls_session(reader, writer, accounts, freedom, &close);
        }
        Carrier::Xhttp { settings, .. } => {
            let Ok(out) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session, out);
            serve_ss_xhttp_carrier(reader, writer, settings, accounts.clone(), freedom);
        }
        Carrier::HttpHeader {
            paths, response, ..
        } => {
            let Ok(raw) = stream.try_clone() else { return };
            let Ok(out) = stream.try_clone() else { return };
            let Some(session) = accept_tls_session(stream, server) else {
                return;
            };
            let (reader, writer) = session_halves(session, out);
            let Some((reader, writer)) =
                crate::httpheader::accept_split(reader, writer, paths, response.as_deref())
            else {
                return;
            };
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let _ = raw.shutdown(Shutdown::Both);
            });
            serve_ss_tls_session(reader, writer, accounts, freedom, &close);
        }
        refused_carriers!() => {}
    }
}

fn serve_ss_tls_session<R, W>(
    reader: R,
    writer: W,
    accounts: &crate::shadowsocks::SsAccounts,
    freedom: bool,
    close: &Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    if accounts.is_2022 {
        crate::shadowsocks2022::serve_session(
            reader,
            writer,
            &accounts.password,
            &accounts.method,
            &accounts.identities,
            freedom,
            close,
        );
    } else {
        crate::shadowsocks::serve_session(reader, writer, &accounts.users, freedom, close);
    }
}

#[cfg(test)]
fn serve_vless(
    stream: Connection,
    users: &[VlessUser],
    carrier: &Carrier,
    freedom: bool,
    fallbacks: Option<&[Fallback]>,
    decryption: Option<&Arc<ferrox_core::vless_encryption::Server>>,
) {
    serve_vless_inner(stream, users, None, carrier, freedom, fallbacks, decryption);
}

fn serve_vless_shared(
    stream: Connection,
    users: &VlessUsers,
    carrier: &Carrier,
    freedom: bool,
    fallbacks: Option<&[Fallback]>,
    decryption: Option<&Arc<ferrox_core::vless_encryption::Server>>,
) {
    serve_vless_inner(
        stream,
        users.as_ref(),
        Some(users),
        carrier,
        freedom,
        fallbacks,
        decryption,
    );
}

fn serve_vless_inner(
    stream: Connection,
    users: &[VlessUser],
    shared: Option<&VlessUsers>,
    carrier: &Carrier,
    freedom: bool,
    fallbacks: Option<&[Fallback]>,
    decryption: Option<&Arc<ferrox_core::vless_encryption::Server>>,
) {
    match carrier {
        Carrier::Raw(_) => match decryption {
            Some(decryption) => serve_vless_encrypted_raw(stream, users, freedom, decryption),
            None => serve_vless_raw(stream, users, freedom, fallbacks),
        },
        Carrier::Ws { path, .. } => {
            serve_vless_ws(stream, users, path, freedom, decryption.cloned().as_deref());
        }
        Carrier::HttpUpgrade { path, host, .. } => {
            serve_vless_httpupgrade(
                stream,
                users,
                path,
                host,
                freedom,
                decryption.cloned().as_deref(),
            );
        }
        Carrier::Grpc(settings) => {
            serve_vless_grpc(
                stream,
                users,
                settings,
                freedom,
                decryption.cloned().as_deref(),
            );
        }
        Carrier::Xhttp { settings, .. } => {
            serve_vless_xhttp(stream, settings, users, shared, freedom, decryption);
        }
        Carrier::HttpHeader {
            paths, response, ..
        } => {
            serve_vless_httpheader(
                stream,
                users,
                paths,
                freedom,
                decryption.cloned().as_deref(),
                response.as_deref(),
            );
        }
        refused_carriers!() => {}
    }
}

/// The reverse branch every stream arm shares: attach the portal and report whether the request
/// was one, so the forward path never runs beside it.
fn reverse_carried(
    ask: ReverseAsk<'_>,
    reader: impl Read + Send + 'static,
    writer: impl Write + Send + 'static,
    closer: Arc<dyn Fn() + Send + Sync>,
) -> bool {
    match ask {
        ReverseAsk::Allowed(portal) => attach_reverse(portal, reader, writer, closer),
        ReverseAsk::Refused | ReverseAsk::NotReverse => false,
    }
}

fn serve_vless_ws(
    stream: Connection,
    users: &[VlessUser],
    path: &str,
    freedom: bool,
    decryption: Option<&ferrox_core::vless_encryption::Server>,
) {
    let Some((reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let mut reader = reader;
    if let Some(decryption) = decryption {
        let close = writer.clone();
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || close.close());
        return serve_sealed_carried_with(
            reader,
            writer,
            users,
            freedom,
            decryption,
            close,
            |reader| {
                reader.set_handshake_budget(Some(Instant::now() + budgets::handshake()));
                reader.set_poll(Some(RELAY_POLL));
            },
            |reader| reader.set_handshake_budget(Some(Instant::now() + budgets::handshake())),
            |reader| reader.set_handshake_budget(None),
        );
    }
    // Past the upgrade the frame layer retries timeouts itself, so bound it by wall clock and poll the socket.
    let Some((got, flow, cmd, target)) = under_handshake(&mut reader, |read| {
        decode_request_gated(
            read,
            |id, flow, cmd, _, _| vless_user_allows(users, &id, flow, cmd, freedom, false),
            resolve_endpoint,
        )
    }) else {
        return;
    };
    let ask = reverse_ask(users, &got, flow, cmd);
    if !matches!(ask, ReverseAsk::NotReverse) {
        let closer_writer = writer.clone();
        reverse_carried(ask, reader, writer, Arc::new(move || closer_writer.close()));
        return;
    }
    if !vless_user_allows(users, &got, flow, cmd, freedom, false) {
        return;
    }
    if cmd == 3 || is_singmux_request(cmd, &target) {
        let closer = writer.clone();
        if !writer.send(&[0, 0]) {
            return;
        }
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
        if cmd == 3 {
            spawn_vless_mux(reader, writer, close);
        } else {
            spawn_singmux_halves(reader, writer, close, Vec::new());
        }
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if !writer.send(&[0, 0]) {
        return;
    }
    reader.set_poll(Some(RELAY_POLL));
    crate::proxy::relay_sink_ws(reader, &writer, &uplink);
}

fn serve_vless_httpupgrade(
    stream: Connection,
    users: &[VlessUser],
    path: &str,
    host: &str,
    freedom: bool,
    decryption: Option<&ferrox_core::vless_encryption::Server>,
) {
    let Some((reader, mut write)) = crate::httpupgrade::accept(stream, path, host) else {
        return;
    };
    let mut reader = reader;
    if let Some(decryption) = decryption {
        let close = connection_closer(&write);
        return serve_sealed_carried_with(
            reader,
            write,
            users,
            freedom,
            decryption,
            close,
            |reader| reader.set_poll(Some(budgets::handshake())),
            |_| {},
            |reader| reader.set_poll(Some(RELAY_POLL)),
        );
    }
    reader.set_poll(Some(RELAY_POLL));
    let decoded = decode_request_bounded_gated(
        &mut reader,
        |id, flow, cmd, _, _| vless_user_allows(users, &id, flow, cmd, freedom, false),
        resolve_endpoint,
    );
    reader.set_poll(None);
    let Some((got, flow, cmd, target)) = decoded else {
        return;
    };
    let ask = reverse_ask(users, &got, flow, cmd);
    if !matches!(ask, ReverseAsk::NotReverse) {
        let closer = connection_closer(&write);
        reverse_carried(ask, reader, write, closer);
        return;
    }
    if !vless_user_allows(users, &got, flow, cmd, freedom, false) {
        return;
    }
    if cmd == 3 || is_singmux_request(cmd, &target) {
        let close = connection_closer(&write);
        if write.write_all(&[0, 0]).is_err() {
            return;
        }
        if cmd == 3 {
            spawn_vless_mux(reader, write, close);
        } else {
            spawn_singmux_halves(reader, write, close, Vec::new());
        }
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if write.write_all(&[0, 0]).is_err() {
        return;
    }
    reader.set_poll(Some(RELAY_POLL));
    crate::proxy::relay_carried(reader, &write, &uplink);
}

fn serve_vless_grpc(
    stream: Connection,
    users: &[VlessUser],
    settings: &crate::config::GrpcSettings,
    freedom: bool,
    decryption: Option<&ferrox_core::vless_encryption::Server>,
) {
    if decryption.is_none() {
        let Ok(write) = stream.try_clone() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(RELAY_POLL));
        return crate::grpc::serve_muxed_conn(
            stream,
            crate::grpc::Tail::new(Box::new(write)),
            settings,
            users,
            freedom,
        );
    }
    let Some((reader, writer)) = crate::grpc::accept_with(stream, settings) else {
        return;
    };
    let Some(decryption) = decryption else {
        return;
    };
    let close = writer.clone();
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || close.close());
    serve_sealed_carried_with(
        reader,
        writer,
        users,
        freedom,
        decryption,
        close,
        |reader| {
            reader.set_handshake_budget(Some(Instant::now() + budgets::handshake()));
            reader.set_poll(Some(RELAY_POLL));
        },
        |reader| reader.set_handshake_budget(Some(Instant::now() + budgets::handshake())),
        |reader| reader.set_handshake_budget(None),
    );
}

/// The VLESS handler for one stream of a multiplexed gRPC connection: the demux has already
/// answered the HTTP/2 head, so only the encrypted-VLESS handshake and the relay remain.
pub(crate) fn serve_grpc_muxed(
    mut reader: crate::grpc::GrpcReader<crate::grpc::BodyFrames>,
    writer: crate::grpc::GrpcWriter,
    users: &[VlessUser],
    freedom: bool,
    opened: &std::sync::atomic::AtomicBool,
) {
    reader.arm_mux_poll();
    let Some((got, flow, cmd, target)) = under_handshake(&mut reader, |read| {
        decode_request_gated(
            read,
            |id, flow, cmd, _, _| {
                let allowed = vless_user_allows(users, &id, flow, cmd, freedom, false);
                if allowed {
                    opened.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                allowed
            },
            resolve_endpoint,
        )
    }) else {
        reader.abort();
        return;
    };
    let ask = reverse_ask(users, &got, flow, cmd);
    if matches!(&ask, ReverseAsk::Refused) {
        reader.abort();
        return;
    }
    if !matches!(&ask, ReverseAsk::NotReverse) {
        let closer = writer.clone();
        reverse_carried(ask, reader, writer, Arc::new(move || closer.close()));
        return;
    }
    if !vless_user_allows(users, &got, flow, cmd, freedom, false) {
        reader.abort();
        return;
    }
    if cmd == 3 || is_singmux_request(cmd, &target) {
        let closer = writer.clone();
        if !writer.send(&[0, 0]) {
            reader.abort();
            return;
        }
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || closer.close());
        if cmd == 3 {
            spawn_carried(move || {
                serve_mux_tunnel(Box::new(reader), Box::new(writer), close, &[]);
            });
        } else {
            spawn_singmux_halves(reader, writer, close, Vec::new());
        }
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        reader.abort();
        return;
    };
    if !writer.send(&[0, 0]) {
        reader.abort();
        return;
    }
    let reset = reader.reset_handle();
    if relay_sink_drained_queued(
        reader,
        &writer,
        &uplink,
        crate::grpc::mark_reader_dead,
        |reader| crate::grpc::request_ended(reader),
    )
    .is_none()
    {
        reset();
    }
}

fn serve_vless_httpheader(
    stream: Connection,
    users: &[VlessUser],
    paths: &[String],
    freedom: bool,
    decryption: Option<&ferrox_core::vless_encryption::Server>,
    response: Option<&[u8]>,
) {
    let Some((reader, mut write)) = crate::httpheader::accept(stream, paths, response) else {
        return;
    };
    let mut reader = reader;
    if let Some(decryption) = decryption {
        let close = connection_closer(&write);
        return serve_sealed_carried_with(
            reader,
            write,
            users,
            freedom,
            decryption,
            close,
            |reader| reader.set_poll(Some(budgets::handshake())),
            |_| {},
            |reader| reader.set_poll(Some(RELAY_POLL)),
        );
    }
    reader.set_poll(Some(RELAY_POLL));
    let decoded = decode_request_bounded_gated(
        &mut reader,
        |id, flow, cmd, _, _| vless_user_allows(users, &id, flow, cmd, freedom, false),
        resolve_endpoint,
    );
    reader.set_poll(None);
    let Some((got, flow, cmd, target)) = decoded else {
        return;
    };
    let ask = reverse_ask(users, &got, flow, cmd);
    if !matches!(ask, ReverseAsk::NotReverse) {
        let closer = connection_closer(&write);
        reverse_carried(ask, reader, write, closer);
        return;
    }
    if !vless_user_allows(users, &got, flow, cmd, freedom, false) {
        return;
    }
    if cmd == 3 || is_singmux_request(cmd, &target) {
        let close = connection_closer(&write);
        if write.write_all(&[0, 0]).is_err() {
            return;
        }
        if cmd == 3 {
            spawn_vless_mux(reader, write, close);
        } else {
            spawn_singmux_halves(reader, write, close, Vec::new());
        }
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if write.write_all(&[0, 0]).is_err() {
        return;
    }
    reader.set_poll(Some(RELAY_POLL));
    crate::proxy::relay_carried(reader, &write, &uplink);
