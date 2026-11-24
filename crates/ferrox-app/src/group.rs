//! sing-box's outbound groups: a `selector` that dials one named lane until something changes it,
//! and a `urltest` that probes its lanes and dials the fastest one it has a reading for.

use crate::json::Json;
use crate::proxy::{self, Outbound, RouteShared};
use crate::router::Network;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
const DEFAULT_INTERVAL: Duration = Duration::from_mins(3);
const DEFAULT_IDLE: Duration = Duration::from_mins(30);
const DEFAULT_TOLERANCE: u16 = 50;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

type ResolvedMember = Option<(String, Outbound, Option<u64>)>;
type ResolvedMembers = HashMap<usize, ResolvedMember>;
type Fastest<'a> = (u16, usize, Cow<'a, str>, Outbound, u64);
type Stored<'a> = (usize, Cow<'a, str>, Outbound, u64, Option<u16>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Selector,
    UrlTest,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Selector => "selector",
            Self::UrlTest => "urltest",
        }
    }
}

/// The name a group entry answers to, from either vocabulary this tree carries.
pub(crate) fn kind(config: &Json) -> Option<Kind> {
    let named = config
        .get("protocol")
        .and_then(Json::as_str)
        .or_else(|| config.get("type").and_then(Json::as_str))?;
    if named.eq_ignore_ascii_case("selector") {
        Some(Kind::Selector)
    } else if named.eq_ignore_ascii_case("urltest") {
        Some(Kind::UrlTest)
    } else {
        None
    }
}

pub(crate) fn is_config(config: &Json) -> bool {
    kind(config).is_some()
}

/// Whether the config names any group, so a table is built even with no `routing` block.
pub(crate) fn is_present(root: &Json) -> bool {
    root.get("outbounds")
        .and_then(Json::as_arr)
        .is_some_and(|outbounds| outbounds.iter().any(is_config))
}

#[derive(Debug)]
struct Reading {
    revision: u64,
    delay: u16,
}

/// The latest delay a probe stored for one leaf tag, shared by every urltest group.
#[derive(Debug, Default)]
pub(crate) struct History {
    delays: Mutex<HashMap<String, Reading>>,
    #[cfg(test)]
    locks: AtomicUsize,
}

impl History {
    /// The shared map, one window at a time: a reading sweep takes it once for every member.
    fn guard(&self) -> Option<std::sync::MutexGuard<'_, HashMap<String, Reading>>> {
        #[cfg(test)]
        self.locks.fetch_add(1, Ordering::Relaxed);
        self.delays.lock().ok()
    }

    fn read(delays: &HashMap<String, Reading>, tag: &str, revision: u64) -> Option<u16> {
        let reading = delays.get(tag)?;
        (reading.revision == revision).then_some(reading.delay)
    }

    fn store(&self, tag: &str, revision: u64, delay: u16) {
        if let Ok(mut delays) = self.delays.lock() {
            delays.insert(tag.to_owned(), Reading { revision, delay });
        }
    }

    fn delete(&self, tag: &str, revision: u64) {
        if let Ok(mut delays) = self.delays.lock() {
            let stale = delays
                .get(tag)
                .is_some_and(|reading| reading.revision == revision);
            if stale {
                delays.remove(tag);
            }
        }
    }
}

/// The member position a group dials on each network: two relaxed atomics, so a dial reads its
/// selection without a lock and a probe's write only moves the one it measured.
#[derive(Debug)]
struct Selected {
    tcp: AtomicUsize,
    udp: AtomicUsize,
}

impl Selected {
    const fn new(at: usize) -> Self {
        Self {
            tcp: AtomicUsize::new(at),
            udp: AtomicUsize::new(at),
        }
    }

    /// The member position a group dials on `network`, so a dial reads a slice rather than hashing a tag.
    fn get(&self, network: Network) -> usize {
        match network {
            Network::Udp => self.udp.load(Ordering::Relaxed),
            _ => self.tcp.load(Ordering::Relaxed),
        }
    }

    fn set(&self, network: Network, at: usize) {
        match network {
            Network::Udp => self.udp.store(at, Ordering::Relaxed),
            _ => self.tcp.store(at, Ordering::Relaxed),
        }
    }
}

/// The clock every group's activity stamp counts from, so a touch is one relaxed store.
static ACTIVITY_EPOCH: OnceLock<Instant> = OnceLock::new();

fn activity_nanos() -> u64 {
    ACTIVITY_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub(crate) struct Group {
    tag: String,
    kind: Kind,
    members: Vec<String>,
    default: Option<usize>,
    selected: Selected,
    history: Arc<History>,
    url: String,
    interval: Duration,
    idle: Duration,
    tolerance: u16,
    active: AtomicU64,
    route: OnceLock<Weak<RouteShared>>,
}

impl Group {
    pub(crate) fn members(&self) -> &[String] {
        &self.members
    }

    pub(crate) fn bind(&self, route: &Arc<RouteShared>) {
        let _ = self.route.set(Arc::downgrade(route));
    }

    fn route(&self) -> Option<Arc<RouteShared>> {
        self.route.get()?.upgrade()
    }

    fn touch(&self) {
        if self.kind == Kind::UrlTest {
            self.active.fetch_max(activity_nanos(), Ordering::Relaxed);
        }
    }

    /// Whether the group has been idle past its timeout; a dial stamps it again.
    fn idle(&self) -> bool {
        let idle = u64::try_from(self.idle.as_nanos()).unwrap_or(u64::MAX);
        activity_nanos().saturating_sub(self.active.load(Ordering::Relaxed)) > idle
    }

    /// The lane this group dials on `network`, resolved through any nested group to the leaf its
    /// tag names.
    pub(crate) fn resolve<'a>(
        &'a self,
        route: &'a RouteShared,
        network: Network,
    ) -> Option<(Cow<'a, str>, Outbound)> {
        self.resolve_with(route, network, &mut HashMap::new(), None)
            .map(|(leaf, out, _)| (leaf, out))
    }

    /// The member position a selector dials on `network`: its stored choice, its default, or its
    /// first member.
    fn choice(&self, network: Network) -> usize {
        let at = self.selected.get(network);
        (at < self.members.len())
            .then_some(at)
            .or(self.default)
            .unwrap_or(0)
    }

    fn resolve_with<'a>(
        &'a self,
        route: &'a RouteShared,
        network: Network,
        resolved: &mut ResolvedMembers,
        readings: Option<&HashMap<String, Reading>>,
    ) -> Option<(Cow<'a, str>, Outbound, Option<u64>)> {
        self.touch();
        match self.kind {
            Kind::Selector => {
                let at = self.choice(network);
                resolve_member(route, &self.members[at], network, resolved, readings)
            }
            Kind::UrlTest => self.pick(route, network, resolved, readings),
        }
    }

    fn pick<'a>(
        &'a self,
        route: &'a RouteShared,
        network: Network,
        resolved: &mut ResolvedMembers,
        readings: Option<&HashMap<String, Reading>>,
    ) -> Option<(Cow<'a, str>, Outbound, Option<u64>)> {
        let stored = self.selected.get(network);
        // Retained: the stored member, the fastest, and the first; any other is resolved and dropped.
        let mut current: Option<Stored<'a>> = None;
        let mut best: Option<Fastest<'a>> = None;
        let mut first: Option<(usize, u64)> = None;
        // One window for the whole tree: a nested group shares this map and is handed it, not locked again.
        let guard = match readings {
            Some(_) => None,
            None => self.history.guard(),
        };
        let readings = readings.or(guard.as_deref());
        for (at, member) in self.members.iter().enumerate() {
            let Some((leaf, out, revision)) =
                resolve_member(route, member, network, resolved, readings)
            else {
                continue;
            };
            if !carries(&out, network) {
                continue;
            }
            let Some(revision) = revision else {
                continue;
            };
            if first.is_none() {
                first = Some((at, revision));
            }
            let delay = readings.and_then(|readings| History::read(readings, &leaf, revision));
            if stored == at {
                current = Some((at, leaf, out, revision, delay));
            } else if let Some(delay) = delay {
                if best.as_ref().is_none_or(|(fastest, ..)| delay < *fastest) {
                    best = Some((delay, at, leaf, out, revision));
                }
            }
        }
        let takeover = match &current {
            Some((_, _, _, _, Some(current_delay))) => {
                best.as_ref().is_some_and(|(fastest, ..)| {
                    fastest.saturating_add(self.tolerance) < *current_delay
                })
            }
            _ => true,
        };
        let (at, leaf, out, revision) = if takeover {
            if let Some((_, at, leaf, out, revision)) = best {
                (at, leaf, out, revision)
            } else {
                let (at, revision) = first?;
                // The stored member is often the first eligible one; its resolution is at hand.
                match current {
                    Some((current_at, leaf, out, _, _)) if current_at == at => {
                        (at, leaf, out, revision)
                    }
                    _ => {
                        let (leaf, out, _) =
                            resolve_member(route, &self.members[at], network, resolved, readings)?;
                        (at, leaf, out, revision)
                    }
                }
            }
        } else {
            let (at, leaf, out, revision, _) = current?;
            (at, leaf, out, revision)
        };
        if stored != at {
            self.selected.set(network, at);
        }
        Some((leaf, out, Some(revision)))
    }

    fn leaves(&self, route: &Arc<RouteShared>) -> Vec<String> {
        let mut leaves = Vec::with_capacity(self.members.len());
        let mut seen = HashSet::with_capacity(self.members.len());
        collect_leaves(
            route,
            &self.members,
            &mut leaves,
            &mut HashSet::new(),
            &mut seen,
        );
        leaves
    }

    fn probe(&self, route: &Arc<RouteShared>) {
        const FANOUT: usize = 10;
        let leaves = self.leaves(route);
        if leaves.is_empty() {
            return;
        }
        let next = AtomicUsize::new(0);
        let url = &self.url;
        std::thread::scope(|scope| {
            let sweep = || loop {
                let at = next.fetch_add(1, Ordering::Relaxed);
                let Some(leaf) = leaves.get(at) else {
                    break;
                };
                let Some(revision) = route.leaf_revision(leaf) else {
                    continue;
                };
                let delay = route.probe_target(leaf).map(|target| {
                    crate::observatory::probe(&target, url, "HEAD", PROBE_TIMEOUT, false)
                        .ok()
                        .map(|delay| u16::try_from(delay.as_millis()).unwrap_or(u16::MAX))
                });
                if route.leaf_revision(leaf) != Some(revision) {
                    continue;
                }
                match delay {
                    Some(Some(millis)) => self.history.store(leaf, revision, millis),
                    Some(None) => self.history.delete(leaf, revision),
                    None => {}
                }
            };
            let mut started = 0usize;
            for _ in 0..leaves.len().min(FANOUT) {
                match std::thread::Builder::new().spawn_scoped(scope, sweep) {
                    Ok(_) => started += 1,
                    Err(_) => break,
                }
            }
            if started == 0 {
                sweep();
            }
        });
    }
}

/// Whether a resolved member can take `network`; a sink is a lane the reference still selects,
/// it just drops what the flow sends.
fn carries(out: &Outbound, network: Network) -> bool {
    matches!(out, Outbound::Block(_)) || proxy::outbound_supports_network(out, network)
}

/// Every leaf a group's members reach, in configuration order, as sing-box's probe walk visits
/// each nested group's own member list rather than only the one it currently selects.
fn collect_leaves(
    route: &RouteShared,
    members: &[String],
    leaves: &mut Vec<String>,
    visited: &mut HashSet<String>,
    seen: &mut HashSet<String>,
) {
    for member in members {
        match route.member(member) {
            Some(Outbound::Group(group)) if group.kind == Kind::Selector => {
                if visited.insert(member.clone()) {
                    collect_leaves(route, group.members(), leaves, visited, seen);
                }
            }
            // A nested urltest keeps its own loop, url and interval; touching it keeps an idle branch sweeping.
            Some(Outbound::Group(group)) => group.touch(),
            Some(out) if carries(&out, Network::Tcp) && seen.insert(member.clone()) => {
                leaves.push(member.clone());
            }
            _ => {}
        }
    }
}

/// The leaf one member tag resolves to, through any nested group. A url-test is the only group a
/// walk can reach twice, so it is the only answer worth sharing; a selector names one member and is
/// walked once.
fn resolve_member<'a>(
    route: &'a RouteShared,
    tag: &'a str,
    network: Network,
    resolved: &mut ResolvedMembers,
    readings: Option<&HashMap<String, Reading>>,
) -> Option<(Cow<'a, str>, Outbound, Option<u64>)> {
    let (out, revision) = route.member_revision(tag)?;
    match &out {
        // A nested group's leaf crosses this call's `Arc` clone, so it is owned; a top-level member borrows.
        Outbound::Group(group) if group.kind == Kind::UrlTest => {
            let key = Arc::as_ptr(group) as usize;
            if let Some(done) = resolved.get(&key) {
                return done
                    .clone()
                    .map(|(leaf, out, revision)| (Cow::Owned(leaf), out, revision));
            }
            // A failed subtree is cached too, so a shared descendant that cannot resolve is walked once per sweep, not once per path into it.
            let done = group
                .resolve_with(route, network, resolved, readings)
                .map(|(leaf, out, revision)| (leaf.into_owned(), out, revision));
            resolved.insert(key, done.clone());
            done.map(|(leaf, out, revision)| (Cow::Owned(leaf), out, revision))
        }
        Outbound::Group(group) => group
            .resolve_with(route, network, resolved, readings)
            .map(|(leaf, out, revision)| (Cow::Owned(leaf.into_owned()), out, revision)),
        _ => Some((Cow::Borrowed(tag), out, revision)),
    }
}

fn members(config: &Json) -> Result<Vec<String>, String> {
    let listed = config
        .get("outbounds")
        .or_else(|| {
            config
                .get("settings")
                .and_then(|settings| settings.get("outbounds"))
        })
        .ok_or_else(|| "group has no outbounds list".to_owned())?
        .as_arr()
        .ok_or_else(|| "group outbounds is not an array".to_owned())?;
    if listed.is_empty() {
        return Err("group has no outbounds".to_owned());
    }
    let mut tags = Vec::with_capacity(listed.len());
    let mut seen = HashSet::with_capacity(listed.len());
    for item in listed {
        let tag = item
            .as_str()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| "group outbounds carries a non-string or empty tag".to_owned())?;
        if !seen.insert(tag) {
            return Err(format!("group names `{tag}` twice"));
        }
        tags.push(tag.to_owned());
    }
    Ok(tags)
}

fn field<'a>(config: &'a Json, key: &str) -> Option<&'a Json> {
    config
        .get(key)
        .filter(|value| !matches!(value, Json::Null))
        .or_else(|| {
            config
                .get("settings")
                .and_then(|settings| settings.get(key))
        })
}

fn text<'a>(config: &'a Json, key: &str, tag: &str) -> Result<Option<&'a str>, String> {
    match field(config, key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Str(value)) => Ok(Some(value)),
        Some(_) => Err(format!("group `{tag}` {key} is not a string")),
    }
}

fn duration(value: Option<&Json>, default: Duration, what: &str) -> Result<Duration, String> {
    let Some(value) = value.filter(|value| !matches!(value, Json::Null)) else {
        return Ok(default);
    };
    let nanos = crate::config::go_duration(value)?
        .ok_or_else(|| format!("group {what} is not a duration"))?;
    let nanos = u64::try_from(nanos).map_err(|_| format!("group {what} is negative"))?;
    Ok(if nanos != 0 {
        Duration::from_nanos(nanos)
    } else {
        default
    })
}

fn flag(config: &Json, key: &str) -> bool {
    field(config, key).and_then(Json::as_bool).unwrap_or(false)
}

impl Group {
    pub(crate) fn parse(tag: &str, config: &Json, history: Arc<History>) -> Result<Self, String> {
        let Some(kind) = kind(config) else {
            return Err(format!("outbound `{tag}` is not a group"));
        };
        let members = members(config)?;
        if flag(config, "interrupt_exist_connections") {
            eprintln!(
                "{}: `interrupt_exist_connections` is not carried; existing flows keep their lane",
                kind.name()
            );
        }
        let mut default = None;
        let mut url = DEFAULT_URL.to_owned();
        let mut interval = DEFAULT_INTERVAL;
        let mut idle = DEFAULT_IDLE;
        let mut tolerance = DEFAULT_TOLERANCE;
        match kind {
            Kind::Selector => {
                if let Some(named) = text(config, "default", tag)? {
                    if !named.is_empty() {
                        let at = members
                            .iter()
                            .position(|member| member == named)
                            .ok_or_else(|| {
                                format!(
                                    "selector `{tag}` default `{named}` is not one of its outbounds"
                                )
                            })?;
                        default = Some(at);
                    }
                }
            }
            Kind::UrlTest => {
                if let Some(named) = text(config, "url", tag)? {
                    if !named.is_empty() {
                        named.clone_into(&mut url);
                    }
                }
                crate::conn::HttpUrl::parse(&url)
                    .map_err(|error| format!("urltest `{tag}` url `{url}`: {error}"))?;
                interval = duration(field(config, "interval"), DEFAULT_INTERVAL, "interval")?;
                idle = duration(field(config, "idle_timeout"), DEFAULT_IDLE, "idle_timeout")?;
                if interval > idle {
                    return Err(format!(
                        "urltest `{tag}` interval is longer than its idle_timeout"
                    ));
                }
                if let Some(value) = field(config, "tolerance").filter(|v| !matches!(v, Json::Null))
                {
                    let value = value
                        .as_u32()
                        .ok_or_else(|| format!("urltest `{tag}` tolerance is not a number"))?;
                    tolerance = if value == 0 {
                        DEFAULT_TOLERANCE
                    } else {
                        u16::try_from(value).map_err(|_| {
                            format!("urltest `{tag}` tolerance is outside 1..=65535")
                        })?
                    };
                }
            }
        }
        let first = default.unwrap_or(0);
        Ok(Self {
            tag: tag.to_owned(),
            kind,
            members,
            default,
            selected: Selected::new(first),
            history,
            url,
            interval,
            idle,
            tolerance,
            active: AtomicU64::new(activity_nanos()),
            route: OnceLock::new(),
        })
    }

    pub(crate) fn unbound(tag: &str, config: &Json) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self::parse(
            tag,
            config,
            Arc::new(History::default()),
        )?))
    }
}

/// A group that names itself, directly or through a chain of groups, would resolve forever.
pub(crate) fn check_cycles(groups: &HashMap<String, Arc<Group>>) -> Result<(), String> {
    fn visit(
        tag: &str,
        groups: &HashMap<String, Arc<Group>>,
        visiting: &mut Vec<String>,
        done: &mut std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if done.contains(tag) {
            return Ok(());
        }
        if let Some(at) = visiting.iter().position(|entry| entry == tag) {
            let mut path = visiting[at..].to_vec();
            path.push(tag.to_owned());
            return Err(format!(
                "group `{}` loops through itself",
                path.join(" -> ")
            ));
        }
        let Some(group) = groups.get(tag) else {
            return Ok(());
        };
        visiting.push(tag.to_owned());
        for member in &group.members {
            visit(member, groups, visiting, done)?;
        }
        visiting.pop();
        done.insert(tag.to_owned());
        Ok(())
    }
    let mut done = std::collections::HashSet::new();
    for tag in groups.keys() {
        visit(tag, groups, &mut Vec::new(), &mut done)?;
    }
    Ok(())
}

/// Start one probe loop per urltest group; a group that has been idle for its timeout is skipped
/// until a flow touches it again.
pub(crate) fn spawn(
    groups: &HashMap<String, Arc<Group>>,
    route: &Arc<RouteShared>,
) -> Result<(), String> {
    for group in groups.values() {
        if group.kind != Kind::UrlTest {
            continue;
        }
        let name = group.tag.clone();
        let group = Arc::clone(group);
        let route = Arc::clone(route);
        std::thread::Builder::new()
            .name(format!("ferrox-urltest-{name}"))
            .spawn(move || {
                group.probe(&route);
                loop {
                    std::thread::sleep(group.interval);
                    let idle = group.idle();
                    if !idle {
                        group.probe(&route);
                    }
                }
            })
            .map_err(|error| format!("urltest `{name}` probe loop did not start: {error}"))?;
    }
    Ok(())
}

impl Group {
    /// The bound group's route, for the dial seams that hold only the outbound. The tag is owned:
    /// the only route this seam can reach is a `Weak::upgrade`, which lives no longer than the call,
    /// and holding the strong `Arc` in the group would close the `RouteShared` cycle.
    pub(crate) fn resolve_bound(&self, network: Network) -> Option<(String, Outbound)> {
        let route = self.route()?;
        self.resolve(&route, network)
            .map(|(leaf, out)| (leaf.into_owned(), out))
    }

    pub(crate) fn route_handle(&self) -> Option<Arc<RouteShared>> {
        self.route()
    }

    #[cfg(test)]
    pub(crate) fn record(&self, tag: &str, delay: u16) {
        self.history.store(tag, 0, delay);
    }

    #[cfg(test)]
    pub(crate) fn history_locks(&self) -> usize {
        self.history.locks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_probe_url_is_refused_at_startup() {
        let config = crate::json::parse(
            r#"{"type":"urltest","outbounds":["a"],"url":"example.com/health"}"#,
        )
        .expect("json");
        let error = Group::parse("pick", &config, Arc::new(History::default()))
            .expect_err("a url without a scheme is refused");
        assert!(error.contains("pick"), "{error}");
    }

    #[test]
    fn a_reading_only_names_the_revision_it_measured() {
        let history = History::default();
        history.store("a", 1, 10);
        let delays = history.guard().expect("map");
        assert_eq!(History::read(&delays, "a", 1), Some(10));
        assert_eq!(History::read(&delays, "a", 2), None);
        drop(delays);
        history.delete("a", 2);
        let delays = history.guard().expect("map");
        assert_eq!(History::read(&delays, "a", 1), Some(10));
        drop(delays);
        history.delete("a", 1);
        let delays = history.guard().expect("map");
        assert_eq!(History::read(&delays, "a", 1), None);
    }
}
