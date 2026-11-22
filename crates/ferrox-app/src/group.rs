//! sing-box's outbound groups: a `selector` that dials one named lane until something changes it,
//! and a `urltest` that probes its lanes and dials the fastest one it has a reading for.

use crate::json::Json;
use crate::proxy::{self, Outbound, RouteShared};
use crate::router::Network;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
const DEFAULT_INTERVAL: Duration = Duration::from_mins(3);
const DEFAULT_IDLE: Duration = Duration::from_mins(30);
const DEFAULT_TOLERANCE: u16 = 50;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

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
}

impl History {
    fn load(&self, tag: &str, revision: u64) -> Option<u16> {
        let delays = self.delays.lock().ok()?;
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

#[derive(Debug, Default)]
struct Selected {
    tcp: Option<String>,
    udp: Option<String>,
}

impl Selected {
    fn get(&self, network: Network) -> Option<&str> {
        match network {
            Network::Udp => self.udp.as_deref(),
            _ => self.tcp.as_deref(),
        }
    }

    fn set(&mut self, network: Network, tag: String) {
        *match network {
            Network::Udp => &mut self.udp,
            _ => &mut self.tcp,
        } = Some(tag);
    }
}

#[derive(Debug)]
pub(crate) struct Group {
    tag: String,
    kind: Kind,
    members: Vec<String>,
    default: Option<String>,
    selected: Mutex<Selected>,
    history: Arc<History>,
    url: String,
    interval: Duration,
    idle: Duration,
    tolerance: u16,
    active: Mutex<Instant>,
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
            if let Ok(mut active) = self.active.lock() {
                *active = Instant::now();
            }
        }
    }

    /// The member a selector dials on `network`: its stored choice, its default, or its first
    /// member.
    pub(crate) fn selected_member(&self, network: Network) -> String {
        self.selected
            .lock()
            .ok()
            .and_then(|selected| selected.get(network).map(str::to_owned))
            .or_else(|| self.default.clone())
            .unwrap_or_else(|| self.members[0].clone())
    }

    /// The lane this group dials on `network`, resolved through any nested group to the leaf its
    /// tag names.
    pub(crate) fn resolve(
        &self,
        route: &RouteShared,
        network: Network,
    ) -> Option<(String, Outbound)> {
        self.resolve_with(route, network, &mut HashMap::new())
    }

    fn resolve_with(
        &self,
        route: &RouteShared,
        network: Network,
        resolved: &mut HashMap<String, Option<(String, Outbound)>>,
    ) -> Option<(String, Outbound)> {
        if let Some(done) = resolved.get(&self.tag) {
            return done.clone();
        }
        self.touch();
        let done = match self.kind {
            Kind::Selector => {
                let tag = self.selected_member(network);
                resolve_member(route, &tag, network, resolved)
            }
            Kind::UrlTest => self.pick(route, network, resolved),
        };
        resolved.insert(self.tag.clone(), done.clone());
        done
    }

    fn pick(
        &self,
        route: &RouteShared,
        network: Network,
        resolved: &mut HashMap<String, Option<(String, Outbound)>>,
    ) -> Option<(String, Outbound)> {
        let current = self
            .selected
            .lock()
            .ok()
            .and_then(|selected| selected.get(network).map(str::to_owned))
            .and_then(|member| {
                let (leaf, out) = resolve_member(route, &member, network, resolved)?;
                carries(&out, network).then_some((member, leaf, out))
            });
        let current_delay = current.as_ref().and_then(|(_, leaf, _)| {
            let revision = route.leaf_revision(leaf)?;
            self.history.load(leaf, revision)
        });
        let mut best: Option<(u16, String, String, Outbound)> = None;
        let mut fallback = None;
        for member in &self.members {
            let Some((leaf, out)) = resolve_member(route, member, network, resolved) else {
                continue;
            };
            if !carries(&out, network) {
                continue;
            }
            fallback.get_or_insert_with(|| (member.clone(), leaf.clone(), out.clone()));
            let Some(revision) = route.leaf_revision(&leaf) else {
                continue;
            };
            let Some(delay) = self.history.load(&leaf, revision) else {
                continue;
            };
            if best.as_ref().is_none_or(|(fastest, ..)| delay < *fastest) {
                best = Some((delay, member.clone(), leaf, out));
            }
        }
        let takeover = match (&current, current_delay) {
            (Some(_), Some(current_delay)) => best.as_ref().is_some_and(|(fastest, ..)| {
                fastest.saturating_add(self.tolerance) < current_delay
            }),
            _ => true,
        };
        let fastest = best.map(|(_, member, leaf, out)| (member, leaf, out));
        let chosen = if takeover { fastest } else { current };
        let chosen = chosen.or(fallback);
        if let Some((member, _, _)) = &chosen {
            if let Ok(mut selected) = self.selected.lock() {
                selected.set(network, member.clone());
            }
        }
        chosen.map(|(_, leaf, out)| (leaf, out))
    }

    fn leaves(&self, route: &Arc<RouteShared>) -> Vec<String> {
        let mut leaves = Vec::with_capacity(self.members.len());
        collect_leaves(route, &self.members, &mut leaves, &mut HashSet::new());
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
) {
    for member in members {
        match route.member(member) {
            Some(Outbound::Group(group)) if group.kind == Kind::Selector => {
                if visited.insert(member.clone()) {
                    collect_leaves(route, group.members(), leaves, visited);
                }
            }
            // A nested urltest keeps its own loop, url and interval; touching it keeps an idle branch sweeping.
            Some(Outbound::Group(group)) => group.touch(),
            Some(out)
                if carries(&out, Network::Tcp) && !leaves.iter().any(|leaf| leaf == member) =>
            {
                leaves.push(member.clone());
            }
            _ => {}
        }
    }
}

/// The leaf one member tag resolves to, through any nested group; one lookup shares the answers
/// so a diamond of nested groups is walked once, not once per path.
fn resolve_member(
    route: &RouteShared,
    tag: &str,
    network: Network,
    resolved: &mut HashMap<String, Option<(String, Outbound)>>,
) -> Option<(String, Outbound)> {
    if let Some(done) = resolved.get(tag) {
        return done.clone();
    }
    let out = route.member(tag)?;
    let done = match &out {
        Outbound::Group(group) => group.resolve_with(route, network, resolved),
        _ => Some((tag.to_owned(), out)),
    };
    resolved.insert(tag.to_owned(), done.clone());
    done
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
    for item in listed {
        let tag = item
            .as_str()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| "group outbounds carries a non-string or empty tag".to_owned())?;
        if tags.iter().any(|have| have == tag) {
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
                        if !members.iter().any(|member| member == named) {
                            return Err(format!(
                                "selector `{tag}` default `{named}` is not one of its outbounds"
                            ));
                        }
                        default = Some(named.to_owned());
                    }
                }
            }
            Kind::UrlTest => {
                if let Some(named) = text(config, "url", tag)? {
                    if !named.is_empty() {
                        named.clone_into(&mut url);
                    }
                }
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
        let first = default.clone().unwrap_or_else(|| members[0].clone());
        let mut selected = Selected::default();
        selected.set(Network::Tcp, first.clone());
        selected.set(Network::Udp, first);
        Ok(Self {
            tag: tag.to_owned(),
            kind,
            members,
            default,
            selected: Mutex::new(selected),
            history,
            url,
            interval,
            idle,
            tolerance,
            active: Mutex::new(Instant::now()),
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
                    let idle = group
                        .active
                        .lock()
                        .is_ok_and(|active| active.elapsed() > group.idle);
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
    /// The bound group's route, for the dial seams that hold only the outbound.
    pub(crate) fn resolve_bound(&self, network: Network) -> Option<(String, Outbound)> {
        let route = self.route()?;
        self.resolve(&route, network)
    }

    pub(crate) fn route_handle(&self) -> Option<Arc<RouteShared>> {
        self.route()
    }

    #[cfg(test)]
    pub(crate) fn record(&self, tag: &str, delay: u16) {
        self.history.store(tag, 0, delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_only_names_the_revision_it_measured() {
        let history = History::default();
        history.store("a", 1, 10);
        assert_eq!(history.load("a", 1), Some(10));
        assert_eq!(history.load("a", 2), None);
        history.delete("a", 2);
        assert_eq!(history.load("a", 1), Some(10));
        history.delete("a", 1);
        assert_eq!(history.load("a", 1), None);
    }
}
