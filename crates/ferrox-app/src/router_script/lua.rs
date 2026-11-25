//! The routing script: xray's Lua hook that answers a flow before the rule table does.
//!
//! The script reads the same context a rule does and returns an outbound tag; the modules it can
//! `require` are rebuilt here from this tree's matchers, not linked from a Lua runtime.

use super::{Picker, Resolver, ScriptCallbacks};
use crate::json::Json;
use crate::router::{
    AssetCache, Assets, DomainMatcher, Flow, IpMatcher, Network, add_domain, ip_matcher,
};
use mlua::{
    AnyUserData, Error as LuaError, HookTriggers, Lua, LuaOptions, MetaMethod, Result as LuaResult,
    StdLib, Table, UserData, UserDataMethods, Value, Variadic, VmState, chunk::ChunkMode,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(6);
const LOAD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_IDLE_STATES: usize = 16;
const NETWORK_UNKNOWN: i64 = 0;
const NETWORK_TCP: i64 = 2;
const NETWORK_UDP: i64 = 3;
const NETWORK_UNIX: i64 = 4;

struct Call {
    resolve: Arc<Resolver>,
    pick: Arc<Picker>,
}

#[derive(Default)]
struct CallHooks {
    call: Mutex<Option<Call>>,
}

impl CallHooks {
    fn set_initial(&self, deadline: Instant, expired: Arc<AtomicBool>) {
        let resolver = crate::dnsapp::installed();
        let resolve: Arc<Resolver> = Arc::new(move |host, _port, fake, v4, v6| {
            if Instant::now() >= deadline {
                expired.store(true, Ordering::Relaxed);
                return (Vec::new(), 0, Some("routing script timed out".to_owned()));
            }
            if let Some(resolver) = resolver.as_ref() {
                return match resolver.script_lookup(host, v4, v6, fake) {
                    crate::dnsapp::Lookup::Records(addrs, ttl) => (addrs, ttl, None),
                    crate::dnsapp::Lookup::Rcode(code) => {
                        (Vec::new(), 0, Some(format!("response code {code}")))
                    }
                    crate::dnsapp::Lookup::Empty => {
                        (Vec::new(), 0, Some("empty response".to_owned()))
                    }
                    crate::dnsapp::Lookup::Skipped | crate::dnsapp::Lookup::Failed => {
                        let (mut addrs, ttl) = crate::router::resolve_ips_system(host, 0, v4, v6);
                        addrs.retain(|address| {
                            (v4 && address.is_ipv4()) || (v6 && address.is_ipv6())
                        });
                        (addrs, ttl, None)
                    }
                };
            }
            let (mut addrs, ttl) = crate::router::resolve_ips_ttl(host, 0);
            addrs.retain(|address| (v4 && address.is_ipv4()) || (v6 && address.is_ipv6()));
            (addrs, ttl, None)
        });
        let pick: Arc<Picker> = Arc::new(|_| Err("no routing context".into()));
        *self.call.lock().unwrap_or_else(PoisonError::into_inner) = Some(Call { resolve, pick });
    }

    fn set(&self, callbacks: &ScriptCallbacks) {
        *self.call.lock().unwrap_or_else(PoisonError::into_inner) = Some(Call {
            resolve: Arc::clone(&callbacks.resolve),
            pick: Arc::clone(&callbacks.pick),
        });
    }

    fn clear(&self) {
        self.call
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn resolve(
        &self,
        host: &str,
        port: u16,
        fake: bool,
        v4: bool,
        v6: bool,
    ) -> LuaResult<(Vec<IpAddr>, u32, Option<String>)> {
        let resolve = {
            let call = self.call.lock().unwrap_or_else(PoisonError::into_inner);
            call.as_ref().map(|call| Arc::clone(&call.resolve))
        }
        .ok_or_else(|| LuaError::RuntimeError("no routing context".into()))?;
        Ok(resolve(host, port, fake, v4, v6))
    }

    fn pick(&self, tag: &str) -> LuaResult<(Option<String>, Option<String>)> {
        let pick = {
            let call = self.call.lock().unwrap_or_else(PoisonError::into_inner);
            call.as_ref().map(|call| Arc::clone(&call.pick))
        }
        .ok_or_else(|| LuaError::RuntimeError("no routing context".into()))?;
        match pick(tag) {
            Ok(tag) => Ok((Some(tag), None)),
            Err(error) => Ok((None, Some(error))),
        }
    }
}

struct State {
    lua: Lua,
    hooks: Arc<CallHooks>,
}

/// The compiled routing script and the states it runs in. A state is lent to one flow at a time and
/// dropped after a failure, so a script that timed out cannot leave a half-entered call behind.
pub(crate) struct ScriptRouter {
    source: Vec<u8>,
    name: String,
    dirs: Arc<Vec<PathBuf>>,
    assets: AssetCache,
    idle: Mutex<Vec<State>>,
}

impl std::fmt::Debug for ScriptRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptRouter")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Everything `HandleRoute` reads, copied out of the borrowed flow before the call because a Lua
/// userdata has to outlive the connection's borrow.
struct ScriptContext {
    source: Vec<IpAddr>,
    target: Vec<IpAddr>,
    local: Vec<IpAddr>,
    inbound: String,
    source_port: u16,
    target_port: u16,
    local_port: u16,
    domain: String,
    network: i64,
    protocol: String,
    user: String,
    vless_route: u16,
    skip_dns: bool,
    attributes: HashMap<String, String>,
}

impl ScriptRouter {
    /// Load the script xray names: a path resolved as `ResolveLuaFile` does, with a syntax error
    /// reported before any socket opens.
    pub(crate) fn parse_in(path: &str, dirs: Vec<PathBuf>) -> Result<Self, String> {
        let name = super::resolve(path, &dirs)?;
        Self::parse_resolved(&name, dirs)
    }

    pub(crate) fn parse_resolved(
        name: &std::path::Path,
        dirs: Vec<PathBuf>,
    ) -> Result<Self, String> {
        let _assets = super::read_assets();
        let source = std::fs::read(name)
            .map_err(|error| format!("routing script `{}`: {error}", name.display()))?;
        let router = Self {
            source,
            name: name.display().to_string(),
            dirs: Arc::new(dirs),
            assets: Arc::new(Mutex::new(HashMap::new())),
            idle: Mutex::new(Vec::new()),
        };
        let state = router.new_state(Instant::now() + LOAD_TIMEOUT)?;
        router.release(state);
        Ok(router)
    }

    /// Rebuild a VM from the source this router already holds, so a geodata refresh does not
    /// reopen a script file the operator may have removed.
    pub(crate) fn rebuilt(&self) -> Result<Self, String> {
        let router = Self {
            source: self.source.clone(),
            name: self.name.clone(),
            dirs: Arc::clone(&self.dirs),
            assets: Arc::new(Mutex::new(HashMap::new())),
            idle: Mutex::new(Vec::new()),
        };
        let state = router.new_state(Instant::now() + LOAD_TIMEOUT)?;
        router.release(state);
        Ok(router)
    }

    fn release(&self, state: State) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < MAX_IDLE_STATES {
            idle.push(state);
        }
    }

    fn acquire(&self, deadline: Instant) -> Result<State, String> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = idle.pop() {
            return Ok(state);
        }
        drop(idle);
        self.new_state(deadline)
    }

    fn new_state(&self, deadline: Instant) -> Result<State, String> {
        let lua = Lua::new_with(
            StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::OS,
            LuaOptions::default(),
        )
        .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let hooks = Arc::new(CallHooks::default());
        let expired = Arc::new(AtomicBool::new(false));
        hooks.set_initial(deadline, Arc::clone(&expired));
        install(&lua, &hooks, &self.dirs, &self.assets)
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let load_expired = Arc::clone(&expired);
        lua.set_global_hook(
            HookTriggers::new().every_nth_instruction(1000),
            move |_, _| {
                if Instant::now() >= deadline {
                    load_expired.store(true, Ordering::Relaxed);
                    Ok(VmState::Yield)
                } else {
                    Ok(VmState::Continue)
                }
            },
        )
        .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let run = super::with_script_initializing(std::ptr::from_ref(self) as usize, || {
            crate::dnsapp::with_system_deadline(deadline, || {
                lua.load(&self.source)
                    .set_name(&self.name)
                    .set_mode(ChunkMode::Text)
                    .exec()
            })
        });
        run.map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        if expired.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(format!("routing script `{}`: timed out", self.name));
        }
        let handle = lua
            .globals()
            .get::<Value>("HandleRoute")
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        if !matches!(handle, Value::Function(_)) {
            return Err("routing script must define HandleRoute(...)".into());
        }
        Ok(State { lua, hooks })
    }

    /// Xray lowercases each code point on its own, so a Greek capital sigma at the end of a
    /// `targetDomain` becomes `σ`, not the final form `ς` that `str::to_lowercase` produces, and
    /// `İ` becomes `i` without the combining dot.
    fn simple_lowercase(text: &str) -> String {
        text.chars()
            .filter_map(|c| c.to_lowercase().next())
            .collect()
    }

    #[cfg(test)]
    fn route(
        &self,
        flow: &Flow,
        callbacks: &ScriptCallbacks,
        skip_dns: bool,
    ) -> Result<Option<String>, String> {
        let _assets = super::read_assets();
        self.route_locked(flow, callbacks, skip_dns)
    }

    /// Run `HandleRoute` for one flow, while the caller holds the asset read guard; `None` means
    /// the script has no clue and the rule table decides.
    pub(crate) fn route_locked(
        &self,
        flow: &Flow,
        callbacks: &ScriptCallbacks,
        skip_dns: bool,
    ) -> Result<Option<String>, String> {
        if super::initializing_script(std::ptr::from_ref(self) as usize) {
            return Ok(None);
        }
        // The live budget starts before acquisition: a pool miss runs the top-level chunk against the same absolute deadline.
        let deadline = Instant::now() + TIMEOUT;
        let state = self.acquire(deadline)?;
        let context = ScriptContext {
            source: flow.source.map_or_default(|ip| vec![ip]),
            target: flow.ip.map_or_default(|ip| vec![ip]),
            local: flow.local.map_or_default(|ip| vec![ip]),
            inbound: flow.inbound_tag.unwrap_or("").to_owned(),
            source_port: flow.source_port,
            target_port: flow.port.unwrap_or(0),
            local_port: flow.local_port,
            domain: Self::simple_lowercase(flow.domain.unwrap_or("")),
            network: match flow.network {
                Network::Tcp => NETWORK_TCP,
                Network::Udp => NETWORK_UDP,
                Network::Other(raw) => i64::from(raw),
            },
            protocol: flow.protocol.unwrap_or("").to_owned(),
            user: flow.user.unwrap_or("").to_owned(),
            vless_route: flow.vless_route,
            skip_dns,
            attributes: flow.attrs.map_or_else(HashMap::new, |attrs| {
                attrs
                    .iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
                    .collect()
            }),
        };
        state.hooks.set(callbacks);
        let guard = ClearOnDrop(&state.hooks);
        let expired = Arc::new(AtomicBool::new(false));
        let call_expired = Arc::clone(&expired);
        state
            .lua
            .set_global_hook(
                HookTriggers::new().every_nth_instruction(1000),
                move |_, _| {
                    if Instant::now() >= deadline {
                        call_expired.store(true, Ordering::Relaxed);
                        Ok(VmState::Yield)
                    } else {
                        Ok(VmState::Continue)
                    }
                },
            )
            .map_err(|error| format!("routing script `{}`: {error}", self.name))?;
        let result = crate::dnsapp::with_system_deadline(deadline, || call(&state.lua, context));
        drop(guard);
        if expired.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err("routing script timed out".into());
        }
        match result {
            Ok(tag) => {
                self.release(state);
                Ok(tag)
            }
            Err(error) => Err(error),
        }
    }
}

struct ClearOnDrop<'a>(&'a CallHooks);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn call(lua: &Lua, context: ScriptContext) -> Result<Option<String>, String> {
    let handle = lua
        .globals()
        .get::<Value>("HandleRoute")
        .map_err(|error| error.to_string())?;
    let Value::Function(handle) = handle else {
        return Err("routing script must define HandleRoute(...)".into());
    };
    let ScriptContext {
        source,
        target,
        local,
        inbound,
        source_port,
        target_port,
        local_port,
        domain,
        network,
        protocol,
        user,
        vless_route,
        skip_dns,
        attributes,
    } = context;
    let context = lua
        .create_userdata(ContextUser {
            source,
            target,
            local,
            attributes,
        })
        .map_err(|error| error.to_string())?;
    let thread = lua
        .create_thread(handle)
        .map_err(|error| error.to_string())?;
    let values = thread
        .resume::<mlua::MultiValue>((
            context,
            inbound,
            source_port,
            target_port,
            local_port,
            domain,
            network,
            protocol,
            user,
            vless_route,
            skip_dns,
        ))
        .map_err(|error| error.to_string())?;
    let mut values = values.into_iter();
    let outbound = values.next().unwrap_or(Value::Nil);
    let rule = values.next().unwrap_or(Value::Nil);
    let error = values.next().unwrap_or(Value::Nil);
    if !matches!(error, Value::Nil) {
        let message = match error {
            Value::String(text) => text.to_string_lossy(),
            Value::Error(error) => error.to_string(),
            other => format!("routing script error must be an error or string, not {other:?}"),
        };
        return Err(message);
    }
    let outbound = match outbound {
        Value::Nil => None,
        Value::String(tag) => {
            let tag = tag.to_string_lossy();
            if tag.is_empty() { None } else { Some(tag) }
        }
        _ => return Err("routing script outboundTag must be a string or nil".into()),
    };
    if outbound.is_none() {
        return Ok(None);
    }
    if !matches!(rule, Value::Nil | Value::String(_)) {
        return Err("routing script ruleTag must be a string".into());
    }
    Ok(outbound)
}

fn dns_flag(value: &Value, name: &str) -> Result<bool, LuaError> {
    match value {
        Value::Boolean(flag) => Ok(*flag),
        _ => Err(LuaError::RuntimeError(format!(
            "DNS `{name}` must be a boolean"
        ))),
    }
}

fn dns_answer(
    lua: &Lua,
    addrs: Vec<IpAddr>,
    ttl: u32,
    ipv4: bool,
    ipv6: bool,
) -> LuaResult<(Value, f64, Option<LuaError>)> {
    let addrs = addrs
        .into_iter()
        .filter(|addr| (ipv4 && addr.is_ipv4()) || (ipv6 && addr.is_ipv6()))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Ok((
            Value::Nil,
            0.0,
            Some(LuaError::RuntimeError("empty response".to_owned())),
        ));
    }
    let list = lua.create_userdata(IpList {
        items: Arc::new(addrs),
    })?;
    Ok((Value::UserData(list), f64::from(ttl), None))
}

#[allow(clippy::too_many_lines)]
fn install(
    lua: &Lua,
    hooks: &Arc<CallHooks>,
    dirs: &Arc<Vec<PathBuf>>,
    assets: &AssetCache,
) -> LuaResult<()> {
    for name in [
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "print",
        "getfenv",
        "setfenv",
        "getmetatable",
        "setmetatable",
        "rawget",
        "rawset",
        "collectgarbage",
        "module",
        "newproxy",
        "_printregs",
        "package",
    ] {
        lua.globals().set(name, Value::Nil)?;
    }
    if let Ok(table) = lua.globals().get::<mlua::Table>("os") {
        for name in [
            "execute",
            "exit",
            "getenv",
            "remove",
            "rename",
            "tmpname",
            "setlocale",
        ] {
            table.set(name, Value::Nil)?;
        }
    }
    if let Ok(table) = lua.globals().get::<mlua::Table>("string") {
        table.set("dump", Value::Nil)?;
    }
    // A table or function tostring would spell a native address; policy sees its type instead, while a userdata's own `__tostring` (an IP) still prints.
    lua.load(
        r#"local raw = tostring
tostring = function(value)
    local kind = type(value)
    if kind == "table" or kind == "function" or kind == "thread" then
        return kind
    end
    return raw(value)
end"#,
    )
    .exec()?;

    let router = lua.create_table()?;
    router.set("NetworkUnknown", NETWORK_UNKNOWN)?;
    router.set("NetworkTCP", NETWORK_TCP)?;
    router.set("NetworkUDP", NETWORK_UDP)?;
    router.set("NetworkUNIX", NETWORK_UNIX)?;
    router.set("LocalOS", crate::router::local_os())?;
    let pick_hooks = Arc::clone(hooks);
    router.set(
        "PickOutbound",
        lua.create_function(move |_, tag: String| pick_hooks.pick(&tag))?,
    )?;
    router.set(
        "FindProcess",
        lua.create_function(|_, _: Variadic<Value>| {
            Ok((
                0,
                String::new(),
                String::new(),
                "process lookup is not carried".to_owned(),
            ))
        })?,
    )?;

    let log = lua.create_table()?;
    for name in ["Debug", "Info"] {
        log.set(name, lua.create_function(|_, _: Variadic<Value>| Ok(()))?)?;
    }
    for name in ["Warning", "Error"] {
        log.set(
            name,
            lua.create_function(|lua, values: Variadic<Value>| {
                let mut text = String::new();
                for value in values {
                    if let Ok(part) = lua.coerce_string(value).and_then(|part| {
                        part.ok_or_else(|| LuaError::RuntimeError("log value is not text".into()))
                    }) {
                        text.push_str(&part.to_string_lossy());
                    }
                }
                if !text.is_empty() {
                    eprintln!("routing script: {text}");
                }
                Ok(())
            })?,
        )?;
    }

    let dns = lua.create_table()?;
    let query_hooks = Arc::clone(hooks);
    dns.set(
        "Query",
        lua.create_function(
            move |lua, (name, ipv4, ipv6, fake): (String, Value, Value, Value)| {
                let ipv4 = dns_flag(&ipv4, "IPv4")?;
                let ipv6 = dns_flag(&ipv6, "IPv6")?;
                let fake = dns_flag(&fake, "FakeEnable")?;
                let (addrs, ttl, error) = match query_hooks.resolve(&name, 0, fake, ipv4, ipv6) {
                    Ok(answer) => answer,
                    Err(error) => return Ok((Value::Nil, 0.0, Some(error))),
                };
                if let Some(error) = error {
                    return Ok((Value::Nil, 0.0, Some(LuaError::RuntimeError(error))));
                }
                dns_answer(lua, addrs, ttl, ipv4, ipv6)
            },
        )?,
    )?;
    let servers = lua.create_table()?;
    if let Some(resolver) = crate::dnsapp::installed() {
        for (id, index) in resolver.script_servers() {
            let server = lua.create_table()?;
            server.set("ID", id)?;
            let resolver = Arc::clone(&resolver);
            server.set(
                "Query",
                lua.create_function(
                    move |lua,
                          (_server, name, ipv4, ipv6, fake): (
                        Value,
                        String,
                        Value,
                        Value,
                        Value,
                    )| {
                        let ipv4 = dns_flag(&ipv4, "IPv4")?;
                        let ipv6 = dns_flag(&ipv6, "IPv6")?;
                        let fake = dns_flag(&fake, "FakeEnable")?;
                        match resolver.script_query(index, &name, ipv4, ipv6, fake) {
                            crate::dnsapp::Lookup::Records(addrs, ttl) => {
                                dns_answer(lua, addrs, ttl, ipv4, ipv6)
                            }
                            crate::dnsapp::Lookup::Empty | crate::dnsapp::Lookup::Skipped => Ok((
                                Value::Nil,
                                0.0,
                                Some(LuaError::RuntimeError("empty response".to_owned())),
                            )),
                            crate::dnsapp::Lookup::Rcode(code) => Ok((
                                Value::Nil,
                                0.0,
                                Some(LuaError::RuntimeError(format!("response code {code}"))),
                            )),
                            crate::dnsapp::Lookup::Failed => Ok((
                                Value::Nil,
                                0.0,
                                Some(LuaError::RuntimeError("lookup failed".to_owned())),
                            )),
                        }
                    },
                )?,
            )?;
            servers.set(index + 1, server)?;
        }
    } else {
        let server = lua.create_table()?;
        server.set("ID", "localhost")?;
        server.set(
            "Query",
            lua.create_function(
                |lua, (_server, name, ipv4, ipv6, fake): (Value, String, Value, Value, Value)| {
                    let ipv4 = dns_flag(&ipv4, "IPv4")?;
                    let ipv6 = dns_flag(&ipv6, "IPv6")?;
                    let _ = dns_flag(&fake, "FakeEnable")?;
                    let (addrs, ttl) = crate::router::resolve_ips_ttl(&name, 0);
                    dns_answer(lua, addrs, ttl, ipv4, ipv6)
                },
            )?,
        )?;
        servers.set(1, server)?;
    }
    dns.set("Servers", servers)?;

    let dns_dirs = Arc::clone(dirs);
    let dns_assets = Arc::clone(assets);
    let geodata = lua.create_table()?;
    geodata.set(
        "BuildDomainMatcher",
        lua.create_function(move |_, rules: Variadic<Value>| {
            let mut strings = Vec::with_capacity(rules.len());
            for rule in rules {
                match rule {
                    Value::String(rule) => strings.push(rule.to_string_lossy()),
                    _ => {
                        return Err(LuaError::RuntimeError(
                            "BuildDomainMatcher rules must be strings".into(),
                        ));
                    }
                }
            }
            build_domain_matcher(&strings, &dns_dirs, &dns_assets)
        })?,
    )?;
    let ip_dirs = Arc::clone(dirs);
    let ip_assets = Arc::clone(assets);
    geodata.set(
        "BuildIPMatcher",
        lua.create_function(move |_, rules: Variadic<String>| {
            let rules: Vec<String> = rules.into_iter().collect();
            build_ip_matcher(&rules, &ip_dirs, &ip_assets)
        })?,
    )?;
    let modules: HashMap<&'static str, Table> = [
        ("xray.router", router),
        ("xray.log", log),
        ("xray.dns", dns),
        ("xray.geodata", geodata),
    ]
    .into_iter()
    .collect();
    let require = lua.create_function(move |_, name: String| {
        modules
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| LuaError::RuntimeError(format!("module '{name}' not found")))
    })?;
    lua.globals().set("require", require)?;
    Ok(())
}

fn fold_literal_rule(rule: &str) -> String {
    for prefix in ["domain:", "full:", "keyword:", "dotless:"] {
        if let Some(rest) = rule.strip_prefix(prefix) {
            return format!("{prefix}{}", ScriptRouter::simple_lowercase(rest));
        }
    }
    rule.to_owned()
}

fn build_domain_matcher(
    rules: &[String],
    dirs: &[PathBuf],
    cache: &AssetCache,
) -> LuaResult<DomainMatcherUser> {
    if rules.is_empty() {
        return Err(LuaError::RuntimeError(
            "BuildDomainMatcher needs at least one rule".into(),
        ));
    }
    let mut assets = Assets::cached(dirs.to_vec(), Arc::clone(cache));
    let mut matchers = Vec::with_capacity(rules.len());
    for rule in rules {
        let rule = match rule.as_str() {
            value
                if value.starts_with("geosite:")
                    || value.starts_with("ext:")
                    || value.starts_with("ext-domain:")
                    || value.starts_with("ext-site:")
                    || value.starts_with("regexp:")
                    || value.starts_with("domain:")
                    || value.starts_with("full:")
                    || value.starts_with("keyword:")
                    || value.starts_with("dotless:") =>
            {
                value.to_owned()
            }
            value => format!("domain:{value}"),
        };
        let rule = fold_literal_rule(&rule);
        let mut matcher = DomainMatcher::new();
        add_domain(&mut matcher, &rule, &mut assets).map_err(LuaError::RuntimeError)?;
        matcher.finish().map_err(LuaError::RuntimeError)?;
        matchers.push(matcher);
    }
    Ok(DomainMatcherUser { matchers })
}

fn build_ip_matcher(
    rules: &[String],
    dirs: &[PathBuf],
    cache: &AssetCache,
) -> LuaResult<IpMatcherUser> {
    if rules.is_empty() {
        return Err(LuaError::RuntimeError(
            "BuildIPMatcher needs at least one rule".into(),
        ));
    }
    let mut groups: [Vec<String>; 4] = std::array::from_fn(|_| Vec::new());
    for rule in rules {
        let (geoip, reverse) = ip_rule_group(rule);
        let at = usize::from(geoip) * 2 + usize::from(reverse);
        groups[at].push(rule.clone());
    }
    let mut assets = Assets::cached(dirs.to_vec(), Arc::clone(cache));
    let mut matchers = Vec::with_capacity(groups.len());
    for group in groups {
        if group.is_empty() {
            continue;
        }
        let value = Json::Arr(group.into_iter().map(Json::Str).collect());
        matchers
            .push(ip_matcher(&value, &mut assets, "geodata ip").map_err(LuaError::RuntimeError)?);
    }
    Ok(IpMatcherUser {
        matchers,
        reverse: None,
        flip: false,
    })
}

fn ip_rule_group(rule: &str) -> (bool, bool) {
    let (rule, mut reverse) = strip_reverse(rule);
    let code = if let Some(code) = rule.strip_prefix("geoip:") {
        Some(code)
    } else {
        rule.strip_prefix("ext:")
            .or_else(|| rule.strip_prefix("ext-ip:"))
            .and_then(|rest| rest.split_once(':').map(|(_, code)| code))
    };
    let geoip = code.is_some();
    if let Some(code) = code {
        reverse ^= strip_reverse(code).1;
    }
    (geoip, reverse)
}

fn strip_reverse(mut value: &str) -> (&str, bool) {
    let mut reverse = false;
    while let Some(rest) = value.strip_prefix('!') {
        value = rest;
        reverse = !reverse;
    }
    (value, reverse)
}

struct DomainMatcherUser {
    matchers: Vec<DomainMatcher>,
}

impl UserData for DomainMatcherUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("Match", |lua, this, domain: String| {
            let mut found = Vec::new();
            for (at, matcher) in this.matchers.iter().enumerate() {
                if matcher.matches(&domain, &domain) {
                    found.push(u32::try_from(at).unwrap_or(u32::MAX));
                }
            }
            lua.create_userdata(DomainMatches {
                items: Arc::new(found),
            })
        });
        methods.add_method("MatchAny", |_, this, domain: String| {
            Ok(this
                .matchers
                .iter()
                .any(|matcher| matcher.matches(&domain, &domain)))
        });
    }
}

struct DomainMatches {
    items: Arc<Vec<u32>>,
}

impl UserData for DomainMatches {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(this.items.len()));
        methods.add_meta_method(MetaMethod::Index, |_, this, key: Value| {
            let at = match key {
                Value::Integer(at) => at,
                Value::Number(at) => at as i64,
                _ => return Ok(Value::Nil),
            };
            if at < 1 {
                return Ok(Value::Nil);
            }
            match this.items.get((at - 1) as usize) {
                Some(index) => Ok(Value::Integer(i64::from(*index))),
                None => Ok(Value::Nil),
            }
        });
        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_, _, (_key, _value): (Value, Value)| {
                Err::<(), _>(LuaError::RuntimeError("slice is read-only".into()))
            },
        );
        methods.add_meta_method(MetaMethod::Call, |lua, this, ()| {
            let items = Arc::clone(&this.items);
            let at = Arc::new(AtomicUsize::new(0));
            lua.create_function(move |_, (): ()| {
                let position = at.fetch_add(1, Ordering::Relaxed);
                Ok(match items.get(position) {
                    Some(index) => (
                        Value::Integer(i64::try_from(position + 1).unwrap_or(i64::MAX)),
                        Value::Integer(i64::from(*index)),
                    ),
                    None => (Value::Nil, Value::Nil),
                })
            })
        });
    }
}

struct IpMatcherUser {
    matchers: Vec<IpMatcher>,
    reverse: Option<bool>,
    flip: bool,
}

impl IpMatcherUser {
    fn matches(&self, ip: std::net::IpAddr) -> bool {
        // Mapped input stays on the shared matcher, where a `::ffff:` rule from /33 through /95 is still checked as the IPv6 range it spells.
        self.matchers
            .iter()
            .any(|matcher| matcher.matches_override(ip, self.reverse, self.flip))
    }
}

impl UserData for IpMatcherUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("Match", |_, this, ip: Option<AnyUserData>| {
            let Some(ip) = ip else {
                return Ok(false);
            };
            let ip = ip.borrow::<IpUser>()?;
            Ok(this.matches(ip.0))
        });
        methods.add_method("AnyMatch", |_, this, ips: Option<AnyUserData>| {
            let Some(ips) = ips else {
                return Ok(false);
            };
            let ips = ips.borrow::<IpList>()?;
            Ok(ips.items.iter().any(|ip| this.matches(*ip)))
        });
        methods.add_method("Matches", |_, this, ips: Option<AnyUserData>| {
            let Some(ips) = ips else {
                return Ok(false);
            };
            let ips = ips.borrow::<IpList>()?;
            Ok(this.matchers.iter().any(|matcher| {
                matcher.matches_all_override(ips.items.as_slice(), this.reverse, this.flip)
            }))
        });
        methods.add_method("FilterIPs", |lua, this, ips: Option<AnyUserData>| {
            let ips = match ips {
                Some(ips) => ips.borrow::<IpList>()?.items.clone(),
                None => Arc::new(Vec::<IpAddr>::new()),
            };
            let mut kept = Vec::new();
            let mut remaining = ips.as_ref().clone();
            let ordered = this.matchers.len() > 1
                || this
                    .matchers
                    .iter()
                    .any(crate::router::IpMatcher::has_buckets);
            for matcher in &this.matchers {
                let mut next = Vec::with_capacity(remaining.len());
                let mut hit = Vec::new();
                for ip in remaining {
                    if matcher.matches_override(ip, this.reverse, this.flip) {
                        hit.push(ip);
                    } else {
                        next.push(ip);
                    }
                }
                // The reference emits each group's IPv4 answers before its IPv6 answers, and a `::ffff:` answer is IPv4.
                if ordered {
                    hit.sort_by_key(|ip| to4(*ip).is_none());
                }
                kept.extend(hit);
                remaining = next;
            }
            let mut unmatched = remaining;
            if ordered {
                unmatched.sort_by_key(|ip| to4(*ip).is_none());
            }
            let kept = lua.create_userdata(IpList {
                items: Arc::new(kept),
            })?;
            let unmatched = lua.create_userdata(IpList {
                items: Arc::new(unmatched),
            })?;
            Ok((kept, unmatched))
        });
        methods.add_method_mut("SetReverse", |_, this, reverse: bool| {
            this.reverse = Some(reverse);
            this.flip = false;
            Ok(())
        });
        methods.add_method_mut("ToggleReverse", |_, this, ()| {
            match this.reverse {
                Some(reverse) => this.reverse = Some(!reverse),
                None => this.flip = !this.flip,
            }
            Ok(())
        });
    }
}

struct ContextUser {
    source: Vec<IpAddr>,
    target: Vec<IpAddr>,
    local: Vec<IpAddr>,
    attributes: HashMap<String, String>,
}

impl UserData for ContextUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("GetSourceIPs", |lua, this, ()| ip_list(lua, &this.source));
        methods.add_method("GetTargetIPs", |lua, this, ()| ip_list(lua, &this.target));
        methods.add_method("GetLocalIPs", |lua, this, ()| ip_list(lua, &this.local));
        methods.add_method("GetAttributes", |lua, this, ()| {
            lua.create_userdata(AttributeView {
                attributes: this.attributes.clone(),
            })
        });
    }
}

fn ip_list(lua: &Lua, addrs: &[IpAddr]) -> LuaResult<Value> {
    if addrs.is_empty() {
        return Ok(Value::Nil);
    }
    Ok(Value::UserData(lua.create_userdata(IpList {
        items: Arc::new(addrs.to_vec()),
    })?))
}

/// A read-only, indexable view of a flow's attributes, shaped like the reference's userdata rather than a table a policy could mutate.
struct AttributeView {
    attributes: HashMap<String, String>,
}

impl UserData for AttributeView {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method("__index", |_, this, key: String| {
            Ok(this.attributes.get(&key).cloned())
        });
    }
}

struct IpList {
    items: Arc<Vec<IpAddr>>,
}

impl UserData for IpList {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(this.items.len()));
        methods.add_meta_method(MetaMethod::Index, |lua, this, key: Value| {
            let at = match key {
                Value::Integer(at) => at,
                Value::Number(at) => at as i64,
                _ => return Ok(Value::Nil),
            };
            if at < 1 {
                return Ok(Value::Nil);
            }
            match this.items.get((at - 1) as usize) {
                Some(ip) => Ok(Value::UserData(lua.create_userdata(IpUser(*ip))?)),
                None => Ok(Value::Nil),
            }
        });
        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_, _, (_key, _value): (Value, Value)| {
                Err::<(), _>(LuaError::RuntimeError("slice is read-only".into()))
            },
        );
        methods.add_meta_method(MetaMethod::Call, |lua, this, ()| {
            let items = Arc::clone(&this.items);
            let at = Arc::new(AtomicUsize::new(0));
            lua.create_function(move |lua, (): ()| {
                let index = at.fetch_add(1, Ordering::Relaxed);
                Ok(match items.get(index) {
                    Some(ip) => (
                        Value::Integer(i64::try_from(index + 1).unwrap_or(i64::MAX)),
                        Value::UserData(lua.create_userdata(IpUser(*ip))?),
                    ),
                    None => (Value::Nil, Value::Nil),
                })
            })
        });
    }
}

struct MaskUser(Vec<u8>);

impl UserData for MaskUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(this.0.len()));
        methods.add_meta_method(MetaMethod::Index, |_, this, key: Value| {
            let at = match key {
                Value::Integer(at) => at,
                Value::Number(at) => at as i64,
                _ => return Ok(Value::Nil),
            };
            if at < 1 {
                return Ok(Value::Nil);
            }
            Ok(this
                .0
                .get((at - 1) as usize)
                .copied()
                .map_or(Value::Nil, |byte| Value::Integer(i64::from(byte))))
        });
        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_, _, (_key, _value): (Value, Value)| {
                Err::<(), _>(LuaError::RuntimeError("mask is read-only".into()))
            },
        );
        methods.add_method("String", |_, this, ()| {
            let mut out = String::with_capacity(this.0.len() * 2);
            for byte in &this.0 {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
            }
            Ok(out)
        });
        methods.add_method("Size", |_, this, ()| {
            let ones = this.0.iter().map(|byte| byte.count_ones()).sum::<u32>();
            Ok((ones, u32::try_from(this.0.len() * 8).unwrap_or(u32::MAX)))
        });
    }
}

#[derive(Clone, Copy)]
struct IpUser(IpAddr);

impl UserData for IpUser {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| Ok(addr_string(this.0)));
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| Ok(ip_user_len(this.0)));
        methods.add_meta_method(MetaMethod::Index, |_, this, index: usize| {
            Ok(ip_user_byte(this.0, index))
        });
        methods.add_method("String", |_, this, ()| Ok(addr_string(this.0)));
        methods.add_method("To4", |_, this, ()| {
            Ok(to4(this.0).map(|ip| IpUser(IpAddr::V4(ip))))
        });
        methods.add_method("To16", |_, this, ()| Ok(Some(IpUser(to16(this.0)))));
        methods.add_method("EqualTo", |_, this, other: AnyUserData| {
            let other = other.borrow::<IpUser>()?;
            Ok(equal(this.0, other.0))
        });
        methods.add_method("Equal", |_, this, other: AnyUserData| {
            let other = other.borrow::<IpUser>()?;
            Ok(equal(this.0, other.0))
        });
        methods.add_method("Is4", |_, this, ()| Ok(to4(this.0).is_some()));
        methods.add_method("Is6", |_, this, ()| {
            Ok(matches!(this.0, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none()))
        });
        methods.add_method("IsUnspecified", |_, this, ()| Ok(unspecified(this.0)));
        methods.add_method("IsLoopback", |_, this, ()| Ok(loopback(this.0)));
        methods.add_method("IsPrivate", |_, this, ()| Ok(private(this.0)));
        methods.add_method("IsMulticast", |_, this, ()| Ok(multicast(this.0)));
        methods.add_method("IsInterfaceLocalMulticast", |_, this, ()| {
            Ok(interface_multicast(this.0))
        });
        methods.add_method("IsLinkLocalMulticast", |_, this, ()| {
            Ok(link_multicast(this.0))
        });
        methods.add_method("IsLinkLocalUnicast", |_, this, ()| Ok(link_unicast(this.0)));
        methods.add_method("IsGlobalUnicast", |_, this, ()| {
            Ok(!unspecified(this.0)
                && !loopback(this.0)
                && !multicast(this.0)
                && !link_unicast(this.0)
                && !limited_broadcast(this.0))
        });
        methods.add_method("DefaultMask", |_, this, ()| {
            Ok(default_mask(this.0).map(MaskUser))
        });
        methods.add_method("Mask", |_, this, mask: AnyUserData| {
            let mask = if mask.is::<MaskUser>() {
                mask.borrow::<MaskUser>()?.0.clone()
            } else {
                let mask = mask.borrow::<IpUser>()?;
                ip_user_bytes(mask.0)
            };
            Ok(mask_ip(this.0, &mask).map(IpUser))
        });
        methods.add_method("MarshalText", |_, this, ()| {
            Ok((addr_string(this.0), Option::<String>::None))
        });
        methods.add_method_mut("UnmarshalText", |_, this, text: String| {
            let addr = text
                .parse::<IpAddr>()
                .map_err(|error| LuaError::RuntimeError(error.to_string()))?;
            this.0 = addr;
            Ok(())
        });
        methods.add_method("AppendText", |_, _, ()| {
            Err::<(), _>(LuaError::RuntimeError("method is not carried".into()))
        });
    }
}

fn addr_string(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.to_string(),
            None => ip.to_string(),
        },
    }
}

fn to4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
}

fn to16(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(ip) => IpAddr::V6(ip.to_ipv6_mapped()),
        IpAddr::V6(_) => addr,
    }
}

fn ip_user_len(addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn ip_user_byte(addr: IpAddr, index: usize) -> Option<u8> {
    let at = index.checked_sub(1)?;
    match addr {
        IpAddr::V4(ip) => ip.octets().get(at).copied(),
        IpAddr::V6(ip) => ip.octets().get(at).copied(),
    }
}

fn ip_user_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn ip_bytes(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn equal(left: IpAddr, right: IpAddr) -> bool {
    ip_bytes(left) == ip_bytes(right)
}

fn unspecified(addr: IpAddr) -> bool {
    if let Some(ip) = to4(addr) {
        return ip.is_unspecified();
    }
    matches!(addr, IpAddr::V6(ip) if ip.is_unspecified())
}

fn loopback(addr: IpAddr) -> bool {
    if let Some(ip) = to4(addr) {
        return ip.is_loopback();
    }
    matches!(addr, IpAddr::V6(ip) if ip.is_loopback())
}

fn multicast(addr: IpAddr) -> bool {
    if let Some(ip) = to4(addr) {
        return ip.is_multicast();
    }
    matches!(addr, IpAddr::V6(ip) if ip.is_multicast())
}

fn private(addr: IpAddr) -> bool {
    match to4(addr) {
        Some(ip) => {
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        None => match addr {
            IpAddr::V6(ip) => ip.segments()[0] & 0xfe00 == 0xfc00,
            IpAddr::V4(_) => false,
        },
    }
}

fn interface_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V6(ip) => ip.segments()[0] & 0xff0f == 0xff01,
        IpAddr::V4(_) => false,
    }
}

fn link_multicast(addr: IpAddr) -> bool {
    if let Some(ip) = to4(addr) {
        let octets = ip.octets();
        return octets[0] == 224 && octets[1] == 0 && octets[2] == 0;
    }
    matches!(addr, IpAddr::V6(ip) if ip.segments()[0] & 0xff0f == 0xff02)
}

fn link_unicast(addr: IpAddr) -> bool {
    if let Some(ip) = to4(addr) {
        let octets = ip.octets();
        return octets[0] == 169 && octets[1] == 254;
    }
    matches!(addr, IpAddr::V6(ip) if ip.segments()[0] & 0xffc0 == 0xfe80)
}

fn limited_broadcast(addr: IpAddr) -> bool {
    matches!(to4(addr), Some(ip) if ip == Ipv4Addr::BROADCAST)
}

fn default_mask(addr: IpAddr) -> Option<Vec<u8>> {
    let ip = to4(addr)?;
    let first = ip.octets()[0];
    let ones = if first & 0x80 == 0 {
        8
    } else if first & 0xc0 == 0x80 {
        16
    } else {
        24
    };
    let mut mask = vec![0xff; ones / 8];
    mask.resize(4, 0);
    Some(mask)
}

fn mask_ip(addr: IpAddr, mask: &[u8]) -> Option<IpAddr> {
    let mut bytes = match addr {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let mut mask = mask.to_vec();
    if mask.len() == 16 && bytes.len() == 4 && mask[..12].iter().all(|byte| *byte == 0xff) {
        mask = mask[12..].to_vec();
    }
    if mask.len() == 4
        && bytes.len() == 16
        && bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
    {
        bytes = bytes[12..].to_vec();
    }
    if bytes.len() != mask.len() {
        return None;
    }
    for (byte, mask) in bytes.iter_mut().zip(mask.iter()) {
        *byte &= mask;
    }
    Some(match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        16 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes);
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_lowercases_one_code_point_at_a_time() {
        assert_eq!(ScriptRouter::simple_lowercase("ΟΣ"), "οσ");
        assert_eq!(ScriptRouter::simple_lowercase("İ.test"), "i.test");
    }

    #[test]
    fn an_ip_address_strings_the_way_go_prints_it() {
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 4).to_ipv6_mapped());
        assert_eq!(addr_string(mapped), "192.0.2.4");
        assert_eq!(
            addr_string(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))),
            "192.0.2.4"
        );
    }

    #[test]
    fn a_classful_mask_follows_the_first_octet() {
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(vec![255, 0, 0, 0])
        );
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            Some(vec![255, 255, 0, 0])
        );
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            Some(vec![255, 255, 255, 0])
        );
        assert_eq!(
            default_mask(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))),
            Some(vec![255, 255, 255, 0])
        );
    }

    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrox-script-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn callbacks() -> ScriptCallbacks {
        ScriptCallbacks {
            resolve: Arc::new(|_, _, _, _, _| (Vec::new(), 0, None)),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        }
    }

    fn flow() -> Flow<'static> {
        Flow {
            network: Network::Tcp,
            domain: Some("blocked.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: Some("in"),
            protocol: Some("http/1.1"),
            user: Some("a@x"),
            attrs: None,
            process: None,
        }
    }

    #[test]
    fn a_script_reads_its_arguments_and_can_pick_a_balancer() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local router = require("xray.router")
function HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, targetDomain, network, protocol, user)
  if inbound ~= "in" or targetDomain ~= "blocked.test" or targetPort ~= 443 then
    return nil
  end
  if network ~= router.NetworkTCP then return nil end
  if user ~= "a@x" then return nil end
  return router.PickOutbound("proxy"), "scripted"
end
"#,
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        assert_eq!(
            router.route(&flow(), &callbacks(), false).expect("routes"),
            Some("picked-proxy".to_owned())
        );
    }

    #[test]
    fn a_script_sees_the_loopback_skip_dns_flag() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
function HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, targetDomain, network, protocol, user, vlessRoute, skipDNSResolve)
  if skipDNSResolve then return "direct" end
  return nil
end
"#,
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        assert_eq!(
            router.route(&flow(), &callbacks(), true).expect("routes"),
            Some("direct".to_owned())
        );
        assert_eq!(
            router.route(&flow(), &callbacks(), false).expect("routes"),
            None
        );
    }

    #[test]
    fn a_script_that_names_no_tag_leaves_the_decision_open() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        assert_eq!(
            router.route(&flow(), &callbacks(), false).expect("routes"),
            None
        );
    }

    #[test]
    fn a_non_string_tag_names_the_field() {
        let dir = dir();
        std::fs::write(dir.join("route.lua"), "function HandleRoute() return 7 end")
            .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        let error = router
            .route(&flow(), &callbacks(), false)
            .expect_err("refused");
        assert!(error.contains("outboundTag"), "{error}");
    }

    #[test]
    fn a_nil_outbound_leaves_a_malformed_rule_tag_unread() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return nil, 7 end",
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        assert_eq!(
            router.route(&flow(), &callbacks(), false).expect("routes"),
            None
        );
    }

    #[test]
    fn a_taken_ipv4_address_indexes_its_four_bytes() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let v6 = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped());
        let bytes = ip_user_bytes(v4);
        assert_eq!(bytes, vec![192, 0, 2, 9]);
        assert_eq!(ip_user_bytes(v6).len(), 16);
        let (len, counts) = ferrox_core::alloc_count::measure(|| ip_user_len(v4));
        assert_eq!(len, 4);
        assert_eq!(counts.allocs, 0, "the length is a family, not a vector");
        let (byte, counts) = ferrox_core::alloc_count::measure(|| ip_user_byte(v4, 1));
        assert_eq!(byte, Some(192));
        assert_eq!(counts.allocs, 0, "one byte is read from the octets");
    }

    #[test]
    fn an_ip_matcher_reads_a_mapped_address_as_its_ipv4_form() {
        use crate::json::Json;

        let mut assets = Assets::new(Vec::new());
        let matcher = ip_matcher(
            &Json::Arr(vec![
                Json::Str("192.0.2.0/24".into()),
                Json::Str("::ffff:198.51.100.0/120".into()),
            ]),
            &mut assets,
            "test",
        )
        .expect("matcher");
        let matcher = IpMatcherUser {
            matchers: vec![matcher],
            reverse: None,
            flip: false,
        };
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped());
        assert!(matcher.matches(mapped));
        let plain = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        assert!(matcher.matches(plain));
    }

    #[test]
    fn a_script_can_query_dns_while_it_initializes() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local dns = require("xray.dns")
local ips = dns.Query("127.0.0.1", true, false, false)
if ips == nil or #ips == 0 then return nil end
function HandleRoute() return "direct" end
"#,
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses after a top-level DNS query");
        assert_eq!(
            router.route(&flow(), &callbacks(), false).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn a_dns_query_returns_its_ttl_and_the_server_table_is_indexed() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local dns = require("xray.dns")
function HandleRoute()
  if #dns.Servers < 1 or type(dns.Servers[1].ID) ~= "string" then return nil end
  local ips, ttl = dns.Query("blocked.test", true, false, false)
  if ips == nil or ttl ~= 60 then return nil end
  return "direct"
end
"#,
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        let callbacks = ScriptCallbacks {
            resolve: Arc::new(|_, _, _, _, _| {
                (vec!["192.0.2.9".parse().expect("address")], 60, None)
            }),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        };
        assert_eq!(
            router.route(&flow(), &callbacks, false).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn a_script_dns_query_reads_the_resolver_ttl() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            r#"
local dns = require("xray.dns")
function HandleRoute()
  local ips, ttl, err = dns.Query("example.com", true, false, true)
  if not err and ttl == 42 and #ips == 1 then return "direct" end
  return nil
end
"#,
        )
        .expect("write");
        let router =
            ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
                .expect("parses");
        let callbacks = ScriptCallbacks {
            resolve: Arc::new(|host, _, fake, v4, v6| {
                assert_eq!(host, "example.com");
                assert!(fake);
                assert!(v4);
                assert!(!v6);
                (vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], 42, None)
            }),
            pick: Arc::new(|tag| Ok(format!("picked-{tag}"))),
        };
        assert_eq!(
            router.route(&flow(), &callbacks, false).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn ipv4_mapped_addresses_use_the_ipv4_predicates() {
        let mapped = |text: &str| text.parse::<IpAddr>().expect("address");
        assert!(loopback(mapped("::ffff:127.0.0.1")));
        assert!(unspecified(mapped("::ffff:0.0.0.0")));
        let multicast_mapped = IpAddr::V6(Ipv4Addr::new(224, 0, 0, 1).to_ipv6_mapped());
        assert!(multicast(multicast_mapped));
        assert!(link_unicast(mapped("::ffff:169.254.1.1")));
        assert!(link_multicast(multicast_mapped));
        assert!(limited_broadcast(mapped("::ffff:255.255.255.255")));
    }

    #[test]
    fn a_script_cannot_read_the_process_environment() {
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        lua.load(r"assert(os.getenv == nil)")
            .exec()
            .expect("environment is hidden");
    }

    #[test]
    fn a_domain_matcher_match_result_is_the_callable_slice_xray_returns() {
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        lua.load(
            r#"
local geodata = require("xray.geodata")
local matcher = geodata.BuildDomainMatcher("domain:other.test", "domain:example.com")
local matches = matcher:Match("www.example.com")
local seen = {}
for pos, index in matches() do seen[#seen + 1] = pos .. ":" .. index end
assert(#seen == 1 and seen[1] == "1:1")
assert(matches[1] == 1)
local folded = geodata.BuildDomainMatcher("domain:ABC.test")
assert(#folded:Match("ABC.test") == 0)
assert(#folded:Match("abc.test") == 1)
"#,
        )
        .exec()
        .expect("calls the match result");
    }

    #[test]
    fn an_ip_slice_iterator_returns_the_position_and_the_address() {
        let lua = Lua::new();
        let list = lua
            .create_userdata(IpList {
                items: Arc::new(vec![
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                ]),
            })
            .expect("list");
        lua.globals().set("ips", list).expect("globals");
        lua.load(
            r#"
local seen = {}
for pos, ip in ips() do seen[#seen + 1] = pos .. ":" .. ip:String() end
assert(#seen == 2 and seen[1] == "1:192.0.2.1" and seen[2] == "2:198.51.100.2")
"#,
        )
        .exec()
        .expect("iterates the slice");
    }

    #[test]
    fn an_ip_matcher_list_must_fit_one_group() {
        let matcher = build_ip_matcher(
            &["192.0.2.0/24".to_owned(), "!192.0.2.0/24".to_owned()],
            &[],
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("matcher");
        let split = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        ];
        assert!(
            !matcher
                .matchers
                .iter()
                .any(|matcher| matcher.matches_all_override(&split, None, false))
        );
        let one = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        ];
        assert!(
            matcher
                .matchers
                .iter()
                .any(|matcher| matcher.matches_all_override(&one, None, false))
        );
    }

    #[test]
    fn custom_reverse_rules_are_combined_before_reversing() {
        let matcher = build_ip_matcher(
            &["!192.0.2.0/24".to_owned(), "!198.51.100.0/24".to_owned()],
            &[],
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("matcher");
        assert!(!matcher.matches("192.0.2.1".parse().expect("address")));
        assert!(!matcher.matches("198.51.100.2".parse().expect("address")));
        assert!(matcher.matches("203.0.113.3".parse().expect("address")));
    }

    #[test]
    fn custom_positive_rules_match_a_list_spanning_both() {
        let matcher = build_ip_matcher(
            &["192.0.2.0/24".to_owned(), "198.51.100.0/24".to_owned()],
            &[],
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("matcher");
        let ips = [
            "192.0.2.1".parse().expect("address"),
            "198.51.100.2".parse().expect("address"),
        ];
        assert!(
            matcher
                .matchers
                .iter()
                .any(|matcher| matcher.matches_all_override(&ips, None, false))
        );
    }

    #[test]
    fn filter_ips_preserves_unmatched_order_for_one_matcher() {
        use crate::json::Json;
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        let mut assets = Assets::new(Vec::new());
        let matcher = ip_matcher(
            &Json::Arr(vec![Json::Str("192.0.2.1/32".into())]),
            &mut assets,
            "test",
        )
        .expect("matcher");
        let matcher = lua
            .create_userdata(IpMatcherUser {
                matchers: vec![matcher],
                reverse: None,
                flip: false,
            })
            .expect("matcher userdata");
        let native: IpAddr = "2001:db8::1".parse().unwrap();
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        let unmatched = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 2).to_ipv6_mapped());
        let ips = lua
            .create_userdata(IpList {
                items: Arc::new(vec![native, mapped, unmatched]),
            })
            .expect("list");
        lua.globals()
            .set("matcher", matcher)
            .expect("matcher global");
        lua.globals().set("ips", ips).expect("ips global");
        lua.load(
            r#"
local kept, rest = matcher:FilterIPs(ips)
local function first(list)
  for _, ip in list() do return ip:String() end
end
assert(first(kept) == "192.0.2.1", first(kept))
local function all(list)
  local out = {}
  for _, ip in list() do out[#out + 1] = ip:String() end
  return out
end
local rest = all(rest)
assert(#rest == 2 and rest[1] == "2001:db8::1" and rest[2] == "198.51.100.2", table.concat(rest, ","))
"#,
        )
        .exec()
        .expect("filters and orders");
    }

    #[test]
    fn filter_ips_orders_a_mixed_width_single_matcher() {
        use crate::json::Json;
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        let mut assets = Assets::new(Vec::new());
        let matcher = ip_matcher(
            &Json::Arr(vec![
                Json::Str("192.0.2.0/24".into()),
                Json::Str("2001:db8::1/128".into()),
            ]),
            &mut assets,
            "test",
        )
        .expect("matcher");
        let matcher = lua
            .create_userdata(IpMatcherUser {
                matchers: vec![matcher],
                reverse: None,
                flip: false,
            })
            .expect("matcher userdata");
        let native: IpAddr = "2001:db8::1".parse().unwrap();
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        let ips = lua
            .create_userdata(IpList {
                items: Arc::new(vec![native, mapped]),
            })
            .expect("list");
        lua.globals()
            .set("matcher", matcher)
            .expect("matcher global");
        lua.globals().set("ips", ips).expect("ips global");
        lua.load(
            r#"
local kept, rest = matcher:FilterIPs(ips)
local function all(list)
  local out = {}
  for _, ip in list() do out[#out + 1] = ip:String() end
  return out
end
local kept = all(kept)
local rest = all(rest)
assert(#kept == 2 and kept[1] == "192.0.2.1" and kept[2] == "2001:db8::1", table.concat(kept, ","))
assert(#rest == 0, table.concat(rest, ","))
"#,
        )
        .exec()
        .expect("filters and orders");
    }

    #[test]
    fn filter_ips_keeps_group_order_for_several_matchers() {
        use crate::json::Json;
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        let mut assets = Assets::new(Vec::new());
        let first = ip_matcher(
            &Json::Arr(vec![Json::Str("192.0.2.1/32".into())]),
            &mut assets,
            "test",
        )
        .expect("first matcher");
        let second = ip_matcher(
            &Json::Arr(vec![Json::Str("198.51.100.2/32".into())]),
            &mut assets,
            "test",
        )
        .expect("second matcher");
        let matcher = lua
            .create_userdata(IpMatcherUser {
                matchers: vec![first, second],
                reverse: None,
                flip: false,
            })
            .expect("matcher userdata");
        let native: IpAddr = "2001:db8::1".parse().unwrap();
        let first_hit = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        let second_hit = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 2).to_ipv6_mapped());
        let miss = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 3).to_ipv6_mapped());
        let ips = lua
            .create_userdata(IpList {
                items: Arc::new(vec![native, first_hit, second_hit, miss]),
            })
            .expect("list");
        lua.globals()
            .set("matcher", matcher)
            .expect("matcher global");
        lua.globals().set("ips", ips).expect("ips global");
        lua.load(
            r#"
local kept, rest = matcher:FilterIPs(ips)
local function all(list)
  local out = {}
  for _, ip in list() do out[#out + 1] = ip:String() end
  return out
end
local kept = all(kept)
assert(#kept == 2 and kept[1] == "192.0.2.1" and kept[2] == "198.51.100.2", table.concat(kept, ","))
local rest = all(rest)
assert(#rest == 2 and rest[1] == "198.51.100.3" and rest[2] == "2001:db8::1", table.concat(rest, ","))
"#,
        )
        .exec()
        .expect("filters and orders groups");
    }

    #[test]
    fn ip_user_rejects_byte_index_zero() {
        let lua = Lua::new();
        let ip = lua
            .create_userdata(IpUser("192.0.2.9".parse().expect("address")))
            .expect("userdata");
        lua.globals().set("ip", ip).expect("ip global");
        lua.load(r"assert(ip[0] == nil); assert(ip[1] == 192)")
            .exec()
            .expect("zero is not a byte index");
    }

    #[test]
    fn an_empty_ip_matcher_rule_list_is_refused() {
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        let error = lua
            .load(r#"require("xray.geodata").BuildIPMatcher()"#)
            .exec()
            .expect_err("refused");
        assert!(error.to_string().contains("at least one rule"), "{error}");
    }

    #[test]
    fn a_binary_routing_script_is_refused() {
        let dir = dir();
        std::fs::write(dir.join("route.lua"), b"\x1bLua\x51\x00").expect("write");
        let error = ScriptRouter::parse_in(&dir.join("route.lua").display().to_string(), vec![dir])
            .expect_err("binary script is refused");
        assert!(error.contains("attempt to load a binary chunk"), "{error}");
    }

    #[test]
    fn a_rebuilt_script_keeps_the_source_it_saved() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return 'direct' end",
        )
        .expect("write");
        let router = ScriptRouter::parse_in(
            &dir.join("route.lua").display().to_string(),
            vec![dir.clone()],
        )
        .expect("parses");
        std::fs::remove_file(dir.join("route.lua")).expect("remove");
        let rebuilt = router.rebuilt().expect("rebuilds");
        assert_eq!(
            rebuilt.route(&flow(), &callbacks(), false).expect("routes"),
            Some("direct".to_owned())
        );
    }

    #[test]
    fn an_empty_domain_matcher_rule_list_is_refused() {
        let lua = Lua::new();
        install(
            &lua,
            &Arc::new(CallHooks::default()),
            &Arc::new(Vec::new()),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("installs");
        let error = lua
            .load(r#"require("xray.geodata").BuildDomainMatcher()"#)
            .exec()
            .expect_err("refused");
        assert!(error.to_string().contains("at least one rule"), "{error}");
    }

    #[test]
    fn a_script_path_must_end_in_lua_after_symlinks() {
        let dir = dir();
        std::fs::write(
            dir.join("route.dat"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let error = ScriptRouter::parse_in(
            &dir.join("route.dat").display().to_string(),
            vec![dir.clone()],
        )
        .expect_err("refused");
        assert!(error.contains(".lua"), "{error}");
        #[cfg(unix)]
        {
            std::fs::write(
                dir.join("route.lua"),
                "function HandleRoute() return nil end",
            )
            .expect("write");
            std::os::unix::fs::symlink(dir.join("route.lua"), dir.join("alias.dat"))
                .expect("symlink");
            ScriptRouter::parse_in(&dir.join("alias.dat").display().to_string(), vec![dir])
                .expect("a symlink to .lua parses");
        }
    }
}
