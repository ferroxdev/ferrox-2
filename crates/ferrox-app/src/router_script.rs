//! The routing script: xray's Lua hook that answers a flow before the rule table does.
//!
//! The script reads the same context a rule does and returns an outbound tag; the modules it can
//! `require` are rebuilt here from this tree's matchers, not linked from a Lua runtime.

use std::cell::Cell;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

static ASSETS: RwLock<()> = RwLock::new(());
static DNS_ASSETS: RwLock<()> = RwLock::new(());

thread_local! {
    static REFRESHING: Cell<bool> = const { Cell::new(false) };
    static INITIALIZING: Cell<Option<usize>> = const { Cell::new(None) };
    static DNS_HOLDING: Cell<bool> = const { Cell::new(false) };
}

thread_local! {
    static HOLDING_ASSETS: Cell<bool> = const { Cell::new(false) };
}

/// One asset read guard; a nested read on the same thread borrows the outer guard instead of asking a writer-preferring lock twice.
pub(crate) struct AssetRead {
    guard: Option<std::sync::RwLockReadGuard<'static, ()>>,
}

impl Drop for AssetRead {
    fn drop(&mut self) {
        if self.guard.is_some() {
            HOLDING_ASSETS.with(|flag| flag.set(false));
        }
    }
}

pub(crate) fn read_assets() -> AssetRead {
    if REFRESHING.with(Cell::get) || HOLDING_ASSETS.with(Cell::get) {
        return AssetRead { guard: None };
    }
    let guard = Some(
        ASSETS
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    HOLDING_ASSETS.with(|flag| flag.set(true));
    AssetRead { guard }
}

/// Whether an ancestor on this thread already holds the DNS job's asset guard.
pub(crate) fn dns_held() -> bool {
    DNS_HOLDING.with(Cell::get)
}

pub(crate) fn with_dns_held<T>(run: impl FnOnce() -> T) -> T {
    let previous = DNS_HOLDING.with(|flag| flag.replace(true));
    let _restore = DnsHeld(previous);
    run()
}

struct DnsHeld(bool);

impl Drop for DnsHeld {
    fn drop(&mut self) {
        DNS_HOLDING.with(|flag| flag.set(self.0));
    }
}

/// Whether this thread is running the top-level chunk of this router, where a DNS query must not re-enter that same script; a query routed through another live router still sees its committed policy.
pub(crate) fn initializing_script(router: usize) -> bool {
    INITIALIZING.with(Cell::get) == Some(router)
}

pub(crate) fn with_script_initializing<T>(router: usize, run: impl FnOnce() -> T) -> T {
    let previous = INITIALIZING.with(|flag| flag.replace(Some(router)));
    let _restore = InitializingScript(previous);
    run()
}

struct InitializingScript(Option<usize>);

impl Drop for InitializingScript {
    fn drop(&mut self) {
        INITIALIZING.with(|flag| flag.set(self.0));
    }
}

/// A DNS job's own read guard: a swap waits for it even after the dial that started the lookup returns.
pub(crate) fn dns_read_assets() -> std::sync::RwLockReadGuard<'static, ()> {
    DNS_ASSETS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn with_assets_held<T>(held: bool, run: impl FnOnce() -> T) -> T {
    if !held {
        return run();
    }
    let previous = HOLDING_ASSETS.with(|flag| flag.replace(true));
    let _restore = HeldAssets(previous);
    run()
}

struct HeldAssets(bool);

impl Drop for HeldAssets {
    fn drop(&mut self) {
        HOLDING_ASSETS.with(|flag| flag.set(self.0));
    }
}

struct ResetRefresh;

impl Drop for ResetRefresh {
    fn drop(&mut self) {
        REFRESHING.with(|flag| flag.set(false));
    }
}

/// Hold live Lua asset reads out of a swap, including the rebuild that validates it and the
/// rollback that follows a failure. The refresh's own rebuild bypasses the read side.
pub(crate) fn refresh_assets<T>(refresh: impl FnOnce() -> T) -> T {
    let _write = ASSETS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _dns = DNS_ASSETS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    REFRESHING.with(|flag| flag.set(true));
    let _reset = ResetRefresh;
    refresh()
}

/// What a script may call back into while it runs: the resolver a `xray.dns.Query` uses, and the
/// balancer table a `xray.router.PickOutbound` reads. Both are built once, so a call clones handles.
pub(crate) type Resolver =
    dyn Fn(&str, u16, bool, bool, bool) -> (Vec<IpAddr>, u32, Option<String>) + Send + Sync;
pub(crate) type Picker = dyn Fn(&str) -> Result<String, String> + Send + Sync;

#[derive(Clone)]
pub(crate) struct ScriptCallbacks {
    pub(crate) resolve: Arc<Resolver>,
    pub(crate) pick: Arc<Picker>,
}

impl std::fmt::Debug for ScriptCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptCallbacks")
    }
}

pub(crate) fn resolve(path: &str, dirs: &[PathBuf]) -> Result<PathBuf, String> {
    let named = PathBuf::from(path);
    let mut candidates = Vec::new();
    if named.is_absolute() {
        candidates.push(named);
    } else {
        for name in [
            "xray.location.confdir",
            "XRAY_LOCATION_CONFDIR",
            "xray.location.config",
            "XRAY_LOCATION_CONFIG",
        ] {
            if let Some(dir) = std::env::var_os(name) {
                candidates.push(PathBuf::from(dir).join(path));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join(path));
        }
        if let Some(parent) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(PathBuf::from))
        {
            candidates.push(parent.join(path));
        }
        for dir in dirs {
            candidates.push(dir.join(path));
        }
    }
    for candidate in &candidates {
        let candidate = std::path::absolute(candidate)
            .map_err(|error| format!("routing script `{path}`: {error}"))?;
        let metadata = match std::fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("routing script `{path}`: {error}")),
        };
        if !metadata.is_file() {
            return Err(format!(
                "routing script `{path}` is not a regular file: {}",
                candidate.display()
            ));
        }
        let resolved = std::fs::canonicalize(&candidate)
            .map_err(|error| format!("routing script `{path}`: {error}"))?;
        if resolved.extension() != Some(std::ffi::OsStr::new("lua")) {
            return Err(format!(
                "routing script `{path}` must have a .lua extension: {}",
                resolved.display()
            ));
        }
        return Ok(resolved);
    }
    Err(format!(
        "routing script `{path}` was not found in {} locations",
        candidates.len()
    ))
}

#[cfg(not(target_os = "ios"))]
mod lua;
#[cfg(not(target_os = "ios"))]
pub(crate) use lua::ScriptRouter;

/// iOS has no `os.execute` and marks `system` unavailable, so the vendored Lua 5.1 runtime does not build there; a config that names a script is refused rather than forwarding what the script would block.
#[cfg(target_os = "ios")]
pub(crate) struct ScriptRouter;

#[cfg(target_os = "ios")]
impl std::fmt::Debug for ScriptRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptRouter")
    }
}

#[cfg(target_os = "ios")]
impl ScriptRouter {
    pub(crate) fn parse_in(path: &str, dirs: Vec<PathBuf>) -> Result<Self, String> {
        let resolved = resolve(path, &dirs)?;
        Self::parse_resolved(&resolved)
    }

    pub(crate) fn parse_resolved(name: &std::path::Path) -> Result<Self, String> {
        Err(format!(
            "routing script `{}`: this platform has no Lua runtime, so the script cannot be enforced",
            name.display()
        ))
    }

    pub(crate) fn rebuilt(&self) -> Result<Self, String> {
        Ok(Self)
    }

    pub(crate) fn route_locked(
        &self,
        _flow: &crate::router::Flow,
        _callbacks: &ScriptCallbacks,
        _skip_dns: bool,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}
