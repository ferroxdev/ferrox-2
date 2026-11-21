//! The routing script: xray's Lua hook that answers a flow before the rule table does.
//!
//! The script reads the same context a rule does and returns an outbound tag; the modules it can
//! `require` are rebuilt here from this tree's matchers, not linked from a Lua runtime.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// What a script may call back into while it runs: the resolver a `xray.dns.Query` uses, and the
/// balancer table a `xray.router.PickOutbound` reads. Both are built once, so a call clones handles.
pub(crate) type Resolver = dyn Fn(&str, u16, bool, bool, bool) -> (Vec<IpAddr>, u32) + Send + Sync;
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

/// iOS has no `os.execute` and marks `system` unavailable, so the vendored Lua 5.1 runtime does not build there; a config that names a script is named in one line and left unregistered, so the rule table and the default outbound decide instead of the stub.
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
        Self::parse_resolved(resolved, dirs)
    }

    pub(crate) fn parse_resolved(name: PathBuf, _dirs: Vec<PathBuf>) -> Result<Self, String> {
        eprintln!(
            "routing script `{}`: this platform has no Lua runtime, so the script is not run",
            name.display()
        );
        Ok(Self)
    }

    pub(crate) fn route(
        &self,
        _flow: &crate::router::Flow,
        _callbacks: &ScriptCallbacks,
        _skip_dns: bool,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}
