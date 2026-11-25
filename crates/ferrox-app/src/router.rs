//! Routing rules and the geosite/geoip assets they name.
//!
//! A rule is a set of selectors that must all hold and one outbound tag the first match decides. The
//! asset containers are xray's protobuf `GeoSiteList` and `GeoIPList`, read here rather than linked,
//! so a config that names a code this host cannot find fails at start with the file and code named.

use crate::json::Json;
use crate::router_script::ScriptRouter;
use crate::xray_pb::Reader;
use std::borrow::Cow;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Seek as _, Write as _};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) enum CacheBody {
    Bytes(Vec<u8>),
    Staged(RemoteBody),
}

impl CacheBody {
    fn read(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.clone()),
            Self::Staged(body) => body.read(),
        }
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Staged(body) => body.read(),
        }
    }
}

impl From<Vec<u8>> for CacheBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

pub(crate) struct CacheWrite {
    pub(crate) id: u64,
    pub(crate) target: PathBuf,
    pub(crate) body: CacheBody,
}

pub(crate) type CacheWrites = Vec<CacheWrite>;
pub(crate) type CacheInputs = HashSet<u64>;

static NEXT_CACHE_WRITE: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static CANDIDATE_ASSETS: RefCell<Option<HashMap<PathBuf, PathBuf>>> =
        const { RefCell::new(None) };
    static CANDIDATE_CACHE_WRITES: RefCell<Option<CacheWrites>> = const { RefCell::new(None) };
    static CANDIDATE_CACHE_INPUTS: RefCell<Option<CacheInputs>> = const { RefCell::new(None) };
}

/// Point asset reads on this thread at staged files, so a refresh validates the candidate without
/// swapping the live files, and hold remote cache writes until the caller commits the swap.
pub(crate) fn with_candidate_assets<T>(
    files: HashMap<PathBuf, PathBuf>,
    build: impl FnOnce() -> T,
) -> (T, CacheWrites, CacheInputs) {
    CANDIDATE_ASSETS.with(|slot| *slot.borrow_mut() = Some(files));
    CANDIDATE_CACHE_WRITES.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    CANDIDATE_CACHE_INPUTS.with(|slot| *slot.borrow_mut() = Some(CacheInputs::new()));
    let _reset = CandidateReset;
    let output = build();
    let writes = CANDIDATE_CACHE_WRITES
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    let inputs = CANDIDATE_CACHE_INPUTS
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    (output, writes, inputs)
}

struct CandidateReset;

impl Drop for CandidateReset {
    fn drop(&mut self) {
        CANDIDATE_ASSETS.with(|slot| *slot.borrow_mut() = None);
        CANDIDATE_CACHE_WRITES.with(|slot| *slot.borrow_mut() = None);
        CANDIDATE_CACHE_INPUTS.with(|slot| *slot.borrow_mut() = None);
    }
}

struct CandidateRestore {
    assets: Option<HashMap<PathBuf, PathBuf>>,
    writes: Option<CacheWrites>,
    inputs: Option<CacheInputs>,
}

impl Drop for CandidateRestore {
    fn drop(&mut self) {
        if let Some(assets) = self.assets.take() {
            CANDIDATE_ASSETS.with(|slot| *slot.borrow_mut() = Some(assets));
        }
        if let Some(writes) = self.writes.take() {
            CANDIDATE_CACHE_WRITES.with(|slot| *slot.borrow_mut() = Some(writes));
        }
        if let Some(inputs) = self.inputs.take() {
            CANDIDATE_CACHE_INPUTS.with(|slot| *slot.borrow_mut() = Some(inputs));
        }
    }
}

/// Run a live-routing call with any candidate overlay removed, so a nested query reads committed assets rather than bytes a refresh has not published.
pub(crate) fn with_committed_assets<T>(build: impl FnOnce() -> T) -> T {
    let _restore = CandidateRestore {
        assets: CANDIDATE_ASSETS.with(|slot| slot.borrow_mut().take()),
        writes: CANDIDATE_CACHE_WRITES.with(|slot| slot.borrow_mut().take()),
        inputs: CANDIDATE_CACHE_INPUTS.with(|slot| slot.borrow_mut().take()),
    };
    build()
}

fn candidate_asset(path: &Path) -> Option<PathBuf> {
    candidate_asset_entry(path).or_else(|| candidate_asset_referent(path))
}

fn candidate_asset_entry(path: &Path) -> Option<PathBuf> {
    CANDIDATE_ASSETS.with(|slot| {
        let slot = slot.borrow();
        let files = slot.as_ref()?;
        files
            .get(path)
            .or_else(|| entry_key(path).and_then(|key| files.get(&key)))
            .cloned()
    })
}

fn candidate_asset_referent(path: &Path) -> Option<PathBuf> {
    CANDIDATE_ASSETS.with(|slot| {
        let slot = slot.borrow();
        let files = slot.as_ref()?;
        let mut current = path.to_path_buf();
        let staged = |path: &Path| {
            files
                .get(path)
                .or_else(|| entry_key(path).and_then(|key| files.get(&key)))
                .cloned()
        };
        for _ in 0..32 {
            if let Some(staged) = staged(&current) {
                return Some(staged);
            }
            let Ok(meta) = std::fs::symlink_metadata(&current) else {
                break;
            };
            if !meta.file_type().is_symlink() {
                break;
            }
            let Ok(target) = std::fs::read_link(&current) else {
                break;
            };
            current = if target.is_absolute() {
                target
            } else {
                current
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(target)
            };
        }
        staged(&current)
    })
}

/// The entry a swap replaces: the real path with a final-component symlink resolved, so an alias spelling and the refreshed spelling name the same staged file; an entry not yet on disk keeps its real parent.
pub(crate) fn asset_key(path: &Path) -> Option<PathBuf> {
    if let Ok(real) = std::fs::canonicalize(path) {
        return Some(real);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = std::fs::canonicalize(parent.unwrap_or_else(|| Path::new("."))).ok()?;
    Some(parent.join(path.file_name()?))
}

/// The directory entry a path names, with the parent canonicalized but the final name kept: a directory symlink is the same entry, a final-component symlink is not.
pub(crate) fn entry_key(path: &Path) -> Option<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = std::fs::canonicalize(parent.unwrap_or_else(|| Path::new("."))).ok()?;
    let name = path.file_name()?;
    // NTFS and default APFS directories compare names without case unless the volume opted into case sensitivity.
    let fold = if cfg!(windows) {
        !windows_case_sensitive(&parent)
    } else if cfg!(target_os = "macos") {
        macos_case_insensitive(&parent)
    } else {
        false
    };
    let name = if fold {
        std::ffi::OsString::from(name.to_string_lossy().to_lowercase())
    } else {
        name.to_os_string()
    };
    Some(parent.join(name))
}

#[cfg(target_os = "macos")]
fn macos_case_insensitive(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(dir) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `dir` is a live NUL-terminated path and `pathconf` only reads it.
    unsafe { libc::pathconf(dir.as_ptr(), libc::_PC_CASE_SENSITIVE) == 0 }
}

#[cfg(not(target_os = "macos"))]
fn macos_case_insensitive(_dir: &Path) -> bool {
    false
}

/// Whether the directory opts into per-directory case sensitivity; a failed query keeps NTFS's default.
#[cfg(windows)]
fn windows_case_sensitive(dir: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_CASE_SENSITIVE_INFO: i32 = 23;
    const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 1;
    #[repr(C)]
    struct CaseSensitive {
        flags: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut core::ffi::c_void,
            class: i32,
            info: *mut core::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
    else {
        return false;
    };
    let mut info = CaseSensitive { flags: 0 };
    // SAFETY: the handle is live, `info` is writable and its size is the class's structure.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_CASE_SENSITIVE_INFO,
            (&raw mut info).cast(),
            std::mem::size_of::<CaseSensitive>() as u32,
        )
    };
    ok != 0 && info.flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0
}

#[cfg(not(windows))]
fn windows_case_sensitive(_dir: &Path) -> bool {
    false
}

/// Resolve a rule-set path in normal search order, taking a queued write for the same directory entry before a live file so the candidate sees what publication will install.
fn resolve_asset_with_queued(path: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates = Vec::with_capacity(dirs.len() + 1);
    candidates.push(PathBuf::from(path));
    candidates.extend(dirs.iter().map(|dir| dir.join(path)));
    candidates.into_iter().find_map(|candidate| {
        // The entry the path names wins over its symlink referent: publication installs its write before the referent's.
        if candidate_cache_present(&candidate) {
            return Some(candidate);
        }
        if let Some(staged) = candidate_asset_entry(&candidate) {
            return Some(staged);
        }
        let symlink =
            std::fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if symlink {
            if candidate_cache_present_referent(&candidate) {
                return Some(candidate);
            }
            if let Some(staged) = candidate_asset_referent(&candidate) {
                return Some(staged);
            }
        }
        candidate.is_file().then_some(candidate)
    })
}

/// The directory entry a rule-set path resolves to, independent of the staged file its candidate read uses.
fn resolve_entry_with_queued(path: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if path.contains("://") {
        return None;
    }
    let mut candidates = Vec::with_capacity(dirs.len() + 1);
    candidates.push(PathBuf::from(path));
    candidates.extend(dirs.iter().map(|dir| dir.join(path)));
    candidates.into_iter().find(|candidate| {
        if candidate_cache_present(candidate) || candidate_asset_entry(candidate).is_some() {
            return true;
        }
        let symlink =
            std::fs::symlink_metadata(candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if symlink && candidate_cache_present_referent(candidate) {
            return true;
        }
        if symlink && candidate_asset_referent(candidate).is_some() {
            return true;
        }
        candidate.is_file()
    })
}

/// Bytes an earlier rule set in this candidate already queued for `path`, so a later local set reads the response the refresh validated instead of the file it is about to replace.
fn entry_matches(path: &Path, queued: &Path) -> bool {
    if queued == path {
        return true;
    }
    let entry = entry_key(path);
    entry.is_some() && entry_key(queued) == entry
}

fn referent_matches(path: &Path, queued: &Path) -> bool {
    // A write through the entry a read's symlink chain points at still reaches that read; a write through the symlink does not reach the target's own readers.
    if std::fs::symlink_metadata(queued).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return false;
    }
    let mut current = path.to_path_buf();
    for _ in 0..32 {
        if entry_matches(&current, queued) {
            return true;
        }
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if !meta.file_type().is_symlink() {
            return false;
        }
        let Ok(target) = std::fs::read_link(&current) else {
            return false;
        };
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
    }
    false
}

/// Walk a final-component symlink chain by its link text, so a referent a queued write has not created yet still resolves.
fn resolve_link_target(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    for _ in 0..32 {
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return Some(current);
        };
        if !meta.file_type().is_symlink() {
            return Some(current);
        }
        let target = std::fs::read_link(&current).ok()?;
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
    }
    None
}

fn candidate_cache_bytes(path: &Path) -> Option<Result<Vec<u8>, String>> {
    candidate_cache_bytes_tracked(path, true)
}

fn candidate_cache_bytes_tracked(path: &Path, record: bool) -> Option<Result<Vec<u8>, String>> {
    candidate_cache_bytes_where(path, entry_matches, record)
        .or_else(|| candidate_cache_bytes_where(path, referent_matches, record))
}

fn candidate_cache_bytes_where(
    path: &Path,
    matches: fn(&Path, &Path) -> bool,
    record: bool,
) -> Option<Result<Vec<u8>, String>> {
    CANDIDATE_CACHE_WRITES.with(|slot| {
        let slot = slot.borrow();
        let writes = slot.as_ref()?;
        writes
            .iter()
            .rev()
            .find(|(queued, _)| matches(path, queued))
            .map(|(queued, body)| {
                let loaded = body.read();
                if record && loaded.is_ok() {
                    CANDIDATE_CACHE_INPUTS.with(|slot| {
                        if let Some(inputs) = slot.borrow_mut().as_mut() {
                            inputs.insert(queued.id);
                        }
                    });
                }
                loaded
            })
    })
}

fn candidate_cache_present(path: &Path) -> bool {
    candidate_cache_present_where(path, entry_matches)
}

fn candidate_cache_present_referent(path: &Path) -> bool {
    candidate_cache_present_where(path, referent_matches)
}

fn candidate_cache_present_where(path: &Path, matches: fn(&Path, &Path) -> bool) -> bool {
    CANDIDATE_CACHE_WRITES.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|writes| writes.iter().any(|(queued, _)| matches(path, queued)))
    })
}

fn publish_cache(target: PathBuf, body: CacheBody) -> Result<(), String> {
    let mut queued = Some(CacheWrite {
        id: NEXT_CACHE_WRITE.fetch_add(1, Ordering::Relaxed),
        target,
        body,
    });
    CANDIDATE_CACHE_WRITES.with(|slot| {
        if let Some(writes) = slot.borrow_mut().as_mut() {
            if let Some(item) = queued.take() {
                writes.push(item);
            }
        }
    });
    match queued {
        Some(write) => crate::geodata::write_atomic(&write.target, &write.body.into_bytes()?),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Network {
    Tcp,
    Udp,
    /// A network no selector this tree accepts names — xray's `unknown` (0) or `unix` (4) — with
    /// the value it arrived as, so a tested context reaches a script unchanged.
    Other(u8),
}

impl Network {
    /// xray's `conf.Network.Build`: `tcp`, `udp`, `unix`, and every other spelling as `unknown` (0).
    fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "unix" => Self::Other(4),
            _ => Self::Other(0),
        }
    }
}

/// One connection as the rules see it: absent fields match no rule, which is what keeps a selector
/// from turning into an unconditional match on a front that cannot answer it. An address and its
/// port are apart because a tested context may name the port alone; `0` is unnamed, as `net.Port(0)` is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Flow<'a> {
    pub(crate) network: Network,
    pub(crate) domain: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) port: Option<u16>,
    pub(crate) source: Option<IpAddr>,
    pub(crate) source_port: u16,
    pub(crate) local: Option<IpAddr>,
    pub(crate) local_port: u16,
    /// The route id a VLESS client sent, which a `vlessRoute` rule names; 0 off such an inbound.
    pub(crate) vless_route: u16,
    pub(crate) inbound_tag: Option<&'a str>,
    pub(crate) protocol: Option<&'a str>,
    /// The authenticated inbound account's email, which is what a `user` rule names.
    pub(crate) user: Option<&'a str>,
    /// The HTTP attributes a front or the sniffer read off the request head, which an `attrs` rule names.
    pub(crate) attrs: Option<&'a Attributes<'a>>,
    /// The process that owns the client socket, which a `process` rule names.
    pub(crate) process: Option<&'a crate::process::Owner>,
}

/// A context `RoutingService.TestRoute` hands to the table: xray's routing context names a list per
/// address role rather than one address, so every combination is a flow that could match.
pub(crate) struct Probe<'a> {
    pub(crate) network: Network,
    pub(crate) domain: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) inbound_tag: Option<&'a str>,
    pub(crate) protocol: Option<&'a str>,
    pub(crate) user: Option<&'a str>,
    pub(crate) attrs: Option<&'a Attributes<'a>>,
    pub(crate) targets: Vec<Option<IpAddr>>,
    pub(crate) sources: Vec<Option<IpAddr>>,
    pub(crate) source_port: u16,
    pub(crate) locals: Vec<Option<IpAddr>>,
    pub(crate) local_port: u16,
    pub(crate) vless_route: u16,
}

impl Probe<'_> {
    /// One combination of the named addresses, as a live flow would carry it.
    pub(crate) fn flow(
        &self,
        ip: Option<IpAddr>,
        source: Option<IpAddr>,
        local: Option<IpAddr>,
    ) -> Flow<'_> {
        Flow {
            network: self.network,
            domain: self.domain,
            ip,
            port: self.port,
            source,
            source_port: self.source_port,
            local,
            local_port: self.local_port,
            vless_route: self.vless_route,
            inbound_tag: self.inbound_tag,
            protocol: self.protocol,
            user: self.user,
            attrs: self.attrs,
            process: None,
        }
    }
}

/// The attributes of one HTTP request head — `:method`, `:path`, then every header — as the front or
/// the sniffer read them. A rule's keys were lowercased at startup and a name is compared without
/// regard to case, so neither side copies a name per match.
#[derive(Debug)]
pub(crate) struct Attributes<'a> {
    entries: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> Attributes<'a> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, name: &'a str, value: Cow<'a, str>) {
        self.entries.push((Cow::Borrowed(name), value));
    }

    /// The pairs a sniffer copied out of a peeked head, which outlives the buffer it read.
    pub(crate) fn from_pairs(pairs: &'a [(String, String)]) -> Self {
        Self {
            entries: pairs
                .iter()
                .map(|(name, value)| (Cow::Borrowed(name.as_str()), Cow::Borrowed(value.as_str())))
                .collect(),
        }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(sent, _)| sent.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_ref())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
    }
}

/// A rule's `attrs` map: each key lowercased and its value compiled as a regexp, which is what the
/// reference builds once at startup. An empty map is no selector, and a bad pattern refuses the config
/// because the reference's `MustCompile` stops the process.
#[derive(Debug)]
struct AttributeSelector {
    keys: Vec<(String, regex::Regex)>,
}

impl AttributeSelector {
    fn parse(value: &Json) -> Result<Option<Self>, String> {
        if matches!(value, Json::Null) {
            return Ok(None);
        }
        let pairs = object(value, "routing attrs")?;
        let mut keys = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            let pattern = value
                .as_str()
                .ok_or_else(|| format!("routing attrs `{key}` is not a string"))?;
            let compiled = regex::Regex::new(pattern)
                .map_err(|error| format!("routing attrs `{key}` is not a regexp: {error}"))?;
            keys.push((key.to_ascii_lowercase(), compiled));
        }
        Ok((!keys.is_empty()).then_some(Self { keys }))
    }

    fn matches(&self, attrs: Option<&Attributes<'_>>) -> bool {
        let Some(attrs) = attrs else {
            return false;
        };
        self.keys
            .iter()
            .all(|(key, pattern)| attrs.get(key).is_some_and(|value| pattern.is_match(value)))
    }
}

/// A rule's `user` list, split once at startup into exact names and compiled `regexp:` patterns;
/// an entry that is empty or does not compile is ignored, as the reference's matcher ignores it.
#[derive(Debug)]
struct UserSelector {
    literal: Vec<String>,
    patterns: Vec<regex::Regex>,
}

impl UserSelector {
    fn parse(names: &[String]) -> Self {
        let mut literal = Vec::new();
        let mut patterns = Vec::new();
        for name in names {
            if name.is_empty() {
                continue;
            }
            match name.strip_prefix("regexp:").filter(|_| name.len() > 7) {
                Some(pattern) => {
                    if let Ok(pattern) = regex::Regex::new(pattern) {
                        patterns.push(pattern);
                    }
                }
                None => literal.push(name.clone()),
            }
        }
        Self { literal, patterns }
    }

    fn matches(&self, user: Option<&str>) -> bool {
        let Some(user) = user.filter(|user| !user.is_empty()) else {
            return false;
        };
        self.literal.iter().any(|literal| literal == user)
            || self.patterns.iter().any(|pattern| pattern.is_match(user))
    }

    fn is_empty(&self) -> bool {
        self.literal.is_empty() && self.patterns.is_empty()
    }
}

/// A rule's `process` list, split once at startup the way the reference's matcher splits it: `self/`
/// names this process, `xray/` this executable, a trailing `/` a folder prefix, an interior `/` an
/// absolute path, and anything else a basename with `.exe` trimmed. The reference drops an `xray/`
/// whose executable path cannot be read, and so does this split.
#[derive(Debug)]
struct ProcessSelector {
    names: Vec<String>,
    abs_paths: Vec<String>,
    folders: Vec<String>,
    this_process: bool,
}

impl ProcessSelector {
    fn parse(list: &[String]) -> Self {
        let mut literal = Vec::new();
        let mut folders = Vec::new();
        let mut abs_paths = Vec::new();
        let mut this_process = false;
        for name in list {
            if name == "self/" {
                this_process = true;
                continue;
            }
            let path = name.replace('\\', "/");
            let path = if path == "xray/" {
                let Ok(executable) = std::env::current_exe() else {
                    continue;
                };
                let Some(executable) = executable.to_str() else {
                    continue;
                };
                executable.to_owned()
            } else {
                path
            };
            if path.ends_with('/') {
                folders.push(path);
                continue;
            }
            if path.contains('/') {
                abs_paths.push(path);
                continue;
            }
            literal.push(path.strip_suffix(".exe").unwrap_or(&path).to_owned());
        }
        Self {
            names: literal,
            abs_paths,
            folders,
            this_process,
        }
    }

    fn matches(&self, owner: Option<&crate::process::Owner>) -> bool {
        let Some(owner) = owner else {
            return false;
        };
        if self.this_process && owner.pid == std::process::id() {
            return true;
        }
        self.names.iter().any(|name| name == &owner.name)
            || self.abs_paths.iter().any(|path| path == &owner.path)
            || self
                .folders
                .iter()
                .any(|folder| owner.path.starts_with(folder))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainStrategy {
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

/// What a matching rule names: an outbound, or a balancer that picks one per flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTarget<'a> {
    Outbound(&'a str),
    Balancer(&'a str),
}

/// One rule's verdict for a flow: where it sends the flow and the callback it names.
pub(crate) struct RuleHit<'a> {
    pub(crate) target: RouteTarget<'a>,
    pub(crate) webhook: Option<&'a Arc<crate::webhook::Webhook>>,
}

#[cfg(test)]
impl<'a> RuleHit<'a> {
    pub(crate) fn tag(&self) -> &'a str {
        match self.target {
            RouteTarget::Outbound(tag) | RouteTarget::Balancer(tag) => tag,
        }
    }
}

fn rule_hit(rule: &Rule) -> RuleHit<'_> {
    let target = if rule.balancer {
        RouteTarget::Balancer(&rule.target)
    } else {
        RouteTarget::Outbound(&rule.target)
    };
    RuleHit {
        target,
        webhook: rule.webhook.as_ref(),
    }
}

enum ScriptSource {
    Resolve,
    Reuse(Option<Arc<ScriptRouter>>),
}

/// One rule as `RoutingService.ListRule` lists it: the tag the rule names (empty when it names a
/// balancer, as the reference's one-of leaves `Tag` empty) and the rule's own tag.
#[derive(Debug, Clone)]
pub(crate) struct ListedRule {
    pub(crate) target: String,
    pub(crate) balancer: bool,
    pub(crate) tag: Option<String>,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Routing {
    strategy: DomainStrategy,
    rules: Vec<Rule>,
    balancers: Vec<Balancer>,
    rule_sets: Vec<Arc<RuleSet>>,
    asset_dirs: Vec<PathBuf>,
    script: Option<Arc<ScriptRouter>>,
    has_domains: bool,
    wants_attrs: bool,
    wants_process: bool,
    /// A `shouldAppend=false` write replaced the whole table, so a reload must keep that replacement
    /// instead of bringing the startup rules back.
    added_replaced: bool,
    /// Startup-rule tags `RemoveRule` deleted; a reparse must not bring them back.
    removed_tags: HashSet<String>,
}

/// One server inbound's fixed direct dial, checked against the rules that can reach it — at startup,
/// and against a candidate table before `AddRule` writes it.
pub(crate) struct ServerProof<'a> {
    pub inbound: Option<&'a str>,
    pub default_direct: bool,
    /// The target networks the inbound serves: a stream-only lane cannot reach a datagram rule.
    pub networks: &'a [Network],
    /// Whether a plain outbound tag needs no dial here: a freedom outbound or the default direct lane.
    pub direct: Box<dyn Fn(&str) -> bool + 'a>,
    /// Whether this inbound's direct handler enforces the policy that tag's lane selects.
    pub direct_policy: Box<dyn Fn(&str) -> bool + 'a>,
    /// Whether a rule selects a portal for the exact domain that portal carries.
    pub portal_rule: Box<dyn Fn(&Rule) -> bool + 'a>,
    /// Each balancer's resolved candidate tags, so every tag it can pick is checked too.
    pub candidates: &'a HashMap<String, Vec<String>>,
    pub fallbacks: &'a HashMap<String, String>,
}

/// One `balancers` entry: a tag a rule may name, the outbound-tag prefixes it draws from, and the
/// strategy that picks one per flow. Xray selects candidates with `strings.HasPrefix`, not a regex.
#[derive(Debug)]
pub(crate) struct Balancer {
    tag: String,
    selectors: Vec<String>,
    strategy: Strategy,
    fallback: Option<String>,
    index: AtomicUsize,
    seed: AtomicU64,
    weights: std::sync::Mutex<HashMap<String, f64>>,
    /// The tag `OverrideBalancerTarget` forced, which the strategy never sees until it is cleared.
    forced: std::sync::Mutex<Option<Arc<str>>>,
}

#[derive(Debug)]
enum Strategy {
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad(LeastLoad),
}

/// One `leastLoad` reading: xray's `StrategyLeastLoadConfig`, with its weight rules compiled once
/// at startup rather than once per flow.
#[derive(Debug)]
struct LeastLoad {
    costs: Vec<Weight>,
    baselines: Vec<i64>,
    expected: i32,
    max_rtt: i64,
    tolerance: f32,
}

#[derive(Debug)]
struct Weight {
    regexp: bool,
    find: String,
    value: f32,
    compiled: Option<regex::Regex>,
}

/// One outbound's health as the balancers read it, in the reference's units: `delay_ms` for the
/// legacy observatory and the nanosecond fields for a burst sample.
#[derive(Debug, Clone, Default)]
pub(crate) struct Observed {
    pub(crate) tag: String,
    pub(crate) alive: bool,
    pub(crate) delay_ms: i64,
    pub(crate) health: Option<HealthPing>,
    pub(crate) last_error: String,
    pub(crate) last_seen: i64,
    pub(crate) last_try: i64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HealthPing {
    pub(crate) all: i64,
    pub(crate) fail: i64,
    pub(crate) deviation: i64,
    pub(crate) average: i64,
}

impl Balancer {
    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn selects(&self, tag: &str) -> bool {
        self.selectors
            .iter()
            .any(|selector| tag.starts_with(selector))
    }

    pub(crate) fn fallback(&self) -> Option<&str> {
        self.fallback.as_deref()
    }

    /// The tag `RoutingService.OverrideBalancerTarget` forced, empty when the strategy decides.
    pub(crate) fn forced(&self) -> String {
        self.forced
            .lock()
            .ok()
            .and_then(|forced| forced.as_deref().map(str::to_owned))
            .unwrap_or_default()
    }

    /// Force every flow this balancer routes to `target`; an empty target hands the pick back.
    pub(crate) fn force(&self, target: &str) {
        if let Ok(mut forced) = self.forced.lock() {
            *forced = (!target.is_empty()).then(|| Arc::from(target));
        }
    }

    /// The tags `RoutingService.GetBalancerInfo` reports as the strategy's principle target: every
    /// candidate the strategy would draw from, which is what each of the reference's four names.
    pub(crate) fn principle<'a>(
        &self,
        candidates: &'a [String],
        observed: Option<&[Observed]>,
    ) -> Vec<&'a str> {
        match &self.strategy {
            Strategy::RoundRobin | Strategy::Random => {
                candidates.iter().map(String::as_str).collect()
            }
            Strategy::LeastPing => vec![least_ping(candidates, observed).unwrap_or("")],
            Strategy::LeastLoad(settings) => self.least_load_tags(candidates, observed, settings),
        }
    }

    /// The candidate for one flow. The two health strategies name nothing without a reading, so
    /// the caller falls back exactly as the reference does without an observatory. `random` and
    /// `roundRobin` drop a candidate the observatory reports dead only when a `fallbackTag` makes
    /// the reference inject the observatory into them.
    pub(crate) fn pick<'a>(
        &self,
        candidates: &'a [String],
        observed: Option<&[Observed]>,
    ) -> Option<Cow<'a, str>> {
        if let Ok(forced) = self.forced.lock() {
            if let Some(forced) = forced.as_deref() {
                return Some(Cow::Owned(forced.to_owned()));
            }
        }
        if candidates.is_empty() {
            return None;
        }
        match &self.strategy {
            Strategy::RoundRobin => {
                let alive = self.alive_candidates(candidates, observed);
                let count = alive.len();
                if count == 0 {
                    return None;
                }
                let at = self.index.fetch_add(1, Ordering::Relaxed) % count;
                Some(Cow::Borrowed(alive[at].as_str()))
            }
            Strategy::Random => {
                let alive = self.alive_candidates(candidates, observed);
                let count = alive.len();
                if count == 0 {
                    return None;
                }
                let at = self.random_index(count);
                Some(Cow::Borrowed(alive[at].as_str()))
            }
            Strategy::LeastPing => least_ping(candidates, observed).map(Cow::Borrowed),
            Strategy::LeastLoad(settings) => {
                let tags = self.least_load_tags(candidates, observed, settings);
                match tags.len() {
                    0 => None,
                    1 => Some(Cow::Borrowed(tags[0])),
                    count => Some(Cow::Borrowed(tags[self.random_index(count)])),
                }
            }
        }
    }

    fn alive_candidates<'a>(
        &self,
        candidates: &'a [String],
        observed: Option<&[Observed]>,
    ) -> Vec<&'a String> {
        let Some(observed) = observed.filter(|_| self.fallback.is_some()) else {
            return candidates.iter().collect();
        };
        candidates
            .iter()
            .filter(|candidate| {
                observed
                    .iter()
                    .find(|status| status.tag == candidate.as_str())
                    .is_none_or(|status| status.alive)
            })
            .collect()
    }

    fn random_index(&self, count: usize) -> usize {
        let mut state = self.seed.load(Ordering::Relaxed);
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.seed.store(state, Ordering::Relaxed);
        (state % count as u64) as usize
    }

    /// The tags the strategy draws from, best first: the qualified nodes the baselines and the
    /// expected count leave, borrowed from `candidates` so a caller can hand them out.
    #[allow(clippy::cast_precision_loss)]
    fn least_load_tags<'a>(
        &self,
        candidates: &'a [String],
        observed: Option<&[Observed]>,
        settings: &LeastLoad,
    ) -> Vec<&'a str> {
        let Some(observed) = observed else {
            return Vec::new();
        };
        let mut nodes: Vec<Node> = observed
            .iter()
            .filter(|status| settings.selects(status, candidates))
            .map(|status| {
                let mut node = Node {
                    tag: status.tag.as_str(),
                    all: 1,
                    fail: 1,
                    average: status.delay_ms.saturating_mul(1_000_000),
                    deviation: status.delay_ms.saturating_mul(1_000_000),
                    cost: 0,
                };
                if let Some(health) = status.health {
                    node.average = health.average;
                    node.deviation = health.deviation;
                    node.all = health.all;
                    node.fail = health.fail;
                }
                let weight = self.weight_for(node.tag, settings);
                node.cost = ((node.deviation as f64) * weight.sqrt()) as i64;
                node
            })
            .collect();
        if nodes.is_empty() {
            return Vec::new();
        }
        nodes.sort_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then(left.average.cmp(&right.average))
                .then(left.fail.cmp(&right.fail))
                .then(right.all.cmp(&left.all))
                .then(left.tag.cmp(right.tag))
        });
        let count = settings.selected(&nodes);
        nodes[..count]
            .iter()
            .filter_map(|node| {
                candidates
                    .iter()
                    .find(|candidate| candidate.as_str() == node.tag)
                    .map(String::as_str)
            })
            .collect()
    }

    fn weight_for(&self, tag: &str, settings: &LeastLoad) -> f64 {
        let Ok(mut cache) = self.weights.lock() else {
            return 1.0;
        };
        if let Some(weight) = cache.get(tag) {
            return *weight;
        }
        let weight = settings.weight(tag);
        cache.insert(tag.to_owned(), weight);
        weight
    }

    fn parse(value: &Json, at: usize) -> Result<Self, String> {
        let pairs = object(value, "routing balancer")?;
        let mut tag = None;
        let mut selectors = None;
        let mut strategy = Strategy::Random;
        let mut fallback = None;
        for (key, field) in pairs {
            match key.as_str() {
                "tag" => {
                    tag = Some(
                        field
                            .as_str()
                            .filter(|tag| !tag.is_empty())
                            .ok_or_else(|| "balancer tag is empty".to_owned())?
                            .to_owned(),
                    );
                }
                "selector" => selectors = string_list(field, "selector")?,
                "strategy" => strategy = parse_strategy(field)?,
                "fallbackTag" => {
                    fallback = field
                        .as_str()
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_owned);
                }
                other => return Err(format!("routing balancer field `{other}` is not carried")),
            }
        }
        let tag = tag.ok_or_else(|| "routing balancer has no tag".to_owned())?;
        let selectors = selectors.ok_or_else(|| format!("balancer `{tag}` has no selector"))?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64)
            .wrapping_add(at as u64)
            | 1;
        Ok(Self {
            tag,
            selectors,
            strategy,
            fallback,
            index: AtomicUsize::new(0),
            seed: AtomicU64::new(seed),
            weights: std::sync::Mutex::new(HashMap::new()),
            forced: std::sync::Mutex::new(None),
        })
    }
}

fn parse_strategy(value: &Json) -> Result<Strategy, String> {
    let (named, settings) = match value {
        Json::Null => return Ok(Strategy::Random),
        Json::Str(named) => (named.as_str(), None),
        Json::Obj(pairs) => {
            let mut named = "";
            let mut settings = None;
            for (key, field) in pairs {
                match key.as_str() {
                    "type" => {
                        named = field
                            .as_str()
                            .ok_or_else(|| "balancer strategy type is not a string".to_owned())?;
                    }
                    "settings" => {
                        if !matches!(field, Json::Null | Json::Obj(_)) {
                            return Err("balancer strategy settings is not an object".into());
                        }
                        settings = Some(field);
                    }
                    other => {
                        return Err(format!(
                            "routing balancer strategy field `{other}` is not carried"
                        ))
                    }
                }
            }
            (named, settings)
        }
        _ => return Err("routing balancer strategy is not a string or object".into()),
    };
    match named.to_ascii_lowercase().as_str() {
        "" | "random" => Ok(Strategy::Random),
        "roundrobin" => Ok(Strategy::RoundRobin),
        "leastping" => Ok(Strategy::LeastPing),
        "leastload" => Ok(Strategy::LeastLoad(LeastLoad::parse(settings)?)),
        _ => Err(format!(
            "routing balancer strategy `{named}` is not random, roundRobin, leastPing or leastLoad"
        )),
    }
}

impl LeastLoad {
    fn parse(value: Option<&Json>) -> Result<Self, String> {
        let empties = [];
        let pairs = match value {
            Some(Json::Obj(pairs)) => pairs.as_slice(),
            Some(Json::Null) | None => &empties,
            Some(_) => return Err("balancer strategy settings is not an object".into()),
        };
        let mut costs = Vec::new();
        let mut baselines = Vec::new();
        let mut expected = 0i32;
        let mut max_rtt = 0i64;
        let mut tolerance = 0.0f32;
        for (key, field) in pairs {
            match key.as_str() {
                "costs" => {
                    for cost in field.as_arr().unwrap_or(&[]) {
                        costs.push(Weight::parse(cost));
                    }
                }
                "baselines" => {
                    for baseline in field.as_arr().unwrap_or(&[]) {
                        if let Some(nanos) = crate::config::go_duration(baseline)? {
                            if nanos > 0 {
                                baselines.push(nanos);
                            }
                        }
                    }
                }
                "expected" => {
                    expected = field
                        .as_u32()
                        .and_then(|value| i32::try_from(value).ok())
                        .unwrap_or(0)
                        .max(0);
                }
                "maxRTT" => max_rtt = crate::config::go_duration(field)?.unwrap_or(0).max(0),
                "tolerance" => {
                    tolerance = match field {
                        Json::Num(value) => *value as f32,
                        _ => 0.0,
                    }
                    .clamp(0.0, 1.0);
                }
                _ => {}
            }
        }
        Ok(Self {
            costs,
            baselines,
            expected,
            max_rtt,
            tolerance,
        })
    }

    #[allow(clippy::cast_precision_loss)]
    fn selects(&self, status: &Observed, candidates: &[String]) -> bool {
        if !status.alive {
            return false;
        }
        if self.max_rtt != 0 && status.delay_ms >= self.max_rtt / 1_000_000 {
            return false;
        }
        if !candidates.iter().any(|candidate| candidate == &status.tag) {
            return false;
        }
        if let Some(health) = status.health {
            if health.all > 0
                && self.tolerance > 0.0
                && health.fail as f64 / health.all as f64 > f64::from(self.tolerance)
            {
                return false;
            }
        }
        true
    }

    fn weight(&self, tag: &str) -> f64 {
        for cost in &self.costs {
            let matched = cost.matched(tag);
            if matched.is_empty() {
                continue;
            }
            if cost.value > 0.0 {
                return f64::from(cost.value);
            }
            if let Some(number) = first_number(matched) {
                return number;
            }
            return 1.0;
        }
        1.0
    }

    fn selected(&self, nodes: &[Node]) -> usize {
        let expected = usize::try_from(self.expected.max(0)).unwrap_or(usize::MAX);
        let available = nodes.len();
        if expected > available {
            return available;
        }
        let expected = if expected == 0 { 1 } else { expected };
        if self.baselines.is_empty() {
            return expected;
        }
        let mut count = 0;
        for baseline in &self.baselines {
            while count < available && nodes[count].cost < *baseline {
                count += 1;
            }
            if count >= expected {
                break;
            }
        }
        if self.expected > 0 && count < expected {
            count = expected;
        }
        count.min(available)
    }
}

impl Weight {
    fn parse(value: &Json) -> Self {
        let mut regexp = false;
        let mut find = String::new();
        let mut amount = 0.0f32;
        if let Json::Obj(pairs) = value {
            for (key, field) in pairs {
                match key.as_str() {
                    "regexp" => regexp = field.as_bool().unwrap_or(false),
                    "match" => field.as_str().unwrap_or("").clone_into(&mut find),
                    "value" => {
                        amount = match field {
                            Json::Num(value) => *value as f32,
                            _ => 0.0,
                        }
                    }
                    _ => {}
                }
            }
        }
        let compiled = regexp.then(|| regex::Regex::new(&find).ok()).flatten();
        Self {
            regexp,
            find,
            value: amount,
            compiled,
        }
    }

    fn matched<'a>(&'a self, tag: &'a str) -> &'a str {
        if self.find.is_empty() {
            return "";
        }
        if self.regexp {
            if let Some(compiled) = &self.compiled {
                return compiled.find(tag).map_or("", |found| found.as_str());
            }
            return "";
        }
        if tag.contains(&self.find) {
            return &self.find;
        }
        ""
    }
}

#[derive(Debug)]
struct Node<'a> {
    tag: &'a str,
    all: i64,
    fail: i64,
    average: i64,
    deviation: i64,
    cost: i64,
}

fn least_ping<'a>(candidates: &'a [String], observed: Option<&[Observed]>) -> Option<&'a str> {
    let observed = observed?;
    let mut least = 99_999_999i64;
    let mut selected = "";
    for status in observed {
        if !status.alive || status.delay_ms >= least {
            continue;
        }
        if candidates.iter().any(|candidate| candidate == &status.tag) {
            selected = status.tag.as_str();
            least = status.delay_ms;
        }
    }
    if selected.is_empty() {
        return None;
    }
    candidates
        .iter()
        .find(|candidate| candidate.as_str() == selected)
        .map(String::as_str)
}

fn first_number(text: &str) -> Option<f64> {
    static FINDER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let finder = FINDER.get_or_init(|| regex::Regex::new(r"\d+(\.\d+)?").expect("number matcher"));
    finder.find(text)?.as_str().parse().ok()
}

/// The name a flow carries, in the form the tables store and the form a regex must see. Lowering
/// happens on the first table that needs it, once per decision, not once per rule.
#[derive(Debug, Clone, Copy)]
struct Names<'a> {
    raw: &'a str,
    needs_lower: bool,
    lower: &'a OnceCell<String>,
}

impl Names<'_> {
    fn lower(&self) -> &str {
        if !self.needs_lower {
            return self.raw;
        }
        self.lower.get_or_init(|| self.raw.to_ascii_lowercase())
    }
}

#[derive(Debug)]
pub(crate) struct Rule {
    target: String,
    balancer: bool,
    tag: Option<String>,
    inbound_tags: Option<Vec<String>>,
    networks: Option<Vec<Network>>,
    local_os: Option<Vec<String>>,
    ports: Option<PortSet>,
    source_ports: Option<PortSet>,
    local_ports: Option<PortSet>,
    domains: Option<DomainMatcher>,
    ips: Option<IpMatcher>,
    source_ips: Option<IpMatcher>,
    local_ips: Option<IpMatcher>,
    protocols: Option<Vec<String>>,
    users: Option<UserSelector>,
    vless_routes: Option<PortSet>,
    attrs: Option<AttributeSelector>,
    process: Option<ProcessSelector>,
    webhook: Option<Arc<crate::webhook::Webhook>>,
    sets: Option<Vec<Arc<RuleSet>>>,
    /// Set by `AddRule`; a geodata reload keeps these and replaces only the startup rules.
    added: bool,
    /// The management API's source JSON, kept so a reload can rebuild geodata and rule-set bindings.
    raw: Option<Json>,
}

impl Rule {
    /// The outbound or balancer tag this rule selects.
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// Whether every name this rule can match is exactly `domain`, so a portal's own domain handler
    /// is the only path it can take.
    pub(crate) fn only_matches_domain(&self, domain: &str) -> bool {
        !self.balancer
            && self.inbound_tags.is_none()
            && self.networks.is_none()
            && self.local_os.is_none()
            && self.ports.is_none()
            && self.source_ports.is_none()
            && self.local_ports.is_none()
            && self.ips.is_none()
            && self.source_ips.is_none()
            && self.local_ips.is_none()
            && self.protocols.is_none()
            && self.users.is_none()
            && self.vless_routes.is_none()
            && self.attrs.is_none()
            && self.process.is_none()
            && self.sets.is_none()
            && self
                .domains
                .as_ref()
                .is_some_and(|matcher| matcher.only_matches(domain))
    }
}

/// One `ruleSet`/`rule_set` entry. A flow matches when any of its headless rules does; each rule is
/// an AND of the selectors it names, and an `invert` flips that rule alone.
#[derive(Debug)]
struct RuleSet {
    tag: String,
    rules: Vec<SetRule>,
}

/// A headless rule, or a logical group of them. `Unknown` is the IP verdict before an address is
/// known: it decides whether `IPIfNonMatch` has to resolve for this rule at all.
#[derive(Debug)]
enum Verdict {
    Yes,
    No,
    Unknown,
}

#[derive(Debug)]
struct SetRule {
    invert: bool,
    logical: Option<SetLogical>,
    networks: Option<Vec<Network>>,
    domains: Option<DomainMatcher>,
    ports: Option<PortSet>,
    source_ports: Option<PortSet>,
    ips: Option<IpMatcher>,
    source_ips: Option<IpMatcher>,
    process: Option<SetProcess>,
}

/// A rule set's process selector: a basename, an exact path, or a pattern over the path.
#[derive(Debug)]
struct SetProcess {
    names: Vec<String>,
    paths: Vec<String>,
    patterns: Vec<regex::Regex>,
}

impl SetProcess {
    fn matches(&self, owner: Option<&crate::process::Owner>) -> bool {
        let Some(owner) = owner else {
            return false;
        };
        (self.names.is_empty() || self.names.iter().any(|name| name == &owner.name))
            && (self.paths.is_empty() || self.paths.iter().any(|path| path == &owner.path))
            && (self.patterns.is_empty()
                || self
                    .patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&owner.path)))
    }
}

#[derive(Debug)]
struct SetLogical {
    all: bool,
    rules: Vec<SetRule>,
}

impl Routing {
    /// The routing block as configured, or `None` when the config has none; every asset it names is
    /// opened here so a missing file or code stops the process before an inbound listens.
    pub(crate) fn parse(root: &Json) -> Result<Option<Self>, String> {
        Self::parse_in(root, asset_dirs())
    }

    /// A table with no rule, so a config that names no `routing` block still has a plan to carry
    /// the outbound fields a dial reads.
    pub(crate) fn empty() -> Self {
        Self {
            strategy: DomainStrategy::AsIs,
            rules: Vec::new(),
            balancers: Vec::new(),
            rule_sets: Vec::new(),
            asset_dirs: Vec::new(),
            script: None,
            has_domains: false,
            wants_attrs: false,
            wants_process: false,
            added_replaced: false,
            removed_tags: HashSet::new(),
        }
    }

    /// Fetch every remote rule set before a geodata refresh takes the live asset lock, so a slow
    /// server delays the refresh rather than a route that needs the old snapshot.
    pub(crate) fn prefetch_remote_sets(root: &Json) -> RemoteSetCache {
        let mut found = HashMap::new();
        let Some(block) = root.get("routing") else {
            return found;
        };
        let Ok(pairs) = object(block, "routing") else {
            return found;
        };
        let Some(raw_sets) = pairs.iter().rev().find_map(|(key, value)| {
            matches!(
                key.as_str(),
                "ruleSet" | "ruleSets" | "rule_set" | "rule_sets"
            )
            .then_some(value)
        }) else {
            return found;
        };
        let Some(items) = raw_sets.as_arr() else {
            return found;
        };
        for item in items {
            let Ok(pairs) = object(item, "routing rule set") else {
                continue;
            };
            let mut kind = None;
            let mut url = None;
            let mut path = None;
            let mut has_rules = false;
            for (key, value) in pairs {
                match key.as_str() {
                    "type" => kind = value.as_str().map(str::to_owned),
                    "url" => url = value.as_str().map(str::to_owned),
                    "path" => path = value.as_str().map(str::to_owned),
                    "rules" => has_rules = true,
                    _ => {}
                }
            }
            let kind = kind.unwrap_or_else(|| {
                if has_rules {
                    "inline".to_owned()
                } else if url.is_some() {
                    "remote".to_owned()
                } else {
                    "local".to_owned()
                }
            });
            if kind != "remote" {
                continue;
            }
            let Some(url) = url.or_else(|| path.filter(|path| path.contains("://"))) else {
                continue;
            };
            found.entry(url.clone()).or_insert_with(|| {
                let bytes = crate::geodata::fetch_remote(&url)?;
                match RemoteBody::stage(&bytes) {
                    Ok(body) => Ok(body),
                    Err(error) => {
                        // A valid response that cannot be staged is not a fetch failure: keep it in memory rather than serve the stale fallback.
                        eprintln!("routing rule set `{url}`: cannot stage the response: {error}; holding it in memory");
                        Ok(RemoteBody::memory(bytes))
                    }
                }
            });
        }
        found
    }

    pub(crate) fn parse_in(root: &Json, dirs: Vec<PathBuf>) -> Result<Option<Self>, String> {
        let (parsed, writes, _) = with_candidate_assets(HashMap::new(), || {
            Self::parse_with(root, dirs, ScriptSource::Resolve, None)
        });
        if parsed.is_ok() {
            for write in writes {
                let CacheWrite { target, body, .. } = write;
                match body.into_bytes() {
                    Ok(bytes) => {
                        if let Err(error) = crate::geodata::write_atomic(&target, &bytes) {
                            eprintln!("routing rule set cache: {error}");
                        }
                    }
                    Err(error) => eprintln!("routing rule set cache: {error}"),
                }
            }
        }
        parsed
    }

    /// A geodata refresh keeps the active script's saved source instead of reopening its file.
    pub(crate) fn parse_in_reusing_script(
        root: &Json,
        dirs: Vec<PathBuf>,
        script: Option<Arc<ScriptRouter>>,
        remote: &RemoteSetCache,
    ) -> Result<Option<Self>, String> {
        Self::parse_with(root, dirs, ScriptSource::Reuse(script), Some(remote))
    }

    /// Whether a rule set is fetched from a URL, either named or inferred as `RuleSet::parse` does.
    fn rule_set_is_remote(value: &Json) -> bool {
        let Ok(pairs) = object(value, "routing rule set") else {
            return false;
        };
        let kind = pairs
            .iter()
            .find_map(|(key, value)| (key.as_str() == "type").then_some(value.as_str()).flatten());
        match kind {
            Some("remote") => true,
            Some(_) => false,
            None => {
                !pairs.iter().any(|(key, _)| key.as_str() == "rules")
                    && pairs
                        .iter()
                        .any(|(key, value)| key.as_str() == "url" && value.as_str().is_some())
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn parse_with(
        root: &Json,
        dirs: Vec<PathBuf>,
        source: ScriptSource,
        remote: Option<&RemoteSetCache>,
    ) -> Result<Option<Self>, String> {
        let Some(block) = root.get("routing") else {
            return Ok(None);
        };
        if matches!(block, Json::Null) {
            return Ok(None);
        }
        let pairs = object(block, "routing")?;
        let mut strategy = DomainStrategy::AsIs;
        let mut raw_rules = None;
        let mut raw_balancers = None;
        let mut raw_sets = None;
        let mut raw_script = None;
        let mut assets = Assets::new(dirs.clone());
        for (key, value) in pairs {
            match key.as_str() {
                "domainStrategy" => {
                    if matches!(value, Json::Null) {
                        continue;
                    }
                    let named = value
                        .as_str()
                        .ok_or_else(|| "routing domainStrategy is not a string".to_owned())?;
                    strategy = match named.to_ascii_lowercase().as_str() {
                        "" | "asis" => DomainStrategy::AsIs,
                        "ipifnonmatch" => DomainStrategy::IpIfNonMatch,
                        "ipondemand" => DomainStrategy::IpOnDemand,
                        _ => {
                            return Err(format!(
                                "routing domainStrategy `{named}` is not AsIs, IpIfNonMatch or IpOnDemand"
                            ))
                        }
                    };
                }
                "rules" => {
                    raw_rules = Some(value);
                }
                "balancers" => {
                    raw_balancers = Some(value);
                }
                "script" => raw_script = Some(value),
                "ruleSet" | "ruleSets" | "rule_set" | "rule_sets" => raw_sets = Some(value),
                other => return Err(format!("routing field `{other}` is not carried")),
            }
        }
        let mut rule_sets = Vec::new();
        if let Some(value) = raw_sets {
            if !matches!(value, Json::Null) {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "routing rule set is not an array".to_owned())?;
                let mut prepared: Vec<Option<RuleSet>> = Vec::with_capacity(items.len());
                for item in items {
                    prepared.push(
                        Self::rule_set_is_remote(item)
                            .then(|| RuleSet::parse(item, &mut assets, &dirs, remote))
                            .transpose()?,
                    );
                }
                let mut tags = HashSet::new();
                for (at, item) in items.iter().enumerate() {
                    let set = match prepared[at].take() {
                        Some(set) => set,
                        None => RuleSet::parse(item, &mut assets, &dirs, remote)?,
                    };
                    if !tags.insert(set.tag.clone()) {
                        return Err(format!("duplicate rule set tag `{}`", set.tag));
                    }
                    rule_sets.push(Arc::new(set));
                }
            }
        }
        let script = match raw_script {
            Some(value) if !matches!(value, Json::Null) => {
                let path = value
                    .as_str()
                    .ok_or_else(|| "routing script is not a string".to_owned())?;
                if path.is_empty() {
                    return Err("routing script is empty".into());
                }
                match source {
                    ScriptSource::Reuse(script) => script,
                    ScriptSource::Resolve => {
                        #[cfg(not(target_os = "ios"))]
                        let script = Some(Arc::new(ScriptRouter::parse_in(path, dirs.clone())?));
                        #[cfg(target_os = "ios")]
                        let script = {
                            // iOS cannot run Lua, so a config that names a script is refused before the inbound opens rather than forwarding what the script would block.
                            let name = crate::router_script::resolve(path, &dirs).map_err(|reason| {
                                format!("routing script `{path}` cannot be enforced on iOS: {reason}")
                            })?;
                            ScriptRouter::parse_resolved(&name)?;
                            None
                        };
                        script
                    }
                }
            }
            _ => None,
        };
        let mut balancers = Vec::new();
        if let Some(value) = raw_balancers {
            if !matches!(value, Json::Null) {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "routing balancers is not an array".to_owned())?;
                let mut tags = HashSet::new();
                for (at, item) in items.iter().enumerate() {
                    let balancer = Balancer::parse(item, at)?;
                    if !tags.insert(balancer.tag.clone()) {
                        return Err(format!("duplicate balancer tag `{}`", balancer.tag));
                    }
                    balancers.push(balancer);
                }
            }
        }
        let mut rules = Vec::new();
        if let Some(value) = raw_rules {
            if !matches!(value, Json::Null) {
                let items = value
                    .as_arr()
                    .ok_or_else(|| "routing rules is not an array".to_owned())?;
                let mut tags = HashSet::new();
                for item in items {
                    let Some(rule) = Rule::parse(item, &mut assets, &rule_sets)? else {
                        continue;
                    };
                    if let Some(tag) = &rule.tag {
                        if !tags.insert(tag.clone()) {
                            return Err(format!("duplicate ruleTag `{tag}`"));
                        }
                    }
                    rules.push(rule);
                }
            }
        }
        for rule in &rules {
            if rule.balancer && !balancers.iter().any(|balancer| balancer.tag == rule.target) {
                return Err(format!("balancer `{}` not found", rule.target));
            }
        }
        let has_domains = rules.iter().any(|rule| {
            rule.domains.is_some()
                || rule
                    .sets
                    .as_ref()
                    .is_some_and(|sets| sets.iter().any(|set| set.has_domains()))
        });
        let wants_attrs = script.is_some() || rules.iter().any(|rule| rule.attrs.is_some());
        let wants_process = rules.iter().any(|rule| {
            rule.process.is_some()
                || rule.sets.as_ref().is_some_and(|sets| {
                    sets.iter()
                        .any(|set| set.rules.iter().any(SetRule::has_process))
                })
        });
        Ok(Some(Self {
            strategy,
            rules,
            balancers,
            rule_sets,
            asset_dirs: dirs,
            script,
            has_domains,
            wants_attrs,
            wants_process,
            added_replaced: false,
            removed_tags: HashSet::new(),
        }))
    }

    /// Move the runtime state a reparse cannot rebuild — a balancer's forced tag, weights and
    /// rotation — onto the freshly parsed table, matched by tag.
    pub(crate) fn adopt_balancer_state(&mut self, old: &mut Self) {
        for balancer in &mut self.balancers {
            let Some(previous) = old
                .balancers
                .iter_mut()
                .find(|previous| previous.tag == balancer.tag)
            else {
                continue;
            };
            balancer
                .index
                .store(previous.index.load(Ordering::Relaxed), Ordering::Relaxed);
            balancer
                .seed
                .store(previous.seed.load(Ordering::Relaxed), Ordering::Relaxed);
            let weights = std::mem::take(
                &mut *previous
                    .weights
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            *balancer
                .weights
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = weights;
            let forced = previous
                .forced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            *balancer
                .forced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = forced;
        }
    }

    /// Carry rules the management API added across a geodata reparse. The startup config does not
    /// contain them, so replacing the table wholesale would make a later `AddRule` rule vanish. A
    /// managed rule that no longer parses fails the reload before `old` is touched.
    pub(crate) fn adopt_added_rules(&mut self, old: &mut Self) -> Result<(), String> {
        struct Managed {
            rule: Option<Rule>,
            original: bool,
        }
        let replaced = old.added_replaced;
        let mut assets = Assets::new(self.asset_dirs.clone());
        let mut managed = Vec::new();
        for rule in old.rules.iter().filter(|rule| rule.added) {
            let Some(raw) = &rule.raw else {
                managed.push(Managed {
                    rule: None,
                    original: true,
                });
                continue;
            };
            let fresh = Rule::parse(raw, &mut assets, &self.rule_sets)?.map(|mut fresh| {
                fresh.added = true;
                fresh.raw = Some(raw.clone());
                fresh
            });
            managed.push(Managed {
                rule: fresh,
                original: false,
            });
        }
        let removed = old.removed_tags.clone();
        let added: Vec<Rule> = std::mem::take(&mut old.rules)
            .into_iter()
            .filter(|rule| rule.added)
            .collect();
        let mut kept = Vec::with_capacity(added.len());
        for (rule, managed) in added.into_iter().zip(managed) {
            if managed.original {
                kept.push(rule);
            } else if let Some(fresh) = managed.rule {
                kept.push(fresh);
            }
        }
        if replaced {
            self.rules = kept;
            self.balancers.clear();
            self.added_replaced = true;
        } else {
            self.rules
                .retain(|rule| !rule.tag.as_ref().is_some_and(|tag| removed.contains(tag)));
            self.rules.extend(kept);
        }
        self.removed_tags = removed;
        self.refresh();
        Ok(())
    }

    /// Append a decoded `AddRule` rule list, or replace the table with it when `append` is false.
    /// Rule tags stay unique across the whole table, as the reference's `AddRule` refuses a repeat,
    /// and every server inbound proves the candidate table before the write so a rule the inbound
    /// would never evaluate is refused instead of stored as a no-op.
    pub(crate) fn add_rules(
        &mut self,
        raw: &[Json],
        append: bool,
        known: impl Fn(&str) -> bool,
        proofs: &[ServerProof<'_>],
    ) -> Result<(), String> {
        let mut assets = Assets::new(self.asset_dirs.clone());
        let mut tags: HashSet<String> = if append {
            self.rules
                .iter()
                .filter_map(|rule| rule.tag.clone())
                .collect()
        } else {
            HashSet::new()
        };
        let mut rules = Vec::with_capacity(raw.len());
        for item in raw {
            let Some(mut rule) = Rule::parse(item, &mut assets, &self.rule_sets)? else {
                continue;
            };
            rule.added = true;
            rule.raw = Some(item.clone());
            if let Some(tag) = &rule.tag {
                if !tags.insert(tag.clone()) {
                    return Err(format!("duplicate ruleTag `{tag}`"));
                }
            }
            if rule.balancer {
                if !(append
                    && self
                        .balancers
                        .iter()
                        .any(|balancer| balancer.tag == rule.target))
                {
                    return Err(format!("balancer `{}` not found", rule.target));
                }
            } else if !known(&rule.target) {
                return Err(format!(
                    "routing targets `{}`, which no outbound names",
                    rule.target
                ));
            }
            rules.push(rule);
        }
        let forced = |tag: &str| self.forced_tag(tag);
        let always_picks = self.always_picks();
        for proof in proofs {
            if append {
                Self::server_routes_over(
                    self.script.is_some(),
                    self.rules.iter().chain(rules.iter()),
                    proof,
                    &forced,
                    &always_picks,
                )?;
            } else {
                Self::server_routes_over(
                    self.script.is_some(),
                    rules.iter(),
                    proof,
                    &forced,
                    &always_picks,
                )?;
            }
        }
        if append {
            self.rules.extend(rules);
        } else {
            self.rules = rules;
            self.added_replaced = true;
            self.removed_tags.clear();
            // The reference rebuilds its balancer map from the same config, which carries none.
            self.balancers.clear();
        }
        self.refresh();
        Ok(())
    }

    /// Drop every rule carrying `tag`, the reference's `RemoveRule`; a tag no rule carries is not
    /// an error there, and the table is unchanged.
    pub(crate) fn remove_rules(
        &mut self,
        tag: &str,
        proofs: &[ServerProof<'_>],
    ) -> Result<(), String> {
        let forced = |tag: &str| self.forced_tag(tag);
        let always_picks = self.always_picks();
        for proof in proofs {
            Self::server_routes_over(
                self.script.is_some(),
                self.rules
                    .iter()
                    .filter(|rule| rule.tag.as_deref() != Some(tag)),
                proof,
                &forced,
                &always_picks,
            )?;
        }
        self.rules.retain(|rule| rule.tag.as_deref() != Some(tag));
        self.removed_tags.insert(tag.to_owned());
        self.refresh();
        Ok(())
    }

    /// Recompute the three flags a front reads before it parses attributes or looks up a process.
    fn refresh(&mut self) {
        self.has_domains = self.rules.iter().any(|rule| {
            rule.domains.is_some()
                || rule
                    .sets
                    .as_ref()
                    .is_some_and(|sets| sets.iter().any(|set| set.has_domains()))
        });
        self.wants_attrs =
            self.script.is_some() || self.rules.iter().any(|rule| rule.attrs.is_some());
        self.wants_process = self.rules.iter().any(|rule| {
            rule.process.is_some()
                || rule.sets.as_ref().is_some_and(|sets| {
                    sets.iter()
                        .any(|set| set.rules.iter().any(SetRule::has_process))
                })
        });
    }

    /// Whether any rule reads the flow's HTTP attributes, which is the only reason a front pays to parse them.
    pub(crate) fn wants_attrs(&self) -> bool {
        self.wants_attrs
    }

    /// Whether any rule names the local process, which is the only reason a flow pays for the lookup.
    pub(crate) fn wants_process(&self) -> bool {
        self.wants_process
    }

    /// The targets rules name and whether each names a balancer, for the registry that has to
    /// build every outbound and every balancer's candidates.
    pub(crate) fn targets(&self) -> impl Iterator<Item = RouteTarget<'_>> {
        self.rules.iter().map(|rule| {
            if rule.balancer {
                RouteTarget::Balancer(rule.target.as_str())
            } else {
                RouteTarget::Outbound(rule.target.as_str())
            }
        })
    }

    /// Every rule in table order, for the management API's listing.
    pub(crate) fn listed_rules(&self) -> impl Iterator<Item = ListedRule> + '_ {
        self.rules.iter().map(|rule| ListedRule {
            target: rule.target.clone(),
            balancer: rule.balancer,
            tag: rule.tag.clone(),
        })
    }

    pub(crate) fn balancers(&self) -> impl Iterator<Item = &Balancer> {
        self.balancers.iter()
    }

    pub(crate) fn balancer(&self, tag: &str) -> Option<&Balancer> {
        self.balancers.iter().find(|balancer| balancer.tag == tag)
    }

    pub(crate) fn script(&self) -> Option<&ScriptRouter> {
        self.script.as_deref()
    }

    /// The script router as a handle a front can keep outside the table's lock.
    pub(crate) fn script_shared(&self) -> Option<Arc<ScriptRouter>> {
        self.script.clone()
    }

    /// The first matching rule's target; `None` leaves the caller's default in place.
    #[cfg(test)]
    pub(crate) fn route(&self, flow: &Flow) -> Option<&str> {
        self.route_target(flow).map(|hit| hit.tag())
    }

    pub(crate) fn route_target(&self, flow: &Flow) -> Option<RuleHit<'_>> {
        self.route_target_with(flow, &resolve_ips)
    }

    /// The first matching rule with no name resolution, as a loopback's `SkipDNSResolve` reads it.
    pub(crate) fn route_target_without_resolve(&self, flow: &Flow) -> Option<RuleHit<'_>> {
        self.route_target_with(flow, &|_, _| Vec::new())
    }

    /// The earliest rule any of a tested context's address choices reaches: xray reads each address
    /// list as any-of, where a live flow carries one address per role.
    pub(crate) fn probe_rule(&self, probe: &Probe<'_>) -> Option<RuleHit<'_>> {
        let mut best: Option<usize> = None;
        for ip in &probe.targets {
            for source in &probe.sources {
                for local in &probe.locals {
                    let flow = probe.flow(*ip, *source, *local);
                    if let Some(at) = self.route_index_with(&flow, &resolve_ips) {
                        if at == 0 {
                            return Some(rule_hit(&self.rules[0]));
                        }
                        if best.is_none_or(|best| at < best) {
                            best = Some(at);
                        }
                    }
                }
            }
        }
        best.map(|at| rule_hit(&self.rules[at]))
    }

    #[cfg(test)]
    fn route_with(&self, flow: &Flow, resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>) -> Option<&str> {
        self.route_target_with(flow, resolve).map(|hit| hit.tag())
    }

    fn route_target_with(
        &self,
        flow: &Flow,
        resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
    ) -> Option<RuleHit<'_>> {
        self.route_index_with(flow, resolve)
            .map(|at| rule_hit(&self.rules[at]))
    }

    fn route_index_with(
        &self,
        flow: &Flow,
        resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
    ) -> Option<usize> {
        let lower = OnceCell::new();
        let names = flow.domain.map(|raw| Names {
            raw,
            needs_lower: self.has_domains && raw.bytes().any(|byte| byte.is_ascii_uppercase()),
            lower: &lower,
        });
        match self.strategy {
            DomainStrategy::AsIs => {
                let mut ips = Ips::never();
                self.first_match(flow, names, &mut ips)
            }
            DomainStrategy::IpOnDemand => {
                let mut ips = Ips::lazy(resolve);
                self.first_match(flow, names, &mut ips)
            }
            DomainStrategy::IpIfNonMatch => self.first_match_if_non_match(flow, names, resolve),
        }
    }

    fn first_match(
        &self,
        flow: &Flow,
        names: Option<Names<'_>>,
        ips: &mut Ips<'_>,
    ) -> Option<usize> {
        self.rules
            .iter()
            .position(|rule| rule.matches(flow, names, ips))
    }

    /// `IpIfNonMatch` only resolves when a rule whose other selectors already hold still has an
    /// address set to test, and the second pass visits only those rules: a rule that failed on a
    /// port, a name or a source cannot be turned by an address it never names.
    fn first_match_if_non_match(
        &self,
        flow: &Flow,
        names: Option<Names<'_>>,
        resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
    ) -> Option<usize> {
        let mut pending = [0u64; 4];
        let mut spilled = false;
        for (at, rule) in self.rules.iter().enumerate() {
            if !rule.base_matches(flow, names) {
                continue;
            }
            let verdict = rule.set_verdict(flow, names, None);
            let needs_ip = rule.ips.is_some() || matches!(verdict, Verdict::Unknown);
            if !needs_ip {
                if matches!(verdict, Verdict::Yes) {
                    return Some(at);
                }
                continue;
            }
            if let Some(ip) = flow.ip {
                if matches!(rule.set_verdict(flow, names, Some(&[ip])), Verdict::Yes)
                    && rule.ip_matches_any(&[ip])
                {
                    return Some(at);
                }
            } else if at < pending.len() * 64 {
                pending[at / 64] |= 1 << (at % 64);
            } else {
                spilled = true;
            }
        }
        if !spilled && pending.iter().all(|word| *word == 0) {
            return None;
        }
        let addrs = resolve(flow.domain?, flow.port.unwrap_or(0));
        if addrs.is_empty() {
            return None;
        }
        for at in 0..self.rules.len().min(pending.len() * 64) {
            if pending[at / 64] & (1 << (at % 64)) != 0
                && self.rules[at].matches_tail(flow, names, &addrs)
            {
                return Some(at);
            }
        }
        if spilled {
            let offset = pending.len() * 64;
            return self.rules[offset..]
                .iter()
                .position(|rule| {
                    rule.base_matches(flow, names)
                        && rule.needs_ip(flow, names)
                        && rule.matches_tail(flow, names, &addrs)
                })
                .map(|at| offset + at);
        }
        None
    }

    /// The one tag a SOCKS association may use when every datagram reaches it; `None` when a
    /// per-destination rule could split the association, which the caller serves one lane per
    /// datagram's chosen tag rather than guessing. A rule carrying a `webhook` splits too: its
    /// event names the datagram's own flow, so a collapsed association could not fire it.
    pub(crate) fn udp_tag<'a>(
        &'a self,
        inbound: Option<&str>,
        default: Option<&'a str>,
    ) -> Result<Option<&'a str>, ()> {
        if self.script.is_some() {
            return Err(());
        }
        let mut decided: Option<&str> = None;
        for rule in &self.rules {
            if !rule.reachable(inbound, Network::Udp) || !rule.local_os_matches() {
                continue;
            }
            if rule.balancer || rule.webhook.is_some() {
                return Err(());
            }
            if !agree(&mut decided, &rule.target) {
                return Err(());
            }
            if rule.association_stable() {
                return Ok(Some(rule.target.as_str()));
            }
        }
        match (decided, default) {
            (None, _) => Ok(None),
            (Some(tag), Some(default)) if tag == default => Ok(None),
            _ => Err(()),
        }
    }

    /// Proves a server inbound's fixed direct dial is what the rules would pick anyway. A rule that
    /// could match and points elsewhere refuses the start, because this tree serves that inbound direct.
    pub(crate) fn server_routes(&self, proof: &ServerProof<'_>) -> Result<(), String> {
        let forced = |tag: &str| self.forced_tag(tag);
        Self::server_routes_over(
            self.script.is_some(),
            self.rules.iter(),
            proof,
            &forced,
            &self.always_picks(),
        )
    }

    fn always_picks(&self) -> HashSet<&str> {
        self.balancers
            .iter()
            .filter(|balancer| matches!(balancer.strategy, Strategy::Random | Strategy::RoundRobin))
            .map(|balancer| balancer.tag.as_str())
            .collect()
    }

    /// The portal tags a server inbound may attach to: a reachable rule names the portal and the
    /// exact domain that portal carries, the same proof `server_routes` accepts at startup.
    pub(crate) fn portal_targets(
        &self,
        inbound: Option<&str>,
        portal: &dyn Fn(&str) -> bool,
        domain: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<String> {
        self.rules
            .iter()
            .filter(|rule| {
                rule.reachable(inbound, Network::Tcp)
                    && portal(rule.target())
                    && domain(rule.target()).is_some_and(|domain| rule.only_matches_domain(&domain))
            })
            .map(|rule| rule.target().to_owned())
            .collect()
    }

    /// The tag `OverrideBalancerTarget` forced on a balancer, when one is active.
    fn forced_tag(&self, tag: &str) -> Option<String> {
        let forced = self.balancer(tag)?.forced();
        (!forced.is_empty()).then_some(forced)
    }

    fn server_routes_over<'r>(
        script: bool,
        rules: impl Iterator<Item = &'r Rule>,
        proof: &ServerProof<'_>,
        forced: &dyn Fn(&str) -> Option<String>,
        always_picks: &HashSet<&str>,
    ) -> Result<(), String> {
        let ServerProof {
            inbound,
            default_direct,
            networks,
            direct,
            direct_policy,
            portal_rule,
            candidates,
            fallbacks,
        } = proof;
        if script {
            return Err(format!(
                "inbound {} names a routing script, which the server inbound cannot evaluate",
                inbound.unwrap_or("<untagged>")
            ));
        }
        // Stop at the first direct rule covering a network; later rules cannot decide it.
        let mut open = [false; 2];
        for network in *networks {
            match network {
                Network::Tcp => open[0] = true,
                Network::Udp => open[1] = true,
                Network::Other(_) => {}
            }
        }
        for rule in rules {
            if !rule.local_os_matches() {
                continue;
            }
            let reaches = [
                open[0] && rule.server_reachable(*inbound, Network::Tcp),
                open[1] && rule.server_reachable(*inbound, Network::Udp),
            ];
            if !reaches[0] && !reaches[1] {
                continue;
            }
            // A rule naming a fact the server flow does not carry still gates the target.
            let dials_direct = if rule.balancer {
                if let Some(tag) = forced(&rule.target) {
                    direct(&tag) && direct_policy(&tag)
                } else {
                    let list = candidates.get(&rule.target).map_or(&[][..], Vec::as_slice);
                    let fallback = fallbacks.get(&rule.target);
                    list.iter().all(|tag| direct(tag) && direct_policy(tag))
                        && fallback.is_none_or(|tag| direct(tag) && direct_policy(tag))
                        && (fallback.is_some()
                            || *default_direct
                            || (always_picks.contains(rule.target.as_str()) && !list.is_empty()))
                }
            } else {
                (direct(&rule.target) && direct_policy(&rule.target)) || portal_rule(rule)
            };
            if !dials_direct {
                return Err(format!(
                    "a rule for inbound {} targets `{}`, which the server inbound serves direct",
                    inbound.unwrap_or("<untagged>"),
                    rule.target
                ));
            }
            if rule.webhook.is_some() {
                eprintln!(
                    "routing: a webhook on a rule for inbound {} never fires, because the server inbound dials direct",
                    inbound.unwrap_or("<untagged>")
                );
            }
            if rule.catch_all() {
                if reaches[0] {
                    open[0] = false;
                }
                if reaches[1] {
                    open[1] = false;
                }
            }
        }
        if !open[0] && !open[1] {
            return Ok(());
        }
        if *default_direct {
            Ok(())
        } else {
            Err(format!(
                "inbound {} falls to a default outbound the server inbound cannot dial direct",
                inbound.unwrap_or("<untagged>")
            ))
        }
    }

    /// The first selector a source-less flow cannot answer, if a rule that could reach it on either network names one.
    pub(crate) fn source_refusal(&self, inbound: Option<&str>) -> Option<&'static str> {
        for network in [Network::Tcp, Network::Udp] {
            for rule in &self.rules {
                if rule.protocols.as_ref().is_some_and(Vec::is_empty)
                    || !rule.reachable(inbound, network)
                    || !rule.local_os_matches()
                {
                    continue;
                }
                if rule
                    .sets
                    .as_ref()
                    .is_some_and(|sets| sets.iter().any(|set| set.needs_source(network)))
                {
                    return Some("ruleSet");
                }
                for (present, name) in [
                    (rule.source_ips.is_some(), "source"),
                    (rule.source_ports.is_some(), "sourcePort"),
                    (rule.local_ips.is_some(), "localIP"),
                    (rule.local_ports.is_some(), "localPort"),
                ] {
                    if present {
                        return Some(name);
                    }
                }
                if rule.catch_all() {
                    break;
                }
            }
        }
        None
    }

    #[cfg(test)]
    fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

fn agree<'a>(decided: &mut Option<&'a str>, tag: &'a str) -> bool {
    if let Some(seen) = decided {
        *seen == tag
    } else {
        *decided = Some(tag);
        true
    }
}

type Resolver<'a> = &'a dyn Fn(&str, u16) -> Vec<IpAddr>;

struct Ips<'a> {
    allowed: bool,
    resolve: Option<Resolver<'a>>,
    addrs: Option<Vec<IpAddr>>,
}

impl<'a> Ips<'a> {
    fn never() -> Self {
        Self {
            allowed: false,
            resolve: None,
            addrs: None,
        }
    }

    fn lazy(resolve: Resolver<'a>) -> Self {
        Self {
            allowed: true,
            resolve: Some(resolve),
            addrs: None,
        }
    }

    fn get(&mut self, flow: &Flow) -> &[IpAddr] {
        if self.addrs.is_none() && self.allowed {
            let addrs = match (self.resolve, flow.domain) {
                (Some(resolve), Some(host)) => resolve(host, flow.port.unwrap_or(0)),
                _ => Vec::new(),
            };
            self.addrs = Some(addrs);
        }
        self.addrs.as_deref().unwrap_or(&[])
    }
}

fn rule_field_target(field: &Json, name: &str) -> Result<Option<String>, String> {
    field
        .as_str()
        .map(|tag| (!tag.is_empty()).then(|| tag.to_owned()))
        .ok_or_else(|| format!("routing rule {name} is not a string"))
}

fn optional_string<'a>(value: &'a Json, name: &str) -> Result<Option<&'a str>, String> {
    match value {
        Json::Null => Ok(None),
        _ => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("routing rule set {name} is not a string")),
    }
}

impl Rule {
    #[allow(clippy::too_many_lines)]
    fn parse(
        value: &Json,
        assets: &mut Assets,
        sets: &[Arc<RuleSet>],
    ) -> Result<Option<Self>, String> {
        let pairs = object(value, "routing rule")?;
        let mut target = None;
        let mut balancing_target = None;
        let mut tag = None;
        let mut inbound_tags = None;
        let mut networks = None;
        let mut local_os = None;
        let mut ports = None;
        let mut source_ports = None;
        let mut local_ports = None;
        let mut domains = None;
        let mut domain_value = None;
        let mut domains_list = None;
        let mut ips = None;
        let mut source_ips = None;
        let mut source_value = None;
        let mut source_ip_value = None;
        let mut local_ips = None;
        let mut protocols = None;
        let mut users = None;
        let mut vless_routes = None;
        let mut attrs = None;
        let mut process = None;
        let mut rule_sets = None;
        let mut webhook = None;
        for (key, field) in pairs {
            match key.as_str() {
                "outboundTag" => target = rule_field_target(field, "outboundTag")?,
                "balancerTag" => balancing_target = rule_field_target(field, "balancerTag")?,
                "type" => {
                    let named = field
                        .as_str()
                        .ok_or_else(|| "routing rule type is not a string".to_owned())?;
                    if !named.eq_ignore_ascii_case("field") {
                        return Err(format!("routing rule type `{named}` is not field"));
                    }
                }
                "ruleTag" => {
                    tag = field
                        .as_str()
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_owned);
                }
                "domain" => domain_value = Some(field),
                "domains" => domains_list = Some(field),
                "ip" => ips = Some(ip_matcher(field, assets, "routing ip")?),
                "port" => ports = port_set(field, "port")?,
                "network" => networks = network_list(field)?,
                "source" => source_value = Some(field),
                "sourceIP" => source_ip_value = Some(field),
                "sourcePort" => source_ports = port_set(field, "sourcePort")?,
                "localIP" => local_ips = Some(ip_matcher(field, assets, "routing localIP")?),
                "localPort" => local_ports = port_set(field, "localPort")?,
                "inboundTag" => inbound_tags = string_list(field, "inboundTag")?,
                "localOS" => local_os = string_list(field, "localOS")?,
                "protocol" => {
                    protocols = string_list(field, "protocol")?.map(|list| {
                        list.into_iter()
                            .filter(|listed| !listed.is_empty())
                            .collect()
                    });
                }
                "user" => {
                    users = string_list(field, "user")?.map(|names| UserSelector::parse(&names));
                }
                "attrs" => attrs = AttributeSelector::parse(field)?,
                "vlessRoute" => vless_routes = port_set(field, "vlessRoute")?,
                "ruleSet" | "rule_set" => {
                    rule_sets = Some(
                        string_list(field, "ruleSet")?
                            .ok_or_else(|| "routing ruleSet is empty".to_owned())?,
                    );
                }
                "process" => {
                    process = string_list(field, "process")?
                        .filter(|names| !names.is_empty())
                        .map(|names| ProcessSelector::parse(&names));
                }
                "webhook" => webhook = crate::webhook::parse(field)?,
                other => return Err(format!("routing rule field `{other}` is not carried")),
            }
        }
        let balancing = target.is_none() && balancing_target.is_some();
        let target = target
            .or(balancing_target)
            .ok_or_else(|| "routing rule names neither outboundTag nor balancerTag".to_owned())?;
        let rule_sets = match rule_sets {
            Some(tags) => Some(
                tags.iter()
                    .map(|tag| {
                        sets.iter()
                            .find(|set| &set.tag == tag)
                            .cloned()
                            .ok_or_else(|| format!("rule set `{tag}` not found"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        let domain_json = domains_list.or(domain_value);
        if let Some(field) = domain_json {
            domains = Some(domain_matcher(field, assets)?);
        }
        let source_json = source_ip_value.or(source_value);
        if let Some(field) = source_json {
            source_ips = Some(ip_matcher(field, assets, "routing sourceIP")?);
        }
        Ok(Some(Self {
            target,
            balancer: balancing,
            tag,
            inbound_tags,
            networks,
            local_os,
            ports,
            source_ports,
            local_ports,
            domains,
            ips,
            source_ips,
            local_ips,
            protocols,
            users,
            vless_routes,
            attrs,
            process,
            webhook,
            sets: rule_sets,
            added: false,
            raw: None,
        }))
    }

    /// True when no selector beyond the inbound, network and local OS narrows this rule.
    fn catch_all(&self) -> bool {
        self.ports.is_none()
            && self.source_ports.is_none()
            && self.local_ports.is_none()
            && self.domains.is_none()
            && self.ips.is_none()
            && self.source_ips.is_none()
            && self.local_ips.is_none()
            && self.protocols.is_none()
            && self.users.is_none()
            && self
                .vless_routes
                .as_ref()
                .is_none_or(|routes| routes.contains(0))
            && self.attrs.is_none()
            && self.process.is_none()
            && self.sets.is_none()
    }

    fn association_stable(&self) -> bool {
        !self.balancer && self.catch_all()
    }

    fn local_os_matches(&self) -> bool {
        let current = local_os();
        self.local_os
            .as_ref()
            .is_none_or(|list| list.iter().any(|os| os.eq_ignore_ascii_case(current)))
    }

    fn reachable(&self, inbound: Option<&str>, network: Network) -> bool {
        if let Some(tags) = &self.inbound_tags {
            let Some(tag) = inbound else {
                return false;
            };
            if !tags.iter().any(|named| named == tag) {
                return false;
            }
        }
        self.networks
            .as_ref()
            .is_none_or(|list| list.contains(&network))
    }

    /// Whether a server flow on `network` could reach this rule. A selector that never holds and
    /// a rule set with no branch on this network both make it unreachable.
    fn server_reachable(&self, inbound: Option<&str>, network: Network) -> bool {
        self.reachable(inbound, network)
            && !self.protocols.as_ref().is_some_and(Vec::is_empty)
            && !self.users.as_ref().is_some_and(UserSelector::is_empty)
            && self
                .sets
                .as_ref()
                .is_none_or(|sets| sets.iter().any(|set| set.can_reach_on(network)))
    }

    fn matches(&self, flow: &Flow, names: Option<Names<'_>>, ips: &mut Ips<'_>) -> bool {
        if !self.base_matches(flow, names) {
            return false;
        }
        let verdict = if let Some(ip) = flow.ip {
            self.set_verdict(flow, names, Some(&[ip]))
        } else {
            let verdict = self.set_verdict(flow, names, None);
            if matches!(verdict, Verdict::Unknown) {
                let addrs = ips.get(flow);
                self.set_verdict(flow, names, Some(addrs))
            } else {
                verdict
            }
        };
        matches!(verdict, Verdict::Yes) && self.ip_matches(flow, ips)
    }

    fn base_matches(&self, flow: &Flow, names: Option<Names<'_>>) -> bool {
        if let Some(networks) = &self.networks {
            if !networks.contains(&flow.network) {
                return false;
            }
        }
        if let Some(tags) = &self.inbound_tags {
            let Some(tag) = flow.inbound_tag else {
                return false;
            };
            if !tags.iter().any(|named| named == tag) {
                return false;
            }
        }
        if !self.local_os_matches() {
            return false;
        }
        if let Some(protocols) = &self.protocols {
            let Some(protocol) = flow.protocol else {
                return false;
            };
            if !protocols.iter().any(|listed| protocol.starts_with(listed)) {
                return false;
            }
        }
        if let Some(ports) = &self.ports {
            if !flow.port.is_some_and(|port| ports.contains(port)) {
                return false;
            }
        }
        if let Some(ports) = &self.source_ports {
            if !ports.contains(flow.source_port) {
                return false;
            }
        }
        if let Some(ports) = &self.local_ports {
            if !ports.contains(flow.local_port) {
                return false;
            }
        }
        if let Some(domains) = &self.domains {
            let Some(names) = names else {
                return false;
            };
            if !domains.matches(names.raw, names.lower()) {
                return false;
            }
        }
        if let Some(users) = &self.users {
            if !users.matches(flow.user) {
                return false;
            }
        }
        if let Some(attrs) = &self.attrs {
            if !attrs.matches(flow.attrs) {
                return false;
            }
        }
        if let Some(process) = &self.process {
            if !process.matches(flow.process) {
                return false;
            }
        }
        if let Some(routes) = &self.vless_routes {
            if !routes.contains(flow.vless_route) {
                return false;
            }
        }
        if let Some(matcher) = &self.source_ips {
            if !flow.source.is_some_and(|ip| matcher.matches(ip)) {
                return false;
            }
        }
        if let Some(matcher) = &self.local_ips {
            if !flow.local.is_some_and(|ip| matcher.matches(ip)) {
                return false;
            }
        }
        true
    }

    fn set_verdict(
        &self,
        flow: &Flow,
        names: Option<Names<'_>>,
        addrs: Option<&[IpAddr]>,
    ) -> Verdict {
        let Some(sets) = &self.sets else {
            return Verdict::Yes;
        };
        let mut verdict = Verdict::No;
        for set in sets {
            match set.verdict(flow, names, addrs) {
                Verdict::Yes => return Verdict::Yes,
                Verdict::Unknown => verdict = Verdict::Unknown,
                Verdict::No => {}
            }
        }
        verdict
    }

    fn needs_ip(&self, flow: &Flow, names: Option<Names<'_>>) -> bool {
        self.ips.is_some() || matches!(self.set_verdict(flow, names, None), Verdict::Unknown)
    }

    fn matches_tail(&self, flow: &Flow, names: Option<Names<'_>>, addrs: &[IpAddr]) -> bool {
        matches!(self.set_verdict(flow, names, Some(addrs)), Verdict::Yes)
            && self.ip_matches_any(addrs)
    }

    fn ip_matches(&self, flow: &Flow, ips: &mut Ips<'_>) -> bool {
        let Some(matcher) = &self.ips else {
            return true;
        };
        match flow.ip {
            Some(ip) => matcher.matches(ip),
            None => ips.get(flow).iter().any(|ip| matcher.matches(*ip)),
        }
    }

    fn ip_matches_any(&self, addrs: &[IpAddr]) -> bool {
        self.ips
            .as_ref()
            .is_none_or(|matcher| addrs.iter().any(|ip| matcher.matches(*ip)))
    }
}

fn parse_source_rules(body: &Json, tag: &str, assets: &mut Assets) -> Result<Vec<SetRule>, String> {
    if let Json::Obj(pairs) = body {
        if let Some((_, version)) = pairs.iter().find(|(key, _)| key == "version") {
            let version = version
                .as_u32()
                .ok_or_else(|| format!("routing rule set `{tag}` version is not a number"))?;
            if !(1..=5).contains(&version) {
                return Err(format!(
                    "routing rule set `{tag}` version {version} is not carried"
                ));
            }
        }
    }
    match body {
        Json::Arr(items) => items
            .iter()
            .map(|item| SetRule::parse(item, assets))
            .collect::<Result<Vec<_>, _>>(),
        Json::Obj(pairs) => {
            if let Some((_, rules)) = pairs.iter().find(|(key, _)| key == "rules") {
                for (key, _) in pairs {
                    if key != "rules" && key != "version" {
                        return Err(format!(
                            "routing rule set `{tag}` field `{key}` is not carried"
                        ));
                    }
                }
                let Some(items) = rules.as_arr() else {
                    return Err(format!("routing rule set `{tag}` rules is not an array"));
                };
                items
                    .iter()
                    .map(|item| SetRule::parse(item, assets))
                    .collect::<Result<Vec<_>, _>>()
            } else {
                let mut out = Vec::new();
                for (key, value) in pairs {
                    match key.as_str() {
                        "version" => {
                            let version = value.as_u32().ok_or_else(|| {
                                format!("routing rule set `{tag}` version is not a number")
                            })?;
                            if !(1..=5).contains(&version) {
                                return Err(format!(
                                    "routing rule set `{tag}` version {version} is not carried"
                                ));
                            }
                        }
                        "domain" => out.push(SetRule::domains(value, assets)?),
                        "ip" => out.push(SetRule::addresses(value, assets)?),
                        other => {
                            return Err(format!(
                                "routing rule set `{tag}` field `{other}` is not carried"
                            ));
                        }
                    }
                }
                if out.is_empty() {
                    return Err(format!(
                        "routing rule set `{tag}` names neither rules nor domain and ip"
                    ));
                }
                Ok(out)
            }
        }
        _ => Err(format!(
            "routing rule set `{tag}` is not a rule list or rule set object"
        )),
    }
}

fn cache_path(path: Option<&str>, dirs: &[PathBuf]) -> Option<PathBuf> {
    let path = path.filter(|path| !path.contains("://"))?;
    let direct = PathBuf::from(path);
    if direct.is_absolute() {
        return Some(direct);
    }
    Some(
        dirs.first()
            .map_or_else(|| direct.clone(), |dir| dir.join(path)),
    )
}

struct SrsReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> SrsReader<'a> {
    fn body(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| "SRS rule set ends early".to_owned())?;
        self.at += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(count)
            .ok_or_else(|| "SRS rule set length overflows".to_owned())?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| "SRS rule set ends early".to_owned())?;
        self.at = end;
        Ok(slice)
    }

    fn uvarint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift >= 64 || (shift == 63 && byte > 1) {
                return Err("SRS rule set varint overflows".to_owned());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    fn string(&mut self) -> Result<String, String> {
        let length = self.uvarint()? as usize;
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "SRS rule set string is not UTF-8".to_owned())
    }

    fn strings(&mut self) -> Result<Vec<String>, String> {
        let count = self.uvarint()? as usize;
        if count > 1_000_000 {
            return Err("SRS rule set names too many strings".to_owned());
        }
        (0..count).map(|_| self.string()).collect()
    }

    fn u16s(&mut self) -> Result<Vec<u16>, String> {
        let count = self.uvarint()? as usize;
        if count > 1_000_000 {
            return Err("SRS rule set names too many values".to_owned());
        }
        (0..count).map(|_| self.u16()).collect()
    }

    fn u64s(&mut self) -> Result<Vec<u64>, String> {
        let count = self.uvarint()? as usize;
        if count > 1_000_000 {
            return Err("SRS rule set names too many values".to_owned());
        }
        (0..count).map(|_| self.u64()).collect()
    }

    fn bytes_vec(&mut self) -> Result<Vec<u8>, String> {
        let count = self.uvarint()? as usize;
        Ok(self.take(count)?.to_vec())
    }
}

fn reverse_domain(value: &str) -> String {
    value.chars().rev().collect()
}

fn read_succinct(reader: &mut SrsReader<'_>) -> Result<SuccinctSet, String> {
    let _version = reader.byte()?;
    let leaves = reader.u64s()?;
    let label_bitmap = reader.u64s()?;
    let labels = reader.bytes_vec()?;
    if label_bitmap.is_empty() {
        if !leaves.is_empty() || !labels.is_empty() {
            return Err("SRS domain matcher is malformed".to_owned());
        }
        return Ok(SuccinctSet {
            leaves,
            label_bitmap,
            labels,
            ranks: vec![0],
            selects: Vec::new(),
        });
    }
    let ones: usize = label_bitmap
        .iter()
        .map(|word| word.count_ones() as usize)
        .sum();
    let last_one = label_bitmap
        .iter()
        .enumerate()
        .rev()
        .find_map(|(at, word)| (*word != 0).then(|| at * 64 + 63 - word.leading_zeros() as usize))
        .unwrap_or(0);
    let zeros = last_one + 1 - ones;
    if ones != zeros + 1 || labels.len() != zeros {
        return Err("SRS domain matcher is malformed".to_owned());
    }
    let ranks = SuccinctSet::ranks(&label_bitmap);
    let selects = SuccinctSet::selects(&label_bitmap);
    Ok(SuccinctSet {
        leaves,
        label_bitmap,
        labels,
        ranks,
        selects,
    })
}

fn parse_srs(bytes: &[u8], tag: &str) -> Result<Vec<SetRule>, String> {
    if !bytes.starts_with(b"SRS") {
        return Err(format!("routing rule set `{tag}` is not an SRS rule set"));
    }
    let version = *bytes
        .get(3)
        .ok_or_else(|| format!("routing rule set `{tag}` is an SRS rule set with no version"))?;
    if !(1..=5).contains(&version) {
        return Err(format!(
            "routing rule set `{tag}` SRS version {version} is not carried"
        ));
    }
    let mut decoder =
        flate2::read::ZlibDecoder::new(&bytes[4..]).take(crate::geodata::MAX_DOWNLOAD + 1);
    let mut body = Vec::new();
    decoder
        .read_to_end(&mut body)
        .map_err(|error| format!("routing rule set `{tag}` SRS body: {error}"))?;
    if body.len() as u64 > crate::geodata::MAX_DOWNLOAD {
        return Err(format!("routing rule set `{tag}` SRS body is too large"));
    }
    let mut reader = SrsReader::body(&body);
    let count = reader.uvarint()? as usize;
    if count > 1_000_000 {
        return Err(format!("routing rule set `{tag}` names too many rules"));
    }
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        rules.push(read_srs_rule(&mut reader, 0, tag)?);
    }
    Ok(rules)
}

fn read_srs_rule(reader: &mut SrsReader<'_>, depth: usize, tag: &str) -> Result<SetRule, String> {
    if depth > 100 {
        return Err(format!(
            "routing rule set `{tag}` logical rule nests too deep"
        ));
    }
    match reader.byte()? {
        0 => {
            let mut rule = SetRule {
                invert: false,
                logical: None,
                networks: None,
                domains: None,
                ports: None,
                source_ports: None,
                ips: None,
                source_ips: None,
                process: None,
            };
            loop {
                let item = reader.byte()?;
                if item == 0xff {
                    rule.invert = reader.byte()? != 0;
                    break;
                }
                read_srs_item(reader, item, &mut rule, tag)?;
            }
            if let Some(matcher) = rule.domains.as_mut() {
                matcher.finish()?;
            }
            if let Some(ports) = rule.ports.as_mut() {
                ports.finish();
            }
            if let Some(ports) = rule.source_ports.as_mut() {
                ports.finish();
            }
            if rule.networks.is_none()
                && rule.domains.is_none()
                && rule.ports.is_none()
                && rule.source_ports.is_none()
                && rule.ips.is_none()
                && rule.source_ips.is_none()
                && rule.process.is_none()
            {
                return Err(format!("routing rule set `{tag}` rule names no condition"));
            }
            Ok(rule)
        }
        1 => {
            let all = match reader.byte()? {
                0 => true,
                1 => false,
                mode => {
                    return Err(format!(
                        "routing rule set `{tag}` logical mode {mode} is not carried"
                    ));
                }
            };
            let count = reader.uvarint()? as usize;
            if count == 0 || count > 1_000_000 {
                return Err(format!(
                    "routing rule set `{tag}` logical rule has no rules"
                ));
            }
            let mut rules = Vec::with_capacity(count);
            for _ in 0..count {
                rules.push(read_srs_rule(reader, depth + 1, tag)?);
            }
            Ok(SetRule {
                invert: reader.byte()? != 0,
                logical: Some(SetLogical { all, rules }),
                networks: None,
                domains: None,
                ports: None,
                source_ports: None,
                ips: None,
                source_ips: None,
                process: None,
            })
        }
        kind => Err(format!(
            "routing rule set `{tag}` rule type {kind} is not carried"
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn read_srs_item(
    reader: &mut SrsReader<'_>,
    item: u8,
    rule: &mut SetRule,
    tag: &str,
) -> Result<(), String> {
    match item {
        1 => {
            let networks = rule.networks.get_or_insert_with(Vec::new);
            for network in reader.strings()? {
                match network.as_str() {
                    "tcp" => networks.push(Network::Tcp),
                    "udp" => networks.push(Network::Udp),
                    other => {
                        return Err(format!(
                            "routing rule set `{tag}` network `{other}` is not carried"
                        ));
                    }
                }
            }
        }
        2 => {
            let set = read_succinct(reader)?;
            let matcher = rule.domains.get_or_insert_with(DomainMatcher::new);
            let budget = reader
                .bytes
                .len()
                .saturating_mul(8)
                .min(MAX_EXPANDED_DOMAIN_BYTES);
            set.walk_keys(budget, &mut |key| {
                let original = reverse_domain(&String::from_utf8_lossy(key));
                match original.as_bytes().first() {
                    Some(&PREFIX_LABEL) => {
                        let domain = original[1..].trim_start_matches('.');
                        if !domain.is_empty() {
                            matcher.add(DomainKind::SuffixOnly, lower_arc(domain))?;
                        }
                    }
                    Some(&ROOT_LABEL) => {
                        let domain = &original[1..];
                        if !domain.is_empty() {
                            matcher.add(DomainKind::Domain, lower_arc(domain))?;
                        }
                    }
                    Some(_) => matcher.add(DomainKind::Full, lower_arc(&original))?,
                    None => {}
                }
                Ok(())
            })?;
        }
        3 => {
            let matcher = rule.domains.get_or_insert_with(DomainMatcher::new);
            for keyword in reader.strings()? {
                matcher.add(DomainKind::Substr, lower_arc(&keyword))?;
            }
        }
        4 => {
            let matcher = rule.domains.get_or_insert_with(DomainMatcher::new);
            for pattern in reader.strings()? {
                matcher
                    .add(DomainKind::Regex, Arc::from(pattern))
                    .map_err(|error| format!("routing rule set `{tag}` {error}"))?;
            }
        }
        5 => {
            let set = read_ip_set(reader, tag)?;
            let matcher = rule
                .source_ips
                .get_or_insert_with(|| IpMatcher { sets: Vec::new() });
            matcher.sets.push((set, false));
        }
        6 => {
            let set = read_ip_set(reader, tag)?;
            let matcher = rule
                .ips
                .get_or_insert_with(|| IpMatcher { sets: Vec::new() });
            matcher.sets.push((set, false));
        }
        7 | 9 => {
            let ports = if item == 7 {
                rule.source_ports.get_or_insert_with(PortSet::default)
            } else {
                rule.ports.get_or_insert_with(PortSet::default)
            };
            for port in reader.u16s()? {
                ports.ranges.push((port, port));
            }
        }
        8 | 10 => {
            let ports = if item == 8 {
                rule.source_ports.get_or_insert_with(PortSet::default)
            } else {
                rule.ports.get_or_insert_with(PortSet::default)
            };
            for range in reader.strings()? {
                for part in range.split(',') {
                    let (start, end) = part
                        .split_once(':')
                        .or_else(|| part.split_once('-'))
                        .ok_or_else(|| {
                            format!("routing rule set `{tag}` port range `{part}` is not a range")
                        })?;
                    let start = start.trim();
                    let start = if start.is_empty() {
                        0
                    } else {
                        start.parse::<u16>().map_err(|_| {
                            format!("routing rule set `{tag}` port range `{part}` is not a range")
                        })?
                    };
                    let end = end.trim();
                    let end = if end.is_empty() {
                        u16::MAX
                    } else {
                        end.parse::<u16>().map_err(|_| {
                            format!("routing rule set `{tag}` port range `{part}` is not a range")
                        })?
                    };
                    if end < start {
                        return Err(format!(
                            "routing rule set `{tag}` port range `{part}` is not a range"
                        ));
                    }
                    ports.ranges.push((start, end));
                }
            }
        }
        11 | 12 | 17 => {
            let values = reader.strings()?;
            if values.is_empty() {
                return Ok(());
            }
            let process = rule.process.get_or_insert_with(|| SetProcess {
                names: Vec::new(),
                paths: Vec::new(),
                patterns: Vec::new(),
            });
            for value in values {
                match item {
                    11 => process.names.push(value),
                    12 => process.paths.push(value),
                    _ => process
                        .patterns
                        .push(regex::Regex::new(&value).map_err(|error| {
                            format!("routing rule set `{tag}` process path regex: {error}")
                        })?),
                }
            }
        }
        16 => {
            let set = read_succinct(reader)?;
            rule.domains
                .get_or_insert_with(DomainMatcher::new)
                .adguard
                .push(set);
        }
        0 | 13 | 14 | 15 | 18 | 19 | 20 | 21 | 22 | 23 => {
            return Err(format!(
                "routing rule set `{tag}` item {} is not carried",
                srs_item_name(item)
            ));
        }
        other => {
            return Err(format!(
                "routing rule set `{tag}` item {other} is not carried"
            ));
        }
    }
    Ok(())
}

fn srs_item_name(item: u8) -> &'static str {
    match item {
        0 => "query_type",
        13 => "package_name",
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        18 => "network_type",
        19 => "network_is_expensive",
        20 => "network_is_constrained",
        21 => "network_interface_address",
        22 => "default_interface_address",
        23 => "package_name_regex",
        _ => "unknown",
    }
}

fn read_ip_set(reader: &mut SrsReader<'_>, tag: &str) -> Result<RangeSet, String> {
    if reader.byte()? != 1 {
        return Err(format!("routing rule set `{tag}` IP set version is not 1"));
    }
    let count = reader.u64()? as usize;
    if count > 1_000_000 {
        return Err(format!(
            "routing rule set `{tag}` IP set names too many ranges"
        ));
    }
    let mut set = RangeSet::default();
    for _ in 0..count {
        let (from, from_len) = read_ip_set_address(reader, tag)?;
        let (to, to_len) = read_ip_set_address(reader, tag)?;
        if from_len != to_len {
            return Err(format!(
                "routing rule set `{tag}` IP set range mixes families"
            ));
        }
        match (from, to) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                let (from, to) = (u32::from(from), u32::from(to));
                if to < from {
                    return Err(format!(
                        "routing rule set `{tag}` IP set range is not a range"
                    ));
                }
                set.v4.push((from, to));
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                let (from, to) = (u128::from(from), u128::from(to));
                if to < from {
                    return Err(format!(
                        "routing rule set `{tag}` IP set range is not a range"
                    ));
                }
                set.add_v6_range(from, to)?;
            }
            _ => {
                return Err(format!(
                    "routing rule set `{tag}` IP set range mixes families"
                ));
            }
        }
    }
    set.finish();
    Ok(set)
}

fn read_ip_set_address(reader: &mut SrsReader<'_>, tag: &str) -> Result<(IpAddr, usize), String> {
    let length = reader.uvarint()? as usize;
    let bytes = reader.take(length)?;
    match length {
        4 => {
            let mut value = [0u8; 4];
            value.copy_from_slice(bytes);
            Ok((IpAddr::V4(std::net::Ipv4Addr::from(value)), 4))
        }
        16 => {
            let mut value = [0u8; 16];
            value.copy_from_slice(bytes);
            Ok((IpAddr::V6(std::net::Ipv6Addr::from(value)), 16))
        }
        other => Err(format!(
            "routing rule set `{tag}` IP set address length {other} is not carried"
        )),
    }
}

impl RuleSet {
    fn can_reach_on(&self, network: Network) -> bool {
        self.rules.iter().any(|rule| rule.can_reach_on(network))
    }

    #[allow(clippy::too_many_lines)]
    fn parse(
        value: &Json,
        assets: &mut Assets,
        dirs: &[PathBuf],
        remote: Option<&RemoteSetCache>,
    ) -> Result<Self, String> {
        let pairs = object(value, "routing rule set")?;
        let mut tag = None;
        let mut kind = None;
        let mut format = None;
        let mut path = None;
        let mut url = None;
        let mut rules = None;
        for (key, value) in pairs {
            match key.as_str() {
                "tag" => {
                    tag = Some(
                        value
                            .as_str()
                            .filter(|tag| !tag.is_empty())
                            .ok_or_else(|| "routing rule set tag is not a string".to_owned())?
                            .to_owned(),
                    );
                }
                "type" => kind = optional_string(value, "type")?.map(str::to_owned),
                "format" => format = optional_string(value, "format")?.map(str::to_owned),
                "path" => path = optional_string(value, "path")?.map(str::to_owned),
                "url" => url = optional_string(value, "url")?.map(str::to_owned),
                "rules" => rules = Some(value),
                other => return Err(format!("routing rule set field `{other}` is not carried")),
            }
        }
        let tag = tag.ok_or_else(|| "routing rule set has no tag".to_owned())?;
        let kind = kind.unwrap_or_else(|| {
            if rules.is_some() {
                "inline".to_owned()
            } else if url.is_some() {
                "remote".to_owned()
            } else {
                "local".to_owned()
            }
        });
        if let Some(format) = format.as_deref() {
            if !matches!(format, "binary" | "srs" | "source" | "json") {
                return Err(format!(
                    "routing rule set `{tag}` format `{format}` is not carried"
                ));
            }
        }
        let mut body = None;
        let mut bytes = None;
        let mut cache = None;
        let mut staged = None;
        match kind.as_str() {
            "inline" => {
                if format
                    .as_deref()
                    .is_some_and(|format| !matches!(format, "source" | "json"))
                {
                    return Err(format!(
                        "routing rule set `{tag}` names a binary format with inline rules"
                    ));
                }
                body = Some(
                    rules
                        .ok_or_else(|| format!("routing rule set `{tag}` has no rules"))?
                        .clone(),
                );
            }
            "local" | "file" => {
                let path = path.ok_or_else(|| format!("routing rule set `{tag}` has no path"))?;
                let file = resolve_asset_with_queued(&path, dirs)
                    .ok_or_else(|| format!("routing rule set `{tag}` path `{path}` not found"))?;
                bytes = Some(match candidate_cache_bytes(&file) {
                    Some(Ok(bytes)) => bytes,
                    Some(Err(error)) => {
                        return Err(format!("routing rule set `{tag}` cannot be read: {error}"));
                    }
                    None => std::fs::read(&file).map_err(|error| {
                        format!("routing rule set `{tag}` cannot be read: {error}")
                    })?,
                });
            }
            "remote" => {
                let url = url
                    .or_else(|| {
                        path.as_deref()
                            .filter(|path| path.contains("://"))
                            .map(str::to_owned)
                    })
                    .ok_or_else(|| format!("routing rule set `{tag}` has no url"))?;
                let fallback = path
                    .as_deref()
                    .and_then(|path| resolve_asset_with_queued(path, dirs));
                // The configured destination stays logical: the staged path only reads candidate fallback bytes.
                cache = path
                    .as_deref()
                    .and_then(|path| resolve_entry_with_queued(path, dirs))
                    .or_else(|| cache_path(path.as_deref(), dirs))
                    .or_else(|| fallback.clone());
                let fetched = match remote.and_then(|sets| sets.get(&url)) {
                    Some(result) => match result.as_ref() {
                        Ok(fetched) => {
                            staged = Some(fetched.clone());
                            fetched.read()
                        }
                        Err(error) => Err(error.clone()),
                    },
                    None => crate::geodata::fetch_remote(&url),
                };
                match fetched {
                    Ok(fetched) => {
                        bytes = Some(fetched);
                    }
                    Err(error) => {
                        let Some(file) = fallback else {
                            return Err(format!(
                                "routing rule set `{tag}` remote `{url}`: {error}"
                            ));
                        };
                        eprintln!(
                            "routing rule set `{tag}`: {error}; using {}",
                            file.display()
                        );
                        cache = None;
                        bytes = Some(match candidate_cache_bytes(&file) {
                            Some(Ok(bytes)) => bytes,
                            Some(Err(error)) => {
                                return Err(format!(
                                    "routing rule set `{tag}` cannot be read: {error}"
                                ));
                            }
                            None => std::fs::read(&file).map_err(|error| {
                                format!("routing rule set `{tag}` cannot be read: {error}")
                            })?,
                        });
                    }
                }
            }
            other => {
                return Err(format!(
                    "routing rule set `{tag}` type `{other}` is not carried"
                ));
            }
        }
        let rules = if let Some(body) = body {
            parse_source_rules(&body, &tag, assets)?
        } else {
            let bytes = bytes.as_deref().unwrap_or_default();
            let binary = match format.as_deref() {
                Some("binary" | "srs") => true,
                Some("source" | "json") => false,
                Some(other) => {
                    return Err(format!(
                        "routing rule set `{tag}` format `{other}` is not carried"
                    ));
                }
                None => bytes.starts_with(b"SRS"),
            };
            if binary {
                parse_srs(bytes, &tag)?
            } else {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| format!("routing rule set `{tag}` is not UTF-8 JSON"))?;
                let body = crate::json::parse(text.trim())
                    .map_err(|error| format!("routing rule set `{tag}` is not JSON: {error}"))?;
                parse_source_rules(&body, &tag, assets)?
            }
        };
        if let (Some(cache), Some(bytes)) = (cache, bytes) {
            let source = staged.map_or_else(|| CacheBody::Bytes(bytes), CacheBody::Staged);
            if let Err(error) = publish_cache(cache, source) {
                eprintln!("routing rule set `{tag}` cache: {error}");
            }
        }
        Ok(Self { tag, rules })
    }

    fn verdict(&self, flow: &Flow, names: Option<Names<'_>>, addrs: Option<&[IpAddr]>) -> Verdict {
        let mut verdict = Verdict::No;
        for rule in &self.rules {
            match rule.verdict(flow, names, addrs) {
                Verdict::Yes => return Verdict::Yes,
                Verdict::Unknown => verdict = Verdict::Unknown,
                Verdict::No => {}
            }
        }
        verdict
    }

    fn needs_source(&self, network: Network) -> bool {
        self.rules.iter().any(|rule| rule.needs_source(network))
    }

    fn has_domains(&self) -> bool {
        self.rules.iter().any(SetRule::has_domains)
    }
}

impl SetRule {
    #[allow(clippy::too_many_lines)]
    fn parse(value: &Json, assets: &mut Assets) -> Result<Self, String> {
        let pairs = object(value, "routing rule set rule")?;
        let mut kind = None;
        let mut mode = None;
        let mut invert = false;
        let mut nested = None;
        let mut networks = None;
        let mut domains = None;
        let mut ports = None;
        let mut port_ranges = None;
        let mut source_ports = None;
        let mut source_port_ranges = None;
        let mut ips = None;
        let mut source_ips = None;
        let mut process = None;
        for (key, value) in pairs {
            match key.as_str() {
                "type" => kind = optional_string(value, "rule type")?.map(str::to_owned),
                "mode" => mode = optional_string(value, "rule mode")?.map(str::to_owned),
                "invert" => {
                    invert = match value {
                        Json::Bool(flag) => *flag,
                        Json::Null => false,
                        _ => return Err("routing rule set rule invert is not a boolean".to_owned()),
                    };
                }
                "rules" => nested = Some(value),
                "network" => networks = network_list(value)?,
                "domain" => {
                    let matcher = domains.get_or_insert_with(DomainMatcher::new);
                    for item in string_list(value, "domain")?.unwrap_or_default() {
                        let item = item.trim_start_matches('.');
                        let item = if has_domain_prefix(item) {
                            item.to_owned()
                        } else {
                            format!("full:{item}")
                        };
                        add_domain(matcher, &item, assets)?;
                    }
                }
                "domain_suffix" => {
                    let matcher = domains.get_or_insert_with(DomainMatcher::new);
                    for item in string_list(value, "domain_suffix")?.unwrap_or_default() {
                        if !has_domain_prefix(&item) {
                            if let Some(rest) = item.strip_prefix('.') {
                                if rest.is_empty() {
                                    return Err(
                                        "routing rule set rule domain_suffix is empty".to_owned()
                                    );
                                }
                                matcher.add(DomainKind::SuffixOnly, lower_arc(rest))?;
                                continue;
                            }
                        }
                        let item = if has_domain_prefix(&item) {
                            item
                        } else {
                            format!("domain:{item}")
                        };
                        add_domain(matcher, &item, assets)?;
                    }
                }
                "domain_keyword" | "domainKeyword" => {
                    let matcher = domains.get_or_insert_with(DomainMatcher::new);
                    for item in string_list(value, "domain_keyword")?.unwrap_or_default() {
                        add_domain(matcher, &format!("keyword:{item}"), assets)?;
                    }
                }
                "domain_regex" | "domainRegex" => {
                    let matcher = domains.get_or_insert_with(DomainMatcher::new);
                    for item in string_list(value, "domain_regex")?.unwrap_or_default() {
                        add_domain(matcher, &format!("regexp:{item}"), assets)?;
                    }
                }
                "ip_cidr" | "ipCIDR" | "ip" => {
                    if !matches!(value, Json::Null) {
                        ips = Some(ip_matcher(value, &mut *assets, "ip_cidr")?);
                    }
                }
                "source_ip_cidr" | "sourceIP" => {
                    if !matches!(value, Json::Null) {
                        source_ips = Some(ip_matcher(value, &mut *assets, "source_ip_cidr")?);
                    }
                }
                "process_name" | "processName" => {
                    let names = string_list(value, "process_name")?.unwrap_or_default();
                    if !names.is_empty() {
                        process
                            .get_or_insert_with(|| SetProcess {
                                names: Vec::new(),
                                paths: Vec::new(),
                                patterns: Vec::new(),
                            })
                            .names
                            .extend(names);
                    }
                }
                "process_path" | "processPath" => {
                    let paths = string_list(value, "process_path")?.unwrap_or_default();
                    if !paths.is_empty() {
                        process
                            .get_or_insert_with(|| SetProcess {
                                names: Vec::new(),
                                paths: Vec::new(),
                                patterns: Vec::new(),
                            })
                            .paths
                            .extend(paths);
                    }
                }
                "process_path_regex" | "processPathRegex" => {
                    let patterns = string_list(value, "process_path_regex")?.unwrap_or_default();
                    if !patterns.is_empty() {
                        let process = process.get_or_insert_with(|| SetProcess {
                            names: Vec::new(),
                            paths: Vec::new(),
                            patterns: Vec::new(),
                        });
                        for pattern in patterns {
                            process.patterns.push(
                                regex::Regex::new(&pattern)
                                    .map_err(|error| format!("process path regex: {error}"))?,
                            );
                        }
                    }
                }
                "port" => ports = port_set(value, "port")?,
                "port_range" | "portRange" => port_ranges = port_range_set(value, "port_range")?,
                "source_port" => source_ports = port_set(value, "source_port")?,
                "source_port_range" | "sourcePortRange" => {
                    source_port_ranges = port_range_set(value, "source_port_range")?;
                }
                other => {
                    return Err(format!(
                        "routing rule set rule field `{other}` is not carried"
                    ))
                }
            }
        }
        let kind = kind.unwrap_or_else(|| {
            if nested.is_some() {
                "logical".to_owned()
            } else {
                "default".to_owned()
            }
        });
        if kind == "logical" {
            if networks.is_some()
                || domains.is_some()
                || ports.is_some()
                || port_ranges.is_some()
                || source_ports.is_some()
                || source_port_ranges.is_some()
                || ips.is_some()
                || source_ips.is_some()
                || process.is_some()
            {
                return Err("routing logical rule mixes nested rules with selectors".to_owned());
            }
            let mode = mode.ok_or_else(|| "routing logical rule has no mode".to_owned())?;
            let all = match mode.as_str() {
                "and" => true,
                "or" => false,
                other => {
                    return Err(format!(
                        "routing logical rule mode `{other}` is not carried"
                    ))
                }
            };
            let items = nested
                .and_then(Json::as_arr)
                .ok_or_else(|| "routing logical rule has no rules".to_owned())?;
            let rules = items
                .iter()
                .map(|item| SetRule::parse(item, assets))
                .collect::<Result<Vec<_>, _>>()?;
            if rules.is_empty() {
                return Err("routing logical rule has no rules".to_owned());
            }
            return Ok(Self {
                invert,
                logical: Some(SetLogical { all, rules }),
                networks: None,
                domains: None,
                ports: None,
                source_ports: None,
                ips: None,
                source_ips: None,
                process: None,
            });
        }
        if kind != "default" {
            return Err(format!(
                "routing rule set rule type `{kind}` is not carried"
            ));
        }
        if mode.is_some() || nested.is_some() {
            return Err("routing rule set rule mode or rules without type logical".to_owned());
        }
        if let Some(range) = port_ranges {
            ports
                .get_or_insert_with(PortSet::default)
                .ranges
                .extend(range.ranges);
        }
        if let Some(range) = source_port_ranges {
            source_ports
                .get_or_insert_with(PortSet::default)
                .ranges
                .extend(range.ranges);
        }
        if let Some(ports) = ports.as_mut() {
            ports.finish();
        }
        if let Some(ports) = source_ports.as_mut() {
            ports.finish();
        }
        if let Some(matcher) = domains.as_mut() {
            matcher.finish()?;
        }
        if networks.is_none()
            && domains.is_none()
            && ports.is_none()
            && source_ports.is_none()
            && ips.is_none()
            && source_ips.is_none()
            && process.is_none()
        {
            return Err("routing rule set rule names no condition".to_owned());
        }
        Ok(Self {
            invert,
            logical: None,
            networks,
            domains,
            ports,
            source_ports,
            ips,
            source_ips,
            process,
        })
    }

    fn domains(value: &Json, assets: &mut Assets) -> Result<Self, String> {
        let mut matcher = DomainMatcher::new();
        for item in string_list(value, "domain")?.unwrap_or_default() {
            let item = item.trim_start_matches('.');
            let item = if has_domain_prefix(item) {
                item.to_owned()
            } else {
                format!("domain:{item}")
            };
            add_domain(&mut matcher, &item, assets)?;
        }
        matcher.finish()?;
        Ok(Self {
            invert: false,
            logical: None,
            networks: None,
            domains: Some(matcher),
            ports: None,
            source_ports: None,
            ips: None,
            source_ips: None,
            process: None,
        })
    }

    fn addresses(value: &Json, assets: &mut Assets) -> Result<Self, String> {
        Ok(Self {
            invert: false,
            logical: None,
            networks: None,
            domains: None,
            ports: None,
            source_ports: None,
            ips: Some(ip_matcher(value, assets, "ip")?),
            source_ips: None,
            process: None,
        })
    }

    fn verdict(&self, flow: &Flow, names: Option<Names<'_>>, addrs: Option<&[IpAddr]>) -> Verdict {
        let verdict = self.evaluate(flow, names, addrs);
        if self.invert {
            match verdict {
                Verdict::Yes => Verdict::No,
                Verdict::No => Verdict::Yes,
                Verdict::Unknown => Verdict::Unknown,
            }
        } else {
            verdict
        }
    }

    fn evaluate(&self, flow: &Flow, names: Option<Names<'_>>, addrs: Option<&[IpAddr]>) -> Verdict {
        if let Some(logical) = &self.logical {
            let mut verdict = if logical.all {
                Verdict::Yes
            } else {
                Verdict::No
            };
            for rule in &logical.rules {
                match rule.verdict(flow, names, addrs) {
                    Verdict::No if logical.all => return Verdict::No,
                    Verdict::Yes if !logical.all => return Verdict::Yes,
                    Verdict::Unknown => verdict = Verdict::Unknown,
                    _ => {}
                }
            }
            return verdict;
        }
        if let Some(networks) = &self.networks {
            if !networks.contains(&flow.network) {
                return Verdict::No;
            }
        }
        if let Some(ports) = &self.ports {
            if !flow.port.is_some_and(|port| ports.contains(port)) {
                return Verdict::No;
            }
        }
        if let Some(ports) = &self.source_ports {
            if !ports.contains(flow.source_port) {
                return Verdict::No;
            }
        }
        let mut destination_unknown = false;
        if self.domains.is_some() || self.ips.is_some() {
            let mut matched = false;
            if let Some(matcher) = &self.domains {
                match names {
                    Some(names) => {
                        if matcher.matches(names.raw, names.lower()) {
                            matched = true;
                        }
                    }
                    None => destination_unknown = true,
                }
            }
            if !matched {
                if let Some(matcher) = &self.ips {
                    match flow.ip {
                        Some(ip) => matched = matcher.matches(ip),
                        None => match addrs {
                            Some(addrs) => {
                                matched = addrs.iter().any(|ip| matcher.matches(*ip));
                            }
                            None => destination_unknown = true,
                        },
                    }
                }
            }
            if matched {
                destination_unknown = false;
            } else if !destination_unknown {
                return Verdict::No;
            }
        }
        if let Some(matcher) = &self.source_ips {
            if !flow.source.is_some_and(|ip| matcher.matches(ip)) {
                return Verdict::No;
            }
        }
        if let Some(process) = &self.process {
            if !process.matches(flow.process) {
                return Verdict::No;
            }
        }
        if destination_unknown {
            return Verdict::Unknown;
        }
        Verdict::Yes
    }

    fn matches_network(&self, network: Network) -> bool {
        self.networks
            .as_ref()
            .is_none_or(|networks| networks.contains(&network))
    }

    /// Whether any flow on this network can reach this rule, counting an inverted child as reachable.
    fn reachable_on(&self, network: Network) -> bool {
        let Some(logical) = &self.logical else {
            return self.matches_network(network);
        };
        if logical.all {
            logical
                .rules
                .iter()
                .all(|rule| rule.invert || rule.reachable_on(network))
        } else {
            logical
                .rules
                .iter()
                .any(|rule| rule.invert || rule.reachable_on(network))
        }
    }

    /// Whether a flow on `network` could match this rule. An inverted rule can turn a network miss
    /// into a hit, so only a non-inverted branch proves the network is impossible.
    fn can_reach_on(&self, network: Network) -> bool {
        if self.invert {
            let network_only = self.logical.is_none()
                && self.domains.is_none()
                && self.ports.is_none()
                && self.source_ports.is_none()
                && self.ips.is_none()
                && self.source_ips.is_none()
                && self.process.is_none();
            if network_only {
                if let Some(networks) = &self.networks {
                    return !networks.contains(&network);
                }
            }
            return true;
        }
        let Some(logical) = &self.logical else {
            return self.matches_network(network);
        };
        if logical.all {
            logical.rules.iter().all(|rule| rule.can_reach_on(network))
        } else {
            logical.rules.iter().any(|rule| rule.can_reach_on(network))
        }
    }

    fn needs_source(&self, network: Network) -> bool {
        if !self.matches_network(network) {
            return false;
        }
        let Some(logical) = &self.logical else {
            return self.source_ports.is_some() || self.source_ips.is_some();
        };
        if logical.all {
            if logical
                .rules
                .iter()
                .any(|rule| !rule.reachable_on(network) && !rule.invert)
            {
                return false;
            }
            return logical
                .rules
                .iter()
                .any(|rule| rule.reachable_on(network) && rule.needs_source(network));
        }
        logical.rules.iter().any(|rule| rule.needs_source(network))
    }

    fn has_domains(&self) -> bool {
        self.domains.is_some()
            || self
                .logical
                .as_ref()
                .is_some_and(|logical| logical.rules.iter().any(SetRule::has_domains))
    }

    fn has_process(&self) -> bool {
        self.process.is_some()
            || self
                .logical
                .as_ref()
                .is_some_and(|logical| logical.rules.iter().any(SetRule::has_process))
    }
}

#[derive(Debug)]
pub(crate) struct DomainMatcher {
    full: DomainSet,
    suffix: DomainSet,
    suffix_only: DomainSet,
    substr: Vec<Arc<str>>,
    ac: Option<aho_corasick::AhoCorasick>,
    regex: Vec<regex::Regex>,
    adguard: Vec<SuccinctSet>,
}

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';
const SUFFIX_LABEL: u8 = 0x08;
const ANY_LABEL: u8 = b'*';
const MAX_DOMAIN_KEY: usize = 4096;
const MAX_EXPANDED_DOMAIN_BYTES: usize = 64 * 1024 * 1024;

/// A `sing-box` succinct domain trie, kept only for `AdGuard` rule items; ordinary domain items are
/// flattened into the hash tables above so a match never walks a trie.
#[derive(Debug)]
struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<u32>,
    selects: Vec<u32>,
}

impl SuccinctSet {
    fn get_bit(bitmap: &[u64], at: usize) -> bool {
        bitmap
            .get(at / 64)
            .is_some_and(|word| word & (1 << (at % 64)) != 0)
    }

    fn ranks(bitmap: &[u64]) -> Vec<u32> {
        let mut ranks = Vec::with_capacity(bitmap.len() + 1);
        let mut ones = 0u32;
        for word in bitmap {
            ranks.push(ones);
            ones += word.count_ones();
        }
        ranks.push(ones);
        ranks
    }

    fn selects(bitmap: &[u64]) -> Vec<u32> {
        let mut selects = Vec::new();
        for (word_at, word) in bitmap.iter().enumerate() {
            let mut word = *word;
            while word != 0 {
                selects.push((word_at * 64 + word.trailing_zeros() as usize) as u32);
                word &= word - 1;
            }
        }
        selects
    }

    fn count_zeros(&self, at: usize) -> usize {
        let word = at / 64;
        let rank = self.ranks.get(word).copied().unwrap_or(0) as usize;
        let bits = self.label_bitmap.get(word).copied().unwrap_or(0) & ((1u64 << (at % 64)) - 1);
        at - rank - bits.count_ones() as usize
    }

    fn select(&self, index: usize) -> Option<usize> {
        self.selects.get(index).map(|value| *value as usize)
    }

    fn has_adguard(&self, key: &[u8], node: usize, bit: usize, depth: usize) -> bool {
        let mut failed = std::collections::HashSet::new();
        self.has_adguard_at(key, 0, node, bit, depth, &mut failed)
    }

    fn has_adguard_at(
        &self,
        key: &[u8],
        offset: usize,
        node: usize,
        bit: usize,
        depth: usize,
        failed: &mut std::collections::HashSet<(usize, usize, usize, usize)>,
    ) -> bool {
        let state = (offset, node, bit, depth);
        if failed.contains(&state) {
            return false;
        }
        let found = self.has_adguard_step(key, offset, node, bit, depth, failed);
        if !found {
            failed.insert(state);
        }
        found
    }

    fn has_adguard_step(
        &self,
        key: &[u8],
        offset: usize,
        node: usize,
        bit: usize,
        depth: usize,
        failed: &mut std::collections::HashSet<(usize, usize, usize, usize)>,
    ) -> bool {
        if depth > 100 {
            return false;
        }
        let mut node = node;
        let mut bit = bit;
        for at in offset..key.len() {
            let current = key[at];
            loop {
                if Self::get_bit(&self.label_bitmap, bit) {
                    return false;
                }
                let Some(&label) = self.labels.get(bit - node) else {
                    return false;
                };
                if label == PREFIX_LABEL {
                    return true;
                }
                if label == ROOT_LABEL {
                    let next = self.count_zeros(bit + 1);
                    if current == b'.' && Self::get_bit(&self.leaves, next) {
                        return true;
                    }
                }
                if label == current {
                    break;
                }
                if label == ANY_LABEL || label == SUFFIX_LABEL {
                    let next = self.count_zeros(bit + 1);
                    let Some(next_bit) = self.select(next - 1).map(|value| value + 1) else {
                        return false;
                    };
                    if self.has_adguard_at(key, at, next, next_bit, depth + 1, failed) {
                        return true;
                    }
                    for end in at + 1..=key.len() {
                        if self.has_adguard_at(key, end, next, next_bit, depth + 1, failed) {
                            return true;
                        }
                    }
                }
                bit += 1;
            }
            node = self.count_zeros(bit + 1);
            let Some(next) = self.select(node - 1) else {
                return false;
            };
            bit = next + 1;
        }
        if Self::get_bit(&self.leaves, node) {
            return true;
        }
        loop {
            if Self::get_bit(&self.label_bitmap, bit) {
                return false;
            }
            let Some(&label) = self.labels.get(bit - node) else {
                return false;
            };
            if label == PREFIX_LABEL || label == ROOT_LABEL || label == SUFFIX_LABEL {
                return true;
            }
            if label == ANY_LABEL {
                let next = self.count_zeros(bit + 1);
                let Some(next_bit) = self.select(next - 1).map(|value| value + 1) else {
                    return false;
                };
                return self.has_adguard_at(key, key.len(), next, next_bit, depth + 1, failed);
            }
            bit += 1;
        }
    }

    fn matches_adguard(&self, domain: &str) -> bool {
        let key: Vec<u8> = reverse_domain(domain).into_bytes();
        if self.has_adguard(&key, 0, 0, 0) {
            return true;
        }
        let mut key = key;
        loop {
            let mut anchored = Vec::with_capacity(key.len() + 1);
            anchored.push(SUFFIX_LABEL);
            anchored.extend_from_slice(&key);
            if self.has_adguard(&anchored, 0, 0, 0) {
                return true;
            }
            let Some(dot) = key.iter().position(|&byte| byte == b'.') else {
                return false;
            };
            key.drain(..=dot);
        }
    }

    fn walk_keys(
        &self,
        budget: usize,
        visit: &mut impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut expanded = 0usize;
        let mut counted = |key: &[u8]| {
            expanded = expanded
                .checked_add(key.len())
                .filter(|total| *total <= budget)
                .ok_or_else(|| "SRS domain keys expand past the body budget".to_owned())?;
            visit(key)
        };
        if Self::get_bit(&self.leaves, 0) {
            counted(b"")?;
        }
        self.walk(0, 0, &mut Vec::new(), &mut counted)
    }

    fn walk(
        &self,
        node: usize,
        bit: usize,
        current: &mut Vec<u8>,
        visit: &mut impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        #[derive(Clone, Copy)]
        struct Frame {
            node: usize,
            bit: usize,
        }
        let mut stack = vec![Frame { node, bit }];
        while let Some(frame) = stack.last().copied() {
            let bit = frame.bit;
            if Self::get_bit(&self.label_bitmap, bit) {
                stack.pop();
                if !stack.is_empty() {
                    current.pop();
                }
                continue;
            }
            let Some(&label) = self.labels.get(bit - frame.node) else {
                stack.pop();
                if !stack.is_empty() {
                    current.pop();
                }
                continue;
            };
            current.push(label);
            if current.len() > MAX_DOMAIN_KEY {
                return Err("SRS domain key is too long".to_owned());
            }
            let next = self.count_zeros(bit + 1);
            let Some(next_bit) = self.select(next - 1).map(|value| value + 1) else {
                current.pop();
                if let Some(parent) = stack.last_mut() {
                    parent.bit += 1;
                }
                continue;
            };
            if Self::get_bit(&self.leaves, next) {
                visit(current)?;
            }
            if let Some(parent) = stack.last_mut() {
                parent.bit += 1;
            }
            stack.push(Frame {
                node: next,
                bit: next_bit,
            });
        }
        Ok(())
    }
}

/// Full and suffix names as an open-addressed table keyed by a suffix hash. Hashing one byte at a
/// time from the right means the hash of every parent domain falls out of a single pass over the
/// name, so a match never allocates a label or hashes the same bytes twice. The string is compared
/// on a hash hit, never trusting the hash alone.
#[derive(Debug, Default)]
struct DomainSet {
    entries: Vec<(u64, Arc<str>)>,
    slots: Vec<u32>,
    mask: usize,
}

/// The hash of a name, folded from its last byte to its first. Two names that share a suffix share
/// a prefix of these states, which is what makes the parent lookups fall out of one pass.
fn suffix_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0u64;
    for &byte in bytes.iter().rev() {
        hash = hash
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(u64::from(byte));
    }
    hash
}

fn hash_slot(hash: u64) -> u64 {
    let mut mixed = hash ^ (hash >> 33);
    mixed = mixed.wrapping_mul(0xff51_afd7_ed55_8ccd);
    mixed ^ (mixed >> 33)
}

impl DomainSet {
    fn insert(&mut self, value: Arc<str>) {
        self.entries.push((suffix_hash(value.as_bytes()), value));
    }

    fn finish(&mut self) {
        self.entries.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.as_ref().cmp(right.1.as_ref()))
        });
        self.entries
            .dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        let mut capacity = 8;
        while capacity < self.entries.len().saturating_mul(2) {
            capacity <<= 1;
        }
        self.mask = capacity - 1;
        self.slots = vec![0; capacity];
        for (at, &(hash, _)) in self.entries.iter().enumerate() {
            let mut slot = hash_slot(hash) as usize & self.mask;
            while self.slots[slot] != 0 {
                slot = (slot + 1) & self.mask;
            }
            self.slots[slot] = at as u32 + 1;
        }
    }

    fn contains(&self, hash: u64, value: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let mut slot = hash_slot(hash) as usize & self.mask;
        loop {
            let at = self.slots[slot];
            if at == 0 {
                return false;
            }
            let (entry_hash, entry) = &self.entries[at as usize - 1];
            if *entry_hash == hash && entry.as_ref() == value {
                return true;
            }
            slot = (slot + 1) & self.mask;
        }
    }

    #[cfg(test)]
    fn first(&self) -> Option<&Arc<str>> {
        self.entries.first().map(|(_, value)| value)
    }
}

#[cfg(test)]
std::thread_local! {
    static DOMAIN_TABLE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl DomainMatcher {
    pub(crate) fn new() -> Self {
        Self {
            full: DomainSet::default(),
            suffix: DomainSet::default(),
            suffix_only: DomainSet::default(),
            substr: Vec::new(),
            ac: None,
            regex: Vec::new(),
            adguard: Vec::new(),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), String> {
        self.full.finish();
        self.suffix.finish();
        self.suffix_only.finish();
        if !self.substr.is_empty() {
            self.ac = Some(
                aho_corasick::AhoCorasick::new(self.substr.iter().map(|value| value.as_bytes()))
                    .map_err(|error| format!("domain keyword matcher: {error}"))?,
            );
        }
        Ok(())
    }

    fn add(&mut self, kind: DomainKind, value: Arc<str>) -> Result<(), String> {
        match kind {
            DomainKind::Substr => self.substr.push(value),
            DomainKind::Domain => self.suffix.insert(value),
            DomainKind::SuffixOnly => self.suffix_only.insert(value),
            DomainKind::Full => self.full.insert(value),
            DomainKind::Regex => {
                let regex = regex::Regex::new(value.as_ref())
                    .map_err(|error| format!("invalid domain regex `{value}`: {error}"))?;
                self.regex.push(regex);
            }
        }
        Ok(())
    }

    pub(crate) fn only_matches(&self, domain: &str) -> bool {
        !self.full.entries.is_empty()
            && self
                .full
                .entries
                .iter()
                .all(|(_, value)| value.eq_ignore_ascii_case(domain))
            && self.suffix.entries.is_empty()
            && self.suffix_only.entries.is_empty()
            && self.substr.is_empty()
            && self.regex.is_empty()
            && self.adguard.is_empty()
    }

    pub(crate) fn matches(&self, host: &str, lower: &str) -> bool {
        #[cfg(test)]
        DOMAIN_TABLE_READS.with(|reads| reads.set(reads.get() + 1));
        let bytes = lower.as_bytes();
        let mut hash = 0u64;
        for at in (0..bytes.len()).rev() {
            if bytes[at] == b'.'
                && (self.suffix.contains(hash, &lower[at + 1..])
                    || self.suffix_only.contains(hash, &lower[at + 1..]))
            {
                return true;
            }
            hash = hash
                .wrapping_mul(0x9e37_79b1_85eb_ca87)
                .wrapping_add(u64::from(bytes[at]));
        }
        if self.suffix.contains(hash, lower) || self.full.contains(hash, lower) {
            return true;
        }
        if self.ac.as_ref().is_some_and(|ac| ac.is_match(lower)) {
            return true;
        }
        if self.regex.iter().any(|regex| regex.is_match(host)) {
            return true;
        }
        self.adguard.iter().any(|set| set.matches_adguard(lower))
    }
}

#[derive(Debug, Clone, Copy)]
enum DomainKind {
    Substr,
    Regex,
    Domain,
    SuffixOnly,
    Full,
}

#[derive(Debug, Clone)]
pub(crate) struct IpMatcher {
    sets: Vec<(RangeSet, bool)>,
}

impl IpMatcher {
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        self.sets
            .iter()
            .any(|(set, reverse)| set.matches(ip, *reverse))
    }

    /// The parsed sets as inclusive address ranges, for a consumer outside this module.
    pub(crate) fn ranges(&self) -> Vec<(Vec<(IpAddr, IpAddr)>, bool)> {
        self.sets
            .iter()
            .map(|(set, reverse)| (set.ranges(), *reverse))
            .collect()
    }

    /// Whether any set holds a range wider than one address, so its order follows the reference's buckets.
    pub(crate) fn has_buckets(&self) -> bool {
        self.sets.iter().any(|(set, _)| set.has_buckets())
    }

    /// Match with a Lua userdata's reverse override or pending flip, without cloning the parsed sets.
    pub(crate) fn matches_override(&self, ip: IpAddr, reverse: Option<bool>, flip: bool) -> bool {
        self.sets.iter().any(|(set, own)| {
            let reverse = reverse.unwrap_or(if flip { !*own } else { *own });
            set.matches(ip, reverse)
        })
    }

    /// A list matches only when one set, with its own reverse applied, accepts every address.
    pub(crate) fn matches_all_override(
        &self,
        ips: &[IpAddr],
        reverse: Option<bool>,
        flip: bool,
    ) -> bool {
        !ips.is_empty()
            && self.sets.iter().any(|(set, own)| {
                let reverse = reverse.unwrap_or(if flip { !*own } else { *own });
                ips.iter().all(|ip| set.matches(*ip, reverse))
            })
    }
}

#[derive(Debug, Default, Clone)]
struct RangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    mapped: Vec<(u128, u128)>,
    mapped_wide: Vec<(u128, u128)>,
}

impl RangeSet {
    fn has_buckets(&self) -> bool {
        self.v4.iter().any(|(start, end)| start != end)
            || self.v6.iter().any(|(start, end)| start != end)
    }

    fn add(&mut self, ip: IpAddr, prefix: u32) -> Result<(), String> {
        match ip {
            IpAddr::V4(ip) => {
                if prefix > 32 {
                    return Err(format!("CIDR prefix {prefix} exceeds 32"));
                }
                let host = u32::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let start = host & mask;
                self.v4.push((start, start | !mask));
            }
            IpAddr::V6(ip) => {
                if prefix > 128 {
                    return Err(format!("CIDR prefix {prefix} exceeds 128"));
                }
                let host = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let start = host & mask;
                let end = start | !mask;
                self.v6.push((start, end));
                if start >= MAPPED_BASE && end <= MAPPED_BASE + u128::from(u32::MAX) {
                    self.mapped.push((start, end));
                } else if end >= MAPPED_BASE && start <= MAPPED_BASE + u128::from(u32::MAX) {
                    self.mapped_wide.push((start, end));
                }
            }
        }
        Ok(())
    }

    /// Add an arbitrary IPv6 range, classing the part inside the mapped block so a mapped input matches it.
    fn add_v6_range(&mut self, start: u128, end: u128) -> Result<(), String> {
        if end < start {
            return Err("IPv6 range is not a range".to_owned());
        }
        self.v6.push((start, end));
        let mapped_end = MAPPED_BASE + u128::from(u32::MAX);
        if start >= MAPPED_BASE && end <= mapped_end {
            self.mapped.push((start, end));
        } else if start <= mapped_end && end >= MAPPED_BASE {
            self.mapped_wide.push((start, end));
        }
        Ok(())
    }

    fn finish(&mut self) {
        self.v4.sort_unstable();
        self.v4 = merge(&self.v4);
        self.v6.sort_unstable();
        self.v6 = merge(&self.v6);
        self.mapped.sort_unstable();
        self.mapped = merge(&self.mapped);
        self.mapped_wide.sort_unstable();
        self.mapped_wide = merge(&self.mapped_wide);
    }

    fn ranges(&self) -> Vec<(IpAddr, IpAddr)> {
        self.v4
            .iter()
            .map(|(start, end)| {
                (
                    IpAddr::V4(std::net::Ipv4Addr::from(*start)),
                    IpAddr::V4(std::net::Ipv4Addr::from(*end)),
                )
            })
            .chain(self.v6.iter().map(|(start, end)| {
                (
                    IpAddr::V6(std::net::Ipv6Addr::from(*start)),
                    IpAddr::V6(std::net::Ipv6Addr::from(*end)),
                )
            }))
            .collect()
    }

    fn matches(&self, ip: IpAddr, reverse: bool) -> bool {
        let mut named = false;
        let mut hit = false;
        match ip {
            IpAddr::V4(ip) => {
                if !self.v4.is_empty() {
                    named = true;
                    hit = contains(&self.v4, u32::from(ip));
                }
                let mapped = u128::from(ip.to_ipv6_mapped());
                if !self.mapped.is_empty() {
                    named = true;
                    hit |= contains(&self.mapped, mapped);
                }
            }
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => {
                    if !self.v4.is_empty() {
                        named = true;
                        hit = contains(&self.v4, u32::from(ip));
                    }
                    let mapped = u128::from(ip.to_ipv6_mapped());
                    if !self.mapped.is_empty() {
                        named = true;
                        hit |= contains(&self.mapped, mapped);
                    }
                    if !self.mapped_wide.is_empty() {
                        named = true;
                        hit |= contains(&self.mapped_wide, mapped);
                    }
                }
                None => {
                    if !self.v6.is_empty() {
                        named = true;
                        hit |= contains(&self.v6, u128::from(ip));
                    }
                }
            },
        }
        named && hit != reverse
    }
}

fn merge<T>(ranges: &[(T, T)]) -> Vec<(T, T)>
where
    T: Copy + Ord + std::ops::Sub<Output = T> + From<u8>,
{
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        match out.last_mut() {
            // `start > last_end` guards the subtraction, so a range ending at `T::MAX` cannot overflow.
            Some((_, last_end)) if start <= *last_end || start - *last_end == T::from(1) => {
                *last_end = (*last_end).max(end);
            }
            _ => out.push((start, end)),
        }
    }
    out
}

fn contains<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> bool {
    let at = ranges.partition_point(|&(_, end)| end < value);
    ranges.get(at).is_some_and(|&(start, _)| start <= value)
}

/// `::ffff:0:0/96`, the block whose ranges also name IPv4 addresses.
const MAPPED_BASE: u128 = 0xffff_0000_0000;

#[derive(Debug, Default)]
struct PortSet {
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    fn finish(&mut self) {
        self.ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(self.ranges.len());
        for &(start, end) in &self.ranges {
            match merged.last_mut() {
                Some((_, last_end)) if start <= last_end.saturating_add(1) => {
                    *last_end = (*last_end).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        self.ranges = merged;
    }

    fn contains(&self, port: u16) -> bool {
        let at = self.ranges.partition_point(|&(_, end)| end < port);
        self.ranges.get(at).is_some_and(|&(start, _)| start <= port)
    }
}

pub(crate) fn object<'a>(value: &'a Json, what: &str) -> Result<&'a [(String, Json)], String> {
    match value {
        Json::Obj(pairs) => Ok(pairs),
        _ => Err(format!("{what} is not an object")),
    }
}

fn string_list(value: &Json, field: &str) -> Result<Option<Vec<String>>, String> {
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let items = if let Some(text) = value.as_str() {
        text.split(',').map(str::to_owned).collect()
    } else if let Some(items) = value.as_arr() {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(
                item.as_str()
                    .ok_or_else(|| format!("routing {field} has a value that is not a string"))?
                    .to_owned(),
            );
        }
        out
    } else {
        return Err(format!("routing {field} is not a string or array"));
    };
    Ok((!items.is_empty()).then_some(items))
}

fn network_list(value: &Json) -> Result<Option<Vec<Network>>, String> {
    let Some(items) = string_list(value, "network")? else {
        return Ok(None);
    };
    Ok(Some(
        items.iter().map(|item| Network::parse(item)).collect(),
    ))
}

fn port_set(value: &Json, field: &str) -> Result<Option<PortSet>, String> {
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let mut set = PortSet::default();
    if let Some(number) = value.as_u32() {
        let port =
            u16::try_from(number).map_err(|_| format!("routing {field} {number} exceeds 65535"))?;
        set.ranges.push((port, port));
    } else if let Some(items) = value.as_arr() {
        for item in items {
            if let Some(number) = item.as_u32() {
                let port = u16::try_from(number)
                    .map_err(|_| format!("routing {field} {number} exceeds 65535"))?;
                set.ranges.push((port, port));
            } else if let Some(text) = item.as_str() {
                add_port_pieces(&mut set, text, field)?;
            } else {
                return Err(format!("routing {field} has a value that is not a port"));
            }
        }
    } else if let Some(text) = value.as_str() {
        add_port_pieces(&mut set, text, field)?;
    } else {
        return Err(format!("routing {field} is not a number, string or array"));
    }
    set.finish();
    Ok(Some(set))
}

fn add_port_pieces(set: &mut PortSet, text: &str, field: &str) -> Result<(), String> {
    for piece in text.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let resolved;
        let piece = match piece.strip_prefix("env:") {
            Some(name) => {
                resolved = std::env::var(name).unwrap_or_default();
                resolved.trim()
            }
            None => piece,
        };
        if piece.is_empty() {
            continue;
        }
        let (from, to) = match piece.split_once('-') {
            Some((from, to)) => (from, to),
            None => (piece, piece),
        };
        let from = parse_port(from, field)?;
        let to = parse_port(to, field)?;
        if from > to {
            return Err(format!("routing {field} range `{piece}` counts down"));
        }
        set.ranges.push((from, to));
    }
    Ok(())
}

fn port_range_set(value: &Json, field: &str) -> Result<Option<PortSet>, String> {
    if matches!(value, Json::Null) {
        return Ok(None);
    }
    let mut set = PortSet::default();
    let mut pieces = Vec::new();
    if let Some(text) = value.as_str() {
        pieces.extend(text.split(',').map(str::to_owned));
    } else if let Some(items) = value.as_arr() {
        for item in items {
            pieces.push(
                item.as_str()
                    .ok_or_else(|| format!("routing {field} has a value that is not a string"))?
                    .to_owned(),
            );
        }
    } else {
        return Err(format!("routing {field} is not a string or array"));
    }
    for piece in pieces {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let (from, to) = piece
            .split_once(':')
            .ok_or_else(|| format!("routing {field} range `{piece}` has no colon"))?;
        let from = if from.is_empty() {
            0
        } else {
            parse_port(from, field)?
        };
        let to = if to.is_empty() {
            u16::MAX
        } else {
            parse_port(to, field)?
        };
        if from > to {
            return Err(format!("routing {field} range `{piece}` counts down"));
        }
        set.ranges.push((from, to));
    }
    set.finish();
    Ok(Some(set))
}

fn parse_port(text: &str, field: &str) -> Result<u16, String> {
    let number = text
        .parse::<u32>()
        .map_err(|_| format!("routing {field} `{text}` is not a port"))?;
    u16::try_from(number).map_err(|_| format!("routing {field} {number} exceeds 65535"))
}

pub(crate) fn local_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn domain_matcher(value: &Json, assets: &mut Assets) -> Result<DomainMatcher, String> {
    let Some(items) = string_list(value, "domain")? else {
        return Err("routing domain is null".into());
    };
    let mut matcher = DomainMatcher::new();
    for item in items {
        add_domain(&mut matcher, &item, assets)?;
    }
    matcher.finish()?;
    Ok(matcher)
}

/// A lowercased name, allocated once when it carries uppercase and borrowed into an `Arc` otherwise.
fn lower_arc(text: &str) -> Arc<str> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Arc::from(text.to_ascii_lowercase())
    } else {
        Arc::from(text)
    }
}

fn has_domain_prefix(value: &str) -> bool {
    [
        "domain:",
        "full:",
        "keyword:",
        "regexp:",
        "dotless:",
        "geosite:",
        "ext:",
        "ext-domain:",
        "ext-site:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

pub(crate) fn add_domain(
    matcher: &mut DomainMatcher,
    value: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    if value.starts_with('!') {
        return Err(format!(
            "domain rule `{value}`: domains have no reverse form"
        ));
    }
    if let Some(rest) = value.strip_prefix("geosite:") {
        return add_geosite(matcher, "geosite.dat", rest, assets);
    }
    for prefix in ["ext:", "ext-domain:", "ext-site:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let (file, code) = rest
                .split_once(':')
                .ok_or_else(|| format!("domain rule `{value}`: expected file:code"))?;
            return add_geosite(matcher, file, code, assets);
        }
    }
    if let Some(rest) = value.strip_prefix("regexp:") {
        if rest.is_empty() {
            return Err("domain rule `regexp:` names an empty pattern".into());
        }
        let regex =
            regex::Regex::new(rest).map_err(|error| format!("domain rule `{value}`: {error}"))?;
        matcher.regex.push(regex);
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("domain:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.suffix.insert(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("full:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.full.insert(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("keyword:") {
        if rest.is_empty() {
            return Err(format!("domain rule `{value}` is empty"));
        }
        matcher.substr.push(lower_arc(rest));
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("dotless:") {
        let pattern = match rest {
            "" => "^[^.]*$".to_owned(),
            substr if !substr.contains('.') => format!("^[^.]*{substr}[^.]*$"),
            _ => {
                return Err(format!(
                    "domain rule `{value}`: the substr cannot contain a dot"
                ))
            }
        };
        let regex = regex::Regex::new(&pattern)
            .map_err(|error| format!("domain rule `{value}`: {error}"))?;
        matcher.regex.push(regex);
        return Ok(());
    }
    if value.is_empty() {
        return Err("domain rule is empty".into());
    }
    matcher.substr.push(lower_arc(value));
    Ok(())
}

fn add_geosite(
    matcher: &mut DomainMatcher,
    file: &str,
    code_with_attrs: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    if file.is_empty() {
        return Err("domain rule names an empty asset file".into());
    }
    if code_with_attrs.ends_with('@') || code_with_attrs.contains("@@") {
        return Err(format!(
            "domain rule `{file}:{code_with_attrs}` has an empty attr"
        ));
    }
    let (code, attrs) = match code_with_attrs.split_once('@') {
        Some((code, attrs)) => (code, attrs),
        None => (code_with_attrs, ""),
    };
    if code.is_empty() {
        return Err(format!("domain rule `{file}:` names an empty code"));
    }
    let attrs = attrs.to_ascii_lowercase();
    for entry in assets.site(file, code, &attrs)?.iter() {
        if let Err(error) = matcher.add(entry.kind, Arc::clone(&entry.value)) {
            eprintln!("routing: ignoring an invalid geosite regex: {error}");
        }
    }
    Ok(())
}

pub(crate) fn ip_matcher(
    value: &Json,
    assets: &mut Assets,
    field: &str,
) -> Result<IpMatcher, String> {
    let Some(items) = string_list(value, field)? else {
        return Err(format!("{field} is null"));
    };
    let mut positive = RangeSet::default();
    let mut negative = RangeSet::default();
    for item in items {
        add_ip_rule(&mut positive, &mut negative, &item, assets)?;
    }
    positive.finish();
    negative.finish();
    let mut sets = Vec::new();
    if !positive.v4.is_empty() || !positive.v6.is_empty() {
        sets.push((positive, false));
    }
    if !negative.v4.is_empty() || !negative.v6.is_empty() {
        sets.push((negative, true));
    }
    if sets.is_empty() {
        return Err(format!("{field} names no address"));
    }
    Ok(IpMatcher { sets })
}

fn add_ip_rule(
    positive: &mut RangeSet,
    negative: &mut RangeSet,
    value: &str,
    assets: &mut Assets,
) -> Result<(), String> {
    let mut value = value;
    let mut reverse = false;
    while let Some(rest) = value.strip_prefix('!') {
        value = rest;
        reverse = !reverse;
    }
    if let Some(rest) = value.strip_prefix("geoip:") {
        if rest.eq_ignore_ascii_case("private") {
            return add_private(positive, negative, reverse);
        }
        return add_geoip(positive, negative, "geoip.dat", rest, reverse, assets);
    }
    for prefix in ["ext:", "ext-ip:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let (file, code) = rest
                .split_once(':')
                .ok_or_else(|| format!("ip rule `{value}`: expected file:code"))?;
            if file.eq_ignore_ascii_case("geoip.dat") && code.eq_ignore_ascii_case("private") {
                return add_private(positive, negative, reverse);
            }
            return add_geoip(positive, negative, file, code, reverse, assets);
        }
    }
    let (ip, prefix) = parse_cidr(value)?;
    let mut set = RangeSet::default();
    match ip {
        IpAddr::V4(ip) => set.add(IpAddr::V4(ip), prefix)?,
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            // A mapped prefix at 96+ keeps its IPv6 range too, so a reverse rule names native IPv6 the same way a GeoIP mapped range does.
            Some(_) if prefix >= 96 => set.add(IpAddr::V6(ip), prefix)?,
            // Shorter mapped prefixes are the IPv4 prefix in a mapped spelling, as they were before.
            Some(v4) if prefix <= 32 => set.add(IpAddr::V4(v4), prefix)?,
            // Prefixes 33 through 95 cannot name an IPv4 width; they stay the IPv6 range they spell.
            _ => set.add(IpAddr::V6(ip), prefix)?,
        },
    }
    let target = if reverse { negative } else { positive };
    target.v4.extend(set.v4);
    target.v6.extend(set.v6);
    target.mapped.extend(set.mapped);
    target.mapped_wide.extend(set.mapped_wide);
    Ok(())
}

/// The reference's built-in `geoip:private` set, so a config that names it does not need a
/// `geoip.dat` on disk before a final rule can refuse a private destination.
const PRIVATE_IPV4_RULES: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),
    ([0, 0, 0, 0], 32),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 29),
    ([192, 0, 0, 8], 32),
    ([192, 0, 0, 9], 32),
    ([192, 0, 0, 10], 32),
    ([192, 0, 0, 170], 32),
    ([192, 0, 0, 171], 32),
    ([192, 0, 2, 0], 24),
    ([192, 52, 193, 0], 24),
    ([192, 88, 99, 2], 32),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
    ([224, 0, 0, 0], 4),
];

const PRIVATE_IPV6_RULES: &[&str] = &[
    "::1/128",
    "::/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/32",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:1::3/128",
    "2001:2::/48",
    "2001:3::/32",
    "2001:20::/28",
    "2001:30::/28",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

fn add_private(
    positive: &mut RangeSet,
    negative: &mut RangeSet,
    reverse: bool,
) -> Result<(), String> {
    let target = if reverse { negative } else { positive };
    for &(octets, prefix) in PRIVATE_IPV4_RULES {
        target.add(
            IpAddr::V4(std::net::Ipv4Addr::from(octets)),
            u32::from(prefix),
        )?;
    }
    for rule in PRIVATE_IPV6_RULES {
        let (ip, prefix) = parse_cidr(rule)?;
        target.add(ip, prefix)?;
    }
    Ok(())
}

fn add_geoip(
    positive: &mut RangeSet,
    negative: &mut RangeSet,
    file: &str,
    code: &str,
    reverse: bool,
    assets: &mut Assets,
) -> Result<(), String> {
    if file.is_empty() {
        return Err("ip rule names an empty asset file".into());
    }
    let mut code = code;
    let mut reverse = reverse;
    while let Some(rest) = code.strip_prefix('!') {
        code = rest;
        reverse = !reverse;
    }
    if code.is_empty() {
        return Err(format!("ip rule `{file}:` names an empty code"));
    }
    if file.eq_ignore_ascii_case("geoip.dat") && code.eq_ignore_ascii_case("private") {
        return add_private(positive, negative, reverse);
    }
    let target = if reverse { negative } else { positive };
    for (ip, prefix) in assets.ip(file, code)?.iter() {
        target.add(*ip, *prefix)?;
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u32), String> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (value, None),
    };
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("ip rule `{value}` is not an address"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u32>()
            .map_err(|_| format!("ip rule `{value}` has a prefix that is not a number"))?,
        None => max,
    };
    if prefix > max {
        return Err(format!("ip rule `{value}` prefix exceeds {max}"));
    }
    Ok((ip, prefix))
}

#[derive(Debug)]
struct DomainEntry {
    kind: DomainKind,
    value: Arc<str>,
}

type SiteCache = HashMap<(String, String, String), Arc<Vec<DomainEntry>>>;
type IpCache = HashMap<(String, String), Arc<Vec<(IpAddr, u32)>>>;

/// A container read as an immutable snapshot in a private mapping: a freed large `Vec` can stay
/// resident, while dropping the mapping returns the pages to the kernel.
#[cfg(unix)]
pub(crate) struct AssetBytes {
    ptr: *mut u8,
    len: usize,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
const MAP_ANON: libc::c_int = libc::MAP_ANONYMOUS;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const MAP_ANON: libc::c_int = libc::MAP_ANON;

#[cfg(unix)]
impl AssetBytes {
    fn read(path: &Path) -> Result<Self, String> {
        let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let len = usize::try_from(file.metadata().map_err(|error| error.to_string())?.len())
            .map_err(|_| "asset is larger than this address space".to_owned())?;
        if len == 0 {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len,
            });
        }
        // SAFETY: an anonymous private mapping is writable and private to this process; its descriptor is ignored.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let buffer = Self {
            ptr: ptr.cast(),
            len,
        };
        // SAFETY: the mapping is `len` writable bytes that nothing else aliases.
        let target = unsafe { std::slice::from_raw_parts_mut(buffer.ptr, len) };
        file.read_exact(target).map_err(|error| error.to_string())?;
        Ok(buffer)
    }
}

#[cfg(unix)]
impl std::ops::Deref for AssetBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: the mapping is `len` readable bytes for the life of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(unix)]
impl Drop for AssetBytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the pointer and length are the ones `mmap` returned.
            unsafe {
                libc::munmap(self.ptr.cast(), self.len);
            }
        }
    }
}

// SAFETY: the mapping is immutable after `read`, and `Drop` needs exclusive ownership.
#[cfg(unix)]
unsafe impl Send for AssetBytes {}
#[cfg(unix)]
unsafe impl Sync for AssetBytes {}

#[cfg(not(unix))]
pub(crate) struct AssetBytes {
    bytes: Vec<u8>,
}

#[cfg(not(unix))]
impl AssetBytes {
    fn read(path: &Path) -> Result<Self, String> {
        Ok(Self {
            bytes: std::fs::read(path).map_err(|error| error.to_string())?,
        })
    }
}

#[cfg(not(unix))]
impl std::ops::Deref for AssetBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A prefetched remote body, normally on disk so a refresh holds one response at a time rather than
/// every URL's bytes in RAM. A response that cannot be staged stays in memory rather than being
/// mistaken for a failed fetch. The temporary directory is removed when the last clone is dropped.
#[derive(Clone)]
pub(crate) struct RemoteBody {
    temp: Option<Arc<RemoteTemp>>,
    memory: Option<Arc<Vec<u8>>>,
}

struct RemoteTemp {
    dir: PathBuf,
}

impl RemoteTemp {
    fn create() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |stamp| stamp.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "ferrox-rule-set-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|error| format!("stage remote rule set: {error}"))?;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("body"))
        {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("stage remote rule set: {error}"));
            }
        };
        drop(file);
        Ok(Self { dir })
    }

    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.dir.join("body"))
            .map_err(|error| format!("stage remote rule set: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("stage remote rule set: {error}"))
    }

    fn read(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::fs::File::open(self.dir.join("body"))
            .map_err(|error| format!("read staged rule set: {error}"))?
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read staged rule set: {error}"))?;
        Ok(bytes)
    }
}

impl Drop for RemoteTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl RemoteBody {
    fn stage(bytes: &[u8]) -> Result<Self, String> {
        let temp = RemoteTemp::create()?;
        temp.write(bytes)?;
        Ok(Self {
            temp: Some(Arc::new(temp)),
            memory: None,
        })
    }

    fn memory(bytes: Vec<u8>) -> Self {
        Self {
            temp: None,
            memory: Some(Arc::new(bytes)),
        }
    }

    fn read(&self) -> Result<Vec<u8>, String> {
        if let Some(temp) = &self.temp {
            return temp.read();
        }
        self.memory
            .as_ref()
            .map(|bytes| (**bytes).clone())
            .ok_or_else(|| "staged rule set is closed".to_owned())
    }
}

pub(crate) type RemoteSetCache = HashMap<String, Result<RemoteBody, String>>;

pub(crate) type AssetCache = Arc<std::sync::Mutex<HashMap<PathBuf, Arc<AssetBytes>>>>;

pub(crate) struct Assets {
    dirs: Vec<PathBuf>,
    files: HashMap<PathBuf, Arc<AssetBytes>>,
    shared: Option<AssetCache>,
    sites: SiteCache,
    ips: IpCache,
}

impl Assets {
    pub(crate) fn new(dirs: Vec<PathBuf>) -> Self {
        Self {
            dirs,
            files: HashMap::new(),
            shared: None,
            sites: HashMap::new(),
            ips: HashMap::new(),
        }
    }

    pub(crate) fn cached(dirs: Vec<PathBuf>, shared: AssetCache) -> Self {
        Self {
            dirs,
            files: HashMap::new(),
            shared: Some(shared),
            sites: HashMap::new(),
            ips: HashMap::new(),
        }
    }

    fn file(&mut self, file: &str) -> Result<Arc<AssetBytes>, String> {
        if !is_local_asset(file) {
            return Err(format!("asset `{file}` is not a local path"));
        }
        let shared_has = |path: &PathBuf| {
            self.shared.as_ref().is_some_and(|shared| {
                shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(path)
            })
        };
        let path = self
            .dirs
            .iter()
            .map(|dir| dir.join(file))
            .find(|path| candidate_asset(path).is_some() || path.is_file() || shared_has(path))
            .ok_or_else(|| format!("asset `{file}` was not found under the asset directories"))?;
        if let Some(staged) = candidate_asset(&path) {
            // The candidate reads the staged bytes but keys them by the public entry publication will install, so a later pool miss reuses this snapshot.
            if let Some(bytes) = self.files.get(&path) {
                return Ok(Arc::clone(bytes));
            }
            let bytes = Arc::new(
                AssetBytes::read(&staged).map_err(|error| format!("asset `{file}`: {error}"))?,
            );
            if let Some(shared) = &self.shared {
                shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(path.clone(), Arc::clone(&bytes));
            }
            self.files.insert(path, Arc::clone(&bytes));
            return Ok(bytes);
        }
        if let Some(bytes) = self.files.get(&path) {
            return Ok(Arc::clone(bytes));
        }
        if let Some(shared) = &self.shared {
            let shared = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(bytes) = shared.get(&path) {
                let bytes = Arc::clone(bytes);
                self.files.insert(path.clone(), Arc::clone(&bytes));
                return Ok(bytes);
            }
        }
        let bytes =
            Arc::new(AssetBytes::read(&path).map_err(|error| format!("asset `{file}`: {error}"))?);
        if let Some(shared) = &self.shared {
            let mut shared = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stored = shared
                .entry(path.clone())
                .or_insert_with(|| Arc::clone(&bytes));
            let stored = Arc::clone(stored);
            self.files.insert(path, Arc::clone(&stored));
            return Ok(stored);
        }
        self.files.insert(path, Arc::clone(&bytes));
        Ok(bytes)
    }

    fn site(
        &mut self,
        file: &str,
        code: &str,
        attrs: &str,
    ) -> Result<Arc<Vec<DomainEntry>>, String> {
        let key = (file.to_owned(), code.to_owned(), attrs.to_owned());
        if let Some(entries) = self.sites.get(&key) {
            return Ok(Arc::clone(entries));
        }
        let bytes = self.file(file)?;
        let wanted: Vec<&str> = attrs.split('@').filter(|attr| !attr.is_empty()).collect();
        let mut entries = Vec::new();
        let mut found = false;
        let mut reader = Reader::new(&bytes, "geosite.dat");
        while let Some((field, wire)) = reader.field()? {
            match (field, wire) {
                (1, 2) => {
                    let entry = reader.bytes()?;
                    if geosite_entry(entry, code, &wanted, &mut entries)? {
                        found = true;
                    }
                }
                _ => reader.skip(wire)?,
            }
        }
        if !found {
            return Err(format!("asset `{file}` has no geosite code `{code}`"));
        }
        let entries = Arc::new(entries);
        self.sites.insert(key, Arc::clone(&entries));
        Ok(entries)
    }

    fn ip(&mut self, file: &str, code: &str) -> Result<Arc<Vec<(IpAddr, u32)>>, String> {
        let key = (file.to_owned(), code.to_owned());
        if let Some(cidrs) = self.ips.get(&key) {
            return Ok(Arc::clone(cidrs));
        }
        let bytes = self.file(file)?;
        let mut cidrs = Vec::new();
        let mut found = false;
        let mut reader = Reader::new(&bytes, "geoip.dat");
        while let Some((field, wire)) = reader.field()? {
            match (field, wire) {
                (1, 2) => {
                    let entry = reader.bytes()?;
                    if geoip_entry(entry, code, &mut cidrs)? {
                        found = true;
                    }
                }
                _ => reader.skip(wire)?,
            }
        }
        if !found {
            return Err(format!("asset `{file}` has no geoip code `{code}`"));
        }
        let cidrs = Arc::new(cidrs);
        self.ips.insert(key, Arc::clone(&cidrs));
        Ok(cidrs)
    }
}

pub(crate) fn is_local_asset(file: &str) -> bool {
    if file.is_empty() || file == "." {
        return false;
    }
    Path::new(file)
        .components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

pub(crate) fn asset_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    match std::env::var_os("xray.location.asset")
        .or_else(|| std::env::var_os("XRAY_LOCATION_ASSET"))
    {
        Some(dir) => dirs.push(PathBuf::from(dir)),
        None => {
            if let Some(parent) = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf))
            {
                dirs.push(parent);
            }
        }
    }
    for fallback in [
        "/usr/local/share/xray/",
        "/usr/share/xray/",
        "/opt/share/xray/",
    ] {
        dirs.push(PathBuf::from(fallback));
    }
    dirs
}

fn geosite_entry(
    bytes: &[u8],
    code: &str,
    wanted: &[&str],
    entries: &mut Vec<DomainEntry>,
) -> Result<bool, String> {
    let mut reader = Reader::new(bytes, "geodata.GeoSite");
    let start = entries.len();
    let mut known = false;
    let mut matched = false;
    let mut deferred = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                matched = String::from_utf8_lossy(reader.bytes()?).eq_ignore_ascii_case(code);
                known = true;
            }
            (2, 2) => {
                let raw = reader.bytes()?;
                if !known {
                    deferred.push(raw);
                } else if matched {
                    if let Some(entry) = domain_entry(raw, wanted)? {
                        entries.push(entry);
                    }
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    if matched {
        for raw in deferred {
            if let Some(entry) = domain_entry(raw, wanted)? {
                entries.push(entry);
            }
        }
    } else {
        entries.truncate(start);
    }
    Ok(matched)
}

fn domain_entry(bytes: &[u8], wanted: &[&str]) -> Result<Option<DomainEntry>, String> {
    let mut reader = Reader::new(bytes, "geodata.Domain");
    let mut kind = DomainKind::Substr;
    let mut value = None;
    let mut attrs = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                kind = match reader.varint()? {
                    0 => DomainKind::Substr,
                    1 => DomainKind::Regex,
                    2 => DomainKind::Domain,
                    3 => DomainKind::Full,
                    _ => return Ok(None),
                };
            }
            (2, 2) => {
                let Ok(text) = std::str::from_utf8(reader.bytes()?) else {
                    return Ok(None);
                };
                value = Some(text);
            }
            (3, 2) => {
                if wanted.is_empty() {
                    reader.skip(wire)?;
                } else if let Some(attr) = domain_attribute(reader.bytes()?)? {
                    attrs.push(attr);
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if !wanted
        .iter()
        .all(|want| attrs.iter().any(|have| have.as_ref() == *want))
    {
        return Ok(None);
    }
    let value = if matches!(kind, DomainKind::Regex) {
        Arc::from(value)
    } else {
        lower_arc(value)
    };
    Ok(Some(DomainEntry { kind, value }))
}

fn domain_attribute(bytes: &[u8]) -> Result<Option<Cow<'_, str>>, String> {
    let mut reader = Reader::new(bytes, "geodata.Domain.Attribute");
    let mut key = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let bytes = reader.bytes()?;
                key = Some(String::from_utf8_lossy(bytes));
            }
            (2 | 3, 0) => {
                reader.varint()?;
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(key)
}

fn geoip_entry(bytes: &[u8], code: &str, cidrs: &mut Vec<(IpAddr, u32)>) -> Result<bool, String> {
    let mut reader = Reader::new(bytes, "geodata.GeoIP");
    let start = cidrs.len();
    let mut known = false;
    let mut matched = false;
    let mut deferred = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                matched = String::from_utf8_lossy(reader.bytes()?).eq_ignore_ascii_case(code);
                known = true;
            }
            (2, 2) => {
                let raw = reader.bytes()?;
                if !known {
                    deferred.push(raw);
                } else if matched {
                    if let Some(cidr) = geoip_cidr(raw)? {
                        cidrs.push(cidr);
                    }
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    if matched {
        for raw in deferred {
            if let Some(cidr) = geoip_cidr(raw)? {
                cidrs.push(cidr);
            }
        }
    } else {
        cidrs.truncate(start);
    }
    Ok(matched)
}

fn geoip_cidr(bytes: &[u8]) -> Result<Option<(IpAddr, u32)>, String> {
    let mut reader = Reader::new(bytes, "geodata.CIDR");
    let mut ip = None;
    let mut prefix = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                ip = match reader.bytes()? {
                    octets if octets.len() == 4 => Some(IpAddr::from(
                        <[u8; 4]>::try_from(octets).map_err(|_| "geodata.CIDR: bad IPv4")?,
                    )),
                    octets if octets.len() == 16 => Some(IpAddr::from(
                        <[u8; 16]>::try_from(octets).map_err(|_| "geodata.CIDR: bad IPv6")?,
                    )),
                    _ => None,
                };
            }
            (2, 0) => prefix = u32::try_from(reader.varint()?).unwrap_or(u32::MAX),
            _ => reader.skip(wire)?,
        }
    }
    match ip {
        Some(ip) if prefix <= if ip.is_ipv4() { 32 } else { 128 } => Ok(Some((ip, prefix))),
        _ => Ok(None),
    }
}

pub(crate) fn resolve_ips(host: &str, port: u16) -> Vec<IpAddr> {
    resolve_ips_ttl(host, port).0
}

pub(crate) fn resolve_ips_ttl(host: &str, port: u16) -> (Vec<IpAddr>, u32) {
    resolve_ips_ttl_with(crate::dnsapp::installed().as_ref(), host, port)
}

fn resolve_ips_ttl_with(
    resolver: Option<&Arc<crate::dnsapp::Resolver>>,
    host: &str,
    port: u16,
) -> (Vec<IpAddr>, u32) {
    if let Some(resolver) = resolver {
        match resolver.lookup_result(host) {
            crate::dnsapp::Lookup::Records(ips, ttl) => return (ips, ttl),
            crate::dnsapp::Lookup::Empty | crate::dnsapp::Lookup::Rcode(_) => {
                return (Vec::new(), 0);
            }
            crate::dnsapp::Lookup::Failed | crate::dnsapp::Lookup::Skipped => {
                let (v4, v6) = resolver.families();
                return resolve_ips_system(host, port, v4, v6);
            }
        }
    }
    resolve_ips_system(host, port, true, true)
}

pub(crate) fn resolve_ips_script(
    host: &str,
    port: u16,
    fake: bool,
    v4: bool,
    v6: bool,
) -> (Vec<IpAddr>, u32, Option<String>) {
    if let Some(resolver) = crate::dnsapp::installed() {
        return match resolver.lookup_outcome(host, v4, v6, fake) {
            crate::dnsapp::Lookup::Records(addrs, ttl) => (addrs, ttl, None),
            crate::dnsapp::Lookup::Rcode(code) => {
                (Vec::new(), 0, Some(format!("response code {code}")))
            }
            crate::dnsapp::Lookup::Empty => (Vec::new(), 0, Some("empty response".to_owned())),
            crate::dnsapp::Lookup::Skipped | crate::dnsapp::Lookup::Failed => {
                let (addrs, ttl) = resolve_ips_system(host, port, v4, v6);
                (addrs, ttl, None)
            }
        };
    }
    let (addrs, ttl) = resolve_ips_system(host, port, v4, v6);
    (addrs, ttl, None)
}

pub(crate) fn resolve_ips_system(host: &str, port: u16, v4: bool, v6: bool) -> (Vec<IpAddr>, u32) {
    use std::net::ToSocketAddrs;
    let budget = crate::dnsapp::system_budget(crate::budgets::dial());
    if budget.is_zero() {
        return (Vec::new(), 0);
    }
    let ips = crate::proxy::resolve_bounded(host, port, budget, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(std::iter::Iterator::collect)
    })
    .unwrap_or_default()
    .into_iter()
    .map(|addr| addr.ip())
    .filter(|ip| (v4 && ip.is_ipv4()) || (v6 && ip.is_ipv6()))
    .collect();
    (ips, 0)
}

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn object(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    fn text(value: &str) -> Json {
        Json::Str(value.to_owned())
    }

    fn array(items: Vec<Json>) -> Json {
        Json::Arr(items)
    }

    fn number(value: u32) -> Json {
        Json::Num(f64::from(value))
    }

    fn rule(target: &str, selectors: Vec<(&str, Json)>) -> Json {
        let mut pairs = vec![("outboundTag", text(target))];
        pairs.extend(selectors);
        object(pairs)
    }

    fn routing(rules: Vec<Json>) -> Json {
        object(vec![("rules", array(rules))])
    }

    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrox-router-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = varint(field << 3 | 2);
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    fn set_bit(bits: &mut Vec<u64>, at: usize, value: bool) {
        while at / 64 >= bits.len() {
            bits.push(0);
        }
        if value {
            bits[at / 64] |= 1 << (at % 64);
        }
    }

    fn put_u64s(out: &mut Vec<u8>, values: &[u64]) {
        out.extend(varint(values.len() as u64));
        for value in values {
            out.extend(value.to_be_bytes());
        }
    }

    fn put_succinct(out: &mut Vec<u8>, keys: &[String]) {
        let mut keys = keys.to_vec();
        keys.sort();
        let mut leaves = Vec::new();
        let mut labels = Vec::new();
        let mut bitmap = Vec::new();
        let mut bit = 0usize;
        let mut queue = vec![(0usize, keys.len(), 0usize)];
        let mut at = 0usize;
        while at < queue.len() {
            let (mut start, end, column) = queue[at];
            if column == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, at, true);
            }
            let mut item = start;
            while item < end {
                let first = item;
                let byte = keys[first].as_bytes()[column];
                while item < end && keys[item].as_bytes()[column] == byte {
                    item += 1;
                }
                queue.push((first, item, column + 1));
                labels.push(byte);
                set_bit(&mut bitmap, bit, false);
                bit += 1;
            }
            set_bit(&mut bitmap, bit, true);
            bit += 1;
            at += 1;
        }
        out.push(0);
        put_u64s(out, &leaves);
        put_u64s(out, &bitmap);
        out.extend(varint(labels.len() as u64));
        out.extend(labels);
    }

    fn put_strings(out: &mut Vec<u8>, values: &[&str]) {
        out.extend(varint(values.len() as u64));
        for value in values {
            out.extend(varint(value.len() as u64));
            out.extend(value.as_bytes());
        }
    }

    fn put_u16s(out: &mut Vec<u8>, values: &[u16]) {
        out.extend(varint(values.len() as u64));
        for value in values {
            out.extend(value.to_be_bytes());
        }
    }

    fn put_ip(out: &mut Vec<u8>, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => {
                out.extend(varint(4));
                out.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                out.extend(varint(16));
                out.extend(ip.octets());
            }
        }
    }

    fn put_ip_set(out: &mut Vec<u8>, ranges: &[(IpAddr, IpAddr)]) {
        out.push(1);
        out.extend((ranges.len() as u64).to_be_bytes());
        for (from, to) in ranges {
            put_ip(out, *from);
            put_ip(out, *to);
        }
    }

    fn wrap_srs(body: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut out = b"SRS".to_vec();
        out.push(5);
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).expect("compresses");
        out.extend(encoder.finish().expect("finishes"));
        out
    }

    fn domain_key(kind: u8, domain: &str) -> String {
        let mut key = String::new();
        if kind != 0 {
            key.push(kind as char);
        }
        key.push_str(domain);
        key.chars().rev().collect()
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    fn domain(kind: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut fields = vec![varint_field(1, kind), bytes_field(2, value.as_bytes())];
        for attr in attrs {
            fields.push(bytes_field(3, &bytes_field(1, attr.as_bytes())));
        }
        fields.concat()
    }

    fn geosite(code: &str, domains: Vec<Vec<u8>>) -> Vec<u8> {
        let mut entry = vec![bytes_field(1, code.as_bytes())];
        entry.extend(domains.into_iter().map(|domain| bytes_field(2, &domain)));
        bytes_field(1, &entry.concat())
    }

    fn geoip(code: &str, cidrs: &[(IpAddr, u32)]) -> Vec<u8> {
        let mut entry = vec![bytes_field(1, code.as_bytes())];
        for (ip, prefix) in cidrs {
            let raw = match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let cidr = [bytes_field(1, &raw), varint_field(2, u64::from(*prefix))].concat();
            entry.push(bytes_field(2, &cidr));
        }
        bytes_field(1, &entry.concat())
    }

    fn geoip_code(path: &Path, code: &str, cidrs: &[(IpAddr, u32)]) {
        std::fs::write(path, geoip(code, cidrs)).expect("writes geoip");
    }

    #[test]
    fn a_rejected_entry_does_not_leave_its_domains_behind() {
        let entry = [
            bytes_field(1, b"TEST"),
            bytes_field(2, &domain(2, "leaked.test", &[])),
            bytes_field(1, b"OTHER"),
        ]
        .concat();
        let mut entries = Vec::new();
        assert!(!geosite_entry(&entry, "TEST", &[], &mut entries).expect("parses"));
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn a_rejected_entry_does_not_leave_its_ranges_behind() {
        let cidr = [bytes_field(1, &[192, 0, 2, 0]), varint_field(2, 24)].concat();
        let entry = [
            bytes_field(1, b"TEST"),
            bytes_field(2, &cidr),
            bytes_field(1, b"OTHER"),
        ]
        .concat();
        let mut cidrs = Vec::new();
        assert!(!geoip_entry(&entry, "TEST", &mut cidrs).expect("parses"));
        assert!(cidrs.is_empty(), "{cidrs:?}");
    }

    #[test]
    fn a_staged_remote_body_reads_through_its_handle_and_cleans_up() {
        let body = RemoteBody::stage(&[1, 2, 3]).expect("stages");
        let dir = body.temp.as_ref().expect("staged on disk").dir.clone();
        assert_eq!(body.read().expect("reads"), vec![1, 2, 3]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dir)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        drop(body);
        assert!(!dir.exists(), "the private staging directory is removed");
    }

    #[test]
    fn an_asset_container_reads_whole_including_its_last_byte() {
        let dir = dir();
        let path = dir.join("container.dat");
        let payload = [0u8, 1, 2, 255, 0, 42];
        std::fs::write(&path, payload).expect("writes");
        let bytes = AssetBytes::read(&path).expect("reads");
        assert_eq!(&*bytes, &payload);
        let empty = dir.join("empty.dat");
        std::fs::write(&empty, []).expect("writes");
        let bytes = AssetBytes::read(&empty).expect("reads");
        assert!(bytes.is_empty());
    }

    #[test]
    fn a_remote_cache_write_waits_for_the_candidate_to_commit() {
        let cache = dir().join("cache");
        let (queued, writes, _) = with_candidate_assets(HashMap::new(), || {
            publish_cache(cache.clone(), vec![1, 2, 3].into()).expect("queues");
            cache.clone()
        });
        assert_eq!(queued, cache);
        assert!(
            !cache.exists(),
            "the candidate did not touch the live cache"
        );
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].target, cache);
        let mut writes = writes;
        let CacheWrite {
            target: path, body, ..
        } = writes.pop().expect("one queued write");
        let bytes = body.into_bytes().expect("reads");
        assert_eq!(bytes, vec![1, 2, 3]);
        crate::geodata::write_atomic(&path, &bytes).expect("publishes");
        assert_eq!(std::fs::read(&cache).expect("reads"), vec![1, 2, 3]);
    }

    #[cfg(unix)]
    #[test]
    fn a_staged_symlink_chain_reads_the_intermediate_target() {
        let root = dir();
        let data = root.join("data.dat");
        std::fs::write(&data, b"live").expect("data");
        let middle = root.join("middle");
        let first = root.join("first");
        std::os::unix::fs::symlink(&data, &middle).expect("middle");
        std::os::unix::fs::symlink(&middle, &first).expect("first");
        let staged = root.join("staged.dat");
        std::fs::write(&staged, b"staged").expect("staged");
        let candidate = HashMap::from([(middle, staged.clone())]);
        let (found, _, _) = with_candidate_assets(candidate, || candidate_asset_referent(&first));
        assert_eq!(found, Some(staged));
    }

    #[test]
    fn a_staged_asset_does_not_override_an_earlier_asset_directory() {
        let root = dir();
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).expect("first");
        std::fs::create_dir_all(&second).expect("second");
        std::fs::write(first.join("geosite.dat"), b"first").expect("first asset");
        std::fs::write(second.join("geosite.dat"), b"second").expect("second asset");
        let staged = root.join("staged");
        std::fs::write(&staged, b"staged").expect("staged asset");
        let candidate = HashMap::from([(second.join("geosite.dat"), staged)]);
        let mut assets = Assets::new(vec![first, second]);
        let (bytes, writes, _) = with_candidate_assets(candidate, || assets.file("geosite.dat"));
        assert_eq!(&**bytes.expect("reads"), b"first");
        assert!(writes.is_empty());
    }

    #[test]
    fn a_suffix_matches_the_name_itself_and_its_subdomains() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = |domain| Flow {
            network: Network::Tcp,
            domain: Some(domain),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow("example.test")), Some("direct"));
        assert_eq!(routing.route(&flow("www.example.test")), Some("direct"));
        assert_eq!(routing.route(&flow("notexample.test")), None);
    }

    #[test]
    fn a_rule_matches_every_selector_it_names() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("network", text("tcp")),
                    ("port", text("80,443")),
                    ("domain", array(vec![text("domain:example.test")])),
                ],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let port = Some(443);
        let matching = Flow {
            network: Network::Tcp,
            domain: Some("www.example.test"),
            ip: None,
            port,
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&matching), Some("direct"));
        for changed in [
            Flow {
                network: Network::Udp,
                ..matching
            },
            Flow {
                port: Some(8080),
                ..matching
            },
            Flow {
                domain: Some("example.test.invalid"),
                ..matching
            },
        ] {
            assert_eq!(routing.route(&changed), None);
        }
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("port", number(80))]),
                rule("second", vec![("port", text("80-90"))]),
                rule("third", vec![("network", text("tcp"))]),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: None,
            ip: None,
            port: Some(80),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("first"));
    }

    #[test]
    fn geosite_attributes_must_all_be_present() {
        let dir = dir();
        let domains = vec![
            domain(2, "both.test", &["a", "b"]),
            domain(2, "one.test", &["a"]),
            domain(3, "full.test", &[]),
        ];
        std::fs::write(dir.join("geosite.dat"), geosite("TEST", domains)).expect("writes");
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![(
                    "domain",
                    array(vec![text("geosite:test@a@b"), text("full:full.test")]),
                )],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = |domain| Flow {
            network: Network::Tcp,
            domain: Some(domain),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow("x.both.test")), Some("direct"));
        assert_eq!(routing.route(&flow("one.test")), None);
        assert_eq!(routing.route(&flow("full.test")), Some("direct"));
    }

    #[test]
    fn a_code_named_by_two_rules_shares_its_entries() {
        let dir = dir();
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "Shared.Test", &[])]),
        )
        .expect("writes");
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("domain", array(vec![text("geosite:test")]))]),
                rule(
                    "second",
                    vec![("domain", array(vec![text("geosite:test")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let rules = routing.rules();
        let first = rules[0]
            .domains
            .as_ref()
            .expect("first matcher")
            .full
            .first()
            .expect("first entry");
        let second = rules[1]
            .domains
            .as_ref()
            .expect("second matcher")
            .full
            .first()
            .expect("second entry");
        assert_eq!(&**first, "shared.test");
        assert!(
            Arc::ptr_eq(first, second),
            "the second rule copies the entry"
        );
    }

    #[test]
    fn an_unwanted_geosite_code_is_not_decoded() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:test")]))],
            )]),
        )]);
        let wanted = || geosite("TEST", vec![domain(3, "wanted.test", &[])]);
        std::fs::write(dir.join("geosite.dat"), wanted()).expect("writes");
        let (_, small) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        let mut file = geosite(
            "HUGE",
            (0..256)
                .map(|at| domain(3, &format!("huge{at}.test"), &[]))
                .collect(),
        );
        file.extend(wanted());
        std::fs::write(dir.join("geosite.dat"), file).expect("writes");
        let (_, big) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            big.allocs, small.allocs,
            "an unwanted code was decoded: {big:?} against {small:?}"
        );
    }

    #[test]
    fn an_unwanted_geoip_code_is_not_decoded() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("ip", array(vec![text("geoip:test")]))],
            )]),
        )]);
        let wanted = || geoip("TEST", &[("192.0.2.0".parse().expect("ip"), 24)]);
        std::fs::write(dir.join("geoip.dat"), wanted()).expect("writes");
        let (_, small) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        let huge: Vec<(IpAddr, u32)> = (0..256)
            .map(|at| (IpAddr::from([10, 0, (at / 256) as u8, at as u8]), 32))
            .collect();
        let mut file = geoip("HUGE", &huge);
        file.extend(wanted());
        std::fs::write(dir.join("geoip.dat"), file).expect("writes");
        let (_, big) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            big.allocs, small.allocs,
            "an unwanted code was decoded: {big:?} against {small:?}"
        );
    }

    #[test]
    fn attributes_are_not_decoded_unless_requested() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:test")]))],
            )]),
        )]);
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "wanted.test", &[])]),
        )
        .expect("writes");
        let (_, plain) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        std::fs::write(
            dir.join("geosite.dat"),
            geosite("TEST", vec![domain(3, "wanted.test", &["ads"])]),
        )
        .expect("writes");
        let (_, attributed) = ferrox_core::alloc_count::measure(|| {
            Routing::parse_in(&root, vec![dir.clone()])
                .expect("parses")
                .expect("routing")
        });
        assert_eq!(
            attributed.allocs, plain.allocs,
            "an unrequested attribute was decoded: {attributed:?} against {plain:?}"
        );
    }

    #[test]
    fn a_reversed_geoip_rule_matches_every_other_address() {
        let dir = dir();
        geoip_code(
            &dir.join("geoip.dat"),
            "TEST",
            &[("192.0.2.0".parse().expect("ip"), 24)],
        );
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![(
                    "ip",
                    array(vec![text("geoip:test"), text("!198.51.100.0/24")]),
                )],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = |ip: IpAddr| Flow {
            network: Network::Tcp,
            domain: None,
            ip: Some(ip),
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(
            routing.route(&flow("192.0.2.9".parse().expect("ip"))),
            Some("direct")
        );
        assert_eq!(
            routing.route(&flow("198.51.100.9".parse().expect("ip"))),
            None
        );
        // A family the negative set never names is not matched by its reverse, as in the reference.
        assert_eq!(
            routing.route(&flow("2001:db8::1".parse().expect("ip"))),
            None
        );
        assert_eq!(
            routing.route(&flow("10.0.0.1".parse().expect("ip"))),
            Some("direct")
        );
    }

    #[test]
    fn a_mapped_geoip_range_matches_beside_a_native_default() {
        let mut set = RangeSet::default();
        set.add("::ffff:192.0.2.0".parse().expect("ip"), 120)
            .expect("adds");
        set.finish();
        assert!(set.matches("192.0.2.1".parse().expect("ip"), false));
        assert!(!set.matches("198.51.100.1".parse().expect("ip"), false));
        set.add("::".parse().expect("ip"), 0).expect("adds");
        set.finish();
        assert!(set.matches("192.0.2.1".parse().expect("ip"), false));
        assert!(
            !set.matches("198.51.100.1".parse().expect("ip"), false),
            "a native IPv6 default capture does not match IPv4"
        );
        assert!(set.matches("2001:db8::1".parse().expect("ip"), false));
    }

    #[test]
    fn a_native_default_matches_mapped_input_in_both_forms() {
        let mapped: IpAddr = "::ffff:198.51.100.1".parse().expect("ip");
        let mut source = RangeSet::default();
        source.add("::".parse().expect("ip"), 0).expect("adds");
        source.finish();
        assert!(source.matches(mapped, false));
        let mut srs = RangeSet::default();
        srs.add_v6_range(0, u128::MAX).expect("adds");
        srs.finish();
        assert!(srs.matches(mapped, false));
    }

    #[test]
    fn an_arbitrary_mapped_v6_range_matches_an_ipv4_input() {
        let mut set = RangeSet::default();
        let start = MAPPED_BASE + u128::from(u32::from(std::net::Ipv4Addr::new(192, 0, 2, 0)));
        set.add_v6_range(start, start + 255).expect("adds");
        set.finish();
        assert!(set.matches("192.0.2.1".parse().expect("ip"), false));
        assert!(!set.matches("198.51.100.1".parse().expect("ip"), false));
        assert!(set.matches("::ffff:192.0.2.1".parse().expect("ip"), false));
    }

    #[test]
    fn a_mapped_input_matches_the_wide_mapped_rule_it_spells() {
        let mut set = RangeSet::default();
        set.add("::ffff:0:0".parse().expect("ip"), 95)
            .expect("adds");
        set.finish();
        assert!(set.matches("::ffff:192.0.2.1".parse().expect("ip"), false));
        assert!(!set.matches("192.0.2.1".parse().expect("ip"), false));
        assert!(!set.matches("198.51.100.1".parse().expect("ip"), false));
        assert!(!set.matches("2001:db8::1".parse().expect("ip"), false));
    }

    #[test]
    fn a_wide_mapped_rule_routes_mapped_input_through_parse() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("ip", array(vec![text("::ffff:0:0/95")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = |ip: &str| Flow {
            network: Network::Tcp,
            domain: None,
            ip: Some(ip.parse().expect("ip")),
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow("::ffff:192.0.2.1")), Some("direct"));
        assert_eq!(routing.route(&flow("192.0.2.1")), None);
    }

    #[test]
    fn a_missing_asset_or_code_is_a_startup_error() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("geosite:CN")]))],
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("geosite.dat"), "{error}");
        let dir = dir();
        std::fs::write(dir.join("geosite.dat"), geosite("US", Vec::new())).expect("writes");
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("CN"), "{error}");
    }

    #[test]
    fn ip_if_non_match_resolves_only_after_no_rule_matched() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![
                        rule(
                            "domain",
                            vec![("domain", array(vec![text("keyword:blocked")]))],
                        ),
                        rule("address", vec![("ip", array(vec![text("192.0.2.0/24")]))]),
                    ]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
        let domain_match = Flow {
            domain: Some("blocked.test"),
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&domain_match, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, Some("domain"));
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn a_skip_dns_route_does_not_resolve_a_name() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![rule(
                        "address",
                        vec![("ip", array(vec![text("192.0.2.0/24")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(
            routing
                .route_target_without_resolve(&flow)
                .map(|hit| hit.tag()),
            None
        );
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
    }

    #[test]
    fn an_ip_candidate_past_the_small_table_still_matches_its_inbound() {
        let mut rules = (0..256)
            .map(|at| {
                rule(
                    "filler",
                    vec![("domain", array(vec![text(&format!("miss{at}.test"))]))],
                )
            })
            .collect::<Vec<_>>();
        rules.push(rule(
            "trusted",
            vec![
                ("inboundTag", array(vec![text("trusted")])),
                ("ip", array(vec![text("192.0.2.0/24")])),
            ],
        ));
        rules.push(rule(
            "public",
            vec![
                ("inboundTag", array(vec![text("public")])),
                ("ip", array(vec![text("192.0.2.0/24")])),
            ],
        ));
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                ("rules", array(rules)),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("public.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: Some("public"),
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(
            routing.route_with(&flow, &|_, _| { vec!["192.0.2.9".parse().expect("ip")] }),
            Some("public")
        );
    }

    #[test]
    fn a_candidate_is_not_re_evaluated_under_ip_if_non_match() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![
                            ("domain", array(vec![text("full:once.test")])),
                            ("ip", array(vec![text("192.0.2.0/24")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("once.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let before = DOMAIN_TABLE_READS.with(std::cell::Cell::get);
        let tag = routing.route_with(&flow, &|_, _| vec!["192.0.2.1".parse().expect("ip")]);
        assert_eq!(tag, Some("direct"));
        assert_eq!(
            DOMAIN_TABLE_READS.with(std::cell::Cell::get) - before,
            1,
            "the second pass re-read the domain table"
        );
    }

    #[test]
    fn ip_on_demand_resolves_only_when_an_ip_matcher_is_reached() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPOnDemand")),
                (
                    "rules",
                    array(vec![
                        rule("address", vec![("ip", array(vec![text("192.0.2.0/24")]))]),
                        rule("tcp", vec![("network", text("tcp"))]),
                    ]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
        let literal = Flow {
            ip: Some("192.0.2.1".parse().expect("ip")),
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&literal, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn a_rule_set_domain_is_exact_and_a_suffix_is_not() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("names")),
                        ("type", text("inline")),
                        (
                            "rules",
                            array(vec![
                                object(vec![("domain", array(vec![text("exact.test")]))]),
                                object(vec![("domain_suffix", array(vec![text(".ends.test")]))]),
                            ]),
                        ),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("names")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("exact.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        for name in ["exact.test", "name.ends.test"] {
            assert_eq!(
                routing.route(&Flow {
                    domain: Some(name),
                    ..flow
                }),
                Some("block"),
                "{name}"
            );
        }
        assert_eq!(
            routing.route(&Flow {
                domain: Some("name.exact.test"),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("ends.test"),
                ..flow
            }),
            None
        );
    }

    #[test]
    fn a_rule_set_matches_its_domains_and_logical_rules() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("blocked")),
                        ("type", text("inline")),
                        (
                            "rules",
                            array(vec![
                                object(vec![("domain_suffix", array(vec![text(".ads.test")]))]),
                                object(vec![
                                    ("type", text("logical")),
                                    ("mode", text("and")),
                                    (
                                        "rules",
                                        array(vec![
                                            object(vec![(
                                                "domain_keyword",
                                                array(vec![text("track")]),
                                            )]),
                                            object(vec![("port", array(vec![number(443)]))]),
                                        ]),
                                    ),
                                ]),
                            ]),
                        ),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("blocked")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("x.Ads.Test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                domain: Some("ads.test"),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("tracker.other.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("tracker.other.test"),
                port: Some(80),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("deep.ads.test"),
                ..flow
            }),
            Some("block")
        );
    }

    #[test]
    fn a_rule_set_address_waits_for_ip_if_non_match() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("net")),
                        (
                            "rules",
                            array(vec![object(vec![(
                                "ip_cidr",
                                array(vec![text("10.0.0.0/8")]),
                            )])]),
                        ),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![("ruleSet", array(vec![text("net")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("once.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(
            routing.route_with(&flow, &|_, _| vec!["10.1.2.3".parse().expect("ip")]),
            Some("direct")
        );
        assert_eq!(
            routing.route_with(&flow, &|_, _| vec!["192.0.2.1".parse().expect("ip")]),
            None
        );
    }

    #[test]
    fn a_logical_rule_set_inverts_without_hiding_the_address() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("plain")),
                        (
                            "rules",
                            array(vec![object(vec![
                                ("domain_suffix", array(vec![text("ok.test")])),
                                ("invert", Json::Bool(true)),
                            ])]),
                        ),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![("ruleSet", array(vec![text("plain")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("other.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("direct"));
        assert_eq!(
            routing.route(&Flow {
                domain: Some("x.ok.test"),
                ..flow
            }),
            None
        );
    }

    #[test]
    fn a_native_rule_set_file_matches_domain_and_address() {
        let dir = dir();
        std::fs::write(
            dir.join("native.json"),
            r#"{"domain":["native.test"],"ip":["192.0.2.0/24"]}"#,
        )
        .expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("native")),
                        ("type", text("local")),
                        ("path", text("native.json")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![("ruleSet", array(vec![text("native")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("native.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("direct"));
        assert_eq!(
            routing.route(&Flow {
                domain: None,
                ip: Some("192.0.2.7".parse().expect("ip")),
                ..flow
            }),
            Some("direct")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: None,
                ip: Some("198.51.100.7".parse().expect("ip")),
                ..flow
            }),
            None
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_binary_rule_set_reads_domains_ports_network_and_addresses() {
        let mut body = Vec::new();
        body.extend(varint(4));
        body.push(0);
        body.push(2);
        put_succinct(
            &mut body,
            &[
                domain_key(0, "exact.test"),
                domain_key(ROOT_LABEL, "suffix.test"),
                domain_key(PREFIX_LABEL, ".only.test"),
            ],
        );
        body.push(1);
        put_strings(&mut body, &["tcp"]);
        body.push(9);
        put_u16s(&mut body, &[443]);
        body.push(0xff);
        body.push(0);
        body.push(0);
        body.push(6);
        put_ip_set(
            &mut body,
            &[(
                "192.0.2.1".parse().expect("address"),
                "192.0.2.1".parse().expect("address"),
            )],
        );
        body.push(0xff);
        body.push(0);
        body.push(0);
        body.push(5);
        put_ip_set(
            &mut body,
            &[(
                "192.0.2.9".parse().expect("address"),
                "192.0.2.9".parse().expect("address"),
            )],
        );
        body.push(0xff);
        body.push(0);
        body.push(0);
        body.push(2);
        put_succinct(&mut body, &[domain_key(0, "either.test")]);
        body.push(6);
        put_ip_set(
            &mut body,
            &[(
                "192.0.2.10".parse().expect("address"),
                "192.0.2.10".parse().expect("address"),
            )],
        );
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("bin")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("bin")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("exact.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                domain: Some("a.suffix.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("suffix.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("a.only.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("only.test"),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                port: Some(80),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: None,
                ip: Some("192.0.2.1".parse().expect("address")),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: None,
                ip: Some("192.0.2.2".parse().expect("address")),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                source: Some("192.0.2.9".parse().expect("address")),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("exact.test"),
                ip: Some("192.0.2.2".parse().expect("address")),
                source: Some("192.0.2.9".parse().expect("address")),
                ..flow
            }),
            Some("block"),
            "the destination domain is an alternative to the destination address"
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                ip: Some("192.0.2.1".parse().expect("address")),
                source: Some("192.0.2.9".parse().expect("address")),
                ..flow
            }),
            Some("block"),
            "the destination address is an alternative to the destination domain"
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("either.test"),
                ..flow
            }),
            Some("block"),
            "a destination domain alone satisfies a leaf that also names a destination address"
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                ip: Some("192.0.2.10".parse().expect("address")),
                ..flow
            }),
            Some("block"),
            "a destination address alone satisfies the same leaf"
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("either.test"),
                ip: Some("192.0.2.10".parse().expect("address")),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                ip: Some("198.51.100.1".parse().expect("address")),
                ..flow
            }),
            None
        );
    }

    #[test]
    fn a_binary_rule_set_refuses_a_domain_regex_that_does_not_compile() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(4);
        put_strings(&mut body, &["["]);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("bin")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("bin")]))],
                    )]),
                ),
            ]),
        )]);
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("regex"), "{error}");
    }

    #[test]
    fn a_binary_rule_set_refuses_domain_keys_past_the_body_budget() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(2);
        let keys: Vec<String> = (0..512)
            .map(|at| domain_key(0, &format!("{at}.{}", "a".repeat(200))))
            .collect();
        put_succinct(&mut body, &keys);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("bin")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("bin")]))],
                    )]),
                ),
            ]),
        )]);
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("budget"), "{error}");
    }

    #[test]
    fn wants_process_follows_the_rules_that_remain() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("proc")),
                        ("type", text("inline")),
                        (
                            "rules",
                            array(vec![object(vec![(
                                "process_name",
                                array(vec![text("curl")]),
                            )])]),
                        ),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![
                            ("ruleTag", text("managed")),
                            ("ruleSet", array(vec![text("proc")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let mut routing = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        assert!(routing.wants_process());
        routing.remove_rules("managed", &[]).expect("removes");
        assert!(!routing.wants_process());
    }

    #[test]
    fn a_removed_startup_rule_stays_removed_after_a_reparse() {
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![rule(
                    "block",
                    vec![
                        ("ruleTag", text("policy")),
                        ("domain", array(vec![text("startup.test")])),
                    ],
                )]),
            )]),
        )]);
        let mut routing = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        routing.remove_rules("policy", &[]).expect("removes");
        routing
            .add_rules(
                &[rule(
                    "block",
                    vec![
                        ("ruleTag", text("policy")),
                        ("domain", array(vec![text("added.test")])),
                    ],
                )],
                true,
                |tag| tag == "block",
                &[],
            )
            .expect("adds");
        let mut next = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        next.adopt_added_rules(&mut routing).expect("adopts");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("added.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(next.route(&flow), Some("block"));
        assert_eq!(
            next.route(&Flow {
                domain: Some("startup.test"),
                ..flow
            }),
            None,
            "the removed startup rule is not restored"
        );
    }

    #[test]
    fn an_added_rule_set_rule_rebinds_to_the_reloaded_set() {
        let root = |domain: &str| {
            object(vec![(
                "routing",
                object(vec![(
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("set")),
                        ("type", text("inline")),
                        (
                            "rules",
                            array(vec![object(vec![("domain", array(vec![text(domain)]))])]),
                        ),
                    ])]),
                )]),
            )])
        };
        let mut routing = Routing::parse_in(&root("old.test"), Vec::new())
            .expect("parses")
            .expect("routing");
        routing
            .add_rules(
                &[rule(
                    "block",
                    vec![
                        ("ruleTag", text("managed")),
                        ("ruleSet", array(vec![text("set")])),
                    ],
                )],
                true,
                |tag| tag == "block",
                &[],
            )
            .expect("adds");
        let mut next = Routing::parse_in(&root("new.test"), Vec::new())
            .expect("parses")
            .expect("routing");
        next.adopt_added_rules(&mut routing).expect("adopts");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("new.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(next.route(&flow), Some("block"));
        assert_eq!(
            next.route(&Flow {
                domain: Some("old.test"),
                ..flow
            }),
            None,
            "the managed rule uses the reloaded set contents"
        );
    }

    #[test]
    fn a_managed_rule_that_no_longer_parses_keeps_the_old_table() {
        let with_set = object(vec![(
            "routing",
            object(vec![(
                "ruleSets",
                array(vec![object(vec![
                    ("tag", text("set")),
                    ("type", text("inline")),
                    (
                        "rules",
                        array(vec![object(vec![(
                            "domain",
                            array(vec![text("old.test")]),
                        )])]),
                    ),
                ])]),
            )]),
        )]);
        let without_set = object(vec![("routing", object(vec![]))]);
        let mut routing = Routing::parse_in(&with_set, Vec::new())
            .expect("parses")
            .expect("routing");
        routing
            .add_rules(
                &[rule(
                    "block",
                    vec![
                        ("ruleTag", text("managed")),
                        ("ruleSet", array(vec![text("set")])),
                    ],
                )],
                true,
                |tag| tag == "block",
                &[],
            )
            .expect("adds");
        let mut next = Routing::parse_in(&without_set, Vec::new())
            .expect("parses")
            .expect("routing");
        assert!(next.adopt_added_rules(&mut routing).is_err());
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("old.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
    }

    #[test]
    fn a_replacement_add_rule_table_survives_a_reparse() {
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![rule(
                    "block",
                    vec![("domain", array(vec![text("startup.test")]))],
                )]),
            )]),
        )]);
        let mut routing = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        routing
            .add_rules(
                &[rule(
                    "block",
                    vec![("domain", array(vec![text("replacement.test")]))],
                )],
                false,
                |tag| tag == "block",
                &[],
            )
            .expect("replaces");
        let mut next = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        next.adopt_added_rules(&mut routing).expect("adopts");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("replacement.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(next.route(&flow), Some("block"));
        assert_eq!(
            next.route(&Flow {
                domain: Some("startup.test"),
                ..flow
            }),
            None,
            "a replacement table does not resurrect the startup rules"
        );
    }

    #[test]
    fn a_binary_rule_set_process_selectors_are_all_required() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(11);
        put_strings(&mut body, &["curl"]);
        body.push(12);
        put_strings(&mut body, &["/usr/bin/other"]);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("proc")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("proc")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("process.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let named = crate::process::Owner {
            pid: 1,
            name: "curl".to_owned(),
            path: "/usr/bin/curl".to_owned(),
        };
        assert_eq!(
            routing.route(&Flow {
                process: Some(&named),
                ..flow
            }),
            None,
            "a name and a path selector are both required"
        );
        let matched = crate::process::Owner {
            path: "/usr/bin/other".to_owned(),
            ..named
        };
        assert_eq!(
            routing.route(&Flow {
                process: Some(&matched),
                ..flow
            }),
            Some("block")
        );
    }

    #[test]
    fn a_binary_rule_set_reads_open_ended_port_ranges() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(10);
        put_strings(&mut body, &["4000:", ":3000"]);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("ports")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("ports")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("ports.test"),
            ip: None,
            port: Some(5000),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                port: Some(80),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                port: Some(3500),
                ..flow
            }),
            None
        );
    }

    #[test]
    fn a_binary_rule_set_refuses_a_descending_ip_range() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(6);
        put_ip_set(
            &mut body,
            &[(
                "192.0.2.2".parse().expect("address"),
                "192.0.2.1".parse().expect("address"),
            )],
        );
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![(
                "ruleSets",
                array(vec![object(vec![
                    ("tag", text("bad")),
                    ("type", text("local")),
                    ("path", text("rules.srs")),
                ])]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("not a range"), "{error}");
    }

    #[test]
    fn a_binary_rule_set_refuses_query_type_by_name() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(0);
        put_u16s(&mut body, &[1]);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![(
                "ruleSets",
                array(vec![object(vec![
                    ("tag", text("queries")),
                    ("type", text("local")),
                    ("path", text("rules.srs")),
                ])]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("query_type"), "{error}");
    }

    #[test]
    fn added_rules_survive_a_reparse() {
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![rule(
                    "block",
                    vec![("domain", array(vec![text("startup.test")]))],
                )]),
            )]),
        )]);
        let mut routing = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        routing
            .add_rules(
                &[rule(
                    "block",
                    vec![("domain", array(vec![text("added.test")]))],
                )],
                true,
                |tag| tag == "block",
                &[],
            )
            .expect("adds");
        let mut next = Routing::parse_in(&root, Vec::new())
            .expect("parses")
            .expect("routing");
        next.adopt_added_rules(&mut routing).expect("adopts");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("startup.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(next.route(&flow), Some("block"));
        assert_eq!(
            next.route(&Flow {
                domain: Some("added.test"),
                ..flow
            }),
            Some("block")
        );
    }

    #[test]
    fn a_binary_rule_set_reads_adguard_domains() {
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(16);
        put_succinct(
            &mut body,
            &[
                domain_key(ROOT_LABEL, "ads.test"),
                domain_key(0, "exact.test"),
                domain_key(0, "例子.test"),
            ],
        );
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("adg")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("adg")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("ads.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                domain: Some("x.ads.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("exact.test"),
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("x.exact.test"),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("ads.test.evil"),
                ..flow
            }),
            None
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("例子.test"),
                ..flow
            }),
            Some("block"),
            "an AdGuard key reverses characters, not bytes"
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("x.例子.test"),
                ..flow
            }),
            None
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_binary_rule_set_reads_logical_process_and_invert() {
        let mut body = Vec::new();
        body.extend(varint(2));
        body.push(1);
        body.push(1);
        body.extend(varint(2));
        body.push(0);
        body.push(1);
        put_strings(&mut body, &["udp"]);
        body.push(0xff);
        body.push(0);
        body.push(0);
        body.push(2);
        put_succinct(&mut body, &[domain_key(0, "logic.test")]);
        body.push(0xff);
        body.push(0);
        body.push(0);
        body.push(0);
        body.push(11);
        put_strings(&mut body, &["curl"]);
        body.push(0xff);
        body.push(0);
        let dir = dir();
        std::fs::write(dir.join("rules.srs"), wrap_srs(&body)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("logic")),
                        ("type", text("local")),
                        ("path", text("rules.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("logic")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir.clone()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("logic.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                network: Network::Udp,
                ..flow
            }),
            Some("block")
        );
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                ..flow
            }),
            None
        );
        let owner = crate::process::Owner {
            pid: 1,
            name: "curl".to_owned(),
            path: "/usr/bin/curl".to_owned(),
        };
        assert_eq!(
            routing.route(&Flow {
                domain: Some("other.test"),
                process: Some(&owner),
                ..flow
            }),
            Some("block")
        );

        let mut inverted = Vec::new();
        inverted.extend(varint(1));
        inverted.push(0);
        inverted.push(2);
        put_succinct(&mut inverted, &[domain_key(0, "invert.test")]);
        inverted.push(0xff);
        inverted.push(1);
        std::fs::write(dir.join("invert.srs"), wrap_srs(&inverted)).expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("invert")),
                        ("type", text("local")),
                        ("path", text("invert.srs")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("invert")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.route(&flow), Some("block"));
        assert_eq!(
            routing.route(&Flow {
                domain: Some("invert.test"),
                ..flow
            }),
            None
        );
    }

    #[test]
    fn a_remote_rule_set_is_fetched_over_http() {
        let dir = dir();
        let mut body = Vec::new();
        body.extend(varint(1));
        body.push(0);
        body.push(2);
        put_succinct(&mut body, &[domain_key(0, "remote.test")]);
        body.push(0xff);
        body.push(0);
        let srs = wrap_srs(&body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload = srs.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream.write_all(head.as_bytes()).expect("head");
            stream.write_all(&payload).expect("body");
        });
        let url = format!("http://127.0.0.1:{port}/rules.srs");
        let cache = dir.join("cache.srs");
        let cache_text = cache.to_string_lossy();
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("remote")),
                        ("type", text("remote")),
                        ("url", text(&url)),
                        ("path", text(&cache_text)),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("remote")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir.clone()])
            .expect("parses")
            .expect("routing");
        server.join().expect("server");
        assert_eq!(
            std::fs::read(&cache).expect("cache"),
            srs,
            "a successful fetch writes the path the fallback will read"
        );
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("remote.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
    }

    #[test]
    fn a_remote_rule_set_falls_back_to_its_cache() {
        let dir = dir();
        std::fs::write(
            dir.join("cache.json"),
            r#"{"version":3,"rules":[{"domain":["cached.test"]}]}"#,
        )
        .expect("write");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            drop(stream);
        });
        let url = format!("http://127.0.0.1:{port}/rules.json");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "ruleSets",
                    array(vec![object(vec![
                        ("tag", text("remote")),
                        ("type", text("remote")),
                        ("url", text(&url)),
                        ("path", text("cache.json")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![rule(
                        "block",
                        vec![("ruleSet", array(vec![text("remote")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        server.join().expect("server");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("cached.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("block"));
    }

    #[test]
    fn missing_and_late_rule_sets_are_refused_by_name() {
        let dir = dir();
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![rule(
                    "direct",
                    vec![("ruleSet", array(vec![text("none")]))],
                )]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir.clone()]).expect_err("refused");
        assert!(error.contains("none"), "{error}");
        std::fs::write(
            dir.join("late.json"),
            r#"{"version":9,"rules":[{"domain":["a.test"]}]}"#,
        )
        .expect("write");
        let root = object(vec![(
            "routing",
            object(vec![(
                "ruleSets",
                array(vec![object(vec![
                    ("tag", text("late")),
                    ("type", text("local")),
                    ("path", text("late.json")),
                ])]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir]).expect_err("refused");
        assert!(error.contains("version 9"), "{error}");
    }

    #[test]
    fn a_rule_set_field_of_the_wrong_type_is_refused() {
        for (field, wanted) in [("type", "type"), ("format", "format"), ("path", "path")] {
            let set = object(vec![
                ("tag", text("bad")),
                (field, number(1)),
                ("rules", array(Vec::new())),
            ]);
            let root = object(vec![(
                "routing",
                object(vec![("ruleSets", array(vec![set]))]),
            )]);
            let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
            assert!(error.contains(wanted), "{error}");
            assert!(error.contains("not a string"), "{error}");
        }
        let set = object(vec![
            ("tag", text("bad")),
            (
                "rules",
                array(vec![object(vec![
                    ("domain", text("bad.test")),
                    ("invert", text("yes")),
                ])]),
            ),
        ]);
        let root = object(vec![(
            "routing",
            object(vec![("ruleSets", array(vec![set]))]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("invert"), "{error}");
        assert!(error.contains("not a boolean"), "{error}");
    }

    #[test]
    fn a_routing_script_accepts_rules_and_leaves_the_decision_open() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let root = object(vec![(
            "routing",
            object(vec![
                ("script", text("route.lua")),
                ("domainStrategy", text("AsIs")),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![("domain", array(vec![text("x.test")]))],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("x.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("direct"));
    }

    #[test]
    fn unknown_routing_fields_are_refused_by_name() {
        let root = object(vec![(
            "routing",
            object(vec![("notAField", text("x")), ("rules", array(Vec::new()))]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("notAField"), "{error}");
        let root = object(vec![(
            "routing",
            routing(vec![rule("direct", vec![("notAField", text("x"))])]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("notAField"), "{error}");
    }

    #[test]
    fn a_protocol_rule_reads_the_sniffed_protocol() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule(
                    "block",
                    vec![
                        ("domain", array(vec![text("x.com")])),
                        ("protocol", array(vec![text("http")])),
                    ],
                ),
                rule("direct", Vec::new()),
            ]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let named = Flow {
            network: Network::Tcp,
            domain: Some("x.com"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: Some("http1"),
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(parsed.route(&named), Some("block"));
        let bare = Flow {
            network: Network::Udp,
            domain: None,
            ip: None,
            port: None,
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(parsed.route(&bare), Some("direct"));
    }

    #[test]
    fn an_empty_protocol_entry_matches_nothing() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("block", vec![("protocol", array(vec![text("")]))]),
                rule("direct", Vec::new()),
            ]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: None,
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: Some("http1"),
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(parsed.route(&flow), Some("direct"));
    }

    /// A `user` rule names an account's email literally or as a `regexp:` pattern; a flow without
    /// an email never matches. An empty list is no selector, while a list whose entries are all
    /// empty or invalid patterns is a matcher that matches nothing — the reference's split.
    #[test]
    fn a_user_rule_matches_only_the_accounts_it_names() {
        let user_rule = |names: Vec<Json>| {
            object(vec![(
                "routing",
                routing(vec![
                    rule("block", vec![("user", array(names))]),
                    rule("direct", Vec::new()),
                ]),
            )])
        };
        let asked = |user: Option<&'static str>| Flow {
            network: Network::Tcp,
            domain: Some("x.com"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user,
            attrs: None,
            process: None,
        };

        let parsed = Routing::parse_in(
            &user_rule(vec![text("a@x"), text("regexp:^b@")]),
            vec![dir()],
        )
        .expect("parses")
        .expect("routing");
        assert_eq!(parsed.route(&asked(Some("a@x"))), Some("block"));
        assert_eq!(parsed.route(&asked(Some("b@y"))), Some("block"));
        assert_eq!(parsed.route(&asked(Some("c@x"))), Some("direct"));
        assert_eq!(parsed.route(&asked(None)), Some("direct"));
        assert_eq!(parsed.route(&asked(Some(""))), Some("direct"));

        let empty = Routing::parse_in(&user_rule(Vec::new()), vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(empty.route(&asked(Some("a@x"))), Some("block"));
        assert_eq!(empty.route(&asked(None)), Some("block"));

        let nothing = Routing::parse_in(&user_rule(vec![text(""), text("regexp:[")]), vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(
            nothing.rules().len(),
            2,
            "a user matcher with no usable entry still survives"
        );
        assert_eq!(nothing.route(&asked(Some("a@x"))), Some("direct"));
    }

    /// A `vlessRoute` rule matches the route id a vless client sent, and every flow this tree routes
    /// reads 0, as xray's context does off a non-vless inbound: a list holding 0 fires on all of them.
    #[test]
    fn a_vless_route_rule_reads_the_zero_a_routed_flow_carries() {
        let route_rule = |routes: Json| {
            object(vec![(
                "routing",
                routing(vec![
                    rule("block", vec![("vlessRoute", routes)]),
                    rule("direct", Vec::new()),
                ]),
            )])
        };
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("x.com"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: Some("in"),
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let parse = |routes: Json| {
            Routing::parse_in(&route_rule(routes), vec![dir()])
                .expect("parses")
                .expect("routing")
        };
        let zero = parse(text("0"));
        assert_eq!(zero.route(&flow), Some("block"));
        assert_eq!(zero.udp_tag(Some("in"), Some("direct")), Ok(Some("block")));
        let other = parse(text("7"));
        assert_eq!(other.route(&flow), Some("direct"));
        let ranged = parse(array(vec![text("0-3")]));
        assert_eq!(ranged.route(&flow), Some("block"));
        let empty = parse(array(Vec::new()));
        assert_eq!(
            empty.rules().len(),
            2,
            "an empty route list is a matcher that matches nothing, not a skipped rule"
        );
        assert_eq!(empty.route(&flow), Some("direct"));
    }

    /// An `attrs` rule reads the HTTP head a front or the sniffer parsed: every key must be present
    /// and its regexp must match, a key compares without regard to case, and a flow carrying no head
    /// matches no `attrs` rule — a rule whose map is empty is no selector at all.
    #[test]
    fn an_attrs_rule_matches_every_key_the_flow_carries() {
        let attrs_rule = |selectors: Vec<(&str, Json)>| {
            object(vec![(
                "routing",
                routing(vec![
                    rule("block", vec![("attrs", object(selectors))]),
                    rule("direct", Vec::new()),
                ]),
            )])
        };
        let route = |parsed: &Routing, entries: &[(&str, &str)]| {
            let mut attrs = Attributes::new();
            for (name, value) in entries {
                attrs.push(name, Cow::Borrowed(*value));
            }
            let flow = Flow {
                network: Network::Tcp,
                domain: Some("x.com"),
                ip: None,
                port: Some(443),
                source: None,
                source_port: 0,
                local: None,
                local_port: 0,
                vless_route: 0,
                inbound_tag: None,
                protocol: None,
                user: None,
                attrs: (!entries.is_empty()).then_some(&attrs),
                process: None,
            };
            parsed.route(&flow).map(str::to_owned)
        };
        let parsed = Routing::parse_in(
            &attrs_rule(vec![
                (":path", text("^/blocked")),
                ("X-Flag", text("^yes$")),
            ]),
            vec![dir()],
        )
        .expect("parses")
        .expect("routing");
        assert_eq!(
            route(
                &parsed,
                &[
                    (":method", "GET"),
                    (":path", "/blocked/x"),
                    ("x-flag", "yes")
                ]
            )
            .as_deref(),
            Some("block")
        );
        assert_eq!(
            route(&parsed, &[(":path", "/blocked"), ("X-FLAG", "yes")]).as_deref(),
            Some("block"),
            "a key compares without regard to case on either side"
        );
        assert_eq!(
            route(&parsed, &[(":path", "/blocked")]).as_deref(),
            Some("direct"),
            "a key the head does not carry fails the rule"
        );
        assert_eq!(
            route(&parsed, &[(":path", "/open"), ("x-flag", "yes")]).as_deref(),
            Some("direct")
        );
        assert_eq!(
            route(&parsed, &[]).as_deref(),
            Some("direct"),
            "no head, no match"
        );

        let empty = Routing::parse_in(&attrs_rule(Vec::new()), vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(
            empty.rules().len(),
            2,
            "an empty attrs map is no selector, as the reference's length check makes it"
        );
        assert_eq!(route(&empty, &[]).as_deref(), Some("block"));

        let broken = Routing::parse_in(&attrs_rule(vec![(":path", text("["))]), vec![dir()])
            .expect_err("a bad pattern refuses the config");
        assert!(broken.contains("not a regexp"), "{broken}");
    }

    /// A `process` rule names the process behind the client socket: `self/` holds for a socket this
    /// process opened, a bare name for this executable's basename (a trailing `.exe` trimmed), an
    /// absolute path for its path, a trailing `/` for its folder, and a flow with no owner fails.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_rule_names_the_process_behind_the_client_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let client =
            std::net::TcpStream::connect(listener.local_addr().expect("local")).expect("connects");
        let (_server, _) = listener.accept().expect("accepts");
        let source = client.local_addr().expect("source");
        let owner = crate::process::owner(Network::Tcp, source).unwrap_or_else(|| {
            let inode = crate::process::socket_inode(Network::Tcp, source)
                .unwrap_or_else(|| panic!("no row of the kernel table spells the source {source}"));
            let pid = crate::process::owner_pid(&inode)
                .unwrap_or_else(|| panic!("no descriptor of any process holds socket:[{inode}]"));
            panic!("pid {pid} names no executable")
        });
        let route = |names: &[&str], owner: Option<&crate::process::Owner>| {
            let root = object(vec![(
                "routing",
                routing(vec![rule(
                    "block",
                    vec![(
                        "process",
                        array(names.iter().map(|name| text(name)).collect()),
                    )],
                )]),
            )]);
            let parsed = Routing::parse_in(&root, vec![dir()])
                .expect("parses")
                .expect("routing");
            let flow = Flow {
                network: Network::Tcp,
                domain: Some("x.com"),
                ip: None,
                port: Some(443),
                source: Some(source.ip()),
                source_port: source.port(),
                local: None,
                local_port: 0,
                vless_route: 0,
                inbound_tag: None,
                protocol: None,
                user: None,
                attrs: None,
                process: owner,
            };
            parsed.route(&flow).map(str::to_owned)
        };
        assert_eq!(route(&["self/"], Some(&owner)).as_deref(), Some("block"));
        assert_eq!(
            route(&["self/"], None).as_deref(),
            None,
            "a flow with no owner matches no process rule"
        );
        assert_eq!(
            route(&[owner.name.as_str()], Some(&owner)).as_deref(),
            Some("block")
        );
        let exe = format!("{}.exe", owner.name);
        assert_eq!(
            route(&[exe.as_str()], Some(&owner)).as_deref(),
            Some("block"),
            "the reference trims a trailing .exe from a bare name"
        );
        assert_eq!(
            route(&[owner.path.as_str()], Some(&owner)).as_deref(),
            Some("block")
        );
        let folder = format!("{}/", owner.path.rsplit_once('/').expect("a folder").0);
        assert_eq!(
            route(&[folder.as_str()], Some(&owner)).as_deref(),
            Some("block")
        );
        assert_eq!(route(&["no-such-process"], Some(&owner)).as_deref(), None);
        assert_eq!(route(&["/no/such/path"], Some(&owner)).as_deref(), None);
        assert_eq!(route(&["/no/such/folder/"], Some(&owner)).as_deref(), None);
    }

    /// Off Linux the reference's lookup answers nothing, so the rule is carried and never holds;
    /// what this proves is that the parser does not drop it.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_process_rule_is_carried_where_no_lookup_exists() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "block",
                vec![("process", array(vec![text("self/")]))],
            )]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(parsed.rules().len(), 1, "the rule survives the parse");
        assert!(!parsed.rules()[0].catch_all(), "and still narrows");
    }

    #[test]
    fn port_and_network_values_are_read_like_the_reference() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("port", text(" 80, 100-101 ")),
                    ("network", text("TCP,udp")),
                ],
            )]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let mut flow = Flow {
            network: Network::Udp,
            domain: None,
            ip: None,
            port: Some(100),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(102);
        assert_eq!(parsed.route(&flow), None);
        for (name, carried) in [("unix", Network::Other(4)), ("sctp", Network::Other(0))] {
            let root = object(vec![(
                "routing",
                routing(vec![rule("direct", vec![("network", text(name))])]),
            )]);
            let parsed = Routing::parse_in(&root, vec![dir()])
                .expect("parses")
                .expect("routing");
            flow.network = Network::Tcp;
            assert_eq!(parsed.route(&flow), None, "{name}");
            flow.network = carried;
            assert_eq!(parsed.route(&flow), Some("direct"), "{name}");
        }
    }

    #[test]
    fn env_names_the_address_and_port_a_rule_reads() {
        let _env = crate::router::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var("FERROX_ROUTING_ENV_IP", "198.51.100.7");
        std::env::set_var("FERROX_ROUTING_ENV_PORT", "101-102");
        let root = crate::json::parse(
            r#"{"routing": {"rules": [{"outboundTag": "direct",
                "ip": ["env:FERROX_ROUTING_ENV_IP"], "port": "100, env:FERROX_ROUTING_ENV_PORT"}]}}"#,
        )
        .expect("parses");
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let mut flow = Flow {
            network: Network::Tcp,
            domain: None,
            ip: Some("198.51.100.7".parse().expect("ip")),
            port: Some(101),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(100);
        assert_eq!(parsed.route(&flow), Some("direct"));
        flow.port = Some(103);
        assert_eq!(parsed.route(&flow), None);
        flow.port = Some(101);
        flow.ip = Some("198.51.100.8".parse().expect("ip"));
        assert_eq!(parsed.route(&flow), None);
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("port", text("100, env:FERROX_ROUTING_ENV_PORT"))],
            )]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        flow.ip = None;
        flow.port = Some(102);
        assert_eq!(parsed.route(&flow), Some("direct"));
        std::env::remove_var("FERROX_ROUTING_ENV_IP");
        std::env::remove_var("FERROX_ROUTING_ENV_PORT");
    }

    #[test]
    fn a_socks_association_that_could_split_is_not_pinned_to_one_tag() {
        let root = |rules| object(vec![("routing", routing(rules))]);
        let split = root(vec![
            rule("block", vec![("domain", array(vec![text("blocked.test")]))]),
            rule("direct", vec![("inboundTag", array(vec![text("in")]))]),
        ]);
        let routing = Routing::parse_in(&split, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Err(()));
        let shared = root(vec![
            rule(
                "direct",
                vec![("domain", array(vec![text("blocked.test")]))],
            ),
            rule("direct", vec![("inboundTag", array(vec![text("in")]))]),
        ]);
        let routing = Routing::parse_in(&shared, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(
            routing.udp_tag(Some("in"), Some("direct")),
            Ok(Some("direct"))
        );
        let unmatched = root(vec![rule(
            "direct",
            vec![("domain", array(vec![text("blocked.test")]))],
        )]);
        let routing = Routing::parse_in(&unmatched, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Ok(None));
        let default_elsewhere = root(vec![rule(
            "block",
            vec![("domain", array(vec![text("blocked.test")]))],
        )]);
        let routing = Routing::parse_in(&default_elsewhere, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.udp_tag(Some("in"), Some("direct")), Err(()));
    }

    #[test]
    fn a_server_inbound_is_refused_when_routing_could_change_its_direct_dial() {
        let direct = |tag: &str| tag == "direct";
        let candidates = HashMap::new();
        let fallbacks = HashMap::new();
        let both = [Network::Tcp, Network::Udp];
        let stream = [Network::Tcp];
        let proof = |inbound, default_direct, networks| ServerProof {
            inbound,
            default_direct,
            networks,
            direct: Box::new(move |tag| direct(tag)),
            direct_policy: Box::new(|_| true),
            portal_rule: Box::new(|_| false),
            candidates: &candidates,
            fallbacks: &fallbacks,
        };
        let root = |rules| object(vec![("routing", routing(rules))]);
        let pinned = root(vec![rule(
            "direct",
            vec![("inboundTag", array(vec![text("server")]))],
        )]);
        let routing = Routing::parse_in(&pinned, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof(Some("server"), false, &both))
            .expect("the tag's rule pins every flow to direct");
        for selector in [
            ("user", array(vec![text("a@x")])),
            ("vlessRoute", array(vec![number(7)])),
            ("attrs", object(vec![(":path", text("/x"))])),
            ("process", array(vec![text("self/")])),
        ] {
            let skipped_field = root(vec![rule("proxy", vec![selector])]);
            let routing = Routing::parse_in(&skipped_field, vec![dir()])
                .expect("parses")
                .expect("routing");
            let error = routing
                .server_routes(&proof(Some("server"), true, &both))
                .expect_err("a rule the server flow cannot evaluate still names a proxy");
            assert!(error.contains("proxy"), "{error}");
        }
        let direct_by_user = root(vec![rule(
            "direct",
            vec![("user", array(vec![text("a@x")]))],
        )]);
        let routing = Routing::parse_in(&direct_by_user, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof(Some("server"), true, &both))
            .expect("a rule that still targets direct changes nothing");
        let by_udp = root(vec![rule(
            "proxy",
            vec![("network", array(vec![text("udp")]))],
        )]);
        let routing = Routing::parse_in(&by_udp, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(&proof(Some("server"), true, &both))
            .expect_err("a UDP-only rule can reach the server too");
        routing
            .server_routes(&proof(Some("server"), true, &stream))
            .expect("a UDP-only rule cannot reach a stream-only inbound");
        assert!(error.contains("proxy"), "{error}");
        let proxy = root(vec![rule("proxy", vec![("port", number(443))])]);
        let routing = Routing::parse_in(&proxy, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(&proof(Some("server"), true, &both))
            .expect_err("a per-flow rule can reach the server");
        assert!(error.contains("proxy"), "{error}");
        let default_proxy = root(Vec::new());
        let routing = Routing::parse_in(&default_proxy, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(&proof(Some("server"), false, &both))
            .expect_err("the default is not direct");
        assert!(error.contains("default"), "{error}");
    }

    #[test]
    fn a_server_inbound_stops_checking_a_network_a_direct_rule_covers() {
        let direct = |tag: &str| tag == "direct";
        let candidates = HashMap::new();
        let fallbacks = HashMap::new();
        let both = [Network::Tcp, Network::Udp];
        let proof = ServerProof {
            inbound: Some("server"),
            default_direct: true,
            networks: &both,
            direct: Box::new(move |tag| direct(tag)),
            direct_policy: Box::new(|_| true),
            portal_rule: Box::new(|_| false),
            candidates: &candidates,
            fallbacks: &fallbacks,
        };
        let root = |rules| object(vec![("routing", routing(rules))]);
        let covered_udp = root(vec![
            rule("direct", vec![("network", array(vec![text("udp")]))]),
            rule("proxy", vec![("network", array(vec![text("udp")]))]),
        ]);
        let routing = Routing::parse_in(&covered_udp, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof)
            .expect("the first UDP rule decides every UDP flow");
        let covered_tcp_only = root(vec![
            rule("direct", vec![("network", array(vec![text("tcp")]))]),
            rule("proxy", Vec::new()),
        ]);
        let routing = Routing::parse_in(&covered_tcp_only, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(&proof)
            .expect_err("the all-network proxy rule still decides UDP");
        assert!(error.contains("proxy"), "{error}");
        let covered_both = root(vec![rule("direct", Vec::new()), rule("proxy", Vec::new())]);
        let routing = Routing::parse_in(&covered_both, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof)
            .expect("the first catch-all rule decides both networks");
        let proxy_first = root(vec![
            rule("proxy", vec![("network", array(vec![text("udp")]))]),
            rule("direct", vec![("network", array(vec![text("udp")]))]),
        ]);
        let routing = Routing::parse_in(&proxy_first, vec![dir()])
            .expect("parses")
            .expect("routing");
        let error = routing
            .server_routes(&proof)
            .expect_err("the first UDP rule names a proxy");
        assert!(error.contains("proxy"), "{error}");
    }

    #[test]
    fn a_rule_set_outside_the_served_networks_is_not_a_refusal() {
        let direct = |tag: &str| tag == "direct";
        let candidates = HashMap::new();
        let fallbacks = HashMap::new();
        let both = [Network::Tcp, Network::Udp];
        let proof = ServerProof {
            inbound: Some("server"),
            default_direct: true,
            networks: &both,
            direct: Box::new(move |tag| direct(tag)),
            direct_policy: Box::new(|_| true),
            portal_rule: Box::new(|_| false),
            candidates: &candidates,
            fallbacks: &fallbacks,
        };
        let set = object(vec![
            ("tag", text("tcp")),
            (
                "rules",
                array(vec![object(vec![("network", array(vec![text("tcp")]))])]),
            ),
        ]);
        let root = object(vec![(
            "routing",
            object(vec![
                ("ruleSets", array(vec![set])),
                (
                    "rules",
                    array(vec![rule(
                        "proxy",
                        vec![
                            ("network", array(vec![text("udp")])),
                            ("ruleSet", array(vec![text("tcp")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof)
            .expect("a TCP-only rule set cannot reach a UDP-only rule");
    }

    #[test]
    fn a_balancer_without_candidates_checks_its_direct_fallback() {
        let direct = |tag: &str| tag == "direct";
        let candidates = HashMap::new();
        let mut fallbacks = HashMap::new();
        fallbacks.insert("pool".to_owned(), "direct".to_owned());
        let both = [Network::Tcp, Network::Udp];
        let proof = ServerProof {
            inbound: Some("server"),
            default_direct: false,
            networks: &both,
            direct: Box::new(move |tag| direct(tag)),
            direct_policy: Box::new(|_| true),
            portal_rule: Box::new(|_| false),
            candidates: &candidates,
            fallbacks: &fallbacks,
        };
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("node")])),
                        ("fallbackTag", text("direct")),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![object(vec![("balancerTag", text("pool"))])]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        routing
            .server_routes(&proof)
            .expect("an empty candidate list falls back to direct");
        let scoped = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("node")])),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![
                        object(vec![("balancerTag", text("pool")), ("port", number(443))]),
                        object(vec![("outboundTag", text("direct"))]),
                    ]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&scoped, vec![dir()])
            .expect("parses")
            .expect("routing");
        let candidates = HashMap::from([("pool".to_owned(), vec!["direct".to_owned()])]);
        let no_fallback = HashMap::new();
        let proxy_default = ServerProof {
            candidates: &candidates,
            fallbacks: &no_fallback,
            default_direct: false,
            ..proof
        };
        routing
            .server_routes(&proxy_default)
            .expect("a nonempty random pool never falls to the proxy default");
        let no_candidates = HashMap::new();
        let no_pick = ServerProof {
            candidates: &no_candidates,
            ..proxy_default
        };
        let error = routing
            .server_routes(&no_pick)
            .expect_err("an empty random pool falls to the proxy default");
        assert!(error.contains("pool"), "{error}");
        let direct_default = ServerProof {
            default_direct: true,
            ..no_pick
        };
        routing
            .server_routes(&direct_default)
            .expect("a direct default covers a strategy with no pick");
    }

    #[test]
    fn an_empty_user_or_protocol_entry_never_reaches_a_server_inbound() {
        let direct = |tag: &str| tag == "direct";
        let candidates = HashMap::new();
        let fallbacks = HashMap::new();
        let both = [Network::Tcp, Network::Udp];
        let proof = ServerProof {
            inbound: Some("server"),
            default_direct: true,
            networks: &both,
            direct: Box::new(move |tag| direct(tag)),
            direct_policy: Box::new(|_| true),
            portal_rule: Box::new(|_| false),
            candidates: &candidates,
            fallbacks: &fallbacks,
        };
        for selector in [
            ("user", array(vec![text("")])),
            ("protocol", array(vec![text("")])),
        ] {
            let root = object(vec![(
                "routing",
                routing(vec![rule("proxy", vec![selector])]),
            )]);
            let routing = Routing::parse_in(&root, vec![dir()])
                .expect("parses")
                .expect("routing");
            routing
                .server_routes(&proof)
                .expect("a selector with no value matches no server flow");
        }
    }

    #[test]
    fn a_tun_inbound_refuses_the_selectors_it_cannot_answer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![
                    ("inboundTag", array(vec![text("tun")])),
                    ("source", array(vec![text("192.0.2.0/24")])),
                ],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), Some("source"));
        assert_eq!(routing.source_refusal(Some("other")), None);
    }

    #[test]
    fn a_shadowed_udp_source_rule_does_not_refuse_the_tun() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule(
                    "direct",
                    vec![
                        ("inboundTag", array(vec![text("tun")])),
                        ("network", text("udp")),
                    ],
                ),
                rule(
                    "direct",
                    vec![
                        ("inboundTag", array(vec![text("tun")])),
                        ("network", text("udp")),
                        ("source", array(vec![text("192.0.2.0/24")])),
                    ],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), None);
    }

    #[test]
    fn a_rule_set_source_selector_is_checked_on_the_flow_network() {
        let mixed = object(vec![
            ("tag", text("mixed")),
            (
                "rules",
                array(vec![
                    object(vec![
                        ("network", text("tcp")),
                        ("source_ip_cidr", array(vec![text("192.0.2.0/24")])),
                    ]),
                    object(vec![
                        ("network", text("udp")),
                        ("ip_cidr", array(vec![text("198.51.100.0/24")])),
                    ]),
                ]),
            ),
        ]);
        let root = object(vec![(
            "routing",
            object(vec![
                ("ruleSets", array(vec![mixed])),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![
                            ("inboundTag", array(vec![text("tun")])),
                            ("network", text("udp")),
                            ("ruleSet", array(vec![text("mixed")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), None);

        let source = object(vec![
            ("tag", text("source")),
            (
                "rules",
                array(vec![object(vec![
                    ("network", text("udp")),
                    ("source_ip_cidr", array(vec![text("192.0.2.0/24")])),
                ])]),
            ),
        ]);
        let root = object(vec![(
            "routing",
            object(vec![
                ("ruleSets", array(vec![source])),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![
                            ("inboundTag", array(vec![text("tun")])),
                            ("network", text("udp")),
                            ("ruleSet", array(vec![text("source")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), Some("ruleSet"));
    }

    #[test]
    fn a_nested_tcp_group_does_not_refuse_the_udp_rule() {
        let nested = object(vec![
            ("tag", text("nested")),
            (
                "rules",
                array(vec![object(vec![
                    ("type", text("logical")),
                    ("mode", text("and")),
                    (
                        "rules",
                        array(vec![
                            object(vec![
                                ("type", text("logical")),
                                ("mode", text("or")),
                                (
                                    "rules",
                                    array(vec![object(vec![
                                        ("network", text("tcp")),
                                        ("ip_cidr", array(vec![text("198.51.100.0/24")])),
                                    ])]),
                                ),
                            ]),
                            object(vec![
                                ("network", text("udp")),
                                ("source_ip_cidr", array(vec![text("192.0.2.0/24")])),
                            ]),
                        ]),
                    ),
                ])]),
            ),
        ]);
        let root = object(vec![(
            "routing",
            object(vec![
                ("ruleSets", array(vec![nested])),
                (
                    "rules",
                    array(vec![rule(
                        "direct",
                        vec![
                            ("inboundTag", array(vec![text("tun")])),
                            ("network", text("udp")),
                            ("ruleSet", array(vec![text("nested")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(routing.source_refusal(Some("tun")), None);
    }

    #[test]
    fn a_tun_inbound_may_use_a_script_but_a_server_inbound_may_not() {
        let dir = dir();
        std::fs::write(
            dir.join("route.lua"),
            "function HandleRoute() return nil end",
        )
        .expect("write");
        let root = object(vec![(
            "routing",
            object(vec![("script", text("route.lua"))]),
        )]);
        #[cfg(not(target_os = "ios"))]
        {
            let routing = Routing::parse_in(&root, vec![dir])
                .expect("parses")
                .expect("routing");
            assert_eq!(routing.source_refusal(Some("tun")), None);
            let both = [Network::Tcp, Network::Udp];
            let proof = ServerProof {
                inbound: Some("server"),
                default_direct: true,
                networks: &both,
                direct: Box::new(|_| true),
                direct_policy: Box::new(|_| true),
                portal_rule: Box::new(|_| false),
                candidates: &HashMap::new(),
                fallbacks: &HashMap::new(),
            };
            let error = routing
                .server_routes(&proof)
                .expect_err("a server inbound cannot evaluate a script");
            assert!(error.contains("script"), "{error}");
        }
        #[cfg(target_os = "ios")]
        {
            let error = Routing::parse_in(&root, vec![dir])
                .expect_err("iOS refuses a config that names a script");
            assert!(error.contains("cannot be enforced"), "{error}");
        }
    }

    #[test]
    fn a_flow_without_a_domain_matcher_allocates_nothing() {
        let root = object(vec![(
            "routing",
            routing(vec![rule("direct", vec![("port", number(80))])]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, None);
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn a_lowercase_host_matches_without_a_buffer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("www.example.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("direct"));
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_takes_one_lowercase_buffer() {
        let root = object(vec![(
            "routing",
            routing(vec![rule(
                "direct",
                vec![("domain", array(vec![text("domain:example.test")]))],
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("direct"));
        assert_eq!(counts.allocs, 1, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_is_lowercased_once_for_the_table() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule(
                    "first",
                    vec![("domain", array(vec![text("keyword:blocked")]))],
                ),
                rule(
                    "second",
                    vec![("domain", array(vec![text("domain:example.test")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("second"));
        assert_eq!(counts.allocs, 1, "{counts:?}");
    }

    #[test]
    fn a_mixed_case_host_matched_before_a_domain_rule_is_not_lowered() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("first", vec![("port", number(443))]),
                rule(
                    "second",
                    vec![("domain", array(vec![text("keyword:blocked")]))],
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("WWW.EXAMPLE.TEST"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let (tag, counts) = ferrox_core::alloc_count::measure(|| routing.route(&flow));
        assert_eq!(tag, Some("first"));
        assert_eq!(counts.allocs, 0, "{counts:?}");
    }

    #[test]
    fn ip_if_non_match_does_not_resolve_without_an_ip_rule() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPIfNonMatch")),
                (
                    "rules",
                    array(vec![rule("udp", vec![("network", text("udp"))])]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            Vec::new()
        });
        assert_eq!(tag, None);
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn ip_on_demand_does_not_resolve_when_a_later_selector_fails() {
        let root = object(vec![(
            "routing",
            object(vec![
                ("domainStrategy", text("IPOnDemand")),
                (
                    "rules",
                    array(vec![rule(
                        "address",
                        vec![
                            ("ip", array(vec![text("192.0.2.0/24")])),
                            ("sourceIP", array(vec![text("10.0.0.0/8")])),
                        ],
                    )]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&flow, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, None);
        assert_eq!(lookups.get(), 0);
        let from_source = Flow {
            source: Some("10.1.2.3".parse().expect("source")),
            source_port: 4242,
            ..flow
        };
        let lookups = std::cell::Cell::new(0);
        let tag = routing.route_with(&from_source, &|_, _| {
            lookups.set(lookups.get() + 1);
            vec!["192.0.2.1".parse().expect("ip")]
        });
        assert_eq!(tag, Some("address"));
        assert_eq!(lookups.get(), 1);
    }

    #[test]
    fn a_balancer_rule_draws_from_the_outbound_tags_it_selects() {
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("lane-")])),
                        ("strategy", object(vec![("type", text("roundRobin"))])),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![object(vec![
                        ("balancerTag", text("pool")),
                        ("network", text("tcp")),
                    ])]),
                ),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let balancer = routing.balancer("pool").expect("the balancer");
        assert!(balancer.selects("lane-a") && balancer.selects("lane-b"));
        assert!(!balancer.selects("direct"));
        let candidates = vec!["lane-a".to_owned(), "lane-b".to_owned()];
        assert_eq!(balancer.pick(&candidates, None).as_deref(), Some("lane-a"));
        assert_eq!(balancer.pick(&candidates, None).as_deref(), Some("lane-b"));
        assert_eq!(balancer.pick(&candidates, None).as_deref(), Some("lane-a"));
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("pool"));
    }

    #[test]
    fn a_least_ping_balancer_picks_the_lowest_alive_delay() {
        let root = object(vec![(
            "routing",
            object(vec![(
                "balancers",
                array(vec![object(vec![
                    ("tag", text("pool")),
                    ("selector", array(vec![text("lane")])),
                    ("strategy", object(vec![("type", text("leastPing"))])),
                ])]),
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let balancer = routing.balancer("pool").expect("the balancer");
        let candidates = vec!["lane-a".to_owned(), "lane-b".to_owned()];
        let first = [observed("lane-a", true, 30), observed("lane-b", true, 10)];
        assert_eq!(
            balancer.pick(&candidates, Some(&first)).as_deref(),
            Some("lane-b")
        );
        let dead = [observed("lane-a", false, 1), observed("lane-b", true, 90)];
        assert_eq!(
            balancer.pick(&candidates, Some(&dead)).as_deref(),
            Some("lane-b")
        );
    }

    #[test]
    fn a_least_load_balancer_honours_weight_baseline_and_tolerance() {
        let root = object(vec![(
            "routing",
            object(vec![(
                "balancers",
                array(vec![object(vec![
                    ("tag", text("pool")),
                    ("selector", array(vec![text("lane")])),
                    (
                        "strategy",
                        object(vec![
                            ("type", text("leastLoad")),
                            (
                                "settings",
                                object(vec![
                                    ("expected", Json::Num(1.0)),
                                    ("baselines", array(vec![text("15ms")])),
                                    ("tolerance", Json::Num(0.05)),
                                    (
                                        "costs",
                                        array(vec![object(vec![
                                            ("match", text("lane-b")),
                                            ("value", Json::Num(4.0)),
                                        ])]),
                                    ),
                                ]),
                            ),
                        ]),
                    ),
                ])]),
            )]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let balancer = routing.balancer("pool").expect("the balancer");
        let candidates = vec!["lane-a".to_owned(), "lane-b".to_owned()];
        let mut b = observed("lane-b", true, 10);
        b.health = Some(HealthPing {
            all: 10,
            fail: 2,
            deviation: 10_000_000,
            average: 10_000_000,
        });
        let observed = [observed("lane-a", true, 10), b];
        assert_eq!(
            balancer.pick(&candidates, Some(&observed)).as_deref(),
            Some("lane-a")
        );
    }

    #[test]
    fn random_skips_a_dead_lane_only_when_a_fallback_exists() {
        let parse = |fallback: bool| {
            let mut pairs = vec![
                ("tag", text("pool")),
                ("selector", array(vec![text("lane")])),
                ("strategy", object(vec![("type", text("random"))])),
            ];
            if fallback {
                pairs.push(("fallbackTag", text("lane-a")));
            }
            object(vec![(
                "routing",
                object(vec![("balancers", array(vec![object(pairs)]))]),
            )])
        };
        let candidates = vec!["lane-a".to_owned(), "lane-b".to_owned()];
        let observed = [observed("lane-a", false, 1), observed("lane-b", true, 2)];
        let plain = Routing::parse_in(&parse(false), vec![dir()])
            .expect("parses")
            .expect("routing");
        let picks = (0..16)
            .map(|_| {
                plain
                    .balancer("pool")
                    .expect("balancer")
                    .pick(&candidates, Some(&observed))
            })
            .collect::<Vec<_>>();
        assert!(picks.iter().any(|p| p.as_deref() == Some("lane-a")));
        assert!(picks.iter().any(|p| p.as_deref() == Some("lane-b")));
        let filtered = Routing::parse_in(&parse(true), vec![dir()])
            .expect("parses")
            .expect("routing");
        for _ in 0..16 {
            assert_eq!(
                filtered
                    .balancer("pool")
                    .expect("balancer")
                    .pick(&candidates, Some(&observed))
                    .as_deref(),
                Some("lane-b")
            );
        }
    }

    fn observed(tag: &str, alive: bool, delay_ms: i64) -> Observed {
        Observed {
            tag: tag.to_owned(),
            alive,
            delay_ms,
            health: None,
            ..Observed::default()
        }
    }

    #[test]
    fn a_balancer_parse_refuses_the_names_it_cannot_honour() {
        let balancer = |pairs: Vec<(&str, Json)>| {
            object(vec![(
                "routing",
                object(vec![("balancers", array(vec![object(pairs)]))]),
            )])
        };
        let error = Routing::parse_in(
            &balancer(vec![
                ("tag", text("pool")),
                ("selector", array(vec![text("lane")])),
                ("strategy", object(vec![("type", text("fancy"))])),
            ]),
            vec![dir()],
        )
        .expect_err("refused");
        assert!(error.contains("fancy"), "{error}");
        let error = Routing::parse_in(
            &balancer(vec![("tag", text("pool")), ("selector", array(Vec::new()))]),
            vec![dir()],
        )
        .expect_err("refused");
        assert!(error.contains("selector"), "{error}");
        let root = object(vec![(
            "routing",
            object(vec![
                (
                    "balancers",
                    array(vec![object(vec![
                        ("tag", text("pool")),
                        ("selector", array(vec![text("lane")])),
                    ])]),
                ),
                (
                    "rules",
                    array(vec![object(vec![
                        ("outboundTag", text("direct")),
                        ("balancerTag", text("pool")),
                        ("network", text("tcp")),
                    ])]),
                ),
            ]),
        )]);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("echo.test"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(
            parsed.route_target(&flow).map(|hit| hit.target),
            Some(RouteTarget::Outbound("direct")),
            "outboundTag wins over balancerTag, as the reference's switch does"
        );
        let root = object(vec![(
            "routing",
            object(vec![(
                "rules",
                array(vec![object(vec![
                    ("balancerTag", text("missing")),
                    ("network", text("tcp")),
                ])]),
            )]),
        )]);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn a_rule_naming_a_webhook_still_routes() {
        let root = crate::json::parse(
            r#"{"routing":{"rules":[{"domain":["example.test"],"outboundTag":"direct",
                "webhook":{"url":"http://127.0.0.1:9/hook"}}]}}"#,
        )
        .expect("parses");
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("example.test"),
            ip: None,
            port: Some(80),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        assert_eq!(
            parsed.route(&flow),
            Some("direct"),
            "the rule must keep routing the flow it matches"
        );
    }

    #[test]
    fn a_webhook_action_rides_the_rule_that_names_it() {
        let routing = |webhook: &str| {
            crate::json::parse(&format!(
                r#"{{"routing":{{"rules":[{{"domain":["example.test"],"outboundTag":"direct",
                    "webhook":{webhook}}}]}}}}"#
            ))
            .expect("parses")
        };
        let flow = Flow {
            network: Network::Tcp,
            domain: Some("example.test"),
            ip: None,
            port: Some(80),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        let root = routing(r#"{"url":"http://127.0.0.1:9/hook","headers":{"X-Probe":"1"}}"#);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let hit = parsed
            .route_target(&flow)
            .expect("the webhook rule matches");
        assert_eq!(hit.tag(), "direct");
        assert!(hit.webhook.is_some(), "the rule carries its notifier");
        let root = routing(r#"{"url":""}"#);
        let parsed = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let hit = parsed.route_target(&flow).expect("the rule still matches");
        assert!(
            hit.webhook.is_none(),
            "an entry with no URL notifies nobody"
        );
        let root = routing(r#"{"url":"http://127.0.0.1:9/hook","headers":["X-Probe"]}"#);
        let error = Routing::parse_in(&root, vec![dir()]).expect_err("refused");
        assert!(error.contains("headers"), "{error}");
    }

    #[test]
    fn the_rule_list_is_kept_in_file_order() {
        let root = object(vec![(
            "routing",
            routing(vec![
                rule("a", vec![("port", number(1))]),
                rule("b", vec![("port", number(2))]),
            ]),
        )]);
        let routing = Routing::parse_in(&root, vec![dir()])
            .expect("parses")
            .expect("routing");
        let targets: Vec<&str> = routing
            .rules()
            .iter()
            .map(|rule| rule.target.as_str())
            .collect();
        assert_eq!(targets, ["a", "b"]);
    }

    fn resolver(root: &Json) -> Arc<crate::dnsapp::Resolver> {
        Arc::new(
            crate::dnsapp::Resolver::from_root(root)
                .expect("resolver")
                .expect("configured"),
        )
    }

    #[test]
    fn a_routed_lookup_uses_the_configured_family_strategy() {
        let root = object(vec![(
            "dns",
            object(vec![
                ("queryStrategy", text("UseIPv4")),
                ("servers", array(vec![text("localhost")])),
                (
                    "hosts",
                    object(vec![
                        (
                            "dual.test",
                            array(vec![text("10.0.0.1"), text("2001:db8::1")]),
                        ),
                        ("localhost", array(vec![text("2001:db8::1")])),
                    ]),
                ),
            ]),
        )]);
        let resolver = resolver(&root);
        let (ips, ttl) = resolve_ips_ttl_with(Some(&resolver), "dual.test", 0);
        assert_eq!(ttl, 10);
        assert_eq!(ips, vec!["10.0.0.1".parse::<IpAddr>().expect("ipv4")]);
        let (ips, _) = resolve_ips_ttl_with(Some(&resolver), "localhost", 0);
        assert!(
            ips.is_empty(),
            "an authoritative empty answer is not retried through the system"
        );
    }

    #[test]
    fn a_skipped_fake_server_falls_back_to_the_system() {
        let root = crate::json::parse(
            r#"{"dns":{"servers":["fakedns"],"queryStrategy":"UseIP"},"fakeDns":{"ipPool":"198.18.0.0/15","poolSize":32768}}"#,
        )
        .expect("parses");
        let resolver = resolver(&root);
        let (ips, _) = resolve_ips_ttl_with(Some(&resolver), "192.0.2.7", 0);
        assert_eq!(
            ips,
            vec!["192.0.2.7".parse::<IpAddr>().expect("ipv4")],
            "a skipped fake server falls back to the system"
        );
    }

    #[test]
    fn a_failed_family_still_falls_back_to_the_system() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        let fixture = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut qtypes = Vec::new();
            for _ in 0..2 {
                let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                    return qtypes;
                };
                let Some(question) = ferrox_core::dns::parse_query(&buf[..len]) else {
                    continue;
                };
                qtypes.push(question.qtype);
                let reply = if question.qtype == 28 {
                    b"not a dns answer".to_vec()
                } else {
                    ferrox_core::dns::ip_answer(&question, 0, 60, &[]).expect("answer")
                };
                socket.send_to(&reply, peer).expect("reply");
            }
            qtypes
        });
        let root = crate::json::parse(&format!(
            r#"{{"dns":{{"servers":["udp://127.0.0.1:{port}"],"queryStrategy":"UseIP"}}}}"#
        ))
        .expect("parses");
        let resolver = resolver(&root);
        let (ips, _) = resolve_ips_ttl_with(Some(&resolver), "192.0.2.7", 0);
        let mut qtypes = fixture.join().expect("fixture");
        qtypes.sort_unstable();
        assert_eq!(qtypes, [1, 28], "the fixture must receive both queries");
        assert_eq!(
            ips,
            vec!["192.0.2.7".parse::<IpAddr>().expect("ipv4")],
            "a failed family is not an authoritative empty answer"
        );
    }

    #[test]
    fn an_inverted_process_rule_reaches_every_network() {
        let rule = SetRule {
            invert: true,
            logical: None,
            networks: Some(vec![Network::Tcp]),
            domains: None,
            ports: None,
            source_ports: None,
            ips: None,
            source_ips: None,
            process: Some(SetProcess {
                names: vec!["x".to_owned()],
                paths: Vec::new(),
                patterns: Vec::new(),
            }),
        };
        assert!(rule.can_reach_on(Network::Tcp));
        assert!(rule.can_reach_on(Network::Udp));
    }
}
