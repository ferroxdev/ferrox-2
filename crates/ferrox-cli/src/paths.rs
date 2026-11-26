//! Where a lane keeps its config, pid, log and proxy transaction. The release
//! package owns no repository, so the paths are the platform's own per-user
//! directories, and `FERROX_CONF_DIR`/`FERROX_STATE_DIR` can move them.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP: AtomicU64 = AtomicU64::new(0);

pub const MAX_PRIVATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Paths {
    pub conf_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cfg: PathBuf,
    pub pid_file: PathBuf,
    pub log: PathBuf,
    pub stop_file: PathBuf,
    pub proxy_ports: PathBuf,
    pub proxy_state: PathBuf,
    pub supervisor_file: PathBuf,
    pub supervisor_pid: PathBuf,
    pub location_file: PathBuf,
    pub locations_file: PathBuf,
    pub psiphon_location: PathBuf,
    pub psiphon_locations: PathBuf,
    pub veepn_location: PathBuf,
    pub veepn_locations: PathBuf,
    pub warp_identity: PathBuf,
    pub psiphon_dir: PathBuf,
    pub lanes_file: PathBuf,
    pub proxy_owner: PathBuf,
    pub creds: PathBuf,
    pub token_file: PathBuf,
}

/// The invoking account's home when `sudo` raised this process: `sudo` resets
/// `HOME` to the target account, so credentials saved without it would vanish.
#[cfg(unix)]
fn passwd_home(uid: Option<u32>, name: Option<&str>) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};

    let mut info: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let result = if let Some(uid) = uid {
        unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut info,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        }
    } else {
        let name = CString::new(name?).ok()?;
        unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut info,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        }
    };
    if result != 0 || found.is_null() || info.pw_dir.is_null() {
        return None;
    }
    let home = unsafe { CStr::from_ptr(info.pw_dir) }.to_str().ok()?;
    (!home.is_empty()).then(|| PathBuf::from(home))
}

#[cfg(unix)]
pub(crate) fn sudo_home() -> Option<PathBuf> {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok());
    let name = std::env::var("SUDO_USER").ok();
    if uid.is_none() && name.is_none() {
        return None;
    }
    passwd_home(uid, name.as_deref())
}

/// A root CLI started through `sudo` hands its files back to the invoking
/// account, so a later unprivileged `status` and `down` can read and remove them.
#[cfg(unix)]
pub fn hand_back(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
    else {
        return;
    };
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|gid| gid.parse::<u32>().ok());
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let _ = unsafe {
        libc::chown(
            path.as_ptr(),
            uid as libc::uid_t,
            gid.map_or(libc::gid_t::MAX, |gid| gid as libc::gid_t),
        )
    };
}

#[cfg(not(unix))]
pub fn hand_back(_path: &Path) {}

fn home() -> PathBuf {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0
        && let Some(home) = sudo_home()
    {
        return home;
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn conf_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERROX_CONF_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(windows)
        && let Some(base) = std::env::var_os("APPDATA")
    {
        return PathBuf::from(base).join("ferrox");
    }
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(base).join("ferrox");
    }
    home().join(".config").join("ferrox")
}

fn state_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("FERROX_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(windows)
        && let Some(base) = std::env::var_os("LOCALAPPDATA")
    {
        return PathBuf::from(base).join("ferrox");
    }
    if cfg!(target_os = "macos") {
        return home()
            .join("Library")
            .join("Application Support")
            .join("ferrox");
    }
    if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(base).join("ferrox");
    }
    home().join(".local").join("state").join("ferrox")
}

fn credential_path(conf_dir: &Path, named: Option<std::ffi::OsString>) -> PathBuf {
    named
        .filter(|path| !path.is_empty())
        .map_or_else(|| conf_dir.join("credentials"), PathBuf::from)
}

impl Paths {
    pub fn new(instance: Option<&str>) -> Self {
        Self::with_dirs(conf_root(), state_root(), instance)
    }

    pub fn with_dirs(conf_dir: PathBuf, state_dir: PathBuf, instance: Option<&str>) -> Self {
        let suffix = instance.map_or_else(String::new, |name| format!("-{name}"));
        let creds = credential_path(&conf_dir, std::env::var_os("FOXY_CREDENTIALS"));
        Self {
            cfg: conf_dir.join(format!("lane{suffix}.json")),
            pid_file: conf_dir.join(format!("lane{suffix}.pid")),
            log: conf_dir.join(format!("lane{suffix}.log")),
            stop_file: state_dir.join(format!("lane{suffix}.stop")),
            proxy_ports: state_dir.join(format!("system-proxy{suffix}.ports")),
            proxy_state: state_dir.join(format!("system-proxy{suffix}.state")),
            supervisor_file: state_dir.join(format!("system-proxy{suffix}.supervisor")),
            supervisor_pid: state_dir.join(format!("system-proxy{suffix}.supervisor.pid")),
            location_file: conf_dir.join(format!("foxy-location{suffix}")),
            locations_file: conf_dir.join("foxy-locations.jsonl"),
            psiphon_location: conf_dir.join(format!("psiphon-location{suffix}")),
            psiphon_locations: conf_dir.join("psiphon-locations.jsonl"),
            veepn_location: conf_dir.join(format!("veepn-location{suffix}")),
            veepn_locations: conf_dir.join("veepn-locations.jsonl"),
            warp_identity: conf_dir.join(format!("warp-identity{suffix}.json")),
            psiphon_dir: conf_dir.join(format!("psiphon{suffix}")),
            lanes_file: state_dir.join("lanes"),
            proxy_owner: state_dir.join("system-proxy.owner"),
            creds,
            token_file: conf_dir.join("foxy-token.json"),
            conf_dir,
            state_dir,
        }
    }
}

#[cfg(windows)]
fn icacls(path: &Path, grant: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "icacls {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

pub fn secure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        hand_back(path);
    }
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        icacls(path, &format!("{user}:(OI)(CI)F"))?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn secure_file(path: &Path) -> std::io::Result<()> {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
    icacls(path, &format!("{user}:F"))?;
    Ok(())
}

/// Replace a private file atomically: a reader never sees a half-written
/// credential, and the new inode is owner-only before a byte lands in it.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    secure_dir(parent)?;
    let name = path
        .file_name()
        .map_or_else(|| "ferrox".into(), |name| name.to_string_lossy());
    for _ in 0..32 {
        let serial = TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".{name}.tmp.{}.{serial}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        if let Err(error) = secure_file(&temp) {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        let written = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.flush());
        drop(file);
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        match std::fs::rename(&temp, path) {
            Ok(()) => {
                hand_back(path);
                return Ok(());
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot create a private temporary file",
    ))
}

/// Read a small private file, refusing instead of silently truncating when a
/// planted file is larger than the launcher ever writes.
pub fn read_trim_checked(path: &Path) -> std::io::Result<String> {
    let mut text = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_PRIVATE_BYTES + 1)
        .read_to_end(&mut text)?;
    if text.len() as u64 > MAX_PRIVATE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file is larger than 8 MiB",
        ));
    }
    Ok(String::from_utf8_lossy(&text).trim().to_owned())
}

pub fn read_trim(path: &Path) -> Option<String> {
    read_trim_checked(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_sudo_uid_resolves_the_invoking_users_home_from_passwd() {
        let uid = unsafe { libc::geteuid() };
        let expected = std::env::var_os("HOME").map(PathBuf::from);
        let resolved =
            passwd_home(Some(uid), None).expect("the current account has a passwd entry");
        if let Some(expected) = expected {
            assert_eq!(resolved, expected);
        }
        assert!(!resolved.as_os_str().is_empty());
    }

    #[test]
    fn a_named_credentials_file_leaves_the_default_beside_the_config() {
        let conf = Path::new("/tmp/ferrox-conf");
        assert_eq!(credential_path(conf, None), conf.join("credentials"));
        assert_eq!(
            credential_path(conf, Some(std::ffi::OsString::from(""))),
            conf.join("credentials")
        );
        assert_eq!(
            credential_path(conf, Some(std::ffi::OsString::from("/tmp/foxy-account"))),
            PathBuf::from("/tmp/foxy-account")
        );
    }

    #[test]
    fn an_oversized_private_read_is_refused_not_truncated() {
        let serial = TEMP.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-paths-big-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("oversized");
        std::fs::write(&path, vec![b'x'; MAX_PRIVATE_BYTES as usize + 1]).expect("write");
        assert!(read_trim_checked(&path).is_err());
        assert!(read_trim(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_private_write_replaces_the_file_and_leaves_no_temp() {
        let serial = TEMP.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-paths-{}-{serial}", std::process::id()));
        let path = dir.join("credentials");
        write_private(&path, "first\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file = std::fs::metadata(&path).expect("file");
            let parent = std::fs::metadata(&dir).expect("dir");
            assert_eq!(file.permissions().mode() & 0o777, 0o600);
            assert_eq!(parent.permissions().mode() & 0o777, 0o700);
        }
        write_private(&path, "second\n").expect("replace");
        assert_eq!(read_trim(&path).as_deref(), Some("second"));
        let names: Vec<String> = std::fs::read_dir(&dir)
            .expect("dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["credentials"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
