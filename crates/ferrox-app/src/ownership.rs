#[cfg(unix)]
fn invoking_uid() -> Option<u32> {
    (unsafe { libc::geteuid() } == 0)
        .then(|| {
            std::env::var("SUDO_UID")
                .ok()
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        .flatten()
}

#[cfg(unix)]
pub(crate) fn is_invoking(uid: u32) -> bool {
    invoking_uid() == Some(uid)
}

/// A root app started through `sudo` hands its files back to the account that
/// raised it, so a later unprivileged lane can still read and replace them.
#[cfg(unix)]
pub(crate) fn hand_back(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let Some(uid) = invoking_uid() else {
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
pub(crate) fn hand_back(_: &std::path::Path) {}
