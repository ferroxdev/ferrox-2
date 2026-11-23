//! Chooses the next slice — ready means `todo` with every dependency `done`, ranked by leverage then smaller effort — and never invents a placeholder value.

#![deny(missing_debug_implementations)]

pub mod advisor;
pub mod check;
pub mod clipboard;
pub mod expand;
pub mod json;
pub mod markdown;
pub mod render;
pub mod state;
pub mod worktree;

use std::path::{Path, PathBuf};

pub use markdown::{Addon, Diagnostic, Effort, Library, Prompt, Severity, Status, Targets};

/// The library's path relative to the root, searched upwards so the tool runs from anywhere inside the repository.
pub const LIBRARY_RELATIVE: &str = "crates/ferrox-prompt/prompts.md";

/// The slice ledger, relative to the root: runtime state, never committed, since one machine's handout log is wrong for every other.
pub const LEDGER_RELATIVE: &str = ".ferrox/slices.log";

/// The matrix, a second source of truth beside `prompts.md`: templates give the work's shape, the matrix says which row is due now.
pub const README_RELATIVE: &str = "README.md";

/// The pinned references: `{references}` is filled from here, never hand-written into a prompt.
pub const PINS_RELATIVE: &str = "upstream/pins.toml";

/// The workspace root, found by walking up for [`LIBRARY_RELATIVE`]; the manifest fallback lets a released binary name where it looked.
pub fn workspace_root(start: &Path) -> PathBuf {
    let mut cursor = Some(start);
    while let Some(dir) = cursor {
        if dir.join(LIBRARY_RELATIVE).is_file() {
            return dir.to_path_buf();
        }
        cursor = dir.parent();
    }
    manifest_root()
}

/// Two levels up from the compile-time `CARGO_MANIFEST_DIR`, so a binary built here still knows where its library is.
pub fn manifest_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or(manifest.clone(), Path::to_path_buf)
}

/// FNV-1a tag naming the exact library text: a tag, not a checksum — nothing about correctness depends on it.
pub fn library_tag(text: &str) -> String {
    tag_bytes(text.as_bytes())
}

/// The same tag over a native path's bytes, so two paths that render alike still get separate histories.
pub fn path_tag(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        tag_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        match path.to_str() {
            Some(text) => tag_bytes(text.as_bytes()),
            None => {
                let mut bytes = vec![0xff];
                for unit in path.as_os_str().encode_wide() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                tag_bytes(&bytes)
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        tag_bytes(path.to_string_lossy().as_bytes())
    }
}

fn tag_bytes(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A library that could not be read at all: no prompts, so nothing to report a line number against.
#[derive(Debug)]
pub struct Unreadable {
    /// The path that was tried.
    pub path: PathBuf,
    /// What the filesystem said.
    pub message: String,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot read prompt library {}: {}",
            self.path.display(),
            self.message
        )
    }
}

impl std::error::Error for Unreadable {}

/// Read and parse the library; `--library` wins over the search, a relative explicit path resolves against `cwd`, and the recorded path stays root-relative so a diagnostic opens.
pub fn load_library(explicit: Option<&Path>, cwd: &Path) -> Result<Library, Unreadable> {
    let root = workspace_root(cwd);
    let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let path = match explicit {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => cwd.join(path),
        None => root.join(LIBRARY_RELATIVE),
    };
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    let text = std::fs::read_to_string(&path).map_err(|source| Unreadable {
        path: path.clone(),
        message: source.to_string(),
    })?;
    let display = path
        .strip_prefix(&canonical_root)
        .map_or_else(|_| path.clone(), Path::to_path_buf);
    let mut library = Library::parse(&display, &text);
    library.source_path = path;
    Ok(library)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_symlinked_library_resolves_to_its_target() {
        use std::os::unix::fs::symlink;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-prompt-link-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("prompts.md");
        std::fs::write(&target, "## P1 · x\n\n**Status:** todo\n").expect("target");
        let link = dir.join("link.md");
        symlink(&target, &link).expect("link");
        let library = load_library(Some(&link), &dir).expect("loads");
        assert_eq!(
            library.source_path,
            std::fs::canonicalize(&target).expect("target path")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_explicit_library_resolves_against_the_given_working_directory() {
        let root = std::env::temp_dir().join(format!(
            "ferrox-prompt-cwd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let library = root.join(LIBRARY_RELATIVE);
        std::fs::create_dir_all(library.parent().unwrap()).expect("dirs");
        std::fs::write(&library, "## P1 · x\n\n**Status:** todo\n").expect("library");
        let loaded = load_library(Some(Path::new(LIBRARY_RELATIVE)), &root).expect("relative path");
        assert_eq!(loaded.source_path, std::fs::canonicalize(&library).unwrap());
        assert_eq!(loaded.path, Path::new(LIBRARY_RELATIVE));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_path_with_lone_surrogates_keeps_its_distinct_tag() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt as _;

        let one = PathBuf::from(OsString::from_wide(&[0xD800]));
        let two = PathBuf::from(OsString::from_wide(&[0xD801]));
        assert_ne!(path_tag(&one), path_tag(&two));
        assert_eq!(path_tag(Path::new("a")), library_tag("a"));
    }

    #[test]
    fn a_tag_is_stable_and_input_sensitive() {
        assert_eq!(library_tag("ferrox"), library_tag("ferrox"));
        assert_ne!(library_tag("ferrox"), library_tag("dovetai"));
        // A trailing newline changes the tag on purpose: it names the file, not its gist.
        assert_ne!(library_tag("ferrox\n"), library_tag("ferrox"));
        assert_eq!(library_tag("").len(), 16);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_tag_sees_bytes_a_lossy_path_does_not() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let one = Path::new(OsStr::from_bytes(b"/tmp/custom-\xff.md"));
        let two = Path::new(OsStr::from_bytes(b"/tmp/custom-\xfe.md"));
        assert_eq!(one.to_string_lossy(), two.to_string_lossy());
        assert_ne!(path_tag(one), path_tag(two));
    }

    #[test]
    fn the_manifest_root_is_the_workspace_root() {
        let root = manifest_root();
        assert!(
            root.join(LIBRARY_RELATIVE).is_file(),
            "manifest root {} does not hold the library",
            root.display()
        );
        assert!(root.join("Cargo.toml").is_file());
    }

    #[test]
    fn the_root_is_found_from_a_subdirectory() {
        let root = manifest_root();
        let deep = root.join("crates/ferrox-core/src");
        assert_eq!(workspace_root(&deep), root);
        // Outside the repository entirely, fall back to the compiled-in root rather than returning nothing.
        assert_eq!(workspace_root(Path::new("/")), manifest_root());
    }
}
