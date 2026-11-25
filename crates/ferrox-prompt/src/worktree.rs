//! One worktree per slice, made only by `scripts/new-worktree.sh`: the tool names the slice's worktree and says whether it exists yet.

use std::path::{Path, PathBuf};

/// The directory `scripts/new-worktree.sh` makes for a slice: a sibling of the checkout it runs from, this prefix on the branch name.
pub const DIR_PREFIX: &str = "ferrox-";

/// The longest label a slice name takes from its row, so a branch, a directory and a `git log --oneline` stay readable.
const LABEL_LIMIT: usize = 40;

/// What the filesystem says about the path a slice's worktree would use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// Nothing there: the script makes it.
    Absent,
    /// The script made it already, elsewhere than this checkout.
    Linked,
    /// This checkout is the slice's worktree.
    Current,
    /// A worktree for the row exists, but its `HEAD` is on another branch.
    Mismatch,
    /// A directory of that name exists and is not a worktree, so the script refuses to overwrite it.
    Occupied,
}

/// The worktree a slice runs in: what it is called, where it sits, and whether it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    /// The branch name, the directory suffix and the pull-request head, as in `p2-shadowsocks-tcp-udp`.
    pub name: String,
    /// The path `scripts/new-worktree.sh` would use for it.
    pub path: PathBuf,
    /// What is at that path right now.
    pub place: Place,
}

impl Worktree {
    /// The worktree for the slice `P{id}` drawing `label` now draws — the row key keeps two rows whose labels slug alike apart.
    #[must_use]
    pub fn plan(id: u32, label: &str, row_key: Option<&str>, root: &Path) -> Self {
        let base = name(id, label);
        let Some(key) = row_key.map(kebab).filter(|key| !key.is_empty()) else {
            return Self::named(base, root);
        };
        let planned = Self::named(format!("{base}--{key}"), root);
        if matches!(
            planned.place,
            Place::Linked | Place::Current | Place::Mismatch
        ) {
            return planned;
        }
        if let Some(existing) = Self::keyed_reuse(id, &key, root) {
            return existing;
        }
        planned
    }

    /// An existing worktree for the same template and row key, whatever label it was made under.
    fn keyed_reuse(id: u32, key: &str, root: &Path) -> Option<Self> {
        let parent = root.parent().unwrap_or(root);
        let unlabeled = format!("{DIR_PREFIX}p{id}");
        let labeled = format!("{unlabeled}-");
        let suffix = format!("--{key}");
        let mut names: Vec<String> = std::fs::read_dir(parent)
            .ok()?
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| {
                let Some(stem) = name.strip_suffix(suffix.as_str()) else {
                    return false;
                };
                if stem == unlabeled {
                    return true;
                }
                stem.strip_prefix(labeled.as_str()).is_some_and(|stem| {
                    !stem.is_empty()
                        && !stem.starts_with('-')
                        && !stem.ends_with('-')
                        && !stem.contains("--")
                        && stem.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
            })
            .collect();
        names.sort();
        names.into_iter().find_map(|name| {
            let branch = name.strip_prefix(DIR_PREFIX)?.to_owned();
            let candidate = Self::named(branch, root);
            matches!(
                candidate.place,
                Place::Linked | Place::Current | Place::Mismatch
            )
            .then_some(candidate)
        })
    }

    /// A worktree whose branch name is already decided, as `bugfix-661` is for an issue template.
    #[must_use]
    pub fn named(name: impl Into<String>, root: &Path) -> Self {
        let name = name.into();
        let path = path_for(&name, root);
        let mut place = probe(&path, root);
        if place == Place::Linked && head_branch(&path).as_deref() != Some(name.as_str()) {
            place = Place::Mismatch;
        }
        Self { name, path, place }
    }

    /// One word for `--json`.
    #[must_use]
    pub fn state(&self) -> &'static str {
        match self.place {
            Place::Absent => "absent",
            Place::Linked => "linked",
            Place::Current => "current",
            Place::Mismatch => "mismatch",
            Place::Occupied => "occupied",
        }
    }

    /// The terminal's one-line verdict: what to do with the worktree, not why.
    #[must_use]
    pub fn brief(&self) -> String {
        match self.place {
            Place::Absent => format!("create it: ./scripts/new-worktree.sh {}", self.name),
            Place::Linked => format!("{} — use it, onto main first", self.path.display()),
            Place::Current => "this checkout — onto main first".to_owned(),
            Place::Mismatch => format!(
                "{} is on another branch; switch it to {} or move it aside",
                self.path.display(),
                self.name
            ),
            Place::Occupied => format!("{} is not a worktree; move it aside", self.path.display()),
        }
    }
}

/// `p2-shadowsocks-tcp-udp`: the template id, so no two classes share a name, and the row's method as a path-safe slug.
#[must_use]
pub fn name(id: u32, label: &str) -> String {
    let slug = kebab(label);
    if slug.is_empty() {
        format!("p{id}")
    } else {
        format!("p{id}-{slug}")
    }
}

/// The label as a slug: alphanumeric runs joined by one hyphen, cut at a word boundary past [`LABEL_LIMIT`].
fn kebab(label: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(label.len());
    let mut pending = false;
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            if pending && !out.is_empty() {
                out.push(b'-');
            }
            pending = false;
            out.push(byte.to_ascii_lowercase());
        } else {
            pending = true;
        }
    }
    if out.len() > LABEL_LIMIT {
        let cut = out[..LABEL_LIMIT]
            .iter()
            .rposition(|byte| *byte == b'-')
            .unwrap_or(LABEL_LIMIT);
        out.truncate(cut);
    }
    out.iter().copied().map(char::from).collect()
}

/// Where the script would put it: beside this checkout, under [`DIR_PREFIX`].
fn path_for(name: &str, root: &Path) -> PathBuf {
    root.parent()
        .unwrap_or(root)
        .join(format!("{DIR_PREFIX}{name}"))
}

/// A linked worktree's `.git` file points at a registered entry with `HEAD` and `commondir`; anything else is not usable.
fn probe(path: &Path, root: &Path) -> Place {
    if path == root {
        return Place::Current;
    }
    if !path.exists() {
        return Place::Absent;
    }
    match gitdir(path) {
        Some(gitdir)
            if gitdir.is_dir()
                && gitdir.join("HEAD").is_file()
                && gitdir.join("commondir").is_file() =>
        {
            Place::Linked
        }
        _ => Place::Occupied,
    }
}

/// The branch a linked worktree's `HEAD` is attached to, if any.
fn head_branch(path: &Path) -> Option<String> {
    let head = std::fs::read_to_string(gitdir(path)?.join("HEAD")).ok()?;
    Some(head.strip_prefix("ref: refs/heads/")?.trim().to_owned())
}

/// The gitdir a linked worktree's `.git` file names, absolute or relative to the worktree.
fn gitdir(path: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(path.join(".git")).ok()?;
    let rest = bytes.strip_prefix(b"gitdir: ")?;
    let mut end = rest.len();
    while end > 0 && matches!(rest[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    #[cfg(unix)]
    let target = path_from_bytes(&rest[..end]);
    #[cfg(not(unix))]
    let target = path_from_bytes(&rest[..end])?;
    Some(if target.is_absolute() {
        target
    } else {
        path.join(target)
    })
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> Option<PathBuf> {
    std::str::from_utf8(bytes).ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own under the system temp dir, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            path.push(format!("ferrox-prompt-worktree-{tag}-{stamp}"));
            std::fs::create_dir_all(&path).expect("scratch");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn the_name_is_the_template_and_the_row_in_path_order() {
        assert_eq!(name(2, "Shadowsocks TCP/UDP"), "p2-shadowsocks-tcp-udp");
        assert_eq!(
            name(17, "REALITY Vision handshake"),
            "p17-reality-vision-handshake"
        );
        assert_eq!(
            name(9, "///"),
            "p9",
            "a label with no slug falls back to the id"
        );
    }

    #[test]
    fn a_long_label_is_cut_at_a_word_boundary() {
        let long = name(3, "VLESS over XHTTP with Multi-Upload Mode Selected Case");
        assert_eq!(long, "p3-vless-over-xhttp-with-multi-upload-mode", "{long}");
        assert!(!long.ends_with('-'), "{long}");
        assert!(
            long["p3-".len()..].len() <= LABEL_LIMIT,
            "the slug alone is what the limit bounds"
        );
    }

    #[test]
    fn the_same_slice_always_gets_the_same_name() {
        assert_eq!(name(7, "VMess TCP (AEAD)"), name(7, "VMess TCP (AEAD)"));
    }

    #[test]
    fn an_explicit_branch_name_is_not_prefixed_or_slugified() {
        let scratch = Scratch::new("named");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let plan = Worktree::named("bugfix-661", &root);
        assert_eq!(plan.name, "bugfix-661");
        assert_eq!(plan.place, Place::Absent);
        assert_eq!(plan.path, scratch.0.join(format!("{DIR_PREFIX}bugfix-661")));
        assert!(
            plan.brief()
                .contains("./scripts/new-worktree.sh bugfix-661")
        );
    }

    #[test]
    fn an_absent_slice_names_the_worktree_the_script_would_make() {
        let scratch = Scratch::new("absent");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.name, "p2-shadowsocks-tcp-udp");
        assert_eq!(plan.place, Place::Absent);
        assert_eq!(plan.state(), "absent");
        assert!(plan.brief().contains("./scripts/new-worktree.sh"));
        assert_eq!(
            plan.path,
            scratch
                .0
                .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"))
        );
    }

    #[test]
    fn rows_that_slug_alike_get_their_key_in_the_worktree_name() {
        let scratch = Scratch::new("rows");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let one = Worktree::plan(2, "VLESS TCP/UDP", Some("A13"), &root);
        let two = Worktree::plan(2, "VLESS TCP UDP", Some("A14"), &root);
        assert_eq!(one.name, "p2-vless-tcp-udp--a13");
        assert_eq!(two.name, "p2-vless-tcp-udp--a14");
        assert_ne!(one.path, two.path);
    }

    #[test]
    fn a_keyed_name_does_not_collide_with_an_unkeyed_label() {
        let scratch = Scratch::new("key-collision");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let keyed = Worktree::plan(2, "VLESS TCP/UDP", Some("A13"), &root);
        let legacy = Worktree::plan(2, "VLESS TCP/UDP A13", None, &root);
        assert_eq!(keyed.name, "p2-vless-tcp-udp--a13");
        assert_eq!(legacy.name, "p2-vless-tcp-udp-a13");
        assert_ne!(keyed.name, legacy.name);
    }

    #[test]
    fn a_worktree_made_before_the_row_key_existed_is_not_adopted() {
        let scratch = Scratch::new("old-name");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(
            gitdir.join("HEAD"),
            "ref: refs/heads/p2-shadowsocks-tcp-udp\n",
        )
        .expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", Some("A13"), &root);
        assert_eq!(plan.name, "p2-shadowsocks-tcp-udp--a13");
        assert_eq!(plan.place, Place::Absent);
        assert_ne!(plan.path, other);
    }

    #[test]
    fn a_keyed_worktree_is_reused_when_the_method_label_changes() {
        let scratch = Scratch::new("relabel");
        let root = scratch.0.join("ferrox");
        let other = scratch.0.join(format!("{DIR_PREFIX}p2-vless-tcp--a13"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/p2-vless-tcp--a13\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "VLESS TCP transport", Some("A13"), &root);
        assert_eq!(plan.name, "p2-vless-tcp--a13");
        assert_eq!(plan.place, Place::Linked);
        assert_eq!(plan.path, other);
    }

    #[test]
    fn an_unlabeled_keyed_worktree_is_reused_after_a_label_change() {
        let scratch = Scratch::new("unlabeled-key");
        let root = scratch.0.join("ferrox");
        let other = scratch.0.join(format!("{DIR_PREFIX}p2--a13"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/p2--a13\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "QUIC", Some("A13"), &root);
        assert_eq!(plan.name, "p2--a13");
        assert_eq!(plan.place, Place::Linked);
        assert_eq!(plan.path, other);
    }

    #[test]
    fn a_keyed_worktree_on_another_branch_is_not_recommended_for_rebase() {
        let scratch = Scratch::new("wrong-branch");
        let root = scratch.0.join("ferrox");
        let other = scratch.0.join(format!("{DIR_PREFIX}p2-vless-tcp--a13"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "VLESS TCP transport", Some("A13"), &root);
        assert_eq!(plan.name, "p2-vless-tcp--a13");
        assert_eq!(plan.place, Place::Mismatch);
        assert!(plan.brief().contains("another branch"), "{}", plan.brief());
        assert!(
            !plan.brief().contains("onto main first"),
            "{}",
            plan.brief()
        );
    }

    #[test]
    fn an_occupied_planned_path_does_not_hide_a_keyed_worktree() {
        let scratch = Scratch::new("occupied-old-key");
        let root = scratch.0.join("ferrox");
        let old = scratch.0.join(format!("{DIR_PREFIX}p2-vless-tcp--a13"));
        let occupied = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-vless-tcp-transport--a13"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&old).expect("worktree");
        std::fs::create_dir_all(&occupied).expect("occupied");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/p2-vless-tcp--a13\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(old.join(".git"), format!("gitdir: {}\n", gitdir.display()))
            .expect(".git file");
        let plan = Worktree::plan(2, "VLESS TCP transport", Some("A13"), &root);
        assert_eq!(plan.name, "p2-vless-tcp--a13");
        assert_eq!(plan.place, Place::Linked);
        assert_eq!(plan.path, old);
    }

    #[test]
    fn a_sibling_with_shell_metacharacters_is_not_reused() {
        let scratch = Scratch::new("metachar");
        let root = scratch.0.join("ferrox");
        let odd = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-evil'$(touch pwned)--a13"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&odd).expect("odd");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(odd.join(".git"), format!("gitdir: {}\n", gitdir.display()))
            .expect(".git file");
        let plan = Worktree::plan(2, "VLESS TCP", Some("A13"), &root);
        assert_eq!(plan.name, "p2-vless-tcp--a13");
        assert_eq!(plan.place, Place::Absent);
    }

    #[test]
    fn an_ambiguous_unkeyed_worktree_is_not_reused() {
        let scratch = Scratch::new("old-name-collision");
        let root = scratch.0.join("ferrox");
        let other = scratch.0.join(format!("{DIR_PREFIX}p2-vless-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "VLESS TCP/UDP", Some("A13"), &root);
        assert_eq!(plan.name, "p2-vless-tcp-udp--a13");
        assert_eq!(plan.place, Place::Absent);
    }

    #[test]
    fn a_worktree_the_script_made_is_found_and_used() {
        let scratch = Scratch::new("linked");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(
            gitdir.join("HEAD"),
            "ref: refs/heads/p2-shadowsocks-tcp-udp\n",
        )
        .expect("HEAD");
        std::fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.place, Place::Linked);
        assert_eq!(plan.path, other);
        assert!(plan.brief().contains("use it"), "{}", plan.brief());
    }

    #[test]
    fn a_stale_git_file_is_not_a_usable_worktree() {
        let scratch = Scratch::new("stale");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        std::fs::write(other.join(".git"), "gitdir: missing\n").expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.place, Place::Occupied);
        assert!(plan.brief().contains("not a worktree"));
    }

    #[cfg(unix)]
    #[test]
    fn a_gitdir_with_non_utf8_bytes_is_still_read() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let scratch = Scratch::new("non-utf8");
        let worktree = scratch.0.join("linked");
        let expected = scratch.0.join(OsStr::from_bytes(b"gitdir-\x80"));
        std::fs::create_dir_all(&worktree).expect("worktree");
        let mut pointer = b"gitdir: ".to_vec();
        pointer.extend(expected.as_os_str().as_bytes());
        std::fs::write(worktree.join(".git"), pointer).expect("git file");
        assert_eq!(gitdir(&worktree), Some(expected));
    }

    #[test]
    fn a_gitdir_with_only_head_is_not_a_usable_worktree() {
        let scratch = Scratch::new("head-only");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        let gitdir = scratch.0.join("gitdir");
        std::fs::create_dir_all(&gitdir).expect("gitdir");
        std::fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
        std::fs::write(
            other.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.place, Place::Occupied);
    }

    #[test]
    fn running_from_the_slices_own_worktree_says_so() {
        let scratch = Scratch::new("current");
        let root = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::write(root.join(".git"), "gitdir: somewhere\n").expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.place, Place::Current);
    }

    #[test]
    fn a_directory_that_is_not_a_worktree_is_not_claimed() {
        let scratch = Scratch::new("occupied");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(other.join("src")).expect("a hand-made directory");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", None, &root);
        assert_eq!(plan.place, Place::Occupied);
        assert!(plan.brief().contains("not a worktree"));
    }

    #[test]
    fn a_gitdir_pointer_needs_gits_exact_space() {
        let scratch = Scratch::new("gitdir-space");
        let worktree = scratch.0.join("worktree");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(worktree.join(".git"), b"gitdir:nested\n").expect(".git file");
        assert_eq!(gitdir(&worktree), None);
        std::fs::write(worktree.join(".git"), b"gitdir:\tnested\n").expect(".git file");
        assert_eq!(gitdir(&worktree), None);
    }

    #[test]
    fn a_gitdir_keeps_trailing_spaces_and_drops_only_the_line_ending() {
        let scratch = Scratch::new("trailing-space");
        let worktree = scratch.0.join("worktree");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(worktree.join(".git"), b"gitdir: nested  \r\n").expect(".git file");
        assert_eq!(gitdir(&worktree), Some(worktree.join("nested  ")));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_gitdir_is_read_as_bytes() {
        use std::os::unix::ffi::OsStrExt as _;

        let scratch = Scratch::new("non-utf8-gitdir");
        let worktree = scratch.0.join("worktree");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(worktree.join(".git"), b"gitdir: nested-\xff\n").expect(".git file");
        let parsed = gitdir(&worktree).expect("the bytes name a path");
        let expected = worktree.join(std::ffi::OsStr::from_bytes(b"nested-\xff"));
        assert_eq!(parsed, expected);
    }
}
