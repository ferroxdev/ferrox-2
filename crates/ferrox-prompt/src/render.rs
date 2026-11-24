//! Assembly order is fixed: shared protocol, prompt protocol, body, add-ons, worktree, gates verbatim; an unfilled required input goes at the top loudly or is not rendered.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::markdown::{is_placeholder_name, Addon, Library, Prompt};
use crate::worktree::{Place, Worktree};

/// What to include beyond the prompt itself.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Print the acceptance gates: a prompt with no acceptance section is a request, not a slice.
    pub gates: bool,
    /// The header and footer describe the tool, not the work, so they frame the request only when asked.
    pub provenance: bool,
    /// Render a prompt with unfilled required inputs, the gap stated at the top; `next` refuses instead.
    pub allow_unfilled: bool,
    /// The library the caller named, so the recovery command can be retried against the same prompt.
    pub retry_library: Option<PathBuf>,
    /// The row the caller selected, so the recovery command does not rotate to another row.
    pub retry_row: Option<String>,
    /// Whether the caller asked not to record the handout, so the retry keeps that choice.
    pub retry_no_ledger: bool,
    /// What the caller actually supplied, so a retry leaves automatic row values to be refilled.
    pub retry_values: Option<BTreeMap<String, String>>,
    /// The add-on selectors the caller typed, so a retry cannot widen a unique selector.
    pub retry_addons: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            gates: true,
            provenance: false,
            allow_unfilled: false,
            retry_library: None,
            retry_row: None,
            retry_no_ledger: false,
            retry_values: None,
            retry_addons: Vec::new(),
        }
    }
}

/// A rendered prompt and what went into it.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The text.
    pub text: String,
    /// Required inputs with no value, in library order; empty means the prompt is complete.
    pub missing: Vec<String>,
    /// The values that were substituted, so a caller can report what it filled.
    pub supplied: BTreeMap<String, String>,
    /// The add-ons that were resolved, in the order given.
    pub addons: Vec<Addon>,
    /// The worktree the slice runs in, when the caller named one: where to make it, or where it already is.
    pub worktree: Option<Worktree>,
}

/// Render `prompt`; a malformed library is `check`'s find, not something to re-detect here.
pub fn render(
    library: &Library,
    prompt: &Prompt,
    values: &BTreeMap<String, String>,
    addons: &[Addon],
    worktree: Option<&Worktree>,
    options: &Options,
) -> Rendered {
    let missing: Vec<String> = prompt
        .required_inputs_for(addons)
        .filter(|name| !values.contains_key(*name))
        .map(str::to_owned)
        .collect();

    let mut parts: Vec<String> = Vec::new();
    if options.provenance {
        parts.push(header(library, prompt));
    }
    if !missing.is_empty() && options.allow_unfilled {
        parts.push(unfilled_block(
            prompt,
            &missing,
            options.retry_values.as_ref().unwrap_or(values),
            addons,
            &options.retry_addons,
            options.retry_library.as_deref(),
            options.retry_row.as_deref(),
            options.retry_no_ledger,
        ));
    }
    if !library.shared_protocol.is_empty() {
        parts.push(library.shared_protocol.clone());
    }
    if !prompt.protocol.is_empty() {
        parts.push(prompt.protocol.clone());
    }
    parts.push(substitute(&prompt.body, values));

    let mut resolved = Vec::new();
    for addon in addons {
        resolved.push(addon.clone());
        parts.push(format!(
            "**Add-on — {}:** {}",
            addon.title,
            substitute(&addon.body, values)
        ));
    }

    if let Some(worktree) = worktree {
        parts.push(worktree_block(worktree));
    }

    if options.gates {
        parts.push(acceptance_block(prompt));
    }

    let mut text = parts.join("\n\n---\n\n");
    let footer = footer(library, prompt, options.provenance);
    if !footer.is_empty() {
        text.push_str("\n\n");
        text.push_str(&footer);
    }

    let supplied = prompt
        .placeholders
        .iter()
        .filter_map(|placeholder| {
            values
                .get(&placeholder.name)
                .map(|value| (placeholder.name.clone(), value.clone()))
        })
        .collect();

    Rendered {
        text,
        missing,
        supplied,
        addons: resolved,
        worktree: worktree.cloned(),
    }
}

/// The first block: which slice this is, and what the roadmap says about it.
fn header(library: &Library, prompt: &Prompt) -> String {
    let opens = prompt.blocks(library).count();
    let mut line = format!(
        "# P{} · {}\n\nstatus {} · leverage {} · effort {}",
        prompt.id,
        prompt.title,
        prompt.status.as_str(),
        prompt.leverage,
        prompt.effort.as_str()
    );
    if !prompt.depends_on.is_empty() {
        let _ = write!(
            line,
            " · depends on {}",
            prompt
                .depends_on
                .iter()
                .map(|id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if opens > 0 {
        let _ = write!(line, " · opens {opens} slice(s)");
    }
    line
}

/// The block that states an unfilled input instead of leaving a hole.
#[allow(clippy::too_many_arguments)]
fn unfilled_block(
    prompt: &Prompt,
    missing: &[String],
    values: &BTreeMap<String, String>,
    addons: &[Addon],
    addon_requests: &[String],
    library: Option<&Path>,
    row: Option<&str>,
    no_ledger: bool,
) -> String {
    let mut block = String::from(
        "## Inputs required before this slice can start\n\n\
         These were not supplied. Do not invent a value for any of them: each is a \
         decision this tool refused to make on your behalf.",
    );
    for name in missing {
        let _ = write!(block, "\n- `{name}` — re-run with `--set {name}=<value>`.");
    }
    let command = suggested_command(
        prompt,
        missing,
        values,
        addons,
        addon_requests,
        library,
        row,
        no_ledger,
    );
    let fence = fence_for(&command);
    let _ = write!(block, "\n\nFull command:\n\n{fence}\n{command}\n{fence}");
    block
}

/// A fence longer than any backtick run in the command, so a quoted value cannot close it early.
fn fence_for(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for byte in text.bytes() {
        if byte == b'`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

/// Where the slice runs: the script makes the worktree when there is none, and an existing one is updated to `main` before the first edit.
fn worktree_block(worktree: &Worktree) -> String {
    let mut line = String::new();
    match worktree.place {
        Place::Absent => {
            let script_name = shell_quote(&worktree.name);
            let _ = write!(
                line,
                "No worktree for this slice yet: create it with \
                 `./scripts/new-worktree.sh {script_name}` and work only there — never a hand-made \
                 `git worktree add`, since the script is what points the build at the shared \
                 `target-dir`, writes the hardware-crypto cfgs CI builds with into \
                 `.cargo/config.toml`, and links the `upstream/` reading copies. \
                 It makes `{path}` on branch `{name}`; open the pull request from it.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Linked => {
            let message = shell_quote(&format!("ferrox {}", worktree.name));
            let _ = write!(
                line,
                "Worktree `{name}` is at `{path}` — do this slice there, not in the \
                 checkout this prompt came from. Put it on `main` first \
                 (`git fetch origin main:refs/remotes/origin/main && git rebase origin/main`). \
                 If `git status --short` shows local changes, save them with \
                 `git stash push -u -m {message}`, rebase, then \
                 `git stash pop --index \"$(git stash list --format=%gd --grep={message} -1)\"`; \
                 if it conflicts, keep the stash until the changes are recovered. `main` moves \
                 under a worktree, and a stale base measures the wrong code.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Current => {
            let message = shell_quote(&format!("ferrox {}", worktree.name));
            let _ = write!(
                line,
                "This slice's worktree `{name}` is the checkout this prompt came from \
                 (`{path}`). Put it on `main` first \
                 (`git fetch origin main:refs/remotes/origin/main && git rebase origin/main`). \
                 If `git status --short` shows local changes, save them with \
                 `git stash push -u -m {message}`, rebase, then \
                 `git stash pop --index \"$(git stash list --format=%gd --grep={message} -1)\"`; \
                 if it conflicts, keep the stash until the changes are recovered, and work here.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Mismatch => {
            let _ = write!(
                line,
                "`{path}` is a worktree for this row, but its `HEAD` is on another branch. \
                 Switch it to `{name}` and use it, or move it aside and create the slice's \
                 worktree — do not rebase the branch it is on.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Occupied => {
            let script_name = shell_quote(&worktree.name);
            let _ = write!(
                line,
                "`{path}` exists but is not a worktree, so `./scripts/new-worktree.sh {script_name}` \
                 refuses it. Move that directory aside, then create `{name}` with the script \
                 and work there.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
    }
    format!("## Worktree\n\n- {line}")
}

/// The gates, verbatim, under a heading that says what they are for.
fn acceptance_block(prompt: &Prompt) -> String {
    let mut block = String::from(
        "## Acceptance\n\n\
         Not done until every gate below is green. Run them; never report the result of \
         a command you did not run.",
    );
    for gate in &prompt.gates {
        let _ = write!(block, "\n- {gate}");
    }
    block
}

/// A comment naming the slice, the file and the tag of the text it came from.
fn footer(library: &Library, prompt: &Prompt, with_provenance: bool) -> String {
    if !with_provenance {
        return String::new();
    }
    format!(
        "<!-- ferrox-prompt · P{} · {} · library tag {} (fnv1a-64, not a checksum) -->",
        prompt.id,
        library.path.display(),
        library.tag()
    )
}

/// `{name}` and `{name=default}` substitute; `{{`/`}}` escape one brace, lone braces are prose, and an unfilled placeholder stays as written.
pub fn substitute(text: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        let Some(character) = text[index..].chars().next() else {
            break;
        };
        if character == '}' {
            if text[index + 1..].starts_with('}') {
                out.push('}');
                index += 2;
            } else {
                out.push('}');
                index += 1;
            }
            continue;
        }
        if character != '{' {
            out.push(character);
            index += character.len_utf8();
            continue;
        }
        let after = index + 1;
        if text[after..].starts_with('{') {
            out.push('{');
            index = after + 1;
            continue;
        }
        let Some(close) = text[after..].find('}').map(|offset| after + offset) else {
            out.push('{');
            index = after;
            continue;
        };
        let body = &text[after..close];
        if !is_placeholder_name(placeholder_name(body)) {
            out.push('{');
            index = after;
            continue;
        }
        // An unfilled placeholder stays exactly as written, so the gap is visible in the output, not in a footnote.
        if let Some(value) = resolved(body, values) {
            out.push_str(&value);
        } else {
            out.push('{');
            out.push_str(body);
            out.push('}');
        }
        index = close + 1;
    }
    out
}

fn placeholder_name(body: &str) -> &str {
    match body.split_once('=') {
        Some((name, _)) => name.trim(),
        None => body.trim(),
    }
}

/// The text for one placeholder body, or `None` to leave the placeholder alone.
fn resolved(body: &str, values: &BTreeMap<String, String>) -> Option<String> {
    let name = placeholder_name(body);
    if !is_placeholder_name(name) {
        return None;
    }
    let default = body.split_once('=').map(|(_, default)| default);
    match values.get(name) {
        Some(value) => Some(value.clone()),
        // An empty default reads as no default so the placeholder stays visible; `check` reports it separately.
        None => default
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned),
    }
}

/// The add-ons `requests` names, slug-exact then unique substring; ambiguity is an error, never a guess.
pub fn resolve_addons(prompt: &Prompt, requests: &[String]) -> Result<Vec<Addon>, String> {
    let mut flat: Vec<&str> = requests
        .iter()
        .flat_map(|request| request.split(','))
        .map(str::trim)
        .filter(|request| !request.is_empty())
        .collect();
    if flat.len() == 1 && flat[0].eq_ignore_ascii_case("all") {
        return Ok(prompt.addons.clone());
    }
    let mut seen = std::collections::HashSet::new();
    flat.retain(|request| seen.insert(request.to_ascii_lowercase()));
    let mut resolved_addons = Vec::new();
    for request in flat {
        if let Some(addon) = prompt.addon(&request.to_ascii_lowercase()) {
            resolved_addons.push(addon.clone());
            continue;
        }
        let needle = request.to_ascii_lowercase();
        let matches: Vec<&Addon> = prompt
            .addons
            .iter()
            .filter(|addon| {
                addon.slug.contains(&needle) || addon.title.to_ascii_lowercase().contains(&needle)
            })
            .collect();
        match matches.as_slice() {
            [only] => resolved_addons.push((*only).clone()),
            [] => {
                let available = prompt
                    .addons
                    .iter()
                    .map(|addon| addon.slug.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "P{} has no add-on matching `{request}`; it has {}",
                    prompt.id,
                    if available.is_empty() {
                        "none".to_owned()
                    } else {
                        available
                    }
                ));
            }
            many => {
                let choices = many
                    .iter()
                    .map(|addon| addon.slug.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "`{request}` matches {choices}; pass the whole slug, or `list` to see them"
                ));
            }
        }
    }
    let mut seen_addons = std::collections::HashSet::new();
    resolved_addons.retain(|addon| seen_addons.insert(addon.slug.clone()));
    Ok(resolved_addons)
}

/// The command line that would render `prompt` with `missing` filled: one paste, not a dialog about four keys.
#[allow(clippy::too_many_arguments)]
pub fn suggested_command(
    prompt: &Prompt,
    missing: &[String],
    values: &BTreeMap<String, String>,
    addons: &[Addon],
    addon_requests: &[String],
    library: Option<&Path>,
    row: Option<&str>,
    no_ledger: bool,
) -> String {
    let mut command = format!("ferrox-prompt render P{}", prompt.id);
    if let Some(library) = library {
        let _ = write!(
            command,
            " --library {}",
            shell_quote(&library.to_string_lossy())
        );
    }
    if let Some(row) = row {
        let _ = write!(command, " --row {}", shell_quote(row));
    }
    if no_ledger {
        command.push_str(" --no-ledger");
    }
    for name in missing {
        if name == "issue" {
            command.push_str(" --issue <number>");
        } else {
            let _ = write!(command, " --set {name}={}", suggested_value(name));
        }
    }
    for placeholder in prompt
        .active_placeholders_for(addons)
        .filter(|placeholder| !missing.contains(&placeholder.name))
    {
        if let Some(value) = values.get(&placeholder.name) {
            let _ = write!(
                command,
                " --set {}={}",
                placeholder.name,
                shell_quote(value)
            );
        }
    }
    // These name the worktree even when the template does not render them, so the retry must carry them.
    for name in ["issue", "method"] {
        if missing.iter().any(|missing| missing == name)
            || prompt
                .active_placeholders_for(addons)
                .any(|placeholder| placeholder.name == name)
        {
            continue;
        }
        if let Some(value) = values.get(name) {
            let _ = write!(command, " --set {name}={}", shell_quote(value));
        }
    }
    if addon_requests.is_empty() {
        for addon in addons {
            let _ = write!(
                command,
                " --addon {}",
                shell_quote(&addon_selector(prompt, addon))
            );
        }
    } else {
        let mut seen = std::collections::HashSet::new();
        for request in addon_requests {
            let request = request.trim();
            if !request.is_empty() && seen.insert(request) {
                let _ = write!(command, " --addon {}", shell_quote(request));
            }
        }
    }
    command
}

/// The selector that names one add-on unambiguously, quoted for the shell.
fn addon_selector(prompt: &Prompt, addon: &Addon) -> String {
    for candidate in [&addon.slug, &addon.title] {
        let request = [(*candidate).clone()];
        let Ok(resolved) = resolve_addons(prompt, &request) else {
            continue;
        };
        if resolved.len() == 1 && resolved[0].slug == addon.slug {
            return (*candidate).clone();
        }
    }
    addon.slug.clone()
}

/// One shell argument, quoted only when the path or selector needs it.
fn shell_quote(value: &str) -> String {
    let plain = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'-' | b'_' | b':' | b'+' | b'@' | b'%' | b','
            )
    });
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// The placeholder a suggested command shows: an issue is always a number, everything else is a value.
fn suggested_value(name: &str) -> &'static str {
    if name == "issue" {
        "<number>"
    } else {
        "<value>"
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::markdown::{Effort, Status};

    fn worktree(place: Place) -> Worktree {
        Worktree {
            name: "p1-one".to_owned(),
            path: PathBuf::from("/tmp/ferrox-p1-one"),
            place,
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn library() -> Library {
        Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
prove it or do not say it
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 4
**Effort:** small
**Targets:** none
**Gates:** `cargo test --workspace`

```text
run with {len=40} and {scope}
```

**Add-on — Local first:** author here

## P2 · Two

**When to use:** second
**Status:** todo
**Leverage:** 4
**Effort:** large
**Targets:** none
**Gates:** `cargo test`
**Depends on:** P1
**Touches:** README.md

```text
with {target=core}
```

**Add-on — Miri limits:** name the limits
**Add-on — Isa matrix:** one runner per ISA
",
        )
    }

    #[test]
    fn the_sections_come_out_in_the_documented_order() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let addons = resolve_addons(prompt, &["local-first".to_owned()]).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &addons,
            Some(&worktree(Place::Absent)),
            &Options {
                provenance: true,
                ..Options::default()
            },
        );
        let protocol = rendered.text.find("prove it or do not say it").unwrap();
        let body = rendered.text.find("run with 40").unwrap();
        let addon = rendered.text.find("**Add-on — Local first:**").unwrap();
        let worktree = rendered.text.find("## Worktree").unwrap();
        let gates = rendered.text.find("## Acceptance").unwrap();
        let footer = rendered.text.find("<!-- ferrox-prompt").unwrap();
        assert!(protocol < body, "protocol before body");
        assert!(body < addon, "body before add-ons");
        assert!(addon < worktree, "add-ons before the worktree");
        assert!(worktree < gates, "worktree before acceptance");
        assert!(gates < footer, "acceptance before the footer");
    }

    #[test]
    fn an_absent_worktree_is_created_with_the_script_it_names() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&worktree(Place::Absent)),
            &Options::default(),
        );
        assert!(
            rendered.text.contains("./scripts/new-worktree.sh p1-one"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("/tmp/ferrox-p1-one"),
            "{}",
            rendered.text
        );
        assert!(
            rendered
                .text
                .contains("never a hand-made `git worktree add`"),
            "the script is named as the only way one is made"
        );
    }

    #[test]
    fn a_worktree_name_with_a_quote_is_still_one_shell_word() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let odd = Worktree {
            name: "p1-a'b".to_owned(),
            path: PathBuf::from("/tmp/ferrox-p1-a'b"),
            place: Place::Absent,
        };
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&odd),
            &Options::default(),
        );
        assert!(
            rendered
                .text
                .contains("./scripts/new-worktree.sh 'p1-a'\\''b'"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn an_existing_worktree_is_used_and_put_onto_main() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        for place in [Place::Linked, Place::Current] {
            let rendered = render(
                &library,
                prompt,
                &values(&[]),
                &[],
                Some(&worktree(place)),
                &Options::default(),
            );
            assert!(
                rendered.text.contains("git rebase origin/main"),
                "{place:?} renders without the update"
            );
            assert!(
                rendered.text.contains("git stash pop --index"),
                "{place:?} does not restore the staging state"
            );
            assert!(
                rendered.text.contains("p1-one"),
                "{place:?} renders without naming the worktree"
            );
            assert!(
                rendered
                    .text
                    .contains("git stash push -u -m 'ferrox p1-one'"),
                "{place:?} saves a named stash"
            );
            assert!(
                rendered
                    .text
                    .contains("git stash list --format=%gd --grep='ferrox p1-one' -1"),
                "{place:?} restores the named stash"
            );
            assert!(
                !rendered.text.contains("./scripts/new-worktree.sh p1-one"),
                "{place:?} tells the reader to make one that exists"
            );
        }
    }

    #[test]
    fn a_worktree_on_another_branch_is_not_told_to_rebase() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&worktree(Place::Mismatch)),
            &Options::default(),
        );
        assert!(
            rendered.text.contains("another branch"),
            "{}",
            rendered.text
        );
        assert!(
            !rendered.text.contains("git rebase origin/main"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn a_directory_in_the_way_is_named_rather_than_worked_around() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&worktree(Place::Occupied)),
            &Options::default(),
        );
        assert!(
            rendered.text.contains("is not a worktree"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("/tmp/ferrox-p1-one"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn a_render_without_a_worktree_says_nothing_about_one() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options::default(),
        );
        assert!(!rendered.text.contains("## Worktree"), "{}", rendered.text);
    }

    #[test]
    fn the_default_output_is_the_request_and_nothing_that_frames_it() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options::default(),
        );
        assert!(!rendered.text.contains("# P1 · One"), "{}", rendered.text);
        assert!(!rendered.text.contains("library tag "));
    }

    #[test]
    fn a_supplied_value_beats_the_default() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[("len", "200")]),
            &[],
            None,
            &Options::default(),
        );
        assert!(rendered.text.contains("run with 200"));
        assert!(!rendered.text.contains("run with 40"));
        assert_eq!(rendered.missing, vec!["scope"]);
    }

    #[test]
    fn a_missing_input_is_reported_not_guessed() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options::default(),
        );
        assert_eq!(rendered.missing, vec!["scope"]);
        assert!(
            rendered.text.contains("{scope}"),
            "the placeholder stays visible"
        );
        assert!(
            !rendered.text.contains("Inputs required"),
            "unless asked for"
        );
    }

    #[test]
    fn an_unfilled_prompt_states_the_gap_before_everything() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let options = Options {
            allow_unfilled: true,
            ..Options::default()
        };
        let rendered = render(&library, prompt, &values(&[]), &[], None, &options);
        let gap = rendered.text.find("## Inputs required").unwrap();
        let protocol = rendered.text.find("prove it or do not say it").unwrap();
        assert!(gap < protocol, "the gap is the first thing read");
        assert!(rendered
            .text
            .contains("ferrox-prompt render P1 --set scope=<value>"));
        assert!(!rendered.text.contains("--set len="), "{}", rendered.text);
    }

    #[test]
    fn the_retry_command_keeps_the_selected_add_ons() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let addons = resolve_addons(prompt, &["local-first".to_owned()]).unwrap();
        let options = Options {
            allow_unfilled: true,
            ..Options::default()
        };
        let rendered = render(
            &library,
            prompt,
            &values(&[("len", "40")]),
            &addons,
            None,
            &options,
        );
        assert!(
            rendered.text.contains("--set len=40 --addon local-first"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn the_retry_command_keeps_a_planner_value_the_template_does_not_render() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let values = values(&[("method", "QUIC test")]);
        assert_eq!(
            suggested_command(
                prompt,
                &["scope".to_owned()],
                &values,
                &[],
                &[],
                None,
                None,
                false,
            ),
            "ferrox-prompt render P1 --set scope=<value> --set method='QUIC test'"
        );
    }

    #[test]
    fn a_retry_command_is_fenced_wider_than_its_backticks() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[("len", "a```b")]),
            &[],
            None,
            &Options {
                allow_unfilled: true,
                ..Options::default()
            },
        );
        assert!(
            rendered
                .text
                .contains("Full command:\n\n````\nferrox-prompt render P1"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn the_retry_command_keeps_the_named_library_and_row() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let options = Options {
            allow_unfilled: true,
            retry_library: Some(PathBuf::from("draft.md")),
            retry_row: Some("A13".to_owned()),
            ..Options::default()
        };
        let rendered = render(&library, prompt, &values(&[]), &[], None, &options);
        assert!(
            rendered
                .text
                .contains("render P1 --library draft.md --row A13 --set scope=<value>"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn a_retry_does_not_freeze_automatic_row_values() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
run with {len=40} and {scope} and {state}
```
",
        );
        let prompt = library.prompt(1).unwrap();
        let options = Options {
            allow_unfilled: true,
            retry_row: Some("A13".to_owned()),
            retry_values: Some(values(&[("issue", "661")])),
            ..Options::default()
        };
        let rendered = render(
            &library,
            prompt,
            &values(&[("state", "planned")]),
            &[],
            None,
            &options,
        );
        assert!(
            rendered
                .text
                .contains("--row A13 --set scope=<value> --set issue=661"),
            "{}",
            rendered.text
        );
        assert!(!rendered.text.contains("state="), "{}", rendered.text);
    }

    #[test]
    fn an_unselected_addon_does_not_add_its_input_to_the_command() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body {core}
```

**Add-on — Extra:** needs {len=40}

**Add-on — Second Pass:** adds no input
",
        );
        let prompt = library.prompt(1).unwrap();
        let missing = ["core".to_owned()];
        let values = BTreeMap::from([("len".to_owned(), "40".to_owned())]);
        assert_eq!(
            suggested_command(prompt, &missing, &values, &[], &[], None, None, false),
            "ferrox-prompt render P1 --set core=<value>"
        );
        for request in ["extra", "Extra", "EXTRA"] {
            let addons = resolve_addons(prompt, &[request.to_owned()]).unwrap();
            assert_eq!(
                suggested_command(prompt, &missing, &values, &addons, &[], None, None, false),
                "ferrox-prompt render P1 --set core=<value> --set len=40 --addon extra"
            );
        }
        for request in ["all", "extra,second-pass"] {
            let addons = resolve_addons(prompt, &[request.to_owned()]).unwrap();
            assert_eq!(
                suggested_command(prompt, &missing, &values, &addons, &[], None, None, false),
                "ferrox-prompt render P1 --set core=<value> --set len=40 \
                 --addon extra --addon second-pass"
            );
        }
        let addons = resolve_addons(prompt, &["Second Pass".to_owned()]).unwrap();
        assert_eq!(
            suggested_command(prompt, &missing, &values, &addons, &[], None, None, false),
            "ferrox-prompt render P1 --set core=<value> --addon second-pass"
        );
        assert_eq!(
            suggested_command(prompt, &missing, &values, &addons, &[], None, None, true),
            "ferrox-prompt render P1 --no-ledger --set core=<value> --addon second-pass"
        );
        assert_eq!(
            suggested_command(
                prompt,
                &missing,
                &values,
                &addons,
                &[],
                Some(Path::new("/tmp/my prompts.md")),
                Some("A13"),
                false
            ),
            "ferrox-prompt render P1 --library '/tmp/my prompts.md' --row A13 \
             --set core=<value> --addon second-pass"
        );
    }

    #[test]
    fn a_retry_keeps_explicit_values() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body {core}
```
",
        );
        let prompt = library.prompt(1).unwrap();
        let values = BTreeMap::from([("core".to_owned(), "a b".to_owned())]);
        assert_eq!(
            suggested_command(prompt, &[], &values, &[], &[], None, None, false),
            "ferrox-prompt render P1 --set core='a b'"
        );
    }

    #[test]
    fn an_addon_slugged_all_is_retried_by_an_unambiguous_selector() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body {core}
```

**Add-on — All!:** one add-on only

**Add-on — Extra:** another add-on
",
        );
        let prompt = library.prompt(1).unwrap();
        let addons = resolve_addons(prompt, &["All!".to_owned()]).unwrap();
        assert_eq!(addons.len(), 1);
        assert_eq!(
            suggested_command(
                prompt,
                &["core".to_owned()],
                &BTreeMap::new(),
                &addons,
                &[],
                None,
                None,
                false
            ),
            "ferrox-prompt render P1 --set core=<value> --addon 'All!'"
        );

        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body {core}
```

**Add-on — All:** one add-on only

**Add-on — Extra:** another add-on
",
        );
        let prompt = library.prompt(1).unwrap();
        let addons = resolve_addons(prompt, &["al".to_owned()]).unwrap();
        assert_eq!(addons.len(), 1);
        assert_eq!(
            suggested_command(
                prompt,
                &["core".to_owned()],
                &BTreeMap::new(),
                &addons,
                &["al".to_owned()],
                None,
                None,
                false
            ),
            "ferrox-prompt render P1 --set core=<value> --addon al"
        );
    }

    #[test]
    fn a_missing_issue_points_at_the_render_command() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Fix an issue

**When to use:** a regression
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** none
**Gates:** `cargo test`

```text
fix issue #{issue}
```
",
        );
        let prompt = library.prompt(1).unwrap();
        assert_eq!(
            suggested_command(
                prompt,
                &["issue".to_owned()],
                &BTreeMap::new(),
                &[],
                &[],
                None,
                None,
                false
            ),
            "ferrox-prompt render P1 --issue <number>"
        );
    }

    #[test]
    fn braces_can_be_escaped() {
        let values = values(&[("a", "1")]);
        assert_eq!(substitute("{{a}} and {a}", &values), "{a} and 1");
        assert_eq!(substitute("a { b", &values), "a { b");
        assert_eq!(substitute("{} {a b}", &values), "{} {a b}");
        // Unfilled stays as written; a supplied value wins over an empty default.
        assert_eq!(substitute("{b=}", &values), "{b=}");
        assert_eq!(substitute("{b= }", &values), "{b= }");
        assert_eq!(substitute("{a=}", &values), "1");
        assert_eq!(substitute("{a= }", &values), "1");
    }

    #[test]
    fn a_lone_brace_does_not_swallow_a_later_placeholder() {
        let filled = values(&[("name", "value")]);
        assert_eq!(substitute("a { b {name}", &filled), "a { b value");
        assert_eq!(substitute("a { b {name}", &values(&[])), "a { b {name}");
    }

    #[test]
    fn addons_resolve_exactly_then_by_unique_substring() {
        let library = library();
        let prompt = library.prompt(2).unwrap();
        assert_eq!(prompt.addon("isa-matrix").unwrap().slug, "isa-matrix");
        assert_eq!(resolve_addons(prompt, &["miri".into()]).unwrap().len(), 1);
        assert_eq!(resolve_addons(prompt, &["all".into()]).unwrap().len(), 2);
        assert_eq!(
            resolve_addons(prompt, &["miri,isa".into()]).unwrap().len(),
            2
        );
        assert_eq!(
            resolve_addons(prompt, &["miri".into(), "MIRI".into(), "isa".into()])
                .unwrap()
                .len(),
            2,
            "the same add-on is selected once, whatever the case and position"
        );
        let missing = resolve_addons(prompt, &["nope".into()]).unwrap_err();
        assert!(missing.contains("isa-matrix"), "{missing}");
        assert!(missing.contains("no add-on matching `nope`"), "{missing}");
    }

    #[test]
    fn only_a_selected_addons_inputs_are_required() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body {core}
```

**Add-on — Extra:** needs {extra}
",
        );
        let prompt = library.prompt(1).unwrap();
        assert_eq!(
            prompt.required_inputs_for(&[]).collect::<Vec<_>>(),
            ["core"]
        );
        let chosen = vec![prompt.addon("extra").unwrap().clone()];
        assert_eq!(
            prompt.required_inputs_for(&chosen).collect::<Vec<_>>(),
            ["core", "extra"]
        );
    }

    #[test]
    fn an_ambiguous_addon_is_an_error_rather_than_a_guess() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body
```

**Add-on — Isa matrix:** one
**Add-on — Isa baseline:** two
",
        );
        let prompt = library.prompt(1).unwrap();
        let error = resolve_addons(prompt, &["isa".into()]).unwrap_err();
        assert!(
            error.contains("isa-matrix") && error.contains("isa-baseline"),
            "{error}"
        );
    }

    #[test]
    fn the_header_states_the_graph_position() {
        let library = library();
        let prompt = library.prompt(2).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options {
                provenance: true,
                ..Options::default()
            },
        );
        assert!(rendered.text.contains("# P2 · Two"), "{}", rendered.text);
        assert!(rendered.text.contains("depends on P1"));
        assert!(rendered
            .text
            .contains("status todo · leverage 4 · effort large"));
    }

    #[test]
    fn the_footer_names_the_tag_and_says_it_is_not_a_checksum() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options {
                provenance: true,
                ..Options::default()
            },
        );
        assert!(rendered.text.contains("library tag "));
        assert!(rendered.text.contains("not a checksum"));
        let quiet = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options::default(),
        );
        assert!(!quiet.text.contains("ferrox-prompt ·"));
    }

    #[test]
    fn gates_can_be_left_out() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            &Options {
                gates: false,
                ..Options::default()
            },
        );
        assert!(!rendered.text.contains("## Acceptance"));
        assert!(rendered.text.contains("run with 40"));
    }

    #[test]
    fn a_prompt_with_no_addons_says_so() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
body
```
",
        );
        let prompt = library.prompt(1).unwrap();
        assert_eq!(prompt.status, Status::Todo);
        assert_eq!(prompt.effort, Effort::Small);
        let error = resolve_addons(prompt, &["any".into()]).unwrap_err();
        assert!(error.contains("has none"), "{error}");
    }
}
