//! The gate `ci.yml` runs on the library's shape — touches, gates, placeholders, graph, restated prose — never a judgement of prose quality.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::markdown::{Addon, Diagnostic, Library, Prompt, Touch, escaped};

/// A run of this many content words that the shared protocol already carries is a restatement, not a coincidence.
const RESTATEMENT_RUN: usize = 5;
/// The same, between two templates, where a shared turn of phrase can be deliberate.
const ECHO_RUN: usize = 6;

/// The words that carry a sentence's meaning, in order: a function word, a number or a `{blank}` is no evidence of copying, so it drops out.
fn content_tokens(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "could", "did",
        "do", "does", "for", "from", "had", "has", "have", "he", "her", "his", "if", "in", "is",
        "it", "its", "may", "might", "must", "no", "nor", "not", "of", "on", "or", "our", "she",
        "so", "than", "that", "the", "their", "them", "then", "there", "these", "they", "this",
        "to", "too", "us", "was", "we", "were", "what", "when", "which", "who", "will", "would",
        "you", "your",
    ];
    let bytes = text.as_bytes();
    let mut stripped = String::new();
    let mut index = 0;
    let mut in_blank = false;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some(close) = blank_end(bytes, index + 1)
        {
            index = close + 1;
            continue;
        }
        match bytes[index] {
            b'`' if !escaped(bytes, index) => {
                let width = bytes[index..]
                    .iter()
                    .take_while(|byte| **byte == b'`')
                    .count();
                let Some(close) = closing_fence(bytes, index + width, width) else {
                    // An unmatched run is literal text, not an endless span.
                    for _ in 0..width {
                        stripped.push('`');
                    }
                    index += width;
                    continue;
                };
                // A command inside a span is not prose evidence; `code_spans` compares commands instead.
                stripped.push(' ');
                index = close + width;
            }
            b'{' => {
                // A `{` with no close the tokenizer can see outside a span is literal text, not a blank that swallows the rest.
                if blank_closes(bytes, index + 1) {
                    in_blank = true;
                } else {
                    stripped.push('{');
                }
                index += 1;
            }
            b'}' => {
                in_blank = false;
                index += 1;
            }
            _ => {
                let character = text[index..].chars().next().expect("a byte starts a char");
                if !in_blank {
                    stripped.push(character);
                }
                index += character.len_utf8();
            }
        }
    }
    stripped
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| {
            word.len() > 2 && !word.chars().all(char::is_numeric) && !STOP.contains(&word.as_str())
        })
        .collect()
}

/// Whether a `}` the tokenizer will read follows, skipping the spans `closing_fence` also skips.
fn blank_closes(bytes: &[u8], index: usize) -> bool {
    blank_end(bytes, index).is_some()
}

/// The `}` that ends the placeholder opening before `index`, skipping code spans inside its default.
fn blank_end(bytes: &[u8], mut index: usize) -> Option<usize> {
    while index < bytes.len() {
        match bytes[index] {
            b'`' if !escaped(bytes, index) => {
                let width = bytes[index..]
                    .iter()
                    .take_while(|byte| **byte == b'`')
                    .count();
                index = closing_fence(bytes, index + width, width)
                    .map_or(index + width, |close| close + width);
            }
            b'}' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// The byte offset of the next backtick run of exactly `width`, or `None` when the span never closes.
fn closing_fence(bytes: &[u8], mut index: usize, width: usize) -> Option<usize> {
    while index < bytes.len() {
        if bytes[index] == b'`' {
            let run = bytes[index..]
                .iter()
                .take_while(|byte| **byte == b'`')
                .count();
            if run == width {
                return Some(index);
            }
            index += run;
        } else {
            index += 1;
        }
    }
    None
}

/// The longest run of consecutive words `a` and `b` share, and the phrase.
fn longest_shared_run(a: &[String], b: &[String]) -> (usize, String) {
    let mut at: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, word) in a.iter().enumerate() {
        at.entry(word.as_str()).or_default().push(index);
    }
    let mut best = 0;
    let mut phrase = String::new();
    for (start_b, word) in b.iter().enumerate() {
        let Some(starts) = at.get(word.as_str()) else {
            continue;
        };
        for &start_a in starts {
            let mut run = 0;
            while start_a + run < a.len()
                && start_b + run < b.len()
                && a[start_a + run] == b[start_b + run]
            {
                run += 1;
            }
            if run > best {
                best = run;
                phrase = a[start_a..start_a + run].join(" ");
            }
        }
    }
    (best, phrase)
}

/// The texts a handout actually carries: the protocol line, the body, and every add-on — not the lines only `list` reads.
fn handout_texts(prompt: &Prompt) -> Vec<(String, String)> {
    let mut texts: Vec<(String, String)> = Vec::new();
    if !prompt.protocol.is_empty() {
        texts.push(("**Prompt protocol:**".to_owned(), prompt.protocol.clone()));
    }
    texts.push(("body".to_owned(), prompt.body.clone()));
    for addon in &prompt.addons {
        let Addon { body, slug, .. } = addon;
        texts.push((format!("add-on `{slug}`"), body.clone()));
    }
    texts
}

/// The code spans a text carries, so two different commands are not read as the same instruction.
fn code_spans(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some(close) = blank_end(bytes, index + 1)
        {
            index = close + 1;
            continue;
        }
        if bytes[index] != b'`' || escaped(bytes, index) {
            index += 1;
            continue;
        }
        let width = bytes[index..]
            .iter()
            .take_while(|byte| **byte == b'`')
            .count();
        let Some(close) = closing_fence(bytes, index + width, width) else {
            index += width;
            continue;
        };
        spans.push(text[index + width..close].trim().to_owned());
        index = close + width;
    }
    spans
}

/// Sentences and clauses, so a command difference excuses only its own instruction.
fn instructions(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some(close) = blank_end(bytes, index + 1)
        {
            index = close + 1;
            continue;
        }
        match bytes[index] {
            b'`' if !escaped(bytes, index) => {
                let width = bytes[index..]
                    .iter()
                    .take_while(|byte| **byte == b'`')
                    .count();
                index = closing_fence(bytes, index + width, width)
                    .map_or(index + width, |close| close + width);
            }
            b';' => {
                let instruction = text[start..index].trim();
                if !instruction.is_empty() {
                    out.push(instruction);
                }
                index += 1;
                start = index;
            }
            b'.' | b'!' | b'?' => {
                let ends = bytes.get(index + 1).is_none_or(u8::is_ascii_whitespace);
                if ends {
                    let instruction = text[start..index].trim();
                    if !instruction.is_empty() {
                        out.push(instruction);
                    }
                    start = index + 1;
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    let instruction = text[start..].trim();
    if !instruction.is_empty() {
        out.push(instruction);
    }
    out
}

/// One segment per instruction, so prose before a differing command still compares while the
/// command itself stays exempt.
fn prose_segments(text: &str) -> Vec<(Vec<String>, Vec<String>)> {
    instructions(text)
        .into_iter()
        .map(|instruction| (content_tokens(instruction), code_spans(instruction)))
        .collect()
}

/// A run that crosses sentence boundaries while every matching word stays bound to the instruction
/// that supplied it: a command only exempts its own instruction, not one at the same offset.
fn adjacent_restatement(
    body: &[(Vec<String>, Vec<String>)],
    rule: &[(Vec<String>, Vec<String>)],
) -> Option<(usize, String)> {
    let mut body_words: Vec<(&str, usize, &[String])> = Vec::new();
    for (offset, (words, commands)) in body.iter().enumerate() {
        for word in words {
            body_words.push((word.as_str(), offset, commands.as_slice()));
        }
    }
    let mut rule_words: Vec<(&str, usize, &[String])> = Vec::new();
    for (offset, (words, commands)) in rule.iter().enumerate() {
        for word in words {
            rule_words.push((word.as_str(), offset, commands.as_slice()));
        }
    }
    for body_start in 0..body_words.len() {
        for rule_start in 0..rule_words.len() {
            let mut run = 0;
            while body_start + run < body_words.len() && rule_start + run < rule_words.len() {
                let (body_word, body_offset, body_commands) = body_words[body_start + run];
                let (rule_word, rule_offset, rule_commands) = rule_words[rule_start + run];
                if body_word != rule_word {
                    break;
                }
                let bound = if body_commands.is_empty() && rule_commands.is_empty() {
                    true
                } else {
                    body_offset == rule_offset
                        && (body_commands.is_empty()
                            || rule_commands.is_empty()
                            || body_commands == rule_commands)
                };
                if !bound {
                    break;
                }
                run += 1;
                if run >= RESTATEMENT_RUN {
                    let phrase = body_words[body_start..body_start + run]
                        .iter()
                        .map(|(word, _, _)| *word)
                        .collect::<Vec<_>>()
                        .join(" ");
                    return Some((run, phrase));
                }
            }
        }
    }
    None
}

/// Prose the shared protocol already says, and prose two templates both say.
fn check_restatements(library: &Library, findings: &mut Vec<Diagnostic>) {
    let protocol = prose_segments(&library.shared_protocol);
    let mut carried: Vec<(u32, usize, String, Vec<String>)> = Vec::new();
    for prompt in &library.prompts {
        for (label, text) in handout_texts(prompt) {
            let tokens = content_tokens(&text);
            let segments = prose_segments(&text);
            let repeated = segments
                .iter()
                .find_map(|(body, commands)| {
                    protocol.iter().find_map(|(rule, rule_commands)| {
                        let (run, phrase) = longest_shared_run(rule, body);
                        let command_differs = !rule_commands.is_empty()
                            && !commands.is_empty()
                            && commands != rule_commands;
                        (run >= RESTATEMENT_RUN && !command_differs).then_some((run, phrase))
                    })
                })
                .or_else(|| adjacent_restatement(&segments, &protocol));
            if let Some((run, phrase)) = repeated {
                findings.push(Diagnostic::error(
                    prompt.line,
                    format!(
                        "P{}: its {label} repeats the shared protocol for {run} words \
                         (\"{phrase}\"); every handout already carries that rule, so keep only \
                         what this slice adds",
                        prompt.id
                    ),
                ));
            }
            carried.push((prompt.id, prompt.line, label, tokens));
        }
    }
    for first in 0..carried.len() {
        for second in first + 1..carried.len() {
            let (one, _, _, a) = &carried[first];
            let (two, line, label_two, b) = &carried[second];
            if one == two {
                continue;
            }
            let (run, phrase) = longest_shared_run(a, b);
            if run >= ECHO_RUN {
                findings.push(Diagnostic::warning(
                    *line,
                    format!(
                        "P{two}: its {label_two} echoes P{one} for {run} words (\"{phrase}\"); one \
                         of the two should say it, or the phrase is load-bearing and belongs in the \
                         shared protocol",
                    ),
                ));
            }
        }
    }
}

/// Parser findings plus filesystem and roadmap-wide ones; `verify_paths` is false for an outside library, and the report says what was skipped.
pub fn run(library: &Library, root: &Path, verify_paths: bool) -> Vec<Diagnostic> {
    let mut findings = library.diagnostics.clone();
    if !verify_paths {
        findings.push(Diagnostic::warning(
            0,
            format!(
                "this library is outside {}, so **Touches:** and the workflows its gates name \
                 were not checked",
                root.display()
            ),
        ));
    }
    for prompt in &library.prompts {
        if verify_paths {
            check_touches(prompt, root, &mut findings);
        }
        check_gates(prompt, root, verify_paths, &mut findings);
        check_placeholders(prompt, &mut findings);
    }
    check_roadmap(library, root, &mut findings);
    check_restatements(library, &mut findings);
    findings.sort_by_key(|finding| (finding.line, finding.severity));
    findings
}

/// Paths this prompt claims, against what is actually there.
fn check_touches(prompt: &Prompt, root: &Path, findings: &mut Vec<Diagnostic>) {
    for touch in &prompt.touches {
        let path = touch.path();
        let full = root.join(path);
        let occupied = std::fs::symlink_metadata(&full).is_ok();
        match touch {
            Touch::Existing(_) if !full.is_file() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `{path}` does not exist or is not a file, so this slice \
                     points at something nothing will edit",
                    prompt.id
                ),
            )),
            Touch::Created(_) if occupied && !full.is_file() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `+{path}` is not a file, so this slice claims to create \
                     something a file edit cannot write — point it at the file inside the directory",
                    prompt.id
                ),
            )),
            Touch::Created(_) if prompt.is_open() && occupied => {
                findings.push(Diagnostic::error(
                    prompt.line,
                    format!(
                        "P{}: **Touches:** `+{path}` already exists, so this slice claims to create \
                         a file that is there — mark the prompt done, or file it against the real path",
                        prompt.id
                    ),
                ));
            }
            _ => {}
        }
    }
}

/// Gates against the repository they name.
fn check_gates(prompt: &Prompt, root: &Path, verify_paths: bool, findings: &mut Vec<Diagnostic>) {
    let workflows = root.join(".github/workflows");
    for gate in &prompt.gates {
        let trimmed = gate.trim();
        if looks_like_a_command(trimmed) && !trimmed.starts_with('`') {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: the gate `{trimmed}` is a command written as plain text; wrap it in \
                     backticks so it reads as one",
                    prompt.id
                ),
            ));
        }
        if !verify_paths {
            continue;
        }
        // A bare filename is still a workflow; a command's arguments are not, so only one unprefixed token is read.
        let reference = match trimmed
            .strip_prefix("CI:")
            .or_else(|| trimmed.strip_prefix('§'))
        {
            Some(reference) => reference,
            None if looks_like_a_command(trimmed) || trimmed.split_whitespace().count() > 1 => {
                continue;
            }
            None => trimmed,
        };
        for token in
            reference.split(|character: char| character.is_whitespace() || character == ',')
        {
            // A `§`-prefixed gate is the conditional form: it names the same workflow.
            let name = token
                .trim_matches('`')
                .trim_start_matches('§')
                .trim_matches('`');
            // Case-insensitive: `CI.yml` and `ci.yml` are one workflow to the author, two strings to a byte compare.
            let extension = Path::new(name)
                .extension()
                .map_or_default(|extension| extension.to_string_lossy().to_ascii_lowercase());
            let names_a_workflow =
                matches!(extension.as_str(), "yml" | "yaml") && !name.contains('/');
            if names_a_workflow && !workflow_exists(&workflows, name) {
                findings.push(Diagnostic::error(
                    prompt.line,
                    format!(
                        "P{}: the gate names `{name}`, which is not in .github/workflows/; a gate \
                         that names a job which does not exist is a promise, not a check",
                        prompt.id
                    ),
                ));
            }
        }
    }
}

/// Exact spelling first, then the same name ignoring case, so `CI.yml` finds `ci.yml`.
fn workflow_exists(workflows: &Path, name: &str) -> bool {
    if workflows.join(name).is_file() {
        return true;
    }
    std::fs::read_dir(workflows).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry.path().is_file()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(name)
        })
    })
}

/// Whether a gate opens like a shell command.
fn looks_like_a_command(gate: &str) -> bool {
    const OPENERS: &[&str] = &[
        "cargo ", "./", "bash ", "sh ", "git ", "gh ", "make ", "npm ",
    ];
    OPENERS.iter().any(|opener| gate.starts_with(opener))
}

/// Defaults that are empty, which render as a hole that looks like a value.
fn check_placeholders(prompt: &Prompt, findings: &mut Vec<Diagnostic>) {
    for placeholder in &prompt.placeholders {
        if prompt.targets.is_matrix()
            && !crate::expand::FILLABLE.contains(&placeholder.name.as_str())
        {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: `{{{}}}` is not a matrix-filled placeholder; a matrix template draws only {}",
                    prompt.id,
                    placeholder.name,
                    crate::expand::FILLABLE.join(", ")
                ),
            ));
        }
        if placeholder
            .default
            .as_deref()
            .is_some_and(|default| default.trim().is_empty())
        {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: `{{{} =}}` has an empty default; give it a value or drop the `=` so it \
                     reads as required",
                    prompt.id, placeholder.name
                ),
            ));
        }
    }
}

/// Name a hole, but cap the diagnostics a sparse id can create.
fn report_missing_ids(first: u32, last: u32, sequence_last: u32, findings: &mut Vec<Diagnostic>) {
    const REPORT_LIMIT: u32 = 8;
    let count = last - first + 1;
    if count <= REPORT_LIMIT {
        for id in first..=last {
            findings.push(Diagnostic::error(0, missing_id(id, id, sequence_last)));
        }
    } else {
        findings.push(Diagnostic::error(0, missing_id(first, last, sequence_last)));
    }
}

/// One line for one missing id, or one bounded range when the hole is large.
fn missing_id(first: u32, last: u32, sequence_last: u32) -> String {
    let subject = if first == last {
        format!("P{first}")
    } else {
        format!("P{first}..=P{last}")
    };
    let verb = if first == last { "is" } else { "are" };
    format!(
        "{subject} {verb} missing; prompt ids are 1..={sequence_last} with no gaps, so a hole in \
         the sequence means a prompt was deleted without the graph being updated"
    )
}

/// Checks about the roadmap as a whole.
fn check_roadmap(library: &Library, root: &Path, findings: &mut Vec<Diagnostic>) {
    let mut ids: Vec<u32> = library.prompts.iter().map(|prompt| prompt.id).collect();
    ids.sort_unstable();
    ids.dedup();
    if let Some(&last) = ids.last() {
        let mut expected = 1;
        for id in ids {
            if id == 0 {
                findings.push(Diagnostic::error(
                    0,
                    String::from(
                        "P0 is below the required starting id 1; prompt ids start at P1 with no gaps",
                    ),
                ));
                continue;
            }
            if id > expected {
                report_missing_ids(expected, id - 1, last, findings);
            }
            expected = id.saturating_add(1);
        }
    }

    let open: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open())
        .collect();
    if open.is_empty() {
        findings.push(Diagnostic::warning(
            0,
            "no prompt is `todo` or `blocked`: the roadmap has nothing to offer, so `next` will \
             only ever say so",
        ));
    }

    // Files more than one available prompt claims. See `contention`.
    let claims = resolved_claims(library, root);
    for prompt in library
        .prompts
        .iter()
        .filter(|prompt| is_available(library, prompt))
    {
        for clash in contention_with(prompt, &claims, root) {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{} and {} are both open now and both claim `{}`; they are one slice, or two \
                     that must be taken in order",
                    prompt.id,
                    clash
                        .also
                        .iter()
                        .map(|id| format!("P{id}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    clash.path
                ),
            ));
        }
    }
}

/// Started or ready now: only two *available* slices claiming one file is a real ordering decision.
pub fn is_available(library: &Library, prompt: &Prompt) -> bool {
    prompt.status == crate::markdown::Status::Doing
        || crate::advisor::readiness(library, prompt) == crate::advisor::Readiness::Ready
}

/// A file this prompt shares with another available prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contention {
    /// The path, as both prompts write it.
    pub path: String,
    /// The other prompts that are available and claim it.
    pub also: Vec<u32>,
}

/// Every available prompt's touches, resolved once so a roadmap check does not canonicalize them
/// again for every prompt it compares.
fn resolved_claims(library: &Library, root: &Path) -> Vec<(u32, Vec<(String, PathBuf)>)> {
    library
        .prompts
        .iter()
        .filter(|prompt| is_available(library, prompt))
        .map(|prompt| {
            let touches = prompt
                .touches
                .iter()
                .map(|touch| (touch.path().to_owned(), resolve_touch(root, touch.path())))
                .collect();
            (prompt.id, touches)
        })
        .collect()
}

fn contention_with(
    prompt: &Prompt,
    claims: &[(u32, Vec<(String, PathBuf)>)],
    root: &Path,
) -> Vec<Contention> {
    let mut found: Vec<Contention> = Vec::new();
    for path in prompt.touches.iter().map(Touch::path) {
        let normalized = claims
            .iter()
            .find(|(id, _)| *id == prompt.id)
            .and_then(|(_, touches)| {
                touches
                    .iter()
                    .find(|(written, _)| written.as_str() == path)
                    .map(|(_, resolved)| resolved.clone())
            })
            .unwrap_or_else(|| resolve_touch(root, path));
        let also: Vec<u32> = claims
            .iter()
            .filter(|(id, _)| *id != prompt.id)
            .filter(|(_, touches)| touches.iter().any(|(_, resolved)| resolved == &normalized))
            .map(|(id, _)| *id)
            .collect();
        if !also.is_empty() {
            found.push(Contention {
                path: path.to_owned(),
                also,
            });
        }
    }
    found
}

/// Files `prompt` shares with a prompt the advisor could also be asked for.
pub fn contention(library: &Library, prompt: &Prompt, root: &Path) -> Vec<Contention> {
    contention_with(prompt, &resolved_claims(library, root), root)
}

/// The path as the filesystem sees it: the longest existing prefix is resolved through symlinks,
/// then the components that are not there yet are kept — so `..` never crosses a symlink.
fn resolve_touch(root: &Path, path: &str) -> std::path::PathBuf {
    let full = root.join(path);
    let components: Vec<Component<'_>> = full.components().collect();
    for end in (0..=components.len()).rev() {
        let mut prefix = std::path::PathBuf::new();
        for component in &components[..end] {
            prefix.push(component.as_os_str());
        }
        let Ok(resolved) = std::fs::canonicalize(&prefix) else {
            continue;
        };
        let mut out = resolved;
        for component in &components[end..] {
            out.push(component.as_os_str());
        }
        return lexical_path(&out);
    }
    lexical_path(&full)
}

/// `.` dropped and `..` folded on a path whose symlinks are already resolved.
fn lexical_path(path: &Path) -> std::path::PathBuf {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let has_normal = matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                );
                if has_normal {
                    normalized.pop();
                } else if !matches!(
                    normalized.components().next_back(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    normalized.push("..");
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    const GOOD: &str = "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** none
**Gates:** `cargo test`; CI: `ci.yml`
**Touches:** Cargo.toml

```text
body
```
";

    #[test]
    fn a_fenced_close_does_not_open_a_blank() {
        let tokens = content_tokens("{ alpha `}` beta gamma delta epsilon zeta");
        assert!(tokens.iter().any(|word| word == "zeta"), "{tokens:?}");
    }

    #[test]
    fn an_escaped_backtick_in_a_placeholder_default_does_not_hide_the_close() {
        let text = "Use {scope=local\\`; preserve stable public interfaces everywhere}; Run";
        let open = text.find('{').expect("blank") + 1;
        let close = text.find('}').expect("close");
        assert_eq!(blank_end(text.as_bytes(), open), Some(close));
    }

    #[test]
    fn an_unmatched_brace_stays_literal() {
        let tokens = content_tokens("{ alpha beta gamma");
        assert!(tokens.iter().any(|word| word == "beta"), "{tokens:?}");
    }

    #[test]
    fn a_command_span_keeps_the_whitespace_its_arguments_carry() {
        let spans = code_spans("run `printf 'a  b'` and `cargo test`");
        assert!(
            spans.iter().any(|span| span == "printf 'a  b'"),
            "{spans:?}"
        );
        assert!(spans.iter().any(|span| span == "cargo test"), "{spans:?}");
    }

    #[test]
    fn a_line_wrap_does_not_start_a_new_instruction() {
        let split =
            instructions("The bar is the best\nimplementation, not a working one; then stop");
        assert_eq!(
            split,
            vec![
                "The bar is the best\nimplementation, not a working one",
                "then stop"
            ]
        );
    }

    #[test]
    fn a_body_that_restates_the_shared_protocol_is_an_error() {
        let text = GOOD.replace(
            "p\n```",
            "p\nThe bar is the best implementation, not a working one\n```",
        );
        let library = load(&text.replace(
            "```text\nbody",
            "```text\nThe bar is the best implementation, not a working one here",
        ));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn adjacent_short_sentences_that_together_restate_the_protocol_are_an_error() {
        let rule = "Preserve stable interfaces. Keep serialized fields compatible.";
        let text = GOOD
            .replace("p\n```", &format!("p\n{rule}\n```"))
            .replace("```text\nbody", &format!("```text\n{rule}"));
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn prose_across_independent_sentence_boundaries_is_a_restatement() {
        let rule = "Preserve stable interfaces. Keep serialized fields compatible.";
        let text = GOOD.replace("p\n```", &format!("p\n{rule}\n```")).replace(
            "```text\nbody",
            "```text\nPreserve stable interfaces and keep serialized fields compatible.",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn prose_before_a_differing_command_is_still_a_restatement() {
        let rule =
            "Preserve stable interfaces. Keep serialized fields compatible. Run `cargo test`.";
        let text = GOOD
            .replace("p\n```", &format!("p\n{rule}\n```"))
            .replace(
                "```text\nbody",
                "```text\nPreserve stable interfaces. Keep serialized fields compatible. Run `cargo fmt`.",
            );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_one_sided_command_span_does_not_hide_adjacent_prose() {
        let rule = "Preserve stable interfaces. Keep serialized fields compatible.";
        let text = GOOD.replace("p\n```", &format!("p\n{rule}\n```")).replace(
            "```text\nbody",
            "```text\nPreserve stable interfaces. Keep `serde` serialized fields compatible.",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn adjacent_prose_around_a_matching_command_is_a_restatement() {
        let rule = "Preserve stable interfaces. Keep `serde` fields compatible.";
        let text = GOOD
            .replace("p\n```", &format!("p\n{rule}\n```"))
            .replace("```text\nbody", &format!("```text\n{rule}"));
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn punctuation_in_a_placeholder_default_is_not_prose() {
        let text = GOOD.replace(
            "```text\nbody",
            "```text\nUse {scope=local; preserve stable public interfaces everywhere}.",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn escaped_backticks_are_literal_prose_not_commands() {
        let rule = "Never copy reference source into this repository \\`alpha\\`.";
        let text = GOOD.replace("p\n```", &format!("p\n{rule}\n```")).replace(
            "```text\nbody",
            "```text\nNever copy reference source into this repository \\`beta\\`.",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn consecutive_command_sentences_still_compare_as_one_rule() {
        let rule = "Keep `serde` fields compatible. Preserve `tokio` task ownership.";
        let text = GOOD
            .replace("p\n```", &format!("p\n{rule}\n```"))
            .replace("```text\nbody", &format!("```text\n{rule}"));
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_command_does_not_excuse_a_sentence_that_belongs_to_another_instruction() {
        let rule = "Run `cargo test` after editing shared parser modules. Check logs.";
        let text = GOOD.replace("p\n```", &format!("p\n{rule}\n```")).replace(
            "```text\nbody",
            "```text\nReminder. Run `cargo fmt` after editing shared parser modules.",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn distinct_commands_are_not_a_restatement_even_when_the_prose_around_them_matches() {
        let text = GOOD
            .replace(
                "p\n```",
                "p\nRun `cargo test` after editing any shared parser module\n```",
            )
            .replace(
                "```text\nbody",
                "```text\nRun `cargo fmt --check` after editing any shared parser module",
            );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn reversed_commands_are_not_a_restatement() {
        let text = GOOD
            .replace(
                "p\n```",
                "p\nRun `cargo fmt` then `cargo test` after editing any shared parser module\n```",
            )
            .replace(
                "```text\nbody",
                "```text\nRun `cargo test` then `cargo fmt` after editing any shared parser module",
            );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn commands_that_differ_only_in_case_are_still_distinct() {
        let text = GOOD
            .replace(
                "p\n```",
                "p\nRun `printf 'OK'` after editing any shared parser module\n```",
            )
            .replace(
                "```text\nbody",
                "```text\nRun `printf 'ok'` after editing any shared parser module",
            );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_distinct_command_does_not_excuse_another_repeated_rule() {
        let text = GOOD
            .replace(
                "p\n```",
                "p\nNever copy reference source into this repository. Run `cargo test`.\n```",
            )
            .replace(
                "```text\nbody",
                "```text\nNever copy reference source into this repository. Run `cargo fmt`.",
            );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_body_that_agrees_with_the_protocol_in_other_words_is_fine() {
        let library = load(&GOOD.replace(
            "```text\nbody",
            "```text\nAim past the passing build: the reference sets the floor, and this tree has to beat it",
        ));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_bodies_that_echo_each_other_are_a_warning() {
        let shared = "fold the record layer framing into one helper everywhere";
        let one = GOOD.replace(
            "```text\nbody",
            &format!("```text\nbody, and {shared} once"),
        );
        let text = format!(
            "{one}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\n{shared} twice\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("echoes P1")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_command_shared_by_two_bodies_is_not_an_echo() {
        let command = "cargo test --workspace --all-features --locked";
        let one = GOOD.replace("```text\nbody", &format!("```text\nbody `{command}`"));
        let text = format!(
            "{one}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nrun `{command}`\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("echoes P1")),
            "{findings:#?}"
        );
    }

    #[test]
    fn the_live_library_passes_its_own_gate() {
        let library = crate::load_library(None, Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("the library is next to this crate");
        let root = crate::workspace_root(Path::new(env!("CARGO_MANIFEST_DIR")));
        let findings = run(&library, &root, true);
        let errors: Vec<&Diagnostic> = findings
            .iter()
            .filter(|finding| finding.severity == crate::markdown::Severity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "prompts.md fails its own gate: {errors:#?}"
        );
    }

    #[test]
    fn a_completed_prompt_may_have_created_its_output() {
        let library = load(
            &GOOD
                .replace("**Status:** todo", "**Status:** done")
                .replace("**Touches:** Cargo.toml", "**Touches:** +Cargo.toml"),
        );
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("already exists")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_completed_prompt_may_not_claim_a_directory_as_created() {
        let library = load(
            &GOOD
                .replace("**Status:** todo", "**Status:** done")
                .replace("**Touches:** Cargo.toml", "**Touches:** +crates"),
        );
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("is not a file")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_parent_component_does_not_hide_two_prompts_claiming_one_file() {
        let text = GOOD.replace(
            "body\n```",
            "body\n```\n\n## P2 · Two\n\n**When to use:** now\n**Status:** doing\n\
             **Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n**Touches:** crates/../Cargo.toml\n\n```text\nb\n```",
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        let root = crate::manifest_root();
        assert_eq!(
            resolve_touch(&root, "crates/../Cargo.toml"),
            resolve_touch(&root, "Cargo.toml")
        );
        assert_ne!(
            resolve_touch(&root, "crates/../Cargo.toml"),
            resolve_touch(&root, "..")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("both open now")),
            "{findings:#?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_component_does_not_fold_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "ferrox-prompt-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("docs/function")).expect("dirs");
        std::fs::write(root.join("README.md"), "root").expect("root readme");
        std::fs::write(root.join("docs/README.md"), "docs").expect("docs readme");
        symlink(root.join("docs/function"), root.join("alias")).expect("symlink");

        let root_readme = resolve_touch(&root, "README.md");
        let docs_readme = resolve_touch(&root, "alias/../README.md");
        assert_eq!(docs_readme, resolve_touch(&root, "docs/README.md"));
        assert_ne!(docs_readme, root_readme);
        assert_eq!(
            resolve_touch(&root, "alias/../new.rs"),
            resolve_touch(&root, "docs/new.rs")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_existing_touch_must_be_a_file_not_a_directory() {
        let library = load(&GOOD.replace("**Touches:** Cargo.toml", "**Touches:** crates"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("does not exist or is not a file")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_workflow_name_is_matched_ignoring_case_and_command_arguments_are_not_workflows() {
        let case = load(&GOOD.replace("CI: `ci.yml`", "CI: `CI.yml`"));
        let findings = run(&case, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("not in .github/workflows")),
            "{findings:#?}"
        );

        for gate in ["CI: §`ci.yml`", "CI: `§ci.yml`"] {
            let conditional = load(&GOOD.replace("CI: `ci.yml`", gate));
            let findings = run(&conditional, &crate::manifest_root(), true);
            assert!(
                findings
                    .iter()
                    .all(|finding| !finding.message.contains("not in .github/workflows")),
                "{findings:#?}"
            );
        }

        let command = load(&GOOD.replace("CI: `ci.yml`", "`yq . settings.yaml`"));
        let findings = run(&command, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("settings.yaml")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_missing_prefix_is_named_and_a_sparse_gap_is_bounded() {
        let prefix = "## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nb\n```\n";
        let findings = run(&load(prefix), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("P1 is missing")),
            "{findings:#?}"
        );

        let sparse = format!(
            "{prefix}## P1000000000 · Sparse\n\n**When to use:** now\n**Status:** todo\n\
             **Leverage:** 1\n**Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n\
             ```text\nb\n```\n"
        );
        let findings = run(&load(&sparse), &crate::manifest_root(), true);
        let holes: Vec<_> = findings
            .iter()
            .filter(|finding| finding.message.contains("missing; prompt ids"))
            .collect();
        assert_eq!(holes.len(), 2, "{findings:#?}");
        assert!(
            holes
                .iter()
                .any(|finding| finding.message.contains("P3..=P999999999"))
        );
    }

    #[test]
    fn prompt_ids_with_a_gap_are_named() {
        let text = "## P1 · One\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 3\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nb\n```\n\n\
             ## P3 · Three\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nb\n```\n";
        let findings = run(&load(text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("P2 is missing")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_p0_prompt_is_outside_the_required_range() {
        let text = "## P0 · Zero\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nb\n```\n\n\
             ## P1 · One\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n\n```text\nb\n```\n";
        let findings = run(&load(text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("P0 is below")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_touch_at_a_missing_file_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "crates/gone.rs"));
        let findings = run(&library, Path::new("/nonexistent-root"), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("does not exist")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_touch_at_an_existing_file_is_fine_against_the_real_root() {
        let library = load(GOOD);
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("does not exist"))
        );
    }

    #[test]
    fn a_created_file_that_already_exists_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "+Cargo.toml"));
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("already exists")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_gate_naming_a_missing_workflow_is_an_error() {
        for gate in ["CI: `no-such.yml`", "`no-such.yml`"] {
            let library = load(&GOOD.replace("CI: `ci.yml`", gate));
            let findings = run(&library, &crate::manifest_root(), true);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.message.contains("not in .github/workflows")),
                "{findings:#?}"
            );
        }
    }

    #[test]
    fn a_command_gate_without_backticks_is_a_warning() {
        let library = load(&GOOD.replace("`cargo test`", "cargo test"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("wrap it in")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_open_prompts_claiming_one_file_are_reported() {
        let text = format!(
            "{GOOD}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n**Touches:** Cargo.toml\n\n```text\nb\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("both claim")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_spellings_of_one_path_are_the_same_claim() {
        let text = format!(
            "{GOOD}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n**Touches:** ./Cargo.toml\n\n```text\nb\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("both claim")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_created_file_claimed_by_two_open_prompts_is_reported() {
        let touched = GOOD.replace(
            "**Touches:** Cargo.toml",
            "**Touches:** +crates/ferrox-prompt/src/contended.rs",
        );
        let text = format!(
            "{touched}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Targets:** none\n**Gates:** `cargo test`\n**Touches:** +crates/ferrox-prompt/src/contended.rs\n\n```text\nb\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings.iter().any(|finding| finding
                .message
                .contains("both claim `crates/ferrox-prompt/src/contended.rs`")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_whitespace_only_default_is_a_warning() {
        let library = load(&GOOD.replace("```text\nbody", "```text\nbody {a= }"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("empty default")),
            "{findings:#?}"
        );
    }

    #[test]
    fn an_empty_default_is_a_warning() {
        let library = load(&GOOD.replace("```text\nbody", "```text\nbody {a=}"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("empty default")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_finished_roadmap_says_so() {
        let text = GOOD.replace("**Status:** todo", "**Status:** done");
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("nothing to offer")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_library_outside_the_repository_says_which_checks_were_skipped() {
        let findings = run(&load(GOOD), &crate::manifest_root(), false);
        let note = findings
            .iter()
            .find(|finding| finding.message.contains("were not checked"))
            .unwrap_or_else(|| panic!("a skipped check must be said out loud: {findings:#?}"));
        assert!(note.message.contains("**Touches:**"));
    }
}
