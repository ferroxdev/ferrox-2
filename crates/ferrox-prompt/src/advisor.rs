//! Ready = `todo` with every dependency done, ranked by leverage then smaller effort; `--rotate` draws only from that ready set, and every draw is ledged.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::expand::ProjectState;
use crate::markdown::{Effort, Library, Prompt, Status};
use crate::state::MethodRow;

/// Whether the advisor may offer a prompt, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Open, and every dependency is done.
    Ready,
    /// Open, waiting on these prompts to be `done`.
    WaitingOn(Vec<u32>),
    /// Open, but a human owns it: a half-finished slice must finish before a new one starts, yet `list` still shows it.
    Deferred,
    /// `done`.
    Finished,
}

/// Why a prompt is or is not ready.
pub fn readiness(library: &Library, prompt: &Prompt) -> Readiness {
    if prompt.status == Status::Done {
        return Readiness::Finished;
    }
    if prompt.status != Status::Todo {
        return Readiness::Deferred;
    }
    let waiting: Vec<u32> = prompt
        .depends_on
        .iter()
        .copied()
        .filter(|id| {
            library
                .prompt(*id)
                .is_none_or(|dependency| dependency.status != Status::Done)
        })
        .collect();
    if waiting.is_empty() {
        Readiness::Ready
    } else {
        Readiness::WaitingOn(waiting)
    }
}

/// Ready prompt indices, best first.
pub fn ranked(library: &Library, effort: Option<Effort>) -> Vec<usize> {
    let mut ready: Vec<usize> = library
        .prompts
        .iter()
        .enumerate()
        .filter(|(_, prompt)| readiness(library, prompt) == Readiness::Ready)
        .filter(|(_, prompt)| effort.is_none_or(|wanted| prompt.effort == wanted))
        .map(|(index, _)| index)
        .collect();
    ready.sort_by_key(|&index| {
        let prompt = &library.prompts[index];
        (Reverse(prompt.leverage), prompt.effort, prompt.id)
    });
    ready
}

/// The best ready prompt skipping `exclude`; `Err` names what was skipped, so an empty answer is explainable.
pub fn next_index(
    library: &Library,
    effort: Option<Effort>,
    exclude: &[u32],
) -> Result<usize, String> {
    let ready = ranked(library, effort);
    if ready.is_empty() {
        return Err(no_ready_reason(library));
    }
    let available: Vec<usize> = ready
        .iter()
        .copied()
        .filter(|&index| !exclude.contains(&library.prompts[index].id))
        .collect();
    match available.first() {
        Some(&index) => Ok(index),
        None => Err(format!(
            "every ready slice is one of the last {} handed out ({}); pass --rotate for a \
             different draw, or --id P<n> for that one on purpose",
            exclude.len(),
            exclude
                .iter()
                .map(|id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Why `ranked` is empty: a dependency, a started slice, a filter, or a finished roadmap are different answers.
fn no_ready_reason(library: &Library) -> String {
    let open: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open())
        .collect();
    let ready = ranked(library, None);
    if open.is_empty() {
        return "no prompt is ready: every prompt is done, so the roadmap has nothing left to \
                hand over"
            .to_owned();
    }
    let unblocked = ready.len();
    if unblocked > 0 {
        return format!(
            "no prompt is ready at the requested effort; {unblocked} unblocked prompt(s) are at \
             another effort, so drop --effort or ask for one of theirs"
        );
    }
    let started = open
        .iter()
        .filter(|prompt| prompt.status == Status::Doing)
        .count();
    let blocked = open
        .iter()
        .filter(|prompt| prompt.status == Status::Blocked)
        .count();
    let waiting = open.len() - started - blocked;
    if waiting == open.len() {
        return "no prompt is ready: every open one is waiting on a dependency".to_owned();
    }
    if started == open.len() {
        return "no prompt is ready: every open one is already started, so finish one before \
                drawing another"
            .to_owned();
    }
    if blocked == open.len() {
        return "no prompt is ready: every open one is blocked on something outside the roadmap"
            .to_owned();
    }
    format!(
        "no prompt is ready: {waiting} waiting on a dependency, {started} already started and \
         {blocked} blocked outside the roadmap"
    )
}

/// A ready prompt the advisor left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The prompt.
    pub id: u32,
    /// The inputs it needs and nobody supplied.
    pub missing: Vec<String>,
    /// A requested add-on this prompt cannot resolve; `missing` is empty when this is set.
    pub problem: Option<String>,
}

/// What the caller supplied and the row it named, the two sources `missing_inputs` checks before a prompt is handed over.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// Values given with `--set`.
    pub supplied: &'a BTreeMap<String, String>,
    /// The row named with `--row`, which may supply a matrix blank even when parked.
    pub named: Option<&'a MethodRow>,
}

impl<'a> Inputs<'a> {
    /// Inputs from explicit values and an optional named row.
    #[must_use]
    pub const fn new(supplied: &'a BTreeMap<String, String>, named: Option<&'a MethodRow>) -> Self {
        Self { supplied, named }
    }
}

/// The matrix and history readiness reads together.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The matrix rows a prompt can draw.
    pub state: &'a ProjectState,
    /// What this template has already been handed.
    pub ledger: &'a Ledger,
}

/// Ready prompts with every required input supplied; one with a hole or an unknown add-on is skipped, not handed over.
pub fn handable<'a>(
    library: &'a Library,
    effort: Option<Effort>,
    exclude: &[u32],
    requested_addons: &[String],
    inputs: Inputs<'_>,
    context: Context<'_>,
    allow_unfilled: bool,
) -> (Vec<&'a Prompt>, Vec<Skipped>) {
    let state = context.state;
    let ledger = context.ledger;
    let mut ready = Vec::new();
    let mut skipped = Vec::new();
    for index in ranked(library, effort) {
        let prompt = &library.prompts[index];
        if exclude.contains(&prompt.id) {
            continue;
        }
        if inputs
            .named
            .is_some_and(|row| !crate::expand::row_fits(row, prompt.targets))
        {
            continue;
        }
        let addons = match crate::render::resolve_addons(prompt, requested_addons) {
            Ok(addons) => addons,
            Err(problem) => {
                skipped.push(Skipped {
                    id: prompt.id,
                    missing: Vec::new(),
                    problem: Some(problem),
                });
                continue;
            }
        };
        let served = ledger.targets_for(prompt.id);
        if !allow_unfilled {
            let missing = missing_inputs(prompt, &addons, inputs, state, &served);
            if !missing.is_empty() {
                skipped.push(Skipped {
                    id: prompt.id,
                    missing,
                    problem: None,
                });
                continue;
            }
        }
        // A named row is explicit retry guidance; automatic readiness must have a row `next` can draw.
        if inputs.named.is_none()
            && prompt.targets.is_matrix()
            && crate::expand::next_target(
                prompt,
                state,
                &served,
                &addons,
                inputs.supplied,
                allow_unfilled,
            )
            .is_none()
        {
            continue;
        }
        ready.push(prompt);
    }
    (ready, skipped)
}

/// The inputs neither supplied nor already available from the row `next` would draw, or the pin file.
pub fn missing_inputs(
    prompt: &Prompt,
    addons: &[crate::markdown::Addon],
    inputs: Inputs<'_>,
    state: &ProjectState,
    served: &[String],
) -> Vec<String> {
    let fills = retry_row(prompt, state, served, inputs.named, addons, inputs.supplied)
        .map(|row| crate::expand::fill(prompt, row, &state.pins));
    let references = !state.references().is_empty();
    prompt
        .required_inputs_for(addons)
        .filter(|name| !inputs.supplied.contains_key(*name))
        .filter(|name| !(*name == "references" && references))
        .filter(|name| {
            !fills
                .as_ref()
                .is_some_and(|values| *name != "references" && values.contains_key(*name))
        })
        .map(str::to_owned)
        .collect()
}

/// The row a retry names: the asked-for row, else the next unserved drawable row, else a fallback to repeat.
pub fn retry_row<'a>(
    prompt: &Prompt,
    state: &'a ProjectState,
    served: &[String],
    named: Option<&'a MethodRow>,
    addons: &[crate::markdown::Addon],
    supplied: &BTreeMap<String, String>,
) -> Option<&'a MethodRow> {
    let candidates = state.candidates(prompt.targets);
    named
        .filter(|row| crate::expand::row_fits(row, prompt.targets))
        .or_else(|| {
            crate::expand::next_target(prompt, state, served, addons, supplied, false)
                .map(|(row, _)| row)
        })
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|row| row.gap.is_drawable() && !served.contains(&row.key()))
        })
        .or_else(|| {
            candidates.iter().copied().find(|row| {
                row.gap.is_drawable()
                    && crate::expand::fills_required(prompt, row, &state.pins, addons, supplied)
            })
        })
        .or_else(|| candidates.iter().copied().find(|row| row.gap.is_drawable()))
}

/// A prompt drawn from `candidates` at random by `**Random weight:**`, deterministic in `seed` so a draw reproduces.
pub fn rotate_among<'a>(candidates: &[&'a Prompt], seed: u64) -> Result<&'a Prompt, String> {
    let total: u64 = candidates
        .iter()
        .map(|prompt| u64::from(prompt.random_weight))
        .sum();
    if total == 0 {
        return Err(
            "every candidate carries `**Random weight:** 0`; raise one above 0 or the draw \
                    is decided before it starts"
                .to_owned(),
        );
    }
    let mut draw = split_mix(seed) % total;
    for prompt in candidates {
        let weight = u64::from(prompt.random_weight);
        if prompt.random_weight == 0 {
            continue;
        }
        if draw < weight {
            return Ok(prompt);
        }
        draw -= weight;
    }
    Err("the weighted draw ran past its total; that is a bug in the weights".to_owned())
}

/// A weighted random ready prompt skipping `exclude`, deterministic in `seed`, which is reported with the result.
pub fn rotate_index(
    library: &Library,
    effort: Option<Effort>,
    exclude: &[u32],
    seed: u64,
) -> Result<usize, String> {
    let candidates: Vec<usize> = ranked(library, effort)
        .into_iter()
        .filter(|&index| {
            let prompt = &library.prompts[index];
            prompt.random_weight > 0 && !exclude.contains(&prompt.id)
        })
        .collect();
    if candidates.is_empty() {
        return Err(
            "nothing to rotate between: every ready slice is either excluded or has \
                    `**Random weight:** 0`"
                .to_owned(),
        );
    }
    let total: u64 = candidates
        .iter()
        .map(|&index| u64::from(library.prompts[index].random_weight))
        .sum();
    let mut draw = split_mix(seed) % total;
    for &index in &candidates {
        let weight = u64::from(library.prompts[index].random_weight);
        if draw < weight {
            return Ok(index);
        }
        draw -= weight;
    }
    // Unreachable while the weights sum to the total; kept so an out-of-range index can never be silent.
    Ok(candidates[0])
}

/// `SplitMix64`'s finalizer: a seed mixed so consecutive seeds do not produce adjacent draws, which a plain multiply does.
fn split_mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The UTC timestamp shape `now_utc` emits; a framed record with anything else is corrupt history.
fn valid_at(at: &str) -> bool {
    let bytes = at.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let digits = [0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
        .iter()
        .all(|range| bytes[range.clone()].iter().all(u8::is_ascii_digit));
    if !digits {
        return false;
    }
    let number = |range: std::ops::Range<usize>| at[range].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// A `how` field the framed form can carry without changing the record's meaning.
fn valid_how(how: &str) -> bool {
    !how.trim().is_empty()
        && !how.contains('\n')
        && !how.contains('\r')
        && !how.contains(" t=")
        && !how.contains('\u{1e}')
}

/// A matrix key the framed form can carry: a section letter and a numeric id, so `garbage` cannot suppress a real row.
fn valid_target(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(section) = chars.next() else {
        return false;
    };
    section.is_ascii_uppercase()
        && chars.next().is_some_and(|first| first.is_ascii_digit())
        && chars.all(|character| character.is_ascii_alphanumeric())
}

/// One recorded handout: when, which slice, how it was asked for, and the matrix row it was served against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// UTC, second resolution.
    pub at: String,
    /// The prompt that was handed out.
    pub id: u32,
    /// `next`, `render`, `next --rotate`.
    pub how: String,
    /// The matrix target key (`A13`) this handout pointed at; `None` for a hand-written slice.
    pub target: Option<String>,
}

/// The log of what has been handed out on this machine.
#[derive(Debug, Default)]
pub struct Ledger {
    /// Where it is written.
    pub path: PathBuf,
    /// Everything it could read.
    pub entries: Vec<Entry>,
    /// Non-entry lines, counted so a truncated or hand-edited log is visible rather than silently shortening suppression.
    pub skipped: usize,
    /// A ledger that exists but could not be read; unlike a missing file, this is not an empty history.
    pub read_error: Option<String>,
}

impl Ledger {
    /// Where the ledger lives, given the workspace root.
    pub fn path_for(root: &Path) -> PathBuf {
        root.join(crate::LEDGER_RELATIVE)
    }

    /// Read a ledger; a missing file is an empty one, not an error — the first run has no history.
    pub fn load(path: PathBuf) -> Self {
        let mut ledger = Self {
            path,
            ..Self::default()
        };
        let bytes = match std::fs::read(&ledger.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return ledger,
            Err(error) => {
                ledger.read_error = Some(format!(
                    "could not read the ledger {}: {error}",
                    ledger.path.display()
                ));
                return ledger;
            }
        };
        for bytes in bytes.split(|byte| *byte == b'\n') {
            let Ok(line) = std::str::from_utf8(bytes) else {
                ledger.skipped += 1;
                continue;
            };
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            let framed = line.starts_with('\u{1e}');
            let line = match line.strip_prefix('\u{1e}') {
                Some(rest) => {
                    let Some(body) = rest.strip_suffix('\u{1e}') else {
                        ledger.skipped += 1;
                        continue;
                    };
                    body
                }
                None => line,
            };
            if line.contains('\u{1e}') {
                ledger.skipped += 1;
                continue;
            }
            let mut fields = line.splitn(3, ' ');
            let (Some(at), Some(id)) = (fields.next(), fields.next()) else {
                ledger.skipped += 1;
                continue;
            };
            let Some(rest) = fields.next() else {
                ledger.skipped += 1;
                continue;
            };
            // `how` may hold spaces (`next --rotate`); only a trailing ` t=` starts the matrix target.
            let (how, target) = match rest.rsplit_once(" t=") {
                Some((how, target)) => (how, Some(target.to_owned())),
                None => (rest, None),
            };
            let parsed = id
                .strip_prefix('P')
                .or_else(|| id.strip_prefix('p'))
                .and_then(|rest| rest.parse::<u32>().ok());
            let valid = target.as_deref().is_none_or(valid_target)
                && (!framed || (valid_at(at) && valid_how(how)));
            match (parsed, valid) {
                (Some(id), true) => ledger.entries.push(Entry {
                    at: at.to_owned(),
                    id,
                    how: how.to_owned(),
                    target,
                }),
                _ => ledger.skipped += 1,
            }
        }
        ledger
    }

    /// Append one handout; a ledger that cannot be written is worth a warning, not a lost prompt.
    pub fn record(&mut self, id: u32, how: &str, target: Option<&str>) -> std::io::Result<()> {
        let invalid = |field: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, field);
        if !valid_how(how) {
            return Err(invalid(
                "`how` must be non-empty and free of a line break, ` t=` and the frame delimiter",
            ));
        }
        if let Some(key) = target
            && !valid_target(key)
        {
            return Err(invalid(
                "a target key must be a section letter and a numeric id, like A13",
            ));
        }
        let entry = Entry {
            at: now_utc(),
            id,
            how: how.to_owned(),
            target: target.map(str::to_owned),
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = match &entry.target {
            Some(key) => format!(
                "\u{1e}{} P{} {} t={key}\u{1e}\n",
                entry.at, entry.id, entry.how
            ),
            None => format!("\u{1e}{} P{} {}\u{1e}\n", entry.at, entry.id, entry.how),
        };
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)?;
        let len = file.metadata()?.len();
        let appended = (|| {
            if len != 0 {
                file.seek(SeekFrom::End(-1))?;
                let mut last = [0u8; 1];
                file.read_exact(&mut last)?;
                if last[0] != b'\n' {
                    file.write_all(b"\n")?;
                }
            }
            file.write_all(line.as_bytes())
        })();
        if let Err(error) = appended {
            return Err(match file.set_len(len) {
                Ok(()) => error,
                Err(_) => std::io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; could not remove the partial frame from {} at byte {len}",
                        self.path.display()
                    ),
                ),
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Keys already served to this template, oldest first, so `next` advances to the next unclaimed row instead of repeating.
    pub fn targets_for(&self, id: u32) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.id == id)
            .filter_map(|entry| entry.target.clone())
            .collect()
    }

    /// The most recent `window` distinct prompt ids, newest first.
    pub fn recent_ids(&self, window: usize) -> Vec<u32> {
        let mut seen: Vec<u32> = Vec::new();
        for entry in self.entries.iter().rev() {
            if seen.len() >= window {
                break;
            }
            if !seen.contains(&entry.id) {
                seen.push(entry.id);
            }
        }
        seen
    }

    /// When a prompt was last handed out, and how often in total.
    pub fn history(&self, id: u32) -> Option<(String, usize)> {
        let last = self
            .entries
            .iter()
            .rev()
            .find(|entry| entry.id == id)
            .map(|entry| entry.at.clone())?;
        let times = self.entries.iter().filter(|entry| entry.id == id).count();
        Some((last, times))
    }
}

/// UTC now as `YYYY-MM-DDTHH:MM:SSZ` — four lines of arithmetic here rather than a dependency, this crate having none.
pub fn now_utc() -> String {
    // Saturating seconds: a wrapped timestamp in a ledger is worse than a clamped one.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant's `civil_from_days`: exact over the whole `i64` day range, no lookup table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;
    use crate::state::Gap;

    /// A directory of its own under the system temp dir, removed when the test ends.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ferrox-prompt-ledger-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("scratch");
            Self(path)
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    fn row(index: &str, state: &str) -> MethodRow {
        MethodRow {
            section: 'A',
            index: index.to_owned(),
            method: "m".to_owned(),
            state: state.to_owned(),
            implemented: false,
            gap: Gap::Planned,
            high_priority: false,
            page: "docs/function/m.md".to_owned(),
            real_page: false,
            text: "m".to_owned(),
        }
    }

    /// P1 done; P2, P3, P4 ready; P5 waiting on P3; P6 deferred.
    fn library() -> Library {
        Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Done

**When to use:** past
**Status:** done
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
b
```

## P2 · Big leverage

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```

## P3 · Small leverage

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 3

```text
b
```

## P4 · Waiter

**When to use:** now
**Status:** todo
**Leverage:** 4
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Depends on:** P3
**Random weight:** 1

```text
b
```

## P5 · Started

**When to use:** now
**Status:** doing
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 9

```text
b
```
",
        )
    }

    fn ids(library: &Library, indices: &[usize]) -> Vec<u32> {
        indices
            .iter()
            .map(|&index| library.prompts[index].id)
            .collect()
    }

    #[test]
    fn readiness_follows_status_and_dependencies() {
        let library = library();
        let by_id = |id: u32| readiness(&library, library.prompt(id).unwrap());
        assert_eq!(by_id(1), Readiness::Finished);
        assert_eq!(by_id(2), Readiness::Ready);
        assert_eq!(by_id(3), Readiness::Ready);
        assert_eq!(by_id(4), Readiness::WaitingOn(vec![3]));
        assert_eq!(by_id(5), Readiness::Deferred);
    }

    #[test]
    fn ranking_is_leverage_then_the_smaller_slice_then_the_id() {
        let library = library();
        // P2 (5) beats P3 (3); P4 is blocked and P5 is `doing`, so neither is ranked however much leverage it claims.
        assert_eq!(ids(&library, &ranked(&library, None)), vec![2, 3]);
    }

    #[test]
    fn an_effort_filter_is_honoured_before_ranking() {
        let library = library();
        assert_eq!(
            ids(&library, &ranked(&library, Some(Effort::Small))),
            vec![3]
        );
        assert_eq!(ranked(&library, Some(Effort::Medium)), []);
    }

    #[test]
    fn the_next_index_skips_what_was_already_handed_out() {
        let library = library();
        assert_eq!(next_index(&library, None, &[]).unwrap(), 1);
        assert_eq!(next_index(&library, None, &[2]).unwrap(), 2);
        let error = next_index(&library, None, &[2, 3]).unwrap_err();
        assert!(error.contains("P2, P3"), "{error}");
        assert!(error.contains("--rotate"), "{error}");
    }

    #[test]
    fn an_empty_ready_set_names_whether_work_is_started_blocked_or_finished() {
        let started = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Started\n\n**When to use:** now\n\
             **Status:** doing\n**Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n\n```text\nb\n```\n",
        );
        let error = next_index(&started, None, &[]).unwrap_err();
        assert!(error.contains("already started"), "{error}");
        assert!(!error.contains("waiting on a dependency"), "{error}");

        let blocked = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Blocked\n\n**When to use:** now\n\
             **Status:** todo\n**Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n**Depends on:** P9\n\n```text\nb\n```\n",
        );
        let error = next_index(&blocked, None, &[]).unwrap_err();
        assert!(error.contains("waiting on a dependency"), "{error}");

        let done = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Done\n\n**When to use:** now\n\
             **Status:** done\n**Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n\n```text\nb\n```\n",
        );
        let blocked = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Blocked\n\n**When to use:** now\n\
             **Status:** blocked\n**Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n\n```text\nb\n```\n",
        );
        let error = next_index(&blocked, None, &[]).unwrap_err();
        assert!(
            error.contains("blocked on something outside the roadmap"),
            "{error}"
        );
        assert!(!error.contains("already started"), "{error}");

        let error = next_index(&done, None, &[]).unwrap_err();
        assert!(error.contains("nothing left"), "{error}");
    }

    #[test]
    fn an_empty_state_cell_does_not_fill_a_required_state() {
        let library = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Open row\n\n**When to use:** now\n\
             **Status:** todo\n**Leverage:** 1\n**Effort:** small\n**Targets:** open\n\
             **Gates:** `cargo test`\n\n```text\nship {state}\n```\n",
        );
        let prompt = library.prompt(1).unwrap();
        let empty = ProjectState {
            methods: vec![row("1", "")],
            pins: Vec::new(),
        };
        let supplied = BTreeMap::new();
        assert_eq!(
            missing_inputs(prompt, &[], Inputs::new(&supplied, None), &empty, &[]),
            ["state"]
        );
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&supplied, None),
            Context {
                state: &empty,
                ledger: &Ledger::default(),
            },
            false,
        );
        assert!(ready.is_empty(), "{ready:?}");
        assert_eq!(skipped[0].missing, ["state"]);

        let filled = ProjectState {
            methods: vec![row("1", "planned")],
            pins: Vec::new(),
        };
        assert_eq!(
            missing_inputs(prompt, &[], Inputs::new(&supplied, None), &filled, &[]),
            Vec::<String>::new()
        );

        let mixed = ProjectState {
            methods: vec![row("1", ""), row("2", "planned")],
            pins: Vec::new(),
        };
        assert_eq!(
            missing_inputs(prompt, &[], Inputs::new(&supplied, None), &mixed, &[]),
            Vec::<String>::new()
        );
        let (target, _) =
            crate::expand::next_target(prompt, &mixed, &[], &[], &BTreeMap::new(), false)
                .expect("a usable row");
        assert_eq!(target.state, "planned");

        let served_usable = ProjectState {
            methods: vec![row("1", "planned"), row("2", "")],
            pins: Vec::new(),
        };
        assert_eq!(
            missing_inputs(
                prompt,
                &[],
                Inputs::new(&supplied, None),
                &served_usable,
                &["A1".to_owned()]
            ),
            ["state"]
        );

        let served_empty = ProjectState {
            methods: vec![row("1", ""), row("2", "planned")],
            pins: Vec::new(),
        };
        assert_eq!(
            missing_inputs(
                prompt,
                &[],
                Inputs::new(&supplied, None),
                &served_empty,
                &["A1".to_owned()]
            ),
            Vec::<String>::new()
        );

        let supplied_state = BTreeMap::from([("state".to_owned(), "planned".to_owned())]);
        assert_eq!(
            missing_inputs(prompt, &[], Inputs::new(&supplied_state, None), &empty, &[]),
            Vec::<String>::new()
        );
        let (target, _) =
            crate::expand::next_target(prompt, &empty, &[], &[], &supplied_state, false)
                .expect("a supplied input makes the row eligible");
        assert_eq!(target.state, "");
    }

    #[test]
    fn a_served_only_row_does_not_make_a_prompt_handable() {
        let library = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Open row\n\n**When to use:** now\n\
             **Status:** todo\n**Leverage:** 1\n**Effort:** small\n**Targets:** open\n\
             **Gates:** `cargo test`\n\n```text\nship {state}\n```\n",
        );
        let supplied = BTreeMap::new();
        let only_served = ProjectState {
            methods: vec![row("1", "planned")],
            pins: Vec::new(),
        };
        let served_ledger = Ledger {
            entries: vec![Entry {
                at: "2026-10-02T00:00:00Z".to_owned(),
                id: 1,
                how: "next".to_owned(),
                target: Some("A1".to_owned()),
            }],
            ..Ledger::default()
        };
        let (ready, _) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&supplied, None),
            Context {
                state: &only_served,
                ledger: &served_ledger,
            },
            false,
        );
        assert!(ready.is_empty(), "{ready:?}");
    }

    #[test]
    fn a_selected_addon_gates_row_eligibility() {
        let library = load(
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Open row\n\n**When to use:** now\n\
             **Status:** todo\n**Leverage:** 1\n**Effort:** small\n**Targets:** open\n\
             **Gates:** `cargo test`\n\n```text\nship {method}\n```\n\n\
             **Add-on — Needs state:** {state}\n",
        );
        let prompt = library.prompt(1).unwrap();
        let state = ProjectState {
            methods: vec![row("1", ""), row("2", "planned")],
            pins: Vec::new(),
        };
        let supplied = BTreeMap::new();
        let (without, _) = crate::expand::next_target(prompt, &state, &[], &[], &supplied, false)
            .expect("the base body only needs the method");
        assert_eq!(without.index, "1");
        let (with, _) =
            crate::expand::next_target(prompt, &state, &[], &prompt.addons, &supplied, false)
                .expect("the second row supplies the add-on state");
        assert_eq!(with.index, "2");
    }

    #[test]
    fn rotation_is_deterministic_for_a_seed_and_respects_weights() {
        let library = library();
        // P2 has weight 0, so rotation never draws it even though it tops the ranking.
        for seed in 0..40 {
            let index = rotate_index(&library, None, &[], seed).unwrap();
            assert_eq!(library.prompts[index].id, 3);
        }
        assert_eq!(
            rotate_index(&library, None, &[], 7).unwrap(),
            rotate_index(&library, None, &[], 7).unwrap()
        );
    }

    #[test]
    fn a_prompt_missing_an_input_is_left_out_rather_than_handed_over() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Needs a decision

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
run it with {scope}
```

## P2 · Ready

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
run it
```
",
        );
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&BTreeMap::new(), None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert_eq!(
            ready.iter().map(|prompt| prompt.id).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            skipped,
            vec![Skipped {
                id: 1,
                missing: vec!["scope".to_owned()],
                problem: None
            }]
        );
        // With the value supplied it becomes the top pick again.
        let supplied = BTreeMap::from([("scope".to_owned(), "crates/**".to_owned())]);
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&supplied, None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert_eq!(
            ready.iter().map(|prompt| prompt.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(skipped, Vec::<Skipped>::new());
        // And with `--allow-unfilled` it was never skipped at all.
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&BTreeMap::new(), None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            true,
        );
        assert_eq!(ready.len(), 2);
        assert_eq!(skipped, Vec::<Skipped>::new());
    }

    #[test]
    fn a_named_row_does_not_skip_unrelated_templates() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Fixed issue

**When to use:** a regression
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
fix {issue}
```

## P2 · Open row

**When to use:** an open row
**Status:** todo
**Leverage:** 4
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship it
```
",
        );
        let row = row("13", "planned");
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&BTreeMap::new(), Some(&row)),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert_eq!(
            ready.iter().map(|prompt| prompt.id).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(skipped, Vec::<Skipped>::new());
    }

    #[test]
    fn an_unselected_addon_does_not_gate_readiness() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Add-on work

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
run {core}
```

**Add-on — Extra:** needs {extra}
",
        );
        let supplied = BTreeMap::from([("core".to_owned(), "x".to_owned())]);
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&supplied, None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert_eq!(ready.len(), 1);
        assert_eq!(skipped, Vec::<Skipped>::new());
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &["extra".to_owned()],
            Inputs::new(&supplied, None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert_eq!(ready.len(), 0);
        assert_eq!(skipped[0].missing, vec!["extra".to_owned()]);
    }

    #[test]
    fn an_unknown_addon_is_not_handed_over_just_to_fail_in_render() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Add-on work

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
run {core}
```

**Add-on — Extra:** needs {extra}
",
        );
        let (ready, skipped) = handable(
            &library,
            None,
            &[],
            &["nope".to_owned()],
            Inputs::new(&BTreeMap::new(), None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        assert!(ready.is_empty());
        assert_eq!(skipped.len(), 1);
        let problem = skipped[0].problem.as_deref().expect("the add-on error");
        assert!(problem.contains("no add-on matching `nope`"), "{problem}");
        let error = crate::render::resolve_addons(library.prompt(1).unwrap(), &["nope".to_owned()])
            .unwrap_err();
        assert!(error.contains("no add-on matching `nope`"), "{error}");
    }

    #[test]
    fn a_rotation_only_draws_from_what_is_handable() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Zero weight

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```

## P2 · Drawn

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 3

```text
b
```
",
        );
        let (ready, _) = handable(
            &library,
            None,
            &[],
            &[],
            Inputs::new(&BTreeMap::new(), None),
            Context {
                state: &ProjectState::default(),
                ledger: &Ledger::default(),
            },
            false,
        );
        for seed in 0..30 {
            assert_eq!(rotate_among(&ready, seed).unwrap().id, 2);
        }
        let none = [library.prompt(1).unwrap()];
        assert!(rotate_among(&none, 1).unwrap_err().contains("weight"));
    }

    #[test]
    fn a_rotation_with_nothing_left_says_what_to_do() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Only

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```
",
        );
        let error = rotate_index(&library, None, &[], 1).unwrap_err();
        assert!(error.contains("Random weight"), "{error}");
    }

    #[test]
    fn the_ledger_remembers_and_suppresses() {
        let scratch = Scratch::new("memory");
        let path = scratch.path("ledger.log");
        let mut ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries, []);
        ledger.record(2, "next", None).unwrap();
        ledger.record(3, "next", Some("A13")).unwrap();
        ledger.record(2, "render", None).unwrap();
        assert_eq!(ledger.recent_ids(2), vec![2, 3]);
        assert_eq!(ledger.targets_for(3), vec!["A13"]);
        assert_eq!(ledger.targets_for(2), Vec::<String>::new());
        let (at, times) = ledger.history(2).unwrap();
        assert_eq!(times, 2);
        assert_eq!(at.len(), 20, "{at}");
        assert_eq!(ledger.history(9), None);
        let reread = Ledger::load(path.clone());
        assert_eq!(reread.entries.len(), 3);
        assert_eq!(reread.skipped, 0);
        assert!(reread.read_error.is_none());
        assert_eq!(reread.targets_for(3), vec!["A13"]);
        drop(ledger);
        drop(reread);
    }

    #[test]
    fn an_unterminated_ledger_is_not_joined_by_the_next_record() {
        let scratch = Scratch::new("open");
        let path = scratch.path("ledger.log");
        std::fs::write(&path, "2026-10-02T00:00:00Z P2 next").unwrap();
        let mut ledger = Ledger::load(path.clone());
        ledger.record(3, "next", Some("A13")).unwrap();
        let reread = Ledger::load(path.clone());
        assert_eq!(reread.entries.len(), 2);
        assert_eq!(reread.skipped, 0);
        assert_eq!(reread.targets_for(2), Vec::<String>::new());
        assert_eq!(reread.targets_for(3), vec!["A13"]);
    }

    #[test]
    fn a_corrupt_ledger_line_is_counted_not_obeyed() {
        let scratch = Scratch::new("bad");
        let path = scratch.path("ledger.log");
        std::fs::write(
            &path,
            "2026-10-02T00:00:00Z P2 next\nnonsense\n\n2026-10-02T00:00:01Z Pthree render\n",
        )
        .unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.skipped, 2);
    }

    #[test]
    fn the_ledger_keeps_the_whole_how_field() {
        let scratch = Scratch::new("how");
        let path = scratch.path("ledger.log");
        let mut ledger = Ledger::load(path.clone());
        ledger.record(2, "next --rotate", Some("A13")).unwrap();
        ledger.record(3, "render --row", None).unwrap();
        let reread = Ledger::load(path.clone());
        assert_eq!(reread.entries[0].how, "next --rotate");
        assert_eq!(reread.entries[1].how, "render --row");
        assert_eq!(reread.targets_for(2), vec!["A13"]);
    }

    #[test]
    fn a_new_record_is_framed_and_a_truncated_frame_is_not_trusted() {
        let scratch = Scratch::new("frame");
        let path = scratch.path("ledger.log");
        let mut ledger = Ledger::load(path.clone());
        ledger.record(3, "next --rotate", Some("A13")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with('\u{1e}') && text.contains("\u{1e}\n"),
            "{text:?}"
        );

        std::fs::write(&path, format!("{text}\u{1e}2026-10-02T00:00:02Z P4 render")).unwrap();
        let reread = Ledger::load(path.clone());
        assert_eq!(reread.entries.len(), 1);
        assert_eq!(reread.skipped, 1);
    }

    #[test]
    fn a_framed_record_with_an_invalid_timestamp_is_not_history() {
        let scratch = Scratch::new("bad-time");
        let path = scratch.path("ledger.log");
        std::fs::write(
            &path,
            "\u{1e}not-a-time P2 next\u{1e}\n\
             \u{1e}2026-13-02T00:00:00Z P2 next\u{1e}\n\
             \u{1e}2026-10-02T24:00:00Z P2 next\u{1e}\n",
        )
        .unwrap();
        let ledger = Ledger::load(path);
        assert_eq!(ledger.entries, Vec::<Entry>::new());
        assert_eq!(ledger.skipped, 3);
    }

    #[test]
    fn a_framed_record_with_an_empty_target_is_not_history() {
        let scratch = Scratch::new("empty-target");
        let path = scratch.path("ledger.log");
        std::fs::write(&path, "\u{1e}2026-10-02T00:00:00Z P2 next t=\u{1e}\n").unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries, Vec::<Entry>::new());
        assert_eq!(ledger.skipped, 1);
    }

    #[test]
    fn a_framed_record_with_a_whitespace_action_is_not_history() {
        let scratch = Scratch::new("blank-how");
        let path = scratch.path("ledger.log");
        std::fs::write(&path, "\u{1e}2026-10-02T00:00:00Z P2   \u{1e}\n").unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries, Vec::<Entry>::new());
        assert_eq!(ledger.skipped, 1);
    }

    #[test]
    fn a_framed_target_must_be_a_matrix_key() {
        let scratch = Scratch::new("bad-target");
        let path = scratch.path("ledger.log");
        std::fs::write(
            &path,
            "\u{1e}2026-10-02T00:00:00Z P2 next t=garbage\u{1e}\n\
             \u{1e}2026-10-02T00:00:01Z P2 next t=A61b\u{1e}\n\
             \u{1e}2026-10-02T00:00:02Z P2 next t=A\u{1e}\n\
             \u{1e}2026-10-02T00:00:03Z P2 next t=13A\u{1e}\n",
        )
        .unwrap();
        let ledger = Ledger::load(path);
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].target.as_deref(), Some("A61b"));
        assert_eq!(ledger.skipped, 3);
    }

    #[test]
    fn an_unframed_record_with_an_empty_target_is_not_history() {
        let scratch = Scratch::new("legacy-empty-target");
        let path = scratch.path("ledger.log");
        std::fs::write(&path, "2026-10-02T00:00:00Z P2 next t=\n").unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries, Vec::<Entry>::new());
        assert_eq!(ledger.skipped, 1);
    }

    #[test]
    fn a_field_that_would_break_the_frame_is_refused() {
        let scratch = Scratch::new("fields");
        let path = scratch.path("ledger.log");
        let mut ledger = Ledger::load(path.clone());
        assert!(ledger.record(2, "next\nP3 render", None).is_err());
        assert!(ledger.record(2, "next\u{1e}P3 render", None).is_err());
        assert!(ledger.record(2, "next t=P3", None).is_err());
        assert!(ledger.record(2, "   ", None).is_err());
        assert!(ledger.record(2, "next", Some("A13\nP3")).is_err());
        assert!(ledger.record(2, "next", Some("A 13")).is_err());
        assert!(ledger.record(2, "next", Some("garbage")).is_err());
        assert!(ledger.record(2, "next", Some("A61b")).is_ok());
    }

    #[test]
    fn an_unreadable_ledger_is_an_error_and_a_bad_line_is_counted() {
        let scratch = Scratch::new("unreadable");
        let dir = scratch.path("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let blocked = Ledger::load(dir.clone());
        assert!(blocked.read_error.is_some(), "a directory is not history");

        let path = scratch.path("utf8.log");
        std::fs::write(
            &path,
            b"2026-10-02T00:00:00Z P2 next\n\xff\n2026-10-02T00:00:01Z P3 next --rotate\n",
        )
        .unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.skipped, 1);
        assert!(ledger.read_error.is_none());
        assert_eq!(ledger.entries[1].how, "next --rotate");
    }

    #[test]
    fn dates_are_exact_at_the_edges() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(20_728), (2026, 10, 2));
        // A leap day, and the day after it.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }

    #[test]
    fn the_clock_is_shaped_like_an_iso_timestamp() {
        let now = now_utc();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[10..11], "T");
    }
}
