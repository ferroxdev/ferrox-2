//! `ferrox-prompt` — the command line: exit 1 is a library not telling the truth, exit 2 a mistake at the keyboard.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferrox_prompt::advisor::{self, Ledger, Readiness};
use ferrox_prompt::check;
use ferrox_prompt::expand::{self, ProjectState};
use ferrox_prompt::json::Value;
use ferrox_prompt::markdown::{
    closes_fence, opens_fence, Addon, Diagnostic, Effort, Library, Prompt, Severity, Status,
    Targets, Touch,
};
use ferrox_prompt::render::{self, Options, Rendered};
use ferrox_prompt::state::{Gap, MethodRow};
use ferrox_prompt::worktree::Worktree;
use ferrox_prompt::{
    clipboard, load_library, path_tag, workspace_root, LEDGER_RELATIVE, LIBRARY_RELATIVE,
};

const USAGE: &str = "\
ferrox-prompt — render the slice to work on next, from a Markdown library

USAGE
    ferrox-prompt <command> [options]

COMMANDS
    check                  read the library and report everything wrong with it
    list                   roadmap progress: templates, matrix rows left, what is next
    next                   the slice to work on, its blanks filled from the matrix
    render <id>            that slice's prompt, with add-ons and gates
    issue <number>         the P0/P1 regression-issue prompt, filled and copied
    show <id>              that slice's metadata, then its full prompt
    rows                   the matrix rows a slice can be about
    set-status <id> <status>  record progress: todo, doing, done or blocked

OPTIONS
    --library <path>       read this Markdown instead of prompts.md
    --set KEY=VALUE        fill a placeholder; repeatable, wins over a default
    --issue <number>       fill the issue template's number, as `issue <number>` does
    --row <key|index|name> the matrix row this slice is about: A13, 13, or part of a name
    --addon <slug|all>     append an add-on; repeatable or comma-separated
    --print                print instead of copying to the clipboard
    --json                 machine-readable output (list, next, render, show, rows)
    --status <status>      list only these: todo, doing, done, blocked
    --effort <effort>      restrict to small, medium or large
    --id <id>              ask for a specific slice from `next`
    --rotate               draw at random among ready slices, weighted by the library
    --seed <n>             make that draw reproducible
    --memory <n>           how many recent slices to keep out of the draw (default 3)
    --no-ledger            do not record the handout in .ferrox/slices.log
    --allow-unfilled       render even when a required input has no value
    --strict               `check` treats warnings as errors
    --version, --help

EXAMPLES
    ferrox-prompt next
    ferrox-prompt next --rotate --seed 4
    ferrox-prompt issue 661
    ferrox-prompt render 5 --addon isa-matrix
    ferrox-prompt render 1 --row A13
    ferrox-prompt next --row quic
    ferrox-prompt rows --row quic
    ferrox-prompt set-status 5 doing
    ferrox-prompt list --status todo
    ferrox-prompt check --library /tmp/draft-prompts.md

A prompt with a required input is never rendered with a hole in it: the tool
prints the command that would fill it instead. Every handout is recorded in
.ferrox/slices.log so the next few calls do not offer the same slice twice.
Every handout also names the worktree the slice runs in and what to do about it:
created with `scripts/new-worktree.sh` when there is none, used and brought onto
`main` when that script has made one for this task already.

`next` reads the matrix's state cells: a partially carried row outranks a
greenfield plan, a high-priority row outranks its unmarked peers, and a
`not-scheduled` row is never drawn unless `--row` names it.

`issue <number>` fills the one template that asks for `{issue}` — the P0/P1
regression template — names its worktree `bugfix-<number>`, and copies the
completed prompt. `--issue` fills the same blank wherever `{issue}` appears.

`--row` names the matrix row a slice is about, so a template and a row can be
picked by hand: `render 1 --row A13` renders P1 for that row, and
`next --row A13` picks the template that draws it. A row is named by its key
(`A13`), its number (`13`) or part of its method name (`quic`); `rows` lists the
matrix so a key can be found.
";

/// What to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// The gate `ci.yml` runs.
    Check,
    /// The roadmap.
    List,
    /// The advisor.
    Next,
    /// One prompt.
    Render,
    /// The regression-issue prompt, filled from a number.
    Issue,
    /// One prompt's metadata.
    Show,
    /// The matrix rows a slice can be about.
    Rows,
    /// Record a prompt's status: the only field progress edits.
    SetStatus,
    /// Usage.
    Help,
    /// Version.
    Version,
}

/// Where the answer goes; one setting, not two booleans, because `--print --json` is one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    /// The clipboard, the default: the next thing to happen to a prompt is a paste.
    Copy,
    /// Standard output.
    Print,
    /// Standard output, as JSON.
    Json,
}

impl Output {
    /// Whether the text goes to standard output rather than the clipboard.
    fn is_stdout(self) -> bool {
        matches!(self, Self::Print | Self::Json)
    }
}

/// How `next` chooses, when it is not asked for a slice by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Draw {
    /// The highest leverage, then the smaller slice.
    Ranked,
    /// At random among ready slices, weighted by the library.
    Rotate,
}

/// Everything the command line said.
#[derive(Debug, Clone)]
struct Args {
    command: Command,
    /// A prompt id, for `render` and `show`.
    id: Option<u32>,
    /// The GitHub issue a regression template fixes.
    issue: Option<u64>,
    library: Option<PathBuf>,
    output: Output,
    draw: Draw,
    /// Whether a handout is recorded in the ledger.
    record: bool,
    /// Whether a prompt with unfilled inputs may be rendered anyway.
    allow_unfilled: bool,
    /// Whether `check` counts warnings as errors.
    strict: bool,
    status: Option<Status>,
    effort: Option<Effort>,
    /// `--id <id>` on `next`: a deliberate choice instead of a ranked one.
    forced: Option<u32>,
    /// `--row <key|index|name>`: the matrix row a slice is about.
    row: Option<String>,
    /// The value `set-status` writes.
    set_to: Option<Status>,
    seed: u64,
    memory: usize,
    values: BTreeMap<String, String>,
    addons: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            command: Command::Help,
            id: None,
            issue: None,
            library: None,
            output: Output::Copy,
            draw: Draw::Ranked,
            record: true,
            allow_unfilled: false,
            strict: false,
            status: None,
            effort: None,
            forced: None,
            row: None,
            set_to: None,
            seed: 1,
            memory: 3,
            values: BTreeMap::new(),
            addons: Vec::new(),
        }
    }
}

fn main() -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&arguments) {
        Ok(args) => args,
        Err(message) => {
            // Print the parse error alone; the whole usage block on every typo would bury it.
            eprintln!("{message}");
            eprintln!("run `ferrox-prompt --help` for the commands");
            return ExitCode::from(2);
        }
    };
    match args.command {
        Command::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("ferrox-prompt {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Check => run_check(&args, &cwd),
        command => {
            let library = match load_library(args.library.as_deref(), &cwd) {
                Ok(library) => library,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            // Parse errors block every verb: a malformed section renders a prompt that looks complete.
            if library.has_errors() {
                eprintln!(
                    "{}: {} error(s) must be fixed first",
                    library.path.display(),
                    library.errors().count()
                );
                for finding in library.errors() {
                    eprintln!("  {}: {finding}", library.path.display());
                }
                return ExitCode::from(1);
            }
            for finding in library
                .diagnostics
                .iter()
                .filter(|finding| finding.severity == Severity::Warning)
            {
                eprintln!("warning: {}: {finding}", library.path.display());
            }
            let root = workspace_root_for(&args, &cwd);
            match command {
                Command::List => run_list(&args, &library, &root),
                Command::Next => run_next(&args, &library, &root),
                Command::Render => run_render(&args, &library, &root),
                Command::Issue => run_issue(&args, &library, &root),
                Command::Show => run_show(&args, &library, &root),
                Command::Rows => run_rows(&args, &library, &root),
                Command::SetStatus => run_set_status(&args, &library, &root),
                Command::Check | Command::Help | Command::Version => ExitCode::SUCCESS,
            }
        }
    }
}

/// Read the command line, written out rather than a crate: this crate's zero dependencies are a decision.
fn parse(arguments: &[String]) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut positional: Vec<String> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].clone();
        index += 1;
        // Both `--flag=value` and `--flag value` parse; the long way is not a reason to be unhelpful.
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with('-') => {
                (flag.to_owned(), Some(value.to_owned()))
            }
            _ => (argument.clone(), None),
        };
        let borrowed = inline.as_deref();
        let text = |at: &mut usize| take_value(arguments, at, borrowed, &flag);
        match flag.as_str() {
            verb @ ("check" | "list" | "ls" | "next" | "render" | "show" | "rows" | "issue"
            | "bug" | "set-status") => {
                parsed.command = verb_of(verb);
            }
            "help" | "-h" | "--help" => parsed.command = Command::Help,
            "version" | "-V" | "--version" => parsed.command = Command::Version,
            "--library" | "-L" => parsed.library = Some(PathBuf::from(text(&mut index)?)),
            "--prompt" | "-p" => {
                if parsed.id.is_some() {
                    return Err("prompt id given twice".to_owned());
                }
                parsed.id = Some(parse_id(&text(&mut index)?)?);
            }
            "--id" => parsed.forced = Some(parse_id(&text(&mut index)?)?),
            "--issue" => {
                if parsed.issue.is_some() {
                    return Err("issue number given twice".to_owned());
                }
                parsed.issue = Some(parse_issue(&text(&mut index)?)?);
            }
            "--row" | "-r" => parsed.row = Some(text(&mut index)?),
            "--set" => assign(&mut parsed.values, &text(&mut index)?)?,
            "--addon" => parsed.addons.push(text(&mut index)?),
            "--print" => {
                if parsed.output != Output::Json {
                    parsed.output = Output::Print;
                }
            }
            // JSON wins over `--print` rather than fighting it: both mean stdout.
            "--json" => parsed.output = Output::Json,
            "--rotate" => parsed.draw = Draw::Rotate,
            "--no-ledger" => parsed.record = false,
            "--allow-unfilled" => parsed.allow_unfilled = true,
            "--strict" => parsed.strict = true,
            "--seed" => {
                parsed.seed = text(&mut index)?
                    .parse()
                    .map_err(|_| "--seed needs a whole number".to_owned())?;
            }
            "--memory" => {
                parsed.memory = text(&mut index)?
                    .parse()
                    .map_err(|_| "--memory needs a whole number".to_owned())?;
            }
            "--status" => {
                let status = text(&mut index)?;
                parsed.status = Some(Status::parse(&status).ok_or_else(|| {
                    format!("`{status}` is not a status: {}", Status::NAMES.join(", "))
                })?);
            }
            "--effort" => {
                let effort = text(&mut index)?;
                parsed.effort = Some(Effort::parse(&effort).ok_or_else(|| {
                    format!("`{effort}` is not an effort: {}", Effort::NAMES.join(", "))
                })?);
            }
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            _ => positional.push(argument),
        }
    }
    parse_positional(&mut parsed, positional)?;
    Ok(parsed)
}

/// The words after the flags: one prompt id for `render`/`show`, one status for `set-status`, one number for `issue`.
fn parse_positional(parsed: &mut Args, mut positional: Vec<String>) -> Result<(), String> {
    if parsed.command == Command::Next && parsed.id.is_some() {
        return Err("`next` chooses by rank; use `--id <id>` for a specific slice".to_owned());
    }
    if parsed.command == Command::SetStatus {
        return parse_set_status(parsed, &positional);
    }
    if parsed.command == Command::Issue {
        if positional.len() > 1 {
            return Err(format!(
                "unexpected arguments after the issue number: {}",
                positional[1..].join(", ")
            ));
        }
        if let Some(number) = positional.pop() {
            if parsed.issue.is_some() {
                return Err("issue number given twice".to_owned());
            }
            parsed.issue = Some(parse_issue(&number)?);
        }
        if parsed.issue.is_none() {
            return Err("issue needs a number, as in `ferrox-prompt issue 661`".to_owned());
        }
        return Ok(());
    }
    if let Some(id) = positional.pop() {
        if parsed.id.is_some() {
            return Err(format!("prompt id given twice: {id}"));
        }
        if !matches!(parsed.command, Command::Render | Command::Show) {
            return Err(format!(
                "`{id}` is not a command this tool has; try `list`, `next`, `render <id>`, `show <id>`, \
                 `rows` or `check`"
            ));
        }
        parsed.id = Some(parse_id(&id)?);
    }
    if !positional.is_empty() {
        return Err(format!("unexpected arguments: {}", positional.join(", ")));
    }
    if matches!(parsed.command, Command::Render | Command::Show) && parsed.id.is_none() {
        let name = if parsed.command == Command::Render {
            "render"
        } else {
            "show"
        };
        return Err(format!(
            "{name} needs a prompt id, as in `ferrox-prompt {name} 2`"
        ));
    }
    Ok(())
}

/// `set-status <id> <status>`, positional in that order; split out of `parse` for the line-count lint.
fn parse_set_status(parsed: &mut Args, positional: &[String]) -> Result<(), String> {
    if positional.len() != 2 {
        return Err(
            "`set-status` needs a prompt id and a status, as in `ferrox-prompt set-status 5 doing`"
                .to_owned(),
        );
    }
    parsed.id = Some(parse_id(&positional[0])?);
    parsed.set_to = Some(Status::parse(&positional[1]).ok_or_else(|| {
        format!(
            "`{}` is not a status: {}",
            positional[1],
            Status::NAMES.join(", ")
        )
    })?);
    Ok(())
}

/// The command a verb names, spelled out so a non-verb flag is a compile error, not a quiet no-op.
fn verb_of(word: &str) -> Command {
    match word {
        "check" => Command::Check,
        "list" | "ls" => Command::List,
        "next" => Command::Next,
        "render" => Command::Render,
        "issue" | "bug" => Command::Issue,
        "show" => Command::Show,
        "rows" => Command::Rows,
        "set-status" => Command::SetStatus,
        _ => Command::Help,
    }
}

/// One `--set KEY=VALUE`: only the first `=` separates, so a value may contain `=`.
fn assign(values: &mut BTreeMap<String, String>, assignment: &str) -> Result<(), String> {
    let Some((name, value)) = assignment.split_once('=') else {
        return Err(format!("`{assignment}` is not KEY=VALUE"));
    };
    if name.trim().is_empty() {
        return Err(format!("`{assignment}` has no key"));
    }
    if value.trim().is_empty() {
        return Err(format!("`{assignment}` has an empty value"));
    }
    values.insert(name.trim().to_owned(), value.to_owned());
    Ok(())
}

/// The value for a flag: what followed `=`, or the next argument.
fn take_value(
    arguments: &[String],
    index: &mut usize,
    inline: Option<&str>,
    flag: &str,
) -> Result<String, String> {
    if let Some(value) = inline {
        return Ok(value.to_owned());
    }
    let value = arguments
        .get(*index)
        .ok_or_else(|| format!("{flag} needs a value"))?
        .clone();
    *index += 1;
    Ok(value)
}

/// `2`, `P2`, `p2` — all the same id.
fn parse_id(text: &str) -> Result<u32, String> {
    text.trim()
        .trim_start_matches(['P', 'p'])
        .parse()
        .map_err(|_| format!("`{text}` is not a prompt id; write it as P<n>"))
}

/// `661` or `#661`: the issue the regression template fixes.
fn parse_issue(text: &str) -> Result<u64, String> {
    let number: u64 = text
        .trim()
        .trim_start_matches('#')
        .parse()
        .map_err(|_| format!("`{text}` is not an issue number; write it as `issue 661`"))?;
    if number == 0 {
        return Err(format!(
            "`{text}` is not an issue number; write it as `issue 661`"
        ));
    }
    Ok(number)
}

/// `check`, and the CI step that runs it.
fn run_check(args: &Args, cwd: &Path) -> ExitCode {
    let library = match load_library(args.library.as_deref(), cwd) {
        Ok(library) => library,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let root = workspace_root_for(args, cwd);
    // A library outside this repo has nothing local to check **Touches:** against; the canonicalised path decides.
    let inside = match args.library.as_deref() {
        None => true,
        Some(given) => {
            let given = std::fs::canonicalize(given).unwrap_or_else(|_| given.to_path_buf());
            let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
            given.starts_with(canonical_root)
        }
    };
    let findings = check::run(&library, &root, inside);
    let (errors, warnings): (Vec<&Diagnostic>, Vec<&Diagnostic>) = findings
        .iter()
        .partition(|finding| finding.severity == Severity::Error);
    for finding in &errors {
        println!(
            "{}:{}: {} [error]",
            library.path.display(),
            finding.line,
            finding.message
        );
    }
    for finding in &warnings {
        println!(
            "{}:{}: {} [warning]",
            library.path.display(),
            finding.line,
            finding.message
        );
    }
    println!(
        "{}: {} prompt(s), {} error(s), {} warning(s)",
        library.path.display(),
        library.prompts.len(),
        errors.len(),
        warnings.len()
    );
    let strict_failures = args.strict && !warnings.is_empty();
    if strict_failures {
        println!("--strict: warnings count as errors");
    }
    if errors.is_empty() && !strict_failures {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `list`: totals, served count and the status summary; per-prompt lines only when `--status`/`--effort` narrowed.
fn run_list(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let ledger = load_ledger(ledger_path(root, library));
    let selected: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| args.status.is_none_or(|wanted| prompt.status == wanted))
        // `--effort` filters list and ranking alike: one flag must not mean two things.
        .filter(|prompt| args.effort.is_none_or(|wanted| prompt.effort == wanted))
        .collect();

    if args.output == Output::Json {
        println!(
            "{}",
            Value::object([
                ("library", Value::text(library.path.display().to_string())),
                ("tag", Value::text(library.tag())),
                ("ready", ready_json(library, args.effort)),
                (
                    "prompts",
                    Value::List(
                        selected
                            .iter()
                            .map(|prompt| prompt_json(prompt, &ledger))
                            .collect()
                    )
                ),
            ])
            .to_pretty()
        );
        return ExitCode::SUCCESS;
    }

    let state = ProjectState::load(root);
    if state.has_matrix() {
        let open = state.candidates(Targets::Open);
        println!(
            "matrix: {} open ({} partial, {} unclassified, {} high priority) · {} implemented · {} rows served here",
            open.len(),
            open.iter().filter(|row| row.gap == Gap::Partial).count(),
            open.iter().filter(|row| row.gap == Gap::Unclassified).count(),
            open.iter().filter(|row| row.high_priority).count(),
            state.candidates(Targets::Implemented).len(),
            ledger
                .entries
                .iter()
                .filter(|entry| entry.target.is_some())
                .count(),
        );
    }
    if args.status.is_some() || args.effort.is_some() {
        for prompt in &selected {
            println!(
                "P{} · {:<7} · lev {} · {:<6} · {:<11} · {}",
                prompt.id,
                prompt.status.as_str(),
                prompt.leverage,
                prompt.effort.as_str(),
                prompt.targets.as_str(),
                prompt.title,
            );
        }
    }
    summarise(library, args.effort);
    ExitCode::SUCCESS
}

/// `rows`: the matrix a slice can be about, so a row can be picked by its key.
fn run_rows(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let state = ProjectState::load(root);
    if !state.has_matrix() {
        eprintln!(
            "no matrix in {} — there is no row to pick",
            root.join(ferrox_prompt::README_RELATIVE).display()
        );
        return ExitCode::from(1);
    }
    let rows: Vec<&MethodRow> = match &args.row {
        Some(selector) => expand::matching_rows(&state, selector),
        None => state.methods.iter().collect(),
    };
    if rows.is_empty() {
        eprintln!(
            "no matrix row matches `{}`; the matrix has {} rows",
            args.row.as_deref().unwrap_or_default().trim(),
            state.methods.len()
        );
        return ExitCode::from(2);
    }
    if args.output == Output::Json {
        println!(
            "{}",
            Value::object([
                ("library", Value::text(library.path.display().to_string())),
                (
                    "rows",
                    Value::List(rows.iter().map(|row| row_json(Some(row))).collect())
                ),
            ])
            .to_pretty()
        );
        return ExitCode::SUCCESS;
    }
    for row in &rows {
        println!(
            "{} · {} · {} · gap: {} · {}{} · {}{}",
            row.key(),
            row.method,
            row.state,
            row.gap.as_str(),
            if row.implemented { "shipped" } else { "open" },
            if row.high_priority {
                " · high priority"
            } else {
                ""
            },
            row.page,
            if row.real_page { "" } else { " (suggested)" }
        );
    }
    println!();
    println!(
        "{} row(s) · {} open · {} partial · {} unclassified · {} high priority · {} shipped",
        rows.len(),
        rows.iter().filter(|row| !row.implemented).count(),
        rows.iter().filter(|row| row.gap == Gap::Partial).count(),
        rows.iter()
            .filter(|row| row.gap == Gap::Unclassified)
            .count(),
        rows.iter().filter(|row| row.high_priority).count(),
        rows.iter().filter(|row| row.implemented).count()
    );
    ExitCode::SUCCESS
}

/// The state-filled placeholder values a template renders with.
type Values = BTreeMap<String, String>;

/// `--set` values plus `--issue`, so both spellings fill the same blank.
fn requested_values(args: &Args) -> Values {
    let mut values = args.values.clone();
    values.retain(|_, value| !value.trim().is_empty());
    if let Some(issue) = args.issue {
        values.insert("issue".to_owned(), issue.to_string());
    }
    values
}

/// The nearest directory at or above `start` that carries the prompt library, without the manifest fallback.
fn workspace_marker(start: &Path) -> Option<PathBuf> {
    let mut cursor = Some(start);
    while let Some(dir) = cursor {
        if dir.join(LIBRARY_RELATIVE).is_file() {
            return Some(dir.to_path_buf());
        }
        cursor = dir.parent();
    }
    None
}

/// The workspace an explicit library belongs to, so a retry reopens its matrix and ledger from there.
fn workspace_root_for(args: &Args, cwd: &Path) -> PathBuf {
    if let Some(library) = args.library.as_deref() {
        let library = if library.is_absolute() {
            library.to_path_buf()
        } else {
            std::fs::canonicalize(cwd.join(library)).unwrap_or_else(|_| cwd.join(library))
        };
        if let Some(root) = workspace_marker(library.parent().unwrap_or(&library)) {
            return root;
        }
    }
    workspace_root(cwd)
}

/// The absolute library the retry reopens, so moving to the slice's worktree does not change it.
fn retry_library_path(args: &Args, library: &Library) -> Option<PathBuf> {
    if library.source_path.to_str().is_some() {
        return Some(library.source_path.clone());
    }
    let given = args.library.as_ref()?;
    let alias = if given.is_absolute() {
        given.clone()
    } else {
        std::env::current_dir().ok()?.join(given)
    };
    if alias.to_str().is_some() {
        Some(alias)
    } else {
        None
    }
}

/// A slice the advisor may hand over: the prompt plus, for a matrix template, the row it draws and that row's values.
type Offer<'p> = (&'p Prompt, Option<(&'p MethodRow, Values)>);

/// A refusal: what to say, and the exit code that names it — 1 for the roadmap, 2 for the keyboard.
type Refusal = (String, u8);

/// A matrix template stays offered only while its class has an unserved row, so `next` moves on when it empties.
fn build_offers<'p>(
    handable: &[&'p Prompt],
    state: &'p ProjectState,
    ledger: &Ledger,
    named: Option<&'p MethodRow>,
    supplied: &Values,
    requested_addons: &[String],
    allow_unfilled: bool,
) -> Vec<Offer<'p>> {
    handable
        .iter()
        .filter_map(|prompt| {
            if let Some(row) = named {
                // A named row is the work, so only a template that draws that class may take it.
                if !prompt.targets.is_matrix() || !expand::row_fits(row, prompt.targets) {
                    return None;
                }
                return Some((*prompt, Some((row, expand::fill(prompt, row, &state.pins)))));
            }
            if prompt.targets.is_matrix() {
                target_for(
                    prompt,
                    state,
                    ledger,
                    None,
                    supplied,
                    requested_addons,
                    allow_unfilled,
                )
                .map(|pair| (*prompt, Some(pair)))
            } else {
                Some((*prompt, None))
            }
        })
        .collect()
}

/// Top-ranked offer, or a weighted draw under `--rotate`; the clone frees the borrow from the slice.
fn choose_offer<'p>(offers: &[Offer<'p>], rotate: bool, seed: u64) -> Result<Offer<'p>, Refusal> {
    if !rotate {
        let (prompt, target) = &offers[0];
        return Ok((*prompt, target.clone()));
    }
    let refs: Vec<&Prompt> = offers.iter().map(|(prompt, _)| *prompt).collect();
    let prompt = advisor::rotate_among(&refs, seed).map_err(|reason| (reason, 1))?;
    let (candidate, target) = offers
        .iter()
        .find(|(p, _)| p.id == prompt.id)
        .expect("a rotated prompt is one of the offers");
    Ok((*candidate, target.clone()))
}

/// Fold `--set` over the state-filled row; `{references}` falls back to the core pins even for a `none` class.
fn merge_values(
    requested: &Values,
    target: Option<&(&MethodRow, Values)>,
    state: &ProjectState,
) -> Values {
    let mut values = requested.clone();
    if let Some((_, fill)) = target {
        for (name, value) in fill {
            values.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    if !values.contains_key("references") {
        let references = state.references();
        if !references.is_empty() {
            values.insert("references".to_owned(), references);
        }
    }
    values.retain(|_, value| !value.trim().is_empty());
    values
}

/// The worktree this slice runs in: named from the matrix row it draws, from its issue when it fixes one, or from its title when it draws neither, so one task keeps one worktree.
fn slice_worktree(
    prompt: &Prompt,
    target: Option<&(&MethodRow, Values)>,
    values: &Values,
    root: &Path,
) -> Worktree {
    if let Some(issue) = values.get("issue") {
        return Worktree::named(format!("bugfix-{issue}"), root);
    }
    let label = target
        .map(|(row, _)| row.method.as_str())
        .or_else(|| values.get("method").map(String::as_str))
        .unwrap_or(prompt.title.as_str());
    let row_key = target.map(|(row, _)| row.key());
    Worktree::plan(prompt.id, label, row_key.as_deref(), root)
}

/// The `--json` shape for a `next` handout, so an agent drives the loop without parsing prose.
fn next_json(
    library: &Library,
    prompt: &Prompt,
    target: Option<&(&MethodRow, Values)>,
    ledger: &Ledger,
    rendered: &render::Rendered,
    selection: Value,
) -> String {
    Value::object([
        ("library", Value::text(library.path.display().to_string())),
        ("tag", Value::text(library.tag())),
        ("selection", selection),
        (
            "target",
            target.map_or(Value::Null, |(row, _)| Value::text(row.key())),
        ),
        ("row", row_json(target.map(|(row, _)| *row))),
        ("slice", prompt_json(prompt, ledger)),
        ("worktree", worktree_json(rendered.worktree.as_ref())),
        ("prompt", Value::text(rendered.text.clone())),
    ])
    .to_pretty()
}

/// The matrix row a slice is about, for `--json`; a slice that draws no row says so.
fn row_json(row: Option<&MethodRow>) -> Value {
    let Some(row) = row else {
        return Value::Null;
    };
    Value::object([
        ("key", Value::text(row.key())),
        ("method", Value::text(row.method.clone())),
        ("state", Value::text(row.state.clone())),
        ("gap", Value::text(row.gap.as_str())),
        ("high_priority", Value::Bool(row.high_priority)),
        ("page", Value::text(row.page.clone())),
        ("real_page", Value::Bool(row.real_page)),
        ("implemented", Value::Bool(row.implemented)),
    ])
}

/// The worktree a handout names, so an agent creates it or reuses it without parsing prose.
fn worktree_json(worktree: Option<&Worktree>) -> Value {
    let Some(worktree) = worktree else {
        return Value::Null;
    };
    Value::object([
        ("name", Value::text(worktree.name.clone())),
        ("path", Value::text(worktree.path.display().to_string())),
        ("state", Value::text(worktree.state())),
    ])
}

/// Refuse a handout whose required blanks the library does not supply, unless `--allow-unfilled`.
fn missing_input_refusal(
    prompt: &Prompt,
    rendered: &render::Rendered,
    supplied: &Values,
    args: &Args,
    library: &Library,
    row: Option<&str>,
) -> Option<ExitCode> {
    if rendered.missing.is_empty() || args.allow_unfilled {
        return None;
    }
    eprintln!(
        "P{} needs a value for {}",
        prompt.id,
        rendered
            .missing
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!(
        "{}",
        render::suggested_command(
            prompt,
            &rendered.missing,
            supplied,
            &rendered.addons,
            &args.addons,
            retry_library_path(args, library).as_deref(),
            row,
            !args.record
        )
    );
    Some(ExitCode::from(2))
}

fn reload_library(library: &Library) -> Result<Library, String> {
    let text = std::fs::read_to_string(&library.source_path)
        .map_err(|error| format!("could not read {}: {error}", library.source_path.display()))?;
    let mut reloaded = Library::parse(&library.path, &text);
    reloaded.source_path.clone_from(&library.source_path);
    if reloaded.has_errors() {
        let mut message = format!(
            "{} has errors; fix them first:",
            library.source_path.display()
        );
        for diagnostic in reloaded.errors() {
            let _ = writeln!(message, "  {diagnostic}");
        }
        return Err(message);
    }
    Ok(reloaded)
}

/// `next`: fills a matrix template from its first unserved row, so repeat runs walk the matrix; `--set` still wins.
#[allow(clippy::too_many_lines)]
fn run_next(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let ledger_path = ledger_path(root, library);
    let Ok(_lock) = lock_if_recording(args.record, &ledger_path) else {
        return ExitCode::from(1);
    };
    let reloaded = match reload_library(library) {
        Ok(reloaded) => reloaded,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let library = &reloaded;
    let ledger = load_ledger(ledger_path);
    let state = ProjectState::load(root);

    // A named row is the work; the template that draws it is then the advisor's choice.
    let named = match &args.row {
        Some(selector) => match expand::select_row(&state, selector) {
            Ok(row) => Some(row),
            Err(reason) => {
                eprintln!("{reason}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // The ledger remembers templates, not rows, so a named row is asked for on purpose and is not withheld.
    let suppressed = if named.is_some() {
        Vec::new()
    } else {
        ledger.recent_ids(args.memory)
    };

    // Only an explicit value is supplied here; `handable` counts what this template's row and the pins can fill.
    let supplied = requested_values(args);

    // Resolve the (template, row) pair: `forced` names one on purpose, else walk the handable set for a live target.
    let ((prompt, target), skipped) = match choose_slice(
        args,
        library,
        &state,
        &ledger,
        &suppressed,
        &supplied,
        named,
    ) {
        Ok(choice) => choice,
        Err((message, code)) => {
            eprintln!("{message}");
            return ExitCode::from(code);
        }
    };

    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    // A forced matrix template with no row to fill says why: spent, parked, or an input no row supplies.
    if target.is_none()
        && expand::is_fillable(prompt, &state)
        && !state.candidates(prompt.targets).is_empty()
    {
        eprintln!(
            "{}",
            no_target_reason(args, library, prompt, &state, &ledger, &addons, &supplied)
        );
        return ExitCode::from(2);
    }
    // `--set` wins over the state-filled value, so an explicit row beats the first unserved candidate.
    let values = merge_values(&supplied, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, target.as_ref(), &values, root);
    let target_key = target.as_ref().map(|(row, _)| row.key());
    let options = Options {
        allow_unfilled: args.allow_unfilled,
        retry_library: retry_library_path(args, library),
        retry_row: target_key.clone(),
        retry_no_ledger: !args.record,
        retry_values: Some(supplied.clone()),
        retry_addons: args.addons.clone(),
        ..Options::default()
    };
    let rendered = render::render(library, prompt, &values, &addons, Some(&worktree), &options);
    if let Some(code) = missing_input_refusal(
        prompt,
        &rendered,
        &supplied,
        args,
        library,
        target_key.as_deref(),
    ) {
        return code;
    }
    if args.output == Output::Json {
        let selection = selection_json(library, prompt, args, &suppressed, &skipped);
        let json = next_json(
            library,
            prompt,
            target.as_ref(),
            &ledger,
            &rendered,
            selection,
        );
        if let Err(error) = emit_json(&json) {
            eprintln!("could not write the handout: {error}");
            return ExitCode::from(1);
        }
    } else {
        report_next(library, prompt, root, &ledger, &skipped, args, &addons);
        report_target(target.as_ref(), &ledger, prompt);
        if let Some(worktree) = &rendered.worktree {
            println!("worktree    {}", worktree.brief());
        }
        deliver(&rendered, library, prompt.id, args.output.is_stdout());
    }
    // A `--json` handout is recorded too, so a JSON-driven agent still walks the matrix.
    record(
        ledger,
        prompt.id,
        &how_asked(args),
        target_key.as_deref(),
        args.record,
    );
    ExitCode::SUCCESS
}

/// The (template, row) pair this handout is about: the one asked for by id, or the best the advisor has.
fn choose_slice<'p>(
    args: &Args,
    library: &'p Library,
    state: &'p ProjectState,
    ledger: &Ledger,
    suppressed: &[u32],
    supplied: &Values,
    named: Option<&'p MethodRow>,
) -> Result<(Offer<'p>, Vec<advisor::Skipped>), Refusal> {
    if let Some(message) = ledger_refusal(ledger) {
        return Err((message, 1));
    }
    if let Some(id) = args.forced {
        let Some(prompt) = library.prompt(id) else {
            return Err((unknown_prompt(library, id), 2));
        };
        if let Some(row) = named {
            if let Err(reason) = row_fits_template(prompt, row, library) {
                return Err((reason, 2));
            }
        }
        return Ok((
            (
                prompt,
                target_for(
                    prompt,
                    state,
                    ledger,
                    named,
                    supplied,
                    &args.addons,
                    args.allow_unfilled,
                ),
            ),
            Vec::new(),
        ));
    }
    let (handable, skipped) = advisor::handable(
        library,
        args.effort,
        suppressed,
        &args.addons,
        advisor::Inputs::new(supplied, named),
        advisor::Context { state, ledger },
        args.allow_unfilled,
    );
    let offers = build_offers(
        &handable,
        state,
        ledger,
        named,
        supplied,
        &args.addons,
        args.allow_unfilled,
    );
    if offers.is_empty() {
        return Err((
            nothing_to_hand_over(library, args, suppressed, &skipped, state, ledger, named),
            1,
        ));
    }
    choose_offer(&offers, args.draw == Draw::Rotate, args.seed).map(|offer| (offer, skipped))
}

/// The row this slice draws, and whether this template was handed it before.
fn report_target(target: Option<&(&MethodRow, Values)>, ledger: &Ledger, prompt: &Prompt) {
    let Some((row, _)) = target else {
        return;
    };
    let again = if ledger.targets_for(prompt.id).contains(&row.key()) {
        "; already served to this template"
    } else {
        ""
    };
    println!(
        "targeting row {} — {} (state: {}; gap: {}{}{})",
        row.key(),
        row.method,
        row.state,
        row.gap.as_str(),
        if row.high_priority {
            ", high priority"
        } else {
            ""
        },
        again
    );
}

/// The row this slice is about: the one the user named, or the first unserved row of the template's class.
fn target_for<'p>(
    prompt: &Prompt,
    state: &'p ProjectState,
    ledger: &Ledger,
    named: Option<&'p MethodRow>,
    supplied: &Values,
    requested_addons: &[String],
    allow_unfilled: bool,
) -> Option<(&'p MethodRow, Values)> {
    if let Some(row) = named {
        return Some((row, expand::fill(prompt, row, &state.pins)));
    }
    if !expand::is_fillable(prompt, state) {
        return None;
    }
    let addons = render::resolve_addons(prompt, requested_addons).unwrap_or_default();
    expand::next_target(
        prompt,
        state,
        &ledger.targets_for(prompt.id),
        &addons,
        supplied,
        allow_unfilled,
    )
}

/// The row the user named, when this template may draw it.
fn named_row<'p>(
    prompt: &Prompt,
    state: &'p ProjectState,
    library: &Library,
    selector: &str,
) -> Result<Option<&'p MethodRow>, String> {
    let row = expand::select_row(state, selector)?;
    row_fits_template(prompt, row, library)?;
    Ok(Some(row))
}

/// Whether a template may draw a row, and the reason it may not.
fn row_fits_template(prompt: &Prompt, row: &MethodRow, library: &Library) -> Result<(), String> {
    if !prompt.targets.is_matrix() {
        return Err(format!(
            "P{} does not draw from the matrix — it is a fixed slice, so `--row` has nothing to fill",
            prompt.id
        ));
    }
    if expand::row_fits(row, prompt.targets) {
        return Ok(());
    }
    let drawers: Vec<String> = library
        .prompts
        .iter()
        .filter(|other| other.targets.is_matrix() && expand::row_fits(row, other.targets))
        .map(|other| format!("P{}", other.id))
        .collect();
    Err(format!(
        "row {} ({}) is {}, and P{} draws {} rows; these draw it: {}",
        row.key(),
        row.method,
        if row.implemented { "shipped" } else { "open" },
        prompt.id,
        prompt.targets.as_str(),
        join_capped(&drawers)
    ))
}

/// A list of ids, capped: the first few name the way out, the count says how many more there are.
fn join_capped(ids: &[String]) -> String {
    const LIMIT: usize = 8;
    if ids.len() <= LIMIT {
        join_or(ids.iter().cloned())
    } else {
        format!("{} (+{} more)", ids[..LIMIT].join(", "), ids.len() - LIMIT)
    }
}

fn render_prompt<'a>(args: &Args, library: &'a Library, id: u32) -> Result<&'a Prompt, ExitCode> {
    if args.command == Command::Issue {
        return issue_prompt(library).map_err(|reason| {
            eprintln!("{reason}");
            ExitCode::from(2)
        });
    }
    library.prompt(id).ok_or_else(|| {
        eprintln!("{}", unknown_prompt(library, id));
        ExitCode::from(2)
    })
}

/// `render <id>`: a matrix template filled from its first unserved row, like `next`, not a page of holes.
#[allow(clippy::too_many_lines)]
fn run_render(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let id = args.id.expect("parse requires an id for render");
    let ledger_path = ledger_path(root, library);
    let Ok(_lock) = lock_if_recording(args.record, &ledger_path) else {
        return ExitCode::from(1);
    };
    let reloaded = match reload_library(library) {
        Ok(reloaded) => reloaded,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let library = &reloaded;
    let prompt = match render_prompt(args, library, id) {
        Ok(prompt) => prompt,
        Err(code) => return code,
    };
    let ledger = load_ledger(ledger_path);
    if let Some(message) = ledger_refusal(&ledger) {
        eprintln!("{message}");
        return ExitCode::from(1);
    }
    let state = ProjectState::load(root);
    let named = match &args.row {
        Some(selector) => match named_row(prompt, &state, library, selector) {
            Ok(row) => row,
            Err(reason) => {
                eprintln!("{reason}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let supplied = requested_values(args);
    let target = target_for(
        prompt,
        &state,
        &ledger,
        named,
        &supplied,
        &args.addons,
        args.allow_unfilled,
    );
    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    // A matrix template with no row to fill says why: spent, parked, or an input no row supplies.
    if target.is_none()
        && expand::is_fillable(prompt, &state)
        && !state.candidates(prompt.targets).is_empty()
    {
        eprintln!(
            "{}",
            no_target_reason(args, library, prompt, &state, &ledger, &addons, &supplied)
        );
        return ExitCode::from(2);
    }
    let values = merge_values(&supplied, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, target.as_ref(), &values, root);
    let target_key = target.as_ref().map(|(row, _)| row.key());
    let options = Options {
        allow_unfilled: args.allow_unfilled,
        retry_library: retry_library_path(args, library),
        retry_row: target_key.clone(),
        retry_no_ledger: !args.record,
        retry_values: Some(supplied.clone()),
        retry_addons: args.addons.clone(),
        ..Options::default()
    };
    let rendered = render::render(library, prompt, &values, &addons, Some(&worktree), &options);
    if let Some(code) = missing_input_refusal(
        prompt,
        &rendered,
        &supplied,
        args,
        library,
        target_key.as_deref(),
    ) {
        return code;
    }
    if args.output == Output::Json {
        let json = Value::object([
            ("tag", Value::text(library.tag())),
            (
                "target",
                target_key
                    .as_deref()
                    .map_or(Value::Null, |key| Value::text(key.to_owned())),
            ),
            ("row", row_json(target.map(|(row, _)| row))),
            ("slice", prompt_json(prompt, &ledger)),
            ("worktree", worktree_json(rendered.worktree.as_ref())),
            ("prompt", Value::text(rendered.text.clone())),
        ])
        .to_pretty();
        if let Err(error) = emit_json(&json) {
            eprintln!("could not write the handout: {error}");
            return ExitCode::from(1);
        }
        // Recorded like a `next` handout, so a by-id JSON render still advances the template's served rows.
        record(
            ledger,
            prompt.id,
            &how_asked(args),
            target_key.as_deref(),
            args.record,
        );
        return ExitCode::SUCCESS;
    }
    deliver(&rendered, library, prompt.id, args.output.is_stdout());
    if args.output == Output::Copy {
        report_render_guide(prompt, target.as_ref(), &values, &state, &addons);
    }
    record(
        ledger,
        prompt.id,
        &how_asked(args),
        target_key.as_deref(),
        args.record,
    );
    ExitCode::SUCCESS
}

/// `issue <number>`: the one template that takes an issue number, rendered and copied like `render`.
fn run_issue(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let prompt = match issue_prompt(library) {
        Ok(prompt) => prompt,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    let mut render = args.clone();
    render.command = Command::Issue;
    render.id = Some(prompt.id);
    run_render(&render, library, root)
}

/// The template that declares `{issue}`; more than one would make `issue <number>` a guess.
fn issue_prompt(library: &Library) -> Result<&Prompt, String> {
    let matching: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| {
            prompt
                .placeholders
                .iter()
                .any(|placeholder| placeholder.name == "issue")
        })
        .collect();
    match matching.as_slice() {
        [only] => Ok(only),
        [] => Err(format!(
            "{} has no template with an {{issue}} blank; add one, or name a template and pass --issue <number>",
            library.path.display()
        )),
        many => Err(format!(
            "{} has {} templates with an {{issue}} blank; `issue <number>` needs exactly one",
            library.path.display(),
            many.len()
        )),
    }
}

/// `show <id>`: metadata, then the same rendered prompt `render <id>` delivers, so one command reads a slice.
fn run_show(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let id = args.id.expect("parse requires an id for show");
    let Some(prompt) = library.prompt(id) else {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    };
    let ledger = load_ledger(ledger_path(root, library));
    let state = ProjectState::load(root);
    let named = match &args.row {
        Some(selector) => match named_row(prompt, &state, library, selector) {
            Ok(row) => row,
            Err(reason) => {
                eprintln!("{reason}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let supplied = requested_values(args);
    let target = target_for(
        prompt,
        &state,
        &ledger,
        named,
        &supplied,
        &args.addons,
        true,
    );
    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    let values = merge_values(&supplied, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, target.as_ref(), &values, root);
    let target_key = target.as_ref().map(|(row, _)| row.key());
    let rendered = render::render(
        library,
        prompt,
        &values,
        &addons,
        Some(&worktree),
        &Options {
            allow_unfilled: true,
            retry_library: retry_library_path(args, library),
            retry_row: target_key.clone(),
            retry_no_ledger: !args.record,
            retry_values: Some(supplied.clone()),
            retry_addons: args.addons.clone(),
            ..Options::default()
        },
    );
    if args.output == Output::Json {
        println!(
            "{}",
            Value::object([
                ("tag", Value::text(library.tag())),
                ("slice", prompt_json(prompt, &ledger)),
                ("selection", selection_json(library, prompt, args, &[], &[])),
                (
                    "target",
                    target_key
                        .as_deref()
                        .map_or(Value::Null, |key| Value::text(key.to_owned())),
                ),
                ("row", row_json(target.map(|(row, _)| row))),
                ("prompt", Value::text(rendered.text.clone())),
            ])
            .to_pretty()
        );
        return ExitCode::SUCCESS;
    }
    println!("P{} · {}", prompt.id, prompt.title);
    report_metadata(prompt, library, root, &ledger, target.as_ref(), &rendered);
    println!();
    println!("--- prompt ---");
    println!();
    println!("{}", rendered.text);
    ExitCode::SUCCESS
}

/// The metadata above the prompt: what this slice is, what it waits on, and which row it draws.
fn report_metadata(
    prompt: &Prompt,
    library: &Library,
    root: &Path,
    ledger: &Ledger,
    target: Option<&(&MethodRow, Values)>,
    rendered: &Rendered,
) {
    println!("  status        {}", prompt.status.as_str());
    println!("  readiness     {}", describe_readiness(library, prompt));
    println!("  leverage      {}", prompt.leverage);
    println!("  effort        {}", prompt.effort.as_str());
    println!("  when to use   {}", prompt.when_to_use);
    println!(
        "  depends on    {}",
        join_or(prompt.depends_on.iter().map(|id| {
            let state = library
                .prompt(*id)
                .map_or("missing", |found| found.status.as_str());
            format!("P{id} ({state})")
        }))
    );
    println!(
        "  opens         {}",
        join_or(prompt.blocks(library).map(|other| format!("P{}", other.id)))
    );
    if !prompt.touches.is_empty() {
        println!("  touches       {}", describe_touches(prompt, root));
    }
    let overlaps = overlaps(library, prompt, root);
    if !overlaps.is_empty() {
        println!("  overlaps      {}", overlaps.join(", "));
    }
    println!("  random weight {}", prompt.random_weight);
    println!("  last drawn    {}", describe_history(ledger, prompt.id));
    println!("  gates         {}", prompt.gates.join("; "));
    println!(
        "  add-ons       {}",
        join_or(prompt.addons.iter().map(|addon| addon.slug.clone()))
    );
    println!("  targets       {}", prompt.targets.as_str());
    if let Some((row, _)) = target {
        println!(
            "  targeting     {} — {} (state: {})",
            row.key(),
            row.method,
            row.state
        );
    }
    if let Some(worktree) = &rendered.worktree {
        println!("  worktree      {} — {}", worktree.name, worktree.brief());
    }
}

/// A custom library gets its own history, so the default roadmap does not inherit sentences for prompts it never had.
fn ledger_path(root: &Path, library: &Library) -> PathBuf {
    let default = root.join(LIBRARY_RELATIVE);
    let identity =
        std::fs::canonicalize(&library.source_path).unwrap_or_else(|_| library.source_path.clone());
    let default_identity = std::fs::canonicalize(&default).unwrap_or_else(|_| default.clone());
    let ordinary_default = identity == default_identity
        && default
            .symlink_metadata()
            .is_ok_and(|metadata| !metadata.file_type().is_symlink());
    if ordinary_default {
        root.join(LEDGER_RELATIVE)
    } else {
        root.join(".ferrox")
            .join(format!("slices-{}.log", path_tag(&identity)))
    }
}

/// Read the handout ledger, saying when it exists but cannot be trusted rather than treating it as empty history.
fn load_ledger(path: PathBuf) -> Ledger {
    let ledger = Ledger::load(path);
    if let Some(error) = &ledger.read_error {
        eprintln!("warning: {error}; the history is incomplete");
    }
    if ledger.skipped > 0 {
        eprintln!(
            "warning: ignored {} unreadable line(s) in {}",
            ledger.skipped,
            ledger.path.display()
        );
    }
    ledger
}

/// Refuse a choice that would repeat served work because the history could not be read in full.
fn ledger_refusal(ledger: &Ledger) -> Option<String> {
    if let Some(error) = &ledger.read_error {
        return Some(format!(
            "{error}; refusing to choose a slice from an unreadable history"
        ));
    }
    (ledger.skipped > 0).then(|| {
        format!(
            "{} ledger record(s) were skipped; refusing to choose a slice from an incomplete history",
            ledger.skipped
        )
    })
}

/// Record progress by rewriting exactly the prompt's `**Status:**` line: reflowing Markdown would fight the contributor's edits.
fn run_set_status(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let id = args.id.expect("parse requires an id for set-status");
    let to = args.set_to.expect("parse requires a status for set-status");
    if library.prompt(id).is_none() {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    }
    let Ok(_source_lock) = lock_state(&library.source_path) else {
        return ExitCode::from(1);
    };
    let Ok(_lock) = lock_state(&ledger_path(root, library)) else {
        return ExitCode::from(1);
    };
    let current = match std::fs::read_to_string(&library.source_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("could not read {}: {error}", library.source_path.display());
            return ExitCode::from(1);
        }
    };
    let current_prompt = Library::parse(&library.source_path, &current)
        .prompt(id)
        .cloned();
    let Some(current_prompt) = current_prompt else {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    };
    if current_prompt.status == to {
        println!("P{id} is already {}", to.as_str());
        return ExitCode::SUCCESS;
    }
    match set_status_text(&current, id, to) {
        Ok(updated) => {
            let reloaded = Library::parse(&library.path, &updated);
            let status_problem = reloaded.diagnostics.iter().any(|diagnostic| {
                diagnostic.severity == Severity::Error
                    && diagnostic
                        .message
                        .starts_with(&format!("P{id}: **Status:**"))
            });
            if status_problem || reloaded.prompt(id).map(|prompt| prompt.status) != Some(to) {
                eprintln!(
                    "P{id} has a second **Status:** line, so rewriting the first would not change \
                     the effective status; remove the duplicate first"
                );
                return ExitCode::from(2);
            }
            if let Err(error) = replace_file(&library.source_path, &updated) {
                eprintln!("could not write {}: {error}", library.source_path.display());
                return ExitCode::from(1);
            }
            if args.output == Output::Json {
                println!(
                    "{}",
                    Value::object([
                        ("id", Value::text(id.to_string())),
                        ("from", Value::text(current_prompt.status.as_str())),
                        ("to", Value::text(to.as_str())),
                    ])
                    .to_pretty()
                );
            } else {
                println!(
                    "P{id}: {} -> {}",
                    current_prompt.status.as_str(),
                    to.as_str()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

/// Byte-identical everywhere else; fenced blocks are skipped, so a body quoting `**Status:**` is prose, not the field.
fn set_status_text(source: &str, id: u32, status: Status) -> Result<String, String> {
    let mut out = Vec::new();
    let mut current: Option<u32> = None;
    let mut fence: Option<(char, usize)> = None;
    let mut replaced = false;
    for raw in source.split_inclusive('\n') {
        let (line, ending) = match raw.strip_suffix('\n') {
            Some(line) if line.ends_with('\r') => (&line[..line.len() - 1], "\r\n"),
            Some(line) => (line, "\n"),
            None => (raw, ""),
        };
        if let Some((marker, width)) = fence {
            if closes_fence(line, marker, width) {
                fence = None;
            }
        } else if let Some((marker, width)) = opens_fence(line) {
            fence = Some((marker, width));
        } else if let Some(body) = line.strip_prefix("## ") {
            current = section_id(body.trim_end());
        } else if current == Some(id) && !replaced && line.starts_with("**Status:**") {
            out.push(format!("**Status:** {}{ending}", status.as_str()));
            replaced = true;
            continue;
        }
        out.push(format!("{line}{ending}"));
    }
    if !replaced {
        return Err(format!("P{id} has no **Status:** line to rewrite"));
    }
    Ok(out.concat())
}

/// `(id)` from a `P<n> · <title>` heading; the separator is permissive, same as the parser.
fn section_id(heading: &str) -> Option<u32> {
    let rest = heading
        .strip_prefix('P')
        .or_else(|| heading.strip_prefix('p'))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Why this slice was or was not offered.
fn describe_readiness(library: &Library, prompt: &Prompt) -> String {
    match advisor::readiness(library, prompt) {
        Readiness::Ready => "ready".to_owned(),
        Readiness::Deferred => "deferred — started or held by a person".to_owned(),
        Readiness::Finished => "done".to_owned(),
        Readiness::WaitingOn(ids) => format!(
            "waiting on {}",
            join_or(ids.iter().map(|id| format!("P{id}")))
        ),
    }
}

fn join_or(values: impl Iterator<Item = String>) -> String {
    let joined: Vec<String> = values.collect();
    if joined.is_empty() {
        "nothing".to_owned()
    } else {
        joined.join(", ")
    }
}

/// When the slice was last handed out, or that it never was.
fn describe_history(ledger: &Ledger, id: u32) -> String {
    match ledger.history(id) {
        Some((at, times)) => format!("{at} ({times} time(s))"),
        None => "never".to_owned(),
    }
}

/// The empty-ready causes with their fixes — ledger withholding, unfilled inputs, a spent class, nothing open — reported separately, and two can hold at once.
fn nothing_to_hand_over(
    library: &Library,
    args: &Args,
    suppressed: &[u32],
    skipped: &[advisor::Skipped],
    state: &ProjectState,
    ledger: &Ledger,
    named: Option<&MethodRow>,
) -> String {
    let withheld: Vec<u32> = advisor::ranked(library, args.effort)
        .iter()
        .map(|&index| library.prompts[index].id)
        .filter(|id| suppressed.contains(id))
        .collect();
    let mut message = match named {
        Some(row) => format!(
            "nothing to hand over for row {} ({}):",
            row.key(),
            row.method
        ),
        None => String::from("nothing to hand over:"),
    };
    if let Some(row) = named {
        let drawers: Vec<String> = library
            .prompts
            .iter()
            .filter(|other| other.targets.is_matrix() && expand::row_fits(row, other.targets))
            .map(|other| format!("P{}", other.id))
            .collect();
        let _ = writeln!(
            message,
            "\n  no ready template draws it; these do: {}",
            join_capped(&drawers)
        );
    }
    if !withheld.is_empty() {
        let _ = writeln!(
            message,
            "\n  withheld by the ledger: {} — the last {} handed out; --rotate draws differently \
             and --memory 0 forgets",
            join_or(withheld.iter().map(|id| format!("P{id}"))),
            withheld.len()
        );
    }
    if !skipped.is_empty() {
        message.push_str(&skipped_retries(
            library, args, skipped, state, ledger, named,
        ));
    }
    let spent = spent_classes(library, args.effort, state, ledger);
    if !spent.is_empty() {
        let _ = writeln!(
            message,
            "\n  its class is spent: {} — every row of it has been served to that template",
            join_or(spent.iter().map(|id| format!("P{id}")))
        );
    }
    let parked = if named.is_none() {
        parked_override(library, args, state, ledger)
    } else {
        None
    };
    if let Some(guidance) = &parked {
        let _ = writeln!(message, "\n  {guidance}");
    }
    if named.is_none()
        && withheld.is_empty()
        && skipped.is_empty()
        && spent.is_empty()
        && parked.is_none()
    {
        return if let Err(reason) = advisor::next_index(library, args.effort, &[]) {
            reason
        } else {
            "no ready template draws an available row: every ready template's class \
             has no outstanding row, so name one with `--row <id>`"
                .to_owned()
        };
    }
    message
}

/// The parked override the automatic path would miss even when another prompt supplies its own reason.
fn parked_override(
    library: &Library,
    args: &Args,
    state: &ProjectState,
    ledger: &Ledger,
) -> Option<String> {
    advisor::ranked(library, args.effort)
        .into_iter()
        .find_map(|index| {
            let prompt = &library.prompts[index];
            if !prompt.targets.is_matrix() {
                return None;
            }
            let served = ledger.targets_for(prompt.id);
            state
                .candidates(prompt.targets)
                .iter()
                .any(|row| !row.gap.is_drawable() && !served.contains(&row.key()))
                .then_some(no_retry_row(prompt, state, &served))
        })
}

/// Each skipped slice with the command that fixes it, or the reason no drawable row is left.
fn skipped_retries(
    library: &Library,
    args: &Args,
    skipped: &[advisor::Skipped],
    state: &ProjectState,
    ledger: &Ledger,
    named: Option<&MethodRow>,
) -> String {
    let values = requested_values(args);
    let mut message = String::from("\n  waiting on a decision this tool will not make:");
    for slice in skipped {
        if let Some(problem) = &slice.problem {
            let _ = writeln!(message, "\n    P{}: {problem}", slice.id);
            continue;
        }
        let missing = slice.missing.clone();
        let prompt = library
            .prompt(slice.id)
            .expect("a skipped id is a prompt id");
        let served = ledger.targets_for(prompt.id);
        let addons = render::resolve_addons(prompt, &args.addons).unwrap_or_default();
        let row_key =
            advisor::retry_row(prompt, state, &served, named, &addons, &values).map(MethodRow::key);
        if prompt.targets.is_matrix()
            && row_key.is_none()
            && !state.candidates(prompt.targets).is_empty()
        {
            let _ = writeln!(
                message,
                "\n    P{} needs {} — {}",
                slice.id,
                join_or(missing.iter().map(|name| format!("`{name}`"))),
                no_retry_row(prompt, state, &served)
            );
            continue;
        }
        let repeat = row_key.as_ref().is_some_and(|key| served.contains(key));
        let _ = write!(
            message,
            "\n    P{} needs {} — {}",
            slice.id,
            join_or(missing.iter().map(|name| format!("`{name}`"))),
            render::suggested_command(
                prompt,
                &missing,
                &values,
                &addons,
                &args.addons,
                retry_library_path(args, library).as_deref(),
                row_key.as_deref(),
                !args.record
            )
        );
        if repeat {
            let _ = write!(
                message,
                "\n      row {} was already served; naming it repeats that row",
                row_key.as_deref().unwrap_or_default()
            );
        }
        message.push('\n');
    }
    message
}

/// Why a skipped slice has no row to retry, naming a parked row the caller can still choose.
fn no_retry_row(prompt: &Prompt, state: &ProjectState, served: &[String]) -> String {
    let parked = state
        .candidates(prompt.targets)
        .iter()
        .copied()
        .find(|row| !row.gap.is_drawable() && !served.contains(&row.key()));
    parked.map_or_else(
        || format!("no {} row exists", prompt.targets.as_str()),
        |row| {
            format!(
                "no drawable {} row remains; name one with `--row {}` if you mean it",
                prompt.targets.as_str(),
                row.key()
            )
        },
    )
}

/// The templates whose class has no row left, so the advisor walks past them.
fn spent_classes(
    library: &Library,
    effort: Option<Effort>,
    state: &ProjectState,
    ledger: &Ledger,
) -> Vec<u32> {
    library
        .prompts
        .iter()
        .filter(|prompt| {
            prompt.targets.is_matrix()
                && advisor::readiness(library, prompt) == Readiness::Ready
                && effort.is_none_or(|wanted| prompt.effort == wanted)
                && expand::is_fillable(prompt, state)
        })
        .filter(|prompt| {
            // A class with no row at all is empty, not spent; only a class whose every row was served is spent.
            let rows = state.candidates(prompt.targets);
            let served = ledger.targets_for(prompt.id);
            !rows.is_empty() && rows.iter().all(|row| served.contains(&row.key()))
        })
        .map(|prompt| prompt.id)
        .collect()
}

/// Why a matrix template has no row: every row was served, every unserved row is parked, or no row supplies the selected inputs.
fn no_target_reason(
    args: &Args,
    library: &Library,
    prompt: &Prompt,
    state: &ProjectState,
    ledger: &Ledger,
    addons: &[Addon],
    supplied: &Values,
) -> String {
    let rows = state.candidates(prompt.targets);
    let served = ledger.targets_for(prompt.id);
    if !rows.is_empty() && rows.iter().all(|row| served.contains(&row.key())) {
        return class_spent(library, prompt, state, ledger);
    }
    let Some(row) = rows
        .into_iter()
        .find(|row| row.gap.is_drawable() && !served.contains(&row.key()))
    else {
        return no_retry_row(prompt, state, &served);
    };
    let missing = advisor::missing_inputs(
        prompt,
        addons,
        advisor::Inputs::new(supplied, Some(row)),
        state,
        &served,
    );
    if missing.is_empty() {
        return format!(
            "P{} has no drawable {} row: the unserved rows are not scheduled",
            prompt.id,
            prompt.targets.as_str()
        );
    }
    format!(
        "P{} has an unserved {} row but needs {} — {}",
        prompt.id,
        prompt.targets.as_str(),
        join_or(missing.iter().map(|name| format!("`{name}`"))),
        render::suggested_command(
            prompt,
            &missing,
            supplied,
            addons,
            &args.addons,
            retry_library_path(args, library).as_deref(),
            Some(row.key().as_str()),
            !args.record
        )
    )
}

/// Every row of a template's class has been served to it; the way on is a row named by hand.
fn class_spent(
    library: &Library,
    prompt: &Prompt,
    state: &ProjectState,
    ledger: &Ledger,
) -> String {
    let served = ledger.targets_for(prompt.id).len();
    let first = state
        .candidates(prompt.targets)
        .first()
        .map(|row| row.key())
        .unwrap_or_default();
    let others: Vec<String> = library
        .prompts
        .iter()
        .filter(|other| other.id != prompt.id && other.targets.is_matrix())
        .map(|other| format!("P{}", other.id))
        .collect();
    format!(
        "P{} has no {} row left: the ledger served {} to it; name one with `--row {}` to render it \
         again, or use a template that draws another class: {}",
        prompt.id,
        prompt.targets.as_str(),
        served,
        first,
        join_or(others.into_iter())
    )
}

/// One line per left-out slice: its add-on problem when it has one, else the inputs it still needs.
fn skipped_reasons(skipped: &[advisor::Skipped]) -> String {
    skipped
        .iter()
        .map(|slice| match &slice.problem {
            Some(problem) => format!("P{}: {problem}", slice.id),
            None => slice
                .missing
                .iter()
                .map(|name| format!("{name} for P{}", slice.id))
                .collect::<Vec<_>>()
                .join(", "),
        })
        .filter(|reason| !reason.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The reasoning, printed above the prompt so it is read before it is obeyed.
fn report_next(
    library: &Library,
    prompt: &Prompt,
    root: &Path,
    ledger: &Ledger,
    skipped: &[advisor::Skipped],
    args: &Args,
    addons: &[Addon],
) {
    let suppressed = if args.row.is_some() {
        Vec::new()
    } else {
        ledger.recent_ids(args.memory)
    };
    let ready = advisor::ranked(library, args.effort);
    let place = ready
        .iter()
        .position(|&index| library.prompts[index].id == prompt.id);
    println!("NEXT SLICE  P{} · {}", prompt.id, prompt.title);
    println!(
        "WHY NOW     leverage {}, effort {} — {}",
        prompt.leverage,
        prompt.effort.as_str(),
        match place {
            Some(0) => format!("first of {} ready, by leverage then by effort", ready.len()),
            Some(at) => format!("{} of {} ready", at + 1, ready.len()),
            None => "asked for by id, so the ranking does not apply".to_owned(),
        }
    );
    println!(
        "OPENS       {}",
        join_or(prompt.blocks(library).map(|other| format!("P{}", other.id)))
    );
    println!(
        "WAITING ON  {}",
        join_or(
            prompt
                .depends_on
                .iter()
                .filter(|id| {
                    library
                        .prompt(**id)
                        .is_some_and(|dependency| dependency.status != Status::Done)
                })
                .map(|id| format!("P{id}"))
        )
    );
    let overlaps = overlaps(library, prompt, root);
    if !overlaps.is_empty() {
        println!("OVERLAPS    {}", overlaps.join(", "));
    }
    if args.draw == Draw::Rotate {
        println!(
            "DRAW        --rotate with seed {} — random among ready slices, weighted by the library",
            args.seed
        );
    }
    println!(
        "SUPPRESSED  {}",
        if !suppressed.is_empty() {
            suppressed
                .iter()
                .map(|&id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        } else if args.row.is_some() {
            "nothing; a named row is asked for on purpose".to_owned()
        } else {
            "nothing; the ledger is empty or --memory is 0".to_owned()
        }
    );
    if !skipped.is_empty() {
        println!(
            "LEFT OUT    {} — ready, but waiting on a decision: {}",
            skipped
                .iter()
                .map(|slice| format!("P{}", slice.id))
                .collect::<Vec<_>>()
                .join(", "),
            skipped_reasons(skipped)
        );
    }
    println!("LAST DRAWN  {}", describe_history(ledger, prompt.id));
    println!(
        "ADD-ONS     {}",
        join_or(addons.iter().map(|addon| addon.slug.clone()))
    );
    println!("ACCEPTANCE  {}", prompt.gates.join("  ·  "));
    println!();
    println!("---");
    println!();
}

/// Counts, and what is waiting on what.
fn summarise(library: &Library, effort: Option<Effort>) {
    let ready = advisor::ranked(library, effort);
    let mut counts = [0usize; 4];
    for prompt in &library.prompts {
        counts[match prompt.status {
            Status::Todo => 0,
            Status::Doing => 1,
            Status::Blocked => 2,
            Status::Done => 3,
        }] += 1;
    }
    let zero_weight = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open() && prompt.random_weight == 0)
        .count();
    println!();
    println!(
        "todo {} · doing {} · blocked {} · done {} · ready {}{}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        ready.len(),
        if zero_weight == 0 {
            String::new()
        } else {
            format!(" · {zero_weight} kept out of rotation by weight 0")
        }
    );
    let waiting: Vec<String> = library
        .prompts
        .iter()
        .filter_map(|prompt| match advisor::readiness(library, prompt) {
            Readiness::WaitingOn(ids) => Some(format!(
                "P{} on {}",
                prompt.id,
                ids.iter()
                    .map(|id| format!("P{id}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ => None,
        })
        .collect();
    if !waiting.is_empty() {
        println!("waiting     {}", waiting.join(" · "));
    }
    let ready_ids: Vec<String> = ready
        .iter()
        .map(|&index| format!("P{}", library.prompts[index].id))
        .collect();
    if !ready_ids.is_empty() {
        println!("ready       {} in this order", ready_ids.join(" → "));
    }
}

/// Print the fill-in guide so a clipboard handoff still explains what was chosen and how to change it.
fn report_render_guide(
    prompt: &Prompt,
    target: Option<&(&MethodRow, Values)>,
    values: &Values,
    state: &ProjectState,
    addons: &[Addon],
) {
    println!("P{} · {}", prompt.id, prompt.title);
    if let Some((row, _)) = target {
        println!(
            "  targeting   row {} — {} (state: {})",
            row.key(),
            row.method,
            row.state
        );
    }
    if !values.is_empty() {
        println!(
            "  filled      {}",
            values
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !prompt.addons.is_empty() {
        let selected: Vec<&str> = addons.iter().map(|a| a.slug.as_str()).collect();
        let available: Vec<String> = prompt
            .addons
            .iter()
            .map(|a| {
                if selected.contains(&a.slug.as_str()) {
                    format!("[{}]", a.slug)
                } else {
                    a.slug.clone()
                }
            })
            .collect();
        println!(
            "  add-ons     {} (bracketed = included)",
            available.join(", ")
        );
    }
    if state.has_matrix() && prompt.targets.is_matrix() {
        let candidates = state.candidates(prompt.targets);
        if candidates.len() > 1 {
            let keys: Vec<String> = candidates.iter().take(5).map(|row| row.key()).collect();
            println!(
                "  alternatives {} rows in class {}; pick one with --row <key> — {}",
                candidates.len(),
                prompt.targets.as_str(),
                keys.join(", "),
            );
        }
    }
    println!("  override    re-run with --set KEY=VALUE to replace any filled value");
    if !prompt.addons.is_empty() {
        println!(
            "  example     cargo run -p ferrox-prompt -- render {} --addon {} --row <key>",
            prompt.id, prompt.addons[0].slug
        );
    }
    println!();
}

/// Hand the text over: the clipboard, or the terminal when asked or unable to.
fn deliver(rendered: &Rendered, library: &Library, id: u32, print: bool) {
    if print {
        println!("{}", rendered.text);
        return;
    }
    match clipboard::copy(&rendered.text) {
        Ok(()) => {
            let note = if rendered.missing.is_empty() {
                String::new()
            } else {
                format!(" with {} input(s) unfilled", rendered.missing.len())
            };
            let chars = rendered.text.chars().count();
            println!(
                "P{id} copied ({chars} chars{note}) from {}",
                library.path.display()
            );
        }
        Err(reason) => {
            eprintln!("clipboard unavailable ({reason}); printing instead:");
            println!("{}", rendered.text);
        }
    }
}

/// Write a finished document before recording it, so a closed pipe cannot leave a ledger entry for a handout nobody saw.
fn emit_json(json: &str) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(json.as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()
}

/// The lock beside the file it protects: every writer of this state, and only they, take the same lock.
fn lock_path(path: &Path) -> PathBuf {
    let path = lock_identity(path);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(|| "state".into(), std::ffi::OsStr::to_os_string);
    let mut lock = std::ffi::OsString::from(".");
    lock.push(name);
    lock.push(".ferrox-lock");
    parent.join(lock)
}

/// The path a lock names, following a final symlink even while it dangles, so creation cannot switch identities.
fn lock_identity(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    for _ in 0..32 {
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
    let parent = resolved(current.parent().unwrap_or_else(|| Path::new(".")));
    current
        .file_name()
        .map_or(parent.clone(), |name| parent.join(name))
}

/// Canonicalize the part of a path that exists, so creating a missing directory cannot change its identity.
fn resolved(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut trailing = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        trailing.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    let mut base = std::fs::canonicalize(existing).unwrap_or_else(|_| existing.to_path_buf());
    for name in trailing.iter().rev() {
        base.push(name);
    }
    base
}

/// A handout that is not recorded needs no write access to the ledger's directory.
fn lock_if_recording(record: bool, path: &Path) -> Result<Option<std::fs::File>, ()> {
    if !record {
        return Ok(None);
    }
    lock_state(path).map(Some).map_err(|_| ())
}

/// Serialise writers to one state file, so two `next` runs cannot hand out the same row or a
/// `set-status` cannot overwrite an update it read before the lock.
fn lock_state(path: &Path) -> Result<std::fs::File, String> {
    let lock = lock_path(path);
    if let Some(parent) = lock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock)
        .map_err(|error| {
            let message = format!(
                "could not lock {}: {error}; nothing was written",
                lock.display()
            );
            eprintln!("{message}");
            message
        })?;
    for _ in 0..200 {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                let message = format!(
                    "could not lock {}: {error}; nothing was written",
                    lock.display()
                );
                eprintln!("{message}");
                return Err(message);
            }
        }
    }
    let message = format!(
        "timed out waiting for {}; nothing was written",
        lock.display()
    );
    eprintln!("{message}");
    Err(message)
}

/// Stage the new text beside the library, then replace it in one step, so a reader sees the old
/// text or the new one, never a half-written file.
fn replace_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let temp = path.with_extension(format!("tmp-{}-{stamp}", std::process::id()));
    let backup = path.with_extension(format!("bak-{}-{stamp}", std::process::id()));
    #[cfg(not(windows))]
    let metadata = std::fs::metadata(path).ok();
    #[cfg(not(windows))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(&temp)?
    };
    #[cfg(windows)]
    let mut file = create_staged(&temp)?;
    // Set the library's own owner, mode and ACL before any text lands, so an inherited grant cannot read it.
    #[cfg(target_os = "linux")]
    if let Some(metadata) = &metadata {
        if let Err(error) = stage_permissions(metadata, path, &temp) {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    if let Some(metadata) = &metadata {
        if let Err(error) = preserve_owner(metadata, &temp) {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        if let Err(error) = std::fs::set_permissions(&temp, metadata.permissions()) {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
    }
    #[cfg(target_os = "macos")]
    if metadata.is_some() {
        preserve_acl(path, &temp).inspect_err(|_| {
            let _ = std::fs::remove_file(&temp);
        })?;
    }
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = replace_path(&temp, path, &backup) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

/// A staging file only its owner can open, created with that DACL in one step so an inherited
/// write grant never reaches it.
#[cfg(windows)]
fn create_staged(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use std::ptr;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            attributes: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl = wide("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)");
    let mut descriptor = ptr::null_mut();
    // SAFETY: the SDDL and path are NUL-terminated wide strings; the descriptor is freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let attributes = SecurityAttributes {
        length: u32::try_from(std::mem::size_of::<SecurityAttributes>()).unwrap_or(u32::MAX),
        descriptor,
        inherit: 0,
    };
    // SAFETY: the descriptor and path outlive the call; CREATE_NEW refuses an existing name.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x4000_0000,
            0,
            &attributes,
            1,
            0x80,
            ptr::null_mut(),
        )
    };
    // SAFETY: this is the same allocation ConvertString... returned.
    unsafe {
        LocalFree(descriptor);
    }
    if handle == -1isize as *mut c_void {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned an owned handle and File is the only owner.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// Keep the owner, group, mode and access ACL, so a staged update is not broader than the library.
#[cfg(target_os = "linux")]
fn stage_permissions(source: &std::fs::Metadata, from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::ptr;

    const ACL: &[u8] = b"system.posix_acl_access\0";
    const NO_DATA: i32 = 61;
    const NOT_SUPPORTED: i32 = 95;

    extern "C" {
        fn getxattr(
            path: *const c_char,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
        ) -> isize;
        fn setxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const c_void,
            size: usize,
            flags: c_int,
        ) -> c_int;
    }

    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to_name = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    preserve_owner(source, to)?;
    // SAFETY: the path is NUL-terminated, and the ACL buffer is sized from the kernel's reply.
    unsafe {
        let size = getxattr(from.as_ptr(), ACL.as_ptr().cast(), ptr::null_mut(), 0);
        if size < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(NO_DATA | NOT_SUPPORTED)) {
                return std::fs::set_permissions(to, source.permissions());
            }
            return Err(error);
        }
        let mut value = vec![0_u8; size as usize];
        let read = getxattr(
            from.as_ptr(),
            ACL.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        );
        if read != size {
            return Err(if read < 0 {
                std::io::Error::last_os_error()
            } else {
                std::io::Error::from(std::io::ErrorKind::InvalidData)
            });
        }
        if setxattr(
            to_name.as_ptr(),
            ACL.as_ptr().cast(),
            value.as_ptr().cast(),
            value.len(),
            0,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Copy the access ACL from the library to the staged file, so an inherited grant cannot read the update.
#[cfg(target_os = "macos")]
fn preserve_acl(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::ptr;

    const COPYFILE_ACL: c_int = 1;

    extern "C" {
        fn copyfile(
            from: *const c_char,
            to: *const c_char,
            state: *mut c_void,
            flags: c_int,
        ) -> c_int;
    }

    let from_name = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to_name = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both paths are NUL-terminated; a null state is accepted by copyfile.
    if unsafe {
        copyfile(
            from_name.as_ptr(),
            to_name.as_ptr(),
            ptr::null_mut(),
            COPYFILE_ACL,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Keep the owner and group of a staged update, so restoring the mode cannot widen access.
#[cfg(unix)]
fn preserve_owner(source: &std::fs::Metadata, to: &Path) -> std::io::Result<()> {
    use std::ffi::{c_char, CString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    extern "C" {
        fn chown(path: *const c_char, owner: u32, group: u32) -> i32;
    }

    let to_name = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: the path is NUL-terminated and the ids come from the source file's metadata.
    if unsafe { chown(to_name.as_ptr(), source.uid(), source.gid()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_path(from: &Path, to: &Path, _backup: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

/// ReplaceFileW keeps the library's access rules while swapping in the staged text.
#[cfg(windows)]
fn replace_path(from: &Path, to: &Path, backup: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut core::ffi::c_void,
            reserved: *mut core::ffi::c_void,
        ) -> i32;
    }

    let wide = |path: &Path| -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let replaced = wide(to);
    let replacement = wide(from);
    let backup_name = wide(backup);
    // SAFETY: every name is a NUL-terminated wide string; the optional trailing pointers are null.
    let replaced_ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            backup_name.as_ptr(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if replaced_ok != 0 {
        let _ = std::fs::remove_file(backup);
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if !to.exists() {
        if let Err(restore) = std::fs::rename(backup, to) {
            if backup.exists() {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; the original library is at {} ({restore})",
                        backup.display()
                    ),
                ));
            }
            return Err(error);
        }
    } else {
        let _ = std::fs::remove_file(backup);
    }
    Err(error)
}

/// Record the handout; an unwritable ledger is a warning, not a failure — the prompt was handed over.
fn record(mut ledger: Ledger, id: u32, how: &str, target: Option<&str>, enabled: bool) {
    if !enabled {
        return;
    }
    if let Err(error) = ledger.record(id, how, target) {
        eprintln!(
            "warning: could not write {}: {error}",
            ledger.path.display()
        );
    }
}

/// How this handout was asked for, for the ledger.
fn how_asked(args: &Args) -> String {
    match args.command {
        Command::Next if args.row.is_some() => "next --row".to_owned(),
        Command::Next if args.draw == Draw::Rotate => "next --rotate".to_owned(),
        Command::Next => "next".to_owned(),
        Command::Render if args.row.is_some() => "render --row".to_owned(),
        Command::Render => "render".to_owned(),
        Command::Issue => "issue".to_owned(),
        _ => "show".to_owned(),
    }
}

/// Files another prompt the advisor could pick right now claims — same availability rule as `check`, so the line means "both in play".
fn overlaps(library: &Library, prompt: &Prompt, root: &Path) -> Vec<String> {
    check::contention(library, prompt, root)
        .iter()
        .map(|clash| {
            let others: Vec<String> = clash.also.iter().map(|id| format!("P{id}")).collect();
            format!("{} (also {})", clash.path, others.join(", "))
        })
        .collect()
}

/// Paths, marked with whether they are there.
fn describe_touches(prompt: &Prompt, root: &Path) -> String {
    prompt
        .touches
        .iter()
        .map(|touch| {
            let present = root.join(touch.path()).exists();
            match touch {
                Touch::Existing(_) => format!(
                    "{}{}",
                    touch.path(),
                    if present { "" } else { " (missing)" }
                ),
                Touch::Created(_) => format!(
                    "+{}{}",
                    touch.path(),
                    if present { " (already there)" } else { "" }
                ),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The choices, for when there is no choice to make.
fn unknown_prompt(library: &Library, id: u32) -> String {
    let available: Vec<String> = library
        .prompts
        .iter()
        .map(|prompt| format!("P{}", prompt.id))
        .collect();
    format!(
        "no P{id} in {}; it has {}",
        library.path.display(),
        available.join(", ")
    )
}

/// Ready ids, for `--json`.
fn ready_json(library: &Library, effort: Option<Effort>) -> Value {
    Value::List(
        advisor::ranked(library, effort)
            .iter()
            .map(|&index| Value::Number(i64::from(library.prompts[index].id)))
            .collect(),
    )
}

/// Everything about one prompt that another tool might want.
fn prompt_json(prompt: &Prompt, ledger: &Ledger) -> Value {
    Value::object([
        ("id", Value::Number(i64::from(prompt.id))),
        ("title", Value::text(prompt.title.clone())),
        ("status", Value::text(prompt.status.as_str())),
        ("leverage", Value::Number(i64::from(prompt.leverage))),
        ("effort", Value::text(prompt.effort.as_str())),
        ("when_to_use", Value::text(prompt.when_to_use.clone())),
        (
            "gates",
            Value::List(
                prompt
                    .gates
                    .iter()
                    .map(|gate| Value::text(gate.clone()))
                    .collect(),
            ),
        ),
        (
            "depends_on",
            Value::List(
                prompt
                    .depends_on
                    .iter()
                    .map(|&id| Value::Number(i64::from(id)))
                    .collect(),
            ),
        ),
        (
            "touches",
            Value::List(
                prompt
                    .touches
                    .iter()
                    .map(|touch| {
                        Value::text(match touch {
                            Touch::Existing(path) => path.clone(),
                            Touch::Created(path) => format!("+{path}"),
                        })
                    })
                    .collect(),
            ),
        ),
        (
            "random_weight",
            Value::Number(i64::from(prompt.random_weight)),
        ),
        ("targets", Value::text(prompt.targets.as_str())),
        (
            "placeholders",
            Value::List(
                prompt
                    .placeholders
                    .iter()
                    .map(|placeholder| {
                        Value::object([
                            ("name", Value::text(placeholder.name.clone())),
                            (
                                "default",
                                match &placeholder.default {
                                    Some(default) => Value::text(default.clone()),
                                    None => Value::Null,
                                },
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "addons",
            Value::List(
                prompt
                    .addons
                    .iter()
                    .map(|addon| {
                        Value::object([
                            ("slug", Value::text(addon.slug.clone())),
                            ("title", Value::text(addon.title.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "last_drawn",
            match ledger.history(prompt.id) {
                Some((at, _)) => Value::text(at),
                None => Value::Null,
            },
        ),
    ])
}

/// Why this slice was chosen, for `--json`.
fn selection_json(
    library: &Library,
    prompt: &Prompt,
    args: &Args,
    suppressed: &[u32],
    skipped: &[advisor::Skipped],
) -> Value {
    let ready = advisor::ranked(library, args.effort);
    let rank = ready
        .iter()
        .position(|&index| library.prompts[index].id == prompt.id)
        .map_or(0, |at| at + 1);
    let count = |value: usize| Value::Number(i64::try_from(value).unwrap_or(i64::MAX));
    let shown = args.command == Command::Show;
    let rotated = !shown && args.forced.is_none() && args.draw == Draw::Rotate;
    Value::object([
        (
            "reason",
            Value::text(if shown {
                "shown by id"
            } else {
                match (args.forced, args.draw) {
                    (Some(id), _) if id == prompt.id => "asked for by id",
                    _ if args.draw == Draw::Rotate => {
                        "rotated among ready slices, weighted by the library"
                    }
                    _ => "highest leverage, then the smaller slice",
                }
            }),
        ),
        ("rank", count(rank)),
        ("ready_count", count(ready.len())),
        (
            "seed",
            if rotated {
                Value::Unsigned(args.seed)
            } else {
                Value::Null
            },
        ),
        (
            "suppressed",
            Value::List(
                suppressed
                    .iter()
                    .map(|&id| Value::Number(i64::from(id)))
                    .collect(),
            ),
        ),
        (
            "left_out",
            Value::List(
                skipped
                    .iter()
                    .map(|slice| {
                        Value::object([
                            ("id", Value::Number(i64::from(slice.id))),
                            (
                                "missing",
                                Value::List(
                                    slice
                                        .missing
                                        .iter()
                                        .map(|name| Value::text(name.clone()))
                                        .collect(),
                                ),
                            ),
                            (
                                "problem",
                                slice
                                    .problem
                                    .as_ref()
                                    .map_or(Value::Null, |problem| Value::text(problem.clone())),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "opens",
            Value::List(
                prompt
                    .blocks(library)
                    .map(|other| Value::Number(i64::from(other.id)))
                    .collect(),
            ),
        ),
        (
            "readiness",
            Value::text(match advisor::readiness(library, prompt) {
                Readiness::Ready => "ready",
                Readiness::Deferred => "deferred",
                Readiness::Finished => "done",
                Readiness::WaitingOn(_) => "waiting",
            }),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_library_names_its_own_workspace() {
        let base = std::env::temp_dir().join(format!(
            "ferrox-prompt-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let root = base.join("original");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(root.join(LIBRARY_RELATIVE).parent().expect("parent"))
            .expect("root");
        std::fs::write(root.join(LIBRARY_RELATIVE), "## P1 · One").expect("library");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");
        let given = root.join(LIBRARY_RELATIVE);
        let args = parse_args(&["render", "P1", "--library", given.to_str().expect("utf8")]);
        assert_eq!(workspace_root_for(&args, &elsewhere), root);

        let relative = Path::new("..")
            .join(root.strip_prefix(&base).expect("root under base"))
            .join(LIBRARY_RELATIVE);
        let args = parse_args(&[
            "render",
            "P1",
            "--library",
            relative.to_str().expect("utf8"),
        ]);
        assert_eq!(
            std::fs::canonicalize(workspace_root_for(&args, &elsewhere)).expect("canonical root"),
            std::fs::canonicalize(&root).expect("canonical expected root")
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn an_external_library_without_a_workspace_uses_the_cwd_workspace() {
        let base = std::env::temp_dir().join(format!(
            "ferrox-prompt-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let root = base.join("checkout");
        let external = base.join("external");
        std::fs::create_dir_all(root.join(LIBRARY_RELATIVE).parent().expect("parent"))
            .expect("root");
        std::fs::write(root.join(LIBRARY_RELATIVE), "## P1 · One").expect("library");
        std::fs::create_dir_all(&external).expect("external");
        let given = external.join("draft.md");
        std::fs::write(&given, "## P1 · One").expect("draft");
        let args = parse_args(&["render", "P1", "--library", given.to_str().expect("utf8")]);
        assert_eq!(workspace_root_for(&args, &root), root);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_retry_reopens_the_library_at_its_resolved_absolute_path() {
        let args = parse(&[
            "render".to_owned(),
            "P1".to_owned(),
            "--library".to_owned(),
            "draft.md".to_owned(),
        ])
        .unwrap();
        let mut library = Library::parse(Path::new("prompts.md"), LIBRARY);
        library.source_path = std::env::temp_dir().join("draft.md");
        assert_eq!(
            retry_library_path(&args, &library),
            Some(std::env::temp_dir().join("draft.md"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_retry_keeps_the_utf8_alias_of_a_non_utf8_library() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "ferrox-prompt-retry-alias-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("real.md");
        std::fs::write(&target, LIBRARY).expect("target");
        let link = dir.join("alias.md");
        symlink(&target, &link).expect("link");
        let args = parse(&[
            "render".to_owned(),
            "P1".to_owned(),
            "--library".to_owned(),
            link.to_str().expect("utf8 alias").to_owned(),
        ])
        .unwrap();
        let mut library = load_library(Some(&link), &dir).expect("loads");
        // macOS cannot put invalid UTF-8 on disk, but a path from another mount still can.
        library.source_path = dir.join(OsString::from_vec(b"real-\x80.md".to_vec()));
        assert_eq!(retry_library_path(&args, &library), Some(link));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A library with one template per target class, so the class rules can be read off a row.
    const LIBRARY: &str = "\
## Shared protocol

```text
p
```

## P1 · Land an open row

**When to use:** an open row
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** open
**Gates:** `cargo test`

```text
implement {method}
```

## P2 · Tune a shipped row

**When to use:** a shipped row
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test`

```text
tune {method}
```

## P3 · A fixed slice

**When to use:** no row at all
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** none
**Gates:** `cargo test`

```text
do the fixed thing
```

## P4 · Fix an issue

**When to use:** an open P0 or P1 regression
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** none
**Gates:** `cargo test`

```text
fix issue #{issue} at {priority=P0 or P1} priority
```
";

    fn library() -> Library {
        Library::parse(Path::new("prompts.md"), LIBRARY)
    }

    fn row(section: char, index: &str, method: &str, implemented: bool) -> MethodRow {
        MethodRow {
            section,
            index: index.to_owned(),
            method: method.to_owned(),
            state: if implemented {
                "implemented"
            } else {
                "planned"
            }
            .to_owned(),
            implemented,
            gap: ferrox_prompt::state::gap_of(if implemented {
                "implemented"
            } else {
                "planned"
            }),
            high_priority: false,
            page: "docs/function/method.md".to_owned(),
            real_page: false,
            text: format!("| {index} | {method} | planned |"),
        }
    }

    fn parse_args(arguments: &[&str]) -> Args {
        let owned: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        parse(&owned).unwrap_or_else(|error| panic!("`{arguments:?}` should parse: {error}"))
    }

    #[test]
    fn a_bare_invocation_asks_for_help() {
        assert_eq!(parse_args(&[]).command, Command::Help);
    }

    #[test]
    fn json_wins_over_print_in_either_order() {
        assert_eq!(
            parse_args(&["list", "--print", "--json"]).output,
            Output::Json
        );
        assert_eq!(
            parse_args(&["list", "--json", "--print"]).output,
            Output::Json
        );
    }

    #[test]
    fn verbs_and_ids_parse_in_both_spellings() {
        assert_eq!(parse_args(&["next"]).command, Command::Next);
        assert_eq!(parse_args(&["render", "P2"]).id, Some(2));
        assert_eq!(parse_args(&["render", "7"]).id, Some(7));
        assert_eq!(parse_args(&["render", "--prompt", "p9"]).id, Some(9));
        assert_eq!(parse_args(&["show", "3"]).command, Command::Show);
        assert_eq!(parse_args(&["ls"]).command, Command::List);
        assert_eq!(parse_args(&["rows"]).command, Command::Rows);
        assert_eq!(parse_args(&["issue", "661"]).command, Command::Issue);
        assert_eq!(parse_args(&["issue", "#661"]).issue, Some(661));
        assert_eq!(
            parse_args(&["render", "P4", "--issue", "661"]).issue,
            Some(661)
        );
    }

    #[test]
    fn the_issue_command_finds_its_template_and_names_the_bugfix_worktree() {
        let library = library();
        let prompt = issue_prompt(&library).expect("the P4 issue template");
        assert_eq!(prompt.id, 4);
        let values = requested_values(&parse_args(&["issue", "661"]));
        assert_eq!(values["issue"], "661");
        let scratch = std::env::temp_dir().join(format!(
            "ferrox-prompt-issue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let root = scratch.join("ferrox");
        std::fs::create_dir_all(&root).expect("scratch root");
        let worktree = slice_worktree(prompt, None, &values, &root);
        assert_eq!(worktree.name, "bugfix-661");
        assert!(worktree
            .brief()
            .contains("./scripts/new-worktree.sh bugfix-661"));
        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn a_method_override_does_not_rename_the_rows_worktree() {
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        let row = row('A', "13", "VLESS over QUIC", false);
        let mut values = Values::new();
        values.insert("method".to_owned(), "QUIC test".to_owned());
        let target = Some((&row, values.clone()));
        let scratch = std::env::temp_dir().join(format!(
            "ferrox-prompt-row-name-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let root = scratch.join("ferrox");
        std::fs::create_dir_all(&root).expect("scratch root");
        let worktree = slice_worktree(prompt, target.as_ref(), &values, &root);
        assert_eq!(worktree.name, "p1-vless-over-quic--a13");
        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn a_row_is_named_by_whatever_the_user_knows() {
        assert_eq!(
            parse_args(&["render", "P1", "--row", "A13"]).row.as_deref(),
            Some("A13")
        );
        assert_eq!(
            parse_args(&["render", "P1", "--row=13"]).row.as_deref(),
            Some("13")
        );
        assert_eq!(
            parse_args(&["next", "--row", "quic"]).row.as_deref(),
            Some("quic")
        );
        assert_eq!(parse_args(&["rows"]).row, None);
    }

    #[test]
    fn a_row_outside_the_template_class_is_refused_by_name() {
        let library = library();
        let open = library.prompt(1).unwrap();
        let shipped = library.prompt(2).unwrap();
        let fixed = library.prompt(3).unwrap();
        let shipped_row = row('A', "3", "VLESS TCP none", true);
        let open_row = row('A', "13", "VLESS over QUIC", false);

        // The template that wants the row takes it.
        assert!(row_fits_template(shipped, &shipped_row, &library).is_ok());
        assert!(row_fits_template(open, &open_row, &library).is_ok());
        // The one that does not is refused, and the refusal names the templates that do.
        let refusal = row_fits_template(open, &shipped_row, &library).unwrap_err();
        assert!(refusal.contains("A3"), "{refusal}");
        assert!(refusal.contains("is shipped"), "{refusal}");
        assert!(refusal.contains("P2"), "{refusal}");
        // A fixed slice draws no row at all, so `--row` has nothing to fill.
        let fixed_refusal = row_fits_template(fixed, &open_row, &library).unwrap_err();
        assert!(
            fixed_refusal.contains("does not draw from the matrix"),
            "{fixed_refusal}"
        );
    }

    #[test]
    fn a_long_list_of_drawers_is_capped_but_counted() {
        let ids: Vec<String> = (1..=10).map(|id| format!("P{id}")).collect();
        let capped = join_capped(&ids);
        assert!(capped.contains("P8"), "{capped}");
        assert!(capped.contains("+2 more"), "{capped}");
        assert_eq!(join_capped(&ids[..3]), "P1, P2, P3");
    }

    #[test]
    fn a_spent_class_says_so_and_names_a_row_to_render() {
        let library = library();
        let state = ferrox_prompt::expand::ProjectState {
            methods: vec![row('A', "13", "VLESS over QUIC", false)],
            pins: Vec::new(),
        };
        let mut path = std::env::temp_dir();
        path.push(format!("ferrox-prompt-spent-{}.log", std::process::id()));
        std::fs::write(&path, "2026-10-02T00:00:00Z P1 next t=A13\n").expect("write the ledger");
        let ledger = Ledger::load(path.clone());
        let prompt = library.prompt(1).expect("P1");
        let message = class_spent(&library, prompt, &state, &ledger);
        assert!(message.contains("no open row left"), "{message}");
        assert!(message.contains("--row A13"), "{message}");
        // And the class is reported as spent, so the advisor's silence is explained.
        assert_eq!(spent_classes(&library, None, &state, &ledger), vec![1]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_unserved_row_missing_an_addon_input_is_not_a_spent_class() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship {method}
```

**Add-on — Needs state:** uses {state}
",
        );
        let prompt = library.prompt(1).expect("P1");
        let mut row = row('A', "13", "VLESS", false);
        row.state.clear();
        let state = ProjectState {
            methods: vec![row],
            pins: Vec::new(),
        };
        let addons = render::resolve_addons(prompt, &["needs".to_owned()]).expect("add-on");
        let args = parse_args(&["render", "P1", "--addon", "needs"]);
        let reason = no_target_reason(
            &args,
            &library,
            prompt,
            &state,
            &Ledger::default(),
            &addons,
            &Values::new(),
        );
        assert!(reason.contains("needs `state`"), "{reason}");
        assert!(!reason.contains("`method`"), "{reason}");
        assert!(!reason.contains("no open row left"), "{reason}");
    }

    #[test]
    fn an_explicit_render_refusal_names_a_parked_row() {
        let library = library();
        let mut parked = row('A', "13", "VLESS", false);
        parked.state = "not-scheduled".to_owned();
        parked.gap = Gap::NotScheduled;
        let state = ProjectState {
            methods: vec![parked],
            pins: Vec::new(),
        };
        let args = parse_args(&["render", "P1"]);
        let reason = no_target_reason(
            &args,
            &library,
            library.prompt(1).expect("P1"),
            &state,
            &Ledger::default(),
            &[],
            &Values::new(),
        );
        assert!(reason.contains("no drawable open row remains"), "{reason}");
        assert!(reason.contains("--row A13"), "{reason}");
    }

    #[test]
    fn a_spent_class_ignores_deferred_finished_and_other_effort() {
        let mut library = library();
        let state = ferrox_prompt::expand::ProjectState {
            methods: vec![row('A', "13", "VLESS over QUIC", false)],
            pins: Vec::new(),
        };
        let ledger = Ledger {
            entries: vec![advisor::Entry {
                at: "2026-10-02T00:00:00Z".to_owned(),
                id: 1,
                how: "next".to_owned(),
                target: Some("A13".to_owned()),
            }],
            ..Ledger::default()
        };
        library.prompts[0].status = Status::Doing;
        assert_eq!(
            spent_classes(&library, None, &state, &ledger),
            Vec::<u32>::new()
        );
        library.prompts[0].status = Status::Done;
        assert_eq!(
            spent_classes(&library, None, &state, &ledger),
            Vec::<u32>::new()
        );
        library.prompts[0].status = Status::Todo;
        library.prompts[0].effort = Effort::Large;
        assert_eq!(
            spent_classes(&library, Some(Effort::Medium), &state, &ledger),
            Vec::<u32>::new()
        );
        assert_eq!(
            spent_classes(&library, Some(Effort::Large), &state, &ledger),
            vec![1]
        );
    }

    #[test]
    fn equals_and_space_forms_are_the_same() {
        let spaced = parse_args(&["render", "P2", "--set", "len=40", "--seed", "7"]);
        let equals = parse_args(&["render", "P2", "--set", "len=40", "--seed=7"]);
        assert_eq!(spaced.values, equals.values);
        assert_eq!(spaced.seed, equals.seed);
    }

    #[test]
    fn every_id_in_the_usage_examples_is_parseable() {
        // Only EXAMPLES lines start with the tool name *and* a verb; the description line is prose.
        let examples: Vec<Vec<String>> = USAGE
            .lines()
            .filter(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("ferrox-prompt")
                    && words.next().is_some_and(|word| {
                        [
                            "check",
                            "list",
                            "next",
                            "render",
                            "issue",
                            "show",
                            "rows",
                            "set-status",
                        ]
                        .contains(&word)
                    })
            })
            .map(|line| line.split_whitespace().skip(1).map(str::to_owned).collect())
            .collect();
        assert!(!examples.is_empty(), "the usage block should have examples");
        for example in &examples {
            assert!(
                parse(example).is_ok(),
                "the usage example `{example:?}` does not parse"
            );
        }
    }

    #[test]
    fn bad_input_is_rejected_with_a_reason() {
        let owned =
            |words: &[&str]| -> Vec<String> { words.iter().map(|w| (*w).to_owned()).collect() };
        assert!(parse(&owned(&["render", "two"])).is_err());
        assert!(parse(&owned(&["render"])).is_err());
        assert!(parse(&owned(&["issue"])).is_err());
        assert!(parse(&owned(&["issue", "two"])).is_err());
        assert!(parse(&owned(&["issue", "0"])).is_err());
        assert!(parse(&owned(&["issue", "661", "662"])).is_err());
        assert!(parse(&owned(&["issue", "661", "--issue", "662"])).is_err());
        assert!(parse(&owned(&["nope"])).is_err());
        assert!(parse(&owned(&["next", "--set", "nope"])).is_err());
        assert!(parse(&owned(&["list", "--status", "finished"])).is_err());
        assert!(parse(&owned(&["list", "--effort", "enormous"])).is_err());
        assert!(parse(&owned(&["next", "--seed", "soon"])).is_err());
        assert!(parse(&owned(&["next", "--rotate", "extra"])).is_err());
        assert!(parse(&owned(&["render", "2", "3"])).is_err());
        assert!(parse(&owned(&["render", "2", "--prompt", "3"])).is_err());
        assert!(parse(&owned(&["list", "--memory"])).is_err());
    }

    #[test]
    fn an_empty_set_value_is_rejected_and_renders_as_missing() {
        let owned: Vec<String> = ["next", "--set", "method="]
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        assert!(parse(&owned).is_err());

        let mut args = parse_args(&["render", "P1"]);
        args.values.insert("method".to_owned(), "   ".to_owned());
        let state = ferrox_prompt::expand::ProjectState {
            methods: Vec::new(),
            pins: Vec::new(),
        };
        let values = merge_values(&requested_values(&args), None, &state);
        assert!(!values.contains_key("method"));
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        let rendered = render::render(&library, prompt, &values, &[], None, &Options::default());
        assert!(rendered.missing.iter().any(|name| name == "method"));
    }

    #[test]
    fn allow_unfilled_keeps_a_row_that_cannot_fill_the_template() {
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        let state = ProjectState {
            methods: vec![row('A', "13", "", false)],
            pins: Vec::new(),
        };
        let ledger = Ledger::default();
        let supplied = Values::new();
        assert!(target_for(prompt, &state, &ledger, None, &supplied, &[], false).is_none());
        let (target, _) = target_for(prompt, &state, &ledger, None, &supplied, &[], true)
            .expect("an unfilled row is still the work");
        assert_eq!(target.key(), "A13");
        let mixed = ProjectState {
            methods: vec![row('A', "13", "", false), row('A', "14", "VLESS", false)],
            pins: Vec::new(),
        };
        let (target, _) = target_for(prompt, &mixed, &ledger, None, &supplied, &[], true)
            .expect("a fully supplied row is preferred");
        assert_eq!(target.key(), "A14");
    }

    #[test]
    fn only_the_blanks_this_template_can_fill_are_supplied() {
        let library = library();
        let state = ProjectState {
            methods: vec![row('A', "13", "VLESS over QUIC", false)],
            pins: Vec::new(),
        };
        assert_eq!(
            advisor::missing_inputs(
                library.prompt(1).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), None),
                &state,
                &[]
            )
            .len(),
            0
        );
        let mut parked = row('D', "2", "A parked row", false);
        parked.state = "not-scheduled".to_owned();
        parked.gap = Gap::NotScheduled;
        let parked_state = ProjectState {
            methods: vec![parked],
            pins: Vec::new(),
        };
        assert!(
            advisor::missing_inputs(
                library.prompt(1).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), None),
                &parked_state,
                &[]
            )
            .contains(&"method".to_owned()),
            "a parked row cannot supply a matrix blank"
        );
        assert!(
            advisor::missing_inputs(
                library.prompt(1).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), Some(&parked_state.methods[0])),
                &parked_state,
                &[]
            )
            .is_empty(),
            "a row the user names may supply a matrix blank"
        );
        assert_eq!(
            advisor::missing_inputs(
                library.prompt(4).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), Some(&parked_state.methods[0])),
                &parked_state,
                &[]
            ),
            vec!["issue"]
        );
        assert_eq!(
            advisor::missing_inputs(
                library.prompt(4).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), None),
                &state,
                &[]
            ),
            vec!["issue"]
        );

        let references = Library::parse(
            Path::new("prompts.md"),
            "## Shared protocol\n\n```text\np\n```\n\n## P1 · Fixed\n\n**When to use:** now\n\
             **Status:** todo\n**Leverage:** 1\n**Effort:** small\n**Targets:** none\n\
             **Gates:** `cargo test`\n\n```text\nread {references}\n```\n",
        );
        assert_eq!(
            advisor::missing_inputs(
                references.prompt(1).unwrap(),
                &[],
                advisor::Inputs::new(&Values::new(), None),
                &state,
                &[]
            ),
            vec!["references"]
        );
    }

    #[test]
    fn a_served_retry_row_supplies_its_own_inputs_to_the_missing_list() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship {method} for {state}
```
",
        );
        let mut served_row = row('A', "13", "VLESS", false);
        served_row.state.clear();
        let state = ProjectState {
            methods: vec![served_row],
            pins: Vec::new(),
        };
        let missing = advisor::missing_inputs(
            library.prompt(1).unwrap(),
            &[],
            advisor::Inputs::new(&Values::new(), None),
            &state,
            &["A13".to_owned()],
        );
        assert_eq!(missing, vec!["state"]);
    }

    #[test]
    fn a_custom_library_gets_its_own_ledger() {
        let root = std::env::temp_dir().join(format!(
            "ferrox-prompt-ledger-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let default = root.join(LIBRARY_RELATIVE);
        std::fs::create_dir_all(default.parent().unwrap()).expect("dirs");
        std::fs::write(&default, "## P1 · x\n").expect("default library");
        let mut built_in = Library::parse(Path::new(LIBRARY_RELATIVE), "## P1 · x\n");
        built_in.source_path = default.clone();
        assert_eq!(ledger_path(&root, &built_in), root.join(LEDGER_RELATIVE));

        let custom = root.join("draft-prompts.md");
        std::fs::write(&custom, "## P1 · x\n").expect("custom library");
        let mut other = Library::parse(Path::new("draft-prompts.md"), "## P1 · x\n");
        other.source_path = custom.clone();
        let path = ledger_path(&root, &other);
        assert_ne!(path, root.join(LEDGER_RELATIVE));
        assert_eq!(path.parent(), Some(root.join(".ferrox").as_path()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let first = root.join("draft-a.md");
            let second = root.join("draft-b.md");
            std::fs::write(&first, "## P1 · x\n").expect("first draft");
            std::fs::write(&second, "## P1 · x\n").expect("second draft");
            std::fs::remove_file(&default).expect("replace default");
            symlink(&first, &default).expect("first link");
            let mut redirected = Library::parse(Path::new(LIBRARY_RELATIVE), "## P1 · x\n");
            redirected.source_path = std::fs::canonicalize(&first).expect("first target");
            let first_ledger = ledger_path(&root, &redirected);
            assert_ne!(first_ledger, root.join(LEDGER_RELATIVE));
            std::fs::remove_file(&default).expect("remove link");
            symlink(&second, &default).expect("second link");
            redirected.source_path = std::fs::canonicalize(&second).expect("second target");
            let second_ledger = ledger_path(&root, &redirected);
            assert_ne!(first_ledger, second_ledger);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn next_takes_an_id_and_refuses_the_prompt_flag() {
        assert_eq!(parse_args(&["next", "--id", "5"]).forced, Some(5));
        let owned: Vec<String> = ["next", "--prompt", "5"]
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        let error = parse(&owned).expect_err("next does not take --prompt");
        assert!(error.contains("--id"), "{error}");
    }

    #[test]
    fn show_json_reports_a_by_id_selection_without_a_draw() {
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        let args = parse_args(&["show", "1", "--json"]);
        let selection = selection_json(&library, prompt, &args, &[], &[]).to_pretty();
        assert!(selection.contains("shown by id"), "{selection}");
        assert!(selection.contains("\"seed\": null"), "{selection}");
        assert!(selection.contains("\"suppressed\": []"), "{selection}");
    }

    #[test]
    fn a_rotation_seed_is_reported_without_clamping() {
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        let args = parse_args(&[
            "next",
            "--json",
            "--rotate",
            "--seed",
            "18446744073709551615",
        ]);
        let selection = selection_json(&library, prompt, &args, &[], &[]).to_pretty();
        assert!(
            selection.contains("\"seed\": 18446744073709551615"),
            "{selection}"
        );
    }

    #[test]
    fn a_seed_is_not_reported_when_a_draw_did_not_run() {
        let library = library();
        let prompt = library.prompt(1).expect("P1");
        for arguments in [
            &["show", "1", "--json", "--rotate", "--seed", "7"][..],
            &["next", "--id", "1", "--json", "--rotate", "--seed", "7"][..],
        ] {
            let args = parse_args(arguments);
            let selection = selection_json(&library, prompt, &args, &[], &[]).to_pretty();
            assert!(selection.contains("\"seed\": null"), "{selection}");
        }
    }

    #[test]
    fn json_touches_keep_the_create_marker() {
        let library = Library::parse(
            Path::new("prompts.md"),
            &LIBRARY.replace(
                "**Gates:** `cargo test`",
                "**Gates:** `cargo test`\n**Touches:** docs/note.md, +docs/new.md",
            ),
        );
        let prompt = library.prompt(1).expect("P1");
        let json = prompt_json(prompt, &Ledger::default()).to_pretty();
        assert!(json.contains("\"docs/note.md\""), "{json}");
        assert!(json.contains("\"+docs/new.md\""), "{json}");
    }

    #[test]
    fn a_handout_that_is_not_recorded_does_not_need_a_ledger_directory() {
        let path = std::env::temp_dir()
            .join(format!(
                "ferrox-no-ledger-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ))
            .join("missing")
            .join("slices.log");
        assert!(lock_if_recording(false, &path).expect("no lock").is_none());
        assert!(!path.parent().expect("parent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_ledger_symlink_keeps_one_lock_identity() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "ferrox-prompt-lock-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("slices.log");
        let link = dir.join("ledger");
        symlink(&target, &link).expect("link");
        let before = lock_path(&link);
        std::fs::write(&target, "").expect("target");
        assert_eq!(lock_path(&link), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_library_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!(
            "ferrox-prompt-permissions-{}-{}.md",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::write(&path, "old").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        replace_file(&path, "new").expect("replace");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn repeatables_accumulate_and_the_last_set_wins() {
        let args = parse_args(&[
            "render", "P2", "--set", "a=1", "--set", "b=2", "--addon", "x,y", "--addon", "z",
            "--set", "a=3",
        ]);
        assert_eq!(args.values["a"], "3");
        assert_eq!(args.values["b"], "2");
        assert_eq!(args.addons, vec!["x,y", "z"]);
    }

    #[test]
    fn a_set_value_may_contain_equals() {
        let args = parse_args(&["render", "P2", "--set", "cmd=cargo test --all-features"]);
        assert_eq!(args.values["cmd"], "cargo test --all-features");
    }

    #[test]
    fn set_wins_over_a_default_because_the_map_is_read_first() {
        let mut values = BTreeMap::new();
        values.insert("len".to_owned(), "40".to_owned());
        values.insert("len".to_owned(), "200".to_owned());
        assert_eq!(render::substitute("{len=40}", &values), "200");
    }

    #[test]
    fn the_handout_is_recorded_as_it_was_asked_for() {
        assert_eq!(how_asked(&parse_args(&["next"])), "next");
        assert_eq!(
            how_asked(&parse_args(&["next", "--rotate"])),
            "next --rotate"
        );
        assert_eq!(how_asked(&parse_args(&["render", "2"])), "render");
        assert_eq!(how_asked(&parse_args(&["issue", "661"])), "issue");
    }

    #[test]
    fn set_status_needs_an_id_and_a_status() {
        let args = parse_args(&["set-status", "P5", "doing"]);
        assert_eq!(args.command, Command::SetStatus);
        assert_eq!(args.id, Some(5));
        assert_eq!(args.set_to, Some(Status::Doing));
        assert!(parse(&["set-status".to_owned()]).is_err());
        assert!(parse(&["set-status".to_owned(), "5".to_owned()]).is_err());
        assert!(parse(&["set-status".to_owned(), "5".to_owned(), "x".to_owned()]).is_err());
    }

    #[test]
    fn set_status_rewrites_one_line_and_nothing_else() {
        let source = "## Shared protocol\n\n```text\n**Status:** not a field here\n```\n\n## P2 · Second\n\n**Status:** todo\n**Leverage:** 5\n";
        let updated = set_status_text(source, 2, Status::Done).expect("the field is there");
        assert_eq!(
            updated,
            "## Shared protocol\n\n```text\n**Status:** not a field here\n```\n\n## P2 · Second\n\n**Status:** done\n**Leverage:** 5\n"
        );
        assert!(set_status_text(source, 9, Status::Done).is_err());
    }

    #[test]
    fn set_status_skips_an_indented_status_example() {
        let source =
            "## P2 · Second\n\n    **Status:** doing\n\n**Status:** todo\n**Leverage:** 5\n";
        let updated = set_status_text(source, 2, Status::Done).expect("the real field is there");
        assert!(
            updated.contains("    **Status:** doing"),
            "the example must not change: {updated}"
        );
        assert!(updated.contains("**Status:** done"), "{updated}");
    }

    #[test]
    fn set_status_follows_the_parser_for_tilde_fences_and_example_headings() {
        let source = "## P1 · First\n\n~~~text\n## P2 · Example\n**Status:** todo\n~~~\n\n## P2 · Second\n\n**Status:** todo\n";
        let updated = set_status_text(source, 2, Status::Done).expect("the real P2 is there");
        assert!(updated.contains("## P2 · Example\n**Status:** todo"));
        assert!(updated.ends_with("## P2 · Second\n\n**Status:** done\n"));
    }

    #[test]
    fn a_left_out_problem_is_reported_not_only_its_missing_inputs() {
        let skipped = vec![
            advisor::Skipped {
                id: 4,
                missing: vec!["scope".to_owned()],
                problem: None,
            },
            advisor::Skipped {
                id: 5,
                missing: Vec::new(),
                problem: Some("no add-on matching `x`".to_owned()),
            },
        ];
        let reasons = skipped_reasons(&skipped);
        assert!(reasons.contains("scope for P4"), "{reasons}");
        assert!(reasons.contains("P5: no add-on matching `x`"), "{reasons}");
    }

    #[test]
    fn a_left_out_addon_input_gets_its_addon_in_the_recovery_command() {
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
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["core".to_owned(), "extra".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next", "--addon", "extra"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &ProjectState::default(),
            &Ledger::default(),
            None,
        );
        assert!(message.contains("--addon extra"), "{message}");
    }

    #[test]
    fn a_served_row_is_named_when_it_is_the_only_way_to_retry() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship it for {issue}
```
",
        );
        let state = ProjectState {
            methods: vec![row('A', "13", "VLESS", false)],
            pins: Vec::new(),
        };
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["issue".to_owned()],
            problem: None,
        }];
        let ledger = Ledger {
            entries: vec![advisor::Entry {
                at: "2026-10-02T00:00:00Z".to_owned(),
                id: 1,
                how: "next".to_owned(),
                target: Some("A13".to_owned()),
            }],
            ..Ledger::default()
        };
        let args = parse_args(&["next"]);
        let message = nothing_to_hand_over(&library, &args, &[], &skipped, &state, &ledger, None);
        assert!(message.contains("needs `issue`"), "{message}");
        assert!(message.contains("--row A13"), "{message}");
        assert!(message.contains("already served"), "{message}");
    }

    #[test]
    fn a_skipped_slice_with_no_drawable_row_names_the_parked_row() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship it for {state}
```
",
        );
        let mut parked = row('A', "13", "VLESS", false);
        parked.state = "not-scheduled".to_owned();
        parked.gap = Gap::NotScheduled;
        let state = ProjectState {
            methods: vec![parked],
            pins: Vec::new(),
        };
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["state".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &state,
            &Ledger::default(),
            None,
        );
        assert!(
            message.contains("no drawable open row remains"),
            "{message}"
        );
        assert!(message.contains("--row A13"), "{message}");
        assert!(!message.contains("ferrox-prompt render"), "{message}");
        let message =
            nothing_to_hand_over(&library, &args, &[], &[], &state, &Ledger::default(), None);
        assert!(
            message.contains("no drawable open row remains"),
            "{message}"
        );
        assert!(message.contains("--row A13"), "{message}");
    }

    #[test]
    fn a_parked_override_is_named_alongside_another_slices_missing_input() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Parked row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship {method}
```

## P2 · Needs issue

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
triage {issue}
```
",
        );
        let mut parked = row('A', "13", "VLESS", false);
        parked.state = "not-scheduled".to_owned();
        parked.gap = Gap::NotScheduled;
        let state = ProjectState {
            methods: vec![parked],
            pins: Vec::new(),
        };
        let skipped = vec![advisor::Skipped {
            id: 2,
            missing: vec!["issue".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &state,
            &Ledger::default(),
            None,
        );
        assert!(message.contains("needs `issue`"), "{message}");
        assert!(message.contains("--row A13"), "{message}");
    }

    #[test]
    fn an_empty_matrix_still_gets_a_manual_retry() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship it for {method}
```
",
        );
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["method".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &ProjectState::default(),
            &Ledger::default(),
            None,
        );
        assert!(message.contains("needs `method`"), "{message}");
        assert!(message.contains("ferrox-prompt render P1"), "{message}");
        assert!(message.contains("--set method="), "{message}");
    }

    #[test]
    fn a_retry_names_the_row_that_fills_the_reported_inputs() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship {state} for {issue}
```
",
        );
        let mut without_state = row('A', "13", "VLESS", false);
        without_state.state = String::new();
        let state = ProjectState {
            methods: vec![without_state, row('A', "14", "VLESS", false)],
            pins: Vec::new(),
        };
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["issue".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &state,
            &Ledger::default(),
            None,
        );
        assert!(message.contains("--row A14"), "{message}");
        assert!(!message.contains("--row A13"), "{message}");
    }

    #[test]
    fn a_skipped_row_names_the_pending_row_and_only_its_missing_input() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Open row

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** open
**Gates:** `cargo test`

```text
ship {method}
```

**Add-on — Needs state:** uses {state}
",
        );
        let state = ProjectState {
            methods: vec![row('A', "13", "", false)],
            pins: Vec::new(),
        };
        let skipped = vec![advisor::Skipped {
            id: 1,
            missing: vec!["state".to_owned()],
            problem: None,
        }];
        let args = parse_args(&["next", "--addon", "needs"]);
        let message = nothing_to_hand_over(
            &library,
            &args,
            &[],
            &skipped,
            &state,
            &Ledger::default(),
            None,
        );
        assert!(message.contains("needs `state`"), "{message}");
        assert!(!message.contains("`method`"), "{message}");
        assert!(message.contains("--row A13"), "{message}");
    }

    #[test]
    fn set_status_keeps_crlf_line_endings() {
        let source = "## P2 · Second\r\n\r\n**Status:** todo\r\n**Leverage:** 5\r\n";
        let updated = set_status_text(source, 2, Status::Done).expect("the field is there");
        assert_eq!(
            updated,
            "## P2 · Second\r\n\r\n**Status:** done\r\n**Leverage:** 5\r\n"
        );
        assert!(!updated.replace("\r\n", "").contains('\n'));
    }
}
