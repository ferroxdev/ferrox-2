//! Never probe a clipboard: running a candidate to test it rewrites it, so only spawn errors tell absence from failure.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A clipboard helper that has not accepted the text by now is hung, not slow.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Why a copy did not happen.
#[derive(Debug)]
pub enum Unavailable {
    /// No candidate exists on this machine.
    NoneFound,
    /// A candidate existed and refused.
    Failed(String),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoneFound => {
                #[cfg(windows)]
                f.write_str("no clipboard program found (tried clip)")?;
                #[cfg(not(windows))]
                f.write_str("no clipboard program found (tried pbcopy, wl-copy, xclip, xsel)")?;
                Ok(())
            }
            Self::Failed(reason) => write!(f, "no clipboard program accepted the text: {reason}"),
        }
    }
}

impl std::error::Error for Unavailable {}

/// Programs tried in order, with the arguments that put stdin on the clipboard.
#[cfg(not(windows))]
const CANDIDATES: &[(&str, &[&str])] = &[
    ("pbcopy", &[]),
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard", "-in"]),
    ("xsel", &["--clipboard", "--input"]),
];

/// Windows: `clip` reads the clipboard from stdin, same idea as `pbcopy`.
#[cfg(windows)]
const CANDIDATES: &[(&str, &[&str])] = &[("clip", &[])];

/// Copy `text` to the clipboard.
pub fn copy(text: &str) -> Result<(), Unavailable> {
    let mut refusal = None;
    for (program, args) in CANDIDATES {
        match write(program, args, text) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => refusal = Some(format!("{program}: {error}")),
        }
    }
    Err(match refusal {
        Some(reason) => Unavailable::Failed(reason),
        None => Unavailable::NoneFound,
    })
}

/// Feed text to stdin; a `NotFound` spawn means absence, anything else a refusal.
fn write(program: &str, args: &[&str], text: &str) -> std::io::Result<()> {
    write_within(program, args, text, TIMEOUT)
}

/// The writer may block on a helper that never reads; the loop keeps both the pipe and the wait bounded.
fn write_within(
    program: &str,
    args: &[&str],
    text: &str,
    timeout: Duration,
) -> std::io::Result<()> {
    let mut child = Command::new(program)
        .args(args.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    match child.stdin.take() {
        Some(mut pipe) => {
            let text = text.as_bytes().to_vec();
            if let Err(error) = std::thread::Builder::new().spawn(move || {
                let _ = sender.send(pipe.write_all(&text));
            }) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        None => {
            let _ = sender.send(Ok(()));
        }
    }

    let deadline = Instant::now() + timeout;
    let mut writer_done = false;
    let mut writer_error = None;
    loop {
        if !writer_done {
            match receiver.try_recv() {
                Ok(Err(error)) => writer_error = Some(error),
                Ok(Ok(())) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    writer_done = true;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(error) = writer_error.take() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !writer_done {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    match receiver.recv_timeout(remaining) {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {
                            return Err(std::io::Error::new(
                                ErrorKind::TimedOut,
                                format!("{program} exited before reading the text"),
                            ));
                        }
                    }
                }
                return if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!("{program} exited non-zero")))
                };
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!("{program} did not accept the text in time"),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_is_reported_as_missing_and_does_not_stop_the_search() {
        let error = write("ferrox-no-such-clipboard-program", &[], "text").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    #[cfg(not(windows))]
    fn a_program_that_exits_non_zero_is_a_refusal_not_an_absence() {
        // `false` exists on every platform here and always exits 1 — what a broken clipboard program looks like.
        let error = write("false", &[], "text").unwrap_err();
        assert_ne!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    #[cfg(unix)]
    fn a_helper_that_never_reads_is_killed_at_the_deadline() {
        let started = Instant::now();
        let error = write_within("sleep", &["5"], "text", Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    #[cfg(unix)]
    fn a_full_pipe_is_killed_at_the_deadline() {
        let started = Instant::now();
        let text = "x".repeat(1024 * 1024);
        let error = write_within(
            "sh",
            &["-c", "exec sleep 5"],
            &text,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn the_failure_message_names_what_was_tried() {
        let expected = if cfg!(windows) { "clip" } else { "pbcopy" };
        assert!(Unavailable::NoneFound.to_string().contains(expected));
    }
}
