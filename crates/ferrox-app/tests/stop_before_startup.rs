#![cfg(unix)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferrox-stop-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn fifo(path: &Path) {
    let name = CString::new(path.as_os_str().as_encoded_bytes()).expect("path");
    // SAFETY: the path is a NUL-terminated C string owned for the call.
    let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(
        made,
        0,
        "mkfifo {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

#[test]
fn a_stop_request_written_before_the_outbound_build_exits_at_once() {
    let dir = temp_dir("before-outbound");
    let token = dir.join("token");
    fifo(&token);
    let stop = dir.join("stop");
    std::fs::write(&stop, "stop\n").expect("stop file");
    let config = dir.join("config.json");
    let body = format!(
        concat!(
            r#"{{"log":{{"loglevel":"warning"}},"inbounds":[],"outbounds":[{{"protocol":"foxy","#,
            r#""settings":{{"email":"probe@example.com","password":"probe","#,
            r#""tokenFile":"{}","servers":[{{"host":"edge.invalid","port":443}}]}}}}]}}"#
        ),
        token.display()
    );
    std::fs::write(&config, body).expect("config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .arg("-config")
        .arg(&config)
        .env("FERROX_STOP_FILE", &stop)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ferrox-app");

    let began = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break Some(status);
        }
        if began.elapsed() > Duration::from_secs(10) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("a stop request written before startup waited for the outbound build");
    }
    assert!(
        status.expect("status").success(),
        "the stop request did not exit cleanly"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
