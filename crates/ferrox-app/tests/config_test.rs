//! `-test` builds every handler a config names and stops before the first listener, so an
//! installer's `ExecStartPre` gets xray's verdict — `Configuration OK.` and status 0, or
//! `Failed to start:` and status 23 — without touching a port a running instance holds.

use std::net::TcpListener;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn ferrox-app")
}

fn config_path(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ferrox-test-{name}-{}.json", std::process::id()));
    std::fs::write(&path, text).expect("write config");
    path
}

#[test]
fn test_proves_a_config_whose_port_is_held() {
    // The parent keeps the configured port, so only a run that never binds it can report OK.
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let text = format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}],
        "outbounds":[{{"protocol":"freedom"}}]}}"#
    );
    let path = config_path("held", &text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-test` refused a servable config: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    // A serve with the same config is the control: the port really is taken.
    let served = run(&["-c", &named]);
    assert!(
        !served.status.success(),
        "the held port was never actually held"
    );
    let _ = std::fs::remove_file(&path);
}

/// A cert path the config names and the disk does not have is a config error: the handler was
/// really built, not just the JSON parsed.
#[test]
fn test_refuses_a_config_whose_cert_is_missing() {
    let text = r#"{"inbounds":[{"listen":"127.0.0.1","port":443,"protocol":"vless",
        "settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none"},
        "streamSettings":{"security":"tls","tlsSettings":{"certificates":[
        {"certificateFile":"/nonexistent/ferrox-test-cert.pem","keyFile":"/nonexistent/ferrox-test-key.pem"}]}}}],
        "outbounds":[{"protocol":"freedom"}]}"#;
    let path = config_path("cert", text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "a missing cert is xray's config-error status: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Failed to start:"),
        "the refusal carries xray's spelling: {stdout}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A fingerprint no table knows is the reference's load-time refusal, and a servable inbound must
/// not soften it into `Configuration OK.` — the lane's own `tlsSettings` is the config's error.
#[test]
fn test_refuses_an_unknown_fingerprint_on_a_front_lane() {
    let lane = |fingerprint: &str| {
        format!(
            r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18096,"protocol":"blackhole"}}],
            "outbounds":[{{"protocol":"socks","settings":{{"servers":[{{"address":"127.0.0.1","port":1080}}]}},
            "streamSettings":{{"security":"tls","tlsSettings":{{"allowInsecure":true,"fingerprint":"{fingerprint}"}}}}}}]}}"#
        )
    };
    let path = config_path("fingerprint", &lane("Bogus"));
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "`-test` reported OK for a fingerprint the reference refuses: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(r#"unknown "fingerprint": bogus"#),
        "the refusal does not name the field: {stdout}"
    );
    // Serve mode refuses on the same line: the config never reaches a listener.
    let served = run(&["-c", &named]);
    let said = String::from_utf8_lossy(&served.stderr);
    assert_eq!(served.status.code(), Some(1), "{said}");
    assert!(
        said.contains(r#"unknown "fingerprint": bogus"#),
        "startup did not name the field: {said}"
    );
    // A fingerprint the table knows still builds, so the refusal is the unknown name alone.
    let good = config_path("fingerprint-good", &lane("chrome"));
    let named = good.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("Configuration OK."), "{stdout}");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&good);
}

#[test]
fn test_refuses_json_it_cannot_parse() {
    let path = config_path("broken", r#"{"inbounds": ]"#);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(23), "{stdout}");
    assert!(stdout.contains("Failed to start:"), "{stdout}");
    let _ = std::fs::remove_file(&path);
}

fn geodata_config(kind: &str, url: &str) -> (String, std::path::PathBuf) {
    let file = format!("ferrox-test-geodata-{}-{kind}.dat", std::process::id());
    let asset = std::path::Path::new(env!("CARGO_BIN_EXE_ferrox-app"))
        .parent()
        .expect("binary directory")
        .join(&file);
    std::fs::write(&asset, b"").expect("write the geodata asset");
    (
        format!(
            r#"{{"geodata": {{"cron": "0 3 * * *", "outbound": "direct",
        "assets": [{{"url": "{url}", "file": "{file}"}}]}},
        "inbounds": [{{"tag": "in", "listen": "127.0.0.1", "port": 18095, "protocol": "socks",
        "settings": {{"auth": "noauth"}}}}],
        "outbounds": [{{"protocol": "freedom", "tag": "direct"}}]}}"#
        ),
        asset,
    )
}

/// The reference refuses an asset URL that is not HTTPS while building the config, so `-test` does too.
#[test]
fn test_refuses_a_geodata_asset_over_plain_http() {
    let (text, asset) = geodata_config("http", "http://example.test/geosite.dat");
    let path = config_path("geodata-http", &text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "a plain-http asset is xray's config error: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("invalid geodata asset url") && stdout.contains("scheme must be https"),
        "the refusal carries the reference's spelling: {stdout}"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&asset);
}

/// A schedule the reference builds and starts is a config this tree accepts too.
#[test]
fn test_accepts_a_geodata_schedule() {
    let (text, asset) = geodata_config("cron", "https://example.test/geosite.dat");
    let path = config_path("geodata-cron", &text);
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid geodata block is servable: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&asset);
}

fn reality_config(seed: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18096,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}},
        "streamSettings":{{"network":"tcp","security":"reality","realitySettings":{{
        "target":"cover.test:443","serverNames":["www.example.com"],
        "privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":[""],
        "mldsa65Seed":"{seed}"}}}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
    )
}

/// The reference refuses a seed that is its own private key while building the config, so `-test` does too.
#[test]
fn test_refuses_a_reality_seed_that_names_the_private_key() {
    let path = config_path(
        "reality-seed-alias",
        &reality_config("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(23),
        "an aliased seed is xray's config error: {}{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(r#""mldsa65Seed" and "privateKey" can not be the same value"#),
        "the refusal carries the reference's spelling: {stderr}"
    );
    assert!(
        !stderr.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "the refusal does not echo the private key: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A seed the reference signs with is a config this tree now carries through the whole handshake.
#[test]
fn test_accepts_a_reality_seed_and_carries_the_binding() {
    let path = config_path(
        "reality-seed",
        &reality_config("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid seed is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .contains("the ML-DSA-65 binding it names is not carried"),
        "a carried binding is not reported absent"
    );
    let _ = std::fs::remove_file(&path);
}

fn xmux_inbound(xmux: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18097,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}},
        "streamSettings":{{"network":"xhttp","xhttpSettings":{{
        "path":"/share","mode":"stream-up","xmux":{xmux}}}}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
    )
}

/// The reference refuses both pool bounds at once while building the config, so `-test` does too.
#[test]
fn test_refuses_xhttp_xmux_with_both_bounds() {
    let path = config_path(
        "xmux-both",
        &xmux_inbound(r#"{"maxConnections":3,"maxConcurrency":2}"#),
    );
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(23),
        "two exclusive bounds are xray's config error: {}{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("maxConnections cannot be specified together with maxConcurrency"),
        "the refusal carries the reference's spelling: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

fn xmux_outbound(xmux: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":18098,"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}],
        "outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"192.0.2.1","port":443,
        "users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}},
        "streamSettings":{{"network":"xhttp","xhttpSettings":{{
        "path":"/share","mode":"stream-up","xmux":{xmux}}}}}}}]}}"#
    )
}

/// A pool bound the reference dials out of is still a config this tree runs, so it starts with one line saying the bound is not applied.
#[test]
fn test_accepts_xhttp_xmux_bounds_it_does_not_apply() {
    let path = config_path("xmux-one", &xmux_outbound(r#"{"maxConnections":3}"#));
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a valid xmux block is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(r#"xhttp: "xmux" bounds are checked"#),
        "the unapplied pool is named instead of silent"
    );
    let _ = std::fs::remove_file(&path);
}

fn config_dir(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ferrox-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create config dir");
    for (file, text) in files {
        std::fs::write(dir.join(file), text).expect("write config");
    }
    dir
}

fn held_port_inbound(port: u16) -> String {
    format!(
        r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless",
        "settings":{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"decryption":"none"}}}}]}}"#
    )
}

/// xray's `-confdir` loads every `*.json` in the directory and merges them; here the flag was refused.
#[test]
fn test_reads_a_confdir_the_reference_discovers() {
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let dir = config_dir(
        "confdir",
        &[
            ("01-inbound.json", &held_port_inbound(port)),
            (
                "02-outbound.json",
                r#"{"outbounds":[{"protocol":"freedom"}]}"#,
            ),
        ],
    );
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-test", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a config dir the reference reads is servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two `-c` files merge into one config, as the reference's `MergeConfig` does.
#[test]
fn test_merges_a_second_config_file() {
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("local address").port();
    let inbound = config_path("merge-inbound", &held_port_inbound(port));
    let outbound = config_path(
        "merge-outbound",
        r#"{"outbounds":[{"protocol":"freedom"}]}"#,
    );
    let output = run(&[
        "-test",
        "-c",
        &inbound.to_string_lossy(),
        "-c",
        &outbound.to_string_lossy(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "two files the reference merges are servable: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Configuration OK."),
        "`-test` reports xray's verdict: {stdout}"
    );
    let _ = std::fs::remove_file(&inbound);
    let _ = std::fs::remove_file(&outbound);
}

/// The reference's `Override` replaces a block whole, replaces an inbound or outbound of the same
/// tag in place, and prepends one no config named yet; `-dump` prints what the merge built.
#[test]
fn dump_prints_the_config_the_reference_would_merge() {
    let base = r#"{"log":{"loglevel":"warning"},
        "inbounds":[{"tag":"in","listen":"127.0.0.1","port":18099,"protocol":"socks",
        "settings":{"auth":"noauth"}}],
        "outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
    let over = r#"{"log":{"loglevel":"debug"},
        "inbounds":[{"tag":"in","listen":"127.0.0.1","port":18100,"protocol":"http"},
        {"tag":"extra","listen":"127.0.0.1","port":18101,"protocol":"socks","settings":{"auth":"noauth"}}],
        "outbounds":[{"tag":"direct","protocol":"blackhole"},{"tag":"new","protocol":"blackhole"}]}"#;
    let dir = config_dir("dump", &[("01-base.json", base), ("02-over.json", over)]);
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-dump", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-dump` prints and exits: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(r#""port":18100"#) && !stdout.contains(r#""port":18099"#),
        "an inbound of the same tag is replaced in place: {stdout}"
    );
    assert!(
        stdout.contains(r#""port":18101"#),
        "an inbound of a tag no file named yet is appended: {stdout}"
    );
    assert!(
        stdout.contains(r#""loglevel":"debug""#) && !stdout.contains("warning"),
        "a block the later file names is replaced whole: {stdout}"
    );
    assert!(
        stdout.contains("blackhole") && !stdout.contains("freedom"),
        "an outbound of the same tag is replaced in place: {stdout}"
    );
    let new = stdout.find(r#""tag":"new""#).expect("the new outbound");
    let direct = stdout
        .find(r#""tag":"direct""#)
        .expect("the replaced outbound");
    assert!(
        new < direct,
        "an outbound no file named yet prepends, so it stays first: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-dump` takes the format the flags name, not only the file's suffix, so a JSONC stream in a
/// `.json` file strips its comments before the merge.
#[test]
fn dump_honors_the_named_format() {
    let text = r#"{
        // the named format, not the suffix, decides
        "outbounds":[{"tag":"named","protocol":"blackhole"}]
    }"#;
    let path = std::env::temp_dir().join(format!(
        "ferrox-test-dump-format-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, text).expect("write config");
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-dump", "-format", "jsonc", "-c", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-dump` ignored the named format: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(r#""tag":"named""#),
        "`-dump` dropped the parsed config: {stdout}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A file whose name contains `tail` appends its new outbounds instead of prepending them.
#[test]
fn a_config_file_named_tail_appends_its_outbounds() {
    let base = r#"{"outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
    let over = r#"{"outbounds":[{"tag":"last","protocol":"blackhole"}]}"#;
    let plain = config_dir(
        "append-plain",
        &[("01-base.json", base), ("02-extra.json", over)],
    );
    let tail = config_dir(
        "append-tail",
        &[("01-base.json", base), ("99-tail.json", over)],
    );
    let first = run(&["-dump", "-confdir", &plain.to_string_lossy()]);
    let second = run(&["-dump", "-confdir", &tail.to_string_lossy()]);
    let first = String::from_utf8_lossy(&first.stdout);
    let second = String::from_utf8_lossy(&second.stdout);
    assert!(
        first.find(r#""tag":"last""#).expect("the new outbound")
            < first.find(r#""tag":"direct""#).expect("the base outbound"),
        "an ordinary file prepends its outbounds: {first}"
    );
    assert!(
        second.find(r#""tag":"direct""#).expect("the base outbound")
            < second.find(r#""tag":"last""#).expect("the new outbound"),
        "a file named tail appends them: {second}"
    );
    let _ = std::fs::remove_dir_all(&plain);
    let _ = std::fs::remove_dir_all(&tail);
}

/// The merged config is what the handlers are built from: a later file's inbound of the same tag
/// is the one built, so its missing certificate is the refusal `-test` reports.
#[test]
fn a_later_config_file_replaces_an_inbound_the_handler_builds() {
    let base = r#"{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":18102,"protocol":"socks",
        "settings":{"auth":"noauth"}}]}"#;
    let over = r#"{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":443,"protocol":"vless",
        "settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none"},
        "streamSettings":{"security":"tls","tlsSettings":{"certificates":[
        {"certificateFile":"/nonexistent/ferrox-test-cert.pem","keyFile":"/nonexistent/ferrox-test-key.pem"}]}}}]}"#;
    let dir = config_dir(
        "merged-inbound",
        &[("01-base.json", base), ("02-over.json", over)],
    );
    let named = dir.to_string_lossy().into_owned();
    let output = run(&["-test", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(23),
        "the later file's inbound is the one built: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("no servable inbound")
            && String::from_utf8_lossy(&output.stderr).contains("unreadable vless tls identity"),
        "the refusal names the certificate the later file's inbound is missing: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn configuration(extension: &str) -> String {
    match extension {
        "yaml" | "yml" => r"inbounds:
  - tag: in
    listen: 127.0.0.1
    port: 0
    protocol: socks
    settings:
      auth: noauth
outbounds:
  - protocol: freedom
"
        .to_owned(),
        "toml" => r#"[[inbounds]]
tag = "in"
listen = "127.0.0.1"
port = 0
protocol = "socks"
[inbounds.settings]
auth = "noauth"

[[outbounds]]
protocol = "freedom"
"#
        .to_owned(),
        _ => r#"{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":0,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}"#.to_owned(),
    }
}

/// A YAML or TOML spelling reaches the same handler build and the same merged dump as JSON.
#[test]
fn yaml_and_toml_configs_build_and_dump_like_json() {
    for extension in ["yaml", "toml"] {
        let path = std::env::temp_dir().join(format!(
            "ferrox-test-{extension}-{}.{extension}",
            std::process::id()
        ));
        std::fs::write(&path, configuration(extension)).expect("write config");
        let named = path.to_string_lossy().into_owned();
        let tested = run(&["-test", "-c", &named]);
        assert_eq!(
            tested.status.code(),
            Some(0),
            "`-test` refused a {extension} config: {}{}",
            String::from_utf8_lossy(&tested.stdout),
            String::from_utf8_lossy(&tested.stderr)
        );
        let dumped = run(&["-dump", "-c", &named]);
        let stdout = String::from_utf8_lossy(&dumped.stdout);
        assert_eq!(dumped.status.code(), Some(0), "{stdout}");
        assert!(
            stdout.contains(r#""tag":"in""#)
                && stdout.contains(r#""protocol":"socks""#)
                && stdout.contains(r#""protocol":"freedom""#),
            "`-dump` dropped the {extension} config: {stdout}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

fn read_close(stream: &mut std::net::TcpStream, closed: &std::sync::atomic::AtomicBool) {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("keep-alive read timeout");
    let mut byte = [0u8; 1];
    closed.store(
        matches!(std::io::Read::read(stream, &mut byte), Ok(0)),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// A config served over HTTP is fetched like a file; a 404 and every wire shape keep the status the reference reports.
#[test]
#[allow(clippy::too_many_lines)]
fn http_config_is_fetched_and_a_missing_one_is_refused() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    let body = configuration("json");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body.as_bytes()).expect("gzip config");
    let gzip = encoder.finish().expect("finish gzip");
    let split = body.len() / 2;
    let chunked = format!(
        "{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        split,
        &body[..split],
        body.len() - split,
        &body[split..]
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP config server");
    let address = listener.local_addr().expect("HTTP config address");
    let keep_alive_closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let closed = keep_alive_closed.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..7 {
            let (mut stream, _) = listener.accept().expect("accept HTTP config request");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = std::io::Read::read(&mut stream, &mut chunk).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            let path = request.split_whitespace().nth(1).unwrap_or_default();
            let (status, extra, body) = match path {
                "/config.json" | "/keep-alive" => ("200 OK", "", body.as_bytes().to_vec()),
                "/chunked" => (
                    "200 OK",
                    "Transfer-Encoding: chunked\r\n",
                    chunked.as_bytes().to_vec(),
                ),
                "/gzip" => ("200 OK", "Content-Encoding: gzip\r\n", gzip.clone()),
                "/redirect" => ("302 Found", "Location: /config.json\r\n", Vec::new()),
                _ => ("404 Not Found", "", b"missing".to_vec()),
            };
            let close = if path == "/keep-alive" {
                ""
            } else {
                "Connection: close\r\n"
            };
            let length = if path == "/chunked" {
                String::new()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let head = format!("HTTP/1.1 {status}\r\n{length}{extra}{close}\r\n");
            std::io::Write::write_all(&mut stream, head.as_bytes()).expect("write HTTP head");
            std::io::Write::write_all(&mut stream, &body).expect("write HTTP body");
            if path == "/keep-alive" {
                read_close(&mut stream, &closed);
            }
        }
    });
    let source = format!("http://{address}/config.json");
    let output = run(&["-test", "-c", &source]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-test` refused an HTTP config: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for path in ["/chunked", "/gzip", "/redirect"] {
        let output = run(&["-test", "-c", &format!("http://{address}{path}")]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "`-test` refused {path}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let keep_alive = run(&["-test", "-c", &format!("http://{address}/keep-alive")]);
    assert_eq!(
        keep_alive.status.code(),
        Some(0),
        "`-test` refused a keep-alive body: {}{}",
        String::from_utf8_lossy(&keep_alive.stdout),
        String::from_utf8_lossy(&keep_alive.stderr)
    );
    let missing = run(&["-test", "-c", &format!("http://{address}/missing")]);
    let stdout = String::from_utf8_lossy(&missing.stdout);
    assert_eq!(missing.status.code(), Some(23), "{stdout}");
    assert!(
        stdout.contains("Failed to start:") && stdout.contains("404"),
        "a missing remote config names the status: {stdout}"
    );
    server.join().expect("HTTP config server");
    assert!(
        keep_alive_closed.load(std::sync::atomic::Ordering::Relaxed),
        "a Content-Length body waited for the peer to close"
    );
}

/// A scheme no source loader reads fails before any file lookup and names the source.
#[test]
fn an_unsupported_config_source_is_a_distinct_refusal() {
    let output = run(&["-test", "-c", "ftp://127.0.0.1/config.json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(23), "{stdout}");
    assert!(
        stdout.contains("unsupported config source")
            && stdout.contains("ftp://127.0.0.1/config.json"),
        "the refusal names the source: {stdout}"
    );
}

/// Every socket spelling `FetchHTTPContent` accepts reaches the same HTTP GET and body.
#[cfg(unix)]
#[test]
fn configs_on_a_unix_socket_use_each_xray_spelling() {
    use std::os::unix::net::UnixListener;

    let path = std::env::temp_dir().join(format!("ferrox-test-config-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind config socket");
    let body = configuration("json");
    let server = std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept config request");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = std::io::Read::read(&mut stream, &mut chunk).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            std::io::Write::write_all(&mut stream, head.as_bytes()).expect("write HTTP head");
            std::io::Write::write_all(&mut stream, body.as_bytes()).expect("write HTTP body");
        }
    });
    let named = path.to_string_lossy().into_owned();
    for source in [
        format!("{named}:/config.json"),
        format!("http+unix://{named}/config.json"),
        format!("http+unix://{named}"),
        format!("sock:{named}:/config.json"),
    ] {
        let output = run(&["-test", "-c", &source]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "`-test` refused {source}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    server.join().expect("config socket server");
    let _ = std::fs::remove_file(&path);
}

/// A YAML merge key is the alias's own fields, with the explicit keys winning.
#[test]
fn yaml_merge_keys_reach_the_same_config() {
    let text = r"
base: &base
  listen: 127.0.0.1
  port: 0
  protocol: socks
  settings:
    auth: noauth
inbounds:
  - <<: *base
    tag: in
outbounds:
  - protocol: freedom
";
    let path = std::env::temp_dir().join(format!(
        "ferrox-test-yaml-merge-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&path, text).expect("write config");
    let named = path.to_string_lossy().into_owned();
    let output = run(&["-test", "-c", &named]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-test` refused a merged YAML config: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(&path);
}

/// A YAML or TOML spelling that does not parse is the same status 23 with the reason on stdout.
#[test]
fn malformed_yaml_and_toml_are_config_errors() {
    for (extension, text) in [("yaml", "inbounds: [\n"), ("toml", "[[inbounds]\n")] {
        let path = std::env::temp_dir().join(format!(
            "ferrox-test-broken-{extension}-{}.{extension}",
            std::process::id()
        ));
        std::fs::write(&path, text).expect("write config");
        let named = path.to_string_lossy().into_owned();
        let output = run(&["-test", "-c", &named]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(23), "{stdout}");
        assert!(
            stdout.contains("Failed to start:") && stdout.contains("bad config"),
            "the refusal names the {extension} source: {stdout}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// A config directory reads YAML and TOML files in the same sorted merge as JSON.
#[test]
fn a_confdir_merges_yaml_and_toml_files() {
    let base = r"inbounds:
  - tag: in
    listen: 127.0.0.1
    port: 0
    protocol: socks
    settings:
      auth: noauth
";
    let over = r#"[[outbounds]]
protocol = "freedom"
"#;
    let dir = config_dir(
        "formats",
        &[("01-base.yaml", base), ("02-extra.toml", over)],
    );
    let named = dir.to_string_lossy().into_owned();
    let tested = run(&["-test", "-confdir", &named]);
    assert_eq!(
        tested.status.code(),
        Some(0),
        "`-test` refused a YAML and TOML confdir: {}{}",
        String::from_utf8_lossy(&tested.stdout),
        String::from_utf8_lossy(&tested.stderr)
    );
    let dumped = run(&["-dump", "-confdir", &named]);
    let stdout = String::from_utf8_lossy(&dumped.stdout);
    assert_eq!(dumped.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains(r#""tag":"in""#) && stdout.contains(r#""protocol":"freedom""#),
        "`-dump` dropped a confdir file: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-format json` reads the JSON spellings alone, as the reference's regex does.
#[test]
fn a_confdir_honors_the_named_format() {
    let json = |tag: &str| {
        format!(
            r#"{{"inbounds":[{{"tag":"{tag}","listen":"127.0.0.1","port":0,"protocol":"socks","settings":{{"auth":"noauth"}}}}]}}"#
        )
    };
    let jsonc = |tag: &str| {
        format!(
            r#"{{
  // the named json format selects this file
  "inbounds":[{{"tag":"{tag}","listen":"127.0.0.1","port":0,"protocol":"socks","settings":{{"auth":"noauth"}}}}],
}}"#
        )
    };
    let yaml = r"inbounds:
  - tag: yaml
    listen: 127.0.0.1
    port: 0
    protocol: socks
    settings:
      auth: noauth
";
    let toml = r#"[[inbounds]]
tag = "toml"
listen = "127.0.0.1"
port = 0
protocol = "socks"
[inbounds.settings]
auth = "noauth"
"#;
    let dir = config_dir(
        "format-filter",
        &[
            ("01.json", &json("json")),
            ("02.jsonc", &jsonc("jsonc")),
            ("03.yaml", yaml),
            ("04.toml", toml),
        ],
    );
    let named = dir.to_string_lossy().into_owned();
    let dumped = run(&["-dump", "-confdir", &named, "-format", "json"]);
    let stdout = String::from_utf8_lossy(&dumped.stdout);
    assert_eq!(dumped.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains(r#""tag":"json""#) && stdout.contains(r#""tag":"jsonc""#),
        "`-format json` dropped a JSON config: {stdout}"
    );
    assert!(
        !stdout.contains(r#""tag":"yaml""#) && !stdout.contains(r#""tag":"toml""#),
        "`-format json` read a non-JSON config: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// On Linux a `@name` source is the abstract socket xray's resolver names.
#[cfg(target_os = "linux")]
#[test]
fn a_config_on_an_abstract_socket_is_fetched() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    let name = format!("ferrox-test-config-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let listener = UnixListener::bind_addr(&address).expect("bind abstract config socket");
    let body = configuration("json");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept abstract config request");
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = std::io::Read::read(&mut stream, &mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        std::io::Write::write_all(&mut stream, head.as_bytes()).expect("write HTTP head");
        std::io::Write::write_all(&mut stream, body.as_bytes()).expect("write HTTP body");
    });
    let output = run(&["-test", "-c", &format!("@{name}:/config.json")]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`-test` refused an abstract socket: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().expect("abstract config server");
}
