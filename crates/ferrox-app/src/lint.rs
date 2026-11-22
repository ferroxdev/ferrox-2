//! Post-processing stages run on a decoded config before it serves, the way the reference's
//! `PostProcessConfigureFile` walks its registry. A stage sees the same JSON the handlers read,
//! and a failure names the stage the way the reference's error does.

use crate::json::Json;

type Stage = fn(&mut Json) -> Result<(), String>;

/// The registry, in the reference's name order. `FakeDNS` is the reference's only built-in stage.
const STAGES: &[(&str, Stage)] = &[("FakeDNS", fakedns)];

pub(crate) fn run(root: &mut Json) -> Result<(), String> {
    for (name, stage) in STAGES {
        stage(root).map_err(|error| format!("Rejected by Postprocessing Stage {name}: {error}"))?;
    }
    Ok(())
}

/// The reference's `FakeDNS` stage: a `fakedns` nameserver with no `fakeDns` block gets the default
/// pool the query strategy allows, and a config that defines `FakeDNS` without sniffing it warns.
#[allow(clippy::unnecessary_wraps)]
fn fakedns(root: &mut Json) -> Result<(), String> {
    let Some(dns) = root.get("dns") else {
        return Ok(());
    };
    let in_use = dns
        .get("servers")
        .and_then(Json::as_arr)
        .is_some_and(|servers| servers.iter().any(names_fakedns));
    if !in_use {
        return Ok(());
    }
    let strategy = dns
        .get("queryStrategy")
        .and_then(Json::as_str)
        .map(str::to_ascii_lowercase);
    let (v4, v6) = match strategy.as_deref() {
        Some(
            "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4" | "use-ipv4"
            | "use-ip-v4",
        ) => (true, false),
        Some(
            "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6" | "use-ipv6"
            | "use-ip-v6",
        ) => (false, true),
        _ => (true, true),
    };
    if root
        .get("fakeDns")
        .is_none_or(|value| matches!(value, Json::Null))
    {
        let pools = default_pools(v4, v6);
        match root {
            Json::Obj(pairs) => {
                if let Some(entry) = pairs.iter_mut().find(|(key, _)| key.as_str() == "fakeDns") {
                    entry.1 = pools;
                } else {
                    pairs.push(("fakeDns".to_owned(), pools));
                }
            }
            _ => return Ok(()),
        }
    }
    if !sniffs_fakedns(root) {
        eprintln!("Defined FakeDNS but haven't enabled FakeDNS destOverride at any inbound.");
    }
    Ok(())
}

fn names_fakedns(server: &Json) -> bool {
    match server {
        Json::Str(address) => address.eq_ignore_ascii_case("fakedns"),
        Json::Obj(_) => server
            .get("address")
            .and_then(Json::as_str)
            .is_some_and(|address| address.eq_ignore_ascii_case("fakedns")),
        _ => false,
    }
}

fn default_pools(v4: bool, v6: bool) -> Json {
    let pool = |ip_pool: &str, size: u32| {
        Json::Obj(vec![
            ("ipPool".to_owned(), Json::Str(ip_pool.to_owned())),
            ("poolSize".to_owned(), Json::Num(f64::from(size))),
        ])
    };
    match (v4, v6) {
        (true, true) => Json::Arr(vec![
            pool(
                crate::dnsapp::FAKE_V4_POOL,
                crate::dnsapp::FAKE_DOUBLE_POOL_SIZE,
            ),
            pool(
                crate::dnsapp::FAKE_V6_POOL,
                crate::dnsapp::FAKE_DOUBLE_POOL_SIZE,
            ),
        ]),
        (false, true) => pool(
            crate::dnsapp::FAKE_V6_POOL,
            crate::dnsapp::FAKE_SINGLE_POOL_SIZE,
        ),
        (true, false) => pool(
            crate::dnsapp::FAKE_V4_POOL,
            crate::dnsapp::FAKE_SINGLE_POOL_SIZE,
        ),
        (false, false) => Json::Obj(Vec::new()),
    }
}

fn sniffs_fakedns(root: &Json) -> bool {
    root.get("inbounds")
        .and_then(Json::as_arr)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                let Some(sniffing) = inbound.get("sniffing") else {
                    return false;
                };
                if !sniffing
                    .get("enabled")
                    .and_then(Json::as_bool)
                    .unwrap_or(false)
                {
                    return false;
                }
                let override_list = sniffing
                    .get("destOverride")
                    .or_else(|| sniffing.get("destinationOverride"));
                match override_list {
                    Some(Json::Str(text)) => names_fakedns_override(text),
                    Some(Json::Arr(items)) => items
                        .iter()
                        .any(|item| item.as_str().is_some_and(names_fakedns_override)),
                    _ => false,
                }
            })
        })
}

fn names_fakedns_override(name: &str) -> bool {
    name.eq_ignore_ascii_case("fakedns") || name.eq_ignore_ascii_case("fakedns+others")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Json {
        crate::json::parse(text).expect("parses")
    }

    #[test]
    fn a_fakedns_nameserver_without_a_pool_gets_the_reference_defaults() {
        let mut root = parsed(r#"{"dns":{"servers":["fakedns"]}}"#);
        run(&mut root).expect("lint");
        assert_eq!(
            root.get("fakeDns"),
            Some(&Json::Arr(vec![
                Json::Obj(vec![
                    ("ipPool".to_owned(), Json::Str("198.18.0.0/15".to_owned())),
                    ("poolSize".to_owned(), Json::Num(32768.0)),
                ]),
                Json::Obj(vec![
                    ("ipPool".to_owned(), Json::Str("2001:2::/48".to_owned())),
                    ("poolSize".to_owned(), Json::Num(32768.0)),
                ]),
            ]))
        );
    }

    #[test]
    fn a_single_family_strategy_gets_one_pool_of_the_reference_size() {
        let mut v4 =
            parsed(r#"{"dns":{"servers":[{"address":"fakedns"}],"queryStrategy":"UseIPv4"}}"#);
        run(&mut v4).expect("lint");
        assert_eq!(
            v4.get("fakeDns"),
            Some(&Json::Obj(vec![
                ("ipPool".to_owned(), Json::Str("198.18.0.0/15".to_owned())),
                ("poolSize".to_owned(), Json::Num(65535.0)),
            ]))
        );

        let mut v6 = parsed(r#"{"dns":{"servers":["fakedns"],"queryStrategy":"use-ip-v6"}}"#);
        run(&mut v6).expect("lint");
        assert_eq!(
            v6.get("fakeDns"),
            Some(&Json::Obj(vec![
                ("ipPool".to_owned(), Json::Str("2001:2::/48".to_owned())),
                ("poolSize".to_owned(), Json::Num(65535.0)),
            ]))
        );
    }

    #[test]
    fn an_explicit_pool_is_left_alone() {
        let mut root = parsed(
            r#"{"dns":{"servers":["fakedns"]},"fakeDns":{"ipPool":"10.0.0.0/8","poolSize":8}}"#,
        );
        run(&mut root).expect("lint");
        assert_eq!(
            root.get("fakeDns"),
            Some(&Json::Obj(vec![
                ("ipPool".to_owned(), Json::Str("10.0.0.0/8".to_owned())),
                ("poolSize".to_owned(), Json::Num(8.0)),
            ]))
        );
    }

    #[test]
    fn a_null_fakedns_entry_is_replaced_in_place() {
        let mut root = parsed(r#"{"dns":{"servers":["fakedns"]},"fakeDns":null}"#);
        run(&mut root).expect("lint");
        assert_eq!(
            root.get("fakeDns"),
            Some(&Json::Arr(vec![
                Json::Obj(vec![
                    ("ipPool".to_owned(), Json::Str("198.18.0.0/15".to_owned())),
                    ("poolSize".to_owned(), Json::Num(32768.0)),
                ]),
                Json::Obj(vec![
                    ("ipPool".to_owned(), Json::Str("2001:2::/48".to_owned())),
                    ("poolSize".to_owned(), Json::Num(32768.0)),
                ]),
            ]))
        );
        let mut twice = root.clone();
        run(&mut twice).expect("lint");
        assert_eq!(root, twice);
    }

    #[test]
    fn a_config_without_fakedns_is_untouched() {
        let mut root = parsed(r#"{"dns":{"servers":["192.0.2.1"]}}"#);
        let before = root.clone();
        run(&mut root).expect("lint");
        assert_eq!(root, before);
    }

    #[test]
    fn the_stage_is_idempotent() {
        let mut once = parsed(r#"{"dns":{"servers":["fakedns"]}}"#);
        run(&mut once).expect("lint");
        let mut twice = once.clone();
        run(&mut twice).expect("lint");
        assert_eq!(once, twice);
    }

    #[test]
    fn an_inbound_that_sniffs_fakedns_silences_the_warning() {
        let sniffing = parsed(
            r#"{"inbounds":[{"sniffing":{"enabled":true,"destOverride":["fakedns+others"]}}]}"#,
        );
        assert!(sniffs_fakedns(&sniffing));
        let off =
            parsed(r#"{"inbounds":[{"sniffing":{"enabled":false,"destOverride":["fakedns"]}}]}"#);
        assert!(!sniffs_fakedns(&off));
        let alias = parsed(
            r#"{"inbounds":[{"sniffing":{"enabled":true,"destinationOverride":["fakedns"]}}]}"#,
        );
        assert!(sniffs_fakedns(&alias));
    }
}
