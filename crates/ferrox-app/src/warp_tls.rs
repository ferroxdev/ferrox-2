//! Chrome's `BoringSSL` hello for the WARP API and MASQUE handshakes, with the
//! fragment, cipher, group, GREASE and ECH overrides Aether's TLS options name.

use std::sync::Arc;

use base64::Engine as _;
use ferrox_core::finalmask::{Fragment, Range};
use ferrox_core::tls::shaped::{Body, Ext, Fingerprint, Profile};

use crate::json::Json;

const GREASE: u16 = 0x0a0a;
const SIZE: (i64, i64) = (8, 16);
const DELAY_MS: (i64, i64) = (2, 10);

#[derive(Debug, Clone)]
pub(crate) struct WarpTls {
    pub(crate) fragment: Option<Fragment>,
    pub(crate) ciphers: Option<Arc<[u16]>>,
    pub(crate) cipher_list: Option<String>,
    pub(crate) groups: Option<Arc<[u16]>>,
    pub(crate) group_list: Option<String>,
    pub(crate) grease: bool,
    pub(crate) fingerprint: Option<Fingerprint>,
    pub(crate) ech: Option<Arc<[u8]>>,
}

impl Default for WarpTls {
    fn default() -> Self {
        Self {
            fragment: None,
            ciphers: None,
            cipher_list: None,
            groups: None,
            group_list: None,
            grease: true,
            fingerprint: None,
            ech: None,
        }
    }
}

impl WarpTls {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        fragment: bool,
        size: Option<&str>,
        delay: Option<&str>,
        ciphers: Option<&str>,
        groups: Option<&str>,
        disable_grease: bool,
        ech: Option<&str>,
        ech_dns: Option<&str>,
        ech_domain: Option<&str>,
        server_name: &str,
    ) -> Result<Self, String> {
        let cipher_list = listed(ciphers);
        let group_list = listed(groups);
        let ciphers = cipher_list.as_deref().map(cipher_ids).transpose()?;
        let groups = group_list.as_deref().map(group_ids).transpose()?;
        let grease = !disable_grease;
        Ok(Self {
            fragment: fragment_stage(fragment, size, delay)?,
            fingerprint: (ciphers.is_some() || !grease).then(|| chrome(ciphers.as_deref(), grease)),
            ciphers: ciphers.map(Arc::from),
            cipher_list,
            groups: groups.map(Arc::from),
            group_list,
            grease,
            ech: ech_key(ech, ech_dns, ech_domain, server_name)?,
        })
    }

    pub(crate) fn from_settings(
        settings: Option<&Json>,
        server_name: &str,
    ) -> Result<Self, String> {
        let Some(settings) = settings else {
            return Ok(Self::default());
        };
        let fragment = match settings.get("fragment") {
            None | Some(Json::Null | Json::Bool(false)) => None,
            Some(Json::Bool(true)) => fragment_stage(
                true,
                settings.get("fragmentSize").and_then(Json::as_str),
                settings.get("fragmentDelay").and_then(Json::as_str),
            )?,
            Some(node @ Json::Obj(_)) => {
                let sni = node
                    .get("packets")
                    .and_then(Json::as_str)
                    .is_some_and(|packets| packets.eq_ignore_ascii_case("tlssni"));
                if sni {
                    return Err("warp: `fragment` must be a `tlshello` stage".to_owned());
                }
                Some(
                    crate::config::fragment(Some(node))
                        .ok_or("warp: `fragment` is not a stage this tree can drive")?,
                )
            }
            Some(_) => return Err("warp: `fragment` must be a bool or a stage object".to_owned()),
        };
        let cipher_list = settings
            .get("tlsCiphers")
            .and_then(Json::as_str)
            .map(str::to_owned)
            .filter(|text| !text.trim().is_empty());
        let ciphers = match settings.get("tlsCiphers") {
            Some(Json::Arr(items)) => Some(u16_array(items)?),
            _ => cipher_list.as_deref().map(cipher_ids).transpose()?,
        };
        let group_list = settings
            .get("tlsGroups")
            .and_then(Json::as_str)
            .map(str::to_owned)
            .filter(|text| !text.trim().is_empty());
        let groups = match settings.get("tlsGroups") {
            Some(Json::Arr(items)) => Some(group_array(items)?),
            _ => group_list.as_deref().map(group_ids).transpose()?,
        };
        let grease = !settings
            .get("disableGrease")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let ech = ech_key(
            settings.get("ech").and_then(Json::as_str),
            settings.get("echDns").and_then(Json::as_str),
            settings.get("echDomain").and_then(Json::as_str),
            server_name,
        )?;
        Ok(Self {
            fragment,
            fingerprint: (ciphers.is_some() || !grease).then(|| chrome(ciphers.as_deref(), grease)),
            ciphers: ciphers.map(Arc::from),
            cipher_list,
            groups: groups.map(Arc::from),
            group_list,
            grease,
            ech,
        })
    }

    /// The same hello on a TLS config: the WARP API and the MASQUE h2 carrier
    /// both build one, so the two handshakes cannot drift apart.
    pub(crate) fn apply(
        &self,
        mut cfg: ferrox_core::tls::TlsConfig,
    ) -> ferrox_core::tls::TlsConfig {
        if let Some(fingerprint) = self.fingerprint {
            cfg.fingerprint = Some(fingerprint);
        }
        if let Some(groups) = &self.groups {
            cfg.curves = Arc::clone(groups);
        }
        if let Some(ech) = &self.ech {
            cfg.ech_config_list = Some(Arc::clone(ech));
        }
        if let Some(fragment) = &self.fragment {
            cfg.fragment = Some(fragment.clone());
        }
        cfg
    }

    /// The stage object the `warp` outbound carries for the inner MASQUE one.
    pub(crate) fn json(&self) -> Option<Json> {
        let mut pairs = Vec::new();
        if let Some(fragment) = &self.fragment {
            pairs.push(("fragment", fragment_json(fragment)));
        }
        if let Some(ciphers) = &self.ciphers {
            pairs.push(("tlsCiphers", number_list(ciphers)));
        }
        if let Some(groups) = &self.groups {
            pairs.push(("tlsGroups", number_list(groups)));
        }
        if !self.grease {
            pairs.push(("disableGrease", Json::Bool(true)));
        }
        if let Some(ech) = &self.ech {
            pairs.push((
                "ech",
                Json::Str(base64::engine::general_purpose::STANDARD.encode(ech)),
            ));
        }
        (!pairs.is_empty()).then(|| object(pairs))
    }

    /// The settings one-tap prints: the flags' own spelling when they had one.
    pub(crate) fn settings(&self) -> Vec<(&'static str, Json)> {
        let mut pairs = Vec::new();
        if let Some(fragment) = &self.fragment {
            pairs.push(("fragment", Json::Bool(true)));
            pairs.push((
                "fragmentSize",
                Json::Str(range_text(&fragment.lengths[0], SIZE)),
            ));
            pairs.push((
                "fragmentDelay",
                Json::Str(range_text(&fragment.delays[0], DELAY_MS)),
            ));
        }
        if let Some(list) = &self.cipher_list {
            pairs.push(("tlsCiphers", Json::Str(list.clone())));
        } else if let Some(ciphers) = &self.ciphers {
            pairs.push(("tlsCiphers", number_list(ciphers)));
        }
        if let Some(list) = &self.group_list {
            pairs.push(("tlsGroups", Json::Str(list.clone())));
        } else if let Some(groups) = &self.groups {
            pairs.push(("tlsGroups", number_list(groups)));
        }
        if !self.grease {
            pairs.push(("disableGrease", Json::Bool(true)));
        }
        if let Some(ech) = &self.ech {
            pairs.push((
                "ech",
                Json::Str(base64::engine::general_purpose::STANDARD.encode(ech)),
            ));
        }
        pairs
    }
}

/// Chrome's hello with the TLS 1.2 suites and GREASE values the flags name.
fn chrome(ciphers: Option<&[u16]>, grease: bool) -> Fingerprint {
    let base = Fingerprint::resolve("chrome_plain")
        .and_then(Fingerprint::profile)
        .expect("chrome_plain is a preset");
    if ciphers.is_none() && grease {
        return Fingerprint::custom(base);
    }
    let table: Vec<u16> = match ciphers {
        Some(list) => base
            .ciphers
            .iter()
            .copied()
            .filter(|id| *id == GREASE || tls13(*id))
            .chain(
                list.iter()
                    .copied()
                    .filter(|id| *id != GREASE && !tls13(*id)),
            )
            .collect(),
        None => base.ciphers.to_vec(),
    };
    let table: Vec<u16> = table
        .into_iter()
        .filter(|id| grease || *id != GREASE)
        .collect();
    let exts = if grease {
        base.exts
    } else {
        let kept: Vec<Ext> = base
            .exts
            .iter()
            .filter(|ext| ext.kind != GREASE)
            .map(|ext| Ext {
                kind: ext.kind,
                body: without_grease(ext.body),
            })
            .collect();
        Box::leak(kept.into_boxed_slice())
    };
    let table = Box::leak(table.into_boxed_slice());
    let profile = Box::leak(Box::new(Profile {
        name: base.name,
        ciphers: table,
        shuffle: base.shuffle,
        exts,
    }));
    Fingerprint::custom(profile)
}

fn without_grease(body: Body) -> Body {
    match body {
        Body::Groups(groups) => Body::Groups(leak_without_grease(groups)),
        Body::KeyShare { groups, reuse } => Body::KeyShare {
            groups: leak_without_grease(groups),
            reuse,
        },
        Body::Versions(versions) => Body::Versions(leak_without_grease(versions)),
        other => other,
    }
}

fn leak_without_grease(values: &'static [u16]) -> &'static [u16] {
    let kept: Vec<u16> = values.iter().copied().filter(|id| *id != GREASE).collect();
    Box::leak(kept.into_boxed_slice())
}

fn tls13(id: u16) -> bool {
    (0x1300..=0x13ff).contains(&id)
}

/// The TLS 1.2 suites a `BoringSSL` cipher string names, in its order.
fn cipher_ids(list: &str) -> Result<Vec<u16>, String> {
    use boring::ssl::{SslContextBuilder, SslMethod};
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|error| format!("warp: tls ciphers: {error}"))?;
    builder
        .set_strict_cipher_list(list)
        .map_err(|_| format!("warp: --tls-ciphers `{list}` is no cipher list BoringSSL takes"))?;
    let ids: Vec<u16> = builder.ciphers().map_or_default(|ciphers| {
        ciphers
            .iter()
            .map(boring::ssl::SslCipherRef::protocol_id)
            .filter(|id| *id != GREASE && !tls13(*id))
            .collect()
    });
    if ids.is_empty() {
        return Err(format!(
            "warp: --tls-ciphers `{list}` names no TLS 1.2 suite"
        ));
    }
    Ok(ids)
}

/// The groups a `BoringSSL` group list names, in its order.
fn group_ids(list: &str) -> Result<Vec<u16>, String> {
    use boring::ssl::{SslContextBuilder, SslMethod};
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|error| format!("warp: tls groups: {error}"))?;
    builder
        .set_curves_list(list)
        .map_err(|_| format!("warp: --tls-groups `{list}` is no group list BoringSSL takes"))?;
    let mut ids = Vec::new();
    for name in list
        .split(':')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let id = group_id(name).ok_or_else(|| {
            format!("warp: --tls-groups `{name}` is a group this tree cannot carry")
        })?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

const GROUPS: &[(u16, &[&str])] = &[
    (0x0017, &["p-256", "prime256v1", "secp256r1"]),
    (0x0018, &["p-384", "secp384r1"]),
    (0x001d, &["x25519"]),
    (0x11ec, &["x25519mlkem768"]),
    (0x6399, &["x25519kyber768draft00"]),
];

fn group_id(name: &str) -> Option<u16> {
    let name = name.to_ascii_lowercase();
    GROUPS
        .iter()
        .find(|(_, names)| names.contains(&name.as_str()))
        .map(|(id, _)| *id)
}

fn group_supported(id: u16) -> bool {
    GROUPS.iter().any(|(known, _)| *known == id)
}

fn group_array(items: &[Json]) -> Result<Vec<u16>, String> {
    let values = u16_array(items)?;
    for id in &values {
        if !group_supported(*id) {
            return Err(format!(
                "warp: tls group {id} is a group this tree cannot carry"
            ));
        }
    }
    Ok(values)
}

fn fragment_stage(
    enabled: bool,
    size: Option<&str>,
    delay: Option<&str>,
) -> Result<Option<Fragment>, String> {
    if !enabled {
        return Ok(None);
    }
    let (low, high) = inclusive(size, SIZE, "--fragment-size")?;
    let (delay_low, delay_high) = inclusive(delay, DELAY_MS, "--fragment-delay")?;
    Fragment::new(
        0,
        1,
        vec![Range::ordered(low, high.saturating_add(1))],
        vec![Range::ordered(delay_low, delay_high.saturating_add(1))],
        Range::ordered(0, 0),
    )
    .map(Some)
    .ok_or_else(|| "warp: --fragment names a cut this tree cannot drive".to_owned())
}

fn inclusive(text: Option<&str>, default: (i64, i64), flag: &str) -> Result<(i64, i64), String> {
    let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(default);
    };
    let parsed = if let Some((low, high)) = text.split_once('-') {
        let low: i64 = low
            .trim()
            .parse()
            .map_err(|_| format!("warp: {flag} `{text}` is not a size"))?;
        let high: i64 = high
            .trim()
            .parse()
            .map_err(|_| format!("warp: {flag} `{text}` is not a size"))?;
        (low.min(high), low.max(high))
    } else {
        let value: i64 = text
            .parse()
            .map_err(|_| format!("warp: {flag} `{text}` is not a size"))?;
        (value, value)
    };
    Ok((parsed.0.max(0), parsed.1.max(0)))
}

fn ech_key(
    setting: Option<&str>,
    dns: Option<&str>,
    domain: Option<&str>,
    server_name: &str,
) -> Result<Option<Arc<[u8]>>, String> {
    let Some(setting) = listed(setting) else {
        return Ok(None);
    };
    let text = if setting.eq_ignore_ascii_case("auto") {
        let domain = listed(domain).unwrap_or_else(|| "cloudflare-ech.com".to_owned());
        let dns = listed(dns).unwrap_or_else(|| crate::warp::ECH_RESOLVER.to_owned());
        format!("{domain}+{dns}")
    } else {
        setting
    };
    let list = crate::ech_dns::resolve(&text, server_name, None)
        .map_err(|why| format!("warp: --ech: {why}"))?;
    Ok(Some(Arc::from(list)))
}

fn listed(text: Option<&str>) -> Option<String> {
    text.map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn u16_array(items: &[Json]) -> Result<Vec<u16>, String> {
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let value = item
            .as_u32()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or("warp: a cipher or group id is not a u16")?;
        values.push(value);
    }
    Ok(values)
}

fn fragment_json(fragment: &Fragment) -> Json {
    let packets = match (fragment.packets_from, fragment.packets_to) {
        (0, 0) => String::new(),
        (0, 1) => "tlshello".to_owned(),
        (from, to) => format!("{from}-{to}"),
    };
    let ranges = |ranges: &[Range]| {
        Json::Arr(
            ranges
                .iter()
                .map(|range| Json::Str(format!("{}-{}", range.low, range.high)))
                .collect(),
        )
    };
    object(vec![
        ("packets", Json::Str(packets)),
        ("lengths", ranges(&fragment.lengths)),
        ("delays", ranges(&fragment.delays)),
        (
            "maxSplit",
            Json::Str(format!(
                "{}-{}",
                fragment.max_split.low, fragment.max_split.high
            )),
        ),
    ])
}

fn range_text(range: &Range, default: (i64, i64)) -> String {
    if range.low == default.0 && range.high == default.1 + 1 {
        format!("{}-{}", default.0, default.1)
    } else if range.high <= range.low + 1 {
        range.low.to_string()
    } else {
        format!("{}-{}", range.low, range.high - 1)
    }
}

fn number_list(values: &[u16]) -> Json {
    Json::Arr(
        values
            .iter()
            .map(|value| Json::Num(f64::from(*value)))
            .collect(),
    )
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fragment_default_size_and_delay_match_aether() {
        let stage = fragment_stage(true, None, None)
            .expect("a stage")
            .expect("the default stage");
        assert_eq!(stage.lengths[0].low, 8);
        assert_eq!(stage.lengths[0].high - 1, 16);
        assert_eq!(stage.delays[0].low, 2);
        assert_eq!(stage.delays[0].high - 1, 10);
    }

    #[test]
    fn a_fragment_range_is_inclusive_at_both_ends() {
        let stage = fragment_stage(true, Some("16-8"), Some("10-2"))
            .expect("a stage")
            .expect("the named stage");
        assert_eq!((stage.lengths[0].low, stage.lengths[0].high), (8, 17));
        assert_eq!((stage.delays[0].low, stage.delays[0].high), (2, 11));
        let exact = fragment_stage(true, Some("12"), Some("0"))
            .expect("a stage")
            .expect("the exact stage");
        assert_eq!((exact.lengths[0].low, exact.lengths[0].high), (12, 13));
        assert_eq!((exact.delays[0].low, exact.delays[0].high), (0, 1));
    }

    #[test]
    fn the_default_profile_carries_chromes_tls12_suites() {
        let profile = chrome(None, true).profile().expect("a shaped profile");
        let suites = profile
            .ciphers
            .iter()
            .filter(|id| **id != GREASE && !tls13(**id))
            .count();
        assert_eq!(suites, 12);
    }

    #[test]
    fn a_shaped_chrome_keeps_an_ech_slot() {
        let has_ech = |profile: &Profile| {
            profile
                .exts
                .iter()
                .any(|ext| matches!(ext.body, Body::Ech { .. }))
        };
        assert!(has_ech(chrome(None, true).profile().expect("a profile")));
        assert!(has_ech(chrome(None, false).profile().expect("a profile")));
        assert!(has_ech(
            chrome(Some(&[0xc02f]), true).profile().expect("a profile")
        ));
    }

    #[test]
    fn a_cipher_list_follows_chromes_tls13_trio() {
        let ids = cipher_ids("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
            .expect("BoringSSL reads it");
        assert_eq!(ids, [0xc02f, 0xc02b]);
        let profile = chrome(Some(&ids), true)
            .profile()
            .expect("a shaped profile");
        assert_eq!(&profile.ciphers[..4], &[GREASE, 0x1301, 0x1302, 0x1303]);
        assert_eq!(&profile.ciphers[4..], &ids);
    }

    #[test]
    fn disabling_grease_removes_every_sentinel() {
        let profile = chrome(None, false).profile().expect("a shaped profile");
        assert!(!profile.ciphers.contains(&GREASE));
        assert!(!profile.exts.iter().any(|ext| ext.kind == GREASE));
        for ext in profile.exts {
            let Body::Groups(groups) = ext.body else {
                continue;
            };
            assert!(!groups.contains(&GREASE));
        }
        for ext in profile.exts {
            match ext.body {
                Body::KeyShare { groups, .. } => assert!(!groups.contains(&GREASE)),
                Body::Versions(versions) => assert!(!versions.contains(&GREASE)),
                _ => {}
            }
        }
    }

    #[test]
    fn the_group_list_keeps_boringssls_order() {
        assert_eq!(
            group_ids("P-256:X25519:P-384").expect("BoringSSL reads it"),
            [0x0017, 0x001d, 0x0018]
        );
        assert!(group_ids("P-256:NO-SUCH-GROUP").is_err());
    }

    #[test]
    fn a_numeric_group_list_rejects_a_group_with_no_shaped_share() {
        let json = crate::json::parse(r#"{"tlsGroups":[25]}"#).expect("the settings");
        let error = WarpTls::from_settings(Some(&json), "consumer-masque.cloudflareclient.com")
            .expect_err("P-521 has no shaped key share");
        assert!(error.contains("25"), "{error}");
    }

    #[test]
    fn a_numeric_group_list_keeps_every_group_with_a_shaped_share() {
        for id in [0x0017, 0x0018, 0x001d, 0x11ec, 0x6399] {
            let json =
                crate::json::parse(&format!(r#"{{"tlsGroups":[{id}]}}"#)).expect("the settings");
            let tls = WarpTls::from_settings(Some(&json), "consumer-masque.cloudflareclient.com")
                .expect("a group the tree can carry");
            assert_eq!(tls.groups.as_deref(), Some(&[id][..]));
        }
    }

    #[test]
    fn a_full_fragment_stage_round_trips_through_its_json() {
        let stage = crate::json::parse(
            r#"{"packets":"2-3","lengths":["4-9","8"],"delays":["1-3"],"maxSplit":"3"}"#,
        )
        .expect("the stage json");
        let tls = WarpTls {
            fragment: crate::config::fragment(Some(&stage)),
            ..Default::default()
        };
        let text = {
            let mut out = String::new();
            crate::json::write(&tls.json().expect("a block"), &mut out);
            out
        };
        let json = crate::json::parse(&text).expect("the JSON");
        let again = WarpTls::from_settings(Some(&json), "consumer-masque.cloudflareclient.com")
            .expect("the block");
        let stage = again.fragment.expect("a stage");
        assert_eq!((stage.packets_from, stage.packets_to), (2, 3));
        assert_eq!(
            stage
                .lengths
                .iter()
                .map(|range| (range.low, range.high))
                .collect::<Vec<_>>(),
            [(4, 9), (8, 8)]
        );
        assert_eq!(
            stage
                .delays
                .iter()
                .map(|range| (range.low, range.high))
                .collect::<Vec<_>>(),
            [(1, 3)]
        );
        assert_eq!((stage.max_split.low, stage.max_split.high), (3, 3));
    }

    #[test]
    fn a_sni_cut_is_refused_because_its_json_cannot_name_it() {
        let json = crate::json::parse(
            r#"{"fragment":{"packets":"tlssni","lengths":["8-16"],"delays":["2-10"]}}"#,
        )
        .expect("the stage json");
        assert!(
            WarpTls::from_settings(Some(&json), "consumer-masque.cloudflareclient.com").is_err()
        );
    }

    #[test]
    fn a_warp_tls_block_round_trips_through_its_json() {
        let tls = WarpTls::from_parts(
            true,
            None,
            None,
            Some("ECDHE-RSA-AES128-GCM-SHA256"),
            Some("P-256:X25519"),
            true,
            None,
            None,
            None,
            "consumer-masque.cloudflareclient.com",
        )
        .expect("the flags");
        let text = {
            let mut out = String::new();
            crate::json::write(&tls.json().expect("a block"), &mut out);
            out
        };
        let json = crate::json::parse(&text).expect("the JSON");
        let again = WarpTls::from_settings(Some(&json), "consumer-masque.cloudflareclient.com")
            .expect("the block");
        assert_eq!(again.ciphers.as_deref(), Some(&[0xc02f][..]));
        assert_eq!(again.groups.as_deref(), Some(&[0x0017, 0x001d][..]));
        assert!(!again.grease);
        let fragment = again.fragment.expect("a fragment");
        assert_eq!((fragment.lengths[0].low, fragment.lengths[0].high), (8, 17));
    }
}
