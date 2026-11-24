//! Zero Trust enrolment: a team's `cloudflareaccess.com` device page, the three ways it hands out
//! a device JWT, and the `CF-Access-Jwt-Assertion` header the WARP API reads. The HTTP exchange is
//! a closure so the flow's redirects, cookies and parsing are testable without a network.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use crate::foxy_account::{Endpoint, Reply};

const TEAM_SUFFIX: &str = "cloudflareaccess.com";
const TEAM_DOMAIN_SUFFIX: &str = ".cloudflareaccess.com";
const ENROLL_PATH: &str = "/warp";
const CODE_ATTEMPTS: u32 = 3;
const INSTALL_ID_LEN: usize = 22;
const FCM_SUFFIX_LEN: usize = 134;
const MAX_REDIRECTS: usize = 10;
const ACCESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

const UA_REGISTER: &str = crate::warp::REGISTER_AGENT;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TeamSettings {
    pub(crate) team: String,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) email: Option<String>,
}

/// The one exchange a flow makes, with the redirect and cookie policy left to the caller.
type Exchange<'a> = dyn Fn(&str, &str, &[(&str, &str)], &[u8]) -> Result<Reply, String> + 'a;

impl TeamSettings {
    pub(crate) fn from_settings(settings: &crate::json::Json) -> Result<Option<Self>, String> {
        let text = |key: &str| -> Result<Option<&str>, String> {
            match settings.get(key) {
                None => Ok(None),
                Some(crate::json::Json::Str(text)) => Ok(Some(text)),
                Some(_) => Err(format!("warp: `{key}` must be a string")),
            }
        };
        Self::from_parts(
            text("team")?,
            text("accessClientId")?,
            text("accessClientSecret")?,
            text("accessToken")?,
            text("accessEmail")?,
        )
    }

    pub(crate) fn from_parts(
        team: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        token: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<Self>, String> {
        Self::from_parts_with(team, client_id, client_secret, token, email, |key| {
            std::env::var(key).ok()
        })
    }

    fn from_parts_with<F>(
        team: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        token: Option<&str>,
        email: Option<&str>,
        env: F,
    ) -> Result<Option<Self>, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        if team.is_some_and(|text| text.trim().is_empty()) {
            return Err("warp: the named team is empty; omit it or name the subdomain".to_owned());
        }
        let raw = pick(team, "AETHER_TEAM", &env);
        let Some(raw) = raw else {
            let supplied = pick(client_id, "AETHER_ACCESS_CLIENT_ID", &env).is_some()
                || pick(client_secret, "AETHER_ACCESS_CLIENT_SECRET", &env).is_some()
                || pick(token, "AETHER_ACCESS_TOKEN", &env).is_some()
                || pick(email, "AETHER_ACCESS_EMAIL", &env).is_some();
            if supplied {
                return Err(
                    "warp: access credentials need a team; name `team` or AETHER_TEAM".to_owned(),
                );
            }
            return Ok(None);
        };
        let team = normalize_team(&raw).ok_or_else(|| {
            format!(
                "warp: `{raw}` is not a usable team name; name the subdomain of <team>.{TEAM_SUFFIX}"
            )
        })?;
        Ok(Some(Self {
            team,
            client_id: pick(client_id, "AETHER_ACCESS_CLIENT_ID", &env),
            client_secret: pick(client_secret, "AETHER_ACCESS_CLIENT_SECRET", &env),
            token: pick(token, "AETHER_ACCESS_TOKEN", &env),
            email: pick(email, "AETHER_ACCESS_EMAIL", &env),
        }))
    }

    fn has_service_token(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }

    pub(crate) fn team_domain(&self) -> String {
        team_domain(&self.team)
    }

    fn login_url(&self) -> String {
        format!("{}{ENROLL_PATH}", self.team_domain())
    }
}

fn pick<F>(value: Option<&str>, key: &str, env: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            env(key)
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty())
        })
}

pub(crate) fn normalize_team(raw: &str) -> Option<String> {
    let mut value = raw.trim().to_lowercase();
    if value.is_empty() {
        return None;
    }
    for prefix in ["https://", "http://"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            value = rest.to_owned();
        }
    }
    value = value.trim_end_matches('/').to_owned();
    if let Some(head) = value.split('/').next() {
        value = head.to_owned();
    }
    if let Some(head) = value.strip_suffix(TEAM_DOMAIN_SUFFIX) {
        value = head.to_owned();
    } else if value == TEAM_SUFFIX {
        return None;
    }
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some(value)
}

fn team_domain(team: &str) -> String {
    format!("https://{team}.{TEAM_SUFFIX}")
}

fn looks_like_jwt(token: &str) -> bool {
    let token = token.trim();
    if token.len() < 32 {
        return false;
    }
    let segments: Vec<&str> = token.split('.').collect();
    segments.len() == 3
        && segments.iter().all(|segment| !segment.is_empty())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && decode_segment(segments[0]).is_some()
}

fn decode_segment(segment: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
}

fn jwt_expiry(token: &str) -> Option<u64> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return None;
    }
    let payload = decode_segment(segments[1])?;
    let root = crate::json::parse(&String::from_utf8_lossy(&payload)).ok()?;
    root.get("exp")
        .and_then(crate::json::Json::as_i64)
        .and_then(|expiry| u64::try_from(expiry).ok())
}

fn jwt_team(token: &str) -> Option<String> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return None;
    }
    let payload = decode_segment(segments[1])?;
    let root = crate::json::parse(&String::from_utf8_lossy(&payload)).ok()?;
    root.get("iss")
        .and_then(crate::json::Json::as_str)
        .and_then(normalize_team)
}

fn jwt_expired(token: &str, now: u64) -> bool {
    jwt_expiry(token).is_none_or(|expiry| expiry <= now)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn extract_jwt_from_html(html: &str) -> Option<String> {
    let marker = "token=";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest
        .find(|c: char| {
            c == '"' || c == '\'' || c == '&' || c == '<' || c == '>' || c.is_whitespace()
        })
        .unwrap_or(rest.len());
    let candidate = rest[..end].trim();
    looks_like_jwt(candidate).then(|| candidate.to_owned())
}

fn extract_jwt_from_cookie(header: &str) -> Option<String> {
    for part in header.split(';') {
        let entry = part.trim();
        let value = entry
            .strip_prefix("CF_Authorization=")
            .or_else(|| entry.strip_prefix("cf_authorization="))?;
        if looks_like_jwt(value) {
            return Some(value.to_owned());
        }
    }
    None
}

fn cookie_expires_at(header: &str) -> Option<u64> {
    let mut max_age = None;
    let mut expires = None;
    for attribute in header.split(';').skip(1) {
        let Some((name, value)) = attribute.split_once('=') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "max-age" => max_age = value.trim().parse::<i64>().ok(),
            "expires" => expires = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    max_age
        .map(|seconds| {
            if seconds <= 0 {
                0
            } else {
                now().saturating_add(u64::try_from(seconds).unwrap_or(u64::MAX))
            }
        })
        .or_else(|| expires.as_deref().and_then(http_date))
}

fn issued_token(reply: &Reply) -> Option<String> {
    let at = now();
    reply
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, value)| {
            let token = extract_jwt_from_cookie(value)?;
            if cookie_expires_at(value).is_some_and(|expires| expires <= at) {
                return None;
            }
            let expiry = jwt_expiry(&token).filter(|&expiry| at < expiry)?;
            Some((expiry, token))
        })
        .max_by_key(|(expiry, _)| *expiry)
        .map(|(_, token)| token)
}

fn extract_totp_form_action(html: &str) -> Option<String> {
    let anchor = html.find("id=\"totp-form\"")?;
    let head = &html[..anchor];
    let form_start = head.rfind("<form")?;
    let tag_end = html[form_start..].find('>')? + form_start;
    let tag = &html[form_start..tag_end];
    let key = "action=";
    let key_at = tag.find(key)? + key.len();
    let rest = tag[key_at..].trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let body = &rest[1..];
    let end = body.find(quote)?;
    let action = decode_entities(&body[..end]);
    action.starts_with("https://").then_some(action)
}

fn decode_entities(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let window = &rest.as_bytes()[..rest.len().min(9)];
        let end = match window.iter().position(|&byte| byte == b';') {
            Some(index) => index,
            None => {
                out.push('&');
                rest = &rest[1..];
                continue;
            }
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            other => other
                .strip_prefix("#x")
                .or_else(|| other.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| other.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = decoded {
            out.push(c);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1.split('#').next().unwrap_or("");
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            if name == key {
                return Some(percent_decode(value));
            }
        }
    }
    None
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(out: &mut String, text: &str) {
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
}

fn form_encode(form: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in form.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        percent_encode(&mut out, key);
        out.push('=');
        percent_encode(&mut out, value);
    }
    out
}

pub(crate) fn generate_install_id() -> String {
    random_alphanumeric(INSTALL_ID_LEN)
}

pub(crate) fn generate_fcm_token(install_id: &str) -> String {
    format!("{install_id}:APA91b{}", random_alphanumeric(FCM_SUFFIX_LEN))
}

fn random_alphanumeric(len: usize) -> String {
    const ALPHANUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).expect("the OS entropy");
    bytes
        .into_iter()
        .map(|byte| char::from(ALPHANUM[usize::from(byte) % ALPHANUM.len()]))
        .collect()
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn url_origin(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty()).then_some((scheme, authority))
}

fn origin(url: &str) -> Option<String> {
    let (scheme, authority) = url_origin(url)?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let (host, port) = split_authority(&authority)?;
    let default = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    let port = match port {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => None,
    }
    .filter(|port| *port != default);
    Some(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &authority[..end + 2];
        return match &rest[end + 1..] {
            "" => Some((host, None)),
            tail => tail.strip_prefix(':').map(|port| (host, Some(port))),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some((host, Some(port)))
        }
        _ => Some((authority, None)),
    }
}

fn url_host(url: &str) -> Option<&str> {
    let (_, authority) = url_origin(url)?;
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']')
            .map(|(host, _)| &authority[..host.len() + 2])
    } else {
        authority.split(':').next()
    }
}

fn url_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if !rest[start..].starts_with('/') {
        return "/";
    }
    let path = rest[start..].split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

fn https_target(url: &str) -> Option<(String, String)> {
    let (scheme, authority) = url_origin(url)?;
    if scheme != "https" {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let mut target = rest[start..].split('#').next().unwrap_or("").to_owned();
    if target.is_empty() {
        target.push('/');
    } else if target.starts_with('?') {
        target.insert(0, '/');
    }
    Some((format!("https://{authority}"), target))
}

fn default_cookie_path(path: &str) -> String {
    if !path.starts_with('/') {
        return "/".to_owned();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(at) => path[..at].to_owned(),
    }
}

fn http_date(value: &str) -> Option<u64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let (year, month, day, clock) = match parts.as_slice() {
        [_weekday, day, month, year, clock, "GMT"] => (
            year.parse::<i64>().ok()?,
            month_number(month)?,
            day.parse::<u32>().ok()?,
            *clock,
        ),
        [_weekday, date, clock, "GMT"] => {
            let mut date = date.split('-');
            let day = date.next()?.parse::<u32>().ok()?;
            let month = month_number(date.next()?)?;
            let year = date.next()?;
            let year = if year.len() == 2 {
                let short = year.parse::<i64>().ok()?;
                if short >= 70 {
                    1900 + short
                } else {
                    2000 + short
                }
            } else {
                year.parse::<i64>().ok()?
            };
            (year, month, day, *clock)
        }
        [_weekday, month, day, clock, year] => (
            year.parse::<i64>().ok()?,
            month_number(month)?,
            day.parse::<u32>().ok()?,
            *clock,
        ),
        _ => return None,
    };
    if !(1601..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hour, minute, second) = parse_clock(clock)?;
    let seconds = days_from_civil(year, month, day)
        .checked_mul(86_400)?
        .checked_add(i64::from(hour * 3600 + minute * 60 + second))?;
    if seconds < 0 {
        Some(0)
    } else {
        u64::try_from(seconds).ok()
    }
}

fn parse_clock(clock: &str) -> Option<(u32, u32, u32)> {
    let mut parts = clock.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn month_number(month: &str) -> Option<u32> {
    match month.get(..3)?.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn resolve_url(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    let (scheme, authority) = url_origin(base)?;
    if location.is_empty() {
        return Some(base.split('#').next().unwrap_or(base).to_owned());
    }
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Some(normalize_path(location));
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Some(normalize_path(&format!("{scheme}://{rest}")));
    }
    let base = base.split('#').next().unwrap_or(base);
    if let Some(fragment) = location.strip_prefix('#') {
        return Some(format!("{base}#{fragment}"));
    }
    if let Some(query) = location.strip_prefix('?') {
        let path = base.split_once('?').map_or(base, |(path, _)| path);
        return Some(format!("{path}?{query}"));
    }
    if let Some(absolute) = location.strip_prefix('/') {
        return Some(normalize_path(&format!(
            "{scheme}://{authority}/{absolute}"
        )));
    }
    let path = url_path(base);
    let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    Some(normalize_path(&format!(
        "{scheme}://{authority}{dir}/{location}"
    )))
}

fn normalize_path(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let tail = &rest[end..];
    let cut = tail.find(['?', '#']).unwrap_or(tail.len());
    let (path, suffix) = tail.split_at(cut);
    if !path.starts_with('/') {
        return url.to_owned();
    }
    let mut out = format!("{scheme}://{authority}{}", remove_dot_segments(path));
    out.push_str(suffix);
    out
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut out = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            pop_segment(&mut out);
        } else if input == "/.." {
            input = "/";
            pop_segment(&mut out);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map_or(input.len(), |at| start + at);
            out.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    out
}

fn pop_segment(out: &mut String) {
    if let Some(at) = out.rfind('/') {
        out.truncate(at);
    } else {
        out.clear();
    }
}

fn resolve_redirect(current: &str, location: &str) -> Result<String, String> {
    let next = resolve_url(current, location)
        .ok_or_else(|| "warp access: the redirect target is not a usable URL".to_owned())?;
    if !next.to_ascii_lowercase().starts_with("https://") {
        return Err("warp access: refusing a redirect away from https".to_owned());
    }
    if next.starts_with("https://") {
        return Ok(next);
    }
    let rest = next.split_once("://").map_or("", |(_, rest)| rest);
    Ok(format!("https://{rest}"))
}

struct Cookie {
    name: String,
    value: String,
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    expires_at: Option<u64>,
}

impl Cookie {
    fn matches(&self, url: &str) -> bool {
        if self.expires_at.is_some_and(|at| at <= now()) {
            return false;
        }
        let Some(host) = url_host(url) else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        let domain = if self.host_only {
            host == self.domain
        } else {
            host == self.domain || host.ends_with(&format!(".{}", self.domain))
        };
        if !domain || (self.secure && !url.to_ascii_lowercase().starts_with("https://")) {
            return false;
        }
        let path = url_path(url);
        path == self.path
            || (path.starts_with(&self.path)
                && (self.path.ends_with('/')
                    || path.as_bytes().get(self.path.len()) == Some(&b'/')))
    }
}

struct Session {
    cookies: Vec<Cookie>,
    allowed_origin: Option<String>,
}

struct Page {
    url: String,
    reply: Reply,
    token: Option<String>,
}

impl Session {
    #[cfg(test)]
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
            allowed_origin: None,
        }
    }

    fn for_origin(url: &str) -> Self {
        Self {
            cookies: Vec::new(),
            allowed_origin: origin(url),
        }
    }

    fn trusts(&self, url: &str) -> bool {
        self.allowed_origin
            .as_deref()
            .is_none_or(|allowed| origin(url).as_deref() == Some(allowed))
    }

    fn exchange(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        exchange: &Exchange<'_>,
    ) -> Result<Reply, String> {
        let mut owned: Vec<(String, String)> = headers
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let trusted = self.trusts(url);
        let mut jar = String::new();
        if trusted {
            for cookie in self.cookies.iter().filter(|cookie| cookie.matches(url)) {
                if !jar.is_empty() {
                    jar.push_str("; ");
                }
                jar.push_str(&cookie.name);
                jar.push('=');
                jar.push_str(&cookie.value);
            }
        }
        if !jar.is_empty() {
            owned.push(("Cookie".to_owned(), jar));
        }
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let reply = exchange(method, url, &borrowed, body)?;
        if trusted {
            self.absorb(url, &reply);
        }
        Ok(reply)
    }

    fn absorb(&mut self, url: &str, reply: &Reply) {
        let Some(host) = url_host(url).map(str::to_ascii_lowercase) else {
            return;
        };
        let request_path = url_path(url);
        for (name, value) in &reply.headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let mut parts = value.split(';');
            let Some(pair) = parts.next() else {
                continue;
            };
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let mut domain = None;
            let mut path = None;
            let mut secure = false;
            let mut max_age = None;
            let mut expires = None;
            for attribute in parts {
                let attribute = attribute.trim();
                if attribute.eq_ignore_ascii_case("secure") {
                    secure = true;
                    continue;
                }
                let Some((name, value)) = attribute.split_once('=') else {
                    continue;
                };
                match name.trim().to_ascii_lowercase().as_str() {
                    "domain" => {
                        let value = value.trim().trim_start_matches('.').to_ascii_lowercase();
                        if !value.is_empty() {
                            domain = Some(value);
                        }
                    }
                    "path" => {
                        let value = value.trim();
                        if value.starts_with('/') {
                            path = Some(value.to_owned());
                        }
                    }
                    "max-age" => max_age = value.trim().parse::<i64>().ok(),
                    "expires" => expires = Some(value.trim().to_owned()),
                    _ => {}
                }
            }
            let (domain, host_only) = match domain {
                Some(domain)
                    if domain.contains('.')
                        && (host == domain || host.ends_with(&format!(".{domain}"))) =>
                {
                    (domain, false)
                }
                Some(_) => continue,
                None => (host.clone(), true),
            };
            let path = path.unwrap_or_else(|| default_cookie_path(request_path));
            let expires_at = max_age
                .map(|seconds| {
                    if seconds <= 0 {
                        0
                    } else {
                        now().saturating_add(u64::try_from(seconds).unwrap_or(u64::MAX))
                    }
                })
                .or_else(|| expires.as_deref().and_then(http_date));
            if expires_at.is_some_and(|at| at <= now()) {
                self.cookies.retain(|cookie| {
                    !(cookie.name == key && cookie.domain == domain && cookie.path == path)
                });
                continue;
            }
            if let Some(existing) = self
                .cookies
                .iter_mut()
                .find(|cookie| cookie.name == key && cookie.domain == domain && cookie.path == path)
            {
                value.trim().clone_into(&mut existing.value);
                existing.secure = secure;
                existing.host_only = host_only;
                existing.expires_at = expires_at;
            } else {
                self.cookies.push(Cookie {
                    name: key.to_owned(),
                    value: value.trim().to_owned(),
                    domain,
                    host_only,
                    path,
                    secure,
                    expires_at,
                });
            }
        }
    }

    fn record_token(&self, current: &str, reply: &Reply, token: &mut Option<String>) {
        if !self.trusts(current) {
            return;
        }
        let Some(candidate) = issued_token(reply) else {
            return;
        };
        let now = now();
        let candidate_expiry = jwt_expiry(&candidate).filter(|&expiry| now < expiry);
        let held_expiry = token
            .as_deref()
            .and_then(|held| jwt_expiry(held).filter(|&expiry| now < expiry));
        if candidate_expiry.is_some_and(|expiry| held_expiry.is_none_or(|held| expiry > held)) {
            *token = Some(candidate);
        }
    }

    fn get(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        exchange: &Exchange<'_>,
    ) -> Result<Page, String> {
        let mut current = url.to_owned();
        let mut token = None;
        for _ in 0..=MAX_REDIRECTS {
            let reply = self.exchange("GET", &current, headers, &[], exchange)?;
            self.record_token(&current, &reply, &mut token);
            let location = if is_redirect(reply.status) {
                reply.header("Location").map(str::to_owned)
            } else {
                None
            };
            let Some(location) = location else {
                return Ok(Page {
                    url: current,
                    reply,
                    token,
                });
            };
            current = resolve_redirect(&current, &location)?;
        }
        Err("warp access: too many redirects".to_owned())
    }

    fn post_form(
        &mut self,
        url: &str,
        form: &[(&str, &str)],
        exchange: &Exchange<'_>,
    ) -> Result<Page, String> {
        let form = form_encode(form);
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        let mut current = url.to_owned();
        let mut body = Some(form);
        let mut token = None;
        for _ in 0..=MAX_REDIRECTS {
            let reply = match body.as_deref() {
                Some(bytes) => {
                    self.exchange("POST", &current, &headers, bytes.as_bytes(), exchange)?
                }
                None => self.exchange("GET", &current, &[], &[], exchange)?,
            };
            self.record_token(&current, &reply, &mut token);
            let location = if is_redirect(reply.status) {
                reply.header("Location").map(str::to_owned)
            } else {
                None
            };
            let Some(location) = location else {
                return Ok(Page {
                    url: current,
                    reply,
                    token,
                });
            };
            let next = resolve_redirect(&current, &location)?;
            if matches!(reply.status, 307 | 308)
                && body.is_some()
                && origin(&current) != origin(&next)
            {
                return Err(
                    "warp access: refusing to resend the login form to another origin".to_owned(),
                );
            }
            current = next;
            if matches!(reply.status, 301..=303) {
                body = None;
            }
        }
        Err("warp access: too many redirects".to_owned())
    }
}

fn sign_in(
    settings: &TeamSettings,
    now: u64,
    exchange: &Exchange<'_>,
    prompt: &mut dyn FnMut(&str, u32) -> Option<String>,
) -> Result<String, String> {
    if let Some(token) = settings.token.as_deref() {
        if !looks_like_jwt(token) {
            return Err(
                "warp: the supplied access token is not a jwt; copy the value that follows token= on the enrolment page"
                    .to_owned(),
            );
        }
        if jwt_expired(token, now) {
            return Err(
                "warp: the supplied access token has expired or has no readable future expiry; sign in again to get a fresh one"
                    .to_owned(),
            );
        }
        let issued_for = jwt_team(token).ok_or_else(|| {
            format!(
                "warp: the supplied access token does not name the team that issued it; sign in at {} to get one for team {}",
                settings.login_url(),
                settings.team
            )
        })?;
        if issued_for != settings.team {
            return Err(format!(
                "warp: the supplied access token was issued for team {issued_for}, not {}; sign in at {}",
                settings.team,
                settings.login_url()
            ));
        }
        eprintln!(
            "[+] using the access token supplied for team {}",
            settings.team
        );
        return Ok(token.to_owned());
    }
    if settings.has_service_token() {
        return with_service_token(settings, exchange);
    }
    if let Some(email) = settings.email.as_deref() {
        return with_email_code(settings, email, exchange, prompt);
    }
    Err(format!(
        "warp: team {} needs a way to sign in. pick one: a service token via `accessClientId` and `accessClientSecret`, an email one-time code via `accessEmail`, or a token you already hold via `accessToken` (sign in at {})",
        settings.team,
        settings.login_url()
    ))
}

fn with_service_token(settings: &TeamSettings, exchange: &Exchange<'_>) -> Result<String, String> {
    let client_id = settings
        .client_id
        .as_deref()
        .ok_or_else(|| "warp: missing access client id".to_owned())?;
    let client_secret = settings
        .client_secret
        .as_deref()
        .ok_or_else(|| "warp: missing access client secret".to_owned())?;
    let url = settings.login_url();
    let headers = [
        ("CF-Access-Client-Id", client_id),
        ("CF-Access-Client-Secret", client_secret),
        ("User-Agent", UA_REGISTER),
    ];
    let reply = exchange("GET", &url, &headers, &[])?;
    if !(200..400).contains(&reply.status) {
        return Err(format!(
            "warp: access refused the service token for team `{}` (status {}); confirm the client id and secret",
            settings.team, reply.status
        ));
    }
    if let Some(token) = issued_token(&reply) {
        eprintln!("[+] access issued a device enrolment token");
        return Ok(token);
    }
    if let Some(token) = extract_jwt_from_html(&String::from_utf8_lossy(&reply.body)) {
        eprintln!("[+] access issued a device enrolment token");
        return Ok(token);
    }
    Err(format!(
        "warp: access did not return a device enrolment token (status {}); confirm the service token has Service Auth device enrolment permission for team {}",
        reply.status, settings.team
    ))
}

fn with_email_code(
    settings: &TeamSettings,
    email: &str,
    exchange: &Exchange<'_>,
    prompt: &mut dyn FnMut(&str, u32) -> Option<String>,
) -> Result<String, String> {
    let email = email.trim();
    if email.is_empty() {
        return Err("warp: an email address is needed to request a login code".to_owned());
    }
    let mut session = Session::for_origin(&settings.team_domain());
    let landing = session.get(&settings.login_url(), &[], exchange)?;
    let verify_url = extract_totp_form_action(&String::from_utf8_lossy(&landing.reply.body))
        .ok_or_else(|| {
            format!(
                "warp: team {} does not offer an email one-time code on its enrolment page; use a service token or sign in at {}",
                settings.team,
                settings.login_url()
            )
        })?;
    if origin(&verify_url) != origin(&settings.team_domain()) {
        return Err(
            "warp: access offered a login form on another origin; refusing to send the email"
                .to_owned(),
        );
    }
    let sent = session.post_form(
        &verify_url,
        &[
            ("email", email),
            ("client_id", ""),
            ("connector_id", ""),
            ("connector_type", ""),
            ("redirect_url", ""),
        ],
        exchange,
    )?;
    if !(200..300).contains(&sent.reply.status) {
        return Err(format!(
            "warp: access did not accept the login code request for team {} (status {}); try again later",
            settings.team, sent.reply.status
        ));
    }
    let nonce = query_value(&sent.url, "nonce")
        .or_else(|| query_value(&landing.url, "nonce"))
        .ok_or_else(|| {
            "warp: cloudflare did not return a nonce for the login code; the enrolment flow may have changed".to_owned()
        })?;
    let callback = format!("{}/cdn-cgi/access/callback", settings.team_domain());
    let mut last = None;
    for attempt in 1..=CODE_ATTEMPTS {
        let Some(code) = prompt(email, attempt) else {
            return Err("warp: no login code was entered".to_owned());
        };
        let code = code.trim();
        if code.is_empty() {
            return Err("warp: no login code was entered".to_owned());
        }
        let page = session.post_form(&callback, &[("code", code), ("nonce", &nonce)], exchange)?;
        if page.reply.status >= 500 || page.reply.status == 429 {
            return Err(format!(
                "warp: access did not answer the login code check (status {}); try again later",
                page.reply.status
            ));
        }
        let html = String::from_utf8_lossy(&page.reply.body);
        let html_token = extract_jwt_from_html(&html);
        let token = [page.token.as_deref(), html_token.as_deref()]
            .into_iter()
            .flatten()
            .find(|candidate| !jwt_expired(candidate, now()))
            .map(str::to_owned);
        if let Some(token) = token {
            eprintln!(
                "[+] signed in to team {} with the email code",
                settings.team
            );
            return Ok(token);
        }
        last = Some(page.reply.status);
        let left = CODE_ATTEMPTS - attempt;
        if left > 0 {
            eprintln!("warp: that login code was not accepted; {left} attempt(s) left");
        }
    }
    Err(format!(
        "warp: the login code was not accepted after {CODE_ATTEMPTS} attempts (last status {}); request a fresh code and try again",
        last.map_or_else(|| "unknown".to_owned(), |status| status.to_string())
    ))
}

pub(crate) fn stdin_prompt(email: &str, attempt: u32) -> Option<String> {
    if attempt == 1 {
        eprintln!("\nA login code was emailed to {email}.\nEnter the code: ");
    } else {
        eprintln!("\nThat code was not accepted. Enter the code emailed to {email} again: ");
    }
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

/// The one request an access flow makes over a fresh TLS connection; redirects and cookies are
/// the caller's, so a test scripts them and a run reads exactly one answer per call.
pub(crate) fn https_exchange(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, String> {
    let (origin, target) = https_target(url)
        .ok_or_else(|| "warp access: the redirect target is not an https URL".to_owned())?;
    let authority = origin.strip_prefix("https://").unwrap_or(&origin);
    let mut endpoint = Endpoint::parse(&origin, crate::quic::system_roots())
        .ok_or_else(|| "warp access: the redirect target is not an https URL".to_owned())?;
    if endpoint.port != 443 {
        endpoint.host_header = Some(authority.to_owned());
    }
    crate::foxy_account::ask_within(
        &endpoint,
        method,
        &target,
        headers,
        body,
        ACCESS_REQUEST_TIMEOUT,
    )
    .map_err(|reason| format!("warp access: {reason}"))
}

/// A token resolver that signs in once per process: `--register all` makes several devices and
/// must not ask for one code per slot.
pub(crate) fn resolve_token(
    settings: &TeamSettings,
    prompt: &mut dyn FnMut(&str, u32) -> Option<String>,
) -> Result<String, String> {
    static CACHED: std::sync::Mutex<Option<(String, String)>> = std::sync::Mutex::new(None);
    let started = now();
    {
        let cached = match CACHED.lock() {
            Ok(cached) => cached,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = now();
        if let Some((team, token)) = cached.as_ref() {
            if *team == settings.team && jwt_expiry(token).is_some_and(|expiry| now < expiry) {
                return Ok(token.clone());
            }
        }
    }
    let token = sign_in(settings, started, &https_exchange, prompt)?;
    let issued = now();
    if jwt_expiry(&token).is_none_or(|expiry| issued >= expiry) {
        return Err(format!(
            "warp: access returned a device token for team {} that is already expired; sign in again",
            settings.team
        ));
    }
    let mut cached = match CACHED.lock() {
        Ok(cached) => cached,
        Err(poisoned) => poisoned.into_inner(),
    };
    *cached = Some((settings.team.clone(), token.clone()));
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            engine.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}"),
            engine.encode(payload.as_bytes()),
            engine.encode(b"signature-bytes-that-are-long-enough")
        )
    }

    fn team_jwt(team: &str, expiry: u64) -> String {
        jwt(&format!(
            "{{\"exp\":{expiry},\"iss\":\"https://{team}.cloudflareaccess.com\"}}"
        ))
    }

    fn reply(status: u16, headers: Vec<(String, String)>, body: &str) -> Reply {
        Reply {
            status,
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_bare_team_name_is_kept_as_is() {
        assert_eq!(normalize_team("my-org"), Some("my-org".to_owned()));
    }

    #[test]
    fn a_full_team_domain_is_reduced_to_the_name() {
        assert_eq!(
            normalize_team("https://My-Org.cloudflareaccess.com/"),
            Some("my-org".to_owned())
        );
        assert_eq!(
            normalize_team("my-org.cloudflareaccess.com"),
            Some("my-org".to_owned())
        );
    }

    #[test]
    fn an_enrolment_url_is_reduced_to_the_name() {
        assert_eq!(
            normalize_team("https://my-org.cloudflareaccess.com/warp"),
            Some("my-org".to_owned())
        );
    }

    #[test]
    fn an_empty_or_malformed_team_is_rejected() {
        assert_eq!(normalize_team("   "), None);
        assert_eq!(normalize_team("bad name!"), None);
        assert_eq!(normalize_team("bad_team"), None);
        assert_eq!(normalize_team("acmecloudflareaccess.com"), None);
        assert_eq!(normalize_team("https://cloudflareaccess.com"), None);
    }

    #[test]
    fn a_non_string_team_setting_is_refused() {
        let settings = crate::json::parse("{\"team\":42}").expect("valid json");
        let error = TeamSettings::from_settings(&settings).expect_err("a non-string team");
        assert!(error.contains("`team` must be a string"));
    }

    #[test]
    fn a_blank_explicit_team_is_refused_even_with_an_environment_team() {
        let error = TeamSettings::from_parts_with(Some("  "), None, None, None, None, |_| {
            Some("env-team".to_owned())
        })
        .expect_err("a blank explicit team");
        assert!(error.contains("empty"), "{error}");
    }

    #[test]
    fn access_credentials_without_a_team_are_refused() {
        let error =
            TeamSettings::from_parts_with(None, None, None, Some("a-token"), None, |_| None)
                .expect_err("access without a team");
        assert!(error.contains("need a team"), "{error}");
    }

    #[test]
    fn an_https_request_keeps_its_path_and_query() {
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com"),
            Some((
                "https://acme.cloudflareaccess.com".to_owned(),
                "/".to_owned()
            ))
        );
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com/warp/"),
            Some((
                "https://acme.cloudflareaccess.com".to_owned(),
                "/warp/".to_owned()
            ))
        );
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com/warp?nonce=abc"),
            Some((
                "https://acme.cloudflareaccess.com".to_owned(),
                "/warp?nonce=abc".to_owned()
            ))
        );
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com?nonce=abc"),
            Some((
                "https://acme.cloudflareaccess.com".to_owned(),
                "/?nonce=abc".to_owned()
            ))
        );
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com/warp#fragment"),
            Some((
                "https://acme.cloudflareaccess.com".to_owned(),
                "/warp".to_owned()
            ))
        );
        assert_eq!(
            https_target("https://acme.cloudflareaccess.com:8443/warp"),
            Some((
                "https://acme.cloudflareaccess.com:8443".to_owned(),
                "/warp".to_owned()
            ))
        );
        assert_eq!(https_target("http://acme.cloudflareaccess.com"), None);
    }

    #[test]
    fn a_default_https_port_is_the_same_origin() {
        assert_eq!(
            origin("https://acme.cloudflareaccess.com"),
            origin("https://acme.cloudflareaccess.com:443")
        );
        assert_eq!(
            origin("https://acme.cloudflareaccess.com:444"),
            Some("https://acme.cloudflareaccess.com:444".to_owned())
        );
        assert_ne!(
            origin("https://acme.cloudflareaccess.com"),
            origin("https://evil.example")
        );
    }

    #[test]
    fn a_parent_reference_is_resolved_before_the_redirect() {
        assert_eq!(
            resolve_url(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/login/start",
                "../verify?nonce=abc",
            )
            .as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access/verify?nonce=abc")
        );
        assert_eq!(
            resolve_url(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/login/start",
                "/cdn-cgi/access//verify",
            )
            .as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access//verify")
        );
    }

    #[test]
    fn a_query_only_redirect_keeps_the_resource_path() {
        assert_eq!(
            resolve_url(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/verify?step=1",
                "?nonce=next",
            )
            .as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access/verify?nonce=next")
        );
    }

    #[test]
    fn a_query_slash_is_not_a_path() {
        assert_eq!(url_path("https://host?next=/access/start"), "/");
        assert_eq!(
            resolve_url("https://host?next=/access/start", "verify").as_deref(),
            Some("https://host/verify")
        );
    }

    #[test]
    fn a_redirect_location_keeps_its_query_entities() {
        assert_eq!(
            resolve_url(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
                "/cdn-cgi/access/callback?a=1&amp;b=2",
            )
            .as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access/callback?a=1&amp;b=2")
        );
    }

    #[test]
    fn a_redirect_away_from_https_is_refused() {
        let error = resolve_redirect(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            "http://evil.example/next",
        )
        .expect_err("an insecure redirect");
        assert!(error.contains("https"));
    }

    #[test]
    fn an_uppercase_https_redirect_is_normalized_before_the_exchange() {
        assert_eq!(
            resolve_redirect(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
                "HTTPS://acme.cloudflareaccess.com/cdn-cgi/access/callback",
            )
            .expect("a usable uppercase scheme"),
            "https://acme.cloudflareaccess.com/cdn-cgi/access/callback"
        );
    }

    #[test]
    fn an_unclosed_bracketed_host_does_not_panic() {
        assert_eq!(url_host("https://[2606:4700::1"), None);
        assert_eq!(
            url_host("https://[2606:4700::1]:443/callback"),
            Some("[2606:4700::1]")
        );
    }

    #[test]
    fn a_cookie_is_scoped_to_its_issuing_host_and_path() {
        let mut session = Session::new();
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=a-token; Path=/cdn-cgi/access; Secure".to_owned(),
                )],
                "",
            ),
        );
        let sent = std::cell::Cell::new(false);
        session
            .exchange(
                "GET",
                "https://acme.cloudflareaccess.com/cdn-cgi/access/callback",
                &[],
                &[],
                &|_, _, headers, _| {
                    sent.set(headers.iter().any(|(key, _)| {
                        key.eq_ignore_ascii_case("cookie")
                            && headers
                                .iter()
                                .any(|(_, value)| value.contains("CF_Authorization=a-token"))
                    }));
                    Ok(reply(200, Vec::new(), ""))
                },
            )
            .expect("a scoped request");
        assert!(sent.get());
        let leaked = std::cell::Cell::new(false);
        session
            .exchange(
                "GET",
                "https://evil.example/cdn-cgi/access/callback",
                &[],
                &[],
                &|_, _, headers, _| {
                    leaked.set(
                        headers
                            .iter()
                            .any(|(key, _)| key.eq_ignore_ascii_case("cookie")),
                    );
                    Ok(reply(200, Vec::new(), ""))
                },
            )
            .expect("a foreign request");
        assert!(!leaked.get());
    }

    #[test]
    fn a_parent_domain_cookie_is_not_sent_to_a_sibling_origin() {
        let mut session = Session::for_origin("https://acme.cloudflareaccess.com");
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=a-token; Domain=cloudflareaccess.com; Path=/; Secure"
                        .to_owned(),
                )],
                "",
            ),
        );
        let sent = std::cell::Cell::new(false);
        session
            .exchange(
                "GET",
                "https://other.cloudflareaccess.com/cdn-cgi/access/callback",
                &[],
                &[],
                &|_, _, headers, _| {
                    sent.set(
                        headers
                            .iter()
                            .any(|(key, _)| key.eq_ignore_ascii_case("cookie")),
                    );
                    Ok(reply(200, Vec::new(), ""))
                },
            )
            .expect("a sibling request");
        assert!(!sent.get());
    }

    #[test]
    fn a_past_expires_date_deletes_a_cookie() {
        let mut session = Session::new();
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=a-token; Path=/; Secure".to_owned(),
                )],
                "",
            ),
        );
        assert_eq!(session.cookies.len(), 1);
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure"
                        .to_owned(),
                )],
                "",
            ),
        );
        assert!(session.cookies.is_empty());
    }

    #[test]
    fn http_dates_parse_the_three_http_forms() {
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(http_date("Thursday, 01-Jan-70 00:00:00 GMT"), Some(0));
        assert_eq!(http_date("Thu Jan  1 00:00:00 1970"), Some(0));
        assert_eq!(http_date("Fri, 01 Jan 1960 00:00:00 GMT"), Some(0));
        assert_eq!(
            http_date("Thu, 01 Jan 999999999999999999 00:00:00 GMT"),
            None
        );
    }

    #[test]
    fn a_cookie_the_server_deletes_is_not_sent_again() {
        let mut session = Session::new();
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=a-token; Path=/; Secure".to_owned(),
                )],
                "",
            ),
        );
        assert_eq!(session.cookies.len(), 1);
        session.absorb(
            "https://acme.cloudflareaccess.com/cdn-cgi/access/verify",
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    "CF_Authorization=; Path=/; Max-Age=0; Secure".to_owned(),
                )],
                "",
            ),
        );
        assert!(session.cookies.is_empty(), "the deleted cookie is gone");
        let sent = std::cell::Cell::new(false);
        session
            .exchange(
                "GET",
                "https://acme.cloudflareaccess.com/cdn-cgi/access/callback",
                &[],
                &[],
                &|_, _, headers, _| {
                    sent.set(
                        headers
                            .iter()
                            .any(|(key, _)| key.eq_ignore_ascii_case("cookie")),
                    );
                    Ok(reply(200, Vec::new(), ""))
                },
            )
            .expect("the next request");
        assert!(!sent.get());
    }

    #[test]
    fn an_off_origin_callback_token_and_cookie_are_ignored() {
        let token = jwt("{\"exp\":4102444800,\"iss\":\"https://acme.cloudflareaccess.com\"}");
        let mut session = Session::for_origin("https://acme.cloudflareaccess.com");
        let page = session
            .get(
                "https://evil.example/cdn-cgi/access/callback",
                &[],
                &|_, _, _, _| {
                    Ok(reply(
                        200,
                        vec![(
                            "Set-Cookie".to_owned(),
                            format!("CF_Authorization={token}; Path=/; Secure"),
                        )],
                        "",
                    ))
                },
            )
            .expect("an off-origin page");
        assert!(page.token.is_none());
        assert!(session.cookies.is_empty());
    }

    #[test]
    fn a_deleted_assertion_cookie_is_not_a_token() {
        let live = jwt("{\"exp\":4102444800}");
        let reply = reply(
            200,
            vec![(
                "Set-Cookie".to_owned(),
                format!("CF_Authorization={live}; Max-Age=0; Path=/; Secure"),
            )],
            "",
        );
        assert!(issued_token(&reply).is_none());
    }

    #[test]
    fn a_later_live_assertion_replaces_an_earlier_one() {
        let origin = "https://acme.cloudflareaccess.com";
        let session = Session::for_origin(origin);
        let earlier = jwt("{\"exp\":4102444800}");
        let later = jwt("{\"exp\":4102444801}");
        let mut token = None;
        session.record_token(
            origin,
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={earlier}; Path=/; Secure"),
                )],
                "",
            ),
            &mut token,
        );
        session.record_token(
            origin,
            &reply(
                200,
                vec![(
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={later}; Path=/; Secure"),
                )],
                "",
            ),
            &mut token,
        );
        assert_eq!(token.as_deref(), Some(later.as_str()));
    }

    #[test]
    fn the_latest_live_assertion_cookie_wins() {
        let earlier = jwt("{\"exp\":4102444800}");
        let later = jwt("{\"exp\":4102444801}");
        let reply = reply(
            200,
            vec![
                (
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={earlier}; Path=/old; Secure"),
                ),
                (
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={later}; Path=/new; Secure"),
                ),
            ],
            "",
        );
        assert_eq!(issued_token(&reply), Some(later));
    }

    #[test]
    fn an_expired_assertion_cookie_does_not_hide_a_live_one() {
        let expired = jwt("{\"exp\":1}");
        let live = jwt("{\"exp\":4102444800}");
        let reply = reply(
            200,
            vec![
                (
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={expired}; Path=/old; Secure"),
                ),
                (
                    "Set-Cookie".to_owned(),
                    format!("CF_Authorization={live}; Path=/new; Secure"),
                ),
            ],
            "",
        );
        assert_eq!(issued_token(&reply), Some(live));
    }

    #[test]
    fn an_expired_stored_assertion_is_replaced_by_a_live_one() {
        let expired = jwt("{\"exp\":1}");
        let live = jwt("{\"exp\":4102444800}");
        let mut session = Session::for_origin("https://acme.cloudflareaccess.com");
        let page = session
            .get(
                "https://acme.cloudflareaccess.com/start",
                &[],
                &|_, url, _, _| {
                    if url.ends_with("/start") {
                        Ok(reply(
                            302,
                            vec![
                                (
                                    "Location".to_owned(),
                                    "https://acme.cloudflareaccess.com/next".to_owned(),
                                ),
                                (
                                    "Set-Cookie".to_owned(),
                                    format!("CF_Authorization={expired}; Path=/; Secure"),
                                ),
                            ],
                            "",
                        ))
                    } else {
                        Ok(reply(
                            200,
                            vec![(
                                "Set-Cookie".to_owned(),
                                format!("CF_Authorization={live}; Path=/; Secure"),
                            )],
                            "",
                        ))
                    }
                },
            )
            .expect("a followed redirect");
        assert_eq!(page.token.as_deref(), Some(live.as_str()));
    }

    #[test]
    fn a_cross_origin_307_does_not_replay_the_code() {
        let calls = std::cell::Cell::new(0);
        let error = Session::new()
            .post_form(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/callback",
                &[("code", "123456"), ("nonce", "abc")],
                &|_, _, _, _| {
                    calls.set(calls.get() + 1);
                    Ok(reply(
                        307,
                        vec![(
                            "Location".to_owned(),
                            "https://evil.example/callback".to_owned(),
                        )],
                        "",
                    ))
                },
            )
            .err()
            .expect("a cross-origin rerun");
        assert!(error.contains("another origin"));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_cross_origin_307_after_the_form_is_spent_is_followed() {
        let calls = std::cell::Cell::new(0);
        let page = Session::new()
            .post_form(
                "https://acme.cloudflareaccess.com/cdn-cgi/access/callback",
                &[("code", "123456")],
                &|method, url, _, body| {
                    calls.set(calls.get() + 1);
                    if method == "POST" {
                        assert_ne!(body, []);
                        return Ok(reply(
                            302,
                            vec![(
                                "Location".to_owned(),
                                "https://acme.cloudflareaccess.com/next".to_owned(),
                            )],
                            "",
                        ));
                    }
                    if url.ends_with("/next") {
                        return Ok(reply(
                            307,
                            vec![(
                                "Location".to_owned(),
                                "https://elsewhere.example/final".to_owned(),
                            )],
                            "",
                        ));
                    }
                    Ok(reply(200, Vec::new(), "done"))
                },
            )
            .expect("the GET after the form is spent may move");
        assert_eq!(page.url, "https://elsewhere.example/final");
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn a_rejected_verify_request_does_not_prompt_for_a_code() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let mut prompted = 0;
        let error = sign_in(
            &settings,
            now(),
            &|method, url, _, _| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(429, Vec::new(), ""));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompted += 1;
                Some("123456".to_owned())
            },
        )
        .expect_err("a refused send");
        assert!(error.contains("did not accept the login code request"));
        assert_eq!(prompted, 0);
    }

    #[test]
    fn a_callback_outage_is_not_a_rejected_code() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let posts = std::cell::Cell::new(0);
        let mut prompted = 0;
        let error = sign_in(
            &settings,
            now(),
            &|method, url, _, _| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![(
                            "Location".to_owned(),
                            "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                        )],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    posts.set(posts.get() + 1);
                    return Ok(reply(524, Vec::new(), ""));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompted += 1;
                Some("123456".to_owned())
            },
        )
        .expect_err("a callback outage");
        assert!(error.contains("did not answer the login code check"));
        assert_eq!(prompted, 1);
        assert_eq!(posts.get(), 1);
    }

    #[test]
    fn a_callback_token_on_a_redirect_is_kept() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let token = jwt("{\"exp\":4102444800}");
        let mut prompted = 0;
        let got = sign_in(
            &settings,
            now(),
            &|method, url, _, _| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![(
                            "Location".to_owned(),
                            "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                        )],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    return Ok(reply(
                        302,
                        vec![
                            (
                                "Location".to_owned(),
                                "https://acme.cloudflareaccess.com/cdn-cgi/access/callback?done=1"
                                    .to_owned(),
                            ),
                            (
                                "Set-Cookie".to_owned(),
                                format!("CF_Authorization={token}; Path=/; Secure"),
                            ),
                        ],
                        "",
                    ));
                }
                if method == "GET" && url.contains("done=1") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompted += 1;
                Some("123456".to_owned())
            },
        )
        .expect("a token issued on the redirect is kept");
        assert_eq!(got, token);
        assert_eq!(prompted, 1);
    }

    #[test]
    fn a_pre_verify_cookie_is_not_proof_the_callback_worked() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let stale = jwt("{\"exp\":4102444800}");
        let mut prompted = 0;
        let error = sign_in(
            &settings,
            now(),
            &|method, url, _, _| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![
                            (
                                "Location".to_owned(),
                                "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                            ),
                            (
                                "Set-Cookie".to_owned(),
                                format!("CF_Authorization={stale}; Path=/verify; Secure"),
                            ),
                        ],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    return Ok(reply(403, Vec::new(), ""));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompted += 1;
                Some("123456".to_owned())
            },
        )
        .expect_err("the stale cookie is not a token");
        assert!(error.contains("was not accepted"), "{error}");
        assert_eq!(prompted, 3);
    }

    #[test]
    fn the_team_domain_and_login_url_follow_cloudflares_shape() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            ..TeamSettings::default()
        };
        assert_eq!(settings.team_domain(), "https://acme.cloudflareaccess.com");
        assert_eq!(
            settings.login_url(),
            "https://acme.cloudflareaccess.com/warp"
        );
    }

    #[test]
    fn a_token_is_pulled_out_of_the_meta_refresh() {
        let token = jwt("{\"exp\":4102444800}");
        let page = format!(
            "<html><meta http-equiv=\"refresh\" content=\"0;url=https://x/cdn-cgi/access/callback?token={token}\"></html>"
        );
        assert_eq!(extract_jwt_from_html(&page), Some(token));
    }

    #[test]
    fn a_token_is_pulled_out_of_the_cookie() {
        let token = jwt("{\"exp\":4102444800}");
        let cookie = format!("CF_Authorization={token}; Path=/; Secure; HttpOnly");
        assert_eq!(extract_jwt_from_cookie(&cookie), Some(token));
    }

    #[test]
    fn a_token_carries_its_own_expiry() {
        let live = jwt("{\"exp\":4102444800}");
        assert_eq!(jwt_expiry(&live), Some(4_102_444_800));
        assert!(!jwt_expired(&live, 1));
        assert!(jwt_expired(&live, 4_102_444_800));
        assert_eq!(jwt_expiry("not-a-jwt"), None);
        assert!(jwt_expired("not-a-jwt", 1));
        assert!(!jwt_expired(&jwt("{\"exp\":4102444800}"), 1));
        assert!(jwt_expired(
            &jwt("{\"iss\":\"https://acme.cloudflareaccess.com\"}"),
            1
        ));
    }

    #[test]
    fn the_totp_form_action_is_read_through_entities() {
        let page = "<div><form method=\"post\" action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify?a=1&amp;b=2\"><input id=\"totp-form\"></form></div>";
        assert_eq!(
            extract_totp_form_action(page).as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access/verify?a=1&b=2")
        );
    }

    #[test]
    fn a_query_value_is_percent_decoded() {
        assert_eq!(
            query_value("https://x/cb?nonce=a%20b&next=1", "nonce").as_deref(),
            Some("a b")
        );
        assert_eq!(query_value("https://x/cb", "nonce"), None);
        assert_eq!(
            query_value("https://x/cb?nonce=abc#step", "nonce").as_deref(),
            Some("abc")
        );
        assert_eq!(
            query_value("https://x/cb?nonce=a%23b#step", "nonce").as_deref(),
            Some("a#b")
        );
    }

    #[test]
    fn a_supplied_token_is_used_without_asking() {
        let token = team_jwt("acme", 4_102_444_800);
        let settings = TeamSettings {
            team: "acme".to_owned(),
            token: Some(token.clone()),
            ..TeamSettings::default()
        };
        let mut asked = 0;
        let got = sign_in(
            &settings,
            now(),
            &|_, _, _, _| Err("must not make a call".to_owned()),
            &mut |_, _| {
                asked += 1;
                None
            },
        )
        .expect("a supplied token");
        assert_eq!(got, token);
        assert_eq!(asked, 0);
    }

    #[test]
    fn a_supplied_token_for_another_team_is_refused() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            token: Some(team_jwt("other", 4_102_444_800)),
            ..TeamSettings::default()
        };
        let error = sign_in(
            &settings,
            now(),
            &|_, _, _, _| Err("must not make a call".to_owned()),
            &mut |_, _| None,
        )
        .expect_err("a token for another team");
        assert!(error.contains("other"), "{error}");
        assert!(error.contains("acme"), "{error}");
    }

    #[test]
    fn a_supplied_token_without_a_team_is_refused() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            token: Some(jwt("{\"exp\":4102444800}")),
            ..TeamSettings::default()
        };
        let error = sign_in(
            &settings,
            now(),
            &|_, _, _, _| Err("must not make a call".to_owned()),
            &mut |_, _| None,
        )
        .expect_err("a token with no issuer");
        assert!(error.contains("does not name"), "{error}");
        assert!(error.contains("acme"), "{error}");
    }

    #[test]
    fn an_expired_supplied_token_is_refused() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            token: Some(team_jwt("acme", 1)),
            ..TeamSettings::default()
        };
        let error = sign_in(
            &settings,
            now(),
            &|_, _, _, _| Err("must not make a call".to_owned()),
            &mut |_, _| None,
        )
        .expect_err("an expired token");
        assert!(error.contains("expired"));
    }

    #[test]
    fn a_service_token_reads_the_cookie_the_plane_sets() {
        let token = jwt("{\"exp\":4102444800}");
        let settings = TeamSettings {
            team: "acme".to_owned(),
            client_id: Some("the-id".to_owned()),
            client_secret: Some("the-secret".to_owned()),
            ..TeamSettings::default()
        };
        let got = sign_in(
            &settings,
            now(),
            &|method, url, headers, _| {
                assert_eq!(method, "GET");
                assert_eq!(url, "https://acme.cloudflareaccess.com/warp");
                assert!(headers.contains(&("CF-Access-Client-Id", "the-id")));
                Ok(reply(
                    200,
                    vec![(
                        "Set-Cookie".to_owned(),
                        format!("CF_Authorization={token}; Path=/; Secure"),
                    )],
                    "",
                ))
            },
            &mut |_, _| None,
        )
        .expect("a service token");
        assert_eq!(got, token);
    }

    #[test]
    fn a_refused_service_token_is_reported() {
        let token = jwt("{\"exp\":4102444800}");
        let settings = TeamSettings {
            team: "acme".to_owned(),
            client_id: Some("the-id".to_owned()),
            client_secret: Some("the-secret".to_owned()),
            ..TeamSettings::default()
        };
        let error = sign_in(
            &settings,
            now(),
            &|_, _, _, _| {
                Ok(reply(
                    403,
                    vec![(
                        "Set-Cookie".to_owned(),
                        format!("CF_Authorization={token}; Path=/; Secure"),
                    )],
                    "",
                ))
            },
            &mut |_, _| None,
        )
        .expect_err("a refused service token");
        assert!(error.contains("403"), "{error}");
        assert!(error.contains("service token"), "{error}");
    }

    #[test]
    fn an_email_form_on_another_origin_is_refused() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let posts = std::cell::Cell::new(0);
        let error = sign_in(
            &settings,
            now(),
            &|method, url, _, _| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://evil.example/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                posts.set(posts.get() + 1);
                Err("must not post".to_owned())
            },
            &mut |_, _| Some("123456".to_owned()),
        )
        .expect_err("a form on another origin");
        assert!(error.contains("another origin"), "{error}");
        assert_eq!(posts.get(), 0);
    }

    #[test]
    fn a_rejected_code_is_tried_three_times() {
        let token = jwt("{\"exp\":4102444800}");
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let posts = std::cell::Cell::new(0);
        let mut prompts = 0;
        let got = sign_in(
            &settings,
            now(),
            &|method, url, _headers, body| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![(
                            "Location".to_owned(),
                            "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                        )],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    posts.set(posts.get() + 1);
                    if posts.get() == 3 {
                        let page = format!("<meta token={token}>");
                        return Ok(reply(200, Vec::new(), &page));
                    }
                    let _ = body;
                    return Ok(reply(403, Vec::new(), "no"));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompts += 1;
                Some("123456".to_owned())
            },
        )
        .expect("a code after retries");
        assert_eq!(got, token);
        assert_eq!(prompts, 3);
        assert_eq!(posts.get(), 3);
    }

    #[test]
    fn a_live_callback_cookie_beats_an_expired_html_token() {
        let live = jwt("{\"exp\":4102444800}");
        let expired = jwt("{\"exp\":1}");
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let got = sign_in(
            &settings,
            now(),
            &|method, url, _headers, _body| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![(
                            "Location".to_owned(),
                            "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                        )],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    return Ok(reply(
                        200,
                        vec![(
                            "Set-Cookie".to_owned(),
                            format!("CF_Authorization={live}; Path=/; Secure"),
                        )],
                        &format!("<meta token={expired}>"),
                    ));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| Some("123456".to_owned()),
        )
        .expect("the live cookie");
        assert_eq!(got, live);
    }

    #[test]
    fn a_code_rejected_three_times_is_an_error() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            email: Some("user@example.com".to_owned()),
            ..TeamSettings::default()
        };
        let posts = std::cell::Cell::new(0);
        let mut prompts = 0;
        let error = sign_in(
            &settings,
            now(),
            &|method, url, _headers, _body| {
                if method == "GET" && url.ends_with("/warp") {
                    return Ok(reply(
                        200,
                        Vec::new(),
                        "<form action=\"https://acme.cloudflareaccess.com/cdn-cgi/access/verify\"><input id=\"totp-form\"></form>",
                    ));
                }
                if method == "POST" && url.ends_with("/verify") {
                    return Ok(reply(
                        302,
                        vec![(
                            "Location".to_owned(),
                            "https://acme.cloudflareaccess.com/verify?nonce=abc".to_owned(),
                        )],
                        "",
                    ));
                }
                if method == "GET" && url.contains("nonce=abc") {
                    return Ok(reply(200, Vec::new(), ""));
                }
                if method == "POST" && url.ends_with("/cdn-cgi/access/callback") {
                    posts.set(posts.get() + 1);
                    return Ok(reply(403, Vec::new(), "no"));
                }
                Err(format!("unexpected {method} {url}"))
            },
            &mut |_, _| {
                prompts += 1;
                Some("123456".to_owned())
            },
        )
        .expect_err("three rejected codes");
        assert!(error.contains("after 3 attempts"), "{error}");
        assert_eq!(prompts, 3);
        assert_eq!(posts.get(), 3);
    }

    #[test]
    fn an_install_id_is_twenty_two_alphanumerics() {
        let id = generate_install_id();
        assert_eq!(id.len(), 22);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn an_fcm_token_carries_the_install_id_and_the_apns_prefix() {
        let id = generate_install_id();
        let token = generate_fcm_token(&id);
        assert!(token.starts_with(&format!("{id}:APA91b")));
        assert_eq!(
            token.len(),
            INSTALL_ID_LEN + ":APA91b".len() + FCM_SUFFIX_LEN
        );
    }
}
