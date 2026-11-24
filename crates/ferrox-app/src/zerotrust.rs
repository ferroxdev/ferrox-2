//! Zero Trust enrolment: a team's `cloudflareaccess.com` device page, the three ways it hands out
//! a device JWT, and the `CF-Access-Jwt-Assertion` header the WARP API reads. The HTTP exchange is
//! a closure so the flow's redirects, cookies and parsing are testable without a network.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use crate::foxy_account::{Endpoint, Reply};

const TEAM_SUFFIX: &str = "cloudflareaccess.com";
const ENROLL_PATH: &str = "/warp";
const CODE_ATTEMPTS: u32 = 3;
const INSTALL_ID_LEN: usize = 22;
const FCM_SUFFIX_LEN: usize = 134;
const MAX_REDIRECTS: usize = 10;

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
        let text = |key: &str| settings.get(key).and_then(crate::json::Json::as_str);
        Self::from_parts(
            text("team"),
            text("accessClientId"),
            text("accessClientSecret"),
            text("accessToken"),
            text("accessEmail"),
        )
    }

    pub(crate) fn from_parts(
        team: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        token: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let raw = pick(team, "AETHER_TEAM");
        let Some(raw) = raw else {
            return Ok(None);
        };
        let team = normalize_team(&raw).ok_or_else(|| {
            format!(
                "warp: `{raw}` is not a usable team name; name the subdomain of <team>.{TEAM_SUFFIX}"
            )
        })?;
        Ok(Some(Self {
            team,
            client_id: pick(client_id, "AETHER_ACCESS_CLIENT_ID"),
            client_secret: pick(client_secret, "AETHER_ACCESS_CLIENT_SECRET"),
            token: pick(token, "AETHER_ACCESS_TOKEN"),
            email: pick(email, "AETHER_ACCESS_EMAIL"),
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

fn pick(value: Option<&str>, key: &str) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(key)
                .ok()
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
    if let Some(head) = value.strip_suffix(TEAM_SUFFIX) {
        value = head.trim_end_matches('.').to_owned();
    }
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
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
        .and_then(crate::json::Json::as_u32)
        .map(u64::from)
}

fn jwt_expired(token: &str, now: u64) -> bool {
    jwt_expiry(token).is_some_and(|expiry| expiry <= now)
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
        let end = match rest.find(';') {
            Some(index) if index <= 8 => index,
            _ => {
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
    let query = url.split_once('?')?.1;
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

fn resolve_url(base: &str, location: &str) -> String {
    let location = decode_entities(location);
    if location.starts_with("https://") || location.starts_with("http://") {
        return location;
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if let Some(absolute) = location.strip_prefix('/') {
        return format!("{scheme}://{authority}/{absolute}");
    }
    match path.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => format!("{scheme}://{authority}/{dir}/{location}"),
        _ => format!("{scheme}://{authority}/{location}"),
    }
}

struct Session {
    cookies: Vec<(String, String)>,
}

struct Page {
    url: String,
    reply: Reply,
}

impl Session {
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
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
        if !self.cookies.is_empty() {
            let mut jar = String::new();
            for (index, (name, value)) in self.cookies.iter().enumerate() {
                if index > 0 {
                    jar.push_str("; ");
                }
                jar.push_str(name);
                jar.push('=');
                jar.push_str(value);
            }
            owned.push(("Cookie".to_owned(), jar));
        }
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let reply = exchange(method, url, &borrowed, body)?;
        self.absorb(&reply);
        Ok(reply)
    }

    fn absorb(&mut self, reply: &Reply) {
        for (name, value) in &reply.headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let Some(cookie) = value.split(';').next() else {
                continue;
            };
            let Some((key, value)) = cookie.split_once('=') else {
                continue;
            };
            match self
                .cookies
                .iter_mut()
                .find(|(known, _)| known == key.trim())
            {
                Some((_, slot)) => value.trim().clone_into(slot),
                None => self
                    .cookies
                    .push((key.trim().to_owned(), value.trim().to_owned())),
            }
        }
    }

    fn get(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        exchange: &Exchange<'_>,
    ) -> Result<Page, String> {
        let mut current = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let reply = self.exchange("GET", &current, headers, &[], exchange)?;
            let location = if is_redirect(reply.status) {
                reply.header("Location").map(str::to_owned)
            } else {
                None
            };
            let Some(location) = location else {
                return Ok(Page {
                    url: current,
                    reply,
                });
            };
            current = resolve_url(&current, &location);
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
        for _ in 0..=MAX_REDIRECTS {
            let reply = match body.as_deref() {
                Some(bytes) => {
                    self.exchange("POST", &current, &headers, bytes.as_bytes(), exchange)?
                }
                None => self.exchange("GET", &current, &[], &[], exchange)?,
            };
            let location = if is_redirect(reply.status) {
                reply.header("Location").map(str::to_owned)
            } else {
                None
            };
            let Some(location) = location else {
                return Ok(Page {
                    url: current,
                    reply,
                });
            };
            current = resolve_url(&current, &location);
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
                "warp: the supplied access token has expired; sign in again to get a fresh one"
                    .to_owned(),
            );
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
    for (name, value) in &reply.headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            if let Some(token) = extract_jwt_from_cookie(value) {
                eprintln!("[+] access issued a device enrolment token");
                return Ok(token);
            }
        }
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
    let mut session = Session::new();
    let landing = session.get(&settings.login_url(), &[], exchange)?;
    let verify_url = extract_totp_form_action(&String::from_utf8_lossy(&landing.reply.body))
        .ok_or_else(|| {
            format!(
                "warp: team {} does not offer an email one-time code on its enrolment page; use a service token or sign in at {}",
                settings.team,
                settings.login_url()
            )
        })?;
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
        let token =
            extract_jwt_from_html(&String::from_utf8_lossy(&page.reply.body)).or_else(|| {
                session
                    .cookies
                    .iter()
                    .rev()
                    .find(|(name, _)| name.eq_ignore_ascii_case("CF_Authorization"))
                    .map(|(_, value)| value.clone())
                    .filter(|value| looks_like_jwt(value))
            });
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
    let endpoint = Endpoint::parse(url, crate::quic::system_roots())
        .ok_or_else(|| format!("warp access: `{url}` is not an https URL"))?;
    let path = if endpoint.base.is_empty() {
        "/"
    } else {
        endpoint.base.as_str()
    };
    crate::foxy_account::ask(&endpoint, method, path, headers, body)
        .map_err(|reason| format!("warp access: {reason}"))
}

/// A token resolver that signs in once per process: `--register all` makes several devices and
/// must not ask for one code per slot.
pub(crate) fn resolve_token(
    settings: &TeamSettings,
    prompt: &mut dyn FnMut(&str, u32) -> Option<String>,
) -> Result<String, String> {
    static CACHED: std::sync::Mutex<Option<(String, String)>> = std::sync::Mutex::new(None);
    let now = now();
    {
        let cached = match CACHED.lock() {
            Ok(cached) => cached,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((team, token)) = cached.as_ref() {
            if *team == settings.team && !jwt_expired(token, now) {
                return Ok(token.clone());
            }
        }
    }
    let token = sign_in(settings, now, &https_exchange, prompt)?;
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
        assert_eq!(normalize_team("https://cloudflareaccess.com"), None);
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
    }

    #[test]
    fn a_supplied_token_is_used_without_asking() {
        let token = jwt("{\"exp\":4102444800}");
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
    fn an_expired_supplied_token_is_refused() {
        let settings = TeamSettings {
            team: "acme".to_owned(),
            token: Some(jwt("{\"exp\":1}")),
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
                    if posts.get() == CODE_ATTEMPTS {
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
        assert_eq!(prompts, CODE_ATTEMPTS);
        assert_eq!(posts.get(), CODE_ATTEMPTS);
    }

    #[test]
    fn an_install_id_is_twenty_two_alphanumerics() {
        let id = generate_install_id();
        assert_eq!(id.len(), INSTALL_ID_LEN);
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
