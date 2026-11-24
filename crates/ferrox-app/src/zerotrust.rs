//! Zero Trust enrolment: a team's `cloudflareaccess.com` device page, the three ways it hands out
//! a device JWT, and the `CF-Access-Jwt-Assertion` header the WARP API reads. The HTTP exchange is
//! a closure so the flow's redirects, cookies and parsing are testable without a network.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use crate::foxy_account::{Endpoint, Reply};

const TEAM_SUFFIX: &str = "cloudflareaccess.com";
const TEAM_DOMAIN_SUFFIX: &str = ".cloudflareaccess.com";
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

fn issued_token(reply: &Reply) -> Option<String> {
    reply
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, value)| extract_jwt_from_cookie(value))
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

fn url_origin(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty()).then_some((scheme, authority))
}

fn origin(url: &str) -> Option<String> {
    url_origin(url).map(|(scheme, authority)| {
        format!(
            "{}://{}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase()
        )
    })
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
    let start = rest.find('/').unwrap_or(rest.len());
    let path = rest[start..].split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        "/"
    } else {
        path
    }
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

fn resolve_url(base: &str, location: &str) -> Option<String> {
    let location = decode_entities(location);
    let location = location.trim();
    let (scheme, authority) = url_origin(base)?;
    if location.is_empty() {
        return Some(base.split('#').next().unwrap_or(base).to_owned());
    }
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Some(location.to_owned());
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Some(format!("{scheme}://{rest}"));
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
        return Some(format!("{scheme}://{authority}/{absolute}"));
    }
    let path = url_path(base);
    let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    Some(format!("{scheme}://{authority}{dir}/{location}"))
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
        let mut jar = String::new();
        for cookie in self.cookies.iter().filter(|cookie| cookie.matches(url)) {
            if !jar.is_empty() {
                jar.push_str("; ");
            }
            jar.push_str(&cookie.name);
            jar.push('=');
            jar.push_str(&cookie.value);
        }
        if !jar.is_empty() {
            owned.push(("Cookie".to_owned(), jar));
        }
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let reply = exchange(method, url, &borrowed, body)?;
        self.absorb(url, &reply);
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
            let expires_at = max_age.map(|seconds| {
                if seconds <= 0 {
                    0
                } else {
                    now().saturating_add(u64::try_from(seconds).unwrap_or(u64::MAX))
                }
            });
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
        let token = extract_jwt_from_html(&String::from_utf8_lossy(&page.reply.body))
            .or_else(|| issued_token(&page.reply));
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
