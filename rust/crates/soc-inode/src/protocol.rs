//! XML message builders/parsers for the V7 protocol (port of `protocol.py`).
//!
//! Element order is significant (some firmwares parse positionally), so the
//! builders emit children in the exact recovered order and are byte-for-byte
//! identical to `FormatLoginXML` / `FormatChallengeAuthXML`. Responses are
//! parsed leniently with the minimal [`crate::safexml`] reader.

use zeroize::Zeroizing;

use crate::constants as c;
use crate::error::Result;
use crate::safexml::{self, Element};

// --------------------------------------------------------------------------
// building
// --------------------------------------------------------------------------
/// `xml.sax.saxutils.escape`: `&`, then `<` and `>` (quotes are left as-is).
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// `_el(tag, value)` with no attributes: empty -> `<tag></tag>`.
fn el(out: &mut String, tag: &str, value: &str) {
    out.push('<');
    out.push_str(tag);
    out.push('>');
    out.push_str(&escape(value));
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

/// Arguments to [`build_login_xml`]; mirrors `FormatLoginXML` defaults.
pub struct LoginXml<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub vld_code: &'a str,
    pub language: &'a str,
    pub os_name: &'a str,
    pub mac: &'a str,
    pub support_challenge_pwd: &'a str,
    pub private: &'a str,
}

impl<'a> LoginXml<'a> {
    /// The usual values: `language="cn"`, `OS="Linux"`, `supportChallengePwd="1"`.
    pub fn new(username: &'a str, password: &'a str) -> LoginXml<'a> {
        LoginXml {
            username,
            password,
            vld_code: "",
            language: "cn",
            os_name: c::OS_FIELD,
            mac: "",
            support_challenge_pwd: "1",
            private: "",
        }
    }
}

/// `FormatLoginXML` — emission order: username, password, vldCode, language,
/// OS, macAddress, supportChallengePwd, private. The result holds the cleartext
/// password, so it is wiped on drop.
pub fn build_login_xml(args: &LoginXml<'_>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    out.push('<');
    out.push_str(c::XML_ROOT);
    out.push('>');
    el(&mut out, "username", args.username);
    el(&mut out, "password", args.password);
    el(&mut out, "vldCode", args.vld_code);
    el(&mut out, "language", args.language);
    el(&mut out, "OS", args.os_name);
    el(&mut out, "macAddress", args.mac);
    el(&mut out, "supportChallengePwd", args.support_challenge_pwd);
    el(&mut out, "private", args.private);
    out.push_str("</");
    out.push_str(c::XML_ROOT);
    out.push('>');
    out
}

/// Arguments to [`build_challenge_xml`]; mirrors `FormatChallengeAuthXML`.
pub struct ChallengeXml<'a> {
    pub username: &'a str,
    pub ctype: &'a str,
    pub code: &'a str,
    pub language: &'a str,
    /// Added for `SMS-IMC` (current password) and `CHANGEPWD` (old password).
    pub password: Option<&'a str>,
    /// Added for `CHANGEPWD` (new password).
    pub new_password: Option<&'a str>,
    pub vld_code: &'a str,
    pub os_name: &'a str,
    pub mac: &'a str,
    pub private: &'a str,
}

impl<'a> ChallengeXml<'a> {
    pub fn new(username: &'a str, ctype: &'a str, code: &'a str) -> ChallengeXml<'a> {
        ChallengeXml {
            username,
            ctype,
            code,
            language: "cn",
            password: None,
            new_password: None,
            vld_code: "",
            os_name: c::OS_FIELD,
            mac: "",
            private: "",
        }
    }
}

/// `FormatChallengeAuthXML`. Always: username, type, code, language. Then
/// `SMS-IMC` adds `<password>`, `CHANGEPWD` adds `<password>` (old) and
/// `<newPassword>`. All paths then append: vldCode, OS, macAddress, private.
pub fn build_challenge_xml(args: &ChallengeXml<'_>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    out.push('<');
    out.push_str(c::XML_ROOT);
    out.push('>');
    el(&mut out, "username", args.username);
    el(&mut out, "type", args.ctype);
    el(&mut out, "code", args.code);
    el(&mut out, "language", args.language);
    if args.ctype == "SMS-IMC" {
        el(&mut out, "password", args.password.unwrap_or(""));
    } else if args.ctype == c::RESULT_CHANGEPWD {
        el(&mut out, "password", args.password.unwrap_or(""));
        el(&mut out, "newPassword", args.new_password.unwrap_or(""));
    }
    el(&mut out, "vldCode", args.vld_code);
    el(&mut out, "OS", args.os_name);
    el(&mut out, "macAddress", args.mac);
    el(&mut out, "private", args.private);
    out.push_str("</");
    out.push_str(c::XML_ROOT);
    out.push('>');
    out
}

// --------------------------------------------------------------------------
// parsing
// --------------------------------------------------------------------------
/// Capabilities parsed from `<data><gatewayinfo><auth>` (GetVpnConnInfo).
#[derive(Debug, Clone)]
pub struct GatewayInfo {
    pub support_password: bool,
    pub support_cert: bool,
    pub support_dkey: bool,
    pub support_vldimg: bool,
    pub vldimg_url: String,
    pub login_url: String,
    pub logout_url: String,
    pub challenge_url: String,
}

impl Default for GatewayInfo {
    fn default() -> Self {
        GatewayInfo {
            support_password: true,
            support_cert: false,
            support_dkey: false,
            support_vldimg: false,
            vldimg_url: c::PATH_IMAGE.to_string(),
            login_url: c::PATH_LOGIN_V7.to_string(),
            logout_url: c::PATH_LOGOUT.to_string(),
            challenge_url: c::PATH_CHALLENGE_V7.to_string(),
        }
    }
}

/// A capability flag. Older builds use `1`/`0`, the live gateway `true`/`false`.
fn flag(el: &Element, tag: &str, default: &str) -> bool {
    let v = el.child_text(tag, default).trim().to_ascii_lowercase();
    matches!(v.as_str(), "1" | "true" | "yes" | "on")
}

/// Choose `value` unless it is empty, then `default`.
fn or_default(value: &str, default: &str) -> String {
    if value.is_empty() { default.to_string() } else { value.to_string() }
}

/// Parse `<data><gatewayinfo>` (handles both the newer `<url>`-block layout and
/// the older `<auth>`-children layout).
pub fn parse_gatewayinfo(xml: &str) -> Result<GatewayInfo> {
    let root = safexml::fromstring(xml)?;
    let mut gi = GatewayInfo::default();

    let auth_opt = root.find(".//gatewayinfo/auth");
    let auth = auth_opt.unwrap_or(&root);
    if auth.find("supportPassword").is_some() {
        gi.support_password = flag(auth, "supportPassword", "1");
    }
    gi.support_cert = flag(auth, "supportCert", "0");
    gi.support_dkey = flag(auth, "supportDKey", "0");
    gi.support_vldimg = flag(auth, "supportvldimg", "0");

    let url_opt = root.find(".//gatewayinfo/url");
    let src = url_opt.unwrap_or(auth);
    if let Some(vimg) = src.find("vldimg") {
        let from_attr = vimg.get("url").unwrap_or("");
        let from_text = vimg.text.trim();
        if !from_attr.is_empty() {
            gi.vldimg_url = from_attr.to_string();
        } else if !from_text.is_empty() {
            gi.vldimg_url = from_text.to_string();
        }
    }
    gi.login_url = or_default(src.child_text("login", ""), &gi.login_url);
    gi.logout_url = or_default(src.child_text("logout", ""), &gi.logout_url);
    gi.challenge_url = or_default(src.child_text("challenge", ""), &gi.challenge_url);
    Ok(gi)
}

/// One authentication domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub url: String,
}

pub fn parse_domainlist(xml: &str) -> Result<Vec<Domain>> {
    let root = safexml::fromstring(xml)?;
    let mut out: Vec<Domain> = root
        .find_all(".//domainlist/domain")
        .into_iter()
        .map(|d| Domain { name: d.child_text("name", "").to_string(), url: d.child_text("url", "").to_string() })
        .collect();
    if out.is_empty() {
        out = root
            .find_all(".//domain")
            .into_iter()
            .map(|d| Domain { name: d.child_text("name", "").to_string(), url: d.child_text("url", "").to_string() })
            .collect();
    }
    Ok(out)
}

/// A `<data>` login/challenge response (GetLogInInfo / parseAuthRespMsgV7).
#[derive(Debug, Clone, Default)]
pub struct LoginResult {
    pub result: String,
    pub reply_message: String,
    pub emo_server: String,
    pub ctype: String,
    pub message: String,
    pub sms_dynamic_pwd: bool,
    pub wait_time: i64,
    pub interval_time: i64,
    pub raw: String,
}

impl LoginResult {
    pub fn is_success(&self) -> bool {
        self.result == c::RESULT_SUCCESS
    }

    pub fn is_challenge(&self) -> bool {
        if self.is_success() {
            return false;
        }
        self.result == c::RESULT_CHALLENGE || c::CHALLENGE_TYPES.contains(&self.ctype.as_str())
    }
}

pub fn parse_login_result(xml: &str) -> Result<LoginResult> {
    let root = safexml::fromstring(xml)?;
    let int_of = |tag: &str| -> i64 { root.child_text(tag, "0").trim().parse::<i64>().unwrap_or(0) };
    Ok(LoginResult {
        result: root.child_text("result", "").to_string(),
        reply_message: root.child_text("replyMessage", "").to_string(),
        emo_server: root.child_text("EMOServer", "").to_string(),
        ctype: root.child_text("type", "").to_string(),
        message: root.child_text("message", "").to_string(),
        sms_dynamic_pwd: root.child_text("smsDynamicPwdd", "0") == "1",
        wait_time: int_of("waitTime"),
        interval_time: int_of("intervaltime"),
        raw: xml.to_string(),
    })
}
