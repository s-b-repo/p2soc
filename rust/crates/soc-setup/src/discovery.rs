//! Suggest login selectors from a credential-free GET of a dashboard page.

use scraper::{ElementRef, Html, Selector};
use soc_core::guard::valid_http_url;
use soc_sys::run::{Runner, SystemRunner, argv};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub struct LoginForm {
    pub product: Option<&'static str>,
    pub user: String,
    pub password: String,
    pub submit: String,
    pub guessed: bool,
}

#[derive(Debug)]
pub enum ProbeError {
    UntrustedCertificate,
    BasicAuth,
    Failed(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedCertificate => f.write_str("the dashboard certificate could not be verified"),
            Self::BasicAuth => f.write_str("the dashboard uses HTTP Basic authentication instead of an HTML form"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

struct Product {
    name: &'static str,
    title: &'static [&'static str],
    page: &'static [&'static str],
    path: &'static [&'static str],
    selectors: [&'static str; 3],
}

const PRODUCTS: &[Product] = &[
    Product {
        name: "Zabbix",
        title: &["zabbix"],
        page: &["zabbix"],
        path: &["/zabbix"],
        selectors: ["#name", "#password", "#enter"],
    },
    Product {
        name: "Grafana",
        title: &["grafana"],
        page: &["grafana-app", "grafanabootdata"],
        path: &[],
        selectors: ["input[name=\"user\"]", "input[name=\"password\"]", "button[type=submit]"],
    },
    Product {
        name: "Wazuh / Kibana",
        title: &["wazuh", "kibana", "opensearch"],
        page: &["kbn-injected-metadata", "opensearch", "wazuh"],
        path: &[],
        selectors: ["[data-test-subj=\"user-name\"]", "[data-test-subj=\"password\"]", "[data-test-subj=\"submit\"]"],
    },
    Product {
        name: "Keycloak (SSO)",
        title: &["keycloak"],
        page: &["kc-form-login", "kc-login"],
        path: &["/realms/"],
        selectors: ["#username", "#password", "#kc-login"],
    },
];

fn fingerprint(title: &str, page: &str, url: &str) -> Option<&'static Product> {
    let path = soc_core::url::Url::split(url)
        .ok()
        .map(|url| url.rest.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase());
    PRODUCTS.iter().find(|p| {
        p.title.iter().any(|signature| title.contains(signature))
            || p.page.iter().any(|signature| page.contains(signature))
            || path.as_ref().is_some_and(|path| p.path.iter().any(|signature| path.contains(signature)))
    })
}

fn guess(p: &Product) -> LoginForm {
    LoginForm {
        product: Some(p.name),
        user: p.selectors[0].into(),
        password: p.selectors[1].into(),
        submit: p.selectors[2].into(),
        guessed: true,
    }
}

fn attr_selector(element: ElementRef<'_>) -> String {
    let tag = element.value().name();
    for key in ["id", "name", "type"] {
        let Some(value) = element.attr(key).filter(|v| !v.is_empty()) else { continue };
        if key == "id"
            && value.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return format!("#{value}");
        }
        let escaped: String = value
            .chars()
            .map(|c| {
                if c.is_control() || matches!(c, '"' | '\\') { format!("\\{:x} ", u32::from(c)) } else { c.to_string() }
            })
            .collect();
        return format!("{tag}[{key}=\"{escaped}\"]");
    }
    tag.to_string()
}

pub fn parse(html: &str, url: &str) -> Option<LoginForm> {
    let document = Html::parse_document(html);
    let title = document
        .select(&Selector::parse("title").ok()?)
        .next()
        .map(|title| title.text().collect::<String>())
        .unwrap_or_default() // audit-allow: a title element is optional
        .to_ascii_lowercase();
    let product = fingerprint(&title, &html.to_ascii_lowercase(), url);
    let inputs: Vec<_> = document.select(&Selector::parse("input").ok()?).collect();
    let is_type = |node: &ElementRef<'_>, kind| node.attr("type").is_some_and(|t| t.eq_ignore_ascii_case(kind));
    let Some(index) = inputs.iter().position(|input| is_type(input, "password")) else { return product.map(guess) };
    let pass = inputs[index];
    let form_id = |e: ElementRef<'_>| {
        e.ancestors().filter_map(ElementRef::wrap).find(|a| a.value().name() == "form").map(|a| a.id())
    };
    let form = form_id(pass);
    let user = inputs[..index].iter().rev().find(|input| {
        form_id(**input) == form
            && !["hidden", "submit", "button", "checkbox", "radio", "image", "file", "password"]
                .iter()
                .any(|kind| is_type(input, kind))
    });
    let submit = document
        .select(&Selector::parse("button").ok()?)
        .find(|b| form_id(*b) == form && (b.attr("type").is_none() || is_type(b, "submit")))
        .or_else(|| inputs.iter().copied().find(|b| form_id(*b) == form && is_type(b, "submit")));
    Some(LoginForm {
        product: product.map(|p| p.name),
        user: user
            .copied()
            .map(attr_selector)
            .unwrap_or_else(|| product.map_or("#username", |p| p.selectors[0]).into()),
        password: attr_selector(pass),
        submit: submit.map(attr_selector).unwrap_or_else(String::new),
        guessed: false,
    })
}

pub fn probe(url: &str, accept_untrusted: bool) -> Result<Option<LoginForm>, ProbeError> {
    if !valid_http_url(url, false) {
        return Err(ProbeError::Failed("enter a valid HTTP or HTTPS dashboard URL".into()));
    }
    let mut args = argv(&[
        "curl",
        "-q",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "5",
        "--max-time",
        "6",
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-filesize",
        "524288",
        "--include",
        "--user-agent",
        "soc-wall-setup",
    ]);
    if accept_untrusted {
        args.push("--insecure".into());
    }
    args.extend(argv(&["--", url]));
    let out = SystemRunner.run(&args, Duration::from_secs(8)).map_err(|e| ProbeError::Failed(e.to_string()))?;
    if !out.success() {
        if matches!(out.code, Some(51 | 60)) && !accept_untrusted {
            return Err(ProbeError::UntrustedCertificate);
        }
        if let Some(product) = fingerprint("", "", url) {
            return Ok(Some(guess(product)));
        }
        return Err(ProbeError::Failed(format!("dashboard probe failed (curl status {:?})", out.code)));
    }
    let mut body = out.stdout.as_str();
    while body.starts_with("HTTP/") {
        let Some((headers, rest)) = body.split_once("\r\n\r\n") else {
            break;
        };
        body = rest;
        if body.starts_with("HTTP/") {
            continue;
        }
        let status = headers.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        if status == 401 && headers.to_ascii_lowercase().contains("www-authenticate: basic") {
            return Err(ProbeError::BasicAuth);
        }
        if !(200..300).contains(&status) {
            return Err(ProbeError::Failed(format!("dashboard returned HTTP {status}")));
        }
    }
    Ok(parse(body, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_password_form_and_escapes_complex_ids() {
        let form = parse(
            r#"<form><input id="unrelated"></form><form><input id="alice"><input type=hidden>
            <input name="password" type="PASSWORD"><button id="sign in">Log in</button></form>"#,
            "",
        )
        .unwrap();
        assert_eq!(form.user, "#alice");
        assert_eq!(form.password, "input[name=\"password\"]");
        assert_eq!(form.submit, "button[id=\"sign in\"]");
    }

    #[test]
    fn recognizes_a_javascript_login_page() {
        let form = parse("<title>Grafana</title><main></main>", "").unwrap();
        assert_eq!(form.product, Some("Grafana"));
        assert!(form.guessed);
    }
}
