//! Byte-for-byte parity with the Python wall.
//!
//! The expected values under `tests/fixtures/` were produced by running the
//! real Python modules (`tests/fixtures/gen_fixtures.py`). The injected
//! JavaScript is the contract with real login pages, so it is compared as
//! exact text; the stylesheet and the origin / host derivations ride along.

use std::path::PathBuf;

use serde_json::{Value, json};
use soc_core::load::{Overrides, from_value};
use soc_core::{Engine, Login, Panel, SecurityCfg};
use soc_web::websecurity::SecurityData;
use soc_web::{AllowList, Palette, Tokens, inject, loginmemory, siteguard, style};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).unwrap()
}

/// Build the panel the way the wall does: through the real config loader.
fn load_panel(raw: &Value) -> Panel {
    let mut panel = raw.clone();
    // Each case is loaded alone, so its wall position is irrelevant.
    panel["grid"] = json!([0, 0]);
    let mut doc = json!({"panels": [panel]});
    if raw["mode"] == "tunnel" {
        doc["tunnel"] = json!({"enabled": true, "jump_host": "u@jump", "identity": "/k"});
    }
    let mut config = from_value(&doc, "case", &Overrides::default()).unwrap_or_else(|e| panic!("{raw}: {e}"));
    config.panels.remove(0)
}

#[test]
fn bootstrap_is_byte_identical_to_the_python_renderer() {
    let cases = fixture_json("cases.json");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut panel = load_panel(&case["panel"]);
        // Runtime mutations the loader would have rejected (hand-edited overrides).
        if let Some(zones) = case["mutate"]["login_zones"].as_object() {
            panel.login_zones = zones.clone();
        }
        let engine = Engine::parse(case["mode"].as_str().unwrap()).unwrap();
        let rendered = inject::render_bootstrap(inject::DEFAULT_TEMPLATE, &panel, engine);
        let expected = fixture(&format!("expected/{name}.js"));
        if rendered != expected {
            let at = rendered.bytes().zip(expected.bytes()).position(|(a, b)| a != b).unwrap_or(0);
            let show = |s: &str| s.get(at.saturating_sub(40)..(at + 80).min(s.len())).unwrap_or("?").to_string();
            panic!("case {name} differs at byte {at}:\n rust:   {:?}\n python: {:?}", show(&rendered), show(&expected));
        }
        // And through the process-wide template (no override in the test env).
        if std::env::var_os(inject::TEMPLATE_ENV).is_none() {
            assert_eq!(inject::bootstrap_js(&panel, engine), expected, "{name}");
        }
    }
}

#[test]
fn rendered_bootstrap_carries_no_credential_and_no_placeholder() {
    let cases = fixture_json("cases.json");
    for case in cases.as_array().unwrap() {
        let panel = load_panel(&case["panel"]);
        let js = inject::render_bootstrap(inject::DEFAULT_TEMPLATE, &panel, Engine::Chromium);
        // (One case deliberately names its vault item like its panel id.)
        if !panel.vault_item.is_empty() && panel.vault_item != panel.id {
            assert!(!js.contains(&panel.vault_item), "{}: the vault item name stays on the host", case["name"]);
        }
        if case["name"] != "token_in_value" {
            let body = &js[js.find("(function ()").unwrap()..];
            assert!(!body.contains("{{"), "{}: unfilled placeholder", case["name"]);
        }
    }
}

#[test]
fn just_in_time_calls_match_python() {
    let calls = fixture_json("calls.json");
    for row in calls["login"].as_array().unwrap() {
        let (user, pass, expected) = (row[0].as_str().unwrap(), row[1].as_str().unwrap(), row[2].as_str().unwrap());
        assert_eq!(inject::login_call(&Login::new(user, pass)).as_str(), expected);
    }
    for row in calls["prompt"].as_array().unwrap() {
        assert_eq!(inject::prompt_call(row[0].as_str().unwrap()), row[1].as_str().unwrap());
    }
    assert_eq!(inject::prompt_clear_call(), calls["prompt_clear"].as_str().unwrap());
    assert_eq!(inject::CALIBRATE_POLL_JS, calls["calibrate_poll"].as_str().unwrap());
    assert_eq!(inject::CALIBRATE_CLEAR_JS, calls["calibrate_clear"].as_str().unwrap());
    assert_eq!(inject::CALIBRATE_ABORT_JS, calls["calibrate_abort"].as_str().unwrap());
    assert_eq!(inject::FALLBACK_BOOTSTRAP, calls["fallback_bootstrap"].as_str().unwrap());
}

#[test]
fn origins_hosts_and_domains_match_python() {
    for row in fixture_json("origins.json").as_array().unwrap() {
        let url = row["url"].as_str().unwrap();
        let (origin, host, domain) =
            (row["origin"].as_str().unwrap(), row["host"].as_str().unwrap(), row["domain"].as_str().unwrap());
        // The credential gate's origin is the Python value, always.
        assert_eq!(inject::panel_origin(url), origin, "panel_origin({url:?})");
        // Host extraction may only be stricter (a URL it will not read), never different.
        if let Some(rust_host) = siteguard::host_of(url) {
            assert_eq!(rust_host, host, "host_of({url:?})");
        }
        // The login-memory key agrees wherever there is an http(s) origin.
        let rust_domain = loginmemory::domain_of(url);
        if !origin.is_empty() && siteguard::host_of(url).is_some() {
            assert_eq!(rust_domain, domain, "domain_of({url:?})");
        } else {
            assert!(rust_domain.is_empty() || rust_domain == domain, "domain_of({url:?}) = {rust_domain:?}");
        }
    }
}

#[test]
fn security_data_matches_python() {
    let expected = fixture_json("security.json");
    let strings = |v: &Value| v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect::<Vec<_>>();
    let data = SecurityData::embedded();
    assert_eq!(data.sso_domains, strings(&expected["sso"]));
    assert_eq!(data.tracker_hosts, strings(&expected["tracker_hosts"]));
    assert_eq!(data.tracker_hosts, strings(&expected["tracker_hosts_websecurity"]));

    let mut panel = Panel::new("a");
    panel.url = Some("https://dash.example.com/overview".into());
    panel.allow = vec!["*.cdn.example.net".into(), "extra.io".into()];
    let security = SecurityCfg {
        allow: vec!["global.example.org".into()],
        sso_allow: vec!["idp.self-hosted.example".into()],
        ..SecurityCfg::default()
    };
    let list = AllowList::build(&panel, &security, &data);
    assert_eq!(list.hosts().collect::<Vec<_>>(), strings(&expected["allowlist"]));
    // The other Python module keeps the entries un-normalised; it must agree on every decision.
    for pattern in strings(&expected["allowlist_websecurity"]) {
        let host = pattern.trim_start_matches("*.");
        assert!(list.matches(host) && list.matches(&format!("sub.{host}")), "{pattern}");
    }
}

#[test]
fn stylesheet_and_tokens_match_python() {
    let palettes = fixture_json("style.json");
    let palettes = palettes.as_array().unwrap();
    assert_eq!(palettes.len(), 4);
    for entry in palettes {
        let name = entry["name"].as_str().unwrap();
        let tokens = Tokens::from_palette(&Palette::from_colors(entry["colors"].as_object().unwrap()));
        let expected = entry["tokens"].as_object().unwrap();
        assert_eq!(tokens.pairs().len(), expected.len(), "{name}");
        for (token, value) in tokens.pairs() {
            assert_eq!(Some(value), expected[token].as_str(), "{name}: token {token}");
        }
        assert_eq!(tokens.bg, entry["background"].as_str().unwrap());
        let css = style::css(&tokens);
        let want = entry["css"].as_str().unwrap();
        if css != want {
            let at = css.bytes().zip(want.bytes()).position(|(a, b)| a != b).unwrap_or(0);
            panic!(
                "{name}: stylesheet differs at byte {at}: {:?} vs {:?}",
                &css[at.saturating_sub(30)..at + 30],
                &want[at.saturating_sub(30)..at + 30]
            );
        }
    }
}
