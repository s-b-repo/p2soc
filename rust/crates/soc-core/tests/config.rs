//! End-to-end config loading: real shipped configs, every validation rule,
//! and the YAML round trip.

use soc_core::dict::DictExt;
use soc_core::emit::to_yaml;
use soc_core::load::{ConfigError, Overrides, load_str_with, load_with};
use soc_core::{Config, Engine, KeepAliveStrategy, Layout, Mode};
use std::path::PathBuf;

fn load(text: &str) -> Result<Config, ConfigError> {
    load_str_with(text, "<test>", &Overrides::default())
}

fn ok(text: &str) -> Config {
    load(text).unwrap_or_else(|e| panic!("expected a valid config, got:\n{e}"))
}

/// The problems of a config that must be rejected.
fn problems(text: &str) -> Vec<String> {
    match load(text) {
        Ok(_) => panic!("expected the config to be rejected:\n{text}"),
        Err(e) => {
            assert!(!e.problems.is_empty(), "structural error instead of findings: {e}");
            e.problems
        }
    }
}

fn rejects(text: &str, needle: &str) {
    let p = problems(text);
    assert!(p.iter().any(|m| m.contains(needle)), "no problem mentions {needle:?}; got {p:#?}");
}

fn warns(text: &str, needle: &str) {
    let c = ok(text);
    assert!(c.warnings.iter().any(|m| m.contains(needle)), "no warning mentions {needle:?}; got {:#?}", c.warnings);
}

fn repo_file(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel)
}

const MINIMAL: &str = "panels:\n  - id: p1\n    url: http://10.0.0.1/\n";

/// One direct panel plus extra top-level YAML.
fn with_panel(extra: &str) -> String {
    format!("{MINIMAL}{extra}")
}

/// One panel carrying extra keys (each line indented four spaces).
fn panel(extra: &str) -> String {
    format!("panels:\n  - id: p1\n{extra}")
}

// --------------------------------------------------------------------------
// Shipped configs
// --------------------------------------------------------------------------

#[test]
fn shipped_template_loads() {
    let c = load_with(&repo_file("config/panels.yaml"), &Overrides::default()).unwrap();
    assert_eq!(c.panels.len(), 4);
    assert_eq!(c.display.layout, Layout::Auto);

    let p1 = c.panel("p1").unwrap();
    assert_eq!(p1.engine, Engine::Webkit);
    assert_eq!(p1.effective_url(), "http://192.168.1.50:3000/login");
    assert_eq!(p1.vault_item, "SOC Panel 1");
    assert_eq!(p1.selectors.text("user"), "#username");
    assert_eq!(p1.keepalive.strategy, KeepAliveStrategy::Reload);
    assert_eq!(p1.keepalive.interval_sec, 600);
    let g = p1.geometry.unwrap();
    assert_eq!((g.x, g.y, g.w, g.h), (0, 0, 960, 540));

    let p2 = c.panel("p2").unwrap();
    assert_eq!(p2.keepalive.strategy, KeepAliveStrategy::Xhr);
    assert_eq!(p2.keepalive.url.as_deref(), Some("http://192.168.1.60:8080/api/ping"));

    let p3 = c.panel("p3").unwrap();
    assert_eq!((p3.engine, p3.mode), (Engine::Chromium, Mode::Tunnel));
    assert_eq!(p3.effective_url(), "http://127.0.0.1:19103/login");
    assert_eq!(p3.tunnel_local_port(), Some(19103));

    assert_eq!(c.tunnel.text("jump_host"), "tunneluser@jump.example.net");
    assert_eq!(c.vpns.len(), 1);
    assert_eq!(c.vpn().unwrap().text("name"), "vpn");
    assert!(!c.vpn().unwrap().truthy("enabled"));
    assert_eq!(c.enabled_vpns().count(), 0);
    assert!(!c.proxy.enabled);
    assert!(c.security.nav_allowlist && c.security.block_trackers);
}

#[test]
fn shipped_presets_load() {
    let dir = repo_file("config/presets");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            load_with(&path, &Overrides::default()).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        }
    }
}

#[test]
fn missing_file_is_a_clear_error() {
    let e = load_with(&repo_file("config/does-not-exist.yaml"), &Overrides::default()).unwrap_err();
    assert!(e.message.contains("config file not found"), "{e}");
    assert!(e.problems.is_empty());
}

// --------------------------------------------------------------------------
// Structure
// --------------------------------------------------------------------------

#[test]
fn structural_errors() {
    for (text, needle) in [
        ("- a\n- b\n", "top level must be a mapping"),
        ("", "top level must be a mapping"),
        ("panels: [\n", "not valid YAML"),
        ("display: 5\n", "display must be a mapping"),
    ] {
        let e = load(text).unwrap_err();
        assert!(e.message.contains(needle), "{text:?} -> {e}");
    }
}

#[test]
fn minimal_config_gets_defaults() {
    let c = ok(MINIMAL);
    let p = &c.panels[0];
    assert_eq!(p.engine, Engine::Webkit);
    assert_eq!(p.mode, Mode::Direct);
    assert_eq!(p.grid, (0, 0));
    assert!(p.proxy && p.persist && p.block_trackers);
    assert!(!p.allow_insecure && !p.allow_media && !p.auto_login());
    assert_eq!(p.keepalive.strategy, KeepAliveStrategy::None);
    assert!(c.vpns.is_empty() && c.tunnel.is_empty());
    assert!(c.display.fullscreen && c.display.auto);
}

#[test]
fn every_problem_is_reported_at_once() {
    let p = problems(
        "display: {cols: 0, layout: tiles}\n\
         panels:\n  - engine: firefox\n    url: ftp://x\n  - id: 'bad id'\n    mode: sideways\n\
         proxy: {enabled: true}\n",
    );
    for needle in [
        "display.cols",
        "display.layout",
        "missing required key 'id'",
        "engine must be",
        "url must be",
        "must match [A-Za-z0-9_-]+",
        "mode must be",
        "proxy: enabled but 'url'",
    ] {
        assert!(p.iter().any(|m| m.contains(needle)), "missing {needle:?} in {p:#?}");
    }
    let e = load("panels:\n  - {}\n").unwrap_err();
    assert!(e.message.starts_with("<test> has 1 problem(s):\n  - "), "{e}");
}

#[test]
fn unknown_keys_warn_but_do_not_fail() {
    warns(&with_panel("vault_iten: x\n"), "unknown key 'vault_iten'");
    warns(&panel("    url: http://h/\n    vault_iten: x\n"), "panel p1: unknown key 'vault_iten'");
    warns(&with_panel("display: {colz: 2}\n"), "display: unknown key 'colz'");
}

// --------------------------------------------------------------------------
// Display
// --------------------------------------------------------------------------

#[test]
fn display_rules() {
    rejects(&with_panel("display: {width: -1}\n"), "display.width");
    rejects(&with_panel("display: {height: 1.5}\n"), "display.height");
    rejects(&with_panel("display: {rows: true}\n"), "display.rows");
    rejects(&with_panel("display: {cols: 100000}\n"), "display.cols");
    rejects(&with_panel("display: {gap: -3}\n"), "display.gap");
    rejects(&with_panel("display: {fullscreen: maybe}\n"), "display.fullscreen");
    let c = ok(&with_panel("display: {cols: 3, rows: 1, gap: 6, layout: single, fullscreen: false}\n"));
    assert_eq!((c.display.cols, c.display.rows, c.display.gap), (3, 1, 6));
    assert_eq!(c.display.layout, Layout::Single);
    assert!(!c.display.fullscreen);
}

#[test]
fn yaml11_booleans_keep_their_meaning() {
    let c = ok(&with_panel("display: {fullscreen: no, auto: off}\n"));
    assert!(!c.display.fullscreen && !c.display.auto);
}

// --------------------------------------------------------------------------
// Panels
// --------------------------------------------------------------------------

#[test]
fn panel_must_be_a_mapping() {
    rejects("panels:\n  - just-a-string\n", "panel #1: must be a mapping");
    rejects("panels: nope\n", "panels: must be a list");
}

#[test]
fn panel_id_cannot_carry_markup() {
    for bad in ["'a b'", "'<x>'", "'a\"b'", "\"p1\\n\"", "'a/b'"] {
        rejects(&format!("panels:\n  - id: {bad}\n    url: http://h/\n"), "must match [A-Za-z0-9_-]+");
    }
    assert_eq!(ok("panels:\n  - id: 7\n    url: http://h/\n").panels[0].id, "7");
}

#[test]
fn grid_rules() {
    rejects(&panel("    url: http://h/\n    grid: [2, 0]\n"), "outside the 2x2 grid");
    rejects(&panel("    url: http://h/\n    grid: [0, -1]\n"), "outside the 2x2 grid");
    rejects(&panel("    url: http://h/\n    grid: [0]\n"), "grid must be [col, row] integers");
    rejects(&panel("    url: http://h/\n    grid: [[1], [2]]\n"), "grid must be [col, row] integers");
    rejects(&panel("    url: http://h/\n    grid: [true, 0]\n"), "grid must be [col, row] integers");
    rejects(
        "panels:\n  - {id: a, url: 'http://h/', grid: [1, 1]}\n  - {id: b, url: 'http://h/', grid: [1, 1]}\n",
        "panels a, b share grid cell [1, 1]",
    );
}

#[test]
fn duplicate_ids_and_ports() {
    rejects(
        "panels:\n  - {id: a, url: 'http://h/'}\n  - {id: a, url: 'http://h/', grid: [1, 0]}\n",
        "panel id 'a' is used more than once",
    );
    rejects(
        "tunnel: {jump_host: u@j}\npanels:\n\
         \x20 - {id: a, mode: tunnel, tunnel: {local_port: 1900, remote_host: h, remote_port: 80}}\n\
         \x20 - {id: b, grid: [1, 0], mode: tunnel, tunnel: {local_port: 1900, remote_host: h, remote_port: 80}}\n",
        "tunnel local_port 1900 is used by more than one panel",
    );
}

#[test]
fn direct_url_rules() {
    for bad in ["ftp://h/", "javascript:alert(1)", "http://u:p@h/", "http://h:99999/", "'http://h/a b'", "http:///x"] {
        rejects(&panel(&format!("    url: {bad}\n")), "url must be a valid http:// or https:// URL");
    }
    warns(&panel("    engine: webkit\n"), "no url yet");
    assert!(!ok(&panel("    engine: webkit\n")).panels[0].configured());
}

#[test]
fn rejected_url_never_leaks_its_password() {
    let e = load(&panel("    url: http://admin:hunter2@h/\n")).unwrap_err();
    assert!(!e.message.contains("hunter2"), "{e}");
    assert!(e.message.contains("***@h"), "{e}");
}

#[test]
fn tunnel_panel_rules() {
    let base = "tunnel: {jump_host: u@j}\npanels:\n  - id: p1\n    mode: tunnel\n";
    rejects(base, "requires a 'tunnel:' mapping");
    let t = |body: &str| format!("{base}    tunnel: {body}\n");
    rejects(&t("{local_port: 0, remote_host: h, remote_port: 80}"), "tunnel.local_port must be a port number");
    rejects(&t("{local_port: '19000', remote_host: h, remote_port: 80}"), "tunnel.local_port must be a port number");
    rejects(&t("{local_port: 19000, remote_port: 80}"), "tunnel.remote_host is required");
    rejects(&t("{local_port: 19000, remote_host: 'h:80', remote_port: 80}"), "embedded ':port'");
    rejects(&t("{local_port: 19000, remote_host: '-oProxyCommand=x', remote_port: 80}"), "option injection");
    rejects(&t("{local_port: 19000, remote_host: h, remote_port: 70000}"), "tunnel.remote_port must be a port number");
    warns(&t("{local_port: 19000, remote_host: h}"), "tunnel.remote_port is not set");
    rejects(
        "panels:\n  - id: p1\n    mode: tunnel\n    tunnel: {local_port: 1, remote_host: h, remote_port: 2}\n",
        "tunnel.jump_host is not set",
    );
}

#[test]
fn tunnel_path_cannot_redirect_the_panel() {
    let t = |path: &str| {
        format!(
            "tunnel: {{jump_host: u@j}}\npanels:\n  - id: p1\n    mode: tunnel\n    path: {path}\n    \
             tunnel: {{local_port: 19000, remote_host: h, remote_port: 80}}\n"
        )
    };
    // "@evil.com/x" would turn 127.0.0.1:port into userinfo.
    rejects(&t("'@evil.com/dash'"), "tunnel path must be a string starting with '/'");
    rejects(&t("7"), "tunnel path must be a string starting with '/'");
    rejects(&t("'/a b'"), "tunnel path must be a string starting with '/'");
    assert_eq!(ok(&t("/dash")).panels[0].effective_url(), "http://127.0.0.1:19000/dash");
}

#[test]
fn boolean_knobs_must_be_booleans() {
    for k in ["proxy", "allow_insecure", "allow_media", "persist", "block_trackers", "insecure_tls"] {
        rejects(&panel(&format!("    url: http://h/\n    {k}: 3\n")), &format!("{k}: must be true or false"));
    }
    rejects(&panel("    url: http://h/\n    insecure_tls: true\n    allow_insecure: false\n"), "conflicting values");
    assert!(ok(&panel("    url: http://h/\n    insecure_tls: true\n")).panels[0].allow_insecure);
    assert!(ok(&panel("    url: http://h/\n    allow_insecure: true\n")).panels[0].allow_insecure);
}

#[test]
fn text_knobs() {
    rejects(&panel("    url: http://h/\n    tenant: \"a\\nb\"\n"), "tenant must be a single-line string");
    rejects(&panel(&format!("    url: http://h/\n    tenant: {}\n", "x".repeat(101))), "tenant must be");
    rejects(&panel("    url: http://h/\n    user_agent: '  '\n"), "user_agent must be");
    rejects(&panel("    url: http://h/\n    user_agent: \"a\\r\\nX-Evil: 1\"\n"), "user_agent must be");
    rejects(&panel("    url: http://h/\n    allow: example.com\n"), "must be a list of non-empty domain strings");
    rejects(&panel("    url: http://h/\n    unblock: ['']\n"), "must be a list of non-empty domain strings");
    rejects(&panel("    url: http://h/\n    scheme: gopher\n"), "scheme must be http or https");
    let c = ok(&panel("    url: http://h/\n    tenant: ' acme '\n    title: Ops\n    allow: ['*.cdn.example']\n"));
    assert_eq!(c.panels[0].tenant, "acme");
    assert_eq!(c.panels[0].display_name(), "Ops");
    assert_eq!(c.panels[0].allow, vec!["*.cdn.example"]);
}

#[test]
fn auto_login_needs_selectors() {
    rejects(&panel("    url: http://h/\n    vault_item: X\n"), "has a vault_item but no 'selectors:' mapping");
    rejects(
        &panel("    url: http://h/\n    vault_item: X\n    selectors: {user: '#u'}\n"),
        "selectors.pass is required",
    );
    rejects(&panel("    url: http://h/\n    selectors: nope\n"), "selectors must be a mapping");
    let c = ok(&panel("    url: http://h/\n    vault_item: X\n    selectors: {user: '#u', pass: '#p'}\n"));
    assert!(c.panels[0].auto_login());
    assert_eq!(c.panels[0].login_marker, "#p", "login_marker defaults to the password selector");
}

#[test]
fn keepalive_rules() {
    rejects(&panel("    url: http://h/\n    keepalive: {strategy: poke}\n"), "keepalive.strategy must be one of");
    rejects(&panel("    url: http://h/\n    keepalive: {strategy: reload, intervalSec: 0}\n"), "keepalive.intervalSec");
    rejects(&panel("    url: http://h/\n    keepalive: 5\n"), "keepalive must be a mapping");
    warns(&panel("    url: http://h/\n    keepalive: {strategy: xhr}\n"), "'xhr' without a 'url'");
    warns(&panel("    url: http://h/\n    keepalive: {strategy: click}\n"), "'click' without a 'target'");
}

#[test]
fn login_zone_rules() {
    let z = |body: &str| panel(&format!("    url: http://h/\n    login_zones: {body}\n"));
    rejects(&z("[1]"), "login_zones must be a mapping");
    rejects(&z("{nope: {x_pct: 0.5, y_pct: 0.5}}"), "unknown login_zones key(s)");
    rejects(&z("{user: 5}"), "login_zones.user must be a mapping");
    rejects(&z("{user: {x_pct: 0.5}}"), "login_zones.user missing");
    rejects(&z("{user: {x_pct: 1.5, y_pct: 0.5}}"), "must be a 0.0..1.0 ratio");
    rejects(&z("{user: {x_pct: true, y_pct: 0.5}}"), "must be a 0.0..1.0 ratio");
    rejects(&z("{user: {x_pct: .nan, y_pct: 0.5}}"), "must be a 0.0..1.0 ratio");
    let c = ok(&z("{user: {x_pct: 0.5, y_pct: 0.25}, submit: {x_pct: 1, y_pct: 0}}"));
    assert_eq!(c.panels[0].login_zones.len(), 2);
}

#[test]
fn single_layout_cannot_host_chromium() {
    rejects(
        "display: {layout: single}\npanels:\n  - {id: c1, engine: chromium, url: 'http://h/'}\n",
        "'single' cannot host chromium panels (c1)",
    );
}

// --------------------------------------------------------------------------
// Tunnel section
// --------------------------------------------------------------------------

#[test]
fn tunnel_section_rules() {
    rejects(&with_panel("tunnel: [1]\n"), "tunnel: must be a mapping");
    rejects(&with_panel("tunnel: {jump_host: '-oProxyCommand=evil'}\n"), "option injection");
    rejects(&with_panel("tunnel: {jump_host: u@j, identity: '-F/tmp/x'}\n"), "tunnel.identity");
    rejects(
        &with_panel("tunnel: {jump_host: u@j, extra_forwards: '8080:h:80'}\n"),
        "tunnel.extra_forwards: must be a list",
    );
    warns(&with_panel("tunnel: {jump_host: u@j, extra_forwards: ['-D 1080']}\n"), "the tunnel will refuse to start");
    warns(&with_panel("tunnel: {jump_host: u@j, host_key_checking: 'no'}\n"), "using strict 'yes'");
    warns(
        &with_panel("tunnel: {jump_host: u@j, host_key_checking: accept-new}\n"),
        "needs an explicit tunnel.known_hosts",
    );
    let c = ok(&with_panel("tunnel: {jump_host: u@j, host_key_checking: accept-new, known_hosts: /k}\n"));
    assert!(c.warnings.iter().all(|w| !w.contains("host_key_checking")), "{:?}", c.warnings);
    // A disabled tunnel is not vetted (and may hold placeholders).
    ok(&with_panel("tunnel: {enabled: false, jump_host: '-x'}\n"));
}

// --------------------------------------------------------------------------
// VPNs
// --------------------------------------------------------------------------

const FORTI: &str = "enabled: true, gateway: vpn.example.com, vault_item: V";

#[test]
fn legacy_single_vpn_is_wrapped_and_named() {
    let c = ok(&with_panel(&format!("vpn: {{{FORTI}}}\n")));
    assert_eq!(c.vpns.len(), 1);
    assert_eq!(c.vpn().unwrap().text("name"), "vpn");
    assert_eq!(c.enabled_vpns().count(), 1);
    warns(&with_panel(&format!("vpn: {{{FORTI}}}\n")), "no trusted_cert / ca_file pinned");
}

#[test]
fn vpn_list_wins_over_stray_block_and_names_entries() {
    let text = with_panel(&format!(
        "vpn: {{{FORTI}}}\nvpns:\n  - {{{FORTI}}}\n  - {{{FORTI}, name: site-b}}\n  - {{{FORTI}}}\n"
    ));
    let c = ok(&text);
    let names: Vec<String> = c.vpns.iter().map(|v| v.text("name")).collect();
    assert_eq!(names, vec!["vpn", "site-b", "vpn3"]);
    warns(&text, "both 'vpn:' and 'vpns:' are set");
}

#[test]
fn vpn_list_rules() {
    rejects(&with_panel("vpns: {a: 1}\n"), "vpns: must be a list of VPN mappings");
    rejects(&with_panel("vpns: [5]\n"), "vpns[0]: must be a mapping");
    rejects(&with_panel("vpns:\n  - {name: 'a b'}\n"), "'name' must start alphanumeric");
    rejects(&with_panel("vpns:\n  - {name: a}\n  - {name: A}\n"), "duplicate VPN name(s)");
    rejects(
        &with_panel("vpns:\n  - {name: a, default_route: true}\n  - {name: b, default_route: true}\n"),
        "at most one VPN may set 'default_route: true'",
    );
    rejects(&with_panel("vpns:\n  - {name: a, default_route: 5}\n"), "default_route: must be true or false");
    let many: String = (0..9).map(|i| format!("  - {{name: v{i}}}\n")).collect();
    rejects(&with_panel(&format!("vpns:\n{many}")), "at most 8 VPNs supported");
}

#[test]
fn disabled_vpn_is_not_vetted() {
    ok(&with_panel("vpn: {enabled: false, gateway: 'not a host', port: 99999}\n"));
}

#[test]
fn fortinet_rules() {
    let v = |body: &str| with_panel(&format!("vpn: {{enabled: true, {body}}}\n"));
    rejects(&v("vault_item: V"), "'gateway' is not set");
    rejects(&v("gateway: gw"), "'vault_item' is not set");
    rejects(&v("gateway: 'a b', vault_item: V"), "vpn.gateway: not a valid hostname or IP address");
    rejects(&v("gateway: '-oX', vault_item: V"), "vpn.gateway: not a valid hostname or IP address");
    rejects(&v("gateway: 'gw:', vault_item: V"), "vpn.gateway: not a valid hostname or IP address");
    rejects(&v("gateway: gw, vault_item: V, port: 0"), "vpn.port: must be a port number");
    rejects(&v("gateway: gw, vault_item: V, trusted_cert: abc"), "expected a sha256 (64-char) or sha1 (40-char)");
    rejects(&v("gateway: gw, vault_item: V, realm: '-x'"), "vpn.realm may not begin with '-'");
    rejects(&v("gateway: gw, vault_item: V, extra_args: '-v'"), "extra_args must be a list");
    rejects(&v("gateway: gw, vault_item: V, persistent: -1"), "vpn.persistent: must be an integer >= 0");
    rejects(&v("gateway: gw, vault_item: V, ready_probe: nohost"), "vpn.ready_probe: want 'host:port'");
    rejects(&v("gateway: gw, vault_item: V, health_check_interval: 30"), "health check needs a host:port");
    rejects(&v("gateway: gw, vault_item: V, type: pptp"), "vpn.type: must be one of");
    // The gateway may come from the vault item instead.
    ok(&v("vault_item: V, config_from_vault: true"));
    ok(&v(&format!("gateway: '[fd00::1]:10443', vault_item: V, trusted_cert: {}", "ab".repeat(32))));
}

#[test]
fn a_non_string_probe_is_an_error_not_a_crash() {
    rejects(&with_panel(&format!("vpn: {{{FORTI}, ready_probe: 443}}\n")), "vpn.ready_probe: want 'host:port'");
}

#[test]
fn openvpn_and_wireguard_rules() {
    let v = |body: &str| with_panel(&format!("vpn: {{enabled: true, {body}}}\n"));
    rejects(&v("type: openvpn"), "requires 'config'");
    rejects(&v("type: openvpn, config_from_vault: true"), "needs 'vault_item'");
    warns(&v("type: openvpn, config: /etc/openvpn/soc.ovpn"), "assuming certificate-only auth");
    ok(&v("type: OpenVPN, config_from_vault: true, vault_item: V"));
    rejects(&v("type: wireguard"), "requires 'config'");
    rejects(&v("type: wireguard, config_from_vault: true"), "needs 'vault_item'");
    warns(&v("type: wireguard, config: wg0, vault_item: V"), "wireguard ignores vault_item");
    // WireGuard health checks need no probe (it checks the handshake).
    ok(&v("type: wireguard, config: wg0, health_check_interval: 30"));
}

#[test]
fn inode_rules() {
    let v = |body: &str| with_panel(&format!("vpn: {{enabled: true, type: inode, {body}}}\n"));
    rejects(&v("vault_item: V"), "'gateway' is not set");
    rejects(&v("gateway: gw"), "'vault_item' is not set");
    rejects(&v("gateway: gw, vault_item: V, insecure: 5"), "vpn.insecure: must be true or false");
    rejects(&v("gateway: gw, vault_item: V, captcha_retries: -1"), "vpn.captcha_retries");
    rejects(&v("gateway: gw, vault_item: V, spa_knock_port: 0"), "vpn.spa_knock_port");
    rejects(&v("gateway: gw, vault_item: V, spa_key: \"a\\nb\""), "vpn.spa_key must not contain newlines");
    warns(&v("gateway: gw, vault_item: V"), "no trusted_cert pin and insecure not set");
    warns(&v("gateway: gw, vault_item: V, trusted_cert: 'zz'"), "does not look like a sha256/sha1 cert pin");
    warns(&v("gateway: gw, vault_item: V, spa_key: k"), "SDP/SPA without cert pin");
}

#[test]
fn a_sensitive_word_is_never_echoed() {
    let e = load(&with_panel("vpn: {enabled: true, type: inode, gateway: gw, vault_item: V, spa_key: '-topsecret'}\n"))
        .unwrap_err();
    assert!(!e.message.contains("topsecret"), "{e}");
}

// --------------------------------------------------------------------------
// Proxy + security
// --------------------------------------------------------------------------

#[test]
fn proxy_rules() {
    let p = |body: &str| with_panel(&format!("proxy: {{enabled: true, {body}}}\n"));
    rejects(&with_panel("proxy: [1]\n"), "proxy: must be a mapping");
    rejects(&p("url: 'ftp://h:1'"), "proxy.url: scheme must be one of");
    rejects(&p("url: 'http://:3128'"), "proxy.url: missing host");
    rejects(&p("url: 'http://h'"), "proxy.url: missing port");
    rejects(&p("url: 'http://u:pw@h:3128'"), "must not embed credentials");
    rejects(&p("url: 'http://h:3128 x'"), "must not contain whitespace");
    rejects(&p("url: 'http://h:3128', ignore_hosts: [1]"), "proxy.ignore_hosts");
    warns(&p("url: 'socks5://h:1080', vault_item: P"), "SOCKS with vault_item");
    let c = ok(&p("url: ' http://proxy.example.com:3128 ', vault_item: P, ignore_hosts: ['*.corp.lan']"));
    assert_eq!(c.proxy.url, "http://proxy.example.com:3128");
    assert_eq!(c.proxy.effective_ignore_hosts(), vec!["*.corp.lan", "localhost", "127.0.0.1", "::1"]);
    // A disabled proxy is not vetted.
    ok(&with_panel("proxy: {enabled: false, url: 'garbage'}\n"));
}

#[test]
fn proxy_error_never_leaks_its_password() {
    let e = load(&with_panel("proxy: {enabled: true, url: 'ftp://u:hunter2@h:1'}\n")).unwrap_err();
    assert!(!e.message.contains("hunter2"), "{e}");
}

#[test]
fn security_rules_and_overrides() {
    rejects(&with_panel("security: 7\n"), "security: must be a mapping");
    rejects(&with_panel("security: {nav_allowlist: 2}\n"), "security.nav_allowlist: must be true or false");
    rejects(&with_panel("security: {allow: x}\n"), "security.allow: must be a list");
    let text = with_panel("security: {block_trackers: false, sso_allow: ['*.sso.corp']}\n");
    let c = ok(&text);
    assert!(c.security.nav_allowlist && !c.security.block_trackers);
    assert_eq!(c.security.sso_allow, vec!["*.sso.corp"]);

    let off = Overrides { nav_allowlist: Some("0".into()), block_trackers: Some("on".into()) };
    let c = load_str_with(&text, "<test>", &off).unwrap();
    assert!(!c.security.nav_allowlist && c.security.block_trackers);

    // A typo'd override falls back to the configured (safe) value.
    let typo = Overrides { nav_allowlist: Some("flase".into()), block_trackers: None };
    assert!(load_str_with(MINIMAL, "<test>", &typo).unwrap().security.nav_allowlist);
}

// --------------------------------------------------------------------------
// Hostile input
// --------------------------------------------------------------------------

#[test]
fn oversized_config_is_refused() {
    let big = format!("{MINIMAL}# {}\n", "x".repeat(1024 * 1024));
    assert!(load(&big).unwrap_err().message.contains("larger than"));
}

#[test]
fn alias_bombs_do_not_blow_up() {
    let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
    let mut prev = 'a';
    for c in 'b'..='k' {
        bomb.push_str(&format!(
            "{c}: &{c} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
        ));
        prev = c;
    }
    bomb.push_str("panels: *k\n");
    // Either outcome is fine as long as it returns promptly and does not OOM.
    let _ = load(&bomb);
}

#[test]
fn garbage_never_panics() {
    for text in [
        "panels: [null, 1, [], {}]\n",
        "panels:\n  - {id: [1], url: {a: 1}, grid: {x: 1}, mode: [], keepalive: [], selectors: 1, tunnel: 2}\n",
        "vpns: [null, {enabled: true, type: [], gateway: {}, port: [], extra_args: {}}]\npanels: []\n",
        "display: {width: 9999999999999999999999}\n",
        "tunnel: {enabled: [], jump_host: {}, extra_forwards: [[], {}], host_key_checking: []}\n",
        "proxy: {enabled: true, url: [], ignore_hosts: {}}\n",
        "security: {allow: [[]], sso_allow: {}}\n",
        "? [a, b]\n: c\n1: 2\ntrue: false\n",
    ] {
        let _ = load(text);
    }
}

// --------------------------------------------------------------------------
// Round trip
// --------------------------------------------------------------------------

fn round_trips(text: &str) {
    let mut first = ok(text);
    let yaml = to_yaml(&first);
    let mut second = load(&yaml).unwrap_or_else(|e| panic!("emitted YAML does not load: {e}\n{yaml}"));
    first.warnings.clear();
    second.warnings.clear();
    assert_eq!(first, second, "round trip changed the config:\n{yaml}");
    assert_eq!(yaml, to_yaml(&second), "emission is not stable");
}

#[test]
fn round_trip_shipped_template() {
    round_trips(&std::fs::read_to_string(repo_file("config/panels.yaml")).unwrap());
}

#[test]
fn round_trip_every_knob() {
    round_trips(&format!(
        "display: {{cols: 3, rows: 2, gap: 4, layout: windows, fullscreen: false, auto: false}}\n\
         panels:\n\
         \x20 - id: a\n    url: https://h.example/x\n    vault_item: A\n    selectors: {{user: '#u', pass: '#p', submit: '#s'}}\n\
         \x20   login_marker: '#marker'\n    keepalive: {{strategy: click, intervalSec: 30, target: '#k'}}\n\
         \x20   proxy: false\n    title: 'Ops: main'\n    allow_insecure: true\n    allow_media: true\n    tenant: acme\n\
         \x20   persist: false\n    user_agent: 'Mozilla/5.0 (X11)'\n    allow: ['*.cdn.example']\n    block_trackers: false\n\
         \x20   unblock: [segment.io]\n    login_zones: {{user: {{x_pct: 0.5, y_pct: 0.25}}}}\n\
         \x20 - id: b\n    grid: [2, 1]\n    engine: chromium\n    mode: tunnel\n    path: /login\n    scheme: https\n\
         \x20   tunnel: {{local_port: 19103, remote_host: 10.20.0.7, remote_port: 8443}}\n\
         tunnel: {{jump_host: u@j, identity: /k, extra_forwards: ['8080:h:80']}}\n\
         vpns:\n  - {{{FORTI}, name: site-a, default_route: true}}\n  - {{enabled: true, type: wireguard, config: wg0}}\n\
         proxy: {{enabled: true, url: 'http://proxy:3128', vault_item: P, ignore_hosts: ['*.lan']}}\n\
         security: {{nav_allowlist: false, block_trackers: false, allow: [a.example], sso_allow: ['*.sso']}}\n"
    ));
}

#[test]
fn single_plain_vpn_stays_a_legacy_block() {
    let yaml = to_yaml(&ok(&with_panel(&format!("vpn: {{{FORTI}}}\n"))));
    assert!(yaml.contains("\nvpn:\n"), "{yaml}");
    assert!(!yaml.contains("vpns:") && !yaml.contains("name: vpn"), "{yaml}");
    let named = to_yaml(&ok(&with_panel(&format!("vpns:\n  - {{{FORTI}, name: site-a}}\n"))));
    assert!(named.contains("vpns:") && named.contains("name: site-a"), "{named}");
}
