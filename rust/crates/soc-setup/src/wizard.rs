//! Terminal setup, including the first-boot flow used on tty1.

use crate::cli::{Flags, read_line_secret, read_master, show_step, system_install, target_of};
use crate::deploy::{DeployPlan, DeployState, DeployStep};
use crate::error::TextResult;
use crate::host::{Probe, SystemHost};
use crate::paths::{SetupPaths, Target, is_configured};
use crate::vault::LoginCred;
use serde_json::{Value, json};
use soc_sys::paths::PathEnv;
use std::fs::OpenOptions;
use std::io::{self, BufReader, IsTerminal, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub(crate) fn ask_secret(label: &str) -> TextResult<Zeroizing<String>> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("cannot open the terminal: {e}; supply --master-fd"))?;
    let stty = |args: &[&str]| -> io::Result<_> {
        Command::new("stty").args(args).stdin(tty.try_clone()?).stderr(Stdio::null()).output()
    };
    let settings = stty(&["-g"]).map_err(|e| e.to_string())?;
    let mode = String::from_utf8_lossy(&settings.stdout);
    if !settings.status.success() || !stty(&["-echo"]).is_ok_and(|o| o.status.success()) {
        return Err("cannot disable terminal echo; supply --master-fd".into());
    }
    let read = || -> TextResult<_> {
        write!(&tty, "{label}: ").map_err(|e| e.to_string())?;
        read_line_secret(BufReader::new(&tty))
    };
    let secret = read();
    let restored = stty(&[mode.trim()]).is_ok_and(|o| o.status.success());
    writeln!(&tty).map_err(|e| e.to_string())?;
    if !restored {
        return Err("could not restore terminal settings".into());
    }
    secret
}

struct Prompt {
    defaults: bool,
}

impl Prompt {
    fn text(&self, label: &str, default: &str) -> TextResult<String> {
        if self.defaults {
            return Ok(default.to_string());
        }
        print!("{label} [{default}]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("setup input closed".into());
        }
        let answer = line.trim();
        Ok(if answer.is_empty() {
            default.to_string()
        } else if answer == "-" {
            String::new()
        } else {
            answer.to_string()
        })
    }

    fn yes(&self, label: &str, default: bool) -> TextResult<bool> {
        loop {
            match self.text(label, if default { "yes" } else { "no" })?.to_ascii_lowercase().as_str() {
                "yes" | "y" | "true" | "1" => return Ok(true),
                "no" | "n" | "false" | "0" => return Ok(false),
                _ => println!("Enter yes or no."),
            }
        }
    }

    fn integer(&self, label: &str, default: i64, low: i64, high: i64) -> TextResult<i64> {
        loop {
            let answer = self.text(label, &default.to_string())?;
            if let Some(n) = answer.parse::<i64>().ok().filter(|n| (low..=high).contains(n)) {
                return Ok(n);
            }
            if self.defaults {
                return Err(format!("{label} must be between {low} and {high}"));
            }
            println!("Enter a number between {low} and {high}.");
        }
    }

    fn choice(&self, label: &str, default: &str, choices: &[&str]) -> TextResult<String> {
        loop {
            let answer = self.text(&format!("{label} ({})", choices.join("/")), default)?;
            if choices.contains(&answer.as_str()) {
                return Ok(answer);
            }
            if self.defaults {
                return Err(format!("invalid {label}: {answer}"));
            }
        }
    }

    fn field(&self, obj: &mut Value, key: &str, label: &str, default: &str) -> TextResult<()> {
        let previous = obj[key].as_str().unwrap_or(default);
        obj[key] = json!(self.text(label, previous)?);
        Ok(())
    }

    fn toggle(&self, obj: &mut Value, key: &str, label: &str, default: bool) -> TextResult<bool> {
        let answer = self.yes(label, obj[key].as_bool().unwrap_or(default))?;
        obj[key] = json!(answer);
        Ok(answer)
    }

    fn number(&self, obj: &mut Value, key: &str, label: &str, default: i64, low: i64, high: i64) -> TextResult<()> {
        obj[key] = json!(self.integer(label, obj[key].as_i64().unwrap_or(default), low, high)?);
        Ok(())
    }
}

fn display(p: &Prompt, d: &mut Value) -> TextResult<()> {
    let sizes = ["auto", "1920x1080", "2560x1440", "3840x2160", "1280x720", "custom"];
    let dimensions = format!("{}x{}", d["width"].as_i64().unwrap_or(1920), d["height"].as_i64().unwrap_or(1080));
    let default = if d["auto"].as_bool().unwrap_or(true) {
        "auto"
    } else if sizes.contains(&dimensions.as_str()) {
        &dimensions
    } else {
        "custom"
    };
    let resolution = p.choice("Screen resolution", default, &sizes)?;
    d["auto"] = json!(resolution == "auto");
    if resolution == "custom" {
        p.number(d, "width", "Screen width", 1920, 1, 32768)?;
        p.number(d, "height", "Screen height", 1080, 1, 32768)?;
    } else if let Some((width, height)) = resolution.split_once('x') {
        d["width"] = json!(width.parse::<u32>().map_err(|e| e.to_string())?);
        d["height"] = json!(height.parse::<u32>().map_err(|e| e.to_string())?);
    }
    for (key, label, default, low, high) in
        [("cols", "Grid columns", 2, 1, 4), ("rows", "Grid rows", 2, 1, 4), ("gap", "Gap between panels", 0, 0, 4096)]
    {
        p.number(d, key, label, default, low, high)?;
    }
    d["layout"] = json!(p.choice("Layout", d["layout"].as_str().unwrap_or("auto"), &["auto", "windows", "single"])?);
    p.toggle(d, "fullscreen", "Fullscreen", true)?;
    Ok(())
}

fn panels(p: &Prompt, doc: &mut Value) -> TextResult<()> {
    let cols = doc["display"]["cols"].as_i64().unwrap_or(2).clamp(1, 4);
    let rows = doc["display"]["rows"].as_i64().unwrap_or(2).clamp(1, 4);
    let old = doc["panels"].as_array().cloned().unwrap_or_else(Vec::new);
    let limit = cols * rows;
    let n = p.integer("Number of panels", (old.len() as i64).min(limit), 0, limit)?;
    let mut edited = Vec::new();
    for i in 0..n {
        println!("Panel {}", i + 1);
        let mut v = old.get(i as usize).cloned().unwrap_or_else(|| json!({}));
        p.field(&mut v, "id", "Panel ID", &format!("p{}", i + 1))?;
        p.field(&mut v, "title", "Title", "")?;
        v["engine"] = json!(p.choice("Engine", v["engine"].as_str().unwrap_or("webkit"), &["webkit", "chromium"])?);
        let col = p.integer("Grid column (zero based)", v["grid"][0].as_i64().unwrap_or(i % cols), 0, cols - 1)?;
        let row = p.integer("Grid row (zero based)", v["grid"][1].as_i64().unwrap_or(i / cols), 0, rows - 1)?;
        v["grid"] = json!([col, row]);
        v["mode"] = json!(p.choice("Connection", v["mode"].as_str().unwrap_or("direct"), &["direct", "tunnel"])?);
        if v["mode"] == "tunnel" {
            let t = &mut v["tunnel"];
            p.number(t, "local_port", "Local port", 19100 + i, 1, 65535)?;
            p.field(t, "remote_host", "Remote host", "")?;
            p.number(t, "remote_port", "Remote port", 443, 1, 65535)?;
            v["scheme"] = json!(p.choice("Scheme", v["scheme"].as_str().unwrap_or("https"), &["http", "https"])?);
            p.field(&mut v, "path", "URL path", "/")?;
        } else {
            p.field(&mut v, "url", "Dashboard URL (blank leaves the tile unconfigured)", "")?;
            if let Some(url) = v["url"].as_str().filter(|u| !u.is_empty()) {
                if p.yes("Detect the login form", false)? {
                    let result = match crate::discovery::probe(url, false) {
                        Err(crate::discovery::ProbeError::UntrustedCertificate)
                            if p.yes("Read the page once without verifying TLS", false)? =>
                        {
                            crate::discovery::probe(url, true)
                        }
                        other => other,
                    };
                    match result {
                        Ok(Some(form)) => {
                            println!("{} selectors", form.product.unwrap_or("Suggested login form"));
                            v["login_marker"] = json!(form.password);
                            v["selectors"] = json!({ "user": form.user, "pass": form.password, "submit": form.submit });
                        }
                        Ok(None) => println!("No login form found. Enter selectors manually."),
                        Err(e) => println!("{e}. Enter selectors manually."),
                    }
                }
            }
        }
        p.field(&mut v, "vault_item", "Vault login item", "")?;
        for (key, label) in
            [("user", "Username selector"), ("pass", "Password selector"), ("submit", "Submit selector")]
        {
            p.field(&mut v["selectors"], key, label, "")?;
        }
        p.field(&mut v, "login_marker", "Login marker selector", "")?;
        let keepalive = &mut v["keepalive"];
        let strategy = p.choice(
            "Keep-alive strategy",
            keepalive["strategy"].as_str().unwrap_or("none"),
            &["none", "reload", "xhr", "click"],
        )?;
        keepalive["strategy"] = json!(strategy);
        if strategy != "none" {
            p.number(keepalive, "intervalSec", "Keep-alive interval in seconds", 600, 1, 86400)?;
        }
        match strategy.as_str() {
            "xhr" => p.field(keepalive, "url", "Heartbeat URL", "")?,
            "click" => p.field(keepalive, "target", "Selector to click", "")?,
            _ => {}
        }
        edited.push(v);
    }
    doc["panels"] = json!(edited);
    Ok(())
}

fn tunnel(p: &Prompt, t: &mut Value) -> TextResult<()> {
    if p.toggle(t, "enabled", "Enable the SSH tunnel", false)? {
        p.field(t, "jump_host", "Jump host (user@host)", "")?;
        p.field(t, "identity", "SSH private key path", "/etc/soc-display/keys/tunnel_ed25519")?;
    }
    Ok(())
}

fn vpns(p: &Prompt, doc: &mut Value) -> TextResult<()> {
    let previous = doc["vpns"]
        .as_array()
        .cloned()
        .or_else(|| doc["vpn"].as_object().map(|v| vec![Value::Object(v.clone())]))
        .unwrap_or_else(Vec::new);
    let n = p.integer("Number of VPNs", previous.len() as i64, 0, soc_core::MAX_VPNS as i64)?;
    let mut edited = Vec::new();
    let mut has_default_route = false;
    for i in 0..n {
        println!("VPN {}", i + 1);
        let mut v = previous.get(i as usize).cloned().unwrap_or_else(|| json!({}));
        p.field(&mut v, "name", "VPN name", &format!("vpn{}", i + 1))?;
        let kind = p.choice(
            "VPN client",
            v["type"].as_str().unwrap_or("fortinet"),
            &["fortinet", "openvpn", "wireguard", "inode"],
        )?;
        v["type"] = json!(kind);
        if p.toggle(&mut v, "enabled", "Enable this VPN", true)? {
            if has_default_route {
                v["default_route"] = json!(false);
            } else {
                has_default_route = p.toggle(&mut v, "default_route", "Make this VPN the default route", false)?;
            }
            match kind.as_str() {
                "fortinet" | "inode" => {
                    p.field(&mut v, "gateway", "Gateway host", "")?;
                    p.number(&mut v, "port", "Gateway port", 443, 1, 65535)?;
                    p.field(&mut v, "trusted_cert", "Gateway SHA-256 fingerprint", "")?;
                    if kind == "inode" {
                        inode_options(p, &mut v)?;
                    } else {
                        p.field(&mut v, "realm", "FortiGate realm", "")?;
                        p.toggle(&mut v, "set_routes", "Accept routes from the FortiGate", true)?;
                        p.toggle(&mut v, "half_internet_routes", "Use split default routes", false)?;
                        p.toggle(&mut v, "set_dns", "Use DNS from the FortiGate", false)?;
                        p.toggle(&mut v, "otp_from_vault", "Use the vault item's TOTP code", false)?;
                        p.number(&mut v, "persistent", "Client reconnect interval in seconds", 0, 0, 86400)?;
                    }
                }
                _ => {
                    if !p.toggle(&mut v, "config_from_vault", "Read VPN configuration from a vault note", false)? {
                        p.field(&mut v, "config", "VPN configuration file", "")?;
                    }
                    if kind == "openvpn" {
                        p.toggle(&mut v, "set_routes", "Accept routes from the VPN server", true)?;
                    }
                }
            }
            p.field(&mut v, "vault_item", "Vault login item", "")?;
            p.field(&mut v, "ready_probe", "Readiness probe (host:port)", "")?;
            if kind == "wireguard" || v["ready_probe"].as_str().is_some_and(|s| !s.is_empty()) {
                p.number(
                    &mut v,
                    "health_check_interval",
                    "Health check interval in seconds (0 to disable)",
                    60,
                    0,
                    86400,
                )?;
                if v["health_check_interval"] != 0 {
                    p.number(&mut v, "health_check_failures", "Failures before reconnecting", 3, 1, 100)?;
                }
            }
        }
        edited.push(v);
    }
    if let Some(root) = doc.as_object_mut() {
        root.remove("vpn");
    }
    doc["vpns"] = json!(edited);
    Ok(())
}

fn inode_options(p: &Prompt, v: &mut Value) -> TextResult<()> {
    p.field(v, "domain", "iNode login domain", "")?;
    if v["trusted_cert"].as_str().is_none_or(str::is_empty) {
        p.toggle(v, "insecure", "Allow an untrusted gateway certificate", false)?;
    }
    p.toggle(v, "ead", "Send the EAD host-check acknowledgement", false)?;
    p.toggle(v, "split_tunnel", "Route only gateway subnets through the tunnel", true)?;
    p.number(v, "captcha_retries", "CAPTCHA retries", 40, 0, 1000)?;
    for (key, label) in [
        ("config", "Legacy iNode client directory"),
        ("ca_file", "Custom CA bundle path"),
        ("client_cert", "Mutual TLS client certificate path"),
        ("client_key", "Mutual TLS client key path"),
        ("mac", "Override MAC address"),
    ] {
        p.field(v, key, label, "")?;
    }
    v["language"] =
        json!(p.choice("Authentication language", v["language"].as_str().unwrap_or("cn"), &["cn", "en"])?);
    if p.yes("Set or replace the SPA key", false)? {
        v["spa_key"] = json!(ask_secret("SPA HOTP key in hex")?.as_str());
    }
    if v["spa_key"].as_str().is_some_and(|key| !key.is_empty()) {
        p.field(v, "spa_aid", "SPA client AID in hex", "")?;
        p.field(v, "spa_ports", "SPA gateway ports (comma separated)", "")?;
        p.number(v, "spa_knock_port", "SPA UDP port", 8000, 1, 65535)?;
    }
    Ok(())
}

fn proxy(p: &Prompt, v: &mut Value) -> TextResult<()> {
    if p.toggle(v, "enabled", "Use an outbound proxy", false)? {
        p.field(v, "url", "Proxy URL", "")?;
        p.field(v, "vault_item", "Proxy credentials vault item", "")?;
        let hosts = v["ignore_hosts"]
            .as_array()
            .map_or_else(String::new, |a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","));
        v["ignore_hosts"] = json!(
            p.text("Comma-separated proxy bypass hosts", &hosts)?
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

pub(crate) fn collect_logins(plan: &mut DeployPlan) -> TextResult<()> {
    collect_login_items(&plan.cfg, &mut plan.creds)
}

fn collect_login_items(cfg: &soc_core::Config, creds: &mut crate::vault::Creds) -> TextResult<()> {
    let prompt = Prompt { defaults: false };
    for item in crate::config::vault_items(cfg) {
        if prompt.yes(&format!("Set credentials for {}", item.name), false)? {
            let user = prompt.text("Username", "")?;
            let pass = ask_secret("Password")?;
            creds.insert(item.name, LoginCred::new(&user, &pass));
        }
    }
    Ok(())
}

fn write_plan(plan: &DeployPlan, sys: &SystemHost, firstboot: bool, prompt: &Prompt) -> TextResult<i32> {
    let host = sys.host();
    let mut state = DeployState { soc_env: plan.soc_env.clone(), ..DeployState::default() };
    let result = plan.run_step(DeployStep::WriteConfig, &host, &mut state);
    show_step(DeployStep::WriteConfig.as_str(), &result);
    if !result.ok {
        return Ok(1);
    }
    if firstboot && !plan.dry_run && !prompt.defaults && io::stdin().is_terminal() {
        let vault = plan.soc_env.get("SOC_VAULT_BACKEND").is_some_and(|b| crate::doctor::is_real_vault(b));
        if vault && !plan.cfg.panels.is_empty() {
            if prompt.yes("Save this wall configuration to Vaultwarden", true)? {
                let result = plan.run_step(DeployStep::PushConfig, &host, &mut state);
                show_step(DeployStep::PushConfig.as_str(), &result);
            }
            if prompt.yes("Enter panel credentials", false)? {
                let mut edits = crate::vault::Creds::new();
                collect_login_items(&plan.cfg, &mut edits)?;
                let password = plan.master.as_deref().map(String::as_str);
                let result = crate::vault::store_credentials(&host, &plan.soc_env, &plan.cfg, password, &edits, false);
                show_step("creds", &result);
            }
        }
    }
    let result = plan.run_step(DeployStep::MarkConfigured, &host, &mut state);
    show_step(DeployStep::MarkConfigured.as_str(), &result);
    Ok(i32::from(!result.ok))
}

pub(crate) fn run(command: &str, args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(
        args,
        &["--target", "--section", "--config", "--mode", "--master-fd", "--pin"],
        &["--dry-run", "--defaults", "--yes", "--fresh", "--master-stdin"],
    )?;
    let (env, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = if command == "firstboot" { Target::Pi } else { target_of(&f, &env, &sys)? };
    let paths = SetupPaths::resolve(target, &env, false);
    if command == "firstboot" {
        if is_configured(&paths) {
            return Ok(0);
        }
        if !sys.probe.is_root() && !f.has("--dry-run") {
            return Err("firstboot needs root".into());
        }
    }
    if command == "install" {
        let install_args = args
            .iter()
            .filter(|s| matches!(s.as_str(), "--dry-run" | "--fresh"))
            .cloned()
            .chain(f.one("--mode").map(|mode| format!("--mode={mode}")))
            .collect::<Vec<_>>();
        let code = system_install(true, &install_args)?;
        if code != 0 {
            return Ok(code);
        }
    }
    let mut plan = DeployPlan::new(target, env, paths);
    plan.dry_run = f.has("--dry-run");
    let prompt = Prompt { defaults: f.has("--defaults") || (plan.dry_run && !io::stdin().is_terminal()) };
    let section = f.one("--section").unwrap_or("all");
    if !matches!(section, "all" | "display" | "panels" | "tunnel" | "vpn" | "proxy" | "vault" | "server") {
        return Err(format!("unknown setup section: {section}"));
    }
    if let Some(file) = f.one("--config") {
        let text = soc_sys::fsutil::read_capped(std::path::Path::new(file), 4 << 20).map_err(|e| e.to_string())?;
        plan.cfg = soc_core::load::load_str(&text, file).map_err(|e| e.to_string())?;
        plan.config_source = Some(text);
    }
    configure(&mut plan, &prompt, section)?;
    if plan.dry_run {
        println!("{}", plan.config_source.clone().unwrap_or_else(|| crate::config::render_panels_yaml(&plan.cfg)));
        println!("{}", crate::render_soc_env(&plan.soc_env));
    } else if !f.has("--yes") && !prompt.yes("Write this configuration", true)? {
        return Ok(1);
    }
    let firstboot = command == "firstboot" || command == "install" && target == Target::Pi;
    if firstboot && !plan.dry_run {
        plan.master = read_master(&f)?;
        let backend = plan.soc_env.get("SOC_VAULT_BACKEND").map_or(plan.paths.default_backend.as_str(), String::as_str);
        let vault_is_real = crate::doctor::is_real_vault(backend);
        let secret = plan
            .soc_env
            .get("SOC_SECRET_DIR")
            .filter(|v| !v.is_empty())
            .map_or(plan.paths.secret_dir.as_path(), std::path::Path::new);
        if plan.master.is_none()
            && vault_is_real
            && !sys.host().seal.is_sealed(secret)
            && io::stdin().is_terminal()
            && prompt.yes("Seal the vault master now", true)?
        {
            plan.master = Some(ask_secret("Vault master password")?);
        }
        if let Some(master) = &plan.master {
            let seal = crate::FirstRunPlan {
                paths: plan.paths.clone(),
                soc_env: plan.soc_env.clone(),
                backend: backend.into(),
                source: soc_seal::MasterSource::Auto,
                master: Some(master.clone()),
                pin: f.one("--pin").map(str::to_string),
                reseal: false,
                dry_run: false,
            };
            let out = seal.run(&sys.host(), &mut |step, result| show_step(step.as_str(), result));
            if !out.ok {
                return Ok(1);
            }
            plan.soc_env.remove("SOC_VAULT_PASSWORD");
        }
    }
    write_plan(&plan, &sys, firstboot, &prompt)
}

pub(crate) fn configure_deploy(plan: &mut DeployPlan) -> TextResult<()> {
    let prompt = Prompt { defaults: false };
    if plan.config_source.is_none() && prompt.yes("Configure the wall now", true)? {
        configure(plan, &prompt, "all")?;
        plan.write_config = true;
    }
    if let Some(email) = plan.soc_env.get("SOC_VAULT_EMAIL") {
        plan.email.clone_from(email);
    }
    if let Some(url) = plan.soc_env.get("SOC_VAULT_URL").filter(|url| !url.is_empty()) {
        plan.url.clone_from(url);
    }
    let real = plan.soc_env.get("SOC_VAULT_BACKEND").is_some_and(|b| crate::doctor::is_real_vault(b));
    let enroll = real
        && (plan.master.is_some() || prompt.yes("Create or verify the vault account and seal its master", true)?);
    if enroll {
        if plan.email.is_empty() {
            plan.email = prompt.text("Vaultwarden account email", "")?;
            if plan.email.is_empty() {
                return Err("a vault account email is required".into());
            }
            plan.soc_env.insert("SOC_VAULT_EMAIL".into(), plan.email.clone());
            plan.write_config = true;
        }
        if plan.master.is_none() {
            let master = ask_secret("Vault master password")?;
            if master.is_empty() {
                return Err("vault master password is empty".into());
            }
            plan.master = Some(master);
        }
    }
    if real && plan.master.is_some() && plan.creds.is_empty() && prompt.yes("Enter panel credentials", false)? {
        collect_logins(plan)?;
    }
    Ok(())
}

fn configure(plan: &mut DeployPlan, prompt: &Prompt, section: &str) -> TextResult<()> {
    let wants = |name| section == "all" || section == name;
    if plan.config_source.is_none() && !prompt.defaults {
        let mut doc = soc_core::emit::to_value(&plan.cfg);
        if wants("display") {
            display(prompt, &mut doc["display"])?;
        }
        if wants("panels") {
            panels(prompt, &mut doc)?;
        }
        if wants("tunnel") {
            tunnel(prompt, &mut doc["tunnel"])?;
        }
        if wants("vpn") {
            vpns(prompt, &mut doc)?;
        }
        if wants("proxy") {
            proxy(prompt, &mut doc["proxy"])?;
        }
        plan.cfg = soc_core::load::from_value(&doc, "setup wizard", &soc_core::load::Overrides::default())
            .map_err(|e| e.to_string())?;
    }
    let backend = plan.soc_env.entry("SOC_VAULT_BACKEND".into()).or_insert_with(|| plan.paths.default_backend.clone());
    if wants("vault") {
        let backend = prompt.choice("Vault backend", backend, &["litebw", "native", "rbw", "dev"])?;
        plan.soc_env.insert("SOC_VAULT_BACKEND".into(), backend);
        for (key, label, fallback) in [
            ("SOC_VAULT_URL", "Vaultwarden URL", "http://127.0.0.1:8222"),
            ("SOC_VAULT_EMAIL", "Vaultwarden account email", ""),
            ("SOC_CONFIG_VAULT_ITEM", "Vault configuration item", "SOC Wall Config"),
        ] {
            let value = prompt.text(label, plan.soc_env.get(key).map_or(fallback, String::as_str))?;
            plan.soc_env.insert(key.into(), value);
        }
    }
    for (key, path) in [
        ("SOC_ROOT", &plan.paths.soc_root),
        ("SOC_PANELS_FILE", &plan.paths.panels_out),
        ("SOC_SECRET_DIR", &plan.paths.secret_dir),
        ("SOC_INJECT_TMPL", &plan.paths.inject_tmpl),
    ] {
        plan.soc_env.entry(key.into()).or_insert_with(|| path.display().to_string());
    }
    if wants("server") {
        let mode = plan.soc_env.get("SOC_SESSION").map_or("auto", String::as_str);
        let mode = prompt.choice("Kiosk session", mode, &["auto", "wayland", "xwayland", "xlibre", "xorg", "x11"])?;
        plan.soc_env.insert("SOC_SESSION".into(), mode);
    }
    Ok(())
}

pub(crate) fn menu(args: &[String]) -> TextResult<i32> {
    if !io::stdin().is_terminal() || !args.is_empty() {
        return run("wizard", args);
    }
    let prompt = Prompt { defaults: false };
    println!(
        "SOC Wall setup\n  1. Configure the wall\n  2. Install and configure\n  3. Check the installation\n  4. Repair the installation\n  5. Seal the vault master\n  0. Exit"
    );
    let commands = ["", "wizard", "install", "doctor", "repair", "first-run"];
    let choice = prompt.integer("Choose an action", 1, 0, 5)? as usize;
    if choice == 0 {
        return Ok(0);
    }
    Ok(crate::setup_cli_main(&[commands[choice].to_string()]))
}
