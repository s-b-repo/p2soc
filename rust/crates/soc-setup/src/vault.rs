//! Writing the config and the panel logins into the vault, on top of the
//! `soc-vault` session (through the [`VaultConnect`] seam).

use crate::config::{VaultItem, render_panels_yaml, vault_items};
use crate::doctor::is_real_vault;
use crate::envfile::SocEnv;
use crate::host::Host;
use crate::seal::DEFAULT_SECRET_DIR;
use crate::step::StepResult;
use soc_core::Config;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zeroize::Zeroizing;

/// A login to write. Passwords are wiped on drop.
#[derive(Debug, Clone)]
pub struct LoginCred {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl LoginCred {
    pub fn new(username: &str, password: &str) -> LoginCred {
        LoginCred { username: username.to_string(), password: Zeroizing::new(password.to_string()) }
    }
}

/// Item name -> login (what `--creds-fd` carries, as JSON in the Python tool).
pub type Creds = BTreeMap<String, LoginCred>;

/// The master from the host-bound seal. Non-interactive: with no usable seal
/// this is `None` and the caller skips the step — a placeholder is never
/// invented (it would be registered as the real master).
pub fn resolve_master(host: &Host<'_>, soc_env: &SocEnv) -> Option<Zeroizing<String>> {
    let sd = soc_env.get("SOC_SECRET_DIR").filter(|v| !v.is_empty()).map_or(DEFAULT_SECRET_DIR, String::as_str);
    let sd = Path::new(sd);
    if host.seal.is_sealed(sd) { host.seal.unseal(sd).ok() } else { None } // audit-allow: an unusable seal means "no master", reported by the caller
}

fn opt(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Inputs of [`write_logins`].
#[derive(Clone, Copy)]
pub struct LoginJob<'a> {
    pub url: &'a str,
    pub email: &'a str,
    pub master: &'a str,
    pub items: &'a [VaultItem],
    pub creds: &'a Creds,
    /// Write an empty placeholder for an item that does not exist yet.
    pub placeholders: bool,
    pub dry: bool,
}

/// Make sure every login in `items` exists in the vault (the `step_vault_seed`
/// core). One session for the whole run (each login costs a key derivation).
///
/// `creds` are written as given, even over an existing item. An item with no
/// entry only gets an EMPTY placeholder when `placeholders` is set AND it does
/// not exist yet, so a re-run can never blank a login someone has filled in.
pub fn write_logins(host: &Host<'_>, job: &LoginJob<'_>) -> StepResult {
    let LoginJob { url, email, master, items, creds, placeholders, dry } = *job;
    if items.is_empty() {
        return StepResult::ok("no panel logins to seed");
    }
    let names = items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ");
    if dry {
        return StepResult::ok(format!("would seed: {names}"))
            .with_line(format!("[dry-run] seed login items at {url}: {names} (NO network)"));
    }
    let n = items.len();
    let session = match host.vault.connect(url, email, master) {
        Ok(s) => s,
        Err(e) => return StepResult::failed(format!("seeded 0/{n} — {e}")),
    };
    let existing: BTreeSet<String> = match session.login_names() {
        Ok(v) => v.into_iter().collect(),
        Err(e) => return StepResult::failed(format!("seeded 0/{n} — {e}")),
    };
    let (mut seeded, mut done) = (0usize, 0usize);
    let mut first_err = String::new();
    let mut res = StepResult::default();
    for it in items {
        let uri = opt(&it.uri);
        let write = |user: &str, pass: &str| session.upsert_login(&it.name, user, pass, uri, None);
        let outcome = match creds.get(&it.name) {
            Some(c) => Some(write(&c.username, &c.password)),
            None if placeholders && !existing.contains(&it.name) => Some(write("", "")),
            None => None,
        };
        match outcome {
            Some(Ok(w)) => {
                seeded += 1;
                done += 1;
                res.lines.push(format!("{} '{}' ({})", w.as_str(), it.name, it.kind));
            }
            Some(Err(e)) => {
                if first_err.is_empty() {
                    first_err = e.clone();
                }
                res.lines.push(format!("could not write '{}': {e}", it.name));
            }
            None => {
                done += 1;
                res.lines.push(format!("skipped '{}' ({})", it.name, it.kind));
            }
        }
    }
    // Total failure (wrong master / wrong URL) is NOT success.
    if done == 0 {
        res.detail = format!("seeded 0/{n} — {}", if first_err.is_empty() { "all upserts failed" } else { &first_err });
        return res;
    }
    res.ok = true;
    res.changed = seeded > 0;
    res.detail = if done < n {
        format!("seeded {done}/{n} (some failed: {first_err})")
    } else {
        format!("{seeded} login(s) written, {} already present", n.saturating_sub(seeded))
    };
    res
}

/// The `setup creds` flow: write each configured item's username + password
/// (from `creds`); an item without an entry is skipped, never blanked.
pub fn store_credentials(
    host: &Host<'_>,
    soc_env: &SocEnv,
    cfg: &Config,
    master: Option<&str>,
    creds: &Creds,
    dry: bool,
) -> StepResult {
    let backend = soc_env.get("SOC_VAULT_BACKEND").map_or("", String::as_str);
    if !is_real_vault(backend) {
        return StepResult::ok("vault backend is 'dev' — credentials live in the dev JSON; skipping.");
    }
    let items = vault_items(cfg);
    if items.is_empty() {
        return StepResult::ok("no vault items configured.");
    }
    let url = soc_env.get("SOC_VAULT_URL").map_or("", String::as_str);
    let email = soc_env.get("SOC_VAULT_EMAIL").map_or("", String::as_str);
    let sealed = if master.is_none() { resolve_master(host, soc_env) } else { None };
    let pw: &str = master.or(sealed.as_deref().map(String::as_str)).unwrap_or("");
    if url.is_empty() || email.is_empty() || pw.is_empty() {
        return StepResult::ok("need the Vaultwarden URL, email and master password — skipping");
    }
    write_logins(host, &LoginJob { url, email, master: pw, items: &items, creds, placeholders: false, dry })
}

/// Store the wall config in the vault as the `SOC_CONFIG_VAULT_ITEM` item (a
/// login whose Notes hold the YAML) — the wall's source of truth at boot.
/// `raw` is the file as written; prefer it, since a re-render needs every
/// optional section and would drop anything the emitter does not know.
pub fn push_config_to_vault(
    host: &Host<'_>,
    soc_env: &SocEnv,
    default_item: &str,
    cfg: &Config,
    raw: Option<&str>,
    master: Option<&str>,
    dry: bool,
) -> StepResult {
    let backend = soc_env.get("SOC_VAULT_BACKEND").map_or("", String::as_str);
    if !is_real_vault(backend) {
        return StepResult::ok("dev backend — config stays in the local file; not pushing to the vault.");
    }
    if cfg.panels.is_empty() {
        return StepResult::ok("no panels configured — nothing to push.");
    }
    let item = soc_env.get("SOC_CONFIG_VAULT_ITEM").filter(|v| !v.is_empty()).map_or(default_item, String::as_str);
    let url = soc_env.get("SOC_VAULT_URL").map_or("", String::as_str);
    let email = soc_env.get("SOC_VAULT_EMAIL").map_or("", String::as_str);
    let sealed = if master.is_none() { resolve_master(host, soc_env) } else { None };
    let pw: &str = master.or(sealed.as_deref().map(String::as_str)).unwrap_or("");
    if url.is_empty() || email.is_empty() || pw.is_empty() {
        return StepResult::ok("need URL + email + master password — skipping the config push");
    }
    let yaml = raw.map_or_else(|| render_panels_yaml(cfg), str::to_string);
    if dry {
        return StepResult::ok(format!("would push {} bytes -> '{item}'", yaml.len()));
    }
    let session = match host.vault.connect(url, email, pw) {
        Ok(s) => s,
        Err(e) => return StepResult::failed(format!("could not push the config: {e}")),
    };
    match session.upsert_login(item, "", "", None, Some(&yaml)) {
        Ok(w) => StepResult::changed(format!("{} config note '{item}' ({} bytes)", w.as_str(), yaml.len())),
        Err(e) => StepResult::failed(format!("could not push the config: {e}")),
    }
}

/// Ensure the vault account exists (create if missing, verify if present).
pub fn ensure_account(host: &Host<'_>, url: &str, email: &str, master: &str, dry: bool) -> StepResult {
    if email.is_empty() {
        return StepResult::failed("no vault email set — skipping");
    }
    if dry {
        return StepResult::ok(format!("would ensure account {email}"));
    }
    match host.vault.ensure_account(url, email, master) {
        Ok(crate::host::Account::Created) => StepResult::changed(format!("account {email}: created")),
        Ok(crate::host::Account::Exists) => StepResult::ok(format!("account {email}: exists")),
        Err(e) => StepResult::failed(e),
    }
}
