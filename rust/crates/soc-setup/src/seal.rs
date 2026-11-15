//! Seal / store the vault master. The shared non-interactive core behind both
//! the CLI and the GUI wizard: given an already-collected master and a source
//! (`auto|sealed|secret-service|env`), do the mechanical work through
//! `soc-seal` and record the choice in `soc.env`.
//!
//! The master is never written to a file — only the SOURCE name is recorded.

use crate::envfile::{Changes, SocEnv, rewrite_env};
use crate::error::SealMasterError;
use crate::host::Host;
use crate::paths::SetupPaths;
use crate::util::CMD_TIMEOUT;
use soc_seal::MasterSource;
use zeroize::Zeroizing;

/// The default sealed-secret directory the pinentry looks in.
pub const DEFAULT_SECRET_DIR: &str = "/etc/soc-display/secret";

/// What to seal and where.
pub struct SealRequest<'a> {
    pub master: &'a str,
    pub source: MasterSource,
    /// The PIN to seal under; `None` generates a random one.
    pub pin: Option<&'a str>,
    pub paths: &'a SetupPaths,
    /// The current `soc.env` (what was loaded before this call).
    pub soc_env: &'a SocEnv,
    pub backend: &'a str,
    pub dry: bool,
}

/// What a seal did.
#[derive(Debug, Clone, Default)]
pub struct SealOutcome {
    /// The one-time PIN actually used (the given one, or a fresh one) for the
    /// sealed path — also in a dry run, so it can be previewed. `None` for the
    /// secret-service and env sources.
    pub pin: Option<Zeroizing<String>>,
    /// The mutations performed (or, in a dry run, skipped), human-readable.
    pub actions: Vec<String>,
}

/// The effective source: `auto` is materialised by sealing host-bound (the
/// unattended default), while `auto` itself is what gets RECORDED so the
/// secret-service -> env runtime fallbacks survive if the seal is removed.
pub fn effective_source(source: MasterSource) -> MasterSource {
    if source == MasterSource::Auto { MasterSource::Sealed } else { source }
}

fn err(msg: impl Into<String>) -> SealMasterError {
    SealMasterError(msg.into())
}

fn set_source(req_paths: &SetupPaths, changes: Changes) -> Result<(), SealMasterError> {
    rewrite_env(&req_paths.soc_env, &changes, req_paths.env_mode, false)
        .map(|_| ())
        .map_err(|e| err(format!("could not update soc.env: {e}")))
}

/// Constant-time-ish equality for secrets (no early exit on the first byte).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn run_client(host: &Host<'_>, argv: Vec<String>, actions: &mut Vec<String>) {
    // A failing `config set` is reported but never fatal: the client may not
    // be installed yet, and first-run is re-runnable.
    let shown = argv.join(" ");
    match host.runner.run(&argv, CMD_TIMEOUT) {
        Ok(o) if o.success() => actions.push(format!("ran: {shown}")),
        Ok(o) => {
            actions.push(format!("failed (rc={}): {shown}", o.code.map_or("signal".to_string(), |c| c.to_string())))
        }
        Err(e) => actions.push(format!("failed ({e}): {shown}")),
    }
}

fn client_config(host: &Host<'_>, backend: &str, key: &str, value: &str, actions: &mut Vec<String>) {
    run_client(host, vec![backend.into(), "config".into(), "set".into(), key.into(), value.into()], actions);
}

/// Seal / store the master per `req`. Never prompts; `Err` carries the
/// operator-facing text. In a dry run nothing is changed but the PIN that
/// would be used is still returned.
pub fn seal_master(req: &SealRequest<'_>, host: &Host<'_>) -> Result<SealOutcome, SealMasterError> {
    let eff = effective_source(req.source);
    let mut out = SealOutcome::default();
    let real_backend = crate::doctor::is_real_vault(req.backend);

    match eff {
        MasterSource::Env => {
            // DEV/seeding only — nothing to seal/store; record the source choice.
            if !req.dry {
                set_source(req.paths, Changes::new().set("SOC_MASTER_SOURCE", "env"))?;
                out.actions.push("recorded SOC_MASTER_SOURCE=env".into());
            }
            Ok(out)
        }
        MasterSource::SecretService => {
            if !host.seal.have_secret_tool() {
                return Err(err("secret-tool (libsecret) is not on PATH — install it (apt: libsecret-tools; \
                     dnf/pacman/apk/xbps: libsecret), or pick the 'sealed' source. Nothing stored."));
            }
            if req.master.is_empty() {
                return Err(err("no master password entered — nothing stored"));
            }
            if !req.dry {
                host.seal
                    .secret_service_store(req.master)
                    .map_err(|e| err(format!("could not store the master in the wallet: {e}")))?;
                let back = host.seal.secret_service_get();
                if !back.is_some_and(|b| same(&b, req.master)) {
                    return Err(err(
                        "could not store the master in the wallet: stored value did not read back — wallet locked?",
                    ));
                }
                out.actions.push("stored the master in the Secret Service wallet".into());
                let mut changes = Changes::new().set("SOC_MASTER_SOURCE", "secret-service");
                if req.soc_env.get("SOC_VAULT_PASSWORD").is_some_and(|v| !v.is_empty()) {
                    changes = changes.remove("SOC_VAULT_PASSWORD");
                }
                set_source(req.paths, changes)?;
                if real_backend && host.probe.have(req.backend) {
                    run_client(
                        host,
                        vec![
                            req.backend.into(),
                            "config".into(),
                            "set".into(),
                            "pinentry".into(),
                            req.paths.pinentry.display().to_string(),
                        ],
                        &mut out.actions,
                    );
                }
            }
            Ok(out)
        }
        // sealed (and, by `effective_source`, never `auto`).
        _ => {
            if req.master.is_empty() {
                return Err(err("no master password entered — nothing sealed"));
            }
            // Honor a custom SOC_SECRET_DIR: doctor, the credential store and the
            // boot-time pinentry all read it, so seal to the SAME place.
            let sd = req
                .soc_env
                .get("SOC_SECRET_DIR")
                .filter(|v| !v.is_empty())
                .map_or_else(|| req.paths.secret_dir.clone(), std::path::PathBuf::from);
            let pin: Zeroizing<String> = match req.pin.filter(|p| !p.is_empty()) {
                Some(p) => Zeroizing::new(p.to_string()),
                None => host.seal.gen_pin().map_err(|e| err(format!("could not generate a PIN: {e}")))?,
            };
            if !req.dry {
                host.seal.seal(&sd, req.master, &pin).map_err(|e| err(format!("could not seal: {e}")))?;
                // Verify it unseals on THIS host before trusting it (and before any
                // plaintext gets scrubbed) — never lock the wall out.
                let back = host.seal.unseal(&sd).map_err(|e| err(format!("could not seal: {e}")))?;
                if !same(&back, req.master) {
                    return Err(err("could not seal: seal did not unseal to the same value"));
                }
                out.actions.push(format!("sealed + verified the master host-bound -> {}", sd.display()));
                seal_housekeeping(
                    host,
                    &sd,
                    &req.source.to_string(),
                    req.paths,
                    req.soc_env,
                    req.backend,
                    &mut out.actions,
                )?;
            }
            out.pin = Some(pin);
            Ok(out)
        }
    }
}

/// Post-seal wiring shared by a fresh seal and by "keep the existing seal":
/// point the rbw/litebw client at the unsealing pinentry (+ email/base_url),
/// scrub any leftover plaintext `SOC_VAULT_PASSWORD` once the seal is confirmed
/// to unseal, and record the chosen source. The master itself is never written.
pub fn seal_housekeeping(
    host: &Host<'_>,
    sd: &std::path::Path,
    record_src: &str,
    paths: &SetupPaths,
    soc_env: &SocEnv,
    backend: &str,
    actions: &mut Vec<String>,
) -> Result<(), SealMasterError> {
    let nonempty = |k: &str| soc_env.get(k).filter(|v| !v.is_empty()).cloned();
    if crate::doctor::is_real_vault(backend) && host.probe.have(backend) {
        if let Some(email) = nonempty("SOC_VAULT_EMAIL") {
            client_config(host, backend, "email", &email, actions);
        }
        if let Some(url) = nonempty("SOC_VAULT_URL") {
            client_config(host, backend, "base_url", &url, actions);
        }
        client_config(host, backend, "pinentry", &paths.pinentry.display().to_string(), actions);
    }
    // Clean any leftover plaintext master out of soc.env now that it is sealed —
    // only after CONFIRMING it unseals, so a failed seal never strands the operator.
    if nonempty("SOC_VAULT_PASSWORD").is_some() && host.seal.is_sealed(sd) && host.seal.unseal(sd).is_ok() {
        let mut changes = Changes::new().remove("SOC_VAULT_PASSWORD");
        let cur = nonempty("SOC_SECRET_DIR").unwrap_or_else(|| DEFAULT_SECRET_DIR.to_string());
        if std::path::Path::new(&cur) != sd {
            changes = changes.set("SOC_SECRET_DIR", &sd.display().to_string());
        }
        if soc_env.get("SOC_PINENTRY").is_some_and(|p| p.ends_with("pinentry-soc.sh")) {
            changes = changes.set("SOC_PINENTRY", &paths.pinentry.display().to_string());
        }
        set_source(paths, changes)?;
        actions.push("removed plaintext SOC_VAULT_PASSWORD from soc.env (master is now host-sealed)".into());
    }
    // Record the chosen source ('auto' preserved verbatim; 'sealed' as 'sealed').
    if host.seal.is_sealed(sd) && soc_env.get("SOC_MASTER_SOURCE").map(String::as_str) != Some(record_src) {
        set_source(paths, Changes::new().set("SOC_MASTER_SOURCE", record_src))?;
        actions.push(format!("recorded SOC_MASTER_SOURCE={record_src}"));
    }
    Ok(())
}

/// The PIN as shown to the operator: digits separated by two spaces.
pub fn pin_display(pin: &str) -> String {
    pin.chars().map(String::from).collect::<Vec<_>>().join("  ")
}

/// The one-time-PIN panel a CLI prints (and a GUI renders): shown once, and
/// the operator must record it. It is needed ONLY to re-seal later.
pub fn pin_banner(pin: &str) -> Vec<String> {
    vec![
        "YOUR ONE-TIME PIN".to_string(),
        String::new(),
        format!("        {}", pin_display(pin)),
        String::new(),
        "   Write this PIN down and keep it safe. It is needed ONLY to re-seal".to_string(),
        "   later (re-deploy, new hardware, or changing the master password) —".to_string(),
        "   NOT for normal boots (the wall self-unlocks from the host-bound seal).".to_string(),
    ]
}

/// True if this exact master is already sealed here. Re-sealing would issue a
/// new PIN, silently invalidating the one the operator recorded.
pub fn already_sealed(host: &Host<'_>, master: &str, sd: &std::path::Path) -> bool {
    host.seal.is_sealed(sd) && host.seal.unseal(sd).is_ok_and(|m| same(&m, master))
}
