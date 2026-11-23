//! Subcommand dispatch: one binary is the whole wall product.
//!
//! The wall session, the VPN supervisor, the vault client, both pinentry
//! helpers and every system tool ship as `soc-wall <subcommand>`, so a
//! deployment ships one executable alongside GTK/WebKit and the system
//! services. Systemd and the session scripts invoke its subcommands.

use crate::vaultsetup;
use soc_core::LOG_TAG;
use soc_core::env::env_str;
use soc_sys::wmrules::Wm;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn eprintln_tag(msg: &str) {
    eprintln!("{LOG_TAG} {msg}");
}

/// Load the config a headless tool operates on: `$SOC_PANELS_FILE`, else the
/// resolved per-host location, else the repo default.
type ToolResult<T> = Result<T, String>; // audit-allow: String is internal CLI glue printed verbatim

fn tool_config() -> ToolResult<soc_core::Config> {
    let paths = soc_sys::paths::PathEnv::from_process();
    let file = env_str("SOC_PANELS_FILE")
        .map(PathBuf::from)
        .or_else(|| paths.resolve_panels())
        .unwrap_or_else(|| PathBuf::from("config/panels.yaml"));
    soc_core::load(&file).map_err(|e| e.to_string())
}

/// Read the whole of stdin (used by the sealing helpers via soc-seal's own
/// readers, so this is only for the directory argument parsing here).
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

/// Dispatch `argv` (without the program name). Returns the process exit code.
pub fn dispatch(argv0: &str, args: &[String]) -> i32 {
    // The VPN pinentry is also reached under its own argv[0], because
    // openfortivpn execs `--pinentry=<prog>` with no arguments.
    if soc_vpn::is_pinentry_argv0(argv0) {
        return soc_vpn::pinentry_main();
    }
    let (command, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => ("run", &[][..]),
    };
    match command {
        "run" | "wall" => run_wall(),
        "with-env" => crate::supervise::with_env(rest),
        "supervise" => crate::supervise::run_supervised(),
        "check" => check(rest),
        "vpn" => vpn(rest),
        "vpn-args" => soc_vpn::args_main(rest),
        "vpn-pinentry" => soc_vpn::pinentry_main(),
        // The native H3C iNode SSL-VPN client (replaces the vendored
        // svpn-connect.sh). The VPN supervisor spawns this as the iNode client.
        "inode-connect" => soc_inode::cli::connect_main(rest),
        "pinentry" => soc_seal::pinentry::run(),
        "seal" => soc_seal::cli::seal_from_stdin(flag_value(rest, "--dir").map(PathBuf::from)),
        "keyring-store" => soc_seal::cli::keyring_store_from_stdin(),
        "keyring-clear" => soc_seal::cli::keyring_clear(),
        "vault" => vault(rest),
        "vault-backup" => soc_vault::backup_cli_main(rest),
        "fetch-vaultwarden" => soc_vault::fetch::main(rest),
        "config-wants" => config_wants(rest),
        "setup" if rest.first().is_some_and(|arg| arg == "wizard-gui") => desktop("setup-gui", &rest[1..]),
        "setup" if rest.is_empty() => soc_setup::setup_cli_main(&["menu".into()]),
        "setup" => soc_setup::setup_cli_main(rest),
        "reinstall" => {
            let setup = std::iter::once("reinstall".to_string()).chain(rest.iter().cloned()).collect::<Vec<_>>();
            soc_setup::setup_cli_main(&setup)
        }
        "menu" | "setup-gui" | "setupwiz" | "credentials" | "credcenter" | "appearance" | "guierror" => {
            desktop(command, rest)
        }
        "export-config" => export_config(rest),
        "import-config" => import_config(rest),
        "configpaths" => soc_sys::configpaths_cli(rest),
        "tunnel-args" => with_config(soc_sys::tunnel::tunnel_args_main),
        "autossh" => autossh(),
        "wm-rc" => wm_rc(rest),
        "session-info" => soc_sys::session::session_info_main(tool_config().as_ref()),
        "pin-jump-host" => soc_sys::pinhost::pin_jump_host_main(&soc_sys::pinhost::known_hosts_from_env(), tool_config),
        "manifest" => soc_sys::manifest::manifest_main(rest),
        "branding" => soc_brand::cli(rest),
        "health" => soc_sys::health::health_main(rest),
        "tarpit" => soc_sys::tarpit_main(rest),
        "update" => soc_sys::update::main(rest),
        "--version" | "-V" | "version" => {
            println!("soc-wall {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "--help" | "-h" | "help" => {
            print_usage();
            0
        }
        other => {
            eprintln_tag(&format!("unknown subcommand '{other}' (try `soc-wall help`)"));
            2
        }
    }
}

fn config_wants(args: &[String]) -> i32 {
    let [service, path] = args else {
        eprintln_tag("usage: soc-wall config-wants <tunnel|vpn> <panels.yaml>");
        return 2;
    };
    let conf = match soc_core::load(Path::new(path)) {
        Ok(conf) => conf,
        Err(e) => {
            eprintln_tag(&e.to_string());
            return 2;
        }
    };
    let enabled = match service.as_str() {
        "tunnel" => {
            !matches!(conf.tunnel.get("enabled"), Some(value) if !soc_core::dict::truthy(value))
                && conf.panels.iter().any(|p| p.mode == soc_core::Mode::Tunnel)
        }
        "vpn" => conf.enabled_vpns().any(|v| !soc_vpn::vpn_incomplete(v)),
        _ => return 2,
    };
    i32::from(!enabled)
}

#[cfg(feature = "gui")]
fn desktop(command: &str, args: &[String]) -> i32 {
    let run = match command {
        "setup-gui" | "setupwiz" => soc_gui::setupwiz::run,
        "credentials" | "credcenter" => soc_gui::credcenter::run,
        "appearance" => soc_gui::appearance::run,
        "menu" => return soc_gui::menu::run(args),
        "guierror" => return soc_gui::errdialog::run(args),
        _ => return 2,
    };
    let result = run(args);
    if result == 0 && args.is_empty() && soc_core::env::env_bool("SOC_RETURN_TO_MENU", false) {
        use std::os::unix::process::CommandExt;
        match std::env::current_exe() {
            Ok(exe) => eprintln_tag(&format!(
                "could not return to the menu: {}",
                std::process::Command::new(exe).arg("menu").env_remove("SOC_RETURN_TO_MENU").exec()
            )),
            Err(e) => eprintln_tag(&format!("could not locate the launcher: {e}")),
        }
    }
    result
}

#[cfg(not(feature = "gui"))]
fn desktop(command: &str, args: &[String]) -> i32 {
    eprintln_tag(&format!("{command} requires the GUI feature ({} arguments)", args.len()));
    2
}

fn with_config(f: impl FnOnce(&soc_core::Config) -> i32) -> i32 {
    match tool_config() {
        Ok(conf) => f(&conf),
        Err(e) => {
            eprintln_tag(&e.to_string());
            2
        }
    }
}

#[cfg(feature = "gui")]
fn run_wall() -> i32 {
    crate::gui::run::run()
}

#[cfg(not(feature = "gui"))]
fn run_wall() -> i32 {
    eprintln_tag("this build has no GUI (built without the `gui` feature); the wall cannot run here");
    2
}

fn check(args: &[String]) -> i32 {
    let Some(path) = args.iter().find(|a| !a.starts_with('-')) else {
        eprintln_tag("usage: soc-wall check <panels.yaml>");
        return 2;
    };
    crate::cli::check(Path::new(path), &mut std::io::stdout(), &mut std::io::stderr())
}

/// The VPN supervisor, with the vault wired to the sealed master and a
/// refresh closure the supervisor calls after a rejected login.
fn vpn(args: &[String]) -> i32 {
    let log = |m: &str| eprintln_tag(m);
    let env = vaultsetup::env_settings();
    // Only build the vault if some VPN actually needs credentials; a
    // cert-only or WireGuard-only config should supervise without a vault.
    let needs_vault = tool_config().map(|c| c.enabled_vpns().any(vpn_needs_creds)).unwrap_or(true);
    if !needs_vault {
        return soc_vpn::supervisor_main(args, soc_vpn::VaultAccess::new(Arc::new(NoCreds)), None);
    }
    let vault = match vaultsetup::open_vault(&env, 1, &log) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("vault backend error: {e}"));
            return 1;
        }
    };
    let creds: Arc<dyn soc_core::CredSource> = vault.clone();
    let mut access = soc_vpn::VaultAccess::new(creds);
    let refresh_vault = vault.clone();
    access.refresh = Some(Arc::new(move || refresh_vault.resync().map_err(Into::into)));
    soc_vpn::supervisor_main(args, access, None)
}

fn vpn_needs_creds(vpn: &soc_core::Dict) -> bool {
    use soc_core::DictExt;
    // Every backend but a cert-only OpenVPN or a plain WireGuard needs a login.
    match soc_core::vpnargs::vpn_kind(vpn) {
        soc_core::VpnKind::Fortinet | soc_core::VpnKind::Inode => true,
        soc_core::VpnKind::Openvpn | soc_core::VpnKind::Wireguard => {
            vpn.truthy("vault_item") || vpn.truthy("config_from_vault")
        }
    }
}

/// A credential source for a vault-less VPN supervisor: everything is absent.
struct NoCreds;

impl soc_core::CredSource for NoCreds {
    fn creds(&self, item: &str) -> Result<soc_core::Login, soc_core::CredError> {
        Err(soc_core::CredError::NotFound(format!("no vault configured (item {item:?})")))
    }
    #[rustfmt::skip]
    fn notes(&self, _item: &str) -> Result<String, soc_core::CredError> { // audit-allow: trait signature fixes the parameter; unused here
        Ok(String::new())
    }
    fn code(&self, item: &str) -> Result<String, soc_core::CredError> {
        Err(soc_core::CredError::NotFound(format!("no vault configured (item {item:?})")))
    }
}

/// The litebw-compatible vault client, with the sealed master wired in so it
/// can unlock an unattended wall (the bare `cli_main` cannot).
fn vault(args: &[String]) -> i32 {
    let resolver = match vaultsetup::resolver() {
        Ok(r) => r,
        Err(e) => {
            eprintln_tag(&format!("vault backend error: {e}"));
            return 1;
        }
    };
    let master = vaultsetup::SealedMaster(resolver);
    let ctx = soc_vault::CliContext::from_env(&master);
    soc_vault::cli_main_with(args, &ctx, &mut std::io::stdout(), &mut std::io::stderr())
}

/// `autossh`: build the tunnel argv from the config and exec autossh, or idle
/// forever when nothing is to be forwarded (so the unit stays active).
fn autossh() -> i32 {
    let env = soc_sys::health::load_env_file(&crate::supervise::env_file());
    match tool_config() {
        Ok(conf) => soc_sys::tunnel::autossh_service_main(Ok(&conf), &env),
        Err(e) => soc_sys::tunnel::autossh_service_main(Err(e.as_str()), &env),
    }
}

/// `export-config [--out <dir>]`: write the effective config (base +
/// overrides) to a timestamped, 0600, loadable YAML file.
fn export_config(args: &[String]) -> i32 {
    let base = match tool_config() {
        Ok(conf) => conf,
        Err(e) => {
            eprintln_tag(&e);
            return 2;
        }
    };
    let state_dir = soc_state::state_dir_from_env();
    let overrides = soc_state::Overrides::load(&state_dir).unwrap_or_else(|_| soc_state::Overrides::new());
    let out_dir = flag_value(args, "--out")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    // A sortable UTC stamp; the file name must be unique so a second export in
    // the same second is refused rather than overwriting the first.
    let stamp = export_stamp();
    match soc_state::export_to_dir(&base, &overrides, &out_dir, &stamp) {
        Ok(path) => {
            println!("exported to {}", path.display());
            0
        }
        Err(e) => {
            eprintln_tag(&format!("export failed: {e}"));
            1
        }
    }
}

/// `import-config <file>`: validate a config file through the full loader and
/// report its panels. It does not replace the running config — that is an
/// explicit Apply step in the settings window — so this is the safe way to
/// vet a file before importing it there.
fn import_config(args: &[String]) -> i32 {
    let Some(path) = args.iter().find(|a| !a.starts_with('-')) else {
        eprintln_tag("usage: soc-wall import-config <file.yaml>");
        return 2;
    };
    match soc_state::import_config(Path::new(path)) {
        Ok(conf) => {
            println!("{path}: OK — {} panel(s)", conf.panels.len());
            for w in &conf.warnings {
                eprintln!("warning: {w}");
            }
            0
        }
        Err(e) => {
            eprintln_tag(&format!("import failed: {e}"));
            1
        }
    }
}

/// A `YYYYmmdd-HHMMSS` UTC timestamp for an export file name.
fn export_stamp() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // Civil date from a Unix timestamp (UTC), without pulling in a date crate.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{y:04}{mo:02}{d:02}-{hh:02}{mm:02}{ss:02}")
}

/// Howard Hinnant's days-from-civil, inverted: a Unix day count to `(year,
/// month, day)` in the proleptic Gregorian calendar (UTC).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn wm_rc(args: &[String]) -> i32 {
    let (wm, rest) = match args.split_first() {
        Some((w, r)) if w == "openbox" => (Wm::Openbox, r),
        Some((w, r)) if w == "labwc" => (Wm::Labwc, r),
        _ => {
            eprintln_tag("usage: soc-wall wm-rc <openbox|labwc> --out <file> [--width W --height H] [--if-auto]");
            return 2;
        }
    };
    let panels = flag_value(rest, "--panels")
        .or_else(|| rest.iter().find_map(|arg| arg.strip_prefix("--panels=").map(str::to_string)));
    match panels {
        Some(panels) => match soc_core::load(Path::new(&panels)) {
            Ok(conf) => soc_sys::wmrules::wm_rc_main(wm, &conf, rest),
            Err(e) => {
                eprintln_tag(&e.to_string());
                2
            }
        },
        None => with_config(|conf| soc_sys::wmrules::wm_rc_main(wm, conf, rest)),
    }
}

fn print_usage() {
    println!(
        "soc-wall {} — SOC video-wall kiosk\n\n\
         USAGE:\n  soc-wall [run]                 start the wall (default)\n\
         \x20 soc-wall check <panels.yaml>   validate a config and print the layout\n\
         \x20 soc-wall supervise            run the wall with a heartbeat watchdog\n\
         \x20 soc-wall vpn [--name N]        supervise the VPN(s)\n\
         \x20 soc-wall vpn-args              print the VPN client argv\n\
         \x20 soc-wall vault <cmd>           vault client (config/login/sync/get/code)\n\
         \x20 soc-wall vault-backup <cmd>    backup | restore the vault\n\
         \x20 soc-wall setup <cmd>          configure, provision, diagnose and repair the wall\n\
         \x20 soc-wall export-config         write the effective config to a YAML file\n\
         \x20 soc-wall import-config <file>  validate a config file before importing it\n\
         \x20 soc-wall seal                  seal the vault master (master+PIN on stdin)\n\
         \x20 soc-wall pinentry              vault pinentry helper\n\
         \x20 soc-wall tunnel-args           print the autossh -L forwards\n\
         \x20 soc-wall autossh               run the jump-host tunnel\n\
         \x20 soc-wall wm-rc <openbox|labwc> --out F   generate window-manager rules\n\
         \x20 soc-wall session-info          print the resolved session layout\n\
         \x20 soc-wall manifest <cmd>        build / check the deploy manifest\n\
         \x20 soc-wall health                health / doctor checks\n\
         \x20 soc-wall update <cmd>          stage updates, report status or roll back\n\
         \x20 soc-wall tarpit                run the SSH/port tarpit\n\
         \x20 soc-wall configpaths <flags>   resolve config/secret/state paths\n\
         \x20 soc-wall menu | setup-gui | credentials | appearance   open a desktop tool\n\
         \x20 soc-wall version",
        env!("CARGO_PKG_VERSION")
    );
}
