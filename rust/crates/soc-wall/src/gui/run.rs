//! `soc-wall run`: boot the wall.
//!
//! Order matters and mirrors what a 24/7 box needs: open the vault first (the
//! wall config itself may live in it), read the config, paint the windows
//! immediately, and only then probe VPN / tunnel readiness off the main
//! thread — so an outage at boot shows each panel's own "connecting…" card
//! instead of a long black screen.

use super::board::{self, EXIT_OPERATOR, EXIT_RELOAD, RunError, StatusBoard};
use super::host::{Host, HostOptions};
use super::panel::Profile;
use super::services::Log;
use super::settings::VaultAccess;
use super::{style, unlock};
use crate::logic::{MASTER_REJECTED, classify_unlock_error, parse_probe, vault_retry_delay};
use soc_brand as branding;
use soc_core::env::{env_bool, env_float, env_int, env_str};
use soc_core::load::ConfigError;
use soc_core::{Config, CredSource, DictExt, Layout, Mode};
use soc_seal::MasterResolver;
use soc_sys::paths::PathEnv;
use soc_vault::{BackendKind, Vault, VaultEnv, VaultError};
use std::cell::{Cell, RefCell};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A complete, valid, panel-less config — what an unconfigured box starts
/// with, so a first launch never dead-ends on an error screen.
const DEFAULT_TEMPLATE: &str =
    "display: {auto: true, cols: 2, rows: 2, gap: 0}\npanels: []\ntunnel: {enabled: false}\nvpn: {enabled: false}\n";

/// An unattended boot step that outlives this is abandoned (the process
/// restarts clean).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

use crate::vaultsetup::SealedMaster;

type CountsFn = Box<dyn Fn() -> (u64, u64)>;

/// Publishes the heartbeat the supervisor watches. It beats from a main-loop
/// timer (so a hung loop goes quiet) and on every state change.
#[derive(Clone)]
struct Pulse {
    inner: Rc<PulseInner>,
}

struct PulseInner {
    path: PathBuf,
    commit: String,
    state: RefCell<String>,
    counts: RefCell<Option<CountsFn>>,
    timer: Cell<Option<glib::SourceId>>,
}

impl Pulse {
    fn start(path: PathBuf, commit: String, state: &str) -> Pulse {
        let pulse = Pulse {
            inner: Rc::new(PulseInner {
                path,
                commit,
                state: RefCell::new(state.to_string()),
                counts: RefCell::default(),
                timer: Cell::new(None),
            }),
        };
        let weak = Rc::downgrade(&pulse.inner);
        let source = glib::timeout_add_local(Duration::from_secs(15), move || {
            if let Some(inner) = weak.upgrade() {
                Pulse { inner }.beat();
            }
            glib::ControlFlow::Continue
        });
        pulse.inner.timer.set(Some(source));
        pulse.beat();
        pulse
    }

    fn beat(&self) {
        let (ok, total) = self.inner.counts.borrow().as_ref().map_or((0, 0), |f| f());
        let beat = soc_sys::heartbeat::Beat::now(total, ok, &self.inner.state.borrow(), &self.inner.commit);
        soc_sys::heartbeat::write(&self.inner.path, &beat);
    }

    fn set(&self, state: &str) {
        *self.inner.state.borrow_mut() = state.to_string();
        self.beat();
    }

    fn watch(&self, counts: impl Fn() -> (u64, u64) + 'static) {
        *self.inner.counts.borrow_mut() = Some(Box::new(counts));
    }

    fn stop(&self) {
        self.set("stopping");
        if let Some(source) = self.inner.timer.take() {
            source.remove();
        }
    }
}

struct Boot {
    log: Log,
    paths: PathEnv,
    unattended: bool,
    display: bool,
    windowed_errors: bool,
    pulse: Pulse,
}

impl Boot {
    fn log(&self, msg: &str) {
        (self.log)(msg);
    }

    /// Show why the wall cannot start and return the exit code to use.
    fn fatal(&self, title: &str, detail: &str, hint: &str) -> i32 {
        self.log(&format!("FATAL: {title}: {detail}"));
        self.pulse.set("fatal");
        if self.unattended {
            let reload = u64::try_from(env_int("SOC_UNATTENDED_RELOAD_SEC", 300, Some(1), Some(86_400))).unwrap_or(300);
            return board::fatal_unattended(
                self.display,
                self.windowed_errors,
                title,
                detail,
                Duration::from_secs(reload),
            );
        }
        if !self.display {
            return EXIT_OPERATOR; // nothing to render on; the log line is the diagnostic
        }
        board::fatal_attended(self.windowed_errors, title, detail, hint, None)
    }
}

fn tcp_open(host: &str, port: u16, timeout: Duration) -> bool {
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .is_some_and(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

/// Best-effort readiness gate, run on a worker thread: for each enabled VPN
/// with a `ready_probe`, then each tunnel port, wait until it answers (or the
/// budget runs out) and say so in the log. It never blocks painting.
fn readiness_probes(conf: &Config, budget: Duration, log: &Log) {
    for vpn in conf.enabled_vpns() {
        let name = vpn.text("name");
        let probe = vpn.text("ready_probe");
        if probe.is_empty() {
            continue;
        }
        let Some((host, port)) = parse_probe(&probe) else {
            log(&format!("[vpn:{name}] ignoring malformed ready_probe '{probe}' (want host:port)"));
            continue;
        };
        log(&format!("[vpn:{name}] waiting for VPN reachability {host}:{port} ..."));
        let deadline = Instant::now() + budget;
        let mut up = false;
        while !up && Instant::now() < deadline {
            up = tcp_open(&host, port, Duration::from_secs(1));
            if !up {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        if up {
            log(&format!("[vpn:{name}] VPN up"));
        } else {
            log(&format!(
                "[vpn:{name}] WARNING {host}:{port} never became reachable; VPN-side panels may show a connection \
                 error"
            ));
        }
    }
    // One sweep over all tunnels, not one wait after another: a dead first
    // tunnel must not hide the rest for its whole budget.
    let mut waiting: Vec<(String, u16)> = conf
        .panels
        .iter()
        .filter(|p| p.mode == Mode::Tunnel)
        .filter_map(|p| Some((p.id.clone(), p.tunnel_local_port()?)))
        .collect();
    for (id, port) in &waiting {
        log(&format!("[{id}] waiting for tunnel port 127.0.0.1:{port} ..."));
    }
    let deadline = Instant::now() + budget;
    while !waiting.is_empty() && Instant::now() < deadline {
        waiting.retain(|(id, port)| {
            let up = tcp_open("127.0.0.1", *port, Duration::from_secs(1));
            if up {
                log(&format!("[{id}] tunnel up"));
            }
            !up
        });
        if !waiting.is_empty() {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    for (id, port) in waiting {
        log(&format!("[{id}] WARNING tunnel port {port} never came up; the panel will show a connection error"));
    }
}

fn config_cache_path(paths: &PathEnv) -> PathBuf {
    paths.state_dir().join("config-cache.yaml")
}

/// Remember the last-known-good vault config so a later boot can paint from
/// it if the vault note is briefly unreadable. Only validated text is cached.
fn cache_config(paths: &PathEnv, text: &str) {
    if paths.ensure_state_dir().is_ok() {
        let _ = soc_sys::fsutil::write_atomic(&config_cache_path(paths), text.as_bytes(), 0o600); // audit-allow: best-effort, config cache is only a last-known-good fallback
    }
}

fn panels_file(paths: &PathEnv) -> PathBuf {
    env_str("SOC_PANELS_FILE")
        .map(PathBuf::from)
        .or_else(|| paths.resolve_panels())
        .unwrap_or_else(|| PathBuf::from("config/panels.yaml"))
}

/// Load the wall config: the vault secure note is the source of truth in
/// production, the last-known-good cache covers a briefly unreadable note,
/// and a local `panels.yaml` is the offline fallback (and the only source
/// for the dev backend, or with `SOC_CONFIG_FROM_VAULT=0`).
fn load_config(creds: &dyn CredSource, from_vault: bool, paths: &PathEnv, log: &Log) -> Result<Config, ConfigError> {
    let item = env_str("SOC_CONFIG_VAULT_ITEM").unwrap_or_else(|| "SOC Wall Config".into());
    if from_vault && !item.is_empty() {
        let text = creds.notes(&item).unwrap_or_else(|e| {
            log(&format!("config note '{item}' unreadable ({e}); falling back"));
            String::new()
        });
        if !text.trim().is_empty() {
            let conf = soc_core::load_str(&text, &format!("vault:{item}"))?;
            cache_config(paths, &text);
            log(&format!("config source: vault note '{item}'"));
            return Ok(conf);
        }
        let cached = soc_sys::fsutil::read_capped(&config_cache_path(paths), soc_core::load::MAX_CONFIG_BYTES);
        let cached_conf = cached.ok().and_then(|t| {
            soc_core::load_str(&t, "cache:config-cache.yaml")
                .map_err(|e| log(&format!("config cache unusable: {e}")))
                .ok()
        });
        if let Some(conf) = cached_conf {
            log("config source: last-known-good cache (vault note unavailable)");
            return Ok(conf);
        }
        log(&format!("config note '{item}' empty/absent; using the local file"));
    }
    let file = panels_file(paths);
    if !file.exists() {
        // Not configured yet: come up empty rather than dead-end. A
        // malformed file still fails loudly below.
        log(&format!(
            "no config at {} — launching the default template; add panels via Setup or the on-screen Settings",
            file.display()
        ));
        return soc_core::load_str(DEFAULT_TEMPLATE, "default-template");
    }
    log(&format!("config source: {}", file.display()));
    soc_core::load(&file)
}

/// `SOC_DRY_RUN=1`: print the geometry of the local config and exit.
fn dry_run(paths: &PathEnv, unattended: bool, log: &Log) -> i32 {
    match soc_core::load(&panels_file(paths)) {
        Ok(conf) => {
            crate::cli::geometry_lines(&conf).iter().for_each(|l| log(l));
            0
        }
        Err(e) => {
            log(&format!("FATAL config error:\n{e}"));
            if unattended { EXIT_RELOAD } else { EXIT_OPERATOR }
        }
    }
}

/// Open the vault with nobody here: on a worker, with the status screen up,
/// retrying on a capped backoff for as long as it takes. A vault that is
/// late, locked or misconfigured all land here, and each attempt re-reads
/// the sealed master and the server, so a fix takes effect without a restart.
fn open_vault_unattended(vault: &Arc<Vault>, url: &str, board: &mut StatusBoard, log: &Log) -> Option<i32> {
    let nothing = "This wall needs nothing pressed. It keeps trying by itself.";
    board.show("Waiting for the vault", "Opening the secrets vault…", nothing);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let v = vault.clone();
        match board.run(ATTEMPT_TIMEOUT, move || v.open()) {
            Ok(Ok(())) => return None,
            Err(RunError::Stopped) => return Some(0),
            Err(RunError::Hung) => {
                log("vault open wedged; exiting so the supervisor starts a clean process");
                return Some(EXIT_RELOAD);
            }
            Ok(Err(e)) => {
                // "Rejected" is the classifier's catch-all, right when someone
                // has just typed a password. Here nobody has: show the cause.
                let mut reason = classify_unlock_error(&e.to_string(), url);
                if reason == MASTER_REJECTED {
                    reason = format!("The vault did not open: {e}");
                }
                let delay = vault_retry_delay(attempt);
                log(&format!("vault not ready (attempt {attempt}): {e}; retrying in {}s", delay.as_secs()));
                board.show(
                    "Waiting for the vault",
                    &reason,
                    &format!(
                        "This wall needs nothing pressed. Attempt {attempt}; trying again in {} s.",
                        delay.as_secs()
                    ),
                );
                board.sleep(delay);
                if board.stopped() {
                    return Some(0);
                }
            }
        }
    }
}

/// Open the vault with an operator present: retry until the deadline, and
/// prompt for the master password when the host has none sealed.
fn open_vault_attended(vault: &Arc<Vault>, env: &VaultEnv, resolver: &MasterResolver, boot: &Boot) -> Option<i32> {
    let (email, url, _) = env.resolved();
    let ready_timeout = env_float("SOC_READY_TIMEOUT", 120.0, Some(0.0), Some(3600.0));
    let deadline = Instant::now() + Duration::from_secs_f64(ready_timeout);
    // A backend that locks again right after accepting the master (clock
    // skew, an invalidated session) would re-open the prompt forever.
    let mut relocks = 0u32;
    loop {
        match vault.open() {
            Ok(()) => return None,
            Err(VaultError::Locked(_)) if boot.display => {
                let verify = |master: &str| {
                    vault.unlock_with(master).map_err(|e| {
                        boot.log(&format!("unlock failed: {e}"));
                        classify_unlock_error(&e.to_string(), &url)
                    })
                };
                let keep_above = !boot.windowed_errors;
                let Some(answer) = unlock::unlock_dialog(&email, &url, keep_above, Duration::from_secs(180), &verify)
                else {
                    return Some(boot.fatal(
                        "Vaultwarden is locked",
                        "No master password is configured for the secrets vault, and the unlock prompt was \
                         cancelled, so the wall cannot read its logins.",
                        "Run Setup to configure + seal the vault master, or relaunch and enter the master password \
                         when prompted.",
                    ));
                };
                if answer.seal {
                    seal_master(&answer.master, resolver, boot);
                }
                drop(answer);
                relocks += 1;
                if relocks >= 3 {
                    return Some(boot.fatal(
                        "Vault keeps re-locking",
                        "The vault accepted the master password but locked again immediately several times in a \
                         row. This usually means the session is rejected right after login (clock skew on this \
                         box or the server, or an invalidated session).",
                        "Check both clocks (chrony/ntp) and the server's session settings, then relaunch.",
                    ));
                }
            }
            Err(e) => {
                if Instant::now() > deadline {
                    return Some(boot.fatal(
                        "Vault did not open",
                        &format!("The vault did not unlock and sync within {ready_timeout}s.\n\n{e}"),
                        "Check that Vaultwarden is running and the master password is configured (sealed \
                         host-bound, or via the keyring), then relaunch.",
                    ));
                }
                boot.log(&format!("vault not ready ({e}); retrying ..."));
                boot.pulse.set("unlocking"); // no loop is turning here: beat by hand
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    }
}

/// Seal an operator-supplied master host-bound so the next boot is
/// unattended. The PIN that guards re-sealing is generated here and shown
/// exactly once — it is not recoverable afterwards.
fn seal_master(master: &str, resolver: &MasterResolver, boot: &Boot) {
    let sealed = soc_seal::gen_pin(soc_seal::DEFAULT_PIN_DIGITS)
        .and_then(|pin| resolver.store().seal(master, &pin).map(|()| pin));
    match sealed {
        Ok(pin) => {
            boot.log("sealed the master host-bound — next boot unlocks unattended");
            unlock::notice(
                "Vault master sealed on this host",
                &format!(
                    "Setup PIN: {}\n\nWrite it down now — it is shown only once. It is needed to re-seal the vault \
                     master or to authorise destructive setup steps.",
                    pin.as_str()
                ),
                Duration::from_secs(300),
            );
        }
        Err(e) => boot.log(&format!("could not seal the master ({e}); will prompt again next boot")),
    }
}

/// Lay `overrides.json` over the loaded config. An unreadable file is logged
/// and ignored for this boot (it is never overwritten by the merge).
fn apply_saved_overrides(conf: Config, log: &Log) -> Config {
    let overrides = match soc_state::Overrides::load(&soc_state::fsio::state_dir_from_env()) {
        Ok(o) => o,
        Err(e) => {
            log(&format!("WARNING saved settings unreadable, ignoring them: {e}"));
            return conf;
        }
    };
    if overrides.is_empty() {
        return conf;
    }
    let merged = soc_state::apply_overrides(&conf, &overrides);
    merged.warnings.iter().for_each(|w| log(&format!("WARNING {w}")));
    log(&format!("applied {} saved setting(s) from the on-screen settings", overrides.len()));
    merged.config
}

fn host_options(conf: &Config, paths: &PathEnv, machine: &soc_sys::perf::Profile) -> HostOptions {
    let profile = Profile {
        low_memory: machine.low_memory,
        hwaccel: machine.webkit_hwaccel,
        unattended: machine.unattended,
        mem_limit_mb: u32::try_from(env_int("SOC_WEBKIT_MEM_LIMIT_MB", 256, Some(16), Some(4096))).unwrap_or(256),
        stable_sec: env_float("SOC_PANEL_STABLE_SEC", crate::logic::PANEL_STABLE_SEC, Some(0.0), None),
        webdata_dir: paths.resolve_webdata_dir(),
    };
    HostOptions {
        profile,
        machine: machine.clone(),
        stagger: Duration::from_secs_f64(env_float("SOC_LAUNCH_STAGGER", 1.5, Some(0.0), Some(60.0))),
        windowed: match env_str("SOC_WINDOW_MODE").as_deref() {
            Some("window") => true,
            Some("fullscreen") => false,
            _ => env_str("SOC_WINDOWED").as_deref() == Some("1") || !conf.display.fullscreen,
        },
        layout: env_str("SOC_LAYOUT").as_deref().and_then(Layout::parse).filter(|l| *l != Layout::Auto),
        // Chromium picks a free DevTools port unless one is pinned on purpose.
        cdp_base: env_str("SOC_CDP_BASE_PORT")
            .map(|_| u16::try_from(env_int("SOC_CDP_BASE_PORT", 9222, Some(1024), Some(65_000))).unwrap_or(9222)),
        branding: branding::Locations::from_env(),
        state_dir: soc_state::fsio::state_dir_from_env(),
    }
}

/// Boot the wall and run it until it is told to stop. Returns the exit code.
pub fn run() -> i32 {
    let log: Log = Arc::new(|m: &str| eprintln!("{} {m}", soc_core::LOG_TAG));
    let machine = soc_sys::perf::Profile::detect();
    let unattended = machine.unattended;
    let paths = PathEnv::from_process();
    if env_str("SOC_DRY_RUN").as_deref() == Some("1") {
        return dry_run(&paths, unattended, &log);
    }

    let display = gtk::init().is_ok();
    if !display
        && env_bool("SOC_SUPERVISED", false)
        && env_str("SOC_WAYLAND_BACKEND").as_deref() == Some("auto")
        && env_str("GDK_BACKEND").as_deref() == Some("wayland")
    {
        log("GTK could not start on native Wayland");
        return 1;
    }
    let looks = branding::Locations::from_env();
    if display {
        style::apply_css(&style::tokens_from_colors(&looks.load().colors));
    }
    let root = env_str("SOC_ROOT").map_or_else(|| paths.repo_root(), PathBuf::from);
    // The heartbeat starts here, before anything can block.
    let pulse = Pulse::start(soc_sys::heartbeat::path(), soc_sys::heartbeat::deployed_commit(&root), "unlocking");
    let boot = Boot {
        log: log.clone(),
        paths,
        unattended,
        display,
        windowed_errors: env_str("SOC_WINDOW_MODE").as_deref() == Some("window"),
        pulse: pulse.clone(),
    };
    let code = run_wall(&boot, &machine);
    pulse.stop();
    code
}

fn run_wall(boot: &Boot, machine: &soc_sys::perf::Profile) -> i32 {
    let log = &boot.log;
    // 1. The vault, first: with the native backend the wall config itself
    //    lives in it.
    let resolver = match MasterResolver::from_env() {
        Ok(r) => r,
        Err(e) => return boot.fatal("Vault backend error", &e.to_string(), ""),
    };
    let mut env = crate::vaultsetup::env_settings();
    // Nobody can answer a prompt on an unattended wall; with a display and an
    // operator, a missing master becomes the Unlock dialog instead of an error.
    env.interactive =
        !boot.unattended && (env.interactive || (boot.display && env_str("SOC_VAULT_INTERACTIVE").is_none()));
    let (_, url, _) = env.resolved();
    let backend = env.backend.clone().unwrap_or_else(|| soc_core::DEFAULT_VAULT_BACKEND.to_string());
    let from_vault = BackendKind::parse(&backend).is_ok_and(|k| !matches!(k, BackendKind::Dev))
        && env_str("SOC_CONFIG_FROM_VAULT").as_deref() != Some("0");
    let vault = match Vault::from_settings(&env, Arc::new(SealedMaster(resolver.clone()))) {
        Ok(v) => Arc::new(v),
        Err(e) => return boot.fatal("Vault backend error", &e.to_string(), ""),
    };
    log(&format!("opening vault (backend={backend}) ..."));

    // 2. Unlock, then read the config.
    let conf = if boot.unattended {
        let mut status = StatusBoard::new(boot.display, boot.windowed_errors);
        if let Some(code) = open_vault_unattended(&vault, &url, &mut status, log) {
            status.close();
            return code;
        }
        log("vault unlocked + synced");
        boot.pulse.set("starting");
        status.show("Starting the wall", "Reading the wall configuration…", "");
        let (v, paths, worker_log) = (vault.clone(), boot.paths.clone(), log.clone());
        let loaded = status.run(ATTEMPT_TIMEOUT, move || load_config(v.as_ref(), from_vault, &paths, &worker_log));
        status.close();
        match loaded {
            Ok(result) => result,
            Err(RunError::Stopped) => return 0,
            Err(RunError::Hung) => return EXIT_RELOAD,
        }
    } else {
        if let Some(code) = open_vault_attended(&vault, &env, &resolver, boot) {
            return code;
        }
        log("vault unlocked + synced");
        boot.pulse.set("starting");
        load_config(vault.as_ref(), from_vault, &boot.paths, log)
    };
    let conf = match conf {
        Ok(conf) => conf,
        Err(e) => {
            return boot.fatal(
                "Configuration error",
                &e.to_string(),
                "The wall config (vault note or panels.yaml) is invalid. Fix it, then relaunch.",
            );
        }
    };
    // What was saved at the glass (and could not reach the vault note) is
    // laid over the loaded config; the merge proves the result still validates.
    let conf = apply_saved_overrides(conf, log);
    for w in &conf.warnings {
        log(&format!("WARNING {w}"));
    }
    log(&format!(
        "{} panels, grid {}x{} @ {}x{}",
        conf.panels.len(),
        conf.display.cols,
        conf.display.rows,
        conf.display.width,
        conf.display.height
    ));
    if conf.proxy.enabled {
        let auth = if conf.proxy.vault_item.is_empty() {
            "no auth".to_string()
        } else {
            format!("auth via vault item '{}'", conf.proxy.vault_item)
        };
        log(&format!("proxy: {} ({auth})", conf.proxy.url));
    }
    if !boot.display {
        return boot.fatal("No display", "The wall needs an X11 or Wayland display to show its panels.", "");
    }

    // 3. Windows first, so every panel paints its own status card at once.
    let memory = Arc::new(soc_web::LoginMemory::from_env());
    let data = Arc::new(soc_web::SecurityData::global().clone());
    let creds: Arc<dyn CredSource> = vault.clone();
    let host = Host::new(
        conf.clone(),
        host_options(&conf, &boot.paths, machine),
        creds,
        memory.clone(),
        data,
        env_bool("SOC_BLOCK_TRACKERS", true),
        log.clone(),
    );
    // The sealed master's setup PIN is the admin override for the kiosk lock,
    // so a forgotten panel-lock credential never strands the operator.
    let admin_store = resolver.store().clone();
    host.set_admin_pin(Rc::new(move |code: &str| admin_store.verify_pin(code)));
    // The Settings window writes and deletes vault items, and writes the
    // config back to its vault note; the master comes only from the sealed store.
    {
        let (email, url, _) = env.resolved();
        let store = resolver.store().clone();
        let sealed = store.is_sealed();
        host.set_vault_access(VaultAccess {
            vault: vault.clone(),
            url,
            email,
            backend: backend.clone(),
            config_item: env_str("SOC_CONFIG_VAULT_ITEM").unwrap_or_else(|| "SOC Wall Config".into()),
            sealed,
            sealed_master: Arc::new(move || store.unseal().ok()),
        });
    }

    // Warm the credential cache off-thread, so the first login of each panel
    // never waits on the vault from the main loop.
    {
        let mut items: Vec<String> = conf.panels.iter().map(|p| p.vault_item.clone()).collect();
        items.push(conf.proxy.vault_item.clone());
        items.extend(memory.load().into_values());
        items.retain(|i| !i.is_empty());
        items.sort();
        items.dedup();
        let (v, worker_log) = (vault.clone(), log.clone());
        std::thread::spawn(move || {
            let names: Vec<&str> = items.iter().map(String::as_str).collect();
            let warmed = v.prewarm(&names, None);
            worker_log(&format!("prewarmed {warmed} vault credential(s)"));
        });
    }

    host.build_and_show();
    {
        let h = host.clone();
        boot.pulse.watch(move || h.panel_counts());
    }
    boot.pulse.set("running");

    // 4. VPN + tunnel readiness, best-effort and off the main thread.
    {
        let (probe_conf, worker_log) = (conf.clone(), log.clone());
        let budget = Duration::from_secs_f64(env_float("SOC_READY_TIMEOUT", 120.0, Some(0.0), Some(3600.0)));
        std::thread::spawn(move || readiness_probes(&probe_conf, budget, &worker_log));
    }

    // Unattended: the vault copy in RAM would never see a rotated password.
    if boot.unattended {
        let every = u32::try_from(env_int("SOC_VAULT_RESYNC_SEC", 3600, Some(60), Some(86_400))).unwrap_or(3600);
        let (v, worker_log) = (vault.clone(), log.clone());
        glib::timeout_add_seconds_local(every, move || {
            let (v, worker_log) = (v.clone(), worker_log.clone());
            std::thread::spawn(move || {
                if let Err(e) = v.resync() {
                    worker_log(&format!("vault re-sync failed; keeping the current copy: {e}"));
                }
            });
            glib::ControlFlow::Continue
        });
    }

    // An unattended wall with no panels has nothing to lose: look for a
    // config again later by restarting.
    if conf.panels.is_empty() {
        log("no panels configured — launching empty; add panels via Setup or the on-screen Settings");
        if boot.unattended {
            let reload = u32::try_from(env_int("SOC_UNATTENDED_RELOAD_SEC", 300, Some(1), Some(86_400))).unwrap_or(300);
            let h = host.clone();
            glib::timeout_add_seconds_local_once(reload, move || h.shutdown());
        }
    }

    for signal in [libc::SIGINT, libc::SIGTERM] {
        let h = host.clone();
        glib::unix_signal_add_local(signal, move || {
            h.shutdown();
            glib::ControlFlow::Continue
        });
    }
    log("entering the main loop");
    if !host.stopping() {
        gtk::main();
    }
    // Idempotent: covers a main loop that ended without going through it.
    host.shutdown();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn log() -> (Log, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        (Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string())), lines)
    }

    #[test]
    fn default_template_is_valid_and_empty() {
        let conf = soc_core::load_str(DEFAULT_TEMPLATE, "default-template").unwrap();
        assert!(conf.panels.is_empty());
        assert_eq!(conf.enabled_vpns().count(), 0);
    }

    #[test]
    fn readiness_probes_report_tunnels_and_vpns() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let up = listener.local_addr().unwrap().port();
        let down = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let yaml = format!(
            "tunnel: {{jump_host: u@j}}\n\
             vpns:\n  - {{name: a, enabled: true, type: wireguard, config: wg0, ready_probe: '127.0.0.1:{up}'}}\n\
             \x20 - {{name: b, enabled: true, type: wireguard, config: wg1, ready_probe: '127.0.0.1:{down}'}}\n\
             panels:\n\
             \x20 - {{id: t1, mode: tunnel, tunnel: {{local_port: {up}, remote_host: h, remote_port: 80}}}}\n\
             \x20 - {{id: t2, grid: [1, 0], mode: tunnel, tunnel: {{local_port: {down}, remote_host: h, remote_port: 80}}}}\n"
        );
        let conf = soc_core::load::load_str_with(&yaml, "<test>", &Default::default()).unwrap();
        let (sink, lines) = log();
        readiness_probes(&conf, Duration::from_millis(50), &sink);
        let lines = lines.lock().unwrap();
        assert!(lines.iter().any(|l| l == "[vpn:a] VPN up"), "{lines:#?}");
        assert!(lines.iter().any(|l| l.starts_with("[vpn:b] WARNING")), "{lines:#?}");
        assert!(lines.iter().any(|l| l == "[t1] tunnel up"), "{lines:#?}");
        assert!(lines.iter().any(|l| l.starts_with("[t2] WARNING tunnel port")), "{lines:#?}");
    }
}
