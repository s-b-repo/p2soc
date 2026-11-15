//! Chromium's command line and on-disk profile. Pure assembly: nothing here
//! starts a process.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use soc_core::guard::{has_ctrl, url_for_msg};
use soc_core::url::Url;
use soc_core::{Panel, ProxyCfg};

use crate::error::Error;

/// Shown for an unconfigured tile, and as the page every panel starts on
/// before the host navigates it: a dark blank document. (Not `about:blank` —
/// that demotes `--app` to a normal tabbed window.)
pub const UNCONFIGURED_URL: &str = "data:text/html,%3Cbody%20style%3D%22background:%230b1020%22%3E";

/// File Chromium writes into the profile once its DevTools server listens
/// (first line: the port).
pub const ACTIVE_PORT_FILE: &str = "DevToolsActivePort";

const DISABLED_FEATURES: &str = "--disable-features=Translate,OptimizationHints,DownloadBubble,\
DownloadBubbleV2,MediaRouter,DialMediaRouteProvider,GlobalMediaControls,\
OptimizationHintsFetching,OptimizationTargetPrediction,\
SegmentationPlatform,AutofillServerCommunication,BackForwardCache,\
PersistentHistograms";

const BINARY_NAMES: [&str; 4] = ["chromium", "chromium-browser", "google-chrome", "chrome"];

/// Machine facts that shape the command line. Kept as plain data so the
/// assembly is testable; [`LaunchEnv::from_env`] is the thin reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEnv {
    /// `--ozone-platform` value (`x11`, `wayland`, ...).
    pub ozone: String,
    /// Small board: one renderer, 10 MB cache.
    pub low_memory: bool,
    /// Add the V3D GPU flags (ARM board with a render node).
    pub gpu_flags: bool,
    /// Development-only escape hatch for containers that cannot start the
    /// sandbox. Never on a real wall.
    pub no_sandbox: bool,
}

impl Default for LaunchEnv {
    fn default() -> Self {
        LaunchEnv { ozone: "x11".into(), low_memory: false, gpu_flags: false, no_sandbox: false }
    }
}

impl LaunchEnv {
    /// Read `$SOC_CHROMIUM_OZONE`, `$DISPLAY`, `$SOC_CHROMIUM_HWACCEL` and
    /// `$SOC_CHROMIUM_NO_SANDBOX`. `low_memory` and `arm_gpu` (an ARM board
    /// with a GPU render node) come from the caller's hardware probe.
    pub fn from_env(low_memory: bool, arm_gpu: bool) -> LaunchEnv {
        let env = |name: &str| std::env::var(name).ok();
        LaunchEnv {
            ozone: ozone_platform(env("SOC_CHROMIUM_OZONE").as_deref(), env("DISPLAY").as_deref()),
            low_memory,
            gpu_flags: hwaccel_enabled(env("SOC_CHROMIUM_HWACCEL").as_deref(), arm_gpu),
            no_sandbox: env("SOC_CHROMIUM_NO_SANDBOX").as_deref() == Some("1"),
        }
    }
}

/// `x11` (which includes XWayland — window-class placement then works under
/// both Openbox and labwc) unless overridden or X is unavailable. An override
/// that is not a plain word is ignored rather than passed to the browser.
pub fn ozone_platform(override_value: Option<&str>, display: Option<&str>) -> String {
    match override_value.map(str::trim) {
        Some(v) if v != "auto" && !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()) => v.to_string(),
        _ if display.is_some_and(|d| !d.is_empty()) => "x11".into(),
        _ => "wayland".into(),
    }
}

/// Whether to add the GPU flags: `SOC_CHROMIUM_HWACCEL` is `auto` (default)
/// and the board is ARM with a render node. Anything else — `never`, a typo —
/// leaves them off.
pub fn hwaccel_enabled(mode: Option<&str>, arm_gpu: bool) -> bool {
    matches!(mode.map(str::to_ascii_lowercase).as_deref(), None | Some("auto" | "")) && arm_gpu
}

/// GPU-acceleration flags for ARM boards (Pi 5 V3D). In a minimal kiosk
/// session Chromium often fails to pick the GPU and silently software-
/// composites the grid — the load a 1 GB board can least afford.
pub fn hwaccel_flags(enabled: bool) -> &'static [&'static str] {
    if enabled {
        &["--ignore-gpu-blocklist", "--enable-gpu-rasterization", "--enable-zero-copy", "--use-gl=egl"]
    } else {
        &[]
    }
}

/// Non-secret proxy flags (safe to appear in `ps`). A proxy URL that carries
/// userinfo is refused outright: credentials belong in the vault, never on a
/// command line every local user can read.
pub fn proxy_flags(proxy: &ProxyCfg) -> Result<Vec<String>, Error> {
    let url = proxy.url.trim();
    let parts = Url::split(url).map_err(|e| Error::Refused(format!("proxy url {}: {e}", url_for_msg(url))))?;
    if url.contains('@') || parts.userinfo.is_some() {
        return Err(Error::Refused(format!(
            "proxy url {} carries credentials; put them in the proxy vault item instead",
            url_for_msg(url)
        )));
    }
    if parts.host.is_none() || has_ctrl(url) || url.chars().any(char::is_whitespace) {
        return Err(Error::Refused(format!("proxy url {} is not scheme://host:port", url_for_msg(url))));
    }
    let bypass = proxy.effective_ignore_hosts().join(";");
    Ok(vec![format!("--proxy-server={url}"), format!("--proxy-bypass-list={bypass}")])
}

/// Everything one launch needs.
#[derive(Debug, Clone)]
pub struct LaunchSpec<'a> {
    pub panel: &'a Panel,
    pub binary: &'a Path,
    pub profile_dir: &'a Path,
    /// DevTools port; `0` lets Chromium pick a free one and report it in
    /// [`ACTIVE_PORT_FILE`] (preferred — see [`crate::chromium`]).
    pub cdp_port: u16,
    /// The global proxy, if one is configured at all.
    pub proxy: Option<&'a ProxyCfg>,
    pub env: &'a LaunchEnv,
}

/// The `chromium --app` command line for a panel.
///
/// The window always opens on [`UNCONFIGURED_URL`]; the host navigates to the
/// panel's URL over DevTools once the bootstrap, the navigation gate and the
/// proxy-auth handler are in place. So nothing loads unguarded, and the panel
/// URL (which can carry a token in its query) stays off the process table.
pub fn chromium_argv(spec: &LaunchSpec<'_>) -> Result<Vec<String>, Error> {
    let p = spec.panel;
    let profile = spec.profile_dir.to_str().ok_or_else(|| Error::UnsafePath(spec.profile_dir.to_path_buf()))?;
    let binary = spec.binary.to_str().ok_or_else(|| Error::UnsafePath(spec.binary.to_path_buf()))?;
    let mut args = vec![
        binary.to_string(),
        format!("--app={UNCONFIGURED_URL}"),
        format!("--class={}", p.wmclass()),
        format!("--user-data-dir={profile}"),
        format!("--remote-debugging-port={}", spec.cdp_port),
        "--remote-debugging-address=127.0.0.1".to_string(),
    ];
    // No --remote-allow-origins: the host's DevTools client sends no Origin
    // header (which Chromium accepts), so with no origin allowed at all no
    // page script — whose websocket always carries its page's Origin — can
    // ever reach the debugger.
    if let Some(g) = p.geometry {
        args.push(format!("--window-position={},{}", g.x, g.y));
        args.push(format!("--window-size={},{}", g.w, g.h));
    }
    let fixed = [
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-translate",
        "--disable-session-crashed-bubble",
        "--noerrdialogs",
        "--disable-infobars",
        "--password-store=basic",
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-breakpad",
        "--metrics-recording-only",
        // 24/7 dashboard wall: keep panels refreshing even when occluded or
        // unfocused (Chromium otherwise throttles their background timers).
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding",
        "--disable-backgrounding-occluded-windows",
        // /dev/shm is tiny on a 1 GB Pi.
        "--disable-dev-shm-usage",
        "--disable-pinch",
        "--overscroll-history-navigation=0",
        // What a kiosk never uses (downloads UI, casting, media controls,
        // on-device prediction) or never goes back to (back/forward cache).
        // PersistentHistograms keeps metrics in an mmap'd profile file,
        // dirtying the SD card all day. Site isolation stays ON: panels
        // render attacker-influenced data.
        DISABLED_FEATURES,
        // No panel-spawned popups or windows.
        "--block-new-web-contents",
    ];
    args.extend(fixed.iter().map(|s| s.to_string()));
    args.push(format!("--ozone-platform={}", spec.env.ozone));
    // The disk cache lives on tmpfs (RAM): shrink it on small boards.
    if spec.env.low_memory {
        args.push("--renderer-process-limit=1".into());
        args.push("--disk-cache-size=10485760".into());
    } else {
        args.push("--disk-cache-size=52428800".into());
    }
    args.extend(hwaccel_flags(spec.env.gpu_flags).iter().map(|s| s.to_string()));
    if !p.allow_media {
        // No WebGL/WebGL2.
        args.push("--disable-3d-apis".into());
    }
    if let Some(ua) = p.user_agent.as_deref().filter(|ua| !ua.is_empty()) {
        if has_ctrl(ua) {
            return Err(Error::Refused(format!("[{}] user_agent contains control characters", p.id)));
        }
        args.push(format!("--user-agent={ua}"));
    }
    match spec.proxy.filter(|proxy| proxy.enabled) {
        Some(proxy) if p.proxy => args.extend(proxy_flags(proxy)?),
        // The panel opted out (`proxy: false`).
        Some(_) => args.push("--no-proxy-server".into()),
        None => {}
    }
    if spec.env.no_sandbox {
        args.push("--no-sandbox".into());
    }
    // Self-signed / untrusted TLS (LAN appliances) only when the panel opts in.
    if p.allow_insecure {
        args.push("--ignore-certificate-errors".into());
    }
    Ok(args)
}

/// First Chromium binary on `path_var` (a `$PATH`-style list).
pub fn find_chromium(path_var: &str) -> Option<PathBuf> {
    BINARY_NAMES.iter().find_map(|name| {
        std::env::split_paths(path_var).filter(|dir| dir.is_absolute()).map(|dir| dir.join(name)).find(|candidate| {
            std::fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

// --------------------------------------------------------------------------- //
// Profile directory
// --------------------------------------------------------------------------- //

/// A panel id is used as a directory name; anything that is not a single
/// plain path component could step out of the profile base.
fn checked_id(panel: &Panel) -> Result<&str, Error> {
    let id = panel.id.as_str();
    let ok = !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if ok { Ok(id) } else { Err(Error::Refused(format!("panel id {id:?} cannot name a profile directory"))) }
}

/// Where a panel's Chromium profile lives.
///
/// * `persist: true` — `<webdata>/chromium/<id>`: cookies and storage survive
///   a reload and a wall restart, keeping a session-cookie dashboard logged in.
/// * `persist: false` — `<runtime>/soc-profiles/<id>` on the per-user tmpfs,
///   wiped each wall start. Without a runtime directory this falls back to
///   `<webdata>/chromium-ephemeral/<id>`: never a guessable name under a
///   world-writable `/tmp`, where another local user could pre-create it.
///
/// Returns the path and whether it is ephemeral.
pub fn profile_dir(panel: &Panel, webdata_dir: &Path, runtime_dir: Option<&Path>) -> Result<(PathBuf, bool), Error> {
    let id = checked_id(panel)?;
    Ok(if panel.persist {
        (webdata_dir.join("chromium").join(id), false)
    } else {
        match runtime_dir {
            Some(rt) => (rt.join("soc-profiles").join(id), true),
            None => (webdata_dir.join("chromium-ephemeral").join(id), true),
        }
    })
}

/// Create `dir` (and missing parents) private to this user and confirm it is
/// a real directory — it holds session tokens. An existing directory is
/// tightened to 0700; a symlink or a file in its place is refused.
pub fn private_dir(dir: &Path) -> Result<(), Error> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| Error::io(format!("stat {}", dir.display()), e))?;
    if !meta.file_type().is_dir() {
        return Err(Error::UnsafePath(dir.to_path_buf()));
    }
    // DirBuilder will not tighten a directory that already existed 0755.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(format!("chmod {}", dir.display()), e))
}

/// Make the profile ready for a launch: every level from the per-engine base
/// down is a real 0700 directory, the stale DevTools port file is gone, and
/// the preferences carry the kiosk settings. With `wipe`, an ephemeral
/// profile is emptied first.
///
/// Returns non-fatal problems for the journal (Chromium recreates default
/// preferences if seeding fails; only the no-bubble hardening is lost).
pub fn prepare_profile(profile: &Path, wipe: bool) -> Result<Vec<String>, Error> {
    let base = profile.parent().ok_or_else(|| Error::UnsafePath(profile.to_path_buf()))?;
    private_dir(base)?;
    if wipe {
        match std::fs::symlink_metadata(profile) {
            Ok(meta) if meta.file_type().is_dir() => {
                std::fs::remove_dir_all(profile).map_err(|e| Error::io(format!("wipe {}", profile.display()), e))?;
            }
            Ok(_) => return Err(Error::UnsafePath(profile.to_path_buf())),
            Err(_) => {} // audit-allow: no profile to wipe; private_dir() below surfaces any real fault
        }
    }
    private_dir(profile)?;
    let default = profile.join("Default");
    private_dir(&default)?;
    match std::fs::remove_file(profile.join(ACTIVE_PORT_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(Error::io(format!("remove stale {ACTIVE_PORT_FILE}"), e));
        }
        _ => {}
    }
    let mut notes = Vec::new();
    if let Err(e) = seed_preferences(&default.join("Preferences")) {
        notes.push(format!("chromium prefs seed failed: {e}"));
    }
    Ok(notes)
}

/// Keep Chromium from ever showing "Save password?" or the session-restore
/// prompt over a panel. An existing healthy file keeps everything else it
/// holds; a truncated or corrupt one (killed mid-write, SD hiccup) is
/// replaced. Written through a temp file and a rename.
fn seed_preferences(path: &Path) -> Result<(), Error> {
    let existing = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let mut prefs = match existing.clone() {
        Some(Value::Object(map)) => Value::Object(map),
        _ => json!({}),
    };
    prefs["credentials_enable_service"] = json!(false);
    if !prefs["profile"].is_object() {
        prefs["profile"] = json!({});
    }
    prefs["profile"]["password_manager_enabled"] = json!(false);
    prefs["profile"]["exit_type"] = json!("Normal");
    if existing.as_ref() == Some(&prefs) {
        return Ok(());
    }
    let tmp = path.with_extension("soc-tmp");
    let _ = std::fs::remove_file(&tmp); // audit-allow: best-effort temp cleanup
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        file.write_all(prefs.to_string().as_bytes())?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp); // audit-allow: best-effort temp cleanup
        Error::io(format!("write {}", path.display()), e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soc_core::Geometry;

    fn dash() -> Panel {
        let mut p = Panel::new("a");
        p.url = Some("https://dash.example.com/overview?token=s3cret".into());
        p.geometry = Some(Geometry { x: 960, y: 0, w: 960, h: 540 });
        p
    }

    fn argv(panel: &Panel, proxy: Option<&ProxyCfg>, env: &LaunchEnv, port: u16) -> Vec<String> {
        let spec = LaunchSpec {
            panel,
            binary: Path::new("/usr/bin/chromium"),
            profile_dir: Path::new("/wd/chromium/a"),
            cdp_port: port,
            proxy,
            env,
        };
        chromium_argv(&spec).unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("soc-web-argv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn kiosk_and_security_flags() {
        let args = argv(&dash(), None, &LaunchEnv::default(), 0);
        assert_eq!(args[0], "/usr/bin/chromium");
        for want in [
            "--class=soc-a",
            "--user-data-dir=/wd/chromium/a",
            "--remote-debugging-port=0",
            "--remote-debugging-address=127.0.0.1",
            "--window-position=960,0",
            "--window-size=960,540",
            "--block-new-web-contents",
            "--password-store=basic",
            "--disable-background-timer-throttling",
            "--ozone-platform=x11",
            "--disk-cache-size=52428800",
            "--disable-3d-apis",
        ] {
            assert!(args.iter().any(|a| a == want), "{want} missing from {args:?}");
        }
        assert!(args.iter().any(|a| a.starts_with("--disable-features=") && a.contains("DownloadBubble")));
        // The sandbox stays on and TLS errors stay fatal unless asked otherwise.
        for never in ["--no-sandbox", "--ignore-certificate-errors", "--no-proxy-server"] {
            assert!(!args.iter().any(|a| a == never), "{never} must not be set by default");
        }
        assert!(!args.iter().any(|a| a.starts_with("--user-agent=") || a.starts_with("--proxy-server=")));
    }

    #[test]
    fn debugger_accepts_no_browser_origin() {
        let args = argv(&dash(), None, &LaunchEnv::default(), 9333);
        assert!(args.iter().any(|a| a == "--remote-debugging-port=9333"));
        assert!(!args.iter().any(|a| a.starts_with("--remote-allow-origins")), "no origin may be allow-listed");
        assert!(!args.iter().any(|a| a.contains("0.0.0.0")));
    }

    #[test]
    fn panel_url_stays_off_the_command_line() {
        let args = argv(&dash(), None, &LaunchEnv::default(), 0);
        assert!(args.iter().any(|a| *a == format!("--app={UNCONFIGURED_URL}")));
        assert!(!args.iter().any(|a| a.contains("dash.example.com") || a.contains("s3cret")));
    }

    #[test]
    fn per_panel_knobs() {
        let mut p = dash();
        p.user_agent = Some("SOC/1.0 (kiosk)".into());
        p.allow_media = true;
        p.allow_insecure = true;
        p.geometry = None;
        let env = LaunchEnv { ozone: "wayland".into(), low_memory: true, gpu_flags: true, no_sandbox: true };
        let args = argv(&p, None, &env, 0);
        for want in [
            "--user-agent=SOC/1.0 (kiosk)",
            "--ignore-certificate-errors",
            "--ozone-platform=wayland",
            "--renderer-process-limit=1",
            "--disk-cache-size=10485760",
            "--ignore-gpu-blocklist",
            "--enable-gpu-rasterization",
            "--use-gl=egl",
            "--no-sandbox",
        ] {
            assert!(args.iter().any(|a| a == want), "{want} missing");
        }
        assert!(!args.iter().any(|a| a == "--disable-3d-apis"));
        assert!(!args.iter().any(|a| a.starts_with("--window-")));

        p.user_agent = Some("evil\r\nX-Injected: 1".into());
        let spec = LaunchSpec {
            panel: &p,
            binary: Path::new("/c"),
            profile_dir: Path::new("/p"),
            cdp_port: 0,
            proxy: None,
            env: &env,
        };
        assert!(matches!(chromium_argv(&spec), Err(Error::Refused(_))));
    }

    #[test]
    fn proxy_flags_carry_no_secret() {
        let proxy = ProxyCfg {
            enabled: true,
            url: "http://proxy.corp:3128".into(),
            vault_item: "SOC Proxy".into(),
            ignore_hosts: vec!["*.lan".into()],
        };
        let flags = proxy_flags(&proxy).unwrap();
        assert_eq!(flags[0], "--proxy-server=http://proxy.corp:3128");
        assert_eq!(flags[1], "--proxy-bypass-list=*.lan;localhost;127.0.0.1;::1");
        assert!(!flags.iter().any(|f| f.contains("SOC Proxy")));

        let args = argv(&dash(), Some(&proxy), &LaunchEnv::default(), 0);
        assert!(args.iter().any(|a| a == "--proxy-server=http://proxy.corp:3128"));
        // A panel that opted out bypasses the proxy explicitly.
        let mut direct = dash();
        direct.proxy = false;
        let args = argv(&direct, Some(&proxy), &LaunchEnv::default(), 0);
        assert!(args.iter().any(|a| a == "--no-proxy-server"));
        assert!(!args.iter().any(|a| a.starts_with("--proxy-server=")));
        // A disabled proxy block adds nothing either way.
        let off = ProxyCfg { enabled: false, ..proxy.clone() };
        let args = argv(&direct, Some(&off), &LaunchEnv::default(), 0);
        assert!(!args.iter().any(|a| a.contains("proxy")));
    }

    #[test]
    fn proxy_url_with_credentials_never_reaches_argv() {
        for url in ["http://user:hunter2@proxy.corp:3128", "http://user@proxy.corp:3128", "not a url", "http://"] {
            let proxy = ProxyCfg { enabled: true, url: url.into(), ..ProxyCfg::default() };
            let err = proxy_flags(&proxy).unwrap_err();
            assert!(!err.to_string().contains("hunter2"), "{err}");
            let spec = LaunchSpec {
                panel: &dash(),
                binary: Path::new("/c"),
                profile_dir: Path::new("/p"),
                cdp_port: 0,
                proxy: Some(&proxy),
                env: &LaunchEnv::default(),
            };
            assert!(chromium_argv(&spec).is_err(), "{url:?} must refuse the launch");
        }
    }

    #[test]
    fn ozone_and_hwaccel_selection() {
        assert_eq!(ozone_platform(None, Some(":0")), "x11");
        assert_eq!(ozone_platform(Some("auto"), None), "wayland");
        assert_eq!(ozone_platform(Some("wayland"), Some(":0")), "wayland");
        assert_eq!(ozone_platform(Some("x11 --no-sandbox"), Some("")), "wayland");
        assert!(hwaccel_enabled(None, true));
        assert!(hwaccel_enabled(Some("AUTO"), true));
        assert!(!hwaccel_enabled(Some("never"), true));
        assert!(!hwaccel_enabled(Some("typo"), true));
        assert!(!hwaccel_enabled(None, false));
        assert!(hwaccel_flags(false).is_empty());
        assert!(hwaccel_flags(true).contains(&"--ignore-gpu-blocklist"));
    }

    #[test]
    fn profile_locations() {
        let wd = Path::new("/wd");
        let (dir, ephemeral) = profile_dir(&dash(), wd, Some(Path::new("/run/user/1000"))).unwrap();
        assert_eq!((dir, ephemeral), (PathBuf::from("/wd/chromium/a"), false));
        let mut p = dash();
        p.persist = false;
        let (dir, ephemeral) = profile_dir(&p, wd, Some(Path::new("/run/user/1000"))).unwrap();
        assert_eq!((dir, ephemeral), (PathBuf::from("/run/user/1000/soc-profiles/a"), true));
        // No runtime dir: still private, never /tmp.
        let (dir, _) = profile_dir(&p, wd, None).unwrap();
        assert_eq!(dir, PathBuf::from("/wd/chromium-ephemeral/a"));
        for bad in ["../../etc", "a/b", "", ".", "a b"] {
            p.id = bad.into();
            assert!(profile_dir(&p, wd, None).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn profile_is_private_and_seeded() {
        let root = scratch("profile");
        // A pre-existing lax base is tightened, not trusted.
        let base = root.join("chromium");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let profile = base.join("a");
        assert!(prepare_profile(&profile, false).unwrap().is_empty());
        assert_eq!(mode(&base), 0o700);
        assert_eq!(mode(&profile), 0o700);
        assert_eq!(mode(&profile.join("Default")), 0o700);
        let prefs_path = profile.join("Default/Preferences");
        assert_eq!(mode(&prefs_path), 0o600);
        let prefs: Value = serde_json::from_str(&std::fs::read_to_string(&prefs_path).unwrap()).unwrap();
        assert_eq!(prefs["credentials_enable_service"], json!(false));
        assert_eq!(prefs["profile"], json!({"password_manager_enabled": false, "exit_type": "Normal"}));

        // Existing preferences keep their other keys; the kiosk keys are re-asserted.
        std::fs::write(
            &prefs_path,
            r#"{"browser":{"x":1},"profile":{"exit_type":"Crashed","name":"n"},"credentials_enable_service":true}"#,
        )
        .unwrap();
        std::fs::write(profile.join(ACTIVE_PORT_FILE), "1234\n/devtools/browser/x\n").unwrap();
        prepare_profile(&profile, false).unwrap();
        let prefs: Value = serde_json::from_str(&std::fs::read_to_string(&prefs_path).unwrap()).unwrap();
        assert_eq!(prefs["browser"], json!({"x": 1}));
        assert_eq!(prefs["profile"]["name"], json!("n"));
        assert_eq!(prefs["profile"]["exit_type"], json!("Normal"));
        assert_eq!(prefs["credentials_enable_service"], json!(false));
        assert!(!profile.join(ACTIVE_PORT_FILE).exists(), "a stale port file must not survive");

        // A corrupt file is replaced.
        std::fs::write(&prefs_path, "{\"profile\": {").unwrap();
        prepare_profile(&profile, false).unwrap();
        assert!(serde_json::from_str::<Value>(&std::fs::read_to_string(&prefs_path).unwrap()).is_ok());
        assert_eq!(std::fs::read_dir(profile.join("Default")).unwrap().count(), 1, "no temp file left");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ephemeral_profile_is_wiped_and_symlinks_refused() {
        let root = scratch("wipe");
        let profile = root.join("soc-profiles").join("a");
        prepare_profile(&profile, true).unwrap();
        std::fs::write(profile.join("Cookies"), "session").unwrap();
        prepare_profile(&profile, false).unwrap();
        assert!(profile.join("Cookies").exists(), "a respawn keeps the session");
        prepare_profile(&profile, true).unwrap();
        assert!(!profile.join("Cookies").exists(), "a wall start wipes it");

        // A symlink where the profile should be is never followed.
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("keep"), "x").unwrap();
        std::fs::remove_dir_all(&profile).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &profile).unwrap();
        assert!(matches!(prepare_profile(&profile, true), Err(Error::UnsafePath(_))));
        assert!(matches!(prepare_profile(&profile, false), Err(Error::UnsafePath(_))));
        assert!(elsewhere.join("keep").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn finds_an_executable_on_the_path() {
        let root = scratch("which");
        let (empty, bin) = (root.join("empty"), root.join("bin"));
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let path_var = format!("{}:{}", empty.display(), bin.display());
        assert_eq!(find_chromium(&path_var), None);
        // Present but not executable does not count.
        std::fs::write(bin.join("chromium"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(bin.join("chromium"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(bin.join("chromium-browser"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(bin.join("chromium-browser"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_chromium(&path_var), Some(bin.join("chromium-browser")));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
