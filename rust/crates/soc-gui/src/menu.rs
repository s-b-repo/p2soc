//! The launcher / control-center menu: `soc-wall menu`.
//!
//! The one window behind `soc-wall.desktop`. It does not take over the machine;
//! it is the place to run, configure and manage the wall, grouped under quiet
//! `// ` section eyebrows:
//!
//! ```text
//!   // run        Desktop mode (windowed)     Kiosk mode (fullscreen)
//!   // configure  Setup / Configure           Appearance     Credentials & Security
//!   // system     Install / Update            Uninstall
//! ```
//!
//! Every tile launches another tool of THIS binary (`soc-wall <subcommand>`)
//! detached in its own process group, or — for Install / Uninstall — the deploy
//! scripts through an honest elevation path (graphical `pkexec`, else a terminal
//! `sudo`, else the exact shell line is shown). Nothing is run through a shell,
//! and a failed launch always surfaces a visible `guierror` window.

use crate::style;
use gtk::prelude::*;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What a tile does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Desktop,
    Kiosk,
    Setup,
    Appearance,
    Credentials,
    Install,
    Uninstall,
}

struct Tile {
    section: &'static str,
    title: &'static str,
    subtitle: &'static str,
    tag: &'static str,
    action: Action,
}

/// Ordered section eyebrows (drives the grouping and the `--check` assertion).
const SECTIONS: [&str; 3] = ["run", "configure", "system"];

const TILES: [Tile; 7] = [
    Tile {
        section: "run",
        title: "Desktop mode",
        subtitle: "Run the wall in a window",
        tag: "windowed",
        action: Action::Desktop,
    },
    Tile {
        section: "run",
        title: "Kiosk mode",
        subtitle: "Fill this display, no desktop",
        tag: "fullscreen",
        action: Action::Kiosk,
    },
    Tile {
        section: "configure",
        title: "Setup / Configure",
        subtitle: "Panels, vault and VPN",
        tag: "",
        action: Action::Setup,
    },
    Tile {
        section: "configure",
        title: "Appearance",
        subtitle: "Theme colours & presets",
        tag: "",
        action: Action::Appearance,
    },
    Tile {
        section: "configure",
        title: "Credentials & Security",
        subtitle: "Vault logins, PIN & TOTP",
        tag: "",
        action: Action::Credentials,
    },
    Tile {
        section: "system",
        title: "Install / Update",
        subtitle: "Deploy or update the wall",
        tag: "",
        action: Action::Install,
    },
    Tile {
        section: "system",
        title: "Uninstall",
        subtitle: "Remove the deployed wall",
        tag: "",
        action: Action::Uninstall,
    },
];

// ---------------------------------------------------------------------------
// Pure planning helpers (unit-tested; no GTK, no process spawning).
// ---------------------------------------------------------------------------

/// A spawn-time failure, carrying the human-readable cause.
#[derive(Debug)]
struct LaunchError(String);

/// An unprivileged child to start: explicit argv plus env edits.
#[derive(Debug, PartialEq, Eq)]
struct Launch {
    argv: Vec<OsString>,
    env_set: Vec<(&'static str, &'static str)>,
    env_remove: Vec<&'static str>,
}

/// The child an unprivileged tile starts (`None` for the privileged ones).
fn plan(action: Action, exe: &Path) -> Option<Launch> {
    let sub = |name: &str| vec![exe.as_os_str().to_owned(), OsString::from(name)];
    let (argv, env_set, env_remove) = match action {
        Action::Desktop => (sub("run"), vec![("SOC_WINDOWED", "1"), ("SOC_WINDOW_MODE", "window")], vec![]),
        Action::Kiosk => (sub("run"), vec![("SOC_WINDOW_MODE", "fullscreen")], vec!["SOC_WINDOWED"]),
        // Ask the wizard to come back HERE when it finishes, so the operator
        // lands on the launcher again rather than the bare desktop.
        Action::Setup => (sub("setup-gui"), vec![("SOC_RETURN_TO_MENU", "1")], vec![]),
        Action::Appearance => (sub("appearance"), vec![], vec![]),
        Action::Credentials => (sub("credentials"), vec![], vec![]),
        Action::Install | Action::Uninstall => return None,
    };
    Some(Launch { argv, env_set, env_remove })
}

/// How a privileged script is elevated.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Elevation {
    /// `SOC_SYSACTION_CMD` stands in for the script, run directly (dev/test).
    Fake(String),
    /// Graphical polkit.
    Pkexec,
    /// `<terminal> -e sudo ...`.
    Terminal(String),
    /// Neither available: show the exact shell line instead.
    Manual,
}

/// Keep a path from ever being read as an option by the program it is handed to.
fn guard_path(p: &Path) -> PathBuf {
    if p.as_os_str().to_string_lossy().starts_with('-') { Path::new(".").join(p) } else { p.to_path_buf() }
}

/// The `K=V` env knobs for a privileged action, plus its extra script args.
fn action_knobs(action: Action, mode: &str, purge: bool) -> (Vec<String>, Vec<&'static str>) {
    if action == Action::Install {
        (vec![format!("INSTALL_MODE={mode}")], vec![])
    } else {
        // No tty under pkexec / terminal for uninstall's y/N prompts, so force.
        (vec![], if purge { vec!["--force", "--purge"] } else { vec!["--force"] })
    }
}

/// Build the elevated argv (never goes through a shell).
fn elevated_argv(how: &Elevation, knobs: &[String], script: &Path, extra: &[&str]) -> Vec<OsString> {
    let script = guard_path(script).into_os_string();
    let mut tail: Vec<OsString> = Vec::new();
    let env_prefix = |v: &mut Vec<OsString>| {
        v.push(OsString::from("env"));
        v.extend(knobs.iter().map(OsString::from));
    };
    let mut out: Vec<OsString> = Vec::new();
    match how {
        Elevation::Fake(cmd) => {
            if !knobs.is_empty() {
                env_prefix(&mut out);
            }
            out.push(OsString::from(cmd));
        }
        Elevation::Pkexec => {
            out.push(OsString::from("pkexec"));
            env_prefix(&mut out);
            out.push(script);
        }
        Elevation::Terminal(term) => {
            out.extend([OsString::from(term), OsString::from("-e"), OsString::from("sudo")]);
            env_prefix(&mut out);
            out.push(script);
        }
        Elevation::Manual => {
            if !knobs.is_empty() {
                env_prefix(&mut out);
            }
            out.push(script);
        }
    }
    tail.extend(extra.iter().map(OsString::from));
    out.extend(tail);
    out
}

fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '=' | ':' | '+' | ','));
    if safe { s.to_string() } else { format!("'{}'", s.replace('\'', "'\\''")) }
}

/// The exact shell line for the manual fallback.
fn manual_hint(knobs: &[String], script: &Path, extra: &[&str]) -> String {
    let mut parts = vec!["sudo".to_string()];
    parts.extend(knobs.iter().map(|k| shell_quote(k)));
    parts.push(shell_quote(&guard_path(script).to_string_lossy()));
    parts.extend(extra.iter().map(|a| shell_quote(a)));
    parts.join(" ")
}

/// The first executable `name` on `$PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// pkexec on PATH AND setuid (a non-setuid pkexec, the Kali default, must fall
/// back to the terminal path rather than fail at runtime).
fn pkexec_ok() -> bool {
    which("pkexec").and_then(|p| p.metadata().ok()).is_some_and(|m| m.permissions().mode() & 0o4000 != 0)
}

fn detect_elevation() -> Elevation {
    if let Some(cmd) = std::env::var("SOC_SYSACTION_CMD").ok().filter(|c| !c.is_empty()) {
        return Elevation::Fake(cmd);
    }
    if pkexec_ok() {
        return Elevation::Pkexec;
    }
    const TERMS: [&str; 6] =
        ["x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal", "xterm"];
    TERMS.iter().find(|t| which(t).is_some()).map_or(Elevation::Manual, |t| Elevation::Terminal((*t).to_string()))
}

/// Self-locate the install root: `$SOC_ROOT`, else the nearest ancestor of the
/// executable holding `install.sh`, else `/opt/soc-wall`.
fn find_root(env_root: Option<&str>, exe: Option<&Path>) -> PathBuf {
    if let Some(r) = env_root.filter(|r| !r.is_empty()) {
        return std::path::absolute(r).unwrap_or_else(|_| PathBuf::from(r));
    }
    if let Some(found) = exe.and_then(|e| e.ancestors().skip(1).take(5).find(|d| d.join("install.sh").is_file())) {
        return found.to_path_buf();
    }
    PathBuf::from("/opt/soc-wall")
}

// ---------------------------------------------------------------------------
// Spawning (fire-and-forget; every failure is surfaced).
// ---------------------------------------------------------------------------

/// Start `argv` in its own process group and reap it on a helper thread so it
/// never becomes a zombie. `report` is `(ok_title, fail_title)`: when set, the
/// child's exit is announced through `guierror`. Returns the spawn-time cause.
fn spawn_detached(
    argv: &[OsString],
    env_set: &[(&str, &str)],
    env_remove: &[&str],
    report: Option<(String, String)>,
) -> Result<(), LaunchError> {
    let (prog, rest) = argv.split_first().ok_or_else(|| LaunchError("empty command".to_string()))?;
    let mut cmd = Command::new(prog);
    cmd.args(rest).stdin(Stdio::null()).process_group(0);
    for (k, v) in env_set {
        cmd.env(k, v);
    }
    for k in env_remove {
        cmd.env_remove(k);
    }
    let mut child =
        cmd.spawn().map_err(|e| LaunchError(format!("could not launch {}: {e}", prog.to_string_lossy())))?;
    let waiter = std::thread::Builder::new().name("menu-reap".into()).spawn(move || {
        let status = child.wait();
        if let Some((ok_title, fail_title)) = report {
            match status {
                Ok(s) if s.success() => show_error(&ok_title, "Completed successfully."),
                Ok(s) => show_error(&fail_title, &format!("The command exited with {s}.")),
                Err(e) => show_error(&fail_title, &format!("Could not wait for the command: {e}")),
            }
        }
    });
    if let Err(e) = waiter {
        eprintln!("soc-wall menu: could not start reaper thread: {e}");
    }
    Ok(())
}

/// Surface a message through `soc-wall guierror` (itself falls back to stderr
/// without a display); if even that cannot start, print to stderr.
fn show_error(title: &str, detail: &str) {
    eprintln!("soc-wall menu: {title}: {detail}");
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let argv = [exe.into_os_string(), OsString::from("guierror"), OsString::from(title), OsString::from(detail)];
    if let Err(e) = spawn_detached(&argv, &[], &[], None) {
        eprintln!("soc-wall menu: {}", e.0);
    }
}

/// Start an unprivileged tile. `Ok` means the helper was started.
fn launch(action: Action) -> Result<(), LaunchError> {
    let exe =
        std::env::current_exe().map_err(|e| LaunchError(format!("cannot locate the soc-wall executable: {e}")))?;
    let l = plan(action, &exe).ok_or_else(|| LaunchError("not a plain launcher action".to_string()))?;
    spawn_detached(&l.argv, &l.env_set, &l.env_remove, None)
}

/// Run Install / Uninstall through the elevation path. Returns a status line.
fn run_privileged(action: Action, mode: &str, purge: bool) -> Result<String, (String, String)> {
    let is_install = action == Action::Install;
    let title = if is_install { "Install / Update" } else { "Uninstall" };
    let exe = std::env::current_exe().ok();
    let root = find_root(std::env::var("SOC_ROOT").ok().as_deref(), exe.as_deref());
    let script = root.join(if is_install { "install.sh" } else { "uninstall.sh" });
    let (knobs, extra) = action_knobs(action, mode, purge);
    let how = detect_elevation();
    let fake = matches!(how, Elevation::Fake(_));
    if !fake && !script.is_file() {
        return Err((
            format!("{title}: script not found"),
            format!("{} does not exist. Set SOC_ROOT.", script.display()),
        ));
    }
    if how == Elevation::Manual {
        let line = manual_hint(&knobs, &script, &extra);
        return Err((
            format!("{title}: run this in a terminal"),
            format!("Neither pkexec nor a terminal emulator is available. Run:\n\n{line}"),
        ));
    }
    let argv = elevated_argv(&how, &knobs, &script, &extra);
    let report = Some((format!("{title} finished"), format!("{title} failed")));
    spawn_detached(&argv, &[], &[], report).map_err(|e| (format!("{title}: could not start"), e.0))?;
    Ok(format!("{title} started — authenticate in the prompt; a notice appears when it finishes."))
}

// ---------------------------------------------------------------------------
// GTK.
// ---------------------------------------------------------------------------

fn make_tile(tile: &Tile) -> gtk::Button {
    let button = gtk::Button::new();
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 2);
    inner.set_margin_top(6);
    inner.set_margin_bottom(6);
    let head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let title = gtk::Label::new(Some(tile.title));
    title.set_xalign(0.0);
    title.style_context().add_class("soc-config-title");
    head.pack_start(&title, false, false, 0);
    if !tile.tag.is_empty() {
        let tag = gtk::Label::new(Some(tile.tag));
        tag.style_context().add_class("soc-config-tag");
        head.pack_end(&tag, false, false, 0);
    }
    let sub = gtk::Label::new(Some(tile.subtitle));
    sub.set_xalign(0.0);
    sub.style_context().add_class("soc-config-sub");
    inner.pack_start(&head, false, false, 0);
    inner.pack_start(&sub, false, false, 0);
    button.add(&inner);
    button.set_hexpand(true);
    if tile.action == Action::Uninstall {
        button.style_context().add_class("destructive-action");
    }
    button
}

/// Confirm Install / Uninstall in a modal dialog, then run it. Non-blocking:
/// the response is handled by a signal, never a nested loop.
fn confirm_privileged(parent: &gtk::Window, action: Action, status: &gtk::Label) {
    let is_install = action == Action::Install;
    let dialog = gtk::Dialog::with_buttons(
        Some(if is_install { "Install / Update" } else { "Uninstall" }),
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[("Cancel", gtk::ResponseType::Cancel), ("Continue", gtk::ResponseType::Accept)],
    );
    dialog.style_context().add_class("soc-config");
    let area = dialog.content_area();
    area.set_spacing(10);
    area.set_margin_start(20);
    area.set_margin_end(20);
    area.set_margin_top(16);
    area.set_margin_bottom(8);
    let text = if is_install {
        "This runs install.sh as root and (re)deploys the wall. Existing configuration is kept."
    } else {
        "This runs uninstall.sh as root and REMOVES the deployed wall."
    };
    let msg = gtk::Label::new(Some(text));
    msg.set_line_wrap(true);
    msg.set_max_width_chars(48);
    msg.set_xalign(0.0);
    msg.style_context().add_class("soc-config-sub");
    area.pack_start(&msg, false, false, 0);

    let desktop = gtk::RadioButton::with_label("Desktop mode install");
    let kiosk = gtk::RadioButton::with_label_from_widget(&desktop, "Kiosk mode install");
    let purge = gtk::CheckButton::with_label("Also purge configuration and data");
    if is_install {
        area.pack_start(&desktop, false, false, 0);
        area.pack_start(&kiosk, false, false, 0);
    } else {
        area.pack_start(&purge, false, false, 0);
    }
    dialog.set_default_response(gtk::ResponseType::Cancel);

    let status = status.clone();
    dialog.connect_response(move |d, resp| {
        if resp == gtk::ResponseType::Accept {
            let mode = if kiosk.is_active() { "kiosk" } else { "desktop" };
            match run_privileged(action, mode, purge.is_active()) {
                Ok(line) => status.set_text(&line),
                Err((title, detail)) => {
                    status.set_text(&title);
                    show_error(&title, &detail);
                }
            }
        }
        d.close();
    });
    dialog.show_all();
}

fn on_tile(window: &gtk::Window, status: &gtk::Label, action: Action) {
    match action {
        Action::Install | Action::Uninstall => confirm_privileged(window, action, status),
        _ => match launch(action) {
            // Helper started: hand off and close the menu, as the Python does.
            Ok(()) => window.close(),
            Err(e) => {
                status.set_text("Could not launch — see the error window.");
                show_error("Could not launch", &e.0);
            }
        },
    }
}

fn build_window() -> gtk::Window {
    let branding = soc_brand::Locations::from_env().load();
    let name = Some(branding.get("name")).filter(|n| !n.is_empty()).unwrap_or("SOC Video Wall");
    let short = Some(branding.get("short_name")).filter(|n| !n.is_empty()).unwrap_or(name);
    let tagline = Some(branding.get("tagline")).filter(|n| !n.is_empty()).unwrap_or("Operations console");

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(short);
    window.set_resizable(true);
    window.set_position(gtk::WindowPosition::Center);
    window.style_context().add_class("soc-config");

    let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.set_size_request(420, -1);
    root.set_margin_top(20);
    root.set_margin_bottom(20);
    root.set_margin_start(24);
    root.set_margin_end(24);

    let over = gtk::Label::new(Some("// launcher"));
    over.set_xalign(0.0);
    over.style_context().add_class("soc-config-sec");
    let title = gtk::Label::new(Some(&name.to_uppercase()));
    title.set_xalign(0.0);
    title.style_context().add_class("soc-config-tag");
    let sub = gtk::Label::new(Some(tagline));
    sub.set_xalign(0.0);
    sub.style_context().add_class("soc-config-sub");
    root.pack_start(&over, false, false, 0);
    root.pack_start(&title, false, false, 0);
    root.pack_start(&sub, false, false, 0);

    let status = gtk::Label::new(None);
    status.set_xalign(0.0);
    status.set_line_wrap(true);
    status.set_max_width_chars(52);
    status.style_context().add_class("soc-config-sub");

    for section in SECTIONS {
        let eyebrow = gtk::Label::new(Some(&format!("// {section}")));
        eyebrow.set_xalign(0.0);
        eyebrow.set_margin_top(12);
        eyebrow.style_context().add_class("soc-config-sec");
        root.pack_start(&eyebrow, false, false, 0);
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.set_homogeneous(true);
        for tile in TILES.iter().filter(|t| t.section == section) {
            let button = make_tile(tile);
            let (win, st, action) = (window.clone(), status.clone(), tile.action);
            button.connect_clicked(move |_| on_tile(&win, &st, action));
            row.pack_start(&button, true, true, 0);
        }
        root.pack_start(&row, false, false, 0);
    }
    root.pack_start(&status, false, false, 6);

    window.add(&root);
    window.connect_destroy(|_| gtk::main_quit());
    window
}

/// Validate the wiring without GTK or a display (for CI).
fn check() -> i32 {
    if TILES.iter().any(|t| !SECTIONS.contains(&t.section)) {
        eprintln!("[soc-wall] menu --check: a tile names an unknown section");
        return 1;
    }
    let exe = Path::new("/usr/bin/soc-wall");
    if TILES.iter().any(|t| !matches!(t.action, Action::Install | Action::Uninstall) && plan(t.action, exe).is_none()) {
        eprintln!("[soc-wall] menu --check: a tile has no launch plan");
        return 1;
    }
    println!("menu: ok ({} tiles, {} sections)", TILES.len(), SECTIONS.len());
    0
}

/// Run the launcher menu (`soc-wall menu`). Returns the exit code.
pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--check") {
        return check();
    }
    if !style::init() {
        eprintln!("[soc-wall] the launcher menu needs a graphical display (none available)");
        return 1;
    }
    let window = build_window();
    window.show_all();
    gtk::main();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn tiles_cover_all_sections_and_actions() {
        assert!(TILES.iter().all(|t| SECTIONS.contains(&t.section)));
        for s in SECTIONS {
            assert!(TILES.iter().any(|t| t.section == s), "{s}");
        }
        assert_eq!(check(), 0);
    }

    #[test]
    fn desktop_and_kiosk_plans() {
        let exe = Path::new("/usr/bin/soc-wall");
        let d = plan(Action::Desktop, exe).expect("desktop plan"); // audit-allow: test
        assert_eq!(d.argv, os(&["/usr/bin/soc-wall", "run"]));
        assert!(d.env_set.contains(&("SOC_WINDOWED", "1")));
        let k = plan(Action::Kiosk, exe).expect("kiosk plan"); // audit-allow: test
        assert!(k.env_remove.contains(&"SOC_WINDOWED"));
        assert!(k.env_set.contains(&("SOC_WINDOW_MODE", "fullscreen")));
    }

    #[test]
    fn tool_plans_use_subcommands() {
        let exe = Path::new("/x/soc-wall");
        let sub = |a| plan(a, exe).map(|l| l.argv.last().cloned());
        assert_eq!(sub(Action::Setup), Some(Some(OsString::from("setup-gui"))));
        assert_eq!(sub(Action::Appearance), Some(Some(OsString::from("appearance"))));
        assert_eq!(sub(Action::Credentials), Some(Some(OsString::from("credentials"))));
        assert!(plan(Action::Install, exe).is_none() && plan(Action::Uninstall, exe).is_none());
        assert!(plan(Action::Setup, exe).is_some_and(|l| l.env_set.contains(&("SOC_RETURN_TO_MENU", "1"))));
    }

    #[test]
    fn elevated_argv_shapes() {
        let (knobs, extra) = action_knobs(Action::Install, "kiosk", false);
        assert_eq!(knobs, vec!["INSTALL_MODE=kiosk".to_string()]);
        let s = Path::new("/opt/soc-wall/install.sh");
        assert_eq!(
            elevated_argv(&Elevation::Pkexec, &knobs, s, &extra),
            os(&["pkexec", "env", "INSTALL_MODE=kiosk", "/opt/soc-wall/install.sh"])
        );
        assert_eq!(
            elevated_argv(&Elevation::Terminal("xterm".into()), &knobs, s, &extra),
            os(&["xterm", "-e", "sudo", "env", "INSTALL_MODE=kiosk", "/opt/soc-wall/install.sh"])
        );
        let (k2, e2) = action_knobs(Action::Uninstall, "desktop", true);
        assert!(k2.is_empty());
        let u = Path::new("/opt/soc-wall/uninstall.sh");
        assert_eq!(
            elevated_argv(&Elevation::Pkexec, &k2, u, &e2),
            os(&["pkexec", "env", "/opt/soc-wall/uninstall.sh", "--force", "--purge"])
        );
        assert_eq!(
            elevated_argv(&Elevation::Fake("/t/fake".into()), &k2, u, &e2),
            os(&["/t/fake", "--force", "--purge"])
        );
    }

    #[test]
    fn manual_hint_quotes_and_guards() {
        let (knobs, extra) = action_knobs(Action::Install, "desktop", false);
        assert_eq!(
            manual_hint(&knobs, Path::new("/opt/a b/install.sh"), &extra),
            "sudo INSTALL_MODE=desktop '/opt/a b/install.sh'"
        );
        assert_eq!(guard_path(Path::new("-rf")), Path::new("./-rf"));
        assert_eq!(guard_path(Path::new("/abs")), Path::new("/abs"));
    }

    #[test]
    fn root_resolution() {
        assert_eq!(find_root(Some("/srv/soc"), None), PathBuf::from("/srv/soc"));
        assert_eq!(find_root(None, Some(Path::new("/nonexistent/zz/soc-wall"))), PathBuf::from("/opt/soc-wall"));
        let base = std::env::temp_dir().join(format!("soc-menu-root-{}", std::process::id()));
        let bin = base.join("bin");
        assert!(std::fs::create_dir_all(&bin).is_ok());
        assert!(std::fs::write(base.join("install.sh"), b"#!/bin/sh\n").is_ok());
        assert_eq!(find_root(None, Some(&bin.join("soc-wall"))), base);
        let _cleanup = std::fs::remove_dir_all(&base); // audit-allow: best-effort test cleanup
    }

    #[test]
    fn spawn_failure_is_reported() {
        let err = spawn_detached(&os(&["/nonexistent/definitely-not-here"]), &[], &[], None);
        assert!(err.is_err_and(|e| e.0.contains("could not launch")));
        assert!(spawn_detached(&[], &[], &[], None).is_err());
    }
}
