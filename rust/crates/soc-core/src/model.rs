//! The wall's data model: what `panels.yaml` describes once validated.

use crate::dict::{Dict, DictExt};

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }
            pub fn parse(s: &str) -> Option<$name> {
                match s { $($text => Some($name::$variant),)+ _ => None }
            }
            /// The accepted spellings, sorted, for error messages.
            pub fn names() -> Vec<&'static str> {
                let mut v = vec![$($text),+];
                v.sort_unstable();
                v
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

str_enum!(
    /// Which browser engine renders a panel.
    Engine { Webkit => "webkit", Chromium => "chromium" }
);
str_enum!(
    /// How a panel's URL is reached.
    Mode { Direct => "direct", Tunnel => "tunnel" }
);
str_enum!(
    /// How the grid is realised on screen.
    Layout { Auto => "auto", Windows => "windows", Single => "single" }
);
str_enum!(
    /// Session keep-alive strategy.
    KeepAliveStrategy { Reload => "reload", Click => "click", Xhr => "xhr", None => "none" }
);
str_enum!(
    /// VPN backend.
    VpnKind { Fortinet => "fortinet", Openvpn => "openvpn", Wireguard => "wireguard", Inode => "inode" }
);
str_enum!(
    /// Display server the session runs on.
    Backend { X11 => "x11", Wayland => "wayland" }
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepAlive {
    pub strategy: KeepAliveStrategy,
    pub interval_sec: u32,
    pub url: Option<String>,
    pub target: Option<String>,
}

impl Default for KeepAlive {
    fn default() -> Self {
        KeepAlive { strategy: KeepAliveStrategy::None, interval_sec: 600, url: None, target: None }
    }
}

/// An on-screen rectangle in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// One tile of the wall.
#[derive(Debug, Clone, PartialEq)]
pub struct Panel {
    pub id: String,
    pub engine: Engine,
    /// `(col, row)`, 0-based.
    pub grid: (u32, u32),
    pub mode: Mode,
    /// Vault login item; empty means a display-only panel (no auto-login).
    pub vault_item: String,
    /// CSS selectors for the login form (`user`, `pass`, `submit`).
    pub selectors: Dict,
    pub login_marker: String,
    pub keepalive: KeepAlive,
    /// Set for `mode: direct`.
    pub url: Option<String>,
    /// Set for `mode: tunnel` (`local_port`, `remote_host`, `remote_port`).
    pub tunnel: Option<Dict>,
    pub path: String,
    pub scheme: String,
    /// Use the global proxy (when one is enabled).
    pub proxy: bool,
    /// Display name (defaults to the id).
    pub title: String,
    /// Accept self-signed TLS (trusted LAN only).
    pub allow_insecure: bool,
    /// Keep WebGL/WebAudio/`<video>` (off by default to save RAM/GPU).
    pub allow_media: bool,
    pub tenant: String,
    /// Persist cookies + web storage so a session survives a wall restart.
    pub persist: bool,
    pub user_agent: Option<String>,
    /// Extra allowed top-level navigation domains (`*.example.com` ok).
    pub allow: Vec<String>,
    pub block_trackers: bool,
    /// Tracker hosts this panel may load anyway.
    pub unblock: Vec<String>,
    /// Click-zone fallback for auto-login: optional `user`/`pass`/`submit`
    /// entries, each `{x_pct, y_pct}` in 0.0..=1.0.
    pub login_zones: Dict,
    pub geometry: Option<Geometry>,
}

impl Panel {
    /// A panel with every knob at its default.
    pub fn new(id: &str) -> Panel {
        Panel {
            id: id.to_string(),
            engine: Engine::Webkit,
            grid: (0, 0),
            mode: Mode::Direct,
            vault_item: String::new(),
            selectors: Dict::new(),
            login_marker: String::new(),
            keepalive: KeepAlive::default(),
            url: None,
            tunnel: None,
            path: "/".into(),
            scheme: "http".into(),
            proxy: true,
            title: String::new(),
            allow_insecure: false,
            allow_media: false,
            tenant: String::new(),
            persist: true,
            user_agent: None,
            allow: Vec::new(),
            block_trackers: true,
            unblock: Vec::new(),
            login_zones: Dict::new(),
            geometry: None,
        }
    }

    /// The X11 `WM_CLASS` / Wayland `app_id` the window manager places by.
    pub fn wmclass(&self) -> String {
        format!("soc-{}", self.id)
    }

    pub fn display_name(&self) -> &str {
        if self.title.is_empty() { &self.id } else { &self.title }
    }

    /// A tunnel panel always resolves; a direct panel needs a URL (which can be
    /// set later from the on-screen config, so it may start empty).
    pub fn configured(&self) -> bool {
        self.mode == Mode::Tunnel || self.url.as_deref().is_some_and(|u| !u.is_empty())
    }

    /// The URL the engine actually loads. Never panics: live reconfiguration
    /// can flip `mode` or null out `tunnel`, and this is read while repainting.
    pub fn effective_url(&self) -> String {
        match self.mode {
            Mode::Tunnel => match self.tunnel_local_port() {
                Some(lp) => format!("{}://127.0.0.1:{lp}{}", self.scheme, self.path),
                None => String::new(),
            },
            Mode::Direct => self.url.clone().unwrap_or_default(), // audit-allow: default is the intended fallback
        }
    }

    /// Inject credentials only when a vault item is configured.
    pub fn auto_login(&self) -> bool {
        !self.vault_item.is_empty()
    }

    pub fn tunnel_local_port(&self) -> Option<u16> {
        if self.mode != Mode::Tunnel {
            return None;
        }
        let lp = self.tunnel.as_ref()?.get("local_port")?.as_u64()?;
        u16::try_from(lp).ok().filter(|p| *p != 0)
    }
}

/// Outbound HTTP(S)/SOCKS proxy for the panel browsers. Authentication is
/// vault-backed: the credentials are answered to the proxy's challenge in
/// memory and never appear in the URL, on a command line, or on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyCfg {
    pub enabled: bool,
    /// `scheme://host:port` — no userinfo.
    pub url: String,
    pub vault_item: String,
    pub ignore_hosts: Vec<String>,
}

impl ProxyCfg {
    /// The effective bypass list: configured hosts + loopback (tunnels, CDP
    /// and the local vault must never be routed through a corporate proxy).
    pub fn effective_ignore_hosts(&self) -> Vec<String> {
        let mut out = self.ignore_hosts.clone();
        for h in ["localhost", "127.0.0.1", "::1"] {
            if !self.ignore_hosts.iter().any(|x| x == h) {
                out.push(h.to_string());
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayCfg {
    pub auto: bool,
    pub width: i32,
    pub height: i32,
    pub cols: u32,
    pub rows: u32,
    pub gap: i32,
    pub layout: Layout,
    /// `false` -> windowed (lives on the desktop).
    pub fullscreen: bool,
}

impl Default for DisplayCfg {
    fn default() -> Self {
        DisplayCfg {
            auto: true,
            width: 1920,
            height: 1080,
            cols: 2,
            rows: 2,
            gap: 0,
            layout: Layout::Auto,
            fullscreen: true,
        }
    }
}

/// Wall-wide renderer security defaults. Every field defaults to the safe/on
/// value, so a config that omits the block is fully hardened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCfg {
    /// Gate top-level navigation to the allowlist.
    pub nav_allowlist: bool,
    /// Extra allowed domains added to every panel.
    pub allow: Vec<String>,
    /// Global default for the per-panel knob.
    pub block_trackers: bool,
    /// Extra SSO/redirect domains on top of the bundled list.
    pub sso_allow: Vec<String>,
}

impl Default for SecurityCfg {
    fn default() -> Self {
        SecurityCfg { nav_allowlist: true, allow: Vec::new(), block_trackers: true, sso_allow: Vec::new() }
    }
}

/// A validated wall configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Config {
    pub display: DisplayCfg,
    pub panels: Vec<Panel>,
    pub tunnel: Dict,
    /// Every configured VPN (any backend), each with a stable `name`.
    pub vpns: Vec<Dict>,
    pub proxy: ProxyCfg,
    pub security: SecurityCfg,
    /// Non-fatal findings (unknown keys, risky settings) for the log.
    pub warnings: Vec<String>,
}

impl Config {
    /// The primary VPN (the first entry), if any.
    pub fn vpn(&self) -> Option<&Dict> {
        self.vpns.first()
    }

    pub fn panel(&self, id: &str) -> Option<&Panel> {
        self.panels.iter().find(|p| p.id == id)
    }

    /// VPNs with `enabled: true`.
    pub fn enabled_vpns(&self) -> impl Iterator<Item = &Dict> {
        self.vpns.iter().filter(|v| v.truthy("enabled"))
    }

    /// Resolve `display.layout` for the running backend. `auto` keeps one
    /// window per panel on X11 (the WM places them) and prefers the single
    /// fullscreen grid on Wayland — where clients cannot position their own
    /// windows — unless a Chromium panel needs its own OS window.
    pub fn resolve_layout(&self, backend: Backend) -> Layout {
        match self.display.layout {
            Layout::Auto => {
                if backend == Backend::Wayland && self.panels.iter().all(|p| p.engine == Engine::Webkit) {
                    Layout::Single
                } else {
                    Layout::Windows
                }
            }
            fixed => fixed,
        }
    }
}

/// Map a `(col, row)` grid cell to an on-screen rectangle. The gap is capped so
/// the grid always fits: an unbounded gap could drive the cell size to zero or
/// negative, and a non-positive window size crashes the compositor.
pub fn compute_geometry(disp: &DisplayCfg, grid: (u32, u32)) -> Geometry {
    let cols = i64::from(disp.cols.max(1));
    let rows = i64::from(disp.rows.max(1));
    let (width, height) = (i64::from(disp.width), i64::from(disp.height));
    let mut gap = i64::from(disp.gap).max(0);
    if cols > 1 {
        gap = gap.min((width - cols).div_euclid(cols - 1));
    }
    if rows > 1 {
        gap = gap.min((height - rows).div_euclid(rows - 1));
    }
    let gap = gap.max(0);
    let cell_w = ((width - gap * (cols - 1)).div_euclid(cols)).max(1);
    let cell_h = ((height - gap * (rows - 1)).div_euclid(rows)).max(1);
    let clamp = |v: i64| i32::try_from(v).unwrap_or(if v < 0 { i32::MIN } else { i32::MAX });
    Geometry {
        x: clamp(i64::from(grid.0) * (cell_w + gap)),
        y: clamp(i64::from(grid.1) * (cell_h + gap)),
        w: clamp(cell_w),
        h: clamp(cell_h),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn geometry_of_a_2x2_grid() {
        let d = DisplayCfg::default();
        assert_eq!(compute_geometry(&d, (0, 0)), Geometry { x: 0, y: 0, w: 960, h: 540 });
        assert_eq!(compute_geometry(&d, (1, 1)), Geometry { x: 960, y: 540, w: 960, h: 540 });
    }

    #[test]
    fn geometry_with_gap() {
        let d = DisplayCfg { gap: 10, ..DisplayCfg::default() };
        assert_eq!(compute_geometry(&d, (1, 0)), Geometry { x: 965, y: 0, w: 955, h: 535 });
    }

    #[test]
    fn absurd_gap_never_yields_a_non_positive_cell() {
        let d = DisplayCfg { gap: 1_000_000, ..DisplayCfg::default() };
        let g = compute_geometry(&d, (1, 1));
        assert!(g.w >= 1 && g.h >= 1, "{g:?}");
        let tiny = DisplayCfg { width: 1, height: 1, cols: 4, rows: 4, gap: 50, ..DisplayCfg::default() };
        let g = compute_geometry(&tiny, (3, 3));
        assert!(g.w >= 1 && g.h >= 1, "{g:?}");
    }

    #[test]
    fn effective_url_direct_and_tunnel() {
        let mut p = Panel::new("p1");
        p.url = Some("http://10.0.0.1/".into());
        assert_eq!(p.effective_url(), "http://10.0.0.1/");
        assert!(p.configured());

        p.mode = Mode::Tunnel;
        p.path = "/login".into();
        assert_eq!(p.effective_url(), "", "tunnel without a mapping must not panic");
        p.tunnel = json!({"local_port": 19103}).as_object().cloned();
        assert_eq!(p.effective_url(), "http://127.0.0.1:19103/login");
        assert_eq!(p.tunnel_local_port(), Some(19103));
    }

    #[test]
    fn unconfigured_direct_panel() {
        let p = Panel::new("p1");
        assert!(!p.configured());
        assert!(!p.auto_login());
        assert_eq!(p.display_name(), "p1");
        assert_eq!(p.wmclass(), "soc-p1");
    }

    #[test]
    fn layout_resolution() {
        let mut c = Config { panels: vec![Panel::new("a"), Panel::new("b")], ..Config::default() };
        assert_eq!(c.resolve_layout(Backend::X11), Layout::Windows);
        assert_eq!(c.resolve_layout(Backend::Wayland), Layout::Single);
        c.panels[1].engine = Engine::Chromium;
        assert_eq!(c.resolve_layout(Backend::Wayland), Layout::Windows);
        c.display.layout = Layout::Single;
        assert_eq!(c.resolve_layout(Backend::X11), Layout::Single);
    }

    #[test]
    fn proxy_bypass_always_includes_loopback() {
        let p = ProxyCfg { ignore_hosts: vec!["*.corp.lan".into(), "localhost".into()], ..ProxyCfg::default() };
        assert_eq!(p.effective_ignore_hosts(), vec!["*.corp.lan", "localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn enum_round_trip() {
        for e in Engine::ALL {
            assert_eq!(Engine::parse(e.as_str()), Some(*e));
        }
        assert_eq!(VpnKind::parse("nope"), None);
        assert_eq!(Layout::names(), vec!["auto", "single", "windows"]);
    }
}
