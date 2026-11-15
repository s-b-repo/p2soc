//! Test helpers: private scratch directories and hand-built configs (config
//! loading lives in another module, so tests construct `Config` directly).

use soc_core::{Config, Dict, DisplayCfg, Mode, Panel, compute_geometry};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// A unique 0700 directory removed on drop. Each test gets its own, so tests
/// run in parallel without sharing state.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "soc-sys-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).expect("create test dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Create `rel` (and its parents) with `text`; returns the full path.
    pub fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(&p, text).expect("write");
        p
    }

    /// Sorted names directly inside the directory.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.0)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A JSON object literal as a [`Dict`].
pub fn dict(v: serde_json::Value) -> Dict {
    v.as_object().cloned().expect("object literal")
}

/// A direct panel at `grid` with its geometry computed like the loader does.
pub fn panel(display: &DisplayCfg, id: &str, grid: (u32, u32)) -> Panel {
    let mut p = Panel::new(id);
    p.grid = grid;
    p.url = Some(format!("http://10.0.0.1/{id}"));
    p.geometry = Some(compute_geometry(display, grid));
    p
}

/// A tunnel panel forwarding `local` to `host:remote`.
pub fn tunnel_panel(display: &DisplayCfg, id: &str, grid: (u32, u32), local: u16, host: &str, remote: u16) -> Panel {
    let mut p = panel(display, id, grid);
    p.mode = Mode::Tunnel;
    p.url = None;
    p.tunnel = Some(dict(serde_json::json!({"local_port": local, "remote_host": host, "remote_port": remote})));
    p
}

/// A config with the given display, panels and `tunnel:` section.
pub fn config(display: DisplayCfg, panels: Vec<Panel>, tunnel: serde_json::Value) -> Config {
    Config { display, panels, tunnel: dict(tunnel), ..Config::default() }
}

/// Where the Python-generated expectations live.
pub fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

/// `tests/fixtures/wall-basic.yaml` as the loader would return it.
pub fn wall_basic() -> Config {
    let d = DisplayCfg::default();
    let mut p3 = tunnel_panel(&d, "p3", (0, 1), 19103, "10.20.0.7", 8443);
    p3.engine = soc_core::Engine::Chromium;
    let panels = vec![panel(&d, "p1", (0, 0)), panel(&d, "p2", (1, 0)), p3, panel(&d, "p4", (1, 1))];
    config(
        d,
        panels,
        serde_json::json!({
            "enabled": true,
            "jump_host": "tunneluser@jump.example.net",
            "identity": "/etc/soc-display/keys/tunnel_ed25519",
            "extra_forwards": [],
            "host_key_checking": "yes",
            "known_hosts": "/etc/soc-display/keys/known_hosts",
        }),
    )
}

/// `tests/fixtures/wall-rich.yaml` as the loader would return it.
pub fn wall_rich() -> Config {
    let d = DisplayCfg { auto: false, width: 2560, height: 1440, cols: 3, rows: 2, gap: 8, ..DisplayCfg::default() };
    let panels = vec![
        tunnel_panel(&d, "alpha", (0, 0), 19101, "fd00::7", 443),
        tunnel_panel(&d, "beta_2", (1, 0), 19102, "grafana.internal", 3000),
        panel(&d, "gamma-3", (2, 1)),
    ];
    config(
        d,
        panels,
        serde_json::json!({
            "enabled": true,
            "jump_host": "soc@jump.example.net",
            "identity": "~/keys/id_ed25519",
            "known_hosts": "~/kh",
            "host_key_checking": "accept-new",
            "extra_forwards": ["127.0.0.1:19200:10.0.0.9:443", "[::1]:19201:[fd00::9]:8443"],
        }),
    )
}

/// `tests/fixtures/wall-notunnel.yaml` as the loader would return it.
pub fn wall_notunnel() -> Config {
    let d = DisplayCfg { width: 1280, height: 720, cols: 2, rows: 1, ..DisplayCfg::default() };
    let panels = vec![panel(&d, "left", (0, 0)), panel(&d, "right", (1, 0))];
    config(d, panels, serde_json::json!({"enabled": false, "jump_host": "u@jump"}))
}
