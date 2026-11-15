//! Facts about the configured wall for the session scripts.
//!
//! The Wayland session script picks its compositor from two facts: `cage`
//! (one fullscreen client) when the layout resolves to a single grid window
//! and every panel is WebKit, `labwc` otherwise. The output is `eval`ed by a
//! shell, so it is built only from closed enums and fixed digits — no config
//! string ever reaches it.

use soc_core::{Backend, Config, Engine, Layout};

/// What the session script needs to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    /// `display.layout` resolved for a Wayland backend.
    pub layout: Layout,
    /// Whether every panel uses the WebKit engine.
    pub all_webkit: bool,
}

impl SessionInfo {
    /// The answer when the config cannot be loaded: one window per panel
    /// under labwc works for any wall, so the session can still start (the
    /// host then reports the config error properly).
    pub const SAFE_DEFAULT: SessionInfo = SessionInfo { layout: Layout::Windows, all_webkit: false };

    /// The `key=value` lines the session script evaluates.
    pub fn render(&self) -> String {
        format!("layout={}\nall_webkit={}\n", self.layout.as_str(), u8::from(self.all_webkit))
    }
}

/// The session facts for `conf`, or the safe defaults without one.
pub fn session_info(conf: Option<&Config>) -> SessionInfo {
    match conf {
        None => SessionInfo::SAFE_DEFAULT,
        Some(conf) => SessionInfo {
            layout: conf.resolve_layout(Backend::Wayland),
            all_webkit: conf.panels.iter().all(|p| p.engine == Engine::Webkit),
        },
    }
}

/// `session-info`: print the facts for the config the caller loaded (or
/// failed to load — the reason goes to stderr as a comment). Always exits 0.
pub fn session_info_main<E: std::fmt::Display>(conf: Result<&Config, E>) -> i32 {
    let info = match conf {
        Ok(conf) => session_info(Some(conf)),
        Err(e) => {
            eprintln!("# session-info: {e}");
            session_info(None)
        }
    };
    print!("{}", info.render());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fixture, wall_basic, wall_notunnel, wall_rich};

    #[test]
    fn output_is_identical_to_the_python_script() {
        assert_eq!(session_info(Some(&wall_basic())).render(), fixture("basic.session-info.txt"));
        assert_eq!(session_info(Some(&wall_rich())).render(), fixture("rich.session-info.txt"));
        assert_eq!(session_info(Some(&wall_notunnel())).render(), fixture("notunnel.session-info.txt"));
    }

    #[test]
    fn a_chromium_panel_needs_per_window_placement() {
        let info = session_info(Some(&wall_basic()));
        assert_eq!(info, SessionInfo { layout: Layout::Windows, all_webkit: false });
    }

    #[test]
    fn an_explicit_layout_is_kept() {
        let mut conf = wall_notunnel();
        conf.display.layout = Layout::Windows;
        assert_eq!(session_info(Some(&conf)), SessionInfo { layout: Layout::Windows, all_webkit: true });
        conf.display.layout = Layout::Single;
        assert_eq!(session_info(Some(&conf)).render(), "layout=single\nall_webkit=1\n");
    }

    #[test]
    fn safe_defaults_without_a_config() {
        assert_eq!(session_info(None).render(), "layout=windows\nall_webkit=0\n");
    }

    #[test]
    fn output_is_safe_to_eval() {
        for conf in [wall_basic(), wall_rich(), wall_notunnel()] {
            let text = session_info(Some(&conf)).render();
            assert!(
                text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_=\n".contains(&b)),
                "{text:?}"
            );
        }
    }
}
