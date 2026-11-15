//! Who may open and save the on-screen settings — the access rules as pure
//! functions, plus thin wrappers that read the two environment switches.

use soc_core::env::parse_bool;

/// Whether the wall insists on a settings credential (`SOC_CONFIG_REQUIRE_PIN`).
/// Production units bake `1`; dev leaves it unset. A value that is set but
/// unparseable counts as required: this gate fails closed.
pub fn require_pin(raw: Option<&str>) -> bool {
    let set = raw.is_some_and(|r| !r.trim().is_empty());
    parse_bool(raw.map(str::to_string), "SOC_CONFIG_REQUIRE_PIN", set)
}

/// [`require_pin`] over the process environment.
pub fn require_pin_from_env() -> bool {
    require_pin(std::env::var("SOC_CONFIG_REQUIRE_PIN").ok().as_deref())
}

/// Whether the on-screen settings exist at all (`SOC_ONSCREEN_CONFIG`). Unset
/// or empty means yes. Any value that is not a recognised "on" turns them off:
/// the Python wall only honoured the exact string `0`, so `false` or `off` —
/// what an admin would naturally write — silently left the window enabled.
pub fn onscreen_config_enabled(raw: Option<&str>) -> bool {
    match raw.map(str::trim) {
        None | Some("") => true,
        Some(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// [`onscreen_config_enabled`] over the process environment.
pub fn onscreen_config_enabled_from_env() -> bool {
    onscreen_config_enabled(std::env::var("SOC_ONSCREEN_CONFIG").ok().as_deref())
}

/// Whether the settings form opens without asking for a code.
///
/// * dev, nothing enrolled — open (convenience);
/// * a credential is enrolled — always gated;
/// * production (`require_pin`) — always gated, even with nothing enrolled, so
///   a passer-by cannot reach the config surface.
pub fn gate_unlocked(require_pin: bool, credential_set: bool) -> bool {
    !require_pin && !credential_set
}

/// Why the gate cannot be opened by any code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateBlock {
    /// `SOC_ONSCREEN_CONFIG` turned the window off.
    Disabled,
    /// The wall requires a credential and none is enrolled.
    NothingEnrolled,
}

impl GateBlock {
    /// The text for the PIN page.
    pub fn message(self) -> &'static str {
        match self {
            GateBlock::Disabled => "On-screen settings are disabled on this wall (SOC_ONSCREEN_CONFIG=0).",
            GateBlock::NothingEnrolled => {
                "This wall requires a Settings PIN or TOTP and none is enrolled, so this window cannot open. An \
                 administrator has to enrol one first."
            }
        }
    }
}

/// Whether the gate is shut for good (`None`: a correct code opens it).
pub fn gate_block(enabled: bool, require_pin: bool, credential_set: bool) -> Option<GateBlock> {
    if !enabled {
        Some(GateBlock::Disabled)
    } else if require_pin && !credential_set {
        Some(GateBlock::NothingEnrolled)
    } else {
        None
    }
}

/// Whether Apply may write. Re-checked at save time, not just when the window
/// opened: a credential can have been removed since.
pub fn may_save(enabled: bool, unlocked: bool, require_pin: bool, credential_set: bool) -> bool {
    enabled && unlocked && (credential_set || !require_pin)
}

/// Whether one of the two settings credentials may be removed: on a wall that
/// requires one, the last cannot go — the form could never be reopened.
pub fn keeps_a_credential(require_pin: bool, other_is_set: bool) -> bool {
    !require_pin || other_is_set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_truth_table() {
        assert!(gate_unlocked(false, false));
        assert!(!gate_unlocked(false, true));
        assert!(!gate_unlocked(true, false));
        assert!(!gate_unlocked(true, true));
    }

    #[test]
    fn require_pin_values() {
        assert!(!require_pin(None));
        assert!(require_pin(Some("1")));
        assert!(!require_pin(Some("0")));
        assert!(require_pin(Some("true")));
        assert!(!require_pin(Some("")));
        assert!(!require_pin(Some("  ")));
    }

    #[test]
    fn require_pin_fails_closed_on_garbage() {
        assert!(require_pin(Some("maybe")));
        assert!(require_pin(Some("2")));
    }

    #[test]
    fn onscreen_switch_fails_closed() {
        for on in [None, Some(""), Some(" "), Some("1"), Some("TRUE"), Some("on")] {
            assert!(onscreen_config_enabled(on), "{on:?}");
        }
        for off in ["0", " 0 ", "false", "off", "no", "disabled", "2"] {
            assert!(!onscreen_config_enabled(Some(off)), "{off:?}");
        }
    }

    #[test]
    fn blocks_and_save_rules() {
        assert_eq!(gate_block(false, false, true), Some(GateBlock::Disabled));
        assert_eq!(gate_block(true, true, false), Some(GateBlock::NothingEnrolled));
        assert_eq!(gate_block(true, true, true), None);
        assert_eq!(gate_block(true, false, false), None);
        assert!(GateBlock::Disabled.message().contains("disabled"));
        assert!(GateBlock::NothingEnrolled.message().contains("none is enrolled"));

        assert!(may_save(true, true, false, false));
        assert!(may_save(true, true, true, true));
        assert!(!may_save(true, true, true, false), "the last credential went away");
        assert!(!may_save(true, false, false, false), "still behind the gate");
        assert!(!may_save(false, true, false, true), "disabled");

        assert!(keeps_a_credential(false, false));
        assert!(keeps_a_credential(true, true));
        assert!(!keeps_a_credential(true, false));
    }
}
