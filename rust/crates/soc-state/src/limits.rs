//! Bounds on what the settings form may save and what `overrides.json` may
//! feed back in. They are the same numbers the form's entries enforce; the
//! boot merge re-applies them because the file can be edited behind our back.

pub const MAX_URL_LEN: usize = 2048;
pub const MAX_TITLE_LEN: usize = 200;
pub const MAX_VAULT_ITEM_LEN: usize = 200;
pub const MAX_SELECTOR_LEN: usize = 500;
pub const MAX_MARKER_LEN: usize = 200;
pub const MAX_VPN_NAME_LEN: usize = 100;
pub const MAX_VPN_GATEWAY_LEN: usize = 253;
pub const MAX_VPN_DOMAIN_LEN: usize = 253;
pub const MAX_VPN_REALM_LEN: usize = 200;
pub const MAX_VPN_CONFIG_LEN: usize = 8192;
/// A hostname or bypass pattern.
pub const MAX_HOST_LEN: usize = 253;
/// A filesystem path typed into a form.
pub const MAX_PATH_LEN: usize = 4096;
/// List-valued settings (bypass hosts, extra forwards).
pub const MAX_LIST_ITEMS: usize = 256;
/// A config file offered to Import.
pub const MAX_IMPORT_BYTES: u64 = 1024 * 1024;
/// `overrides.json` itself: a few KiB in practice.
pub const MAX_OVERRIDES_BYTES: u64 = 1024 * 1024;
/// The on-screen display form's grid and resolution ranges; an override
/// outside them is ignored at boot.
pub const MAX_FORM_GRID: i64 = 8;
pub const MIN_FORM_PIXELS: i64 = 320;
pub const MAX_FORM_PIXELS: i64 = 16384;
/// How long a flow that must stop for a vault/PAM answer waits before giving up.
pub const VAULT_WAIT_SEC: u64 = 20;

/// Trim a form value and cut it to `max_len` characters.
pub fn sanitize_len(s: &str, max_len: usize) -> String {
    s.trim().chars().take(max_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_trims_then_truncates_by_character() {
        assert_eq!(sanitize_len("  abc  ", 10), "abc");
        assert_eq!(sanitize_len("  abcdef", 3), "abc");
        assert_eq!(sanitize_len("éèà", 2), "éè");
        assert_eq!(sanitize_len("", 2), "");
    }
}
