//! Where the vault master password comes from.
//!
//! The master (which derives the account key) must not live in a plaintext
//! `.env`. It is resolved from one of three sources, chosen by
//! `$SOC_MASTER_SOURCE` (default `auto`):
//!
//! * `sealed` — the host-bound seal ([`SecretStore`]). The default for
//!   unattended kiosks: no login session, wallet or prompt is needed, so the
//!   wall self-unlocks at boot.
//! * `secret-service` — the freedesktop Secret Service via `secret-tool`
//!   (KWallet, GNOME Keyring, KeePassXC). The wallet must be running and
//!   unlocked.
//! * `env` — `$SOC_VAULT_PASSWORD`. Dev / seeding only; warns when used.
//! * `auto` — sealed (if a complete seal exists) → secret-service (if
//!   `secret-tool` is present and has the item) → env.
//!
//! Resolution never fails for a missing or broken source: it yields `None`
//! and writes a one-line note to stderr, so a locked wallet or absent tool
//! never wedges the boot. Storing does return a typed error — it is only
//! called from setup, which shows it to the operator.

use crate::secret_tool::{Attrs, SecretTool, SecretToolError};
use crate::store::SecretStore;
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroizing;

const LABEL: &str = "SOC wall vault master";

/// One place a master password can come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasterSource {
    Auto,
    Sealed,
    SecretService,
    Env,
}

impl MasterSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            MasterSource::Auto => "auto",
            MasterSource::Sealed => "sealed",
            MasterSource::SecretService => "secret-service",
            MasterSource::Env => "env",
        }
    }
}

impl fmt::Display for MasterSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MasterSource {
    type Err = MasterSourceError;

    fn from_str(s: &str) -> Result<MasterSource, MasterSourceError> {
        match s.trim() {
            "" | "auto" => Ok(MasterSource::Auto),
            "sealed" => Ok(MasterSource::Sealed),
            "secret-service" => Ok(MasterSource::SecretService),
            "env" => Ok(MasterSource::Env),
            other => Err(MasterSourceError::UnknownSource(other.chars().take(40).collect())),
        }
    }
}

/// Why a source could not be selected or written. Never contains the master.
#[derive(Debug)]
pub enum MasterSourceError {
    /// `$SOC_MASTER_SOURCE` names no known source.
    UnknownSource(String),
    /// Refusing to store an empty master password.
    EmptyMaster,
    /// The source cannot be written through this API: `sealed` needs the
    /// PIN + host-key flow of [`SecretStore::seal`], and `env`/`auto` are
    /// read-only — the guarantee that no production flow writes the master to
    /// a file.
    NotWritable(MasterSource),
    /// The wallet refused or could not be reached.
    SecretService(SecretToolError),
}

impl fmt::Display for MasterSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MasterSourceError::UnknownSource(name) => {
                write!(f, "unknown SOC_MASTER_SOURCE {name:?} (expected: auto|sealed|secret-service|env)")
            }
            MasterSourceError::EmptyMaster => f.write_str("refusing to store an empty master password"),
            MasterSourceError::NotWritable(MasterSource::Sealed) => f.write_str(
                "the 'sealed' source is written by first-run setup (one-time PIN + host-bound seal), \
                 not by store_master()",
            ),
            MasterSourceError::NotWritable(source) => write!(
                f,
                "the '{source}' source is read-only; refusing to write a plaintext master to any file \
                 (writable: secret-service)"
            ),
            MasterSourceError::SecretService(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MasterSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MasterSourceError::SecretService(e) => Some(e),
            _ => None,
        }
    }
}

/// The fixed attribute pair the master is stored under unless
/// `$SOC_SECRET_ATTRS` overrides it.
pub fn default_attrs() -> Attrs {
    vec![("service".into(), "soc-wall".into()), ("account".into(), "vault-master".into())]
}

/// Parse `$SOC_SECRET_ATTRS` (space-separated `key=value` pairs; a repeated
/// key keeps its last value). `None` if it holds no usable pair.
pub fn parse_attrs(raw: &str) -> Option<Attrs> {
    let mut attrs: Attrs = Vec::new();
    for token in raw.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else { continue };
        if key.is_empty() {
            continue;
        }
        match attrs.iter_mut().find(|(k, _)| k == key) {
            Some(existing) => existing.1 = value.to_string(),
            None => attrs.push((key.to_string(), value.to_string())),
        }
    }
    (!attrs.is_empty()).then_some(attrs)
}

/// Resolves the master password from the configured source.
#[derive(Clone)]
pub struct MasterResolver {
    source: MasterSource,
    store: SecretStore,
    secret_tool: SecretTool,
    attrs: Attrs,
    env_password: Option<Zeroizing<String>>,
}

impl fmt::Debug for MasterResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterResolver")
            .field("source", &self.source)
            .field("store", &self.store)
            .field("secret_tool", &self.secret_tool)
            .field("attrs", &self.attrs)
            .field("env_password", &self.env_password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl MasterResolver {
    /// A resolver over `store` that reads nothing from the environment:
    /// source `auto`, no `secret-tool`, no env password.
    pub fn new(store: SecretStore) -> MasterResolver {
        MasterResolver {
            source: MasterSource::Auto,
            store,
            secret_tool: SecretTool::absent(),
            attrs: default_attrs(),
            env_password: None,
        }
    }

    /// The operator's configuration: `$SOC_MASTER_SOURCE`, the store's own
    /// `SOC_*` settings, `secret-tool` from `$PATH`, `$SOC_SECRET_ATTRS` and
    /// `$SOC_VAULT_PASSWORD`. An unknown source is an error here rather than
    /// a silent fallback to some other source.
    pub fn from_env() -> Result<MasterResolver, MasterSourceError> {
        let source = std::env::var("SOC_MASTER_SOURCE").unwrap_or_default().parse()?; // audit-allow: default is the intended fallback (unset means the default source)
        let mut resolver = MasterResolver::new(SecretStore::from_env());
        resolver.source = source;
        resolver.secret_tool = SecretTool::locate();
        if let Some(attrs) = std::env::var("SOC_SECRET_ATTRS").ok().as_deref().and_then(parse_attrs) {
            resolver.attrs = attrs;
        }
        resolver.env_password = soc_core::env::env_str("SOC_VAULT_PASSWORD").map(Zeroizing::new);
        Ok(resolver)
    }

    pub fn with_source(mut self, source: MasterSource) -> MasterResolver {
        self.source = source;
        self
    }

    pub fn with_secret_tool(mut self, tool: SecretTool) -> MasterResolver {
        self.secret_tool = tool;
        self
    }

    /// Attributes to look the master up / store it under (empty keeps the
    /// current ones).
    pub fn with_attrs(mut self, attrs: Attrs) -> MasterResolver {
        if !attrs.is_empty() {
            self.attrs = attrs;
        }
        self
    }

    /// The dev/seeding password (`$SOC_VAULT_PASSWORD`).
    pub fn with_env_password(mut self, password: Option<Zeroizing<String>>) -> MasterResolver {
        self.env_password = password.filter(|p| !p.is_empty());
        self
    }

    pub fn source(&self) -> MasterSource {
        self.source
    }

    pub fn store(&self) -> &SecretStore {
        &self.store
    }

    /// The master from the configured source, or `None` (with a note on
    /// stderr saying why). Never fails: the boot path stays crash-free.
    pub fn get_master(&self) -> Option<Zeroizing<String>> {
        self.get_master_from(self.source)
    }

    /// [`MasterResolver::get_master`] from an explicit source.
    pub fn get_master_from(&self, source: MasterSource) -> Option<Zeroizing<String>> {
        self.resolve(source, &mut |note| eprintln!("mastersource: {note}"))
    }

    fn resolve(&self, source: MasterSource, note: &mut dyn FnMut(String)) -> Option<Zeroizing<String>> {
        match source {
            MasterSource::Sealed => self.sealed_master(note),
            MasterSource::SecretService => self.wallet_master(note),
            MasterSource::Env => self.env_master(note),
            MasterSource::Auto => {
                // Sealed first, so a sealed wall never reads a master from
                // anywhere else.
                if self.store.is_sealed() {
                    let master = self.sealed_master(note);
                    if master.is_none() {
                        // A seal EXISTS but did not open. Fail closed: do not
                        // silently downgrade to a weaker source (a leftover
                        // wallet entry or a dev SOC_VAULT_PASSWORD). The
                        // caller then shows the Unlock prompt, which can
                        // re-seal.
                        note(
                            "a host-bound seal exists but did not unseal (wrong machine / corrupt) — not \
                              falling back to a weaker source; re-run first-run setup to re-seal"
                                .into(),
                        );
                    }
                    return master;
                }
                if self.secret_tool.available() {
                    if let Some(master) = self.wallet_master(note) {
                        return Some(master);
                    }
                }
                self.env_master(note)
            }
        }
    }

    fn sealed_master(&self, note: &mut dyn FnMut(String)) -> Option<Zeroizing<String>> {
        if !self.store.is_sealed() {
            return None;
        }
        match self.store.unseal() {
            Ok(master) => Some(master).filter(|m| !m.is_empty()),
            Err(e) => {
                note(e.to_string());
                None
            }
        }
    }

    fn wallet_master(&self, note: &mut dyn FnMut(String)) -> Option<Zeroizing<String>> {
        match self.secret_tool.lookup(&self.attrs) {
            Ok(found) => found,
            Err(SecretToolError::Missing) => {
                note("secret-tool not found (install libsecret)".into());
                None
            }
            Err(SecretToolError::TimedOut) => {
                note("secret-tool timed out (wallet locked?)".into());
                None
            }
            Err(e) => {
                note(e.to_string());
                None
            }
        }
    }

    fn env_master(&self, note: &mut dyn FnMut(String)) -> Option<Zeroizing<String>> {
        let password = self.env_password.clone()?;
        // Loud on purpose, so an accidental production use is visible.
        note(
            "SOC_VAULT_PASSWORD from the environment is DEV/seeding only; production uses the sealed or \
              secret-service source"
                .into(),
        );
        Some(password)
    }

    /// Sources usable right now, in resolution order — for doctor / wizard
    /// reporting. A pure capability probe: it never unseals or performs a
    /// lookup, so it has no side effects and touches no secret.
    pub fn available_sources(&self) -> Vec<MasterSource> {
        let mut sources = Vec::with_capacity(3);
        if self.store.is_sealed() {
            sources.push(MasterSource::Sealed);
        }
        if self.secret_tool.available() {
            sources.push(MasterSource::SecretService);
        }
        // Always listed: the variable may be set later.
        sources.push(MasterSource::Env);
        sources
    }

    /// Persist `master` to `source`. Only `secret-service` is writable here:
    /// it hands the value to the wallet daemon over stdin, never to a file.
    pub fn store_master(&self, master: &str, source: MasterSource) -> Result<(), MasterSourceError> {
        if master.is_empty() {
            return Err(MasterSourceError::EmptyMaster);
        }
        match source {
            MasterSource::SecretService => {
                self.secret_tool.store(LABEL, &self.attrs, master).map_err(MasterSourceError::SecretService)
            }
            other => Err(MasterSourceError::NotWritable(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;
    use crate::secret_tool::testutil::fake_secret_tool;
    use std::time::Duration;

    const SEALED: &str = "SEALED-master";

    struct Fixture {
        seal_dir: TestDir,
        tool_dir: TestDir,
    }

    impl Fixture {
        fn new(sealed: bool) -> Fixture {
            let f = Fixture { seal_dir: TestDir::new("ms-seal"), tool_dir: TestDir::new("ms-tool") };
            if sealed {
                f.store().seal(SEALED, "12345678").unwrap();
            }
            f
        }

        fn store(&self) -> SecretStore {
            SecretStore::for_unit_tests(self.seal_dir.path())
        }

        /// A resolver with a fake wallet holding `wallet` and `env` set.
        fn resolver(&self, wallet: Option<&str>, env: Option<&str>) -> MasterResolver {
            let tool = SecretTool::at(fake_secret_tool(self.tool_dir.path()));
            if let Some(value) = wallet {
                std::fs::write(self.tool_dir.join("value"), value).unwrap();
            }
            MasterResolver::new(self.store())
                .with_secret_tool(tool)
                .with_env_password(env.map(|e| Zeroizing::new(e.to_string())))
        }
    }

    fn get(r: &MasterResolver, source: MasterSource) -> (Option<String>, Vec<String>) {
        let mut notes = Vec::new();
        let master = r.resolve(source, &mut |n| notes.push(n));
        (master.map(|m| m.to_string()), notes)
    }

    #[test]
    fn source_names_parse_and_unknown_ones_are_refused() {
        for source in [MasterSource::Auto, MasterSource::Sealed, MasterSource::SecretService, MasterSource::Env] {
            assert_eq!(source.as_str().parse::<MasterSource>().unwrap(), source);
        }
        assert_eq!(" sealed\n".parse::<MasterSource>().unwrap(), MasterSource::Sealed);
        assert_eq!("".parse::<MasterSource>().unwrap(), MasterSource::Auto);
        let err = "bogus".parse::<MasterSource>().unwrap_err();
        assert!(err.to_string().contains("auto|sealed|secret-service|env"));
    }

    #[test]
    fn sealed_source() {
        let f = Fixture::new(true);
        let r = f.resolver(Some("SS"), Some("ENV"));
        assert_eq!(get(&r, MasterSource::Sealed).0.as_deref(), Some(SEALED));
        let unsealed = Fixture::new(false);
        assert_eq!(get(&unsealed.resolver(None, Some("ENV")), MasterSource::Sealed), (None, vec![]));
    }

    #[test]
    fn sealed_source_degrades_with_a_note_instead_of_failing() {
        let f = Fixture::new(true);
        let wrong_host = MasterResolver::new(f.store().with_machine_id("host-B"));
        let (master, notes) = get(&wrong_host, MasterSource::Sealed);
        assert_eq!(master, None);
        assert!(notes[0].contains("wrong machine"), "{notes:?}");
    }

    #[test]
    fn secret_service_source() {
        let f = Fixture::new(false);
        assert_eq!(
            get(&f.resolver(Some("SS-master"), None), MasterSource::SecretService).0.as_deref(),
            Some("SS-master")
        );
        assert_eq!(
            get(&f.resolver(Some("  pw with spaces  "), None), MasterSource::SecretService).0.as_deref(),
            Some("  pw with spaces  ")
        );
    }

    #[test]
    fn secret_service_absent_item_tool_or_wallet_all_degrade() {
        let f = Fixture::new(false);
        assert_eq!(get(&f.resolver(None, None), MasterSource::SecretService), (None, vec![]));

        let no_tool = MasterResolver::new(f.store());
        let (master, notes) = get(&no_tool, MasterSource::SecretService);
        assert_eq!(master, None);
        assert!(notes[0].contains("secret-tool not found"));

        let locked = crate::proc::testutil::script(f.tool_dir.path(), "locked", "exec sleep 30");
        let slow = MasterResolver::new(f.store())
            .with_secret_tool(SecretTool::at(locked).with_timeout(Duration::from_millis(100)));
        let (master, notes) = get(&slow, MasterSource::SecretService);
        assert_eq!(master, None);
        assert!(notes[0].contains("timed out"));
    }

    #[test]
    fn env_source_warns_that_it_is_dev_only() {
        let f = Fixture::new(false);
        let (master, notes) = get(&f.resolver(None, Some("ENV-master")), MasterSource::Env);
        assert_eq!(master.as_deref(), Some("ENV-master"));
        assert!(notes[0].contains("DEV/seeding only"));
        assert_eq!(get(&f.resolver(None, None), MasterSource::Env), (None, vec![]));
        assert_eq!(get(&f.resolver(None, Some("")), MasterSource::Env), (None, vec![]));
    }

    #[test]
    fn auto_prefers_sealed() {
        let f = Fixture::new(true);
        assert_eq!(get(&f.resolver(Some("SS"), Some("ENV")), MasterSource::Auto).0.as_deref(), Some(SEALED));
    }

    #[test]
    fn auto_falls_through_secret_service_then_env() {
        let f = Fixture::new(false);
        assert_eq!(get(&f.resolver(Some("SS"), Some("ENV")), MasterSource::Auto).0.as_deref(), Some("SS"));
        let empty_wallet = Fixture::new(false);
        assert_eq!(get(&empty_wallet.resolver(None, Some("ENV")), MasterSource::Auto).0.as_deref(), Some("ENV"));
        let no_tool = MasterResolver::new(f.store()).with_env_password(Some(Zeroizing::new("ENV".into())));
        assert_eq!(get(&no_tool, MasterSource::Auto).0.as_deref(), Some("ENV"));
        assert_eq!(get(&MasterResolver::new(f.store()), MasterSource::Auto), (None, vec![]));
    }

    #[test]
    fn auto_fails_closed_when_a_seal_exists_but_does_not_open() {
        // Provenance: a broken seal must not be papered over by a leftover
        // wallet entry or a dev password.
        let f = Fixture::new(true);
        let r = f.resolver(Some("SS"), Some("ENV"));
        let wrong_host = MasterResolver { store: f.store().with_machine_id("host-B"), ..r };
        let (master, notes) = get(&wrong_host, MasterSource::Auto);
        assert_eq!(master, None);
        assert!(notes.iter().any(|n| n.contains("not falling back to a weaker source")), "{notes:?}");
    }

    #[test]
    fn configured_source_drives_get_master() {
        let f = Fixture::new(true);
        let r = f.resolver(None, Some("ENV"));
        assert_eq!(r.source(), MasterSource::Auto);
        assert_eq!(r.get_master().unwrap().as_str(), SEALED);
        assert_eq!(r.with_source(MasterSource::Env).get_master().unwrap().as_str(), "ENV");
    }

    #[test]
    fn available_sources_is_a_probe_that_never_unseals() {
        let f = Fixture::new(true);
        assert_eq!(
            f.resolver(None, None).available_sources(),
            [MasterSource::Sealed, MasterSource::SecretService, MasterSource::Env]
        );
        let runs = crate::kdf::counter::get();
        assert_eq!(MasterResolver::new(f.store()).available_sources(), [MasterSource::Sealed, MasterSource::Env]);
        assert_eq!(crate::kdf::counter::get(), runs, "no KDF ran: nothing was unsealed");
        let unsealed = Fixture::new(false);
        assert_eq!(MasterResolver::new(unsealed.store()).available_sources(), [MasterSource::Env]);
    }

    #[test]
    fn attrs_default_override_and_explicit() {
        assert_eq!(
            default_attrs(),
            [("service".to_string(), "soc-wall".to_string()), ("account".into(), "vault-master".into())]
        );
        let parsed = parse_attrs("service=acme account=vw extra=1 junk =nokey service=acme2").unwrap();
        let want: Attrs =
            vec![("service".into(), "acme2".into()), ("account".into(), "vw".into()), ("extra".into(), "1".into())];
        assert_eq!(parsed, want);
        assert_eq!(parse_attrs("  "), None);
        assert_eq!(parse_attrs("no-pairs here"), None);
        assert_eq!(parse_attrs("k=a=b").unwrap(), [("k".to_string(), "a=b".to_string())]);
    }

    #[test]
    fn lookup_and_store_present_the_same_attributes() {
        let f = Fixture::new(false);
        let r = f.resolver(None, None).with_attrs(vec![("service".into(), "explicit".into())]);
        r.store_master("the-master", MasterSource::SecretService).unwrap();
        let rec = std::fs::read_to_string(f.tool_dir.join("rec")).unwrap();
        let (argv, stdin) = rec.trim_end_matches('\n').split_once('\t').unwrap();
        assert_eq!(argv.split('\u{1f}').collect::<Vec<_>>(), ["store", "--label", LABEL, "service", "explicit"]);
        // The master reached the child ONLY via stdin (no leak via ps / proc).
        assert_eq!(stdin, "the-master");
        assert!(!argv.contains("the-master"));
        // Default attributes when none are given.
        let d = f.resolver(None, None).with_attrs(vec![]);
        assert_eq!(d.attrs, default_attrs());
    }

    #[test]
    fn store_master_writes_only_to_the_wallet() {
        let f = Fixture::new(false);
        let r = f.resolver(None, None);
        for refused in [MasterSource::Env, MasterSource::Sealed, MasterSource::Auto] {
            assert!(matches!(r.store_master("pw", refused), Err(MasterSourceError::NotWritable(s)) if s == refused));
        }
        assert!(matches!(r.store_master("", MasterSource::SecretService), Err(MasterSourceError::EmptyMaster)));
        assert!(!f.tool_dir.join("rec").exists());
    }

    #[test]
    fn store_master_surfaces_a_missing_tool_and_a_failed_store() {
        let f = Fixture::new(false);
        let no_tool = MasterResolver::new(f.store());
        let err = no_tool.store_master("pw", MasterSource::SecretService).unwrap_err();
        assert!(matches!(err, MasterSourceError::SecretService(SecretToolError::Missing)));
        assert!(err.to_string().contains("install libsecret"));

        let r = f.resolver(None, None);
        std::fs::write(f.tool_dir.join("store-fails"), "").unwrap();
        let err = r.store_master("pw-that-must-not-leak", MasterSource::SecretService).unwrap_err();
        assert!(err.to_string().contains("no Secret Service"));
        assert!(!format!("{err} {err:?}").contains("pw-that-must-not-leak"));
    }

    #[test]
    fn debug_output_redacts_the_env_password() {
        let f = Fixture::new(false);
        let shown = format!("{:?}", f.resolver(None, Some("ENV-master")));
        assert!(shown.contains("<redacted>") && !shown.contains("ENV-master"));
    }
}
