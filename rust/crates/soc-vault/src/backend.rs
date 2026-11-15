//! Credential backends, selected by `$SOC_VAULT_BACKEND`:
//!
//! * `native` (alias `litebw`, the default) — the in-process Vaultwarden
//!   client. Unattended unlock asks the [`MasterSource`]; no plaintext master
//!   password ever touches disk.
//! * `dev` — a JSON file, so the wall runs end-to-end without Vaultwarden.
//! * `rbw` — the legacy `rbw` CLI, still selectable where it is installed.

use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use soc_core::Login;
use soc_core::url::Url;
use zeroize::Zeroizing;

use crate::config::LitebwConfig;
use crate::error::VaultError;
use crate::fsutil::write_private_atomic;
use crate::http::sanitize;
use crate::master::MasterSource;
use crate::session::{Cipher, Session, SessionOptions};
use crate::totp;

/// What the [`Vault`](crate::Vault) facade needs from a credential store.
pub trait Backend: Send + Sync {
    /// Open the store unattended. In interactive mode with no master yet this
    /// succeeds without a session; the next read then reports
    /// [`VaultError::Locked`].
    fn unlock(&self) -> Result<(), VaultError>;

    /// Open the store with a master the operator just typed.
    fn unlock_with(
        &self,
        _master: &str, // audit-allow: default impl ignores the argument
    ) -> Result<(), VaultError> {
        Err(VaultError::Config("this vault backend cannot be unlocked interactively".into()))
    }

    /// Re-read the store so later lookups see current data.
    fn sync(&self) -> Result<(), VaultError>;

    /// Username and (non-empty) password of an item.
    fn get(&self, item: &str) -> Result<Login, VaultError>;

    /// The item's Notes, `""` when it has none or does not exist.
    fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError>;

    /// A current TOTP code for the item.
    fn code(&self, item: &str) -> Result<String, VaultError>;

    /// Delete an item. `Ok(false)` when there was nothing to delete.
    fn delete(&self, item: &str) -> Result<bool, VaultError>;

    /// Names of every item in the folder named `folder`.
    fn list_by_folder(&self, folder: &str) -> Result<Vec<String>, VaultError>;

    /// A session that can write to the vault (the credential editor, TOTP
    /// enrolment). Only the native backend has one.
    fn session(&self) -> Result<Arc<Session>, VaultError> {
        Err(VaultError::Config("this vault backend cannot write to the vault".into()))
    }
}

/// Fail when a Notes field that must carry content (a VPN config, say) is
/// blank — otherwise the failure shows up later as a parser error that never
/// mentions the vault. `purpose` names the feature that needs it.
pub fn require_notes(notes: Zeroizing<String>, item: &str, purpose: &str) -> Result<Zeroizing<String>, VaultError> {
    if !notes.trim().is_empty() {
        return Ok(notes);
    }
    let what = if purpose.is_empty() { String::new() } else { format!(" for {purpose}") };
    Err(VaultError::NotFound(format!(
        "vault item '{item}' has an empty Notes field{what} — paste the .ovpn / .conf content into the Notes \
         section of that item in Vaultwarden (web UI or the Credentials tab)."
    )))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// --------------------------------------------------------------------------- //
// Native (in-process Vaultwarden client)
// --------------------------------------------------------------------------- //

/// Settings of the native backend.
#[derive(Debug, Clone)]
pub struct NativeConfig {
    pub url: String,
    pub email: String,
    /// Only persisted for the benefit of external tools; unused here.
    pub pinentry: String,
    /// When true, a missing master is a "please unlock" signal, not an error.
    pub interactive: bool,
    /// After a failed unlock, further *implicit* unlock attempts inside this
    /// window re-report the cached failure instead of re-deriving keys and
    /// hitting the server again.
    pub reunlock_cooldown: Duration,
    /// How long a fetched item list is served before it is re-fetched. Bounds
    /// how stale a rotated password can be.
    pub sync_ttl: Duration,
    pub session: SessionOptions,
    /// Where to persist email/base_url/pinentry so the CLI agrees with the
    /// host; `None` to leave the file alone.
    pub config_path: Option<PathBuf>,
}

impl Default for NativeConfig {
    fn default() -> Self {
        NativeConfig {
            url: String::new(),
            email: String::new(),
            pinentry: String::new(),
            interactive: false,
            reunlock_cooldown: Duration::from_secs(8),
            sync_ttl: Duration::from_secs(30),
            session: SessionOptions::default(),
            config_path: None,
        }
    }
}

#[derive(Default)]
struct NativeState {
    session: Option<Arc<Session>>,
    /// The last fetched item list. Holds names and ciphertext only: secret
    /// fields are decrypted per lookup, so no plaintext lingers here.
    snapshot: Option<(Instant, Arc<Vec<Cipher>>)>,
    unlock_failure: Option<(Instant, VaultError)>,
}

/// The in-process Vaultwarden backend.
pub struct NativeBackend {
    cfg: NativeConfig,
    master: Arc<dyn MasterSource>,
    state: Mutex<NativeState>,
    /// Serialises unlock + sync so concurrent callers share one login and one
    /// fetch instead of each paying for their own.
    flight: Mutex<()>,
}

impl NativeBackend {
    pub fn new(cfg: NativeConfig, master: Arc<dyn MasterSource>) -> NativeBackend {
        NativeBackend { cfg, master, state: Mutex::new(NativeState::default()), flight: Mutex::new(()) }
    }

    /// Persist email / base_url / pinentry to the config file so the CLI path
    /// and the host path agree. Idempotent; a failed write is not fatal.
    pub fn configure(&self) {
        let Some(path) = &self.cfg.config_path else { return };
        let mut file = LitebwConfig::load(path);
        let mut changed = false;
        for (key, value) in [("email", &self.cfg.email), ("base_url", &self.cfg.url), ("pinentry", &self.cfg.pinentry)]
        {
            if !value.is_empty() && file.get(key) != value {
                file.set(key, value);
                changed = true;
            }
        }
        if changed {
            let _ = file.save(path); // audit-allow: best-effort: the config cache is rewritten on the next login
        }
    }

    fn locked_error() -> VaultError {
        VaultError::Locked("vault is locked — Vaultwarden master needed".into())
    }

    /// Log in with the master from the source. `Ok(None)` means interactive
    /// mode with no master yet.
    fn login_unattended(&self) -> Result<Option<Arc<Session>>, VaultError> {
        self.configure();
        let master = match self.master.master() {
            Ok(m) if !m.is_empty() => m,
            Ok(_) | Err(VaultError::NoMaster(_)) if self.cfg.interactive => return Ok(None),
            Ok(_) => {
                return Err(VaultError::NoMaster(
                    "no vault master password (host not sealed and no $SOC_VAULT_PASSWORD)".into(),
                ));
            }
            Err(e) => return Err(e),
        };
        Session::login(&self.cfg.url, &self.cfg.email, &master, &self.cfg.session).map(|s| Some(Arc::new(s)))
    }

    fn install(&self, session: Arc<Session>) {
        let mut state = lock(&self.state);
        state.session = Some(session);
        state.snapshot = None;
        state.unlock_failure = None;
    }

    /// The live session, logging in if there is none. Must be called with
    /// `flight` held. Implicit logins are rate-limited by the cooldown so a
    /// wrong sealed password or a refusing server cannot make every panel
    /// reload re-derive keys and re-hit the login endpoint.
    fn ensure_session(&self) -> Result<Arc<Session>, VaultError> {
        {
            let state = lock(&self.state);
            if let Some(session) = &state.session {
                return Ok(Arc::clone(session));
            }
            if let Some((at, err)) = &state.unlock_failure {
                if at.elapsed() < self.cfg.reunlock_cooldown {
                    return Err(err.clone());
                }
            }
        }
        match self.login_unattended() {
            Ok(Some(session)) => {
                self.install(Arc::clone(&session));
                Ok(session)
            }
            Ok(None) => Err(Self::locked_error()),
            Err(e) => {
                lock(&self.state).unlock_failure = Some((Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    /// Run `op` with a session. A 401 that survived the session's own token
    /// refresh means the session is dead: it is dropped and the master is
    /// asked for again, once.
    fn with_session_locked<T>(&self, op: &dyn Fn(&Session) -> Result<T, VaultError>) -> Result<T, VaultError> {
        let session = self.ensure_session()?;
        match op(&session) {
            Err(e) if e.http_status() == Some(401) => {
                {
                    let mut state = lock(&self.state);
                    state.session = None;
                    state.snapshot = None;
                }
                let session = self.ensure_session()?;
                let retried = op(&session);
                if let Err(e2) = &retried {
                    if e2.http_status() == Some(401) {
                        let mut state = lock(&self.state);
                        state.session = None;
                        state.unlock_failure = Some((Instant::now(), e2.clone()));
                    }
                }
                retried
            }
            other => other,
        }
    }

    /// Run `op` against the authenticated session, re-unlocking once if the
    /// session turns out to be dead. This is how the editor writes items.
    pub fn with_session<T>(&self, op: impl Fn(&Session) -> Result<T, VaultError>) -> Result<T, VaultError> {
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        self.with_session_locked(&op)
    }

    fn fresh_snapshot(&self) -> Option<Arc<Vec<Cipher>>> {
        let state = lock(&self.state);
        state.snapshot.as_ref().filter(|(at, _)| at.elapsed() < self.cfg.sync_ttl).map(|(_, items)| Arc::clone(items))
    }

    fn sync_locked(&self) -> Result<Arc<Vec<Cipher>>, VaultError> {
        let items = Arc::new(self.with_session_locked(&|session| session.ciphers())?);
        lock(&self.state).snapshot = Some((Instant::now(), Arc::clone(&items)));
        Ok(items)
    }

    /// The item list, re-fetched when older than `sync_ttl`. Concurrent
    /// callers (a prewarm burst) share one fetch.
    fn items(&self) -> Result<Arc<Vec<Cipher>>, VaultError> {
        if let Some(items) = self.fresh_snapshot() {
            return Ok(items);
        }
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        if let Some(items) = self.fresh_snapshot() {
            return Ok(items);
        }
        self.sync_locked()
    }
}

impl Backend for NativeBackend {
    fn unlock(&self) -> Result<(), VaultError> {
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        // An explicit unlock is never rate-limited: it is the operator (or
        // boot) asking, and its outcome replaces any cached failure.
        match self.login_unattended() {
            Ok(Some(session)) => {
                self.install(session);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => {
                lock(&self.state).unlock_failure = Some((Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    fn unlock_with(&self, master: &str) -> Result<(), VaultError> {
        if master.is_empty() {
            return Err(VaultError::NoMaster("empty master password".into()));
        }
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        match Session::login(&self.cfg.url, &self.cfg.email, master, &self.cfg.session) {
            Ok(session) => {
                self.install(Arc::new(session));
                Ok(())
            }
            Err(e) => {
                let mut state = lock(&self.state);
                state.session = None;
                state.snapshot = None;
                Err(e)
            }
        }
    }

    fn sync(&self) -> Result<(), VaultError> {
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        self.sync_locked().map(|_| ())
    }

    fn get(&self, item: &str) -> Result<Login, VaultError> {
        let items = self.items()?;
        let mut failure = None;
        // Several items may share a name (a login and its TOTP note, say):
        // the first one that actually carries a password wins.
        for cipher in items.iter().filter(|c| c.name == item && c.has_password()) {
            match cipher.password().and_then(|pw| Ok((cipher.username()?, pw))) {
                Ok((mut user, mut password)) if !password.is_empty() => {
                    return Ok(Login::new(std::mem::take(&mut *user), std::mem::take(&mut *password)));
                }
                Ok(_) => {}
                Err(e) => failure = Some(e),
            }
        }
        Err(failure
            .unwrap_or_else(|| VaultError::NotFound(format!("vault item '{item}' has no password (or not found)"))))
    }

    fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError> {
        for cipher in self.items()?.iter().filter(|c| c.name == item) {
            let notes = cipher.notes()?;
            if !notes.is_empty() {
                return Ok(notes);
            }
        }
        Ok(Zeroizing::new(String::new()))
    }

    fn code(&self, item: &str) -> Result<String, VaultError> {
        match self.items()?.iter().find(|c| c.name == item && c.has_totp()) {
            Some(cipher) => totp::generate_now(&cipher.totp()?),
            None => Err(VaultError::NotFound(format!("vault item '{item}' has no TOTP secret"))),
        }
    }

    fn delete(&self, item: &str) -> Result<bool, VaultError> {
        let deleted = self.with_session(|session| session.delete(item))?;
        if deleted {
            lock(&self.state).snapshot = None;
        }
        Ok(deleted)
    }

    /// Uncached on purpose: the settings UI calls it on demand.
    fn list_by_folder(&self, folder: &str) -> Result<Vec<String>, VaultError> {
        self.with_session(|session| session.names_in_folder(folder))
    }

    fn session(&self) -> Result<Arc<Session>, VaultError> {
        let _flight = lock(&self.flight); // audit-allow: RAII guard serialising sessions, held for the scope
        self.ensure_session()
    }
}

// --------------------------------------------------------------------------- //
// Dev (JSON file)
// --------------------------------------------------------------------------- //

/// A JSON file of `{"Item Name": {"username": .., "password": .., "notes": ..,
/// "totp": .., "folder": ..}}`, for running the wall without Vaultwarden.
pub struct DevFileBackend {
    path: PathBuf,
    data: Mutex<Option<Map<String, Value>>>,
}

impl DevFileBackend {
    pub fn new(path: impl Into<PathBuf>) -> DevFileBackend {
        DevFileBackend { path: path.into(), data: Mutex::new(None) }
    }

    fn read(path: &Path) -> Result<Map<String, Value>, VaultError> {
        let raw = std::fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => VaultError::Config(format!("dev vault file not found: {}", path.display())),
            _ => VaultError::Io(format!("cannot read dev vault file {}: {e}", path.display())),
        })?;
        match serde_json::from_slice::<Value>(&raw) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(VaultError::Config(format!("dev vault file {} is not a JSON object", path.display()))),
        }
    }

    fn with_data<T>(&self, f: impl FnOnce(&mut Map<String, Value>) -> T) -> Result<T, VaultError> {
        let mut guard = lock(&self.data);
        if guard.is_none() {
            *guard = Some(Self::read(&self.path)?);
        }
        match guard.as_mut() {
            Some(data) => Ok(f(data)),
            None => Err(VaultError::Io("dev vault data is unavailable".into())),
        }
    }

    fn field(&self, item: &str, key: &str) -> Result<Option<String>, VaultError> {
        self.with_data(|data| data.get(item).and_then(|rec| rec.get(key)).and_then(Value::as_str).map(str::to_string))
    }
}

impl Backend for DevFileBackend {
    fn unlock(&self) -> Result<(), VaultError> {
        self.with_data(|_| ())
    }

    fn sync(&self) -> Result<(), VaultError> {
        *lock(&self.data) = None;
        self.with_data(|_| ())
    }

    fn get(&self, item: &str) -> Result<Login, VaultError> {
        if !self.with_data(|data| data.get(item).is_some_and(Value::is_object))? {
            return Err(VaultError::NotFound(format!("dev vault has no item '{item}'")));
        }
        match self.field(item, "password")?.filter(|p| !p.is_empty()) {
            Some(password) => Ok(Login::new(self.field(item, "username")?.unwrap_or_default(), password)), // audit-allow: default is the intended fallback (no username)
            None => Err(VaultError::NotFound(format!("dev vault item '{item}' has no password"))),
        }
    }

    fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError> {
        Ok(Zeroizing::new(self.field(item, "notes")?.unwrap_or_default())) // audit-allow: default is the intended fallback (no notes)
    }

    fn code(&self, item: &str) -> Result<String, VaultError> {
        match self.field(item, "totp")?.filter(|t| !t.is_empty()) {
            Some(secret) => totp::generate_now(&secret),
            None => Err(VaultError::NotFound(format!("dev vault item '{item}' has no TOTP secret"))),
        }
    }

    fn delete(&self, item: &str) -> Result<bool, VaultError> {
        let rewritten = self.with_data(|data| {
            data.shift_remove(item)?;
            Some(serde_json::to_vec_pretty(&Value::Object(data.clone())))
        })?;
        let Some(encoded) = rewritten else { return Ok(false) };
        let encoded = encoded.map_err(|e| VaultError::Io(format!("cannot encode the dev vault: {e}")))?;
        // 0600 and atomic: even a dev vault holds real-looking credentials.
        write_private_atomic(&self.path, &encoded).map_err(|e| VaultError::io("cannot rewrite the dev vault", &e))?;
        Ok(true)
    }

    fn list_by_folder(&self, folder: &str) -> Result<Vec<String>, VaultError> {
        self.with_data(|data| {
            data.iter()
                .filter(|(_, rec)| rec.get("folder").and_then(Value::as_str) == Some(folder))
                .map(|(name, _)| name.clone())
                .collect()
        })
    }
}

// --------------------------------------------------------------------------- //
// rbw (legacy CLI)
// --------------------------------------------------------------------------- //

/// Is something listening at `url`'s host:port? Lets unlock say "Vaultwarden
/// is not listening" instead of relaying an opaque "connection refused".
pub fn tcp_reachable(url: &str, timeout: Duration) -> bool {
    let Ok(parsed) = Url::split(url) else { return false };
    let host = parsed.host.as_deref().unwrap_or("127.0.0.1");
    let port = parsed.port.unwrap_or(if parsed.scheme == "https" { 443 } else { 8222 });
    let Ok(addrs) = (host, port).to_socket_addrs() else { return false };
    addrs.into_iter().any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

/// Reads logins through the `rbw` CLI. The master password is rbw's business
/// (its pinentry wrapper unseals it); only item names appear in argv.
pub struct RbwBackend {
    program: PathBuf,
    email: String,
    url: String,
    pinentry: String,
    interactive: bool,
    timeout: Duration,
}

impl RbwBackend {
    pub fn new(email: &str, url: &str, pinentry: &str, interactive: bool) -> RbwBackend {
        RbwBackend {
            program: PathBuf::from("rbw"),
            email: email.to_string(),
            url: url.to_string(),
            pinentry: pinentry.to_string(),
            interactive,
            timeout: Duration::from_secs(30),
        }
    }

    /// Use a specific `rbw` executable instead of the one on `$PATH`.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> RbwBackend {
        self.program = program.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> RbwBackend {
        self.timeout = timeout;
        self
    }

    /// Run `rbw <args>` and return its trimmed stdout. With `check`, a
    /// non-zero exit is an error (its stderr is relayed, sanitised).
    fn rbw(&self, args: &[&str], check: bool) -> Result<Zeroizing<String>, VaultError> {
        let shown = sanitize(&args.join(" "));
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    VaultError::Config("rbw not found on PATH (install it or use SOC_VAULT_BACKEND=native)".into())
                }
                _ => VaultError::Backend(format!("cannot run rbw: {e}")),
            })?;
        // Drain both pipes on threads so a chatty child can never block on a
        // full pipe while we wait for it.
        let drain = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut buf = Zeroizing::new(Vec::new());
                if let Some(mut pipe) = pipe {
                    let _ = pipe.read_to_end(&mut buf); // audit-allow: best-effort: a read error just truncates the drained output
                }
                buf
            })
        };
        let stdout = drain(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let stderr = drain(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill(); // audit-allow: best-effort: the child may already have exited
                    let _ = child.wait(); // audit-allow: best-effort: reaping a killed child
                    return Err(VaultError::Backend(format!("rbw {shown} timed out")));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(15)),
                Err(e) => return Err(VaultError::Backend(format!("rbw {shown} failed: {e}"))),
            }
        };
        let out = stdout.join().unwrap_or_default(); // audit-allow: default is the intended fallback (drain thread panicked: no output)
        let err = stderr.join().unwrap_or_default(); // audit-allow: default is the intended fallback (drain thread panicked: no output)
        if check && !status.success() {
            // stderr only: stdout may hold a secret.
            let detail = sanitize(&String::from_utf8_lossy(&err));
            return Err(VaultError::Backend(format!("rbw {shown} failed: {detail}")));
        }
        Ok(Zeroizing::new(String::from_utf8_lossy(&out).trim().to_string()))
    }

    /// Idempotently point rbw at the right server / account / pinentry.
    pub fn configure(&self) -> Result<(), VaultError> {
        for (key, value) in [("email", &self.email), ("base_url", &self.url), ("pinentry", &self.pinentry)] {
            if !value.is_empty() {
                self.rbw(&["config", "set", key, value], false)?;
            }
        }
        Ok(())
    }
}

impl Backend for RbwBackend {
    fn unlock(&self) -> Result<(), VaultError> {
        if self.email.is_empty() {
            return Err(VaultError::Config(
                "SOC_VAULT_EMAIL is empty — the wall cannot unlock the vault. Run the setup wizard (sets the email) \
                 followed by first-run (seals the master + registers the Vaultwarden account)."
                    .into(),
            ));
        }
        if !self.url.is_empty() && !tcp_reachable(&self.url, Duration::from_millis(1500)) {
            return Err(VaultError::Unreachable(format!(
                "Vaultwarden at {} is not reachable — check 'systemctl status vaultwarden' (the wall needs the \
                 vault to start, even with blank tiles, so the GUI can read/write credentials at the glass).",
                sanitize(&self.url)
            )));
        }
        self.configure()?;
        if self.interactive {
            // The operator unlocks manually after boot; just make sure the agent is up.
            self.rbw(&["unlocked"], false)?;
            return Ok(());
        }
        self.rbw(&["unlock"], true).map(|_| ())
    }

    fn sync(&self) -> Result<(), VaultError> {
        self.rbw(&["sync"], true).map(|_| ())
    }

    fn get(&self, item: &str) -> Result<Login, VaultError> {
        let user = self.rbw(&["get", "--field", "username", "--", item], false)?;
        let mut password = self.rbw(&["get", "--", item], true)?;
        if password.is_empty() {
            return Err(VaultError::NotFound(format!("vault item '{item}' has no password (or not found)")));
        }
        Ok(Login::new(user.as_str(), std::mem::take(&mut *password)))
    }

    fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError> {
        let notes = self.rbw(&["get", "--field", "notes", "--", item], false)?;
        if !notes.is_empty() {
            return Ok(notes);
        }
        // Secure-note items return the note as the main value.
        self.rbw(&["get", "--", item], false)
    }

    fn code(&self, item: &str) -> Result<String, VaultError> {
        let code = self.rbw(&["code", "--", item], true)?;
        if code.is_empty() {
            return Err(VaultError::NotFound(format!("vault item '{item}' has no TOTP secret")));
        }
        Ok(code.as_str().to_owned())
    }

    fn delete(&self, item: &str) -> Result<bool, VaultError> {
        Ok(self.rbw(&["remove", "--", item], true).is_ok())
    }

    fn list_by_folder(&self, folder: &str) -> Result<Vec<String>, VaultError> {
        let out = self.rbw(&["list", "--fields", "name,folder"], true)?;
        Ok(out
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(name, in_folder)| in_folder.trim() == folder && !name.trim().is_empty())
            .map(|(name, _)| name.trim().to_string())
            .collect())
    }
}

// --------------------------------------------------------------------------- //
// Selection
// --------------------------------------------------------------------------- //

/// Which backend `$SOC_VAULT_BACKEND` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Native,
    Dev,
    Rbw,
}

impl BackendKind {
    /// `native` / `litebw`, `dev`, `rbw` — any case.
    pub fn parse(name: &str) -> Result<BackendKind, VaultError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "native" | "litebw" => Ok(BackendKind::Native),
            "dev" => Ok(BackendKind::Dev),
            "rbw" => Ok(BackendKind::Rbw),
            other => Err(VaultError::Config(format!("unknown SOC_VAULT_BACKEND={}", sanitize(other)))),
        }
    }
}

/// Everything backend selection reads from the environment, gathered once so
/// the selection itself is a pure function of this value.
#[derive(Debug, Clone)]
pub struct VaultEnv {
    /// `$SOC_VAULT_BACKEND`.
    pub backend: Option<String>,
    /// `$SOC_VAULT_EMAIL` / `$SOC_VAULT_URL` / `$SOC_PINENTRY`.
    pub email: Option<String>,
    pub url: Option<String>,
    pub pinentry: Option<String>,
    /// `$SOC_VAULT_INTERACTIVE == "1"`.
    pub interactive: bool,
    /// `$SOC_VAULT_REUNLOCK_COOLDOWN`, seconds.
    pub reunlock_cooldown: Duration,
    /// `$SOC_DEV_VAULT`.
    pub dev_vault: PathBuf,
    /// `$SOC_CRED_TTL` / `$SOC_CRED_STALE_TTL`, seconds.
    pub cred_ttl: Duration,
    pub stale_ttl: Duration,
    /// The litebw config file for this user.
    pub config_path: PathBuf,
    pub session: SessionOptions,
}

impl Default for VaultEnv {
    fn default() -> Self {
        VaultEnv {
            backend: None,
            email: None,
            url: None,
            pinentry: None,
            interactive: false,
            reunlock_cooldown: Duration::from_secs(8),
            dev_vault: PathBuf::from("dev/run/dev-vault.json"),
            cred_ttl: Duration::from_secs(30),
            stale_ttl: Duration::ZERO,
            config_path: PathBuf::from("/nonexistent/litebw/config.json"),
            session: SessionOptions::default(),
        }
    }
}

impl VaultEnv {
    /// Read the process environment. The only place this module touches it.
    pub fn from_process() -> VaultEnv {
        use soc_core::env::{env_float, env_str};
        VaultEnv {
            backend: env_str("SOC_VAULT_BACKEND"),
            email: env_str("SOC_VAULT_EMAIL"),
            url: env_str("SOC_VAULT_URL"),
            pinentry: env_str("SOC_PINENTRY"),
            interactive: std::env::var("SOC_VAULT_INTERACTIVE").is_ok_and(|v| v == "1"),
            reunlock_cooldown: Duration::from_secs_f64(env_float(
                "SOC_VAULT_REUNLOCK_COOLDOWN",
                8.0,
                Some(0.0),
                Some(3600.0),
            )),
            dev_vault: env_str("SOC_DEV_VAULT").map_or_else(|| VaultEnv::default().dev_vault, PathBuf::from),
            cred_ttl: Duration::from_secs_f64(env_float("SOC_CRED_TTL", 30.0, Some(1.0), Some(86_400.0))),
            stale_ttl: Duration::from_secs_f64(env_float("SOC_CRED_STALE_TTL", 0.0, Some(0.0), Some(86_400.0))),
            config_path: crate::config::default_config_path(),
            session: SessionOptions::from_env(),
        }
    }

    /// Environment first, then the config file, for email / URL / pinentry.
    pub fn resolved(&self) -> (String, String, String) {
        let file = LitebwConfig::load(&self.config_path);
        let pick = |env: &Option<String>, key: &str| crate::config::resolve(env.as_deref(), file.get(key)).to_string();
        (pick(&self.email, "email"), pick(&self.url, "base_url"), pick(&self.pinentry, "pinentry"))
    }
}

/// Build the backend `env` selects.
pub fn make_backend(env: &VaultEnv, master: Arc<dyn MasterSource>) -> Result<Box<dyn Backend>, VaultError> {
    let name = env.backend.as_deref().unwrap_or(soc_core::DEFAULT_VAULT_BACKEND);
    match BackendKind::parse(name)? {
        BackendKind::Dev => Ok(Box::new(DevFileBackend::new(&env.dev_vault))),
        BackendKind::Rbw => Ok(Box::new(RbwBackend::new(
            env.email.as_deref().unwrap_or(""),
            env.url.as_deref().unwrap_or(""),
            env.pinentry.as_deref().unwrap_or(""),
            env.interactive,
        ))),
        BackendKind::Native => {
            let (email, url, pinentry) = env.resolved();
            let cfg = NativeConfig {
                url,
                email,
                pinentry,
                interactive: env.interactive,
                reunlock_cooldown: env.reunlock_cooldown,
                sync_ttl: env.cred_ttl,
                session: env.session.clone(),
                config_path: Some(env.config_path.clone()),
            };
            Ok(Box::new(NativeBackend::new(cfg, master)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use crate::master::{FixedMaster, NoMaster};
    use crate::testutil::{FakeVaultwarden, TEST_EMAIL, TEST_MASTER, test_options};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn native_cfg(fake: &FakeVaultwarden) -> NativeConfig {
        NativeConfig {
            url: fake.url().to_string(),
            email: TEST_EMAIL.to_string(),
            session: test_options(),
            ..NativeConfig::default()
        }
    }

    fn native(fake: &FakeVaultwarden) -> NativeBackend {
        NativeBackend::new(native_cfg(fake), Arc::new(FixedMaster::new(TEST_MASTER)))
    }

    fn seeded() -> FakeVaultwarden {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let wazuh = s.add_login("wazuh", "admin", "s3cr3t");
            let totp = s.enc(RFC_SECRET);
            let notes = s.enc("panel notes");
            s.cipher_mut(&wazuh)["login"]["totp"] = json!(totp);
            s.cipher_mut(&wazuh)["notes"] = json!(notes);
            s.add_login("nouser", "", "pw-only");
            let nopw = s.add_login("nopw", "u", "");
            let note = s.enc("just a note");
            s.cipher_mut(&nopw)["notes"] = json!(note);
        }
        fake
    }

    // --- native ------------------------------------------------------------- //

    #[test]
    fn native_reads_logins_notes_and_codes() {
        let fake = seeded();
        let be = native(&fake);
        be.unlock().unwrap();
        be.sync().unwrap();
        let login = be.get("wazuh").unwrap();
        assert_eq!((login.username.as_str(), login.password.as_str()), ("admin", "s3cr3t"));
        assert_eq!(be.get("nouser").unwrap().username, "");
        assert_eq!(be.notes("wazuh").unwrap().as_str(), "panel notes");
        assert_eq!(be.notes("ghost").unwrap().as_str(), "");
        assert_eq!(be.code("wazuh").unwrap().len(), 6);
        assert!(matches!(be.get("nopw"), Err(VaultError::NotFound(_))));
        assert!(matches!(be.get("ghost"), Err(VaultError::NotFound(_))));
        assert!(matches!(be.code("nouser"), Err(VaultError::NotFound(m)) if m.contains("no TOTP")));
    }

    #[test]
    fn native_unlocks_lazily_on_first_use() {
        let fake = seeded();
        let be = native(&fake);
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
        assert_eq!(fake.password_logins(), 1);
    }

    #[test]
    fn a_trashed_item_never_shadows_the_live_one() {
        let fake = seeded();
        {
            let mut s = fake.state();
            let old = s.add_login("wazuh", "admin", "revoked-password");
            s.cipher_mut(&old)["deletedDate"] = json!("2026-01-01T00:00:00Z");
        }
        assert_eq!(native(&fake).get("wazuh").unwrap().password, "s3cr3t");
    }

    #[test]
    fn a_rotated_password_is_picked_up_after_the_sync_ttl() {
        let fake = seeded();
        let cfg = NativeConfig { sync_ttl: Duration::from_millis(40), ..native_cfg(&fake) };
        let be = NativeBackend::new(cfg, Arc::new(FixedMaster::new(TEST_MASTER)));
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
        {
            let mut s = fake.state();
            let rotated = s.enc("rotated");
            s.ciphers[0]["login"]["password"] = json!(rotated);
        }
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(be.get("wazuh").unwrap().password, "rotated");
        // ...and immediately after an explicit sync, whatever the TTL.
        let be = native(&fake);
        be.get("wazuh").unwrap();
        {
            let mut s = fake.state();
            let again = s.enc("again");
            s.ciphers[0]["login"]["password"] = json!(again);
        }
        assert_eq!(be.get("wazuh").unwrap().password, "rotated");
        be.sync().unwrap();
        assert_eq!(be.get("wazuh").unwrap().password, "again");
    }

    #[test]
    fn a_burst_of_lookups_shares_one_login_and_one_fetch() {
        let fake = seeded();
        let be = native(&fake);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t"));
            }
        });
        assert_eq!(fake.password_logins(), 1);
        assert_eq!(fake.count("GET /api/ciphers"), 1);
    }

    #[test]
    fn a_dead_session_is_reopened_once_with_the_master() {
        let fake = seeded();
        let be = native(&fake);
        be.sync().unwrap();
        {
            let mut s = fake.state();
            s.expire_tokens();
            s.refresh_works = false;
        }
        be.sync().unwrap();
        assert_eq!(fake.password_logins(), 2);
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
    }

    #[test]
    fn failed_unlocks_are_rate_limited_but_an_operator_unlock_clears_them() {
        let fake = seeded();
        let cfg = NativeConfig { reunlock_cooldown: Duration::from_secs(60), ..native_cfg(&fake) };
        let be = NativeBackend::new(cfg, Arc::new(FixedMaster::new("the wrong master")));
        for _ in 0..5 {
            assert!(matches!(be.get("wazuh"), Err(VaultError::LoginRejected(_))));
        }
        assert_eq!(fake.password_logins(), 1, "a wrong master must not hammer the login endpoint");

        // The operator types the right one: immediate recovery.
        be.unlock_with(TEST_MASTER).unwrap();
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
    }

    #[test]
    fn the_cooldown_expires() {
        let fake = seeded();
        let cfg = NativeConfig { reunlock_cooldown: Duration::from_millis(30), ..native_cfg(&fake) };
        let be = NativeBackend::new(cfg, Arc::new(FixedMaster::new("the wrong master")));
        assert!(be.get("wazuh").is_err());
        std::thread::sleep(Duration::from_millis(50));
        assert!(be.get("wazuh").is_err());
        assert_eq!(fake.password_logins(), 2);
    }

    #[test]
    fn interactive_without_a_master_signals_locked_then_unlocks_with_a_typed_one() {
        let fake = seeded();
        let cfg = NativeConfig { interactive: true, ..native_cfg(&fake) };
        let be = NativeBackend::new(cfg, Arc::new(NoMaster));
        be.unlock().unwrap(); // defers: no error, no session
        assert!(matches!(be.sync(), Err(VaultError::Locked(_))));
        assert!(matches!(be.get("wazuh"), Err(VaultError::Locked(_))));
        assert!(matches!(be.list_by_folder("x"), Err(VaultError::Locked(_))));
        assert!(fake.server.requests().is_empty());

        assert!(matches!(be.unlock_with(""), Err(VaultError::NoMaster(_))));
        assert!(matches!(be.unlock_with("wrong"), Err(VaultError::LoginRejected(_))));
        assert!(matches!(be.sync(), Err(VaultError::Locked(_))), "a bad attempt leaves it locked, not broken");
        be.unlock_with(TEST_MASTER).unwrap();
        be.sync().unwrap();
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
    }

    #[test]
    fn non_interactive_without_a_master_is_a_hard_error() {
        let fake = seeded();
        let be = NativeBackend::new(native_cfg(&fake), Arc::new(NoMaster));
        assert!(matches!(be.unlock(), Err(VaultError::NoMaster(_))));
        let empty = || Ok(Zeroizing::new(String::new()));
        let be = NativeBackend::new(native_cfg(&fake), Arc::new(empty));
        assert!(matches!(be.unlock(), Err(VaultError::NoMaster(_))));
    }

    #[test]
    fn the_master_is_asked_for_once_not_kept() {
        let fake = seeded();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        let source = move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(TEST_MASTER.to_string()))
        };
        let be = NativeBackend::new(native_cfg(&fake), Arc::new(source));
        be.get("wazuh").unwrap();
        be.sync().unwrap();
        // Deleting uses the live session — no second unseal, no stored master.
        assert!(be.delete("nouser").unwrap());
        assert!(!be.delete("nouser").unwrap());
        assert!(matches!(be.get("nouser"), Err(VaultError::NotFound(_))));
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(fake.password_logins(), 1);
    }

    #[test]
    fn native_lists_folders_and_exposes_a_write_session() {
        let fake = seeded();
        let be = native(&fake);
        let session = be.session().unwrap();
        session.upsert_secure_note("SOC Settings TOTP", RFC_SECRET, Some("SOC Wall Auth")).unwrap();
        assert_eq!(be.list_by_folder("SOC Wall Auth").unwrap(), ["SOC Settings TOTP"]);
        assert!(be.list_by_folder("nope").unwrap().is_empty());
        let made = be.with_session(|s| s.upsert_secure_note("another", "x", None)).unwrap();
        assert_eq!(made, crate::session::Upsert::Created);
    }

    #[test]
    fn configure_persists_settings_for_the_cli() {
        let fake = seeded();
        let dir = TestDir::new("backend-config");
        let path = dir.path().join("litebw").join("config.json");
        let cfg =
            NativeConfig { config_path: Some(path.clone()), pinentry: "/usr/bin/pin".into(), ..native_cfg(&fake) };
        let be = NativeBackend::new(cfg, Arc::new(FixedMaster::new(TEST_MASTER)));
        be.unlock().unwrap();
        let file = LitebwConfig::load(&path);
        assert_eq!((file.email(), file.base_url(), file.pinentry()), (TEST_EMAIL, fake.url(), "/usr/bin/pin"));
    }

    #[test]
    fn an_unreachable_vault_is_transient_not_a_lockout() {
        let dead = crate::testutil::dead_url();
        let cfg =
            NativeConfig { url: dead, email: TEST_EMAIL.into(), session: test_options(), ..NativeConfig::default() };
        let be = NativeBackend::new(cfg, Arc::new(FixedMaster::new(TEST_MASTER)));
        let err = be.get("x").unwrap_err();
        assert!(matches!(err, VaultError::Unreachable(_)) && err.is_transient());
    }

    // --- dev ---------------------------------------------------------------- //

    fn dev(dir: &TestDir, data: Value) -> DevFileBackend {
        let path = dir.path().join("dev-vault.json");
        std::fs::write(&path, data.to_string()).unwrap();
        DevFileBackend::new(path)
    }

    #[test]
    fn dev_backend_reads_items() {
        let dir = TestDir::new("dev");
        let be = dev(
            &dir,
            json!({
                "Item 1": {"username": "u1", "password": "s3cr3t", "notes": "n", "totp": RFC_SECRET, "folder": "F"},
                "No Pass": {"username": "u"}, "Second": {"password": "p", "folder": "F"}, "Junk": 5,
            }),
        );
        be.unlock().unwrap();
        let login = be.get("Item 1").unwrap();
        assert_eq!((login.username.as_str(), login.password.as_str()), ("u1", "s3cr3t"));
        assert_eq!(be.get("Second").unwrap().username, "");
        assert_eq!(be.notes("Item 1").unwrap().as_str(), "n");
        assert_eq!(be.notes("nope").unwrap().as_str(), "");
        assert_eq!(be.code("Item 1").unwrap().len(), 6);
        assert!(matches!(be.code("Second"), Err(VaultError::NotFound(_))));
        assert!(matches!(be.get("nope"), Err(VaultError::NotFound(m)) if m.contains("no item 'nope'")));
        assert!(matches!(be.get("No Pass"), Err(VaultError::NotFound(m)) if m.contains("no password")));
        assert!(matches!(be.get("Junk"), Err(VaultError::NotFound(_))));
        assert_eq!(be.list_by_folder("F").unwrap(), ["Item 1", "Second"]);
        assert!(be.list_by_folder("G").unwrap().is_empty());
        assert!(matches!(be.unlock_with("x"), Err(VaultError::Config(_))));
        assert!(matches!(be.session(), Err(VaultError::Config(_))));
    }

    #[test]
    fn dev_backend_delete_rewrites_the_file_privately() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("dev-delete");
        let be = dev(&dir, json!({"foo": {"password": "x"}, "bar": {"password": "y"}}));
        assert!(be.delete("foo").unwrap());
        assert!(!be.delete("foo").unwrap());
        let path = dir.path().join("dev-vault.json");
        let on_disk: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk, json!({"bar": {"password": "y"}}));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // sync re-reads what is on disk.
        std::fs::write(&path, json!({"new": {"password": "z"}}).to_string()).unwrap();
        assert!(be.get("new").is_err());
        be.sync().unwrap();
        assert_eq!(be.get("new").unwrap().password, "z");
    }

    #[test]
    fn dev_backend_reports_missing_and_malformed_files() {
        let dir = TestDir::new("dev-bad");
        let missing = DevFileBackend::new(dir.path().join("absent.json"));
        assert!(matches!(missing.unlock(), Err(VaultError::Config(m)) if m.contains("not found")));
        let path = dir.path().join("bad.json");
        for junk in ["", "not json", "[1]"] {
            std::fs::write(&path, junk).unwrap();
            assert!(matches!(DevFileBackend::new(&path).unlock(), Err(VaultError::Config(_))), "{junk:?}");
        }
    }

    // --- rbw ---------------------------------------------------------------- //

    /// A stand-in `rbw` that logs its argv and answers from a tiny script.
    fn fake_rbw(dir: &TestDir, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join("rbw");
        let log = dir.path().join("argv.log");
        let script = format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{body}\n", log.display());
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn argv_log(dir: &TestDir) -> Vec<String> {
        std::fs::read_to_string(dir.path().join("argv.log")).unwrap_or_default().lines().map(str::to_string).collect()
    }

    const RBW_SCRIPT: &str = r#"
case "$*" in
  "get --field username -- wazuh") echo admin ;;
  "get -- wazuh") echo s3cr3t ;;
  "get --field notes -- wazuh") echo "panel notes" ;;
  "get --field notes -- note") ;;
  "get -- note") echo "note body" ;;
  "get -- ghost") echo "no such item" >&2; exit 1 ;;
  "code -- wazuh") echo 123456 ;;
  "remove -- wazuh") ;;
  "remove -- ghost") exit 1 ;;
  "list --fields name,folder") printf 'A\tSOC Wall Auth\nB\tOther\nC\tSOC Wall Auth\n\tSOC Wall Auth\n' ;;
  "sync"|"unlock"|"unlocked") ;;
  config*) ;;
  *) echo "unexpected: $*" >&2; exit 9 ;;
esac"#;

    #[test]
    fn rbw_backend_drives_the_cli() {
        let dir = TestDir::new("rbw");
        let be = RbwBackend::new("k@soc.local", "", "/bin/pin", false).with_program(fake_rbw(&dir, RBW_SCRIPT));
        be.unlock().unwrap();
        be.sync().unwrap();
        let login = be.get("wazuh").unwrap();
        assert_eq!((login.username.as_str(), login.password.as_str()), ("admin", "s3cr3t"));
        assert_eq!(be.notes("wazuh").unwrap().as_str(), "panel notes");
        assert_eq!(be.notes("note").unwrap().as_str(), "note body");
        assert_eq!(be.code("wazuh").unwrap(), "123456");
        assert!(be.delete("wazuh").unwrap());
        assert!(!be.delete("ghost").unwrap());
        assert_eq!(be.list_by_folder("SOC Wall Auth").unwrap(), ["A", "C"]);
        let err = be.get("ghost").unwrap_err();
        assert!(matches!(&err, VaultError::Backend(m) if m.contains("no such item")), "{err:?}");
        let log = argv_log(&dir);
        assert_eq!(&log[..3], ["config set email k@soc.local", "config set pinentry /bin/pin", "unlock"]);
    }

    #[test]
    fn rbw_interactive_unlock_only_checks_the_agent() {
        let dir = TestDir::new("rbw-interactive");
        let be = RbwBackend::new("k@soc.local", "", "", true).with_program(fake_rbw(&dir, RBW_SCRIPT));
        be.unlock().unwrap();
        assert_eq!(argv_log(&dir), ["config set email k@soc.local", "unlocked"]);
    }

    #[test]
    fn rbw_preflight_failures_are_actionable() {
        let dir = TestDir::new("rbw-preflight");
        let program = fake_rbw(&dir, RBW_SCRIPT);
        let no_email = RbwBackend::new("", "", "", false).with_program(&program);
        assert!(matches!(no_email.unlock(), Err(VaultError::Config(m)) if m.contains("SOC_VAULT_EMAIL")));
        let dead = crate::testutil::dead_url();
        let down = RbwBackend::new("k@soc.local", &dead, "", false).with_program(&program);
        assert!(matches!(down.unlock(), Err(VaultError::Unreachable(m)) if m.contains("not reachable")));
        assert!(argv_log(&dir).is_empty(), "rbw must not run when the preflight fails");

        let absent = RbwBackend::new("k@soc.local", "", "", false).with_program(dir.path().join("no-such-rbw"));
        assert!(matches!(absent.sync(), Err(VaultError::Config(m)) if m.contains("rbw not found")));
    }

    #[test]
    fn rbw_hangs_are_killed_and_secrets_stay_out_of_errors() {
        let dir = TestDir::new("rbw-hang");
        let hang = fake_rbw(&dir, "echo leaked-secret; echo oops >&2; exec sleep 30");
        let be = RbwBackend::new("k", "", "", false).with_program(hang).with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        let err = be.sync().unwrap_err();
        assert!(matches!(&err, VaultError::Backend(m) if m.contains("timed out")), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(10));

        let dir = TestDir::new("rbw-fail");
        let fail = fake_rbw(&dir, "echo leaked-secret; printf 'agent\\nlocked\\n' >&2; exit 1");
        let be = RbwBackend::new("k", "", "", false).with_program(fail);
        let err = be.sync().unwrap_err().to_string();
        assert!(err.contains("agent locked") && !err.contains("leaked-secret") && !err.contains('\n'), "{err}");
    }

    #[test]
    fn tcp_preflight() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        assert!(tcp_reachable(&url, Duration::from_millis(500)));
        assert!(!tcp_reachable(&crate::testutil::dead_url(), Duration::from_millis(500)));
        assert!(!tcp_reachable("http://127.0.0.1:notaport", Duration::from_millis(100)));
    }

    // --- selection ---------------------------------------------------------- //

    #[test]
    fn backend_names() {
        assert_eq!(BackendKind::parse("native").unwrap(), BackendKind::Native);
        assert_eq!(BackendKind::parse("LiteBW").unwrap(), BackendKind::Native);
        assert_eq!(BackendKind::parse(" dev ").unwrap(), BackendKind::Dev);
        assert_eq!(BackendKind::parse("rbw").unwrap(), BackendKind::Rbw);
        assert!(
            matches!(BackendKind::parse("keepass"), Err(VaultError::Config(m)) if m.contains("SOC_VAULT_BACKEND=keepass"))
        );
    }

    #[test]
    fn selection_is_a_function_of_the_gathered_environment() {
        let dir = TestDir::new("select");
        std::fs::write(
            dir.path().join("dev.json"),
            json!({"Item 1": {"username": "u1", "password": "s3cr3t"}}).to_string(),
        )
        .unwrap();
        let env =
            VaultEnv { backend: Some("dev".into()), dev_vault: dir.path().join("dev.json"), ..VaultEnv::default() };
        let be = make_backend(&env, Arc::new(NoMaster)).unwrap();
        be.unlock().unwrap();
        assert_eq!(be.get("Item 1").unwrap().password, "s3cr3t");

        let bogus = VaultEnv { backend: Some("bogus".into()), ..VaultEnv::default() };
        assert!(matches!(make_backend(&bogus, Arc::new(NoMaster)), Err(VaultError::Config(_))));

        // The default is the native backend; email and URL fall back to the config file.
        let fake = seeded();
        let config_path = dir.path().join("litebw").join("config.json");
        let mut file = LitebwConfig::default();
        file.set("email", TEST_EMAIL);
        file.set("base_url", "http://127.0.0.1:1");
        file.save(&config_path).unwrap();
        let env =
            VaultEnv { url: Some(fake.url().to_string()), config_path, session: test_options(), ..VaultEnv::default() };
        assert_eq!(env.resolved(), (TEST_EMAIL.to_string(), fake.url().to_string(), String::new()));
        let be = make_backend(&env, Arc::new(FixedMaster::new(TEST_MASTER))).unwrap();
        assert_eq!(be.get("wazuh").unwrap().password, "s3cr3t");
    }

    #[test]
    fn blank_notes_are_reported_with_their_purpose() {
        let ok = require_notes(Zeroizing::new("[Interface]".into()), "WG", "the VPN").unwrap();
        assert_eq!(ok.as_str(), "[Interface]");
        let err = require_notes(Zeroizing::new(" \n".into()), "WG", "the VPN").unwrap_err().to_string();
        assert!(err.contains("vault item 'WG' has an empty Notes field for the VPN"));
        let err = require_notes(Zeroizing::new(String::new()), "WG", "").unwrap_err().to_string();
        assert!(err.contains("empty Notes field —"));
    }
}
