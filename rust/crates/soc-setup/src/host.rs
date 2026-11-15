//! The seams between the setup logic and the machine: filesystem/system
//! probes, the sealed-master store and the vault. Every check and step takes
//! these as trait objects, so the logic is tested without root, a display or a
//! network, and the real implementations live in exactly one place.

use crate::error::TextResult;
use soc_seal::{MasterResolver, MasterSource, SecretStore, SecretTool};
use soc_sys::fsutil;
use soc_sys::health;
use soc_sys::run::{Runner, SystemRunner};
use soc_vault::{Session, SessionOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// What this machine looks like. Read-only questions only.
pub trait Probe {
    /// Is `bin` on `PATH`?
    fn have(&self, bin: &str) -> bool;
    fn exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> bool;
    /// A regular file with an execute bit.
    fn is_exec_file(&self, path: &Path) -> bool;
    /// `st_mode & 0o777`.
    fn mode(&self, path: &Path) -> Option<u32>;
    /// Does `GET <url>/alive` answer 200?
    fn alive(&self, url: &str) -> bool;
    /// `systemctl` exists and systemd is the running init.
    fn systemd_running(&self) -> bool {
        self.have("systemctl") && self.is_dir(Path::new("/run/systemd/system"))
    }
    fn is_root(&self) -> bool;
    fn current_user(&self) -> String;
    /// Does a local account called `name` exist?
    fn user_exists(&self, name: &str) -> bool;
    /// `~` / `~/x` expanded for the current user.
    fn expand_user(&self, path: &str) -> String;
}

/// The real machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProbe;

impl Probe for SystemProbe {
    fn have(&self, bin: &str) -> bool {
        let path = std::env::var("PATH").unwrap_or_default(); // audit-allow: an unset PATH means nothing is found
        fsutil::which(bin, &path).is_some()
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn is_exec_file(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }

    fn mode(&self, path: &Path) -> Option<u32> {
        std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
    }

    fn alive(&self, url: &str) -> bool {
        // Plain HTTP only (the local Vaultwarden); for https the answer is
        // reduced to "the port accepts a connection".
        let Some(hostport) = health::vault_hostport(url) else { return false };
        if url.trim().starts_with("https://") {
            return health::tcp_ok(&hostport, Duration::from_secs(4)) == Some(true);
        }
        let Some(mut stream) = connect(&hostport) else { return false };
        let req = format!("GET /alive HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
        if stream.write_all(req.as_bytes()).is_err() {
            return false;
        }
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).is_ok() && (&head == b"HTTP/1.1 200" || &head == b"HTTP/1.0 200")
    }

    fn is_root(&self) -> bool {
        fsutil::euid() == 0
    }

    fn user_exists(&self, name: &str) -> bool {
        fsutil::passwd_lookup(Path::new(fsutil::PASSWD), |e| e.name == name).is_some()
    }

    fn expand_user(&self, path: &str) -> String {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        fsutil::expand_user(path, home.as_deref(), Path::new(fsutil::PASSWD))
    }

    fn current_user(&self) -> String {
        std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(|| fsutil::passwd_lookup(Path::new(fsutil::PASSWD), |e| e.uid == fsutil::euid()).map(|e| e.name))
            .unwrap_or_default() // audit-allow: an unknown user name only affects an advisory check
    }
}

fn connect(hostport: &str) -> Option<TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = hostport.to_socket_addrs().ok()?.next()?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(4)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok()?;
    Some(stream)
}

/// The sealed-master store and the other master sources.
pub trait SealBackend {
    fn is_sealed(&self, dir: &Path) -> bool;
    fn seal(&self, dir: &Path, master: &str, pin: &str) -> TextResult<()>;
    fn unseal(&self, dir: &Path) -> TextResult<Zeroizing<String>>;
    /// Sources usable right now, by name, in resolution order.
    fn available_sources(&self, dir: &Path) -> Vec<String>;
    fn have_secret_tool(&self) -> bool;
    /// The master from the Secret Service wallet, if there is one.
    fn secret_service_get(&self) -> Option<Zeroizing<String>>;
    fn secret_service_store(&self, master: &str) -> TextResult<()>;
    fn gen_pin(&self) -> TextResult<Zeroizing<String>> {
        soc_seal::gen_pin(soc_seal::DEFAULT_PIN_DIGITS).map_err(|e| e.to_string())
    }
}

/// [`SealBackend`] over `soc-seal`.
#[derive(Debug, Clone)]
pub struct RealSeal {
    /// `$SOC_MACHINE_ID`-style override (tests, containers).
    pub machine_id: Option<String>,
    pub secret_tool: SecretTool,
}

impl RealSeal {
    /// The operator's environment: `$SOC_MACHINE_ID`, `secret-tool` from `PATH`.
    pub fn from_env() -> RealSeal {
        RealSeal { machine_id: soc_core::env::env_str("SOC_MACHINE_ID"), secret_tool: SecretTool::locate() }
    }

    fn store(&self, dir: &Path) -> SecretStore {
        let store = SecretStore::new(dir);
        match &self.machine_id {
            Some(id) => store.with_machine_id(id.clone()),
            None => store,
        }
    }

    fn resolver(&self, dir: &Path) -> MasterResolver {
        let attrs = std::env::var("SOC_SECRET_ATTRS").ok().as_deref().and_then(soc_seal::parse_attrs);
        let r = MasterResolver::new(self.store(dir)).with_secret_tool(self.secret_tool.clone());
        match attrs {
            Some(a) => r.with_attrs(a),
            None => r,
        }
    }
}

impl SealBackend for RealSeal {
    fn is_sealed(&self, dir: &Path) -> bool {
        self.store(dir).is_sealed()
    }

    fn seal(&self, dir: &Path, master: &str, pin: &str) -> TextResult<()> {
        self.store(dir).seal(master, pin).map_err(|e| e.to_string())
    }

    fn unseal(&self, dir: &Path) -> TextResult<Zeroizing<String>> {
        self.store(dir).unseal().map_err(|e| e.to_string())
    }

    fn available_sources(&self, dir: &Path) -> Vec<String> {
        self.resolver(dir).available_sources().iter().map(|s| s.as_str().to_string()).collect()
    }

    fn have_secret_tool(&self) -> bool {
        self.secret_tool.available()
    }

    fn secret_service_get(&self) -> Option<Zeroizing<String>> {
        self.resolver(Path::new("")).get_master_from(MasterSource::SecretService)
    }

    fn secret_service_store(&self, master: &str) -> TextResult<()> {
        self.resolver(Path::new("")).store_master(master, MasterSource::SecretService).map_err(|e| e.to_string())
    }
}

/// How an `ensure_account` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Account {
    Created,
    Exists,
}

/// What a vault login write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrote {
    Created,
    Updated,
}

impl Wrote {
    pub const fn as_str(self) -> &'static str {
        match self {
            Wrote::Created => "created",
            Wrote::Updated => "updated",
        }
    }
}

/// One logged-in vault session (one PBKDF2 derivation for a whole run).
pub trait VaultWriter {
    fn login_names(&self) -> TextResult<Vec<String>>;
    fn upsert_login(
        &self,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        notes: Option<&str>,
    ) -> TextResult<Wrote>;
}

/// Opens vault sessions and ensures the account.
pub trait VaultConnect {
    fn connect(&self, url: &str, email: &str, master: &str) -> TextResult<Box<dyn VaultWriter>>;
    fn ensure_account(&self, url: &str, email: &str, master: &str) -> TextResult<Account>;
}

/// [`VaultConnect`] over `soc-vault`.
#[derive(Debug, Clone, Default)]
pub struct RealVault {
    pub opts: Option<SessionOptions>,
}

impl RealVault {
    fn opts(&self) -> SessionOptions {
        self.opts.clone().unwrap_or_else(SessionOptions::from_env)
    }
}

struct SessionWriter(Session);

impl VaultWriter for SessionWriter {
    fn login_names(&self) -> TextResult<Vec<String>> {
        self.0.list_logins().map(|l| l.into_iter().map(|x| x.name).collect()).map_err(|e| e.to_string())
    }

    fn upsert_login(
        &self,
        name: &str,
        username: &str,
        password: &str,
        uri: Option<&str>,
        notes: Option<&str>,
    ) -> TextResult<Wrote> {
        let spec = soc_vault::LoginSpec { name, username, password, notes, uri, ..soc_vault::LoginSpec::default() };
        match self.0.upsert_login(&spec).map_err(|e| e.to_string())? {
            soc_vault::Upsert::Created => Ok(Wrote::Created),
            soc_vault::Upsert::Updated => Ok(Wrote::Updated),
        }
    }
}

impl VaultConnect for RealVault {
    fn connect(&self, url: &str, email: &str, master: &str) -> TextResult<Box<dyn VaultWriter>> {
        let session = Session::login(url, email, master, &self.opts()).map_err(|e| e.to_string())?;
        Ok(Box::new(SessionWriter(session)))
    }

    fn ensure_account(&self, url: &str, email: &str, master: &str) -> TextResult<Account> {
        match soc_vault::register::ensure_account(
            url,
            email,
            master,
            soc_vault::register::DEFAULT_ACCOUNT_NAME,
            &self.opts(),
        )
        .map_err(|e| e.to_string())?
        {
            soc_vault::register::Registered::Created => Ok(Account::Created),
            soc_vault::register::Registered::Exists => Ok(Account::Exists),
        }
    }
}

/// Everything a step may touch, borrowed.
#[derive(Clone, Copy)]
pub struct Host<'a> {
    pub runner: &'a dyn Runner,
    pub probe: &'a dyn Probe,
    pub seal: &'a dyn SealBackend,
    pub vault: &'a dyn VaultConnect,
}

/// The real machine, owning its parts; [`SystemHost::host`] borrows them.
pub struct SystemHost {
    pub runner: SystemRunner,
    pub probe: SystemProbe,
    pub seal: RealSeal,
    pub vault: RealVault,
}

impl SystemHost {
    pub fn from_env() -> SystemHost {
        SystemHost { runner: SystemRunner, probe: SystemProbe, seal: RealSeal::from_env(), vault: RealVault::default() }
    }

    pub fn host(&self) -> Host<'_> {
        Host { runner: &self.runner, probe: &self.probe, seal: &self.seal, vault: &self.vault }
    }
}
