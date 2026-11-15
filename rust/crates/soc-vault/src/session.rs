//! An authenticated Vaultwarden session: login, token refresh, and the read
//! and write sides of the cipher API.
//!
//! One session type serves both the 24/7 reader and the setup-time writer. It
//! keeps the account key and the tokens — never the master password — so a
//! long-running wall can refresh its bearer on a 401 and edit items without
//! the master being held in memory for the life of the process.

use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::crypto::{Kdf, MasterKey, SymKey, normalize_email};
use crate::error::VaultError;
use crate::http::{Http, HttpOptions, Method, Payload, parse_json, sanitize};

/// The iteration count assumed when `prelogin` omits it (Bitwarden's default).
const DEFAULT_PBKDF2_ITERATIONS: u64 = 600_000;

/// How a session identifies itself to the server.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub http: HttpOptions,
    /// Vaultwarden keys refresh tokens by device, so this stays stable.
    pub device_id: String,
    pub device_name: String,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            http: HttpOptions::default(),
            device_id: "soc-litebw-0001".to_string(),
            device_name: "soc-litebw".to_string(),
        }
    }
}

impl SessionOptions {
    /// Defaults plus the transport settings from the environment.
    pub fn from_env() -> SessionOptions {
        SessionOptions { http: HttpOptions::from_env(), ..SessionOptions::default() }
    }
}

/// First present, non-null value among a field's PascalCase / camelCase names
/// (Bitwarden switched casing; both are still seen in the wild).
fn pick<'a>(obj: &'a Value, names: [&str; 2]) -> Option<&'a Value> {
    names.iter().filter_map(|n| obj.get(*n)).find(|v| !v.is_null())
}

fn text(obj: &Value, names: [&str; 2]) -> Option<String> {
    pick(obj, names).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The `data` array of a Bitwarden list response.
fn list_data(body: &[u8], what: &str) -> Result<Vec<Value>, VaultError> {
    let shape = || VaultError::Protocol(format!("{what}: unexpected response shape"));
    match parse_json(body, what)? {
        Value::Array(items) => Ok(items),
        obj @ Value::Object(_) => match pick(&obj, ["Data", "data"]) {
            Some(Value::Array(items)) => Ok(items.clone()),
            Some(_) => Err(shape()),
            None => Ok(Vec::new()),
        },
        _ => Err(shape()),
    }
}

/// The user id from an access token (the JWT `sub` claim), or `""`. It only
/// labels our own writes, so the signature needs no checking: the server does
/// that on every request.
pub(crate) fn token_subject(token: &str) -> String {
    token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok())
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|claims| claims.get("sub").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default() // audit-allow: default is the intended fallback (no subject claim)
}

/// A vault item whose name is decrypted and whose secret fields are still
/// ciphertext. Fields are decrypted only when asked for, so plaintext
/// passwords exist in memory only for as long as a caller holds them.
#[derive(Clone)]
pub struct Cipher {
    pub id: String,
    pub name: String,
    /// Bitwarden cipher type: [`Cipher::LOGIN`], [`Cipher::SECURE_NOTE`], ...
    pub kind: u8,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub reprompt: Option<i64>,
    key: Arc<SymKey>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    notes: Option<String>,
    uri: Option<String>,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher").field("id", &self.id).field("name", &self.name).field("kind", &self.kind).finish()
    }
}

impl Cipher {
    pub const LOGIN: u8 = 1;
    pub const SECURE_NOTE: u8 = 2;

    /// Parse one raw cipher. `None` for anything this account cannot or must
    /// not use: trashed items, organisation items (their key is not ours) and
    /// items whose name does not authenticate under our key.
    fn parse(raw: &Value, user_key: &Arc<SymKey>) -> Option<Cipher> {
        if pick(raw, ["DeletedDate", "deletedDate"]).is_some()
            || pick(raw, ["OrganizationId", "organizationId"]).is_some()
        {
            return None;
        }
        // Newer clients give each item its own key, wrapped under the account key.
        let key = match text(raw, ["Key", "key"]) {
            Some(wrapped) => Arc::new(SymKey::from_bytes(&user_key.decrypt(&wrapped).ok()?).ok()?),
            None => Arc::clone(user_key),
        };
        let name = key.decrypt_str(&text(raw, ["Name", "name"])?).ok()?;
        let null = Value::Null;
        let login = pick(raw, ["Login", "login"]).unwrap_or(&null);
        let uri = pick(login, ["Uris", "uris"])
            .and_then(Value::as_array)
            .and_then(|uris| uris.first())
            .and_then(|first| text(first, ["Uri", "uri"]));
        Some(Cipher {
            id: text(raw, ["Id", "id"]).unwrap_or_default(), // audit-allow: default is the intended fallback (id-less record)
            name: name.as_str().to_owned(),
            kind: pick(raw, ["Type", "type"]).and_then(Value::as_u64).and_then(|t| u8::try_from(t).ok()).unwrap_or(0),
            folder_id: text(raw, ["FolderId", "folderId"]),
            favorite: pick(raw, ["Favorite", "favorite"]).and_then(Value::as_bool).unwrap_or(false),
            reprompt: pick(raw, ["Reprompt", "reprompt"]).and_then(Value::as_i64),
            key,
            username: text(login, ["Username", "username"]),
            password: text(login, ["Password", "password"]),
            totp: text(login, ["Totp", "totp"]),
            notes: text(raw, ["Notes", "notes"]),
            uri,
        })
    }

    fn field(&self, enc: &Option<String>) -> Result<Zeroizing<String>, VaultError> {
        match enc {
            None => Ok(Zeroizing::new(String::new())),
            Some(enc) => self.key.decrypt_str(enc).map_err(|e| {
                VaultError::Crypto(format!("vault item '{}' has a field that cannot be decrypted: {e}", self.name))
            }),
        }
    }

    /// Login username (`""` when absent).
    pub fn username(&self) -> Result<Zeroizing<String>, VaultError> {
        self.field(&self.username)
    }

    /// Login password (`""` when absent).
    pub fn password(&self) -> Result<Zeroizing<String>, VaultError> {
        self.field(&self.password)
    }

    /// The login's TOTP value: a Base32 secret or an `otpauth://` URI.
    pub fn totp(&self) -> Result<Zeroizing<String>, VaultError> {
        self.field(&self.totp)
    }

    /// The Notes field (a secure note's whole body).
    pub fn notes(&self) -> Result<Zeroizing<String>, VaultError> {
        self.field(&self.notes)
    }

    /// The login's first URI.
    pub fn uri(&self) -> Result<Zeroizing<String>, VaultError> {
        self.field(&self.uri)
    }

    pub fn has_totp(&self) -> bool {
        self.totp.is_some()
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }
}

/// What to write for a login item. Borrowed so secrets are not copied around.
#[derive(Clone, Copy, Default)]
pub struct LoginSpec<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub notes: Option<&'a str>,
    pub uri: Option<&'a str>,
    pub totp: Option<&'a str>,
    /// The item's current name when renaming it in place.
    pub rename_from: Option<&'a str>,
}

/// Whether an upsert made a new item or changed an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Created,
    Updated,
}

impl Upsert {
    pub fn as_str(self) -> &'static str {
        match self {
            Upsert::Created => "created",
            Upsert::Updated => "updated",
        }
    }
}

/// One row of [`Session::list_logins`]. Never carries the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSummary {
    pub name: String,
    pub username: String,
    pub has_totp: bool,
    pub uri: String,
}

/// A fully decrypted login, for the credential editor. Wiped on drop.
pub struct LoginRecord {
    pub name: String,
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub totp: Zeroizing<String>,
    pub uri: Zeroizing<String>,
    pub notes: Zeroizing<String>,
}

impl std::fmt::Debug for LoginRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRecord").field("name", &self.name).finish_non_exhaustive()
    }
}

type Encrypt<'a> = &'a dyn Fn(&str) -> Result<String, VaultError>;

fn encrypt_opt(enc: Encrypt<'_>, value: Option<&str>) -> Result<Value, VaultError> {
    match value.filter(|v| !v.is_empty()) {
        Some(v) => Ok(Value::String(enc(v)?)),
        None => Ok(Value::Null),
    }
}

/// The request body for a login cipher. Pure, so its shape is testable
/// without a server; an absent TOTP leaves no `totp` key at all.
pub(crate) fn login_body(enc: Encrypt<'_>, spec: &LoginSpec<'_>) -> Result<Value, VaultError> {
    let uris = match spec.uri.filter(|u| !u.is_empty()) {
        Some(uri) => json!([{"uri": enc(uri)?, "match": null}]),
        None => Value::Null,
    };
    let mut login = json!({
        "username": encrypt_opt(enc, Some(spec.username))?,
        "password": encrypt_opt(enc, Some(spec.password))?,
        "uris": uris,
    });
    if let Some(totp) = spec.totp.filter(|t| !t.is_empty()) {
        login["totp"] = Value::String(enc(totp)?);
    }
    Ok(json!({
        "type": Cipher::LOGIN,
        "name": enc(spec.name)?,
        "favorite": false,
        "notes": encrypt_opt(enc, spec.notes)?,
        "login": login,
    }))
}

/// The request body for a secure note.
pub(crate) fn note_body(
    enc: Encrypt<'_>,
    name: &str,
    notes: &str,
    folder_id: Option<&str>,
) -> Result<Value, VaultError> {
    let mut body = json!({
        "type": Cipher::SECURE_NOTE,
        "name": enc(name)?,
        "favorite": false,
        "notes": encrypt_opt(enc, Some(notes))?,
        "secureNote": {"type": 0},
    });
    if let Some(id) = folder_id.filter(|id| !id.is_empty()) {
        body["folderId"] = Value::String(id.to_string());
    }
    Ok(body)
}

/// Server-issued ids are interpolated into request paths, so they must be
/// plain identifiers — never something that could re-target the request.
fn checked_id(id: &str) -> Result<&str, VaultError> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        Ok(id)
    } else {
        Err(VaultError::Protocol("the vault returned an item id that is not a plain identifier".into()))
    }
}

struct Tokens {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
}

/// The parts of a token response this client uses.
#[derive(serde::Deserialize)]
struct TokenResponse {
    #[serde(default, rename = "Key")]
    key_pascal: Option<String>,
    #[serde(default, rename = "key")]
    key_camel: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// An authenticated session.
pub struct Session {
    http: Http,
    email: String,
    key: Arc<SymKey>,
    user_id: String,
    tokens: Mutex<Tokens>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("base", &self.http.base()).field("email", &self.email).finish_non_exhaustive()
    }
}

impl Session {
    /// Log in: `prelogin` → derive the master key → password grant → unwrap
    /// the account key. The master password is used here and not retained.
    pub fn login(url: &str, email: &str, master: &str, opts: &SessionOptions) -> Result<Session, VaultError> {
        if url.trim().is_empty() {
            return Err(VaultError::Config(
                "no Vaultwarden URL (set SOC_VAULT_URL or `litebw config set base_url ...`)".into(),
            ));
        }
        let email = normalize_email(email);
        if email.is_empty() {
            return Err(VaultError::Config(
                "no vault email (set SOC_VAULT_EMAIL or `litebw config set email ...`)".into(),
            ));
        }
        if master.is_empty() {
            return Err(VaultError::NoMaster("empty master password".into()));
        }
        let http = Http::new(url, &opts.http)?;

        let prelogin = "/identity/accounts/prelogin";
        let pre = parse_json(
            &http.request(Method::Post, prelogin, None, Payload::Json(&json!({"email": email})))?,
            prelogin,
        )?;
        if !pre.is_object() {
            return Err(VaultError::Protocol(format!("{prelogin}: unexpected response shape")));
        }
        let number = |names: [&str; 2], default: u64| match pick(&pre, names) {
            None => Ok(default),
            Some(v) => {
                v.as_u64().ok_or_else(|| VaultError::Kdf("the vault announced a non-numeric KDF parameter".into()))
            }
        };
        let iterations = match number(["kdfIterations", "KdfIterations"], DEFAULT_PBKDF2_ITERATIONS)? {
            0 => DEFAULT_PBKDF2_ITERATIONS,
            n => n,
        };
        let kdf = Kdf::from_prelogin(
            number(["kdf", "Kdf"], 0)?,
            iterations,
            number(["kdfMemory", "KdfMemory"], 0)?,
            number(["kdfParallelism", "KdfParallelism"], 0)?,
        )?;

        let master_key = MasterKey::derive(master, &email, kdf)?;
        let hash = master_key.password_hash(master);
        let token_path = "/identity/connect/token";
        let form = [
            ("grant_type", "password"),
            ("username", email.as_str()),
            ("password", hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", "8"),
            ("deviceIdentifier", opts.device_id.as_str()),
            ("deviceName", opts.device_name.as_str()),
        ];
        let reply = http.send(Method::Post, token_path, None, Payload::Form(&form))?;
        if !reply.is_success() {
            if !matches!(reply.status, 400 | 401) {
                return Err(http.status_error(Method::Post, token_path, &reply));
            }
            let shown = sanitize(&email);
            if String::from_utf8_lossy(&reply.body).contains("TwoFactorProviders") {
                return Err(VaultError::LoginRejected(format!(
                    "Vaultwarden wants a two-step login code for '{shown}', which an unattended wall cannot supply — \
                     turn two-step login off for the kiosk account"
                )));
            }
            return Err(VaultError::LoginRejected(format!(
                "Vaultwarden rejected the login for '{shown}'. Either the master password is wrong, or no account \
                 exists for that email — register at {}/#/login (a kiosk install typically uses first-run setup, \
                 which can register the account for you).",
                http.base()
            )));
        }
        let token: TokenResponse = serde_json::from_slice(&reply.body)
            .map_err(|_| VaultError::Protocol(format!("{token_path}: the vault did not answer with a token")))?; // audit-allow: serde error text can quote token content; deliberately not echoed
        let incomplete = || VaultError::Protocol("login failed — check the email/master password".into());
        let wrapped_key = token.key_pascal.or(token.key_camel).ok_or_else(incomplete)?;
        let access = Zeroizing::new(token.access_token.filter(|t| !t.is_empty()).ok_or_else(incomplete)?);
        let refresh = token.refresh_token.filter(|t| !t.is_empty()).map(Zeroizing::new);

        let account_key = master_key
            .stretch()
            .decrypt(&wrapped_key)
            .and_then(|raw| SymKey::from_bytes(&raw))
            .map_err(|e| VaultError::Crypto(format!("cannot unwrap the account key: {e}")))?;
        Ok(Session {
            user_id: token_subject(&access),
            http,
            email,
            key: Arc::new(account_key),
            tokens: Mutex::new(Tokens { access, refresh }),
        })
    }

    /// The server base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        self.http.base()
    }

    /// The (normalised) account email.
    pub fn email(&self) -> &str {
        &self.email
    }

    fn lock(&self) -> MutexGuard<'_, Tokens> {
        self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Refresh the bearer with the refresh token (no master needed). False
    /// when there is none or the server refuses it; the caller then re-unlocks.
    fn refresh_locked(&self, tokens: &mut Tokens) -> bool {
        let Some(refresh) = tokens.refresh.clone() else { return false };
        let form = [("grant_type", "refresh_token"), ("refresh_token", refresh.as_str()), ("client_id", "cli")];
        let Ok(reply) = self.http.send(Method::Post, "/identity/connect/token", None, Payload::Form(&form)) else {
            return false;
        };
        if !reply.is_success() {
            if matches!(reply.status, 400 | 401) {
                // Refused for good: do not offer a dead token again.
                tokens.refresh = None;
            }
            return false;
        }
        let Ok(token) = serde_json::from_slice::<TokenResponse>(&reply.body) else { return false };
        let Some(access) = token.access_token.filter(|t| !t.is_empty()) else { return false };
        tokens.access = Zeroizing::new(access);
        if let Some(rotated) = token.refresh_token.filter(|t| !t.is_empty()) {
            tokens.refresh = Some(Zeroizing::new(rotated));
        }
        true
    }

    /// Refresh unless another thread already replaced the token that just
    /// drew a 401 — concurrent callers must not each burn a refresh.
    fn refresh_after(&self, stale: &str) -> bool {
        let mut tokens = self.lock();
        if tokens.access.as_str() != stale {
            return true;
        }
        self.refresh_locked(&mut tokens)
    }

    /// An authenticated request, refreshing the bearer once on a 401.
    fn authed(&self, method: Method, path: &str, payload: Payload<'_>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let token = self.lock().access.clone();
        let mut reply = self.http.send(method, path, Some(&token), payload)?;
        if reply.status == 401 && self.refresh_after(&token) {
            let token = self.lock().access.clone();
            reply = self.http.send(method, path, Some(&token), payload)?;
        }
        if reply.is_success() { Ok(reply.body) } else { Err(self.http.status_error(method, path, &reply)) }
    }

    /// Every usable item of the personal vault. Items that cannot be
    /// authenticated are skipped, never fatal: one bad cipher must not take
    /// the whole wall down.
    pub fn ciphers(&self) -> Result<Vec<Cipher>, VaultError> {
        let body = self.authed(Method::Get, "/api/ciphers", Payload::None)?;
        Ok(list_data(&body, "/api/ciphers")?.iter().filter_map(|raw| Cipher::parse(raw, &self.key)).collect())
    }

    /// The first item named `name`, if any.
    pub fn find(&self, name: &str) -> Result<Option<Cipher>, VaultError> {
        Ok(self.ciphers()?.into_iter().find(|c| c.name == name))
    }

    fn folders(&self) -> Result<Vec<(String, String)>, VaultError> {
        let body = self.authed(Method::Get, "/api/folders", Payload::None)?;
        Ok(list_data(&body, "/api/folders")?
            .iter()
            .filter_map(|raw| {
                let name = self.key.decrypt_str(&text(raw, ["Name", "name"])?).ok()?;
                Some((text(raw, ["Id", "id"])?, name.as_str().to_owned()))
            })
            .collect())
    }

    /// Names of every item in the folder NAMED `folder` (empty if unknown).
    /// Folder names are encrypted, so they are matched client-side.
    pub fn names_in_folder(&self, folder: &str) -> Result<Vec<String>, VaultError> {
        let ids: Vec<String> =
            self.folders()?.into_iter().filter(|(_, name)| name == folder).map(|(id, _)| id).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .ciphers()?
            .into_iter()
            .filter(|c| c.folder_id.as_ref().is_some_and(|f| ids.contains(f)))
            .map(|c| c.name)
            .collect())
    }

    /// Id of the folder named `folder`, created if absent.
    fn folder_id(&self, folder: &str) -> Result<String, VaultError> {
        if let Some((id, _)) = self.folders()?.into_iter().find(|(_, name)| name == folder) {
            return Ok(id);
        }
        let body = json!({"name": self.key.encrypt_str(folder)?});
        let made = parse_json(&self.authed(Method::Post, "/api/folders", Payload::Json(&body))?, "/api/folders")?;
        text(&made, ["Id", "id"]).ok_or_else(|| VaultError::Protocol("/api/folders: the new folder has no id".into()))
    }

    /// Current Vaultwarden rejects a cipher write with HTTP 422 unless it
    /// names the user it was encrypted for; older servers ignore the field.
    fn for_user(&self, mut body: Value) -> Value {
        if !self.user_id.is_empty() {
            body["encryptedFor"] = Value::String(self.user_id.clone());
        }
        body
    }

    fn create(&self, body: Value) -> Result<Upsert, VaultError> {
        self.authed(Method::Post, "/api/ciphers", Payload::Json(&self.for_user(body)))?;
        Ok(Upsert::Created)
    }

    /// Replace `existing` with `body`, keeping the organisational attributes
    /// this client does not manage. A plain PUT of our minimal body would
    /// silently un-file and un-favourite an item the operator arranged in the
    /// web vault.
    fn update(&self, existing: &Cipher, mut body: Value) -> Result<Upsert, VaultError> {
        body["favorite"] = Value::Bool(existing.favorite);
        if body.get("folderId").is_none() {
            if let Some(folder) = &existing.folder_id {
                body["folderId"] = Value::String(folder.clone());
            }
        }
        if let Some(reprompt) = existing.reprompt {
            body["reprompt"] = json!(reprompt);
        }
        let path = format!("/api/ciphers/{}", checked_id(&existing.id)?);
        self.authed(Method::Put, &path, Payload::Json(&self.for_user(body)))?;
        Ok(Upsert::Updated)
    }

    /// Create or update the login named `spec.name`.
    ///
    /// With `rename_from` set (and different), the item currently called that
    /// is renamed in place instead of leaving an orphan behind; if a
    /// *different* login already owns the new name this fails closed rather
    /// than overwrite it. Only live login items are ever matched, so a write
    /// can never land on a secure note or a trashed item of the same name.
    pub fn upsert_login(&self, spec: &LoginSpec<'_>) -> Result<Upsert, VaultError> {
        let enc = |s: &str| self.key.encrypt_str(s);
        let body = login_body(&enc, spec)?;
        let ciphers = self.ciphers()?;
        let login_named = |name: &str| ciphers.iter().find(|c| c.kind == Cipher::LOGIN && c.name == name);
        let existing = login_named(spec.name);
        if let Some(old_name) = spec.rename_from.filter(|old| !old.is_empty() && *old != spec.name) {
            let source = login_named(old_name);
            if let Some(clash) = existing {
                if source.map(|s| &s.id) != Some(&clash.id) {
                    return Err(VaultError::Conflict(format!(
                        "a login named '{}' already exists",
                        sanitize(spec.name)
                    )));
                }
            }
            return match source {
                Some(source) => self.update(source, body),
                // The original vanished under the editor: create the renamed login fresh.
                None => self.create(body),
            };
        }
        match existing {
            Some(existing) => self.update(existing, body),
            None => self.create(body),
        }
    }

    /// Create or update a secure note — for items whose payload is the Notes
    /// field, such as the wall's own TOTP secrets. `folder` is a folder NAME,
    /// created if needed.
    pub fn upsert_secure_note(&self, name: &str, notes: &str, folder: Option<&str>) -> Result<Upsert, VaultError> {
        let folder_id = match folder.filter(|f| !f.is_empty()) {
            Some(folder) => Some(self.folder_id(folder)?),
            None => None,
        };
        let enc = |s: &str| self.key.encrypt_str(s);
        let body = note_body(&enc, name, notes, folder_id.as_deref())?;
        match self.ciphers()?.iter().find(|c| c.kind == Cipher::SECURE_NOTE && c.name == name) {
            Some(existing) => self.update(existing, body),
            None => self.create(body),
        }
    }

    /// One row per login item, without passwords. Items with an undecryptable
    /// field are skipped rather than aborting the list.
    pub fn list_logins(&self) -> Result<Vec<LoginSummary>, VaultError> {
        Ok(self
            .ciphers()?
            .iter()
            .filter(|c| c.kind == Cipher::LOGIN)
            .filter_map(|c| {
                Some(LoginSummary {
                    name: c.name.clone(),
                    username: c.username().ok()?.as_str().to_owned(),
                    has_totp: c.has_totp(),
                    uri: c.uri().ok()?.as_str().to_owned(),
                })
            })
            .collect())
    }

    /// The full decrypted login named `name`, for the editor.
    pub fn get_login(&self, name: &str) -> Result<Option<LoginRecord>, VaultError> {
        // An undecryptable duplicate is skipped; the next same-named login is tried.
        Ok(self.ciphers()?.iter().filter(|c| c.kind == Cipher::LOGIN && c.name == name).find_map(|c| {
            (|| {
                Ok::<_, VaultError>(LoginRecord {
                    name: c.name.clone(),
                    username: c.username()?,
                    password: c.password()?,
                    totp: c.totp()?,
                    uri: c.uri()?,
                    notes: c.notes()?,
                })
            })()
            .ok()
        }))
    }

    fn delete_kind(&self, ciphers: &[Cipher], name: &str, kind: u8) -> Result<bool, VaultError> {
        let Some(found) = ciphers.iter().find(|c| c.kind == kind && c.name == name) else { return Ok(false) };
        let path = format!("/api/ciphers/{}", checked_id(&found.id)?);
        self.authed(Method::Delete, &path, Payload::None)?;
        Ok(true)
    }

    /// Delete the login named `name`. `Ok(false)` when there is none.
    pub fn delete_login(&self, name: &str) -> Result<bool, VaultError> {
        self.delete_kind(&self.ciphers()?, name, Cipher::LOGIN)
    }

    /// Delete the secure note named `name`. `Ok(false)` when there is none.
    pub fn delete_note(&self, name: &str) -> Result<bool, VaultError> {
        self.delete_kind(&self.ciphers()?, name, Cipher::SECURE_NOTE)
    }

    /// Delete the login named `name` or, failing that, the secure note of
    /// that name (where TOTP secrets live).
    pub fn delete(&self, name: &str) -> Result<bool, VaultError> {
        let ciphers = self.ciphers()?;
        Ok(self.delete_kind(&ciphers, name, Cipher::LOGIN)? || self.delete_kind(&ciphers, name, Cipher::SECURE_NOTE)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeVaultwarden, TEST_EMAIL, TEST_MASTER, TEST_USER_ID, test_options};

    fn login(fake: &FakeVaultwarden) -> Session {
        Session::login(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()).unwrap()
    }

    fn fake_enc(s: &str) -> Result<String, VaultError> {
        Ok(format!("ENC({s})"))
    }

    // --- login ------------------------------------------------------------ //

    #[test]
    fn login_speaks_the_bitwarden_wire_protocol() {
        let fake = FakeVaultwarden::start();
        fake.state().add_login("wazuh", "admin", "s3cr3t");
        // Mixed case and stray whitespace in the configured email are normalised.
        let session = Session::login(fake.url(), "  Kiosk@SOC.local ", TEST_MASTER, &test_options()).unwrap();
        assert_eq!(session.email(), TEST_EMAIL);
        assert_eq!(session.base_url(), fake.url());
        assert_eq!(session.user_id, TEST_USER_ID);

        let reqs = fake.server.requests();
        assert_eq!(fake.server.calls(), ["POST /identity/accounts/prelogin", "POST /identity/connect/token"]);
        assert_eq!(reqs[0].json(), json!({"email": TEST_EMAIL}));
        assert_eq!(reqs[0].header("content-type"), Some("application/json"));
        assert_eq!(reqs[1].header("content-type"), Some("application/x-www-form-urlencoded"));
        let form = reqs[1].form();
        let expect = [
            ("grant_type", "password"),
            ("username", TEST_EMAIL),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", "8"),
            ("deviceIdentifier", "soc-litebw-0001"),
            ("deviceName", "soc-litebw"),
        ];
        for (key, value) in expect {
            assert_eq!(form.get(key).map(String::as_str), Some(value), "{key}");
        }
        // The master password itself never goes on the wire — only its hash.
        let wire = String::from_utf8_lossy(&reqs[1].body).into_owned();
        assert!(!wire.contains("correct") && !wire.contains("horse"));
        let kdf = Kdf::Pbkdf2 { iterations: 5000 };
        let hash = MasterKey::derive(TEST_MASTER, TEST_EMAIL, kdf).unwrap().password_hash(TEST_MASTER);
        assert_eq!(form.get("password").map(String::as_str), Some(hash.as_str()));

        let items = session.ciphers().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "wazuh");
        assert_eq!(items[0].username().unwrap().as_str(), "admin");
        assert_eq!(items[0].password().unwrap().as_str(), "s3cr3t");
        let api = fake.server.requests().pop().unwrap();
        assert_eq!((api.method.as_str(), api.path.as_str()), ("GET", "/api/ciphers"));
        assert!(api.header("authorization").unwrap().starts_with("Bearer "));
    }

    #[test]
    fn pascal_case_prelogin_and_argon2id_accounts_log_in() {
        let kdf = Kdf::Argon2id { iterations: 2, memory_mib: 16, parallelism: 1 };
        let prelogin = json!({"Kdf": 1, "KdfIterations": 2, "KdfMemory": 16, "KdfParallelism": 1});
        let fake = FakeVaultwarden::start_with_kdf(kdf, prelogin);
        fake.state().add_login("a", "u", "p");
        assert_eq!(login(&fake).ciphers().unwrap().len(), 1);
    }

    #[test]
    fn missing_settings_fail_before_any_request() {
        let fake = FakeVaultwarden::start();
        let opts = test_options();
        assert!(
            matches!(Session::login("", TEST_EMAIL, TEST_MASTER, &opts), Err(VaultError::Config(m)) if m.contains("URL"))
        );
        assert!(
            matches!(Session::login(fake.url(), " ", TEST_MASTER, &opts), Err(VaultError::Config(m)) if m.contains("email"))
        );
        assert!(matches!(Session::login(fake.url(), TEST_EMAIL, "", &opts), Err(VaultError::NoMaster(_))));
        assert!(fake.server.requests().is_empty());
    }

    #[test]
    fn a_wrong_password_is_login_rejected_and_leaks_nothing() {
        let fake = FakeVaultwarden::start();
        let err = Session::login(fake.url(), TEST_EMAIL, "wrong-master-password", &test_options()).unwrap_err();
        assert!(matches!(&err, VaultError::LoginRejected(m) if m.contains("rejected the login")), "{err:?}");
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("wrong-master-password"));
        let hash = fake.server.requests()[1].form()["password"].clone();
        assert!(!shown.contains(&hash));
    }

    #[test]
    fn a_two_factor_challenge_is_explained() {
        let fake = FakeVaultwarden::start();
        fake.state().require_two_factor = true;
        let err = Session::login(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()).unwrap_err();
        assert!(matches!(&err, VaultError::LoginRejected(m) if m.contains("two-step")), "{err:?}");
    }

    #[test]
    fn a_kdf_downgrade_is_refused_before_the_hash_is_sent() {
        for weak in [
            json!({"kdf": 0, "kdfIterations": 1}),
            json!({"kdf": 1, "kdfIterations": 1, "kdfMemory": 1, "kdfParallelism": 1}),
        ] {
            let fake = FakeVaultwarden::start();
            fake.state().kdf = weak;
            let err = Session::login(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()).unwrap_err();
            assert!(matches!(err, VaultError::Kdf(_)), "{err:?}");
            assert_eq!(fake.server.calls(), ["POST /identity/accounts/prelogin"], "no token request may follow");
        }
    }

    #[test]
    fn hostile_prelogin_values_are_errors_not_work() {
        for evil in [
            json!({"kdf": 0, "kdfIterations": 2_000_000_000u64}),
            json!({"kdf": 1, "kdfIterations": 3, "kdfMemory": 8_000_000, "kdfParallelism": 4}),
            json!({"kdf": 0, "kdfIterations": "many"}),
            json!({"kdf": 0, "kdfIterations": -5}),
            json!({"kdf": 9, "kdfIterations": 600_000}),
        ] {
            let fake = FakeVaultwarden::start();
            fake.state().kdf = evil.clone();
            let started = std::time::Instant::now();
            let err = Session::login(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()).unwrap_err();
            assert!(matches!(err, VaultError::Kdf(_)), "{evil}: {err:?}");
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
        }
        let fake = FakeVaultwarden::start();
        fake.state().kdf = json!([1, 2, 3]);
        assert!(matches!(
            Session::login(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()),
            Err(VaultError::Protocol(_))
        ));
    }

    #[test]
    fn a_tampered_account_key_fails_closed() {
        let fake = FakeVaultwarden::start();
        // The server hands back a key wrapped under some other master.
        let other = MasterKey::derive("another password", TEST_EMAIL, Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        let forged = other.stretch().encrypt(&[7u8; 64]).unwrap();
        let server = crate::testutil::MockServer::start({
            let state = std::sync::Arc::clone(&fake.state);
            move |req| match req.path.as_str() {
                "/identity/accounts/prelogin" => crate::testutil::MockResponse::json(200, &state.lock().unwrap().kdf),
                _ => crate::testutil::MockResponse::json(200, &json!({"access_token": "a.b.c", "Key": forged})),
            }
        });
        let err = Session::login(&server.url, TEST_EMAIL, TEST_MASTER, &test_options()).unwrap_err();
        assert!(matches!(&err, VaultError::Crypto(m) if m.contains("account key")), "{err:?}");
    }

    #[test]
    fn a_token_response_without_a_key_is_a_protocol_error() {
        let server = crate::testutil::MockServer::start(|req| match req.path.as_str() {
            "/identity/accounts/prelogin" => {
                crate::testutil::MockResponse::json(200, &json!({"kdf": 0, "kdfIterations": 5000}))
            }
            _ => crate::testutil::MockResponse::json(200, &json!({"access_token": "a.b.c"})),
        });
        let err = Session::login(&server.url, TEST_EMAIL, TEST_MASTER, &test_options()).unwrap_err();
        assert!(matches!(err, VaultError::Protocol(_)), "{err:?}");
    }

    #[test]
    fn debug_output_holds_no_tokens() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        let shown = format!("{session:?}");
        let token = fake.state().valid_tokens[0].clone();
        assert!(shown.contains(TEST_EMAIL) && !shown.contains(&token) && !shown.contains("refresh-token-1"));
    }

    // --- token lifecycle ---------------------------------------------------- //

    #[test]
    fn an_expired_bearer_is_refreshed_once_without_the_master() {
        let fake = FakeVaultwarden::start();
        fake.state().add_login("wazuh", "admin", "s3cr3t");
        let session = login(&fake);
        fake.state().expire_tokens();
        fake.server.clear();

        assert_eq!(session.ciphers().unwrap().len(), 1);
        assert_eq!(fake.server.calls(), ["GET /api/ciphers", "POST /identity/connect/token", "GET /api/ciphers"]);
        let refresh = fake.server.requests()[1].form();
        assert_eq!(refresh.get("grant_type").map(String::as_str), Some("refresh_token"));
        assert_eq!(refresh.get("refresh_token").map(String::as_str), Some("refresh-token-1"));
        assert_eq!(refresh.get("client_id").map(String::as_str), Some("cli"));
        assert!(!refresh.contains_key("password"));
        assert_eq!(fake.password_logins(), 0);
        // The new bearer sticks.
        fake.server.clear();
        session.ciphers().unwrap();
        assert_eq!(fake.server.calls(), ["GET /api/ciphers"]);
    }

    #[test]
    fn a_refused_refresh_surfaces_the_401_and_is_not_retried() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        {
            let mut state = fake.state();
            state.expire_tokens();
            state.refresh_works = false;
        }
        fake.server.clear();
        assert_eq!(session.ciphers().unwrap_err().http_status(), Some(401));
        assert_eq!(session.ciphers().unwrap_err().http_status(), Some(401));
        // One refresh attempt in total: a refused token is dropped, not hammered.
        assert_eq!(fake.count("POST /identity/connect/token"), 1);
    }

    #[test]
    fn concurrent_401s_share_one_refresh() {
        let fake = FakeVaultwarden::start();
        fake.state().add_login("wazuh", "admin", "s3cr3t");
        let session = login(&fake);
        fake.state().expire_tokens();
        fake.server.clear();
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| assert_eq!(session.ciphers().unwrap().len(), 1));
            }
        });
        assert_eq!(fake.count("POST /identity/connect/token"), 1);
    }

    #[test]
    fn server_errors_and_bad_shapes_map_to_typed_errors() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        fake.state().api_failure = Some(500);
        let err = session.ciphers().unwrap_err();
        assert_eq!(err.http_status(), Some(500));
        assert!(
            err.to_string().contains("GET") && err.to_string().contains("/api/ciphers -> HTTP 500: simulated failure")
        );
        assert!(err.is_transient());

        assert!(matches!(list_data(b"<html>", "x"), Err(VaultError::Protocol(_))));
        assert!(matches!(list_data(b"\"text\"", "x"), Err(VaultError::Protocol(_))));
        assert!(matches!(list_data(b"{\"data\": 5}", "x"), Err(VaultError::Protocol(_))));
        assert_eq!(list_data(b"{\"Data\": [1]}", "x").unwrap(), vec![json!(1)]);
        assert_eq!(list_data(b"[2]", "x").unwrap(), vec![json!(2)]);
        assert!(list_data(b"{}", "x").unwrap().is_empty());
    }

    // --- reading ------------------------------------------------------------ //

    #[test]
    fn unusable_and_forged_items_are_skipped_without_losing_the_rest() {
        let fake = FakeVaultwarden::start();
        let foreign = SymKey::random().unwrap();
        {
            let mut s = fake.state();
            s.add_login("keep", "u", "pw");
            // Trashed: must never shadow a live item.
            let trashed = s.add_login("keep", "old-user", "old-pw");
            s.cipher_mut(&trashed)["deletedDate"] = json!("2026-01-01T00:00:00Z");
            // Organisation item: not our key.
            let org = s.add_login("org item", "u", "p");
            s.cipher_mut(&org)["organizationId"] = json!("org-1");
            // Encrypted under a key we do not hold.
            let alien = s.add_login("x", "u", "p");
            s.cipher_mut(&alien)["name"] = json!(foreign.encrypt_str("alien").unwrap());
            // A hostile server smuggling plaintext or MAC-less values.
            let plain = s.add_login("x", "u", "p");
            s.cipher_mut(&plain)["name"] = json!("SOC Panel 1");
            let type0 = s.add_login("x", "u", "p");
            s.cipher_mut(&type0)["name"] =
                json!(format!("0.{}|{}", crate::crypto::b64(&[1; 16]), crate::crypto::b64(&[2; 16])));
            let nameless = s.add_login("x", "u", "p");
            s.cipher_mut(&nameless)["name"] = Value::Null;
            s.ciphers.push(json!("not even an object"));
        }
        let items = login(&fake).ciphers().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "keep");
        assert_eq!(items[0].username().unwrap().as_str(), "u");
    }

    #[test]
    fn a_forged_field_fails_on_use_and_names_the_item() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let id = s.add_login("panel", "admin", "real");
            s.cipher_mut(&id)["login"]["password"] = json!("attacker-chosen-plaintext");
        }
        let item = login(&fake).find("panel").unwrap().unwrap();
        assert_eq!(item.username().unwrap().as_str(), "admin");
        let err = item.password().unwrap_err();
        assert!(matches!(&err, VaultError::Crypto(m) if m.contains("'panel'")), "{err:?}");
        assert!(!err.to_string().contains("attacker-chosen-plaintext"));
    }

    #[test]
    fn items_with_their_own_key_and_pascal_case_fields_decrypt() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let item_key = SymKey::random().unwrap();
            let wrapped = s.account_key.encrypt(item_key.to_bytes().as_slice()).unwrap();
            let e = |t: &str| item_key.encrypt_str(t).unwrap();
            s.ciphers.push(json!({
                "Id": "item-key-1", "Type": 1, "Key": wrapped, "Name": e("modern"), "Notes": e("the notes"),
                "FolderId": "f-1", "Favorite": true, "Reprompt": 1,
                "Login": {"Username": e("u"), "Password": e("p"), "Totp": e("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                    "Uris": [{"Uri": e("https://a.example/")}, {"Uri": e("https://b.example/")}]},
            }));
        }
        let item = login(&fake).find("modern").unwrap().unwrap();
        assert_eq!(
            (item.id.as_str(), item.kind, item.favorite, item.reprompt),
            ("item-key-1", Cipher::LOGIN, true, Some(1))
        );
        assert_eq!(item.folder_id.as_deref(), Some("f-1"));
        assert_eq!(item.password().unwrap().as_str(), "p");
        assert_eq!(item.notes().unwrap().as_str(), "the notes");
        assert_eq!(item.uri().unwrap().as_str(), "https://a.example/");
        assert!(item.has_totp() && item.has_password());
        assert_eq!(crate::totp::generate(&item.totp().unwrap(), 59).unwrap(), "287082");
        assert!(!format!("{item:?}").contains("2."), "Debug must not dump ciphertext fields");
    }

    #[test]
    fn folders_are_matched_by_decrypted_name() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let auth = s.add_folder("SOC Wall Auth");
            s.add_folder("Other");
            let a = s.add_login("SOC Settings TOTP", "", "");
            let b = s.add_login("SOC Panel Lock TOTP", "", "");
            s.add_login("unfiled", "u", "p");
            s.cipher_mut(&a)["folderId"] = json!(auth);
            s.cipher_mut(&b)["folderId"] = json!(auth);
        }
        let session = login(&fake);
        assert_eq!(session.names_in_folder("SOC Wall Auth").unwrap(), ["SOC Settings TOTP", "SOC Panel Lock TOTP"]);
        assert!(session.names_in_folder("Other").unwrap().is_empty());
        assert!(session.names_in_folder("does-not-exist").unwrap().is_empty());
    }

    // --- writing ------------------------------------------------------------ //

    #[test]
    fn login_body_shape_is_stable() {
        let spec = LoginSpec { name: "Item", username: "alice", password: "s3cret", ..LoginSpec::default() };
        let body = login_body(&fake_enc, &spec).unwrap();
        assert_eq!(
            body,
            json!({"type": 1, "name": "ENC(Item)", "favorite": false, "notes": null,
                "login": {"username": "ENC(alice)", "password": "ENC(s3cret)", "uris": null}})
        );
        assert!(body["login"].get("totp").is_none());
        assert!(body.get("encryptedFor").is_none());
        // Key order is part of the historical wire shape.
        assert_eq!(
            body.to_string(),
            r#"{"type":1,"name":"ENC(Item)","favorite":false,"notes":null,"login":{"username":"ENC(alice)","password":"ENC(s3cret)","uris":null}}"#
        );

        let spec = LoginSpec { notes: Some("hello"), uri: Some("https://x/"), totp: Some("JBSWY3DPEHPK3PXP"), ..spec };
        let body = login_body(&fake_enc, &spec).unwrap();
        assert_eq!(body["notes"], "ENC(hello)");
        assert_eq!(body["login"]["uris"], json!([{"uri": "ENC(https://x/)", "match": null}]));
        assert_eq!(body["login"]["totp"], "ENC(JBSWY3DPEHPK3PXP)");

        let empty = LoginSpec { name: "I", totp: Some(""), notes: Some(""), uri: Some(""), ..LoginSpec::default() };
        let body = login_body(&fake_enc, &empty).unwrap();
        assert!(body["login"].get("totp").is_none());
        assert_eq!(body["login"]["username"], Value::Null);
        assert_eq!(body["login"]["password"], Value::Null);
        assert_eq!(body["notes"], Value::Null);
    }

    #[test]
    fn note_body_shape_is_stable() {
        let body = note_body(&fake_enc, "N", "secret", None).unwrap();
        assert_eq!(
            body,
            json!({"type": 2, "name": "ENC(N)", "favorite": false, "notes": "ENC(secret)", "secureNote": {"type": 0}})
        );
        assert_eq!(note_body(&fake_enc, "N", "s", Some("folder-9")).unwrap()["folderId"], "folder-9");
    }

    #[test]
    fn user_id_comes_from_the_access_token() {
        let jwt = |claims: Value| format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
        assert_eq!(token_subject(&jwt(json!({"sub": "user-uuid"}))), "user-uuid");
        // Some issuers pad the payload; that is tolerated.
        let padded = format!("e30.{}=.sig", URL_SAFE_NO_PAD.encode(json!({"sub": "pad"}).to_string()));
        assert_eq!(token_subject(&padded), "pad");
        for bad in ["", "notajwt", "a.%%%.c", "a.bm90anNvbg.c", &jwt(json!({"sub": 5})), &jwt(json!([1]))] {
            assert_eq!(token_subject(bad), "", "{bad}");
        }
    }

    #[test]
    fn upsert_login_creates_then_updates_with_encrypted_fields() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        let spec = LoginSpec {
            name: "SOC Panel 1",
            username: "alice",
            password: "p@ss word!",
            totp: Some("JBSWY3DPEHPK3PXP"),
            uri: Some("https://siem.example/"),
            ..LoginSpec::default()
        };
        assert_eq!(session.upsert_login(&spec).unwrap(), Upsert::Created);
        let sent = fake.server.requests().pop().unwrap();
        assert_eq!((sent.method.as_str(), sent.path.as_str()), ("POST", "/api/ciphers"));
        let wire = String::from_utf8_lossy(&sent.body).into_owned();
        for secret in ["alice", "p@ss word!", "JBSWY3DPEHPK3PXP", "SOC Panel 1", "siem.example"] {
            assert!(!wire.contains(secret), "{secret} went out in the clear");
        }
        assert_eq!(sent.json()["encryptedFor"], TEST_USER_ID);
        assert!(sent.json()["login"]["password"].as_str().unwrap().starts_with("2."));

        let record = session.get_login("SOC Panel 1").unwrap().unwrap();
        assert_eq!(record.username.as_str(), "alice");
        assert_eq!(record.password.as_str(), "p@ss word!");
        assert_eq!(record.totp.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(record.uri.as_str(), "https://siem.example/");
        assert!(!format!("{record:?}").contains("p@ss"));

        // Second write updates in place.
        let changed = LoginSpec { password: "rotated", ..spec };
        assert_eq!(session.upsert_login(&changed).unwrap(), Upsert::Updated);
        let sent = fake.server.requests().pop().unwrap();
        assert_eq!((sent.method.as_str(), sent.path.as_str()), ("PUT", "/api/ciphers/cipher-1"));
        assert_eq!(fake.state().ciphers.len(), 1);
        assert_eq!(session.get_login("SOC Panel 1").unwrap().unwrap().password.as_str(), "rotated");
        assert_eq!(Upsert::Created.as_str(), "created");
        assert_eq!(Upsert::Updated.as_str(), "updated");
    }

    #[test]
    fn an_update_keeps_folder_favourite_and_reprompt() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let id = s.add_login("filed", "u", "old");
            let c = s.cipher_mut(&id);
            c["folderId"] = json!("folder-77");
            c["favorite"] = json!(true);
            c["reprompt"] = json!(1);
        }
        let session = login(&fake);
        let spec = LoginSpec { name: "filed", username: "u", password: "new", ..LoginSpec::default() };
        assert_eq!(session.upsert_login(&spec).unwrap(), Upsert::Updated);
        let stored = fake.state().ciphers[0].clone();
        assert_eq!(stored["folderId"], "folder-77");
        assert_eq!(stored["favorite"], true);
        assert_eq!(stored["reprompt"], 1);
    }

    #[test]
    fn a_login_write_never_lands_on_a_note_or_a_trashed_item() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        session.upsert_secure_note("shared name", "note body", None).unwrap();
        {
            let mut s = fake.state();
            let trashed = s.add_login("shared name", "u", "trashed");
            s.cipher_mut(&trashed)["deletedDate"] = json!("2026-01-01T00:00:00Z");
        }
        let spec = LoginSpec { name: "shared name", username: "u", password: "p", ..LoginSpec::default() };
        assert_eq!(session.upsert_login(&spec).unwrap(), Upsert::Created);
        assert_eq!(fake.state().ciphers.len(), 3);
        // And the note write updates the note, not the login.
        assert_eq!(session.upsert_secure_note("shared name", "new body", None).unwrap(), Upsert::Updated);
        assert_eq!(session.get_login("shared name").unwrap().unwrap().password.as_str(), "p");
    }

    #[test]
    fn rename_in_place_and_its_collision_guard() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            s.add_login("old", "u", "p");
            s.add_login("taken", "u2", "p2");
        }
        let session = login(&fake);
        let rename = |to: &'static str, from: &'static str| LoginSpec {
            name: to,
            username: "u",
            password: "p",
            rename_from: Some(from),
            ..LoginSpec::default()
        };
        // A different login already owns the new name: fail closed.
        let err = session.upsert_login(&rename("taken", "old")).unwrap_err();
        assert!(matches!(&err, VaultError::Conflict(m) if m.contains("'taken' already exists")), "{err:?}");
        assert_eq!(session.get_login("taken").unwrap().unwrap().username.as_str(), "u2");

        assert_eq!(session.upsert_login(&rename("new", "old")).unwrap(), Upsert::Updated);
        assert!(session.get_login("old").unwrap().is_none());
        assert!(session.get_login("new").unwrap().is_some());
        assert_eq!(fake.state().ciphers.len(), 2);

        // The source vanished: the renamed login is created fresh.
        assert_eq!(session.upsert_login(&rename("fresh", "gone")).unwrap(), Upsert::Created);
        // rename_from equal to the name (or empty) is a plain upsert.
        assert_eq!(session.upsert_login(&rename("fresh", "fresh")).unwrap(), Upsert::Updated);
        assert_eq!(session.upsert_login(&rename("fresh", "")).unwrap(), Upsert::Updated);
    }

    #[test]
    fn secure_notes_are_filed_in_a_folder_created_once() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        assert_eq!(
            session.upsert_secure_note("SOC Settings TOTP", "JBSWY3DPEHPK3PXP", Some("SOC Wall Auth")).unwrap(),
            Upsert::Created
        );
        assert_eq!(
            session.upsert_secure_note("SOC Panel Lock TOTP", "ABCD2345", Some("SOC Wall Auth")).unwrap(),
            Upsert::Created
        );
        assert_eq!(
            session.upsert_secure_note("SOC Settings TOTP", "NEWSECRET234", Some("SOC Wall Auth")).unwrap(),
            Upsert::Updated
        );
        assert_eq!(fake.count("POST /api/folders"), 1);
        {
            let s = fake.state();
            assert_eq!(s.folders.len(), 1);
            assert_eq!(s.ciphers.len(), 2);
            assert_eq!(s.ciphers[0]["type"], 2);
            assert_eq!(s.ciphers[0]["secureNote"], json!({"type": 0}));
            assert_eq!(s.ciphers[0]["folderId"], s.folders[0]["id"]);
            assert!(!s.ciphers[0].to_string().contains("NEWSECRET234"));
        }
        assert_eq!(session.names_in_folder("SOC Wall Auth").unwrap().len(), 2);
        assert_eq!(session.find("SOC Settings TOTP").unwrap().unwrap().notes().unwrap().as_str(), "NEWSECRET234");
    }

    #[test]
    fn listing_never_returns_passwords_and_skips_notes() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        let spec = LoginSpec {
            name: "wazuh",
            username: "admin",
            password: "s3cr3t",
            uri: Some("https://w/"),
            totp: Some("GEZDGNBVGY3TQOJQ"),
            ..LoginSpec::default()
        };
        session.upsert_login(&spec).unwrap();
        session
            .upsert_login(&LoginSpec { name: "plain", username: "", password: "x", ..LoginSpec::default() })
            .unwrap();
        session.upsert_secure_note("a note", "body", None).unwrap();
        let rows = session.list_logins().unwrap();
        assert_eq!(
            rows,
            [
                LoginSummary {
                    name: "wazuh".into(),
                    username: "admin".into(),
                    has_totp: true,
                    uri: "https://w/".into()
                },
                LoginSummary { name: "plain".into(), username: String::new(), has_totp: false, uri: String::new() },
            ]
        );
        assert!(session.get_login("a note").unwrap().is_none());
        assert!(session.get_login("missing").unwrap().is_none());
    }

    #[test]
    fn delete_prefers_the_login_then_the_note() {
        let fake = FakeVaultwarden::start();
        let session = login(&fake);
        session.upsert_login(&LoginSpec { name: "x", username: "u", password: "p", ..LoginSpec::default() }).unwrap();
        session.upsert_secure_note("x", "note", None).unwrap();
        session.upsert_secure_note("only-note", "note", None).unwrap();
        fake.server.clear();

        assert!(!session.delete("missing").unwrap());
        assert_eq!(fake.server.calls(), ["GET /api/ciphers"], "nothing to delete means no DELETE");

        assert!(session.delete("x").unwrap());
        let last = fake.server.requests().pop().unwrap();
        assert_eq!((last.method.as_str(), last.path.as_str()), ("DELETE", "/api/ciphers/cipher-1"));
        assert!(last.header("authorization").unwrap().starts_with("Bearer "));
        assert!(session.get_login("x").unwrap().is_none());
        assert!(session.find("x").unwrap().is_some(), "the note of the same name survives");

        assert!(session.delete("x").unwrap());
        assert!(session.find("x").unwrap().is_none());
        assert!(!session.delete_login("only-note").unwrap());
        assert!(session.delete_note("only-note").unwrap());
        assert!(fake.state().ciphers.is_empty());
    }

    #[test]
    fn a_failed_delete_is_an_error_not_a_quiet_false() {
        let fake = FakeVaultwarden::start();
        fake.state().add_login("x", "u", "p");
        let session = login(&fake);
        let ciphers = session.ciphers().unwrap();
        fake.state().api_failure = Some(500);
        assert_eq!(session.delete_kind(&ciphers, "x", Cipher::LOGIN).unwrap_err().http_status(), Some(500));
    }

    #[test]
    fn hostile_item_ids_never_reach_a_request_path() {
        let fake = FakeVaultwarden::start();
        {
            let mut s = fake.state();
            let id = s.add_login("x", "u", "p");
            s.cipher_mut(&id)["id"] = json!("../../identity/accounts/delete");
        }
        let session = login(&fake);
        fake.server.clear();
        assert!(matches!(session.delete("x"), Err(VaultError::Protocol(_))));
        let spec = LoginSpec { name: "x", username: "u", password: "p2", ..LoginSpec::default() };
        assert!(matches!(session.upsert_login(&spec), Err(VaultError::Protocol(_))));
        assert!(fake.server.calls().iter().all(|c| c == "GET /api/ciphers"), "{:?}", fake.server.calls());
    }
}
