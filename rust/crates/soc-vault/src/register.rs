//! Create / verify a Vaultwarden account from the host, so first-run setup can
//! make the kiosk account instead of dead-ending on the cryptic HTTP 400 that
//! an absent account produces at login.
//!
//! The master password is an in-memory argument only: never written to a file,
//! never placed in argv, never logged.

use serde_json::{Value, json};

use crate::crypto::{Kdf, MasterKey, SymKey, b64, normalize_email};
use crate::error::VaultError;
use crate::http::{Http, HttpOptions, Method, Payload};
use crate::session::{Session, SessionOptions};

/// Vaultwarden's current default. An *existing* account's count comes from
/// `prelogin`; a *new* account is registered with this.
pub const KDF_ITERATIONS: u32 = 600_000;

/// The display name given to the kiosk account.
pub const DEFAULT_ACCOUNT_NAME: &str = "SOC Kiosk";

/// Step one of a current registration: ask for a token.
const VERIFY_ENDPOINT: &str = "/identity/accounts/register/send-verification-email";
/// Step two, with the token.
const FINISH_ENDPOINT: &str = "/identity/accounts/register/finish";
/// Single-step registration on servers that predate the token. A 404 means
/// "not this version", so the next one is tried.
const LEGACY_ENDPOINTS: [&str; 2] = ["/api/accounts/register", "/identity/accounts/register"];

/// The outcome of a registration attempt that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// The account was created.
    Created,
    /// The server reports the account already exists.
    Exists,
}

/// Produces `(public key, base64 SPKI DER)` and `(private key, PKCS#8 DER as
/// an EncString under the account key)`. Injected so tests need not spend
/// seconds generating RSA keys in a debug build.
type KeyPair<'a> = &'a dyn Fn(&SymKey) -> Result<(String, String), VaultError>;

/// Generate the account's RSA keypair, wrapped the way the web vault does it
/// so the result is a fully-formed Bitwarden account.
fn rsa_keypair(account_key: &SymKey, bits: usize) -> Result<(String, String), VaultError> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let fail = |what: &str| VaultError::Crypto(format!("cannot create the account's RSA keypair ({what})"));
    let private = rsa::PrivateKey::new(&mut getrandom::SysRng, bits).map_err(|_| fail("generation"))?; // audit-allow: rsa error is opaque; fail() names the stage without key material
    let public_der = private.to_public_key().to_public_key_der().map_err(|_| fail("public key encoding"))?; // audit-allow: rsa error is opaque; fail() names the stage without key material
    let private_der = private.to_pkcs8_der().map_err(|_| fail("private key encoding"))?; // audit-allow: rsa error is opaque; fail() names the stage without key material
    Ok((b64(public_der.as_bytes()), account_key.encrypt(private_der.as_bytes())?))
}

/// Step one of a modern registration. With no mail server configured the
/// token comes straight back, as raw text rather than JSON. `None` on a
/// server too old to have this step.
fn verification_token(http: &Http, email: &str, name: &str) -> Result<Option<String>, VaultError> {
    let body = json!({"email": email, "name": name});
    let reply = http.send(Method::Post, VERIFY_ENDPOINT, None, Payload::Json(&body))?;
    if reply.status == 404 {
        return Ok(None);
    }
    if !reply.is_success() {
        return Err(http.status_error(Method::Post, VERIFY_ENDPOINT, &reply));
    }
    let text = String::from_utf8_lossy(&reply.body);
    let token = text.trim().trim_matches('"');
    // A token is a compact JWT-like string; anything else (an HTML page from a
    // proxy, say) must not be echoed back to the server as if it were one.
    let plausible = !token.is_empty() && token.len() <= 4096 && token.bytes().all(|b| b.is_ascii_graphic());
    Ok(plausible.then(|| token.to_string()))
}

fn looks_like(text: &str, needles: &[&str]) -> bool {
    let lower = text.to_lowercase();
    needles.iter().any(|n| lower.contains(n))
}

/// Turn a refused registration into the caller-visible outcome. Vaultwarden
/// gives one answer for two cases — "Registration not allowed or user already
/// exists" — so "not allowed" is checked first, and [`ensure_account`] tells
/// the two apart by trying a login.
fn classify(error: VaultError) -> Result<Registered, VaultError> {
    let VaultError::Http { message, .. } = &error else { return Err(error) };
    if looks_like(message, &["signups", "not allowed", "disabled", "whitelist", "blacklisted"]) {
        return Err(VaultError::SignupsDisabled(format!(
            "Vaultwarden is refusing this registration: signups are off (enable SIGNUPS_ALLOWED, or whitelist this \
             email domain), or the account already exists. Server said: {message}"
        )));
    }
    if looks_like(message, &["already", "exists", "in use"]) {
        return Ok(Registered::Exists);
    }
    Err(error)
}

fn register_with(
    url: &str,
    email: &str,
    master: &str,
    name: &str,
    kdf_iterations: u32,
    opts: &HttpOptions,
    keypair: KeyPair<'_>,
) -> Result<Registered, VaultError> {
    // The account boundary must never be driven with an empty master (an
    // EOF or placeholder leaking out of a non-interactive resolver).
    if master.is_empty() {
        return Err(VaultError::NoMaster("refusing to register with an empty master password".into()));
    }
    let kdf = Kdf::from_prelogin(0, u64::from(kdf_iterations), 0, 0)?;
    let http = Http::new(url, opts)?;
    let email = normalize_email(email);
    if email.is_empty() {
        return Err(VaultError::Config("no vault email to register".into()));
    }

    let master_key = MasterKey::derive(master, &email, kdf)?;
    let account_key = SymKey::random()?;
    let (public_key, encrypted_private_key) = keypair(&account_key)?;
    let mut body = json!({
        "email": email,
        "name": name,
        "masterPasswordHash": master_key.password_hash(master).as_str(),
        "masterPasswordHint": null,
        "key": master_key.stretch().encrypt(account_key.to_bytes().as_slice())?,
        "kdf": 0,
        "kdfIterations": kdf_iterations,
        "keys": {"publicKey": public_key, "encryptedPrivateKey": encrypted_private_key},
    });

    let token = match verification_token(&http, &email, name) {
        Ok(token) => token,
        Err(e) => return classify(e),
    };
    let endpoints: &[&str] = match &token {
        Some(token) => {
            body["emailVerificationToken"] = Value::String(token.clone());
            &[FINISH_ENDPOINT]
        }
        None => &LEGACY_ENDPOINTS,
    };
    let mut last = VaultError::Protocol(format!("registration failed at {}", http.base()));
    for endpoint in endpoints {
        match http.request(Method::Post, endpoint, None, Payload::Json(&body)) {
            Ok(_) => return Ok(Registered::Created),
            Err(e) if e.http_status() == Some(404) => last = e,
            Err(e) => return classify(e),
        }
    }
    Err(last)
}

/// Register a Bitwarden/Vaultwarden account (PBKDF2, `kdf_iterations` rounds).
///
/// `Ok(Created)` on success, `Ok(Exists)` if the server says the account is
/// already there, [`VaultError::SignupsDisabled`] if it refuses signups.
pub fn register_account(
    url: &str,
    email: &str,
    master: &str,
    name: &str,
    kdf_iterations: u32,
    opts: &HttpOptions,
) -> Result<Registered, VaultError> {
    register_with(url, email, master, name, kdf_iterations, opts, &|key| rsa_keypair(key, 2048))
}

/// True if `email` + `master` opens a session. False if the server rejects
/// the login (no account OR wrong password — the API hides which). Anything
/// else, such as an unreachable vault, is an error.
pub fn account_exists(url: &str, email: &str, master: &str, opts: &SessionOptions) -> Result<bool, VaultError> {
    match Session::login(url, email, master, opts) {
        Ok(_) => Ok(true),
        Err(VaultError::LoginRejected(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

fn ensure_with(
    url: &str,
    email: &str,
    master: &str,
    name: &str,
    opts: &SessionOptions,
    keypair: KeyPair<'_>,
) -> Result<Registered, VaultError> {
    // A login first: it is the one thing that proves the account exists AND
    // that this master opens it. Only a rejected login leads to registration;
    // an unreachable or misbehaving vault is reported as what it is.
    if account_exists(url, email, master, opts)? {
        return Ok(Registered::Exists);
    }
    match register_with(url, email, master, name, KDF_ITERATIONS, &opts.http, keypair)? {
        Registered::Created => Ok(Registered::Created),
        Registered::Exists => Err(VaultError::WrongMaster(format!(
            "an account for {} already exists but the master password is incorrect — enter the existing master (or \
             reset it in the web vault).",
            normalize_email(email)
        ))),
    }
}

/// Make sure the account exists AND the master unlocks it.
///
/// `Ok(Exists)` when it is already there and the master is right,
/// `Ok(Created)` when it was just registered. [`VaultError::WrongMaster`] if
/// it exists but the master is wrong — an existing vault is never
/// re-registered or clobbered.
pub fn ensure_account(
    url: &str,
    email: &str,
    master: &str,
    name: &str,
    opts: &SessionOptions,
) -> Result<Registered, VaultError> {
    ensure_with(url, email, master, name, opts, &|key| rsa_keypair(key, 2048))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        FakeVaultwarden, MockRequest, MockResponse, MockServer, TEST_EMAIL, TEST_MASTER, test_options,
    };
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    const REFUSED: &str = "Registration not allowed or user already exists";

    #[derive(Default)]
    struct Registry {
        accounts: HashSet<String>,
        signups_off: bool,
        legacy: bool,
        /// A server that pre-dates the token step but is not "legacy" either.
        no_token_step: bool,
    }

    /// Behaves as a live Vaultwarden 1.37 was observed to: two-step
    /// registration, a raw-text token, and one message for two refusals.
    fn registry_server(state: &Arc<Mutex<Registry>>) -> MockServer {
        let state = Arc::clone(state);
        MockServer::start(move |req: &MockRequest| {
            let mut s = state.lock().unwrap();
            let body = req.json();
            let email = body["email"].as_str().unwrap_or("").to_string();
            let refuse = |msg: &str| MockResponse::json(400, &json!({"message": msg}));
            let not_found = || MockResponse::json(404, &json!({"error": "Not Found"}));
            if req.path == "/identity/connect/token" || req.path == "/identity/accounts/prelogin" {
                return not_found();
            }
            if s.legacy {
                return if req.path == "/api/accounts/register" {
                    s.accounts.insert(email);
                    MockResponse::text(200, "")
                } else {
                    not_found()
                };
            }
            match req.path.as_str() {
                VERIFY_ENDPOINT if s.no_token_step => not_found(),
                VERIFY_ENDPOINT if s.signups_off => refuse(REFUSED),
                VERIFY_ENDPOINT => MockResponse::text(200, "\"eyJ.token.sig\""),
                FINISH_ENDPOINT if body.get("emailVerificationToken").is_none() => {
                    refuse("Registration is missing required parameters")
                }
                FINISH_ENDPOINT if s.accounts.contains(&email) || s.signups_off => refuse(REFUSED),
                FINISH_ENDPOINT => {
                    s.accounts.insert(email);
                    MockResponse::text(200, "")
                }
                "/identity/accounts/register" => refuse("Registration is missing required parameters"),
                _ => not_found(),
            }
        })
    }

    fn fake_keys(_: &SymKey) -> Result<(String, String), VaultError> {
        Ok(("PUBLIC".to_string(), "2.wrapped-private".to_string()))
    }

    fn register(server: &MockServer, master: &str) -> Result<Registered, VaultError> {
        register_with(&server.url, "A@B.c", master, DEFAULT_ACCOUNT_NAME, 5000, &test_options().http, &fake_keys)
    }

    #[test]
    fn registration_is_two_steps_and_sends_the_token() {
        let state = Arc::new(Mutex::new(Registry::default()));
        let server = registry_server(&state);
        assert_eq!(register(&server, "master").unwrap(), Registered::Created);
        assert_eq!(server.calls(), [format!("POST {VERIFY_ENDPOINT}"), format!("POST {FINISH_ENDPOINT}")]);
        let reqs = server.requests();
        assert_eq!(reqs[0].json(), json!({"email": "a@b.c", "name": "SOC Kiosk"}));
        let body = reqs[1].json();
        assert_eq!(body["emailVerificationToken"], "eyJ.token.sig");
        assert_eq!(body["email"], "a@b.c");
        assert_eq!(body["name"], "SOC Kiosk");
        assert_eq!(body["kdf"], 0);
        assert_eq!(body["kdfIterations"], 5000);
        assert_eq!(body["masterPasswordHint"], Value::Null);
        assert_eq!(body["keys"], json!({"publicKey": "PUBLIC", "encryptedPrivateKey": "2.wrapped-private"}));
        assert!(state.lock().unwrap().accounts.contains("a@b.c"));
    }

    #[test]
    fn the_registered_account_can_be_opened_with_the_same_master() {
        let state = Arc::new(Mutex::new(Registry::default()));
        let server = registry_server(&state);
        register(&server, "the master pässword").unwrap();
        let body = server.requests()[1].json();
        // What the server stored is exactly what a later login would verify and unwrap.
        let master_key = MasterKey::derive("the master pässword", "a@b.c", Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        assert_eq!(body["masterPasswordHash"], master_key.password_hash("the master pässword").as_str());
        let account_key = master_key.stretch().decrypt(body["key"].as_str().unwrap()).unwrap();
        assert_eq!(account_key.len(), 64);
        let wire = body.to_string();
        assert!(!wire.contains("pässword"), "the master must never be sent");
    }

    #[test]
    fn signups_off_is_reported_as_signups_off_not_as_an_existing_account() {
        let state = Arc::new(Mutex::new(Registry { signups_off: true, ..Registry::default() }));
        let server = registry_server(&state);
        // The message contains both "not allowed" and "exists".
        assert!(matches!(register(&server, "master"), Err(VaultError::SignupsDisabled(m)) if m.contains(REFUSED)));
    }

    #[test]
    fn a_malformed_registration_is_not_mistaken_for_signups_off() {
        let state = Arc::new(Mutex::new(Registry { no_token_step: true, ..Registry::default() }));
        let server = registry_server(&state);
        let err = register(&server, "master").unwrap_err();
        assert_eq!(err.http_status(), Some(400), "{err:?}");
        assert!(err.to_string().contains("missing required parameters"));
    }

    #[test]
    fn older_servers_register_in_one_step() {
        let state = Arc::new(Mutex::new(Registry { legacy: true, ..Registry::default() }));
        let server = registry_server(&state);
        assert_eq!(register(&server, "master").unwrap(), Registered::Created);
        assert_eq!(server.calls().last().unwrap(), "POST /api/accounts/register");
        assert!(server.requests().last().unwrap().json().get("emailVerificationToken").is_none());
    }

    #[test]
    fn a_server_with_no_registration_endpoint_reports_the_404() {
        let server = MockServer::start(|_| MockResponse::json(404, &json!({"error": "Not Found"})));
        let err = register(&server, "master").unwrap_err();
        assert_eq!(err.http_status(), Some(404));
        assert_eq!(server.calls().len(), 3);
    }

    #[test]
    fn an_empty_or_weakly_stretched_master_is_never_registered() {
        let state = Arc::new(Mutex::new(Registry::default()));
        let server = registry_server(&state);
        assert!(matches!(register(&server, ""), Err(VaultError::NoMaster(_))));
        let weak = register_with(&server.url, "a@b.c", "master", "n", 1, &test_options().http, &fake_keys);
        assert!(matches!(weak, Err(VaultError::Kdf(_))));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_non_token_answer_is_not_replayed_as_a_token() {
        let server = MockServer::start(|req| match req.path.as_str() {
            VERIFY_ENDPOINT => MockResponse::text(200, "<html>\n<body>proxy login</body></html>"),
            "/api/accounts/register" => MockResponse::text(200, ""),
            _ => MockResponse::text(404, ""),
        });
        assert_eq!(register(&server, "master").unwrap(), Registered::Created);
        assert!(server.requests().last().unwrap().json().get("emailVerificationToken").is_none());
    }

    #[test]
    fn rsa_keypair_is_a_wrapped_pkcs8_key_with_its_spki_public_half() {
        use base64::Engine;
        use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
        let account_key = SymKey::random().unwrap();
        // 1024 bits keeps a debug-build test quick; production uses 2048 via the same code.
        let (public, wrapped_private) = rsa_keypair(&account_key, 1024).unwrap();
        let public_der = base64::engine::general_purpose::STANDARD.decode(public).unwrap();
        let public = rsa::PublicKey::from_public_key_der(&public_der).unwrap();
        let private_der = account_key.decrypt(&wrapped_private).unwrap();
        let private = rsa::PrivateKey::from_pkcs8_der(&private_der).unwrap();
        assert_eq!(private.to_public_key().to_public_key_der().unwrap().as_bytes(), public_der.as_slice());
        assert_eq!(public, private.to_public_key());
        assert!(rsa_keypair(&account_key, 512).is_err(), "undersized keys are refused");
    }

    // --- ensure_account ------------------------------------------------------- //

    #[test]
    fn an_existing_account_with_the_right_master_never_touches_registration() {
        let fake = FakeVaultwarden::start();
        let got = ensure_with(fake.url(), TEST_EMAIL, TEST_MASTER, "n", &test_options(), &fake_keys).unwrap();
        assert_eq!(got, Registered::Exists);
        assert!(fake.server.calls().iter().all(|c| !c.contains("register")), "{:?}", fake.server.calls());
        assert!(account_exists(fake.url(), TEST_EMAIL, TEST_MASTER, &test_options()).unwrap());
        assert!(!account_exists(fake.url(), TEST_EMAIL, "wrong", &test_options()).unwrap());
    }

    /// A server whose login always fails and whose registration answers `status`/`message`.
    fn rejecting_server(register_status: u16, register_message: &'static str) -> MockServer {
        MockServer::start(move |req| match req.path.as_str() {
            "/identity/accounts/prelogin" => MockResponse::json(200, &json!({"kdf": 0, "kdfIterations": 5000})),
            "/identity/connect/token" => {
                MockResponse::json(400, &json!({"message": "Username or password is incorrect. Try again"}))
            }
            VERIFY_ENDPOINT => MockResponse::text(200, "tok"),
            FINISH_ENDPOINT if register_status == 200 => MockResponse::text(200, ""),
            FINISH_ENDPOINT => MockResponse::json(register_status, &json!({"message": register_message})),
            _ => MockResponse::text(404, ""),
        })
    }

    #[test]
    fn a_rejected_login_leads_to_registration() {
        let server = rejecting_server(200, "");
        let got = ensure_with(&server.url, "a@b.c", "master", "SOC Kiosk", &test_options(), &fake_keys).unwrap();
        assert_eq!(got, Registered::Created);
        // A new account is registered at the full default cost, never a weak one.
        assert_eq!(server.requests().last().unwrap().json()["kdfIterations"], KDF_ITERATIONS);
    }

    #[test]
    fn closed_signups_surface_so_the_caller_can_open_them() {
        let server = rejecting_server(400, REFUSED);
        let got = ensure_with(&server.url, "a@b.c", "master", "n", &test_options(), &fake_keys);
        assert!(matches!(got, Err(VaultError::SignupsDisabled(_))));
    }

    #[test]
    fn a_wrong_master_on_an_existing_account_is_named_as_such() {
        let server = rejecting_server(400, "Email 'a@b.c' is already taken");
        let got = ensure_with(&server.url, "A@b.c", "master", "n", &test_options(), &fake_keys);
        assert!(matches!(got, Err(VaultError::WrongMaster(m)) if m.contains("a@b.c already exists")));
    }

    #[test]
    fn an_unreachable_vault_is_reported_as_unreachable_not_registered() {
        let dead = crate::testutil::dead_url();
        let got = ensure_with(&dead, "a@b.c", "master", "n", &test_options(), &fake_keys);
        assert!(matches!(got, Err(VaultError::Unreachable(_))));
    }
}
