"""
Create / verify a Vaultwarden account from the host (Setup wizard + CLI).

Ports ``dev/register-vaultwarden.py``'s Bitwarden PBKDF2 registration into the
running host so the GUI's Vault page can *create* the kiosk account when it does
not exist yet — instead of dead-ending on the cryptic ``HTTP 400 'Username or
password is incorrect'`` that an absent account produces at login.

It REUSES ``vaultseed``'s crypto primitives (``_enc`` / ``_hkdf_expand`` /
``_b64`` and the same master-key / master-hash KDF flow) so there is no second
crypto implementation to drift. The only pieces unique to registration are the
RSA-2048 keypair and the ``/api/accounts/register`` POST.

The master password is an in-memory argument only — it is NEVER written to a
file, never placed in argv, never logged.

Error model (so the GUI can give an actionable message instead of a guess):

  * ``SignupsDisabledError`` — the server refused the signup (``SIGNUPS_ALLOWED``
    is off / domain not whitelisted). The operator must enable signups or add the
    account in the web vault.
  * ``WrongMasterError``     — the account ALREADY exists but the supplied master
    does not unlock it. We must NOT re-register (that would never clobber an
    existing vault, but the user needs to be told it's the wrong password).
  * ``VaultSeedError``       — transport / crypto / unexpected-status failures
    (re-used from vaultseed so callers catch one base type).
"""
from __future__ import annotations

import urllib.error

from host import vaultseed
from host.vaultseed import VaultSeedError, _b64, _enc, _hkdf_expand, _req

# Vaultwarden's current default. The actual iteration count for an *existing*
# account comes from prelogin (vaultseed.Session honours it); for a *new* account
# we register with this and Vaultwarden stores it.
KDF_ITERS = 600_000


class SignupsDisabledError(VaultSeedError):
    """The server rejected the registration because signups are disabled."""


class WrongMasterError(VaultSeedError):
    """The account exists but the supplied master password does not unlock it."""


def _rsa_keypair(sym_key: bytes):
    """Generate an RSA-2048 keypair and return (public_b64, encrypted_private_b64).

    The private key is wrapped with the user symmetric key exactly like the web
    vault does, so the registered account is a fully-formed Bitwarden account
    (matches dev/register-vaultwarden.py)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise VaultSeedError(
            "the 'cryptography' package is required to create a Vaultwarden "
            "account — install it (pip install cryptography), or create the "
            "account in the Vaultwarden web vault instead")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    enc_priv = _enc(priv_der, sym_key[:32], sym_key[32:])
    return _b64(pub_der), enc_priv


def _looks_like(body: str, *needles: str) -> bool:
    low = (body or "").lower()
    return any(n in low for n in needles)


def register_account(url: str, email: str, master: str,
                     name: str = "SOC Kiosk") -> str:
    """Register a Bitwarden/Vaultwarden account. Returns ``'created'`` on success
    or ``'exists'`` if the server reports the account already exists.

    REUSES vaultseed's master-key / master-hash KDF and ``_enc`` / ``_hkdf_expand``
    so the protected symmetric key matches a vaultseed/litebw login. The master is
    an in-memory argument only.

    Raises ``SignupsDisabledError`` if the server refuses signups, ``VaultSeedError``
    on any other failure (transport, crypto, unexpected status)."""
    import hashlib
    import os

    # Defence in depth: the account boundary must never be driven with an empty
    # master (e.g. an EOF/placeholder leaking out of a non-interactive resolver).
    # Fail CLOSED here so a blank master can never register a vault.
    if not master:
        raise VaultSeedError("refusing to register with an empty master password")

    base = url.rstrip("/")
    email = email.lower()
    pw = master.encode()

    # Same KDF flow as vaultseed.Session.__init__ (PBKDF2-SHA256), registering at
    # Vaultwarden's default iteration count.
    master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), KDF_ITERS, 32)
    master_hash = _b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
    senc = _hkdf_expand(master_key, b"enc")
    smac = _hkdf_expand(master_key, b"mac")

    sym_key = os.urandom(64)                       # 32 enc || 32 mac
    protected_key = _enc(sym_key, senc, smac)
    pub_b64, enc_priv = _rsa_keypair(sym_key)

    body = {
        "email": email,
        "name": name,
        "masterPasswordHash": master_hash,
        "masterPasswordHint": None,
        "key": protected_key,
        "kdf": 0,                                  # 0 = PBKDF2_SHA256
        "kdfIterations": KDF_ITERS,
        "keys": {"publicKey": pub_b64, "encryptedPrivateKey": enc_priv},
    }

    last_err = None
    for ep in ("/api/accounts/register", "/identity/accounts/register"):
        try:
            _req(base + ep, data=body, method="POST")
            return "created"
        except VaultSeedError as e:
            # _req flattens HTTPError into a VaultSeedError whose message carries
            # the status + body. Classify on that text (no second request).
            msg = str(e)
            if _looks_like(msg, "already", "exists", "in use"):
                return "exists"
            if _looks_like(msg, "signups", "registration", "not allowed",
                           "disabled", "whitelist", "blacklisted"):
                raise SignupsDisabledError(
                    "Vaultwarden is refusing signups — enable SIGNUPS_ALLOWED "
                    "(or whitelist this email domain) on the server, or create "
                    f"the account in the web vault. Server said: {msg}")
            last_err = e
        except urllib.error.URLError as e:  # pragma: no cover - transport
            raise VaultSeedError(f"could not reach Vaultwarden at {base}: {e}")
    raise last_err or VaultSeedError(f"registration failed at {base}")


def account_exists(url: str, email: str) -> bool:
    """Best-effort probe: does an account for ``email`` exist?

    Vaultwarden's ``/identity/accounts/prelogin`` returns KDF parameters for any
    email (defaults for unknown ones), so it can't authoritatively answer. The
    authoritative check is a register attempt (``'exists'`` vs ``'created'``);
    callers that must not create should prefer ``ensure_account``. This helper
    exists for the GUI's failure-branch heuristic only and returns False when it
    cannot tell."""
    base = url.rstrip("/")
    try:
        _req(base + "/identity/accounts/prelogin",
             data={"email": email.lower()}, method="POST")
        # prelogin succeeding tells us the server is up, not that the account
        # exists. We can't distinguish here — the caller uses register/login.
        return False
    except VaultSeedError:
        return False


def ensure_account(url: str, email: str, master: str,
                   name: str = "SOC Kiosk") -> str:
    """Provision-core entry: make sure the account exists AND the master unlocks it.

    Returns ``'created'`` (we registered it) or ``'exists'`` (already there and the
    master is correct). Raises ``WrongMasterError`` if the account exists but the
    master is wrong (NEVER re-registers — an existing vault is never clobbered),
    or ``SignupsDisabledError`` / ``VaultSeedError`` per ``register_account``.

    The master is an in-memory argument; nothing is written to disk."""
    result = register_account(url, email, master, name=name)
    if result == "created":
        return "created"
    # 'exists' — verify the supplied master actually unlocks it. A successful
    # ReadSession login (prelogin -> token -> decrypt) is the authoritative check.
    from host import litebw  # lazy: avoids importing litebw on the register path
    try:
        litebw.ReadSession(url, email, master).list_ciphers()
    except VaultSeedError as e:
        raise WrongMasterError(
            f"an account for {email} already exists but the master password is "
            f"incorrect — enter the existing master (or reset it in the web "
            f"vault). Vault said: {e}")
    return "exists"


def available() -> bool:
    """True if the crypto backend needed to register (AES + RSA) is importable."""
    if not vaultseed.available():
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
        return True
    except ImportError:
        return False
