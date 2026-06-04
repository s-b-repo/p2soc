#!/usr/bin/env python3
"""
DEV ONLY: register a Bitwarden/Vaultwarden account non-interactively so the rbw
integration can be tested on an x86 workstation.

On a real Pi you create the kiosk account the normal way (Vaultwarden web vault
in a browser) — this script just automates it for CI/dev. Implements the
Bitwarden PBKDF2 registration: derive master key, build the protected symmetric
key + RSA keypair, POST /api/accounts/register.

Usage: python3 dev/register-vaultwarden.py <url> <email> <password>
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KDF_ITERS = 600_000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    # single-block HKDF-Expand (length == hashlen == 32)
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def enc_string(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    url, email, password = sys.argv[1], sys.argv[2].lower(), sys.argv[3]
    pw = password.encode()

    master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), KDF_ITERS, 32)
    master_pw_hash = b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))

    # stretch master key (HKDF) to protect the user symmetric key
    stretch_enc = hkdf_expand(master_key, b"enc")
    stretch_mac = hkdf_expand(master_key, b"mac")

    sym_key = os.urandom(64)                      # 32 enc || 32 mac
    protected_key = enc_string(sym_key, stretch_enc, stretch_mac)

    # RSA keypair; private key protected with the user symmetric key
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    enc_priv = enc_string(priv_der, sym_key[:32], sym_key[32:])

    body = {
        "email": email,
        "name": "SOC Kiosk",
        "masterPasswordHash": master_pw_hash,
        "masterPasswordHint": None,
        "key": protected_key,
        "kdf": 0,                                 # 0 = PBKDF2_SHA256
        "kdfIterations": KDF_ITERS,
        "keys": {"publicKey": b64(pub_der), "encryptedPrivateKey": enc_priv},
    }

    for ep in ("/api/accounts/register", "/identity/accounts/register"):
        req = urllib.request.Request(
            url.rstrip("/") + ep,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                print(f"registered via {ep}: HTTP {r.status}")
                return
        except urllib.error.HTTPError as e:
            msg = e.read().decode()[:300]
            if e.code in (400, 409) and ("already" in msg.lower()):
                print(f"account already exists ({ep}); continuing")
                return
            print(f"{ep} -> HTTP {e.code}: {msg}")
        except Exception as e:  # noqa: BLE001
            print(f"{ep} -> {e}")
    sys.exit(2)


if __name__ == "__main__":
    main()
