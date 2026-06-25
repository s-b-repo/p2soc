#!/usr/bin/env python3
"""
DEV ONLY: seed login ciphers into Vaultwarden via the REST API.

Used instead of `rbw add` for unattended/CI seeding (rbw's editor-based add
needs a TTY). The kiosk host still READS via rbw — this only writes test data.

Logs in (password grant), recovers the account symmetric key by decrypting the
protected key with the stretched master key, deletes any existing ciphers, then
creates fresh login items. On the Pi you'd just use the Vaultwarden web vault.

Usage: python3 dev/seed-ciphers.py <url> <email> <password>
       (items are hard-coded to match config/panels.dev.yaml)
"""
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KDF_ITERS = 600_000
ITEMS = [
    ("SOC Dev Panel 1", "viewer1", "devpass1", "http://127.0.0.1:9001"),
    ("SOC Dev Panel 2", "viewer2", "devpass2", "http://127.0.0.1:19102"),
    ("SOC Dev Panel 3", "viewer3", "devpass3", "http://127.0.0.1:9003"),
    ("SOC Dev Panel 4", "viewer4", "devpass4", "http://127.0.0.1:9004"),
]


def b64(b):       return base64.b64encode(b).decode()
def ub64(s):      return base64.b64decode(s)


def hkdf_expand(prk, info, length=32):
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def enc_string(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    import os
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def dec_string(s: str, enc_key: bytes, mac_key: bytes) -> bytes:
    body = s.split(".", 1)[1]
    iv_b, ct_b, mac_b = body.split("|")
    iv, ct, mac = ub64(iv_b), ub64(ct_b), ub64(mac_b)
    if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac):
        raise ValueError("MAC mismatch decrypting protected key")
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt[:-pt[-1]]


def post(url, data, headers, form=False):
    if form:
        body = urllib.parse.urlencode(data).encode()
        headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
    else:
        body = json.dumps(data).encode()
        headers = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def get(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def delete(url, headers):
    req = urllib.request.Request(url, headers=headers, method="DELETE")
    urllib.request.urlopen(req, timeout=15).read()


def main():
    url, email, password = sys.argv[1], sys.argv[2].lower(), sys.argv[3]
    base = url.rstrip("/")
    pw = password.encode()

    master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), KDF_ITERS, 32)
    master_pw_hash = b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
    stretch_enc = hkdf_expand(master_key, b"enc")
    stretch_mac = hkdf_expand(master_key, b"mac")

    tok = post(base + "/identity/connect/token", {
        "grant_type": "password",
        "username": email,
        "password": master_pw_hash,
        "scope": "api offline_access",
        "client_id": "cli",
        "deviceType": "8",
        "deviceIdentifier": "soc-seed-0001",
        "deviceName": "soc-seed",
    }, headers={}, form=True)
    access = tok["access_token"]
    sym_key = dec_string(tok["Key"], stretch_enc, stretch_mac)  # 64 bytes
    ek, mk = sym_key[:32], sym_key[32:]
    auth = {"Authorization": f"Bearer {access}"}
    print("logged in; recovered account key")

    resp = get(base + "/api/ciphers", auth)
    existing = resp.get("Data", resp.get("data", []))   # Vaultwarden casing varies
    for c in existing:
        cid = c.get("Id") or c.get("id")
        delete(base + f"/api/ciphers/{cid}", auth)
    if existing:
        print(f"deleted {len(existing)} existing cipher(s)")

    for name, user, secret, uri in ITEMS:
        cipher = {
            "type": 1,
            "name": enc_string(name.encode(), ek, mk),
            "notes": None,
            "favorite": False,
            "login": {
                "username": enc_string(user.encode(), ek, mk),
                "password": enc_string(secret.encode(), ek, mk),
                "uris": [{"uri": enc_string(uri.encode(), ek, mk), "match": None}],
            },
        }
        post(base + "/api/ciphers", cipher, auth)
        print(f"created: {name} ({user})")


if __name__ == "__main__":
    main()
