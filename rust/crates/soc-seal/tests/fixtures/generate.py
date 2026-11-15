#!/usr/bin/env python3
"""Regenerate the on-disk compatibility fixtures with the REAL Python release.

    cd kiosk-host && python3 ../rust/crates/soc-seal/tests/fixtures/generate.py

Everything here is an obviously fake test value. The v2 seals, the interrupted
migration and the session ticket are written by host/secretstore.py itself; the
legacy seal is written by hand with hashlib + cryptography, exactly as
kiosk-host/tests/test_secretstore_migration.py does, because no current code
path writes that format any more.
"""
import hashlib
import os
import shutil
import sys
import tempfile

OUT = os.path.dirname(os.path.abspath(__file__))
MACHINE_ID = "fixture-host-0001"
MASTER = "Fixture-Master ✓ not-a-real-secret"
PIN = "135790"
LEGACY_PIN = "4321"          # earlier releases allowed 4-digit PINs
BOOT_ID = b"fixture-boot-id"
NOW = 2_000_000_000

os.environ["SOC_MACHINE_ID"] = MACHINE_ID
os.environ["SOC_UNSEAL_CACHE_TTL"] = "0"
os.environ.pop("SOC_FIPS_KDF", None)
os.environ.pop("SOC_SECRET_BACKEND", None)
sys.path.insert(0, os.getcwd())

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from host import secretstore as ss  # noqa: E402


def fresh(name):
    d = os.path.join(OUT, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    return d


def legacy_blob(material, plaintext):
    salt, nonce = os.urandom(16), os.urandom(12)
    key = hashlib.scrypt(material, salt=salt, n=2 ** 14, r=8, p=1, dklen=32,
                         maxmem=96 * 1024 * 1024)
    return salt + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def write_legacy_seal(d, pin):
    hash_salt = os.urandom(16)
    digest = hashlib.sha256(hash_salt + pin.encode()).hexdigest()
    files = {
        "pin.hash": f"{hash_salt.hex()}${digest}".encode(),
        "pin.enc": legacy_blob(MACHINE_ID.encode(), pin.encode()),
        "master.enc": legacy_blob((MACHINE_ID + pin).encode(), MASTER.encode()),
    }
    for name, data in files.items():
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(data)


# 1. v2, default KDF (scrypt N=2**17)
v2 = fresh("v2-scrypt")
ss.seal(MASTER, PIN, v2)
assert ss.unseal(v2) == MASTER

# 2. v2, FIPS KDF (PBKDF2-HMAC-SHA256)
os.environ["SOC_FIPS_KDF"] = "1"
fips = fresh("v2-pbkdf2")
ss.seal(MASTER, PIN, fips)
assert ss.unseal(fips) == MASTER
del os.environ["SOC_FIPS_KDF"]

# 3. legacy: salt|nonce|ct, scrypt N=2**14, machine-id only, no host.key
write_legacy_seal(fresh("legacy"), LEGACY_PIN)

# 4. a migration cut off after two renames: host.key + v2 pin.enc are in place,
#    master.enc is still legacy, and the staged master.enc.tmp is left behind
mid = fresh("mid-migration")
write_legacy_seal(mid, LEGACY_PIN)


class PowerCut(BaseException):
    pass


real_replace, done = os.replace, []


def replace(src, dst):
    if len(done) == 2:
        raise PowerCut
    done.append(dst)
    return real_replace(src, dst)


ss.os.replace = replace
try:
    ss.unseal(mid)
    raise SystemExit("the power cut never happened")
except PowerCut:
    pass
ss.os.replace = real_replace
assert sorted(os.listdir(mid)) == ["host.key", "master.enc", "master.enc.tmp",
                                   "pin.enc", "pin.hash"], os.listdir(mid)
assert ss._is_v2_blob(open(os.path.join(mid, "pin.enc"), "rb").read())
assert not ss._is_v2_blob(open(os.path.join(mid, "master.enc"), "rb").read())

# 5. the session ticket Python leaves for the v2-scrypt seal, with the boot id
#    and the clock pinned so the Rust test can present the same ones
run = tempfile.mkdtemp()
os.chmod(run, 0o700)
os.environ.pop("SOC_UNSEAL_CACHE_TTL")
ss._runtime_dir = lambda: run
ss._boot_id = lambda: BOOT_ID
real_time = ss.time.time
ss.time.time = lambda: NOW
assert ss.unseal(v2) == MASTER
ss._kdf = None                      # the ticket alone must serve this one
assert ss.unseal(v2) == MASTER
ss.time.time = real_time
shutil.copy(os.path.join(run, ss._TICKET_FILE), os.path.join(fresh("ticket"), ss._TICKET_FILE))
shutil.rmtree(run)

for root, _dirs, files in os.walk(OUT):
    for name in files:
        if name != os.path.basename(__file__):
            os.chmod(os.path.join(root, name), 0o600)
print("fixtures written to", OUT)
