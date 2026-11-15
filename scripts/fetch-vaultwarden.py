#!/usr/bin/env python3
"""
Install the official Vaultwarden binary without Docker.

Upstream publishes no static binaries, only multi-arch container images. Running
Docker just to host one small server keeps dockerd and containerd resident on a
1 GB Pi, so this pulls the binary straight out of the image over
the registry's HTTP API: no daemon, no container, no compile.

Integrity is a chain from one pinned value. security/vaultwarden.lock holds the
SHA-256 of the multi-arch image index. That index names each per-arch manifest
by digest, and each manifest names its layers by digest. Every hop is hashed and
compared before it is trusted, so the bytes installed are exactly the ones pinned
in this repository, whatever the network or a mirror returns.

Vaultwarden's database migrations only run forwards, so this NEVER downgrades:
rolling a release back keeps the newer binary. Pass --force to override that.

    fetch-vaultwarden.py --lock security/vaultwarden.lock --dest /usr/local/bin/vaultwarden
    fetch-vaultwarden.py --resolve 1.37.5-alpine     # print a lock for a new version

Exit codes: 0 installed or already current, 1 failed.
Stdlib only, because it runs before the venv exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"

INDEX_TYPES = ("application/vnd.oci.image.index.v1+json, "
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json, "
                  "application/vnd.docker.distribution.manifest.v2+json")

# uname -m -> (OCI architecture, OCI variant, ELF e_machine)
ARCHES = {
    "x86_64": ("amd64", None, 62),
    "amd64": ("amd64", None, 62),
    "aarch64": ("arm64", None, 183),
    "arm64": ("arm64", None, 183),
    "armv7l": ("arm", "v7", 40),
    "armv6l": ("arm", "v6", 40),
}

ATTEMPTS = 3
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class FetchError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[fetch-vaultwarden] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# The lock
# --------------------------------------------------------------------------- #
def read_lock(path: str) -> Dict[str, str]:
    lock: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                lock[key.strip()] = value.strip()
    for key in ("image", "tag", "digest"):
        if not lock.get(key):
            raise FetchError(f"{path}: missing {key}=")
    if not _DIGEST_RE.match(lock["digest"]):
        raise FetchError(f"{path}: digest is not a sha256 digest")
    if not _TAG_RE.match(lock["tag"]):
        raise FetchError(f"{path}: invalid tag")
    return lock


def version_key(tag: str) -> Tuple[int, ...]:
    """'1.37.5-alpine' -> (1, 37, 5). Anything unparsable sorts lowest."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(g) for g in m.groups()) if m else (0,)


def stamp_path(dest: str) -> str:
    return dest + ".lock-stamp"


def read_stamp(dest: str) -> Dict[str, str]:
    try:
        with open(stamp_path(dest), encoding="utf-8") as fh:
            tag, digest = fh.read().split()
        return {"tag": tag, "digest": digest}
    except (OSError, ValueError):
        return {}


def decide(lock: Dict[str, str], dest: str, force: bool = False) -> Optional[str]:
    """Why to install, or None to leave things alone."""
    if not os.path.exists(dest):
        return "not installed"
    stamp = read_stamp(dest)
    if not stamp:
        # A binary this tool did not install: the operator put it there on purpose.
        return "forced" if force else None
    if stamp["digest"] == lock["digest"]:
        return None
    if version_key(lock["tag"]) < version_key(stamp["tag"]) and not force:
        log(f"keeping {stamp['tag']}: refusing to downgrade to {lock['tag']} "
            "(database migrations only run forwards)")
        return None
    return f"{stamp['tag']} -> {lock['tag']}"


# --------------------------------------------------------------------------- #
# Registry access
# --------------------------------------------------------------------------- #
def _open(url: str, headers: Dict[str, str]):
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-https URL {url}")
    return urllib.request.urlopen(  # noqa: S310 - https enforced above
        urllib.request.Request(url, headers=headers), timeout=60)


def _retry(what: str, fn):
    """Bounded retry: first boot often races Wi-Fi coming up. A digest mismatch is
    never retried, because it means the content is wrong, not the connection."""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return fn()
        except (urllib.error.URLError, OSError, ValueError) as e:
            if attempt == ATTEMPTS:
                raise FetchError(f"{what}: {e}")
            log(f"{what} failed ({e}); retry {attempt}/{ATTEMPTS - 1}")
            time.sleep(2 ** attempt)
    raise FetchError(what)


class Registry:
    def __init__(self, image: str):
        self.image = image
        self.token = ""

    def _auth(self) -> Dict[str, str]:
        if not self.token:
            def get_token():
                with _open(AUTH.format(image=self.image), {}) as r:
                    return json.load(r)["token"]
            self.token = _retry("auth", get_token)
        return {"Authorization": f"Bearer {self.token}"}

    def fetch_json(self, ref: str, accept: str, digest: Optional[str]) -> Tuple[dict, str]:
        """A manifest by tag or digest. If `digest` is given the bytes must hash to
        it exactly; the parsed document is only returned after that check."""
        url = f"{REGISTRY}/v2/{self.image}/manifests/{ref}"

        def get():
            with _open(url, dict(self._auth(), Accept=accept)) as r:
                return r.read()
        raw = _retry(f"manifest {ref[:24]}", get)
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest and actual != digest:
            raise FetchError(f"manifest digest mismatch: wanted {digest}, got {actual}")
        return json.loads(raw), actual

    def fetch_blob(self, digest: str, dest) -> None:
        """Stream a blob into `dest`, hashing as it goes (layers are tens of MB)."""
        url = f"{REGISTRY}/v2/{self.image}/blobs/{digest}"

        def get():
            dest.seek(0)
            dest.truncate()
            h = hashlib.sha256()
            with _open(url, self._auth()) as r:
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    h.update(chunk)
                    dest.write(chunk)
            dest.flush()
            return "sha256:" + h.hexdigest()
        actual = _retry(f"blob {digest[:24]}", get)
        if actual != digest:
            raise FetchError(f"blob digest mismatch: wanted {digest}, got {actual}")


def pick_platform(index: dict, machine: str) -> str:
    if machine not in ARCHES:
        raise FetchError(f"unsupported architecture {machine!r}")
    arch, variant, _ = ARCHES[machine]
    for m in index.get("manifests", []):
        p = m.get("platform", {})
        if (p.get("os") == "linux" and p.get("architecture") == arch
                and (variant is None or p.get("variant") == variant)):
            return m["digest"]
    raise FetchError(f"image has no linux/{arch}{'/' + variant if variant else ''} build")


def check_elf(path: str, machine: str) -> None:
    """Refuse a binary for the wrong CPU without ever executing it: running it to
    find out would produce only a confusing failure at boot."""
    with open(path, "rb") as fh:
        head = fh.read(20)
    if len(head) < 20 or head[:4] != b"\x7fELF":
        raise FetchError("extracted file is not an ELF binary")
    endian = "<" if head[5] == 1 else ">"
    e_machine = struct.unpack(endian + "H", head[18:20])[0]
    want = ARCHES[machine][2]
    if e_machine != want:
        raise FetchError(f"binary is for ELF machine {e_machine}, this host needs {want}")


def extract_binary(reg: Registry, manifest: dict, member: str, out_path: str,
                   workdir: str) -> None:
    """Find the binary in the image. Upper layers win, so search newest first; the
    binary sits in a late layer, which usually spares downloading the base image.
    Only this one member is read, so nothing else in the layer reaches the disk."""
    for layer in reversed(manifest.get("layers", [])):
        with tempfile.NamedTemporaryFile(dir=workdir, suffix=".layer") as blob:
            reg.fetch_blob(layer["digest"], blob)
            blob.seek(0)
            try:
                with tarfile.open(fileobj=blob, mode="r:*") as tar:
                    for info in tar:
                        if info.name.lstrip("./") == member and info.isfile():
                            src = tar.extractfile(info)
                            with open(out_path, "wb") as out:
                                shutil.copyfileobj(src, out, 1 << 20)
                            return
            except tarfile.TarError as e:
                raise FetchError(f"bad layer {layer['digest'][:24]}: {e}")
    raise FetchError(f"{member!r} not found in the image")


def install(lock: Dict[str, str], dest: str, machine: str) -> None:
    reg = Registry(lock["image"])
    index, _ = reg.fetch_json(lock["digest"], INDEX_TYPES, lock["digest"])
    manifest_digest = pick_platform(index, machine)
    manifest, _ = reg.fetch_json(manifest_digest, MANIFEST_TYPES, manifest_digest)

    parent = os.path.dirname(dest) or "."
    os.makedirs(parent, mode=0o755, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent, prefix=".vw-fetch-") as work:
        staged = os.path.join(work, "vaultwarden")
        extract_binary(reg, manifest, "vaultwarden", staged, work)
        check_elf(staged, machine)
        os.chmod(staged, 0o755)
        # On disk before the rename: otherwise a power cut can leave the new name
        # pointing at empty data, with the stamp saying all is well.
        fd = os.open(staged, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        # Atomic: a power cut leaves the old binary or the new one, never a torn one.
        os.replace(staged, dest)
    tmp = stamp_path(dest) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{lock['tag']} {lock['digest']}\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, stamp_path(dest))


def resolve(image: str, tag: str) -> str:
    _, digest = Registry(image).fetch_json(tag, INDEX_TYPES, None)
    return f"image={image}\ntag={tag}\ndigest={digest}\n"


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="fetch-vaultwarden",
                                 description=__doc__.split("\n")[1])
    ap.add_argument("--lock", help="lock file (image=, tag=, digest=)")
    ap.add_argument("--dest", default="/usr/local/bin/vaultwarden")
    ap.add_argument("--force", action="store_true",
                    help="replace an unmanaged binary, or allow a downgrade")
    ap.add_argument("--check", action="store_true",
                    help="exit 0 if an install is needed, 1 if not; change nothing")
    ap.add_argument("--resolve", metavar="TAG", help="print a lock for TAG")
    ap.add_argument("--image", default="vaultwarden/server")
    args = ap.parse_args(argv)

    try:
        if args.resolve:
            if not _TAG_RE.match(args.resolve):
                raise FetchError("invalid tag")
            sys.stdout.write(resolve(args.image, args.resolve))
            return 0
        if not args.lock:
            ap.error("--lock is required")
        lock = read_lock(args.lock)
        reason = decide(lock, args.dest, force=args.force)
        if args.check:
            return 0 if reason else 1
        if reason is None:
            log(f"{args.dest} is current")
            return 0
        log(f"installing {lock['tag']} ({reason})")
        install(lock, args.dest, platform.machine())
        log(f"installed {args.dest} ({lock['tag']}, {lock['digest'][:19]})")
        return 0
    except (FetchError, OSError, ValueError, KeyError) as e:
        log(f"failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
