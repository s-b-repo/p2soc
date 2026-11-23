//! Install the Vaultwarden ELF from the digest-pinned OCI image.

use crate::http::tls;
use flate2::read::MultiGzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use soc_sys::fsutil;
use soc_sys::sha256::hex;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

const REGISTRY: &str = "https://registry-1.docker.io";
const INDEX: &str =
    "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";
const MANIFEST: &str =
    "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const DOC_LIMIT: u64 = 4 << 20;
const BLOB_LIMIT: u64 = 1 << 30;
const BINARY_LIMIT: u64 = 128 << 20;

type Result<T> = std::result::Result<T, String>; // audit-allow: command-line diagnostics

fn digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn tag(s: &str) -> bool {
    s.len() <= 128
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn image(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 256
        && s.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}

#[derive(Debug)]
struct Lock {
    image: String,
    tag: String,
    digest: String,
}

impl Lock {
    fn load(path: &Path) -> Result<Self> {
        let text = fsutil::read_capped(path, 65536).map_err(|e| format!("{}: {e}", path.display()))?;
        let env = soc_sys::health::parse_env(&text);
        let field = |key: &str| env.get(key).cloned().ok_or_else(|| format!("{}: missing {key}=", path.display()));
        let lock = Self { image: field("image")?, tag: field("tag")?, digest: field("digest")? };
        if !image(&lock.image) || !tag(&lock.tag) || !digest(&lock.digest) {
            return Err(format!("{}: invalid image, tag or digest", path.display()));
        }
        Ok(lock)
    }

    fn install_reason(&self, dest: &Path, force: bool) -> Option<String> {
        if !dest.exists() {
            return Some("not installed".into());
        }
        let stamp = fsutil::read_capped(&stamp_path(dest), 512).ok();
        let pair = stamp.as_deref().and_then(|text| {
            let words = text.split_whitespace().collect::<Vec<_>>();
            match words.as_slice() {
                [tag, digest] => Some((*tag, *digest)),
                _ => None,
            }
        });
        match pair {
            None => force.then(|| "forced".to_string()),
            Some((_, installed)) if installed == self.digest => None,
            Some((installed, _)) if !force && version(&self.tag) < version(installed) => {
                eprintln!("[fetch-vaultwarden] keeping {installed}: refusing to downgrade to {}", self.tag);
                None
            }
            Some((installed, _)) => Some(format!("{installed} -> {}", self.tag)),
        }
    }
}

fn version(s: &str) -> Option<[u64; 3]> {
    let mut parts = s.split('.');
    Some([
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()?,
    ])
}

fn stamp_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(".lock-stamp");
    name.into()
}

fn retry<T>(what: &str, mut get: impl FnMut() -> Result<T>) -> Result<T> {
    for delay in [2, 4] {
        match get() {
            Ok(value) => return Ok(value),
            Err(e) => {
                eprintln!("[fetch-vaultwarden] {what}: {e}; retrying in {delay}s");
                std::thread::sleep(Duration::from_secs(delay));
            }
        }
    }
    get().map_err(|e| format!("{what}: {e}"))
}

struct Registry {
    agent: ureq::Agent,
    image: String,
    authorization: Zeroizing<String>,
}

impl Registry {
    fn open(name: &str) -> Result<Self> {
        if !image(name) {
            return Err("invalid OCI image name".into());
        }
        let ca_file = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
        let config = ureq::Agent::config_builder()
            .tls_config(tls::config(ca_file.as_deref()).map_err(|e| e.to_string())?)
            .https_only(true)
            .max_redirects(5)
            .timeout_global(Some(Duration::from_secs(240)))
            .timeout_connect(Some(Duration::from_secs(20)))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let url = format!("https://auth.docker.io/token?service=registry.docker.io&scope=repository:{name}:pull");
        let authorization = retry("registry authentication", || {
            let response = agent.get(&url).call().map_err(|e| e.to_string())?;
            let data = capped(response.into_body().into_reader(), DOC_LIMIT)?;
            let value: Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
            value["token"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| Zeroizing::new(format!("Bearer {s}")))
                .ok_or_else(|| "registry did not send a token".into())
        })?;
        Ok(Self { agent, image: name.into(), authorization })
    }

    fn get(&self, kind: &str, reference: &str, accept: &str) -> Result<impl Read + use<>> {
        let url = format!("{REGISTRY}/v2/{}/{kind}/{reference}", self.image);
        let response = self
            .agent
            .get(&url)
            .header("Accept", accept)
            .header("Authorization", self.authorization.as_str())
            .call()
            .map_err(|e| e.to_string())?;
        Ok(response.into_body().into_reader())
    }

    fn document(&self, reference: &str, accept: &str, pinned: bool) -> Result<(Value, String)> {
        let body = retry("registry manifest", || capped(self.get("manifests", reference, accept)?, DOC_LIMIT))?;
        let hash = format!("sha256:{}", hex(&Sha256::digest(&body)));
        if pinned && hash != reference {
            return Err(format!("manifest digest mismatch: expected {reference}, got {hash}"));
        }
        let value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        Ok((value, hash))
    }

    fn blob(&self, expected: &str, dest: &mut File) -> Result<()> {
        if !digest(expected) {
            return Err("invalid layer digest".into());
        }
        let actual = retry("registry layer", || {
            dest.set_len(0).and_then(|()| dest.rewind()).map_err(|e| e.to_string())?;
            let mut body = self.get("blobs", expected, "application/octet-stream")?.take(BLOB_LIMIT + 1);
            let mut hash = Sha256::new();
            let mut buf = vec![0; 128 << 10];
            let mut count = 0;
            loop {
                let bytes = body.read(&mut buf).map_err(|e| e.to_string())?;
                if bytes == 0 {
                    break;
                }
                count += bytes as u64;
                if count > BLOB_LIMIT {
                    return Err("registry layer exceeds 1 GiB".into());
                }
                hash.update(&buf[..bytes]);
                std::io::Write::write_all(dest, &buf[..bytes]).map_err(|e| e.to_string())?;
            }
            Ok(format!("sha256:{}", hex(&hash.finalize())))
        })?;
        if actual != expected {
            return Err(format!("layer digest mismatch: expected {expected}, got {actual}"));
        }
        dest.rewind().map_err(|e| e.to_string())
    }
}

fn capped(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(limit + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
    if out.len() as u64 > limit {
        return Err("registry response exceeds the size limit".into());
    }
    Ok(out)
}

struct Platform {
    arch: &'static str,
    variant: Option<&'static str>,
    elf: u16,
}

fn platform(machine: &str) -> Result<Platform> {
    let (arch, variant, elf) = match machine {
        "x86_64" | "amd64" => ("amd64", None, 62),
        "aarch64" | "arm64" => ("arm64", None, 183),
        "armv7l" => ("arm", Some("v7"), 40),
        "armv6l" => ("arm", Some("v6"), 40),
        other => return Err(format!("unsupported architecture {other:?}")),
    };
    Ok(Platform { arch, variant, elf })
}

fn pick_platform<'a>(index: &'a Value, p: &Platform) -> Result<&'a str> {
    index["manifests"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|manifest| {
            let platform = &manifest["platform"];
            if platform["os"] != "linux"
                || platform["architecture"] != p.arch
                || p.variant.is_some_and(|v| platform["variant"] != v)
            {
                return None;
            }
            manifest["digest"].as_str().filter(|s| digest(s))
        })
        .ok_or_else(|| format!("image contains no linux/{} build for this host", p.arch))
}

fn check_elf(head: &[u8], platform: &Platform) -> Result<()> {
    if head.len() < 20 || !head.starts_with(b"\x7fELF") {
        return Err("extracted file is not ELF".into());
    }
    let field = [head[18], head[19]];
    let elf = match head[5] {
        1 => u16::from_le_bytes(field),
        2 => u16::from_be_bytes(field),
        _ => return Err("invalid ELF byte order".into()),
    };
    if elf != platform.elf {
        return Err(format!("image has ELF machine {elf}, this host needs {}", platform.elf));
    }
    Ok(())
}

struct WorkDir(PathBuf);

impl WorkDir {
    fn new(parent: &Path) -> Result<Self> {
        let mut id = [0u8; 12];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let path = parent.join(format!(".vw-fetch-{name}"));
        fs::DirBuilder::new().mode(0o700).create(&path).map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0); // audit-allow: best-effort cleanup of only our staging directory
    }
}

fn extract_layer(reader: impl Read, stage: &Path) -> Result<bool> {
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry
            .path()
            .map_err(|e| e.to_string())?
            .components()
            .filter(|p| *p != std::path::Component::CurDir)
            .eq(Path::new("vaultwarden").components())
            && entry.header().entry_type().is_file()
        {
            if entry.size() > BINARY_LIMIT {
                return Err("Vaultwarden binary exceeds 128 MiB".into());
            }
            let mut out =
                OpenOptions::new().write(true).create_new(true).mode(0o700).open(stage).map_err(|e| e.to_string())?;
            io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
            out.sync_all().map_err(|e| e.to_string())?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn install(lock: &Lock, dest: &Path, platform: &Platform) -> Result<()> {
    let registry = Registry::open(&lock.image)?;
    let (index, _) = registry.document(&lock.digest, INDEX, true)?;
    let (manifest, _) = registry.document(pick_platform(&index, platform)?, MANIFEST, true)?;
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let work = WorkDir::new(parent)?;
    let staged = work.0.join("vaultwarden");
    let mut blob = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(work.0.join("layer"))
        .map_err(|e| e.to_string())?;
    let mut extracted = false;
    for layer in manifest["layers"].as_array().into_iter().flatten().rev() {
        let hash = layer["digest"].as_str().ok_or("manifest layer has no digest")?;
        registry.blob(hash, &mut blob)?;
        let mut magic = [0; 2];
        blob.read_exact(&mut magic).and_then(|()| blob.rewind()).map_err(|e| e.to_string())?;
        extracted = if magic == [0x1f, 0x8b] {
            extract_layer(MultiGzDecoder::new(&mut blob), &staged)?
        } else {
            extract_layer(&mut blob, &staged)?
        };
        if extracted {
            break;
        }
    }
    if !extracted {
        return Err("the pinned image contains no Vaultwarden binary".into());
    }
    let file = File::open(&staged).map_err(|e| e.to_string())?;
    let mut header = [0; 20];
    (&file).read_exact(&mut header).map_err(|e| e.to_string())?;
    check_elf(&header, platform)?;
    file.set_permissions(fs::Permissions::from_mode(0o755))
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&staged, dest).and_then(|()| File::open(parent)?.sync_all()).map_err(|e| e.to_string())?;
    fsutil::write_atomic(&stamp_path(dest), format!("{} {}\n", lock.tag, lock.digest).as_bytes(), 0o644)
        .map_err(|e| e.to_string())
}

const HELP: &str = "usage: soc-wall fetch-vaultwarden --lock FILE [--dest FILE] [--check] [--force]\n       soc-wall fetch-vaultwarden --resolve TAG [--image IMAGE]";

fn execute(args: &[String]) -> Result<i32> {
    let mut dest = PathBuf::from("/usr/local/bin/vaultwarden");
    let mut lock = None;
    let mut resolve = None;
    let mut name = "vaultwarden/server";
    let (mut check, mut force) = (false, false);
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        let (key, inline) = arg.split_once('=').map_or((arg, None), |(key, value)| (key, Some(value)));
        let mut value = || {
            inline
                .or_else(|| args.next())
                .filter(|s| !s.starts_with("--"))
                .ok_or_else(|| format!("{key} needs a value"))
        };
        match key {
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(0);
            }
            "--lock" => lock = Some(Path::new(value()?)),
            "--dest" => dest = PathBuf::from(value()?),
            "--resolve" => resolve = Some(value()?),
            "--image" => name = value()?,
            "--check" if inline.is_none() => check = true,
            "--force" if inline.is_none() => force = true,
            _ => return Err(format!("unknown argument {arg:?}\n{HELP}")),
        }
    }
    if let Some(release) = resolve {
        if !tag(release) {
            return Err("invalid OCI tag".into());
        }
        let (_, digest) = Registry::open(name)?.document(release, INDEX, false)?;
        println!("image={name}\ntag={release}\ndigest={digest}");
        return Ok(0);
    }
    let lock = Lock::load(lock.ok_or("--lock is required")?)?;
    let reason = lock.install_reason(&dest, force);
    if check {
        return Ok(i32::from(reason.is_none()));
    }
    if let Some(reason) = reason {
        let machine = String::from_utf8(
            std::process::Command::new("uname").arg("-m").output().map_err(|e| e.to_string())?.stdout,
        )
        .map_err(|e| e.to_string())?;
        println!("[fetch-vaultwarden] installing {} ({reason})", lock.tag);
        install(&lock, &dest, &platform(machine.trim())?)?;
        println!("[fetch-vaultwarden] installed {}", dest.display());
    }
    Ok(0)
}

pub fn main(args: &[String]) -> i32 {
    match execute(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[fetch-vaultwarden] {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_numerically_and_variants_do_not_change_version() {
        assert!(version("1.10.0-alpine") > version("1.9.20"));
        assert_eq!(version("1.10.0-alpine"), version("1.10.0"));
    }

    #[test]
    fn elf_validation_rejects_another_architecture() {
        let mut elf = [0; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[5] = 1;
        elf[18] = 183;
        assert!(check_elf(&elf, &platform("aarch64").unwrap()).is_ok());
        assert!(check_elf(&elf, &platform("x86_64").unwrap()).is_err());
    }
}
