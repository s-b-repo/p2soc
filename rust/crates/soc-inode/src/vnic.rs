//! Virtual NIC: TUN device + address/route/DNS programming (port of `vnic.py`).
//!
//! We open `/dev/net/tun` with the exact `TUNSETIFF` ioctl the client uses, then
//! program the address/routes with the `ip` command (explicit argv, no shell —
//! easy to audit) and DNS by rewriting `/etc/resolv.conf` with the same marker
//! line, restoring everything on teardown. Requires `CAP_NET_ADMIN` (root).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command, Stdio};

use crate::constants as c;
use crate::error::{InodeError, Result};
use crate::tunnel::NetworkConfig;

const RESOLV_BAK: &str = "/etc/resolv.conf.h3c-svpn.bak";

/// The TUN device and the host state we changed, restored on [`VirtualNIC::close`].
#[derive(Default)]
pub struct VirtualNIC {
    pub name_template: String,
    pub ifname: String,
    tun: Option<File>,
    dns_changed: bool,
    /// `(is_ipv6, cidr)` for each route we added, for family-correct cleanup.
    added_routes: Vec<(bool, String)>,
}

impl VirtualNIC {
    pub fn new(name_template: &str) -> VirtualNIC {
        let tmpl = if name_template.is_empty() { c::IFNAME_TEMPLATE.to_string() } else { name_template.to_string() };
        VirtualNIC {
            name_template: tmpl,
            ifname: String::new(),
            tun: None,
            dns_changed: false,
            added_routes: Vec::new(),
        }
    }

    // -- device ------------------------------------------------------------
    /// Create the TUN device and record its kernel-assigned name.
    pub fn open(&mut self) -> Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(c::TUN_DEVICE).map_err(InodeError::Io)?;
        let flags = (c::IFF_TUN | c::IFF_NO_PI).to_le_bytes();
        // struct ifreq: name[16] then the flags short; zero-pad the 40-byte whole.
        let mut ifr = [0u8; 40];
        for (dst, src) in ifr.iter_mut().zip(self.name_template.as_bytes().iter().take(16)) {
            *dst = *src;
        }
        if let Some(slot) = ifr.get_mut(16..18) {
            slot.copy_from_slice(&flags);
        }
        tun_set_iff(file.as_raw_fd(), &mut ifr).map_err(InodeError::Io)?;
        let name_field = ifr.get(..16).unwrap_or(&[]);
        let end = name_field.iter().position(|&b| b == 0).unwrap_or(name_field.len());
        self.ifname = String::from_utf8_lossy(name_field.get(..end).unwrap_or(&[])).into_owned();
        self.tun = Some(file);
        Ok(())
    }

    /// Hand the TUN device to the tunnel pump (it then owns the fd). The NIC
    /// keeps the interface name and change-log for teardown.
    pub fn take_tun(&mut self) -> Option<File> {
        self.tun.take()
    }

    // -- addressing --------------------------------------------------------
    /// Program address, routes and DNS. `server_ip` (the gateway's own IP) must
    /// keep bypassing the tunnel in full-tunnel mode; `split_tunnel` forces
    /// enterprise split routing (only the gateway's own routes go via the VPN).
    pub fn configure(&mut self, cfg: &NetworkConfig, server_ip: Option<&str>, split_tunnel: bool) -> Result<()> {
        if self.ifname.is_empty() {
            return Err(InodeError::Config("TUN device not open".into()));
        }
        let prefix = if !cfg.prefixlength.is_empty() {
            cfg.prefixlength.clone()
        } else if !cfg.subnetmask.is_empty() {
            mask_to_prefix(&cfg.subnetmask).to_string()
        } else {
            "32".to_string()
        };
        let ifname = self.ifname.clone();
        run_ip(&["addr", "flush", "dev", ifname.as_str()], false)?;
        let addr = format!("{}/{}", cfg.ipaddress, prefix);
        run_ip(&["addr", "add", addr.as_str(), "dev", ifname.as_str()], true)?;
        run_ip(&["link", "set", "dev", ifname.as_str(), "up"], true)?;
        if !cfg.ipv6address.is_empty() {
            let v6p = if cfg.prefixlength.contains(':') { cfg.prefixlength.clone() } else { "64".to_string() };
            let v6addr = format!("{}/{}", cfg.ipv6address, v6p);
            run_ip(&["-6", "addr", "add", v6addr.as_str(), "dev", ifname.as_str()], false)?;
        }
        self.program_routes(cfg, server_ip, split_tunnel)?;
        self.program_dns(cfg, split_tunnel)?;
        Ok(())
    }

    fn add_route(&mut self, v6: bool, args: &[&str]) -> Result<()> {
        let mut full: Vec<&str> = Vec::new();
        if v6 {
            full.push("-6");
        }
        full.push("route");
        full.push("add");
        full.extend_from_slice(args);
        if run_ip(&full, false)? == 0 {
            if let Some(net) = args.first() {
                self.added_routes.push((v6, (*net).to_string()));
            }
        }
        Ok(())
    }

    fn program_routes(&mut self, cfg: &NetworkConfig, server_ip: Option<&str>, split_tunnel: bool) -> Result<()> {
        let ifname = self.ifname.clone();
        let orig_gw = original_default_gw();
        let full_tunnel = cfg.default_gateway && cfg.routes.is_empty() && !split_tunnel;
        if split_tunnel && cfg.default_gateway && cfg.routes.is_empty() {
            eprintln!(
                "[split-tunnel] gateway requested redirect-all but no specific routes were provided; nothing routed via the VPN"
            );
        }

        // 1) keep the gateway IP and explicit exclusions OFF the tunnel.
        let mut bypass: Vec<String> = cfg.exclude_routes.clone();
        if full_tunnel {
            if let Some(ip) = server_ip {
                bypass.push(format!("{ip}/32"));
            }
        }
        for r in &bypass {
            if let Some(net) = normalize_cidr(r) {
                if !orig_gw.is_empty() {
                    self.add_route(false, &[net.as_str(), "via", orig_gw.as_str()])?;
                }
            }
        }

        // 2) IPv4 tunnel routes.
        if full_tunnel {
            for net in ["0.0.0.0/1", "128.0.0.0/1"] {
                self.add_route(false, &[net, "dev", ifname.as_str()])?;
            }
        }
        for r in &cfg.routes {
            if let Some(net) = normalize_cidr(r) {
                self.add_route(false, &[net.as_str(), "dev", ifname.as_str()])?;
            }
        }

        // 3) IPv6 routes.
        if !cfg.ipv6address.is_empty() && cfg.default_gateway && cfg.ipv6routes.is_empty() {
            for net in ["::/1", "8000::/1"] {
                self.add_route(true, &[net, "dev", ifname.as_str()])?;
            }
        }
        for r in &cfg.ipv6routes {
            let net = r.trim();
            if !net.is_empty() {
                self.add_route(true, &[net, "dev", ifname.as_str()])?;
            }
        }
        Ok(())
    }

    fn program_dns(&mut self, cfg: &NetworkConfig, split_tunnel: bool) -> Result<()> {
        let mut servers: Vec<String> = cfg.dns.clone();
        servers.extend(cfg.ipv6dns.iter().cloned());
        if servers.is_empty() {
            return Ok(());
        }
        if split_tunnel {
            // Don't hijack the system resolver; attach the gateway DNS to the tun
            // link only (systemd-resolved) so it serves the routed networks.
            if which_exists("resolvectl") && !self.ifname.is_empty() {
                let mut args: Vec<String> = vec!["dns".to_string(), self.ifname.clone()];
                args.extend(servers.iter().cloned());
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                drop(
                    Command::new("resolvectl")
                        .args(&refs)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status(),
                );
            }
            return Ok(());
        }
        // Idempotent + crash-safe: restore a stale marker file first.
        self.restore_dns_if_stale();
        let original = std::fs::read(c::RESOLV_CONF).unwrap_or_else(|_| Vec::new());
        if std::fs::write(RESOLV_BAK, &original).is_err() {
            return Ok(()); // can't back up safely -> don't touch resolv.conf
        }
        let mut body = String::new();
        body.push_str(c::RESOLV_MARKER);
        body.push('\n');
        for s in &servers {
            body.push_str("nameserver ");
            body.push_str(s);
            body.push('\n');
        }
        atomic_write(c::RESOLV_CONF, body.as_bytes())?;
        self.dns_changed = true;
        Ok(())
    }

    fn restore_dns_if_stale(&self) {
        let Ok(cur) = std::fs::read(c::RESOLV_CONF) else { return };
        if find_subslice(&cur, c::RESOLV_MARKER.as_bytes()) && std::path::Path::new(RESOLV_BAK).exists() {
            match std::fs::read(RESOLV_BAK) {
                Ok(bak) => drop(atomic_write(c::RESOLV_CONF, &bak)),
                Err(e) => drop(e),
            }
        }
    }

    // -- teardown ----------------------------------------------------------
    pub fn close(&mut self) {
        for (v6, net) in self.added_routes.iter().rev() {
            let mut full: Vec<&str> = Vec::new();
            if *v6 {
                full.push("-6");
            }
            full.push("route");
            full.push("del");
            full.push(net.as_str());
            drop(run_ip(&full, false));
        }
        self.added_routes.clear();
        if self.dns_changed {
            if std::path::Path::new(RESOLV_BAK).exists() {
                match std::fs::read(RESOLV_BAK) {
                    Ok(bak) => {
                        drop(atomic_write(c::RESOLV_CONF, &bak));
                        drop(std::fs::remove_file(RESOLV_BAK));
                    }
                    Err(e) => drop(e),
                }
            }
            self.dns_changed = false;
        }
        self.tun = None; // closes the device if we still hold it
    }
}

impl Drop for VirtualNIC {
    fn drop(&mut self) {
        self.close();
    }
}

/// `TUNSETIFF` — the one place in this crate that needs `unsafe`.
#[allow(unsafe_code)] // audit-allow: TUNSETIFF requires a raw ioctl with a struct ifreq; rustix's Ioctl trait is itself unsafe to implement, so one confined, documented libc call is the smaller surface
fn tun_set_iff(fd: RawFd, ifr: &mut [u8; 40]) -> std::io::Result<()> {
    // SAFETY: `fd` is a valid, open file descriptor for /dev/net/tun (kept open
    // by an owning `File` for the whole call). `ifr` is a 40-byte, fully
    // zero-initialised buffer laid out as `struct ifreq` (name[16] + flags
    // short); `TUNSETIFF` reads the name/flags from it and writes the resolved
    // interface name back into the same buffer, never beyond its 40 bytes.
    let rc = unsafe { libc::ioctl(fd, c::TUNSETIFF, ifr.as_mut_ptr()) };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Run `ip <args>`. With `check`, a non-zero exit is an error. Returns the exit
/// code otherwise (`-1` if the process was signalled).
fn run_ip(args: &[&str], check: bool) -> Result<i32> {
    let output = Command::new("ip")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(InodeError::Io)?;
    if check && !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(InodeError::Config(format!("`ip {}` failed: {}", args.join(" "), err.trim())));
    }
    Ok(output.status.code().unwrap_or(-1))
}

fn original_default_gw() -> String {
    match Command::new("ip").args(["route", "show", "default"]).stderr(Stdio::null()).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let toks: Vec<&str> = s.split_whitespace().collect();
            if let Some(pos) = toks.iter().position(|&t| t == "via") {
                return toks.get(pos + 1).copied().unwrap_or("").to_string();
            }
            String::new()
        }
        Err(e) => {
            drop(e);
            String::new()
        }
    }
}

fn atomic_write(path: &str, data: &[u8]) -> Result<()> {
    let tmp = format!("{path}.h3c-tmp.{}", std::process::id());
    {
        let mut f = File::create(&tmp).map_err(InodeError::Io)?;
        f.write_all(data).map_err(InodeError::Io)?;
        f.sync_all().map_err(InodeError::Io)?;
    }
    std::fs::rename(&tmp, path).map_err(InodeError::Io)?;
    Ok(())
}

fn mask_to_prefix(mask: &str) -> u32 {
    let mask = mask.trim();
    if !mask.contains('.') {
        return mask.parse::<u32>().ok().filter(|n| *n <= 32).unwrap_or(32);
    }
    let mut bits = 0u32;
    for octet in mask.split('.') {
        match octet.parse::<u32>().ok() {
            Some(v) => bits += (v & 0xFF).count_ones(),
            None => return 32,
        }
    }
    bits
}

/// Accept `ip`, `ip/len` or `ip mask` and return `ip/len`.
fn normalize_cidr(route: &str) -> Option<String> {
    let route = route.trim();
    if route.is_empty() {
        return None;
    }
    if route.contains('/') {
        return Some(route.to_string());
    }
    let parts: Vec<&str> = route.split_whitespace().collect();
    if parts.len() == 2 {
        let ip = parts.first().copied().unwrap_or("");
        let mask = parts.get(1).copied().unwrap_or("");
        return Some(format!("{ip}/{}", mask_to_prefix(mask)));
    }
    Some(format!("{route}/32"))
}

fn which_exists(cmd: &str) -> bool {
    match std::env::var_os("PATH") {
        Some(paths) => std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()),
        None => false,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    crate::httpclient::find_subslice(haystack, needle).is_some()
}

/// True when the process has the root privileges needed to create the TUN.
pub fn have_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// True when the `ip` command is available.
pub fn have_ip_cmd() -> bool {
    which_exists("ip")
}
