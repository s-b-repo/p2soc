//! Data-plane: 4-byte framing, network-config parsing, heartbeat and the
//! TUN <-> TLS pump (port of `tunnel.py`).
//!
//! Frame layout (both directions), big-endian length:
//! ```text
//!   0  1  type     (1=data, 2=heartbeat, 3=netconfig, 4=force-logoff)
//!   1  1  subtype
//!   2  2  length   (uint16 BE) = payload byte count
//!   4  N  payload
//! ```
//! The pump is single-threaded: one `poll` loop waits on the TLS socket and the
//! TUN fd and folds the heartbeat timer into the poll timeout (the binary loops
//! every second but only sends a heartbeat every KEEPALIVETIME seconds).

use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::constants as c;
use crate::error::{InodeError, Result};
use crate::transport::TlsStream;

/// A decoded frame: `(type, subtype, payload)`.
pub type Frame = (u8, u8, Vec<u8>);

// --------------------------------------------------------------------------
// framing
// --------------------------------------------------------------------------
pub fn encode_frame(ftype: u8, subtype: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(payload.len())
        .map_err(|e| InodeError::Protocol(format!("frame payload exceeds 65535 bytes: {e}")))?;
    let mut out = Vec::with_capacity(c::FRAME_HEADER_LEN + payload.len());
    out.push(ftype);
    out.push(subtype);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reassembles frames from a byte stream that may split/coalesce them.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Frame>> {
        self.buf.extend_from_slice(data);
        // A single frame can never exceed header + 65535; an ever-growing
        // buffer is a slow memory-exhaustion DoS, so cap and bail.
        if self.buf.len() > c::MAX_FRAME_BUFFER {
            return Err(InodeError::Protocol("frame reassembly buffer overflow (stalled/garbage stream)".into()));
        }
        let mut out: Vec<Frame> = Vec::new();
        while let Some(hslice) = self.buf.get(..c::FRAME_HEADER_LEN) {
            let Ok(hdr) = <[u8; 4]>::try_from(hslice) else { break };
            let [ftype, subtype, len_hi, len_lo] = hdr;
            let length = usize::from(u16::from_be_bytes([len_hi, len_lo]));
            let end = c::FRAME_HEADER_LEN + length;
            let Some(pslice) = self.buf.get(c::FRAME_HEADER_LEN..end) else { break };
            let payload = pslice.to_vec();
            self.buf.drain(..end);
            out.push((ftype, subtype, payload));
        }
        Ok(out)
    }
}

// --------------------------------------------------------------------------
// network-config param block
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    pub ipaddress: String,
    pub subnetmask: String,
    pub gateway: String,
    pub prefixlength: String,
    pub dns: Vec<String>,
    pub routes: Vec<String>,
    pub exclude_routes: Vec<String>,
    pub restrict: String,
    pub keepalive_time: i64,
    pub default_gateway: bool,
    pub ipv6address: String,
    pub ipv6gateway: String,
    pub ipv6dns: Vec<String>,
    pub ipv6routes: Vec<String>,
    pub raw: String,
}

impl NetworkConfig {
    /// Missing IP or GATEWAY -> error (getVpnParamFromResp).
    pub fn is_valid(&self) -> bool {
        !self.ipaddress.is_empty() && (!self.gateway.is_empty() || self.default_gateway)
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.replace(';', ",").split(',').map(|x| x.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn first_net(route: &str) -> &str {
    route.split('/').next().unwrap_or("").trim()
}

/// Parse the plaintext `KEY:value` block (newline-separated).
pub fn parse_netconfig(data: &[u8]) -> NetworkConfig {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut cfg = NetworkConfig { raw: text.clone(), ..NetworkConfig::default() };

    for raw_line in text.replace('\r', "\n").split('\n') {
        let line = raw_line.trim();
        if line.is_empty() || !line.contains(':') {
            continue;
        }
        let (key, val) = line.split_once(':').unwrap_or((line, ""));
        let key = key.trim().to_ascii_uppercase();
        let val = val.trim();
        match key.as_str() {
            "IPADDRESS" => cfg.ipaddress = val.to_string(),
            "SUBNETMASK" => cfg.subnetmask = val.to_string(),
            "GATEWAY" => cfg.gateway = val.to_string(),
            "PREFIXLENGTH" => cfg.prefixlength = val.to_string(),
            "DNS" => cfg.dns = split_list(val),
            "ROUTES" => cfg.routes = split_list(val),
            "EXCLUDE ROUTES" => cfg.exclude_routes = split_list(val),
            "RESTRICT" => cfg.restrict = val.to_string(),
            "KEEPALIVETIME" => cfg.keepalive_time = val.parse::<i64>().unwrap_or(cfg.keepalive_time),
            "IPV6ADDRESS" => cfg.ipv6address = val.to_string(),
            "IPV6GATEWAY" => cfg.ipv6gateway = val.to_string(),
            "IPV6DNS" => cfg.ipv6dns = split_list(val),
            "IPV6ROUTES" => cfg.ipv6routes = split_list(val),
            _ => {}
        }
    }
    // A "0.0.0.0/0" route (or no routes) means redirect-all. Fold the catch-all
    // into default_gateway and drop it from the explicit route list so the vnic
    // full-tunnel path (split-default + server-IP bypass) engages.
    if cfg.routes.is_empty() {
        cfg.default_gateway = true;
    } else if cfg.routes.iter().any(|r| first_net(r) == "0.0.0.0") {
        cfg.default_gateway = true;
        cfg.routes.retain(|r| first_net(r) != "0.0.0.0");
    }
    cfg
}

// --------------------------------------------------------------------------
// tunnel runtime
// --------------------------------------------------------------------------
/// Events the pump reports so the supervisor can classify link state. The
/// string payloads carry the stable substrings the supervisor matches on.
#[derive(Debug, Clone)]
pub enum Event {
    /// The data pump has started.
    Up(String),
    /// A mid-session network-config update frame (type 3 / sub 2). Boxed to keep
    /// the enum small (the other variants are tiny).
    NetConfig(Box<NetworkConfig>),
    /// A heartbeat was sent (or an inbound frame kept the link alive).
    Heartbeat,
    /// The gateway sent a forced log-off (type 4).
    LogOff(String),
    /// The link went down; the message says why.
    Down(String),
}

/// Pumps packets between a TUN device and the TLS tunnel socket, runs the
/// heartbeat, and dispatches control frames. The TUN may be absent (headless
/// construction tests); data frames are then simply discarded.
pub struct Tunnel {
    stream: TlsStream,
    tun: Option<File>,
    dec: FrameDecoder,
    keepalive_interval: Duration,
    keepalive_max_miss: u32,
    early: Vec<Frame>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Tunnel {
    /// Build a tunnel around a fresh TLS stream. `initial_buffer` holds any
    /// bytes already read past the `NET_EXTEND` preamble; they are decoded and
    /// held (not dispatched) until [`Tunnel::run`].
    pub fn new(stream: TlsStream, initial_buffer: &[u8], keepalive_max_miss: u32) -> Result<Tunnel> {
        let mut dec = FrameDecoder::default();
        let early = if initial_buffer.is_empty() { Vec::new() } else { dec.feed(initial_buffer)? };
        Ok(Tunnel {
            stream,
            tun: None,
            dec,
            keepalive_interval: Duration::from_secs(c::DEFAULT_KEEPALIVE_INTERVAL),
            keepalive_max_miss,
            early,
            bytes_in: 0,
            bytes_out: 0,
        })
    }

    /// Attach the TUN device (its fd is read/written by the pump).
    pub fn set_tun(&mut self, tun: File) {
        self.tun = Some(tun);
    }

    /// Override the heartbeat send interval (from the netconfig KEEPALIVETIME).
    pub fn set_keepalive_interval(&mut self, secs: u64) {
        self.keepalive_interval = Duration::from_secs(secs.max(1));
    }

    pub fn keepalive_interval_secs(&self) -> u64 {
        self.keepalive_interval.as_secs()
    }

    // -- sending -----------------------------------------------------------
    pub fn send_frame(&mut self, ftype: u8, subtype: u8, payload: &[u8]) -> Result<()> {
        let frame = encode_frame(ftype, subtype, payload)?;
        Write::write_all(&mut self.stream, &frame).map_err(InodeError::Io)?;
        Write::flush(&mut self.stream).map_err(InodeError::Io)?;
        Ok(())
    }

    pub fn send_ip(&mut self, packet: &[u8]) -> Result<()> {
        self.send_frame(c::FRAME_DATA, 0, packet)?;
        self.bytes_out += u64::try_from(packet.len()).unwrap_or(0);
        Ok(())
    }

    // -- netconfig handshake (before the pump) -----------------------------
    /// Block until the first type=3/sub=2 netconfig frame arrives. Other frames
    /// seen meanwhile are retained in `early` so [`Tunnel::run`] delivers them.
    pub fn wait_netconfig(&mut self, timeout: Duration) -> Result<Option<NetworkConfig>> {
        let mut keep: Vec<Frame> = Vec::new();
        let mut found: Option<NetworkConfig> = None;
        for fr in std::mem::take(&mut self.early) {
            if found.is_none() && fr.0 == c::FRAME_NETCONFIG && fr.1 == c::NETCONFIG_SUB_UPDATE {
                found = Some(parse_netconfig(&fr.2));
            } else {
                keep.push(fr);
            }
        }
        self.early = keep;
        if let Some(cfg) = found {
            return Ok(Some(cfg));
        }

        let deadline = Instant::now() + timeout;
        let mut early_bytes: usize = self.early.iter().map(|f| f.2.len()).sum();
        let mut buf = vec![0u8; c::BIG_BUF_SIZE];
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (sock_ready, _) = self.poll_fds(remaining)?;
            if !sock_ready {
                continue;
            }
            let n = match Read::read(&mut self.stream, &mut buf) {
                Ok(0) => return Err(InodeError::Tunnel("tunnel socket closed before netconfig".into())),
                Ok(n) => n,
                Err(e) if is_retry(&e) => continue,
                Err(e) => return Err(InodeError::Io(e)),
            };
            for fr in self.dec.feed(buf.get(..n).unwrap_or(&[]))? {
                if fr.0 == c::FRAME_NETCONFIG && fr.1 == c::NETCONFIG_SUB_UPDATE {
                    return Ok(Some(parse_netconfig(&fr.2)));
                }
                early_bytes += fr.2.len();
                self.early.push(fr);
                if early_bytes > c::MAX_EARLY_BYTES {
                    return Err(InodeError::Tunnel("too many early frames before netconfig (flood)".into()));
                }
            }
        }
        Ok(None)
    }

    // -- run ---------------------------------------------------------------
    /// Pump packets until `stop` is set or the link drops. Classification
    /// events are delivered through `on_event`.
    pub fn run(&mut self, stop: &AtomicBool, on_event: &dyn Fn(Event)) -> Result<()> {
        on_event(Event::Up("tunnel data pump started".to_string()));
        let mut miss: u32 = 0;
        // Replay frames buffered during NET_EXTEND / wait_netconfig.
        let early = std::mem::take(&mut self.early);
        if !self.dispatch(early, &mut miss, on_event)? {
            return Ok(());
        }
        let interval = self.keepalive_interval;
        let mut next_hb = Instant::now() + interval;
        let mut buf = vec![0u8; c::BIG_BUF_SIZE];

        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let now = Instant::now();
            if now >= next_hb {
                if miss >= self.keepalive_max_miss {
                    on_event(Event::Down("heartbeat: no response, going offline".to_string()));
                    self.stream.shutdown();
                    return Ok(());
                }
                miss += 1;
                match self.send_frame(c::FRAME_HEARTBEAT, 1, &[]) {
                    Ok(()) => on_event(Event::Heartbeat),
                    Err(e) => {
                        on_event(Event::Down(format!("tunnel socket closed: {e}")));
                        return Ok(());
                    }
                }
                next_hb = now + interval;
            }

            let timeout = next_hb.saturating_duration_since(Instant::now()).min(Duration::from_secs(1));
            let (sock_ready, tun_ready) = self.poll_fds(timeout)?;

            if sock_ready {
                let n = match Read::read(&mut self.stream, &mut buf) {
                    Ok(0) => {
                        on_event(Event::Down("tunnel socket closed".to_string()));
                        return Ok(());
                    }
                    Ok(n) => n,
                    Err(e) if is_retry(&e) => 0,
                    Err(e) => {
                        on_event(Event::Down(format!("tunnel socket closed: {e}")));
                        return Ok(());
                    }
                };
                if n > 0 {
                    let frames = self.dec.feed(buf.get(..n).unwrap_or(&[]))?;
                    if !self.dispatch(frames, &mut miss, on_event)? {
                        return Ok(());
                    }
                }
            }

            if tun_ready {
                let n = match self.tun.as_mut() {
                    Some(tun) => match Read::read(tun, &mut buf) {
                        Ok(n) => n,
                        Err(e) if is_retry(&e) => 0,
                        Err(e) => {
                            on_event(Event::Down(format!("tunnel socket closed: TUN read failed: {e}")));
                            return Ok(());
                        }
                    },
                    None => 0,
                };
                if n > 0 {
                    self.send_ip(buf.get(..n).unwrap_or(&[]))?;
                }
            }
        }
    }

    /// Dispatch decoded frames. Returns `false` when a forced log-off was seen.
    fn dispatch(&mut self, frames: Vec<Frame>, miss: &mut u32, on_event: &dyn Fn(Event)) -> Result<bool> {
        for (ftype, subtype, payload) in frames {
            *miss = 0; // any inbound frame proves the link is alive
            match ftype {
                c::FRAME_DATA => {
                    self.bytes_in += u64::try_from(payload.len()).unwrap_or(0);
                    if let Some(tun) = self.tun.as_mut() {
                        Write::write_all(tun, &payload).map_err(InodeError::Io)?;
                    }
                }
                c::FRAME_HEARTBEAT => {}
                c::FRAME_NETCONFIG => {
                    if subtype == c::NETCONFIG_SUB_UPDATE {
                        on_event(Event::NetConfig(Box::new(parse_netconfig(&payload))));
                    }
                    // NETCONFIG_SUB_DTLS is ignored on Linux.
                }
                c::FRAME_LOGOFF => {
                    on_event(Event::LogOff("gateway forced log-off (type=4)".to_string()));
                    return Ok(false);
                }
                _ => {}
            }
        }
        Ok(true)
    }

    /// `poll` the TLS socket (and the TUN, if attached) for readability.
    fn poll_fds(&self, timeout: Duration) -> Result<(bool, bool)> {
        let ts = to_timespec(timeout);
        let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(2);
        fds.push(PollFd::new(self.stream.get_ref(), PollFlags::IN));
        if let Some(tun) = self.tun.as_ref() {
            fds.push(PollFd::new(tun, PollFlags::IN));
        }
        match poll(&mut fds, Some(&ts)) {
            Ok(_) => {}
            Err(e) if e == rustix::io::Errno::INTR => return Ok((false, false)),
            Err(e) => return Err(InodeError::Io(std::io::Error::from(e))),
        }
        let ready = |p: &PollFd<'_>| p.revents().intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP);
        let sock = fds.first().map(ready).unwrap_or(false);
        let tun = fds.get(1).map(ready).unwrap_or(false);
        Ok((sock, tun))
    }
}

pub(crate) fn is_retry(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted)
}

/// `poll` a single TLS socket for readability (used by the NET_EXTEND preamble).
pub(crate) fn poll_readable(stream: &TlsStream, timeout: Duration) -> Result<bool> {
    let ts = to_timespec(timeout);
    let mut fds = [PollFd::new(stream.get_ref(), PollFlags::IN)];
    match poll(&mut fds, Some(&ts)) {
        Ok(_) => {}
        Err(e) if e == rustix::io::Errno::INTR => return Ok(false),
        Err(e) => return Err(InodeError::Io(std::io::Error::from(e))),
    }
    Ok(fds.first().map(|p| p.revents().intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP)).unwrap_or(false))
}

pub(crate) fn to_timespec(d: Duration) -> Timespec {
    Timespec { tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX), tv_nsec: d.subsec_nanos().into() }
}
