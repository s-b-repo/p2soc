//! Zero-Trust SPA (Single Packet Authorization) knock (port of `spa.py`).
//!
//! Before the SSL VPN port is reachable on a Zero-Trust gateway, the client
//! fires a 47-byte UDP knock (to UDP/8000 by default) authenticated with an RFC
//! 4226 HOTP over a random per-packet counter. The per-client `client_key`/`aid`
//! come from an out-of-scope SDP registration and are supplied by the caller.
//!
//! Packet (47-byte base, confirmed against `onKnockUDPMsg`):
//! ```text
//!   0x00  u16  declaredLen = 0x0110, native little-endian -> bytes 10 01
//!   0x02  [32] clientAid (raw bytes, padded/truncated to 32)
//!   0x22  u32  pktID = random, big-endian on the wire
//!   0x26  [6]  password = HOTP(client_key, pktID) (5 digits + 1 Luhn, SHA-1)
//!   0x2c  u8   portCount
//!   0x2d  u16  port0 (big-endian) ... portN
//! ```

use std::net::UdpSocket;

use zeroize::Zeroizing;

use crate::constants as c;
use crate::crypto::hotp_bytes;
use crate::error::{InodeError, Result};

/// SPA knock parameters.
#[derive(Clone)]
pub struct SpaConfig {
    /// Client AID (<=32 bytes) from SDP registration.
    pub aid: Vec<u8>,
    /// Per-client HOTP key from SDP registration (wiped on drop).
    pub client_key: Zeroizing<Vec<u8>>,
    /// Ports to request; defaults to the auth port (443).
    pub ports: Vec<u16>,
    /// HOTP digit count (5 before the Luhn digit).
    pub digits: u32,
}

impl SpaConfig {
    pub fn new(aid: Vec<u8>, client_key: Vec<u8>) -> SpaConfig {
        SpaConfig {
            aid,
            client_key: Zeroizing::new(client_key),
            ports: vec![c::SPA_AUTH_PORT],
            digits: u32::try_from(c::SPA_HOTP_DIGITS).unwrap_or(5),
        }
    }
}

/// Build the knock packet. `pkt_id` is normally random; a caller may pin it
/// (tests) to get a deterministic packet.
pub fn build_knock(cfg: &SpaConfig, pkt_id: Option<u32>) -> Result<Vec<u8>> {
    let pkt_id = match pkt_id {
        Some(v) => v,
        None => random_u32()?,
    };
    // aid padded/truncated to 32 bytes.
    let mut aid = [0u8; c::SPA_AID_LEN];
    for (dst, src) in aid.iter_mut().zip(cfg.aid.iter()) {
        *dst = *src;
    }
    // digits=5 + Luhn checksum -> 6 chars filling the password[6] field.
    let pw = hotp_bytes(&cfg.client_key, u64::from(pkt_id), 6, cfg.digits, true)?;
    let port_count =
        u8::try_from(cfg.ports.len()).map_err(|e| InodeError::Config(format!("too many SPA ports: {e}")))?;

    let mut pkt = Vec::with_capacity(c::SPA_HEADER_LEN + cfg.ports.len() * 2);
    pkt.extend_from_slice(&c::SPA_DECLARED_LEN.to_le_bytes()); // native little-endian
    pkt.extend_from_slice(&aid);
    pkt.extend_from_slice(&pkt_id.to_be_bytes());
    pkt.extend_from_slice(&pw);
    pkt.push(port_count);
    for p in &cfg.ports {
        pkt.extend_from_slice(&p.to_be_bytes());
    }
    Ok(pkt)
}

/// Build and fire-and-forget the knock over UDP to `host:port`.
pub fn send_knock(host: &str, cfg: &SpaConfig, port: u16, pkt_id: Option<u32>) -> Result<Vec<u8>> {
    let pkt = build_knock(cfg, pkt_id)?;
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.send_to(&pkt, (host, port))?;
    Ok(pkt)
}

fn random_u32() -> Result<u32> {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).map_err(|e| InodeError::Config(format!("OS random source unavailable: {e}")))?;
    Ok(u32::from_be_bytes(buf))
}
