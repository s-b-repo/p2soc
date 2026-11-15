//! Native H3C iNode SSL-VPN (V7) client — a clean-room Rust port of
//! `vendor/iNode-VPN-Client/backends/h3csvpn`.
//!
//! Two front ends share one implementation:
//!
//! * a **library API** the VPN supervisor drives in-process —
//!   [`Client::new`] → [`Client::authenticate`] → [`Session::open_tunnel`] →
//!   [`Tunnel::run`], with [`Event`] reporting link state and a typed
//!   [`InodeError`]; and
//! * [`connect_main`], a CLI entry matching the argv the supervisor already
//!   builds for the iNode backend (`svpn-connect.sh`'s interface).
//!
//! The password lives in [`zeroize::Zeroizing`] and never reaches a log line or
//! argv. The transport is raw TLS over `std::net::TcpStream` (rustls); after the
//! `NET_EXTEND` upgrade the same socket carries binary frames.

pub mod captcha;
pub mod cli;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod httpclient;
pub mod protocol;
mod safexml;
pub mod session;
pub mod spa;
pub mod transport;
pub mod tunnel;
pub mod vnic;

pub use cli::connect_main;
pub use error::{InodeError, Result};
pub use protocol::{
    Domain, GatewayInfo, LoginResult, build_challenge_xml, build_login_xml, parse_domainlist, parse_gatewayinfo,
    parse_login_result,
};
pub use session::{Client, ClientConfig, Prompter, Session, StdinPrompter};
pub use spa::SpaConfig;
pub use transport::{TlsConfig, TlsStream};
pub use tunnel::{Event, FrameDecoder, NetworkConfig, Tunnel, encode_frame, parse_netconfig};

/// Crate version marker.
pub const INODE_CLIENT_VERSION: &str = "0.1.0";
