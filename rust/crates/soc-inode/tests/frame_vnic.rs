//! Frame codec and netconfig parser (direct), plus vnic construction/guard
//! tests (the real TUN device needs root, so only the non-privileged paths are
//! exercised here).

use soc_inode::NetworkConfig;
use soc_inode::tunnel::{FrameDecoder, encode_frame, parse_netconfig};
use soc_inode::vnic::{self, VirtualNIC};

#[test]
fn decoder_reassembles_split_and_coalesced_frames() {
    let f1 = encode_frame(1, 0, b"abc").unwrap();
    let f2 = encode_frame(2, 1, b"").unwrap();
    let f3 = encode_frame(3, 2, b"IPADDRESS:10.0.0.1").unwrap();
    let mut stream = Vec::new();
    stream.extend_from_slice(&f1);
    stream.extend_from_slice(&f2);
    stream.extend_from_slice(&f3);

    let mut dec = FrameDecoder::default();
    // Feed the stream one byte at a time: frames must only emit once complete.
    let mut frames = Vec::new();
    for b in &stream {
        frames.extend(dec.feed(&[*b]).unwrap());
    }
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0], (1, 0, b"abc".to_vec()));
    assert_eq!(frames[1], (2, 1, Vec::new()));
    assert_eq!(frames[2].0, 3);
    assert_eq!(frames[2].1, 2);
    assert_eq!(frames[2].2, b"IPADDRESS:10.0.0.1".to_vec());
}

#[test]
fn decoder_handles_a_coalesced_feed() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_frame(1, 0, b"x").unwrap());
    blob.extend_from_slice(&encode_frame(1, 0, b"yy").unwrap());
    let mut dec = FrameDecoder::default();
    let frames = dec.feed(&blob).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].2, b"x".to_vec());
    assert_eq!(frames[1].2, b"yy".to_vec());
}

#[test]
fn netconfig_prefixlength_and_ipv6() {
    let nc = parse_netconfig(
        b"IPADDRESS:172.16.0.5\nPREFIXLENGTH:20\nGATEWAY:172.16.0.1\nIPV6ADDRESS:fd00::2\nIPV6ROUTES:fd00::/64\n",
    );
    assert_eq!(nc.ipaddress, "172.16.0.5");
    assert_eq!(nc.prefixlength, "20");
    assert_eq!(nc.ipv6address, "fd00::2");
    assert_eq!(nc.ipv6routes, vec!["fd00::/64"]);
    assert!(nc.is_valid());
}

#[test]
fn netconfig_without_routes_is_full_tunnel() {
    let nc = parse_netconfig(b"IPADDRESS:10.0.0.9\nGATEWAY:10.0.0.1\n");
    assert!(nc.routes.is_empty());
    assert!(nc.default_gateway);
}

#[test]
fn netconfig_missing_ip_is_invalid() {
    let nc = parse_netconfig(b"GATEWAY:10.0.0.1\nROUTES:10.0.0.0/8\n");
    assert!(!nc.is_valid());
}

#[test]
fn vnic_new_sets_template() {
    let nic = VirtualNIC::new("inode%d");
    assert_eq!(nic.name_template, "inode%d");
    assert!(nic.ifname.is_empty());
    // An empty template falls back to the default.
    assert_eq!(VirtualNIC::new("").name_template, "inode%d");
}

#[test]
fn vnic_configure_requires_open_device() {
    let mut nic = VirtualNIC::new("inode%d");
    let cfg = NetworkConfig {
        ipaddress: "10.0.0.2".to_string(),
        gateway: "10.0.0.1".to_string(),
        ..NetworkConfig::default()
    };
    // No device opened (ifname empty) -> a typed error, no privileged syscall.
    assert!(nic.configure(&cfg, None, false).is_err());
}

#[test]
fn vnic_capability_probes_do_not_panic() {
    // Smoke: these just return bools and must never panic.
    let _ = vnic::have_root();
    let _ = vnic::have_ip_cmd();
}
