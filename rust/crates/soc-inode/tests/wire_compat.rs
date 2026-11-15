//! Wire-compat fixtures: expected bytes/strings were produced by running the
//! real vendored Python backend
//! (`cd vendor/iNode-VPN-Client && PYTHONPATH=backends python3 ...`). These
//! assert the Rust port is byte-identical.

use soc_inode::captcha;
use soc_inode::crypto;
use soc_inode::protocol::{self, ChallengeXml, LoginXml};
use soc_inode::spa::SpaConfig;
use soc_inode::tunnel::{encode_frame, parse_netconfig};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn urlencode_body_is_byte_exact() {
    let mut args = LoginXml::new("jane doe@corp", "p@ss word/<>&");
    args.vld_code = "A1b2";
    args.language = "en";
    args.mac = "00:11:22:33:44:55";
    let xml = protocol::build_login_xml(&args);
    assert_eq!(
        xml.as_str(),
        "<data><username>jane doe@corp</username><password>p@ss word/&lt;&gt;&amp;</password>\
         <vldCode>A1b2</vldCode><language>en</language><OS>Linux</OS>\
         <macAddress>00:11:22:33:44:55</macAddress><supportChallengePwd>1</supportChallengePwd>\
         <private></private></data>"
    );
    let body = crypto::urlencode_body(&xml);
    assert_eq!(
        body.as_str(),
        "request=%3Cdata%3E%3Cusername%3Ejane+doe%40corp%3C%2Fusername%3E%3Cpassword%3Ep%40ss+word%2F%26lt%3B%26gt%3B%26amp%3B%3C%2Fpassword%3E%3CvldCode%3EA1b2%3C%2FvldCode%3E%3Clanguage%3Een%3C%2Flanguage%3E%3COS%3ELinux%3C%2FOS%3E%3CmacAddress%3E00%3A11%3A22%3A33%3A44%3A55%3C%2FmacAddress%3E%3CsupportChallengePwd%3E1%3C%2FsupportChallengePwd%3E%3Cprivate%3E%3C%2Fprivate%3E%3C%2Fdata%3E"
    );
}

#[test]
fn challenge_xml_variants() {
    let sms = protocol::build_challenge_xml(&{
        let mut c = ChallengeXml::new("u@d", "SMS", "123456");
        c.language = "cn";
        c
    });
    assert_eq!(
        sms.as_str(),
        "<data><username>u@d</username><type>SMS</type><code>123456</code><language>cn</language>\
         <vldCode></vldCode><OS>Linux</OS><macAddress></macAddress><private></private></data>"
    );

    let smsimc = protocol::build_challenge_xml(&{
        let mut c = ChallengeXml::new("u@d", "SMS-IMC", "999");
        c.language = "cn";
        c.password = Some("secret");
        c.mac = "aa:bb";
        c
    });
    assert_eq!(
        smsimc.as_str(),
        "<data><username>u@d</username><type>SMS-IMC</type><code>999</code><language>cn</language>\
         <password>secret</password><vldCode></vldCode><OS>Linux</OS><macAddress>aa:bb</macAddress>\
         <private></private></data>"
    );

    let changepwd = protocol::build_challenge_xml(&{
        let mut c = ChallengeXml::new("u@d", "CHANGEPWD", "");
        c.language = "cn";
        c.password = Some("old");
        c.new_password = Some("new");
        c
    });
    assert_eq!(
        changepwd.as_str(),
        "<data><username>u@d</username><type>CHANGEPWD</type><code></code><language>cn</language>\
         <password>old</password><newPassword>new</newPassword><vldCode></vldCode><OS>Linux</OS>\
         <macAddress></macAddress><private></private></data>"
    );
    assert_eq!(
        crypto::urlencode_body(&changepwd).as_str(),
        "request=%3Cdata%3E%3Cusername%3Eu%40d%3C%2Fusername%3E%3Ctype%3ECHANGEPWD%3C%2Ftype%3E%3Ccode%3E%3C%2Fcode%3E%3Clanguage%3Ecn%3C%2Flanguage%3E%3Cpassword%3Eold%3C%2Fpassword%3E%3CnewPassword%3Enew%3C%2FnewPassword%3E%3CvldCode%3E%3C%2FvldCode%3E%3COS%3ELinux%3C%2FOS%3E%3CmacAddress%3E%3C%2FmacAddress%3E%3Cprivate%3E%3C%2Fprivate%3E%3C%2Fdata%3E"
    );
}

#[test]
fn hotp_rfc4226_vectors() {
    let key = b"12345678901234567890";
    // (counter, 6-digit, 5-digit+Luhn)
    let cases: &[(u64, &str, &str)] = &[
        (0, "755224", "552240"),
        (1, "287082", "870824"),
        (0x1234_ABCD, "912365", "123653"),
        (0xFFFF_FFFF, "117190", "171900"),
    ];
    for (ctr, d6, d5l) in cases {
        assert_eq!(crypto::hotp(key, *ctr, 6, false).unwrap(), *d6, "d6 counter {ctr:#x}");
        assert_eq!(crypto::hotp(key, *ctr, 5, true).unwrap(), *d5l, "d5+luhn counter {ctr:#x}");
    }
    // The 6-byte SPA password field for counter 0 is ASCII "552240".
    assert_eq!(hex(&crypto::hotp_bytes(key, 0, 6, 5, true).unwrap()), "353532323430");
}

#[test]
fn spa_knock_is_byte_exact() {
    let mut cfg = SpaConfig::new(b"MYAID-0123456789".to_vec(), b"topsecretkey".to_vec());
    cfg.ports = vec![443, 8443];
    let pkt = crypto_build(&cfg, 0x1122_3344);
    assert_eq!(
        hex(&pkt),
        "10014d594149442d3031323334353637383900000000000000000000000000000000112233443232343735380201bb20fb"
    );

    let mut cfg2 = SpaConfig::new(vec![b'A'; 40], b"k".to_vec());
    cfg2.ports = vec![443];
    let pkt2 = crypto_build(&cfg2, 1);
    assert_eq!(
        hex(&pkt2),
        "10014141414141414141414141414141414141414141414141414141414141414141000000013135383233380101bb"
    );
}

fn crypto_build(cfg: &SpaConfig, pkt_id: u32) -> Vec<u8> {
    soc_inode::spa::build_knock(cfg, Some(pkt_id)).unwrap()
}

#[test]
fn frame_encoding() {
    assert_eq!(hex(&encode_frame(1, 0, b"hello").unwrap()), "0100000568656c6c6f");
    assert_eq!(hex(&encode_frame(2, 1, b"").unwrap()), "02010000");
}

#[test]
fn netconfig_parsing() {
    let nc = parse_netconfig(
        b"IPADDRESS:10.8.0.3\r\nSUBNETMASK:24\r\nGATEWAY:10.8.0.1\r\nDNS:8.8.8.8,1.1.1.1\r\nROUTES:10.0.0.0/8;192.168.0.0/16\r\nKEEPALIVETIME:45\r\n",
    );
    assert_eq!(nc.ipaddress, "10.8.0.3");
    assert_eq!(nc.subnetmask, "24");
    assert_eq!(nc.gateway, "10.8.0.1");
    assert_eq!(nc.dns, vec!["8.8.8.8", "1.1.1.1"]);
    assert_eq!(nc.routes, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    assert_eq!(nc.keepalive_time, 45);
    assert!(!nc.default_gateway);
    assert!(nc.is_valid());

    // A 0.0.0.0/0 route folds into default_gateway and is dropped.
    let redir = parse_netconfig(b"IPADDRESS:10.0.0.2\nGATEWAY:10.0.0.1\nROUTES:0.0.0.0/0,10.1.0.0/16\n");
    assert_eq!(redir.routes, vec!["10.1.0.0/16"]);
    assert!(redir.default_gateway);
}

#[test]
fn gatewayinfo_parsing() {
    let gw = "<data><gatewayinfo><auth><supportPassword>true</supportPassword><supportCert>false</supportCert><supportvldimg>true</supportvldimg></auth><url><login>/_xml/login.cgi</login><logout>/_xml/logout.cgi</logout><challenge>/_xml/check_return.cgi</challenge><vldimg>/vldimg.cgi</vldimg></url></gatewayinfo></data>";
    let gi = protocol::parse_gatewayinfo(gw).unwrap();
    assert!(gi.support_password);
    assert!(!gi.support_cert);
    assert!(gi.support_vldimg);
    assert_eq!(gi.login_url, "/_xml/login.cgi");
    assert_eq!(gi.logout_url, "/_xml/logout.cgi");
    assert_eq!(gi.challenge_url, "/_xml/check_return.cgi");
    assert_eq!(gi.vldimg_url, "/vldimg.cgi");
}

#[test]
fn domainlist_parsing() {
    let dl = "<data><domainlist><domain><name>corp</name><url>/corp/login.cgi</url></domain><domain><name>guest</name><url>/guest/login.cgi</url></domain></domainlist></data>";
    let doms = protocol::parse_domainlist(dl).unwrap();
    assert_eq!(doms.len(), 2);
    assert_eq!(doms[0].name, "corp");
    assert_eq!(doms[0].url, "/corp/login.cgi");
    assert_eq!(doms[1].name, "guest");
}

#[test]
fn login_result_parsing() {
    let lr = protocol::parse_login_result(
        "<data><result>Challenge</result><type>SMS</type><message>enter code</message><waitTime>60</waitTime></data>",
    )
    .unwrap();
    assert_eq!(lr.result, "Challenge");
    assert_eq!(lr.ctype, "SMS");
    assert_eq!(lr.message, "enter code");
    assert_eq!(lr.wait_time, 60);
    assert!(lr.is_challenge());
    assert!(!lr.is_success());

    let ok =
        protocol::parse_login_result("<data><result>Success</result><EMOServer>10.1.1.1</EMOServer></data>").unwrap();
    assert!(ok.is_success());
    assert_eq!(ok.emo_server, "10.1.1.1");
}

#[test]
fn bmp_decode_matches_python() {
    // Fixture produced by the Python captcha.decode_bmp on a 3x2 24-bit BMP.
    let bmp = include_bytes!("fixtures/captcha_3x2.bmp");
    let img = captcha::decode_bmp(bmp).unwrap();
    assert_eq!((img.width, img.height), (3, 2));
    // row 0 = TOP of the image.
    assert_eq!(img.rows[0], vec![[255, 0, 0], [0, 255, 0], [0, 0, 255]]);
    assert_eq!(img.rows[1], vec![[255, 255, 255], [0, 0, 0], [255, 255, 0]]);
    // The ANSI render is non-empty and resets colour at the end of each line.
    let ansi = captcha::render_ansi(&img.rows, 96);
    assert!(ansi.contains("\u{1b}[0m"));
}

#[test]
fn urlencode_space_becomes_plus_not_percent20() {
    // Classic form-urlencoding: a space is '+', and '-._~' are NOT unreserved.
    assert_eq!(crypto::urlencode_body("a b-c.d_e~f").as_str(), "request=a+b%2Dc%2Ed%5Fe%7Ef");
}

// --- RSA password mode (H3C_USER_RSAKEY firmware variant) -------------------

#[test]
fn rsa_password_mode_round_trips_pem_and_der() {
    use base64::Engine as _;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

    // A throwaway 1024-bit key is plenty to exercise the encode path.
    let mut rng = rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
    let pub_key = RsaPublicKey::from(&priv_key);
    let pem = pub_key.to_public_key_pem(LineEnding::LF).expect("spki pem");
    let der = pub_key.to_public_key_der().expect("spki der");

    let password = "s3cr3t-p@ss/<>&";
    // Both PEM (SubjectPublicKeyInfo) and DER must be accepted, and the
    // base64 ciphertext must decrypt back to the exact plaintext password.
    for key_bytes in [pem.as_bytes(), der.as_bytes()] {
        let b64 = crypto::rsa_encrypt_password_b64(key_bytes, password).expect("encrypt");
        let ct = base64::engine::general_purpose::STANDARD.decode(&b64).expect("b64 decode");
        let pt = priv_key.decrypt(Pkcs1v15Encrypt, &ct).expect("decrypt");
        assert_eq!(pt, password.as_bytes());
    }
}

#[test]
fn rsa_password_mode_accepts_pkcs1_encodings() {
    use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    let mut rng = rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
    let pub_key = RsaPublicKey::from(&priv_key);
    let pem = pub_key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
    let der = pub_key.to_pkcs1_der().expect("pkcs1 der");

    // `BEGIN RSA PUBLIC KEY` (PKCS#1) and its DER both parse via the fallback.
    assert!(crypto::rsa_encrypt_password_b64(pem.as_bytes(), "pw").is_ok());
    assert!(crypto::rsa_encrypt_password_b64(der.as_bytes(), "pw").is_ok());
}

#[test]
fn rsa_password_mode_rejects_a_bad_key() {
    assert!(crypto::rsa_encrypt_password_b64(b"-----BEGIN PUBLIC KEY-----\nnonsense\n", "pw").is_err());
    assert!(crypto::rsa_encrypt_password_b64(b"not a key at all", "pw").is_err());
}
