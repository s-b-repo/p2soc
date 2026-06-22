# Protocol implementation status & roadmap

## 802.1X (iNode port id 8021) — ✅ working

Implemented in `src/protocols/Dot1xProtocol.cpp` as a thin wrapper around `minieap` (or `mentohust` as fallback). Both are open-source community reimplementations of the HC-CHAPv2 variant that H3C's `libInodeX1Pt.so` speaks.

The wrapper exposes the full knob set the original client offers through its "Advanced" panel:
- auth mode (PAP / CHAP / MSCHAPv2 / EAP-MD5 / EAP-PEAP / HC-CHAPv2)
- rjv3 on/off, service type, carrier string
- heartbeat (`-r` for minieap, `-t` for mentohust)
- arbitrary extra args (free-form) — useful for the campus-specific flags some iMC builds require

**IP addressing:** 802.1X only authenticates the port — the supplicant brings no
address of its own. The profile's *IP mode* (Advanced tab) is applied right after
auth succeeds: **Inherit** leaves the OS as-is, **DHCP** triggers a renew, and
**Static** programs the address / netmask / gateway / DNS via the privileged
`inode-ipcfg-helper` (polkit `org.inode.ClientQt.ipcfg`). It is torn down on
disconnect. The same applies to WLAN (which wraps the 802.1X plugin).

**Known limitations:**
- Campus deployments with custom iNode hash salts may require passing extra `--rjv3` flags through *Extra args*. Capture a successful auth from the original client and compare if the default profile doesn't work.
- `libInodeX1Pt.so` also implements H3C's "智能感知" (smart re-auth) heartbeat — `minieap` covers it for the common case, but some server builds expect a client-hello frame minieap doesn't send.

## WLAN (iNode port id 1100) — ✅ working

Wireless 802.1X in `src/protocols/WlanProtocol.cpp`:

1. `nmcli device wifi connect <ssid> password <pw> ifname <iface>` — hands association to NetworkManager, which is the only supplicant that plays nicely with WPA3/802.11w on modern distros.
2. Once associated, the Dot1x plugin runs the same 802.1X flow as the wired case on the now-connected `wlanX` interface.

If the profile's SSID field is empty, the plugin falls back to plain 802.1X (useful for pre-associated setups).

## L2TP/IPSec (port 2401) — ✅ working against RFC-compliant servers

Uses system `strongswan` + `xl2tpd`. The GUI writes fragment configs under `/etc/ipsec.conf.d/` and `/etc/xl2tpd/xl2tpd.conf.d/` through the polkit helper (`scripts/inode-l2tp-helper`). `forceencaps=yes` can be toggled per-profile for concentrators that always require UDP encap on 4500. The PSK and password are streamed to the helper on **stdin** (`--secrets-stdin`), never passed as command-line arguments, so they never appear in `ps`/`/proc`.

**Where it won't work:** iMC/EIA deployments that require H3C's proprietary IKE vendor ID exchange or custom phase-2 transforms. Those need custom strongswan plugin work or a userspace IKE implementation — not trivial, but out of scope here.

## Portal v2 — ✅ working

Implemented natively in `src/protocols/PortalProtocol.cpp`. Full state machine: REQ_CHALLENGE → ACK_CHALLENGE → REQ_AUTH → ACK_AUTH → AFF_ACK_AUTH, plus a timer-driven keep-alive and REQ_LOGOUT on disconnect. MD5-keyed checksum uses the per-profile shared secret (defaults to `h3c` if unset).

Each iMC Portal deployment ships with:
- a shared secret (typical defaults: `h3c`, `huawei3com`, `portalsecret`),
- a UDP port (2000 is default; some deployments use 50100),
- a dialect switch (v2 vs H3C-TLV).

The **v2 standard** dialect is on the wire here. The **H3C TLV** dialect is still a stub — see below.

## H3C Portal (TLV dialect) — 🚧 stub

**Wire protocol reference:** `libInodePortalPt.so` in the original client. H3C's Portal extends the GB/T 28181 Portal standard with proprietary TLVs.

**How to implement:**

1. Capture a successful auth from the original client against your Portal server. Expect UDP traffic to port 50100 plus optional HTTP redirects.
2. Decode the extra attribute types beyond the standard 1–7. H3C uses TLV types 0x0A (user-mac), 0x0F (challenge-type), 0x13 (auth-vlan), plus a checksum variant.
3. Extend `PortalProtocol::sendAuth()` to append those attributes when `profile.portalDialect == 1`.
4. Some H3C builds change the shared secret to an iMC-generated string (check `custom/clientfiles/5020/*.icnf` in the original install).

**Scope:** ~1–2 weeks of work with packet captures available.

## SSL VPN (port 7000) — ✅ working (via the bundled `h3csvpn` backend)

**Wire protocol reference:** `libiNodeSslvpnPt.so` (SslVpnXmlParser.cpp, SslvpnMgr.cpp, HttpsAuth.cpp) in the unstripped Linux iNode 7.3 client. The protocol was reverse-engineered first-hand and is **not** the speculative `POST /svpn/login` JSON flow earlier guessed here — it is XML-over-HTTPS ("V7").

**How it's implemented.** Rather than re-deriving the wire format in C++, `SslVpnProtocol` drives a bundled clean-room backend — the pure-Python `h3csvpn` package under `backends/h3csvpn/` — exactly as the 802.1X plugin wraps `minieap` and the L2TP plugin wraps `strongswan`. The backend was reverse-engineered from the binary above and validated end-to-end against a live `SSLVPN-Gateway/7.0`.

Flow (`backends/h3csvpn`; full spec in `docs/PROTOCOL.md` of the h3c-svpn source tree):

1. *(optional SPA knock)* → TLS → `GET /svpn/index.cgi` → **302 → `/client_getinfo.cgi`**; parse the `gatewayinfo` (capability flags `true`/`false`, CGI URLs in a `<url>` block, domain list).
2. *(optional CAPTCHA)* `GET /vldimg.cgi` → BMP; the backend OCR-solves it (`tesseract`) and auto-retries against the server's reply oracle.
3. `POST <login.cgi>` body `request=` + URL-encoded `<data>` login XML (username `user@domain`, password cleartext-in-TLS by default, or RSA/SM2 variants) → challenge/2FA loop (SMS, PROMPTPWD, CHANGEPWD), kick-concurrent-session, optional EAD ack.
4. `NET_EXTEND` on a fresh TLS socket → network-config block → program a TUN device + routes + DNS → raw IP packets in 4-byte frames with a 1 s heartbeat → `GET /svpn/logout.cgi` on teardown. The live `SSLVPN-Gateway/7.0` returns the param block in the **HTTP response headers** (`IPADDRESS`/`SUBNETMASK`/`ROUTES`/`GATEWAY`, with `Content-Length: 0`), and `SUBNETMASK` is a prefix length (e.g. `24` = `/24`); the backend parses both that header form and the older body/frame forms.

**Split tunnel (enterprise).** By default the client routes only the subnets the gateway pushes (`ROUTES`) through the VPN and leaves the host default route + system DNS untouched, so general internet traffic is unaffected. The per-profile *Split tunnel* toggle (CLI `--split-tunnel`) enforces this even if a gateway requests redirect-all. The live test gateway pushes specific corporate subnets (`10.16.0.0/16`, `10.13.0.0/24`, …) and no DNS, so it is naturally split. Verified live end-to-end: with the tunnel up, the host default route and `/etc/resolv.conf` are unchanged, public internet stays reachable directly, and the corporate subnets are reachable through `inode0`.

**Integration plumbing.** Because the tunnel needs `CAP_NET_ADMIN`, the GUI launches the backend through `scripts/inode-svpn-helper` via `pkexec` (polkit action `org.inode.ClientQt.svpn`), or directly if already root. The password is streamed on the helper's **stdin** (never in argv/`ps`); `PYTHONSAFEPATH=1` pins module resolution to the vendored backend. `disconnect()` runs `inode-svpn-helper stop`, which `SIGINT`s the backend for a clean gateway logout + TUN teardown. The Qt layer parses backend output to drive connection state and live stats (interface / IP / DNS).

**Profile mapping.** `serverHost[:serverPort]` (or the SSL VPN *Gateway URL*) → gateway; `username`/`domain` → `-u`/`-d`; trust mode → system CA (default) / `--cafile` (Pinned, from `caCertPath`) / `--insecure` (None); a per-profile **SHA-256 cert pin** (with a one-click *Fetch* button) → `--pin-sha256`, which **overrides** the trust mode — the correct, secure way to trust a self-signed gateway whose cert CN doesn't match the host (so a CA bundle can't validate it); `userCertPath` → mutual-TLS client cert.

**Runtime deps:** `python3` (stdlib only for the core), `tesseract` for CAPTCHA OCR, `pkexec`/polkit for the tunnel. Optional `python3-defusedxml` (hardened XML) and `python3-cryptography` (RSA password variant).

**Limitations (inherited from the backend):** GM/SM2 (CNTLS / SKF UKey) gateways are TLS-layer-only (unsupported); Zero-Trust SDP registration that issues the per-client SPA key is out of scope (only the knock builder exists).

## EAD (port 9019) — 🚧 stub

**Wire protocol reference:** `libInodeSecurityAuth.so`.

**Why this is hard:** EAD is a posture-check protocol. The server expects a signed binary blob describing the endpoint (installed AV, patch level, running services, disk encryption, …). The signing key is baked into the closed collector (`libwacollector.so` in the original client).

**Realistic options:**

- **Dummy-mode:** send a blob that passes a lax server config. Brittle — breaks the moment the server tightens its policy.
- **Proxy-mode:** forward the real client's EAD traffic through your Qt client. Useful for "headless" uses (e.g., a server that needs to pass posture check once and stay connected) but not a real replacement.
- **Server-side:** if you control the iMC/EIA server, disable EAD enforcement for specific users. Often the fastest path.

**Scope:** indefinite. Not pursuing here.

## SDP (port 19006)

SDP is layered on top of the other protocols in H3C's stack (SDP = software-defined perimeter wrapper). Deferred until the base protocols it depends on are solid *and* a real spec surfaces.
