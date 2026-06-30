# SOC Video Wall — Quick Start

Single-page guide covering install, launch, theme, panels, and shortcuts.

## Install

### Local (no root, current folder)

```bash
cd /path/to/p2soc
make install-local
```

This creates the venv, generates desktop entries with correct paths, and installs
PATH symlinks under `~/.local/bin/`.  The "SOC Video Wall" icon appears in your
application menu immediately.  **No root needed.**

To remove:

```bash
make uninstall-local
```

### System (Raspberry Pi, needs root)

```bash
sudo ./install.sh                      # desktop mode (keeps your DE)
sudo ./install.sh INSTALL_MODE=kiosk   # dedicated appliance (tty1 autologin)
```

After install the control center auto-launches in desktop mode.

## Launch

| What | How |
|------|-----|
| Control center | Desktop icon "SOC Video Wall", or `soc-wall-menu` |
| Wall (desktop) | Control center → **Desktop mode** |
| Wall (kiosk)   | Control center → **Kiosk mode** (fullscreen) |
| Setup wizard   | Control center → **Setup / Configure** |
| Appearance     | Control center → **Appearance** |

The control center is the hub — everything starts from there.

## Theme / Appearance

The wall, control center, and setup wizard share one theme.  Change it once:

1. Open the control center → **Appearance**
2. Pick a preset or tune individual colours — see a **live preview**
3. Click **Save** — the control center repaints immediately
4. The **running wall repaints within 5 seconds** (no restart)

Or change it from the setup wizard: **Setup → Appearance → Save**.

The theme file lives at `~/.config/soc-display/branding.yaml`.  Delete it to
reset to the default green-on-white console theme.

### How it works

- `branding.py` saves colours to `~/.config/soc-display/branding.yaml` and
  touches a marker file at `~/.cache/soc-display/branding-changed`
- The wall polls the marker every 5 seconds (`_check_branding` in `main.py`)
- On change, `style.apply_css()` rebuilds all CSS from the new palette and
  reloads the GTK provider — every window repaints live

## Panels (on-screen settings)

Open the wall's on-screen settings: click the ⚙ gear in the corner, or press
**Ctrl+Shift+C**.

### Edit a panel

1. **Panels** tab — change URL, title, vault login name, or engine (WebKit/Chromium)
2. Click **Apply** — URL and title changes take effect **immediately** (no restart)

### Add a panel

1. **Panels** tab → click **＋ Add Panel**
2. Fill in the URL, title, vault item, and engine
3. Click **Apply** — the new panel appears in the grid **live**

The panel gets an auto-computed grid position (fills columns first).  Engine
selectors and login markers apply on the next wall restart.

### Remove a panel

1. **Panels** tab → click **✕ Remove** on the panel you want gone
2. Click **Apply** — the panel is destroyed and removed from the grid **live**

The Remove button is hidden when only one panel remains (wall needs at least one).

### Other tabs

| Tab | What it does |
|-----|-------------|
| Credentials | Store usernames/passwords directly in Vaultwarden |
| Display | Change grid layout and gap (gap applies live; layout on restart) |
| VPN | Configure Fortinet/OpenVPN/WireGuard/iNode connection. ➕ Add VPN / ➖ Remove Last for parallel tunnels. Each VPN has its own vault_item for credentials. |
| Status | Connection state, memory usage, panel health |

If a **PIN is set** (Setup → Security), the settings window prompts for it before
showing any tabs.

### Lock the wall

Click 🔒 **Lock** in the wall toolbar (or Ctrl+Alt+L). A popup window
appears — enter your PIN to unlock. 3 wrong attempts = escalating cooldown
(5s, 10s, 15s…). Set the PIN in ⚙ Settings → Security.

## Desktop shortcuts

The `.desktop` files use **absolute paths generated at install time** — they
always work regardless of where the repo is cloned.

```
~/.local/share/applications/soc-wall.desktop       → control center
~/.local/share/applications/soc-wall-setup.desktop  → setup wizard (hidden)
~/.local/share/applications/soc-wall-appearance.desktop → appearance (hidden)
~/.local/bin/soc-wall-menu                          → symlink to scripts/
```

Regenerate after moving the repo:

```bash
make install-local
```

## CLI shortcuts

```bash
soc-wall-menu              # control center
make dev                   # wall in Xephyr window (dev)
make verify                # headless end-to-end check
make test                  # unit tests
python3 setup.py wizard    # text-mode setup wizard
python3 setup.py deploy    # headless full deploy
```

## Troubleshooting

**Wall doesn't pick up theme changes:**
Restart the wall once after updating code (`Ctrl+C`, then launch again).
After that, theme changes apply live within 5 seconds.

**"pkexec must be setuid root":**
```bash
sudo chmod u+s /usr/bin/pkexec
```
Or the control center falls back to a terminal with `sudo`.

**Desktop icon doesn't appear:**
```bash
make install-local    # regenerates entries and refreshes the desktop DB
```

**Config window shows no Add/Remove buttons:**
Restart the wall — the running process has old code.  `Ctrl+C` then relaunch.

**Wall won't start (no display):**
Run `make dev` (Xephyr window) or `make verify` (headless check) for
development without a dedicated display.
