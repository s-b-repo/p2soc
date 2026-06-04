# Configuration

Everything about the wall lives in **`config/panels.yaml`** (deployed to
`/etc/soc-display/panels.yaml`). The kiosk host reads it to decide what to render,
where, how to log in, and how to keep the session alive.

## `display`

```yaml
display:
  auto: true        # detect resolution from xrandr at launch
  width: 1920       # used when auto: false (or as a fallback)
  height: 1080
  cols: 2           # grid columns
  rows: 2           # grid rows
  gap: 0            # px between cells (0 = seamless)
```

Cell geometry is computed as `(width - gap*(cols-1)) / cols` × `(height - gap*(rows-1)) / rows`.

## `panels[]`

```yaml
panels:
  - id: p1                      # short id; window class = soc-p1
    engine: webkit              # webkit (light, default) | chromium (per-panel fallback)
    grid: [0, 0]                # [col, row]; [0,0]=top-left, [1,1]=bottom-right
    mode: direct                # direct | tunnel
    url: "http://10.0.0.5:3000/login"
    vault_item: "SOC Panel 1"   # Vaultwarden login item name (exact match)
    selectors:
      user:   "#username"       # CSS selector for the username field
      pass:   "#password"       # CSS selector for the password field
      submit: "button[type=submit]"   # selector for the submit button (optional)
    login_marker: "#password"   # selector present ONLY on the login page
    keepalive:
      strategy: reload          # reload | click | xhr | none
      intervalSec: 600
```

### Tunneled panels

For a panel reachable only through the SSH jump host, use `mode: tunnel`:

```yaml
  - id: p3
    engine: chromium
    grid: [0, 1]
    mode: tunnel
    tunnel:
      local_port: 19103         # autossh -L 127.0.0.1:19103:remote_host:remote_port
      remote_host: 10.20.0.7
      remote_port: 8443
    path: "/login"              # path on the local side of the tunnel
    scheme: "http"              # http | https (local side)
    vault_item: "SOC Panel 3"
    selectors: { user: "#user", pass: "#pw", submit: "#submit" }
    login_marker: "#pw"
    keepalive: { strategy: reload, intervalSec: 900 }
```

The host builds `effective_url = http://127.0.0.1:19103/login` and waits for that
port before opening the window.

## `tunnel`

```yaml
tunnel:
  enabled: true
  jump_host: "tunneluser@jump.example.net"
  identity: "/etc/soc-display/keys/tunnel_ed25519"
  extra_forwards: []            # optional extra "127.0.0.1:lport:rhost:rport" strings
```

`-L` forwards are derived automatically from every `mode: tunnel` panel.

## Finding selectors

1. Open the panel's login page in a desktop browser.
2. Right-click the username field → **Inspect**.
3. Pick a stable CSS selector — prefer `#id`, then `input[name="…"]`, then a class.
4. Do the same for the password field and the submit button.
5. Set `login_marker` to something that exists **only** on the login page (the
   password field is usually perfect). It's how the host detects "logged out" and
   re-logs-in.

Selectors are JSON-escaped before injection, so quotes are safe:
`input[name="user"]` works verbatim.

## Keep-alive strategies

| `strategy` | Behaviour | Use when |
|---|---|---|
| `reload` | periodically reloads the page (skipped while on the login page) | most dashboards |
| `xhr` | periodically `fetch`es `keepalive.url` with credentials | the app has a lightweight ping/heartbeat endpoint |
| `click` | periodically clicks `keepalive.target` | activity-based idle timers |
| `none` | nothing | the app never times out, or you rely on auto re-login only |

The real anti-timeout safety net is the `MutationObserver` that detects the login
form reappearing and re-logs-in — the timer just reduces how often that happens.

## Performance on 1 GB

- Prefer `engine: webkit`; use `engine: chromium` only for a panel WebKit can't render.
- For Grafana/Kibana-style panels, add kiosk/refresh params to the URL, e.g.
  `…/d/abc?kiosk&refresh=30s`, to cut live-update CPU/RAM.
- Increase `SOC_LAUNCH_STAGGER` (in `soc.env`) to spread the boot RAM spike.
