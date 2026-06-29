#!/usr/bin/env python3
"""
Dummy SOC panels for local development.

Spins up 4 tiny login-protected web apps on 127.0.0.1:9001-9004, each mimicking
a real panel so the kiosk host can be tested end-to-end on an x86 workstation
without touching the Pi or any real infrastructure.

Per-panel behaviour:
  9001  p1  plain dashboard, HARD session expiry every 60s  -> exercises auto re-login
  9002  p2  plain dashboard, exposes /api/ping               -> exercises xhr keepalive
  9003  p3  plain dashboard                                  -> rendered via Chromium (CDP)
  9004  p4  LIVE-CHART dashboard (canvas + setInterval)      -> exercises RAM behaviour

All sessions are sliding by default (any request resets the TTL), except p1
which uses a hard wall-clock expiry to force the login form to reappear.

Run:  python3 dev/dummy-panels/server.py
Stop: Ctrl-C
"""
import json
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from wsgiref.simple_server import WSGIServer, make_server, WSGIRequestHandler

HOST = "127.0.0.1"


@dataclass
class Panel:
    port: int
    name: str
    user: str
    password: str
    chart: bool = False
    hard_ttl: float = 0.0          # >0 => hard expiry; 0 => sliding only
    sliding_ttl: float = 300.0
    # session_token -> (created_at, last_seen)
    sessions: dict = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def new_session(self) -> str:
        tok = f"{self.port}-{time.time_ns()}"
        now = time.time()
        with self.lock:
            self.sessions[tok] = [now, now]
        return tok

    def valid(self, tok: str) -> bool:
        now = time.time()
        with self.lock:
            rec = self.sessions.get(tok)
            if not rec:
                return False
            created, last = rec
            if self.hard_ttl and (now - created) > self.hard_ttl:
                del self.sessions[tok]
                return False
            if (now - last) > self.sliding_ttl:
                del self.sessions[tok]
                return False
            rec[1] = now           # slide
            return True


PANELS = [
    Panel(9001, "Panel 1 — Alerts",  "viewer1", "devpass1", hard_ttl=60),
    Panel(9002, "Panel 2 — Traffic", "viewer2", "devpass2"),
    Panel(9003, "Panel 3 — Firewall", "viewer3", "devpass3"),
    Panel(9004, "Panel 4 — Metrics", "viewer4", "devpass4", chart=True),
]

# ---------------------------------------------------------------------------- #
# HTML
# ---------------------------------------------------------------------------- #
LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>{name} — Login</title><style>
 body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e6e9f0;
   display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
 form{{background:#161c33;padding:32px;border-radius:12px;width:280px;
   box-shadow:0 8px 30px rgba(0,0,0,.4)}}
 h2{{margin:0 0 18px;font-weight:600}} label{{font-size:13px;opacity:.8}}
 input{{width:100%;box-sizing:border-box;margin:6px 0 14px;padding:10px;
   border:1px solid #2a3354;border-radius:8px;background:#0d1226;color:#fff}}
 button{{width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;
   color:#fff;font-weight:600;cursor:pointer}}
 .err{{color:#f87171;font-size:13px;margin-bottom:10px}}
</style></head><body>
 <form method=post action="/login">
   <h2>{name}</h2>
   {err}
   <label>Username</label>
   <input id=username name=username autocomplete=username autofocus>
   <label>Password</label>
   <input id=password name=password type=password autocomplete=current-password>
   <button type=submit>Sign in</button>
 </form></body></html>"""

DASH_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>{name}</title><style>
 body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e6e9f0;margin:0}}
 header{{padding:14px 20px;background:#161c33;font-weight:600;
   display:flex;justify-content:space-between;align-items:center}}
 .ok{{color:#34d399}} main{{padding:24px}} canvas{{background:#0d1226;border-radius:10px}}
 .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}}
 .card{{background:#161c33;padding:16px;border-radius:10px}}
 .big{{font-size:28px;font-weight:700}}
</style></head><body>
 <header><span>{name}</span><span class=ok>● authenticated as {user}</span></header>
 <main>
   <div class=grid>
     <div class=card><div>Events/min</div><div class=big id=m1>0</div></div>
     <div class=card><div>Sessions</div><div class=big id=m2>0</div></div>
     <div class=card><div>Health</div><div class=big style="color:#34d399">OK</div></div>
   </div>
   {chart}
 </main>
 <script>
   // light periodic metric churn (all panels) — also doubles as a keepalive nudge
   setInterval(()=>{{document.getElementById('m1').textContent=Math.floor(Math.random()*900);
     document.getElementById('m2').textContent=Math.floor(Math.random()*4000);}},2000);
   {chartjs}
 </script>
</body></html>"""

CHART_BLOCK = '<canvas id=c width=900 height=320></canvas>'
CHART_JS = """
 const cv=document.getElementById('c'),cx=cv.getContext('2d');let t=0,data=[];
 function frame(){t++;data.push(50+45*Math.sin(t/8)+Math.random()*20);
   if(data.length>180)data.shift();
   cx.clearRect(0,0,cv.width,cv.height);cx.strokeStyle='#3b82f6';cx.lineWidth=2;cx.beginPath();
   data.forEach((v,i)=>{const x=i*(cv.width/180),y=cv.height-v*2;i?cx.lineTo(x,y):cx.moveTo(x,y);});
   cx.stroke();}
 setInterval(frame,250);   // live-updating chart -> exercises CPU/RAM
"""


def respond(start, status, body, headers=None):
    hdrs = [("Content-Type", "text/html; charset=utf-8")]
    if headers:
        hdrs += headers
    start(status, hdrs)
    return [body.encode("utf-8")]


def parse_cookies(environ):
    c = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    return {k: m.value for k, m in c.items()}


def read_form(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size).decode("utf-8") if size else ""
    out = {}
    for pair in raw.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[_unq(k)] = _unq(v)
    return out


def _unq(s):
    from urllib.parse import unquote_plus
    return unquote_plus(s)


def make_app(panel: Panel):
    def app(environ, start):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        cookies = parse_cookies(environ)
        tok = cookies.get("soc_session", "")

        # keepalive ping endpoint (xhr strategy)
        if path == "/api/ping":
            alive = panel.valid(tok)
            start("200 OK", [("Content-Type", "application/json"),
                             ("Access-Control-Allow-Origin", "*")])
            return [json.dumps({"alive": alive, "ts": int(time.time())}).encode()]

        if path == "/logout":
            with panel.lock:
                panel.sessions.pop(tok, None)
            return respond(start, "302 Found", "", [("Location", "/login"),
                           ("Set-Cookie", "soc_session=; Max-Age=0; Path=/")])

        if method == "POST" and path == "/login":
            form = read_form(environ)
            if form.get("username") == panel.user and form.get("password") == panel.password:
                newtok = panel.new_session()
                return respond(start, "302 Found", "", [
                    ("Location", "/"),
                    ("Set-Cookie", f"soc_session={newtok}; Path=/; HttpOnly")])
            return respond(start, "200 OK", LOGIN_HTML.format(
                name=panel.name, err='<div class=err>Invalid credentials</div>'))

        # protected area
        if panel.valid(tok):
            chart = CHART_BLOCK if panel.chart else ""
            chartjs = CHART_JS if panel.chart else ""
            return respond(start, "200 OK", DASH_HTML.format(
                name=panel.name, user=panel.user, chart=chart, chartjs=chartjs))

        # not authed -> show login
        return respond(start, "200 OK", LOGIN_HTML.format(name=panel.name, err=""))

    return app


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *a):
        pass  # keep dev output clean


def serve(panel: Panel):
    httpd = make_server(HOST, panel.port, make_app(panel),
                        server_class=WSGIServer, handler_class=QuietHandler)
    print(f"  dummy {panel.name:24s} http://{HOST}:{panel.port}  "
          f"(user={panel.user} pass={panel.password}"
          f"{' chart' if panel.chart else ''}"
          f"{' hard-expiry=%ds' % panel.hard_ttl if panel.hard_ttl else ''})")
    httpd.serve_forever()


def main():
    print("Starting dummy SOC panels (Ctrl-C to stop):")
    threads = []
    for p in PANELS:
        t = threading.Thread(target=serve, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
