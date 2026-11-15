/* =========================================================================
 * SOC kiosk — auto-login + keep-alive + auto re-login
 * Injected into every panel page by the kiosk host (WebKit via user script,
 * Chromium via CDP addScriptToEvaluateOnNewDocument).
 *
 * Placeholders ({{...}}) are substituted by host/inject.py. This bootstrap
 * NEVER contains credentials — it only detects login state and sets up
 * keep-alive. Credentials are delivered just-in-time:
 *   - WebKit:   page posts window.webkit.messageHandlers.socCreds; host replies
 *               by evaluating socLogin({user,pass}).
 *   - Chromium: host polls window.__SOC.needLogin via CDP and evaluates
 *               socLogin({user,pass}) when true.
 * ========================================================================= */
(function () {
  if (window.__SOC && window.__SOC.installed) return;   // idempotent
  var CFG = {
    id:          "v6",
    mode:        "chromium",            // "webkit" | "chromium"
    userSel:     "#u",
    passSel:     "#p",
    submitSel:   "#s",
    loginMarker: "#p",   // selector present ONLY on the login page
    keepalive:   {"strategy": "none", "intervalSec": 600},   // {strategy,intervalSec,url?,target?}
    // Origin (scheme://host[:non-default-port]) this panel is configured for.
    // socLogin refuses to fill credentials on any other origin, so an open
    // redirect / compromised dashboard can't autofill SOC creds into an
    // attacker page. Empty string = unset = legacy behaviour (no gate).
    allowedOrigin: "http://fd00::1:8080",
    // Click-zone fallback for auto-login. The Calibrate tool stores relative
    // ratios, so a resize keeps the zones accurate. Each of user/pass/submit is
    // optional, as {x_pct, y_pct} with ratios in 0.0..1.0.
    loginZones: {}
  };

  window.__SOC = { installed: true, cfg: CFG, needLogin: false,
                   justLoggedIn: false, lastLogin: 0 };

  // Post a short reason string to the host (WebKit message handler).
  function postMsg(s) {
    if (CFG.mode === "webkit" &&
        window.webkit && window.webkit.messageHandlers &&
        window.webkit.messageHandlers.socCreds) {
      window.webkit.messageHandlers.socCreds.postMessage(s);
    }
  }

  // In-page popup (rendered inside the document, so it shows over the page and
  // the user can still sign in below it — a GTK overlay would be painted over
  // by the native webview). socPrompt(msg) shows it; socPromptClear() removes it.
  window.socPrompt = function (msg) {
    try {
      var el = document.getElementById("__soc_prompt");
      if (!el) {
        el = document.createElement("div");
        el.id = "__soc_prompt";
        el.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
          "background:#1b2b4a;color:#e7ecff;font:bold 14px/1.5 system-ui,sans-serif;" +
          "padding:9px 14px;border-bottom:2px solid #7e96ff;text-align:center;" +
          "box-shadow:0 2px 10px rgba(0,0,0,.5)";
        (document.body || document.documentElement).appendChild(el);
      }
      var text = "🔑 " + msg;
      if (el.textContent !== text) el.textContent = text;
    } catch (e) {}
  };
  window.socPromptClear = function () {
    try { var el = document.getElementById("__soc_prompt"); if (el) el.remove(); }
    catch (e) {}
  };

  // React/Vue-safe value setter (bypasses framework input shadowing).
  function setValue(el, val) {
    try {
      var proto = Object.getPrototypeOf(el);
      var desc = Object.getOwnPropertyDescriptor(proto, "value");
      (desc && desc.set ? desc.set : function (v) { this.value = v; }).call(el, val);
    } catch (e) { el.value = val; }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function onLoginPage() {
    try {
      // 1. Configured marker selector wins (operator-set, panel-specific).
      if (CFG.loginMarker) return !!document.querySelector(CFG.loginMarker);
      // 2. Heuristic: a real password input means it's a login form.
      if (document.querySelector('input[type="password"]')) return true;
      // 3. FALLBACK (text-pattern): the dashboard was redesigned and the selectors
      //    miss, but the page clearly says "Sign in" / "Password" / "Username".
      //    Requires a password-shaped input too, so a help page that merely
      //    mentions passwords doesn't count. That cheap query comes FIRST: this
      //    runs on every DOM mutation, and reading innerText forces a reflow, so
      //    an ordinary logged-in dashboard must never reach it.
      var pw = document.querySelector(
        'input[name*="pass" i], input[id*="pass" i]');
      if (!pw) return false;
      var txt = (document.body && document.body.innerText || "").slice(0, 8192);
      return /\b(sign\s+in|log\s+in|password|user\s*name|email\s+address)\b/i.test(txt);
    } catch (e) { return false; }
  }

  function passField() {
    if (CFG.passSel) {
      var p = document.querySelector(CFG.passSel);
      if (p) return p;
    }
    // Loose fallback: type=password OR a name/id containing "pass" (same heuristic
    // as onLoginPage), then the calibrated click zone.
    var p2 = document.querySelector(
      'input[type="password"], input[name*="pass" i], input[id*="pass" i]');
    if (p2) return p2;
    return zoneInput("pass");
  }

  // Locate an input via the calibrated click zone. Null when no zone is set or the
  // element at that point isn't an <input> (closest() climbs in case the operator
  // clicked a label/wrapper).
  function zoneInput(which) {
    var z = CFG.loginZones && CFG.loginZones[which];
    if (!z || typeof z.x_pct !== "number" || typeof z.y_pct !== "number") return null;
    var el = document.elementFromPoint(z.x_pct * window.innerWidth,
                                       z.y_pct * window.innerHeight);
    if (!el) return null;
    if (el.tagName === "INPUT") return el;
    return el.closest ? el.closest("input") : null;
  }

  function userField(p) {
    if (CFG.userSel) { var u = document.querySelector(CFG.userSel); if (u) return u; }
    // heuristic: a visible text/email/username field, preferably before pass
    var sel = 'input[type="email"],input[type="text"],input[name*="user" i],' +
              'input[name*="email" i],input[id*="user" i],input[id*="email" i]';
    var cands = document.querySelectorAll(sel), best = null;
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i];
      if (c.type === "hidden" || c.offsetParent === null) continue;
      if (p && (c.compareDocumentPosition(p) & Node.DOCUMENT_POSITION_FOLLOWING))
        return c;                                        // sits before the pass field
      if (!best) best = c;
    }
    return best || zoneInput("user");
  }

  // Called by the host with real creds. Returns true if it submitted.
  window.socLogin = function (creds) {
    try {
      // Origin gate: never fill credentials on a page that is not the panel's
      // configured origin (defends against open redirects / compromised
      // dashboards navigating off-site). Unset allowedOrigin = legacy behaviour.
      if (CFG.allowedOrigin && location.origin !== CFG.allowedOrigin) {
        try {
          console.warn("SOC: refusing credential injection — origin " +
                       location.origin + " != allowed " + CFG.allowedOrigin);
        } catch (e) {}
        return false;
      }
      var p = passField();
      if (!p) return false;
      var u = userField(p);
      if (!u) return false;
      setValue(u, creds.user);
      setValue(p, creds.pass);
      creds.pass = "";                                   // scrub ASAP
      window.__SOC.lastLogin = Date.now();
      window.__SOC.needLogin = false;
      var btn = CFG.submitSel ? document.querySelector(CFG.submitSel) : null;
      if (!btn && p.form)
        btn = p.form.querySelector('button[type="submit"],input[type="submit"],button');
      if (!btn) {
        // Calibrated submit zone. elementFromPoint may land on a wrapper.
        var z = CFG.loginZones && CFG.loginZones.submit;
        if (z && typeof z.x_pct === "number" && typeof z.y_pct === "number") {
          var hit = document.elementFromPoint(z.x_pct * window.innerWidth,
                                              z.y_pct * window.innerHeight);
          if (hit) btn = (hit.closest && hit.closest('button,input[type="submit"]')) || hit;
        }
      }
      if (btn) { btn.click(); }
      else if (p.form && p.form.requestSubmit) { p.form.requestSubmit(); }
      else if (p.form) { p.form.submit(); }
      return true;
    } catch (e) { return false; }
  };

  function requestLogin(periodic) {
    // Debounce: don't hammer login within 4s of the last attempt.
    if (Date.now() - window.__SOC.lastLogin < 4000) return;
    window.__SOC.needLogin = true;
    // The prompt means the host has already answered "can't log in". Ask again on
    // the periodic check, not on every mutation: its answer is a page script that
    // can itself mutate the DOM, and that ping-pong pegs both processes.
    if (!periodic && document.getElementById("__soc_prompt")) return;
    postMsg("login");
    // chromium: host polls window.__SOC.needLogin and injects socLogin().
  }

  // ---- keep-alive --------------------------------------------------------
  function startKeepAlive() {
    var ka = CFG.keepalive || {};
    var ms = (ka.intervalSec || 600) * 1000;
    if (ka.strategy === "reload") {
      setInterval(function () { if (!onLoginPage()) location.reload(); }, ms);
    } else if (ka.strategy === "click") {
      setInterval(function () {
        var t = ka.target && document.querySelector(ka.target);
        if (t) t.click();
      }, ms);
    } else if (ka.strategy === "xhr") {
      setInterval(function () {
        try { fetch(ka.url, { credentials: "include", cache: "no-store" }).catch(function () {}); }
        catch (e) {}
      }, ms);
    } else if (ka.strategy === "mouse") {
      // A synthetic in-DOM mousemove with a little jitter. The OS cursor doesn't
      // move: this only resets page-level idle timers (dashboards that log a user
      // out after N minutes of inactivity).
      setInterval(function () {
        try {
          var t = document.body || document.documentElement;
          if (!t) return;
          var x = Math.floor(Math.random() * 8), y = Math.floor(Math.random() * 8);
          t.dispatchEvent(new MouseEvent("mousemove", {
            bubbles: true, cancelable: true, view: window,
            clientX: x, clientY: y, screenX: x, screenY: y
          }));
        } catch (e) {}
      }, ms);
    }
  }

  // ---- login-state watcher ----------------------------------------------
  // Track the page's login state and tell the host on each change. Reporting
  // the non-login ("ok") state — not just an in-place form disappearing — means
  // a login that navigates to a new page still resets the host's attempt
  // counter and records the domain (the new page reports "ok" on load).
  var _state = "";                     // "" | "login" | "ok"
  function check(periodic) {
    var now = onLoginPage() ? "login" : "ok";
    if (now === "login") requestLogin(periodic);
    if (now !== _state) {
      _state = now;
      if (now === "ok") {
        window.__SOC.justLoggedIn = true;
        window.__SOC.needLogin = false;
        postMsg("loggedin");
        window.socPromptClear();
      }
    }
  }

  function boot() {
    check();                                   // initial
    startKeepAlive();
    try {
      // While logged in, once a second is enough: a busy dashboard mutates at
      // frame rate, and this page is not waiting on a login. Anywhere else, at once.
      var moTimer = 0;
      var mo = new MutationObserver(function () {
        if (_state !== "ok") { check(); return; }
        if (!moTimer) {
          moTimer = setTimeout(function () { moTimer = 0; check(); }, 1000);
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {}
    // periodic safety re-check (covers SPA states the observer may miss)
    setInterval(function () { check(true); }, 5000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else { boot(); }
})();
