"""
VPN MANAGER — supervise N independent VPN connections concurrently.

Where host/fortivpn.py owns ONE connection (one Supervisor with its own
classified backoff + reconnect loop), this module fans a `vpns:[]` list out to
one Supervisor per ENABLED entry, each on its own daemon thread, keyed by the
entry's `name`. Each supervisor already brings up its own tunnel, classifies its
own logs, and reconnects on its own backoff — so concurrent, independent
supervision falls out for free; the manager only owns the lifecycle (start all /
stop all) + the routing policy across them.

ROUTING — the hard part, decided deliberately (see docs/CONFIGURATION.md):

  * SPLIT-TUNNEL by default. Each VPN installs ONLY its own declared routes; a
    panel is reached over whichever VPN owns the route to its subnet. The
    backends already have the levers (fortinet --set-routes=0 /
    --half-internet-routes, openvpn --route-nopull, wireguard's AllowedIPs), so
    the manager forces them OFF for every non-owner so two VPNs can NEVER both
    silently grab 0.0.0.0/0.

  * AT-MOST-ONE default-route owner. _validate_vpns already rejects >1
    `default_route:true` at config time; the manager re-asserts it at runtime
    (defensive: a hand-built list, an override, a future caller) and is the
    component that actually COERCES the non-owners split-tunnel.

  * WireGuard is the sharp edge: wg-quick installs whatever the materialized
    .conf declares and the manager cannot cleanly rewrite a vault-sourced .conf.
    For a non-owner wg entry it forces `set_routes:false` where it can, logs a
    loud WARNING that a non-owner wg .conf MUST scope its AllowedIPs (never
    0.0.0.0/0 or ::/0), and documents that the operator owns that .conf.

The manager runs IN-PROCESS (threads) rather than spawning a templated
soc-vpn@.service stack: it matches the host's GLib.idle_add discipline + the
verify-vpn threaded harness, keeps one journald stream (forti-vpn.service) tagged
per name, and keeps sudoers/install simple. The tradeoff (one unit = shared
blast radius) is documented in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import copy
import ipaddress
import os
import signal
import threading
import time
import traceback
from typing import Callable, Optional

from . import config as cfg
from . import fortivpn
from . import vpndrivers
from . import vpnstatus


def _name_of(entry: dict, idx: int) -> str:
    """The identity key. _normalize_vpns fills this for every parsed entry; the
    fallback only covers a hand-built list that skipped normalization."""
    nm = str((entry or {}).get("name", "") or "").strip()
    return nm or ("vpn" if idx == 0 else f"vpn{idx + 1}")


def _is_enabled(entry: dict) -> bool:
    return bool(isinstance(entry, dict) and entry.get("enabled"))


def coerce_split_tunnel(entry: dict, *, is_owner: bool, log: Callable[[str], None]):
    """Force a NON-owner VPN to split-tunnel so it cannot grab the default route.

    Mutates a COPY (callers pass the manager's private per-entry dict). The owner
    (or a single/legacy VPN with no list semantics) is left untouched — it may
    honour its own set_routes / full-tunnel config.

    Levers, per backend (all already understood by config.openfortivpn_args /
    openvpn_args, and by wg-quick):
      * fortinet : set_routes=False + half_internet_routes=False -> the gateway
                   cannot push a default route onto us.
      * openvpn  : set_routes=False -> emits --route-nopull (ignore pushed routes).
      * inode    : split_tunnel=True -> --split-tunnel, so a gateway requesting
                   redirect-all cannot capture the default route.
      * wireguard: we cannot rewrite a vault .conf; force set_routes=False where
                   the materialize path honours it AND warn loudly so the operator
                   scopes AllowedIPs. The wg 0.0.0.0/0 guard runs at materialize.
    """
    if is_owner or not isinstance(entry, dict):
        return entry
    entry["_soc_non_owner"] = True      # re-checked after any vault Notes overlay
    kind = cfg.vpn_kind(entry)
    name = entry.get("name") or "?"
    if kind == "fortinet":
        if entry.get("set_routes") or entry.get("half_internet_routes"):
            log(f"[vpn:{name}] not the default-route owner — forcing split-tunnel "
                f"(--set-routes=0)")
        entry["set_routes"] = False
        entry["half_internet_routes"] = False
    elif kind == "openvpn":
        if entry.get("set_routes") is not False:
            log(f"[vpn:{name}] not the default-route owner — forcing split-tunnel "
                f"(--route-nopull)")
        entry["set_routes"] = False
    elif kind == "wireguard":
        # We can't rewrite the .conf; flag it and let the materialize-time guard
        # strip a 0.0.0.0/0 AllowedIPs if one slips through.
        entry["_soc_split_tunnel"] = True
        log(f"[vpn:{name}] WireGuard and NOT the default-route owner: its .conf "
            f"MUST scope AllowedIPs (never 0.0.0.0/0 or ::/0). The wall cannot "
            f"rewrite a vault-sourced .conf — a catch-all here would hijack the "
            f"default route from the owner.")
    elif kind == "inode":
        if entry.get("split_tunnel") is False:
            log(f"[vpn:{name}] not the default-route owner — forcing split-tunnel "
                f"(--split-tunnel)")
        entry["split_tunnel"] = True
    return entry


def _is_catch_all(cidr: str) -> bool:
    """True for any /0, however it is spelled: wg-quick reads '::0/0', '0::/0' and
    '10.0.0.1/0' as the whole address space too, not just the two canonical forms."""
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    except ValueError:
        return False


class _GuardedSupervisor(fortivpn.Supervisor):
    """A Supervisor that, for a non-owner WireGuard entry, refuses to install a
    0.0.0.0/0 (or ::/0) AllowedIPs from a materialized .conf — the one routing
    hazard the config layer cannot pre-empt (wg-quick obeys the .conf verbatim).

    Everything else is the stock Supervisor: same backoff, same auth/cert holds,
    same reconnect loop. We only hook _materialize_config, to scrub a catch-all
    AllowedIPs out of the on-disk .conf BEFORE wg-quick reads it and to re-assert
    the split-tunnel coercion, which a Fortinet vault Notes overlay (set_routes,
    half_internet_routes) would otherwise undo after _prepare ran."""

    def _materialize_config(self) -> bool:
        ok = super()._materialize_config()
        if not ok:
            return ok
        if self.vpn.get("_soc_non_owner") and self.driver.kind == "fortinet":
            coerce_split_tunnel(self.vpn, is_owner=False, log=self.log)
        if not self.vpn.get("_soc_split_tunnel"):
            return ok
        if self.driver.kind != "wireguard":
            return ok
        path = self._materialized
        if not path:
            return ok
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as e:
            # Fail closed: "could not check" must not bring up an unchecked .conf.
            self.log(f"[vpn:{self.vpn.get('name')}] could not read .conf to check "
                     f"for a catch-all route: {e}")
            return False
        changed = False
        out = []
        for line in lines:
            stripped = line.strip()
            if stripped.lower().startswith("allowedips"):
                _, _, rhs = stripped.partition("=")
                cidrs = [c.strip() for c in rhs.split(",") if c.strip()]
                kept = [c for c in cidrs if not _is_catch_all(c)]
                if len(kept) != len(cidrs):
                    changed = True
                    name = self.vpn.get("name") or "?"
                    self.log(f"[vpn:{name}] REFUSED a catch-all AllowedIPs "
                             f"(0.0.0.0/0 or ::/0) in a non-owner WireGuard .conf "
                             f"— stripping it so it cannot hijack the default "
                             f"route. Scope AllowedIPs to the panel subnets.")
                    if kept:
                        out.append(f"AllowedIPs = {', '.join(kept)}\n")
                    # if nothing is left, drop the line entirely (no routes)
                    continue
            out.append(line)
        if changed:
            # Atomic rewrite: stage to a tmp in the SAME dir, fsync, then
            # os.replace — never open(path,'w') which truncates first, leaving a
            # torn/empty .conf if the process is killed mid-write (then wg-quick
            # would load a corrupt or under-scoped config). On any write error,
            # unlink the tmp and return False so the supervisor idles this entry
            # rather than bringing up an unstripped catch-all tunnel — the
            # security intent (no default-route hijack) fails closed.
            tmp = path + ".tmp"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.writelines(out)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except OSError as e:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                self.log(f"[vpn:{self.vpn.get('name')}] could not rewrite .conf "
                         f"to strip catch-all route: {e} — refusing to bring up an "
                         f"unstripped catch-all tunnel")
                return False
        return ok


class VpnManager:
    """Owns one Supervisor (its own thread) per ENABLED vpns[] entry.

    Lifecycle:
      * start()  — spawn every enabled entry's supervisor; staggered slightly so
                   N vault unseals don't thunder on a 1 GB Pi.
      * stop()   — signal every supervisor to stop, terminate children, join.
      * states() — {name: vpnstatus.vpn_state(entry)} for the per-name pill.
      * state_aggregate() — one overall state for the pill's main label.
      * stalled() — names not making progress; gates the systemd watchdog.

    Disabled / malformed entries are skipped (they were reported by validation).
    `only` restricts the supervisors to one entry (a forti-vpn@<name> instance);
    the routing policy is still decided across the whole list, so that instance
    does not mistake itself for the single VPN that owns the default route.
    """

    # small gap between supervisor starts so N concurrent vault unseals
    # (scrypt + HTTPS sync) don't spike RAM/CPU at boot on the 1 GB board.
    _START_STAGGER = 0.4

    def __init__(self, vpns: list, pinentry: str,
                 log: Optional[Callable[[str], None]] = None, only: str = ""):
        self._log = log or (lambda m: print(f"[soc-vpn] {m}", flush=True))
        self.pinentry = pinentry
        self._only = (only or "").strip()
        # Longer than any legitimate gap between heartbeats. The worst is a vault
        # open through the rbw CLI (about 210s of 30s subprocess calls); a false
        # positive restarts every tunnel, so err long. Every other step beats.
        self._stall_after = cfg.env_float("SOC_VPN_STALL_SECS", 300.0, lo=60.0, hi=3600.0)
        # Deep-copy each entry so the manager's split-tunnel coercion + the
        # supervisor's in-place config materialization never mutate the caller's
        # conf.vpns (the GTK side reads it for the pill).
        self._entries: list = []
        self._supers: dict = {}        # name -> Supervisor
        self._threads: dict = {}       # name -> Thread
        self._lock = threading.Lock()
        self._started = False
        self._prepare(vpns)

    # ---- preparation: routing policy across the whole list ------------------
    def _prepare(self, vpns: list):
        enabled = [(i, e) for i, e in enumerate(vpns or [])
                   if _is_enabled(e)]
        owners = [_name_of(e, i) for i, e in enabled if e.get("default_route")]
        if len(owners) > 1:
            # Defensive: validation should have rejected this. Refuse to grant
            # ANY of them the default route rather than let two fight over it.
            self._log(f"ERROR multiple VPNs claim default_route ({', '.join(owners)}) "
                      f"— refusing all of them the default route; every VPN runs "
                      f"split-tunnel until exactly one owns it")
            owner_name = None
        elif owners:
            owner_name = owners[0]
        elif len(enabled) == 1:
            # Exactly one VPN: there is nothing to fight over, so it implicitly
            # owns the default route and keeps its own set_routes / full-tunnel
            # config. This makes the legacy single-VPN case byte-for-byte
            # identical to the old single-Supervisor behaviour (a full-tunnel
            # Fortinet/OpenVPN must NOT be silently coerced split-tunnel).
            owner_name = _name_of(enabled[0][1], enabled[0][0])
        else:
            owner_name = None
        # Only narrate routing for a genuine MULTI-VPN list — a single VPN owns
        # its route implicitly and its journal must stay as quiet as before.
        if owner_name and len(enabled) > 1:
            self._log(f"routing: '{owner_name}' owns the default route "
                      f"(full-tunnel); all other VPNs are split-tunnel")
        elif len(enabled) > 1:
            self._log("routing: split-tunnel — no default-route owner; each VPN "
                      "installs only its own routes (mark one default_route:true "
                      "for catch-all traffic)")

        for i, e in enabled:
            entry = copy.deepcopy(e)
            name = _name_of(entry, i)
            entry["name"] = name
            if self._only and name != self._only:
                continue
            is_owner = (name == owner_name)
            coerce_split_tunnel(entry, is_owner=is_owner, log=self._log)
            self._entries.append((name, entry, is_owner))

    # ---- lifecycle ----------------------------------------------------------
    def start(self):
        """Spawn one supervisor thread per enabled entry. Idempotent."""
        with self._lock:
            if self._started:
                return
            self._started = True
            entries = list(self._entries)
        if not entries:
            self._log("no enabled VPNs to start")
            return
        for name, entry, _owner in entries:
            self._spawn_one(name, entry)
            time.sleep(self._START_STAGGER)

    # Supervisor.run() cleans up and propagates an unexpected failure, so this is
    # where a supervisor thread is kept alive. The growing delay stops a
    # deterministically-crashing entry from hot-looping on the 1 GB Pi. There is
    # deliberately no cap: this wall runs unattended, so giving up would mean
    # offline until someone restarts it. _RELAUNCH_MAX only marks when to shout.
    # A run that lasted _RELAUNCH_STABLE was healthy, so its crash starts afresh.
    _RELAUNCH_MAX = 3
    _RELAUNCH_DELAY = 5.0
    _RELAUNCH_DELAY_MAX = 60.0
    _RELAUNCH_STABLE = 600.0

    def _spawn_one(self, name: str, entry: dict):
        def tagged(msg, _n=name):
            # Prefix every supervisor/driver line so journald is attributable
            # per VPN; the log viewer filters on this [vpn:<name>] tag.
            if str(msg).startswith(f"[vpn:{_n}]"):
                self._log(msg)
            else:
                self._log(f"[vpn:{_n}] {msg}")
        driver = vpndrivers.get_driver(entry)
        sup = _GuardedSupervisor(entry, self.pinentry, log=tagged, driver=driver)
        sup.watchdog.notify = False     # beats only; see fortivpn._supervise
        t = threading.Thread(target=self._supervised_run, args=(name, sup, tagged),
                             name=f"vpn:{name}", daemon=True)
        with self._lock:
            self._supers[name] = sup
            self._threads[name] = t
        t.start()

    def _supervised_run(self, name: str, sup, tagged: Callable[[str], None]):
        """Run sup.run(), relaunching it after any UNEXPECTED exception with a
        bounded backoff, for as long as the manager runs. Never resurrects a VPN
        whose stop was requested, and every catch logs loudly (no silent swallow).
        One entry's crash loop stays in-process so its siblings keep their tunnels."""
        delay = self._RELAUNCH_DELAY
        crashes = 0
        while not sup.stop_event.is_set():
            started = time.monotonic()
            try:
                sup.run()
                return                                 # clean stop — done
            except Exception as e:                     # noqa: BLE001
                tagged(f"supervisor crashed: {e!r}; {traceback.format_exc()}")
            if sup.stop_event.is_set():
                return
            if time.monotonic() - started >= self._RELAUNCH_STABLE:
                delay, crashes = self._RELAUNCH_DELAY, 0
            crashes += 1
            if crashes == self._RELAUNCH_MAX:
                tagged(f"supervisor has crashed {crashes} times running — this VPN "
                       f"is down and will keep retrying every "
                       f"{self._RELAUNCH_DELAY_MAX:.0f}s at most (see the journal "
                       f"above for the cause)")
            tagged(f"relaunching supervisor in {delay:.0f}s (crash {crashes})")
            sup._sleep(delay)                  # stop() ends this immediately
            delay = min(delay * 2.0, self._RELAUNCH_DELAY_MAX)

    def stop(self, grace: float = 20.0):
        """Tear EVERY supervisor down: signal stop, terminate the child, join.
        The default grace leaves room inside systemd's TimeoutStopSec=30 for a
        wedged supervisor's forced cleanup below; past that, systemd SIGKILLs us
        and the keys wait for the next start's orphan sweep."""
        with self._lock:
            supers = dict(self._supers)
            threads = dict(self._threads)
        for name, sup in supers.items():
            sup.stop_event.set()
            child = sup.child
            if child is not None and child.poll() is None:
                # Not _terminate_child: that blocks per child, so one slow client
                # would delay the SIGTERM to every other. Each thread does the
                # waiting and escalation for its own.
                sup._signal_group(child, signal.SIGTERM)
        deadline = time.monotonic() + grace
        for name, t in threads.items():
            t.join(timeout=max(0.0, deadline - time.monotonic()))
        for name, t in threads.items():
            if not t.is_alive():
                continue
            self._log(f"WARNING vpn '{name}' supervisor did not stop within the "
                      f"grace period; cleaning up for it")
            # It is a daemon thread: the process exit would kill it before its own
            # teardown ran, leaving the key on disk and the child orphaned.
            sup = supers[name]
            for step in (sup._cleanup_materialized, sup._cleanup_mgmt,
                         lambda s=sup: s._terminate_child(grace=2.0)):
                try:
                    step()
                except Exception as e:                 # noqa: BLE001
                    self._log(f"ERROR vpn '{name}' forced cleanup failed: {e!r}")
        with self._lock:
            self._supers.clear()
            self._threads.clear()
            self._started = False

    # ---- introspection ------------------------------------------------------
    @property
    def names(self) -> list:
        """The enabled entry names, in config order."""
        return [name for name, _e, _o in self._entries]

    @property
    def count(self) -> int:
        return len(self._entries)

    # A short per-probe timeout for the status path. The supervise loop calls
    # states() under the systemd watchdog; a black-holed ready_probe would
    # otherwise block ~2s each and, across many VPNs, a single batch could exceed
    # WatchdogSec and self-kill the unit. A live tunnel's probe connects far
    # inside this, so green/offline classification is unchanged (matches
    # health.py's PROBE_TIMEOUT idiom).
    _PROBE_TIMEOUT = 0.5

    def states(self, on_each: Optional[Callable[[], None]] = None) -> dict:
        """Per-name {name: state}. Each state is computed from the entry the
        manager actually started (post-coercion), so e.g. ready_probe is the
        live one. Safe to call from any thread — it only does TCP/sysfs reads.

        `on_each`, when given, is invoked between per-VPN probes so the caller
        can pet the systemd watchdog inside the loop — no batch size can starve
        the heartbeat regardless of how many probes stall."""
        out = {}
        for name, entry, _owner in self._entries:
            try:
                out[name] = vpnstatus.vpn_state(entry, timeout=self._PROBE_TIMEOUT)
            except Exception:                          # noqa: BLE001
                out[name] = vpnstatus.STATE_OFFLINE
            if on_each is not None:
                try:
                    on_each()
                except Exception:                      # noqa: BLE001
                    pass
        return out

    def stalled(self) -> list:
        """Names of supervisors the unit must be restarted to recover: thread died,
        or it has not beaten within SOC_VPN_STALL_SECS. A thread cannot be killed
        from inside the process, so all the caller can do is withhold the systemd
        watchdog. A stopping supervisor is not stalled."""
        now = time.monotonic()
        with self._lock:
            running = [(n, s, self._threads.get(n)) for n, s in self._supers.items()]
        out = []
        for name, sup, t in running:
            if sup.stop_event.is_set() or t is None or t.ident is None:
                continue
            if not t.is_alive() or now - sup.watchdog.beat > self._stall_after:
                out.append(name)
        return out

    def state_aggregate(self) -> str:
        """Collapse per-name states to ONE for the pill's main label:
          * no enabled entries -> not_configured
          * every enabled entry online -> online
          * otherwise -> offline (at least one is down/flapping)."""
        return aggregate_state(self.states())


def aggregate_state(states: dict) -> str:
    """Pure: collapse a {name: state} dict to a single overall state.

    Kept standalone so main.py can aggregate states it computed itself (it polls
    conf.vpns directly off the GTK thread — it does not hold a manager).

    STATE_CONNECTING counts as not online: the per-name breakdown shows it, but
    the pill's CSS classes have no amber state to give the aggregate."""
    vals = [s for s in (states or {}).values()
            if s != vpnstatus.STATE_NOT_CONFIGURED]
    if not vals:
        return vpnstatus.STATE_NOT_CONFIGURED
    if all(s == vpnstatus.STATE_ONLINE for s in vals):
        return vpnstatus.STATE_ONLINE
    return vpnstatus.STATE_OFFLINE
