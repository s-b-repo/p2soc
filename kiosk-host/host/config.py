"""
Configuration loading for the SOC kiosk host.

Reads config/panels.yaml (path from $SOC_PANELS_FILE), normalises each panel,
derives the effective URL (direct vs. tunnel) and the on-screen geometry of each
2x2 cell. Pure data — no GTK / no I/O beyond reading the YAML.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class KeepAlive:
    strategy: str = "none"          # reload | click | xhr | none
    intervalSec: int = 600
    url: Optional[str] = None
    target: Optional[str] = None


@dataclass
class Geometry:
    x: int
    y: int
    w: int
    h: int


@dataclass
class Panel:
    id: str
    engine: str                     # webkit | chromium
    grid: tuple                     # (col, row)
    mode: str                       # direct | tunnel
    vault_item: str
    selectors: dict
    login_marker: str
    keepalive: KeepAlive
    # one of these is set depending on mode:
    url: Optional[str] = None
    tunnel: Optional[dict] = None
    path: str = "/"
    scheme: str = "http"
    geometry: Optional[Geometry] = None

    @property
    def wmclass(self) -> str:
        return f"soc-{self.id}"

    @property
    def effective_url(self) -> str:
        if self.mode == "tunnel":
            lp = self.tunnel["local_port"]
            return f"{self.scheme}://127.0.0.1:{lp}{self.path}"
        return self.url

    @property
    def tunnel_local_port(self) -> Optional[int]:
        return self.tunnel["local_port"] if self.mode == "tunnel" else None


@dataclass
class DisplayCfg:
    auto: bool = True
    width: int = 1920
    height: int = 1080
    cols: int = 2
    rows: int = 2
    gap: int = 0


@dataclass
class Config:
    display: DisplayCfg
    panels: list = field(default_factory=list)
    tunnel: dict = field(default_factory=dict)


def _keepalive(d: dict) -> KeepAlive:
    d = d or {}
    return KeepAlive(
        strategy=d.get("strategy", "none"),
        intervalSec=int(d.get("intervalSec", 600)),
        url=d.get("url"),
        target=d.get("target"),
    )


def compute_geometry(disp: DisplayCfg, grid) -> Geometry:
    """Map a (col,row) grid cell to an on-screen rectangle."""
    col, row = grid
    gap = disp.gap
    cell_w = (disp.width - gap * (disp.cols - 1)) // disp.cols
    cell_h = (disp.height - gap * (disp.rows - 1)) // disp.rows
    x = col * (cell_w + gap)
    y = row * (cell_h + gap)
    return Geometry(x=x, y=y, w=cell_w, h=cell_h)


def load(path: Optional[str] = None) -> Config:
    path = path or os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    d = raw.get("display", {}) or {}
    disp = DisplayCfg(
        auto=d.get("auto", True),
        width=int(d.get("width", 1920)),
        height=int(d.get("height", 1080)),
        cols=int(d.get("cols", 2)),
        rows=int(d.get("rows", 2)),
        gap=int(d.get("gap", 0)),
    )

    panels = []
    for p in raw.get("panels", []):
        panel = Panel(
            id=p["id"],
            engine=p.get("engine", "webkit"),
            grid=tuple(p.get("grid", [0, 0])),
            mode=p.get("mode", "direct"),
            vault_item=p["vault_item"],
            selectors=p["selectors"],
            login_marker=p.get("login_marker", p["selectors"].get("pass", "")),
            keepalive=_keepalive(p.get("keepalive")),
            url=p.get("url"),
            tunnel=p.get("tunnel"),
            path=p.get("path", "/"),
            scheme=p.get("scheme", "http"),
        )
        panel.geometry = compute_geometry(disp, panel.grid)
        panels.append(panel)

    return Config(display=disp, panels=panels, tunnel=raw.get("tunnel", {}) or {})
