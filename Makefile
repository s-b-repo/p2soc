# SOC video-wall kiosk — developer entrypoints.
# Production install on the Pi:  sudo ./install.sh   (or: make install)
.DEFAULT_GOAL := help
SHELL := /bin/bash
PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help
help:  ## show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

.venv:  ## create the venv (system-site-packages for PyGObject/WebKit)
	python3 -m venv --system-site-packages .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q PyYAML websocket-client pytest
	$(PIP) install -q --only-binary=:all: cryptography  # never source-build (Rust ext.)

.PHONY: venv
venv: .venv  ## alias for creating the venv

.PHONY: dev-vault
dev-vault:  ## write dev/run/dev-vault.json (dev vault backend, no server needed)
	@mkdir -p dev/run
	@printf '%s\n' '{' \
	  '  "SOC Dev Panel 1": {"username": "viewer1", "password": "devpass1"},' \
	  '  "SOC Dev Panel 2": {"username": "viewer2", "password": "devpass2"},' \
	  '  "SOC Dev Panel 3": {"username": "viewer3", "password": "devpass3"},' \
	  '  "SOC Dev Panel 4": {"username": "viewer4", "password": "devpass4"},' \
	  '  "SOC Dev VPN": {"username": "vpnuser", "password": "vpnpass"}' \
	  '}' > dev/run/dev-vault.json
	@echo "wrote dev/run/dev-vault.json"

.PHONY: vault
vault: .venv  ## start Vaultwarden in Docker + seed it via litebw (full vault path)
	docker rm -f soc-vaultwarden 2>/dev/null || true
	mkdir -p dev/run/vw-data
	docker run -d --name soc-vaultwarden -e ADMIN_TOKEN=devadmintoken \
	  -e SIGNUPS_ALLOWED=true -e ROCKET_PORT=8222 \
	  -v "$$PWD/dev/run/vw-data:/data" -p 127.0.0.1:8222:8222 \
	  vaultwarden/server:latest
	@echo "waiting for vaultwarden..."; for i in $$(seq 1 20); do \
	  curl -sf http://127.0.0.1:8222/alive >/dev/null && break || sleep 1; done
	bash dev/seed-vault.sh

.PHONY: dev
dev: .venv dev-vault  ## run the wall in a Xephyr window (interactive; Ctrl-C to stop)
	bash dev/run-wall.sh

.PHONY: wizard-gui
wizard-gui: .venv  ## graphical setup wizard (presets + live validation; needs a display)
	PYTHONPATH=kiosk-host $(PY) -m host.setupgui

.PHONY: appearance
appearance: .venv  ## graphical theme editor (presets + per-colour pickers; needs a display)
	PYTHONPATH=kiosk-host $(PY) -m host.appearance

.PHONY: desktop-dev
desktop-dev: .venv  ## install user-level app icons pointing at THIS checkout (no sudo)
	@mkdir -p $(HOME)/.local/share/applications $(HOME)/.local/share/icons/hicolor/scalable/apps
	@install -m0644 share/icons/soc-wall.svg $(HOME)/.local/share/icons/hicolor/scalable/apps/soc-wall.svg
	@PYTHONPATH=kiosk-host SOC_ROOT="$(CURDIR)" $(PY) -m host.branding desktop \
	  "$(CURDIR)/scripts/soc-wall-menu" soc-wall > $(HOME)/.local/share/applications/soc-wall.desktop
	@printf '%s\n' '[Desktop Entry]' 'Name=SOC Wall Setup' 'Comment=Configure the SOC video wall' \
	  'Exec=$(CURDIR)/scripts/soc-wall-setup-gui.sh' 'Icon=soc-wall' 'Terminal=false' \
	  'Type=Application' 'NoDisplay=true' 'Categories=Settings;' > $(HOME)/.local/share/applications/soc-wall-setup.desktop
	@printf '%s\n' '[Desktop Entry]' 'Name=SOC Wall Appearance' 'Comment=Theme colours and presets' \
	  'Exec=$(CURDIR)/scripts/soc-wall-appearance.sh' 'Icon=soc-wall' 'Terminal=false' \
	  'Type=Application' 'NoDisplay=true' 'Categories=Settings;' > $(HOME)/.local/share/applications/soc-wall-appearance.desktop
	@command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database $(HOME)/.local/share/applications 2>/dev/null || true
	@command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -qtf $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "dev app icons installed -> $(HOME)/.local/share/applications (only 'SOC Video Wall' is advertised; Setup + Appearance are NoDisplay, reached via the control center)"

.PHONY: verify
verify: .venv dev-vault  ## headless end-to-end check (Xvfb) — asserts logins + tunnel + screenshot
	bash dev/verify.sh

.PHONY: verify-single
verify-single: .venv dev-vault  ## headless check of the single-window (Wayland) layout
	bash dev/verify-single.sh

.PHONY: verify-proxy
verify-proxy: .venv dev-vault  ## headless check of the authenticated-proxy path
	bash dev/verify-proxy.sh

.PHONY: test
test: .venv  ## run unit tests (no display needed)
	cd kiosk-host && ../$(PY) -m pytest tests/ -q

.PHONY: verify-vpn
verify-vpn: .venv  ## behavioral check of all 3 VPN backends (fortinet/openvpn/wireguard) with fake clients
	bash dev/verify-vpn.sh

.PHONY: vpn-check
vpn-check: .venv dev-vault  ## dry-run the Fortinet VPN: resolve creds + print the openfortivpn command (no connect)
	SOC_PANELS_FILE=config/panels.vpn-dev.yaml SOC_VAULT_BACKEND=dev \
	  SOC_DEV_VAULT=dev/run/dev-vault.json SOC_VPN_DRY_RUN=1 \
	  PYTHONPATH=kiosk-host $(PY) scripts/forti-vpn-connect.py
	@echo "--- non-secret args (forti-vpn-args.py) ---"
	@SOC_PANELS_FILE=config/panels.vpn-dev.yaml PYTHONPATH=kiosk-host $(PY) scripts/forti-vpn-args.py

.PHONY: gen-openbox
gen-openbox: .venv  ## render openbox rc.xml from config/panels.yaml
	$(PY) scripts/gen-openbox-rc.py --panels config/panels.yaml \
	  --template openbox/rc.xml.tmpl --out dev/run/openbox/rc.xml --width 1920 --height 1080

.PHONY: gen-labwc
gen-labwc: .venv  ## render labwc rc.xml (Wayland) from config/panels.yaml
	$(PY) scripts/gen-labwc-rc.py --panels config/panels.yaml \
	  --template labwc/rc.xml.tmpl --out dev/run/labwc/rc.xml

.PHONY: verify-arm
verify-arm:  ## aarch64 gate: assert no compile-on-Pi / wrong-arch regression (no display/root)
	bash dev/verify-arm.sh

.PHONY: lint
lint: .venv verify-arm  ## syntax-check shell + python + run the aarch64 gate
	@bash -n install.sh && echo "install.sh: ok"
	@for s in scripts/*.sh dev/*.sh; do bash -n "$$s" && echo "$$s: ok"; done
	@$(PY) -m py_compile setup.py kiosk-host/host/*.py scripts/*.py dev/*.py && echo "python: ok"
	@# headless wiring smokes (no GTK / no display): config resolver, launcher,
	@# health dot, the privileged sysaction runner.
	@PYTHONPATH=kiosk-host $(PY) -m host.configpaths --check
	@PYTHONPATH=kiosk-host $(PY) -m host.health --check
	@PYTHONPATH=kiosk-host $(PY) -m host.sysaction --check
	@PYTHONPATH=kiosk-host $(PY) -m host.launchermenu --check

.PHONY: install
install:  ## install on the Pi (run as root)
	sudo ./install.sh

.PHONY: uninstall
uninstall:  ## uninstall from the Pi (root; preserves data — ARGS="--purge" to wipe)
	sudo ./uninstall.sh $(ARGS)

.PHONY: clean
clean:  ## stop dev procs and remove dev runtime state
	-pkill -f "dummy-panels/server.py" 2>/dev/null
	-pkill -f "tcp-forward.py" 2>/dev/null
	-pkill -f "host.main" 2>/dev/null
	-pkill -f "Xephyr :8" 2>/dev/null; pkill -f "Xvfb :7" 2>/dev/null
	rm -rf dev/run/xdgrt/soc-profiles dev/run/*.log dev/run/*.png
	@echo "cleaned"

.PHONY: package-clean
package-clean:  ## remove build cruft (__pycache__/*.pyc/.egg-info) so nfpm packages a clean tree
	@find . -path ./.venv -prune -o \( -name '__pycache__' -o -name '*.py[cod]' -o -name '*.egg-info' -o -name '.pytest_cache' \) -print0 2>/dev/null | xargs -0 rm -rf 2>/dev/null || true
	@echo "package-clean: stripped __pycache__/*.pyc/.pytest_cache"

.PHONY: distclean
distclean: clean  ## also remove venv and all dev/run state
	docker rm -f soc-vaultwarden 2>/dev/null || true
	rm -rf .venv dev/run
