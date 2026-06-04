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

.PHONY: venv
venv: .venv  ## alias for creating the venv

.PHONY: dev-vault
dev-vault:  ## write dev/run/dev-vault.json (dev vault backend, no server needed)
	@mkdir -p dev/run
	@printf '%s\n' '{' \
	  '  "SOC Dev Panel 1": {"username": "viewer1", "password": "devpass1"},' \
	  '  "SOC Dev Panel 2": {"username": "viewer2", "password": "devpass2"},' \
	  '  "SOC Dev Panel 3": {"username": "viewer3", "password": "devpass3"},' \
	  '  "SOC Dev Panel 4": {"username": "viewer4", "password": "devpass4"}' \
	  '}' > dev/run/dev-vault.json
	@echo "wrote dev/run/dev-vault.json"

.PHONY: vault
vault: .venv  ## start Vaultwarden in Docker + seed it via rbw (full vault path)
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

.PHONY: verify
verify: .venv dev-vault  ## headless end-to-end check (Xvfb) — asserts logins + tunnel + screenshot
	bash dev/verify.sh

.PHONY: test
test: .venv  ## run unit tests (no display needed)
	cd kiosk-host && ../$(PY) -m pytest tests/ -q

.PHONY: gen-openbox
gen-openbox: .venv  ## render openbox rc.xml from config/panels.yaml
	$(PY) scripts/gen-openbox-rc.py --panels config/panels.yaml \
	  --template openbox/rc.xml.tmpl --out dev/run/openbox/rc.xml --width 1920 --height 1080

.PHONY: lint
lint: .venv  ## syntax-check shell + python
	@bash -n install.sh && echo "install.sh: ok"
	@for s in scripts/*.sh dev/*.sh; do bash -n "$$s" && echo "$$s: ok"; done
	@$(PY) -m py_compile kiosk-host/host/*.py scripts/*.py dev/*.py && echo "python: ok"

.PHONY: install
install:  ## install on the Pi (run as root)
	sudo ./install.sh

.PHONY: clean
clean:  ## stop dev procs and remove dev runtime state
	-pkill -f "dummy-panels/server.py" 2>/dev/null
	-pkill -f "tcp-forward.py" 2>/dev/null
	-pkill -f "host.main" 2>/dev/null
	-pkill -f "Xephyr :8" 2>/dev/null; pkill -f "Xvfb :7" 2>/dev/null
	rm -rf dev/run/xdgrt/soc-profiles dev/run/*.log dev/run/*.png
	@echo "cleaned"

.PHONY: distclean
distclean: clean  ## also remove venv and all dev/run state
	docker rm -f soc-vaultwarden 2>/dev/null || true
	rm -rf .venv dev/run
