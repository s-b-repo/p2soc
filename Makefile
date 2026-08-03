# SOC video-wall kiosk — maintenance entrypoints.
# Install on the Pi:                 sudo python3 setup.py   (or: make install)
# Run / configure / repair the wall: ./launch.sh
.DEFAULT_GOAL := help
SHELL := /bin/bash
PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help
help:  ## show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

.venv:  ## create the venv (system-site-packages for PyGObject/WebKit) — used by tests
	python3 -m venv --system-site-packages .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q PyYAML websocket-client pytest cryptography

.PHONY: venv
venv: .venv  ## alias for creating the venv

.PHONY: test
test: .venv  ## run unit tests (no display needed)
	cd kiosk-host && ../$(PY) -m pytest tests/ -q

.PHONY: lint
lint: .venv  ## syntax-check shell + python
	@bash -n install.sh && echo "install.sh: ok"
	@bash -n launch.sh && echo "launch.sh: ok"
	@for s in scripts/*.sh; do bash -n "$$s" && echo "$$s: ok"; done
	@$(PY) -m py_compile setup.py kiosk-host/host/*.py scripts/*.py && echo "python: ok"

.PHONY: install
install:  ## install on the Pi (run as root)
	sudo bash install.sh

.PHONY: secrets-scan
secrets-scan:  ## run .githooks/pre-commit against the staged set
	@.githooks/pre-commit && echo "secrets-scan: ok"

.PHONY: refresh-manifest
refresh-manifest:  ## re-hash /opt/soc-display so the boot drift warning clears
	@# Write the source commit into /opt/soc-display/.commit so the
	@# manifest carries the right "deployed commit" tag even though
	@# /opt/soc-display isn't a git checkout (rsync excludes .git).
	@sha=$$(git rev-parse HEAD 2>/dev/null || true); \
	  if [ -n "$$sha" ]; then \
	    printf '%s\n' "$$sha" | sudo tee /opt/soc-display/.commit >/dev/null; \
	  fi
	@PYTHONPATH=/opt/soc-display/kiosk-host sudo \
	    /opt/soc-display/.venv/bin/python -m host.manifest 2>&1

.PHONY: clean
clean:  ## remove Python caches
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"

.PHONY: distclean
distclean: clean  ## also remove the venv
	rm -rf .venv
