# Releasing p2soc

p2soc ships as native distro **packages** (`.deb` / `.rpm` / `.apk`). The payload
is pure Python + shell — there is nothing to compile. A "release" is therefore
just: build the packages from the current tree and attach them to a GitHub
Release. CI does this automatically when you push a `vX.Y.Z` tag.

## What a package contains

- **Prod files only** — the package excludes `dev/`, `dev/dummy-panels/`,
  `dev-vault.json`, `tests/`, `.github/`, `.claude/`, `.venv/`, and `dev/run/`.
  The repo keeps those (CI needs them); only the package drops them.
- The package's declared `Depends` pull the OS packages (PyGObject/WebKitGTK,
  `autossh`, `openfortivpn`, `secret-tool`, …).
- The postinstall runs `install.sh` with `SOC_SKIP_PACKAGES=1`, so the existing
  deploy/config/service logic (create `soc`/`socsvc` users, lay the tree into
  `/opt/soc-display`, install systemd units, session/autologin, zram) runs while
  the package manager owns dependency install. No deploy logic is re-implemented.

## Versioning

- The single source of truth for the version is the top-level [`VERSION`](../VERSION)
  file (one semver line).
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/); pre-1.0
  changes accumulate under `## [Unreleased]`.

## Cutting a release

1. **Bump the version.** Edit `VERSION` to the new semver (e.g. `1.1.0`).
2. **Update the changelog.** Rename the `## [Unreleased]` section to
   `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
3. **Commit** the version + changelog bump.
   ```bash
   git add VERSION CHANGELOG.md
   git commit -m "release: vX.Y.Z"
   ```
4. **Tag and push.** The tag must match `vX.Y.Z` to trigger the release workflow.
   ```bash
   git tag vX.Y.Z
   git push origin main
   git push --tags
   ```
5. **CI builds and publishes.** GitHub Actions (`ubuntu-latest`, amd64 — no
   cross-compile, the payload is interpreted) runs `nfpm` once per packaging
   format/arch from a single YAML spec, then publishes the `.deb`/`.rpm`/`.apk`
   artifacts to the GitHub Release for that tag using only `GITHUB_TOKEN`.

## Before tagging

Run the gates locally (CI runs them too):

```bash
make lint          # shell + python syntax
make test          # unit tests (no display)
make verify        # headless e2e
make verify-arm    # aarch64 / Pi-5 compatibility gate
```

## Verifying a published release

- Confirm the GitHub Release for `vX.Y.Z` has `.deb`, `.rpm`, and `.apk` assets
  for each published arch.
- Spot-install on a target distro; the postinstall should deploy to
  `/opt/soc-display` and install the systemd units without re-running the
  package-manager step.
