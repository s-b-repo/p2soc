# Releasing p2soc

p2soc ships as native distro **packages** (`.deb` / `.rpm` / `.apk`). CI
builds the Rust executable and packages it with the installer, system units, and
runtime assets when you push a `vX.Y.Z` tag.

## What a package contains

- **Prod files only** — the package excludes `dev/`, `dev/dummy-panels/`,
  `dev-vault.json`, `tests/`, `.github/`, `.claude/`, `.venv/`, and `dev/run/`.
  The repo keeps those (CI needs them); only the package drops them.
- The package's declared `Depends` pull the OS packages (GTK/WebKitGTK,
  `autossh`, `openfortivpn`, `secret-tool`, …).
- The postinstall runs `install.sh` with `SOC_SKIP_PACKAGES=1`, so the existing
  deploy/config/service logic (create `soc`/`socsvc` users, lay the tree into
  `/opt/soc-display`, install systemd units, session/autologin, zram) runs while
  the package manager owns dependency install. No deploy logic is re-implemented.

## Versioning

- The release tag, top-level [`VERSION`](../VERSION), Rust workspace version and
  Python compatibility package version must agree. Tag builds check the binary's
  `--version` output and package version against `VERSION`.
- Changes accumulate under `## [Unreleased]` in [CHANGELOG](../CHANGELOG.md).

## Cutting a release

1. **Bump the version.** Update `VERSION`, `rust/Cargo.toml`,
   `kiosk-host/pyproject.toml`, and the crate versions in the two Cargo lockfiles.
2. **Update the changelog.** Rename the `## [Unreleased]` section to
   `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
3. **Commit** the version + changelog bump.
   ```bash
   git add VERSION CHANGELOG.md rust/Cargo.toml rust/Cargo.lock rust/fuzz/Cargo.lock kiosk-host/pyproject.toml
   git commit -m "Release vX.Y.Z"
   ```
4. **Tag and push.** The tag must match `vX.Y.Z` to trigger the release workflow.
   ```bash
   git tag -a vX.Y.Z -m "p2soc vX.Y.Z"
   git push --atomic origin HEAD:refs/heads/rust-vX.Y.Z refs/tags/vX.Y.Z
   ```
5. **CI builds and publishes.** GitHub Actions builds the native executable
   for each architecture and libc, stages it for `nfpm`, and uploads the
   resulting `.deb`, `.rpm`, and `.apk` packages to the tagged release.

The matrix publishes DEB for AMD64, ARM64 and ARMv7 hard float. RPM and APK
cover AMD64 and ARM64. APK uses the musl build. The release also includes a
source archive and SHA256 checksums.

## Before tagging

Run the gates locally (CI runs them too):

```bash
make lint          # shell + python syntax
make test          # Rust workspace tests with a virtual display
make test-python   # Python compatibility tests
make rust-release  # build the binary for the current machine
```

## Verifying a published release

- Confirm the GitHub Release for `vX.Y.Z` has `.deb`, `.rpm`, and `.apk` assets
  for each published arch.
- Spot-install on a target distro; the postinstall should deploy to
  `/opt/soc-display` and install the systemd units without re-running the
  package-manager step.
