# Development

The normal build produces one Linux executable, `rust/target/release/soc-wall`.
The checkout also keeps the Python compatibility host and tests.

## Requirements

- Rust 1.87 or newer, a C compiler, `pkg-config`, GTK 3 and WebKitGTK 4.1
  development headers. On Debian or Ubuntu, the headers are in `libgtk-3-dev`
  and `libwebkit2gtk-4.1-dev`.
- Xvfb and `xauth` for the GUI tests. Chromium is required when using Chromium
  panels. The WebKit tests run without it.
- Python with PyGObject, WebKitGTK introspection, PyYAML, websocket-client,
  cryptography and pytest for the compatibility tests. The resource benchmark
  needs the Python runtime dependencies and a release build of the Rust binary.

## Build, run and check

| Command | What it does |
|---|---|
| `make rust-release` | Build the native release binary. |
| `./launch.sh` | Open a window with the empty preset and the development vault. |
| `./launch.sh --setup` | Open the terminal setup menu. |
| `./launch.sh --headless` | Run native WebKit and Settings smoke tests under Xvfb. |
| `make test` | Run the Rust workspace tests under Xvfb. |
| `make test-python` | Run the Python compatibility suite. |
| `make lint` | Check shell and Python syntax. |

Use a preset to exercise the parser without writing system configuration:

```sh
make rust-release
rust/target/release/soc-wall setup-gui --list-presets
rust/target/release/soc-wall setup-gui --non-interactive --preset single-panel --output dev/run/preset
rust/target/release/soc-wall check dev/run/preset/panels.yaml
```

`SOC_PANELS_FILE` overrides the preview configuration. Set `SOC_VAULT_BACKEND=dev`
and `SOC_DEV_VAULT=/path/to/fixture.json` to provide test logins. The fixture maps
vault item names to objects with `username` and `password` fields.

## Native checks

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check -p soc-wall --no-default-features --locked
bash scripts/audit-bad-patterns.sh --strict
```

The WebKit test logs in to a local fixture, exercises login-zone calibration
and checks navigation restrictions. The Chromium runtime talks to a launched
browser over CDP. Its library tests cover the protocol and launch arguments.
Both engines use the shared template at `inject/login.js.tmpl`.

The process tree benchmark measures both hosts on an identical four-panel
workload. Its command, method and results are in [Performance](PERFORMANCE.md).

## Runtime configuration

| Variable | Purpose |
|---|---|
| `SOC_PANELS_FILE` | Explicit panel configuration. |
| `SOC_ENV_FILE` | Explicit environment file. |
| `SOC_ROOT` | Checkout or installed resource directory. |
| `SOC_DEV_VAULT` | Development vault fixture. |
| `SOC_WEBDATA_DIR`, `SOC_STATE_DIR` | Alternate browser and Settings state directories for isolated runs. |
| `SOC_CHROMIUM_HWACCEL`, `SOC_WEBKIT_HWACCEL` | Override the detected hardware profile. |
| `SOC_LEGACY_PYTHON=1` | Select the compatibility runtime in shell entry points. Its dependencies must be installed. |

See [Architecture](ARCHITECTURE.md) for the crate map and [Releasing](RELEASING.md)
for package builds.
