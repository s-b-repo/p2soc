"""Regression tests recovered from v1.3.0 (test_setup_commands.py): cases for this line's own
features that were lost when the suite was replaced. Kept separate so they stay
visibly additive to test_setup_commands.py."""
import importlib.util


import os


import re


_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _setup():
    spec = importlib.util.spec_from_file_location(
        "soc_setup_cmds", os.path.join(_REPO, "setup.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _deploy_paths(m, tmp_path, backend="dev", stamped=False):
    soc_env = tmp_path / "soc.env"
    soc_env.write_text(f"SOC_VAULT_BACKEND={backend}\n")
    if stamped:
        (tmp_path / ".installed").write_text("installed")
    return dict(mode="pi", soc_env=str(soc_env), soc_root="/nonexistent",
                panels_installed=str(tmp_path / "none.yaml"), vw_env=str(tmp_path / "vw"),
                secret_dir=str(tmp_path / "secret"), default_backend=backend,
                config_vault_item="X")


def _install_calls(calls):
    return [c for c in calls if any("install.sh" in str(x) for x in c)]


_WALL_ENV = {
    "SOC_VAULT_BACKEND": "rbw", "SOC_VAULT_EMAIL": "k@soc.local",
    "SOC_VAULT_URL": "http://127.0.0.1:8222",
    "SOC_SECRET_DIR": "/etc/soc-display/secret",
    "SOC_CONFIG_VAULT_ITEM": "SOC Wall Config", "SOC_ROOT": "/opt/soc-display",
    "SOC_PANELS_FILE": "/etc/soc-display/panels.yaml",
    "SOC_INJECT_TMPL": "/opt/soc-display/inject/login.js.tmpl",
    "SOC_LAUNCH_STAGGER": "1.5", "SOC_READY_TIMEOUT": "120",
    "SOC_CDP_BASE_PORT": "9222", "SOC_CRED_TTL": "30", "SOC_VPN_DRY_RUN": "0",
    "SOC_SESSION": "auto",
}


def test_install_ends_by_naming_the_single_next_step():
    """Deployment is one command now, so the installer must point at it rather than
    list manual steps (creating the vault account by hand, rebooting, ...)."""
    with open(os.path.join(_REPO, "install.sh"), encoding="utf-8") as fh:
        text = fh.read()
    ending = text[text.rindex("Install complete."):]
    assert "setup.py deploy" in ending
    assert "web vault" not in ending
    assert "systemctl reboot" not in ending
