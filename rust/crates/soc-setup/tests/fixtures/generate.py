#!/usr/bin/env python3
"""Regenerate the parity fixtures from the REAL setup.py (fake values only).

    python3 rust/crates/soc-setup/tests/fixtures/generate.py

Each case writes <name>.input.json (the env dict), <name>.soc.env (render_soc_env)
and <name>.service (render_wall_unit with the case's user/soc_root). The parse
cases write parse-<n>.in / parse-<n>.json (load_env_file) and unit-<n>.in /
unit-<n>.json (load_unit_env); rewrite cases write rewrite-<n>.{in,args.json,out}.
"""
import importlib.util
import json
import os
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, *[".."] * 5))

spec = importlib.util.spec_from_file_location("soc_setup_gen", os.path.join(REPO, "setup.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

WALL = {
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
CASES = {
    "minimal": ({"SOC_VAULT_EMAIL": "a@b.c"}, "soc", "/opt/soc-display"),
    "empty": ({}, "soc", "/opt/soc-display"),
    "wall": (WALL, "soc", "/opt/soc-display"),
    "kiosk-extras": (dict(WALL, SOC_UNATTENDED="1", SOC_MASTER_SOURCE="sealed",
                          SOC_SECRET_ATTRS="service=soc-wall account=vault-master",
                          SOC_ONSCREEN_CONFIG="0", SOC_ZZ_LAST="z", SOC_AA_FIRST="a",
                          SOC_VAULT_PASSWORD="fake-hunter2", SOC_PINENTRY="/x/pinentry-soc.sh",
                          NOT_SOC="ignored"), "kiosk", "/srv/soc wall"),
    "quoting": (dict(WALL, SOC_VAULT_EMAIL="o'brien@soc.local",
                     SOC_CONFIG_VAULT_ITEM="It's a $HOME `x` \"q\"",
                     SOC_ROOT="/opt/with space", SOC_SESSION="x11",
                     SOC_OPERATOR_NOTE="a b", SOC_EMPTY="", SOC_UNICODE="caf\u00e9"),
                "soc", "/opt/soc-display"),
    "falsy-defaults": (dict(WALL, SOC_VAULT_BACKEND="", SOC_VAULT_URL="", SOC_MEM_MIN_AVAIL_MB="",
                            SOC_CRED_TTL="0"), "soc", "/opt/soc-display"),
}
for name, (env, user, root) in CASES.items():
    with open(f"{HERE}/{name}.input.json", "w") as fh:
        json.dump({"env": env, "user": user, "soc_root": root}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    with open(f"{HERE}/{name}.soc.env", "w") as fh:
        fh.write(m.render_soc_env(env))
    with open(f"{HERE}/{name}.service", "w") as fh:
        fh.write(m.render_wall_unit(env, user=user, soc_root=root))

PARSE = [
    "# c\n\nA=1\nB = two \nC='quoted val'\nD=\"dq\"\nE=a=b=c\nNOEQ\n  F=  spaced  \nG=\"mismatch'\nH=\"\nI=''\nJ=\nexport K=1\n#L=3\n=empty\n",
    "SOC_VAULT_URL=http://127.0.0.1:8222\nSOC_X='it'\\''s'\nA=\"\"\nA=second\n",
    "\ufeffBOM=1\nT=\u00e9\r\nCRLF=1\r\n",
]
UNIT = [
    "[Service]\nEnvironment=A=1\nEnvironment=\"B=two words\"\n  Environment=C=3  \nEnvironment=NOEQ\nEnvironment=\nEnvironment=\"\"\nEnvironment=D=x=y\nEnvironment=E=1 F=2\nEnvironment=\"G=\nEnvironment=H=\"q\"\nExecStart=/x\n# Environment=Z=9\n",
]
for i, text in enumerate(PARSE):
    p = f"{HERE}/parse-{i}.in"
    with open(p, "w", newline="") as fh:
        fh.write(text)
    with open(f"{HERE}/parse-{i}.json", "w") as fh:
        json.dump(m.load_env_file(p), fh, indent=1, sort_keys=True)
        fh.write("\n")
for i, text in enumerate(UNIT):
    p = f"{HERE}/unit-{i}.in"
    with open(p, "w", newline="") as fh:
        fh.write(text)
    with open(f"{HERE}/unit-{i}.json", "w") as fh:
        json.dump(m.load_unit_env(p), fh, indent=1, sort_keys=True)
        fh.write("\n")

REWRITE = [
    ("# header\nA=1\n\nB=2\n# c\nC=3\nA=dup\n", {"remove": ["B"], "set": [["A", "9"], ["N", "new"], ["M", "x"]]}),
    ("SOC_VAULT_PASSWORD=fake\nSOC_MASTER_SOURCE=auto\nSOC_PINENTRY=/x/pinentry-soc.sh\n",
     {"remove": ["SOC_VAULT_PASSWORD"], "set": [["SOC_MASTER_SOURCE", "sealed"], ["SOC_PINENTRY", "/opt/p"]]}),
    ("A=1\n", {"remove": [], "set": []}),
]
for i, (text, args) in enumerate(REWRITE):
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "soc.env")
        with open(p, "w") as fh:
            fh.write(text)
        m.rewrite_env(p, remove=args["remove"], set_kv=dict(args["set"]), mode=0o600)
        out = open(p).read()
        assert os.stat(p).st_mode & 0o777 == 0o600
    with open(f"{HERE}/rewrite-{i}.in", "w") as fh:
        fh.write(text)
    with open(f"{HERE}/rewrite-{i}.args.json", "w") as fh:
        json.dump(args, fh)
        fh.write("\n")
    with open(f"{HERE}/rewrite-{i}.out", "w") as fh:
        fh.write(out)
print("ok")
