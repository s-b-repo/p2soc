//! Byte-for-byte parity with the real Python `setup.py` (fixtures written by
//! `tests/fixtures/generate.py`).

use serde_json::Value;
use soc_setup::{Changes, UnitOpts, parse_env_file, parse_unit_env, render_soc_env, render_wall_unit, rewrite_env};
use std::collections::BTreeMap;
use std::path::PathBuf;

mod common;

fn fx(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn map(v: &Value) -> BTreeMap<String, String> {
    v.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
}

const CASES: [&str; 6] = ["minimal", "empty", "wall", "kiosk-extras", "quoting", "falsy-defaults"];

#[test]
fn soc_env_and_unit_match_python() {
    for case in CASES {
        let input: Value = serde_json::from_str(&fx(&format!("{case}.input.json"))).unwrap();
        let env = map(&input["env"]);
        assert_eq!(render_soc_env(&env), fx(&format!("{case}.soc.env")), "soc.env: {case}");
        let opts = UnitOpts {
            user: input["user"].as_str().unwrap().into(),
            soc_root: input["soc_root"].as_str().unwrap().into(),
        };
        assert_eq!(render_wall_unit(&env, &opts), fx(&format!("{case}.service")), "unit: {case}");
    }
}

#[test]
fn env_file_parsing_matches_python() {
    for i in 0..3 {
        let want: Value = serde_json::from_str(&fx(&format!("parse-{i}.json"))).unwrap();
        assert_eq!(parse_env_file(&fx(&format!("parse-{i}.in"))), map(&want), "parse-{i}");
    }
}

#[test]
fn unit_env_parsing_matches_python() {
    let want: Value = serde_json::from_str(&fx("unit-0.json")).unwrap();
    assert_eq!(parse_unit_env(&fx("unit-0.in")), map(&want));
}

#[test]
fn rewrite_env_matches_python() {
    for i in 0..3 {
        let args: Value = serde_json::from_str(&fx(&format!("rewrite-{i}.args.json"))).unwrap();
        let mut ch = Changes::new();
        for k in args["remove"].as_array().unwrap() {
            ch = ch.remove(k.as_str().unwrap());
        }
        for kv in args["set"].as_array().unwrap() {
            ch = ch.set(kv[0].as_str().unwrap(), kv[1].as_str().unwrap());
        }
        let dir = common::TempDir::new("rw");
        let p = dir.join("soc.env");
        std::fs::write(&p, fx(&format!("rewrite-{i}.in"))).unwrap();
        rewrite_env(&p, &ch, 0o600, false).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), fx(&format!("rewrite-{i}.out")), "rewrite-{i}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn rewritten_env_leaves_a_backup_and_missing_file_is_a_noop() {
    let dir = common::TempDir::new("rwb");
    let p = dir.join("soc.env");
    assert_eq!(
        rewrite_env(&p, &Changes::new().set("A", "1"), 0o600, false).unwrap(),
        soc_setup::envfile::Rewrite::Missing
    );
    std::fs::write(&p, "A=0\n").unwrap();
    let r = rewrite_env(&p, &Changes::new().set("A", "1"), 0o600, false).unwrap();
    let soc_setup::envfile::Rewrite::Written { backup: Some(b) } = r else { panic!("no backup") };
    assert_eq!(std::fs::read_to_string(b).unwrap(), "A=0\n");
}

#[test]
fn rendered_env_round_trips_through_the_loader() {
    let env = common::env(&[("SOC_ONSCREEN_CONFIG", "0"), ("SOC_UNATTENDED", "1"), ("SOC_VAULT_EMAIL", "o'b@x.y")]);
    let back = parse_env_file(&render_soc_env(&env));
    assert_eq!(back["SOC_ONSCREEN_CONFIG"], "0");
    assert_eq!(back["SOC_UNATTENDED"], "1");
}

#[test]
fn rerender_never_carries_a_plaintext_master_forward() {
    let out = render_soc_env(&common::env(&[("SOC_VAULT_PASSWORD", "hunter2"), ("SOC_PINENTRY", "x")]));
    assert!(!out.contains("hunter2") && !out.contains("SOC_VAULT_PASSWORD") && !out.contains("SOC_PINENTRY"));
}

#[test]
fn wall_unit_env_roundtrip_and_supervision() {
    let env = common::env(&[
        ("SOC_VAULT_EMAIL", "k@soc.local"),
        ("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config"),
        ("SOC_SESSION", "auto"),
    ]);
    let unit = render_wall_unit(&env, &UnitOpts::default());
    assert!(unit.contains("Restart=always") && unit.contains("MemoryHigh=80%") && !unit.contains("MemoryMax="));
    assert!(unit.contains("Environment=\"SOC_CONFIG_VAULT_ITEM=SOC Wall Config\""));
    assert!(unit.contains("ExecStart=/opt/soc-display/scripts/start-session.sh"));
    let back = parse_unit_env(&unit);
    assert_eq!(back["SOC_CONFIG_VAULT_ITEM"], "SOC Wall Config");
    assert_eq!(back["SOC_VAULT_EMAIL"], "k@soc.local");
}
