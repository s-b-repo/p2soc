//! Exercise the installed command boundary on an isolated configuration.
#![cfg(feature = "gui")]

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soc-wall")).args(args).output().unwrap()
}

#[test]
fn native_setup_presets_and_maintenance_commands_work_without_a_display() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let dir = std::env::temp_dir().join(format!("p2soc-cli-{}", std::process::id()));
    let paths = dir.to_str().unwrap();
    let preset = Command::new(env!("CARGO_BIN_EXE_soc-wall"))
        .env("SOC_ROOT", &repo)
        .args(["setup-gui", "--non-interactive", "--preset", "single-panel", "--output", paths])
        .output()
        .unwrap();
    assert!(preset.status.success(), "{}", String::from_utf8_lossy(&preset.stderr));
    let panels = dir.join("panels.yaml");
    assert!(run(&["check", panels.to_str().unwrap()]).status.success());
    let env = std::fs::read_to_string(dir.join("soc.env")).unwrap();
    assert!(env.contains("SOC_VAULT_BACKEND=dev"));
    assert!(env.contains(panels.to_str().unwrap()));
    assert!(run(&["update", "self-test"]).status.success());
    assert!(run(&["setup", "vault-reset", "--email", "fake@example.test", "--dry-run"]).status.success());
    let lock = repo.join("security/vaultwarden.lock");
    assert!(
        run(&[
            "fetch-vaultwarden",
            "--check",
            "--lock",
            lock.to_str().unwrap(),
            "--dest",
            dir.join("unused").to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(!dir.join("unused").exists());
    std::fs::remove_dir_all(dir).unwrap();
}
