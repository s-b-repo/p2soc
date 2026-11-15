use soc_setup::setup_cli_main;

fn a(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(setup_cli_main(&[]), 2);
    assert_eq!(setup_cli_main(&a(&["bogus"])), 2);
    assert_eq!(setup_cli_main(&a(&["render-env", "--nope"])), 2);
    assert_eq!(setup_cli_main(&a(&["render-env", "--set", "NOEQ"])), 2);
    assert_eq!(setup_cli_main(&a(&["doctor", "--target", "mars"])), 2);
    assert_eq!(setup_cli_main(&a(&["help"])), 0);
}

#[test]
fn render_commands_succeed_from_flags() {
    assert_eq!(setup_cli_main(&a(&["render-env", "--set", "SOC_VAULT_EMAIL=a@b.c"])), 0);
    assert_eq!(
        setup_cli_main(&a(&["render-unit", "--set", "SOC_VAULT_EMAIL=a@b.c", "--user", "kiosk", "--soc-root=/srv/x"])),
        0
    );
}
