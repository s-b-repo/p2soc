//! Source-checkout reinstallation, with the same data retention options as the
//! original standalone tool.

use crate::cli::Flags;
use crate::error::TextResult;
use soc_sys::{
    fsutil,
    paths::PathEnv,
    run::{Runner, SystemRunner, argv},
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const UNITS: &[&str] = &[
    "soc-update.timer",
    "soc-update.service",
    "soc-wall.service",
    "soc-tarpit.service",
    "soc-firstboot.service",
    "autossh-tunnel.service",
    "forti-vpn.service",
    "forti-vpn@.service",
    "soc-vpn.service",
    "soc-vpn@.service",
];
const TIMEOUT: Duration = Duration::from_secs(120);

struct Run<'a> {
    flags: &'a Flags,
}

impl Run<'_> {
    fn dry(&self) -> bool {
        self.flags.has("--dry-run")
    }

    fn command(&self, args: &[&str]) -> io::Result<soc_sys::run::Output> {
        if self.dry() || self.flags.has("--verbose") {
            println!("{}", args.join(" "));
        }
        if self.dry() {
            return Ok(soc_sys::run::Output { code: Some(0), ..Default::default() });
        }
        let out = SystemRunner.run(&argv(args), TIMEOUT)?;
        if self.flags.has("--verbose") {
            print!("{}", out.stdout);
            eprint!("{}", out.stderr);
        }
        Ok(out)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        if self.dry() || self.flags.has("--verbose") {
            println!("remove {}", path.display());
        }
        if self.dry() {
            return Ok(());
        }
        match path.symlink_metadata() {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
            Ok(_) => std::fs::remove_file(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn service_cleanup(&self, etc: &Path) -> TextResult<()> {
        let instances = self
            .command(&[
                "systemctl",
                "list-units",
                "--all",
                "--no-legend",
                "--plain",
                "forti-vpn@*.service",
                "soc-vpn@*.service",
            ])
            .map_err(|e| e.to_string())?;
        let units: Vec<_> = UNITS
            .iter()
            .copied()
            .chain(instances.stdout.lines().filter_map(|line| {
                line.split_whitespace().next().filter(|u| {
                    !u.starts_with('-')
                        && (u.starts_with("forti-vpn@") || u.starts_with("soc-vpn@"))
                        && u.ends_with(".service")
                })
            }))
            .collect();
        for verb in ["stop", "disable"] {
            let mut args = vec!["systemctl", verb];
            args.extend(&units);
            self.command(&args).map_err(|e| e.to_string())?;
        }
        if !self.flags.has("--keep-units") {
            let system = Path::new("/etc/systemd/system");
            for unit in UNITS
                .iter()
                .copied()
                .chain(["vaultwarden.service"].into_iter().filter(|_| self.flags.has("--purge-vault")))
            {
                self.remove(&system.join(unit)).map_err(|e| e.to_string())?;
            }
            for name in ["autologin.conf", "override.conf"] {
                self.remove(&system.join("getty@tty1.service.d").join(name)).map_err(|e| e.to_string())?;
            }
            self.command(&["systemctl", "daemon-reload"]).map_err(|e| e.to_string())?;
        }
        let target = fsutil::read_capped(&etc.join(".prior-target"), 4096)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| {
                !s.starts_with('-')
                    && s.ends_with(".target")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
            .unwrap_or_else(|| "graphical.target".into());
        let current = self.command(&["systemctl", "get-default"]).map_err(|e| e.to_string())?;
        if self.dry() || current.success() && current.stdout.trim() != target {
            self.command(&["systemctl", "set-default", &target]).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

pub(crate) fn run(args: &[String]) -> TextResult<i32> {
    let switches = &[
        "--uninstall-only",
        "--purge",
        "--purge-vault",
        "--purge-vault-data",
        "--keep-units",
        "--no-firstrun",
        "--dry-run",
        "--yes",
        "--verbose",
    ];
    if args == ["--help"] {
        println!(
            "usage: soc-wall reinstall {}",
            switches.iter().map(|s| format!("[{s}]")).collect::<Vec<_>>().join(" ")
        );
        return Ok(0);
    }
    let flags = Flags::parse(args, &[], switches)?;
    let runner = Run { flags: &flags };
    let penv = PathEnv::from_process();
    let deployed = Path::new("/opt/soc-display");
    let releases = Path::new("/opt/soc-releases");
    let root = penv.repo_root().canonicalize().map_err(|e| e.to_string())?;
    if root.starts_with(deployed) || root.starts_with(releases) || !root.join("install.sh").is_file() {
        return Err("run reinstall from the source checkout".into());
    }
    if !runner.dry() {
        if fsutil::euid() != 0 {
            return Err("reinstall needs root (or --dry-run)".into());
        }
        if !flags.has("--yes") {
            print!("Remove the deployed wall and generated settings? [y/N] ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
            if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                return Ok(1);
            }
        }
    }
    let etc = penv.etc_dir();
    if runner.dry() || Path::new("/run/systemd/system").is_dir() {
        runner.service_cleanup(&etc)?;
    }
    for path in [deployed, releases] {
        runner.remove(path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    for name in [
        "soc.env",
        "tarpit.env",
        "tarpit-paths.list",
        "manifest.json",
        "panels.yaml",
        "keys",
        ".configured",
        "config-cache.yaml",
        ".installed",
        ".deps-rev",
    ] {
        let path = etc.join(name);
        runner.remove(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if flags.has("--purge") {
        runner.remove(&etc.join("secret")).map_err(|e| e.to_string())?;
    }
    if flags.has("--purge-vault") || flags.has("--purge-vault-data") {
        for action in ["stop", "rm"] {
            match runner.command(&["docker", action, "soc-vaultwarden"]) {
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        if flags.has("--purge-vault-data") {
            for path in [penv.home.join(".local/share/soc-vaultwarden"), PathBuf::from("/var/lib/vaultwarden")] {
                runner.remove(&path).map_err(|e| e.to_string())?;
            }
        }
    }
    if flags.has("--uninstall-only") {
        return Ok(0);
    }
    if runner.dry() {
        println!("run {}", root.join("install.sh").display());
        if !flags.has("--no-firstrun") {
            println!("run soc-wall setup first-run --target pi");
        }
        return Ok(0);
    }
    let status = Command::new(root.join("install.sh"))
        .current_dir(&root)
        .env_remove("SOC_ROOT")
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Ok(status.code().unwrap_or(1));
    }
    if flags.has("--no-firstrun") {
        return Ok(0);
    }
    let status = Command::new(deployed.join("bin/soc-wall"))
        .args(["setup", "first-run", "--target", "pi"])
        .env_remove("SOC_ROOT")
        .status()
        .map_err(|e| e.to_string())?;
    Ok(status.code().unwrap_or(1))
}
