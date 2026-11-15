//! Performance profile detection.
//!
//! The wall targets anything from a 1 GB Raspberry Pi to an x86 workstation.
//! Rather than asking the operator to hand-tune browser knobs, the host picks
//! a profile from the actual hardware and exposes overrides:
//!
//! - `SOC_LOW_MEMORY=0|1` — force the low-memory profile off/on (auto: on
//!   when MemTotal <= ~1.5 GB).
//! - `SOC_WEBKIT_HWACCEL=auto|always|never|ondemand` — WebKit GPU policy.
//!   `auto` is *always* on ARM boards with a render node (Pi 5 V3D:
//!   compositing on the GPU instead of the CPU), *on demand* under the
//!   low-memory profile, engine default elsewhere.
//! - `SOC_CHROMIUM_HWACCEL=auto|never` — the Chromium counterpart.
//! - `SOC_UNATTENDED=0|1` — nobody is at this box.
//! - `SOC_FAKE_ARCH=<machine>` — test-only: pretend to be this architecture
//!   so the ARM tuning branch can be exercised on an x86 box.
//!
//! Every `/proc` reader takes the proc root as a parameter (tests use fixture
//! trees) and treats what it reads as untrusted text: bounded reads, strict
//! unsigned parsing, and no assumption that a process still exists.

use crate::fsutil::read_prefix_lossy;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// 1 GB-class boards (Pi) after the GPU carve-out.
pub const LOW_MEMORY_THRESHOLD_MB: u64 = 1536;

/// The real proc filesystem.
pub const PROC: &str = "/proc";
/// Where DRM render nodes appear.
pub const DRI_DIR: &str = "/dev/dri";

/// `/proc` text files the wall reads are a few KiB; anything beyond this is
/// not what it claims to be.
const PROC_READ_CAP: u64 = 64 * 1024;

/// The value of a `Name:   <n> kB` line. Strict: the number must be plain
/// ASCII digits that fit a `u64`.
fn field_kb(text: &str, field: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix(field)?.strip_prefix(':')?.split_ascii_whitespace().next()?;
        if value.bytes().all(|b| b.is_ascii_digit()) { value.parse().ok() } else { None }
    })
}

fn meminfo_mb(proc_root: &Path, field: &str) -> Option<u64> {
    let text = read_prefix_lossy(&proc_root.join("meminfo"), PROC_READ_CAP)?;
    field_kb(&text, field).map(|kb| kb / 1024)
}

/// MemTotal in MiB, or `None` when it cannot be read.
pub fn total_ram_mb(proc_root: &Path) -> Option<u64> {
    meminfo_mb(proc_root, "MemTotal")
}

/// MemAvailable in MiB — the kernel's estimate of allocatable memory, which
/// the memory watchdog uses to detect pressure on a 1 GB Pi.
pub fn mem_available_mb(proc_root: &Path) -> Option<u64> {
    meminfo_mb(proc_root, "MemAvailable")
}

/// Resident-set size (KiB) of a process, or `None` if it is gone.
pub fn proc_rss_kb(proc_root: &Path, pid: u32) -> Option<u64> {
    let text = read_prefix_lossy(&proc_root.join(pid.to_string()).join("status"), PROC_READ_CAP)?;
    field_kb(&text, "VmRSS")
}

/// One live process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub ppid: u32,
    /// The command name (cut to 15 characters by the kernel).
    pub comm: String,
}

/// `pid -> (ppid, comm)` for every live process.
pub type ProcTable = BTreeMap<u32, ProcEntry>;

fn parse_stat(raw: &str) -> Option<ProcEntry> {
    // comm may itself hold spaces and parentheses, so split on the LAST ')'.
    let (head, tail) = raw.rsplit_once(')')?;
    let mut fields = tail.split_ascii_whitespace();
    let state = fields.next()?;
    let ppid = fields.next()?;
    if state == "Z" || state == "X" || !ppid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let comm = head.split_once('(')?.1;
    Some(ProcEntry { ppid: ppid.parse().ok()?, comm: comm.to_string() })
}

/// Every live process, zombies left out. One pass over `/proc`: a few
/// milliseconds and no fork, so it is safe on the main thread.
pub fn proc_table(proc_root: &Path) -> ProcTable {
    let mut table = ProcTable::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return table;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<u32>() else { continue };
        // A process can exit while we are looking: a missing file is normal.
        if let Some(e) = read_prefix_lossy(&entry.path().join("stat"), PROC_READ_CAP).as_deref().and_then(parse_stat) {
            table.insert(pid, e);
        }
    }
    table
}

/// The `WebKitWebProcess` children of `parent`.
pub fn web_process_pids(table: &ProcTable, parent: u32) -> BTreeSet<u32> {
    table
        .iter()
        .filter(|(_, e)| e.ppid == parent && e.comm.starts_with("WebKitWebProces"))
        .map(|(pid, _)| *pid)
        .collect()
}

/// Summed RSS (KiB) of `pid` and all its descendants, or `None` if `pid` is
/// gone. A browser's memory is in its renderers, so its own RSS says little.
/// Shared pages count once per process: this ranks panels, it is not a total.
///
/// The table is a non-atomic snapshot, so pid reuse during the scan can make
/// it look cyclic; every pid is visited at most once.
pub fn proc_tree_rss_kb(pid: u32, table: &ProcTable, rss: impl Fn(u32) -> Option<u64>) -> Option<u64> {
    if !table.contains_key(&pid) {
        return None;
    }
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (p, e) in table {
        children.entry(e.ppid).or_default().push(*p);
    }
    let mut seen = BTreeSet::new();
    let mut stack = vec![pid];
    let mut total = 0u64;
    while let Some(p) = stack.pop() {
        if !seen.insert(p) {
            continue;
        }
        total = total.saturating_add(rss(p).unwrap_or(0));
        if let Some(kids) = children.get(&p) {
            stack.extend(kids);
        }
    }
    Some(total)
}

/// [`log_repeat_with`] at the default cadence (first 5, then every 30th).
pub fn log_repeat(n: u64) -> bool {
    log_repeat_with(n, 5, 30)
}

/// Is the n-th straight repeat of a failure worth a log line? The journal
/// lives on the SD card and a panel that stays down retries for as long as it
/// takes: tell the story of the first few, then one line in `every`.
pub fn log_repeat_with(n: u64, first: u64, every: u64) -> bool {
    n <= first || (every != 0 && n % every == 0)
}

/// True when available memory is known and below the floor.
pub fn under_pressure(avail_mb: Option<u64>, min_mb: u64) -> bool {
    avail_mb.is_some_and(|a| a < min_mb)
}

/// `SOC_UNATTENDED`: nobody is at the keyboard, so anything that would wait
/// for a human must instead show its state and retry on a capped backoff.
pub fn unattended_from(raw: Option<&str>) -> bool {
    matches!(raw.unwrap_or("").trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// [`unattended_from`] on the process environment (read at each use).
pub fn unattended() -> bool {
    unattended_from(std::env::var("SOC_UNATTENDED").ok().as_deref())
}

/// Whether a machine name (`uname -m` spelling, or Rust's `arm`) is ARM.
pub fn is_arm_machine(machine: &str) -> bool {
    matches!(machine, "aarch64" | "arm64" | "armv7l" | "armv6l" | "arm")
}

/// Whether a DRM render node exists under `dri_dir`.
pub fn has_gpu_render_node(dri_dir: &Path) -> bool {
    std::fs::read_dir(dri_dir)
        .is_ok_and(|entries| entries.flatten().any(|e| e.file_name().to_string_lossy().starts_with("renderD")))
}

/// The low-memory decision: an explicit `0`/`1` wins, else the RAM size.
pub fn low_memory_from(env: Option<&str>, total_mb: Option<u64>) -> bool {
    match env {
        Some("1") => true,
        Some("0") => false,
        _ => total_mb.is_some_and(|mb| mb <= LOW_MEMORY_THRESHOLD_MB),
    }
}

/// WebKit hardware-acceleration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwAccel {
    Always,
    Never,
    OnDemand,
    /// Leave the engine default.
    Default,
}

impl HwAccel {
    pub const fn as_str(self) -> &'static str {
        match self {
            HwAccel::Always => "always",
            HwAccel::Never => "never",
            HwAccel::OnDemand => "ondemand",
            HwAccel::Default => "default",
        }
    }
}

/// Resolve `SOC_WEBKIT_HWACCEL` against the hardware facts. An unrecognised
/// value leaves the engine default rather than guessing.
pub fn hwaccel_mode_from(env: Option<&str>, low_memory: bool, arm: bool, render_node: bool) -> HwAccel {
    match env.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "always" => HwAccel::Always,
        "never" => HwAccel::Never,
        "ondemand" => HwAccel::OnDemand,
        "" | "auto" => {
            if low_memory {
                HwAccel::OnDemand
            } else if arm && render_node {
                HwAccel::Always
            } else {
                HwAccel::Default
            }
        }
        _ => HwAccel::Default,
    }
}

/// Whether Chromium should be nudged onto the GPU (`SOC_CHROMIUM_HWACCEL`):
/// only in `auto` mode on an ARM board with a render node, where it otherwise
/// silently falls back to software compositing.
pub fn chromium_gpu_from(env: Option<&str>, arm: bool, render_node: bool) -> bool {
    matches!(env.unwrap_or("auto").to_ascii_lowercase().as_str(), "" | "auto") && arm && render_node
}

/// How much the web engine may cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheModel {
    /// Smallest caches: panels trade cache for headroom on small boards.
    DocumentViewer,
    /// Leave the engine default.
    EngineDefault,
}

/// The detected hardware profile with every override applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub total_ram_mb: Option<u64>,
    pub low_memory: bool,
    pub arm: bool,
    pub render_node: bool,
    pub webkit_hwaccel: HwAccel,
    pub chromium_gpu: bool,
    pub cache_model: CacheModel,
    pub unattended: bool,
}

/// The raw inputs of [`Profile::resolve`], so the policy is testable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileInputs {
    pub total_ram_mb: Option<u64>,
    /// Machine architecture name.
    pub machine: String,
    pub render_node: bool,
    pub low_memory_env: Option<String>,
    pub webkit_hwaccel_env: Option<String>,
    pub chromium_hwaccel_env: Option<String>,
    pub unattended_env: Option<String>,
}

impl Profile {
    /// Apply the profile policy to explicit inputs.
    pub fn resolve(inputs: &ProfileInputs) -> Profile {
        let low_memory = low_memory_from(inputs.low_memory_env.as_deref(), inputs.total_ram_mb);
        let arm = is_arm_machine(&inputs.machine);
        Profile {
            total_ram_mb: inputs.total_ram_mb,
            low_memory,
            arm,
            render_node: inputs.render_node,
            webkit_hwaccel: hwaccel_mode_from(
                inputs.webkit_hwaccel_env.as_deref(),
                low_memory,
                arm,
                inputs.render_node,
            ),
            chromium_gpu: chromium_gpu_from(inputs.chromium_hwaccel_env.as_deref(), arm, inputs.render_node),
            cache_model: if low_memory { CacheModel::DocumentViewer } else { CacheModel::EngineDefault },
            unattended: unattended_from(inputs.unattended_env.as_deref()),
        }
    }

    /// Detect the profile of this machine from `/proc`, `/dev/dri` and the
    /// environment.
    pub fn detect() -> Profile {
        let var = |name: &str| std::env::var(name).ok();
        Profile::resolve(&ProfileInputs {
            total_ram_mb: total_ram_mb(Path::new(PROC)),
            // An ARM binary only runs on an ARM machine, so the compile-time
            // architecture is the machine's.
            machine: var("SOC_FAKE_ARCH").filter(|v| !v.is_empty()).unwrap_or_else(|| std::env::consts::ARCH.into()),
            render_node: has_gpu_render_node(Path::new(DRI_DIR)),
            low_memory_env: var("SOC_LOW_MEMORY"),
            webkit_hwaccel_env: var("SOC_WEBKIT_HWACCEL"),
            chromium_hwaccel_env: var("SOC_CHROMIUM_HWACCEL"),
            unattended_env: var("SOC_UNATTENDED"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// `procs`: `(pid, ppid, comm, state, rss_kb)`.
    fn fake_proc(t: &TempDir, procs: &[(u32, u32, &str, &str, u64)]) {
        for (pid, ppid, comm, state, rss) in procs {
            t.write(&format!("{pid}/stat"), &format!("{pid} ({comm}) {state} {ppid} 0 0 0 0"));
            t.write(&format!("{pid}/status"), &format!("Name:\t{comm}\nVmRSS:\t{rss} kB\n"));
        }
    }

    fn entry(ppid: u32, comm: &str) -> ProcEntry {
        ProcEntry { ppid, comm: comm.into() }
    }

    #[test]
    fn meminfo_fields() {
        let t = TempDir::new("perf-meminfo");
        t.write("meminfo", "MemTotal:     1024000 kB\nMemAvailable:    65536 kB\nMemFree: 1 kB\n");
        assert_eq!(total_ram_mb(t.path()), Some(1000));
        assert_eq!(mem_available_mb(t.path()), Some(64));
        assert_eq!(total_ram_mb(&t.path().join("missing")), None);
        assert_eq!(mem_available_mb(&t.path().join("missing")), None);
    }

    #[test]
    fn meminfo_parsing_is_strict() {
        for bad in [
            "MemAvailable:\n",
            "MemAvailable: -5 kB\n",
            "MemAvailable: 1_000 kB\n",
            "MemAvailable: 99999999999999999999999 kB\n",
            "MemAvailable: +12 kB\n",
            "MemAvailableX: 12 kB\n",
            "XMemAvailable: 12 kB\n",
        ] {
            assert_eq!(field_kb(bad, "MemAvailable"), None, "{bad:?}");
        }
        assert_eq!(field_kb("MemAvailable:12 kB", "MemAvailable"), Some(12));
        assert_eq!(field_kb("MemAvailable:\t  7", "MemAvailable"), Some(7));
    }

    #[test]
    fn rss_of_a_process() {
        let t = TempDir::new("perf-rss");
        t.write("42/status", "Name:\tchromium\nVmRSS:\t  204800 kB\nThreads:\t9\n");
        assert_eq!(proc_rss_kb(t.path(), 42), Some(204_800));
        assert_eq!(proc_rss_kb(t.path(), 43), None);
    }

    #[test]
    fn proc_table_reads_odd_comms_and_skips_zombies() {
        let t = TempDir::new("perf-table");
        fake_proc(&t, &[(10, 1, "plain", "S", 1), (11, 10, "a) b (c", "R", 1), (12, 10, "dead", "Z", 0)]);
        t.write("self/stat", "1 (x) S 0");
        t.write("13/stat", "garbage without parens");
        t.write("14/stat", "14 (neg) S -1 0");
        std::fs::create_dir(t.path().join("15")).unwrap();
        let table = proc_table(t.path());
        assert_eq!(table, ProcTable::from([(10, entry(1, "plain")), (11, entry(10, "a) b (c"))]));
    }

    #[test]
    fn proc_table_without_proc_is_empty() {
        let t = TempDir::new("perf-noproc");
        assert!(proc_table(&t.path().join("nope")).is_empty());
    }

    #[test]
    fn web_process_pids_are_our_webkit_children_only() {
        let table = ProcTable::from([
            (5, entry(1, "WebKitWebProces")), // the kernel cuts comm at 15 characters
            (6, entry(1, "WebKitNetworkPr")),
            (7, entry(2, "WebKitWebProces")), // somebody else's
        ]);
        assert_eq!(web_process_pids(&table, 1), BTreeSet::from([5]));
    }

    #[test]
    fn proc_tree_rss_sums_the_whole_tree() {
        let t = TempDir::new("perf-tree");
        fake_proc(
            &t,
            &[
                (20, 1, "chromium", "S", 100),
                (21, 20, "zygote", "S", 10),
                (22, 21, "renderer", "S", 500),
                (23, 1, "unrelated", "S", 9000),
            ],
        );
        let table = proc_table(t.path());
        assert_eq!(proc_tree_rss_kb(20, &table, |p| proc_rss_kb(t.path(), p)), Some(610));
    }

    #[test]
    fn proc_tree_rss_of_a_gone_process_is_none() {
        let table = ProcTable::from([(1, entry(0, "init"))]);
        assert_eq!(proc_tree_rss_kb(99, &table, |_| Some(1)), None);
    }

    #[test]
    fn a_cyclic_snapshot_terminates() {
        // pid reuse while scanning can produce a parent loop
        let table = ProcTable::from([(50, entry(100, "a")), (100, entry(50, "b")), (7, entry(7, "self"))]);
        assert_eq!(proc_tree_rss_kb(50, &table, |_| Some(3)), Some(6));
        assert_eq!(proc_tree_rss_kb(7, &table, |_| Some(3)), Some(3));
    }

    #[test]
    fn log_repeat_tells_the_start_then_samples() {
        let lines: Vec<u64> = (1..=120).filter(|n| log_repeat(*n)).collect();
        assert_eq!(lines, [1, 2, 3, 4, 5, 30, 60, 90, 120]);
        assert!(!log_repeat_with(7, 5, 0), "a zero cadence must not divide by zero");
    }

    #[test]
    fn pressure_needs_a_known_reading() {
        assert!(under_pressure(Some(50), 96));
        assert!(!under_pressure(Some(200), 96));
        assert!(!under_pressure(None, 96));
    }

    #[test]
    fn unattended_spellings() {
        for on in ["1", "true", " YES ", "On"] {
            assert!(unattended_from(Some(on)), "{on:?}");
        }
        for off in ["", "0", "no", "maybe"] {
            assert!(!unattended_from(Some(off)), "{off:?}");
        }
        assert!(!unattended_from(None));
    }

    #[test]
    fn arm_detection() {
        for m in ["aarch64", "arm64", "armv7l", "armv6l", "arm"] {
            assert!(is_arm_machine(m), "{m}");
        }
        assert!(!is_arm_machine("x86_64"));
    }

    #[test]
    fn render_node_detection() {
        let t = TempDir::new("perf-dri");
        t.write("card0", "");
        assert!(!has_gpu_render_node(t.path()));
        t.write("renderD128", "");
        assert!(has_gpu_render_node(t.path()));
        assert!(!has_gpu_render_node(&t.path().join("missing")));
    }

    #[test]
    fn low_memory_env_wins_over_ram_size() {
        assert!(low_memory_from(Some("1"), Some(8000)));
        assert!(!low_memory_from(Some("0"), Some(512)));
        assert!(low_memory_from(None, Some(1536)));
        assert!(!low_memory_from(Some("yes"), Some(1537)));
        assert!(!low_memory_from(None, None));
    }

    #[test]
    fn hwaccel_policy() {
        for (val, want) in [("always", HwAccel::Always), ("never", HwAccel::Never), ("OnDemand", HwAccel::OnDemand)] {
            assert_eq!(hwaccel_mode_from(Some(val), true, true, true), want);
        }
        // low-memory boards prefer on-demand acceleration
        assert_eq!(hwaccel_mode_from(Some("auto"), true, true, true), HwAccel::OnDemand);
        // an ARM board with a V3D render node composites on the GPU
        assert_eq!(hwaccel_mode_from(None, false, true, true), HwAccel::Always);
        assert_eq!(hwaccel_mode_from(Some(""), false, true, false), HwAccel::Default);
        assert_eq!(hwaccel_mode_from(Some("auto"), false, false, true), HwAccel::Default);
        assert_eq!(hwaccel_mode_from(Some("turbo"), true, true, true), HwAccel::Default);
    }

    #[test]
    fn chromium_gpu_policy() {
        assert!(chromium_gpu_from(None, true, true));
        assert!(chromium_gpu_from(Some("AUTO"), true, true));
        assert!(!chromium_gpu_from(Some("never"), true, true));
        assert!(!chromium_gpu_from(Some("always"), true, true));
        assert!(!chromium_gpu_from(None, false, true));
        assert!(!chromium_gpu_from(None, true, false));
    }

    #[test]
    fn profile_of_a_one_gigabyte_pi() {
        let p = Profile::resolve(&ProfileInputs {
            total_ram_mb: Some(900),
            machine: "aarch64".into(),
            render_node: true,
            ..ProfileInputs::default()
        });
        assert!(p.low_memory && p.arm && p.chromium_gpu);
        assert_eq!(p.webkit_hwaccel, HwAccel::OnDemand);
        assert_eq!(p.cache_model, CacheModel::DocumentViewer);
        let desktop = Profile::resolve(&ProfileInputs {
            total_ram_mb: Some(16_000),
            machine: "x86_64".into(),
            ..ProfileInputs::default()
        });
        assert_eq!(desktop.webkit_hwaccel, HwAccel::Default);
        assert_eq!(desktop.cache_model, CacheModel::EngineDefault);
        assert!(!desktop.chromium_gpu && !desktop.low_memory);
    }
}
