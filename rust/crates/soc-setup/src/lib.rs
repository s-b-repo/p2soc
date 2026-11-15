//! p2soc setup backend: the non-interactive logic of the Python `setup.py`,
//! as testable Rust that a `soc-wall setup <cmd>` CLI and a GUI wizard share.

pub mod check;
pub mod cli;
pub mod config;
pub mod deploy;
pub mod doctor;
pub mod envfile;
pub mod error;
pub mod firstrun;
pub mod host;
pub mod paths;
pub mod repair;
pub mod seal;
pub mod step;
pub mod unit;
pub mod util;
pub mod vault;

/// How hints name this tool.
pub const CLI: &str = "soc-wall setup";

pub use check::{CheckResult, Report, Status};
pub use cli::setup_cli_main;
pub use deploy::{DeployOutcome, DeployPlan, DeployStep};
pub use doctor::{Doctor, DoctorInputs};
pub use envfile::{Changes, SocEnv, envq, parse_env_file, render_soc_env, rewrite_env};
pub use error::{Result, SealMasterError, SetupError, TextResult};
pub use firstrun::{FirstRunPlan, FirstRunStep};
pub use host::{Host, SystemHost};
pub use repair::{Repair, RepairOpts};
pub use unit::{UnitOpts, parse_unit_env, render_wall_unit};
