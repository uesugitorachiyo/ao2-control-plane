//! ao2-cp-gc — operator-facing storage retention pruner.
//!
//! Wraps `ao2_cp_storage::Storage::prune_retention` so cron-style
//! out-of-band maintenance can enforce count-based retention without
//! going through the authenticated HTTP API. Emits the prune result
//! as JSON on stdout. Exit non-zero on error.
//!
//! Trust posture: ao2-cp-gc only deletes content-addressed observer
//! evidence on a per-kind LRU basis. It does not approve AO2 digests,
//! close AO2 runs, execute provider plugins, or open any network
//! surface. It is a maintenance tool for the flat-file store.

use std::path::PathBuf;
use std::process::ExitCode;

use ao2_cp_storage::{RetentionPolicy, Storage};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ao2-cp-gc",
    version,
    about = "Operator-facing retention pruner for ao2-control-plane storage"
)]
struct Args {
    /// Path to the ao2-control-plane data directory (same value passed
    /// to ao2-cp-server --data-dir).
    #[arg(long, value_name = "PATH")]
    data_dir: PathBuf,

    /// Number of most-recent entries to retain per prunable kind.
    #[arg(long, value_name = "N")]
    keep_latest: usize,

    /// Plan the prune without modifying the store. Mutually exclusive
    /// with --apply.
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,

    /// Apply the prune (delete pruned bundle files and rewrite the
    /// index). Mutually exclusive with --dry-run.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if !args.dry_run && !args.apply {
        eprintln!(
            "ao2-cp-gc: must pass exactly one of --dry-run or --apply (no implicit default to avoid accidental deletions)"
        );
        return ExitCode::from(64); // EX_USAGE
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("ao2-cp-gc: failed to build tokio runtime: {err}");
            return ExitCode::from(70); // EX_SOFTWARE
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ao2-cp-gc: {err:#}");
            ExitCode::from(70)
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let storage = Storage::open(args.data_dir.clone()).await?;
    let policy = RetentionPolicy {
        keep_latest: args.keep_latest,
    };
    let dry_run = args.dry_run;
    let result = storage.prune_retention(policy, dry_run).await?;
    let json = serde_json::to_string_pretty(&result)?;
    println!("{json}");
    Ok(())
}
