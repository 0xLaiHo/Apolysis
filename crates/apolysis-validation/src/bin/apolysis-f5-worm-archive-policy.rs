// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{evaluate_f5_worm_archive_policy, F5WormArchivePolicy};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    policy: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-f5-worm-archive-policy: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let policy_json = fs::read_to_string(&args.policy).map_err(|error| {
        format!(
            "failed to read WORM archive policy {}: {error}",
            args.policy.display()
        )
    })?;
    let policy: F5WormArchivePolicy = serde_json::from_str(&policy_json)
        .map_err(|error| format!("failed to parse WORM archive policy JSON: {error}"))?;
    let report = evaluate_f5_worm_archive_policy(policy);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize WORM archive policy report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    match args.as_slice() {
        [flag, path] if flag == "--policy" => Ok(CliArgs {
            policy: PathBuf::from(path),
        }),
        _ => Err("usage: apolysis-f5-worm-archive-policy --policy <path>".to_string()),
    }
}
