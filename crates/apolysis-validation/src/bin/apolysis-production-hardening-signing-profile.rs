// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_production_hardening_signing_profile, ProductionHardeningSigningProfile,
};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    profile: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-production-hardening-signing-profile: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let profile_json = fs::read_to_string(&args.profile).map_err(|error| {
        format!(
            "failed to read signing profile {}: {error}",
            args.profile.display()
        )
    })?;
    let profile: ProductionHardeningSigningProfile = serde_json::from_str(&profile_json)
        .map_err(|error| format!("failed to parse signing profile JSON: {error}"))?;
    let report = evaluate_production_hardening_signing_profile(profile);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize signing profile report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    match args.as_slice() {
        [flag, path] if flag == "--profile" => Ok(CliArgs {
            profile: PathBuf::from(path),
        }),
        _ => {
            Err("usage: apolysis-production-hardening-signing-profile --profile <path>".to_string())
        }
    }
}
