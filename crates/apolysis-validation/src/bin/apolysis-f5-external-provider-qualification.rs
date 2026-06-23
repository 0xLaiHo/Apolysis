// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_f5_external_provider_qualification_bundle, F5ExternalProviderQualificationBundle,
};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    bundle: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-f5-external-provider-qualification: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let bundle_json = fs::read_to_string(&args.bundle).map_err(|error| {
        format!(
            "failed to read external provider qualification bundle {}: {error}",
            args.bundle.display()
        )
    })?;
    let bundle: F5ExternalProviderQualificationBundle = serde_json::from_str(&bundle_json)
        .map_err(|error| {
            format!("failed to parse external provider qualification bundle JSON: {error}")
        })?;
    let report = evaluate_f5_external_provider_qualification_bundle(bundle);
    let output = serde_json::to_string_pretty(&report).map_err(|error| {
        format!("failed to serialize external provider qualification report: {error}")
    })?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    match args.as_slice() {
        [flag, path] if flag == "--bundle" => Ok(CliArgs {
            bundle: PathBuf::from(path),
        }),
        _ => Err("usage: apolysis-f5-external-provider-qualification --bundle <path>".to_string()),
    }
}
