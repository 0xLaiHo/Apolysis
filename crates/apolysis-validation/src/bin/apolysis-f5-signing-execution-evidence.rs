// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{evaluate_f5_signing_execution_evidence, F5SigningExecutionEvidence};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    evidence: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-f5-signing-execution-evidence: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let evidence_json = fs::read_to_string(&args.evidence).map_err(|error| {
        format!(
            "failed to read signing execution evidence {}: {error}",
            args.evidence.display()
        )
    })?;
    let evidence: F5SigningExecutionEvidence = serde_json::from_str(&evidence_json)
        .map_err(|error| format!("failed to parse signing execution evidence JSON: {error}"))?;
    let report = evaluate_f5_signing_execution_evidence(evidence);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize signing execution report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    match args.as_slice() {
        [flag, path] if flag == "--evidence" => Ok(CliArgs {
            evidence: PathBuf::from(path),
        }),
        _ => Err("usage: apolysis-f5-signing-execution-evidence --evidence <path>".to_string()),
    }
}
