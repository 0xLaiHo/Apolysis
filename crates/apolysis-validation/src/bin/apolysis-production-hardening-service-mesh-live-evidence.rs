// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_production_hardening_service_mesh_live_evidence,
    ProductionHardeningServiceMeshLiveEvidence,
};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    evidence: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-production-hardening-service-mesh-live-evidence: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let evidence_json = fs::read_to_string(&args.evidence).map_err(|error| {
        format!(
            "failed to read service-mesh live evidence {}: {error}",
            args.evidence.display()
        )
    })?;
    let evidence: ProductionHardeningServiceMeshLiveEvidence = serde_json::from_str(&evidence_json)
        .map_err(|error| format!("failed to parse service-mesh live evidence JSON: {error}"))?;
    let report = evaluate_production_hardening_service_mesh_live_evidence(evidence);
    let output = serde_json::to_string_pretty(&report).map_err(|error| {
        format!("failed to serialize service-mesh live evidence report: {error}")
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
        [flag, path] if flag == "--evidence" => Ok(CliArgs {
            evidence: PathBuf::from(path),
        }),
        _ => Err(
            "usage: apolysis-production-hardening-service-mesh-live-evidence --evidence <path>"
                .to_string(),
        ),
    }
}
