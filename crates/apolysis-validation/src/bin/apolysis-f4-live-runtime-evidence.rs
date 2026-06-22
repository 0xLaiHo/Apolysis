// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{
    evaluate_f4_live_runtime_evidence_bundle, F4LiveRuntimeEvidenceBundleRequest,
};

fn main() {
    match run() {
        Ok(passed) => {
            if !passed {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("apolysis-f4-live-runtime-evidence: {error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let request: F4LiveRuntimeEvidenceBundleRequest =
        serde_json::from_str(&input).map_err(|error| {
            format!("failed to parse F4 live runtime evidence bundle JSON: {error}")
        })?;
    let report = evaluate_f4_live_runtime_evidence_bundle(request);
    let passed = report.passed;
    let output = serde_json::to_string_pretty(&report).map_err(|error| {
        format!("failed to serialize F4 live runtime evidence bundle report: {error}")
    })?;
    println!("{output}");
    Ok(passed)
}
