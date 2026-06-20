// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{evaluate_f4_runtime_guardrail_matrix, F3BlockValidationReport};

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-f4-runtime-guardrail-matrix: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let reports: Vec<F3BlockValidationReport> = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse F3 block validation reports JSON: {error}"))?;

    let matrix = evaluate_f4_runtime_guardrail_matrix(reports);
    let output = serde_json::to_string_pretty(&matrix)
        .map_err(|error| format!("failed to serialize F4 runtime guardrail matrix: {error}"))?;
    println!("{output}");
    Ok(())
}
