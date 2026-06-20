// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{evaluate_f3_block_validation_gate, F3BlockValidationReport};

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-f3-block-validation: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let reports: Vec<F3BlockValidationReport> = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse F3 block validation report JSON: {error}"))?;

    let gate = evaluate_f3_block_validation_gate(reports);
    let output = serde_json::to_string_pretty(&gate)
        .map_err(|error| format!("failed to serialize F3 block validation gate report: {error}"))?;
    println!("{output}");
    if gate.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
