// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{evaluate_visibility_report_gate, VisibilityReport};

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-f2-visibility: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let reports: Vec<VisibilityReport> = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse visibility report JSON: {error}"))?;
    let gate = evaluate_visibility_report_gate(reports);
    let output = serde_json::to_string_pretty(&gate)
        .map_err(|error| format!("failed to serialize visibility gate report: {error}"))?;
    println!("{output}");
    if gate.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
