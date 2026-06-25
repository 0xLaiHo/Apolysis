// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{
    default_runtime_foundation_performance_budgets, evaluate_performance_gate, PerformanceBudget,
    PerformanceSample,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PerformanceReportInput {
    Samples(Vec<PerformanceSample>),
    Custom {
        budgets: Vec<PerformanceBudget>,
        samples: Vec<PerformanceSample>,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-runtime-foundation-performance: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let parsed: PerformanceReportInput = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse performance sample JSON: {error}"))?;
    let (budgets, samples) = match parsed {
        PerformanceReportInput::Samples(samples) => {
            (default_runtime_foundation_performance_budgets(), samples)
        }
        PerformanceReportInput::Custom { budgets, samples } => (budgets, samples),
    };

    let report = evaluate_performance_gate(budgets, samples);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize performance report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
