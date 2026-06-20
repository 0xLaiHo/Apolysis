// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{
    f3_block_operator_audit_records, F3BlockEnablementPolicyReport, F3BlockOperatorAuditOperation,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Args {
    operation: F3BlockOperatorAuditOperation,
    operator: String,
    timestamp_unix_ms: u128,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-f3-block-operator-audit: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let report: F3BlockEnablementPolicyReport = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse enablement policy report JSON: {error}"))?;
    let records = f3_block_operator_audit_records(
        &report,
        args.operation,
        &args.operator,
        args.timestamp_unix_ms,
    )?;

    for record in records {
        println!("{}", record.to_json_line()?);
    }
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Args, String> {
    let mut operation = None;
    let mut operator = None;
    let mut timestamp_unix_ms = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--operation" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--operation requires a value".to_string())?;
                operation = Some(match value.as_str() {
                    "approve" => F3BlockOperatorAuditOperation::Approve,
                    "rollback" => F3BlockOperatorAuditOperation::Rollback,
                    _ => return Err("--operation must be approve or rollback".to_string()),
                });
            }
            "--operator" => {
                index += 1;
                operator = Some(
                    args.get(index)
                        .ok_or_else(|| "--operator requires a value".to_string())?
                        .clone(),
                );
            }
            "--timestamp-unix-ms" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--timestamp-unix-ms requires a value".to_string())?;
                timestamp_unix_ms = Some(
                    value
                        .parse()
                        .map_err(|error| format!("invalid --timestamp-unix-ms: {error}"))?,
                );
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        index += 1;
    }

    Ok(Args {
        operation: operation.ok_or_else(|| "--operation is required".to_string())?,
        operator: operator.ok_or_else(|| "--operator is required".to_string())?,
        timestamp_unix_ms: timestamp_unix_ms
            .ok_or_else(|| "--timestamp-unix-ms is required".to_string())?,
    })
}
