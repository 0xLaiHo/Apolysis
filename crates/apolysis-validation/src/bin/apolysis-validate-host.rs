// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    collect_host_validation_report, parse_validate_host_args, validate_host_usage,
};

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("apolysis-validate-host: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run() -> Result<(), String> {
    let args = parse_validate_host_args(std::env::args().skip(1))?;
    if !args.dry_run {
        return Err(validate_host_usage().to_string());
    }
    let report = collect_host_validation_report(args.output_dir.clone())?;
    println!(
        "apolysis-validation: captured {} files, {} services, {} workloads, {} restore actions in {}",
        report.backup_manifest.entries.len(),
        report.services.len(),
        report.kubernetes.workloads.len(),
        report.restore_plan.actions.len(),
        args.output_dir.display()
    );
    Ok(())
}
