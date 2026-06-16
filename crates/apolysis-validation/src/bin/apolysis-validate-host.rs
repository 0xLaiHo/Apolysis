// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    collect_and_apply_host_runtime_registration, collect_host_validation_report,
    parse_validate_host_args, restore_validation_from_output, SystemctlServiceController,
    ValidateHostMode,
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
    match args.mode {
        ValidateHostMode::DryRun => {
            let report = collect_host_validation_report(args.output_dir.clone())?;
            println!(
                "apolysis-validation: captured {} files, {} services, {} workloads, {} restore actions in {}",
                report.backup_manifest.entries.len(),
                report.services.len(),
                report.kubernetes.workloads.len(),
                report.restore_plan.actions.len(),
                args.output_dir.display()
            );
        }
        ValidateHostMode::ApplyRuntimeRegistration => {
            let report = collect_and_apply_host_runtime_registration(args.output_dir.clone())?;
            println!(
                "apolysis-validation: captured {} files and wrote {} runtime registration files in {}",
                report.validation.backup_manifest.entries.len(),
                report.registration.files_written,
                args.output_dir.display()
            );
        }
        ValidateHostMode::Restore => {
            let mut controller = SystemctlServiceController;
            let report = restore_validation_from_output(&args.output_dir, &mut controller)?;
            println!(
                "apolysis-validation: applied {} restore actions from {}",
                report.actions_applied,
                args.output_dir.display()
            );
        }
    }
    Ok(())
}
