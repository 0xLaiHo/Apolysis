// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{parse_validate_host_args, ValidateHostMode};

#[test]
fn parses_explicit_dry_run_output_directory() {
    let args = ["--dry-run", "--output", "/tmp/apolysis-backup"]
        .into_iter()
        .map(str::to_string);

    let parsed = parse_validate_host_args(args).expect("parse args");

    assert_eq!(parsed.mode, ValidateHostMode::DryRun);
    assert_eq!(
        parsed.output_dir,
        std::path::PathBuf::from("/tmp/apolysis-backup")
    );
}

#[test]
fn parses_apply_and_restore_modes() {
    let apply = parse_validate_host_args(
        [
            "--apply-runtime-registration",
            "--output",
            "/tmp/apolysis-backup",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("parse apply args");
    let restore = parse_validate_host_args(
        ["--restore", "--output", "/tmp/apolysis-backup"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("parse restore args");

    assert_eq!(apply.mode, ValidateHostMode::ApplyRuntimeRegistration);
    assert_eq!(restore.mode, ValidateHostMode::Restore);
}

#[test]
fn rejects_missing_mode_flag() {
    let error = parse_validate_host_args(
        ["--output", "/tmp/apolysis-backup"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("mode flag is mandatory");

    assert!(error.contains("--dry-run"), "{error}");
    assert!(error.contains("--apply-runtime-registration"), "{error}");
}

#[test]
fn rejects_multiple_modes() {
    let error = parse_validate_host_args(
        ["--dry-run", "--restore", "--output", "/tmp/apolysis-backup"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("modes are mutually exclusive");

    assert!(error.contains("exactly one mode"), "{error}");
}
