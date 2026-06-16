// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::parse_validate_host_args;

#[test]
fn parses_explicit_dry_run_output_directory() {
    let args = ["--dry-run", "--output", "/tmp/apolysis-backup"]
        .into_iter()
        .map(str::to_string);

    let parsed = parse_validate_host_args(args).expect("parse args");

    assert!(parsed.dry_run);
    assert_eq!(
        parsed.output_dir,
        std::path::PathBuf::from("/tmp/apolysis-backup")
    );
}

#[test]
fn rejects_missing_dry_run_flag() {
    let error = parse_validate_host_args(
        ["--output", "/tmp/apolysis-backup"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("dry-run flag is mandatory");

    assert!(error.contains("--dry-run"), "{error}");
}
