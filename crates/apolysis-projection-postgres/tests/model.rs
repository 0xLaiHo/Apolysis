// SPDX-License-Identifier: Apache-2.0

use apolysis_projection_postgres::{ComputationVersion, GenerationId, ProjectionErrorCode};

#[test]
fn computation_versions_are_bounded_safe_identifiers() {
    assert_eq!(
        ComputationVersion::try_from("run-lifecycle-v1")
            .expect("safe computation version")
            .as_str(),
        "run-lifecycle-v1"
    );

    for invalid in ["", "../version", "version with spaces", "version\nleak"] {
        assert_eq!(
            ComputationVersion::try_from(invalid)
                .expect_err("unsafe computation version must fail")
                .code(),
            ProjectionErrorCode::InvalidArgument
        );
    }

    let oversized = "v".repeat(129);
    assert_eq!(
        ComputationVersion::try_from(oversized.as_str())
            .expect_err("oversized computation version must fail")
            .code(),
        ProjectionErrorCode::InvalidArgument
    );
}

#[test]
fn generation_identifiers_are_strictly_positive() {
    assert_eq!(
        GenerationId::try_from(0_i64)
            .expect_err("zero is not a generation")
            .code(),
        ProjectionErrorCode::InvalidArgument
    );
    assert_eq!(
        GenerationId::try_from(-1_i64)
            .expect_err("negative values are not generations")
            .code(),
        ProjectionErrorCode::InvalidArgument
    );
    assert_eq!(GenerationId::try_from(7_i64).expect("generation").get(), 7);
}
