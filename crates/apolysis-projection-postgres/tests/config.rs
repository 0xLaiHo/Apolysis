// SPDX-License-Identifier: Apache-2.0

use apolysis_projection_postgres::{
    ProjectionConfig, ProjectionErrorCode, MAX_LIFECYCLE_PAGE_SIZE, MAX_PROJECTION_BATCH_SIZE,
};

#[test]
fn operational_limits_are_bounded_before_database_work() {
    assert_eq!(MAX_PROJECTION_BATCH_SIZE, 200);
    assert_eq!(MAX_LIFECYCLE_PAGE_SIZE, 200);

    let error = ProjectionConfig::new(0, 4, 2_000, 15_000)
        .expect_err("a zero batch size must fail before database work");
    assert_eq!(error.code(), ProjectionErrorCode::InvalidArgument);

    let error = ProjectionConfig::new(201, 4, 2_000, 15_000)
        .expect_err("an oversized batch must fail before database work");
    assert_eq!(error.code(), ProjectionErrorCode::InvalidArgument);
}

#[test]
fn operational_deadlines_and_retries_are_bounded() {
    for config in [
        ProjectionConfig::new(20, 0, 2_000, 15_000),
        ProjectionConfig::new(20, 9, 2_000, 15_000),
        ProjectionConfig::new(20, 4, 0, 15_000),
        ProjectionConfig::new(20, 4, 30_001, 15_000),
        ProjectionConfig::new(20, 4, 2_000, 0),
        ProjectionConfig::new(20, 4, 2_000, 120_001),
    ] {
        assert_eq!(
            config
                .expect_err("unsafe operational setting must fail")
                .code(),
            ProjectionErrorCode::InvalidArgument
        );
    }
}
