// SPDX-License-Identifier: Apache-2.0

use apolysis_core::scalars::{clean_scalar, parse_bool};

#[test]
fn clean_scalar_trims_quotes_and_whitespace() {
    assert_eq!(clean_scalar(r#" "runsc" "#), "runsc");
    assert_eq!(clean_scalar(" 'kata' "), "kata");
    assert_eq!(clean_scalar("default"), "default");
}

#[test]
fn parse_bool_accepts_yaml_boolean_literals() {
    assert!(parse_bool("true", "automountServiceAccountToken").expect("true"));
    assert!(!parse_bool("false", "automountServiceAccountToken").expect("false"));

    let error = parse_bool("maybe", "automountServiceAccountToken").expect_err("invalid bool");
    assert_eq!(error, "invalid automountServiceAccountToken boolean: maybe");
}
