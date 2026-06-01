// SPDX-License-Identifier: Apache-2.0

use apolysis_core::fields::PipeFields;

#[test]
fn pipe_fields_parse_trimmed_key_value_pairs() {
    let fields =
        PipeFields::parse("timestamp=123 | pid=42 | comm=python3 | resource=/workspace/app.py")
            .expect("valid pipe fields");

    assert_eq!(fields.required("comm").expect("comm"), "python3");
    assert_eq!(fields.parse_u128("timestamp").expect("timestamp"), 123);
    assert_eq!(fields.parse_u32("pid").expect("pid"), 42);
    assert_eq!(fields.optional("resource"), Some("/workspace/app.py"));
}

#[test]
fn pipe_fields_report_invalid_and_missing_fields() {
    let error = PipeFields::parse("pid=42 | malformed").expect_err("invalid field");
    assert!(error.contains("invalid pipe field: malformed"));

    let fields = PipeFields::parse("pid=").expect("empty value is parsed");
    let missing = fields.required("pid").expect_err("empty value is missing");
    assert!(missing.contains("missing pipe field: pid"));
}
