// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, fs, path::PathBuf};

#[test]
fn committed_json_schemas_match_the_rust_contract_roots() {
    let schema_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/contracts/v0.1");
    let generated = apolysis_contracts::contract_schemas();

    let committed_names: BTreeSet<_> = fs::read_dir(&schema_dir)
        .expect("committed contract schema directory")
        .map(|entry| {
            entry
                .expect("read schema entry")
                .file_name()
                .into_string()
                .expect("UTF-8 schema filename")
        })
        .collect();
    let generated_names: BTreeSet<_> = generated.keys().map(|name| (*name).to_string()).collect();
    assert_eq!(committed_names, generated_names);

    for (filename, schema) in generated {
        let committed: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(schema_dir.join(filename)).expect("read committed schema"),
        )
        .expect("valid committed JSON Schema");
        let generated = serde_json::to_value(schema).expect("serialize generated schema");
        assert_eq!(committed, generated, "schema drift: {filename}");
    }
}

#[test]
fn schemas_preserve_critical_runtime_validation_boundaries() {
    let generated = apolysis_contracts::contract_schemas();
    let source = serde_json::to_value(
        generated
            .get("source-envelope.schema.json")
            .expect("source envelope schema"),
    )
    .expect("serialize source schema");
    assert_eq!(source["additionalProperties"], false);
    assert_eq!(source["properties"]["source_sequence"]["minimum"], 1);
    assert_eq!(source["properties"]["payload_digest"]["minLength"], 64);
    assert_eq!(source["properties"]["payload_digest"]["maxLength"], 64);
    assert_eq!(source["oneOf"].as_array().map(Vec::len), Some(2));

    let ingest = serde_json::to_value(
        generated
            .get("ingest-request.schema.json")
            .expect("ingest request schema"),
    )
    .expect("serialize ingest schema");
    assert_eq!(ingest["properties"]["envelopes"]["minItems"], 1);
    assert_eq!(ingest["properties"]["envelopes"]["maxItems"], 256);
}
