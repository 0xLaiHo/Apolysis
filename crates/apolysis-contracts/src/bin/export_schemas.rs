// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("schemas/contracts/v0.1")
    });
    fs::create_dir_all(&output)?;

    for (filename, schema) in apolysis_contracts::contract_schemas() {
        let encoded = format!("{}\n", serde_json::to_string_pretty(&schema)?);
        fs::write(output.join(filename), encoded)?;
    }
    Ok(())
}
