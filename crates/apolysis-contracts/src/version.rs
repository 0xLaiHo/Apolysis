// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Wire schema versions understood by this crate.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub enum SchemaVersion {
    /// Agent Execution Record schema v0.1.
    #[serde(rename = "0.1")]
    V0_1,
}
