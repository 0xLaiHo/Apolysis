// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const RUNTIME_BINDING_SCHEMA_VERSION: u32 = 1;
pub const MAX_RUNTIME_AGENT_RUN_ID_BYTES: usize = 128;
pub const MAX_RUNTIME_WORKLOAD_ID_BYTES: usize = 256;
pub const MAX_RUNTIME_START_MARKER_BYTES: usize = 128;
pub const MAX_RUNTIME_HANDLER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuntimeBindingRecordType {
    #[serde(rename = "runtime_binding_observed")]
    Observed,
    #[serde(rename = "runtime_binding_retired")]
    Retired,
    #[serde(rename = "runtime_binding_suspended")]
    Suspended,
}

impl RuntimeBindingRecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "runtime_binding_observed",
            Self::Retired => "runtime_binding_retired",
            Self::Suspended => "runtime_binding_suspended",
        }
    }

    pub const fn is_observed(self) -> bool {
        matches!(self, Self::Observed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RuntimeBindingRuntimeHandler(pub Option<String>);

impl<'de> Deserialize<'de> for RuntimeBindingRuntimeHandler {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RuntimeHandlerVisitor;

        impl<'de> Visitor<'de> for RuntimeHandlerVisitor {
            type Value = RuntimeBindingRuntimeHandler;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or null runtime handler")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(RuntimeBindingRuntimeHandler(None))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(RuntimeBindingRuntimeHandler(None))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(RuntimeBindingRuntimeHandler(Some(value.to_string())))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(RuntimeBindingRuntimeHandler(Some(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(RuntimeBindingRuntimeHandler(Some(value)))
            }
        }

        deserializer.deserialize_any(RuntimeHandlerVisitor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingWireV1 {
    pub record_type: RuntimeBindingRecordType,
    pub schema_version: u32,
    pub agent_run_id: String,
    pub adapter: String,
    pub workload_id: String,
    pub start_marker: String,
    pub host_boot_id: String,
    pub init_process_start_time_ticks: u64,
    pub cgroup_device: u64,
    pub cgroup_id: u64,
    pub runtime_handler: RuntimeBindingRuntimeHandler,
}

impl RuntimeBindingWireV1 {
    pub fn validate(&self) -> Result<(), RuntimeBindingWireValidationError> {
        if self.schema_version != RUNTIME_BINDING_SCHEMA_VERSION {
            return Err(RuntimeBindingWireValidationError::UnsupportedSchemaVersion);
        }
        validate_runtime_identifier_segment(
            "agent_run_id",
            &self.agent_run_id,
            MAX_RUNTIME_AGENT_RUN_ID_BYTES,
        )?;
        validate_runtime_workload_identity_v1(
            &self.adapter,
            &self.workload_id,
            &self.start_marker,
        )?;
        if !is_canonical_nonzero_uuid(&self.host_boot_id) {
            return Err(RuntimeBindingWireValidationError::InvalidField {
                field: "host_boot_id",
                reason: "must be a canonical lowercase non-zero UUID",
            });
        }
        validate_nonzero(
            "init_process_start_time_ticks",
            self.init_process_start_time_ticks,
        )?;
        validate_nonzero("cgroup_device", self.cgroup_device)?;
        validate_nonzero("cgroup_id", self.cgroup_id)?;
        if let Some(runtime_handler) = self.runtime_handler.0.as_deref() {
            validate_runtime_identifier_segment(
                "runtime_handler",
                runtime_handler,
                MAX_RUNTIME_HANDLER_BYTES,
            )?;
        }
        Ok(())
    }

    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.agent_run_id == other.agent_run_id
            && self.adapter == other.adapter
            && self.workload_id == other.workload_id
            && self.start_marker == other.start_marker
            && self.host_boot_id == other.host_boot_id
            && self.init_process_start_time_ticks == other.init_process_start_time_ticks
            && self.cgroup_device == other.cgroup_device
            && self.cgroup_id == other.cgroup_id
            && self.runtime_handler == other.runtime_handler
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeBindingWireValidationError {
    UnsupportedSchemaVersion,
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

impl RuntimeBindingWireValidationError {
    pub const fn field(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "schema_version",
            Self::InvalidField { field, .. } => field,
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "must equal the v1 schema version",
            Self::InvalidField { reason, .. } => reason,
        }
    }
}

impl fmt::Display for RuntimeBindingWireValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime_binding_wire_invalid field={} reason={}",
            self.field(),
            self.reason()
        )
    }
}

impl std::error::Error for RuntimeBindingWireValidationError {}

pub fn validate_runtime_container_id_v1(
    container_id: &str,
) -> Result<(), RuntimeBindingWireValidationError> {
    let bytes = container_id.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !bytes.iter().any(|byte| *byte != b'0')
    {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field: "workload_id",
            reason: "must match the adapter-specific runtime identity domain",
        });
    }
    Ok(())
}

pub fn validate_runtime_workload_identity_v1(
    adapter: &str,
    workload_id: &str,
    start_marker: &str,
) -> Result<(), RuntimeBindingWireValidationError> {
    validate_bounded_text("workload_id", workload_id, MAX_RUNTIME_WORKLOAD_ID_BYTES)?;
    validate_bounded_text("start_marker", start_marker, MAX_RUNTIME_START_MARKER_BYTES)?;
    let container_id = match adapter {
        "docker" => workload_id,
        "containerd" => workload_id.strip_prefix("containerd/").ok_or(
            RuntimeBindingWireValidationError::InvalidField {
                field: "workload_id",
                reason: "must match the adapter-specific runtime identity domain",
            },
        )?,
        "k3s_containerd" => workload_id.strip_prefix("k3s_containerd/").ok_or(
            RuntimeBindingWireValidationError::InvalidField {
                field: "workload_id",
                reason: "must match the adapter-specific runtime identity domain",
            },
        )?,
        _ => {
            return Err(RuntimeBindingWireValidationError::InvalidField {
                field: "adapter",
                reason: "must be a supported runtime adapter",
            });
        }
    };
    validate_runtime_container_id_v1(container_id)?;
    match adapter {
        "docker" => validate_runtime_docker_start_marker_v1(start_marker),
        "containerd" | "k3s_containerd" => validate_runtime_cri_start_marker_v1(start_marker),
        _ => unreachable!("adapter domain was validated above"),
    }
}

pub fn validate_runtime_cri_start_marker_v1(
    start_marker: &str,
) -> Result<(), RuntimeBindingWireValidationError> {
    if start_marker.is_empty()
        || start_marker.len() > MAX_RUNTIME_START_MARKER_BYTES
        || start_marker.starts_with('0')
        || !start_marker.bytes().all(|byte| byte.is_ascii_digit())
        || start_marker
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field: "start_marker",
            reason: "must be a canonical positive decimal CRI startedAt marker",
        });
    }
    Ok(())
}

pub fn validate_runtime_docker_start_marker_v1(
    start_marker: &str,
) -> Result<(), RuntimeBindingWireValidationError> {
    if !valid_docker_started_at(start_marker) {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field: "start_marker",
            reason: "must be a canonical Docker StartedAt timestamp",
        });
    }
    Ok(())
}

fn validate_runtime_identifier_segment(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RuntimeBindingWireValidationError> {
    validate_bounded_text(field, value, maximum)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field,
            reason: "must contain only ASCII alphanumeric, '.', '_', or '-'",
        });
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RuntimeBindingWireValidationError> {
    if value.is_empty() || value.trim() != value {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field,
            reason: "must be non-empty without surrounding whitespace",
        });
    }
    if value.len() > maximum {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field,
            reason: "exceeds the byte limit",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn validate_nonzero(
    field: &'static str,
    value: u64,
) -> Result<(), RuntimeBindingWireValidationError> {
    if value == 0 {
        return Err(RuntimeBindingWireValidationError::InvalidField {
            field,
            reason: "must be non-zero",
        });
    }
    Ok(())
}

fn is_canonical_nonzero_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let mut non_zero = false;
    for (index, byte) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return false;
        } else if byte != b'0' {
            non_zero = true;
        }
    }
    non_zero
}

fn valid_docker_started_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    let fraction_digits = match bytes.len() {
        20 if bytes[19] == b'Z' => 0,
        22..=30 if bytes[19] == b'.' && bytes[bytes.len() - 1] == b'Z' => bytes.len() - 21,
        _ => return false,
    };
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
        || (fraction_digits > 0
            && !bytes[20..20 + fraction_digits]
                .iter()
                .all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1970 && (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}
