// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use apolysis_accountability::AdapterKind;
use apolysis_core::{
    validate_runtime_container_id_v1, validate_runtime_cri_start_marker_v1,
    validate_runtime_docker_start_marker_v1, validate_runtime_workload_identity_v1,
    RuntimeBindingRecordType, RuntimeBindingRuntimeHandler, RuntimeBindingWireV1,
    RuntimeBindingWireValidationError, RUNTIME_BINDING_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};

pub const MAX_RUNTIME_INVENTORY_BINDINGS: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CgroupIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RuntimeWorkloadIdentity {
    pub adapter: AdapterKind,
    pub workload_id: String,
    pub start_marker: String,
    pub host_boot_id: String,
    pub init_process_start_time_ticks: u64,
    pub cgroup: CgroupIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeBinding {
    pub agent_run_id: String,
    pub identity: RuntimeWorkloadIdentity,
    pub runtime_handler: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInventory {
    pub adapter: AdapterKind,
    pub bindings: Vec<RuntimeBinding>,
}

impl RuntimeInventory {
    pub fn new(adapter: AdapterKind, bindings: Vec<RuntimeBinding>) -> Self {
        Self { adapter, bindings }
    }
}

impl RuntimeBinding {
    pub(crate) fn validate(&self) -> Result<(), RuntimeBindingError> {
        validate_binding(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeBindingGapKind {
    RuntimeSourceUnavailable,
    IdentityTransition,
    DaemonRestart,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeBindingEffect {
    PersistGap {
        binding: RuntimeBinding,
        kind: RuntimeBindingGapKind,
    },
    Suspend {
        binding: RuntimeBinding,
    },
    Retire {
        binding: RuntimeBinding,
    },
    RetireDormant {
        binding: RuntimeBinding,
    },
    Attach {
        binding: RuntimeBinding,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeBindingSummary {
    pub gaps: usize,
    pub suspended: usize,
    pub retired: usize,
    pub attached: usize,
    pub unchanged: usize,
    pub missing_intent: usize,
    pub active: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeBindingReconcile {
    pub effects: Vec<RuntimeBindingEffect>,
    pub summary: RuntimeBindingSummary,
}

impl RuntimeBindingReconcile {
    pub(crate) fn from_effects(effects: Vec<RuntimeBindingEffect>, active: usize) -> Self {
        let mut summary = RuntimeBindingSummary {
            active,
            ..RuntimeBindingSummary::default()
        };
        for effect in &effects {
            match effect {
                RuntimeBindingEffect::PersistGap { .. } => summary.gaps += 1,
                RuntimeBindingEffect::Suspend { .. } => summary.suspended += 1,
                RuntimeBindingEffect::Retire { .. }
                | RuntimeBindingEffect::RetireDormant { .. } => summary.retired += 1,
                RuntimeBindingEffect::Attach { .. } => summary.attached += 1,
            }
        }
        Self { effects, summary }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RuntimeBindingError {
    UnsupportedAdapter(AdapterKind),
    InventoryTooLarge {
        actual: usize,
        maximum: usize,
    },
    AdapterMismatch {
        inventory: AdapterKind,
        binding: AdapterKind,
    },
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    DuplicateWorkloadKey {
        adapter: AdapterKind,
        workload_id: String,
    },
    CgroupConflict {
        cgroup: CgroupIdentity,
    },
}

impl fmt::Display for RuntimeBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAdapter(adapter) => write!(
                formatter,
                "runtime_binding_invalid code=unsupported_adapter adapter={}",
                adapter_code(*adapter)
            ),
            Self::InventoryTooLarge { actual, maximum } => write!(
                formatter,
                "runtime_binding_invalid code=inventory_too_large actual={actual} maximum={maximum}"
            ),
            Self::AdapterMismatch { inventory, binding } => write!(
                formatter,
                "runtime_binding_invalid code=adapter_mismatch inventory_adapter={} binding_adapter={}",
                adapter_code(*inventory),
                adapter_code(*binding)
            ),
            Self::InvalidField { field, reason } => write!(
                formatter,
                "runtime_binding_invalid code=invalid_field field={field} reason={reason}"
            ),
            Self::DuplicateWorkloadKey { adapter, .. } => write!(
                formatter,
                "runtime_binding_invalid code=duplicate_workload_key adapter={}",
                adapter_code(*adapter)
            ),
            Self::CgroupConflict { .. } => {
                formatter.write_str("runtime_binding_invalid code=cgroup_conflict")
            }
        }
    }
}

impl fmt::Debug for RuntimeBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for RuntimeBindingError {}

const fn adapter_code(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Docker => "docker",
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s_containerd",
        AdapterKind::Kubernetes => "kubernetes",
    }
}

fn runtime_binding_wire_error(error: RuntimeBindingWireValidationError) -> RuntimeBindingError {
    let field = match error.field() {
        "cgroup_device" => "cgroup.device",
        "cgroup_id" => "cgroup.inode",
        field => field,
    };
    let reason = match field {
        // Preserve the established daemon-domain diagnostic while the shared
        // wire validator keeps the stricter non-zero wording.
        "host_boot_id" => "must be a canonical lowercase UUID",
        _ => error.reason(),
    };
    RuntimeBindingError::InvalidField { field, reason }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimeWorkloadKey {
    adapter: AdapterKind,
    workload_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeBindingCoordinator {
    active: BTreeMap<RuntimeWorkloadKey, RuntimeBinding>,
    dormant: BTreeMap<RuntimeWorkloadKey, RuntimeBinding>,
    unavailable: BTreeSet<AdapterKind>,
}

impl RuntimeBindingCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recover_dormant(bindings: Vec<RuntimeBinding>) -> Result<Self, RuntimeBindingError> {
        if bindings.len() > MAX_RUNTIME_INVENTORY_BINDINGS {
            return Err(RuntimeBindingError::InventoryTooLarge {
                actual: bindings.len(),
                maximum: MAX_RUNTIME_INVENTORY_BINDINGS,
            });
        }
        let mut dormant = BTreeMap::new();
        let mut cgroups = BTreeSet::new();
        for binding in bindings {
            validate_binding(&binding)?;
            let key = RuntimeWorkloadKey::from_binding(&binding);
            if dormant.contains_key(&key) {
                return Err(RuntimeBindingError::DuplicateWorkloadKey {
                    adapter: key.adapter,
                    workload_id: key.workload_id,
                });
            }
            if !cgroups.insert(binding.identity.cgroup.inode) {
                return Err(RuntimeBindingError::CgroupConflict {
                    cgroup: binding.identity.cgroup,
                });
            }
            dormant.insert(key, binding);
        }
        Ok(Self {
            dormant,
            ..Self::default()
        })
    }

    pub fn reconcile(
        &mut self,
        inventory: RuntimeInventory,
    ) -> Result<RuntimeBindingReconcile, RuntimeBindingError> {
        let incoming = validate_inventory(&inventory, &self.active)?;
        self.unavailable.remove(&inventory.adapter);
        let dormant_keys = self
            .dormant
            .keys()
            .filter(|key| key.adapter == inventory.adapter)
            .cloned()
            .collect::<Vec<_>>();
        let mut gaps = Vec::with_capacity(dormant_keys.len());
        let mut recovered = Vec::with_capacity(dormant_keys.len());
        for key in dormant_keys {
            if let Some(binding) = self.dormant.remove(&key) {
                gaps.push(RuntimeBindingEffect::PersistGap {
                    binding: binding.clone(),
                    kind: RuntimeBindingGapKind::DaemonRestart,
                });
                recovered.push(binding);
            }
        }
        let mut retires = recovered
            .into_iter()
            .map(|binding| RuntimeBindingEffect::RetireDormant { binding })
            .collect::<Vec<_>>();
        let mut attaches = Vec::new();
        let mut unchanged = 0;
        let absent: Vec<_> = self
            .active
            .keys()
            .filter(|key| key.adapter == inventory.adapter && !incoming.contains_key(*key))
            .cloned()
            .collect();
        for key in absent {
            if let Some(binding) = self.active.remove(&key) {
                retires.push(RuntimeBindingEffect::Retire { binding });
            }
        }
        for (key, binding) in incoming {
            if self.active.get(&key) == Some(&binding) {
                unchanged += 1;
                continue;
            }
            if let Some(previous) = self.active.remove(&key) {
                if previous.identity != binding.identity
                    || previous.agent_run_id != binding.agent_run_id
                {
                    gaps.push(RuntimeBindingEffect::PersistGap {
                        binding: previous.clone(),
                        kind: RuntimeBindingGapKind::IdentityTransition,
                    });
                }
                retires.push(RuntimeBindingEffect::Retire { binding: previous });
            }
            attaches.push(RuntimeBindingEffect::Attach {
                binding: binding.clone(),
            });
            self.active.insert(key, binding);
        }
        let effects = gaps.into_iter().chain(retires).chain(attaches).collect();
        Ok(reconcile_result(effects, unchanged, self.active.len()))
    }

    pub fn source_unavailable(
        &mut self,
        adapter: AdapterKind,
    ) -> Result<RuntimeBindingReconcile, RuntimeBindingError> {
        validate_adapter(adapter)?;
        if !self.unavailable.insert(adapter) {
            return Ok(reconcile_result(Vec::new(), 0, self.active.len()));
        }
        let keys: Vec<_> = self
            .active
            .keys()
            .filter(|key| key.adapter == adapter)
            .cloned()
            .collect();
        let bindings: Vec<_> = keys
            .iter()
            .filter_map(|key| self.active.get(key).cloned())
            .collect();
        let mut effects = bindings
            .iter()
            .cloned()
            .map(|binding| RuntimeBindingEffect::PersistGap {
                binding,
                kind: RuntimeBindingGapKind::RuntimeSourceUnavailable,
            })
            .collect::<Vec<_>>();
        for key in keys {
            self.active.remove(&key);
        }
        effects.extend(
            bindings
                .into_iter()
                .map(|binding| RuntimeBindingEffect::Suspend { binding }),
        );
        Ok(reconcile_result(effects, 0, self.active.len()))
    }

    pub fn retire_agent_run(&mut self, agent_run_id: &str) -> RuntimeBindingReconcile {
        let active_keys: Vec<_> = self
            .active
            .iter()
            .filter(|(_, binding)| binding.agent_run_id == agent_run_id)
            .map(|(key, _)| key.clone())
            .collect();
        let dormant_keys: Vec<_> = self
            .dormant
            .iter()
            .filter(|(_, binding)| binding.agent_run_id == agent_run_id)
            .map(|(key, _)| key.clone())
            .collect();
        let mut retired = BTreeMap::new();
        for key in active_keys {
            if let Some(binding) = self.active.remove(&key) {
                retired.insert(key, binding);
            }
        }
        for key in dormant_keys {
            if let Some(binding) = self.dormant.remove(&key) {
                retired.insert(key, binding);
            }
        }
        let effects = retired
            .into_values()
            .map(|binding| RuntimeBindingEffect::Retire { binding })
            .collect();
        reconcile_result(effects, 0, self.active.len())
    }

    pub fn bindings_for_agent_run(&self, agent_run_id: &str) -> Vec<RuntimeBinding> {
        self.active
            .values()
            .filter(|binding| binding.agent_run_id == agent_run_id)
            .cloned()
            .collect()
    }
}

impl RuntimeWorkloadKey {
    fn from_binding(binding: &RuntimeBinding) -> Self {
        Self {
            adapter: binding.identity.adapter,
            workload_id: binding.identity.workload_id.clone(),
        }
    }
}

fn reconcile_result(
    effects: Vec<RuntimeBindingEffect>,
    unchanged: usize,
    active: usize,
) -> RuntimeBindingReconcile {
    let mut reconciliation = RuntimeBindingReconcile::from_effects(effects, active);
    reconciliation.summary.unchanged = unchanged;
    reconciliation
}

fn validate_inventory(
    inventory: &RuntimeInventory,
    active: &BTreeMap<RuntimeWorkloadKey, RuntimeBinding>,
) -> Result<BTreeMap<RuntimeWorkloadKey, RuntimeBinding>, RuntimeBindingError> {
    validate_adapter(inventory.adapter)?;
    if inventory.bindings.len() > MAX_RUNTIME_INVENTORY_BINDINGS {
        return Err(RuntimeBindingError::InventoryTooLarge {
            actual: inventory.bindings.len(),
            maximum: MAX_RUNTIME_INVENTORY_BINDINGS,
        });
    }

    let other_source_cgroups: BTreeSet<_> = active
        .values()
        .filter(|binding| binding.identity.adapter != inventory.adapter)
        .map(|binding| binding.identity.cgroup.inode)
        .collect();
    let mut incoming = BTreeMap::new();
    let mut cgroups = BTreeSet::new();
    for binding in &inventory.bindings {
        validate_binding(binding)?;
        if binding.identity.adapter != inventory.adapter {
            return Err(RuntimeBindingError::AdapterMismatch {
                inventory: inventory.adapter,
                binding: binding.identity.adapter,
            });
        }
        let key = RuntimeWorkloadKey::from_binding(binding);
        if incoming.contains_key(&key) {
            return Err(RuntimeBindingError::DuplicateWorkloadKey {
                adapter: key.adapter,
                workload_id: key.workload_id,
            });
        }
        if !cgroups.insert(binding.identity.cgroup.inode)
            || other_source_cgroups.contains(&binding.identity.cgroup.inode)
        {
            return Err(RuntimeBindingError::CgroupConflict {
                cgroup: binding.identity.cgroup,
            });
        }
        incoming.insert(key, binding.clone());
    }
    Ok(incoming)
}

fn validate_binding(binding: &RuntimeBinding) -> Result<(), RuntimeBindingError> {
    validate_adapter(binding.identity.adapter)?;
    RuntimeBindingWireV1 {
        record_type: RuntimeBindingRecordType::Observed,
        schema_version: RUNTIME_BINDING_SCHEMA_VERSION,
        agent_run_id: binding.agent_run_id.clone(),
        adapter: adapter_code(binding.identity.adapter).to_string(),
        workload_id: binding.identity.workload_id.clone(),
        start_marker: binding.identity.start_marker.clone(),
        host_boot_id: binding.identity.host_boot_id.clone(),
        init_process_start_time_ticks: binding.identity.init_process_start_time_ticks,
        cgroup_device: binding.identity.cgroup.device,
        cgroup_id: binding.identity.cgroup.inode,
        runtime_handler: RuntimeBindingRuntimeHandler(binding.runtime_handler.clone()),
    }
    .validate()
    .map_err(runtime_binding_wire_error)
}

pub(crate) fn validate_runtime_container_id(container_id: &str) -> Result<(), RuntimeBindingError> {
    validate_runtime_container_id_v1(container_id).map_err(runtime_binding_wire_error)
}

pub(crate) fn validate_runtime_workload_identity(
    adapter: AdapterKind,
    workload_id: &str,
    start_marker: &str,
) -> Result<(), RuntimeBindingError> {
    validate_adapter(adapter)?;
    validate_runtime_workload_identity_v1(adapter_code(adapter), workload_id, start_marker)
        .map_err(runtime_binding_wire_error)
}

pub(crate) fn validate_cri_start_marker(start_marker: &str) -> Result<(), RuntimeBindingError> {
    validate_runtime_cri_start_marker_v1(start_marker).map_err(runtime_binding_wire_error)
}

pub(crate) fn canonical_cri_rfc3339_to_unix_nanos(start_marker: &str) -> Option<u64> {
    let bytes = start_marker.as_bytes();
    let (timestamp, offset) = if bytes.last() == Some(&b'Z') {
        (
            parse_canonical_rfc3339_date_time(&bytes[..bytes.len() - 1]).ok()?,
            None,
        )
    } else {
        let (timestamp, offset) = parse_canonical_rfc3339_numeric_offset(bytes).ok()?;
        (timestamp, Some(offset))
    };
    let local_nanos = rfc3339_timestamp_to_unix_nanos(timestamp)?;
    let utc_nanos = match offset {
        None => local_nanos,
        Some(offset) if offset.east_of_utc => local_nanos.checked_sub(offset.nanoseconds)?,
        Some(offset) => local_nanos.checked_add(offset.nanoseconds)?,
    };
    u64::try_from(utc_nanos).ok().filter(|value| *value > 0)
}

fn rfc3339_timestamp_to_unix_nanos(timestamp: CanonicalRfc3339Timestamp) -> Option<u128> {
    let mut days =
        u128::from(days_before_year(timestamp.year).checked_sub(days_before_year(1970))?);
    for month in 1..timestamp.month {
        days = days.checked_add(u128::from(days_in_month(timestamp.year, month)?))?;
    }
    days = days.checked_add(u128::from(timestamp.day - 1))?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(u128::from(timestamp.hour).checked_mul(3_600)?)?
        .checked_add(u128::from(timestamp.minute).checked_mul(60)?)?
        .checked_add(u128::from(timestamp.second))?;
    seconds
        .checked_mul(1_000_000_000)?
        .checked_add(u128::from(timestamp.nanosecond))
}

pub(crate) fn validate_docker_start_marker(start_marker: &str) -> Result<(), RuntimeBindingError> {
    validate_runtime_docker_start_marker_v1(start_marker).map_err(runtime_binding_wire_error)
}

#[derive(Clone, Copy)]
struct CanonicalRfc3339Timestamp {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanosecond: u32,
}

#[derive(Clone, Copy)]
struct CanonicalRfc3339NumericOffset {
    east_of_utc: bool,
    nanoseconds: u128,
}

fn parse_canonical_rfc3339_numeric_offset(
    bytes: &[u8],
) -> Result<(CanonicalRfc3339Timestamp, CanonicalRfc3339NumericOffset), RuntimeBindingError> {
    let offset_start = bytes
        .len()
        .checked_sub(6)
        .ok_or_else(invalid_utc_start_marker)?;
    let east_of_utc = match bytes[offset_start] {
        b'+' => true,
        b'-' => false,
        _ => return Err(invalid_utc_start_marker()),
    };
    if bytes[offset_start + 3] != b':'
        || !bytes[offset_start + 1..offset_start + 3]
            .iter()
            .all(u8::is_ascii_digit)
        || !bytes[offset_start + 4..offset_start + 6]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(invalid_utc_start_marker());
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    let hour = number(offset_start + 1..offset_start + 3).ok_or_else(invalid_utc_start_marker)?;
    let minute = number(offset_start + 4..offset_start + 6).ok_or_else(invalid_utc_start_marker)?;
    let seconds = hour
        .checked_mul(3_600)
        .and_then(|value| value.checked_add(minute.checked_mul(60)?))
        .filter(|_| hour <= 23 && minute <= 59)
        // `Z` is the only canonical UTC spelling; `-00:00` is also RFC3339's
        // unknown-local-offset sentinel, so neither signed zero is accepted.
        .filter(|value| *value > 0)
        .ok_or_else(invalid_utc_start_marker)?;
    Ok((
        parse_canonical_rfc3339_date_time(&bytes[..offset_start])?,
        CanonicalRfc3339NumericOffset {
            east_of_utc,
            nanoseconds: u128::from(seconds)
                .checked_mul(1_000_000_000)
                .ok_or_else(invalid_utc_start_marker)?,
        },
    ))
}

fn parse_canonical_rfc3339_date_time(
    bytes: &[u8],
) -> Result<CanonicalRfc3339Timestamp, RuntimeBindingError> {
    let fraction_digits = match bytes.len() {
        19 => 0,
        21..=29 if bytes[19] == b'.' => bytes.len() - 20,
        _ => return Err(invalid_utc_start_marker()),
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
        return Err(invalid_utc_start_marker());
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
        return Err(invalid_utc_start_marker());
    };
    let Some(days_in_month) = days_in_month(year, month) else {
        return Err(invalid_utc_start_marker());
    };
    if year < 1970 || !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59
    {
        return Err(invalid_utc_start_marker());
    }
    let nanosecond = if fraction_digits == 0 {
        0
    } else {
        number(20..20 + fraction_digits)
            .ok_or_else(invalid_utc_start_marker)?
            .checked_mul(10_u32.pow((9 - fraction_digits) as u32))
            .ok_or_else(invalid_utc_start_marker)?
    };
    Ok(CanonicalRfc3339Timestamp {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanosecond,
    })
}

const fn invalid_utc_start_marker() -> RuntimeBindingError {
    RuntimeBindingError::InvalidField {
        field: "start_marker",
        reason: "must be a canonical UTC RFC3339 timestamp",
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_before_year(year: u32) -> u64 {
    let years = (year.saturating_sub(1)) as u64;
    years * 365 + years / 4 - years / 100 + years / 400
}

const fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn validate_adapter(adapter: AdapterKind) -> Result<(), RuntimeBindingError> {
    match adapter {
        AdapterKind::Docker | AdapterKind::Containerd | AdapterKind::K3sContainerd => Ok(()),
        AdapterKind::Kubernetes => Err(RuntimeBindingError::UnsupportedAdapter(adapter)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_ID: &str = "82b46386-b87a-4d86-93f6-232bb04c37fb";

    fn binding(adapter: AdapterKind, workload_id: &str, inode: u64) -> RuntimeBinding {
        let container_id = match workload_id {
            "container-a" => "a".repeat(64),
            "container-b" => "b".repeat(64),
            "container-c" => "c".repeat(64),
            value => value.to_string(),
        };
        let workload_id = match adapter {
            AdapterKind::Docker => container_id,
            AdapterKind::Containerd if container_id.starts_with("containerd/") => container_id,
            AdapterKind::Containerd => format!("containerd/{container_id}"),
            AdapterKind::K3sContainerd if container_id.starts_with("k3s_containerd/") => {
                container_id
            }
            AdapterKind::K3sContainerd => format!("k3s_containerd/{container_id}"),
            AdapterKind::Kubernetes => container_id,
        };
        RuntimeBinding {
            agent_run_id: "agent-run-1".to_string(),
            identity: RuntimeWorkloadIdentity {
                adapter,
                workload_id,
                start_marker: if adapter == AdapterKind::Docker {
                    "2026-08-11T01:02:03.000000000Z".to_string()
                } else {
                    "42".to_string()
                },
                host_boot_id: BOOT_ID.to_string(),
                init_process_start_time_ticks: 42,
                cgroup: CgroupIdentity { device: 7, inode },
            },
            runtime_handler: Some("runc".to_string()),
        }
    }

    fn qualified_binding(adapter: AdapterKind, id_digit: char, inode: u64) -> RuntimeBinding {
        let container_id = id_digit.to_string().repeat(64);
        let workload_id = match adapter {
            AdapterKind::Docker => container_id,
            AdapterKind::Containerd => format!("containerd/{container_id}"),
            AdapterKind::K3sContainerd => format!("k3s_containerd/{container_id}"),
            AdapterKind::Kubernetes => container_id,
        };
        let mut binding = binding(adapter, &workload_id, inode);
        if matches!(
            adapter,
            AdapterKind::Containerd | AdapterKind::K3sContainerd
        ) {
            binding.identity.start_marker = "42".to_string();
        }
        binding
    }

    #[test]
    fn complete_inventory_attaches_a_fresh_runtime_binding() {
        let expected = binding(AdapterKind::Docker, "container-a", 100);
        let mut coordinator = RuntimeBindingCoordinator::new();

        let result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![expected.clone()],
            ))
            .unwrap();

        assert_eq!(
            result.effects,
            vec![RuntimeBindingEffect::Attach {
                binding: expected.clone()
            }]
        );
        assert_eq!(result.summary.attached, 1);
        assert_eq!(result.summary.active, 1);
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![expected]
        );
    }

    #[test]
    fn identical_complete_inventory_is_a_no_op() {
        let current = binding(AdapterKind::Docker, "container-a", 100);
        let inventory = || RuntimeInventory::new(AdapterKind::Docker, vec![current.clone()]);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator.reconcile(inventory()).unwrap();

        let result = coordinator.reconcile(inventory()).unwrap();

        assert!(result.effects.is_empty());
        assert_eq!(result.summary.unchanged, 1);
        assert_eq!(result.summary.active, 1);
    }

    #[test]
    fn successful_complete_inventory_retires_absent_binding() {
        let current = binding(AdapterKind::Docker, "container-a", 100);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .unwrap();

        let result = coordinator
            .reconcile(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
            .unwrap();

        assert_eq!(
            result.effects,
            vec![RuntimeBindingEffect::Retire { binding: current }]
        );
        assert_eq!(result.summary.retired, 1);
        assert_eq!(result.summary.active, 0);
        assert!(coordinator.bindings_for_agent_run("agent-run-1").is_empty());
    }

    #[test]
    fn changed_stable_proof_is_an_ordered_identity_transition() {
        let old = binding(AdapterKind::Docker, "container-a", 100);
        let mut replacement = binding(AdapterKind::Docker, "container-a", 200);
        replacement.identity.start_marker = "2026-08-11T02:03:04.000000000Z".to_string();
        replacement.identity.init_process_start_time_ticks = 84;
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![old.clone()],
            ))
            .unwrap();

        let result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![replacement.clone()],
            ))
            .unwrap();

        assert_eq!(
            result.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: old.clone(),
                    kind: RuntimeBindingGapKind::IdentityTransition,
                },
                RuntimeBindingEffect::Retire { binding: old },
                RuntimeBindingEffect::Attach {
                    binding: replacement.clone(),
                },
            ]
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![replacement]
        );
    }

    #[test]
    fn changed_agent_run_ownership_is_an_identity_transition_even_when_proof_is_identical() {
        let original = binding(AdapterKind::Docker, "container-a", 100);
        let mut replacement = original.clone();
        replacement.agent_run_id = "agent-run-2".to_string();
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![original.clone()],
            ))
            .unwrap();

        let result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![replacement.clone()],
            ))
            .unwrap();

        assert_eq!(
            result.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: original.clone(),
                    kind: RuntimeBindingGapKind::IdentityTransition,
                },
                RuntimeBindingEffect::Retire { binding: original },
                RuntimeBindingEffect::Attach {
                    binding: replacement.clone(),
                },
            ]
        );
        assert!(coordinator.bindings_for_agent_run("agent-run-1").is_empty());
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-2"),
            vec![replacement]
        );
    }

    #[test]
    fn invalid_inventory_is_rejected_before_active_state_changes() {
        let current = binding(AdapterKind::Docker, "container-a", 100);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .unwrap();
        let mut invalid = binding(AdapterKind::Docker, "container-b", 200);
        invalid.identity.host_boot_id = "not-a-boot-uuid".to_string();

        assert_eq!(
            coordinator.reconcile(RuntimeInventory::new(AdapterKind::Docker, vec![invalid])),
            Err(RuntimeBindingError::InvalidField {
                field: "host_boot_id",
                reason: "must be a canonical lowercase UUID",
            })
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![current]
        );
        assert_eq!(
            coordinator.reconcile(RuntimeInventory::new(AdapterKind::Kubernetes, Vec::new())),
            Err(RuntimeBindingError::UnsupportedAdapter(
                AdapterKind::Kubernetes
            ))
        );
    }

    #[test]
    fn complete_inventory_rejects_workload_ids_outside_the_adapter_domain() {
        let cases = [
            (
                AdapterKind::Docker,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            (
                AdapterKind::Docker,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                AdapterKind::Containerd,
                "docker/1111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                AdapterKind::K3sContainerd,
                "containerd/2222222222222222222222222222222222222222222222222222222222222222",
            ),
        ];

        for (adapter, workload_id) in cases {
            let mut invalid = qualified_binding(adapter, '1', 100);
            invalid.identity.workload_id = workload_id.to_string();
            let mut coordinator = RuntimeBindingCoordinator::new();

            assert_eq!(
                coordinator.reconcile(RuntimeInventory::new(adapter, vec![invalid])),
                Err(RuntimeBindingError::InvalidField {
                    field: "workload_id",
                    reason: "must match the adapter-specific runtime identity domain",
                })
            );
            assert!(coordinator.active.is_empty());
        }
    }

    #[test]
    fn complete_docker_inventory_rejects_noncanonical_started_at_markers() {
        for start_marker in [
            "0001-01-01T00:00:00Z",
            "2026-02-30T01:02:03Z",
            "2026-08-11 01:02:03Z",
            "2026-08-11T01:02:03+00:00",
            "2026-08-11T01:02:03.1234567890Z",
        ] {
            let mut invalid = qualified_binding(AdapterKind::Docker, '1', 100);
            invalid.identity.start_marker = start_marker.to_string();
            let mut coordinator = RuntimeBindingCoordinator::new();

            assert_eq!(
                coordinator.reconcile(RuntimeInventory::new(AdapterKind::Docker, vec![invalid])),
                Err(RuntimeBindingError::InvalidField {
                    field: "start_marker",
                    reason: "must be a canonical Docker StartedAt timestamp",
                })
            );
        }
    }

    #[test]
    fn complete_cri_inventory_rejects_noncanonical_started_at_markers() {
        for adapter in [AdapterKind::Containerd, AdapterKind::K3sContainerd] {
            for start_marker in ["0", "01", "+1", "1.0", "18446744073709551616"] {
                let mut invalid = qualified_binding(adapter, '1', 100);
                invalid.identity.start_marker = start_marker.to_string();
                let mut coordinator = RuntimeBindingCoordinator::new();

                assert_eq!(
                    coordinator.reconcile(RuntimeInventory::new(adapter, vec![invalid])),
                    Err(RuntimeBindingError::InvalidField {
                        field: "start_marker",
                        reason: "must be a canonical positive decimal CRI startedAt marker",
                    })
                );
            }
        }
    }

    #[test]
    fn first_source_outage_gaps_then_suspends_without_retiring() {
        let first = binding(AdapterKind::Docker, "container-a", 100);
        let second = binding(AdapterKind::Docker, "container-b", 200);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![second.clone(), first.clone()],
            ))
            .unwrap();

        let result = coordinator.source_unavailable(AdapterKind::Docker).unwrap();

        assert_eq!(
            result.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: first.clone(),
                    kind: RuntimeBindingGapKind::RuntimeSourceUnavailable,
                },
                RuntimeBindingEffect::PersistGap {
                    binding: second.clone(),
                    kind: RuntimeBindingGapKind::RuntimeSourceUnavailable,
                },
                RuntimeBindingEffect::Suspend { binding: first },
                RuntimeBindingEffect::Suspend { binding: second },
            ]
        );
        assert_eq!(result.summary.gaps, 2);
        assert_eq!(result.summary.suspended, 2);
        assert_eq!(result.summary.retired, 0);
        assert!(coordinator.bindings_for_agent_run("agent-run-1").is_empty());

        let repeated = coordinator.source_unavailable(AdapterKind::Docker).unwrap();
        assert!(repeated.effects.is_empty());
        assert_eq!(repeated.summary.active, 0);
    }

    #[test]
    fn recovered_binding_stays_dormant_until_fresh_inventory() {
        let recovered = binding(AdapterKind::Containerd, "container-a", 100);
        let mut coordinator =
            RuntimeBindingCoordinator::recover_dormant(vec![recovered.clone()]).unwrap();

        assert!(coordinator.bindings_for_agent_run("agent-run-1").is_empty());

        let result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![recovered.clone()],
            ))
            .unwrap();

        assert_eq!(
            result.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: recovered.clone(),
                    kind: RuntimeBindingGapKind::DaemonRestart,
                },
                RuntimeBindingEffect::RetireDormant {
                    binding: recovered.clone(),
                },
                RuntimeBindingEffect::Attach {
                    binding: recovered.clone(),
                },
            ]
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![recovered]
        );
    }

    #[test]
    fn each_runtime_source_revalidates_only_its_own_dormant_bindings() {
        let docker = qualified_binding(AdapterKind::Docker, 'a', 100);
        let containerd = qualified_binding(AdapterKind::Containerd, 'b', 200);
        let mut coordinator =
            RuntimeBindingCoordinator::recover_dormant(vec![containerd.clone(), docker.clone()])
                .unwrap();

        let docker_result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![docker.clone()],
            ))
            .unwrap();
        assert_eq!(docker_result.summary.gaps, 1);
        assert_eq!(docker_result.summary.attached, 1);

        let containerd_result = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![containerd.clone()],
            ))
            .unwrap();
        assert_eq!(
            containerd_result.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: containerd.clone(),
                    kind: RuntimeBindingGapKind::DaemonRestart,
                },
                RuntimeBindingEffect::RetireDormant {
                    binding: containerd.clone(),
                },
                RuntimeBindingEffect::Attach {
                    binding: containerd,
                },
            ]
        );
    }

    #[test]
    fn fresh_inventory_retires_a_dormant_binding_that_is_now_absent() {
        let dormant = binding(AdapterKind::Docker, "container-a", 100);
        let mut coordinator =
            RuntimeBindingCoordinator::recover_dormant(vec![dormant.clone()]).unwrap();

        let absent = coordinator
            .reconcile(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
            .unwrap();

        assert_eq!(
            absent.effects,
            vec![
                RuntimeBindingEffect::PersistGap {
                    binding: dormant.clone(),
                    kind: RuntimeBindingGapKind::DaemonRestart,
                },
                RuntimeBindingEffect::RetireDormant {
                    binding: dormant.clone(),
                },
            ]
        );
        let later = coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![dormant.clone()],
            ))
            .unwrap();
        assert_eq!(
            later.effects,
            vec![RuntimeBindingEffect::Attach { binding: dormant }]
        );
    }

    #[test]
    fn closing_an_agent_run_retires_only_its_bindings_and_is_idempotent() {
        let run_one = binding(AdapterKind::Docker, "container-a", 100);
        let mut run_two = binding(AdapterKind::Docker, "container-b", 200);
        run_two.agent_run_id = "agent-run-2".to_string();
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![run_two.clone(), run_one.clone()],
            ))
            .unwrap();

        let result = coordinator.retire_agent_run("agent-run-1");

        assert_eq!(
            result.effects,
            vec![RuntimeBindingEffect::Retire { binding: run_one }]
        );
        assert_eq!(result.summary.active, 1);
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-2"),
            vec![run_two]
        );
        assert!(coordinator
            .retire_agent_run("agent-run-1")
            .effects
            .is_empty());
    }

    #[test]
    fn conflicting_complete_inventory_fails_atomically() {
        let current = binding(AdapterKind::Docker, "container-a", 100);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .unwrap();

        let duplicate_key = vec![
            binding(AdapterKind::Docker, "container-b", 200),
            binding(AdapterKind::Docker, "container-b", 300),
        ];
        assert_eq!(
            coordinator.reconcile(RuntimeInventory::new(AdapterKind::Docker, duplicate_key)),
            Err(RuntimeBindingError::DuplicateWorkloadKey {
                adapter: AdapterKind::Docker,
                workload_id: "b".repeat(64),
            })
        );

        let cgroup_conflict = vec![
            binding(AdapterKind::Docker, "container-b", 200),
            binding(AdapterKind::Docker, "container-c", 200),
        ];
        assert_eq!(
            coordinator.reconcile(RuntimeInventory::new(AdapterKind::Docker, cgroup_conflict)),
            Err(RuntimeBindingError::CgroupConflict {
                cgroup: CgroupIdentity {
                    device: 7,
                    inode: 200,
                },
            })
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![current]
        );
    }

    #[test]
    fn numeric_cgroup_inode_cannot_have_two_owners_even_across_devices() {
        let first = binding(AdapterKind::Docker, "container-a", 100);
        let mut conflicting = binding(AdapterKind::Containerd, "container-b", 100);
        conflicting.identity.cgroup.device = 99;
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator
            .reconcile(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![first.clone()],
            ))
            .unwrap();

        assert_eq!(
            coordinator.reconcile(RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![conflicting.clone()],
            )),
            Err(RuntimeBindingError::CgroupConflict {
                cgroup: conflicting.identity.cgroup,
            })
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![first]
        );

        let recovery_error = RuntimeBindingCoordinator::recover_dormant(vec![
            binding(AdapterKind::Docker, "container-a", 100),
            conflicting.clone(),
        ])
        .unwrap_err();
        assert_eq!(
            recovery_error,
            RuntimeBindingError::CgroupConflict {
                cgroup: conflicting.identity.cgroup,
            }
        );
    }

    #[test]
    fn inventory_recovery_reattaches_after_an_outage() {
        let current = binding(AdapterKind::K3sContainerd, "container-a", 100);
        let inventory = || RuntimeInventory::new(AdapterKind::K3sContainerd, vec![current.clone()]);
        let mut coordinator = RuntimeBindingCoordinator::new();
        coordinator.reconcile(inventory()).unwrap();
        coordinator
            .source_unavailable(AdapterKind::K3sContainerd)
            .unwrap();

        let recovered = coordinator.reconcile(inventory()).unwrap();

        assert_eq!(
            recovered.effects,
            vec![RuntimeBindingEffect::Attach {
                binding: current.clone(),
            }]
        );
        assert_eq!(
            coordinator.bindings_for_agent_run("agent-run-1"),
            vec![current]
        );
    }

    #[test]
    fn recovered_dormant_binding_can_be_retired_without_becoming_queryable() {
        let dormant = binding(AdapterKind::Containerd, "container-a", 100);
        let mut coordinator =
            RuntimeBindingCoordinator::recover_dormant(vec![dormant.clone()]).unwrap();

        let result = coordinator.retire_agent_run("agent-run-1");

        assert_eq!(
            result.effects,
            vec![RuntimeBindingEffect::Retire { binding: dormant }]
        );
        assert!(coordinator.bindings_for_agent_run("agent-run-1").is_empty());
        assert!(coordinator
            .retire_agent_run("agent-run-1")
            .effects
            .is_empty());
    }

    #[test]
    fn stable_identity_proof_must_be_nonempty_bounded_and_nonzero() {
        let mut cases = Vec::new();

        let mut empty_agent_run = binding(AdapterKind::Docker, "container-a", 100);
        empty_agent_run.agent_run_id.clear();
        cases.push((empty_agent_run, "agent_run_id"));

        let mut empty_workload = binding(AdapterKind::Docker, "container-a", 100);
        empty_workload.identity.workload_id.clear();
        cases.push((empty_workload, "workload_id"));

        let mut empty_marker = binding(AdapterKind::Docker, "container-a", 100);
        empty_marker.identity.start_marker.clear();
        cases.push((empty_marker, "start_marker"));

        let mut zero_start = binding(AdapterKind::Docker, "container-a", 100);
        zero_start.identity.init_process_start_time_ticks = 0;
        cases.push((zero_start, "init_process_start_time_ticks"));

        let mut zero_device = binding(AdapterKind::Docker, "container-a", 100);
        zero_device.identity.cgroup.device = 0;
        cases.push((zero_device, "cgroup.device"));

        let mut zero_inode = binding(AdapterKind::Docker, "container-a", 100);
        zero_inode.identity.cgroup.inode = 0;
        cases.push((zero_inode, "cgroup.inode"));

        let mut empty_handler = binding(AdapterKind::Docker, "container-a", 100);
        empty_handler.runtime_handler = Some(String::new());
        cases.push((empty_handler, "runtime_handler"));

        let mut unsafe_agent_run = binding(AdapterKind::Docker, "container-a", 100);
        unsafe_agent_run.agent_run_id = "../tenant/run".to_string();
        cases.push((unsafe_agent_run, "agent_run_id"));

        let mut unsafe_handler = binding(AdapterKind::Docker, "container-a", 100);
        unsafe_handler.runtime_handler = Some("io.containerd/runc:v2".to_string());
        cases.push((unsafe_handler, "runtime_handler"));

        for (invalid, expected_field) in cases {
            let error = RuntimeBindingCoordinator::new()
                .reconcile(RuntimeInventory::new(AdapterKind::Docker, vec![invalid]))
                .unwrap_err();
            assert!(matches!(
                error,
                RuntimeBindingError::InvalidField { field, .. } if field == expected_field
            ));
        }

        let too_many = (0..=MAX_RUNTIME_INVENTORY_BINDINGS)
            .map(|index| {
                binding(
                    AdapterKind::Docker,
                    &format!("container-{index}"),
                    index as u64 + 1,
                )
            })
            .collect();
        assert!(matches!(
            RuntimeBindingCoordinator::new()
                .reconcile(RuntimeInventory::new(AdapterKind::Docker, too_many)),
            Err(RuntimeBindingError::InventoryTooLarge { .. })
        ));
    }

    #[test]
    fn runtime_binding_errors_redact_hostile_runtime_identifiers() {
        let hostile_workload = "container-secret-tenant-a";
        let duplicate = RuntimeBindingError::DuplicateWorkloadKey {
            adapter: AdapterKind::Docker,
            workload_id: hostile_workload.to_string(),
        };
        let cgroup = RuntimeBindingError::CgroupConflict {
            cgroup: CgroupIdentity {
                device: 0xdead_beef,
                inode: 9_876_543_210,
            },
        };

        for rendered in [
            duplicate.to_string(),
            format!("{duplicate:?}"),
            cgroup.to_string(),
            format!("{cgroup:?}"),
        ] {
            assert!(!rendered.contains(hostile_workload));
            assert!(!rendered.contains("9876543210"));
            assert!(!rendered.contains("3735928559"));
        }
        assert_eq!(
            duplicate.to_string(),
            "runtime_binding_invalid code=duplicate_workload_key adapter=docker"
        );
        assert_eq!(
            cgroup.to_string(),
            "runtime_binding_invalid code=cgroup_conflict"
        );
    }
}
