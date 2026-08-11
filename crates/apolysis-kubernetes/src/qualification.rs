// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use apolysis_core::{
    validate_runtime_container_id_v1, KubernetesAttributionOptionalRef,
    KubernetesAttributionRecordType, KubernetesAttributionWireV1, KubernetesContainerKind,
    KubernetesWorkloadClaimV1, RuntimeBindingRecordType, RuntimeBindingWireV1,
    KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
};

pub const MAX_KUBERNETES_SNAPSHOT_PODS: usize = 4_096;
pub const MAX_KUBERNETES_SNAPSHOT_CONTAINERS: usize = 4_096;
pub const MAX_KUBERNETES_CONTAINERS_PER_POD: usize = 32;
pub const MAX_KUBERNETES_REGISTERED_CLAIMS: usize = 4_096;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KubernetesSnapshotIdentity {
    pub source_epoch: String,
    pub cluster_id: String,
    pub namespace_ref: String,
    pub node_ref: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KubernetesContainerCandidate {
    pub kind: KubernetesContainerKind,
    pub container_ref: String,
    pub runtime_container_id: Option<String>,
    pub running: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KubernetesPodCandidate {
    pub pod_uid: String,
    pub pod_revision_ref: String,
    pub marked_for_observation: bool,
    pub deleting: bool,
    pub runtime_class_ref: Option<String>,
    pub containers: Vec<KubernetesContainerCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesPodSnapshot {
    pub sequence: u64,
    pub identity: KubernetesSnapshotIdentity,
    pub pods: Vec<KubernetesPodCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesRuntimeInventory {
    pub adapter: String,
    pub bindings: Vec<RuntimeBindingWireV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesQualificationCycle {
    pub agent_run_id: String,
    pub claim_revision: u64,
    pub claims: Vec<KubernetesWorkloadClaimV1>,
    pub before: KubernetesPodSnapshot,
    pub runtime: KubernetesRuntimeInventory,
    pub after: KubernetesPodSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubernetesAttributionGapKind {
    ApiUnavailable,
    RuntimeUnavailable,
    SnapshotInvalid,
    DaemonRestart,
    IdentityTransition,
    LateAttach,
}

impl KubernetesAttributionGapKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiUnavailable => "kubernetes_api_unavailable",
            Self::RuntimeUnavailable => "kubernetes_runtime_unavailable",
            Self::SnapshotInvalid => "kubernetes_snapshot_invalid",
            Self::DaemonRestart => "kubernetes_daemon_restart",
            Self::IdentityTransition => "kubernetes_identity_transition",
            Self::LateAttach => "kubernetes_late_attach",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KubernetesSourceUnavailableReason {
    ApiUnavailable,
    RuntimeUnavailable,
    SnapshotInvalid,
}

impl KubernetesSourceUnavailableReason {
    pub const fn gap_kind(self) -> KubernetesAttributionGapKind {
        match self {
            Self::ApiUnavailable => KubernetesAttributionGapKind::ApiUnavailable,
            Self::RuntimeUnavailable => KubernetesAttributionGapKind::RuntimeUnavailable,
            Self::SnapshotInvalid => KubernetesAttributionGapKind::SnapshotInvalid,
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.gap_kind().as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KubernetesAttributionEffect {
    /// Dependency gate only. Applying this must not write a second runtime record.
    EnsureRuntimeObserved { binding: RuntimeBindingWireV1 },
    PersistGap {
        agent_run_id: String,
        cluster_id: String,
        kind: KubernetesAttributionGapKind,
    },
    SuspendAttribution {
        attribution: KubernetesAttributionWireV1,
    },
    RetireAttribution {
        attribution: KubernetesAttributionWireV1,
    },
    RetireDormantAttribution {
        attribution: KubernetesAttributionWireV1,
    },
    ObserveAttribution {
        attribution: KubernetesAttributionWireV1,
        late_attach_if_runtime_preexisting: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KubernetesAttributionSummary {
    pub gaps: usize,
    pub suspended: usize,
    pub retired: usize,
    pub observed: usize,
    pub unchanged: usize,
    pub active: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KubernetesAttributionPlan {
    pub claim_revision: u64,
    pub effects: Vec<KubernetesAttributionEffect>,
    pub summary: KubernetesAttributionSummary,
}

#[derive(Clone, Eq, PartialEq)]
pub enum KubernetesQualificationError {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    InventoryTooLarge {
        inventory: &'static str,
        actual: usize,
        maximum: usize,
    },
    SnapshotChanged,
    DuplicateClaim,
    DuplicatePod,
    DuplicateContainer,
    DuplicateRuntimeBinding,
    RuntimeBindingConflict,
    RuntimeBindingMissing,
}

impl KubernetesQualificationError {
    /// Typed evidence classification without exposing rejected source values.
    pub const fn gap_kind(&self) -> Option<KubernetesAttributionGapKind> {
        match self {
            Self::InvalidField { .. }
            | Self::InventoryTooLarge { .. }
            | Self::SnapshotChanged
            | Self::DuplicateClaim
            | Self::DuplicatePod
            | Self::DuplicateContainer
            | Self::DuplicateRuntimeBinding
            | Self::RuntimeBindingConflict
            | Self::RuntimeBindingMissing => Some(KubernetesAttributionGapKind::SnapshotInvalid),
        }
    }

    /// Whether a complete runtime scan failed to prove the claimed D1
    /// dependency and therefore the runtime scope must also be suspended.
    pub fn requires_runtime_suspension(&self) -> bool {
        match self {
            Self::InvalidField { field, .. } => matches!(
                *field,
                "runtime.adapter" | "runtime" | "runtime_container_id" | "attribution"
            ),
            Self::InventoryTooLarge { inventory, .. } => *inventory == "runtime_bindings",
            Self::DuplicateRuntimeBinding
            | Self::RuntimeBindingConflict
            | Self::RuntimeBindingMissing => true,
            Self::SnapshotChanged
            | Self::DuplicateClaim
            | Self::DuplicatePod
            | Self::DuplicateContainer => false,
        }
    }
}

impl fmt::Display for KubernetesQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => write!(
                formatter,
                "kubernetes_qualification_invalid code=invalid_field field={field} reason={reason}"
            ),
            Self::InventoryTooLarge {
                inventory,
                actual,
                maximum,
            } => write!(
                formatter,
                "kubernetes_qualification_invalid code=inventory_too_large inventory={inventory} actual={actual} maximum={maximum}"
            ),
            Self::SnapshotChanged => {
                formatter.write_str("kubernetes_qualification_invalid code=snapshot_changed")
            }
            Self::DuplicateClaim => {
                formatter.write_str("kubernetes_qualification_invalid code=duplicate_claim")
            }
            Self::DuplicatePod => {
                formatter.write_str("kubernetes_qualification_invalid code=duplicate_pod")
            }
            Self::DuplicateContainer => formatter
                .write_str("kubernetes_qualification_invalid code=duplicate_container_slot"),
            Self::DuplicateRuntimeBinding => formatter
                .write_str("kubernetes_qualification_invalid code=duplicate_runtime_binding"),
            Self::RuntimeBindingConflict => formatter
                .write_str("kubernetes_qualification_invalid code=runtime_binding_conflict"),
            Self::RuntimeBindingMissing => formatter
                .write_str("kubernetes_qualification_invalid code=runtime_binding_missing"),
        }
    }
}

impl fmt::Debug for KubernetesQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for KubernetesQualificationError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct KubernetesAttributionKey {
    cluster_id: String,
    pod_uid: String,
    container_kind: KubernetesContainerKind,
    container_ref: String,
}

#[derive(Clone, Debug, Default)]
pub struct KubernetesAttributionCoordinator {
    active: BTreeMap<KubernetesAttributionKey, KubernetesAttributionWireV1>,
    dormant: BTreeMap<KubernetesAttributionKey, KubernetesAttributionWireV1>,
    unavailable: BTreeMap<String, (String, KubernetesSourceUnavailableReason)>,
    qualified_revisions: BTreeMap<String, u64>,
    source_progress: BTreeMap<String, KubernetesSourceProgress>,
    resumable_after_outage: BTreeMap<String, BTreeSet<KubernetesAttributionKey>>,
}

#[derive(Clone, Debug)]
struct KubernetesSourceProgress {
    identity: KubernetesSnapshotIdentity,
    terminal_sequence: u64,
}

impl KubernetesAttributionCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recover_dormant(
        attributions: Vec<KubernetesAttributionWireV1>,
    ) -> Result<Self, KubernetesQualificationError> {
        if attributions.len() > MAX_KUBERNETES_REGISTERED_CLAIMS {
            return Err(KubernetesQualificationError::InventoryTooLarge {
                inventory: "recovered_attributions",
                actual: attributions.len(),
                maximum: MAX_KUBERNETES_REGISTERED_CLAIMS,
            });
        }
        let mut dormant = BTreeMap::new();
        let mut runtime_bindings = BTreeSet::new();
        for attribution in attributions {
            attribution
                .validate()
                .map_err(|_| KubernetesQualificationError::InvalidField {
                    field: "recovered_attributions",
                    reason: "must contain valid observed Kubernetes attributions",
                })?;
            if attribution.record_type != KubernetesAttributionRecordType::Observed {
                return Err(KubernetesQualificationError::InvalidField {
                    field: "recovered_attributions",
                    reason: "must contain valid observed Kubernetes attributions",
                });
            }
            let runtime_key = (
                attribution.runtime_binding.adapter.clone(),
                attribution.runtime_binding.workload_id.clone(),
            );
            if !runtime_bindings.insert(runtime_key) {
                return Err(KubernetesQualificationError::RuntimeBindingConflict);
            }
            let key = KubernetesAttributionKey::from(&attribution);
            if dormant.insert(key, attribution).is_some() {
                return Err(KubernetesQualificationError::DuplicateClaim);
            }
        }
        Ok(Self {
            dormant,
            ..Self::default()
        })
    }

    pub fn reconcile(
        &mut self,
        cycle: KubernetesQualificationCycle,
    ) -> Result<KubernetesAttributionPlan, KubernetesQualificationError> {
        let incoming = qualify_cycle(&cycle)?;
        let source_restarted = match self.source_progress.get(&cycle.agent_run_id) {
            None => false,
            Some(progress) => {
                if progress.identity.cluster_id != cycle.before.identity.cluster_id
                    || progress.identity.namespace_ref != cycle.before.identity.namespace_ref
                    || progress.identity.node_ref != cycle.before.identity.node_ref
                {
                    return Err(KubernetesQualificationError::SnapshotChanged);
                }
                if progress.identity.source_epoch == cycle.before.identity.source_epoch {
                    if cycle.before.sequence <= progress.terminal_sequence {
                        return Err(KubernetesQualificationError::SnapshotChanged);
                    }
                    false
                } else {
                    true
                }
            }
        };
        for (key, attribution) in &incoming {
            let conflicting_slot = self
                .active
                .get(key)
                .or_else(|| self.dormant.get(key))
                .is_some_and(|existing| existing.agent_run_id != cycle.agent_run_id);
            let conflicting_runtime =
                self.active
                    .values()
                    .chain(self.dormant.values())
                    .any(|existing| {
                        existing.agent_run_id != cycle.agent_run_id
                            && existing.runtime_binding.adapter
                                == attribution.runtime_binding.adapter
                            && existing.runtime_binding.workload_id
                                == attribution.runtime_binding.workload_id
                    });
            if conflicting_slot || conflicting_runtime {
                return Err(KubernetesQualificationError::RuntimeBindingConflict);
            }
        }
        let resumable = self
            .resumable_after_outage
            .remove(&cycle.agent_run_id)
            .unwrap_or_default();
        self.unavailable.remove(&cycle.agent_run_id);

        let mut gaps = Vec::new();
        let mut retires = Vec::new();
        let mut observations = Vec::with_capacity(incoming.len() * 2);
        let mut summary = KubernetesAttributionSummary::default();
        let dormant_keys = self
            .dormant
            .iter()
            .filter(|(_, attribution)| attribution.agent_run_id == cycle.agent_run_id)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut recovered = Vec::with_capacity(dormant_keys.len());
        let mut bounded_reobservations = BTreeSet::new();
        for key in dormant_keys {
            if let Some(attribution) = self.dormant.remove(&key) {
                bounded_reobservations.insert(key);
                recovered.push(attribution);
            }
        }
        if let Some(first) = recovered.first() {
            gaps.push(KubernetesAttributionEffect::PersistGap {
                agent_run_id: cycle.agent_run_id.clone(),
                cluster_id: first.cluster_id.clone(),
                kind: KubernetesAttributionGapKind::DaemonRestart,
            });
            summary.gaps = 1;
        }
        for attribution in recovered {
            retires.push(KubernetesAttributionEffect::RetireDormantAttribution {
                attribution: attribution.with_record_type(KubernetesAttributionRecordType::Retired),
            });
            summary.retired += 1;
        }
        if source_restarted {
            gaps.push(KubernetesAttributionEffect::PersistGap {
                agent_run_id: cycle.agent_run_id.clone(),
                cluster_id: cycle.before.identity.cluster_id.clone(),
                kind: KubernetesAttributionGapKind::DaemonRestart,
            });
            summary.gaps = 1;
            let restarted_keys = self
                .active
                .iter()
                .filter(|(_, attribution)| attribution.agent_run_id == cycle.agent_run_id)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            for key in restarted_keys {
                if let Some(previous) = self.active.remove(&key) {
                    bounded_reobservations.insert(key.clone());
                    retires.push(KubernetesAttributionEffect::RetireAttribution {
                        attribution: previous
                            .with_record_type(KubernetesAttributionRecordType::Retired),
                    });
                    summary.retired += 1;
                }
            }
        }
        let absent = self
            .active
            .iter()
            .filter(|(key, attribution)| {
                attribution.agent_run_id == cycle.agent_run_id && !incoming.contains_key(*key)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in absent {
            if let Some(previous) = self.active.remove(&key) {
                retires.push(KubernetesAttributionEffect::RetireAttribution {
                    attribution: previous
                        .with_record_type(KubernetesAttributionRecordType::Retired),
                });
                summary.retired += 1;
            }
        }
        for (key, attribution) in incoming {
            if self.active.get(&key) == Some(&attribution) {
                summary.unchanged += 1;
                continue;
            }
            let transitioned = if let Some(previous) = self.active.remove(&key) {
                if gaps.is_empty() {
                    gaps.push(KubernetesAttributionEffect::PersistGap {
                        agent_run_id: cycle.agent_run_id.clone(),
                        cluster_id: cycle.before.identity.cluster_id.clone(),
                        kind: KubernetesAttributionGapKind::IdentityTransition,
                    });
                }
                retires.push(KubernetesAttributionEffect::RetireAttribution {
                    attribution: previous
                        .with_record_type(KubernetesAttributionRecordType::Retired),
                });
                summary.gaps = 1;
                summary.retired += 1;
                true
            } else {
                false
            };
            observations.push(KubernetesAttributionEffect::EnsureRuntimeObserved {
                binding: attribution.runtime_binding.clone(),
            });
            observations.push(KubernetesAttributionEffect::ObserveAttribution {
                attribution: attribution.clone(),
                late_attach_if_runtime_preexisting: !(transitioned
                    || bounded_reobservations.contains(&key)
                    || resumable.contains(&key)),
            });
            self.active.insert(key, attribution);
            summary.observed += 1;
        }
        summary.active = self
            .active
            .values()
            .filter(|attribution| attribution.agent_run_id == cycle.agent_run_id)
            .count();
        self.qualified_revisions
            .insert(cycle.agent_run_id.clone(), cycle.claim_revision);
        self.source_progress.insert(
            cycle.agent_run_id.clone(),
            KubernetesSourceProgress {
                identity: cycle.after.identity.clone(),
                terminal_sequence: cycle.after.sequence,
            },
        );
        Ok(KubernetesAttributionPlan {
            claim_revision: cycle.claim_revision,
            effects: gaps
                .into_iter()
                .chain(retires)
                .chain(observations)
                .collect(),
            summary,
        })
    }

    pub fn attributions_for_agent_run(
        &self,
        agent_run_id: &str,
    ) -> Vec<KubernetesAttributionWireV1> {
        self.active
            .values()
            .filter(|attribution| attribution.agent_run_id == agent_run_id)
            .cloned()
            .collect()
    }

    pub fn attributions_for_agent_run_at_revision(
        &self,
        agent_run_id: &str,
        claim_revision: u64,
    ) -> Vec<KubernetesAttributionWireV1> {
        if self.qualified_revisions.get(agent_run_id) != Some(&claim_revision) {
            return Vec::new();
        }
        self.attributions_for_agent_run(agent_run_id)
    }

    pub fn agent_run_ids(&self) -> Vec<String> {
        self.active
            .values()
            .chain(self.dormant.values())
            .map(|attribution| attribution.agent_run_id.clone())
            .chain(self.unavailable.keys().cloned())
            .chain(self.qualified_revisions.keys().cloned())
            .chain(self.source_progress.keys().cloned())
            .chain(self.resumable_after_outage.keys().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn source_unavailable(
        &mut self,
        agent_run_id: &str,
        claim_revision: u64,
        cluster_id: &str,
        reason: KubernetesSourceUnavailableReason,
    ) -> Result<KubernetesAttributionPlan, KubernetesQualificationError> {
        validate_agent_run_and_revision(agent_run_id, claim_revision)?;
        validate_canonical_uuid("cluster_id", cluster_id)?;
        if self
            .unavailable
            .get(agent_run_id)
            .is_some_and(|(current_cluster, current_reason)| {
                current_cluster == cluster_id && *current_reason == reason
            })
        {
            return Ok(KubernetesAttributionPlan {
                claim_revision,
                summary: KubernetesAttributionSummary {
                    active: self
                        .active
                        .values()
                        .filter(|attribution| attribution.agent_run_id == agent_run_id)
                        .count(),
                    ..KubernetesAttributionSummary::default()
                },
                ..KubernetesAttributionPlan::default()
            });
        }
        self.unavailable
            .insert(agent_run_id.to_string(), (cluster_id.to_string(), reason));
        let keys = self
            .active
            .iter()
            .filter(|(_, attribution)| attribution.agent_run_id == agent_run_id)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        self.resumable_after_outage
            .entry(agent_run_id.to_string())
            .or_default()
            .extend(keys.iter().cloned());
        let mut active = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(attribution) = self.active.remove(&key) {
                active.push(attribution);
            }
        }
        let mut effects = Vec::with_capacity(active.len() + 1);
        effects.push(KubernetesAttributionEffect::PersistGap {
            agent_run_id: agent_run_id.to_string(),
            cluster_id: cluster_id.to_string(),
            kind: reason.gap_kind(),
        });
        effects.extend(active.iter().map(|attribution| {
            KubernetesAttributionEffect::SuspendAttribution {
                attribution: attribution
                    .with_record_type(KubernetesAttributionRecordType::Suspended),
            }
        }));
        Ok(KubernetesAttributionPlan {
            claim_revision,
            effects,
            summary: KubernetesAttributionSummary {
                gaps: 1,
                suspended: active.len(),
                active: 0,
                ..KubernetesAttributionSummary::default()
            },
        })
    }

    pub fn retire_agent_run(
        &mut self,
        agent_run_id: &str,
        claim_revision: u64,
    ) -> Result<KubernetesAttributionPlan, KubernetesQualificationError> {
        validate_agent_run_and_revision(agent_run_id, claim_revision)?;
        self.unavailable.remove(agent_run_id);
        self.qualified_revisions.remove(agent_run_id);
        self.source_progress.remove(agent_run_id);
        self.resumable_after_outage.remove(agent_run_id);
        let active_keys = self
            .active
            .iter()
            .filter(|(_, attribution)| attribution.agent_run_id == agent_run_id)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let dormant_keys = self
            .dormant
            .iter()
            .filter(|(_, attribution)| attribution.agent_run_id == agent_run_id)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut effects = Vec::with_capacity(active_keys.len() + dormant_keys.len());
        for key in active_keys {
            if let Some(attribution) = self.active.remove(&key) {
                effects.push(KubernetesAttributionEffect::RetireAttribution {
                    attribution: attribution
                        .with_record_type(KubernetesAttributionRecordType::Retired),
                });
            }
        }
        for key in dormant_keys {
            if let Some(attribution) = self.dormant.remove(&key) {
                effects.push(KubernetesAttributionEffect::RetireDormantAttribution {
                    attribution: attribution
                        .with_record_type(KubernetesAttributionRecordType::Retired),
                });
            }
        }
        Ok(KubernetesAttributionPlan {
            claim_revision,
            summary: KubernetesAttributionSummary {
                retired: effects.len(),
                active: 0,
                ..KubernetesAttributionSummary::default()
            },
            effects,
        })
    }
}

fn validate_agent_run_and_revision(
    agent_run_id: &str,
    claim_revision: u64,
) -> Result<(), KubernetesQualificationError> {
    if agent_run_id.is_empty()
        || agent_run_id.len() > 128
        || !agent_run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KubernetesQualificationError::InvalidField {
            field: "agent_run_id",
            reason: "must be a bounded canonical identifier",
        });
    }
    if claim_revision == 0 {
        return Err(KubernetesQualificationError::InvalidField {
            field: "claim_revision",
            reason: "must be non-zero",
        });
    }
    Ok(())
}

fn qualify_cycle(
    cycle: &KubernetesQualificationCycle,
) -> Result<
    BTreeMap<KubernetesAttributionKey, KubernetesAttributionWireV1>,
    KubernetesQualificationError,
> {
    validate_agent_run_and_revision(&cycle.agent_run_id, cycle.claim_revision)?;
    validate_snapshot_identity(&cycle.before.identity)?;
    validate_snapshot_identity(&cycle.after.identity)?;
    enforce_bound(
        "claims",
        cycle.claims.len(),
        MAX_KUBERNETES_REGISTERED_CLAIMS,
    )?;
    enforce_bound(
        "runtime_bindings",
        cycle.runtime.bindings.len(),
        MAX_KUBERNETES_SNAPSHOT_CONTAINERS,
    )?;
    if !matches!(
        cycle.runtime.adapter.as_str(),
        "containerd" | "k3s_containerd"
    ) {
        return Err(KubernetesQualificationError::InvalidField {
            field: "runtime.adapter",
            reason: "must be containerd or k3s_containerd",
        });
    }
    validate_snapshot_bounds(&cycle.before)?;
    validate_snapshot_bounds(&cycle.after)?;
    if cycle.before.identity != cycle.after.identity
        || cycle.before.sequence == 0
        || cycle.after.sequence <= cycle.before.sequence
    {
        return Err(KubernetesQualificationError::SnapshotChanged);
    }
    let before_pods = canonical_pod_candidates(&cycle.before.pods);
    let after_pods = canonical_pod_candidates(&cycle.after.pods);
    if before_pods != after_pods {
        return Err(KubernetesQualificationError::SnapshotChanged);
    }

    let mut claim_slots = BTreeSet::new();
    for claim in &cycle.claims {
        claim
            .validate()
            .map_err(|_| KubernetesQualificationError::InvalidField {
                field: "claims",
                reason: "must contain valid exact workload claims",
            })?;
        if claim.claim_revision != cycle.claim_revision {
            return Err(KubernetesQualificationError::InvalidField {
                field: "claim_revision",
                reason: "must equal every registered claim revision",
            });
        }
        if claim.cluster_id != cycle.before.identity.cluster_id
            || claim.namespace_ref != cycle.before.identity.namespace_ref
        {
            return Err(KubernetesQualificationError::InvalidField {
                field: "claims",
                reason: "must belong to the cycle cluster and namespace",
            });
        }
        if !claim_slots.insert((
            claim.cluster_id.as_str(),
            claim.namespace_ref.as_str(),
            claim.pod_uid.as_str(),
            claim.container_kind,
            claim.container_ref.as_str(),
        )) {
            return Err(KubernetesQualificationError::DuplicateClaim);
        }
    }

    let mut runtime_by_container = BTreeMap::new();
    let mut runtime_cgroups = BTreeSet::new();
    for binding in &cycle.runtime.bindings {
        binding
            .validate()
            .map_err(|_| KubernetesQualificationError::InvalidField {
                field: "runtime",
                reason: "must contain valid exact runtime bindings",
            })?;
        if binding.record_type != RuntimeBindingRecordType::Observed
            || binding.adapter != cycle.runtime.adapter
        {
            return Err(KubernetesQualificationError::InvalidField {
                field: "runtime",
                reason: "must contain observed bindings from one runtime adapter",
            });
        }
        if !runtime_cgroups.insert(binding.cgroup_id) {
            return Err(KubernetesQualificationError::RuntimeBindingConflict);
        }
        let container_id =
            runtime_container_id(binding).ok_or(KubernetesQualificationError::InvalidField {
                field: "runtime",
                reason: "must contain adapter-canonical container identities",
            })?;
        if runtime_by_container
            .insert(container_id.to_string(), binding)
            .is_some()
        {
            return Err(KubernetesQualificationError::DuplicateRuntimeBinding);
        }
    }

    let mut pods = BTreeMap::new();
    for pod in &cycle.before.pods {
        if pods.insert(pod.pod_uid.as_str(), pod).is_some() {
            return Err(KubernetesQualificationError::DuplicatePod);
        }
        let mut slots = BTreeMap::new();
        for container in &pod.containers {
            if slots
                .insert((container.kind, container.container_ref.as_str()), ())
                .is_some()
            {
                return Err(KubernetesQualificationError::DuplicateContainer);
            }
        }
    }
    let mut incoming = BTreeMap::new();
    let mut claimed_runtime_containers = BTreeSet::new();
    for claim in &cycle.claims {
        let Some(pod) = pods.get(claim.pod_uid.as_str()).copied() else {
            continue;
        };
        if !pod.marked_for_observation {
            return Err(KubernetesQualificationError::InvalidField {
                field: "marked_for_observation",
                reason: "must remain true for every claimed Pod candidate",
            });
        }
        if pod.deleting {
            continue;
        }
        let Some(container) = pod.containers.iter().find(|candidate| {
            candidate.kind == claim.container_kind && candidate.container_ref == claim.container_ref
        }) else {
            continue;
        };
        if !container.running {
            continue;
        }
        let container_id = container.runtime_container_id.as_deref().ok_or(
            KubernetesQualificationError::InvalidField {
                field: "runtime_container_id",
                reason: "must be present for a running container",
            },
        )?;
        let binding = runtime_by_container
            .get(container_id)
            .copied()
            .ok_or(KubernetesQualificationError::RuntimeBindingMissing)?;
        if !claimed_runtime_containers.insert(container_id) {
            return Err(KubernetesQualificationError::RuntimeBindingConflict);
        }
        if binding.agent_run_id != cycle.agent_run_id {
            return Err(KubernetesQualificationError::RuntimeBindingConflict);
        }
        let attribution = KubernetesAttributionWireV1 {
            record_type: KubernetesAttributionRecordType::Observed,
            schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
            agent_run_id: cycle.agent_run_id.clone(),
            cluster_id: claim.cluster_id.clone(),
            namespace_ref: claim.namespace_ref.clone(),
            pod_uid: claim.pod_uid.clone(),
            node_ref: cycle.before.identity.node_ref.clone(),
            runtime_class_ref: KubernetesAttributionOptionalRef(pod.runtime_class_ref.clone()),
            container_kind: claim.container_kind,
            container_ref: claim.container_ref.clone(),
            runtime_binding: binding.clone(),
        };
        attribution
            .validate()
            .map_err(|_| KubernetesQualificationError::InvalidField {
                field: "attribution",
                reason: "must form a valid exact Kubernetes attribution",
            })?;
        let key = KubernetesAttributionKey::from(&attribution);
        if incoming.insert(key, attribution).is_some() {
            return Err(KubernetesQualificationError::DuplicateClaim);
        }
    }
    Ok(incoming)
}

fn canonical_pod_candidates(pods: &[KubernetesPodCandidate]) -> Vec<KubernetesPodCandidate> {
    let mut canonical = pods.to_vec();
    for pod in &mut canonical {
        pod.containers.sort();
    }
    canonical.sort();
    canonical
}

fn validate_snapshot_bounds(
    snapshot: &KubernetesPodSnapshot,
) -> Result<(), KubernetesQualificationError> {
    enforce_bound("pods", snapshot.pods.len(), MAX_KUBERNETES_SNAPSHOT_PODS)?;
    let mut total = 0usize;
    let mut pod_uids = BTreeSet::new();
    let mut runtime_container_ids = BTreeSet::new();
    for pod in &snapshot.pods {
        validate_canonical_uuid("pod_uid", &pod.pod_uid)?;
        validate_privacy_reference("pod_revision_ref", &pod.pod_revision_ref)?;
        if !pod_uids.insert(pod.pod_uid.as_str()) {
            return Err(KubernetesQualificationError::DuplicatePod);
        }
        if let Some(runtime_class_ref) = pod.runtime_class_ref.as_deref() {
            validate_privacy_reference("runtime_class_ref", runtime_class_ref)?;
        }
        enforce_bound(
            "pod_containers",
            pod.containers.len(),
            MAX_KUBERNETES_CONTAINERS_PER_POD,
        )?;
        let mut slots = BTreeSet::new();
        for container in &pod.containers {
            validate_privacy_reference("container_ref", &container.container_ref)?;
            match container.runtime_container_id.as_deref() {
                Some(container_id) => {
                    validate_runtime_container_id_v1(container_id).map_err(|_| {
                        KubernetesQualificationError::InvalidField {
                            field: "runtime_container_id",
                            reason: "must be a canonical full runtime container ID",
                        }
                    })?;
                    if !runtime_container_ids.insert(container_id) {
                        return Err(KubernetesQualificationError::RuntimeBindingConflict);
                    }
                }
                None if container.running => {
                    return Err(KubernetesQualificationError::InvalidField {
                        field: "runtime_container_id",
                        reason: "must be present for a running container",
                    });
                }
                None => {}
            }
            if !slots.insert((container.kind, container.container_ref.as_str())) {
                return Err(KubernetesQualificationError::DuplicateContainer);
            }
        }
        total = total.checked_add(pod.containers.len()).ok_or(
            KubernetesQualificationError::InventoryTooLarge {
                inventory: "containers",
                actual: usize::MAX,
                maximum: MAX_KUBERNETES_SNAPSHOT_CONTAINERS,
            },
        )?;
    }
    enforce_bound("containers", total, MAX_KUBERNETES_SNAPSHOT_CONTAINERS)
}

fn enforce_bound(
    inventory: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), KubernetesQualificationError> {
    if actual > maximum {
        return Err(KubernetesQualificationError::InventoryTooLarge {
            inventory,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_snapshot_identity(
    identity: &KubernetesSnapshotIdentity,
) -> Result<(), KubernetesQualificationError> {
    validate_canonical_uuid("source_epoch", &identity.source_epoch)?;
    validate_canonical_uuid("cluster_id", &identity.cluster_id)?;
    validate_privacy_reference("namespace_ref", &identity.namespace_ref)?;
    validate_privacy_reference("node_ref", &identity.node_ref)
}

fn validate_canonical_uuid(
    field: &'static str,
    value: &str,
) -> Result<(), KubernetesQualificationError> {
    let mut non_zero = false;
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                if byte != b'0' {
                    non_zero = true;
                }
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && non_zero;
    if !valid {
        return Err(KubernetesQualificationError::InvalidField {
            field,
            reason: "must be a canonical lowercase non-zero UUID",
        });
    }
    Ok(())
}

fn validate_privacy_reference(
    field: &'static str,
    value: &str,
) -> Result<(), KubernetesQualificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(KubernetesQualificationError::InvalidField {
            field,
            reason: "must be a 64-byte lowercase hexadecimal privacy reference",
        });
    }
    Ok(())
}

fn runtime_container_id(binding: &RuntimeBindingWireV1) -> Option<&str> {
    match binding.adapter.as_str() {
        "containerd" => binding.workload_id.strip_prefix("containerd/"),
        "k3s_containerd" => binding.workload_id.strip_prefix("k3s_containerd/"),
        _ => None,
    }
}

impl From<&KubernetesAttributionWireV1> for KubernetesAttributionKey {
    fn from(attribution: &KubernetesAttributionWireV1) -> Self {
        Self {
            cluster_id: attribution.cluster_id.clone(),
            pod_uid: attribution.pod_uid.clone(),
            container_kind: attribution.container_kind,
            container_ref: attribution.container_ref.clone(),
        }
    }
}
