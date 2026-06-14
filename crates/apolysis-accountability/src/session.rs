// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::{IntentError, SessionIntent};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Active,
    Expired,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionState {
    pub intent: SessionIntent,
    pub expires_at_unix_ms: u64,
    pub status: SessionStatus,
    pub cgroup_ids: Vec<u64>,
}

impl SessionState {
    fn new(intent: SessionIntent) -> Self {
        Self {
            expires_at_unix_ms: intent.expires_at_unix_ms,
            intent,
            status: SessionStatus::Active,
            cgroup_ids: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterOutcome {
    Inserted,
    Replaced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssociationOutcome {
    Attached,
    MissingIntent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidIntent(IntentError),
    SessionCapacityReached { capacity: usize },
    PendingCapacityReached { capacity: usize },
    SessionNotFound(String),
    SessionNotActive(String),
    CgroupAlreadyAssigned { cgroup_id: u64, session_id: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIntent(error) => write!(formatter, "invalid intent: {error}"),
            Self::SessionCapacityReached { capacity } => {
                write!(formatter, "session capacity reached: {capacity}")
            }
            Self::PendingCapacityReached { capacity } => {
                write!(formatter, "pending workload capacity reached: {capacity}")
            }
            Self::SessionNotFound(session_id) => {
                write!(formatter, "session not found: {session_id}")
            }
            Self::SessionNotActive(session_id) => {
                write!(formatter, "session is not active: {session_id}")
            }
            Self::CgroupAlreadyAssigned {
                cgroup_id,
                session_id,
            } => write!(
                formatter,
                "cgroup {cgroup_id} is already assigned to session {session_id}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

pub struct SessionRegistry {
    max_sessions: usize,
    max_pending: usize,
    sessions: BTreeMap<String, SessionState>,
    cgroup_index: BTreeMap<u64, String>,
    pending: BTreeMap<String, Vec<u64>>,
    pending_count: usize,
}

impl SessionRegistry {
    pub fn new(max_sessions: usize, max_pending: usize) -> Self {
        Self {
            max_sessions,
            max_pending,
            sessions: BTreeMap::new(),
            cgroup_index: BTreeMap::new(),
            pending: BTreeMap::new(),
            pending_count: 0,
        }
    }

    pub fn register(
        &mut self,
        intent: SessionIntent,
        now_unix_ms: u64,
    ) -> Result<RegisterOutcome, RegistryError> {
        intent
            .validate(now_unix_ms)
            .map_err(RegistryError::InvalidIntent)?;
        let session_id = intent.session_id.clone();
        let outcome = if let Some(state) = self.sessions.get_mut(&session_id) {
            state.intent = intent;
            state.expires_at_unix_ms = state.intent.expires_at_unix_ms;
            state.status = SessionStatus::Active;
            RegisterOutcome::Replaced
        } else {
            if self.sessions.len() >= self.max_sessions {
                return Err(RegistryError::SessionCapacityReached {
                    capacity: self.max_sessions,
                });
            }
            self.sessions
                .insert(session_id.clone(), SessionState::new(intent));
            RegisterOutcome::Inserted
        };

        if let Some(cgroups) = self.pending.remove(&session_id) {
            self.pending_count -= cgroups.len();
            for cgroup_id in cgroups {
                self.attach_known_cgroup(&session_id, cgroup_id)?;
            }
        }

        Ok(outcome)
    }

    pub fn renew(
        &mut self,
        session_id: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), RegistryError> {
        if expires_at_unix_ms <= now_unix_ms {
            return Err(RegistryError::InvalidIntent(IntentError::Expired));
        }
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RegistryError::SessionNotFound(session_id.to_string()))?;
        if state.status == SessionStatus::Closed {
            return Err(RegistryError::SessionNotActive(session_id.to_string()));
        }
        state.expires_at_unix_ms = expires_at_unix_ms;
        state.intent.expires_at_unix_ms = expires_at_unix_ms;
        state.status = SessionStatus::Active;
        Ok(())
    }

    pub fn close(&mut self, session_id: &str) -> Result<SessionState, RegistryError> {
        self.deactivate(session_id, SessionStatus::Closed)?;
        self.sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| RegistryError::SessionNotFound(session_id.to_string()))
    }

    pub fn expire(&mut self, now_unix_ms: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, state)| {
                state.status == SessionStatus::Active
                    && state.expires_at_unix_ms <= now_unix_ms
            })
            .map(|(session_id, _)| session_id.clone())
            .collect();
        for session_id in &expired {
            let _ = self.deactivate(session_id, SessionStatus::Expired);
        }
        expired
    }

    pub fn associate_cgroup(
        &mut self,
        session_id: &str,
        cgroup_id: u64,
    ) -> Result<(), RegistryError> {
        let state = self
            .sessions
            .get(session_id)
            .ok_or_else(|| RegistryError::SessionNotFound(session_id.to_string()))?;
        if state.status != SessionStatus::Active {
            return Err(RegistryError::SessionNotActive(session_id.to_string()));
        }
        self.attach_known_cgroup(session_id, cgroup_id)
    }

    pub fn discover_cgroup(
        &mut self,
        session_id: &str,
        cgroup_id: u64,
    ) -> Result<AssociationOutcome, RegistryError> {
        if self.sessions.contains_key(session_id) {
            self.associate_cgroup(session_id, cgroup_id)?;
            return Ok(AssociationOutcome::Attached);
        }
        self.ensure_cgroup_available(session_id, cgroup_id)?;
        if self.pending_count >= self.max_pending {
            return Err(RegistryError::PendingCapacityReached {
                capacity: self.max_pending,
            });
        }
        let cgroups = self.pending.entry(session_id.to_string()).or_default();
        if !cgroups.contains(&cgroup_id) {
            cgroups.push(cgroup_id);
            cgroups.sort_unstable();
            self.pending_count += 1;
            self.cgroup_index.insert(cgroup_id, session_id.to_string());
        }
        Ok(AssociationOutcome::MissingIntent)
    }

    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    pub fn is_scope_admitted(&self, session_id: &str) -> bool {
        self.sessions
            .get(session_id)
            .map(|state| state.status == SessionStatus::Active)
            .unwrap_or(false)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    fn attach_known_cgroup(
        &mut self,
        session_id: &str,
        cgroup_id: u64,
    ) -> Result<(), RegistryError> {
        self.ensure_cgroup_available(session_id, cgroup_id)?;
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RegistryError::SessionNotFound(session_id.to_string()))?;
        if !state.cgroup_ids.contains(&cgroup_id) {
            state.cgroup_ids.push(cgroup_id);
            state.cgroup_ids.sort_unstable();
        }
        self.cgroup_index.insert(cgroup_id, session_id.to_string());
        Ok(())
    }

    fn ensure_cgroup_available(
        &self,
        session_id: &str,
        cgroup_id: u64,
    ) -> Result<(), RegistryError> {
        if let Some(owner) = self.cgroup_index.get(&cgroup_id) {
            if owner != session_id {
                return Err(RegistryError::CgroupAlreadyAssigned {
                    cgroup_id,
                    session_id: owner.clone(),
                });
            }
        }
        Ok(())
    }

    fn deactivate(
        &mut self,
        session_id: &str,
        status: SessionStatus,
    ) -> Result<(), RegistryError> {
        let cgroup_ids = {
            let state = self
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| RegistryError::SessionNotFound(session_id.to_string()))?;
            state.status = status;
            state.cgroup_ids.clone()
        };
        for cgroup_id in cgroup_ids {
            self.cgroup_index.remove(&cgroup_id);
        }
        Ok(())
    }
}
