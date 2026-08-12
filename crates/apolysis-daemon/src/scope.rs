// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU64;

use apolysis_accountability::SessionIntent;
use apolysis_core::{CollectorFailureReason, CollectorLifecycleRecord};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeOperation {
    Track,
    RefreshContext,
    Untrack,
    CloseAgentRun,
    FinalizeAgentRunClose,
    CancelAgentRunClose,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScopeCompletion {
    Applied,
    AgentRunClosePrepared(PreparedAgentRunClose),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedAgentRunClose {
    agent_run_id: String,
    token: Option<NonZeroU64>,
    stopped: Option<CollectorLifecycleRecord>,
}

impl PreparedAgentRunClose {
    pub(crate) fn new(
        agent_run_id: impl Into<String>,
        token: NonZeroU64,
        stopped: Option<CollectorLifecycleRecord>,
    ) -> Self {
        Self {
            agent_run_id: agent_run_id.into(),
            token: Some(token),
            stopped,
        }
    }

    fn external(agent_run_id: impl Into<String>) -> Self {
        Self {
            agent_run_id: agent_run_id.into(),
            token: None,
            stopped: None,
        }
    }

    pub(crate) fn agent_run_id(&self) -> &str {
        &self.agent_run_id
    }

    pub(crate) const fn token(&self) -> Option<NonZeroU64> {
        self.token
    }

    pub(crate) fn stopped(&self) -> Option<&CollectorLifecycleRecord> {
        self.stopped.as_ref()
    }
}

pub struct ScopeRequest {
    operation: ScopeOperation,
    cgroup_id: u64,
    agent_run_id: Option<String>,
    agent_intent: Option<SessionIntent>,
    runtime_container_id: Option<String>,
    failure_reason: Option<CollectorFailureReason>,
    close_token: Option<NonZeroU64>,
    response: oneshot::Sender<Result<ScopeCompletion, String>>,
}

impl ScopeRequest {
    pub fn operation(&self) -> ScopeOperation {
        self.operation
    }

    pub fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub fn agent_run_id(&self) -> Option<&str> {
        self.agent_run_id.as_deref()
    }

    pub fn agent_intent(&self) -> Option<&SessionIntent> {
        self.agent_intent.as_ref()
    }

    pub fn runtime_container_id(&self) -> Option<&str> {
        self.runtime_container_id.as_deref()
    }

    pub fn failure_reason(&self) -> Option<CollectorFailureReason> {
        self.failure_reason
    }

    pub(crate) const fn close_token(&self) -> Option<NonZeroU64> {
        self.close_token
    }

    pub fn complete(self, result: Result<(), String>) {
        let _ = self
            .response
            .send(result.map(|()| ScopeCompletion::Applied));
    }

    pub(crate) fn complete_agent_run_close(self, result: Result<PreparedAgentRunClose, String>) {
        let _ = self
            .response
            .send(result.map(ScopeCompletion::AgentRunClosePrepared));
    }
}

#[derive(Clone)]
pub struct ScopeController {
    sender: mpsc::Sender<ScopeRequest>,
}

impl ScopeController {
    pub async fn track(&self, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Track, cgroup_id, None, None, None, None)
            .await
    }

    pub async fn untrack(&self, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Untrack, cgroup_id, None, None, None, None)
            .await
    }

    pub async fn track_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
    ) -> Result<(), String> {
        self.apply(
            ScopeOperation::Track,
            cgroup_id,
            Some(agent_run_id),
            intent,
            None,
            None,
        )
        .await
    }

    pub async fn track_runtime_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
        container_id: &str,
    ) -> Result<(), String> {
        self.apply(
            ScopeOperation::Track,
            cgroup_id,
            Some(agent_run_id),
            intent,
            Some(container_id),
            None,
        )
        .await
    }

    pub async fn untrack_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
    ) -> Result<(), String> {
        self.apply(
            ScopeOperation::Untrack,
            cgroup_id,
            Some(agent_run_id),
            intent,
            None,
            None,
        )
        .await
    }

    pub async fn untrack_runtime_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
        container_id: &str,
    ) -> Result<(), String> {
        self.apply(
            ScopeOperation::Untrack,
            cgroup_id,
            Some(agent_run_id),
            intent,
            Some(container_id),
            None,
        )
        .await
    }

    pub async fn refresh_runtime_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
        container_id: &str,
    ) -> Result<(), String> {
        self.apply(
            ScopeOperation::RefreshContext,
            cgroup_id,
            Some(agent_run_id),
            intent,
            Some(container_id),
            None,
        )
        .await
    }

    pub async fn fail_agent_run(
        &self,
        agent_run_id: &str,
        intent: Option<&SessionIntent>,
        cgroup_id: u64,
        reason: CollectorFailureReason,
    ) -> Result<(), String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(ScopeRequest {
                operation: ScopeOperation::Untrack,
                cgroup_id,
                agent_run_id: Some(agent_run_id.to_string()),
                agent_intent: intent.cloned(),
                runtime_container_id: None,
                failure_reason: Some(reason),
                close_token: None,
                response,
            })
            .await
            .map_err(|error| format!("observer scope failure channel unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|_| ())
    }

    pub(crate) async fn prepare_agent_run_close(
        &self,
        agent_run_id: &str,
    ) -> Result<PreparedAgentRunClose, String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation: ScopeOperation::CloseAgentRun,
                cgroup_id: 0,
                agent_run_id: Some(agent_run_id.to_string()),
                agent_intent: None,
                runtime_container_id: None,
                failure_reason: None,
                close_token: None,
                response,
            })
            .map_err(|error| format!("observer scope command queue unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|completion| match completion {
                ScopeCompletion::AgentRunClosePrepared(prepared) => prepared,
                ScopeCompletion::Applied => PreparedAgentRunClose::external(agent_run_id),
            })
    }

    pub(crate) async fn finalize_agent_run_close(
        &self,
        prepared: &PreparedAgentRunClose,
    ) -> Result<(), String> {
        self.complete_agent_run_close(ScopeOperation::FinalizeAgentRunClose, prepared)
            .await
    }

    pub(crate) async fn cancel_agent_run_close(
        &self,
        prepared: &PreparedAgentRunClose,
    ) -> Result<(), String> {
        self.complete_agent_run_close(ScopeOperation::CancelAgentRunClose, prepared)
            .await
    }

    async fn complete_agent_run_close(
        &self,
        operation: ScopeOperation,
        prepared: &PreparedAgentRunClose,
    ) -> Result<(), String> {
        let Some(close_token) = prepared.token() else {
            return Ok(());
        };
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation,
                cgroup_id: 0,
                agent_run_id: Some(prepared.agent_run_id().to_string()),
                agent_intent: None,
                runtime_container_id: None,
                failure_reason: None,
                close_token: Some(close_token),
                response,
            })
            .map_err(|error| format!("observer scope command queue unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|_| ())
    }

    async fn apply(
        &self,
        operation: ScopeOperation,
        cgroup_id: u64,
        agent_run_id: Option<&str>,
        agent_intent: Option<&SessionIntent>,
        runtime_container_id: Option<&str>,
        failure_reason: Option<CollectorFailureReason>,
    ) -> Result<(), String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation,
                cgroup_id,
                agent_run_id: agent_run_id.map(str::to_owned),
                agent_intent: agent_intent.cloned(),
                runtime_container_id: runtime_container_id.map(str::to_owned),
                failure_reason,
                close_token: None,
                response,
            })
            .map_err(|error| format!("observer scope command queue unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|_| ())
    }
}

pub fn scope_channel(capacity: usize) -> (ScopeController, mpsc::Receiver<ScopeRequest>) {
    assert!(capacity > 0, "scope channel capacity must be non-zero");
    let (sender, receiver) = mpsc::channel(capacity);
    (ScopeController { sender }, receiver)
}
