// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::SessionIntent;
use apolysis_core::CollectorFailureReason;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeOperation {
    Track,
    RefreshContext,
    Untrack,
    CloseAgentRun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopeCompletion {
    Applied,
    AgentRunClosePersisted,
}

pub struct ScopeRequest {
    operation: ScopeOperation,
    cgroup_id: u64,
    agent_run_id: Option<String>,
    agent_intent: Option<SessionIntent>,
    runtime_container_id: Option<String>,
    failure_reason: Option<CollectorFailureReason>,
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

    pub fn complete(self, result: Result<(), String>) {
        let _ = self
            .response
            .send(result.map(|()| ScopeCompletion::Applied));
    }

    pub(crate) fn complete_agent_run_close(self, result: Result<(), String>) {
        let _ = self
            .response
            .send(result.map(|()| ScopeCompletion::AgentRunClosePersisted));
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
                response,
            })
            .await
            .map_err(|error| format!("observer scope failure channel unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|_| ())
    }

    pub(crate) async fn close_agent_run(&self, agent_run_id: &str) -> Result<bool, String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation: ScopeOperation::CloseAgentRun,
                cgroup_id: 0,
                agent_run_id: Some(agent_run_id.to_string()),
                agent_intent: None,
                runtime_container_id: None,
                failure_reason: None,
                response,
            })
            .map_err(|error| format!("observer scope command queue unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
            .map(|completion| completion == ScopeCompletion::AgentRunClosePersisted)
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
