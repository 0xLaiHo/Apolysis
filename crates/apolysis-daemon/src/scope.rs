// SPDX-License-Identifier: Apache-2.0

use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeOperation {
    Track,
    Untrack,
}

pub struct ScopeRequest {
    operation: ScopeOperation,
    cgroup_id: u64,
    agent_run_id: Option<String>,
    response: oneshot::Sender<Result<(), String>>,
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

    pub fn complete(self, result: Result<(), String>) {
        let _ = self.response.send(result);
    }
}

#[derive(Clone)]
pub struct ScopeController {
    sender: mpsc::Sender<ScopeRequest>,
}

impl ScopeController {
    pub async fn track(&self, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Track, cgroup_id, None).await
    }

    pub async fn untrack(&self, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Untrack, cgroup_id, None).await
    }

    pub async fn track_agent_run(&self, agent_run_id: &str, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Track, cgroup_id, Some(agent_run_id))
            .await
    }

    pub async fn untrack_agent_run(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> Result<(), String> {
        self.apply(ScopeOperation::Untrack, cgroup_id, Some(agent_run_id))
            .await
    }

    async fn apply(
        &self,
        operation: ScopeOperation,
        cgroup_id: u64,
        agent_run_id: Option<&str>,
    ) -> Result<(), String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation,
                cgroup_id,
                agent_run_id: agent_run_id.map(str::to_owned),
                response,
            })
            .map_err(|error| format!("observer scope command queue unavailable: {error}"))?;
        receiver
            .await
            .map_err(|_| "observer scope worker stopped before responding".to_string())?
    }
}

pub fn scope_channel(capacity: usize) -> (ScopeController, mpsc::Receiver<ScopeRequest>) {
    assert!(capacity > 0, "scope channel capacity must be non-zero");
    let (sender, receiver) = mpsc::channel(capacity);
    (ScopeController { sender }, receiver)
}
