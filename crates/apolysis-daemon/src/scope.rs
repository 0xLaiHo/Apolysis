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
    response: oneshot::Sender<Result<(), String>>,
}

impl ScopeRequest {
    pub fn operation(&self) -> ScopeOperation {
        self.operation
    }

    pub fn cgroup_id(&self) -> u64 {
        self.cgroup_id
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
        self.apply(ScopeOperation::Track, cgroup_id).await
    }

    pub async fn untrack(&self, cgroup_id: u64) -> Result<(), String> {
        self.apply(ScopeOperation::Untrack, cgroup_id).await
    }

    async fn apply(&self, operation: ScopeOperation, cgroup_id: u64) -> Result<(), String> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ScopeRequest {
                operation,
                cgroup_id,
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
