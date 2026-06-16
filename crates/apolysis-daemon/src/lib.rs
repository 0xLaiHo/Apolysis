// SPDX-License-Identifier: Apache-2.0

mod adapter;
mod config;
mod metrics;
mod pipeline;
mod runtime;
mod scope;
mod server;
mod state;

pub use adapter::{
    cgroup_id_from_proc_cgroup, containerd_task_snapshot_from_metadata,
    containerd_workload_from_snapshot, docker_container_pid_from_engine_inspect,
    docker_snapshot_from_engine_inspect, docker_workload_from_snapshot,
    kubernetes_pod_snapshot_from_api_object, kubernetes_workload_from_pod_snapshot,
    run_runtime_adapter, ContainerdTaskSnapshot, DockerContainerSnapshot, DockerEngineClient,
    DockerEngineRuntimeAdapter, KubernetesPodSnapshot, RuntimeAdapterBackend,
    RuntimeAdapterSummary, RuntimeWorkload, APOLYSIS_SESSION_ANNOTATION, APOLYSIS_SESSION_LABEL,
};
pub use config::DaemonConfig;
pub use metrics::render_prometheus_metrics;
pub use pipeline::{DaemonRecord, EventPipeline, SubmitError, WriterSummary};
pub use runtime::{
    ingest_observer_batch, run_observer_runtime, ObserverIngestSummary, ObserverRuntimeBackend,
    ObserverRuntimeSummary,
};
pub use scope::{scope_channel, ScopeController, ScopeOperation, ScopeRequest};
pub use server::{serve, DaemonResponse, DAEMON_SCHEMA_V1};
pub use state::DaemonState;
