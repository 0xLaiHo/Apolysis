// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    run_source_server, AuthoritativeSnapshotSource, CaptureLimits, DirtyTracker, KubeListAdapter,
    KubernetesClusterId, KubernetesSourceError, KubernetesSourceErrorKind, SourceProfile,
    SourceServerConfig, WatchPollOutcome, SOURCE_CONTAINER_GID, SOURCE_CONTAINER_UID,
};

const KUBE_RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
const KUBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionSecurityProfile {
    effective_uid: u32,
    effective_gid: u32,
    effective_capabilities: u64,
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub struct ProductionSourceConfig {
    profile: SourceProfile,
    server: SourceServerConfig,
}

impl ProductionSourceConfig {
    pub fn from_environment() -> Result<Self, KubernetesSourceError> {
        Self::from_values(
            environment("APOLYSIS_KUBERNETES_SOCKET")?,
            environment("APOLYSIS_KUBERNETES_CLUSTER_ID")?,
            environment("APOLYSIS_KUBERNETES_NAMESPACE")?,
            environment("APOLYSIS_KUBERNETES_NODE_NAME")?,
        )
    }

    pub fn from_values(
        socket_path: impl Into<PathBuf>,
        cluster_id: impl AsRef<str>,
        namespace: impl Into<String>,
        node_name: impl Into<String>,
    ) -> Result<Self, KubernetesSourceError> {
        let socket_path = socket_path.into();
        if !socket_path.is_absolute() {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Malformed,
            ));
        }
        let cluster_id = KubernetesClusterId::parse(cluster_id.as_ref())
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        let profile =
            SourceProfile::new(cluster_id, namespace, node_name, CaptureLimits::default())?;
        Ok(Self {
            profile,
            server: SourceServerConfig::new(socket_path),
        })
    }
}

pub async fn run_production_source<S>(
    config: ProductionSourceConfig,
    shutdown: S,
) -> Result<(), KubernetesSourceError>
where
    S: Future<Output = ()> + Send,
{
    validate_production_security_profile(current_production_security_profile()?)?;
    let adapter = KubeListAdapter::in_cluster(KUBE_RESPONSE_LIMIT, KUBE_REQUEST_TIMEOUT)?;
    let source = Arc::new(AuthoritativeSnapshotSource::new(config.profile, adapter));
    let dirty = Arc::new(DirtyTracker::new(source.source_epoch().clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server_shutdown = shutdown_rx.clone();
    let mut watcher_shutdown = shutdown_rx;

    let server = run_source_server(
        config.server,
        Arc::clone(&source),
        Arc::clone(&dirty),
        async move {
            while !*server_shutdown.borrow() {
                if server_shutdown.changed().await.is_err() {
                    break;
                }
            }
        },
    );
    let watcher = watch_loop(source, dirty, async move {
        while !*watcher_shutdown.borrow() {
            if watcher_shutdown.changed().await.is_err() {
                break;
            }
        }
    });
    tokio::pin!(server);
    tokio::pin!(watcher);
    tokio::pin!(shutdown);

    enum Stop {
        Shutdown,
        Server(Result<crate::SourceServerSummary, KubernetesSourceError>),
        Watcher(Result<(), KubernetesSourceError>),
    }
    let stop = tokio::select! {
        _ = &mut shutdown => Stop::Shutdown,
        result = &mut server => Stop::Server(result),
        result = &mut watcher => Stop::Watcher(result),
    };
    let _ = shutdown_tx.send(true);
    match stop {
        Stop::Shutdown => tokio::time::timeout(Duration::from_secs(6), async {
            let server_result = (&mut server).await.map(|_| ());
            let watcher_result = (&mut watcher).await;
            server_result.and(watcher_result)
        })
        .await
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Timeout))?,
        Stop::Server(result) => {
            let _ = tokio::time::timeout(Duration::from_secs(6), &mut watcher).await;
            result.map(|_| ())
        }
        Stop::Watcher(result) => {
            let server_result = tokio::time::timeout(Duration::from_secs(6), &mut server)
                .await
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Timeout))??;
            result.and(Ok(server_result)).map(|_| ())
        }
    }
}

fn current_production_security_profile() -> Result<ProductionSecurityProfile, KubernetesSourceError>
{
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let result = unsafe {
        libc::syscall(
            libc::SYS_capget,
            std::ptr::from_mut(&mut header),
            data.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    Ok(ProductionSecurityProfile {
        effective_uid: unsafe { libc::geteuid() },
        effective_gid: unsafe { libc::getegid() },
        effective_capabilities: u64::from(data[0].effective) | (u64::from(data[1].effective) << 32),
    })
}

fn validate_production_security_profile(
    profile: ProductionSecurityProfile,
) -> Result<(), KubernetesSourceError> {
    if profile.effective_uid != SOURCE_CONTAINER_UID
        || profile.effective_gid != SOURCE_CONTAINER_GID
        || profile.effective_capabilities != 0
    {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    Ok(())
}

async fn watch_loop<S>(
    source: Arc<AuthoritativeSnapshotSource<KubeListAdapter>>,
    dirty: Arc<DirtyTracker>,
    shutdown: S,
) -> Result<(), KubernetesSourceError>
where
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);
    loop {
        let outcome = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            outcome = source.poll_watch() => outcome,
        };
        match outcome {
            Ok(WatchPollOutcome::Dirty) => {
                dirty.mark_dirty(false).await?;
            }
            Ok(WatchPollOutcome::RelistRequired) | Err(_) => {
                dirty.mark_dirty(true).await?;
                tokio::select! {
                    _ = &mut shutdown => return Ok(()),
                    _ = tokio::time::sleep(WATCH_RETRY_DELAY) => {}
                }
            }
            Ok(WatchPollOutcome::Idle) => {}
        }
    }
}

fn environment(name: &'static str) -> Result<String, KubernetesSourceError> {
    let value = std::env::var(name)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    if value.is_empty() || value.len() > 4_096 {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Malformed,
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_security_profile_accepts_only_the_source_identity_without_capabilities() {
        assert!(
            validate_production_security_profile(ProductionSecurityProfile {
                effective_uid: 65_532,
                effective_gid: 65_532,
                effective_capabilities: 0,
            })
            .is_ok()
        );
    }

    #[test]
    fn production_security_profile_rejects_the_wrong_effective_group() {
        let error = validate_production_security_profile(ProductionSecurityProfile {
            effective_uid: 65_532,
            effective_gid: 0,
            effective_capabilities: 0,
        })
        .expect_err("wrong source GID");
        assert_eq!(error.kind(), KubernetesSourceErrorKind::Unauthorized);
    }

    #[test]
    fn production_security_profile_rejects_effective_capabilities() {
        let error = validate_production_security_profile(ProductionSecurityProfile {
            effective_uid: 65_532,
            effective_gid: 65_532,
            effective_capabilities: 1_u64 << 10,
        })
        .expect_err("effective source capability");
        assert_eq!(error.kind(), KubernetesSourceErrorKind::Unauthorized);
    }
}
