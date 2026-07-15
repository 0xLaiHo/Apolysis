// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::OpenOptions,
    future::pending,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use crate::{http::GatewayRouteOperation, GatewayServerError};

const MARKER_CONTENTS: &[u8] = b"committed\n";

impl GatewayRouteOperation {
    pub fn parse(value: &str) -> Result<Self, GatewayServerError> {
        match value {
            "open_run" => Ok(Self::OpenRun),
            "bind_runtime" => Ok(Self::BindRuntime),
            "ingest" => Ok(Self::Ingest),
            "finish_run" => Ok(Self::FinishRun),
            _ => Err(GatewayServerError::configuration(
                "Gateway qualification operation is unsupported",
            )),
        }
    }
}

pub(crate) struct QualificationBarrier {
    operation: GatewayRouteOperation,
    marker: PathBuf,
}

impl QualificationBarrier {
    pub(crate) fn new(
        operation: GatewayRouteOperation,
        marker: PathBuf,
    ) -> Result<Self, GatewayServerError> {
        if !marker.is_absolute() {
            return Err(GatewayServerError::configuration(
                "Gateway qualification marker path must be absolute",
            ));
        }
        Ok(Self { operation, marker })
    }

    pub(crate) fn marker(&self) -> &Path {
        &self.marker
    }

    pub(crate) async fn reach(
        &self,
        operation: GatewayRouteOperation,
    ) -> Result<(), GatewayServerError> {
        if operation != self.operation {
            return Ok(());
        }

        write_private_marker(&self.marker)?;
        pending::<()>().await;
        Ok(())
    }
}

fn write_private_marker(path: &Path) -> Result<(), GatewayServerError> {
    let parent = path.parent().ok_or_else(|| {
        GatewayServerError::configuration("Gateway qualification marker parent is invalid")
    })?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK);
    let parent_directory = parent_options
        .open(parent)
        .map_err(|error| GatewayServerError::io_at("qualification-parent-open", error))?;
    let parent_metadata = parent_directory
        .metadata()
        .map_err(|error| GatewayServerError::io_at("qualification-parent-metadata", error))?;
    // SAFETY: geteuid has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o077 != 0
        || parent_metadata.uid() != effective_uid
    {
        return Err(GatewayServerError::configuration(
            "Gateway qualification marker parent must be private",
        ));
    }

    let mut marker_options = OpenOptions::new();
    marker_options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut marker = marker_options
        .open(path)
        .map_err(|error| GatewayServerError::io_at("qualification-marker-open", error))?;
    let marker_metadata = marker
        .metadata()
        .map_err(|error| GatewayServerError::io_at("qualification-marker-metadata", error))?;
    if !marker_metadata.is_file()
        || marker_metadata.mode() & 0o777 != 0o600
        || marker_metadata.nlink() != 1
        || marker_metadata.uid() != effective_uid
    {
        return Err(GatewayServerError::configuration(
            "Gateway qualification marker is not a private regular file",
        ));
    }

    marker
        .write_all(MARKER_CONTENTS)
        .map_err(|error| GatewayServerError::io_at("qualification-marker-write", error))?;
    marker
        .sync_all()
        .map_err(|error| GatewayServerError::io_at("qualification-marker-sync", error))?;
    parent_directory
        .sync_all()
        .map_err(|error| GatewayServerError::io_at("qualification-parent-sync", error))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn private() -> Self {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "apolysis-gateway-qualification-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create qualification test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make qualification test directory private");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_only_frozen_lifecycle_operations() {
        assert_eq!(
            GatewayRouteOperation::parse("open_run").unwrap(),
            GatewayRouteOperation::OpenRun
        );
        assert_eq!(
            GatewayRouteOperation::parse("finish_run").unwrap(),
            GatewayRouteOperation::FinishRun
        );
        assert!(GatewayRouteOperation::parse("query").is_err());
    }

    #[tokio::test]
    async fn writes_one_private_static_marker_before_holding() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let barrier = QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker.clone())
            .expect("valid qualification barrier");
        let worker =
            tokio::spawn(async move { barrier.reach(GatewayRouteOperation::OpenRun).await });

        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(fs::read(&marker).unwrap(), MARKER_CONTENTS);
        let metadata = fs::symlink_metadata(&marker).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(!worker.is_finished());
        worker.abort();
    }

    #[tokio::test]
    async fn rejects_a_symlinked_marker_without_overwriting_its_target() {
        let directory = TestDirectory::private();
        let target = directory.path().join("target");
        let marker = directory.path().join("reached");
        fs::write(&target, b"unchanged\n").unwrap();
        symlink(&target, &marker).unwrap();
        let barrier = QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker).unwrap();

        assert!(barrier.reach(GatewayRouteOperation::OpenRun).await.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged\n");
    }

    #[tokio::test]
    async fn non_target_operations_do_not_create_a_marker() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let barrier =
            QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker.clone()).unwrap();

        barrier.reach(GatewayRouteOperation::Ingest).await.unwrap();

        assert!(!marker.exists());
    }
}
