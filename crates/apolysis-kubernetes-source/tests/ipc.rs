// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use apolysis_kubernetes_source::{
    kubernetes_namespace_ref, kubernetes_node_ref, run_source_server, DirtyTracker,
    DirtyWaitOutcome, KubernetesClusterId, KubernetesSnapshot, KubernetesSourceClient,
    KubernetesSourceClientConfig, KubernetesSourceError, KubernetesSourceErrorKind,
    SnapshotProvider, SourceEpoch, SourceRequest, SourceResponse, SourceServerConfig,
    KUBERNETES_SOURCE_SCHEMA_V1,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

#[test]
fn source_server_does_not_change_the_process_umask() {
    let status = Command::new(std::env::current_exe().expect("current IPC test binary"))
        .args([
            "--exact",
            "source_server_umask_isolation_child",
            "--test-threads=1",
        ])
        .env("APOLYSIS_UMASK_ISOLATION_CHILD", "1")
        .status()
        .expect("run isolated umask exercise");
    assert!(status.success(), "isolated umask exercise failed");
}

#[test]
fn source_server_umask_isolation_child() {
    if std::env::var_os("APOLYSIS_UMASK_ISOLATION_CHILD").is_none() {
        return;
    }

    let original_umask = unsafe { libc::umask(0o022) };
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("umask exercise runtime");
                barrier.wait();
                runtime.block_on(async {
                    for _ in 0..64 {
                        let directory = tempfile::tempdir().expect("temporary socket directory");
                        let socket = directory.path().join("source/source.sock");
                        let provider = Arc::new(FixedProvider(empty_snapshot(1)));
                        let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
                        run_source_server(
                            SourceServerConfig::new(&socket)
                                .with_expected_collector_uid(unsafe { libc::geteuid() }),
                            provider,
                            dirty,
                            std::future::ready(()),
                        )
                        .await
                        .expect("start and stop source server");
                    }
                });
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().expect("umask exercise worker");
    }
    let observed_umask = unsafe { libc::umask(0o022) };
    unsafe { libc::umask(original_umask) };
    assert_eq!(
        observed_umask, 0o022,
        "source server changed the process umask"
    );
}

#[test]
fn abandoned_socket_creator_child() {
    let Some(path) = std::env::var_os("APOLYSIS_ABANDONED_SOCKET_PATH") else {
        return;
    };
    let mode = std::env::var("APOLYSIS_ABANDONED_SOCKET_MODE")
        .ok()
        .and_then(|value| u32::from_str_radix(&value, 8).ok())
        .expect("canonical abandoned socket mode");
    let listener = StdUnixListener::bind(&path).expect("bind abandoned socket");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("set abandoned socket mode");
    drop(listener);
}

fn create_abandoned_socket(path: &Path, mode: u32) {
    let status = Command::new(std::env::current_exe().expect("current IPC test binary"))
        .args([
            "--exact",
            "abandoned_socket_creator_child",
            "--test-threads=1",
        ])
        .env("APOLYSIS_ABANDONED_SOCKET_PATH", path)
        .env("APOLYSIS_ABANDONED_SOCKET_MODE", format!("{mode:o}"))
        .status()
        .expect("run isolated abandoned socket creator");
    assert!(status.success(), "abandoned socket creator failed");
}

#[tokio::test]
async fn collector_receives_an_exact_bounded_snapshot_from_the_source_socket() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let listener = bound_source_socket(&socket).await;
    let expected = empty_snapshot(4);

    let server = tokio::spawn({
        let expected = expected.clone();
        async move {
            let (mut stream, _) = listener.accept().await.expect("accept collector");
            let request = read_frame(&mut stream, 4096).await;
            let request: SourceRequest =
                serde_json::from_slice(&request).expect("decode source request");
            assert_eq!(
                request,
                SourceRequest::Capture {
                    schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                }
            );
            let response = SourceResponse::Snapshot {
                schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                snapshot: expected,
            };
            write_frame(
                &mut stream,
                &serde_json::to_vec(&response).expect("encode source response"),
            )
            .await;
        }
    });

    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1))
            .with_max_frame_bytes(64 * 1024),
    )
    .expect("valid client config");

    assert_eq!(client.capture().await.expect("capture snapshot"), expected);
    server.await.expect("source task");
}

#[tokio::test]
async fn collector_receives_only_a_dirty_hint_from_the_watch_path() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let listener = bound_source_socket(&socket).await;
    let epoch = SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000").expect("source epoch");

    let server = tokio::spawn({
        let epoch = epoch.clone();
        async move {
            let (mut stream, _) = listener.accept().await.expect("accept collector");
            let request = read_frame(&mut stream, 4096).await;
            let request: SourceRequest =
                serde_json::from_slice(&request).expect("decode source request");
            assert_eq!(
                request,
                SourceRequest::WaitDirty {
                    schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                    source_epoch: None,
                    after_dirty_sequence: 0,
                }
            );
            let response = SourceResponse::Dirty {
                schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                source_epoch: epoch,
                dirty_sequence: 1,
                relist_required: true,
            };
            write_frame(
                &mut stream,
                &serde_json::to_vec(&response).expect("encode dirty hint"),
            )
            .await;
        }
    });

    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1)),
    )
    .expect("valid client config");

    assert_eq!(
        client
            .wait_dirty(None, 0)
            .await
            .expect("receive dirty hint"),
        DirtyWaitOutcome::Dirty {
            source_epoch: SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000")
                .expect("source epoch"),
            dirty_sequence: 1,
            relist_required: true,
        }
    );
    server.await.expect("source task");
}

#[tokio::test]
async fn collector_rejects_an_idle_reply_that_advanced_past_the_requested_sequence() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let listener = bound_source_socket(&socket).await;
    let epoch = SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000").expect("source epoch");

    let server = tokio::spawn({
        let epoch = epoch.clone();
        async move {
            let (mut stream, _) = listener.accept().await.expect("accept collector");
            let _request = read_frame(&mut stream, 4096).await;
            let response = SourceResponse::Idle {
                schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                source_epoch: epoch,
                dirty_sequence: 8,
            };
            write_frame(
                &mut stream,
                &serde_json::to_vec(&response).expect("encode invalid idle reply"),
            )
            .await;
        }
    });

    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1)),
    )
    .expect("valid client config");

    assert_eq!(
        client
            .wait_dirty(Some(epoch), 7)
            .await
            .expect_err("advanced sequence cannot be idle")
            .kind(),
        KubernetesSourceErrorKind::Protocol
    );
    server.await.expect("source task");
}

#[tokio::test]
async fn production_server_owns_a_restricted_socket_and_unlinks_only_its_inode() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source/source.sock");
    let provider = Arc::new(FixedProvider(empty_snapshot(1)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(run_source_server(
        SourceServerConfig::new(&socket)
            .with_expected_collector_uid(unsafe { libc::geteuid() })
            .with_request_timeout(Duration::from_secs(1))
            .with_dirty_wait_timeout(Duration::from_millis(100))
            .with_max_connections(2),
        provider,
        dirty,
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if socket.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("source socket readiness");
    let parent_metadata =
        std::fs::metadata(socket.parent().expect("socket parent")).expect("source-owned parent");
    assert_eq!(parent_metadata.mode() & 0o777, 0o700);
    assert_eq!(parent_metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(parent_metadata.gid(), unsafe { libc::getegid() });
    let metadata = std::fs::symlink_metadata(&socket).expect("source socket metadata");
    assert_eq!(metadata.mode() & 0o777, 0o660);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    let published_entries = std::fs::read_dir(socket.parent().expect("socket parent"))
        .expect("read source-owned parent")
        .map(|entry| entry.expect("source directory entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(published_entries, [std::ffi::OsString::from("source.sock")]);

    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1)),
    )
    .expect("valid client");
    assert_eq!(
        client
            .capture()
            .await
            .expect("server capture")
            .snapshot_sequence,
        1
    );

    shutdown_tx.send(()).expect("request server shutdown");
    server
        .await
        .expect("server task")
        .expect("clean source shutdown");
    assert!(!socket.exists(), "server left its owned socket behind");
}

#[tokio::test]
async fn collector_rejects_a_permissive_source_socket_before_sending_credentials() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let _listener = UnixListener::bind(&socket).expect("bind source socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
        .expect("make socket intentionally permissive");
    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_millis(50)),
    )
    .expect("valid client config");

    let error = client
        .capture()
        .await
        .expect_err("permissive source socket");
    assert_eq!(error.kind(), KubernetesSourceErrorKind::Unauthorized);
    assert_eq!(
        error.to_string(),
        "kubernetes_source_error kind=unauthorized"
    );
    assert!(!error.to_string().contains("source.sock"));
}

#[tokio::test]
async fn collector_rejects_a_source_socket_with_the_wrong_group_identity() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let _listener = bound_source_socket(&socket).await;
    let unexpected_gid = unsafe { libc::getegid() }.wrapping_add(1);
    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unexpected_gid)
            .with_io_timeout(Duration::from_millis(50)),
    )
    .expect("valid client config");

    assert_eq!(
        client
            .capture()
            .await
            .expect_err("wrong source group")
            .kind(),
        KubernetesSourceErrorKind::Unauthorized
    );
}

#[tokio::test]
async fn collector_rejects_an_oversized_frame_from_an_authorized_peer() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let listener = bound_source_socket(&socket).await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept collector");
        let _request = read_frame(&mut stream, 4096).await;
        stream
            .write_all(&(65_537_u32).to_be_bytes())
            .await
            .expect("write oversized frame header");
    });
    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1))
            .with_max_frame_bytes(65_536),
    )
    .expect("valid client config");

    assert_eq!(
        client.capture().await.expect_err("oversized frame").kind(),
        KubernetesSourceErrorKind::Oversized
    );
    server.await.expect("source task");
}

#[tokio::test]
async fn collector_applies_one_deadline_to_the_whole_ipc_exchange() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    let listener = bound_source_socket(&socket).await;
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept collector");
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_millis(10)),
    )
    .expect("valid client config");

    assert_eq!(
        client.capture().await.expect_err("IPC deadline").kind(),
        KubernetesSourceErrorKind::Timeout
    );
    server.await.expect("source task");
}

#[tokio::test]
async fn production_server_never_removes_a_preexisting_path() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source.sock");
    std::fs::write(&socket, b"caller-owned").expect("create caller-owned path");
    let provider = Arc::new(FixedProvider(empty_snapshot(1)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));

    let error = run_source_server(
        SourceServerConfig::new(&socket).with_expected_collector_uid(unsafe { libc::geteuid() }),
        provider,
        dirty,
        std::future::pending(),
    )
    .await
    .expect_err("preexisting socket path");

    assert_eq!(error.kind(), KubernetesSourceErrorKind::Unauthorized);
    assert_eq!(
        std::fs::read(&socket).expect("preexisting path retained"),
        b"caller-owned"
    );
}

#[tokio::test]
async fn production_server_recovers_only_an_owned_stale_socket_after_a_crash() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let parent = directory.path().join("source");
    std::fs::create_dir(&parent).expect("create source-owned parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restrict source-owned parent");
    let socket = parent.join("source.sock");
    create_abandoned_socket(&socket, 0o660);

    let provider = Arc::new(FixedProvider(empty_snapshot(9)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(run_source_server(
        SourceServerConfig::new(&socket)
            .with_expected_collector_uid(unsafe { libc::geteuid() })
            .with_request_timeout(Duration::from_secs(1))
            .with_dirty_wait_timeout(Duration::from_millis(100)),
        provider,
        dirty,
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    // The isolated umask regression intentionally runs many source startups in
    // a child process alongside this test. Startup itself has no one-second
    // contract, so leave enough scheduling headroom for that stress workload.
    let readiness = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let client = KubernetesSourceClient::new(
                KubernetesSourceClientConfig::new(&socket)
                    .with_expected_source_uid(unsafe { libc::geteuid() })
                    .with_expected_source_gid(unsafe { libc::getegid() })
                    .with_io_timeout(Duration::from_millis(100)),
            )
            .expect("valid client");
            if client.capture().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    if readiness.is_err() && server.is_finished() {
        let error = server
            .await
            .expect("source task")
            .expect_err("finished source task must explain missing readiness");
        panic!(
            "source task failed before stale recovery readiness: kind={:?}",
            error.kind()
        );
    }
    readiness.expect("recovered source socket readiness");

    shutdown_tx.send(()).expect("request server shutdown");
    server
        .await
        .expect("server task")
        .expect("clean source shutdown");
    assert!(std::fs::symlink_metadata(&socket).is_err());
}

#[tokio::test]
async fn production_server_recovers_an_owned_pending_socket_left_before_publication() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let parent = directory.path().join("source");
    std::fs::create_dir(&parent).expect("create source-owned parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restrict source-owned parent");
    let pending = parent.join(".apolysis-source-pending-550e8400-e29b-41d4-a716-446655440000");
    create_abandoned_socket(&pending, 0o000);
    let socket = parent.join("source.sock");
    let provider = Arc::new(FixedProvider(empty_snapshot(12)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
    run_source_server(
        SourceServerConfig::new(&socket)
            .with_expected_collector_uid(unsafe { libc::geteuid() })
            .with_request_timeout(Duration::from_secs(1))
            .with_dirty_wait_timeout(Duration::from_millis(100)),
        provider,
        dirty,
        std::future::ready(()),
    )
    .await
    .expect("source recovers abandoned pending socket");
    assert!(
        std::fs::symlink_metadata(&pending).is_err(),
        "source retained an abandoned pending socket"
    );
}

#[tokio::test]
async fn production_server_recovers_an_owned_stale_quarantine_left_before_unlink() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let parent = directory.path().join("source");
    std::fs::create_dir(&parent).expect("create source-owned parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restrict source-owned parent");
    let quarantine = parent.join(".apolysis-source-stale-550e8400-e29b-41d4-a716-446655440000");
    create_abandoned_socket(&quarantine, 0o660);
    let socket = parent.join("source.sock");
    let provider = Arc::new(FixedProvider(empty_snapshot(13)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));

    run_source_server(
        SourceServerConfig::new(&socket)
            .with_expected_collector_uid(unsafe { libc::geteuid() })
            .with_request_timeout(Duration::from_secs(1))
            .with_dirty_wait_timeout(Duration::from_millis(100)),
        provider,
        dirty,
        std::future::ready(()),
    )
    .await
    .expect("source recovers abandoned stale quarantine");
    assert!(
        std::fs::symlink_metadata(&quarantine).is_err(),
        "source retained an abandoned stale quarantine"
    );
}

#[tokio::test]
async fn production_server_preserves_an_active_owned_socket() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let parent = directory.path().join("source");
    std::fs::create_dir(&parent).expect("create source-owned parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restrict source-owned parent");
    let socket = parent.join("source.sock");
    let active = bound_source_socket(&socket).await;
    let provider = Arc::new(FixedProvider(empty_snapshot(10)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));

    let error = run_source_server(
        SourceServerConfig::new(&socket).with_expected_collector_uid(unsafe { libc::geteuid() }),
        provider,
        dirty,
        std::future::pending(),
    )
    .await
    .expect_err("active source socket must not be replaced");

    assert_eq!(error.kind(), KubernetesSourceErrorKind::Unauthorized);
    assert!(std::fs::symlink_metadata(&socket).is_ok());
    drop(active);
}

#[tokio::test]
async fn production_server_preserves_a_saturated_active_socket_without_blocking() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let parent = directory.path().join("source");
    std::fs::create_dir(&parent).expect("create source-owned parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restrict source-owned parent");
    let socket = parent.join("source.sock");
    let active = bound_source_socket(&socket).await;
    assert_eq!(unsafe { libc::listen(active.as_raw_fd(), 0) }, 0);
    let queued = StdUnixStream::connect(&socket).expect("fill active socket backlog");
    let original = std::fs::symlink_metadata(&socket).expect("active socket identity");

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let worker_socket = socket.clone();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("active probe runtime");
        let provider = Arc::new(FixedProvider(empty_snapshot(11)));
        let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
        let result = runtime.block_on(run_source_server(
            SourceServerConfig::new(&worker_socket)
                .with_expected_collector_uid(unsafe { libc::geteuid() }),
            provider,
            dirty,
            std::future::pending(),
        ));
        let _ = result_tx.send(result);
    });

    let result = result_rx.recv_timeout(Duration::from_millis(250));
    drop(queued);
    drop(active);
    worker.join().expect("active probe worker");
    let error = result
        .expect("active socket probe exceeded its deadline")
        .expect_err("active source socket must not be replaced");
    assert!(matches!(
        error.kind(),
        KubernetesSourceErrorKind::Unauthorized | KubernetesSourceErrorKind::Unavailable
    ));
    let retained = std::fs::symlink_metadata(&socket).expect("retained active socket");
    assert_eq!(retained.dev(), original.dev());
    assert_eq!(retained.ino(), original.ino());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_source_servers_publish_one_socket_without_staging_leaks() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source/source.sock");
    let (first_shutdown_tx, first_shutdown_rx) = tokio::sync::oneshot::channel();
    let (second_shutdown_tx, second_shutdown_rx) = tokio::sync::oneshot::channel();
    let first = tokio::spawn(run_source_server(
        SourceServerConfig::new(&socket).with_expected_collector_uid(unsafe { libc::geteuid() }),
        Arc::new(FixedProvider(empty_snapshot(21))),
        Arc::new(DirtyTracker::new(
            SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000").expect("source epoch"),
        )),
        async move {
            let _ = first_shutdown_rx.await;
        },
    ));
    let second = tokio::spawn(run_source_server(
        SourceServerConfig::new(&socket).with_expected_collector_uid(unsafe { libc::geteuid() }),
        Arc::new(FixedProvider(empty_snapshot(22))),
        Arc::new(DirtyTracker::new(
            SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000").expect("source epoch"),
        )),
        async move {
            let _ = second_shutdown_rx.await;
        },
    ));

    tokio::time::timeout(Duration::from_secs(1), async {
        while !socket.exists() || (!first.is_finished() && !second.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one source server publishes and one fails");
    let client = KubernetesSourceClient::new(
        KubernetesSourceClientConfig::new(&socket)
            .with_expected_source_uid(unsafe { libc::geteuid() })
            .with_expected_source_gid(unsafe { libc::getegid() })
            .with_io_timeout(Duration::from_secs(1)),
    )
    .expect("valid client");
    assert!(matches!(
        client
            .capture()
            .await
            .expect("winner source capture")
            .snapshot_sequence,
        21 | 22
    ));

    let _ = first_shutdown_tx.send(());
    let _ = second_shutdown_tx.send(());
    let first = first.await.expect("first source task");
    let second = second.await.expect("second source task");
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(
        std::fs::read_dir(socket.parent().expect("source parent"))
            .expect("read source parent")
            .next()
            .is_none(),
        "source parent retained a published or staging socket"
    );
}

#[tokio::test]
async fn production_server_preserves_a_replacement_canary_and_reports_cleanup_failure() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("source/source.sock");
    let moved_socket = directory.path().join("source/source-owned.sock");
    let provider = Arc::new(FixedProvider(empty_snapshot(1)));
    let dirty = Arc::new(DirtyTracker::new(provider.0.source_epoch.clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(run_source_server(
        SourceServerConfig::new(&socket).with_expected_collector_uid(unsafe { libc::geteuid() }),
        provider,
        dirty,
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if socket.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("source socket readiness");
    std::fs::rename(&socket, &moved_socket).expect("move source-owned socket inode");
    std::fs::write(&socket, b"replacement-canary").expect("place replacement canary");

    shutdown_tx.send(()).expect("request server shutdown");
    let error = server
        .await
        .expect("server task")
        .expect_err("replacement prevents verified cleanup");
    assert_eq!(error.kind(), KubernetesSourceErrorKind::Inconsistent);
    assert_eq!(
        std::fs::read(&socket).expect("replacement canary retained"),
        b"replacement-canary"
    );
    assert!(
        moved_socket.exists(),
        "server removed its moved socket inode"
    );
}

struct FixedProvider(KubernetesSnapshot);

impl SnapshotProvider for FixedProvider {
    fn source_epoch(&self) -> &SourceEpoch {
        &self.0.source_epoch
    }

    async fn capture(&self) -> Result<KubernetesSnapshot, KubernetesSourceError> {
        Ok(self.0.clone())
    }
}

async fn bound_source_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind source socket");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .expect("restrict source socket");
    listener
}

async fn read_frame(stream: &mut tokio::net::UnixStream, maximum: usize) -> Vec<u8> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .expect("read frame size");
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= maximum);
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await.expect("read frame body");
    body
}

async fn write_frame(stream: &mut tokio::net::UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .expect("write frame size");
    stream.write_all(body).await.expect("write frame body");
}

fn empty_snapshot(sequence: u64) -> KubernetesSnapshot {
    KubernetesSnapshot {
        schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
        source_epoch: SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("source epoch"),
        snapshot_sequence: sequence,
        cluster_id: KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000")
            .expect("cluster ID"),
        namespace_ref: kubernetes_namespace_ref("agents").expect("namespace ref"),
        node_ref: kubernetes_node_ref("worker-a").expect("node ref"),
        pods: Vec::new(),
    }
}
