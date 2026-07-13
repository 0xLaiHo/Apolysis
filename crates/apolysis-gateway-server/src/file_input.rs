// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::GatewayServerError;

/// Read a bounded regular file without following a terminal symlink.
///
/// Secret-bearing inputs additionally require that group and other permission
/// bits are clear. Callers own format validation and any required zeroization.
pub(crate) fn read_bounded_file(
    path: &Path,
    maximum_bytes: u64,
    require_private_permissions: bool,
) -> Result<Vec<u8>, GatewayServerError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        // Opening a FIFO read-only blocks before `metadata` can reject it.
        // O_NONBLOCK makes the open safe; it has no effect on regular files.
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|error| GatewayServerError::io_at("input-open", error))?;
    // This is fstat on the opened descriptor, not a second path lookup.
    let metadata = file
        .metadata()
        .map_err(|error| GatewayServerError::io_at("input-metadata", error))?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(GatewayServerError::configuration(
            "Gateway input file is not a bounded regular file",
        ));
    }
    if require_private_permissions && metadata.mode() & 0o077 != 0 {
        return Err(GatewayServerError::configuration(
            "Gateway secret file permissions are too broad",
        ));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| GatewayServerError::io_at("input-read", error))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(GatewayServerError::configuration(
            "Gateway input file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::CString,
        fs::{self, OpenOptions},
        os::unix::{ffi::OsStrExt, fs::symlink, fs::OpenOptionsExt},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use super::read_bounded_file;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "apolysis-gateway-file-input-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create real temporary test directory");
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
    fn rejects_a_symlinked_secret_input() {
        let directory = TestDirectory::create();
        let target = directory.path().join("secret.target");
        let link = directory.path().join("secret.link");
        fs::write(&target, b"secret").expect("write real temporary secret");
        symlink(&target, &link).expect("create real temporary symlink");

        assert!(read_bounded_file(&link, 32, false).is_err());
    }

    #[test]
    fn rejects_a_real_fifo_without_blocking() {
        let directory = TestDirectory::create();
        let fifo = directory.path().join("secret.fifo");
        let fifo_bytes = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
        // SAFETY: fifo_bytes is a live NUL-terminated pathname and mkfifo does
        // not retain the pointer after returning.
        let result = unsafe { libc::mkfifo(fifo_bytes.as_ptr(), 0o600) };
        assert_eq!(result, 0, "create real kernel FIFO");

        let worker_path = fifo.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = read_bounded_file(&worker_path, 32, true);
            let _ = sender.send(result);
        });

        let read_result = match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Keep the regression test bounded even if O_NONBLOCK is
                // accidentally removed: an O_RDWR FIFO descriptor releases a
                // reader blocked in open so the worker can finish and join.
                let mut options = OpenOptions::new();
                options
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
                let unblocker = options
                    .open(&fifo)
                    .expect("unblock a regressed FIFO reader");
                let result = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("FIFO reader exits after being unblocked");
                drop(unblocker);
                worker.join().expect("join FIFO reader");
                assert!(result.is_err());
                panic!("bounded file reader blocked while opening a FIFO");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                worker.join().expect("surface FIFO reader panic");
                panic!("FIFO reader disconnected without a result");
            }
        };

        worker.join().expect("join FIFO reader");
        assert!(read_result.is_err());
    }
}
