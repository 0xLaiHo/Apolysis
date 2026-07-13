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
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path).map_err(GatewayServerError::io)?;
    let metadata = file.metadata().map_err(GatewayServerError::io)?;
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
        .map_err(GatewayServerError::io)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(GatewayServerError::configuration(
            "Gateway input file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::read_bounded_file;

    #[test]
    fn rejects_a_symlinked_secret_input() {
        let directory = std::env::temp_dir().join(format!(
            "apolysis-gateway-file-input-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("create real temporary test directory");
        let target = directory.join("secret.target");
        let link = directory.join("secret.link");
        fs::write(&target, b"secret").expect("write real temporary secret");
        symlink(&target, &link).expect("create real temporary symlink");

        assert!(read_bounded_file(&link, 32, false).is_err());

        fs::remove_dir_all(&directory).expect("remove real temporary test directory");
    }
}
