// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use zeroize::Zeroizing;

use crate::{file_input::read_bounded_file, GatewayServerError};

pub(super) const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;
pub(super) const MAX_DATABASE_URL_BYTES: usize = 8 * 1024;
pub(super) const MAX_REGISTRATION_BYTES: usize = 64 * 1024;
pub(super) const MAX_CERTIFICATE_PEM_BYTES: usize = 128 * 1024;

pub(super) fn read_database_url(path: &Path) -> Result<Zeroizing<String>, GatewayServerError> {
    require_absolute_path(path)?;
    let bytes = Zeroizing::new(read_bounded_file(
        path,
        MAX_DATABASE_URL_BYTES as u64,
        true,
    )?);
    if bytes.is_empty() || bytes.len() > MAX_DATABASE_URL_BYTES {
        return Err(GatewayServerError::configuration(
            "Gateway database URL file is invalid",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        GatewayServerError::configuration("Gateway database URL file must be UTF-8")
    })?;
    let value = text.trim();
    if value.is_empty()
        || value.chars().any(char::is_control)
        || !(value.starts_with("postgres://") || value.starts_with("postgresql://"))
    {
        return Err(GatewayServerError::configuration(
            "Gateway database URL file is invalid",
        ));
    }
    Ok(Zeroizing::new(value.to_string()))
}

pub(super) fn current_unix_ms() -> Result<u64, GatewayServerError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayServerError::configuration("Gateway clock is invalid"))?
        .as_millis();
    u64::try_from(milliseconds)
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_IJSON_INTEGER)
        .ok_or_else(|| GatewayServerError::configuration("Gateway clock is invalid"))
}

pub(super) fn checked_database_integer(
    value: u64,
    message: &'static str,
) -> Result<i64, GatewayServerError> {
    if value == 0 || value > MAX_IJSON_INTEGER {
        return Err(GatewayServerError::configuration(message));
    }
    i64::try_from(value).map_err(|_| GatewayServerError::configuration(message))
}

pub(super) fn validate_contract_identifier(
    value: &str,
    message: &'static str,
) -> Result<(), GatewayServerError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(message))
    }
}

pub(super) fn require_only_options(
    options: &BTreeMap<String, OsString>,
    allowed: &[&str],
) -> Result<(), GatewayServerError> {
    if options
        .keys()
        .all(|option| allowed.contains(&option.as_str()))
    {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(
            "Authority received an unsupported option",
        ))
    }
}

pub(super) fn required_path(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<PathBuf, GatewayServerError> {
    let path = PathBuf::from(options.remove(option).ok_or_else(|| {
        GatewayServerError::configuration("Authority is missing a required option")
    })?);
    require_absolute_path(&path)?;
    Ok(path)
}

pub(super) fn required_string(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<String, GatewayServerError> {
    options
        .remove(option)
        .ok_or_else(|| GatewayServerError::configuration("Authority is missing a required option"))?
        .into_string()
        .map_err(|_| GatewayServerError::configuration("Authority option values must be UTF-8"))
}

pub(super) fn require_absolute_path(path: &Path) -> Result<(), GatewayServerError> {
    if !path.as_os_str().is_empty() && path.is_absolute() {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(
            "Authority file paths must be absolute",
        ))
    }
}
