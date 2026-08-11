// SPDX-License-Identifier: Apache-2.0

use crate::{ensure, Result, VerifierError};
use std::collections::BTreeMap;

type Directives = BTreeMap<String, String>;

pub(crate) fn validate_unit(unit_text: &str) -> Result<()> {
    let parsed = parse_unit(unit_text)?;
    let expected = expected_unit();
    ensure!(
        parsed.keys().collect::<Vec<_>>() == expected.keys().collect::<Vec<_>>(),
        "systemd unit section set mismatch"
    );
    for (section, expected_directives) in expected {
        let directives = parsed.get(section).ok_or_else(|| {
            VerifierError::new(format!("systemd unit section is missing: {section}"))
        })?;
        ensure!(
            directives == &expected_directives,
            format!("systemd unit {section} contract mismatch")
        );
    }
    Ok(())
}

fn parse_unit(unit_text: &str) -> Result<BTreeMap<String, Directives>> {
    let mut sections = BTreeMap::new();
    let mut section_order = Vec::new();
    let mut current_section: Option<String> = None;

    for (line_index, raw_line) in unit_text.lines().enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(section) = parse_section_header(line) {
            ensure!(
                matches!(section, "Unit" | "Service" | "Install"),
                "systemd unit section set mismatch"
            );
            ensure!(
                !sections.contains_key(section),
                format!("duplicate systemd unit section: {section}")
            );
            sections.insert(section.to_owned(), Directives::new());
            section_order.push(section.to_owned());
            current_section = Some(section.to_owned());
            continue;
        }
        ensure!(
            !line.starts_with(char::is_whitespace),
            format!(
                "systemd unit continuation line is forbidden at line {}",
                line_index + 1
            )
        );
        let (key, value) = split_directive(line).ok_or_else(|| {
            VerifierError::new(format!(
                "invalid systemd unit directive at line {}",
                line_index + 1
            ))
        })?;
        ensure!(
            !key.is_empty(),
            format!("empty systemd unit directive at line {}", line_index + 1)
        );
        let section = current_section
            .as_deref()
            .ok_or_else(|| VerifierError::new("systemd unit DEFAULT entries are forbidden"))?;
        let directives = sections
            .get_mut(section)
            .ok_or_else(|| VerifierError::new(format!("systemd parser lost section {section}")))?;
        ensure!(
            directives
                .insert(key.to_owned(), value.to_owned())
                .is_none(),
            format!("duplicate systemd unit directive: {section}.{key}")
        );
    }

    ensure!(
        section_order == ["Unit", "Service", "Install"],
        "systemd unit section headers differ from the contract"
    );
    Ok(sections)
}

fn parse_section_header(line: &str) -> Option<&str> {
    let line = line.trim_end_matches([' ', '\t']);
    line.strip_prefix('[')?.strip_suffix(']')
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    let equal = line.find('=');
    let colon = line.find(':');
    let delimiter = match (equal, colon) {
        (Some(equal), Some(colon)) => equal.min(colon),
        (Some(equal), None) => equal,
        (None, Some(colon)) => colon,
        (None, None) => return None,
    };
    Some((line[..delimiter].trim(), line[delimiter + 1..].trim()))
}

fn expected_unit() -> BTreeMap<&'static str, Directives> {
    BTreeMap::from([
        (
            "Unit",
            directives(&[
                (
                    "Description",
                    "Apolysis local eBPF Agent observability daemon",
                ),
                ("After", "network-online.target"),
                ("Wants", "network-online.target"),
                ("StartLimitIntervalSec", "60s"),
                ("StartLimitBurst", "5"),
            ]),
        ),
        (
            "Service",
            directives(&[
                ("Type", "simple"),
                ("User", "root"),
                ("Group", "apolysis"),
                ("UMask", "0027"),
                ("RuntimeDirectory", "apolysis"),
                ("RuntimeDirectoryMode", "0750"),
                ("StateDirectory", "apolysis"),
                ("StateDirectoryMode", "0750"),
                (
                    "ExecStart",
                    "/usr/local/bin/apolysisd --bpf-object /usr/local/lib/apolysis/apolysis_observer.bpf.o --queue-capacity 16384 --scope-command-capacity 1024 --shutdown-drain-ms 5000",
                ),
                ("KillSignal", "SIGTERM"),
                ("TimeoutStopSec", "15s"),
                ("Restart", "on-failure"),
                ("RestartSec", "2s"),
                ("NoNewPrivileges", "yes"),
                ("ProtectHome", "yes"),
                ("ProtectSystem", "strict"),
                ("ReadWritePaths", "/run/apolysis /var/lib/apolysis"),
                ("PrivateTmp", "yes"),
            ]),
        ),
        (
            "Install",
            directives(&[("WantedBy", "multi-user.target")]),
        ),
    ])
}

fn directives(values: &[(&str, &str)]) -> Directives {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}
