// SPDX-License-Identifier: Apache-2.0

use crate::{ensure, Result, ResultContext, VerifierError};
use std::collections::BTreeMap;

const ELF_HEADER_BYTES: usize = 64;
const ET_REL: u16 = 1;
const ET_DYN: u16 = 3;
const EM_BPF: u16 = 247;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const BTF_MAGIC: u16 = 0xeb9f;

#[derive(Clone, Copy)]
struct Section {
    section_type: u32,
    flags: u64,
    file_offset: u64,
    size: u64,
}

pub(crate) fn validate_userspace(
    metadata: &[u8],
    observed_size: u64,
    relative_path: &str,
    expected_machine: u16,
) -> Result<()> {
    validate_identity(metadata, relative_path, ET_DYN, expected_machine)?;
    let entry_point = read_u64(metadata, 24, relative_path)?;
    let program_offset = read_u64(metadata, 32, relative_path)?;
    let program_entry_size = u64::from(read_u16(metadata, 54, relative_path)?);
    let program_count = u64::from(read_u16(metadata, 56, relative_path)?);
    ensure!(
        entry_point != 0,
        format!("userspace ELF has no entry point: {relative_path}")
    );
    ensure!(
        program_offset >= ELF_HEADER_BYTES as u64 && program_entry_size == 56 && program_count > 0,
        format!("userspace ELF has no valid program table: {relative_path}")
    );
    let table_size = program_entry_size
        .checked_mul(program_count)
        .ok_or_else(|| {
            VerifierError::new(format!(
                "userspace ELF program table overflows: {relative_path}"
            ))
        })?;
    let table_end = program_offset.checked_add(table_size).ok_or_else(|| {
        VerifierError::new(format!(
            "userspace ELF program table overflows: {relative_path}"
        ))
    })?;
    ensure!(
        table_end <= observed_size,
        format!("userspace ELF program table exceeds the file: {relative_path}")
    );
    ensure!(
        table_end <= metadata.len() as u64,
        format!("userspace ELF program table exceeds the metadata bound: {relative_path}")
    );

    let mut executable_entry = false;
    for index in 0..program_count {
        let start = program_offset
            .checked_add(index.checked_mul(program_entry_size).ok_or_else(|| {
                VerifierError::new(format!(
                    "userspace ELF program offset overflows: {relative_path}"
                ))
            })?)
            .ok_or_else(|| {
                VerifierError::new(format!(
                    "userspace ELF program offset overflows: {relative_path}"
                ))
            })?;
        let start = usize::try_from(start)
            .context(|| format!("userspace ELF program offset is invalid: {relative_path}"))?;
        let program_type = read_u32(metadata, start, relative_path)?;
        let program_flags = read_u32(metadata, start + 4, relative_path)?;
        let file_offset = read_u64(metadata, start + 8, relative_path)?;
        let virtual_address = read_u64(metadata, start + 16, relative_path)?;
        let file_size = read_u64(metadata, start + 32, relative_path)?;
        let memory_size = read_u64(metadata, start + 40, relative_path)?;
        let alignment = read_u64(metadata, start + 48, relative_path)?;
        let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
            VerifierError::new(format!("userspace ELF segment overflows: {relative_path}"))
        })?;
        ensure!(
            file_end <= observed_size,
            format!("userspace ELF segment exceeds the file: {relative_path}")
        );
        if program_type == PT_LOAD {
            ensure!(
                file_size <= memory_size,
                format!("userspace LOAD file size exceeds memory size: {relative_path}")
            );
            ensure!(
                matches!(alignment, 0 | 1) || alignment.is_power_of_two(),
                format!("userspace LOAD alignment is invalid: {relative_path}")
            );
            if alignment > 1 {
                ensure!(
                    virtual_address % alignment == file_offset % alignment,
                    format!("userspace LOAD alignment is inconsistent: {relative_path}")
                );
            }
        }
        let virtual_file_end = virtual_address.checked_add(file_size).ok_or_else(|| {
            VerifierError::new(format!("userspace LOAD address overflows: {relative_path}"))
        })?;
        if program_type == PT_LOAD
            && program_flags & PF_X != 0
            && file_size > 0
            && memory_size >= file_size
            && virtual_address <= entry_point
            && entry_point < virtual_file_end
        {
            executable_entry = true;
        }
    }
    ensure!(
        executable_entry,
        format!("userspace ELF entry is not in an executable LOAD: {relative_path}")
    );
    Ok(())
}

pub(crate) fn validate_bpf(metadata: &[u8], observed_size: u64) -> Result<()> {
    const PATH: &str = "ebpf/apolysis_observer.bpf.o";
    validate_identity(metadata, PATH, ET_REL, EM_BPF)?;
    ensure!(
        read_u64(metadata, 24, PATH)? == 0,
        "eBPF ELF entry point is nonzero"
    );
    ensure!(
        read_u64(metadata, 32, PATH)? == 0 && read_u16(metadata, 56, PATH)? == 0,
        "eBPF ELF has program headers"
    );
    let section_offset = read_u64(metadata, 40, PATH)?;
    let section_entry_size = u64::from(read_u16(metadata, 58, PATH)?);
    let section_count = u64::from(read_u16(metadata, 60, PATH)?);
    let string_table_index = u64::from(read_u16(metadata, 62, PATH)?);
    ensure!(
        section_offset >= ELF_HEADER_BYTES as u64 && section_entry_size == 64 && section_count > 0,
        "eBPF ELF has no valid section table"
    );
    let table_size = section_entry_size
        .checked_mul(section_count)
        .ok_or_else(|| VerifierError::new("eBPF ELF section table overflows"))?;
    let table_end = section_offset
        .checked_add(table_size)
        .ok_or_else(|| VerifierError::new("eBPF ELF section table overflows"))?;
    ensure!(
        table_end <= observed_size,
        "eBPF ELF section table exceeds the file"
    );
    ensure!(
        table_end <= metadata.len() as u64,
        "eBPF ELF section table exceeds the metadata bound"
    );
    ensure!(
        string_table_index > 0 && string_table_index < section_count,
        "eBPF ELF has no section-name table"
    );

    let mut sections = Vec::with_capacity(
        usize::try_from(section_count)
            .context(|| "eBPF section count does not fit memory".to_owned())?,
    );
    for index in 0..section_count {
        let start = section_offset
            .checked_add(
                index
                    .checked_mul(section_entry_size)
                    .ok_or_else(|| VerifierError::new("eBPF section table offset overflows"))?,
            )
            .ok_or_else(|| VerifierError::new("eBPF section table offset overflows"))?;
        let start =
            usize::try_from(start).context(|| "eBPF section table offset is invalid".to_owned())?;
        let name_offset = read_u32(metadata, start, PATH)?;
        let section_type = read_u32(metadata, start + 4, PATH)?;
        let flags = read_u64(metadata, start + 8, PATH)?;
        let file_offset = read_u64(metadata, start + 24, PATH)?;
        let size = read_u64(metadata, start + 32, PATH)?;
        if section_type != SHT_NOBITS {
            let section_end = file_offset
                .checked_add(size)
                .ok_or_else(|| VerifierError::new("eBPF section range overflows"))?;
            ensure!(
                section_end <= observed_size,
                "eBPF section exceeds the file"
            );
        }
        sections.push((
            name_offset,
            Section {
                section_type,
                flags,
                file_offset,
                size,
            },
        ));
    }

    let string_index = usize::try_from(string_table_index)
        .context(|| "eBPF section-name table index is invalid".to_owned())?;
    let string_section = sections
        .get(string_index)
        .map(|(_, section)| *section)
        .ok_or_else(|| VerifierError::new("eBPF section-name table is missing"))?;
    ensure!(
        string_section.section_type == SHT_STRTAB && string_section.size > 0,
        "eBPF section-name table is invalid"
    );
    let string_table = section_payload(metadata, string_section, "section-name table")?;

    let mut named_sections = BTreeMap::new();
    for (name_offset, section) in sections {
        let name = section_name(string_table, name_offset)?;
        ensure!(
            named_sections.insert(name, section).is_none(),
            "duplicate eBPF section name"
        );
    }
    for required in ["license", ".maps", ".BTF", ".BTF.ext"] {
        let section = named_sections
            .get(required)
            .ok_or_else(|| VerifierError::new("eBPF object lacks required metadata sections"))?;
        ensure!(
            section.section_type == SHT_PROGBITS && section.size > 0,
            "eBPF metadata section is empty"
        );
    }
    ensure!(
        named_sections.iter().any(|(name, section)| {
            name.starts_with("tracepoint/")
                && section.section_type == SHT_PROGBITS
                && section.flags & (SHF_ALLOC | SHF_EXECINSTR) == (SHF_ALLOC | SHF_EXECINSTR)
                && section.size > 0
                && section.size % 8 == 0
        }),
        "eBPF object lacks an executable tracepoint section"
    );

    let btf_section = *named_sections
        .get(".BTF")
        .ok_or_else(|| VerifierError::new("eBPF BTF section is missing"))?;
    validate_btf(section_payload(metadata, btf_section, ".BTF")?)?;
    let btf_ext_section = *named_sections
        .get(".BTF.ext")
        .ok_or_else(|| VerifierError::new("eBPF BTF.ext section is missing"))?;
    validate_btf_ext(section_payload(metadata, btf_ext_section, ".BTF.ext")?)
}

fn validate_identity(
    metadata: &[u8],
    relative_path: &str,
    expected_type: u16,
    expected_machine: u16,
) -> Result<()> {
    ensure!(
        metadata.len() >= ELF_HEADER_BYTES && metadata.get(0..4) == Some(b"\x7fELF"),
        format!("not ELF: {relative_path}")
    );
    ensure!(
        metadata.get(4..7) == Some(&[2, 1, 1]),
        format!("unsupported ELF identity: {relative_path}")
    );
    ensure!(
        read_u16(metadata, 16, relative_path)? == expected_type,
        format!("wrong ELF type: {relative_path}")
    );
    ensure!(
        read_u16(metadata, 18, relative_path)? == expected_machine,
        format!("wrong ELF machine: {relative_path}")
    );
    ensure!(
        read_u32(metadata, 20, relative_path)? == 1,
        format!("wrong ELF version: {relative_path}")
    );
    ensure!(
        read_u16(metadata, 52, relative_path)? == ELF_HEADER_BYTES as u16,
        format!("wrong ELF header size: {relative_path}")
    );
    Ok(())
}

fn validate_btf(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 24 && read_u16(bytes, 0, ".BTF")? == BTF_MAGIC,
        "eBPF BTF header is invalid"
    );
    ensure!(
        bytes[2] == 1 && bytes[3] == 0,
        "eBPF BTF version or flags are invalid"
    );
    let header_size = u64::from(read_u32(bytes, 4, ".BTF")?);
    ensure!(
        header_size >= 24 && header_size <= bytes.len() as u64,
        "eBPF BTF header size is invalid"
    );
    let type_offset = u64::from(read_u32(bytes, 8, ".BTF")?);
    let type_size = u64::from(read_u32(bytes, 12, ".BTF")?);
    let string_offset = u64::from(read_u32(bytes, 16, ".BTF")?);
    let string_size = u64::from(read_u32(bytes, 20, ".BTF")?);
    ensure_relative_range(
        bytes.len() as u64,
        header_size,
        type_offset,
        type_size,
        "eBPF BTF type data exceeds its section",
    )?;
    ensure_relative_range(
        bytes.len() as u64,
        header_size,
        string_offset,
        string_size,
        "eBPF BTF string data exceeds its section",
    )?;
    let string_start = header_size
        .checked_add(string_offset)
        .ok_or_else(|| VerifierError::new("eBPF BTF string table overflows"))?;
    let string_start = usize::try_from(string_start)
        .context(|| "eBPF BTF string table offset is invalid".to_owned())?;
    ensure!(
        string_size > 0 && bytes.get(string_start) == Some(&0),
        "eBPF BTF string table is invalid"
    );
    Ok(())
}

fn validate_btf_ext(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 32 && read_u16(bytes, 0, ".BTF.ext")? == BTF_MAGIC,
        "eBPF BTF.ext header is invalid"
    );
    ensure!(
        bytes[2] == 1 && bytes[3] == 0,
        "eBPF BTF.ext version or flags are invalid"
    );
    let header_size = u64::from(read_u32(bytes, 4, ".BTF.ext")?);
    ensure!(
        header_size >= 32 && header_size <= bytes.len() as u64,
        "eBPF BTF.ext header size is invalid"
    );
    for offset_index in [8, 16, 24] {
        let subsection_offset = u64::from(read_u32(bytes, offset_index, ".BTF.ext")?);
        let subsection_size = u64::from(read_u32(bytes, offset_index + 4, ".BTF.ext")?);
        ensure_relative_range(
            bytes.len() as u64,
            header_size,
            subsection_offset,
            subsection_size,
            "eBPF BTF.ext subsection exceeds its section",
        )?;
    }
    Ok(())
}

fn ensure_relative_range(
    container_size: u64,
    header_size: u64,
    offset: u64,
    size: u64,
    message: &str,
) -> Result<()> {
    let end = header_size
        .checked_add(offset)
        .and_then(|start| start.checked_add(size))
        .ok_or_else(|| VerifierError::new(message))?;
    ensure!(end <= container_size, message);
    Ok(())
}

fn section_payload<'a>(metadata: &'a [u8], section: Section, name: &str) -> Result<&'a [u8]> {
    let start = usize::try_from(section.file_offset)
        .context(|| format!("eBPF {name} offset is invalid"))?;
    let size = usize::try_from(section.size).context(|| format!("eBPF {name} size is invalid"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| VerifierError::new(format!("eBPF {name} range overflows")))?;
    metadata
        .get(start..end)
        .ok_or_else(|| VerifierError::new(format!("eBPF {name} exceeds the file")))
}

fn section_name(string_table: &[u8], offset: u32) -> Result<String> {
    let start =
        usize::try_from(offset).context(|| "eBPF section name offset is invalid".to_owned())?;
    let suffix = string_table
        .get(start..)
        .ok_or_else(|| VerifierError::new("eBPF section name offset is invalid"))?;
    let length = suffix
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| VerifierError::new("eBPF section name is unterminated"))?;
    std::str::from_utf8(&suffix[..length])
        .context(|| "eBPF section name is not ASCII".to_owned())
        .and_then(|name| {
            ensure!(name.is_ascii(), "eBPF section name is not ASCII");
            Ok(name.to_owned())
        })
}

fn read_u16(bytes: &[u8], offset: usize, name: &str) -> Result<u16> {
    let array = read_array::<2>(bytes, offset, name)?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize, name: &str) -> Result<u32> {
    let array = read_array::<4>(bytes, offset, name)?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    let array = read_array::<8>(bytes, offset, name)?;
    Ok(u64::from_le_bytes(array))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize, name: &str) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| VerifierError::new(format!("ELF offset overflows: {name}")))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| VerifierError::new(format!("ELF metadata is truncated: {name}")))?
        .try_into()
        .context(|| format!("ELF field has the wrong width: {name}"))
}
