//! Native structural triage of PE / ELF / Mach-O in pure Rust (via `goblin`).
//!
//! Runs in milliseconds with no Java or Ghidra, and produces the same
//! [`WisdraReport`] shape as the Ghidra engine (minus decompilation-based
//! findings such as vulnerabilities and kill chains). It also supplies
//! [`BinaryInfo`] (imphash, signature presence, overlay, packer hints) that
//! the Ghidra engine attaches to its own reports.

use crate::error::{Result, WisdraError};
use crate::heuristics;
use crate::model::{BinaryInfo, EntropyEntry, ImportEntry, Metadata, SCHEMA_VERSION, SectionInfo, WisdraReport};
use crate::{hashing, save_report};
use goblin::Object;
use md5::{Digest, Md5};
use std::path::{Path, PathBuf};

/// Max strings kept in a report.
const MAX_STRINGS: usize = 500;
const MIN_STRING_LEN: usize = 6;

/// Section names left behind by common packers and protectors.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    ("PEC2", "PECompact"),
    ("pec2", "PECompact"),
    (".packed", "generic"),
    ("FSG!", "FSG"),
    (".perplex", "Perplex"),
    (".y0da", "yoda"),
];

/// Result of a native analysis.
#[derive(Debug)]
pub struct Analysis {
    pub report: WisdraReport,
    pub report_path: PathBuf,
}

/// Hash, parse and assess `target`, then save `<output_dir>/<sha256>.json`.
pub fn analyze_file(target: &Path, output_dir: &Path) -> Result<Analysis> {
    if !target.is_file() {
        return Err(WisdraError::TargetNotFound(target.to_path_buf()));
    }
    let hashes = hashing::hash_file(target)?;
    let data = std::fs::read(target)?;
    let name = target.file_name().map_or_else(|| "unknown".into(), |n| n.to_string_lossy().into_owned());

    let mut report = analyze_bytes(&data, &name)
        .map_err(|reason| WisdraError::Unparseable { path: target.to_path_buf(), reason })?;
    report.metadata.sha256 = hashes.sha256;
    report.metadata.md5 = hashes.md5;
    report.metadata.sha1 = hashes.sha1;
    report.metadata.file_size = hashes.size;

    let report_path = save_report(&report, output_dir)?;
    Ok(Analysis { report, report_path })
}

/// Parse an in-memory binary into a report (hash fields left empty).
pub fn analyze_bytes(data: &[u8], file_name: &str) -> std::result::Result<WisdraReport, String> {
    let parsed = parse(data)?;

    let exec: Vec<&str> =
        parsed.sections.iter().filter(|s| s.info.permissions.contains('X')).map(|s| s.info.name.as_str()).collect();
    let entropy: Vec<EntropyEntry> = parsed
        .sections
        .iter()
        .filter_map(|s| s.data.map(|d| (s, heuristics::shannon_entropy(d))))
        .map(|(s, e)| EntropyEntry {
            section: s.info.name.clone(),
            entropy: (e * 10_000.0).round() / 10_000.0,
            suspicious: e > 7.0,
            verdict: heuristics::entropy_verdict(e).into(),
        })
        .collect();

    let mut threat = heuristics::assess(&parsed.imports, &entropy, &exec, &parsed.info.packer_hints);
    threat.extra.insert("engine".into(), "native".into());

    Ok(WisdraReport {
        schema_version: SCHEMA_VERSION,
        metadata: Metadata {
            file_name: file_name.to_string(),
            file_format: parsed.format.into(),
            architecture: parsed.arch,
            entry_point: format!("0x{:X}", parsed.entry),
            image_base: format!("0x{:X}", parsed.image_base),
            file_size: data.len() as u64,
            engine: "native".into(),
            ..Default::default()
        },
        threat_indicators: threat,
        imports: parsed.imports,
        sections: parsed.sections.into_iter().map(|s| s.info).collect(),
        entropy_analysis: entropy,
        binary: Some(parsed.info),
        vulnerabilities: Vec::new(),
        kill_chains: Vec::new(),
        deobfuscation: Vec::new(),
        strings: extract_strings(data),
        extra: Default::default(),
    })
}

/// Format-level details only (used to enrich Ghidra reports).
pub fn binary_info(data: &[u8]) -> std::result::Result<BinaryInfo, String> {
    parse(data).map(|p| p.info)
}

struct Section<'a> {
    info: SectionInfo,
    data: Option<&'a [u8]>,
}

struct Parsed<'a> {
    format: &'static str,
    arch: String,
    entry: u64,
    image_base: u64,
    sections: Vec<Section<'a>>,
    imports: Vec<ImportEntry>,
    info: BinaryInfo,
}

fn parse(data: &[u8]) -> std::result::Result<Parsed<'_>, String> {
    match Object::parse(data).map_err(|e| e.to_string())? {
        Object::PE(pe) => Ok(parse_pe(&pe, data)),
        Object::Elf(elf) => Ok(parse_elf(&elf, data)),
        Object::Mach(goblin::mach::Mach::Binary(m)) => Ok(parse_macho(&m)),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => match fat.get(0).map_err(|e| e.to_string())? {
            goblin::mach::SingleArch::MachO(m) => Ok(parse_macho(&m)),
            goblin::mach::SingleArch::Archive(_) => Err("fat Mach-O containing an archive".into()),
        },
        Object::Archive(_) => Err("static archives (.a/.lib) are not supported".into()),
        _ => Err("unrecognized file format".into()),
    }
}

// ---------------------------------------------------------------- PE

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn parse_pe<'a>(pe: &goblin::pe::PE<'a>, data: &'a [u8]) -> Parsed<'a> {
    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| {
            let name = s.name().unwrap_or("?").trim_end_matches('\0').to_string();
            let mut perms = String::new();
            for (flag, c) in [(IMAGE_SCN_MEM_READ, 'R'), (IMAGE_SCN_MEM_WRITE, 'W'), (IMAGE_SCN_MEM_EXECUTE, 'X')] {
                if s.characteristics & flag != 0 {
                    perms.push(c);
                }
            }
            let start = s.pointer_to_raw_data as usize;
            let raw = data.get(start..start.saturating_add(s.size_of_raw_data as usize));
            Section {
                info: SectionInfo {
                    name,
                    virtual_address: format!("0x{:X}", pe.image_base + u64::from(s.virtual_address)),
                    virtual_size: u64::from(s.virtual_size),
                    raw_size: u64::from(s.size_of_raw_data),
                    permissions: perms,
                },
                data: raw.filter(|d| !d.is_empty()),
            }
        })
        .collect();

    let imports: Vec<ImportEntry> = pe
        .imports
        .iter()
        .map(|i| {
            let function = import_name(i);
            ImportEntry {
                library: i.dll.to_string(),
                category: heuristics::categorize(&function).map(str::to_string),
                address: format!("0x{:X}", pe.image_base + i.rva as u64),
                function,
            }
        })
        .collect();

    let optional = pe.header.optional_header.as_ref();
    let cert = optional.and_then(|o| o.data_directories.get_certificate_table()).filter(|c| c.size > 0);
    let has_signature = cert.is_some();

    // Overlay: data past the end of the last section, excluding a trailing certificate table.
    let sections_end =
        pe.sections.iter().map(|s| u64::from(s.pointer_to_raw_data) + u64::from(s.size_of_raw_data)).max().unwrap_or(0);
    let mut overlay = (data.len() as u64).saturating_sub(sections_end);
    if let Some(c) = cert
        && u64::from(c.virtual_address) >= sections_end
    {
        overlay = overlay.saturating_sub(u64::from(c.size));
    }

    let mut packer_hints: Vec<String> = Vec::new();
    for s in &sections {
        if let Some((_, packer)) = PACKER_SECTIONS.iter().find(|(n, _)| *n == s.info.name)
            && !packer_hints.iter().any(|h| h == packer)
        {
            packer_hints.push((*packer).to_string());
        }
    }
    let entry_rva = pe.entry as u64;
    if let Some(s) = pe.sections.iter().find(|s| {
        let start = u64::from(s.virtual_address);
        entry_rva >= start && entry_rva < start + u64::from(s.virtual_size.max(s.size_of_raw_data))
    }) && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
    {
        packer_hints.push("entry point in writable section".into());
    }
    let has_resolver = pe.imports.iter().any(|i| i.name.starts_with("GetProcAddress"))
        && pe.imports.iter().any(|i| i.name.starts_with("LoadLibrary"));
    if !pe.imports.is_empty() && pe.imports.len() <= 6 && has_resolver {
        packer_hints.push("minimal import table with runtime API resolution".into());
    }

    Parsed {
        format: "Portable Executable (PE)",
        arch: goblin::pe::header::machine_to_str(pe.header.coff_header.machine).to_string(),
        entry: pe.image_base + entry_rva,
        image_base: pe.image_base,
        info: BinaryInfo {
            is_64bit: pe.is_64,
            is_library: pe.is_lib,
            imphash: imphash(pe),
            compile_timestamp: Some(pe.header.coff_header.time_date_stamp),
            subsystem: optional.map(|o| subsystem_name(o.windows_fields.subsystem).to_string()),
            has_signature,
            overlay_size: overlay,
            export_count: pe.exports.len(),
            packer_hints,
            interpreter: None,
            stripped: pe.debug_data.is_none(),
        },
        sections,
        imports,
    }
}

/// Name of a PE import; ordinal-only imports are resolved like pefile does
/// (known ws2_32/wsock32/oleaut32 ordinals by name, otherwise `ordN`).
fn import_name(i: &goblin::pe::import::Import) -> String {
    if i.name.starts_with("ORDINAL ") {
        crate::ordinals::lookup(&i.dll.to_ascii_lowercase(), i.ordinal)
            .map_or_else(|| format!("ord{}", i.ordinal), str::to_string)
    } else {
        i.name.to_string()
    }
}

/// Import hash, byte-for-byte compatible with `pefile.get_imphash()`.
pub fn imphash(pe: &goblin::pe::PE) -> Option<String> {
    if pe.imports.is_empty() {
        return None;
    }
    let parts: Vec<String> = pe
        .imports
        .iter()
        .map(|i| {
            let dll = i.dll.to_ascii_lowercase();
            let lib = match dll.rsplit_once('.') {
                Some((stem, "dll" | "ocx" | "sys")) => stem.to_string(),
                _ => dll,
            };
            format!("{lib}.{}", import_name(i).to_ascii_lowercase())
        })
        .collect();
    Some(hex::encode(Md5::digest(parts.join(",").as_bytes())))
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_console",
        5 => "os2_console",
        7 => "posix_console",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------- ELF

fn parse_elf<'a>(elf: &goblin::elf::Elf<'a>, data: &'a [u8]) -> Parsed<'a> {
    use goblin::elf::section_header::{SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

    let sections: Vec<Section> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_name != 0)
        .map(|sh| {
            let mut perms = String::from("R");
            if sh.sh_flags & u64::from(SHF_WRITE) != 0 {
                perms.push('W');
            }
            if sh.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
                perms.push('X');
            }
            let raw = if sh.sh_type == SHT_NOBITS {
                None
            } else {
                let start = sh.sh_offset as usize;
                data.get(start..start.saturating_add(sh.sh_size as usize)).filter(|d| !d.is_empty())
            };
            Section {
                info: SectionInfo {
                    name: elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?").to_string(),
                    virtual_address: format!("0x{:X}", sh.sh_addr),
                    virtual_size: sh.sh_size,
                    raw_size: if sh.sh_type == SHT_NOBITS { 0 } else { sh.sh_size },
                    permissions: perms,
                },
                data: raw,
            }
        })
        .collect();

    // Undefined dynamic symbols are the binary's imports. ELF does not bind a
    // symbol to a specific library, so `library` lists the DT_NEEDED set.
    let needed = elf.libraries.join(",");
    let imports: Vec<ImportEntry> = elf
        .dynsyms
        .iter()
        .filter(|s| s.st_shndx == 0 && s.st_name != 0)
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .map(|name| {
            let base = name.split('@').next().unwrap_or(name);
            ImportEntry {
                library: needed.clone(),
                function: base.to_string(),
                address: String::new(),
                category: heuristics::categorize(base).map(str::to_string),
            }
        })
        .collect();

    let mut packer_hints = Vec::new();
    if sections.is_empty() && !elf.program_headers.is_empty() {
        packer_hints.push("no section headers".into());
    }
    if data.windows(4).any(|w| w == b"UPX!") {
        packer_hints.push("UPX".into());
    }

    Parsed {
        format: "Executable and Linking Format (ELF)",
        arch: goblin::elf::header::machine_to_str(elf.header.e_machine).to_string(),
        entry: elf.entry,
        image_base: elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0),
        info: BinaryInfo {
            is_64bit: elf.is_64,
            is_library: elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none(),
            interpreter: elf.interpreter.map(str::to_string),
            stripped: elf.syms.is_empty(),
            export_count: elf.dynsyms.iter().filter(|s| s.st_shndx != 0 && s.st_name != 0).count(),
            packer_hints,
            ..Default::default()
        },
        sections,
        imports,
    }
}

// ---------------------------------------------------------------- Mach-O

fn parse_macho<'a>(m: &goblin::mach::MachO<'a>) -> Parsed<'a> {
    const VM_PROT_READ: u32 = 1;
    const VM_PROT_WRITE: u32 = 2;
    const VM_PROT_EXECUTE: u32 = 4;

    let mut sections = Vec::new();
    for seg in &m.segments {
        let prot = seg.initprot;
        let mut perms = String::new();
        for (flag, c) in [(VM_PROT_READ, 'R'), (VM_PROT_WRITE, 'W'), (VM_PROT_EXECUTE, 'X')] {
            if prot & flag != 0 {
                perms.push(c);
            }
        }
        for (sec, bytes) in seg.sections().unwrap_or_default() {
            sections.push(Section {
                info: SectionInfo {
                    name: format!("{},{}", sec.segname().unwrap_or("?"), sec.name().unwrap_or("?")),
                    virtual_address: format!("0x{:X}", sec.addr),
                    virtual_size: sec.size,
                    raw_size: bytes.len() as u64,
                    permissions: perms.clone(),
                },
                data: Some(bytes).filter(|d| !d.is_empty()),
            });
        }
    }

    let imports: Vec<ImportEntry> = m
        .imports()
        .unwrap_or_default()
        .iter()
        .map(|i| {
            let name = i.name.trim_start_matches('_');
            ImportEntry {
                library: i.dylib.to_string(),
                function: name.to_string(),
                address: format!("0x{:X}", i.offset),
                category: heuristics::categorize(name).map(str::to_string),
            }
        })
        .collect();

    let text_base = m.segments.iter().find(|s| s.name().is_ok_and(|n| n == "__TEXT")).map_or(0, |s| s.vmaddr);

    Parsed {
        format: "Mac OS X Mach-O",
        arch: goblin::mach::constants::cputype::get_arch_name_from_types(m.header.cputype(), m.header.cpusubtype())
            .unwrap_or("unknown")
            .to_string(),
        entry: m.entry,
        image_base: text_base,
        info: BinaryInfo {
            is_64bit: m.is_64,
            is_library: m.header.filetype == goblin::mach::header::MH_DYLIB,
            export_count: m.exports().map(|e| e.len()).unwrap_or(0),
            stripped: m.symbols.is_none(),
            ..Default::default()
        },
        sections,
        imports,
    }
}

// ---------------------------------------------------------------- strings

/// Printable ASCII and UTF-16LE runs of at least `MIN_STRING_LEN` characters.
pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let printable = |b: u8| b.is_ascii_graphic() || b == b' ';
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |s: String, out: &mut Vec<String>| {
        if out.len() < MAX_STRINGS && seen.insert(s.clone()) {
            out.push(s);
        }
    };

    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_STRING_LEN {
                    push(String::from_utf8_lossy(&data[s..i]).into_owned(), &mut out);
                }
                start = None;
            }
            _ => {}
        }
    }

    for offset in 0..2 {
        let mut run = String::new();
        for pair in data.get(offset..).unwrap_or_default().chunks_exact(2) {
            if pair[1] == 0 && printable(pair[0]) {
                run.push(pair[0] as char);
            } else {
                if run.len() >= MIN_STRING_LEN {
                    push(std::mem::take(&mut run), &mut out);
                }
                run.clear();
            }
        }
        if run.len() >= MIN_STRING_LEN {
            push(run, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary itself is a real PE on Windows, ELF on Linux, Mach-O on macOS.
    fn self_bytes() -> Vec<u8> {
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    }

    #[test]
    fn parses_own_test_binary() {
        let report = analyze_bytes(&self_bytes(), "self").unwrap();
        assert_eq!(report.metadata.engine, "native");
        assert!(!report.sections.is_empty());
        assert!(report.sections.iter().any(|s| s.permissions.contains('X')));
        assert!(!report.entropy_analysis.is_empty());
        assert!(!report.strings.is_empty());
        let info = report.binary.unwrap();
        assert_eq!(info.is_64bit, cfg!(target_pointer_width = "64"));
        #[cfg(windows)]
        {
            assert!(report.metadata.is_pe());
            assert!(info.imphash.as_deref().is_some_and(|h| h.len() == 32));
            assert!(report.imports.iter().any(|i| i.library.eq_ignore_ascii_case("kernel32.dll")));
        }
        #[cfg(target_os = "linux")]
        assert!(report.metadata.is_elf());
    }

    #[test]
    fn ordinal_imports_resolve_like_pefile() {
        assert_eq!(crate::ordinals::lookup("oleaut32.dll", 6), Some("SysFreeString"));
        assert_eq!(crate::ordinals::lookup("ws2_32.dll", 115), Some("WSAStartup"));
        assert_eq!(crate::ordinals::lookup("user32.dll", 1), None);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(analyze_bytes(b"definitely not an executable", "x").is_err());
    }

    #[test]
    fn analyze_file_hashes_and_saves() {
        let out = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let a = analyze_file(&exe, out.path()).unwrap();
        assert_eq!(a.report.metadata.sha256.len(), 64);
        assert!(a.report_path.is_file());
        let reloaded = crate::load_report(&a.report_path).unwrap();
        assert_eq!(reloaded.metadata.engine, "native");
    }

    #[test]
    fn extracts_ascii_and_utf16_strings() {
        let mut data = b"\x00\x01hello world\x00ab\x00\x01\x01\x01".to_vec();
        data.extend("wide string".encode_utf16().flat_map(u16::to_le_bytes));
        data.extend([0, 0]);
        let s = extract_strings(&data);
        assert!(s.contains(&"hello world".to_string()));
        assert!(s.contains(&"wide string".to_string()));
        assert!(!s.iter().any(|x| x == "ab"));
    }
}
