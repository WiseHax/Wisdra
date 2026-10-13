//! Live process memory scanning (Windows only).
//!
//! Walks a process's virtual address space and flags committed
//! PAGE_EXECUTE_READWRITE regions, optionally dumping them for analysis.

use crate::error::Result;
use std::path::Path;

/// Regions larger than this are reported but not dumped.
pub const MAX_DUMP_BYTES: usize = 64 * 1024 * 1024;

#[cfg(not(windows))]
pub fn scan_process_memory(_pid: u32, _output_dir: &Path) -> Result<usize> {
    Err(crate::error::WisdraError::UnsupportedPlatform)
}

#[cfg(windows)]
pub fn scan_process_memory(pid: u32, output_dir: &Path) -> Result<usize> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, VirtualQueryEx,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    /// Closes the process handle on every exit path.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful OpenProcess call.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // SAFETY: plain FFI call; the returned handle is owned by `Handle`.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map(Handle)
        .map_err(|e| std::io::Error::other(format!("cannot open PID {pid} (try an elevated prompt): {e}")))?;

    println!("[+] Attached to PID {pid}; walking virtual memory map...");
    std::fs::create_dir_all(output_dir)?;

    let mut address = 0usize;
    let mut suspicious = 0usize;
    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `info` is a valid, correctly sized out-buffer.
        let written = unsafe {
            VirtualQueryEx(handle.0, Some(address as *const c_void), &mut info, size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if written == 0 || info.RegionSize == 0 {
            break; // end of the address space
        }
        let base = info.BaseAddress as usize;

        if info.State == MEM_COMMIT && info.Protect == PAGE_EXECUTE_READWRITE {
            suspicious += 1;
            println!("[!] RWX region at 0x{base:X} ({} bytes)", info.RegionSize);

            if info.RegionSize > MAX_DUMP_BYTES {
                println!("    [-] Skipping dump: region exceeds {} MiB cap", MAX_DUMP_BYTES >> 20);
            } else {
                let mut buffer = vec![0u8; info.RegionSize];
                let mut read = 0usize;
                // SAFETY: `buffer` has exactly RegionSize writable bytes.
                let ok = unsafe {
                    ReadProcessMemory(
                        handle.0,
                        info.BaseAddress,
                        buffer.as_mut_ptr() as *mut c_void,
                        info.RegionSize,
                        Some(&mut read),
                    )
                };
                if ok.is_ok() && read > 0 {
                    buffer.truncate(read);
                    let path = output_dir.join(format!("pid_{pid}_region_0x{base:X}.bin"));
                    std::fs::write(&path, &buffer)?;
                    println!("    [>] Dumped {read} bytes to {}", path.display());
                } else {
                    println!("    [-] Could not read region at 0x{base:X}");
                }
            }
        }

        match base.checked_add(info.RegionSize) {
            Some(next) if next > address => address = next,
            _ => break,
        }
    }

    if suspicious == 0 {
        println!("[+] No RWX anomalies detected in PID {pid}");
    } else {
        println!("[!] Scan complete: {suspicious} suspicious region(s)");
    }
    Ok(suspicious)
}
