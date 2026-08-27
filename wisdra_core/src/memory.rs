use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use std::ffi::c_void;
use std::mem::size_of;

/// Scans a running process for suspicious memory artifacts (e.g. unbacked RWX pages).
/// This provides the live memory extraction (Valkyrie) capabilities directly in Wisdra.
pub fn scan_process_memory(pid: u32) -> Result<(), String> {
    println!("[*] Initializing Valkyrie Live Memory Engine on PID: {}", pid);
    
    // Attempt to open the process with read and query permissions
    let process_handle: HANDLE = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    }.map_err(|e| format!("Failed to open process (Are you running as Admin?): {}", e))?;

    println!("[+] Successfully attached to process {}", pid);
    println!("[*] Scanning virtual memory map for anomalies...");

    let mut current_address = 0;
    let mut suspicious_regions = 0;
    let max_address = 0x7FFFFFFF0000usize; // User-mode address space limit

    while current_address < max_address {
        let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(current_address as *const c_void),
                &mut mem_info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break; // Finished scanning or error
        }

        // Check for suspicious memory pages (e.g., Committed and Execute-Read-Write)
        // Advanced malware often allocates RWX memory that isn't backed by a module on disk.
        if mem_info.State == MEM_COMMIT && mem_info.Protect == PAGE_EXECUTE_READWRITE {
            println!("[!] ALERT: Suspicious RWX memory region found at 0x{:X} (Size: {} bytes)", 
                     mem_info.BaseAddress as usize, mem_info.RegionSize);
            suspicious_regions += 1;
            
            // In a future update, we will dump this memory to disk here and pass it to Ghidra
        }

        // Move to the next memory region
        current_address = mem_info.BaseAddress as usize + mem_info.RegionSize;
    }

    if suspicious_regions == 0 {
        println!("[+] No immediate memory anomalies detected in PID {}", pid);
    } else {
        println!("[!] Scan complete. Found {} suspicious memory regions.", suspicious_regions);
    }

    unsafe {
        let _ = CloseHandle(process_handle);
    }

    Ok(())
}
