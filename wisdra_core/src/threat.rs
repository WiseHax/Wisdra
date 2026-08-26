//! API Categorization and Threat Assessment Engine

/// Categorizes a Windows API function name into tactical capability buckets
/// based on known adversarial behavior and malware techniques.
pub fn categorize_api(func_name: &str) -> &'static str {
    let lower_func = func_name.to_lowercase();
    
    // Process Injection / Memory Manipulation
    if lower_func.contains("virtualalloc") || 
       lower_func.contains("createremotethread") ||
       lower_func.contains("writeprocessmemory") ||
       lower_func.contains("mapviewoffile") {
        return "<injection>";
    }
    
    // Anti-Analysis / Anti-Debugging
    if lower_func.contains("isdebuggerpresent") ||
       lower_func.contains("checkremotedebuggerpresent") ||
       lower_func.contains("queryperformancecounter") ||
       lower_func.contains("gettickcount") ||
       lower_func.contains("findwindow") {
        return "<anti_debug>";
    }
    
    // Dynamic Loading / Evasion
    if lower_func.contains("loadlibrary") ||
       lower_func.contains("getprocaddress") ||
       lower_func.contains("ldrloaddll") {
        return "<dynamic_load>";
    }
    
    // Cryptography / Ransomware Primitives
    if lower_func.contains("cryptacquirecontext") ||
       lower_func.contains("cryptencrypt") ||
       lower_func.contains("bcryptexportkey") ||
       lower_func.contains("rsa") {
        return "<crypto>";
    }
    
    // Execution / Spawning
    if lower_func.contains("createprocess") ||
       lower_func.contains("shellexecute") ||
       lower_func.contains("winexec") {
        return "<execution>";
    }
    
    // Network / C2 Communication
    if lower_func.contains("wsastartup") ||
       lower_func.contains("socket") ||
       lower_func.contains("connect") ||
       lower_func.contains("internetopen") ||
       lower_func.contains("httpsendrequest") ||
       lower_func.contains("urldownloadtofile") {
        return "<network>";
    }

    // Default unclassified
    "<general_api>"
}
