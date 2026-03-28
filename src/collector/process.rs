use anyhow::Result;
use std::path::PathBuf;
use sysinfo::System;
use std::process::Command;

use super::pe_info;

pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        Command::new("net")
            .args(["session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    { false }
}

#[derive(Debug, Clone)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub is_elevated_process: bool,
    // The OriginalFilename field from the PE VersionInfo resource.
    // Survives file renames — used to detect renamed LOLBins.
    pub original_filename: Option<String>,
}

// Jadi gini Ko, kita pakai ExecutablePath() dari windows API
// Habis itu kita pakai sysinfo::Process::exe() sebagai fallback
// Kenapa? Karena sysinfo::Process::exe() itu kadang error
// Terus kita pakai PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
// Supaya bisa baca process SYSTEM
#[cfg(target_os = "windows")]
fn query_exe_path_win(pid: u32) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // Constants
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    // FFI declarations (kernel32)
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        fn QueryFullProcessImageNameW(
            process: *mut std::ffi::c_void,
            flags: u32,
            buffer: *mut u16,
            size: *mut u32,
        ) -> i32;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;

        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);

        if ok == 0 || len == 0 {
            return None;
        }

        let path = OsString::from_wide(&buf[..len as usize]);
        Some(PathBuf::from(path))
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
fn query_exe_path_win(_pid: u32) -> Option<PathBuf> {
    None
}

pub fn collect_process_snapshot() -> Result<Vec<ProcSnapshot>> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut out = Vec::new();

    for (pid, proc_) in sys.processes() {
        let pid_u32 = pid.to_string().parse::<u32>().unwrap_or(0);
        let name = proc_.name().to_string();

        // Primary source dari sysinfo.  Falls back to the Windows API jika:
        // crate cannot read the path (e.g. for SYSTEM / other-user processes).
        let exe_path: Option<PathBuf> = proc_
            .exe()
            .map(|p| p.to_path_buf())
            .or_else(|| query_exe_path_win(pid_u32));

        // Extract OriginalFilename from PE VersionInfo resource.
        // This survives file renames and is the key to detecting renamed LOLBins.
        let original_filename = exe_path
            .as_ref()
            .and_then(|p| pe_info::read_pe_metadata(p))
            .and_then(|m| m.original_filename);

        out.push(ProcSnapshot {
            pid: pid_u32,
            name,
            exe_path,
            is_elevated_process: false,
            original_filename,
        });
    }

    Ok(out)
}
