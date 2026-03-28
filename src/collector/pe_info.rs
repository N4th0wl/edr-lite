use std::path::Path;

// Metadata extracted from a PE file's version information resources.
#[derive(Debug, Clone, Default)]
pub struct PeMetadata {
    // The `OriginalFilename` field from the VS_VERSION_INFO resource.
    // This is baked into the binary at compile time and survives renaming.
    pub original_filename: Option<String>,
}

// Read PE version-info from an executable on disk.

/// Di Windows kita pakai `GetFileVersionInfoW` / `VerQueryValueW` melalui FFI.
/// Kalau di non-Windows platforms ini cuma no-op stub yang selalu return `None`.
pub fn read_pe_metadata<P: AsRef<Path>>(path: P) -> Option<PeMetadata> {
    _read_pe_metadata_impl(path.as_ref())
}

// Windows implementation
#[cfg(target_os = "windows")]
fn _read_pe_metadata_impl(path: &Path) -> Option<PeMetadata> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // FFI declarations (version.dll)
    #[link(name = "version")]
    extern "system" {
        fn GetFileVersionInfoSizeW(
            lptstr_filename: *const u16,
            lpdw_handle: *mut u32,
        ) -> u32;

        fn GetFileVersionInfoW(
            lptstr_filename: *const u16,
            dw_handle: u32,
            dw_len: u32,
            lp_data: *mut u8,
        ) -> i32;

        fn VerQueryValueW(
            p_block: *const u8,
            lp_sub_block: *const u16,
            lp_buffer: *mut *const u8,
            pu_len: *mut u32,
        ) -> i32;
    }

    /// Encode a Rust string as a null-terminated wide (UTF-16) string.
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Safely read a null-terminated UTF-16 string from a raw pointer.
    unsafe fn wide_ptr_to_string(ptr: *const u8, byte_len: u32) -> String {
        if ptr.is_null() || byte_len == 0 {
            return String::new();
        }
        // byte_len is in *characters* (WCHARs) for string queries
        let slice = std::slice::from_raw_parts(ptr as *const u16, byte_len as usize);
        // Strip trailing NUL
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf16_lossy(&slice[..end])
    }

    // Get the size of the version-info block
    let file_wide = to_wide(&path.to_string_lossy());
    let mut handle: u32 = 0;
    let size = unsafe { GetFileVersionInfoSizeW(file_wide.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }

    // Retrieve the version-info block
    let mut data = vec![0u8; size as usize];
    let ok = unsafe {
        GetFileVersionInfoW(file_wide.as_ptr(), handle, size, data.as_mut_ptr())
    };
    if ok == 0 {
        return None;
    }

    // Query the translation array to learn the code page/language pair
    let translation_key = to_wide("\\VarFileInfo\\Translation");
    let mut trans_ptr: *const u8 = std::ptr::null();
    let mut trans_len: u32 = 0;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr(),
            translation_key.as_ptr(),
            &mut trans_ptr,
            &mut trans_len,
        )
    };

    // Each translation entry is 4 bytes: u16 lang_id + u16 code_page
    if ok == 0 || trans_len < 4 || trans_ptr.is_null() {
        return None;
    }

    let (lang_id, code_page) = unsafe {
        let words = std::slice::from_raw_parts(trans_ptr as *const u16, 2);
        (words[0], words[1])
    };

    // Build the sub-block path for OriginalFilename
    let sub_block = format!(
        "\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename",
        lang_id, code_page
    );
    let sub_wide = to_wide(&sub_block);

    let mut val_ptr: *const u8 = std::ptr::null();
    let mut val_len: u32 = 0;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr(),
            sub_wide.as_ptr(),
            &mut val_ptr,
            &mut val_len,
        )
    };

    let original_filename = if ok != 0 && !val_ptr.is_null() && val_len > 0 {
        let s = unsafe { wide_ptr_to_string(val_ptr, val_len) };
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    };

    Some(PeMetadata { original_filename })
}

// Non-Windows stub
#[cfg(not(target_os = "windows"))]
fn _read_pe_metadata_impl(_path: &Path) -> Option<PeMetadata> {
    None
}
