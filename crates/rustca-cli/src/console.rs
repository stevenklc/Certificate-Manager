//! Windows 主控台設定：切換為 UTF-8 並啟用 ANSI 色彩，避免中文亂碼。

#[cfg(windows)]
pub fn init() {
    #[allow(clippy::upper_case_acronyms)]
    type HANDLE = *mut core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleOutputCP(cp: u32) -> i32;
        fn SetConsoleCP(cp: u32) -> i32;
        fn GetStdHandle(n: u32) -> HANDLE;
        fn GetConsoleMode(h: HANDLE, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: HANDLE, mode: u32) -> i32;
    }
    const CP_UTF8: u32 = 65001;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    // SAFETY: 都是單純的 Win32 主控台 API 呼叫，參數皆為有效值。
    unsafe {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        for n in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let h = GetStdHandle(n);
            let mut mode = 0u32;
            if !h.is_null() && GetConsoleMode(h, &mut mode) != 0 {
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn init() {}
