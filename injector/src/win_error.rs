use std::fmt::{Display, Formatter};
use std::ptr::null_mut;

use winapi::{
    shared::{
        minwindef::{
            BOOL,
            DWORD,
            HLOCAL
        }
    },
    um::{
        errhandlingapi::GetLastError,
        winbase::{
            LocalFree,
            FormatMessageW,
            FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
            FORMAT_MESSAGE_ALLOCATE_BUFFER
        },
        winnt::{
            HANDLE,
            LPWSTR,
            MAKELANGID,
            LANG_NEUTRAL,
            SUBLANG_DEFAULT
        }
    }
};
use crate::win_wrappers::WinHandle;

#[derive(Debug)]
pub struct WinError {
    error_code: u32
}

impl WinError {
    pub fn new() -> WinError {
        unsafe {
            WinError { error_code: GetLastError() }
        }
    }

    fn format_message(&self) -> String {
        unsafe {
            let mut buffer: LPWSTR = null_mut();

            let count = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM  |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                self.error_code,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
                (&mut buffer as *mut LPWSTR) as LPWSTR,
                0,
                null_mut()
            );

            let str = widestring::U16Str::from_ptr(buffer, count as usize);

            LocalFree(buffer as HLOCAL);
            return str.to_string_lossy()
        }
    }
}

impl Display for WinError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}) {}", self.error_code, self.format_message())
    }
}

impl std::error::Error for WinError { }

pub fn get_win_result_handle(result: HANDLE) -> Result<WinHandle, WinError> {
    if result == null_mut() {
        return Err(WinError::new());
    }

    Ok(WinHandle::from(result))
}

pub fn get_win_result_dword<T>(result: DWORD, value: T) -> Result<T, WinError> {
    match result {
        0 => Err(WinError::new()),
        _ => Ok(value)
    }
}

pub fn get_win_result_bool<T>(result: BOOL, value: T) -> Result<T, WinError> {
    match result {
        0 => Err(WinError::new()),
        _ => Ok(value)
    }
}