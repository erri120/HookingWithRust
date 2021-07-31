use crate::win_error;
use winapi::um::winnt::HANDLE;
use winapi::um::handleapi::CloseHandle;

pub struct WinHandle {
    handle: HANDLE
}

impl WinHandle {
    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }
}

impl From<HANDLE> for WinHandle {
    fn from(handle: HANDLE) -> Self {
        WinHandle { handle }
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        close_handle(self.handle).unwrap();
    }
}

fn close_handle(handle: HANDLE) -> Result<(), win_error::WinError> {
    unsafe {
        win_error::get_win_result_bool(CloseHandle(handle), ())
    }
}