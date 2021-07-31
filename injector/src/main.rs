mod opt;
mod win_error;
mod win_wrappers;

use std::path::PathBuf;

use std::mem::{zeroed, size_of};
use std::ptr::null_mut;
use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;

use anyhow::{anyhow, Context};

use winapi::{
    shared::minwindef::{
        FALSE,
        LPVOID,
        LPCVOID,
        FARPROC
    },
    um::{
        processthreadsapi::{
            CreateProcessW,
            OpenProcess,
            CreateRemoteThread,
            ResumeThread,
            STARTUPINFOW,
            PROCESS_INFORMATION
        },
        memoryapi::{
            VirtualAllocEx,
            VirtualFreeEx,
            WriteProcessMemory
        },
        libloaderapi::{
            GetProcAddress,
            GetModuleHandleW
        },
        synchapi::WaitForSingleObject,
        winnt::{
            HANDLE,
            MEM_RESERVE,
            MEM_COMMIT,
            MEM_RELEASE,
            PAGE_EXECUTE_READWRITE,
            PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE,
            PROCESS_VM_READ,
        },
        winbase::{
            CREATE_SUSPENDED,
            WAIT_ABANDONED,
            WAIT_FAILED
        },
        minwinbase::{LPTHREAD_START_ROUTINE}
    }
};

fn create_process(executable: &PathBuf, si: &mut STARTUPINFOW, pi: &mut PROCESS_INFORMATION)
    -> Result<(), win_error::WinError> {
    unsafe {
        let application_name: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let res = CreateProcessW(
            application_name.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            FALSE,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            si as *mut STARTUPINFOW,
            pi as *mut PROCESS_INFORMATION
        );

        return win_error::get_win_result_bool(res, ());
    }
}

fn open_process(process_id: u32) -> Result<win_wrappers::WinHandle, win_error::WinError> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_CREATE_THREAD |
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION |
                PROCESS_VM_WRITE |
                PROCESS_VM_READ,
            FALSE,
            process_id
        );

        return win_error::get_win_result_handle(handle);
    }
}

fn get_proc_address(module: &str, symbol: &str) -> Result<FARPROC, win_error::WinError> {
    unsafe {
        let lp_module_name = module
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        let handle = GetModuleHandleW(lp_module_name.as_ptr());
        if handle == null_mut() {
            return Err(win_error::WinError::new());
        }

        let lp_proc_name = CString::new(symbol).unwrap();
        let address = GetProcAddress(handle, lp_proc_name.as_ptr());

        if address == null_mut() {
            return Err(win_error::WinError::new());
        }

        Ok(address)
    }
}

fn allocate_memory(process_handle: &win_wrappers::WinHandle) -> Result<win_wrappers::WinHandle, win_error::WinError> {
    unsafe {
        let res = VirtualAllocEx(
            process_handle.get_handle(),
            null_mut(),
            8196,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        return win_error::get_win_result_handle(res);
    }
}

fn write_memory(process_handle: &win_wrappers::WinHandle, base_address: LPVOID, buffer: LPCVOID, size: usize) -> Result<usize, win_error::WinError> {
    unsafe {
        let mut bytes_written: usize = 0;

        let res = WriteProcessMemory(
            process_handle.get_handle(),
            base_address,
            buffer,
            size,
            &mut bytes_written
        );

        return win_error::get_win_result_bool(res, bytes_written);
    }
}

fn create_remote_thread(process_handle: &win_wrappers::WinHandle, lp_start_address: LPTHREAD_START_ROUTINE, lp_parameter: LPVOID)
    -> Result<win_wrappers::WinHandle, win_error::WinError> {
    unsafe {
        let handle = CreateRemoteThread(
            process_handle.get_handle(),
            null_mut(),
            0,
            lp_start_address,
            lp_parameter,
            0,
            null_mut()
        );

        return win_error::get_win_result_handle(handle);
    }
}

fn free_memory(process_handle: &win_wrappers::WinHandle, address: LPVOID) -> Result<(), win_error::WinError> {
    unsafe {
        let res = VirtualFreeEx(
            process_handle.get_handle(),
            address,
            0,
            MEM_RELEASE
        );

        return win_error::get_win_result_bool(res, ());
    }
}

fn resume_thread(thread_handle: HANDLE) -> Result<(), win_error::WinError> {
    unsafe {
        win_error::get_win_result_dword(ResumeThread(thread_handle), ())
    }
}

fn main() -> Result<(), anyhow::Error> {
    let options: opt::Opt = argh::from_env();

    if !options.target.exists() {
        return Err(anyhow!("Target does not exist at path {}", options.target.display()));
    }

    if !options.dll.exists() {
        return Err(anyhow!("Dll does not exist at path {}", options.dll.display()));
    }

    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        let mut pi: PROCESS_INFORMATION = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;

        create_process(&options.target, &mut si, &mut pi)
            .with_context(|| format!("Unable to create process for executable {}", options.target.display()))?;

        let process_handle = open_process(pi.dwProcessId)
            .with_context(|| format!("Unable to open process with process id {}", pi.dwProcessId))?;

        let load_library_address = get_proc_address("kernel32.dll", "LoadLibraryA")
            .with_context(|| format!("Unable to get address of function LoadLibraryA in module kernel32.dll"))?;

        let hook_base = allocate_memory(&process_handle)
            .with_context(|| format!("Unable to allocate memory in process"))?;

        let dll_name = options.dll.as_os_str().to_str().unwrap();
        let dll_name_len = dll_name.len() + 1;
        let dll_name_buffer = CString::new(dll_name)?;

        let bytes_written = write_memory(&process_handle, hook_base.get_handle(), dll_name_buffer.as_ptr().cast(), dll_name_len)
            .with_context(|| format!("Unable to write buffer to process memory"))?;

        if bytes_written != dll_name_len {
            return Err(anyhow!("WinApi did not write all bytes to process memory: {} != {}", bytes_written, dll_name_len));
        }

        let lp_start_address = Some(*(&load_library_address as *const _ as *const unsafe extern "system" fn(LPVOID) -> u32));
        let thread_handle = create_remote_thread(&process_handle, lp_start_address, hook_base.get_handle())
            .with_context(|| format!("Unable to create remote thread for process"))?;

        let wait_res = WaitForSingleObject(thread_handle.get_handle(), 1000 * 64);
        if wait_res == WAIT_ABANDONED {
            return Err(anyhow!("WAIT_ABANDONED!"));
        }

        if wait_res == WAIT_FAILED {
            return Err(anyhow!(win_error::WinError::new()));
        }

        free_memory(&process_handle, hook_base.get_handle())?;
        resume_thread(pi.hThread)?;
    }

    Ok(())
}
