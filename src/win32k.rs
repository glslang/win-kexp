use core::ffi::c_void;
use thiserror::Error;

use windows::Win32::System::{
    LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
    Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE},
};
use windows_core::PSTR;

pub use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{
            CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            CreateFileA, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
        },
        System::{
            Ioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_NEITHER},
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryExA},
            Memory::{
                VirtualAlloc, VirtualLock, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
            },
            ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameA},
            Threading::{
                CreateProcessA, CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
                STARTUPINFOA,
            },
            IO::DeviceIoControl,
        },
    },
};

#[macro_export]
macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        ($DeviceType << 16) | ($Access << 14) | ($Function << 2) | $Method
    };
}

// IOCTL macro
#[macro_export]
macro_rules! IOCTL {
    ($Function:expr) => {
        CTL_CODE!(
            FILE_DEVICE_UNKNOWN,
            $Function,
            METHOD_NEITHER,
            FILE_ANY_ACCESS
        )
    };
}

pub fn get_device_handle(device_path: &str) -> HANDLE {
    unsafe {
        CreateFileA(
            PCSTR::from_raw(device_path.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .expect("[-] Unable to open device handle")
    }
}

pub fn close_handle(handle: HANDLE) {
    unsafe {
        CloseHandle(handle).expect("[-] Failed to close device handle");
    }
}

pub fn io_device_control(
    h_device: HANDLE,
    dwcontrolcode: u32,
    lpinbuffer: *const c_void,
    inbuffersize: u32,
    lpooutputbuffer: *mut c_void,
    outbuffersize: u32,
) -> u32 {
    unsafe {
        let mut bytes_returned: u32 = 0;
        DeviceIoControl(
            h_device,
            dwcontrolcode,
            Some(lpinbuffer),
            inbuffersize,
            Some(lpooutputbuffer),
            outbuffersize,
            Some(&mut bytes_returned),
            None,
        )
        .expect("[-] Unable to trigger IOCTL");

        bytes_returned
    }
}

pub fn create_cmd_process() -> PROCESS_INFORMATION {
    let si = windows::Win32::System::Threading::STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: INVALID_HANDLE_VALUE,
        hStdOutput: INVALID_HANDLE_VALUE,
        hStdError: INVALID_HANDLE_VALUE,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let command_line = c"cmd.exe".as_ptr() as *mut u8;

    unsafe {
        CreateProcessA(
            None,
            Some(PSTR(command_line)),
            None,
            None,
            false,
            CREATE_NEW_CONSOLE,
            None,
            None,
            &si,
            &mut pi,
        )
        .expect("[-] Failed to create process");

        pi
    }
}

/// # Safety
///
/// This function is unsafe because it uses raw pointers and assumes that the caller has the necessary permissions and knowledge about the memory layout.
/// It is the responsibility of the caller to ensure that the memory is allocated correctly and that the shellcode is valid.
pub unsafe fn allocate_shellcode(
    shellcode: *const u8,
    shellcode_len: usize,
) -> (*mut c_void, usize) {
    unsafe {
        let sc = VirtualAlloc(
            None,
            shellcode_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        std::ptr::copy_nonoverlapping(shellcode, sc.cast(), shellcode_len);
        (sc, shellcode_len)
    }
}

pub fn get_function_address(dll_name: &str, function_name: &str) -> *mut c_void {
    unsafe {
        let h_module = GetModuleHandleA(PCSTR(format!("{}\0", dll_name).as_ptr()))
            .expect("[-] Failed to get module handle");

        get_function_address_from_module(h_module, function_name)
    }
}

pub fn get_function_address_from_module(h_module: HMODULE, function_name: &str) -> *mut c_void {
    unsafe {
        let proc_addr = GetProcAddress(h_module, PCSTR(format!("{}\0", function_name).as_ptr()))
            .expect("[-] Failed to get function address");

        proc_addr as *mut c_void
    }
}

pub fn load_library_no_resolve(dll_name: &str) -> Result<HMODULE, windows_core::Error> {
    unsafe {
        LoadLibraryExA(
            PCSTR(format!("{}\0", dll_name).as_ptr()),
            None,
            DONT_RESOLVE_DLL_REFERENCES,
        )
    }
}

pub fn allocate_memory(
    lpaddress: u64,
    size: usize,
    alloc_type: VIRTUAL_ALLOCATION_TYPE,
    protect: PAGE_PROTECTION_FLAGS,
) -> *mut c_void {
    unsafe { VirtualAlloc(Some(lpaddress as *const c_void), size, alloc_type, protect) }
}

/// # Safety
///
/// This function is unsafe because it uses raw pointers and assumes that the caller has the necessary permissions and knowledge about the memory layout.
/// It is the responsibility of the caller to ensure that the memory is allocated correctly and that the shellcode is valid.
pub unsafe fn lock_memory(lpaddress: *const c_void, size: usize) {
    unsafe { VirtualLock(lpaddress, size).expect("[-] Failed to lock memory") }
}

#[derive(Error, Debug)]
pub enum KernelError {
    #[error("Failed to find driver: {0}")]
    DriverNotFound(String),
    #[error("Failed to get driver name: {0}")]
    DriverNameNotFound(String),
}

pub fn get_driver_base(driver_name: &str) -> Result<*mut c_void, KernelError> {
    unsafe {
        let mut needed_size: u32 = 0;

        // First call to get required size for addresses
        EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed_size)
            .expect("[-] Failed to get required size for drivers");

        // Allocate buffers with exact sizes needed
        let driver_count = needed_size as usize / std::mem::size_of::<*mut c_void>();
        let mut drivers = vec![std::ptr::null_mut(); driver_count];

        // Get driver addresses and names
        EnumDeviceDrivers(drivers.as_mut_ptr(), needed_size, &mut needed_size)
            .expect("[-] Failed to enumerate drivers");

        // Iterate through drivers to find matching name
        for &driver in drivers.iter() {
            if driver.is_null() {
                continue;
            }

            let mut name_buf = [0u8; 1024];
            let name_len = GetDeviceDriverBaseNameA(driver, &mut name_buf);

            if name_len == 0 {
                return Err(KernelError::DriverNameNotFound(driver_name.to_string()));
            }

            let driver_name_c = std::str::from_utf8(&name_buf[..name_len as usize])
                .expect("[-] Failed to convert driver name to string")
                .to_lowercase();

            if driver_name_c.contains(&driver_name.to_lowercase()) {
                return Ok(driver);
            }
        }

        Err(KernelError::DriverNotFound(driver_name.to_string()))
    }
}

pub fn get_ntoskrnl_base_address() -> Result<*mut c_void, KernelError> {
    get_driver_base("ntoskrnl")
}
