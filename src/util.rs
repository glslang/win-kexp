use core::ffi::c_void;
use std::slice;

use windows::Win32::System::Diagnostics::Debug::DebugBreak;

pub fn pause() {
    dbg!("Pausing! Press enter to continue...");

    let mut buffer = String::new();

    std::io::stdin()
        .read_line(&mut buffer)
        .expect("Failed to read line");
}

pub fn debug_break() {
    unsafe {
        DebugBreak();
    }
}

pub fn bytes_to_hex_string(ptr: *mut c_void, len: usize) -> String {
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, len) };
    hex::encode(bytes)
}
