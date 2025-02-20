use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Pipes::CreatePipe;

use crate::win32k::close_handle;

pub struct AnonymousPipe {
    read_handle: HANDLE,
    write_handle: HANDLE,
}

impl AnonymousPipe {
    pub fn new(buffer_size: u32) -> Self {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();

        // Create the anonymous pipe with specified buffer size
        unsafe {
            CreatePipe(&mut read_handle, &mut write_handle, None, buffer_size)
                .expect("[-] Failed to create anonymous pipe");
        }

        Self {
            read_handle,
            write_handle,
        }
    }

    pub fn get_read_handle(&self) -> HANDLE {
        self.read_handle
    }

    pub fn get_write_handle(&self) -> HANDLE {
        self.write_handle
    }

    pub fn write(&self, data: &[u8]) -> u32 {
        let mut bytes_written: u32 = 0;

        unsafe {
            WriteFile(
                self.write_handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )
            .expect("[-] Failed to write to anonymous pipe");
        }

        bytes_written
    }
}

impl Drop for AnonymousPipe {
    fn drop(&mut self) {
        if self.read_handle != INVALID_HANDLE_VALUE {
            close_handle(self.read_handle);
        }
        if self.write_handle != INVALID_HANDLE_VALUE {
            close_handle(self.write_handle);
        }
    }
}
