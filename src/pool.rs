use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;

use crate::win32k::close_handle;

pub struct AnonymousPipe {
    read_handle: HANDLE,
    write_handle: HANDLE,
    buf_size: u32,
}

impl AnonymousPipe {
    pub fn new(buffer_size: u32) -> Self {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();
        let buf_size = buffer_size;

        // Create the anonymous pipe with specified buffer size
        unsafe {
            CreatePipe(&mut read_handle, &mut write_handle, None, buffer_size)
                .expect("[-] Failed to create anonymous pipe");
        }

        Self {
            read_handle,
            write_handle,
            buf_size,
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

    pub fn read(&self, buffer: &mut [u8]) -> u32 {
        let mut bytes_read: u32 = 0;

        unsafe {
            ReadFile(self.read_handle, Some(buffer), Some(&mut bytes_read), None)
                .expect("[-] Failed to read from anonymous pipe");
        }
        bytes_read
    }

    pub fn drain(&self) {
        let mut buffer = vec![0; self.buf_size as usize];
        self.read(&mut buffer);
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
