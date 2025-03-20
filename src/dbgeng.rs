use thiserror::Error;
use windows::core::{Interface, PCSTR};

// Import the necessary Windows Debug Engine interfaces
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugBreakpoint, IDebugClient3, IDebugControl4, IDebugDataSpaces4, IDebugSymbols3,
    DEBUG_ANY_ID, DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_ATTACH_LOCAL_KERNEL, DEBUG_BREAKPOINT_CODE,
    DEBUG_END_ACTIVE_DETACH, DEBUG_EXECUTE_ECHO, DEBUG_OUTCTL_THIS_CLIENT,
};
use windows_core::IUnknown;

#[derive(Debug, Error)]
pub enum DbgEngError {
    #[error("Failed to initialize COM: {0}")]
    ComInitFailed(#[from] windows::core::Error),

    #[error("Failed to create debug client: {0}")]
    CreateClientFailed(windows::core::Error),

    #[error("Failed to get debug control: {0}")]
    GetControlFailed(windows::core::Error),

    #[error("Failed to get debug symbols: {0}")]
    GetSymbolsFailed(windows::core::Error),

    #[error("Failed to attach to kernel: {0}")]
    AttachFailed(windows::core::Error),

    #[error("Debug command failed: {0}")]
    CommandFailed(windows::core::Error),

    #[error("Symbol path operation failed: {0}")]
    SymbolPathFailed(windows::core::Error),

    #[error("Breakpoint failed: {0}")]
    BreakpointFailed(windows::core::Error),
}

pub struct DebugEngine {
    client: IDebugClient3,
    control: IDebugControl4,
    dataspaces: IDebugDataSpaces4,
    symbols: IDebugSymbols3,
}

impl Default for DebugEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugEngine {
    /// Creates a new instance of the Debug Engine client
    pub fn new() -> Self {
        // Create the debug client
        let client: IDebugClient3 =
            unsafe { windows::Win32::System::Diagnostics::Debug::Extensions::DebugCreate() }
                .expect("[-] Failed to create debug client");

        Self::from_client_interface(client)
    }

    pub fn from_windbg_client(client: &IUnknown) -> Self {
        let client: IDebugClient3 = client.cast().expect("[-] Failed to cast debug client");

        Self::from_client_interface(client)
    }

    pub fn from_client_interface(client: IDebugClient3) -> Self {
        let control: IDebugControl4 = client
            .cast::<IDebugControl4>()
            .expect("[-] Failed to get debug control interface");

        let dataspaces: IDebugDataSpaces4 = client
            .cast::<IDebugDataSpaces4>()
            .expect("[-] Failed to get debug data spaces interface");

        let symbols: IDebugSymbols3 = client
            .cast::<IDebugSymbols3>()
            .expect("[-] Failed to get debug symbols interface");

        Self {
            client,
            control,
            dataspaces,
            symbols,
        }
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
        let mut buffer = vec![0; size];
        unsafe {
            self.dataspaces
                .ReadVirtual(address, buffer.as_mut_ptr() as *mut _, size as u32, None)
                .expect("[-] Failed to read memory")
        };

        Ok(buffer)
    }

    /// Attaches to the local kernel
    pub fn attach_local_kernel(&self) {
        unsafe {
            self.client
                .AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, None)
                .expect("[-] Failed to attach to local kernel")
        };
    }

    /// Attaches to a kernel using a connection string
    pub fn attach_kernel(&self, connection_string: &str) {
        let connection = PCSTR::from_raw(connection_string.as_ptr());

        unsafe {
            self.client
                .AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, connection)
                .expect("[-] Failed to attach to kernel");
        }
    }

    /// Sets the symbol path
    pub fn set_symbol_path(&self, symbol_path: &str) {
        let path = PCSTR::from_raw(symbol_path.as_ptr());

        unsafe {
            self.symbols
                .SetSymbolPath(path)
                .expect("[-] Failed to set symbol path")
        };
    }

    /// Executes a debug command
    pub fn execute_command(&self, command: &str) -> Result<String, DbgEngError> {
        let cmd = PCSTR::from_raw(command.as_ptr());

        // Create a buffer to capture the output
        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface = output_callbacks.into();

        // Set the output callbacks
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .expect("[-] Failed to set output callbacks");
        }

        // Execute the command
        let result = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };

        // Reset the output callbacks
        unsafe {
            self.client.SetOutputCallbacks(None)?;
        }

        if result.is_err() {
            return Err(DbgEngError::CommandFailed(result.err().unwrap()));
        }

        // Convert the output to a string
        let output = String::from_utf8_lossy(&output_buffer).to_string();

        Ok(output)
    }

    /// Waits for the target to break
    pub fn wait_for_event(&self, timeout_ms: u32) -> Result<(), DbgEngError> {
        let result = unsafe { self.control.WaitForEvent(0, timeout_ms) };

        if result.is_err() {
            return Err(DbgEngError::CommandFailed(result.err().unwrap()));
        }

        Ok(())
    }
}

// Output callbacks implementation to capture command output
#[windows::core::implement(
    windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks
)]
#[derive(Debug)]
pub struct OutputCallbacks {
    buffer: *mut Vec<u8>,
}

impl OutputCallbacks {
    fn new(buffer: &mut Vec<u8>) -> Self {
        Self {
            buffer: buffer as *mut Vec<u8>,
        }
    }
}

#[allow(non_snake_case)]
impl windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks_Impl
    for OutputCallbacks_Impl
{
    fn Output(&self, _mask: u32, text: &PCSTR) -> windows::core::Result<()> {
        let this = unsafe {
            (self as *const _ as *const OutputCallbacks)
                .as_ref()
                .unwrap()
        };
        let c_str = unsafe { std::ffi::CStr::from_ptr(text.0 as *const i8) };
        if let Ok(str_slice) = c_str.to_str() {
            unsafe {
                (*this.buffer).extend_from_slice(str_slice.as_bytes());
            }
        }
        Ok(())
    }
}

// Implement Drop for DebugEngine to ensure proper cleanup
impl Drop for DebugEngine {
    fn drop(&mut self) {
        // Detach from any targets
        unsafe {
            let _ = self.client.EndSession(DEBUG_END_ACTIVE_DETACH);
        }
    }
}

pub struct Breakpoint<'a> {
    control: &'a IDebugControl4,
    breakpoint: IDebugBreakpoint,
}

impl<'a> Breakpoint<'a> {
    pub fn new(engine: &'a DebugEngine) -> Result<Self, DbgEngError> {
        let breakpoint = unsafe {
            engine
                .control
                .AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
        };

        if breakpoint.is_err() {
            return Err(DbgEngError::BreakpointFailed(breakpoint.err().unwrap()));
        }

        Ok(Self {
            breakpoint: breakpoint.unwrap(),
            control: &engine.control,
        })
    }
}

impl<'a> Drop for Breakpoint<'a> {
    fn drop(&mut self) {
        unsafe {
            self.control
                .RemoveBreakpoint(&self.breakpoint)
                .expect("[-] Failed to remove breakpoint");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_debug_engine() {
        // Create new debug engine instance
        let _ = DebugEngine::new();

        println!("Debug engine created successfully");

        // DebugEngine's Drop impl will handle cleanup and detach
    }
}
