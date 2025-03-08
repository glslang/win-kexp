use thiserror::Error;
use windows::core::{Interface, PCSTR};

// Import the necessary Windows Debug Engine interfaces
use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugClient3;
use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl4;
use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols3;
use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_ATTACH_KERNEL_CONNECTION;
use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_ATTACH_LOCAL_KERNEL;
use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_OUTCTL_THIS_CLIENT;

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
}

pub struct DebugEngine {
    client: IDebugClient3,
    control: IDebugControl4,
    symbols: IDebugSymbols3,
}

impl DebugEngine {
    /// Creates a new instance of the Debug Engine client
    pub fn new() -> Result<Self, DbgEngError> {
        // Create the debug client
        let client: IDebugClient3 =
            unsafe { windows::Win32::System::Diagnostics::Debug::Extensions::DebugCreate() }
                .map_err(DbgEngError::CreateClientFailed)?;

        // Get the debug control interface
        let control: IDebugControl4 = client
            .cast::<IDebugControl4>()
            .expect("[-] Failed to get debug control interface");

        // Get the debug symbols interface
        let symbols: IDebugSymbols3 = client
            .cast::<IDebugSymbols3>()
            .expect("[-] Failed to get debug symbols interface");

        Ok(Self {
            client,
            control,
            symbols,
        })
    }

    /// Attaches to the local kernel
    pub fn attach_local_kernel(&self) -> Result<(), DbgEngError> {
        let result = unsafe { self.client.AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, None) };

        if result.is_err() {
            return Err(DbgEngError::AttachFailed(result.err().unwrap()));
        }

        Ok(())
    }

    /// Attaches to a kernel using a connection string
    pub fn attach_kernel(&self, connection_string: &str) -> Result<(), DbgEngError> {
        let connection = PCSTR::from_raw(connection_string.as_ptr());

        let result = unsafe {
            self.client
                .AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, connection)
        };

        if result.is_err() {
            return Err(DbgEngError::AttachFailed(result.err().unwrap()));
        }

        Ok(())
    }

    /// Sets the symbol path
    pub fn set_symbol_path(&self, symbol_path: &str) -> Result<(), DbgEngError> {
        let path = PCSTR::from_raw(symbol_path.as_ptr());

        let result = unsafe { self.symbols.SetSymbolPath(path) };

        if result.is_err() {
            return Err(DbgEngError::SymbolPathFailed(result.err().unwrap()));
        }

        Ok(())
    }

    /// Executes a debug command
    pub fn execute_command(&self, command: &str) -> Result<String, DbgEngError> {
        let cmd = PCSTR::from_raw(command.as_ptr());

        // Create a buffer to capture the output
        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = unsafe {
            OutputCallbacks::new(&mut output_buffer).cast::<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks>().expect("[-] Failed to cast output callbacks")
        };

        // Set the output callbacks
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_callbacks))
                .expect("[-] Failed to set output callbacks");
        }

        // Execute the command
        let result = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_DEFAULT)
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

// Define the DEBUG_EXECUTE_DEFAULT constant
const DEBUG_EXECUTE_DEFAULT: u32 = 0;

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
            let _ = self.client.EndSession(DEBUG_END_ACTIVE);
        }
    }
}

// Define the DEBUG_END_ACTIVE constant
const DEBUG_END_ACTIVE: u32 = 0;
