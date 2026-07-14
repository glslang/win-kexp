use std::ffi::{CStr, c_void};
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_UNEXPECTED, S_OK};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE,
};
use windows::core::{HRESULT, IUnknown, Interface, PCSTR};

use crate::dbgeng::DebugEngine;
use crate::pool::decode::parse_tag;
use crate::pool::index::SnapshotCache;
use crate::pool::layout::{LayoutCache, SessionKey};
use crate::pool::render::{RenderOptions, render_pool_map};
use crate::pool::snapshot::SnapshotWalker;

const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
const DEBUG_NOTIFY_SESSION_ACTIVE: u32 = 0x0000_0000;
const DEBUG_NOTIFY_SESSION_INACTIVE: u32 = 0x0000_0001;
const DEBUG_NOTIFY_SESSION_ACCESSIBLE: u32 = 0x0000_0002;
const DEBUG_NOTIFY_SESSION_INACCESSIBLE: u32 = 0x0000_0003;

static SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn snapshots() -> &'static SnapshotCache {
    static CACHE: OnceLock<SnapshotCache> = OnceLock::new();
    CACHE.get_or_init(SnapshotCache::default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolFilter {
    Paged,
    NonPaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolCommand {
    tag: Option<u32>,
    filter: Option<PoolFilter>,
    refresh: bool,
    address: Option<u64>,
}

fn usage() -> &'static str {
    "Usage: !win_kexp.poolmap -tag <1..4 ASCII bytes> [-paged|-nonpaged] [-refresh]\n       !win_kexp.poolmap <address> [-refresh]\n"
}

fn parse_address(text: &str) -> Option<u64> {
    let compact = text.replace('`', "");
    let digits = compact.strip_prefix("0x").unwrap_or(&compact);
    (!digits.is_empty())
        .then(|| u64::from_str_radix(digits, 16).ok())
        .flatten()
}

fn validate_pool_target(processor: u32) -> Result<(), String> {
    (processor == IMAGE_FILE_MACHINE_AMD64)
        .then_some(())
        .ok_or_else(|| format!("pool walking supports x64 targets only (machine {processor:#x})"))
}

fn parse_args(args: &str) -> Result<PoolCommand, String> {
    let mut tag = None;
    let mut filter = None;
    let mut refresh = false;
    let mut address = None;
    let tokens: Vec<_> = args.split_ascii_whitespace().collect();
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "-tag" => {
                index += 1;
                let text = tokens
                    .get(index)
                    .ok_or_else(|| "-tag requires 1..4 ASCII bytes".to_string())?;
                if tag.is_some() {
                    return Err("-tag may be specified only once".into());
                }
                tag = Some(
                    parse_tag(text)
                        .ok_or_else(|| "tag must contain 1..4 ASCII bytes".to_string())?,
                );
            }
            "-paged" => {
                if filter.replace(PoolFilter::Paged).is_some() {
                    return Err("-paged and -nonpaged are mutually exclusive".into());
                }
            }
            "-nonpaged" => {
                if filter.replace(PoolFilter::NonPaged).is_some() {
                    return Err("-paged and -nonpaged are mutually exclusive".into());
                }
            }
            "-refresh" => refresh = true,
            value if !value.starts_with('-') && address.is_none() => {
                address =
                    Some(parse_address(value).ok_or_else(|| format!("invalid address `{value}`"))?);
            }
            value => return Err(format!("unrecognized argument `{value}`")),
        }
        index += 1;
    }
    if tag.is_none() && address.is_none() {
        return Err("a tag or address is required".into());
    }
    if tag.is_some() && address.is_some() {
        return Err("use either -tag or an address, not both".into());
    }
    Ok(PoolCommand {
        tag,
        filter,
        refresh,
        address,
    })
}

fn with_engine<T>(
    client: *mut c_void,
    action: impl FnOnce(&DebugEngine) -> T,
) -> Result<T, String> {
    if client.is_null() {
        return Err("WinDbg supplied a null debug client".into());
    }
    // The callback borrows this COM pointer. ManuallyDrop prevents Release on the
    // command-supplied reference; casts performed by DebugEngine own their references.
    let unknown = ManuallyDrop::new(unsafe { IUnknown::from_raw(client) });
    let engine =
        DebugEngine::try_from_windbg_client(&unknown).map_err(|error| error.to_string())?;
    Ok(action(&engine))
}

fn args_string(args: PCSTR) -> Result<String, String> {
    if args.is_null() {
        return Ok(String::new());
    }
    Ok(unsafe { CStr::from_ptr(args.0.cast()) }
        .to_string_lossy()
        .into_owned())
}

fn span_contains_address(span: &crate::pool::PoolSpan, address: u64) -> bool {
    address >= span.header_address && address < span.end()
}

fn command_poolmap(engine: &DebugEngine, args: &str) -> Result<(), String> {
    let command = parse_args(args)?;
    if !engine
        .is_kernel_target()
        .map_err(|error| error.to_string())?
    {
        return Err("poolmap requires a kernel target".into());
    }
    let status = engine
        .execution_status()
        .map_err(|error| error.to_string())?;
    if status == DEBUG_STATUS_NO_DEBUGGEE {
        return Err("no accessible target is attached".into());
    }
    if status != DEBUG_STATUS_BREAK {
        return Err("target is running; break in before taking a pool snapshot".into());
    }
    let processor = engine.processor_type().map_err(|error| error.to_string())?;
    validate_pool_target(processor)?;
    let kernel_base = engine.kernel_base().map_err(|error| error.to_string())?;
    let generation = SESSION_GENERATION.load(Ordering::Acquire);
    let key = SessionKey {
        kernel_base,
        session: generation,
    };
    let layout = LayoutCache::global()
        .get_or_resolve(engine, key)
        .map_err(|error| error.to_string())?;
    let index = snapshots().get_or_refresh(generation, command.refresh, || {
        SnapshotWalker {
            memory: engine,
            layout: &layout,
            traversal_limit: 1_000_000,
        }
        .walk()
        .map_err(|error| error.to_string())
    })?;

    if let Some(address) = command.address {
        let detail = index
            .spans
            .iter()
            .find(|span| span_contains_address(span, address))
            .map(|span| {
                format!(
                    "{address:#x}: {} {:#x}+{:#x} tag `{}` {:?} {:?}\n",
                    if span.state == crate::pool::PoolState::Allocated {
                        "allocation"
                    } else {
                        "hole"
                    },
                    span.usable_address,
                    span.size,
                    span.display_tag,
                    span.pool_kind,
                    span.backend
                )
            })
            .unwrap_or_else(|| format!("{address:#x} is not in the cached pool snapshot\n"));
        engine.output(&detail).map_err(|error| error.to_string())?;
        return Ok(());
    }

    let mut filtered = index.clone();
    if let Some(filter) = command.filter {
        filtered.spans.retain(|span| match filter {
            PoolFilter::Paged => span.pool_kind.is_paged(),
            PoolFilter::NonPaged => !span.pool_kind.is_paged(),
        });
        // Rebuild postings after retaining spans while keeping their local context.
        let snapshot = crate::pool::PoolSnapshot {
            spans: filtered.spans,
            diagnostics: filtered.diagnostics,
            complete: true,
        };
        filtered = crate::pool::PoolIndex::build(snapshot);
    }
    for chunk in render_pool_map(
        &filtered,
        RenderOptions {
            tag: command.tag,
            dml: true,
        },
    ) {
        engine
            .output_dml(&chunk)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn command_hresult(client: *mut c_void, args: PCSTR, help_command: bool) -> HRESULT {
    match catch_unwind(AssertUnwindSafe(|| {
        let args = args_string(args)?;
        with_engine(client, |engine| {
            let result = if help_command {
                engine.output(usage()).map_err(|error| error.to_string())
            } else {
                command_poolmap(engine, &args)
            };
            if let Err(message) = &result {
                let _ = engine.output(&format!("win_kexp: {message}\n{}", usage()));
            }
            result
        })?
    })) {
        Ok(Ok(())) => S_OK,
        Ok(Err(message)) => {
            if message.contains("argument")
                || message.contains("tag")
                || message.contains("address")
                || message.contains("mutually exclusive")
            {
                E_INVALIDARG
            } else {
                E_FAIL
            }
        }
        Err(_) => E_UNEXPECTED,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionInitialize(
    version: *mut u32,
    flags: *mut u32,
) -> HRESULT {
    match catch_unwind(AssertUnwindSafe(|| {
        if version.is_null() || flags.is_null() {
            return E_INVALIDARG;
        }
        // DEBUG_EXTENSION_VERSION(1, 0); initialization performs no target access.
        unsafe {
            version.write(1 << 16);
            flags.write(0);
        }
        S_OK
    })) {
        Ok(result) => result,
        Err(_) => E_UNEXPECTED,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionUninitialize() {
    let _ = catch_unwind(AssertUnwindSafe(invalidate_session));
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionNotify(notify: u32, _argument: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| match notify {
        DEBUG_NOTIFY_SESSION_ACTIVE | DEBUG_NOTIFY_SESSION_INACTIVE => invalidate_session(),
        DEBUG_NOTIFY_SESSION_INACCESSIBLE => snapshots().invalidate(),
        DEBUG_NOTIFY_SESSION_ACCESSIBLE => {}
        _ => {}
    }));
}

fn invalidate_session() {
    SESSION_GENERATION.fetch_add(1, Ordering::AcqRel);
    snapshots().invalidate();
    LayoutCache::global().invalidate();
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn poolmap(client: *mut c_void, args: PCSTR) -> HRESULT {
    command_hresult(client, args, false)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn help(client: *mut c_void, args: PCSTR) -> HRESULT {
    command_hresult(client, args, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_extension_abi_and_args() {
        let _initialize: unsafe extern "system" fn(*mut u32, *mut u32) -> HRESULT =
            DebugExtensionInitialize;
        let _uninitialize: unsafe extern "system" fn() = DebugExtensionUninitialize;
        let _notify: unsafe extern "system" fn(u32, u64) = DebugExtensionNotify;
        let _poolmap: unsafe extern "system" fn(*mut c_void, PCSTR) -> HRESULT = poolmap;
        let _help: unsafe extern "system" fn(*mut c_void, PCSTR) -> HRESULT = help;

        let mut version = 0;
        let mut flags = 99;
        assert_eq!(
            unsafe { DebugExtensionInitialize(&mut version, &mut flags) },
            S_OK
        );
        assert_eq!(version, 0x0001_0000);
        assert_eq!(flags, 0);
        assert_eq!(
            unsafe { DebugExtensionInitialize(std::ptr::null_mut(), &mut flags) },
            E_INVALIDARG
        );

        let command = parse_args("-tag Pipe -nonpaged -refresh").unwrap();
        assert_eq!(command.tag, Some(u32::from_le_bytes(*b"Pipe")));
        assert_eq!(command.filter, Some(PoolFilter::NonPaged));
        assert!(command.refresh);
        assert_eq!(
            parse_args("fffff800`12345678").unwrap().address,
            Some(0xffff_f800_1234_5678)
        );
        assert!(parse_args("-tag ABCDE").is_err());
        assert!(parse_args("-tag Test -paged -nonpaged").is_err());
        assert_eq!(validate_pool_target(IMAGE_FILE_MACHINE_AMD64), Ok(()));
        assert_eq!(
            validate_pool_target(0xaa64),
            Err("pool walking supports x64 targets only (machine 0xaa64)".into())
        );

        let mut span = crate::pool::PoolSpan::allocation(
            0x1010,
            0x20,
            0,
            crate::pool::PoolKind::Paged,
            crate::pool::HeapIdentity {
                pool_state: 1,
                heap: 2,
                special: false,
            },
            crate::pool::PoolBackend::Vs,
        );
        span.header_address = 0x1000;
        assert!(span_contains_address(&span, 0x1000));
        assert!(span_contains_address(&span, 0x100f));
        assert!(span_contains_address(&span, 0x1010));
        assert!(span_contains_address(&span, 0x102f));
        assert!(!span_contains_address(&span, 0x0fff));
        assert!(!span_contains_address(&span, 0x1030));

        let before = SESSION_GENERATION.load(Ordering::Acquire);
        unsafe { DebugExtensionNotify(DEBUG_NOTIFY_SESSION_INACTIVE, 0) };
        assert!(SESSION_GENERATION.load(Ordering::Acquire) > before);
        assert_eq!(
            unsafe { poolmap(std::ptr::null_mut(), PCSTR::null()) },
            E_FAIL
        );
    }
}
