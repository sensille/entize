use std::os::raw::{ c_int, c_char, c_void };
use std::ffi::{ CStr, OsStr };
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use entize::TableType;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct mapping {
    pub nentries: u64,
    pub entries: [map_entry; 1000],
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct map_entry {
    pub vma_start: u64,
    pub offset: u64,
    pub offsetmap_id: u32,
    pub start_in_map: u32,
}

#[allow(non_camel_case_types)]
pub struct ent {
    ent: entize::Ent,
    pids: Vec<u32>,
}

type Callback = extern "C" fn(
    ctx: *mut c_void,
    table_type: c_int,
    key: u32,
    value: *const c_void,
    value_size: u32
) -> c_int;

#[unsafe(no_mangle)]
extern "C" fn ent_init() -> * mut ent {
    let ent = entize::Ent::new();

    Box::into_raw(Box::new(ent {
        ent,
        pids: Vec::new()
    }))
}

fn cb_wrapper(cb: Callback, ctx: *mut c_void, table_type: TableType, key: u32, value: &[u8])
    -> entize::Result<()>
{
    let res = cb(ctx, table_type as i32, key, value.as_ptr() as *const c_void, value.len() as u32);
    if res == 0 {
        Ok(())
    } else {
        Err(entize::EntError::CallbackFailed)
    }
}

#[unsafe(no_mangle)]
extern "C" fn ent_add_pid(ent: *mut ent, pid: u32, cb: Callback, ctx: *mut c_void) -> c_int {
    let ent: &mut ent = unsafe { &mut *(ent as *mut ent) };

    let Err(_e) = ent.ent.add_pid(pid, &|t, k, v| cb_wrapper(cb, ctx, t, k, v)) else {
        ent.pids.push(pid);
        return 0;
    };

    // XXX fixme: map error properly
    -1
}

#[unsafe(no_mangle)]
extern "C" fn ent_add_file(ent: &mut ent, file_path: *const c_char,
    cb: Callback, ctx: *mut c_void) -> c_int
{
    let file_path = unsafe { CStr::from_ptr(file_path) };
    let file_path = OsStr::from_bytes(file_path.to_bytes());
    let file_path = PathBuf::from(file_path);

    let Err(_e) = ent.ent.add_file(file_path, &|t, k, v| cb_wrapper(cb, ctx, t, k, v)) else {
        return 0;
    };

    // XXX fixme: map error properly
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn ent_free(ent: &mut ent) {
    unsafe {
        let _boxed_db = Box::from_raw(ent);
    }
}
