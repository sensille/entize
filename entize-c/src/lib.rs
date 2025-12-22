use std::os::raw::{ c_int, c_char, c_void };
use std::ffi::{ CStr, OsStr };
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

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

#[unsafe(no_mangle)]
extern "C" fn ent_init() -> * mut ent {
    let ent = entize::Ent::new();

    Box::into_raw(Box::new(ent {
        ent,
        pids: Vec::new()
    }))
}

#[unsafe(no_mangle)]
extern "C" fn ent_add_pid(ent: *mut ent, pid: u32) -> c_int {
    let ent: &mut ent = unsafe { &mut *(ent as *mut ent) };

    let Err(_e) = ent.ent.add_pid(pid) else {
        ent.pids.push(pid);
        return 0;
    };

    // XXX fixme: map error properly
    -1
}

/* TODO: do we really need to sort the unwind entries?
   Test. If not, we can beautifully stream the tables
   Also: make value encoding more complex, but don't decode
   on the way down, only at the end
*/
#[unsafe(no_mangle)]
extern "C" fn ent_add_file(ent: &mut ent, file_path: *const c_char) {
    let file_path = unsafe { CStr::from_ptr(file_path) };
    let file_path = OsStr::from_bytes(file_path.to_bytes());
    let file_path = PathBuf::from(file_path);

    println!("Would add file {:?} to ent module", file_path);
}

#[unsafe(no_mangle)]
pub extern "C" fn ent_build_tables(ent: &mut ent,
    cb: extern "C" fn(ctx: *mut c_void, table_type: c_int, key: u32,
                      value: *const c_void, value_size: u32) -> c_int,
    ctx: *mut c_void) -> c_int
{
    let ent: &mut ent = unsafe { &mut *(ent as *mut ent) };

    let (unwind_tables, unwind_entries, expressions) =
        match ent.ent.build_tables()
    {
        Ok(tables) => tables,
        Err(_e) => {
            // XXX fixme: map error properly
            return -1;
        }
    };

    for (id, table) in unwind_tables.iter().enumerate() {
        let res = cb(ctx, 1, id as u32,
                     table.as_ptr() as *const c_void,
                     table.len() as u32);
        if res != 0 {
            // XXX fixme: map error properly
            return -1;
        }
    }

    for (id, entry) in unwind_entries.iter().enumerate() {
        let res = cb(ctx, 2, id as u32,
                     entry.as_ptr() as *const c_void,
                     entry.len() as u32);
        if res != 0 {
            // XXX fixme: map error properly
            return -1;
        }
    }

    for (id, expr) in expressions.iter().enumerate() {
        let res = cb(ctx, 3, id as u32,
                     expr.as_ptr() as *const c_void,
                     expr.len() as u32);
        if res != 0 {
            // XXX fixme: map error properly
            return -1;
        }
    }


    for pid in &ent.pids {
println!("Generating mapping for pid {}", pid);
        let mapping = match ent.ent.build_mapping_for_pid(*pid) {
            Ok(mapping) => mapping,
            Err(_e) => {
                // XXX fixme: map error properly
                return -1;
            }
        };
println!("Mapping for pid {} is {} bytes", pid, mapping.len());
        let res = cb(ctx, 4, *pid,
                     mapping.as_ptr() as *const c_void,
                     mapping.len() as u32);
        if res != 0 {
            // XXX fixme: map error properly
            return -1;
        }
    }

    println!("Generated tables for ent module");

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ent_free(ent: &mut ent) {
    unsafe {
        let _boxed_db = Box::from_raw(ent);
    }
}
