use object::{Object, ObjectSection};
use gimli::UnwindSection;
use thiserror::Error;
use std::collections::{ HashMap, BTreeMap };
use log::{ debug, info, warn };
use std::ffi::OsString;

mod table;

const NUM_REGISTERS: usize = 17; // r0 - r15 + pc
const CFT_ENTRY_SIZE: usize = 228;
const MAX_MAPPINGS: usize = 1000;
const CHUNK_SIZE: usize = 256 * 1024; // 256 KB per eBPF map entry

#[derive(Error, Debug)]
pub enum EntError {
    #[error("File open failed")]
    FileOpenError(std::io::Error),
    #[error("MMap failed")]
    MmapError(std::io::Error),
    #[error("Object could not be parsed")]
    ObjectParseError(object::Error),
    #[error("No exception handling information in object")]
    NoEhInfo,
    #[error("Dwarf error: bad expression offset")]
    DwarfErrorExpressionOffset,
    #[error("Dwarf error: unknown register rule")]
    DwarfErrorUnknownRegisterRule,
    #[error("Gimli error")]
    GimliError(gimli::Error),
    #[error("CIE missing for FDE")]
    MissingCie,
    #[error("Object table is full")]
    TooManyObjects,
    #[error("Can't encode table value")]
    TableValueEncodeError,
    #[error("Can't encode table ptr")]
    TablePtrEncodeError,
    #[error("Can't decode table value")]
    TableValueDecodeError,
    #[error("Table build error")]
    TableBuildError,
    #[error("Table not yet built")]
    TableNotBuilt,
    #[error("PID not found")]
    PidNotFound,
    #[error("Unexpected object type, expected ELF")]
    UnexpectedObjectType,
    #[error("Callback function failed")]
    CallbackFailed,

}
use EntError::*;

#[derive(Debug, Clone, Copy)]
pub enum TableType {
    UnwindTable = 1,
    UnwindEntries = 2,
    Expressions = 3,
    Mappings = 4,
}

pub type Result<T> = std::result::Result<T, EntError>;
// table_type: i32, key: u32, value: &[u8] -> result: i32;
pub trait Callback: Fn(TableType, u32, &[u8]) -> Result<()> {}
impl<T> Callback for T where T: Fn(TableType, u32, &[u8]) -> Result<()> {}

/*
#[derive(Debug)]
struct EvaluationContext {
    address_size: usize,
    dwarf_version: usize,
    dwarf64: bool,
}
*/

#[derive(Debug)]
pub struct Ent {
    next_oid: usize,
    next_entry_id: usize,
    next_expression_id: usize,
    current_table_id: usize,
    unwind_entries_rev: BTreeMap<Vec<u8>, usize>,
    expressions_rev: BTreeMap<Vec<u8>, usize>,
    total_eh_frame_size: usize,
    table_mappings: HashMap<usize, Vec<(u64, usize, usize)>>, // oid -> ( table id, offset)
    files_seen: HashMap<OsString, Option<usize>>, // file path -> oid
    current_table: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ParsingError {
    NoError,
    BadExpressionOffset,
    UnknownRegisterRule,
    RowOverlap,
}

impl Ent {
    pub fn new() -> Self {
        Ent {
            next_oid: 0,
            next_entry_id: 1, // entry id 0 means no unwind info
            next_expression_id: 0,
            current_table_id: 0,
            unwind_entries_rev: BTreeMap::new(),
            expressions_rev: BTreeMap::new(),
            total_eh_frame_size: 0,
            table_mappings: HashMap::new(),
            files_seen: HashMap::new(),
            current_table: Vec::new(),
        }
    }


    // returns (oid, parsing errors, unwind_table)
    // the returned unwind table is normally not needed, it is returned
    // so that it is possible to easily build a lookup tool
    // to aid in debugging
    fn add_new_file<P: AsRef<std::path::Path>, F: Callback>(&mut self, path: P, cb: &F)
        -> Result<(usize, HashMap<ParsingError, u64>, BTreeMap<u64, Option<usize>>)>
    {
        let oid = self.next_oid;
        if oid == u16::MAX as usize {
            return Err(TooManyObjects);
        }
        if oid == 0 {
            // first time here, add empty unwind entry at id 0
            cb(TableType::UnwindEntries, 0, &[0u8; CFT_ENTRY_SIZE])?;
        }
        self.next_oid += 1;
        let file = std::fs::File::open(&path).map_err(FileOpenError)?;

        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(MmapError)? };
        let object = object::File::parse(&*mmap).map_err(ObjectParseError)?;

        /*
         * enumerate all sections and store the offset between VMA and file offset
         */
        let mut map_offsets: BTreeMap<u64, i64> = BTreeMap::new();
        for section in object.sections() {
            let object::SectionFlags::Elf{ sh_flags: flags} = section.flags() else {
                return Err(UnexpectedObjectType);
            };
            if (flags as u32 & object::elf::SHF_ALLOC) == 0 {
                continue;
            }
            let addr = section.address();
            let Some((offset, _)) = section.file_range() else {
                continue;
            };
            if addr == offset {
                continue;
            }
            map_offsets.insert(addr, addr as i64 - offset as i64);
        }

        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or(NoEhInfo)?;

        let mut unwind_table = BTreeMap::new();
        let mut parsing_errors = HashMap::new();
        let eh_frame_data = eh_frame_section.uncompressed_data().map_err(ObjectParseError)?;
        debug!("Parsing .eh_frame of size {}", eh_frame_data.len());
        self.total_eh_frame_size += eh_frame_data.len();
        let eh_frame = gimli::EhFrame::new(&eh_frame_data, gimli::NativeEndian);
        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address());
        let mut entries = eh_frame.entries(&bases);
        let mut cies = HashMap::new();
        let mut unwind_ctx = gimli::UnwindContext::new();
        while let Some(entry) = entries.next().map_err(GimliError)? {
            match entry {
                gimli::CieOrFde::Cie(cie) => {
                    cies.insert(cie.offset(), cie);
                }
                gimli::CieOrFde::Fde(partial_fde) => {
                    let fde = partial_fde.parse(
                        |_, _, o| {
                            if let Some(cie) = cies.get(&o.0) {
                                Ok(cie.clone())
                            } else {
                                Err(gimli::read::Error::Io)
                            }
                        })
                        .map_err(GimliError)?;

                    let mut table = fde.rows(&eh_frame, &bases, &mut unwind_ctx)
                        .map_err(GimliError)?;
                    let mut error = ParsingError::NoError;
                    let map_offset = map_offsets.range(..=fde.initial_address())
                        .next_back()
                        .map(|(_, o)| *o)
                        .unwrap_or(0);
                    'rows: while let Some(row) = table.next_row().map_err(GimliError)? {
                        let mut s = Vec::new();
                        // serialize row into the format used by our eBPF program
                        let saved_args_size = row.saved_args_size() as u64;
                        s.extend_from_slice(&saved_args_size.to_le_bytes());

                        match row.cfa() {
                            gimli::CfaRule::RegisterAndOffset { register, offset } => {
                                let reg = register.0 as u32;
                                let off = *offset as i64;
                                s.extend_from_slice(&1u32.to_le_bytes());
                                s.extend_from_slice(&reg.to_le_bytes());
                                s.extend_from_slice(&off.to_le_bytes());
                            }
                            gimli::CfaRule::Expression(e) => {
                                if e.offset + e.length > eh_frame_data.len() {
                                    break 'rows;
                                }
                                let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                    [e.offset .. e.offset + e.length]), cb)?;
                                let expr_id = expr_id as u32;
                                s.extend_from_slice(&2u32.to_le_bytes());
                                s.extend_from_slice(&expr_id.to_le_bytes());
                                s.extend_from_slice(&[0u8; 8]);
                            }
                        }
                        // convert registers
                        let mut rules_s = Vec::new();
                        for (reg, rule) in row.registers() {
                            let mut rs = Vec::new();
                            match rule {
                                gimli::RegisterRule::Undefined => {
                                    rs.extend_from_slice(&1u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::SameValue => {
                                    rs.extend_from_slice(&2u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::Offset(o) => {
                                    let off = *o as i64;
                                    rs.extend_from_slice(&3u32.to_le_bytes());
                                    rs.extend_from_slice(&off.to_le_bytes());
                                }
                                gimli::RegisterRule::ValOffset(o) => {
                                    let off = *o as i64;
                                    rs.extend_from_slice(&4u32.to_le_bytes());
                                    rs.extend_from_slice(&off.to_le_bytes());
                                }
                                gimli::RegisterRule::Register(r) => {
                                    let reg = r.0 as u64;
                                    rs.extend_from_slice(&5u32.to_le_bytes());
                                    rs.extend_from_slice(&reg.to_le_bytes());
                                },
                                gimli::RegisterRule::Expression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]), cb)?;
                                        let expr_id = expr_id as u64;
                                        rs.extend_from_slice(&6u32.to_le_bytes());
                                        rs.extend_from_slice(&expr_id.to_le_bytes());
                                }
                                gimli::RegisterRule::ValExpression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]), cb)?;
                                    rs.extend_from_slice(&7u32.to_le_bytes());
                                    rs.extend_from_slice(&expr_id.to_le_bytes());
                                }
                                gimli::RegisterRule::Architectural => {
                                    rs.extend_from_slice(&8u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::Constant(c) => {
                                    let c = *c as u64;
                                    rs.extend_from_slice(&9u32.to_le_bytes());
                                    rs.extend_from_slice(&c.to_le_bytes());
                                }
                                _ => {
                                    error = ParsingError::UnknownRegisterRule;
                                    break 'rows;
                                }
                            };
                            rules_s.push((reg.0, rs));
                        }

                        for i in 0 .. NUM_REGISTERS as u16 {
                            if let Some((_, rule)) = rules_s.iter().find(|(r, _)| *r == i) {
                                s.extend_from_slice(rule);
                            } else {
                                // uninitialized
                                s.extend_from_slice(&0u32.to_le_bytes());
                                s.extend_from_slice(&[0u8; 8]);
                            }
                        }
                        assert_eq!(s.len(), CFT_ENTRY_SIZE);

                        // get row index or create new
                        let entryid = if let Some(id) = self.unwind_entries_rev.get(&s) {
                            *id
                        } else {
                            let id = self.next_entry_id;
                            self.next_entry_id += 1;
                            cb(TableType::UnwindEntries, id as u32, &s)?;
                            self.unwind_entries_rev.insert(s, id);
                            id
                        };
                        // VMAs are much smaller than 64 bits
                        let start = (row.start_address() as i64 - map_offset) as u64;
                        let end = (row.end_address() as i64 - map_offset) as u64;
                        // start may override end
                        // start may not override start
                        // end overrides nothing
                        if let Some(Some(_)) = unwind_table.get(&start) {
                            error = ParsingError::RowOverlap;
                            break 'rows;
                        }
                        unwind_table.insert(start, Some(entryid));
                        if unwind_table.get(&end).is_none() {
                            unwind_table.insert(end, None);
                        }
                    }
                    if error != ParsingError::NoError {
                        *parsing_errors.entry(error).or_default() += 1;
                    }
                }
            }
        }
        warn!("Parsing errors: {:?}", parsing_errors);
        info!("Unwind entries: {}", self.next_entry_id);
        info!("Unwind table  : {}", unwind_table.len());
        info!("Expressions   : {}", self.next_expression_id);

        // convert unwind table to arr with u64 -> u64
        let mut arr = Vec::with_capacity(unwind_table.len());
        for (&addr, &entry_opt) in &unwind_table {
            let entry_id = match entry_opt {
                Some(eid) => eid,
                None => 0,             // 0 means end of unwind info
            };
            arr.push((addr, entry_id as u64));
        }

        let mut start = 0;
        while arr.len() > start {
            // leave 16 bytes to relax bounds checks in eBPF
            let sz = CHUNK_SIZE - self.current_table.len() - 16;
            let (table, entries) = table::build(&arr[start..], sz)?;
            let entry = self.table_mappings.entry(oid).or_default();
            entry.push((arr[start].0, self.current_table_id, self.current_table.len()));
            println!("Mapping file offset {:x} to table id {} offset {:x}",
                arr[start].0, self.current_table_id, self.current_table.len());
            if self.current_table.is_empty() {
                self.current_table = table;
            } else {
                self.current_table.extend_from_slice(&table);
            }
            if self.current_table.len() >= CHUNK_SIZE - 200 {
                cb(TableType::UnwindTable, self.current_table_id as u32,
                    &self.current_table)?;
                self.current_table = Vec::new();
                self.current_table_id += 1;
            }
            start += entries;
        }

        Ok((oid, parsing_errors, unwind_table))
    }

    fn add_file_nopush<P: AsRef<std::path::Path>, F: Callback>(&mut self, path: P, cb: &F) ->
        Result<Option<(usize, Option<(HashMap<ParsingError, u64>, BTreeMap<u64, Option<usize>>)>)>>
    {
        let path: OsString = path.as_ref().as_os_str().to_os_string();
        if let Some(r) = self.files_seen.get(&path) {
            if let Some(oid) = r {
                return Ok(Some((*oid, None)));
            }
            return Ok(None);
        }

        match self.add_new_file(&path, cb) {
            Ok((oid, errors, unwind_table)) => {
                self.files_seen.insert(path, Some(oid));
                Ok(Some((oid, Some((errors, unwind_table)))))
            }
            Err(e) => {
                self.files_seen.insert(path, None);
                Err(e)
            },
        }
    }

    pub fn add_file<P: AsRef<std::path::Path>, F: Callback>(&mut self, path: P, cb: &F) ->
        Result<Option<(usize, Option<(HashMap<ParsingError, u64>, BTreeMap<u64, Option<usize>>)>)>>
    {
        let res = self.add_file_nopush(path, cb)?;
        self.push_current_table(cb)?;
        Ok(res)
    }

    fn add_expression<F: Callback>(&mut self, expr: Vec<u8>, cb: &F) -> Result<usize> {
        debug!("expression: {:?}", expr);
        if let Some(id) = self.expressions_rev.get(&expr) {
            Ok(*id)
        } else {
            let id = self.next_expression_id;
            self.next_expression_id += 1;
            assert!(expr.len() < 256);
            let mut e = expr.clone();
            e.extend_from_slice(&[e.len() as u8; 1]);
            e.extend(vec![0u8; 255 - expr.len()]); // align to 16 bytes
            cb(TableType::Expressions, id as u32, &e)?;

            self.expressions_rev.insert(expr, id);
            Ok(id)
        }
    }

    pub fn add_pid<F: Callback>(&mut self, pid: u32, cb: &F) -> Result<()> {
        let maps = read_process_maps(pid)?;
        let mut s = vec![0u8; 8]; // reserve space for number of entries
        let mut num_entries = 0;
        for map in &maps {
            let res = self.add_file(&map.file_path, cb);
            let Ok(Some((oid, _))) = res else {
                debug!("File not added: {}, res {:?}", map.file_path, res);
                continue;
            };
            let Some(mapping) = self.table_mappings.get(&oid) else {
                println!("No mapping found for oid {}", oid);
                break;
            };
println!("mappings {:x?}", mapping);
            let map_offset_end = map.offset + (map.vm_end - map.vm_start);
            for (file_offset, table_id, table_offset) in mapping.iter() {
                if *file_offset >= map_offset_end {
                    break;
                }
                if *file_offset < map.offset {
                    continue;
                }
                let delta = *file_offset - map.offset;

                let start = (map.vm_start + delta) as u64;
                let offset = (map.offset + delta) as u64;
                let table_id = *table_id as u32;
                let table_offset = *table_offset as u32;

println!("Mapping VM {:x} offset {:x} to table id {} offset {:x}", start, offset, table_id, table_offset);
                s.extend_from_slice(&start.to_le_bytes());
                s.extend_from_slice(&offset.to_le_bytes());
                s.extend_from_slice(&table_id.to_le_bytes());
                s.extend_from_slice(&table_offset.to_le_bytes());

                num_entries += 1;
            }
        }
        self.push_current_table(cb)?;
        // prepend number of entries
        let num_entries_u64 = num_entries as u64;
        s[0..8].copy_from_slice(&num_entries_u64.to_le_bytes());
        // fill up to expected size
        s.extend(vec![0u8; (MAX_MAPPINGS - num_entries) * 24]);

        cb(TableType::Mappings, pid, &s)?;

        Ok(())
    }

    fn push_current_table<F: Callback>(&mut self, cb: &F) -> Result<()> {
        if !self.current_table.is_empty() {
            let mut t = self.current_table.clone();
            t.extend(vec![0u8; CHUNK_SIZE - self.current_table.len()]); // pad end
            cb(TableType::UnwindTable, self.current_table_id as u32, &t)?;
        }
        Ok(())
    }

    /*
    pub fn lookup(&self, pid: u32, addr: u64) -> Option<(usize, usize)> {
        let Some(maps) = self.pid_map.get(&pid) else {
            return None;
        };
        for map in maps.iter() {
            if addr >= map.vm_start && addr < map.vm_end {
                let Some(Some(oid)) = self.files_seen.get(&map.file_path) else {
                    return None;
                };
                let unwind_table = &self.unwind_tables[*oid];
                let offset = addr - map.vm_start + map.offset;
                let entry = unwind_table.range(..=offset).next_back();
                println!("Unwind table entry for addr {:x} off {:x}: {:x?}", addr, offset, entry);
                let Some((_, entry_opt)) = entry else {
                    println!("No unwind info for addr {:x}", addr);
                    return None;
                };
                let entry_id = match entry_opt {
                    Some(eid) => *eid + 1, // entry ids start at 1
                    None => 0,             // 0 means end of unwind info
                };
                println!("Found unwind entry id {} for addr {:x}", entry_id, addr);
                let rules = self.unwind_entries.get(&entry_id)?;
                println!("Unwind rules: {:x?}", rules);
            }
        }
        None
    }
    */
}
#[derive(Debug)]
pub struct ProcessMap {
    pub vm_start: u64,
    pub vm_end: u64,
    pub offset: u64,
    pub file_path: String,
}

pub fn read_process_maps(pid: u32) -> Result<Vec<ProcessMap>> {
    let path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(path).map_err(FileOpenError)?;
    let mut maps = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() < 6 {  // ignore all lines without file path
            continue;
        }
        if !parts[5].starts_with("/") {  // ignore anon mappings
            continue;
        }
        if parts[5].ends_with(" (deleted)") {  // ignore deleted files
            continue;
        }
        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let vm_start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let vm_end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
        let file_path = parts[5].to_string();
println!("map: {:x}-{:x} offset {:x} file {}", vm_start, vm_end, offset, file_path);
        maps.push(ProcessMap {
            vm_start,
            vm_end,
            offset,
            file_path,
        });
    }
    Ok(maps)
}
