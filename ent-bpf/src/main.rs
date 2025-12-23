use anyhow::{Result, bail, Context};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::{ MapCore, MapFlags, RingBufferBuilder };
use std::default::Default;
use blazesym::symbolize::source::{ Process, Source };
use blazesym::symbolize::{ Symbolizer, Symbolized, Input };
use blazesym::Pid;

#[allow(non_camel_case_types)]
pub struct mapping {
    pub nentries: u64,
    pub entries: [map_entry; 1000],
}
impl Default for mapping {
    fn default() -> Self {
        Self {
            nentries: u64::default(),
            entries: [map_entry::default(); 1000],
        }
    }
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

mod ent {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/ent.skel.rs"
    ));
}
use ent::*;
mod syscall;

fn init_perf(freq: u64, sw_event: bool) -> Result<Vec<i32>> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = -1;
    let attr = syscall::perf_event_attr {
        _type: if sw_event {
            syscall::PERF_TYPE_SOFTWARE
        } else {
            syscall::PERF_TYPE_HARDWARE
        },
        size: std::mem::size_of::<syscall::perf_event_attr>() as u32,
        config: if sw_event {
            syscall::PERF_COUNT_SW_CPU_CLOCK
        } else {
            syscall::PERF_COUNT_HW_CPU_CYCLES
        },
        sample: syscall::sample_un { sample_freq: freq },
        flags: 1 << 10, // freq = 1
        ..Default::default()
    };
    let mut fds = Vec::new();
    for cpu in 0..nprocs {
        let fd = syscall::perf_event_open(&attr, pid, cpu as i32, -1, 0) as i32;
        if fd == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENODEV) => continue, // CPU does not exist
                Some(libc::ENOENT) if !sw_event => return init_perf(freq, true),
                Some(x) => bail!("Failed to open perf event: error {}", x),
                None => bail!("Failed to open perf event"),
            }
        } else {
            fds.push(fd);
        }
    }

    Ok(fds)
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &libbpf_rs::ProgramMut,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
}

fn main() -> Result<()> {
    env_logger::init();

    let pid = (std::env::args().nth(1).unwrap()).parse::<u32>()?;

    let mut ent = entize::Ent::new();

    let mut skel_builder = EntSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)
        .context("failed to open ENT skel")?;

    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .expect("`rodata` is not memory mapped");

    // Write arguments into prog
    rodata.targ_pid = pid;

    // set map sizes
    open_skel.maps.offsetmaps.set_max_entries(1000)?;
    open_skel.maps.mappings.set_max_entries(1)?;
    open_skel.maps.cfts.set_max_entries(10000)?;
    open_skel.maps.expressions.set_max_entries(100)?;

    let mut skel = open_skel.load()
        .context("failed to load ENT skel")?;

    ent.add_pid(pid, &|table, key, value| {
println!("Adding to table {:?} key {} value len {}", table, key, value.len());
        let tab = match table {
            entize::TableType::UnwindTable => &skel.maps.offsetmaps,
            entize::TableType::UnwindEntries => &skel.maps.cfts,
            entize::TableType::Expressions => &skel.maps.expressions,
            entize::TableType::Mappings => &skel.maps.mappings,
        };
        let res = tab.update(&key.to_le_bytes(), value, MapFlags::ANY);
        if res.is_err() {
            return Err(entize::EntError::CallbackFailed);
        }
        Ok(())
    })?;

    let pefds = init_perf(7, false)
        .context("failed to initialize perf monitor")?;
    let _links = attach_perf_event(&pefds, &skel.progs.ustack);

    skel.attach()
        .context("failed to attach ENT skel")?;

    println!("ENT attached, sleeping...");

    let src = Source::Process(Process::new(Pid::from(pid)));
    let symbolizer = Symbolizer::new();

    #[repr(C)]
    struct StackOut {
            nframes: u32,
            frames: [u64; 64],
    }
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps.rb, |data| {
                assert_eq!(data.len(), std::mem::size_of::<StackOut>());
                let data = unsafe {
                    &*(data.as_ptr() as *const StackOut)
                };
                println!("nframes {}", data.nframes);
                for i in 0..data.nframes as usize {
                    let ip = data.frames[i];
                    let sym = symbolizer.symbolize_single(&src, Input::AbsAddr(ip));
                    let s = match sym {
                        Ok(Symbolized::Sym(s)) => s.name.to_string(),
                        Ok(Symbolized::Unknown(r)) => r.to_string(),
                        Err(e) => {
                            println!("    symbolization error: {:?}", e);
                            continue;
                        }
                    };
                    println!("   {:#x} {}", ip, s);
                }
                1
        })
        .context("failed to build ring buffer")?;
    let rb = rbb.build()?;
    loop {
        rb.poll(std::time::Duration::from_secs(100))?;
    }
}
