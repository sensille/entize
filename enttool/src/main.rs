use anyhow::Result;
use entize::Ent;

fn main() -> Result<()> {
    env_logger::init();

    let mut ent = Ent::new();
    /*
    ent.add_file("../entutil/ceph-osd")?;
    ent.build_unwind_tables()?;
    return Ok(());
    ent.add_file("/usr/lib/libz.so.1.3.1")?;
    */
    let pid = 4504;
    //ent.add_file("/usr/lib/firefox/libxul.so")?;
    ent.add_pid(pid)?;
    ent.build_tables()?;
    let res = ent.lookup(pid, 0x7cd5da39a1cb);
    println!("{:?}", res);

    Ok(())
}
