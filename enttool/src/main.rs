use anyhow::Result;
use entize::Ent;

fn cb(_t: entize::TableType, _k: u32, _v: &[u8]) -> entize::Result<()> {
    println!("TableType: {:?}, Key: {}, Value Length: {}", _t, _k, _v.len());
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    //let pid = (std::env::args().nth(1).unwrap()).parse::<u32>()?;

    let mut ent = Ent::new();

    ent.add_file("ceph-osd-19.2.3-0.el9.x86_64.debug", &cb)?;
    //ent.add_file("ceph-osd", &cb)?;
    /*
    ent.build_unwind_tables()?;
    return Ok(());
    ent.add_file("/usr/lib/libz.so.1.3.1")?;
    */

    //ent.add_file("/usr/lib/firefox/libxul.so")?;

    /*
    ent.add_pid(pid, &|_t, _k, _v| {
        Ok(())
    })?;

    */
    //let res = ent.lookup(pid, 0x7cd5da39a1cb);
    //println!("{:?}", res);

    Ok(())
}
