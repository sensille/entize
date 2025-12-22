use cbindgen::Language;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(manifest_dir)
        .with_language(Language::C)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file("entize.h");
}
