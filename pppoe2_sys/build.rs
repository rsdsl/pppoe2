use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new().file("pppoe2/pppoe2.c").compile("pppoe2");

    let header = "pppoe2";
    let bindings = bindgen::Builder::default()
        .header(format!("pppoe2/{}.h", header))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join(format!("{}_bindings.rs", header)))
        .expect("Couldn't write bindings");
}
