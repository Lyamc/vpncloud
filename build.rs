// Compile the vendored ML-KEM-768 (PQClean clean) into a static library.
use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let kem = manifest.join("third_party/pqclean/ml-kem-768");
    let common = manifest.join("third_party/pqclean/common");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", kem.display());
    println!("cargo:rerun-if-changed={}", common.display());

    let sources = [
        kem.join("cbd.c"),
        kem.join("indcpa.c"),
        kem.join("kem.c"),
        kem.join("ntt.c"),
        kem.join("poly.c"),
        kem.join("polyvec.c"),
        kem.join("reduce.c"),
        kem.join("symmetric-shake.c"),
        kem.join("verify.c"),
        common.join("fips202.c"),
        common.join("randombytes.c"),
    ];
    let mut objects = Vec::new();
    for src in &sources {
        let obj = out.join(src.file_name().unwrap()).with_extension("o");
        let status = Command::new("clang")
            .args(["-O2", "-fPIC", "-std=c99", "-Wall"])
            .arg("-I")
            .arg(&kem)
            .arg("-I")
            .arg(&common)
            .arg("-c")
            .arg(src)
            .arg("-o")
            .arg(&obj)
            .status()
            .expect("clang");
        if !status.success() {
            panic!("clang failed on {}", src.display());
        }
        objects.push(obj);
    }
    let lib = out.join("libmlkem.a");
    let status = Command::new("ar").arg("rcs").arg(&lib).args(&objects).status().expect("ar");
    if !status.success() {
        panic!("ar failed");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=mlkem");
}
