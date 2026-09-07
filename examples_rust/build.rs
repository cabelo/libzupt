use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let zupt_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let include_dir = zupt_dir.join("include");

    println!("cargo:rerun-if-changed={}", include_dir.join("zupt_cxx.h").display());
    println!("cargo:rerun-if-changed={}", include_dir.join("zupt.h").display());
    println!("cargo:rerun-if-changed={}", include_dir.join("zupt_keccak.h").display());
    println!("cargo:rerun-if-changed=build.rs");

    let bindings = bindgen::Builder::default()
        .header(include_dir.join("zupt_cxx.h").to_str().unwrap())
        .header(include_dir.join("zupt.h").to_str().unwrap())
        .header(include_dir.join("zupt_keccak.h").to_str().unwrap())
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg("-isystem")
        .clang_arg("/usr/lib64/clang/19/include")
        .allowlist_function("zupt_.*")
        .allowlist_type("zupt_.*")
        .allowlist_var("ZUPT_.*")
        .allowlist_var("MLKEM_.*")
        .allowlist_var("HYBRID_.*")
        .allowlist_var("AES_.*")
        .allowlist_var("HMAC_.*")
        .allowlist_var("X25519_.*")
        .use_core()
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let build_dir = zupt_dir.join("build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    if build_dir.join("libzupt.so").exists() || build_dir.join("libzupt.so.1").exists() {
        println!("cargo:rustc-link-lib=dylib=zupt");
    } else if build_dir.join("libzupt_static.a").exists() {
        println!("cargo:rustc-link-lib=static=zupt_static");
    } else {
        println!("cargo:rustc-link-lib=dylib=zupt");
    }

    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", build_dir.display());
}
