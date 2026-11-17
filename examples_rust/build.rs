use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

fn compiler_directory(compiler: &OsStr, argument: &str) -> Option<PathBuf> {
    let output = Command::new(compiler).arg(argument).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(value.trim());
    // GCC returns the literal "include" when it cannot resolve the directory.
    path.is_absolute().then_some(path)
}

fn with_builtin_headers(builder: bindgen::Builder) -> bindgen::Builder {
    let target = env::var("TARGET").unwrap_or_default();
    let target_flags = format!("BINDGEN_EXTRA_CLANG_ARGS_{}", target);
    let target_flags_underscored = target_flags.replace('-', "_");
    let mut explicit_flags = false;
    for variable in [
        "BINDGEN_EXTRA_CLANG_ARGS",
        &target_flags,
        &target_flags_underscored,
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
        explicit_flags |= env::var_os(variable).is_some_and(|value| !value.is_empty());
    }

    if let Some(directory) = env::var_os("LIBZUPT_CLANG_RESOURCE_DIR") {
        let directory = PathBuf::from(directory);
        assert!(
            directory.join("include/stddef.h").is_file(),
            "LIBZUPT_CLANG_RESOURCE_DIR must contain include/stddef.h: {}",
            directory.display()
        );
        return builder.clang_arg(format!("-resource-dir={}", directory.display()));
    }

    // Leave explicit sysroots/header flags and cross builds to bindgen. In
    // particular, never add the host GCC's headers to a different Rust target.
    if explicit_flags || env::var("HOST").unwrap_or_default() != target {
        return builder;
    }

    let clang = env::var_os("CLANG_PATH").unwrap_or_else(|| "clang".into());
    if let Some(directory) = compiler_directory(&clang, "-print-resource-dir") {
        if directory.join("include/stddef.h").is_file() {
            println!(
                "cargo:warning=Using Clang resource headers: {}",
                directory.display()
            );
            return builder.clang_arg(format!("-resource-dir={}", directory.display()));
        }
    }

    // Some distributions install libclang without a clang executable or with
    // a resource layout libclang cannot infer. For native C API generation,
    // the installed C compiler can supply stddef.h without a versioned path.
    let cc = env::var_os("CC").unwrap_or_else(|| "cc".into());
    if let Some(directory) = compiler_directory(&cc, "-print-file-name=include") {
        if directory.join("stddef.h").is_file() {
            println!(
                "cargo:warning=Using C compiler builtin headers: {}",
                directory.display()
            );
            return builder
                .clang_arg("-isystem")
                .clang_arg(directory.to_string_lossy());
        }
    }
    builder
}

fn main() {
    let zupt_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let include_dir = zupt_dir.join("include");

    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("zupt_cxx.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("zupt.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("zupt_keccak.h").display()
    );
    println!("cargo:rerun-if-changed=build.rs");
    for variable in [
        "LIBZUPT_CLANG_RESOURCE_DIR",
        "CLANG_PATH",
        "LIBCLANG_PATH",
        "CC",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let builder = bindgen::Builder::default()
        .header(include_dir.join("zupt_cxx.h").to_str().unwrap())
        .header(include_dir.join("zupt.h").to_str().unwrap())
        .header(include_dir.join("zupt_keccak.h").to_str().unwrap())
        .clang_arg(format!("-I{}", include_dir.display()))
        .allowlist_function("zupt_.*")
        .allowlist_type("zupt_.*")
        .allowlist_var("ZUPT_.*")
        .allowlist_var("MLKEM_.*")
        .allowlist_var("HYBRID_.*")
        .allowlist_var("AES_.*")
        .allowlist_var("HMAC_.*")
        .allowlist_var("X25519_.*")
        .use_core();
    let bindings = with_builtin_headers(builder)
        .generate()
        .unwrap_or_else(|error| {
            panic!(
                "Unable to generate libzupt bindings: {error}\n\
                 If stddef.h is missing, install the Clang resource headers, set \
                 CLANG_PATH to the matching clang executable, or set \
                 LIBZUPT_CLANG_RESOURCE_DIR to a directory containing include/stddef.h. \
                 Native GCC builds can also use BINDGEN_EXTRA_CLANG_ARGS='-isystem <gcc-include-dir>'."
            )
        });

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let build_dir = env::var_os("LIBZUPT_LIBRARY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| zupt_dir.join("build"));
    println!("cargo:rerun-if-env-changed=LIBZUPT_LIBRARY_DIR");
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
