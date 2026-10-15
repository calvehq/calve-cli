fn main() {
    // The exact target triple the crate is compiled for (`catalog::HOST_TARGET`).
    println!(
        "cargo:rustc-env=CALVE_HOST_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET")
    );
}
