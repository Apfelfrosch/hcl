fn main() {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        println!("cargo::rustc-link-search=c/lib/macos_aarch64");
        println!("cargo::rustc-link-lib=static=sodium");
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        println!("cargo::rustc-link-search=c/lib/windows_x86_64");
        println!("cargo::rustc-link-lib=static=sodium");
    } else if cfg!(all(
        target_os = "linux",
        target_env = "gnu",
        target_arch = "x86_64"
    )) {
        println!("cargo::rustc-link-search=c/lib/linux_gnu_x86_64");
        println!("cargo::rustc-link-lib=static=sodium");
    } else {
        panic!("Can't setup sodium for this platform");
    }
}
