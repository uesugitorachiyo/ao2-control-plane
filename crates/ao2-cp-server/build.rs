fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=AO2_CP_BUILD_TARGET={target}");
    println!("cargo:rustc-env=AO2_CP_BUILD_PROFILE={profile}");
    println!("cargo:rerun-if-changed=build.rs");
}
