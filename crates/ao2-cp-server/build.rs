use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let workspace = manifest_dir.join("../..");
    let cargo_lock = workspace.join("Cargo.lock");

    println!("cargo:rerun-if-env-changed=AO2_CP_BUILD_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed={}", cargo_lock.display());
    println!("cargo:rerun-if-changed=build.rs");
    emit_tracked_file_reruns(&workspace);

    let git_commit = env::var("AO2_CP_BUILD_GIT_COMMIT")
        .ok()
        .or_else(|| env::var("GITHUB_SHA").ok())
        .or_else(|| git_head_from(&workspace))
        .filter(|value| is_sha1(value))
        .unwrap_or_else(|| "unknown".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let lock = fs::read(&cargo_lock).expect("read Cargo.lock");
    let lock_sha256 = format!("{:x}", Sha256::digest(&lock));
    let source_modified = git_source_modified(&workspace);
    let target = target_label();

    println!("cargo:rustc-env=AO2_CP_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=AO2_CP_BUILD_TARGET={target}");
    println!("cargo:rustc-env=AO2_CP_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=AO2_CP_CARGO_LOCK_SHA256={lock_sha256}");
    println!("cargo:rustc-env=AO2_CP_SOURCE_MODIFIED={source_modified}");
}

fn emit_tracked_file_reruns(workspace: &PathBuf) {
    let Ok(output) = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(workspace)
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(files) = String::from_utf8(output.stdout) else {
        return;
    };
    for path in files.split('\0').filter(|path| !path.is_empty()) {
        println!("cargo:rerun-if-changed={}", workspace.join(path).display());
    }
}

fn git_source_modified(workspace: &PathBuf) -> bool {
    Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=no"])
        .current_dir(workspace)
        .output()
        .map(|output| !output.status.success() || !output.stdout.is_empty())
        .unwrap_or(true)
}

fn target_label() -> String {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    format!("{os}-{arch}")
}

fn git_head_from(workspace: &PathBuf) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|value| value.trim().to_ascii_lowercase())
}

fn is_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
