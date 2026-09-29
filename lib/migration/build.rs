//! Hashes the migration sources into `MIGRATION_FINGERPRINT`. The test fixtures
//! rebuild their shared databases when it changes, also when a migration is edited
//! in place.

use std::io;
use std::path::{Path, PathBuf};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=src");

    let mut files = vec![];
    collect(Path::new("src"), &mut files)?;
    files.sort();

    // FNV-1a: stable across Rust versions, unlike `DefaultHasher`.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for file in files {
        let path = file.to_string_lossy().replace('\\', "/");
        let content = std::fs::read(&file)?;
        for byte in path.bytes().chain([0]).chain(content).chain([0]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    println!("cargo:rustc-env=MIGRATION_FINGERPRINT={hash:016x}");
    Ok(())
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}
