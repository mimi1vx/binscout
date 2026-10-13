//! Shared M6 e2e helpers: temp dirs, synthetic ELF fixture, binary paths.
//!
//! Each integration test target compiles this module separately and uses a
//! different subset, so unused helpers are expected.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Unique temp dir for one test.
pub fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "binscout-m6-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

pub fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Path of the `binscout` CLI under test.
pub fn binscout_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_binscout"))
}

/// Path of the `binscout-mcp` server: sibling of the CLI binary, so the
/// dashed target name never has to round-trip through an env var.
pub fn mcp_bin() -> PathBuf {
    let cli = binscout_bin();
    cli.parent()
        .expect("cli has a parent dir")
        .join(format!("binscout-mcp{}", std::env::consts::EXE_SUFFIX))
}

/// Minimal 64-bit LE ELF: one `PT_LOAD` (`nop; nop; ret`) at `0x400000`.
pub fn minimal_elf() -> Vec<u8> {
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], off: usize, x: u64) {
        v[off..off + 8].copy_from_slice(&x.to_le_bytes());
    }
    let mut f = vec![0u8; 0x78];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x400000);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, 3);
    put64(&mut f, p + 40, 3);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

/// Write `bytes` to `dir/name`; returns the binary path.
pub fn write_bin(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let bin = dir.join(name);
    std::fs::write(&bin, bytes).expect("write fixture binary");
    bin
}

/// Temp DB path that cannot collide with a fixture sidecar.
pub fn temp_db(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.redb"))
}
