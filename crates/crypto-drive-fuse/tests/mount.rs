// crypto-drive
// Copyright (C) 2026  Marcel Joachim Kloubert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Real mount tests. They need FUSE, so they are ignored by default; run
//! them with `cargo test -p crypto-drive-fuse -- --ignored`.

use crypto_drive_core::fs::{CryptoFs, VPath};
use crypto_drive_core::testutil::test_vault;
use crypto_drive_fuse::{MountRequest, StopReason, mount_and_wait, unmount_command};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::TempDir;

struct Mounted {
    _vault: TempDir,
    _mp: TempDir,
    mountpoint: PathBuf,
    /// The mounted drive, for changes that bypass the kernel (as a sync
    /// client changes the vault behind the kernel's back).
    fs: Arc<CryptoFs>,
    thread: JoinHandle<std::io::Result<StopReason>>,
}

impl Mounted {
    /// Mounts a fresh test vault; None when FUSE is not available here.
    fn new() -> Option<Mounted> {
        #[cfg(target_os = "linux")]
        if !std::path::Path::new("/dev/fuse").exists() {
            eprintln!("skipped: /dev/fuse does not exist");
            return None;
        }
        let (vault_dir, vault, _mk) = test_vault();
        let fs = Arc::new(CryptoFs::new(vault).unwrap());
        let drive = Arc::clone(&fs);
        let mp = TempDir::new().unwrap();
        let mountpoint = mp.path().to_path_buf();
        // Extra FUSE options, e.g. CRYPTO_DRIVE_TEST_MOUNT_OPTS=backend=fskit
        // (comma separated) to use macFUSE's FSKit backend on macOS 26.
        let extra_options = std::env::var("CRYPTO_DRIVE_TEST_MOUNT_OPTS")
            .map(|s| {
                s.split(',')
                    .filter(|o| !o.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let req = MountRequest {
            mountpoint: mountpoint.clone(),
            volume_name: "test".to_string(),
            extra_options,
        };
        let (ready_tx, ready_rx) = channel();
        let thread = std::thread::spawn(move || {
            mount_and_wait(fs, &req, || {
                let _ = ready_tx.send(());
            })
        });
        if let Err(e) = ready_rx.recv_timeout(Duration::from_secs(30)) {
            // The mount thread ended (or hangs): show its real error.
            if thread.is_finished() {
                match thread.join() {
                    Ok(result) => panic!("mount did not become ready: {result:?}"),
                    Err(_) => panic!("mount thread panicked"),
                }
            }
            panic!("mount did not become ready: {e}");
        }
        Some(Mounted {
            _vault: vault_dir,
            _mp: mp,
            mountpoint,
            fs: drive,
            thread,
        })
    }

    /// Unmounts from outside and checks the stop reason.
    fn unmount(self) {
        let status = unmount_command(&self.mountpoint, false).status().unwrap();
        assert!(status.success(), "unmount command failed");
        let reason = self.thread.join().unwrap().unwrap();
        assert_eq!(reason, StopReason::Unmounted);
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
#[ignore = "needs FUSE"]
fn write_read_rename_and_unmount() {
    let Some(m) = Mounted::new() else { return };
    let a = m.mountpoint.join("a.bin");
    let data = pattern(5 * 1024 * 1024);
    fs::write(&a, &data).unwrap();
    assert_eq!(fs::read(&a).unwrap(), data);
    let b = m.mountpoint.join("b.bin");
    fs::rename(&a, &b).unwrap();
    assert!(!a.exists());
    assert_eq!(fs::read(&b).unwrap(), data);
    m.unmount();
}

#[test]
#[ignore = "needs FUSE"]
fn directories_and_read_dir() {
    let Some(m) = Mounted::new() else { return };
    let deep = m.mountpoint.join("a/b/c");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("f"), b"x").unwrap();
    let names: Vec<String> = fs::read_dir(m.mountpoint.join("a/b"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["c".to_string()]);
    fs::remove_dir_all(m.mountpoint.join("a")).unwrap();
    assert_eq!(fs::read_dir(&m.mountpoint).unwrap().count(), 0);
    m.unmount();
}

#[test]
#[ignore = "needs FUSE"]
fn set_len_and_append() {
    let Some(m) = Mounted::new() else { return };
    let p = m.mountpoint.join("f");
    fs::write(&p, b"hello").unwrap();
    let f = OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(100_000).unwrap();
    drop(f);
    let grown = fs::read(&p).unwrap();
    assert_eq!(grown.len(), 100_000);
    assert_eq!(&grown[..5], b"hello");
    assert!(grown[5..].iter().all(|b| *b == 0));
    let f = OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(3).unwrap();
    drop(f);
    assert_eq!(fs::read(&p).unwrap(), b"hel");
    let mut f = OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(b"lo").unwrap();
    drop(f);
    assert_eq!(fs::read(&p).unwrap(), b"hello");
    m.unmount();
}

#[test]
#[ignore = "needs FUSE"]
fn page_cache_is_kept_but_never_stale() {
    let Some(m) = Mounted::new() else { return };
    let p = m.mountpoint.join("cached.bin");
    let first = pattern(3 * 65536 + 17);
    fs::write(&p, &first).unwrap();
    // The second open may use the kernel cache; it must still be right.
    assert_eq!(fs::read(&p).unwrap(), first);
    assert_eq!(fs::read(&p).unwrap(), first);
    // Change the content behind the kernel's back, same size.
    std::thread::sleep(Duration::from_millis(50));
    let changed: Vec<u8> = first.iter().map(|b| b ^ 0xff).collect();
    let path = crypto_drive_core::fs::VPath::parse("/cached.bin").unwrap();
    let fh = m.fs.open(&path, true, false).unwrap();
    m.fs.write(fh, 0, &changed).unwrap();
    m.fs.release(fh).unwrap();
    // Wait for the attribute TTL (1 s), then the next open must see it.
    std::thread::sleep(Duration::from_millis(1500));
    let got = fs::read(&p).unwrap();
    // Unmount first, so a failure does not leave the drive mounted.
    m.unmount();
    assert!(
        got == changed,
        "read {} bytes: {}",
        got.len(),
        if got == first {
            "the OLD content (stale kernel cache)"
        } else {
            "neither the old nor the new content"
        }
    );
}

#[test]
#[ignore = "needs FUSE"]
fn dropping_the_cache_keeps_unwritten_data_of_open_files() {
    use std::os::unix::fs::PermissionsExt;
    let Some(m) = Mounted::new() else { return };
    let p = m.mountpoint.join("open.bin");
    let old = pattern(2 * 65536 + 5);
    fs::write(&p, &old).unwrap();
    assert_eq!(fs::read(&p).unwrap(), old);
    // One program writes and keeps the file open (data may still be in
    // the kernel's buffer cache)...
    let new: Vec<u8> = old.iter().map(|b| b.wrapping_add(1)).collect();
    let mut writer = OpenOptions::new().write(true).open(&p).unwrap();
    writer.write_all(&new).unwrap();
    // ...a chmod changes the real file, so the next open drops the cache...
    std::thread::sleep(Duration::from_millis(50));
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    // ...and another program reads it: the written data must not be lost.
    let seen = fs::read(&p).unwrap();
    drop(writer);
    let after_close = fs::read(&p).unwrap();
    m.unmount();
    let what = |got: &[u8]| {
        if got == new.as_slice() {
            "the new content"
        } else if got == old.as_slice() {
            "the OLD content (written data lost)"
        } else {
            "a mix or other content"
        }
    };
    assert!(
        seen == new && after_close == new,
        "while open: {}; after close: {}",
        what(&seen),
        what(&after_close)
    );
}

/// Runs a command and asserts that it succeeds.
fn run_ok(cmd: &mut std::process::Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A time set on the open file (futimens before close, as `cp -p` and
/// macOS copyfile do) must survive the close. The mtime is read from the
/// drive behind the kernel, so a cached attribute cannot hide a change.
#[test]
#[ignore = "needs FUSE"]
fn mtime_set_before_close_is_kept() {
    let Some(m) = Mounted::new() else { return };
    let t = std::time::UNIX_EPOCH + Duration::from_secs(946_684_800);
    let data = pattern(300_000);
    let mut f = fs::File::create(m.mountpoint.join("fd.bin")).unwrap();
    f.write_all(&data).unwrap();
    f.set_modified(t).unwrap();
    drop(f);

    let src_dir = TempDir::new().unwrap();
    let src = src_dir.path().join("src.bin");
    fs::write(&src, &data).unwrap();
    fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_modified(t)
        .unwrap();
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut names = vec!["fd.bin", "cp.bin"];
    run_ok(
        std::process::Command::new("cp")
            .arg("-p")
            .arg(&src)
            .arg(m.mountpoint.join("cp.bin")),
    );
    #[cfg(target_os = "macos")]
    {
        run_ok(
            std::process::Command::new("ditto")
                .arg(&src)
                .arg(m.mountpoint.join("ditto.bin")),
        );
        names.push("ditto.bin");
    }
    for name in names {
        let path = VPath::parse(&format!("/{name}")).unwrap();
        let attr = m.fs.getattr(&path).unwrap();
        assert_eq!((attr.mtime, attr.size), (t, data.len() as u64), "{name}");
        assert_eq!(fs::read(m.mountpoint.join(name)).unwrap(), data, "{name}");
    }
    m.unmount();
}

/// Copy tools must not fail on a source file with extended attributes
/// (spec 5.6). On macOS the source gets a quarantine attribute, which `cp`
/// copies even with `-X`.
#[test]
#[ignore = "needs FUSE"]
fn copy_tools_ignore_extended_attributes() {
    let Some(m) = Mounted::new() else { return };
    let src_dir = TempDir::new().unwrap();
    let src = src_dir.path().join("src.bin");
    let data = pattern(300_000);
    fs::write(&src, &data).unwrap();
    #[cfg(target_os = "macos")]
    run_ok(std::process::Command::new("xattr").args([
        "-w",
        "com.apple.quarantine",
        "0081;00000000;crypto-drive-test;",
        src.to_str().unwrap(),
    ]));
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut targets = vec![m.mountpoint.join("cp.bin")];
    run_ok(std::process::Command::new("cp").arg(&src).arg(&targets[0]));
    #[cfg(target_os = "macos")]
    {
        let ditto = m.mountpoint.join("ditto.bin");
        run_ok(std::process::Command::new("ditto").arg(&src).arg(&ditto));
        targets.push(ditto);
    }
    for t in &targets {
        assert_eq!(fs::read(t).unwrap(), data, "{}", t.display());
    }
    m.unmount();
}

/// Sets an extended attribute (no flags) or panics.
fn set_xattr(path: &std::path::Path, name: &str, value: &[u8]) {
    rustix::fs::setxattr(path, name, value, rustix::fs::XattrFlags::empty())
        .unwrap_or_else(|e| panic!("setxattr {name}: {e}"));
}

/// Reads an extended attribute; None if it does not exist.
fn get_xattr(path: &std::path::Path, name: &str) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    let missing = rustix::io::Errno::NOATTR;
    #[cfg(not(target_os = "macos"))]
    let missing = rustix::io::Errno::NODATA;
    let mut buf = vec![0u8; 64 * 1024];
    match rustix::fs::getxattr(path, name, &mut buf[..]) {
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(e) if e == missing => None,
        Err(e) => panic!("getxattr {name}: {e}"),
    }
}

/// Finder writes markers like `com.apple.finder.copy.source` and reads them
/// back during a copy, so a set value must be readable while mounted.
#[test]
#[ignore = "needs FUSE"]
fn extended_attributes_read_back_while_mounted() {
    let Some(m) = Mounted::new() else { return };
    let name = if cfg!(target_os = "macos") {
        "com.apple.finder.copy.source"
    } else {
        "user.test"
    };
    let dir = m.mountpoint.join("d");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    fs::write(&file, b"x").unwrap();
    for p in [&dir, &file] {
        assert_eq!(get_xattr(p, name), None);
        set_xattr(p, name, b"marker");
        assert_eq!(get_xattr(p, name).as_deref(), Some(&b"marker"[..]));
    }
    let moved = m.mountpoint.join("moved");
    fs::rename(&dir, &moved).unwrap();
    assert_eq!(
        get_xattr(&moved.join("f"), name).as_deref(),
        Some(&b"marker"[..])
    );
    m.unmount();
}

/// Finder aborts a folder copy (error -8062) when it cannot write the
/// `.DS_Store` of the source, so the mount must accept such files.
#[test]
#[ignore = "needs FUSE"]
fn ds_store_files_can_be_written() {
    let Some(m) = Mounted::new() else { return };
    let dir = m.mountpoint.join("d");
    fs::create_dir(&dir).unwrap();
    let ds = dir.join(".DS_Store");
    fs::write(&ds, b"view settings").unwrap();
    assert_eq!(fs::read(&ds).unwrap(), b"view settings");
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![".DS_Store".to_string()]);
    m.unmount();
}
