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

//! Directory-handle based access to the real (encrypted) directory.
//!
//! All syscalls on the encrypted directory go through this module. They are
//! relative to directory file descriptors, so `PATH_MAX` never applies.

use crate::{Error, Result};
use rustix::fs::Timespec;
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RawMode, Timestamps, UTIME_OMIT,
};
use rustix::io::Errno;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Kind of a directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Other,
}

/// Metadata of a directory entry (symbolic links are not followed).
#[derive(Clone, Debug)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub dev: u64,
    pub ino: u64,
}

#[cfg(test)]
thread_local! {
    /// Device and inode of each directory this thread synced.
    static SYNCED_DIRS: std::cell::RefCell<Vec<(u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Takes the list of directories this thread synced since the last call.
#[cfg(test)]
pub(crate) fn take_synced_dirs() -> Vec<(u64, u64)> {
    SYNCED_DIRS.with(|v| std::mem::take(&mut *v.borrow_mut()))
}

/// An open directory in the real (encrypted) tree.
pub struct DirHandle {
    fd: OwnedFd,
}

fn map_errno(e: Errno) -> Error {
    if e == Errno::NOENT {
        Error::NotFound
    } else if e == Errno::EXIST {
        Error::AlreadyExists
    } else if e == Errno::NOTEMPTY {
        Error::NotEmpty
    } else if e == Errno::NOTDIR {
        Error::NotADirectory
    } else if e == Errno::ISDIR {
        Error::IsADirectory
    } else {
        Error::Io(std::io::Error::from(e))
    }
}

/// Checks that `name` is a single, safe path component.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn to_system_time(secs: i64, nsecs: i64) -> SystemTime {
    let nanos = Duration::from_nanos(u64::try_from(nsecs).unwrap_or(0));
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs()) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs()) + nanos
    }
}

fn to_timespec(t: Option<SystemTime>) -> Timespec {
    match t {
        None => Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        Some(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Timespec {
                tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: d.subsec_nanos().into(),
            },
            Err(e) => {
                let d = e.duration();
                let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                if d.subsec_nanos() == 0 {
                    Timespec {
                        tv_sec: -secs,
                        tv_nsec: 0,
                    }
                } else {
                    Timespec {
                        tv_sec: -secs - 1,
                        tv_nsec: (1_000_000_000 - d.subsec_nanos()).into(),
                    }
                }
            }
        },
    }
}

// The raw stat field types differ between platforms, so plain casts are used.
#[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
fn convert_stat(st: &rustix::fs::Stat) -> Stat {
    let kind = match FileType::from_raw_mode(st.st_mode as RawMode) {
        FileType::RegularFile => Kind::File,
        FileType::Directory => Kind::Dir,
        _ => Kind::Other,
    };
    let time = |s, n| to_system_time(s as i64, n as i64);
    Stat {
        kind,
        size: st.st_size as u64,
        mode: st.st_mode as RawMode as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        atime: time(st.st_atime, st.st_atime_nsec),
        mtime: time(st.st_mtime, st.st_mtime_nsec),
        ctime: time(st.st_ctime, st.st_ctime_nsec),
        dev: st.st_dev as u64,
        ino: st.st_ino,
    }
}

fn mode_bits(mode: u32) -> Mode {
    Mode::from_bits_truncate(mode as RawMode)
}

/// Metadata of an open file.
pub fn stat_file(file: &File) -> Result<Stat> {
    let st = rustix::fs::fstat(file).map_err(map_errno)?;
    Ok(convert_stat(&st))
}

impl DirHandle {
    /// Opens `name` without following links and without blocking, and requires
    /// a regular file. A planted FIFO or device must never hang or be read.
    fn open_regular(&self, name: &str, flags: OFlags, mode: Mode) -> Result<File> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            mode,
        )
        .map_err(map_errno)?;
        let st = rustix::fs::fstat(&fd).map_err(map_errno)?;
        if FileType::from_raw_mode(st.st_mode as RawMode) != FileType::RegularFile {
            return Err(Error::InvalidFormat {
                what: name.to_owned(),
            });
        }
        let current = rustix::fs::fcntl_getfl(&fd).map_err(map_errno)?;
        rustix::fs::fcntl_setfl(&fd, current - OFlags::NONBLOCK).map_err(map_errno)?;
        Ok(File::from(fd))
    }

    /// Opens the vault root directory by path.
    pub fn open_root(path: &Path) -> Result<DirHandle> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_errno)?;
        Ok(DirHandle { fd })
    }

    /// Opens a sub directory (symbolic links are refused).
    pub fn open_dir(&self, name: &str) -> Result<DirHandle> {
        check_name(name)?;
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_errno)?;
        Ok(DirHandle { fd })
    }

    pub fn stat_self(&self) -> Result<Stat> {
        let st = rustix::fs::fstat(&self.fd).map_err(map_errno)?;
        Ok(convert_stat(&st))
    }

    pub fn stat(&self, name: &str) -> Result<Stat> {
        check_name(name)?;
        let st =
            rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        Ok(convert_stat(&st))
    }

    /// Lists entry names without "." and "..". Non-UTF-8 names are skipped.
    pub fn list(&self) -> Result<Vec<String>> {
        // A fresh descriptor keeps the read position of `self` untouched.
        let fd = rustix::fs::openat(
            &self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_errno)?;
        let dir = Dir::new(fd).map_err(map_errno)?;
        let mut names = Vec::new();
        for entry in dir {
            let entry = entry.map_err(map_errno)?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            match std::str::from_utf8(raw) {
                Ok(n) => names.push(n.to_owned()),
                Err(_) => log::warn!("skipping a directory entry with a non-UTF-8 name"),
            }
        }
        Ok(names)
    }

    pub fn open_file(&self, name: &str, write: bool) -> Result<File> {
        check_name(name)?;
        let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
        self.open_regular(name, access, Mode::empty())
    }

    /// Creates a new file; fails with `AlreadyExists` if it exists.
    pub fn create_file(&self, name: &str, mode: u32) -> Result<File> {
        check_name(name)?;
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::RDWR | OFlags::CLOEXEC,
            mode_bits(mode),
        )
        .map_err(map_errno)?;
        Ok(File::from(fd))
    }

    /// Reads a whole file; a file longer than `max` is `InvalidFormat`.
    pub fn read_small(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        let file = self.open_file(name, false)?;
        let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
        let mut data = Vec::new();
        file.take(limit).read_to_end(&mut data)?;
        if data.len() > max {
            return Err(Error::InvalidFormat {
                what: name.to_owned(),
            });
        }
        Ok(data)
    }

    /// Writes `data` to `<name>.tmp`, syncs, and renames it over `name`.
    pub fn write_atomic(&self, name: &str, data: &[u8], mode: u32) -> Result<()> {
        check_name(name)?;
        let tmp = format!("{name}.tmp");
        let result = self.write_atomic_inner(name, &tmp, data, mode);
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.fd, tmp.as_str(), AtFlags::empty());
        }
        result
    }

    fn write_atomic_inner(&self, name: &str, tmp: &str, data: &[u8], mode: u32) -> Result<()> {
        let mut file = self.open_regular(
            tmp,
            OFlags::CREATE | OFlags::TRUNC | OFlags::WRONLY,
            mode_bits(mode),
        )?;
        file.write_all(data)?;
        rustix::fs::fsync(&file).map_err(map_errno)?;
        drop(file);
        rustix::fs::renameat(&self.fd, tmp, &self.fd, name).map_err(map_errno)?;
        rustix::fs::fsync(&self.fd).map_err(map_errno)?;
        Ok(())
    }

    pub fn mkdir(&self, name: &str, mode: u32) -> Result<()> {
        check_name(name)?;
        rustix::fs::mkdirat(&self.fd, name, mode_bits(mode)).map_err(map_errno)
    }

    pub fn rmdir(&self, name: &str) -> Result<()> {
        check_name(name)?;
        match rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR) {
            Ok(()) => Ok(()),
            // Some systems report a non-empty directory as EEXIST.
            Err(e) if e == Errno::EXIST || e == Errno::NOTEMPTY => Err(Error::NotEmpty),
            Err(e) => Err(map_errno(e)),
        }
    }

    pub fn unlink(&self, name: &str) -> Result<()> {
        check_name(name)?;
        match rustix::fs::unlinkat(&self.fd, name, AtFlags::empty()) {
            Ok(()) => Ok(()),
            // Linux reports EISDIR, macOS reports EPERM for a directory.
            Err(e) if e == Errno::ISDIR || e == Errno::PERM => {
                if matches!(self.stat(name), Ok(st) if st.kind == Kind::Dir) {
                    Err(Error::IsADirectory)
                } else {
                    Err(map_errno(e))
                }
            }
            Err(e) => Err(map_errno(e)),
        }
    }

    pub fn rename(&self, from: &str, to_dir: &DirHandle, to: &str) -> Result<()> {
        check_name(from)?;
        check_name(to)?;
        rustix::fs::renameat(&self.fd, from, &to_dir.fd, to).map_err(map_errno)
    }

    /// Sets times; `None` leaves that time unchanged.
    pub fn set_times(
        &self,
        name: &str,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<()> {
        check_name(name)?;
        let times = Timestamps {
            last_access: to_timespec(atime),
            last_modification: to_timespec(mtime),
        };
        rustix::fs::utimensat(&self.fd, name, &times, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)
    }

    /// Sets times of this directory itself.
    pub fn set_times_self(
        &self,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<()> {
        let times = Timestamps {
            last_access: to_timespec(atime),
            last_modification: to_timespec(mtime),
        };
        rustix::fs::futimens(&self.fd, &times).map_err(map_errno)
    }

    /// Sets the mode of this directory itself.
    pub fn set_mode_self(&self, mode: u32) -> Result<()> {
        rustix::fs::fchmod(&self.fd, mode_bits(mode)).map_err(map_errno)
    }

    pub fn set_mode(&self, name: &str, mode: u32) -> Result<()> {
        // chmodat cannot refuse links on Linux, so check the type first. A
        // small window remains between the check and the chmod (TOCTOU).
        if self.stat(name)?.kind == Kind::Other {
            return Err(Error::NotPermitted);
        }
        rustix::fs::chmodat(&self.fd, name, mode_bits(mode), AtFlags::empty()).map_err(map_errno)
    }

    /// Syncs this directory, so its entry changes are on the device.
    pub fn sync(&self) -> Result<()> {
        rustix::fs::fsync(&self.fd).map_err(map_errno)?;
        #[cfg(test)]
        if let Ok(st) = self.stat_self() {
            SYNCED_DIRS.with(|v| v.borrow_mut().push((st.dev, st.ino)));
        }
        Ok(())
    }

    pub fn statvfs(&self) -> Result<rustix::fs::StatVfs> {
        rustix::fs::fstatvfs(&self.fd).map_err(map_errno)
    }

    /// Takes an exclusive lock without waiting; `AlreadyMounted` if it is held.
    pub fn lock_exclusive_nonblocking(file: &File) -> Result<()> {
        match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(()),
            Err(e) if e == Errno::WOULDBLOCK => Err(Error::AlreadyMounted),
            Err(e) => Err(map_errno(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::time::{Duration, UNIX_EPOCH};

    fn mkfifo(path: &std::path::Path) {
        nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    }

    fn root() -> (tempfile::TempDir, DirHandle) {
        let t = tempfile::tempdir().unwrap();
        let d = DirHandle::open_root(t.path()).unwrap();
        (t, d)
    }

    #[test]
    fn mkdir_open_list() {
        let (_t, d) = root();
        d.mkdir("sub", 0o700).unwrap();
        d.create_file("f", 0o600).unwrap();
        let sub = d.open_dir("sub").unwrap();
        assert!(sub.list().unwrap().is_empty());
        let mut l = d.list().unwrap();
        l.sort();
        assert_eq!(l, vec!["f", "sub"]);
        assert_eq!(d.list().unwrap().len(), 2);
        assert_eq!(d.stat("sub").unwrap().kind, Kind::Dir);
        assert_eq!(d.stat("f").unwrap().kind, Kind::File);
        assert_eq!(d.stat_self().unwrap().kind, Kind::Dir);
    }

    #[test]
    fn create_twice_fails() {
        let (_t, d) = root();
        d.create_file("f", 0o600).unwrap();
        assert!(matches!(
            d.create_file("f", 0o600),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn atomic_write_round_trip() {
        let (_t, d) = root();
        d.write_atomic("x", b"hello", 0o600).unwrap();
        d.write_atomic("x", b"world!", 0o600).unwrap();
        assert_eq!(d.read_small("x", 100).unwrap(), b"world!");
        assert_eq!(d.list().unwrap(), vec!["x"]);
        assert!(matches!(
            d.read_small("x", 3),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn rename_across_handles() {
        let (_t, d) = root();
        d.mkdir("a", 0o700).unwrap();
        d.mkdir("b", 0o700).unwrap();
        let a = d.open_dir("a").unwrap();
        let b = d.open_dir("b").unwrap();
        a.create_file("f", 0o600).unwrap();
        a.rename("f", &b, "g").unwrap();
        assert!(matches!(a.stat("f"), Err(Error::NotFound)));
        assert_eq!(b.stat("g").unwrap().kind, Kind::File);
    }

    #[test]
    fn rmdir_non_empty() {
        let (_t, d) = root();
        d.mkdir("a", 0o700).unwrap();
        d.open_dir("a").unwrap().create_file("f", 0o600).unwrap();
        assert!(matches!(d.rmdir("a"), Err(Error::NotEmpty)));
        d.open_dir("a").unwrap().unlink("f").unwrap();
        d.rmdir("a").unwrap();
    }

    #[test]
    fn stat_missing() {
        let (_t, d) = root();
        assert!(matches!(d.stat("nope"), Err(Error::NotFound)));
    }

    #[test]
    fn set_mode_visible() {
        let (_t, d) = root();
        d.create_file("f", 0o600).unwrap();
        d.set_mode("f", 0o640).unwrap();
        assert_eq!(d.stat("f").unwrap().mode & 0o7777, 0o640);
    }

    #[test]
    fn set_mode_can_restore_after_zero() {
        let (_t, d) = root();
        d.create_file("f", 0o600).unwrap();
        d.set_mode("f", 0o000).unwrap();
        d.set_mode("f", 0o600).unwrap();
        assert_eq!(d.stat("f").unwrap().mode & 0o7777, 0o600);
        d.mkdir("d", 0o700).unwrap();
        d.set_mode("d", 0o000).unwrap();
        d.set_mode("d", 0o700).unwrap();
        assert_eq!(d.stat("d").unwrap().mode & 0o7777, 0o700);
    }

    #[test]
    fn fifo_is_rejected_without_blocking() {
        let (t, d) = root();
        mkfifo(&t.path().join("p"));
        assert!(matches!(
            d.open_file("p", false),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(matches!(
            d.read_small("p", 10),
            Err(Error::InvalidFormat { .. })
        ));
        // A FIFO planted at the temporary name must not hang write_atomic.
        mkfifo(&t.path().join("q.tmp"));
        assert!(matches!(
            d.write_atomic("q", b"x", 0o600),
            Err(Error::InvalidFormat { .. }) | Err(Error::Io(_))
        ));
    }

    #[test]
    fn unlink_dir_is_is_a_directory() {
        let (_t, d) = root();
        d.mkdir("d", 0o700).unwrap();
        assert!(matches!(d.unlink("d"), Err(Error::IsADirectory)));
    }

    #[test]
    fn set_times_mtime() {
        let (_t, d) = root();
        d.create_file("f", 0o600).unwrap();
        let m = UNIX_EPOCH + Duration::from_secs(1_000_000);
        d.set_times("f", None, Some(m)).unwrap();
        assert_eq!(d.stat("f").unwrap().mtime, m);
    }

    #[test]
    fn bad_names_rejected() {
        let (_t, d) = root();
        for n in ["", ".", "..", "a/b", "a\0b"] {
            assert!(matches!(d.stat(n), Err(Error::InvalidArgument)), "{n:?}");
        }
    }

    #[test]
    fn second_lock_fails() {
        let (t, d) = root();
        d.create_file("lock", 0o600).unwrap();
        let a = d.open_file("lock", true).unwrap();
        let b = std::fs::File::open(t.path().join("lock")).unwrap();
        DirHandle::lock_exclusive_nonblocking(&a).unwrap();
        assert!(matches!(
            DirHandle::lock_exclusive_nonblocking(&b),
            Err(Error::AlreadyMounted)
        ));
        let _ = d.statvfs().unwrap();
    }
}
