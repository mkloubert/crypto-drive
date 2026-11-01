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

//! Directory operations and attributes: getattr, readdir, mkdir, rmdir,
//! unlink, set_times, set_mode, statfs.

use super::dirstate::{DIR_TMP_FILE, DirState, EntryRef, display_key};
use super::listing::Layout;
use super::path::VPath;
use super::{Attr, CryptoFs, DirEntry, FileKind, StatFs};
use crate::backing::{DirHandle, Kind, Stat};
use crate::content::plaintext_size;
use crate::error::{Error, Result};
use crate::keys::{DirId, random_entry_id};
use crate::names::BackingName;
use crate::vault::{CONTENT_FILE, DIR_FILE, NAME_FILE};
use std::sync::Arc;
use std::time::SystemTime;

/// Length of a directory id file.
const DIR_ID_FILE_LEN: u64 = 16;

/// Ignores "already gone".
pub(crate) fn ok_if_missing(r: Result<()>) -> Result<()> {
    match r {
        Err(Error::NotFound) => Ok(()),
        other => other,
    }
}

/// Mode bits that are passed through (permissions, setuid, setgid, sticky).
pub(crate) const MODE_MASK: u32 = 0o7777;
const OWNER_RWX: u32 = 0o700;
pub(crate) const CONTROL_FILE_MODE: u32 = 0o600;
const MAX_NAME_LEN: u32 = 255;

pub(super) fn attr(st: &Stat, kind: FileKind, size: u64) -> Attr {
    Attr {
        kind,
        size,
        mode: st.mode & MODE_MASK,
        uid: st.uid,
        gid: st.gid,
        atime: st.atime,
        mtime: st.mtime,
        ctime: st.ctime,
        nlink: match kind {
            FileKind::File => 1,
            FileKind::Directory => 2,
        },
    }
}

pub(crate) fn dir_attr(st: &Stat) -> Attr {
    attr(st, FileKind::Directory, st.size)
}

/// Attributes of a real content file; the size is the clear size.
pub(crate) fn file_attr(st: &Stat, what: &str) -> Result<Attr> {
    let invalid = || Error::InvalidFormat {
        what: what.to_owned(),
    };
    if st.kind != Kind::File {
        return Err(invalid());
    }
    let size = plaintext_size(st.size).map_err(|_| invalid())?;
    Ok(attr(st, FileKind::File, size))
}

/// Attributes of the directory `entry` in `parent`. The directory is not
/// opened, so a directory with mode 000 still has attributes. Files go
/// through `CryptoFs::file_entry_attr`.
pub(crate) fn dir_entry_attr(parent: &DirState, entry: &EntryRef) -> Result<Attr> {
    Ok(dir_attr(&parent.handle.stat(&entry.real)?))
}

fn real_name(backing: &BackingName) -> &str {
    match backing {
        BackingName::Short(s) => s,
        BackingName::Long { entry, .. } => entry,
    }
}

/// Writes `.cd-name` (long names) and then `.cd-dir` with `dir_id` into a
/// new directory. `.cd-dir` comes last, so a crash leaves an incomplete
/// directory.
fn init_new_dir(parent: &DirHandle, backing: &BackingName, dir_id: &DirId) -> Result<()> {
    let dir = parent.open_dir(real_name(backing))?;
    if let BackingName::Long { full, .. } = backing {
        dir.write_atomic(NAME_FILE, full.as_bytes(), CONTROL_FILE_MODE)?;
    }
    dir.write_atomic(DIR_FILE, dir_id, CONTROL_FILE_MODE)
}

/// Removes the three parts of a long file entry.
fn remove_long_file(parent: &DirHandle, entry: &str) -> Result<()> {
    let dir = parent.open_dir(entry)?;
    dir.unlink(CONTENT_FILE)?;
    ok_if_missing(dir.unlink(NAME_FILE))?;
    parent.rmdir(entry)
}

/// Removes a file entry (short, or long with its three parts).
pub(crate) fn remove_file_entry(parent: &DirHandle, entry: &EntryRef) -> Result<()> {
    match entry.layout {
        Layout::LongFile => remove_long_file(parent, &entry.real),
        _ => parent.unlink(&entry.real),
    }
}

/// Removes an empty directory entry. Only the control files of the directory
/// may be present; anything else gives `NotEmpty` and nothing is deleted.
pub(super) fn remove_empty_dir(parent: &DirHandle, entry: &EntryRef) -> Result<()> {
    let dir = parent.open_dir(&entry.real)?;
    let mut names = dir.list()?;
    names.sort();
    let removable = |n: &str| {
        n == DIR_FILE
            || n == DIR_TMP_FILE
            // A short directory may hold a stray `.cd-name` from an
            // interrupted rename to a long name (HS 9.4); it is ignored.
            || n == NAME_FILE
            || (n.starts_with(DIR_FILE)
                && matches!(dir.stat(n), Ok(st)
                    if st.kind == Kind::File && st.size == DIR_ID_FILE_LEN))
    };
    if !names.iter().all(|n| removable(n)) {
        return Err(Error::NotEmpty);
    }
    // `.cd-dir` goes last, so an interrupted rmdir leaves an incomplete
    // directory and not a directory without its name file.
    let order = |n: &String| match n.as_str() {
        DIR_FILE => 2,
        NAME_FILE => 1,
        _ => 0,
    };
    names.sort_by_key(order);
    names
        .iter()
        .try_for_each(|n| ok_if_missing(dir.unlink(n)))?;
    parent.rmdir(&entry.real)
}

/// Makes the new directory `backing` with `dir_id` in `parent` and returns
/// its attributes. An incomplete directory is removed again (best effort).
fn make_dir(parent: &DirHandle, backing: &BackingName, dir_id: &DirId, mode: u32) -> Result<Attr> {
    let real = real_name(backing);
    let mode = mode & MODE_MASK;
    // The owner needs write access to add the control files.
    parent.mkdir(real, mode | OWNER_RWX)?;
    if let Err(e) = init_new_dir(parent, backing, dir_id) {
        // Best effort: the directory is incomplete, so it may go.
        if let Ok(dir) = parent.open_dir(real) {
            let _ = dir.unlink(NAME_FILE);
        }
        let _ = parent.rmdir(real);
        return Err(e);
    }
    let mut st = parent.stat(real)?;
    let missing = OWNER_RWX & !mode;
    if missing != 0 {
        // Keep what the umask removed, and remove what the caller did not ask for.
        let final_mode = st.mode & MODE_MASK & !missing;
        parent.set_mode(real, final_mode)?;
        st = parent.stat(real)?;
    }
    Ok(dir_attr(&st))
}

impl CryptoFs {
    pub fn getattr(&self, path: &VPath) -> Result<Attr> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Ok(dir_attr(&self.root.stat_self()?));
        };
        let parent = self.dir_state(&parent_path)?;
        let entry = self.find(&parent, name)?;
        if entry.layout.is_dir() {
            dir_entry_attr(&parent, &entry)
        } else {
            self.file_entry_attr(&parent, &entry)
        }
    }

    /// Entries sorted by name, without "." and "..".
    pub fn readdir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        let state = self.dir_state(path)?;
        self.with_listing(&state, |l| {
            l.entries
                .iter()
                .map(|(name, e)| DirEntry {
                    name: name.clone(),
                    kind: e.layout.kind(),
                })
                .collect()
        })
    }

    /// Syncs the real directory of `path`, so the creates, renames and
    /// removes in it are on the device (fsyncdir).
    pub fn fsyncdir(&self, path: &VPath) -> Result<()> {
        self.dir_state(path)?.handle.sync()
    }

    pub fn mkdir(&self, path: &VPath, mode: u32) -> Result<Attr> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Err(Error::AlreadyExists);
        };
        self.with_change(&[&parent_path], |dirs| {
            let parent = &dirs[0];
            self.ensure_free(parent, path, name)?;
            // The entry id of a directory is its directory id (HS 3.2).
            let dir_id = random_entry_id()?;
            let backing = self.new_entry_name(parent, &dir_id, name)?;
            let result = make_dir(&parent.handle, &backing, &dir_id, mode);
            if result.is_ok() {
                let entry = self.new_entry_ref(&backing, true, dir_id);
                self.index_insert(parent, display_key(name), entry)?;
            }
            self.end_change(parent, result.is_ok());
            result
        })
    }

    /// Resolves a non-root `path` to its parent state, parent path and entry.
    fn resolve(&self, path: &VPath) -> Result<Option<(Arc<DirState>, VPath, EntryRef)>> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Ok(None);
        };
        let parent = self.dir_state(&parent_path)?;
        let entry = self.find(&parent, name)?;
        Ok(Some((parent, parent_path, entry)))
    }

    /// Removes a file. Open handles of it keep working.
    pub fn unlink(&self, path: &VPath) -> Result<()> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Err(Error::InvalidArgument);
        };
        self.with_change(&[&parent_path], |dirs| {
            let parent = &dirs[0];
            let entry = self.find(parent, name)?;
            if entry.layout.is_dir() {
                return Err(Error::IsADirectory);
            }
            let result = remove_file_entry(&parent.handle, &entry);
            if result.is_ok() {
                self.index_remove(parent, &display_key(name));
            }
            self.end_change(parent, result.is_ok());
            result
        })
    }

    /// Removes an empty directory (see `remove_empty_dir`).
    pub fn rmdir(&self, path: &VPath) -> Result<()> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Err(Error::InvalidArgument);
        };
        let result = self.with_change(&[&parent_path], |dirs| {
            let parent = &dirs[0];
            let entry = self.find(parent, name)?;
            if !entry.layout.is_dir() {
                return Err(Error::NotADirectory);
            }
            let result = remove_empty_dir(&parent.handle, &entry);
            if result.is_ok() {
                self.index_remove(parent, &display_key(name));
            }
            self.end_change(parent, result.is_ok());
            result
        });
        // The removed directory and its cached subtree.
        self.invalidate(path);
        result
    }

    /// Sets times; `None` leaves that time unchanged. Long files act on
    /// `.cd-content`.
    pub fn set_times(
        &self,
        path: &VPath,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<()> {
        match self.resolve(path)? {
            None => self.root.set_times_self(atime, mtime),
            Some((parent, _, entry)) if entry.layout == Layout::LongFile => parent
                .handle
                .open_dir(&entry.real)?
                .set_times(CONTENT_FILE, atime, mtime),
            Some((parent, _, entry)) => parent.handle.set_times(&entry.real, atime, mtime),
        }
    }

    /// Sets the permission bits (`mode & 0o7777`). Long files act on
    /// `.cd-content`.
    pub fn set_mode(&self, path: &VPath, mode: u32) -> Result<()> {
        let mode = mode & MODE_MASK;
        match self.resolve(path)? {
            None => self.root.set_mode_self(mode),
            Some((parent, _, entry)) if entry.layout == Layout::LongFile => parent
                .handle
                .open_dir(&entry.real)?
                .set_mode(CONTENT_FILE, mode),
            Some((parent, _, entry)) => parent.handle.set_mode(&entry.real, mode),
        }
    }

    pub fn statfs(&self) -> Result<StatFs> {
        let s = self.root.statvfs()?;
        Ok(StatFs {
            blocks: s.f_blocks,
            bfree: s.f_bfree,
            bavail: s.f_bavail,
            files: s.f_files,
            ffree: s.f_ffree,
            bsize: u32::try_from(s.f_bsize).unwrap_or(u32::MAX),
            namelen: MAX_NAME_LEN,
            frsize: u32::try_from(s.f_frsize).unwrap_or(u32::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CryptoFs, VPath};
    use crate::Error;
    use crate::keys::MasterKey;
    use crate::names::LONG_PREFIX;
    use crate::testutil::{test_vault, test_vault_with};
    use crate::vault::{CONTROL_PREFIX, UnlockedVault};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, UNIX_EPOCH};

    struct Fx {
        _tmp: tempfile::TempDir,
        fs: CryptoFs,
        root: PathBuf,
    }

    fn fx_from((tmp, v, _mk): (tempfile::TempDir, UnlockedVault, MasterKey)) -> Fx {
        let root = v.root_path.clone();
        let fs = CryptoFs::new(v).unwrap();
        Fx {
            _tmp: tmp,
            fs,
            root,
        }
    }

    fn fx() -> Fx {
        fx_from(test_vault())
    }

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    fn write_file(fs: &CryptoFs, path: &str, data: &[u8]) {
        let (_, h) = fs.create(&p(path), 0o644).unwrap();
        fs.write(h, 0, data).unwrap();
        fs.release(h).unwrap();
    }

    /// Real entries of `dir` that are not the vault control files.
    fn real_entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with(CONTROL_PREFIX) || n.starts_with(LONG_PREFIX))
            .collect()
    }

    fn only_entry(dir: &Path) -> PathBuf {
        let v = real_entries(dir);
        assert_eq!(v.len(), 1, "entries: {v:?}");
        dir.join(&v[0])
    }

    #[test]
    fn unlink_removes_file() {
        let f = fx();
        write_file(&f.fs, "a", b"data");
        f.fs.unlink(&p("a")).unwrap();
        assert!(matches!(f.fs.getattr(&p("a")), Err(Error::NotFound)));
        assert!(real_entries(&f.root).is_empty());
        assert!(matches!(f.fs.unlink(&p("a")), Err(Error::NotFound)));
    }

    #[test]
    fn rmdir_non_empty_is_not_empty() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "d/x", b"1");
        assert!(matches!(f.fs.rmdir(&p("d")), Err(Error::NotEmpty)));
        assert!(f.fs.getattr(&p("d/x")).is_ok());
    }

    #[test]
    fn rmdir_empty_leaves_nothing() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.rmdir(&p("d")).unwrap();
        assert!(matches!(f.fs.getattr(&p("d")), Err(Error::NotFound)));
        assert!(real_entries(&f.root).is_empty());
    }

    #[test]
    fn rmdir_with_foreign_file_is_not_empty() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let real = only_entry(&f.root);
        std::fs::write(real.join(".DS_Store"), b"x").unwrap();
        assert!(matches!(f.fs.rmdir(&p("d")), Err(Error::NotEmpty)));
        assert!(real.join(".DS_Store").exists());
        assert!(real.join(".cd-dir").exists());
    }

    #[test]
    fn rmdir_removes_conflict_copy_of_dir_id() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let real = only_entry(&f.root);
        std::fs::copy(real.join(".cd-dir"), real.join(".cd-dir (conflict)")).unwrap();
        f.fs.rmdir(&p("d")).unwrap();
        assert!(real_entries(&f.root).is_empty());
    }

    #[test]
    fn unlink_directory_and_rmdir_file_fail() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "a", b"1");
        assert!(matches!(f.fs.unlink(&p("d")), Err(Error::IsADirectory)));
        assert!(matches!(f.fs.rmdir(&p("a")), Err(Error::NotADirectory)));
        assert!(matches!(
            f.fs.rmdir(&VPath::root()),
            Err(Error::InvalidArgument)
        ));
        assert!(matches!(
            f.fs.unlink(&VPath::root()),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn long_names_unlink_and_rmdir_leave_nothing() {
        let f = fx_from(test_vault_with(64));
        let name = "l".repeat(120);
        write_file(&f.fs, &name, b"data");
        f.fs.unlink(&p(&name)).unwrap();
        assert!(real_entries(&f.root).is_empty());
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        assert!(only_entry(&f.root).join(".cd-name").exists());
        f.fs.rmdir(&p(&name)).unwrap();
        assert!(real_entries(&f.root).is_empty());
        assert!(std::fs::read_dir(&f.root).unwrap().all(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            !n.starts_with(LONG_PREFIX)
        }));
    }

    #[test]
    fn set_mode_is_seen_in_getattr() {
        let f = fx();
        write_file(&f.fs, "a", b"1");
        f.fs.set_mode(&p("a"), 0o600).unwrap();
        assert_eq!(f.fs.getattr(&p("a")).unwrap().mode & 0o777, 0o600);
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.set_mode(&p("d"), 0o750).unwrap();
        assert_eq!(f.fs.getattr(&p("d")).unwrap().mode & 0o777, 0o750);
        f.fs.set_mode(&VPath::root(), 0o750).unwrap();
        assert_eq!(f.fs.getattr(&VPath::root()).unwrap().mode & 0o777, 0o750);
    }

    #[test]
    fn set_times_is_seen_in_getattr() {
        let f = fx();
        write_file(&f.fs, "a", b"1");
        let t = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        f.fs.set_times(&p("a"), None, Some(t)).unwrap();
        let st = f.fs.getattr(&p("a")).unwrap();
        assert_eq!(st.mtime, t);
        let t2 = UNIX_EPOCH + Duration::from_secs(1_100_000_000);
        f.fs.set_times(&p("a"), Some(t2), None).unwrap();
        let st = f.fs.getattr(&p("a")).unwrap();
        assert_eq!((st.atime, st.mtime), (t2, t));
    }

    #[test]
    fn long_name_attributes_act_on_the_content() {
        let f = fx_from(test_vault_with(64));
        let name = "l".repeat(120);
        write_file(&f.fs, &name, b"data");
        let t = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        f.fs.set_times(&p(&name), None, Some(t)).unwrap();
        f.fs.set_mode(&p(&name), 0o600).unwrap();
        let st = f.fs.getattr(&p(&name)).unwrap();
        assert_eq!(st.mtime, t);
        assert_eq!(st.mode & 0o777, 0o600);
    }

    #[test]
    fn unlink_keeps_open_handle_working() {
        let f = fx();
        write_file(&f.fs, "a", b"still here");
        let h = f.fs.open(&p("a"), false, false).unwrap();
        f.fs.unlink(&p("a")).unwrap();
        assert!(matches!(f.fs.getattr(&p("a")), Err(Error::NotFound)));
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"still here");
        f.fs.release(h).unwrap();
    }
}
