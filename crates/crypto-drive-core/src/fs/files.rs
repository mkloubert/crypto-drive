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

//! File operations: create, open, read, write, flush, release, truncate.
//!
//! All handles of one real file share one `OpenFile` (spec 5.4). The map
//! locks are never held during file I/O, and no directory lookup is done
//! while a file lock is held.

use super::dirs::{CONTROL_FILE_MODE, MODE_MASK, attr, file_attr};
use super::dirstate::{DirState, EntryRef, display_key, is_permission_denied};
use super::listing::Layout;
use super::{Attr, CryptoFs, FileHandleId, FileKind, FileStamp, RealFileId, VPath};
use crate::backing::{DirHandle, Kind, stat_file};
use crate::content::{CHUNK_OVERHEAD, PADDED_HEADER_LEN};
use crate::error::{Error, Result};
use crate::file::{OpenFile, read_file_meta};
use crate::keys::{EntryId, random_entry_id};
use crate::names::BackingName;
use crate::vault::{CONTENT_FILE, NAME_FILE};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

/// Mode of the `.cd-cdl` directory of a long file name.
pub(super) const LONG_ENTRY_MODE: u32 = 0o700;

type Shared = Arc<Mutex<OpenFile>>;

/// One open file handle.
pub(crate) struct Handle {
    file: Shared,
    write: bool,
    append: bool,
}

/// Where the content of a file entry lives.
struct Location {
    dir: Arc<DirHandle>,
    name: String,
    /// The real relative name, for error messages.
    what: String,
    /// The entry id from the name; the header file id must match (HS 3.2).
    entry_id: EntryId,
}

impl Location {
    /// Checks that the file id of the header is the entry id of the name.
    /// Otherwise the content belongs to another file.
    fn check_binding(&self, file_id: &EntryId) -> Result<()> {
        if *file_id == self.entry_id {
            Ok(())
        } else {
            Err(Error::AuthFailed {
                what: self.what.clone(),
            })
        }
    }
}

fn lock(file: &Shared) -> MutexGuard<'_, OpenFile> {
    file.lock().expect("open file lock poisoned")
}

/// Removes a `.cd-cdl` entry this call created (best effort).
fn remove_long_entry(parent: &DirHandle, entry: &str) {
    if let Ok(dir) = parent.open_dir(entry) {
        let _ = dir.unlink(CONTENT_FILE);
        let _ = dir.unlink(NAME_FILE);
    }
    let _ = parent.rmdir(entry);
}

impl CryptoFs {
    fn locate(&self, parent: &DirState, entry: &EntryRef) -> Result<Location> {
        match entry.layout {
            Layout::ShortFile => Ok(Location {
                dir: Arc::clone(&parent.handle),
                name: entry.real.clone(),
                what: entry.real.clone(),
                entry_id: entry.entry_id,
            }),
            Layout::LongFile => Ok(Location {
                dir: Arc::new(parent.handle.open_dir(&entry.real)?),
                name: CONTENT_FILE.to_owned(),
                what: format!("{}/{CONTENT_FILE}", entry.real),
                entry_id: entry.entry_id,
            }),
            Layout::ShortDir | Layout::LongDir => Err(Error::IsADirectory),
        }
    }

    fn locate_path(&self, path: &VPath) -> Result<Location> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Err(Error::IsADirectory);
        };
        let parent = self.dir_state(&parent_path)?;
        let entry = self.find(&parent, name)?;
        self.locate(&parent, &entry)
    }

    /// The live shared state of a real file, if it is open.
    fn live(&self, key: RealFileId) -> Option<Shared> {
        self.open_files
            .lock()
            .expect("open files lock poisoned")
            .get(&key)
            .and_then(Weak::upgrade)
    }

    /// Attributes of a file entry. An open file reports its size in memory.
    pub(super) fn file_entry_attr(&self, parent: &DirState, entry: &EntryRef) -> Result<Attr> {
        let loc = self.locate(parent, entry)?;
        let st = loc.dir.stat(&loc.name)?;
        if st.kind == Kind::File
            && let Some(shared) = self.live((st.dev, st.ino))
        {
            let (len, file_id) = {
                let open = lock(&shared);
                (open.len(), open.file_id())
            };
            // Like the header check below; an unpadded vault reads no header.
            if self.padded {
                loc.check_binding(&file_id)?;
            }
            return Ok(attr(&st, FileKind::File, len));
        }
        if !self.padded {
            return file_attr(&st, &loc.what);
        }
        // A padded file: the clear size is in the size block.
        if st.kind != Kind::File {
            return Err(Error::InvalidFormat { what: loc.what });
        }
        let file = match loc.dir.open_file(&loc.name, false) {
            Ok(file) => file,
            // Not readable: the size block is out of reach, so report an
            // upper bound (header and one chunk overhead off the real size).
            Err(e) if is_permission_denied(&e) => {
                let bound = st.size.saturating_sub(PADDED_HEADER_LEN + CHUNK_OVERHEAD);
                return Ok(attr(&st, FileKind::File, bound));
            }
            Err(e) => return Err(e),
        };
        let (header, len) = read_file_meta(&file, &self.keys, true).map_err(|e| match e {
            Error::InvalidFormat { .. } => Error::InvalidFormat {
                what: loc.what.clone(),
            },
            e => e,
        })?;
        loc.check_binding(&header.file_id)?;
        Ok(attr(&st, FileKind::File, len))
    }

    /// Uses `shared`. If it can only read and `file` can write the same real
    /// file, `file` takes its place.
    fn adopt(&self, shared: Shared, file: std::fs::File, writable: bool) -> Result<Shared> {
        if writable {
            let mut open = lock(&shared);
            if !open.is_writable() {
                open.flush()?;
                open.set_writable_file(file);
            }
        }
        Ok(shared)
    }

    /// Makes `open` the shared state of the real file `key`, unless another
    /// call did so first; then that state is used.
    fn register(&self, key: RealFileId, open: OpenFile) -> Result<Shared> {
        let mut map = self.open_files.lock().expect("open files lock poisoned");
        if let Some(existing) = map.get(&key).and_then(Weak::upgrade) {
            drop(map);
            let writable = open.is_writable();
            return self.adopt(existing, open.into_file(), writable);
        }
        let shared = Arc::new(Mutex::new(open));
        map.insert(key, Arc::downgrade(&shared));
        Ok(shared)
    }

    /// The shared state of the file at `loc`. The real file is opened for
    /// writing if allowed, else for reading; `write` requires writing.
    fn open_shared(&self, loc: &Location, write: bool) -> Result<Shared> {
        let (file, writable) = match loc.dir.open_file(&loc.name, true) {
            Ok(file) => (file, true),
            Err(e) if is_permission_denied(&e) => {
                if write {
                    return Err(Error::NotPermitted);
                }
                (loc.dir.open_file(&loc.name, false)?, false)
            }
            Err(e) => return Err(e),
        };
        let st = stat_file(&file)?;
        let key = (st.dev, st.ino);
        if let Some(shared) = self.live(key) {
            let file_id = lock(&shared).file_id();
            loc.check_binding(&file_id)?;
            return self.adopt(shared, file, writable);
        }
        let open = if writable {
            OpenFile::open(file, &self.keys, self.padded)?
        } else {
            OpenFile::open_read_only(file, &self.keys, self.padded)?
        };
        loc.check_binding(&open.file_id())?;
        self.register(key, open)
    }

    fn add_handle(&self, file: Shared, write: bool, append: bool) -> FileHandleId {
        let id = FileHandleId(self.next_handle.fetch_add(1, Ordering::Relaxed));
        let handle = Handle {
            file,
            write,
            append,
        };
        self.handles
            .lock()
            .expect("handles lock poisoned")
            .insert(id, handle);
        id
    }

    /// The shared state and the flags (write, append) of a handle.
    fn handle(&self, fh: FileHandleId) -> Result<(Shared, bool, bool)> {
        let handles = self.handles.lock().expect("handles lock poisoned");
        let h = handles.get(&fh).ok_or(Error::InvalidArgument)?;
        Ok((Arc::clone(&h.file), h.write, h.append))
    }

    /// Forgets real files that are no longer open.
    fn prune_open_files(&self) {
        self.open_files
            .lock()
            .expect("open files lock poisoned")
            .retain(|_, w| w.strong_count() > 0);
    }

    /// Creates the new file and returns its attributes and a handle that
    /// can write.
    pub fn create(&self, path: &VPath, mode: u32) -> Result<(Attr, FileHandleId)> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Err(Error::AlreadyExists);
        };
        let (attr, shared) = self.with_change(&[&parent_path], |dirs| {
            let parent = &dirs[0];
            self.ensure_free(parent, path, name)?;
            let mode = mode & MODE_MASK;
            // The file id in the header is the entry id of the name (HS 3.2).
            let file_id = random_entry_id()?;
            let backing = self.new_entry_name(parent, &file_id, name)?;
            let result = match &backing {
                BackingName::Short(real) => {
                    parent.handle.create_file(real, mode).and_then(|file| {
                        let result = self.init_new_file(file, file_id);
                        if result.is_err() {
                            let _ = parent.handle.unlink(real);
                        }
                        result
                    })
                }
                BackingName::Long { entry, full } => {
                    parent.handle.mkdir(entry, LONG_ENTRY_MODE).and_then(|()| {
                        let result = parent.handle.open_dir(entry).and_then(|dir| {
                            dir.write_atomic(NAME_FILE, full.as_bytes(), CONTROL_FILE_MODE)?;
                            let file = dir.create_file(CONTENT_FILE, mode)?;
                            self.init_new_file(file, file_id)
                        });
                        if result.is_err() {
                            remove_long_entry(&parent.handle, entry);
                        }
                        result
                    })
                }
            };
            if result.is_ok() {
                let entry = self.new_entry_ref(&backing, false, file_id);
                self.index_insert(parent, display_key(name), entry)?;
            }
            self.end_change(parent, result.is_ok());
            result
        })?;
        Ok((attr, self.add_handle(shared, true, false)))
    }

    /// Writes the empty encrypted content into a new real file.
    fn init_new_file(&self, file: std::fs::File, file_id: EntryId) -> Result<(Attr, Shared)> {
        let open = OpenFile::create(file, &self.keys, file_id, self.padded)?;
        let st = stat_file(open.file())?;
        let shared = self.register((st.dev, st.ino), open)?;
        Ok((attr(&st, FileKind::File, 0), shared))
    }

    pub fn open(&self, path: &VPath, write: bool, append: bool) -> Result<FileHandleId> {
        let loc = self.locate_path(path)?;
        let shared = self.open_shared(&loc, write)?;
        Ok(self.add_handle(shared, write, append))
    }

    pub fn read(&self, fh: FileHandleId, offset: u64, size: u32) -> Result<Vec<u8>> {
        let (file, _, _) = self.handle(fh)?;
        let size = usize::try_from(size).map_err(|_| Error::InvalidArgument)?;
        lock(&file).read(offset, size)
    }

    /// Writes `data`; a handle opened with `append` writes at the end.
    pub fn write(&self, fh: FileHandleId, offset: u64, data: &[u8]) -> Result<u32> {
        let (file, write, append) = self.handle(fh)?;
        if !write {
            return Err(Error::NotPermitted);
        }
        let written = u32::try_from(data.len()).map_err(|_| Error::InvalidArgument)?;
        let mut open = lock(&file);
        let offset = if append { open.len() } else { offset };
        open.write(offset, data)?;
        Ok(written)
    }

    pub fn flush(&self, fh: FileHandleId) -> Result<()> {
        let (file, _, _) = self.handle(fh)?;
        lock(&file).flush()
    }

    /// Syncs the file. With `path` (where the file is now), it also syncs
    /// the real directories that hold its entry, so a new or renamed file
    /// is found after a crash. A path that no longer exists (the file was
    /// removed or moved from outside) only syncs the file.
    pub fn fsync(&self, fh: FileHandleId, path: Option<&VPath>) -> Result<()> {
        let (file, _, _) = self.handle(fh)?;
        lock(&file).sync()?;
        let Some(path) = path else {
            return Ok(());
        };
        match self.sync_entry_dirs(path) {
            Err(Error::NotFound) => Ok(()),
            r => r,
        }
    }

    /// Syncs the real directory that holds the entry of `path` and, for a
    /// long name, the `.cd-cdl` directory of the entry too.
    fn sync_entry_dirs(&self, path: &VPath) -> Result<()> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return Ok(());
        };
        let parent = self.dir_state(&parent_path)?;
        let entry = self.find(&parent, name)?;
        if matches!(entry.layout, Layout::LongFile) {
            parent.handle.open_dir(&entry.real)?.sync()?;
        }
        parent.handle.sync()
    }

    /// Flushes and drops the handle. The handle is gone even if the flush
    /// fails; the flush error is returned.
    pub fn release(&self, fh: FileHandleId) -> Result<()> {
        let handle = self
            .handles
            .lock()
            .expect("handles lock poisoned")
            .remove(&fh)
            .ok_or(Error::InvalidArgument)?;
        let result = lock(&handle.file).flush();
        drop(handle);
        self.prune_open_files();
        result
    }

    /// Sets the clear size of the file at `path` and writes it to disk.
    pub fn truncate(&self, path: &VPath, len: u64) -> Result<()> {
        let loc = self.locate_path(path)?;
        let shared = self.open_shared(&loc, true)?;
        let result = lock(&shared).truncate(len);
        drop(shared);
        self.prune_open_files();
        result
    }

    /// The stamp of the real file behind an open handle (see `FileStamp`).
    /// Writes that are not flushed yet are not in it; they change the
    /// stamp when they reach the real file.
    pub fn handle_stamp(&self, fh: FileHandleId) -> Result<FileStamp> {
        let (file, _, _) = self.handle(fh)?;
        let st = stat_file(lock(&file).file())?;
        Ok(FileStamp {
            dev: st.dev,
            ino: st.ino,
            size: st.size,
            mtime: st.mtime,
            ctime: st.ctime,
        })
    }

    /// Attributes of an open file from its handle, so they stay available
    /// after unlink or rename-over (fstat). Size is the size in memory.
    pub fn getattr_handle(&self, fh: FileHandleId) -> Result<Attr> {
        let (file, _, _) = self.handle(fh)?;
        let open = lock(&file);
        let st = stat_file(open.file())?;
        Ok(attr(&st, FileKind::File, open.len()))
    }

    /// Sets the clear size of an open file through its handle (ftruncate);
    /// works after unlink. The handle must be able to write.
    pub fn truncate_handle(&self, fh: FileHandleId, len: u64) -> Result<()> {
        let (file, write, _) = self.handle(fh)?;
        if !write {
            return Err(Error::NotPermitted);
        }
        lock(&file).truncate(len)
    }

    /// Flushes every open file; returns the first error after trying all.
    pub fn flush_all(&self) -> Result<()> {
        let open: Vec<Shared> = self
            .open_files
            .lock()
            .expect("open files lock poisoned")
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut first_error = None;
        for file in open {
            if let Err(e) = lock(&file).flush()
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CryptoFs, FileHandleId, FileKind, VPath};
    use crate::Error;
    use crate::content::ciphertext_size;
    use crate::keys::{DirId, MasterKey};
    use crate::names::{LONG_PREFIX, NameKeys};
    use crate::testutil::{real_name_of, test_vault, test_vault_padded, test_vault_with};
    use crate::vault::{CONTENT_FILE, CONTROL_PREFIX, NAME_FILE, UnlockedVault};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct Fx {
        _tmp: tempfile::TempDir,
        fs: CryptoFs,
        root: PathBuf,
        names: NameKeys,
        vault_id: DirId,
        mk: MasterKey,
    }

    fn fx_from((tmp, v, mk): (tempfile::TempDir, UnlockedVault, MasterKey)) -> Fx {
        let root = v.root_path.clone();
        let names = NameKeys::new(&v.keys);
        let vault_id = v.marker.vault_id;
        let fs = CryptoFs::new(v).unwrap();
        Fx {
            _tmp: tmp,
            fs,
            root,
            names,
            vault_id,
            mk,
        }
    }

    impl Fx {
        /// The real path of the existing entry `name` in the root.
        fn real(&self, name: &str) -> PathBuf {
            self.root
                .join(real_name_of(&self.names, &self.vault_id, &self.root, name))
        }
    }

    fn fx() -> Fx {
        fx_from(test_vault())
    }

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    fn write_file(fs: &CryptoFs, path: &str, data: &[u8], mode: u32) {
        let (_, h) = fs.create(&p(path), mode).unwrap();
        assert_eq!(fs.write(h, 0, data).unwrap() as usize, data.len());
        fs.release(h).unwrap();
    }

    fn read_file(fs: &CryptoFs, path: &str) -> Vec<u8> {
        let h = fs.open(&p(path), false, false).unwrap();
        let data = fs.read(h, 0, 1 << 24).unwrap();
        fs.release(h).unwrap();
        data
    }

    fn stamp_of(fs: &CryptoFs, path: &str) -> super::super::FileStamp {
        let h = fs.open(&p(path), false, false).unwrap();
        let s = fs.handle_stamp(h).unwrap();
        fs.release(h).unwrap();
        s
    }

    #[test]
    fn stamp_stays_while_unchanged_and_changes_with_the_file() {
        let f = fx();
        write_file(&f.fs, "/a", b"one", 0o644);
        write_file(&f.fs, "/b", b"two", 0o644);
        let first = stamp_of(&f.fs, "/a");
        assert_eq!(stamp_of(&f.fs, "/a"), first);
        // ctime moves in ticks of the kernel clock (a few ms on Linux), so
        // each change below comes in a later tick.
        let tick = || std::thread::sleep(std::time::Duration::from_millis(50));
        tick();
        // A write through the drive changes it once it is flushed.
        let h = f.fs.open(&p("/a"), true, false).unwrap();
        f.fs.write(h, 0, b"ONE").unwrap();
        f.fs.release(h).unwrap();
        let written = stamp_of(&f.fs, "/a");
        assert_ne!(written, first);
        // Another real file under the same name (rename over it).
        f.fs.rename(&p("/b"), &p("/a")).unwrap();
        let replaced = stamp_of(&f.fs, "/a");
        assert_ne!(replaced.ino, written.ino);
        // An outside change of the real file (a sync client) changes it too.
        let real = f.real("a");
        tick();
        let before = std::fs::read(&real).unwrap();
        std::fs::write(&real, &before).unwrap();
        assert_ne!(stamp_of(&f.fs, "/a"), replaced);
        assert!(matches!(
            f.fs.handle_stamp(FileHandleId(9999)),
            Err(Error::InvalidArgument)
        ));
    }

    /// The single real entry of `dir` that is not a control file.
    fn only_entry(dir: &Path) -> PathBuf {
        let v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with(CONTROL_PREFIX) || n.starts_with(LONG_PREFIX))
            .collect();
        assert_eq!(v.len(), 1, "entries: {v:?}");
        dir.join(&v[0])
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn create_write_release_open_read() {
        let f = fx();
        let (attr, h) = f.fs.create(&p("f.txt"), 0o644).unwrap();
        assert_eq!(attr.kind, FileKind::File);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.nlink, 1);
        assert_eq!(f.fs.write(h, 0, b"hello").unwrap(), 5);
        f.fs.release(h).unwrap();
        let h = f.fs.open(&p("f.txt"), false, false).unwrap();
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"hello");
        assert_eq!(f.fs.read(h, 3, 100).unwrap(), b"lo");
        assert!(f.fs.read(h, 5, 100).unwrap().is_empty());
        f.fs.release(h).unwrap();
        assert_eq!(f.fs.getattr(&p("f.txt")).unwrap().size, 5);
        let names: Vec<String> =
            f.fs.readdir(&VPath::root())
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
        assert_eq!(names, vec!["f.txt"]);
        let real = only_entry(&f.root);
        assert_eq!(
            std::fs::metadata(real).unwrap().len(),
            ciphertext_size(5, false)
        );
    }

    #[test]
    fn padded_vault_sizes_and_getattr() {
        let f = fx_from(test_vault_padded());
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        write_file(&f.fs, "f.bin", &data, 0o644);
        assert_eq!(f.fs.getattr(&p("f.bin")).unwrap().size, 70_000);
        assert_eq!(read_file(&f.fs, "f.bin"), data);
        let real = only_entry(&f.root);
        assert_eq!(
            std::fs::metadata(&real).unwrap().len(),
            ciphertext_size(70_000, true)
        );
        f.fs.truncate(&p("f.bin"), 10).unwrap();
        assert_eq!(f.fs.getattr(&p("f.bin")).unwrap().size, 10);
        assert_eq!(std::fs::metadata(&real).unwrap().len(), 4096);
        assert_eq!(read_file(&f.fs, "f.bin"), &data[..10]);
        // One byte more than the stage: getattr refuses the file.
        let file = std::fs::OpenOptions::new().write(true).open(&real).unwrap();
        file.set_len(4097).unwrap();
        assert!(matches!(
            f.fs.getattr(&p("f.bin")),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn padded_getattr_of_unreadable_file_is_an_upper_bound() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let f = fx_from(test_vault_padded());
        write_file(&f.fs, "f.bin", &[7u8; 5000], 0o644);
        let real = only_entry(&f.root);
        let real_len = std::fs::metadata(&real).unwrap().len();
        set_mode(&real, 0o000);
        let result = f.fs.getattr(&p("f.bin"));
        set_mode(&real, 0o644);
        assert_eq!(result.unwrap().size, real_len - 89 - 28);
    }

    #[test]
    fn swapped_file_content_is_auth_failed() {
        for padded in [false, true] {
            let f = fx_from(if padded {
                test_vault_padded()
            } else {
                test_vault()
            });
            write_file(&f.fs, "a", b"content of a", 0o644);
            write_file(&f.fs, "b", b"content of b", 0o644);
            std::fs::copy(f.real("a"), f.real("b")).unwrap();
            // A new instance, so no open file state hides the change.
            let fs =
                CryptoFs::new(crate::vault::open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
            let r = fs.open(&p("b"), false, false);
            assert!(matches!(r, Err(Error::AuthFailed { .. })), "{r:?}");
            assert!(matches!(
                fs.truncate(&p("b"), 0),
                Err(Error::AuthFailed { .. })
            ));
            if padded {
                // getattr reads the header of a padded file.
                assert!(matches!(fs.getattr(&p("b")), Err(Error::AuthFailed { .. })));
            }
            assert_eq!(read_file(&fs, "a"), b"content of a");
        }
    }

    #[test]
    fn padded_getattr_checks_the_binding_of_an_open_file() {
        let f = fx_from(test_vault_padded());
        write_file(&f.fs, "a", b"content of a", 0o644);
        write_file(&f.fs, "b", b"content of b", 0o644);
        // The real name of "b" now points at the real file of "a".
        let real_b = f.real("b");
        std::fs::remove_file(&real_b).unwrap();
        std::fs::hard_link(f.real("a"), &real_b).unwrap();
        let h = f.fs.open(&p("a"), false, false).unwrap();
        let r = f.fs.getattr(&p("b"));
        f.fs.release(h).unwrap();
        assert!(matches!(r, Err(Error::AuthFailed { .. })), "{r:?}");
        assert_eq!(f.fs.getattr(&p("a")).unwrap().size, 12);
    }

    #[test]
    fn handle_ids_start_at_one_and_are_not_reused() {
        let f = fx();
        let (_, h1) = f.fs.create(&p("a"), 0o644).unwrap();
        assert_eq!(h1, FileHandleId(1));
        f.fs.release(h1).unwrap();
        let h2 = f.fs.open(&p("a"), false, false).unwrap();
        assert_eq!(h2, FileHandleId(2));
        f.fs.release(h2).unwrap();
        assert!(matches!(f.fs.read(h1, 0, 1), Err(Error::InvalidArgument)));
        assert!(matches!(f.fs.release(h2), Err(Error::InvalidArgument)));
    }

    #[test]
    fn two_handles_share_state() {
        let f = fx();
        let (_, h1) = f.fs.create(&p("f"), 0o644).unwrap();
        let h2 = f.fs.open(&p("f"), false, false).unwrap();
        f.fs.write(h1, 0, b"shared").unwrap();
        assert_eq!(f.fs.read(h2, 0, 100).unwrap(), b"shared");
        let real = only_entry(&f.root);
        assert_eq!(std::fs::metadata(&real).unwrap().len(), 81);
        f.fs.release(h1).unwrap();
        f.fs.release(h2).unwrap();
        assert!(f.fs.open_files.lock().unwrap().is_empty());
    }

    #[test]
    fn concurrent_reader_sees_unflushed_data() {
        let f = fx();
        let (_, writer) = f.fs.create(&p("f"), 0o644).unwrap();
        let reader = f.fs.open(&p("f"), false, false).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let fs = &f.fs;
        std::thread::scope(|s| {
            s.spawn(move || {
                fs.write(writer, 0, b"from another thread").unwrap();
                tx.send(()).unwrap();
            });
            s.spawn(move || {
                rx.recv().unwrap();
                assert_eq!(fs.read(reader, 0, 100).unwrap(), b"from another thread");
            });
        });
        let real = only_entry(&f.root);
        assert_eq!(std::fs::metadata(&real).unwrap().len(), 81);
        f.fs.release(writer).unwrap();
        f.fs.release(reader).unwrap();
    }

    #[test]
    fn append_writes_at_end() {
        let f = fx();
        write_file(&f.fs, "f", b"abc", 0o644);
        let h = f.fs.open(&p("f"), true, true).unwrap();
        assert_eq!(f.fs.write(h, 0, b"def").unwrap(), 3);
        assert_eq!(f.fs.write(h, 1, b"g").unwrap(), 1);
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, "f"), b"abcdefg");
    }

    #[test]
    fn write_on_read_only_handle_is_not_permitted() {
        let f = fx();
        write_file(&f.fs, "f", b"abc", 0o644);
        let h = f.fs.open(&p("f"), false, false).unwrap();
        assert!(matches!(f.fs.write(h, 0, b"x"), Err(Error::NotPermitted)));
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, "f"), b"abc");
    }

    #[test]
    fn long_file_name_round_trip() {
        let f = fx_from(test_vault_with(64));
        let name = "l".repeat(120);
        let data = vec![9u8; 70_000];
        write_file(&f.fs, &name, &data, 0o644);
        assert_eq!(read_file(&f.fs, &name), data);
        assert_eq!(f.fs.getattr(&p(&name)).unwrap().size, 70_000);
        let names: Vec<String> =
            f.fs.readdir(&VPath::root())
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
        assert_eq!(names, vec![name.clone()]);
        let entry = only_entry(&f.root);
        assert!(
            entry
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(LONG_PREFIX)
        );
        assert!(entry.join(NAME_FILE).is_file());
        assert_eq!(
            std::fs::metadata(entry.join(CONTENT_FILE)).unwrap().len(),
            ciphertext_size(70_000, false)
        );
        assert!(matches!(
            f.fs.create(&p(&name), 0o644),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn create_existing_name_is_already_exists() {
        let f = fx();
        write_file(&f.fs, "f", b"abc", 0o644);
        assert!(matches!(
            f.fs.create(&p("f"), 0o644),
            Err(Error::AlreadyExists)
        ));
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        assert!(matches!(
            f.fs.create(&p("d"), 0o644),
            Err(Error::AlreadyExists)
        ));
        assert!(matches!(
            f.fs.create(&VPath::root(), 0o644),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(read_file(&f.fs, "f"), b"abc");
    }

    #[test]
    fn getattr_while_dirty_shows_memory_size() {
        let f = fx();
        let (_, h) = f.fs.create(&p("f"), 0o644).unwrap();
        f.fs.write(h, 0, &[1u8; 1000]).unwrap();
        assert_eq!(f.fs.getattr(&p("f")).unwrap().size, 1000);
        let real = only_entry(&f.root);
        assert_eq!(std::fs::metadata(&real).unwrap().len(), 81);
        f.fs.flush(h).unwrap();
        assert_eq!(
            std::fs::metadata(&real).unwrap().len(),
            ciphertext_size(1000, false)
        );
        f.fs.fsync(h, None).unwrap();
        f.fs.release(h).unwrap();
        assert_eq!(f.fs.getattr(&p("f")).unwrap().size, 1000);
    }

    #[test]
    fn read_only_mode_file_can_be_opened_for_reading() {
        let f = fx();
        write_file(&f.fs, "ro", b"read me", 0o444);
        assert_eq!(f.fs.getattr(&p("ro")).unwrap().mode & 0o777, 0o444);
        let h = f.fs.open(&p("ro"), false, false).unwrap();
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"read me");
        assert!(matches!(
            f.fs.open(&p("ro"), true, false),
            Err(Error::NotPermitted)
        ));
        assert!(matches!(
            f.fs.truncate(&p("ro"), 0),
            Err(Error::NotPermitted)
        ));
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, "ro"), b"read me");
    }

    #[test]
    fn read_only_shared_file_is_reopened_for_write() {
        let f = fx();
        write_file(&f.fs, "f", b"abc", 0o444);
        let reader = f.fs.open(&p("f"), false, false).unwrap();
        set_mode(&only_entry(&f.root), 0o644);
        let writer = f.fs.open(&p("f"), true, false).unwrap();
        f.fs.write(writer, 3, b"def").unwrap();
        assert_eq!(f.fs.read(reader, 0, 100).unwrap(), b"abcdef");
        f.fs.release(writer).unwrap();
        f.fs.release(reader).unwrap();
        assert_eq!(read_file(&f.fs, "f"), b"abcdef");
    }

    #[test]
    fn directories_and_files_are_not_mixed() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "f", b"abc", 0o644);
        assert!(matches!(
            f.fs.open(&p("d"), false, false),
            Err(Error::IsADirectory)
        ));
        assert!(matches!(
            f.fs.open(&VPath::root(), false, false),
            Err(Error::IsADirectory)
        ));
        assert!(matches!(
            f.fs.truncate(&p("d"), 0),
            Err(Error::IsADirectory)
        ));
        assert!(matches!(
            f.fs.create(&p("f/x"), 0o644),
            Err(Error::NotADirectory)
        ));
        assert!(matches!(
            f.fs.open(&p("nope"), false, false),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn truncate_without_open_handle() {
        let f = fx();
        write_file(&f.fs, "f", &[5u8; 100_000], 0o644);
        f.fs.truncate(&p("f"), 10).unwrap();
        assert_eq!(f.fs.getattr(&p("f")).unwrap().size, 10);
        assert_eq!(read_file(&f.fs, "f"), [5u8; 10]);
        f.fs.truncate(&p("f"), 20).unwrap();
        let mut expected = vec![5u8; 10];
        expected.resize(20, 0);
        assert_eq!(read_file(&f.fs, "f"), expected);
        assert!(f.fs.open_files.lock().unwrap().is_empty());
    }

    #[test]
    fn truncate_goes_through_shared_state() {
        let f = fx();
        let (_, h) = f.fs.create(&p("f"), 0o644).unwrap();
        f.fs.write(h, 0, b"0123456789").unwrap();
        f.fs.truncate(&p("f"), 4).unwrap();
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"0123");
        assert_eq!(f.fs.getattr(&p("f")).unwrap().size, 4);
        f.fs.write(h, 4, b"x").unwrap();
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, "f"), b"0123x");
    }

    #[test]
    fn flush_all_writes_every_dirty_file() {
        let f = fx();
        let (_, a) = f.fs.create(&p("a"), 0o644).unwrap();
        let (_, b) = f.fs.create(&p("b"), 0o644).unwrap();
        f.fs.write(a, 0, b"aaaa").unwrap();
        f.fs.write(b, 0, b"bb").unwrap();
        f.fs.flush_all().unwrap();
        let mut sizes: Vec<u64> = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| !e.file_name().to_str().unwrap().starts_with(CONTROL_PREFIX))
            .map(|e| e.metadata().unwrap().len())
            .collect();
        sizes.sort();
        assert_eq!(
            sizes,
            vec![ciphertext_size(2, false), ciphertext_size(4, false)]
        );
        f.fs.release(a).unwrap();
        f.fs.release(b).unwrap();
    }

    #[test]
    fn files_in_sub_directories() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "d/f", b"inside", 0o600);
        assert_eq!(read_file(&f.fs, "d/f"), b"inside");
        assert_eq!(f.fs.getattr(&p("d/f")).unwrap().mode & 0o777, 0o600);
        assert!(matches!(
            f.fs.create(&p("nope/f"), 0o644),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn getattr_handle_works_after_unlink() {
        let f = fx();
        let (_, h) = f.fs.create(&p("a"), 0o640).unwrap();
        f.fs.write(h, 0, b"hello world").unwrap();
        f.fs.unlink(&p("a")).unwrap();
        assert!(matches!(f.fs.getattr(&p("a")), Err(Error::NotFound)));
        let a = f.fs.getattr_handle(h).unwrap();
        assert_eq!(a.kind, FileKind::File);
        assert_eq!(a.size, 11);
        assert_eq!(a.nlink, 1);
        assert_eq!(a.mode & 0o777, 0o640);
        f.fs.release(h).unwrap();
        assert!(matches!(
            f.fs.getattr_handle(h),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn truncate_handle_works_after_unlink() {
        let f = fx();
        let (_, h) = f.fs.create(&p("a"), 0o644).unwrap();
        f.fs.write(h, 0, b"hello world").unwrap();
        f.fs.unlink(&p("a")).unwrap();
        f.fs.truncate_handle(h, 5).unwrap();
        assert_eq!(f.fs.getattr_handle(h).unwrap().size, 5);
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"hello");
        f.fs.release(h).unwrap();
    }

    #[test]
    fn truncate_handle_needs_write_handle() {
        let f = fx();
        write_file(&f.fs, "a", b"abc", 0o644);
        let h = f.fs.open(&p("a"), false, false).unwrap();
        assert!(matches!(
            f.fs.truncate_handle(h, 0),
            Err(Error::NotPermitted)
        ));
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, "a"), b"abc");
    }
}
