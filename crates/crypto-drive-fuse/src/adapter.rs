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

//! The `fuser::Filesystem` implementation on top of the core `CryptoFs`.

use crate::errno::to_errno;
use crate::inodes::{InodeTable, ROOT_INO};
use crate::xattrs::{Answer, Stored, XattrStore};
use crypto_drive_core::Error;
use crypto_drive_core::fs::{Attr, CryptoFs, FileHandleId, FileKind, FileStamp, VPath};
use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime};

/// Attribute and entry TTL (spec section 6).
const TTL: Duration = Duration::from_secs(1);
const GENERATION: Generation = Generation(0);
const BLOCK_SIZE: u32 = 4096;
const NAME_MAX: u32 = 255;
const PERM_MASK: u32 = 0o7777;
/// Snapshot lines prepared per step while filling a readdir reply.
const READDIR_CHUNK: usize = 128;
/// Set in every synthetic readdir inode, so it never collides with a table
/// inode (those count up from 1) and is never 0.
const SYNTHETIC_BIT: u64 = 1 << 63;

/// An errno value; the error type of the adapter helpers.
type Res<T> = Result<T, i32>;

/// One readdir line: inode, kind, name.
type DirLine = (u64, FileType, String);

/// One snapshot line of an open directory: kind and name.
type SnapLine = (FileType, String);

/// The FUSE file system. Every request maps the inode to a clear path and
/// calls the core. The inode lock is never held while the core runs.
pub struct FuseFs {
    fs: Arc<CryptoFs>,
    inodes: Mutex<InodeTable>,
    /// Ops that compute a path from an inode and later change the table or
    /// the file (lookup, create, mkdir, unlink, rmdir, open, setattr,
    /// xattrs) hold the read side from the path computation to the change;
    /// rename holds the write side across the core rename and the table
    /// update. So no op can put a path into the table that a concurrent
    /// rename already moved away, or change a file that a rename just put
    /// under the path. Read-only ops (getattr, readdir, fsync) do not take
    /// it: at worst they see the state from just before a rename.
    rename_lock: RwLock<()>,
    /// Listing snapshots of open directories, by directory handle.
    dirs: Mutex<HashMap<u64, Vec<SnapLine>>>,
    next_dir: AtomicU64,
    /// Extended attributes, in memory only (spec 5.6).
    xattrs: Mutex<XattrStore>,
    /// The stamp of the real file at the last open, by inode. If it is the
    /// same at the next open, the kernel may keep its page cache of the
    /// file (`FOPEN_KEEP_CACHE`). Removed when the kernel forgets the inode.
    stamps: Mutex<HashMap<u64, FileStamp>>,
    on_destroy: Option<Sender<()>>,
}

/// The open reply flags: keep the kernel cache, or drop it.
///
/// Linux drops the page cache on open unless `FOPEN_KEEP_CACHE` is set.
/// macFUSE does not: it keeps its buffer cache (UBC) and cached attributes
/// unless told to purge them, so after an outside change a read could
/// return the old content.
pub(crate) fn open_flags(keep: bool) -> FopenFlags {
    if keep {
        return FopenFlags::FOPEN_KEEP_CACHE;
    }
    #[cfg(target_os = "macos")]
    {
        FopenFlags::FOPEN_PURGE_UBC | FopenFlags::FOPEN_PURGE_ATTR
    }
    #[cfg(not(target_os = "macos"))]
    {
        FopenFlags::empty()
    }
}

/// True if the kernel may keep its cached pages of a file at this open:
/// the real file is in the same state as at the last open of this inode,
/// and the open does not truncate. Own writes go through the kernel and
/// keep its cache right, but they change the stamp, so the next open
/// drops the cache anyway (safe, a bit slower).
pub(crate) fn keep_cache(seen: Option<&FileStamp>, now: &FileStamp, truncate: bool) -> bool {
    !truncate && seen == Some(now)
}

/// The changes of one setattr request that the adapter handles.
#[derive(Default)]
pub(crate) struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<TimeOrNow>,
    pub mtime: Option<TimeOrNow>,
}

/// How a file is opened, from the open flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenMode {
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
}

impl OpenMode {
    pub(crate) fn from_flags(flags: i32) -> Self {
        OpenMode {
            write: (flags & libc::O_ACCMODE) != libc::O_RDONLY,
            append: (flags & libc::O_APPEND) != 0,
            truncate: (flags & libc::O_TRUNC) != 0,
        }
    }
}

/// A file name from the kernel as UTF-8; anything else gives `EINVAL`.
pub fn name_to_str(name: &OsStr) -> Result<&str, i32> {
    name.to_str().ok_or(libc::EINVAL)
}

fn file_type(kind: FileKind) -> FileType {
    match kind {
        FileKind::File => FileType::RegularFile,
        FileKind::Directory => FileType::Directory,
    }
}

pub fn to_file_attr(ino: u64, a: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: a.size,
        blocks: a.size.div_ceil(512),
        atime: a.atime,
        mtime: a.mtime,
        ctime: a.ctime,
        crtime: a.ctime,
        kind: file_type(a.kind),
        perm: u16::try_from(a.mode & PERM_MASK).unwrap_or(0),
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

/// `EPERM` if the request changes the owner or group (spec 5.6: no chown).
/// Setting them to their current values is allowed.
pub(crate) fn check_owner_change(cur: &Attr, uid: Option<u32>, gid: Option<u32>) -> Res<()> {
    if uid.is_some_and(|u| u != cur.uid) || gid.is_some_and(|g| g != cur.gid) {
        return Err(libc::EPERM);
    }
    Ok(())
}

/// A stable inode number for a readdir entry the table does not know.
/// `d_ino` from readdir is only advisory: the kernel uses the inode from a
/// later `lookup`, so readdir must not add inodes (that would leak lookup
/// counts). The high bit keeps it apart from table inodes and never 0.
pub(crate) fn synthetic_ino(path: &VPath) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish() | SYNTHETIC_BIT
}

fn time(t: TimeOrNow) -> SystemTime {
    match t {
        TimeOrNow::SpecificTime(t) => t,
        TimeOrNow::Now => SystemTime::now(),
    }
}

/// Logs a core error and maps it to errno. Auth and format errors carry the
/// real (encrypted) name and are logged as warnings; clear names never
/// appear in the core errors.
fn core_err(op: &str, e: Error) -> i32 {
    match &e {
        Error::AuthFailed { .. } | Error::InvalidFormat { .. } => log::warn!("{op}: {e}"),
        _ => log::debug!("{op}: {e}"),
    }
    to_errno(&e)
}

fn errno(code: i32) -> Errno {
    Errno::from_i32(code)
}

/// Directory handle ids have this bit set, so they never equal a file
/// handle id of the core.
const DIR_FH_BIT: u64 = 1 << 63;

/// The handle to use for a handle lookup: directory handles are no file
/// handles, so they are dropped and the path is used instead.
fn file_handle_only(fh: Option<FileHandleId>) -> Option<FileHandleId> {
    fh.filter(|h| h.0 & DIR_FH_BIT == 0)
}

fn fh_id(fh: FileHandle) -> FileHandleId {
    FileHandleId(fh.0)
}

impl FuseFs {
    pub fn new(fs: Arc<CryptoFs>, on_destroy: Option<Sender<()>>) -> Self {
        FuseFs {
            fs,
            inodes: Mutex::new(InodeTable::new()),
            rename_lock: RwLock::new(()),
            dirs: Mutex::new(HashMap::new()),
            next_dir: AtomicU64::new(1),
            xattrs: Mutex::new(XattrStore::default()),
            stamps: Mutex::new(HashMap::new()),
            on_destroy,
        }
    }

    fn inodes(&self) -> MutexGuard<'_, InodeTable> {
        self.inodes.lock().expect("inode table lock poisoned")
    }

    /// The read side of `rename_lock`; see there.
    fn no_rename(&self) -> RwLockReadGuard<'_, ()> {
        self.rename_lock.read().expect("rename lock poisoned")
    }

    fn xattrs(&self) -> MutexGuard<'_, XattrStore> {
        self.xattrs.lock().expect("xattr store lock poisoned")
    }

    fn dirs(&self) -> MutexGuard<'_, HashMap<u64, Vec<SnapLine>>> {
        self.dirs.lock().expect("dir handles lock poisoned")
    }

    fn path_of(&self, ino: INodeNo) -> Res<VPath> {
        self.inodes().path(ino.0).ok_or(libc::ENOENT)
    }

    fn child(&self, parent: INodeNo, name: &OsStr) -> Res<VPath> {
        let parent = self.path_of(parent)?;
        parent.join(name_to_str(name)?).map_err(|e| to_errno(&e))
    }

    /// The inode for a readdir entry: the known one, else a synthetic one.
    fn listed_ino(table: &InodeTable, path: &VPath) -> u64 {
        table.ino_of(path).unwrap_or_else(|| synthetic_ino(path))
    }

    fn do_lookup(&self, parent: INodeNo, name: &OsStr) -> Res<FileAttr> {
        let _guard = self.no_rename();
        let path = self.child(parent, name)?;
        let attr = self.fs.getattr(&path).map_err(|e| core_err("lookup", e))?;
        let ino = self.inodes().lookup(&path);
        log::debug!("lookup {path:?} -> {ino}");
        Ok(to_file_attr(ino, &attr))
    }

    /// Attributes by open handle when there is one (fstat works after
    /// unlink or rename-over), else by path. A handle the core does not
    /// know (`InvalidArgument`) falls back to the path.
    fn current_attr(&self, ino: INodeNo, fh: Option<FileHandleId>) -> Res<Attr> {
        if let Some(fh) = file_handle_only(fh) {
            match self.fs.getattr_handle(fh) {
                Ok(attr) => return Ok(attr),
                Err(Error::InvalidArgument) => {}
                Err(e) => return Err(core_err("getattr", e)),
            }
        }
        let path = self.path_of(ino)?;
        self.fs.getattr(&path).map_err(|e| core_err("getattr", e))
    }

    fn do_getattr(&self, ino: INodeNo, fh: Option<FileHandleId>) -> Res<FileAttr> {
        Ok(to_file_attr(ino.0, &self.current_attr(ino, fh)?))
    }

    /// Holds the read side of `rename_lock` from the path lookup to the
    /// change, so a truncate or chmod never hits a file that a concurrent
    /// rename just put under this path.
    fn do_setattr(&self, ino: INodeNo, fh: Option<FileHandleId>, c: &SetAttr) -> Res<FileAttr> {
        let _guard = self.no_rename();
        let fh = file_handle_only(fh);
        let cur = self.current_attr(ino, fh)?;
        check_owner_change(&cur, c.uid, c.gid)?;
        if let Some(size) = c.size {
            let by_handle = match fh.map(|fh| self.fs.truncate_handle(fh, size)) {
                Some(Ok(())) => true,
                None | Some(Err(Error::InvalidArgument)) => false,
                Some(Err(e)) => return Err(core_err("truncate", e)),
            };
            if !by_handle {
                let path = self.path_of(ino)?;
                self.fs
                    .truncate(&path, size)
                    .map_err(|e| core_err("truncate", e))?;
            }
        }
        if let Some(mode) = c.mode {
            let path = self.path_of(ino)?;
            self.fs
                .set_mode(&path, mode & PERM_MASK)
                .map_err(|e| core_err("chmod", e))?;
        }
        if c.atime.is_some() || c.mtime.is_some() {
            let path = self.path_of(ino)?;
            self.fs
                .set_times(&path, c.atime.map(time), c.mtime.map(time))
                .map_err(|e| core_err("utimens", e))?;
        }
        self.do_getattr(ino, fh)
    }

    fn do_mkdir(&self, parent: INodeNo, name: &OsStr, mode: u32, umask: u32) -> Res<FileAttr> {
        let _guard = self.no_rename();
        let path = self.child(parent, name)?;
        let attr = self
            .fs
            .mkdir(&path, mode & !umask & PERM_MASK)
            .map_err(|e| core_err("mkdir", e))?;
        let ino = self.inodes().lookup(&path);
        Ok(to_file_attr(ino, &attr))
    }

    fn do_create(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Res<(FileAttr, FileHandleId)> {
        let _guard = self.no_rename();
        let path = self.child(parent, name)?;
        let (attr, fh) = self
            .fs
            .create(&path, mode & !umask & PERM_MASK)
            .map_err(|e| core_err("create", e))?;
        // The core gives a plain write handle; O_APPEND needs its own.
        let fh = if OpenMode::from_flags(flags).append {
            let reopened = self.fs.open(&path, true, true);
            self.release_quietly(fh);
            reopened.map_err(|e| core_err("create", e))?
        } else {
            fh
        };
        let ino = self.inodes().lookup(&path);
        Ok((to_file_attr(ino, &attr), fh))
    }

    fn stamps(&self) -> MutexGuard<'_, HashMap<u64, FileStamp>> {
        self.stamps.lock().expect("stamps lock poisoned")
    }

    /// Opens the file; also returns whether the kernel may keep its page
    /// cache (see `keep_cache`).
    /// Holds the read side of `rename_lock` like `do_setattr`: an open with
    /// `O_TRUNC` must not empty a file renamed over this path meanwhile.
    fn do_open(&self, ino: INodeNo, flags: i32) -> Res<(FileHandleId, bool)> {
        let _guard = self.no_rename();
        let path = self.path_of(ino)?;
        let mode = OpenMode::from_flags(flags);
        let fh = self
            .fs
            .open(&path, mode.write, mode.append)
            .map_err(|e| core_err("open", e))?;
        let truncate = mode.write && mode.truncate;
        if truncate && let Err(e) = self.fs.truncate(&path, 0) {
            self.release_quietly(fh);
            return Err(core_err("open", e));
        }
        let keep = match self.fs.handle_stamp(fh) {
            Ok(now) => {
                let mut stamps = self.stamps();
                let keep = keep_cache(stamps.get(&ino.0), &now, truncate);
                stamps.insert(ino.0, now);
                keep
            }
            // Without a stamp the cache is dropped, as before.
            Err(e) => {
                core_err("open", e);
                self.stamps().remove(&ino.0);
                false
            }
        };
        Ok((fh, keep))
    }

    /// Drops `nlookup` kernel lookups. Once the inode is gone, the kernel
    /// has dropped its cache too, so its stamp goes.
    fn do_forget(&self, ino: INodeNo, nlookup: u64) {
        let gone = {
            let mut inodes = self.inodes();
            inodes.forget(ino.0, nlookup);
            inodes.path(ino.0).is_none()
        };
        if gone {
            self.stamps().remove(&ino.0);
        }
    }

    fn release_quietly(&self, fh: FileHandleId) {
        if let Err(e) = self.fs.release(fh) {
            core_err("release", e);
        }
    }

    fn do_unlink(&self, parent: INodeNo, name: &OsStr) -> Res<()> {
        let _guard = self.no_rename();
        let path = self.child(parent, name)?;
        self.fs.unlink(&path).map_err(|e| core_err("unlink", e))?;
        self.inodes().remove_path(&path);
        self.xattrs().remove_path(&path);
        Ok(())
    }

    fn do_rmdir(&self, parent: INodeNo, name: &OsStr) -> Res<()> {
        let _guard = self.no_rename();
        let path = self.child(parent, name)?;
        self.fs.rmdir(&path).map_err(|e| core_err("rmdir", e))?;
        self.inodes().remove_path(&path);
        self.xattrs().remove_path(&path);
        Ok(())
    }

    fn do_rename(
        &self,
        parent: INodeNo,
        name: &OsStr,
        new_parent: INodeNo,
        new_name: &OsStr,
        flags: u32,
    ) -> Res<()> {
        // RENAME_NOREPLACE and RENAME_EXCHANGE are not in the MVP (spec 5.5).
        if flags != 0 {
            return Err(libc::EINVAL);
        }
        let _guard = self.rename_lock.write().expect("rename lock poisoned");
        let from = self.child(parent, name)?;
        let to = self.child(new_parent, new_name)?;
        self.fs
            .rename(&from, &to)
            .map_err(|e| core_err("rename", e))?;
        self.inodes().rename(&from, &to);
        self.xattrs().rename(&from, &to);
        Ok(())
    }

    fn do_setxattr(
        &self,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Res<()> {
        let _guard = self.no_rename();
        let path = self.path_of(ino)?;
        let stored = self
            .xattrs()
            .set(&path, name.as_bytes(), value, flags, position)?;
        if stored == Stored::Dropped {
            // The name is a clear name, so it is only logged at debug level.
            log::debug!("setxattr: not kept: {name:?} ({} bytes)", value.len());
        }
        Ok(())
    }

    fn do_getxattr(&self, ino: INodeNo, name: &OsStr, size: u32) -> Res<Answer> {
        let _guard = self.no_rename();
        let path = self.path_of(ino)?;
        self.xattrs().get(&path, name.as_bytes(), size)
    }

    fn do_listxattr(&self, ino: INodeNo, size: u32) -> Res<Answer> {
        let _guard = self.no_rename();
        let path = self.path_of(ino)?;
        self.xattrs().list(&path, size)
    }

    /// Removing a missing attribute is not an error, so copy tools never
    /// fail on it.
    fn do_removexattr(&self, ino: INodeNo, name: &OsStr) -> Res<()> {
        let _guard = self.no_rename();
        let path = self.path_of(ino)?;
        self.xattrs().remove(&path, name.as_bytes());
        Ok(())
    }

    /// A fresh listing of the directory with "." and ".." first.
    fn snapshot(&self, ino: INodeNo) -> Res<Vec<SnapLine>> {
        let path = self.path_of(ino)?;
        let entries = self.fs.readdir(&path).map_err(|e| core_err("readdir", e))?;
        let mut lines = Vec::with_capacity(entries.len() + 2);
        lines.push((FileType::Directory, ".".to_string()));
        lines.push((FileType::Directory, "..".to_string()));
        lines.extend(entries.into_iter().map(|e| (file_type(e.kind), e.name)));
        Ok(lines)
    }

    /// Opens a directory: takes a listing snapshot under a new handle.
    fn do_opendir(&self, ino: INodeNo) -> Res<u64> {
        let lines = self.snapshot(ino)?;
        let dh = self.next_dir.fetch_add(1, Ordering::Relaxed) | DIR_FH_BIT;
        self.dirs().insert(dh, lines);
        Ok(dh)
    }

    /// Up to `max` lines of the snapshot from `offset` on, each with the
    /// offset of the line after it (index + 1). Offset 0 (rewinddir) takes
    /// a new snapshot. Serving later pages from the snapshot keeps offsets
    /// valid while entries are deleted (rm -r). It never adds inodes.
    fn do_readdir(
        &self,
        ino: INodeNo,
        dh: u64,
        offset: u64,
        max: usize,
    ) -> Res<Vec<(u64, DirLine)>> {
        if offset == 0 {
            if !self.dirs().contains_key(&dh) {
                return Err(libc::EBADF);
            }
            let fresh = self.snapshot(ino)?;
            match self.dirs().get_mut(&dh) {
                Some(lines) => *lines = fresh,
                None => return Err(libc::EBADF),
            }
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let page: Vec<(usize, SnapLine)> = {
            let dirs = self.dirs();
            let lines = dirs.get(&dh).ok_or(libc::EBADF)?;
            lines
                .iter()
                .enumerate()
                .skip(start)
                .take(max)
                .map(|(i, l)| (i, l.clone()))
                .collect()
        };
        let path = self.path_of(ino)?;
        let table = self.inodes();
        let mut out = Vec::with_capacity(page.len());
        for (i, (kind, name)) in page {
            let line_ino = match name.as_str() {
                "." => ino.0,
                ".." => match path.parent() {
                    None => ROOT_INO,
                    Some(parent) => Self::listed_ino(&table, &parent),
                },
                _ => match path.join(&name) {
                    Ok(p) => Self::listed_ino(&table, &p),
                    // Core names are valid; d_ino is advisory anyway.
                    Err(err) => {
                        log::debug!("readdir: bad name {name:?}: {err}");
                        synthetic_ino(&path)
                    }
                },
            };
            let next = u64::try_from(i + 1).unwrap_or(u64::MAX);
            out.push((next, (line_ino, kind, name)));
        }
        Ok(out)
    }

    fn do_releasedir(&self, dh: u64) -> Res<()> {
        self.dirs().remove(&dh).map(|_| ()).ok_or(libc::EBADF)
    }
}

impl Filesystem for FuseFs {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        log::debug!("fuse init");
        Ok(())
    }

    fn destroy(&mut self) {
        if let Err(e) = self.fs.flush_all() {
            log::error!("could not write all buffers at unmount: {e}");
        }
        if let Some(tx) = &self.on_destroy {
            // The receiver may be gone already; nothing to do then.
            let _ = tx.send(());
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.do_lookup(parent, name) {
            Ok(attr) => reply.entry(&TTL, &attr, GENERATION),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.do_forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.do_getattr(ino, fh.map(fh_id)) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let changes = SetAttr {
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
        };
        match self.do_setattr(ino, fh.map(fh_id), &changes) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        match self.do_mkdir(parent, name, mode, umask) {
            Ok(attr) => reply.entry(&TTL, &attr, GENERATION),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.do_unlink(parent, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.do_rmdir(parent, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &Path,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        match self.do_rename(parent, name, newparent, newname, flags.bits()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        match self.do_open(ino, flags.0) {
            Ok((fh, keep)) => reply.opened(FileHandle(fh.0), open_flags(keep)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.fs.read(fh_id(fh), offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno(core_err("read", e))),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.fs.write(fh_id(fh), offset, data) {
            Ok(n) => reply.written(n),
            Err(e) => reply.error(errno(core_err("write", e))),
        }
    }

    /// Called on every close(); write errors reach the program here.
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.fs.flush(fh_id(fh)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(core_err("flush", e))),
        }
    }

    /// The kernel ignores errors of release; `flush` reports them.
    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.fs.release(fh_id(fh)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(core_err("release", e))),
        }
    }

    /// Syncs the file and the real directories that hold its entry. An
    /// inode without a known path only syncs the file.
    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let path = self.path_of(ino).ok();
        match self.fs.fsync(fh_id(fh), path.as_ref()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(core_err("fsync", e))),
        }
    }

    /// Without this, Linux answers every later fsync of a directory with
    /// success and does nothing (ENOSYS is remembered).
    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let result = self
            .path_of(ino)
            .and_then(|path| self.fs.fsyncdir(&path).map_err(|e| core_err("fsyncdir", e)));
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    /// Directories need no state: readdir lists again on each call.
    /// Takes a listing snapshot; readdir serves from it.
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.do_opendir(ino) {
            Ok(dh) => reply.opened(FileHandle(dh), FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }

    /// Sends snapshot lines from `offset` on until the reply buffer is
    /// full. The offset of each entry is its index + 1.
    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut offset = offset;
        loop {
            let page = match self.do_readdir(ino, fh.0, offset, READDIR_CHUNK) {
                Ok(page) => page,
                Err(e) => return reply.error(errno(e)),
            };
            let Some(&(last, _)) = page.last() else {
                break;
            };
            for (next, (line_ino, kind, name)) in &page {
                if reply.add(INodeNo(*line_ino), *next, *kind, name) {
                    return reply.ok();
                }
            }
            offset = last;
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        match self.do_releasedir(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.fs.statfs() {
            Ok(s) => reply.statfs(
                s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, NAME_MAX, s.frsize,
            ),
            Err(e) => reply.error(errno(core_err("statfs", e))),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.do_create(parent, name, mode, umask, flags) {
            Ok((attr, fh)) => reply.created(
                &TTL,
                &attr,
                GENERATION,
                FileHandle(fh.0),
                FopenFlags::empty(),
            ),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        match self.do_setxattr(ino, name, value, flags, position) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        match self.do_getxattr(ino, name, size) {
            Ok(Answer::Size(n)) => reply.size(n),
            Ok(Answer::Data(d)) => reply.data(&d),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        match self.do_listxattr(ino, size) {
            Ok(Answer::Size(n)) => reply.size(n),
            Ok(Answer::Data(d)) => reply.data(&d),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.do_removexattr(ino, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xattrs::NO_XATTR;
    use crypto_drive_core::fs::{Attr, CryptoFs, FileKind};
    use crypto_drive_core::testutil::test_vault;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, SystemTime};

    fn attr(kind: FileKind, size: u64, mode: u32) -> Attr {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        Attr {
            kind,
            size,
            mode,
            uid: 501,
            gid: 20,
            atime: t,
            mtime: t,
            ctime: t,
            nlink: 1,
        }
    }

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    struct Fx {
        _tmp: Box<dyn std::any::Any>,
        fuse: FuseFs,
    }

    fn fx() -> Fx {
        let (tmp, vault, _mk) = test_vault();
        let fs = CryptoFs::new(vault).unwrap();
        Fx {
            _tmp: Box::new(tmp),
            fuse: FuseFs::new(Arc::new(fs), None),
        }
    }

    /// A name that is kept on this OS (Linux keeps only `user.`).
    fn xname(s: &str) -> std::ffi::OsString {
        if cfg!(target_os = "macos") {
            s.into()
        } else {
            format!("user.{s}").into()
        }
    }

    fn xget(fuse: &FuseFs, ino: INodeNo, name: &OsStr) -> Res<Vec<u8>> {
        match fuse.do_getxattr(ino, name, 1 << 20)? {
            Answer::Data(d) => Ok(d),
            Answer::Size(n) => panic!("size {n} instead of data"),
        }
    }

    #[test]
    fn xattrs_follow_rename_and_go_with_unlink() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        let q = xname("com.apple.quarantine");
        f.fuse.do_setxattr(a.ino, &q, b"0081;x", 0x8, 0).unwrap();
        assert_eq!(xget(&f.fuse, a.ino, &q).unwrap(), b"0081;x");
        let mut names = q.as_bytes().to_vec();
        names.push(0);
        assert_eq!(
            f.fuse.do_listxattr(a.ino, 0),
            Ok(Answer::Size(names.len() as u32))
        );

        f.fuse.do_rename(root, os("a"), root, os("b"), 0).unwrap();
        assert_eq!(xget(&f.fuse, a.ino, &q).unwrap(), b"0081;x");

        f.fuse.do_unlink(root, os("b")).unwrap();
        let (c, fh) = f
            .fuse
            .do_create(root, os("b"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        assert_eq!(xget(&f.fuse, c.ino, &q), Err(NO_XATTR));
    }

    #[test]
    fn xattr_remove_of_a_missing_name_is_ok() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let a = f.fuse.do_mkdir(root, os("d"), 0o755, 0).unwrap();
        assert_eq!(
            f.fuse.do_removexattr(a.ino, &xname("com.apple.FinderInfo")),
            Ok(())
        );
        assert_eq!(f.fuse.do_listxattr(a.ino, 0), Ok(Answer::Size(0)));
    }

    #[test]
    fn xattr_on_unknown_inode_is_enoent() {
        let f = fx();
        assert_eq!(
            f.fuse.do_setxattr(INodeNo(999), &xname("a"), b"x", 0, 0),
            Err(libc::ENOENT)
        );
    }

    fn assert_send_sync_static<T: Send + Sync + 'static>() {}

    /// Reads a whole directory like the kernel: opendir, readdir, releasedir.
    fn list_all(fuse: &FuseFs, ino: INodeNo) -> Vec<DirLine> {
        let dh = fuse.do_opendir(ino).unwrap();
        let lines = fuse.do_readdir(ino, dh, 0, usize::MAX).unwrap();
        fuse.do_releasedir(dh).unwrap();
        lines.into_iter().map(|(_, line)| line).collect()
    }

    #[test]
    fn fuse_fs_is_send_sync_static() {
        assert_send_sync_static::<FuseFs>();
    }

    #[test]
    fn name_to_str_rejects_non_utf8() {
        assert_eq!(
            name_to_str(OsStr::from_bytes(b"\xff\xfe")),
            Err(libc::EINVAL)
        );
        assert_eq!(name_to_str(os("abc")), Ok("abc"));
    }

    #[test]
    fn to_file_attr_maps_fields() {
        let a = to_file_attr(7, &attr(FileKind::File, 1000, 0o100644));
        assert_eq!(a.ino, INodeNo(7));
        assert_eq!(a.size, 1000);
        assert_eq!(a.blocks, 2);
        assert_eq!(a.blksize, 4096);
        assert_eq!(a.kind, FileType::RegularFile);
        assert_eq!(a.perm, 0o644);
        assert_eq!(a.uid, 501);
        assert_eq!(a.gid, 20);
        assert_eq!(a.nlink, 1);
        let d = to_file_attr(1, &attr(FileKind::Directory, 0, 0o40755));
        assert_eq!(d.kind, FileType::Directory);
        assert_eq!(d.blocks, 0);
        assert_eq!(d.perm, 0o755);
        assert_eq!(to_file_attr(1, &attr(FileKind::File, 512, 0)).blocks, 1);
        assert_eq!(to_file_attr(1, &attr(FileKind::File, 513, 0)).blocks, 2);
    }

    #[test]
    fn owner_change_gives_eperm() {
        let a = attr(FileKind::File, 0, 0o644);
        assert_eq!(check_owner_change(&a, None, None), Ok(()));
        assert_eq!(check_owner_change(&a, Some(501), Some(20)), Ok(()));
        assert_eq!(check_owner_change(&a, Some(0), None), Err(libc::EPERM));
        assert_eq!(check_owner_change(&a, None, Some(0)), Err(libc::EPERM));
    }

    #[test]
    fn open_mode_from_flags() {
        assert_eq!(
            OpenMode::from_flags(libc::O_RDONLY),
            OpenMode {
                write: false,
                append: false,
                truncate: false
            }
        );
        assert!(OpenMode::from_flags(libc::O_WRONLY).write);
        assert!(OpenMode::from_flags(libc::O_RDWR).write);
        let m = OpenMode::from_flags(libc::O_WRONLY | libc::O_APPEND | libc::O_TRUNC);
        assert!(m.write && m.append && m.truncate);
    }

    #[test]
    fn synthetic_ino_is_stable_and_never_zero() {
        let a = VPath::parse("a/b").unwrap();
        assert_eq!(synthetic_ino(&a), synthetic_ino(&a));
        assert_ne!(synthetic_ino(&a), 0);
        assert_ne!(synthetic_ino(&a), ROOT_INO);
        assert_ne!(synthetic_ino(&a) & (1 << 63), 0);
        assert_ne!(synthetic_ino(&VPath::root()), 0);
        assert_ne!(
            synthetic_ino(&a),
            synthetic_ino(&VPath::parse("a/c").unwrap())
        );
    }

    #[test]
    fn unknown_inode_gives_enoent() {
        let f = fx();
        assert_eq!(
            f.fuse.do_getattr(INodeNo(99), None).err(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            f.fuse.do_lookup(INodeNo(99), os("a")).err(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn invalid_names_map_to_errno() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        assert_eq!(
            f.fuse.do_mkdir(root, os("a/b"), 0o755, 0).err(),
            Some(libc::EINVAL)
        );
        let long = "x".repeat(1025);
        assert_eq!(
            f.fuse.do_lookup(root, os(&long)).err(),
            Some(libc::ENAMETOOLONG)
        );
        assert_eq!(
            f.fuse.do_lookup(root, OsStr::from_bytes(b"\xff")).err(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn mkdir_lookup_and_readdir() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let d = f.fuse.do_mkdir(root, os("dir"), 0o777, 0o022).unwrap();
        assert_eq!(d.kind, FileType::Directory);
        assert_eq!(d.perm, 0o755);
        let again = f.fuse.do_lookup(root, os("dir")).unwrap();
        assert_eq!(again.ino, d.ino);
        assert_eq!(f.fuse.do_lookup(root, os("nope")).err(), Some(libc::ENOENT));

        let (file, fh) = f
            .fuse
            .do_create(d.ino, os("f.txt"), 0o666, 0o022, libc::O_WRONLY)
            .unwrap();
        assert_eq!(file.perm, 0o644);
        f.fuse.fs.release(fh).unwrap();

        let entries = list_all(&f.fuse, d.ino);
        let names: Vec<&str> = entries.iter().map(|e| e.2.as_str()).collect();
        assert_eq!(names, vec![".", "..", "f.txt"]);
        assert_eq!(entries[0].0, d.ino.0);
        assert_eq!(entries[1].0, ROOT_INO);
        assert_eq!(entries[2].0, file.ino.0);
        assert_eq!(entries[2].1, FileType::RegularFile);

        // readdir does not add inodes: an unknown entry gets a synthetic ino.
        f.fuse.do_mkdir(root, os("other"), 0o755, 0).unwrap();
        f.fuse.inodes().remove_path(&VPath::parse("other").unwrap());
        let root_entries = list_all(&f.fuse, root);
        let other = root_entries.iter().find(|e| e.2 == "other").unwrap();
        assert_eq!(other.0, synthetic_ino(&VPath::parse("other").unwrap()));
        assert_eq!(
            f.fuse.inodes().ino_of(&VPath::parse("other").unwrap()),
            None
        );
    }

    #[test]
    fn open_write_read_and_truncate() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        assert_eq!(f.fuse.fs.write(fh, 0, b"hello").unwrap(), 5);
        f.fuse.fs.release(fh).unwrap();

        let (fh, _) = f.fuse.do_open(a.ino, libc::O_RDONLY).unwrap();
        assert_eq!(f.fuse.fs.read(fh, 0, 100).unwrap(), b"hello");
        assert_eq!(
            f.fuse.fs.write(fh, 0, b"x").err().map(|e| to_errno(&e)),
            Some(libc::EPERM)
        );
        f.fuse.fs.release(fh).unwrap();

        let (fh, keep) = f
            .fuse
            .do_open(a.ino, libc::O_WRONLY | libc::O_TRUNC)
            .unwrap();
        assert!(!keep, "a truncating open never keeps the cache");
        f.fuse.fs.release(fh).unwrap();
        assert_eq!(f.fuse.do_getattr(a.ino, None).unwrap().size, 0);
    }

    #[test]
    fn create_with_append_writes_at_end() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        f.fuse.fs.write(fh, 0, b"ab").unwrap();
        f.fuse.fs.write(fh, 0, b"cd").unwrap();
        f.fuse.fs.release(fh).unwrap();
        assert_eq!(f.fuse.do_getattr(a.ino, None).unwrap().size, 4);
    }

    #[test]
    fn setattr_size_mode_times_and_owner() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(123_456);
        let changes = SetAttr {
            mode: Some(0o100600),
            size: Some(10),
            mtime: Some(TimeOrNow::SpecificTime(t)),
            atime: Some(TimeOrNow::Now),
            ..SetAttr::default()
        };
        let got = f.fuse.do_setattr(a.ino, None, &changes).unwrap();
        assert_eq!(got.size, 10);
        assert_eq!(got.perm, 0o600);
        assert_eq!(got.mtime, t);
        assert!(got.atime > t);

        let chown = SetAttr {
            uid: Some(got.uid.wrapping_add(1)),
            ..SetAttr::default()
        };
        assert_eq!(
            f.fuse.do_setattr(a.ino, None, &chown).err(),
            Some(libc::EPERM)
        );
        let same = SetAttr {
            uid: Some(got.uid),
            gid: Some(got.gid),
            ..SetAttr::default()
        };
        assert!(f.fuse.do_setattr(a.ino, None, &same).is_ok());
    }

    #[test]
    fn rename_updates_table_and_unlink_removes() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let d = f.fuse.do_mkdir(root, os("d"), 0o755, 0).unwrap();
        let (x, fh) = f
            .fuse
            .do_create(d.ino, os("x"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();

        assert_eq!(
            f.fuse.do_rename(root, os("d"), root, os("e"), 1).err(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            f.fuse
                .do_rename(root, os("missing"), root, os("e"), 0)
                .err(),
            Some(libc::ENOENT)
        );
        f.fuse.do_rename(root, os("d"), root, os("e"), 0).unwrap();
        assert_eq!(
            f.fuse.inodes().path(x.ino.0),
            Some(VPath::parse("e/x").unwrap())
        );
        assert!(f.fuse.do_getattr(x.ino, None).is_ok());

        assert_eq!(f.fuse.do_rmdir(root, os("e")).err(), Some(libc::ENOTEMPTY));
        f.fuse.do_unlink(d.ino, os("x")).unwrap();
        assert_eq!(f.fuse.inodes().path(x.ino.0), None);
        f.fuse.do_rmdir(root, os("e")).unwrap();
        assert_eq!(f.fuse.inodes().path(d.ino.0), None);
    }

    fn stamp(ino: u64, size: u64) -> FileStamp {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        FileStamp {
            dev: 1,
            ino,
            size,
            mtime: t,
            ctime: t,
        }
    }

    #[test]
    fn open_flags_keep_or_drop_the_cache() {
        assert_eq!(open_flags(true), FopenFlags::FOPEN_KEEP_CACHE);
        let drop = open_flags(false);
        assert!(!drop.contains(FopenFlags::FOPEN_KEEP_CACHE));
        #[cfg(target_os = "macos")]
        assert!(drop.contains(FopenFlags::FOPEN_PURGE_UBC | FopenFlags::FOPEN_PURGE_ATTR));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(drop, FopenFlags::empty());
    }

    #[test]
    fn keep_cache_only_for_the_same_state() {
        let a = stamp(5, 100);
        assert!(!keep_cache(None, &a, false), "first open");
        assert!(keep_cache(Some(&a), &a, false));
        assert!(!keep_cache(Some(&a), &a, true), "truncating open");
        assert!(!keep_cache(Some(&a), &stamp(6, 100), false), "other file");
        assert!(!keep_cache(Some(&a), &stamp(5, 101), false), "other size");
        let mut later = a;
        later.ctime += Duration::from_nanos(1);
        assert!(!keep_cache(Some(&a), &later, false), "changed");
    }

    /// Opens `ino` for reading and releases it; returns the keep flag.
    fn open_keep(fuse: &FuseFs, ino: INodeNo) -> bool {
        let (fh, keep) = fuse.do_open(ino, libc::O_RDONLY).unwrap();
        fuse.fs.release(fh).unwrap();
        keep
    }

    #[test]
    fn open_keeps_the_cache_until_the_file_changes() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.write(fh, 0, b"hello").unwrap();
        f.fuse.fs.release(fh).unwrap();
        assert!(!open_keep(&f.fuse, a.ino), "first open");
        assert!(open_keep(&f.fuse, a.ino), "unchanged");
        assert!(open_keep(&f.fuse, a.ino), "still unchanged");
        // ctime moves in ticks of a few ms; change in a later tick.
        std::thread::sleep(Duration::from_millis(50));
        let (fh, _) = f.fuse.do_open(a.ino, libc::O_RDWR).unwrap();
        f.fuse.fs.write(fh, 0, b"HELLO").unwrap();
        f.fuse.fs.release(fh).unwrap();
        assert!(!open_keep(&f.fuse, a.ino), "after a write");
        assert!(open_keep(&f.fuse, a.ino), "unchanged again");
        // Another real file under the name (as after a sync client
        // replaced it): never the old cache.
        let (_, fh) = f
            .fuse
            .do_create(root, os("b"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.write(fh, 0, b"other").unwrap();
        f.fuse.fs.release(fh).unwrap();
        f.fuse
            .fs
            .rename(&VPath::parse("/b").unwrap(), &VPath::parse("/a").unwrap())
            .unwrap();
        assert!(!open_keep(&f.fuse, a.ino), "replaced");
    }

    #[test]
    fn forget_drops_the_stamp_with_the_inode() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        open_keep(&f.fuse, a.ino);
        assert!(f.fuse.stamps().contains_key(&a.ino.0));
        f.fuse.do_lookup(root, os("a")).unwrap();
        f.fuse.do_forget(a.ino, 1);
        assert!(f.fuse.stamps().contains_key(&a.ino.0), "still looked up");
        f.fuse.do_forget(a.ino, 1);
        assert!(!f.fuse.stamps().contains_key(&a.ino.0));
    }

    #[test]
    fn forget_drops_inode() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let d = f.fuse.do_mkdir(root, os("d"), 0o755, 0).unwrap();
        f.fuse.do_lookup(root, os("d")).unwrap();
        f.fuse.inodes().forget(d.ino.0, 2);
        assert_eq!(f.fuse.do_getattr(d.ino, None).err(), Some(libc::ENOENT));
    }

    #[test]
    fn statfs_reports_namelen_255() {
        let f = fx();
        let s = f.fuse.fs.statfs().unwrap();
        assert_eq!(s.namelen, 255);
    }

    /// Runs `f` on another thread while `hold` is in place; returns whether
    /// `f` finished before `hold` was dropped.
    fn finishes_while_held<G>(hold: G, f: impl FnOnce() + Send) -> bool {
        use std::sync::mpsc::{RecvTimeoutError, channel};
        let (tx, rx) = channel();
        std::thread::scope(|s| {
            s.spawn(move || {
                f();
                let _ = tx.send(());
            });
            let early = match rx.recv_timeout(Duration::from_millis(300)) {
                Ok(()) => true,
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => panic!("worker died"),
            };
            drop(hold);
            if !early {
                rx.recv().unwrap();
            }
            early
        })
    }

    #[test]
    fn rename_waits_for_in_flight_lookup() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        f.fuse.do_mkdir(root, os("a"), 0o755, 0).unwrap();
        // A lookup holds the read side from path computation to the table
        // update; a rename must wait for it.
        let in_flight = f.fuse.rename_lock.read().unwrap();
        let fuse = &f.fuse;
        let early = finishes_while_held(in_flight, || {
            fuse.do_rename(root, os("a"), root, os("b"), 0).unwrap();
        });
        assert!(!early, "rename did not wait for the lookup");
        assert!(f.fuse.do_lookup(root, os("b")).is_ok());
    }

    #[test]
    fn lookup_create_mkdir_unlink_wait_for_rename() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let d = f.fuse.do_mkdir(root, os("d"), 0o755, 0).unwrap();
        let (_, fh) = f
            .fuse
            .do_create(d.ino, os("x"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        let fuse = &f.fuse;
        let ops: Vec<Box<dyn FnOnce() + Send + '_>> = vec![
            Box::new(|| assert!(fuse.do_lookup(d.ino, os("x")).is_ok())),
            Box::new(|| assert!(fuse.do_mkdir(d.ino, os("m"), 0o755, 0).is_ok())),
            Box::new(|| {
                let (_, fh) = fuse
                    .do_create(d.ino, os("c"), 0o644, 0, libc::O_RDWR)
                    .unwrap();
                fuse.fs.release(fh).unwrap();
            }),
            Box::new(|| assert!(fuse.do_unlink(d.ino, os("x")).is_ok())),
            Box::new(|| assert!(fuse.do_rmdir(d.ino, os("m")).is_ok())),
        ];
        for op in ops {
            let renaming = f.fuse.rename_lock.write().unwrap();
            assert!(!finishes_while_held(renaming, op), "op did not wait");
        }
    }

    #[test]
    fn open_and_setattr_wait_for_rename() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (x, fh) = f
            .fuse
            .do_create(root, os("x"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        let fuse = &f.fuse;
        let truncate = SetAttr {
            size: Some(0),
            ..SetAttr::default()
        };
        let chmod = SetAttr {
            mode: Some(0o600),
            ..SetAttr::default()
        };
        let ops: Vec<Box<dyn FnOnce() + Send + '_>> = vec![
            Box::new(|| {
                let (fh, _) = fuse.do_open(x.ino, libc::O_RDWR | libc::O_TRUNC).unwrap();
                fuse.fs.release(fh).unwrap();
            }),
            Box::new(|| assert!(fuse.do_setattr(x.ino, None, &truncate).is_ok())),
            Box::new(|| assert!(fuse.do_setattr(x.ino, None, &chmod).is_ok())),
        ];
        for op in ops {
            let renaming = f.fuse.rename_lock.write().unwrap();
            assert!(!finishes_while_held(renaming, op), "op did not wait");
        }
    }

    #[test]
    fn rename_race_cannot_leave_stale_path() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let a = f.fuse.do_mkdir(root, os("a"), 0o755, 0).unwrap();
        let (x, fh) = f
            .fuse
            .do_create(a.ino, os("x"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        f.fuse.do_rename(root, os("a"), root, os("b"), 0).unwrap();
        // A lookup under the moved directory sees the new path only.
        let again = f.fuse.do_lookup(a.ino, os("x")).unwrap();
        assert_eq!(again.ino, x.ino);
        assert_eq!(f.fuse.inodes().ino_of(&VPath::parse("a/x").unwrap()), None);
    }

    #[test]
    fn readdir_snapshot_survives_deletes() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let d = f.fuse.do_mkdir(root, os("big"), 0o755, 0).unwrap();
        let mut want: Vec<String> = (0..200).map(|i| format!("f{i:03}")).collect();
        for n in &want {
            let (_, fh) = f
                .fuse
                .do_create(d.ino, os(n), 0o644, 0, libc::O_RDWR)
                .unwrap();
            f.fuse.fs.release(fh).unwrap();
        }
        let dh = f.fuse.do_opendir(d.ino).unwrap();
        let first = f.fuse.do_readdir(d.ino, dh, 0, 50).unwrap();
        assert_eq!(first.len(), 50);
        let mut seen: Vec<String> = Vec::new();
        for (_, (_, _, name)) in &first {
            seen.push(name.clone());
            if name != "." && name != ".." {
                f.fuse.do_unlink(d.ino, os(name)).unwrap();
            }
        }
        let mut offset = first.last().unwrap().0;
        loop {
            let page = f.fuse.do_readdir(d.ino, dh, offset, 50).unwrap();
            let Some(last) = page.last() else { break };
            offset = last.0;
            seen.extend(page.into_iter().map(|(_, (_, _, n))| n));
        }
        f.fuse.do_releasedir(dh).unwrap();
        want.push(".".into());
        want.push("..".into());
        want.sort();
        seen.sort();
        assert_eq!(seen, want);
    }

    #[test]
    fn readdir_offset_zero_refreshes_and_releasedir_drops() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let dh = f.fuse.do_opendir(root).unwrap();
        assert_eq!(f.fuse.do_readdir(root, dh, 0, usize::MAX).unwrap().len(), 2);
        f.fuse.do_mkdir(root, os("new"), 0o755, 0).unwrap();
        // Later pages come from the snapshot ...
        assert!(
            f.fuse
                .do_readdir(root, dh, 2, usize::MAX)
                .unwrap()
                .is_empty()
        );
        // ... and offset 0 (rewinddir) lists again.
        let lines = f.fuse.do_readdir(root, dh, 0, usize::MAX).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2].1.2, "new");
        assert_eq!(lines.iter().map(|l| l.0).collect::<Vec<_>>(), vec![1, 2, 3]);
        f.fuse.do_releasedir(dh).unwrap();
        assert_eq!(
            f.fuse.do_readdir(root, dh, 0, usize::MAX).err(),
            Some(libc::EBADF)
        );
        assert_eq!(f.fuse.do_releasedir(dh).err(), Some(libc::EBADF));
        assert_eq!(f.fuse.do_opendir(INodeNo(99)).err(), Some(libc::ENOENT));
    }

    #[test]
    fn getattr_and_ftruncate_by_handle_after_unlink() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.write(fh, 0, b"0123456789").unwrap();
        f.fuse.do_unlink(root, os("a")).unwrap();
        assert_eq!(f.fuse.do_getattr(a.ino, None).err(), Some(libc::ENOENT));
        let got = f.fuse.do_getattr(a.ino, Some(fh)).unwrap();
        assert_eq!(got.size, 10);
        assert_eq!(got.ino, a.ino);
        let shrink = SetAttr {
            size: Some(4),
            ..SetAttr::default()
        };
        assert_eq!(f.fuse.do_setattr(a.ino, Some(fh), &shrink).unwrap().size, 4);
        f.fuse.fs.release(fh).unwrap();
    }

    #[test]
    fn getattr_with_stale_handle_falls_back_to_path() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (a, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.release(fh).unwrap();
        assert_eq!(f.fuse.do_getattr(a.ino, Some(fh)).unwrap().size, 0);
    }

    #[test]
    fn dir_handles_have_high_bit_and_are_not_file_handles() {
        let f = fx();
        let root = INodeNo(ROOT_INO);
        let (_, fh) = f
            .fuse
            .do_create(root, os("a"), 0o644, 0, libc::O_RDWR)
            .unwrap();
        f.fuse.fs.write(fh, 0, b"abc").unwrap();
        let d = f.fuse.do_mkdir(root, os("d"), 0o755, 0).unwrap();
        let dh = f.fuse.do_opendir(d.ino).unwrap();
        assert_ne!(dh & DIR_FH_BIT, 0);
        assert_eq!(fh.0 & DIR_FH_BIT, 0);
        // Directory handles are never used for handle lookups.
        assert_eq!(file_handle_only(Some(FileHandleId(dh))), None);
        assert_eq!(file_handle_only(Some(fh)), Some(fh));
        let got = f.fuse.do_getattr(d.ino, Some(FileHandleId(dh))).unwrap();
        assert_eq!(got.kind, FileType::Directory);
        let chmod = SetAttr {
            mode: Some(0o700),
            ..SetAttr::default()
        };
        let got = f
            .fuse
            .do_setattr(d.ino, Some(FileHandleId(dh)), &chmod)
            .unwrap();
        assert_eq!(got.kind, FileType::Directory);
        f.fuse.do_releasedir(dh).unwrap();
        f.fuse.fs.release(fh).unwrap();
    }
}
