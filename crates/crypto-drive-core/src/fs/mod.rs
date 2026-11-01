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

//! The path based file system over the encrypted directory (spec 5).

pub(crate) mod dirs;
pub(crate) mod dirstate;
mod files;
pub(crate) mod listing;
mod path;
pub(crate) mod rename;

pub use path::VPath;

use crate::backing::DirHandle;
use crate::error::Result;
use crate::file::OpenFile;
use crate::keys::DirId;
use crate::names::NameKeys;
use crate::vault::{UnlockedVault, VaultKeys};
use dirstate::DirState;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

/// Most directory states kept in the cache.
const MAX_CACHE_CAPACITY: usize = 1024;

/// Fewest directory states kept in the cache, also with a very low
/// open-file limit.
const MIN_CACHE_CAPACITY: usize = 16;

/// The directory cache may use one part in `CACHE_FD_SHARE` of the
/// open-file limit. Every cached directory state holds an open file
/// descriptor; the rest of the limit stays for open files, the FUSE device
/// and the libraries.
const CACHE_FD_SHARE: u64 = 4;

/// Size of the directory cache for the soft open-file limit
/// `RLIMIT_NOFILE` (`None`: no limit). macOS terminals often start with a
/// soft limit of 256, Linux with 1024; a cache of 1024 open directories
/// then made every later open fail with EMFILE.
fn dir_cache_capacity(soft_limit: Option<u64>) -> NonZeroUsize {
    let share = soft_limit.map_or(u64::MAX, |l| l / CACHE_FD_SHARE);
    let n = usize::try_from(share)
        .unwrap_or(usize::MAX)
        .clamp(MIN_CACHE_CAPACITY, MAX_CACHE_CAPACITY);
    NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN)
}

/// The current soft open-file limit of the process (`None`: no limit).
fn soft_open_file_limit() -> Option<u64> {
    rustix::process::getrlimit(rustix::process::Resource::Nofile).current
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
}

/// Attributes of an entry. `mode` holds only the permission bits (0o7777).
#[derive(Clone, Debug)]
pub struct Attr {
    pub kind: FileKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub nlink: u32,
}

/// One state of the real content file of an entry. If the real file is
/// replaced or changed (also from outside, by a sync client), at least
/// one field changes: a new file has another inode, a write changes the
/// ctime (which cannot be set by hand). A change in the same ctime tick
/// (the kernel clock moves in steps of a few milliseconds) that keeps the
/// size is not seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: FileKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileHandleId(pub u64);

#[derive(Clone, Debug)]
pub struct StatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

/// Identifies a real file: (dev, ino).
type RealFileId = (u64, u64);

/// The drive: clear paths over the encrypted vault directory.
pub struct CryptoFs {
    root: Arc<DirHandle>,
    /// Names of every epoch; new names use the write epoch.
    names: NameKeys,
    /// The keys of every epoch in the key set; files are opened with the
    /// key of their header epoch.
    keys: VaultKeys,
    /// The vault pads file sizes (marker flag `pad_sizes`).
    padded: bool,
    max_name_length: u16,
    /// The root has no `.cd-dir`; its id is the vault id.
    root_id: DirId,
    cache: Mutex<LruCache<VPath, Arc<DirState>>>,
    /// The data every state of one real directory shares (change lock,
    /// name index, mtime), by (dev, ino) and canonical id of the real
    /// directory.
    shared_dirs: Mutex<HashMap<(u64, u64, DirId), Weak<dirstate::SharedDir>>>,
    next_generation: AtomicU64,
    /// The shared state of each open real file.
    open_files: Mutex<HashMap<RealFileId, Weak<Mutex<OpenFile>>>>,
    handles: Mutex<HashMap<FileHandleId, files::Handle>>,
    /// The next file handle id; ids are never reused.
    next_handle: AtomicU64,
}

// The FUSE adapter shares one `CryptoFs` between threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CryptoFs>();
};

impl CryptoFs {
    pub fn new(vault: UnlockedVault) -> Result<CryptoFs> {
        let root = DirHandle::open_root(&vault.root_path)?;
        let names = NameKeys::new(&vault.keys);
        Ok(CryptoFs {
            root: Arc::new(root),
            names,
            keys: vault.keys,
            padded: vault.marker.pad_sizes,
            max_name_length: vault.marker.max_name_length,
            root_id: vault.marker.vault_id,
            cache: Mutex::new(LruCache::new(dir_cache_capacity(soft_open_file_limit()))),
            shared_dirs: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(0),
            open_files: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::keys::{DirId, MasterKey};
    use crate::names::{LONG_PREFIX, NameKeys};
    use crate::testutil::{real_name_of, test_vault, test_vault_with};
    use crate::vault::{CONTROL_PREFIX, DIR_FILE, NAME_FILE, open_with_master_key};
    use std::path::{Path, PathBuf};

    #[test]
    fn dir_cache_capacity_follows_the_open_file_limit() {
        let cap = |l| dir_cache_capacity(l).get();
        assert_eq!(cap(Some(256)), 64);
        assert_eq!(cap(Some(1024)), 256);
        assert_eq!(cap(Some(10240)), MAX_CACHE_CAPACITY);
        assert_eq!(cap(None), MAX_CACHE_CAPACITY);
        assert_eq!(cap(Some(u64::MAX)), MAX_CACHE_CAPACITY);
        assert_eq!(cap(Some(20)), MIN_CACHE_CAPACITY);
        assert_eq!(cap(Some(0)), MIN_CACHE_CAPACITY);
    }

    struct Fx {
        _tmp: tempfile::TempDir,
        fs: CryptoFs,
        root: PathBuf,
        mk: MasterKey,
        names: NameKeys,
        vault_id: DirId,
    }

    fn fx_from((tmp, v, mk): (tempfile::TempDir, UnlockedVault, MasterKey)) -> Fx {
        let names = NameKeys::new(&v.keys);
        let root = v.root_path.clone();
        let vault_id = v.marker.vault_id;
        let fs = CryptoFs::new(v).unwrap();
        Fx {
            _tmp: tmp,
            fs,
            root,
            mk,
            names,
            vault_id,
        }
    }

    fn fx() -> Fx {
        fx_from(test_vault())
    }

    impl Fx {
        /// A real name for `name` in the root, as an entry with id `[0; 16]`.
        fn enc(&self, name: &str) -> String {
            self.names
                .encrypt_write(&self.vault_id, &[0u8; 16], name)
                .unwrap()
        }

        /// The real path of the existing entry `name` in the root.
        fn real(&self, name: &str) -> PathBuf {
            self.root
                .join(real_name_of(&self.names, &self.vault_id, &self.root, name))
        }
    }

    fn fx_with(max: u16) -> Fx {
        fx_from(test_vault_with(max))
    }

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    fn listed(fs: &CryptoFs, path: &str) -> Vec<String> {
        fs.readdir(&p(path))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    /// All real entry names of a directory, sorted.
    fn real_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// Real entry names that are not control files (long entries count).
    fn user_names(dir: &Path) -> Vec<String> {
        real_names(dir)
            .into_iter()
            .filter(|n| !n.starts_with(CONTROL_PREFIX) || n.starts_with(LONG_PREFIX))
            .collect()
    }

    /// The single real entry of `dir` that is not a control file.
    fn only_entry(dir: &Path) -> PathBuf {
        let v = user_names(dir);
        assert_eq!(v.len(), 1, "entries: {v:?}");
        dir.join(&v[0])
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn crypto_fs_is_send_and_sync() {
        assert_send_sync::<CryptoFs>();
    }

    #[test]
    fn vpath_parse_and_helpers() {
        assert!(VPath::parse("").unwrap().is_root());
        assert!(VPath::parse("/").unwrap().is_root());
        assert_eq!(VPath::root(), p("/"));
        assert_eq!(p("/a/b"), p("a/b"));
        assert!(matches!(VPath::parse("a//b"), Err(Error::InvalidName)));
        assert!(matches!(VPath::parse("a/"), Err(Error::InvalidName)));
        assert!(matches!(VPath::parse("a/../b"), Err(Error::InvalidName)));
        assert!(matches!(VPath::parse("a/./b"), Err(Error::InvalidName)));
        let long = "x".repeat(1025);
        assert!(matches!(VPath::parse(&long), Err(Error::NameTooLong)));
        let ab = p("a/b");
        assert_eq!(ab.name(), Some("b"));
        assert_eq!(ab.parent(), Some(p("a")));
        assert_eq!(p("a").parent(), Some(VPath::root()));
        assert_eq!(VPath::root().parent(), None);
        assert_eq!(VPath::root().name(), None);
        assert_eq!(p("a").join("b").unwrap(), ab);
        assert!(matches!(p("a").join("b/c"), Err(Error::InvalidName)));
        assert!(ab.starts_with(&p("a")));
        assert!(ab.starts_with(&ab));
        assert!(ab.starts_with(&VPath::root()));
        assert!(!p("ab").starts_with(&p("a")));
        assert!(!p("a").starts_with(&ab));
        assert_eq!(ab.replace_prefix(&p("a"), &p("x/y")), Some(p("x/y/b")));
        assert_eq!(ab.replace_prefix(&ab, &p("z")), Some(p("z")));
        assert_eq!(ab.replace_prefix(&p("c"), &p("z")), None);
    }

    #[test]
    fn vpath_normalizes_to_nfc() {
        assert_eq!(p("cafe\u{301}"), p("caf\u{e9}"));
        assert_eq!(p("cafe\u{301}").name(), Some("caf\u{e9}"));
    }

    #[test]
    fn mkdir_readdir_getattr() {
        let f = fx();
        let a = f.fs.mkdir(&p("a"), 0o755).unwrap();
        assert_eq!(a.kind, FileKind::Directory);
        assert_eq!(a.nlink, 2);
        f.fs.mkdir(&p("a/b"), 0o700).unwrap();
        assert_eq!(
            f.fs.readdir(&VPath::root()).unwrap(),
            vec![DirEntry {
                name: "a".into(),
                kind: FileKind::Directory
            }]
        );
        assert_eq!(listed(&f.fs, "a"), vec!["b"]);
        let b = f.fs.getattr(&p("a/b")).unwrap();
        assert_eq!(b.kind, FileKind::Directory);
        assert_eq!(b.mode & 0o777, 0o700);
        assert_eq!(b.nlink, 2);
        let root = f.fs.getattr(&VPath::root()).unwrap();
        assert_eq!(root.kind, FileKind::Directory);
    }

    #[test]
    fn real_tree_holds_no_clear_names() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p("a/b"), 0o755).unwrap();
        let real_a = only_entry(&f.root);
        let inside = real_names(&real_a);
        assert_eq!(inside.len(), 2, "{inside:?}");
        assert!(inside.contains(&DIR_FILE.to_string()));
        assert_eq!(std::fs::read(real_a.join(DIR_FILE)).unwrap().len(), 16);
        let real_b = only_entry(&real_a);
        assert_eq!(std::fs::read(real_b.join(DIR_FILE)).unwrap().len(), 16);
        for n in real_names(&f.root)
            .into_iter()
            .chain(inside)
            .chain(real_names(&real_b))
        {
            assert!(n != "a" && n != "b", "clear name {n} in the real tree");
        }
    }

    #[test]
    fn missing_and_existing() {
        let f = fx();
        assert!(matches!(f.fs.getattr(&p("nope")), Err(Error::NotFound)));
        assert!(matches!(f.fs.getattr(&p("nope/x")), Err(Error::NotFound)));
        assert!(matches!(f.fs.readdir(&p("nope")), Err(Error::NotFound)));
        assert!(matches!(
            f.fs.mkdir(&p("nope/x"), 0o755),
            Err(Error::NotFound)
        ));
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        assert!(matches!(
            f.fs.mkdir(&p("a"), 0o755),
            Err(Error::AlreadyExists)
        ));
        assert!(matches!(
            f.fs.mkdir(&VPath::root(), 0o755),
            Err(Error::AlreadyExists)
        ));
    }

    fn dev_ino(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn fsync_with_a_path_syncs_the_directory_of_the_entry() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let (_, h) = f.fs.create(&p("d/x"), 0o644).unwrap();
        f.fs.write(h, 0, b"data").unwrap();
        crate::backing::take_synced_dirs();
        f.fs.fsync(h, None).unwrap();
        assert!(crate::backing::take_synced_dirs().is_empty());
        f.fs.fsync(h, Some(&p("d/x"))).unwrap();
        assert_eq!(
            crate::backing::take_synced_dirs(),
            vec![dev_ino(&f.real("d"))]
        );
        f.fs.release(h).unwrap();
    }

    #[test]
    fn fsync_of_a_long_name_syncs_its_entry_directory_too() {
        let f = fx_with(64);
        let name = "n".repeat(100);
        let (_, h) = f.fs.create(&p(&name), 0o644).unwrap();
        let entry = only_entry(&f.root);
        crate::backing::take_synced_dirs();
        f.fs.fsync(h, Some(&p(&name))).unwrap();
        assert_eq!(
            crate::backing::take_synced_dirs(),
            vec![dev_ino(&entry), dev_ino(&f.root)]
        );
        f.fs.release(h).unwrap();
    }

    #[test]
    fn fsync_of_a_removed_file_still_syncs_the_file() {
        let f = fx();
        let (_, h) = f.fs.create(&p("x"), 0o644).unwrap();
        f.fs.write(h, 0, b"data").unwrap();
        f.fs.unlink(&p("x")).unwrap();
        crate::backing::take_synced_dirs();
        f.fs.fsync(h, Some(&p("x"))).unwrap();
        assert!(crate::backing::take_synced_dirs().is_empty());
        f.fs.release(h).unwrap();
    }

    #[test]
    fn fsyncdir_syncs_the_real_directory() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        crate::backing::take_synced_dirs();
        f.fs.fsyncdir(&p("d")).unwrap();
        f.fs.fsyncdir(&VPath::root()).unwrap();
        assert_eq!(
            crate::backing::take_synced_dirs(),
            vec![dev_ino(&f.real("d")), dev_ino(&f.root)]
        );
        assert!(matches!(f.fs.fsyncdir(&p("missing")), Err(Error::NotFound)));
    }

    #[test]
    fn long_names() {
        let f = fx_with(64);
        let name = "n".repeat(100);
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        let entry = only_entry(&f.root);
        let entry_name = entry.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(entry_name.starts_with(LONG_PREFIX));
        assert_eq!(entry_name.len(), 50);
        assert!(entry.join(NAME_FILE).is_file());
        assert_eq!(listed(&f.fs, "/"), vec![name.clone()]);
        let attr = f.fs.getattr(&p(&name)).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);
        let child = format!("{name}/{}", "c".repeat(90));
        f.fs.mkdir(&p(&child), 0o755).unwrap();
        assert_eq!(listed(&f.fs, &name), vec!["c".repeat(90)]);
        assert_eq!(f.fs.getattr(&p(&child)).unwrap().kind, FileKind::Directory);
    }

    #[test]
    fn longest_clear_name_works() {
        let f = fx();
        let name = "\u{e9}".repeat(512);
        assert_eq!(name.len(), 1024);
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec![name.clone()]);
        assert!(matches!(
            VPath::root().join(&format!("{name}x")),
            Err(Error::NameTooLong)
        ));
    }

    #[test]
    fn long_entry_with_wrong_name_file_is_hidden() {
        let f = fx_with(64);
        let name = "n".repeat(100);
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        let entry = only_entry(&f.root);
        let other = f.enc(&"m".repeat(100));
        std::fs::write(entry.join(NAME_FILE), other).unwrap();
        // The root mtime did not change, so a new instance builds the index.
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        assert!(listed(&fs, "/").is_empty());
        assert!(matches!(fs.getattr(&p(&name)), Err(Error::NotFound)));
    }

    #[test]
    fn foreign_entries_are_hidden() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        std::fs::write(f.root.join(".DS_Store"), b"x").unwrap();
        std::fs::write(f.root.join("garbage (1)"), b"x").unwrap();
        std::fs::create_dir(f.root.join("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["a"]);
    }

    #[test]
    fn second_instance_changes_are_seen() {
        let f = fx();
        assert!(listed(&f.fs, "/").is_empty());
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "a"), Vec::<String>::new());
        let v2 = open_with_master_key(&f.root, &f.mk).unwrap();
        let fs2 = CryptoFs::new(v2).unwrap();
        fs2.mkdir(&p("x"), 0o755).unwrap();
        fs2.mkdir(&p("a/y"), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["a", "x"]);
        assert_eq!(listed(&f.fs, "a"), vec!["y"]);
    }

    #[test]
    fn outside_rename_of_cached_dir_is_seen() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p("a/b"), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "a"), vec!["b"]);
        let real_a = only_entry(&f.root);
        std::fs::rename(&real_a, f.root.join(".hidden")).unwrap();
        assert!(matches!(f.fs.readdir(&p("a")), Err(Error::NotFound)));
        assert!(matches!(f.fs.getattr(&p("a/b")), Err(Error::NotFound)));
    }

    #[test]
    fn two_dir_ids_are_both_used() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.mkdir(&p("d/c"), 0o755).unwrap();
        let real_d = f.real("d");
        // A merged directory of another device: its `.cd-dir` became a
        // conflict copy, and its child "e" is named under that id.
        let other: DirId = crate::secret::random_bytes::<16>().unwrap();
        std::fs::write(real_d.join(".cd-dir (conflicted copy)"), other).unwrap();
        let e_id: DirId = crate::secret::random_bytes::<16>().unwrap();
        let e = f.names.encrypt_write(&other, &e_id, "e").unwrap();
        std::fs::create_dir(real_d.join(&e)).unwrap();
        std::fs::write(real_d.join(&e).join(DIR_FILE), e_id).unwrap();
        std::fs::write(real_d.join(".cd-dir.tmp"), [0u8; 16]).unwrap();
        f.fs.mkdir(&p("d/g"), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["c", "e", "g"]);
        assert_eq!(f.fs.getattr(&p("d/c")).unwrap().kind, FileKind::Directory);
        assert_eq!(f.fs.getattr(&p("d/e")).unwrap().kind, FileKind::Directory);
        assert!(f.fs.readdir(&p("d/e")).unwrap().is_empty());
        // New entries use the canonical id.
        let canonical: DirId = std::fs::read(real_d.join(DIR_FILE))
            .unwrap()
            .try_into()
            .unwrap();
        real_name_of(&f.names, &canonical, &real_d, "g");
    }

    /// A known gap (README, threat model): a copy of the `.cd-dir` of `a`
    /// put into `b` lets a file moved from `a` to `b` be read there. It is
    /// not detected, but a warning is logged, once per directory.
    #[test]
    fn move_with_a_planted_dir_id_copy_is_read_and_warned_once() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p("b"), 0o755).unwrap();
        let (_, h) = f.fs.create(&p("a/x"), 0o644).unwrap();
        f.fs.write(h, 0, b"secret").unwrap();
        f.fs.release(h).unwrap();
        let (real_a, real_b) = (f.real("a"), f.real("b"));
        // Listing a normal directory logs nothing.
        let before = listing::extra_id_warnings();
        assert_eq!(listed(&f.fs, "b"), Vec::<String>::new());
        assert_eq!(listing::extra_id_warnings(), before);

        let x = only_entry(&real_a);
        std::fs::rename(&x, real_b.join(x.file_name().unwrap())).unwrap();
        std::fs::copy(real_a.join(DIR_FILE), real_b.join(".cd-dir 2")).unwrap();
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        assert_eq!(listed(&fs, "b"), vec!["x"]);
        let h = fs.open(&p("b/x"), false, false).unwrap();
        assert_eq!(fs.read(h, 0, 100).unwrap(), b"secret");
        fs.release(h).unwrap();
        assert_eq!(listing::extra_id_warnings(), before + 1);

        // An outside change makes a new listing, but no second warning.
        std::fs::write(real_b.join("foreign"), b"").unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::open(&real_b)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let built = listing::listings_built();
        assert_eq!(listed(&fs, "b"), vec!["x"]);
        assert!(listing::listings_built() > built);
        assert_eq!(listing::extra_id_warnings(), before + 1);
    }

    #[test]
    fn swapped_directories_are_auth_failed() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p("b"), 0o755).unwrap();
        f.fs.mkdir(&p("a/x"), 0o755).unwrap();
        let (_, h) = f.fs.create(&p("b/y"), 0o644).unwrap();
        f.fs.release(h).unwrap();
        let (real_a, real_b) = (f.real("a"), f.real("b"));
        let id_a = std::fs::read(real_a.join(DIR_FILE)).unwrap();
        let id_b = std::fs::read(real_b.join(DIR_FILE)).unwrap();
        std::fs::write(real_a.join(DIR_FILE), &id_b).unwrap();
        std::fs::write(real_b.join(DIR_FILE), &id_a).unwrap();
        let mut before = Vec::new();
        for d in [&real_a, &real_b] {
            before.push(real_names(d));
        }
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        for d in ["a", "b"] {
            let r = fs.readdir(&p(d));
            assert!(matches!(r, Err(Error::AuthFailed { .. })), "{d}: {r:?}");
        }
        assert!(matches!(
            fs.getattr(&p("a/x")),
            Err(Error::AuthFailed { .. })
        ));
        assert!(matches!(
            fs.mkdir(&p("b/z"), 0o755),
            Err(Error::AuthFailed { .. })
        ));
        assert_eq!(before, vec![real_names(&real_a), real_names(&real_b)]);
        assert_eq!(listed(&fs, "/"), vec!["a", "b"]);
    }

    #[test]
    fn bad_dir_id_is_invalid_format() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let real_d = only_entry(&f.root);
        std::fs::write(real_d.join(DIR_FILE), [1u8; 15]).unwrap();
        let v2 = open_with_master_key(&f.root, &f.mk).unwrap();
        let fs2 = CryptoFs::new(v2).unwrap();
        assert!(matches!(
            fs2.readdir(&p("d")),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn conflict_copies_are_shown() {
        let f = fx();
        f.fs.mkdir(&p("d.txt"), 0o755).unwrap();
        let real = only_entry(&f.root);
        let real_name = real.file_name().unwrap().to_str().unwrap().to_owned();
        for suffix in [" (1)", "-DESKTOP1"] {
            let copy = f.root.join(format!("{real_name}{suffix}"));
            std::fs::create_dir(&copy).unwrap();
            std::fs::copy(real.join(DIR_FILE), copy.join(DIR_FILE)).unwrap();
        }
        // N follows the real name order: " (1)" sorts before "-DESKTOP1".
        assert_eq!(
            listed(&f.fs, "/"),
            vec!["d (conflict 1).txt", "d (conflict 2).txt", "d.txt"]
        );
        let attr = f.fs.getattr(&p("d (conflict 2).txt")).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);
        assert!(f.fs.readdir(&p("d (conflict 1).txt")).unwrap().is_empty());
    }

    #[test]
    fn conflict_copy_is_found_without_a_prior_listing() {
        let f = fx();
        f.fs.mkdir(&p("d.txt"), 0o755).unwrap();
        let real = only_entry(&f.root);
        let real_name = real.file_name().unwrap().to_str().unwrap().to_owned();
        let copy = f.root.join(format!("{real_name} (1)"));
        std::fs::create_dir(&copy).unwrap();
        std::fs::copy(real.join(DIR_FILE), copy.join(DIR_FILE)).unwrap();
        // A fresh instance has no cached listing.
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        let attr = fs.getattr(&p("d (conflict 1).txt")).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);
    }

    #[test]
    fn repeated_lookups_build_the_index_once() {
        let f = fx();
        f.fs.mkdir(&p("/d"), 0o755).unwrap();
        let built = listing::listings_built();
        for _ in 0..10 {
            assert!(f.fs.getattr(&p("/d")).is_ok());
            assert!(matches!(f.fs.getattr(&p("/nope")), Err(Error::NotFound)));
        }
        // mkdir built the index and kept it.
        assert_eq!(listing::listings_built(), built);
    }

    /// Two live states of one real directory (a cold load race: the cache
    /// may keep the one that was stored last). An own create through one of
    /// them must be seen through the other. With `coarse`, the real mtime is
    /// set back after the create, as on a file system where both land in
    /// one mtime tick.
    fn second_state_sees_own_create(coarse: bool) {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        // State C, built by another thread, with its index built.
        f.fs.cache.lock().unwrap().pop(&p("d"));
        let sc = f.fs.dir_state(&p("d")).unwrap();
        f.fs.cache.lock().unwrap().pop(&p("d"));
        assert!(f.fs.find(&sc, "zz").is_err());
        let before = sc.mtime();
        // State A is the cached one when the create runs.
        let sa = f.fs.dir_state(&p("d")).unwrap();
        assert!(!Arc::ptr_eq(&sa, &sc));
        let (_, h) = f.fs.create(&p("d/x"), 0o644).unwrap();
        f.fs.release(h).unwrap();
        drop(sa);
        let real_d = only_entry(&f.root);
        if coarse {
            std::fs::File::open(&real_d)
                .unwrap()
                .set_modified(before)
                .unwrap();
        }
        // The store of C lands last.
        f.fs.cache.lock().unwrap().put(p("d"), sc);
        assert_eq!(f.fs.getattr(&p("d/x")).unwrap().kind, FileKind::File);
        assert!(matches!(
            f.fs.create(&p("d/x"), 0o644),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(user_names(&real_d).len(), 1);
        assert_eq!(listed(&f.fs, "d"), vec!["x"]);
    }

    #[test]
    fn second_state_sees_own_create_same_tick() {
        second_state_sees_own_create(false);
    }

    #[test]
    fn second_state_sees_own_create_coarse_mtime() {
        second_state_sees_own_create(true);
    }

    #[test]
    fn create_many_files_builds_index_once() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let built = listing::listings_built();
        let start = std::time::Instant::now();
        for i in 0..2000 {
            let path = p(&format!("d/f{i}"));
            assert!(matches!(f.fs.getattr(&path), Err(Error::NotFound)));
            let (_, h) = f.fs.create(&path, 0o644).unwrap();
            f.fs.release(h).unwrap();
        }
        let took = start.elapsed();
        assert!(listing::listings_built() <= built + 1);
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
        assert_eq!(f.fs.readdir(&p("d")).unwrap().len(), 2000);
    }

    #[test]
    fn outside_changes_are_seen() {
        // Each change of the second instance lands in another mtime tick
        // than the last change of the first one. Within one tick an outside
        // change can stay unseen (HS 3.3, documented limit).
        let tick = || std::thread::sleep(std::time::Duration::from_millis(20));
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let (_, h) = f.fs.create(&p("d/a"), 0o644).unwrap();
        f.fs.release(h).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["a"]);
        let fs2 = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        tick();
        let (_, h) = fs2.create(&p("d/b"), 0o644).unwrap();
        fs2.release(h).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["a", "b"]);
        assert!(f.fs.getattr(&p("d/b")).is_ok());
        tick();
        fs2.rename(&p("d/b"), &p("d/c")).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["a", "c"]);
        assert!(matches!(f.fs.getattr(&p("d/b")), Err(Error::NotFound)));
        assert!(f.fs.getattr(&p("d/c")).is_ok());
        tick();
        fs2.unlink(&p("d/a")).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["c"]);
        assert!(matches!(f.fs.getattr(&p("d/a")), Err(Error::NotFound)));
        // An outside change followed by an own change: the own change must
        // not hide the outside one.
        tick();
        fs2.mkdir(&p("d/e"), 0o755).unwrap();
        tick();
        let (_, h) = f.fs.create(&p("d/g"), 0o644).unwrap();
        f.fs.release(h).unwrap();
        assert_eq!(listed(&f.fs, "d"), vec!["c", "e", "g"]);
        assert_eq!(f.fs.getattr(&p("d/e")).unwrap().kind, FileKind::Directory);
    }

    #[test]
    fn concurrent_creates_of_one_name_make_one_entry() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let rounds = 50;
        for i in 0..rounds {
            let path = p(&format!("d/n{i}"));
            let barrier = std::sync::Barrier::new(2);
            let results: Vec<Result<()>> = std::thread::scope(|s| {
                let run = || {
                    barrier.wait();
                    let (_, h) = f.fs.create(&path, 0o644)?;
                    f.fs.release(h)
                };
                let a = s.spawn(run);
                let b = s.spawn(run);
                vec![a.join().unwrap(), b.join().unwrap()]
            });
            assert_eq!(
                results.iter().filter(|r| r.is_ok()).count(),
                1,
                "{results:?}"
            );
            assert!(
                results
                    .iter()
                    .any(|r| matches!(r, Err(Error::AlreadyExists))),
                "{results:?}"
            );
        }
        let real_d = only_entry(&f.root);
        assert_eq!(user_names(&real_d).len(), rounds);
        assert_eq!(listed(&f.fs, "d").len(), rounds);
    }

    #[test]
    fn conflict_display_name_collision_takes_next_number() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        let real = only_entry(&f.root);
        f.fs.mkdir(&p("d (conflict 1)"), 0o755).unwrap();
        let real_name = real.file_name().unwrap().to_str().unwrap().to_owned();
        let copy = f.root.join(format!("{real_name} (1)"));
        std::fs::create_dir(&copy).unwrap();
        std::fs::copy(real.join(DIR_FILE), copy.join(DIR_FILE)).unwrap();
        assert_eq!(
            listed(&f.fs, "/"),
            vec!["d", "d (conflict 1)", "d (conflict 2)"]
        );
        assert!(matches!(
            f.fs.mkdir(&p("d (conflict 2)"), 0o755),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn long_conflict_copy_is_shown() {
        let f = fx_with(64);
        let name = "n".repeat(100);
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        let entry = only_entry(&f.root);
        let mut moved = entry.clone().into_os_string();
        moved.push(" (1)");
        std::fs::rename(&entry, &moved).unwrap();
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        assert_eq!(
            listed(&f.fs, "/"),
            vec![name.clone(), format!("{name} (conflict 1)")]
        );
    }

    #[test]
    fn files_are_listed_and_sized() {
        let f = fx();
        let enc = f.enc("f");
        std::fs::write(f.root.join(&enc), [0u8; 81 + 10]).unwrap();
        let bad = f.enc("bad");
        std::fs::write(f.root.join(&bad), [0u8; 10]).unwrap();
        assert_eq!(
            f.fs.readdir(&VPath::root()).unwrap(),
            vec![
                DirEntry {
                    name: "bad".into(),
                    kind: FileKind::File
                },
                DirEntry {
                    name: "f".into(),
                    kind: FileKind::File
                },
            ]
        );
        let attr = f.fs.getattr(&p("f")).unwrap();
        assert_eq!(attr.kind, FileKind::File);
        assert_eq!(attr.size, 10);
        assert_eq!(attr.nlink, 1);
        assert!(matches!(
            f.fs.getattr(&p("bad")),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(matches!(f.fs.readdir(&p("f")), Err(Error::NotADirectory)));
        assert!(matches!(
            f.fs.mkdir(&p("f/x"), 0o755),
            Err(Error::NotADirectory)
        ));
        assert!(matches!(
            f.fs.mkdir(&p("f"), 0o755),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn statfs_namelen_is_255() {
        let f = fx();
        let s = f.fs.statfs().unwrap();
        assert_eq!(s.namelen, 255);
        assert!(s.bsize > 0);
    }

    /// Creates the real directory for `name` in the root without `.cd-dir`.
    fn incomplete_dir(f: &Fx, name: &str, files: &[&str]) -> PathBuf {
        let enc = f.enc(name);
        let real = f.root.join(&enc);
        std::fs::create_dir(&real).unwrap();
        for file in files {
            std::fs::write(real.join(file), b"12").unwrap();
        }
        real
    }

    /// Sets the mtime of `dir` 61 seconds into the past.
    fn backdate(dir: &Path) {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(61);
        std::fs::File::open(dir)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
    }

    #[test]
    fn incomplete_dir_with_tmp_files_is_removed() {
        let f = fx();
        let real = incomplete_dir(&f, "inc", &[".cd-dir.tmp", ".cd-name.tmp"]);
        backdate(&real);
        assert!(matches!(f.fs.readdir(&p("inc")), Err(Error::NotFound)));
        assert!(!real.exists());
        assert!(matches!(f.fs.getattr(&p("inc")), Err(Error::NotFound)));
        // mkdir over an old incomplete directory works.
        backdate(&incomplete_dir(&f, "inc", &[".cd-dir.tmp"]));
        f.fs.mkdir(&p("inc"), 0o755).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["inc"]);
        assert!(f.fs.readdir(&p("inc")).unwrap().is_empty());
    }

    #[test]
    fn empty_incomplete_dir_is_removed() {
        let f = fx();
        let real = incomplete_dir(&f, "inc", &[]);
        backdate(&real);
        assert!(matches!(f.fs.readdir(&p("inc")), Err(Error::NotFound)));
        assert!(!real.exists());
    }

    #[test]
    fn fresh_empty_incomplete_dir_is_kept() {
        // A sync client may have created the directory but not yet its `.cd-dir`.
        for files in [&[][..], &[".cd-dir.tmp"]] {
            let f = fx();
            let real = incomplete_dir(&f, "inc", files);
            assert!(matches!(f.fs.readdir(&p("inc")), Err(Error::NotFound)));
            assert!(matches!(
                f.fs.mkdir(&p("inc"), 0o755),
                Err(Error::AlreadyExists)
            ));
            assert!(real.exists());
            for file in files {
                assert!(real.join(file).exists(), "{file} was deleted");
            }
        }
    }

    #[test]
    fn incomplete_dir_with_other_files_is_invalid_format_and_kept() {
        for files in [
            &["foreign"][..],
            &[".cd-name"],
            &[".cd-dir.tmp", ".cd-other"],
        ] {
            let f = fx();
            let real = incomplete_dir(&f, "inc", files);
            assert!(matches!(
                f.fs.readdir(&p("inc")),
                Err(Error::InvalidFormat { .. })
            ));
            assert!(matches!(
                f.fs.mkdir(&p("inc"), 0o755),
                Err(Error::AlreadyExists)
            ));
            for file in files {
                assert!(real.join(file).exists(), "{file} was deleted");
            }
        }
    }

    #[test]
    fn incomplete_long_entries_are_hidden_and_kept() {
        for files in [&[][..], &[".cd-content (conflicted copy)"]] {
            let f = fx_with(64);
            let name = "n".repeat(100);
            let enc = f.enc(&name);
            let entry = f.root.join(crate::names::long_entry_name(&enc));
            std::fs::create_dir(&entry).unwrap();
            std::fs::write(entry.join(NAME_FILE), &enc).unwrap();
            for file in files {
                std::fs::write(entry.join(file), [0u8; 81]).unwrap();
            }
            assert!(matches!(f.fs.getattr(&p(&name)), Err(Error::NotFound)));
            assert!(matches!(f.fs.readdir(&p(&name)), Err(Error::NotFound)));
            assert!(listed(&f.fs, "/").is_empty());
            assert!(entry.join(NAME_FILE).exists());
            for file in files {
                assert!(entry.join(file).exists(), "{file} was deleted");
            }
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn dir_with_mode_000_has_attributes() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o000).unwrap();
        assert_eq!(f.fs.getattr(&p("d")).unwrap().mode, 0o000);
        assert_eq!(listed(&f.fs, "/"), vec!["d"]);
        set_mode(&only_entry(&f.root), 0o700);
    }

    #[test]
    fn long_dir_with_mode_000_is_found_once_readable() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let f = fx_with(64);
        let name = "n".repeat(100);
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p(&name), 0o000).unwrap();
        // The own index knows the new entry.
        assert!(f.fs.getattr(&p(&name)).is_ok());
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        // Its `.cd-name` cannot be read, so the name index cannot hold it
        // (HS 3.3: lookups use the index only); the rest still lists.
        assert!(matches!(fs.getattr(&p(&name)), Err(Error::NotFound)));
        assert_eq!(listed(&fs, "/"), vec!["a"]);
        for n in user_names(&f.root) {
            if n.starts_with(LONG_PREFIX) {
                set_mode(&f.root.join(n), 0o700);
            }
        }
        assert_eq!(listed(&fs, "/"), vec!["a".to_string(), name.clone()]);
        let attr = fs.getattr(&p(&name)).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);
        assert_eq!(attr.mode, 0o700);
    }

    fn is_denied<T: std::fmt::Debug>(r: &Result<T>) -> bool {
        matches!(r, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied)
    }

    #[test]
    fn unreadable_long_entry_blocks_only_long_names() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let f = fx_with(64);
        let name = "n".repeat(100);
        f.fs.mkdir(&p(&name), 0o000).unwrap();
        // A new instance cannot read the entry; the own index knows it.
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        // Short new names are free: they cannot be the long entry.
        let (_, h) = fs.create(&p("a"), 0o644).unwrap();
        fs.release(h).unwrap();
        fs.mkdir(&p("d"), 0o755).unwrap();
        let before = user_names(&f.root);
        // Long new names may be the unreadable entry, so they are refused.
        let other = "o".repeat(100);
        let mkdir = fs.mkdir(&p(&name), 0o755);
        let create = fs.create(&p(&other), 0o644);
        let rename = fs.rename(&p("a"), &p(&name));
        // A pure lookup still says the name is not there.
        let lookup = fs.getattr(&p(&name));
        let after = user_names(&f.root);
        let renamed = fs.rename(&p("a"), &p("b"));
        for n in user_names(&f.root) {
            if n.starts_with(LONG_PREFIX) {
                set_mode(&f.root.join(n), 0o700);
            }
        }
        assert!(is_denied(&mkdir), "{mkdir:?}");
        assert!(is_denied(&create), "{create:?}");
        assert!(is_denied(&rename), "{rename:?}");
        assert!(matches!(lookup, Err(Error::NotFound)), "{lookup:?}");
        assert_eq!(before, after);
        renamed.unwrap();
        assert_eq!(
            listed(&fs, "/"),
            vec!["b".to_string(), "d".to_string(), name]
        );
    }

    #[test]
    fn unreadable_short_entry_blocks_only_its_name() {
        let f = fx();
        f.fs.mkdir(&p("x"), 0o755).unwrap();
        let real_x = f.real("x");
        let real_x = real_x.file_name().unwrap().to_str().unwrap().to_owned();
        listing::fail_stat_of(Some(real_x));
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        let before = user_names(&f.root);
        let mkdir = fs.mkdir(&p("x"), 0o755);
        let create = fs.create(&p("x"), 0o644);
        let after = user_names(&f.root);
        let (_, h) = fs.create(&p("y"), 0o644).unwrap();
        fs.release(h).unwrap();
        listing::fail_stat_of(None);
        assert!(is_denied(&mkdir), "{mkdir:?}");
        assert!(is_denied(&create), "{create:?}");
        assert_eq!(before, after);
        assert_eq!(listed(&fs, "/"), vec!["x", "y"]);
    }

    #[test]
    fn ensure_free_with_a_stale_listing_ends() {
        let f = fx();
        f.fs.mkdir(&p("inc"), 0o755).unwrap();
        // This state keeps its complete listing, which holds "inc".
        let parent = f.fs.dir_state(&VPath::root()).unwrap();
        assert!(f.fs.find(&parent, "inc").is_ok());
        std::fs::remove_dir_all(f.real("inc")).unwrap();
        // `dir_state` now looks "inc" up in a new root state, so the
        // listing of `parent` stays stale.
        f.fs.ensure_free(&parent, &p("inc"), "inc").unwrap();
        assert!(f.fs.find(&parent, "inc").is_err());
    }

    #[test]
    fn removed_incomplete_dir_does_not_hide_a_second_entry() {
        let f = fx();
        // An old incomplete "inc" whose real name sorts first, so it gets
        // the plain display name and the complete one is a conflict entry.
        let (incomplete, complete, id) = loop {
            let a = f.enc("inc");
            let id: DirId = crate::secret::random_bytes::<16>().unwrap();
            let b = f.names.encrypt_write(&f.vault_id, &id, "inc").unwrap();
            if a < b {
                break (a, b, id);
            }
        };
        std::fs::create_dir(f.root.join(&complete)).unwrap();
        std::fs::write(f.root.join(&complete).join(DIR_FILE), id).unwrap();
        std::fs::create_dir(f.root.join(&incomplete)).unwrap();
        backdate(&f.root.join(&incomplete));
        assert_eq!(listed(&f.fs, "/"), vec!["inc", "inc (conflict 1)"]);
        assert!(matches!(
            f.fs.mkdir(&p("inc"), 0o755),
            Err(Error::AlreadyExists)
        ));
        assert!(!f.root.join(&incomplete).exists());
        assert_eq!(user_names(&f.root), vec![complete]);
        assert_eq!(listed(&f.fs, "/"), vec!["inc"]);
    }

    #[test]
    fn planted_symlink_long_entry_does_not_break_listing() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        let link = format!("{LONG_PREFIX}{}", "A".repeat(43));
        std::os::unix::fs::symlink("/", f.root.join(&link)).unwrap();
        std::os::unix::fs::symlink("loop", f.root.join("loop")).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["a"]);
    }

    #[test]
    fn mkdir_without_owner_write_bit() {
        let f = fx();
        let attr = f.fs.mkdir(&p("ro"), 0o500).unwrap();
        assert_eq!(attr.mode & 0o700, 0o500);
        assert_eq!(listed(&f.fs, "/"), vec!["ro"]);
        assert!(f.fs.readdir(&p("ro")).unwrap().is_empty());
        let real = only_entry(&f.root);
        assert_eq!(std::fs::read(real.join(DIR_FILE)).unwrap().len(), 16);
        // Let the temp dir clean up.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
