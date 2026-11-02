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

//! Directory state: handle, directory ids and cached listing (spec 5.2).

use super::CryptoFs;
use super::listing::{Layout, Listing};
use super::path::VPath;
use crate::backing::{DirHandle, Kind, Stat};
use crate::error::{Error, Result};
use crate::keys::{DirId, EntryId, Epoch};
use crate::names::{BackingName, to_backing_name, validate_name};
use crate::vault::DIR_FILE;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime};
use unicode_normalization::UnicodeNormalization;

/// Temporary file of `write_atomic(".cd-dir")`; never a directory id.
pub(super) const DIR_TMP_FILE: &str = ".cd-dir.tmp";
/// Temporary file of `write_atomic(".cd-name")`.
pub(crate) const NAME_TMP_FILE: &str = ".cd-name.tmp";
const DIR_ID_LEN: usize = 16;
/// An empty incomplete directory is only removed when it is older than this.
const INCOMPLETE_MIN_AGE: Duration = Duration::from_secs(60);
/// Most removed incomplete entries `ensure_free` looks past for one name.
const MAX_FREE_ROUNDS: usize = 64;
/// Most times `with_change` takes the states again because one changed
/// from outside between taking and locking it.
const MAX_LOCK_ROUNDS: usize = 8;
/// The map of shared directory data is pruned of unused entries above
/// this size.
const SHARED_DIRS_PRUNE: usize = 4096;

/// One entry of a directory, as found in the real directory (an entry of the
/// name index, HS 3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EntryRef {
    /// The real entry name in the parent (for long names the `.cd-cdl` entry).
    pub(crate) real: String,
    pub(crate) layout: Layout,
    /// The entry id from the name: the file id of a file, the directory id
    /// of a directory (HS 3.2).
    pub(crate) entry_id: EntryId,
    /// The epoch whose name key decrypted the name.
    pub(crate) epoch: Epoch,
}

/// What every state of one real directory shares (found by device, inode
/// and canonical id), so an own change made through one state is seen
/// through all. Not by the id alone: a sync conflict copy of a directory
/// has the same id but other entries. The id guards against a reused inode.
pub(crate) struct SharedDir {
    /// Held across every own change of the real directory: check that the
    /// name is free, change, update the index, read the mtime again. Taken
    /// before `index`, never while `index` is held.
    change: Mutex<()>,
    /// The name index and the mtime it belongs to. A leaf lock.
    index: Mutex<Index>,
    /// Set after the warning about entries named under an extra directory
    /// id was logged, so it is logged once per real directory.
    warned_extra_ids: AtomicBool,
}

/// The name index of a real directory (HS 3.3) and its mtime.
pub(crate) struct Index {
    /// The mtime of the real directory when it was last seen by a new
    /// state, read again after each own change.
    mtime: SystemTime,
    /// Counts the outside changes seen: a new state found another mtime
    /// than `mtime`. A state with an older version is outdated.
    version: u64,
    /// Built on first use; own changes update it in place.
    pub(crate) listing: Option<Listing>,
}

/// What is known about one real directory.
pub(crate) struct DirState {
    pub(crate) handle: Arc<DirHandle>,
    /// Never empty. The canonical id from `.cd-dir` comes first.
    pub(crate) dir_ids: Vec<DirId>,
    shared: Arc<SharedDir>,
    /// The `Index::version` this state was built at.
    version: u64,
    /// Unique per built state. A cached child is only valid while its parent
    /// state is the one it was built from.
    generation: u64,
    parent_generation: Option<u64>,
}

impl DirState {
    /// The id for new entries.
    pub(crate) fn canonical_id(&self) -> &DirId {
        // `dir_ids` is never empty (see the field).
        &self.dir_ids[0]
    }

    /// True the first time it is called for this real directory.
    pub(crate) fn first_extra_id_warning(&self) -> bool {
        !self.shared.warned_extra_ids.swap(true, Ordering::Relaxed)
    }

    /// The shared name index of the real directory.
    pub(crate) fn index(&self) -> MutexGuard<'_, Index> {
        self.shared.index.lock().expect("index lock poisoned")
    }

    /// True if no outside change was seen since this state was built, so
    /// it may keep a listing it builds.
    pub(crate) fn is_latest(&self, index: &Index) -> bool {
        index.version == self.version
    }

    /// Drops the cached listing so the next use lists the directory again.
    pub(crate) fn forget_listing(&self) {
        self.index().listing = None;
    }

    /// The stored mtime of the real directory.
    #[cfg(test)]
    pub(crate) fn mtime(&self) -> SystemTime {
        self.index().mtime
    }

    /// True if the real directory did not change from outside since this
    /// state was built or last changed by us.
    fn is_current(&self) -> bool {
        let Ok(st) = self.handle.stat_self() else {
            return false;
        };
        let index = self.index();
        self.is_latest(&index) && st.mtime == index.mtime
    }
}

/// The index key of the clear name `name`: its NFC form.
pub(crate) fn display_key(name: &str) -> String {
    name.nfc().collect()
}

fn invalid(what: String) -> Error {
    Error::InvalidFormat { what }
}

pub(super) fn is_permission_denied(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied)
}

impl CryptoFs {
    fn new_generation(&self) -> u64 {
        self.next_generation.fetch_add(1, Ordering::Relaxed)
    }

    fn cached(&self, path: &VPath) -> Option<Arc<DirState>> {
        self.cache
            .lock()
            .expect("cache lock poisoned")
            .get(path)
            .cloned()
    }

    fn store(&self, path: &VPath, state: &Arc<DirState>) {
        self.cache
            .lock()
            .expect("cache lock poisoned")
            .put(path.clone(), Arc::clone(state));
    }

    /// Returns the state of the directory at `path`, from the cache if the
    /// real directory and all its parents did not change.
    pub(crate) fn dir_state(&self, path: &VPath) -> Result<Arc<DirState>> {
        let (Some(parent_path), Some(name)) = (path.parent(), path.name()) else {
            return self.root_state();
        };
        let parent = self.dir_state(&parent_path)?;
        if let Some(s) = self.cached(path)
            && s.parent_generation == Some(parent.generation)
            && s.is_current()
        {
            return Ok(s);
        }
        let result = self.load_child(&parent, name);
        match &result {
            Ok(state) => self.store(path, state),
            Err(_) => {
                self.cache.lock().expect("cache lock poisoned").pop(path);
            }
        }
        result
    }

    /// The shared data of the real directory `st` (from `stat_self`) with
    /// the canonical id `id`, and its version. If the stored mtime is not
    /// the one in `st`, this is an outside change: the index is dropped and
    /// the version counts up.
    fn shared_dir(&self, st: &Stat, id: &DirId) -> (Arc<SharedDir>, u64) {
        let key = (st.dev, st.ino, *id);
        let shared = {
            let mut dirs = self.shared_dirs.lock().expect("shared dirs poisoned");
            match dirs.get(&key).and_then(Weak::upgrade) {
                Some(shared) => shared,
                None => {
                    if dirs.len() >= SHARED_DIRS_PRUNE {
                        dirs.retain(|_, w| w.strong_count() > 0);
                    }
                    let shared = Arc::new(SharedDir {
                        change: Mutex::new(()),
                        index: Mutex::new(Index {
                            mtime: st.mtime,
                            version: 0,
                            listing: None,
                        }),
                        warned_extra_ids: AtomicBool::new(false),
                    });
                    dirs.insert(key, Arc::downgrade(&shared));
                    shared
                }
            }
        };
        // Not under the map lock: building a listing holds `index` long.
        let version = {
            let mut index = shared.index.lock().expect("index lock poisoned");
            if index.mtime != st.mtime {
                index.mtime = st.mtime;
                index.version += 1;
                index.listing = None;
            }
            index.version
        };
        (shared, version)
    }

    /// Runs the own change `f` on the states of the directories at `paths`
    /// while holding their change locks, so a name checked as free stays
    /// free until the change and the index update are done. The locks are
    /// taken in a fixed order (by address), so two changes never wait for
    /// each other. The states are current when `f` starts: a state that
    /// changed from outside before the lock is taken again, so that
    /// `refresh_mtime` does not hide that change.
    pub(crate) fn with_change<R>(
        &self,
        paths: &[&VPath],
        f: impl FnOnce(&[Arc<DirState>]) -> Result<R>,
    ) -> Result<R> {
        for _ in 0..MAX_LOCK_ROUNDS {
            let states = paths
                .iter()
                .map(|p| self.dir_state(p))
                .collect::<Result<Vec<_>>>()?;
            let mut shared: Vec<&Arc<SharedDir>> = states.iter().map(|s| &s.shared).collect();
            shared.sort_by_key(|d| Arc::as_ptr(d) as usize);
            shared.dedup_by(|a, b| Arc::ptr_eq(a, b));
            let guards: Vec<MutexGuard<'_, ()>> = shared
                .iter()
                .map(|d| d.change.lock().expect("change lock poisoned"))
                .collect();
            if states.iter().all(|s| s.is_current()) {
                let result = f(&states);
                drop(guards);
                return result;
            }
        }
        Err(Error::Io(std::io::Error::other(
            "the directory keeps changing from outside",
        )))
    }

    /// Adds `entry` under the display name `display` to the index of `dir`
    /// after an own change. Does nothing if the index is not built; it is
    /// built on the next use. The name was checked as free, so it is not
    /// a display name yet.
    pub(crate) fn index_insert(
        &self,
        dir: &DirState,
        display: String,
        entry: EntryRef,
    ) -> Result<()> {
        if let Some(l) = dir.index().listing.as_mut() {
            l.entries.insert(display, entry);
        }
        Ok(())
    }

    /// Removes the display name `display` from the index of `dir` after an
    /// own change. The display names of other conflict copies of that name
    /// stay as they are until the index is built again.
    pub(crate) fn index_remove(&self, dir: &DirState, display: &str) {
        if let Some(l) = dir.index().listing.as_mut() {
            l.entries.remove(display);
        }
    }

    /// Reads the mtime of the real directory again after an own change, so
    /// the change does not count as an outside one (HS 3.3). Called with
    /// the change lock held; the index and mtime are shared by every state
    /// of the directory. Limit (HS 3.3): an outside change made after the
    /// `is_current` check in `with_change` and before this read is not
    /// seen. It stays unseen as long as only own changes follow; the next
    /// outside change of the directory makes the index be built again.
    pub(crate) fn refresh_mtime(&self, dir: &DirState) -> Result<()> {
        let mtime = dir.handle.stat_self()?.mtime;
        dir.index().mtime = mtime;
        Ok(())
    }

    /// Ends an own change of `dir`. If the index is not known to be right
    /// (`index_ok` is false, as after a change that failed partway) or the
    /// mtime cannot be read, the index is dropped and built again on the
    /// next use.
    pub(crate) fn end_change(&self, dir: &DirState, index_ok: bool) {
        if !index_ok {
            dir.forget_listing();
            return;
        }
        if let Err(e) = self.refresh_mtime(dir) {
            log::debug!("could not read the mtime of a changed directory: {e}");
            dir.forget_listing();
        }
    }

    fn root_state(&self) -> Result<Arc<DirState>> {
        let root = VPath::root();
        if let Some(s) = self.cached(&root)
            && s.is_current()
        {
            return Ok(s);
        }
        let (shared, version) = self.shared_dir(&self.root.stat_self()?, &self.root_id);
        let state = Arc::new(DirState {
            handle: Arc::clone(&self.root),
            dir_ids: vec![self.root_id],
            shared,
            version,
            generation: self.new_generation(),
            parent_generation: None,
        });
        self.store(&root, &state);
        Ok(state)
    }

    fn load_child(&self, parent: &DirState, name: &str) -> Result<Arc<DirState>> {
        let entry = self.find(parent, name)?;
        if !entry.layout.is_dir() {
            return Err(Error::NotADirectory);
        }
        let handle = parent.handle.open_dir(&entry.real)?;
        // Take the mtime before reading anything, so a change made while
        // reading makes the state outdated instead of being missed.
        let st = handle.stat_self()?;
        let mtime = st.mtime;
        let mut names = handle.list()?;
        names.sort();
        if !names.iter().any(|n| n == DIR_FILE) {
            return Err(remove_incomplete(
                parent,
                &entry.real,
                &handle,
                &names,
                mtime,
            ));
        }
        let dir_ids = read_dir_ids(&handle, &entry.real, &names)?;
        // The canonical id must be the entry id of the name (HS 3.2), or
        // this is the subtree of another directory under this name.
        if dir_ids[0] != entry.entry_id {
            return Err(Error::AuthFailed { what: entry.real });
        }
        let (shared, version) = self.shared_dir(&st, &dir_ids[0]);
        Ok(Arc::new(DirState {
            handle: Arc::new(handle),
            dir_ids,
            shared,
            version,
            generation: self.new_generation(),
            parent_generation: Some(parent.generation),
        }))
    }

    /// Finds the display name `name` in `parent` through the name index
    /// only (HS 3.3); the index is built on first use. A real name holds a
    /// random entry id, so it cannot be computed from the clear name.
    pub(crate) fn find(&self, parent: &DirState, name: &str) -> Result<EntryRef> {
        validate_name(name)?;
        let nfc = display_key(name);
        self.with_listing(parent, |l| l.entries.get(&nfc).cloned())?
            .ok_or(Error::NotFound)
    }

    /// Like `find`, but for a name that is about to be created or replaced:
    /// `None` only if the name is free. If the index skipped an entry that
    /// could not be read and the missing name may be that entry (see
    /// `Skipped::may_hold`), this fails closed with the error of the skipped
    /// entry; otherwise a new random entry id would make a second entry with
    /// the same name.
    pub(crate) fn find_for_change(
        &self,
        parent: &DirState,
        name: &str,
    ) -> Result<Option<EntryRef>> {
        validate_name(name)?;
        let nfc = display_key(name);
        let max = self.max_name_length;
        self.with_listing(parent, |l| match (l.entries.get(&nfc), &l.skipped) {
            (Some(entry), _) => Ok(Some(entry.clone())),
            (None, Some(s)) if s.may_hold(&nfc, max) => Err(Error::Io(s.kind.into())),
            (None, _) => Ok(None),
        })?
    }

    /// The real name for the new entry `name` with `entry_id` in `parent`,
    /// under the canonical id and the write epoch.
    pub(crate) fn new_entry_name(
        &self,
        parent: &DirState,
        entry_id: &EntryId,
        name: &str,
    ) -> Result<BackingName> {
        let encoded = self
            .names
            .encrypt_write(parent.canonical_id(), entry_id, name)?;
        Ok(to_backing_name(encoded, self.max_name_length))
    }

    /// The index entry of a new entry made with the real name `backing`
    /// (from `new_entry_name`).
    pub(crate) fn new_entry_ref(
        &self,
        backing: &BackingName,
        dir: bool,
        entry_id: EntryId,
    ) -> EntryRef {
        let (real, layout) = match (backing, dir) {
            (BackingName::Short(s), false) => (s.clone(), Layout::ShortFile),
            (BackingName::Short(s), true) => (s.clone(), Layout::ShortDir),
            (BackingName::Long { entry, .. }, false) => (entry.clone(), Layout::LongFile),
            (BackingName::Long { entry, .. }, true) => (entry.clone(), Layout::LongDir),
        };
        EntryRef {
            real,
            layout,
            entry_id,
            epoch: self.keys.write_epoch(),
        }
    }

    /// Fails with `AlreadyExists` unless the clear name `name` (at `path`) is
    /// free in `parent`. An incomplete directory with only control files
    /// that `dir_state` removed frees the name, unless another entry with
    /// the same name shows up then; a young one is kept and so still holds
    /// it.
    pub(crate) fn ensure_free(&self, parent: &DirState, path: &VPath, name: &str) -> Result<()> {
        for _ in 0..MAX_FREE_ROUNDS {
            let Some(entry) = self.find_for_change(parent, name)? else {
                return Ok(());
            };
            if !entry.layout.is_dir() || !matches!(self.dir_state(path), Err(Error::NotFound)) {
                return Err(Error::AlreadyExists);
            }
            match parent.handle.stat(&entry.real) {
                // Gone (removed by `dir_state`, or from outside): look
                // again, as the next entry with this name may now hold it
                // (it was a conflict entry before). `dir_state` may have
                // reset another state's listing, so reset this one.
                Err(Error::NotFound) => parent.forget_listing(),
                Ok(_) => return Err(Error::AlreadyExists),
                Err(e) => return Err(e),
            }
        }
        Err(Error::Io(std::io::Error::other(
            "too many incomplete entries with one name",
        )))
    }

    /// Drops `path` and every cached path under it.
    pub(crate) fn invalidate(&self, path: &VPath) {
        let dropped: Vec<Arc<DirState>> = {
            let mut cache = self.cache.lock().expect("cache lock poisoned");
            let keys: Vec<VPath> = cache
                .iter()
                .filter(|(k, _)| k.starts_with(path))
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| cache.pop(k)).collect()
        };
        // Callers may still hold a dropped state; make it list again.
        for state in dropped {
            state.forget_listing();
        }
    }
}

/// Most directory ids used for one real directory: the canonical one and
/// the first copies by name. Copies are allowed for sync conflicts (a
/// handful at most); each listing tries every name with every id, so
/// thousands of planted copies would make a listing take minutes. Names
/// under the other copies stay hidden; `check` reports every copy.
pub const MAX_DIR_IDS: usize = 16;

/// Reads the canonical `.cd-dir` and the ids of its sync conflict copies.
pub(crate) fn read_dir_ids(handle: &DirHandle, real: &str, names: &[String]) -> Result<Vec<DirId>> {
    let bytes = handle.read_small(DIR_FILE, DIR_ID_LEN)?;
    let canonical: DirId = bytes
        .try_into()
        .map_err(|_| invalid(format!("{real}/{DIR_FILE}")))?;
    let mut ids = vec![canonical];
    // In name order, so the same copies are used on every listing.
    let mut copies: Vec<&String> = names
        .iter()
        .filter(|n| *n != DIR_FILE && *n != DIR_TMP_FILE && n.starts_with(DIR_FILE))
        .collect();
    copies.sort();
    for n in copies {
        if ids.len() >= MAX_DIR_IDS {
            break;
        }
        // Only regular files of exactly 16 bytes count; anything else is
        // ignored here and reported by `check`.
        if !matches!(handle.stat(n), Ok(st) if st.kind == Kind::File) {
            continue;
        }
        let id: DirId = match handle.read_small(n, DIR_ID_LEN) {
            Ok(b) => match b.try_into() {
                Ok(id) => id,
                Err(_) => continue,
            },
            Err(Error::NotFound | Error::InvalidFormat { .. }) => continue,
            Err(e) => return Err(e),
        };
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Handles a directory without `.cd-dir` (spec 5.5). If it is empty or holds
/// only the temporary files of an interrupted mkdir, the result is
/// `NotFound`; it is also removed if its `mtime` is older than
/// `INCOMPLETE_MIN_AGE`. Otherwise it is `InvalidFormat` and nothing is
/// deleted. Returns the error to give.
fn remove_incomplete(
    parent: &DirState,
    real: &str,
    handle: &DirHandle,
    names: &[String],
    mtime: SystemTime,
) -> Error {
    let only_tmp = names.iter().all(|n| {
        (n == DIR_TMP_FILE || n == NAME_TMP_FILE)
            && matches!(handle.stat(n), Ok(st) if st.kind == Kind::File)
    });
    if !only_tmp {
        return invalid(real.to_owned());
    }
    // A young one may still be in the making: a sync client that has not
    // yet written `.cd-dir`, or a mkdir of another instance. A mtime in the
    // future counts as young.
    let old = SystemTime::now()
        .duration_since(mtime)
        .is_ok_and(|age| age > INCOMPLETE_MIN_AGE);
    if !old {
        return Error::NotFound;
    }
    let removed = names
        .iter()
        .try_for_each(|n| match handle.unlink(n) {
            Ok(()) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        })
        .and_then(|()| parent.handle.rmdir(real));
    parent.forget_listing();
    match removed {
        Ok(()) | Err(Error::NotFound) => Error::NotFound,
        Err(Error::NotEmpty) => invalid(real.to_owned()),
        Err(e) => e,
    }
}
