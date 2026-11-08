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

//! Directory listing with conflict copies (spec 5.3).

use super::CryptoFs;
use super::FileKind;
use super::dirstate::{DirState, EntryRef};
use crate::backing::{DirHandle, Kind};
use crate::conflict::{conflict_display_name, long_candidate, short_candidates};
use crate::error::{Error, Result};
use crate::keys::{EntryId, Epoch};
use crate::names::{MAX_ENCODED_NAME_LEN, long_entry_name, needs_long_entry, validate_name};
use crate::vault::{CONTENT_FILE, DIR_FILE, NAME_FILE};
use std::collections::{BTreeMap, HashMap, HashSet, btree_map};

#[cfg(test)]
thread_local! {
    /// Listings built by this thread (tests run each test in its own thread).
    static LISTINGS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Warnings about extra directory ids logged by this thread.
    static EXTRA_ID_WARNINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// A short real name whose stat fails in this thread (a stat failure
    /// of one entry cannot be made portably on a real file system).
    static FAIL_STAT_OF: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// How many listings this thread has built.
#[cfg(test)]
pub(crate) fn listings_built() -> usize {
    LISTINGS_BUILT.with(|c| c.get())
}

/// How many warnings about extra directory ids this thread has logged.
#[cfg(test)]
pub(crate) fn extra_id_warnings() -> usize {
    EXTRA_ID_WARNINGS.with(|c| c.get())
}

/// Makes the stat of the short real name `real` fail in this thread.
#[cfg(test)]
pub(crate) fn fail_stat_of(real: Option<String>) {
    FAIL_STAT_OF.with(|f| *f.borrow_mut() = real);
}

/// How an entry is stored in the real directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    /// A file named with the encrypted name.
    ShortFile,
    /// A directory named with the encrypted name.
    ShortDir,
    /// A `.cd-cdl` directory with `.cd-name` and `.cd-content`.
    LongFile,
    /// A `.cd-cdl` directory with `.cd-name` and `.cd-dir`; it is the directory.
    LongDir,
}

impl Layout {
    pub(crate) fn is_dir(self) -> bool {
        matches!(self, Layout::ShortDir | Layout::LongDir)
    }

    pub(crate) fn kind(self) -> FileKind {
        if self.is_dir() {
            FileKind::Directory
        } else {
            FileKind::File
        }
    }
}

/// The visible entries of a directory, by display name: the name index
/// (HS 3.3).
pub(crate) struct Listing {
    pub(crate) entries: BTreeMap<String, EntryRef>,
    /// `Some` if an entry was skipped because it could not be read. Its
    /// name may be missing from `entries`.
    pub(crate) skipped: Option<Skipped>,
}

/// What is known about the entries a listing skipped.
#[derive(Debug)]
pub(crate) struct Skipped {
    /// The I/O error kind of the first one (`PermissionDenied` for an
    /// error that is not I/O).
    pub(crate) kind: std::io::ErrorKind,
    /// Clear names of skipped short entries: their real name decrypts
    /// without I/O, only reading the entry failed.
    pub(crate) short_names: HashSet<String>,
    /// True if a `.cd-cdl` entry was skipped; its clear name is unknown.
    pub(crate) long: bool,
}

impl Skipped {
    /// True if the NFC name `nfc`, which is not in the listing, may be the
    /// name of a skipped entry: a skipped short entry has it, or it would
    /// get an overflow entry and a skipped long entry exists.
    pub(crate) fn may_hold(&self, nfc: &str, max_name_length: u16) -> bool {
        self.short_names.contains(nfc)
            || (self.long && needs_long_entry(nfc.len(), max_name_length))
    }
}

/// Maps errors that mean "this entry is not what we look for" to `None`.
fn skip_missing<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotFound | Error::NotADirectory | Error::InvalidFormat { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Opens `name` if it is a real directory (not a link or file).
pub(crate) fn open_entry_dir(parent: &DirHandle, name: &str) -> Result<Option<DirHandle>> {
    match skip_missing(parent.stat(name))? {
        Some(st) if st.kind == Kind::Dir => skip_missing(parent.open_dir(name)),
        _ => Ok(None),
    }
}

fn is_file(dir: &DirHandle, name: &str) -> Result<bool> {
    Ok(skip_missing(dir.stat(name))?.is_some_and(|st| st.kind == Kind::File))
}

/// Reads `.cd-name` of a long entry; `None` if it is missing or not valid.
pub(crate) fn read_long_name(entry_dir: &DirHandle) -> Result<Option<String>> {
    let Some(bytes) = skip_missing(entry_dir.read_small(NAME_FILE, MAX_ENCODED_NAME_LEN))? else {
        return Ok(None);
    };
    Ok(String::from_utf8(bytes).ok())
}

/// `LongFile` or `LongDir`; `None` for an incomplete entry.
pub(crate) fn long_layout(entry_dir: &DirHandle) -> Result<Option<Layout>> {
    if is_file(entry_dir, CONTENT_FILE)? {
        Ok(Some(Layout::LongFile))
    } else if is_file(entry_dir, DIR_FILE)? {
        Ok(Some(Layout::LongDir))
    } else {
        Ok(None)
    }
}

/// A real entry whose name decrypted.
struct Found {
    real: String,
    clear: String,
    layout: Layout,
    entry_id: EntryId,
    epoch: Epoch,
    /// Index of the directory id that decrypted the name.
    id_index: usize,
    /// True if the real name has a sync conflict suffix.
    conflict: bool,
}

/// A name that decrypted under one of the directory ids.
struct Decrypted {
    clear: String,
    entry_id: EntryId,
    epoch: Epoch,
    id_index: usize,
}

impl Found {
    fn new(real: &str, d: Decrypted, layout: Layout, conflict: bool) -> Found {
        Found {
            real: real.to_owned(),
            clear: d.clear,
            layout,
            entry_id: d.entry_id,
            epoch: d.epoch,
            id_index: d.id_index,
            conflict,
        }
    }

    fn into_entry(self) -> EntryRef {
        EntryRef {
            real: self.real,
            layout: self.layout,
            entry_id: self.entry_id,
            epoch: self.epoch,
        }
    }
}

impl CryptoFs {
    /// Runs `f` on the listing of `state`, building it first if needed.
    pub(crate) fn with_listing<R>(
        &self,
        state: &DirState,
        f: impl FnOnce(&Listing) -> R,
    ) -> Result<R> {
        let mut index = state.index();
        if let Some(l) = &index.listing {
            return Ok(f(l));
        }
        let now = self.now();
        let listing = self.build_listing(state)?;
        // A listing that skipped unreadable entries is not kept, so they show
        // up as soon as they can be read (a chmod does not change the mtime).
        // An outdated state does not set the index of the newer one.
        if listing.skipped.is_some() || !state.is_latest(&index) {
            return Ok(f(&listing));
        }
        // Read after the stored mtime became safe, the listing holds every
        // change of its tick (spec 2026-11-08 coarse mtime, 3.2).
        index.listing_built_at(now);
        Ok(f(index.listing.insert(listing)))
    }

    /// Decrypts with each directory id and each epoch; the first that
    /// authenticates wins.
    fn decrypt_name(&self, state: &DirState, encoded: &str) -> Option<Decrypted> {
        state.dir_ids.iter().enumerate().find_map(|(id_index, id)| {
            let (epoch, entry_id, clear) = self.names.decrypt_any(id, encoded)?;
            validate_name(&clear).ok()?;
            Some(Decrypted {
                clear,
                entry_id,
                epoch,
                id_index,
            })
        })
    }

    fn classify(&self, state: &DirState, real: &str) -> Result<Option<Found>> {
        if let Some((entry, suffix)) = long_candidate(real) {
            let Some(dir) = open_entry_dir(&state.handle, real)? else {
                return Ok(None);
            };
            let Some(full) = read_long_name(&dir)? else {
                return Ok(None);
            };
            if long_entry_name(&full) != entry {
                return Ok(None);
            }
            let Some(layout) = long_layout(&dir)? else {
                return Ok(None);
            };
            let Some(d) = self.decrypt_name(state, &full) else {
                return Ok(None);
            };
            return Ok(Some(Found::new(real, d, layout, !suffix.is_empty())));
        }
        // Control files and foreign dot files.
        if real.starts_with('.') {
            return Ok(None);
        }
        let Some((d, conflict)) =
            short_candidates(real)
                .into_iter()
                .find_map(|(prefix, suffix)| {
                    Some((self.decrypt_name(state, prefix)?, !suffix.is_empty()))
                })
        else {
            return Ok(None);
        };
        #[cfg(test)]
        if FAIL_STAT_OF.with(|f| f.borrow().as_deref() == Some(real)) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
        }
        let layout = match skip_missing(state.handle.stat(real))?.map(|st| st.kind) {
            Some(Kind::File) => Layout::ShortFile,
            Some(Kind::Dir) => Layout::ShortDir,
            Some(Kind::Other) | None => return Ok(None),
        };
        Ok(Some(Found::new(real, d, layout, conflict)))
    }

    /// Lists the real directory and assigns display names (spec 5.3).
    fn build_listing(&self, state: &DirState) -> Result<Listing> {
        #[cfg(test)]
        LISTINGS_BUILT.with(|c| c.set(c.get() + 1));
        let mut names = state.handle.list()?;
        names.sort();
        let mut normal = Vec::new();
        let mut conflicts = Vec::new();
        let mut skipped = None;
        for real in &names {
            // One entry that cannot be read must not hide the others.
            match self.classify(state, real) {
                Ok(Some(f)) if f.conflict => conflicts.push(f),
                Ok(Some(f)) => normal.push(f),
                Ok(None) => {}
                Err(e) => {
                    log::debug!("skipping real entry {real}: {e}");
                    let s = skipped.get_or_insert_with(|| Skipped {
                        kind: match &e {
                            Error::Io(io) => io.kind(),
                            _ => std::io::ErrorKind::PermissionDenied,
                        },
                        short_names: HashSet::new(),
                        long: false,
                    });
                    if long_candidate(real).is_some() {
                        s.long = true;
                    } else if let Some(d) = short_candidates(real)
                        .into_iter()
                        .find_map(|(prefix, _)| self.decrypt_name(state, prefix))
                    {
                        // A conflict copy is held by its clear name too.
                        s.short_names.insert(d.clear);
                    }
                }
            }
        }
        warn_extra_ids(state, &normal, &conflicts);
        let mut entries = BTreeMap::new();
        // The same clear name under two directory ids: the one `find` would
        // pick first keeps the name, the others become conflict entries.
        normal.sort_by(|a, b| (a.id_index, &a.real).cmp(&(b.id_index, &b.real)));
        for f in normal {
            match entries.entry(f.clear.clone()) {
                btree_map::Entry::Vacant(slot) => {
                    slot.insert(f.into_entry());
                }
                btree_map::Entry::Occupied(_) => conflicts.push(f),
            }
        }
        // N counts per clear name in the order of the real names. A display
        // name that is already used takes the next N.
        conflicts.sort_by(|a, b| a.real.cmp(&b.real));
        let mut next_n: HashMap<String, u32> = HashMap::new();
        for f in conflicts {
            let n = next_n.entry(f.clear.clone()).or_insert(1);
            let display = loop {
                let candidate = conflict_display_name(&f.clear, *n);
                *n += 1;
                if !entries.contains_key(&candidate) {
                    break candidate;
                }
            };
            entries.insert(display, f.into_entry());
        }
        Ok(Listing { entries, skipped })
    }
}

/// Logs a warning (once per real directory) if entries only decrypt under an
/// extra directory id, the id of a `.cd-dir` copy. A sync merge makes such
/// entries, but so can an attacker who puts a copy of another directory's
/// `.cd-dir` next to entries moved from there: the move is not detected.
fn warn_extra_ids(state: &DirState, normal: &[Found], conflicts: &[Found]) {
    let extra = normal
        .iter()
        .chain(conflicts)
        .filter(|f| f.id_index > 0)
        .count();
    if extra == 0 || !state.first_extra_id_warning() {
        return;
    }
    #[cfg(test)]
    EXTRA_ID_WARNINGS.with(|c| c.set(c.get() + 1));
    log::warn!(
        "{extra} entries in one directory are named under the id of a .cd-dir copy, not under its own id. \
         A sync conflict makes this, but they may also have been moved here from another directory \
         without being noticed. Run `crypto-drive check` to find the copy (multiple-dir-ids)."
    );
}
