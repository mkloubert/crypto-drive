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

//! Which real directories have changes that are not synced yet (review
//! P4-a, P5-b; spec `2026-11-08-fewer-syncs-design.md`).
//!
//! A directory is synced only when one of its entries changed through this
//! process since its last sync, and the `.cd-dir` of a new directory is
//! synced only before something in it is synced. Directories are found by
//! device and inode, so the marks stay with a directory across renames and
//! new states.

use std::collections::HashSet;

/// A real directory: device and inode.
pub(crate) type DirKey = (u64, u64);

/// Most directories in each set. A full set makes the caller sync at once
/// (the behavior without this tracking), so memory stays bounded.
pub(crate) const MAX_UNSYNCED_DIRS: usize = 65_536;

/// What a sync of one directory has to do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pending {
    /// Own entry changes are not synced: sync the directory.
    pub(crate) changed: bool,
    /// A new directory whose `.cd-dir` is not synced: sync `.cd-dir`, the
    /// directory, and its entry in the parent.
    pub(crate) new: bool,
}

pub(crate) struct Unsynced {
    changed: HashSet<DirKey>,
    new: HashSet<DirKey>,
    cap: usize,
}

impl Unsynced {
    pub(crate) fn new(cap: usize) -> Unsynced {
        Unsynced {
            changed: HashSet::new(),
            new: HashSet::new(),
            cap,
        }
    }

    /// Marks an own entry change of `dir`. False if the set is full: the
    /// caller must sync the directory now.
    pub(crate) fn mark_changed(&mut self, dir: DirKey) -> bool {
        mark(&mut self.changed, dir, self.cap)
    }

    /// True if a new directory can be marked (`mark_new`).
    pub(crate) fn has_room_for_new(&self) -> bool {
        self.new.len() < self.cap && self.changed.len() < self.cap
    }

    /// Marks the new directory `dir` (its `.cd-dir` and its own entries).
    /// False if a set is full: the caller must sync them now.
    pub(crate) fn mark_new(&mut self, dir: DirKey) -> bool {
        if !self.has_room_for_new() && !(self.new.contains(&dir) && self.changed.contains(&dir)) {
            return false;
        }
        self.new.insert(dir);
        self.changed.insert(dir);
        true
    }

    /// Takes the marks of `dir` out, before it is synced. If the sync
    /// fails, `put_back` returns them; a change during the sync marks the
    /// directory again and is not lost.
    pub(crate) fn take(&mut self, dir: DirKey) -> Pending {
        Pending {
            changed: self.changed.remove(&dir),
            new: self.new.remove(&dir),
        }
    }

    /// Returns the marks after a failed sync (a full set is ignored here:
    /// the marks were in it a moment ago).
    pub(crate) fn put_back(&mut self, dir: DirKey, pending: Pending) {
        if pending.changed {
            self.changed.insert(dir);
        }
        if pending.new {
            self.new.insert(dir);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
    }
}

fn mark(set: &mut HashSet<DirKey>, dir: DirKey, cap: usize) -> bool {
    if set.len() >= cap && !set.contains(&dir) {
        return false;
    }
    set.insert(dir);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_taken_once_and_put_back_after_a_failure() {
        let mut u = Unsynced::new(4);
        assert!(u.mark_changed((1, 1)));
        assert!(u.mark_new((1, 2)));
        assert_eq!(
            u.take((1, 1)),
            Pending {
                changed: true,
                new: false
            }
        );
        assert_eq!(u.take((1, 1)), Pending::default());
        let p = u.take((1, 2));
        assert_eq!(
            p,
            Pending {
                changed: true,
                new: true
            }
        );
        u.put_back((1, 2), p);
        assert_eq!(u.take((1, 2)), p);
    }

    #[test]
    fn a_full_set_asks_for_a_sync_now() {
        let mut u = Unsynced::new(2);
        assert!(u.mark_changed((0, 1)));
        assert!(u.mark_changed((0, 2)));
        assert!(!u.mark_changed((0, 3)));
        // A directory that is already marked can always be marked again.
        assert!(u.mark_changed((0, 1)));
        assert!(!u.has_room_for_new());
        assert!(!u.mark_new((0, 4)));
        u.take((0, 2));
        assert!(u.mark_new((0, 4)));
        assert!(!u.mark_new((0, 5)));
    }
}
