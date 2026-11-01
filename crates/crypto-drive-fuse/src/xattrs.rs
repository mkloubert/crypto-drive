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

//! Extended attributes kept in memory while the drive is mounted (spec 5.6).
//!
//! Nothing is written to disk, so the values are lost at unmount. Copy tools
//! (Finder, `cp`, `ditto`) abort on any xattr error, and Finder reads its
//! own markers back during a copy, so set values must be readable again.
//! Values that do not fit the limits are accepted and dropped, so a copy
//! never fails on them.

use crate::inodes::subtree;
use crypto_drive_core::fs::VPath;
use std::collections::BTreeMap;

/// The errno for "this extended attribute does not exist".
#[cfg(target_os = "macos")]
pub(crate) const NO_XATTR: i32 = libc::ENOATTR;
/// The errno for "this extended attribute does not exist".
#[cfg(not(target_os = "macos"))]
pub(crate) const NO_XATTR: i32 = libc::ENODATA;

/// Most bytes (names plus values) kept for one entry.
pub(crate) const MAX_ENTRY_BYTES: usize = 1024 * 1024;
/// Most bytes (names plus values) kept for all entries together.
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

type Attrs = BTreeMap<Vec<u8>, Vec<u8>>;

fn attrs_bytes(attrs: &Attrs) -> usize {
    attrs.iter().map(|(n, v)| n.len() + v.len()).sum()
}

/// True if a name is kept. On Linux only the `user.` namespace is kept;
/// other namespaces (`security.`, `trusted.`, `system.`) belong to the
/// kernel and are dropped. macOS has no namespaces.
fn is_kept_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    cfg!(target_os = "macos") || name.starts_with(b"user.")
}

/// The answer to a get or list request: the size only (`size == 0`), the
/// data, or `ERANGE` when the buffer is too small.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Size(u32),
    Data(Vec<u8>),
}

fn answer(data: Vec<u8>, size: u32) -> Result<Answer, i32> {
    let len = u32::try_from(data.len()).map_err(|_| libc::E2BIG)?;
    if size == 0 {
        Ok(Answer::Size(len))
    } else if len > size {
        Err(libc::ERANGE)
    } else {
        Ok(Answer::Data(data))
    }
}

/// What a set request did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    Kept,
    /// Accepted but not kept (name not kept, or over a limit).
    Dropped,
}

/// The extended attributes of all entries, by clear path.
#[derive(Default)]
pub(crate) struct XattrStore {
    /// Sorted by path, so a subtree is one range (see `subtree`).
    by_path: BTreeMap<VPath, Attrs>,
    total: usize,
}

impl XattrStore {
    pub(crate) fn get(&self, path: &VPath, name: &[u8], size: u32) -> Result<Answer, i32> {
        match self.by_path.get(path).and_then(|a| a.get(name)) {
            Some(value) => answer(value.clone(), size),
            None => Err(NO_XATTR),
        }
    }

    /// The names, each followed by a NUL byte.
    pub(crate) fn list(&self, path: &VPath, size: u32) -> Result<Answer, i32> {
        let mut names = Vec::new();
        if let Some(attrs) = self.by_path.get(path) {
            for name in attrs.keys() {
                names.extend_from_slice(name);
                names.push(0);
            }
        }
        answer(names, size)
    }

    /// Sets `name`. `XATTR_CREATE` fails with `EEXIST` if it exists,
    /// `XATTR_REPLACE` with "no attribute" if it does not. With `position`
    /// (macOS resource forks) the value is written at that offset into the
    /// old value. A value that does not fit a limit is dropped, and an old
    /// value of that name is removed, so a read never returns stale data.
    pub(crate) fn set(
        &mut self,
        path: &VPath,
        name: &[u8],
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<Stored, i32> {
        let old = self.by_path.get(path).and_then(|a| a.get(name));
        if flags & libc::XATTR_CREATE != 0 && old.is_some() {
            return Err(libc::EEXIST);
        }
        if flags & libc::XATTR_REPLACE != 0 && old.is_none() {
            return Err(NO_XATTR);
        }
        if !is_kept_name(name) {
            return Ok(Stored::Dropped);
        }
        // The new length is known before any memory is taken, so a large
        // `position` cannot make a huge buffer that the limit then drops.
        let pos = position as usize;
        let end = pos.saturating_add(value.len());
        let new_len = match (pos, old) {
            (0, _) => value.len(),
            (_, old) => end.max(old.map_or(0, Vec::len)),
        };
        let old_len = old.map_or(0, |v| name.len() + v.len());
        let entry_now = self.by_path.get(path).map_or(0, attrs_bytes);
        let entry_after = (entry_now - old_len)
            .saturating_add(name.len())
            .saturating_add(new_len);
        let total_after = (self.total - old_len)
            .saturating_add(name.len())
            .saturating_add(new_len);
        if entry_after > MAX_ENTRY_BYTES || total_after > MAX_TOTAL_BYTES {
            self.remove(path, name);
            return Ok(Stored::Dropped);
        }
        let new = if pos == 0 {
            value.to_vec()
        } else {
            let mut v = old.cloned().unwrap_or_default();
            if v.len() < end {
                v.resize(end, 0);
            }
            v[pos..end].copy_from_slice(value);
            v
        };
        self.total = total_after;
        self.by_path
            .entry(path.clone())
            .or_default()
            .insert(name.to_vec(), new);
        Ok(Stored::Kept)
    }

    /// Removes `name`; a missing name is not an error.
    pub(crate) fn remove(&mut self, path: &VPath, name: &[u8]) {
        let Some(attrs) = self.by_path.get_mut(path) else {
            return;
        };
        if let Some(v) = attrs.remove(name) {
            self.total -= name.len() + v.len();
        }
        if attrs.is_empty() {
            self.by_path.remove(path);
        }
    }

    /// Drops the attributes of `path` and everything below it (after
    /// unlink or rmdir).
    pub(crate) fn remove_path(&mut self, path: &VPath) {
        let gone: Vec<VPath> = subtree(&self.by_path, path)
            .map(|(p, _)| p.clone())
            .collect();
        for p in gone {
            if let Some(attrs) = self.by_path.remove(&p) {
                self.total -= attrs_bytes(&attrs);
            }
        }
    }

    /// Moves the attributes of `from` and everything below it to `to`. The
    /// attributes that were at or below `to` are dropped (the rename
    /// replaced those entries).
    pub(crate) fn rename(&mut self, from: &VPath, to: &VPath) {
        if from == to {
            return;
        }
        let replaced: Vec<VPath> = subtree(&self.by_path, to)
            .filter(|(p, _)| !p.starts_with(from))
            .map(|(p, _)| p.clone())
            .collect();
        for p in replaced {
            if let Some(attrs) = self.by_path.remove(&p) {
                self.total -= attrs_bytes(&attrs);
            }
        }
        let moved: Vec<VPath> = subtree(&self.by_path, from)
            .map(|(p, _)| p.clone())
            .collect();
        let mut taken = Vec::with_capacity(moved.len());
        for p in moved {
            if let Some(attrs) = self.by_path.remove(&p) {
                taken.push((p, attrs));
            }
        }
        for (p, attrs) in taken {
            match p.replace_prefix(from, to) {
                Some(new) => {
                    self.by_path.insert(new, attrs);
                }
                None => self.total -= attrs_bytes(&attrs),
            }
        }
    }

    #[cfg(test)]
    fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    /// A name that is kept on this OS.
    fn n(s: &str) -> Vec<u8> {
        if cfg!(target_os = "macos") {
            s.as_bytes().to_vec()
        } else {
            format!("user.{s}").into_bytes()
        }
    }

    fn data(a: Result<Answer, i32>) -> Vec<u8> {
        match a {
            Ok(Answer::Data(d)) => d,
            other => panic!("not data: {other:?}"),
        }
    }

    #[test]
    fn set_then_get_and_list() {
        let mut s = XattrStore::default();
        assert_eq!(s.set(&p("f"), &n("b"), b"2", 0, 0), Ok(Stored::Kept));
        assert_eq!(s.set(&p("f"), &n("a"), b"one", 0, 0), Ok(Stored::Kept));
        assert_eq!(data(s.get(&p("f"), &n("a"), 100)), b"one");
        assert_eq!(s.get(&p("f"), &n("a"), 0), Ok(Answer::Size(3)));
        let mut want = n("a");
        want.push(0);
        want.extend(n("b"));
        want.push(0);
        assert_eq!(data(s.list(&p("f"), 100)), want);
        assert_eq!(s.list(&p("f"), 0), Ok(Answer::Size(want.len() as u32)));
        assert_eq!(s.list(&p("other"), 0), Ok(Answer::Size(0)));
    }

    #[test]
    fn small_buffer_gives_erange() {
        let mut s = XattrStore::default();
        s.set(&p("f"), &n("a"), b"four", 0, 0).unwrap();
        assert_eq!(s.get(&p("f"), &n("a"), 3), Err(libc::ERANGE));
        assert_eq!(s.list(&p("f"), 1), Err(libc::ERANGE));
    }

    #[test]
    fn missing_attribute() {
        let s = XattrStore::default();
        assert_eq!(s.get(&p("f"), &n("a"), 10), Err(NO_XATTR));
        #[cfg(target_os = "macos")]
        assert_eq!(NO_XATTR, libc::ENOATTR);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(NO_XATTR, libc::ENODATA);
    }

    #[test]
    fn create_and_replace_flags() {
        let mut s = XattrStore::default();
        assert_eq!(
            s.set(&p("f"), &n("a"), b"x", libc::XATTR_REPLACE, 0),
            Err(NO_XATTR)
        );
        assert_eq!(
            s.set(&p("f"), &n("a"), b"x", libc::XATTR_CREATE, 0),
            Ok(Stored::Kept)
        );
        assert_eq!(
            s.set(&p("f"), &n("a"), b"y", libc::XATTR_CREATE, 0),
            Err(libc::EEXIST)
        );
        assert_eq!(
            s.set(&p("f"), &n("a"), b"y", libc::XATTR_REPLACE, 0),
            Ok(Stored::Kept)
        );
        assert_eq!(data(s.get(&p("f"), &n("a"), 10)), b"y");
    }

    #[test]
    fn other_flag_bits_are_ignored() {
        // macOS sends XATTR_NOSECURITY (0x8) for the quarantine attribute.
        let mut s = XattrStore::default();
        assert_eq!(s.set(&p("f"), &n("q"), b"x", 0x8, 0), Ok(Stored::Kept));
    }

    #[test]
    fn position_writes_into_the_old_value() {
        let mut s = XattrStore::default();
        s.set(&p("f"), &n("r"), b"abcd", 0, 0).unwrap();
        s.set(&p("f"), &n("r"), b"XY", 0, 2).unwrap();
        assert_eq!(data(s.get(&p("f"), &n("r"), 10)), b"abXY");
        s.set(&p("f"), &n("r"), b"Z", 0, 6).unwrap();
        assert_eq!(data(s.get(&p("f"), &n("r"), 10)), b"abXY\0\0Z");
        // Position 0 replaces the whole value.
        s.set(&p("f"), &n("r"), b"new", 0, 0).unwrap();
        assert_eq!(data(s.get(&p("f"), &n("r"), 10)), b"new");
    }

    #[test]
    fn huge_position_is_dropped_without_a_huge_buffer() {
        let mut s = XattrStore::default();
        s.set(&p("f"), &n("r"), b"old", 0, 0).unwrap();
        // Before the fix this grew a buffer of about 4 GiB first.
        assert_eq!(
            s.set(&p("f"), &n("r"), b"x", 0, u32::MAX),
            Ok(Stored::Dropped)
        );
        assert_eq!(s.get(&p("f"), &n("r"), 10), Err(NO_XATTR));
        assert_eq!(s.total(), 0);
        // A position just past the limit is dropped too, one inside is kept.
        let limit = MAX_ENTRY_BYTES - n("r").len();
        let past = u32::try_from(limit).unwrap();
        assert_eq!(s.set(&p("f"), &n("r"), b"x", 0, past), Ok(Stored::Dropped));
        let inside = u32::try_from(limit - 1).unwrap();
        assert_eq!(s.set(&p("f"), &n("r"), b"x", 0, inside), Ok(Stored::Kept));
        assert_eq!(s.total(), MAX_ENTRY_BYTES);
    }

    #[test]
    fn remove_is_quiet_and_frees_memory() {
        let mut s = XattrStore::default();
        s.remove(&p("f"), &n("a"));
        s.set(&p("f"), &n("a"), b"123", 0, 0).unwrap();
        assert_eq!(s.total(), n("a").len() + 3);
        s.remove(&p("f"), &n("a"));
        assert_eq!(s.get(&p("f"), &n("a"), 10), Err(NO_XATTR));
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn entry_limit_drops_and_removes_the_old_value() {
        let mut s = XattrStore::default();
        s.set(&p("f"), &n("a"), b"old", 0, 0).unwrap();
        let big = vec![7u8; MAX_ENTRY_BYTES];
        assert_eq!(s.set(&p("f"), &n("a"), &big, 0, 0), Ok(Stored::Dropped));
        assert_eq!(s.get(&p("f"), &n("a"), 10), Err(NO_XATTR));
        assert_eq!(s.total(), 0);
        // Just under the limit is kept.
        let fits = vec![7u8; MAX_ENTRY_BYTES - n("a").len()];
        assert_eq!(s.set(&p("f"), &n("a"), &fits, 0, 0), Ok(Stored::Kept));
    }

    #[test]
    fn total_limit_drops() {
        let mut s = XattrStore::default();
        let value = vec![1u8; MAX_ENTRY_BYTES - 16];
        let mut i = 0;
        while s.total() + n("a").len() + value.len() <= MAX_TOTAL_BYTES {
            let path = p(&format!("f{i}"));
            assert_eq!(s.set(&path, &n("a"), &value, 0, 0), Ok(Stored::Kept));
            i += 1;
        }
        let path = p(&format!("f{i}"));
        assert_eq!(s.set(&path, &n("a"), &value, 0, 0), Ok(Stored::Dropped));
        assert!(s.total() <= MAX_TOTAL_BYTES);
        // Small values still fit.
        assert_eq!(s.set(&path, &n("b"), b"x", 0, 0), Ok(Stored::Kept));
    }

    #[test]
    fn empty_name_is_dropped() {
        let mut s = XattrStore::default();
        assert_eq!(s.set(&p("f"), b"", b"x", 0, 0), Ok(Stored::Dropped));
        assert_eq!(s.total(), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_keeps_only_the_user_namespace() {
        let mut s = XattrStore::default();
        for name in ["security.selinux", "trusted.x", "system.posix_acl_access"] {
            assert_eq!(
                s.set(&p("f"), name.as_bytes(), b"x", 0, 0),
                Ok(Stored::Dropped)
            );
            assert_eq!(s.get(&p("f"), name.as_bytes(), 10), Err(NO_XATTR));
        }
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn rename_moves_the_subtree_and_replaces_the_target() {
        let mut s = XattrStore::default();
        s.set(&p("a"), &n("x"), b"1", 0, 0).unwrap();
        s.set(&p("a/c"), &n("x"), b"2", 0, 0).unwrap();
        s.set(&p("ab"), &n("x"), b"3", 0, 0).unwrap();
        s.set(&p("b"), &n("x"), b"old", 0, 0).unwrap();
        s.rename(&p("a"), &p("b"));
        assert_eq!(data(s.get(&p("b"), &n("x"), 10)), b"1");
        assert_eq!(data(s.get(&p("b/c"), &n("x"), 10)), b"2");
        assert_eq!(data(s.get(&p("ab"), &n("x"), 10)), b"3");
        assert_eq!(s.get(&p("a"), &n("x"), 10), Err(NO_XATTR));
        assert_eq!(s.get(&p("a/c"), &n("x"), 10), Err(NO_XATTR));
        assert_eq!(s.total(), 3 * (n("x").len() + 1));
    }

    #[test]
    fn rename_to_itself_keeps_everything() {
        let mut s = XattrStore::default();
        s.set(&p("a"), &n("x"), b"1", 0, 0).unwrap();
        s.rename(&p("a"), &p("a"));
        assert_eq!(data(s.get(&p("a"), &n("x"), 10)), b"1");
    }

    #[test]
    fn remove_path_drops_the_subtree_only() {
        let mut s = XattrStore::default();
        s.set(&p("a"), &n("x"), b"1", 0, 0).unwrap();
        s.set(&p("a/c"), &n("x"), b"2", 0, 0).unwrap();
        s.set(&p("ab"), &n("x"), b"3", 0, 0).unwrap();
        s.remove_path(&p("a"));
        assert_eq!(s.get(&p("a"), &n("x"), 10), Err(NO_XATTR));
        assert_eq!(s.get(&p("a/c"), &n("x"), 10), Err(NO_XATTR));
        assert_eq!(data(s.get(&p("ab"), &n("x"), 10)), b"3");
        assert_eq!(s.total(), n("x").len() + 1);
    }
}
