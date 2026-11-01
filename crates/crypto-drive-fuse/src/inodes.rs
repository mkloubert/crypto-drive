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

//! Maps inode numbers to clear paths for the kernel.

use crypto_drive_core::fs::VPath;
use std::collections::{BTreeMap, HashMap};

pub const ROOT_INO: u64 = 1;

struct Node {
    path: VPath,
    lookups: u64,
}

/// Inode number <-> clear path, with the kernel lookup count of each inode.
/// Inode numbers are never reused. The root is always present.
///
/// `by_ino` and `by_path` always hold the same inodes. `by_path` is sorted,
/// so a path and everything below it are one range (see `subtree`); a
/// rename or unlink costs the entries it touches, not the whole table.
pub struct InodeTable {
    by_ino: HashMap<u64, Node>,
    by_path: BTreeMap<VPath, u64>,
    next: u64,
}

/// The entries of `map` at or below `prefix`, in path order.
///
/// `VPath` orders by its components, so every path that starts with
/// `prefix` comes right after `prefix` itself, before any other path: the
/// range from `prefix` up to the first path that does not start with it.
pub(crate) fn subtree<'a, V>(
    map: &'a BTreeMap<VPath, V>,
    prefix: &'a VPath,
) -> impl Iterator<Item = (&'a VPath, &'a V)> {
    map.range(prefix..)
        .take_while(move |(path, _)| path.starts_with(prefix))
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable {
    pub fn new() -> Self {
        let mut t = InodeTable {
            by_ino: HashMap::new(),
            by_path: BTreeMap::new(),
            next: ROOT_INO + 1,
        };
        t.by_ino.insert(
            ROOT_INO,
            Node {
                path: VPath::root(),
                lookups: 0,
            },
        );
        t.by_path.insert(VPath::root(), ROOT_INO);
        t
    }

    /// Returns the inode of `path`, adding it if needed, and counts one
    /// kernel lookup.
    pub fn lookup(&mut self, path: &VPath) -> u64 {
        if let Some(&ino) = self.by_path.get(path)
            && let Some(node) = self.by_ino.get_mut(&ino)
        {
            node.lookups = node.lookups.saturating_add(1);
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(
            ino,
            Node {
                path: path.clone(),
                lookups: 1,
            },
        );
        self.by_path.insert(path.clone(), ino);
        ino
    }

    pub fn path(&self, ino: u64) -> Option<VPath> {
        self.by_ino.get(&ino).map(|n| n.path.clone())
    }

    /// The inode of `path` if the table knows it; never adds one.
    pub fn ino_of(&self, path: &VPath) -> Option<u64> {
        self.by_path.get(path).copied()
    }

    /// Drops `n` lookups; the inode is removed at zero. The root stays.
    pub fn forget(&mut self, ino: u64, n: u64) {
        if ino == ROOT_INO {
            return;
        }
        let Some(node) = self.by_ino.get_mut(&ino) else {
            return;
        };
        node.lookups = node.lookups.saturating_sub(n);
        if node.lookups == 0 {
            self.drop_ino(ino);
        }
    }

    /// Moves `from` and everything below it to `to`. Inodes that were at or
    /// below `to` before are dropped (the rename replaced them).
    pub fn rename(&mut self, from: &VPath, to: &VPath) {
        if from == to {
            return;
        }
        let replaced: Vec<u64> = subtree(&self.by_path, to)
            .filter(|(path, _)| !path.starts_with(from))
            .map(|(_, &ino)| ino)
            .collect();
        for ino in replaced {
            self.drop_ino(ino);
        }
        let moved: Vec<u64> = subtree(&self.by_path, from).map(|(_, &ino)| ino).collect();
        for ino in &moved {
            if let Some(node) = self.by_ino.get(ino) {
                self.by_path.remove(&node.path);
            }
        }
        for ino in moved {
            if let Some(node) = self.by_ino.get_mut(&ino)
                && let Some(new) = node.path.replace_prefix(from, to)
            {
                node.path = new.clone();
                self.by_path.insert(new, ino);
            }
        }
    }

    /// Drops the inodes of `path` and everything below it (after unlink or
    /// rmdir). The root stays.
    pub fn remove_path(&mut self, path: &VPath) {
        let gone: Vec<u64> = subtree(&self.by_path, path)
            .map(|(_, &ino)| ino)
            .filter(|&ino| ino != ROOT_INO)
            .collect();
        for ino in gone {
            self.drop_ino(ino);
        }
    }

    fn drop_ino(&mut self, ino: u64) {
        if ino == ROOT_INO {
            return;
        }
        if let Some(node) = self.by_ino.remove(&ino)
            && self.by_path.get(&node.path) == Some(&ino)
        {
            self.by_path.remove(&node.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_drive_core::fs::VPath;

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    /// Names that sort right next to "a" and its children.
    const NEAR_A: [&str; 8] = ["/a", "/a/x", "/a/x/y", "/a-b", "/a!", "/ab", "/a b", "/b"];

    #[test]
    fn subtree_is_exactly_the_paths_below() {
        let map: BTreeMap<VPath, u64> = NEAR_A.iter().map(|s| (p(s), 0)).collect();
        let below = |prefix: &str| -> Vec<String> {
            let prefix = p(prefix);
            subtree(&map, &prefix)
                .map(|(k, _)| format!("{k:?}"))
                .collect()
        };
        assert_eq!(below("/a").len(), 3);
        assert_eq!(below("/a/x").len(), 2);
        assert_eq!(below("/a-b").len(), 1);
        assert_eq!(below("/c"), Vec::<String>::new());
        assert_eq!(below("/").len(), NEAR_A.len());
    }

    #[test]
    fn subtree_matches_a_full_scan() {
        // Many paths from a small alphabet, so neighbours of every prefix
        // exist; compare the range with a scan of all paths.
        let parts = ["a", "a-b", "a!", "ab", "b", "a b", "ä", "z"];
        let mut seed: u64 = 42;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        let mut map = BTreeMap::new();
        for _ in 0..2000 {
            let depth = 1 + next() % 4;
            let path: Vec<&str> = (0..depth).map(|_| parts[next() % parts.len()]).collect();
            map.insert(p(&path.join("/")), 0u64);
        }
        for prefix in map.keys().cloned().collect::<Vec<_>>() {
            let range: Vec<&VPath> = subtree(&map, &prefix).map(|(k, _)| k).collect();
            let scan: Vec<&VPath> = map.keys().filter(|k| k.starts_with(&prefix)).collect();
            assert_eq!(range, scan, "prefix {prefix:?}");
        }
    }

    #[test]
    fn remove_and_rename_leave_neighbours_alone() {
        let mut t = InodeTable::new();
        let inos: Vec<u64> = NEAR_A.iter().map(|s| t.lookup(&p(s))).collect();
        t.remove_path(&p("/a/x"));
        assert_eq!(t.ino_of(&p("/a/x")), None);
        assert_eq!(t.ino_of(&p("/a/x/y")), None);
        assert_eq!(t.ino_of(&p("/a")), Some(inos[0]));
        t.rename(&p("/a"), &p("/b"));
        assert_eq!(t.ino_of(&p("/b")), Some(inos[0]), "moved");
        assert_eq!(t.path(inos[7]), None, "the old /b was replaced");
        for (i, s) in NEAR_A.iter().enumerate().skip(3).take(4) {
            assert_eq!(t.ino_of(&p(s)), Some(inos[i]), "{s} untouched");
        }
    }

    #[test]
    fn root_is_one() {
        let t = InodeTable::new();
        assert_eq!(ROOT_INO, 1);
        assert_eq!(t.path(ROOT_INO), Some(VPath::root()));
        assert_eq!(t.ino_of(&VPath::root()), Some(ROOT_INO));
    }

    #[test]
    fn lookup_twice_gives_same_ino() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        assert_ne!(a, ROOT_INO);
        assert_eq!(t.lookup(&p("a")), a);
        assert_eq!(t.path(a), Some(p("a")));
        assert_ne!(t.lookup(&p("b")), a);
    }

    #[test]
    fn forget_removes_at_zero_lookups() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        t.lookup(&p("a"));
        t.forget(a, 1);
        assert_eq!(t.path(a), Some(p("a")));
        t.forget(a, 1);
        assert_eq!(t.path(a), None);
        assert_eq!(t.ino_of(&p("a")), None);
        // A new lookup gives a new number; numbers are never reused.
        assert_ne!(t.lookup(&p("a")), a);
    }

    #[test]
    fn forget_on_root_keeps_it() {
        let mut t = InodeTable::new();
        t.forget(ROOT_INO, 5);
        assert_eq!(t.path(ROOT_INO), Some(VPath::root()));
    }

    #[test]
    fn forget_unknown_is_a_no_op() {
        let mut t = InodeTable::new();
        t.forget(42, 1);
        assert_eq!(t.path(42), None);
    }

    #[test]
    fn rename_moves_the_subtree() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        let x = t.lookup(&p("a/x"));
        let other = t.lookup(&p("ab"));
        t.rename(&p("a"), &p("b"));
        assert_eq!(t.path(a), Some(p("b")));
        assert_eq!(t.path(x), Some(p("b/x")));
        assert_eq!(t.path(other), Some(p("ab")));
        assert_eq!(t.ino_of(&p("a")), None);
        assert_eq!(t.ino_of(&p("a/x")), None);
        assert_eq!(t.ino_of(&p("b/x")), Some(x));
    }

    #[test]
    fn rename_onto_existing_path_drops_old_inode() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        let b = t.lookup(&p("b"));
        t.rename(&p("a"), &p("b"));
        assert_eq!(t.path(b), None);
        assert_eq!(t.path(a), Some(p("b")));
        assert_eq!(t.ino_of(&p("b")), Some(a));
        // A late forget of the dropped inode does not touch the moved one.
        t.forget(b, 1);
        assert_eq!(t.path(a), Some(p("b")));
    }

    #[test]
    fn rename_to_same_path_keeps_entry() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        t.rename(&p("a"), &p("a"));
        assert_eq!(t.path(a), Some(p("a")));
    }

    #[test]
    fn remove_path_drops_entry() {
        let mut t = InodeTable::new();
        let a = t.lookup(&p("a"));
        let keep = t.lookup(&p("ab"));
        t.remove_path(&p("a"));
        assert_eq!(t.path(a), None);
        assert_eq!(t.ino_of(&p("a")), None);
        assert_eq!(t.path(keep), Some(p("ab")));
    }

    #[test]
    fn remove_path_never_drops_root() {
        let mut t = InodeTable::new();
        t.remove_path(&VPath::root());
        assert_eq!(t.path(ROOT_INO), Some(VPath::root()));
    }
}
