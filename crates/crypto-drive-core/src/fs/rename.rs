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

//! Rename and move for all name layouts (spec 5.5).

use super::dirs::{CONTROL_FILE_MODE, ok_if_missing, remove_empty_dir, remove_file_entry};
use super::dirstate::{DirState, EntryRef, display_key};
use super::files::LONG_ENTRY_MODE;
use super::listing::Layout;
use super::{CryptoFs, VPath};
use crate::backing::DirHandle;
use crate::error::{Error, Result};
use crate::names::BackingName;
use crate::vault::{CONTENT_FILE, NAME_FILE};

#[cfg(test)]
thread_local! {
    /// Warnings about a replaced entry with conflict copies in this thread.
    static REPLACE_WARNINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many warnings about a replaced entry with conflict copies this
/// thread has logged.
#[cfg(test)]
pub(crate) fn replace_warnings() -> usize {
    REPLACE_WARNINGS.with(|c| c.get())
}

/// True if both handles are the same real directory.
fn same_dir(a: &DirHandle, b: &DirHandle) -> Result<bool> {
    let (a, b) = (a.stat_self()?, b.stat_self()?);
    Ok((a.dev, a.ino) == (b.dev, b.ino))
}

/// Writes the `.cd-name` of the long entry `entry` in `dir`.
pub(crate) fn write_name(dir: &DirHandle, entry: &str, full: &str) -> Result<()> {
    dir.open_dir(entry)?
        .write_atomic(NAME_FILE, full.as_bytes(), CONTROL_FILE_MODE)
}

/// Runs the finishing step `finish` after `from` in `from_dir` was renamed to
/// `to` in `to_dir`. If it fails, the rename is undone (best effort).
fn finish_or_undo(
    from_dir: &DirHandle,
    from: &str,
    to_dir: &DirHandle,
    to: &str,
    finish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let result = finish();
    if result.is_err()
        && let Err(e) = to_dir.rename(to, from_dir, from)
    {
        log::warn!("could not undo the rename of {from} to {to}: {e}");
    }
    result
}

/// Removes the long file entry `real` whose `.cd-content` was moved away.
/// The rename already happened, so a failure is only logged: the leftover
/// entry has no content, is hidden and is reported by `check`.
fn remove_emptied_long_entry(src_dir: &DirHandle, entry_dir: &DirHandle, real: &str) {
    let result = ok_if_missing(entry_dir.unlink(NAME_FILE)).and_then(|()| src_dir.rmdir(real));
    if let Err(e) = result {
        log::warn!("could not remove the old long entry {real}: {e}");
    }
}

/// Moves `src` over the existing `target` in `dst_dir`. The target is never
/// removed before the move succeeded, except an empty target directory.
/// Returns false if the move worked but the old target is still there.
fn replace_entry(
    src_dir: &DirHandle,
    src: &EntryRef,
    dst_dir: &DirHandle,
    target: &EntryRef,
    backing: &BackingName,
) -> Result<bool> {
    match (src.layout.is_dir(), target.layout.is_dir()) {
        (true, false) => Err(Error::NotADirectory),
        (false, true) => Err(Error::IsADirectory),
        (true, true) => {
            remove_empty_dir(dst_dir, target)?;
            move_entry(src_dir, src, dst_dir, backing).map(|()| true)
        }
        (false, false) => match backing {
            // `renameat` onto the same short name replaces it atomically.
            BackingName::Short(new) if *new == target.real => {
                move_entry(src_dir, src, dst_dir, backing).map(|()| true)
            }
            // The target entry keeps its `.cd-name`; only the content is
            // replaced.
            BackingName::Long { entry, .. } if *entry == target.real => {
                move_into_long_file(src_dir, src, dst_dir, entry).map(|()| true)
            }
            // Another real name (a conflict copy, another directory id):
            // move first, then remove the target. A crash leaves a duplicate.
            _ => {
                move_entry(src_dir, src, dst_dir, backing)?;
                if let Err(e) = remove_file_entry(dst_dir, target) {
                    log::warn!("could not remove the replaced entry {}: {e}", target.real);
                    return Ok(false);
                }
                Ok(true)
            }
        },
    }
}

/// Moves the file `src` into the existing long file entry `entry`, replacing
/// its `.cd-content` atomically.
pub(crate) fn move_into_long_file(
    src_dir: &DirHandle,
    src: &EntryRef,
    dst_dir: &DirHandle,
    entry: &str,
) -> Result<()> {
    let dir = dst_dir.open_dir(entry)?;
    if src.layout == Layout::LongFile {
        let src_entry = src_dir.open_dir(&src.real)?;
        src_entry.rename(CONTENT_FILE, &dir, CONTENT_FILE)?;
        remove_emptied_long_entry(src_dir, &src_entry, &src.real);
        Ok(())
    } else {
        src_dir.rename(&src.real, &dir, CONTENT_FILE)
    }
}

/// Moves `src` of `src_dir` to the real name `backing` in `dst_dir`. Each
/// order first builds the target and then removes the source, so a crash
/// leaves at most a duplicate or an orphan entry and never loses data.
pub(crate) fn move_entry(
    src_dir: &DirHandle,
    src: &EntryRef,
    dst_dir: &DirHandle,
    backing: &BackingName,
) -> Result<()> {
    let real = src.real.as_str();
    match (src.layout, backing) {
        (Layout::ShortFile | Layout::ShortDir, BackingName::Short(new)) => {
            src_dir.rename(real, dst_dir, new)
        }
        (Layout::ShortFile, BackingName::Long { entry, full }) => {
            dst_dir.mkdir(entry, LONG_ENTRY_MODE)?;
            let result = dst_dir.open_dir(entry).and_then(|dir| {
                dir.write_atomic(NAME_FILE, full.as_bytes(), CONTROL_FILE_MODE)?;
                src_dir.rename(real, &dir, CONTENT_FILE)
            });
            if result.is_err() {
                // The content did not move, so the new entry holds at most
                // its `.cd-name`.
                let cleanup = dst_dir.open_dir(entry).and_then(|dir| {
                    ok_if_missing(dir.unlink(NAME_FILE))?;
                    dst_dir.rmdir(entry)
                });
                if let Err(e) = cleanup {
                    log::warn!("could not remove the new long entry {entry}: {e}");
                }
            }
            result
        }
        // `.cd-name` first: a crash then leaves a short directory with a
        // stray `.cd-name` (ignored), never a long entry without a name
        // that would hide the directory and its children.
        (Layout::ShortDir, BackingName::Long { entry, full }) => {
            write_name(src_dir, real, full)?;
            let result = src_dir.rename(real, dst_dir, entry);
            if result.is_err() {
                let cleanup = src_dir
                    .open_dir(real)
                    .and_then(|dir| ok_if_missing(dir.unlink(NAME_FILE)));
                if let Err(e) = cleanup {
                    log::warn!("could not remove the new .cd-name of {real}: {e}");
                }
            }
            result
        }
        (Layout::LongFile, BackingName::Short(new)) => {
            let dir = src_dir.open_dir(real)?;
            dir.rename(CONTENT_FILE, dst_dir, new)?;
            remove_emptied_long_entry(src_dir, &dir, real);
            Ok(())
        }
        (Layout::LongDir, BackingName::Short(new)) => {
            src_dir.rename(real, dst_dir, new)?;
            finish_or_undo(src_dir, real, dst_dir, new, || {
                ok_if_missing(dst_dir.open_dir(new)?.unlink(NAME_FILE))
            })
        }
        (Layout::LongFile | Layout::LongDir, BackingName::Long { entry, full }) => {
            src_dir.rename(real, dst_dir, entry)?;
            finish_or_undo(src_dir, real, dst_dir, entry, || {
                write_name(dst_dir, entry, full)
            })
        }
    }
}

/// Logs that a rename replaced the entry `real`, which has sync conflict
/// copies with the same name (spec 2026-11-08 stable display names, 3.4).
/// Only the real name is logged, never a clear name.
fn warn_replaced_copy(real: &str) {
    #[cfg(test)]
    REPLACE_WARNINGS.with(|c| c.set(c.get() + 1));
    log::warn!(
        "a rename replaced the entry {real}, which has sync conflict copies with the same name; check them"
    );
}

impl CryptoFs {
    /// True if the target `target` of the name `to_name` in `dir` is a
    /// conflict entry or has conflict entries with the same clear name,
    /// not counting the entry `moving` (the source of the rename).
    fn has_conflict_copies(
        &self,
        dir: &DirState,
        target: &EntryRef,
        to_name: &str,
        moving: Option<&str>,
    ) -> Result<bool> {
        if target.conflict_of.is_some() {
            return Ok(true);
        }
        let clear = display_key(to_name);
        self.with_listing(dir, |l| {
            l.entries.values().any(|e| {
                e.conflict_of.as_deref() == Some(clear.as_str()) && Some(e.real.as_str()) != moving
            })
        })
    }

    /// Renames or moves a file or directory (spec 5.5). An existing target
    /// file or empty target directory is replaced. The new name is encrypted
    /// with the same entry id under the canonical id of the target parent
    /// and the write epoch (HS 3.2), which also gives a conflict copy a clean
    /// name. Content and `.cd-dir` are not touched. Open files keep working.
    pub fn rename(&self, from: &VPath, to: &VPath) -> Result<()> {
        let (Some(from_parent), Some(from_name), Some(to_parent), Some(to_name)) =
            (from.parent(), from.name(), to.parent(), to.name())
        else {
            return Err(Error::InvalidArgument);
        };
        if from == to {
            return Ok(());
        }
        if to.starts_with(from) {
            return Err(Error::InvalidArgument);
        }
        // A missing source is reported before a bad target parent.
        self.find(&*self.dir_state(&from_parent)?, from_name)?;
        // Both parents are locked for the whole change; one parent only
        // once, so source and target index are the same.
        let parents: Vec<&VPath> = if from_parent == to_parent {
            vec![&from_parent]
        } else {
            vec![&from_parent, &to_parent]
        };
        let mut moves_dir = false;
        let result = self.with_change(&parents, |dirs| {
            let (src_dir, dst_dir) = (&dirs[0], &dirs[dirs.len() - 1]);
            let src = self.find(src_dir, from_name)?;
            let target = self.find_for_change(dst_dir, to_name)?;
            if let Some(t) = &target
                && t.real == src.real
                && same_dir(&src_dir.handle, &dst_dir.handle)?
            {
                return Ok(());
            }
            moves_dir = src.layout.is_dir() || target.as_ref().is_some_and(|t| t.layout.is_dir());
            let replaces_copy = match &target {
                Some(t) if !t.layout.is_dir() => {
                    // The source leaves the group: renaming a copy over the
                    // plain name resolves the conflict.
                    let moving =
                        same_dir(&src_dir.handle, &dst_dir.handle)?.then_some(src.real.as_str());
                    self.has_conflict_copies(dst_dir, t, to_name, moving)?
                }
                _ => false,
            };
            let backing = self.new_entry_name(dst_dir, &src.entry_id, to_name)?;
            let result = match &target {
                Some(t) => replace_entry(&src_dir.handle, &src, &dst_dir.handle, t, &backing),
                None => move_entry(&src_dir.handle, &src, &dst_dir.handle, &backing).map(|()| true),
            };
            if replaces_copy
                && result.is_ok()
                && let Some(t) = &target
            {
                warn_replaced_copy(&t.real);
            }
            // After a failure partway the indexes are built again.
            let index_ok = matches!(result, Ok(true));
            if index_ok {
                let to_key = display_key(to_name);
                self.index_remove(src_dir, &display_key(from_name));
                self.index_remove(dst_dir, &to_key);
                let entry = self.new_entry_ref(&backing, src.layout.is_dir(), src.entry_id);
                self.index_insert(dst_dir, to_key, entry)?;
            }
            for dir in dirs {
                self.end_change(dir, index_ok);
            }
            result.map(|_| ())
        });
        // A moved directory has a new path, a replaced one is gone: drop
        // their cached subtrees, also after a failure partway.
        if moves_dir {
            self.invalidate(from);
            self.invalidate(to);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CryptoFs, FileKind, VPath};
    use crate::Error;
    use crate::keys::{DirId, MasterKey};
    use crate::names::{BackingName, LONG_PREFIX, NameKeys};
    use crate::testutil::{real_name_of, test_vault, test_vault_with};
    use crate::vault::{CONTROL_PREFIX, NAME_FILE, UnlockedVault, open_with_master_key};
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
        let names = NameKeys::new(&v.keys);
        let root = v.root_path.clone();
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
        /// The real name of the existing entry `name` in the root.
        fn real(&self, name: &str) -> String {
            real_name_of(&self.names, &self.vault_id, &self.root, name)
        }
    }

    fn fx() -> Fx {
        fx_from(test_vault())
    }

    fn fx64() -> Fx {
        fx_from(test_vault_with(64))
    }

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    fn write_file(fs: &CryptoFs, path: &str, data: &[u8]) {
        let (_, h) = fs.create(&p(path), 0o644).unwrap();
        fs.write(h, 0, data).unwrap();
        fs.release(h).unwrap();
    }

    fn read_file(fs: &CryptoFs, path: &str) -> Vec<u8> {
        let h = fs.open(&p(path), false, false).unwrap();
        let data = fs.read(h, 0, 1 << 20).unwrap();
        fs.release(h).unwrap();
        data
    }

    fn listed(fs: &CryptoFs, path: &str) -> Vec<String> {
        fs.readdir(&p(path))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    /// Real entries of `dir` that are not control files (long entries count).
    fn user_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with(CONTROL_PREFIX) || n.starts_with(LONG_PREFIX))
            .collect();
        v.sort();
        v
    }

    fn only_entry(dir: &Path) -> PathBuf {
        let v = user_names(dir);
        assert_eq!(v.len(), 1, "entries: {v:?}");
        dir.join(&v[0])
    }

    fn is_long(real: &Path) -> bool {
        real.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(LONG_PREFIX)
    }

    /// The inode of the real directory of `path`.
    fn dir_ino(fs: &CryptoFs, path: &str) -> u64 {
        fs.dir_state(&p(path))
            .unwrap()
            .handle
            .stat_self()
            .unwrap()
            .ino
    }

    #[test]
    fn rename_file_in_same_dir() {
        let f = fx();
        write_file(&f.fs, "a.txt", b"content");
        f.fs.rename(&p("a.txt"), &p("b.txt")).unwrap();
        assert_eq!(read_file(&f.fs, "b.txt"), b"content");
        assert!(matches!(f.fs.getattr(&p("a.txt")), Err(Error::NotFound)));
        assert_eq!(listed(&f.fs, "/"), vec!["b.txt"]);
    }

    #[test]
    fn rename_moves_file_into_other_dir() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "a.txt", b"moved");
        let old_enc = f.real("a.txt");
        f.fs.rename(&p("a.txt"), &p("d/a.txt")).unwrap();
        assert_eq!(read_file(&f.fs, "d/a.txt"), b"moved");
        assert!(matches!(f.fs.getattr(&p("a.txt")), Err(Error::NotFound)));
        assert_eq!(listed(&f.fs, "/"), vec!["d"]);
        assert_eq!(listed(&f.fs, "d"), vec!["a.txt"]);
        let real_d = only_entry(&f.root);
        let inside = user_names(&real_d);
        assert_eq!(inside.len(), 1);
        assert_ne!(inside[0], old_enc);
    }

    #[test]
    fn rename_moves_dir_with_children_in_one_step() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.mkdir(&p("d/sub"), 0o755).unwrap();
        write_file(&f.fs, "d/sub/x", b"child");
        f.fs.mkdir(&p("t"), 0o755).unwrap();
        let ino = dir_ino(&f.fs, "d");
        f.fs.rename(&p("d"), &p("t/e")).unwrap();
        assert_eq!(dir_ino(&f.fs, "t/e"), ino);
        assert_eq!(read_file(&f.fs, "t/e/sub/x"), b"child");
        assert_eq!(listed(&f.fs, "t/e"), vec!["sub"]);
        assert!(matches!(f.fs.getattr(&p("d")), Err(Error::NotFound)));
        assert!(matches!(f.fs.readdir(&p("d/sub")), Err(Error::NotFound)));
    }

    #[test]
    fn own_rename_updates_both_indexes() {
        let f = fx();
        f.fs.mkdir(&p("a"), 0o755).unwrap();
        f.fs.mkdir(&p("b"), 0o755).unwrap();
        write_file(&f.fs, "a/x", b"x");
        write_file(&f.fs, "b/y", b"y");
        f.fs.mkdir(&p("a/sub"), 0o755).unwrap();
        // Settle: listings built after the racy window are not built again.
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(listed(&f.fs, "a"), vec!["sub", "x"]);
        assert_eq!(listed(&f.fs, "b"), vec!["y"]);
        assert_eq!(listed(&f.fs, "/"), vec!["a", "b"]);
        let built = super::super::listing::listings_built();
        f.fs.rename(&p("a/x"), &p("b/z")).unwrap();
        f.fs.rename(&p("b/y"), &p("b/w")).unwrap();
        assert_eq!(listed(&f.fs, "a"), vec!["sub"]);
        assert_eq!(listed(&f.fs, "b"), vec!["w", "z"]);
        assert_eq!(listed(&f.fs, "/"), vec!["a", "b"]);
        assert_eq!(read_file(&f.fs, "b/z"), b"x");
        assert_eq!(super::super::listing::listings_built(), built);
        // A moved directory is found under its new path only.
        f.fs.rename(&p("a/sub"), &p("b/sub2")).unwrap();
        assert!(listed(&f.fs, "a").is_empty());
        assert_eq!(listed(&f.fs, "b"), vec!["sub2", "w", "z"]);
        assert!(matches!(f.fs.readdir(&p("a/sub")), Err(Error::NotFound)));
        assert!(f.fs.readdir(&p("b/sub2")).unwrap().is_empty());
    }

    /// Renames `from` to `to` in the root and checks listing and content.
    /// Directories hold a child file "c" with the content.
    fn layout_change(dir: bool, from: &str, to: &str, to_long: bool) {
        let f = fx64();
        if dir {
            f.fs.mkdir(&p(from), 0o755).unwrap();
            write_file(&f.fs, &format!("{from}/c"), b"inside");
        } else {
            write_file(&f.fs, from, b"inside");
        }
        f.fs.rename(&p(from), &p(to)).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec![to.to_string()]);
        let real = only_entry(&f.root);
        assert_eq!(is_long(&real), to_long, "{real:?}");
        if to_long {
            assert!(real.join(NAME_FILE).is_file());
        } else if dir {
            assert!(!real.join(NAME_FILE).exists());
        }
        let file = if dir {
            format!("{to}/c")
        } else {
            to.to_string()
        };
        assert_eq!(read_file(&f.fs, &file), b"inside");
        let kind = f.fs.getattr(&p(to)).unwrap().kind;
        let want = if dir {
            FileKind::Directory
        } else {
            FileKind::File
        };
        assert_eq!(kind, want);
        assert!(matches!(f.fs.getattr(&p(from)), Err(Error::NotFound)));
    }

    fn long(c: char) -> String {
        c.to_string().repeat(100)
    }

    /// The states a crash can leave in a rename of a short directory to a
    /// long name: before anything, after `.cd-name` was written into the
    /// short directory, and after the rename. Each one is readable.
    #[test]
    fn short_dir_to_long_after_a_crash_at_any_point_is_readable() {
        for stop in 0..3 {
            let f = fx64();
            f.fs.mkdir(&p("d"), 0o755).unwrap();
            write_file(&f.fs, "d/c", b"inside");
            let real = f.real("d");
            let backing = f.fs.new_entry_name(
                &f.fs.dir_state(&p("/")).unwrap(),
                &real_entry_id(&f, &real),
                &long('d'),
            );
            let BackingName::Long { entry, full } = backing.unwrap() else {
                panic!("not long");
            };
            let short = f.root.join(&real);
            if stop >= 1 {
                std::fs::write(short.join(NAME_FILE), &full).unwrap();
            }
            if stop >= 2 {
                std::fs::rename(&short, f.root.join(&entry)).unwrap();
            }
            let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
            let want = if stop == 2 { long('d') } else { "d".to_owned() };
            assert_eq!(listed(&fs, "/"), vec![want.clone()], "stop {stop}");
            assert_eq!(read_file(&fs, &format!("{want}/c")), b"inside");
            // A stray `.cd-name` in the short directory is ignored: check
            // finds nothing, and the directory can be removed.
            let vault = open_with_master_key(&f.root, &f.mk).unwrap();
            let findings = crate::check::check_vault(&vault).unwrap();
            assert!(findings.is_empty(), "stop {stop}: {findings:?}");
            fs.unlink(&p(&format!("{want}/c"))).unwrap();
            fs.rmdir(&p(&want)).unwrap();
            assert!(listed(&fs, "/").is_empty(), "stop {stop}");
        }
    }

    /// The entry id of the root entry `real`.
    fn real_entry_id(f: &Fx, real: &str) -> crate::keys::EntryId {
        f.names.decrypt_any(&f.vault_id, real).unwrap().1
    }

    #[test]
    fn failed_short_dir_to_long_rename_leaves_no_name_file() {
        if is_root() {
            return;
        }
        let f = fx64();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.mkdir(&p("e"), 0o755).unwrap();
        let real_e = f.root.join(f.real("e"));
        // The target parent cannot be written, so the rename fails.
        set_mode(&real_e, 0o500);
        let result = f.fs.rename(&p("d"), &p(&format!("e/{}", long('d'))));
        set_mode(&real_e, 0o700);
        assert!(result.is_err(), "{result:?}");
        assert!(!f.root.join(f.real("d")).join(NAME_FILE).exists());
        assert_eq!(listed(&f.fs, "/"), vec!["d", "e"]);
    }

    #[test]
    fn rename_short_file_to_short() {
        layout_change(false, "a", "b", false);
    }

    #[test]
    fn rename_short_file_to_long() {
        layout_change(false, "a", &long('b'), true);
    }

    #[test]
    fn rename_long_file_to_short() {
        layout_change(false, &long('a'), "b", false);
    }

    #[test]
    fn rename_long_file_to_long() {
        layout_change(false, &long('a'), &long('b'), true);
    }

    #[test]
    fn rename_short_dir_to_short() {
        layout_change(true, "a", "b", false);
    }

    #[test]
    fn rename_short_dir_to_long() {
        layout_change(true, "a", &long('b'), true);
    }

    #[test]
    fn rename_long_dir_to_short() {
        layout_change(true, &long('a'), "b", false);
    }

    #[test]
    fn rename_long_dir_to_long() {
        layout_change(true, &long('a'), &long('b'), true);
    }

    #[test]
    fn rename_long_dir_into_other_dir_keeps_inode() {
        let f = fx64();
        let name = long('a');
        f.fs.mkdir(&p(&name), 0o755).unwrap();
        write_file(&f.fs, &format!("{name}/c"), b"x");
        f.fs.mkdir(&p("t"), 0o755).unwrap();
        let ino = dir_ino(&f.fs, &name);
        let to = format!("t/{}", long('b'));
        f.fs.rename(&p(&name), &p(&to)).unwrap();
        assert_eq!(dir_ino(&f.fs, &to), ino);
        assert_eq!(read_file(&f.fs, &format!("{to}/c")), b"x");
        assert_eq!(listed(&f.fs, "/"), vec!["t"]);
    }

    #[test]
    fn rename_replaces_existing_file() {
        let f = fx();
        write_file(&f.fs, "a", b"new");
        write_file(&f.fs, "b", b"old content");
        f.fs.rename(&p("a"), &p("b")).unwrap();
        assert_eq!(read_file(&f.fs, "b"), b"new");
        assert_eq!(listed(&f.fs, "/"), vec!["b"]);
        assert_eq!(user_names(&f.root).len(), 1);
    }

    #[test]
    fn rename_replaces_existing_file_with_long_names() {
        let f = fx64();
        let (a, b) = (long('a'), long('b'));
        // long over long, short over long, long over short
        for (from, to) in [
            (a.as_str(), b.as_str()),
            ("s", b.as_str()),
            (a.as_str(), "s"),
        ] {
            write_file(&f.fs, from, b"new");
            write_file(&f.fs, to, b"old content");
            f.fs.rename(&p(from), &p(to)).unwrap();
            assert_eq!(read_file(&f.fs, to), b"new");
            assert_eq!(listed(&f.fs, "/"), vec![to.to_string()]);
            assert_eq!(user_names(&f.root).len(), 1);
            f.fs.unlink(&p(to)).unwrap();
        }
    }

    #[test]
    fn rename_replaces_empty_dir() {
        let f = fx64();
        for to in ["e".to_string(), long('e')] {
            f.fs.mkdir(&p("d"), 0o755).unwrap();
            write_file(&f.fs, "d/x", b"1");
            f.fs.mkdir(&p(&to), 0o755).unwrap();
            f.fs.rename(&p("d"), &p(&to)).unwrap();
            assert_eq!(listed(&f.fs, "/"), vec![to.clone()]);
            assert_eq!(read_file(&f.fs, &format!("{to}/x")), b"1");
            assert_eq!(user_names(&f.root).len(), 1);
            f.fs.unlink(&p(&format!("{to}/x"))).unwrap();
            f.fs.rmdir(&p(&to)).unwrap();
        }
    }

    #[test]
    fn rename_over_non_empty_dir_is_not_empty() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.mkdir(&p("e"), 0o755).unwrap();
        write_file(&f.fs, "e/x", b"keep");
        assert!(matches!(
            f.fs.rename(&p("d"), &p("e")),
            Err(Error::NotEmpty)
        ));
        assert_eq!(read_file(&f.fs, "e/x"), b"keep");
        assert_eq!(listed(&f.fs, "/"), vec!["d", "e"]);
    }

    #[test]
    fn rename_mixing_file_and_dir_fails() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "a", b"1");
        assert!(matches!(
            f.fs.rename(&p("d"), &p("a")),
            Err(Error::NotADirectory)
        ));
        assert!(matches!(
            f.fs.rename(&p("a"), &p("d")),
            Err(Error::IsADirectory)
        ));
        assert_eq!(listed(&f.fs, "/"), vec!["a", "d"]);
    }

    #[test]
    fn rename_into_own_child_is_invalid_argument() {
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        f.fs.mkdir(&p("d/c"), 0o755).unwrap();
        assert!(matches!(
            f.fs.rename(&p("d"), &p("d/c/x")),
            Err(Error::InvalidArgument)
        ));
        assert!(matches!(
            f.fs.rename(&p("d"), &p("d/x")),
            Err(Error::InvalidArgument)
        ));
        assert!(matches!(
            f.fs.rename(&VPath::root(), &p("x")),
            Err(Error::InvalidArgument)
        ));
        assert!(matches!(
            f.fs.rename(&p("d"), &VPath::root()),
            Err(Error::InvalidArgument)
        ));
        assert_eq!(listed(&f.fs, "d"), vec!["c"]);
    }

    #[test]
    fn rename_onto_itself_does_nothing() {
        let f = fx();
        write_file(&f.fs, "caf\u{e9}", b"same");
        f.fs.rename(&p("caf\u{e9}"), &p("caf\u{e9}")).unwrap();
        f.fs.rename(&p("caf\u{e9}"), &p("cafe\u{301}")).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["caf\u{e9}"]);
        assert_eq!(read_file(&f.fs, "caf\u{e9}"), b"same");
    }

    #[test]
    fn missing_source_comes_before_a_file_as_target_parent() {
        let f = fx();
        write_file(&f.fs, "f", b"1");
        // The model order: the source is checked first.
        assert!(matches!(
            f.fs.rename(&p("missing"), &p("f/x")),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn rename_into_missing_parent_is_not_found() {
        let f = fx();
        write_file(&f.fs, "a", b"1");
        assert!(matches!(
            f.fs.rename(&p("a"), &p("nope/a")),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            f.fs.rename(&p("missing"), &p("b")),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            f.fs.rename(&p("a"), &p("a/b")),
            Err(Error::InvalidArgument)
        ));
        write_file(&f.fs, "f", b"2");
        assert!(matches!(
            f.fs.rename(&p("a"), &p("f/b")),
            Err(Error::NotADirectory)
        ));
        assert_eq!(read_file(&f.fs, "a"), b"1");
    }

    #[test]
    fn rename_keeps_open_handle_working() {
        let f = fx64();
        write_file(&f.fs, "a", b"before");
        let h = f.fs.open(&p("a"), true, false).unwrap();
        // short -> long moves the real file into a new entry directory
        let to = long('b');
        f.fs.rename(&p("a"), &p(&to)).unwrap();
        assert_eq!(f.fs.read(h, 0, 100).unwrap(), b"before");
        f.fs.write(h, 6, b" after").unwrap();
        f.fs.release(h).unwrap();
        assert_eq!(read_file(&f.fs, &to), b"before after");
    }

    #[test]
    fn rename_conflict_copy_gets_a_clean_name() {
        let f = fx();
        write_file(&f.fs, "a.txt", b"copy");
        let real = only_entry(&f.root);
        let mut copy = real.clone().into_os_string();
        copy.push(" (1)");
        std::fs::copy(&real, &copy).unwrap();
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(listed(&f.fs, "/"), vec!["a (conflict 1).txt", "a.txt"]);
        f.fs.rename(&p("a (conflict 1).txt"), &p("b.txt")).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["a.txt", "b.txt"]);
        assert_eq!(read_file(&f.fs, "b.txt"), b"copy");
        assert!(user_names(&f.root).iter().all(|n| !n.ends_with(" (1)")));
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The real directory of the clear directory `d` in the root (the root
    /// may also hold long file entries, which have no `.cd-dir`).
    fn real_dir_in_root(f: &Fx) -> PathBuf {
        let v: Vec<PathBuf> = user_names(&f.root)
            .into_iter()
            .map(|n| f.root.join(n))
            .filter(|p| p.join(".cd-dir").is_file())
            .collect();
        assert_eq!(v.len(), 1, "{v:?}");
        v.into_iter().next().unwrap()
    }

    /// Root ignores directory permissions, so the injected failure cannot happen.
    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    /// Moves "d/<from>" over the existing root file `to` while the real
    /// directory that holds the source content cannot be written. The move
    /// fails, and both the source and the target keep their content.
    fn failed_replace_keeps_both(from: &str, to: &str) {
        if is_root() {
            return;
        }
        let f = fx64();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, &format!("d/{from}"), b"new");
        write_file(&f.fs, to, b"old content");
        let real_d = real_dir_in_root(&f);
        let src_parent = if from.len() > 50 {
            only_entry(&real_d)
        } else {
            real_d
        };
        set_mode(&src_parent, 0o500);
        let result = f.fs.rename(&p(&format!("d/{from}")), &p(to));
        set_mode(&src_parent, 0o700);
        assert!(result.is_err(), "{result:?}");
        assert_eq!(read_file(&f.fs, &format!("d/{from}")), b"new");
        assert_eq!(read_file(&f.fs, to), b"old content");
    }

    #[test]
    fn rename_failed_replace_short_over_short_keeps_both() {
        failed_replace_keeps_both("s", "t");
    }

    #[test]
    fn rename_failed_replace_long_over_short_keeps_both() {
        failed_replace_keeps_both(&long('a'), "t");
    }

    #[test]
    fn rename_failed_replace_short_over_long_keeps_both() {
        failed_replace_keeps_both("s", &long('b'));
    }

    #[test]
    fn rename_failed_replace_long_over_long_keeps_both() {
        failed_replace_keeps_both(&long('a'), &long('b'));
    }

    /// Makes a real conflict copy " (1)" of the root file `name`.
    fn conflict_copy(f: &Fx, name: &str, data: &[u8]) {
        write_file(&f.fs, name, data);
        let enc = f.real(name);
        let real = f.root.join(&enc);
        std::fs::copy(&real, f.root.join(format!("{enc} (1)"))).unwrap();
        // An outside change: seen at once only after the racy window.
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
    }

    #[test]
    fn rename_over_conflict_copy_moves_first_then_removes_it() {
        let f = fx();
        conflict_copy(&f, "a.txt", b"old content");
        write_file(&f.fs, "x", b"new");
        f.fs.rename(&p("x"), &p("a (conflict 1).txt")).unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["a (conflict 1).txt", "a.txt"]);
        assert_eq!(read_file(&f.fs, "a (conflict 1).txt"), b"new");
        assert_eq!(read_file(&f.fs, "a.txt"), b"old content");
        // The old conflict copy is gone: one entry per name.
        assert_eq!(user_names(&f.root).len(), 2);
        assert!(user_names(&f.root).iter().all(|n| !n.ends_with(" (1)")));
    }

    #[test]
    fn rename_failed_replace_of_conflict_copy_keeps_both() {
        if is_root() {
            return;
        }
        let f = fx();
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, "d/x", b"new");
        conflict_copy(&f, "a.txt", b"old content");
        let real_d = real_dir_in_root(&f);
        set_mode(&real_d, 0o500);
        let result = f.fs.rename(&p("d/x"), &p("a (conflict 1).txt"));
        set_mode(&real_d, 0o700);
        assert!(result.is_err(), "{result:?}");
        assert_eq!(read_file(&f.fs, "d/x"), b"new");
        assert_eq!(read_file(&f.fs, "a (conflict 1).txt"), b"old content");
    }

    #[test]
    fn rename_long_over_long_leaves_one_entry() {
        let f = fx64();
        let (a, b) = (long('a'), long('b'));
        f.fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(&f.fs, &format!("d/{a}"), b"new");
        write_file(&f.fs, &b, b"old content");
        f.fs.rename(&p(&format!("d/{a}")), &p(&b)).unwrap();
        assert_eq!(read_file(&f.fs, &b), b"new");
        assert!(listed(&f.fs, "d").is_empty());
        assert!(user_names(&real_dir_in_root(&f)).is_empty());
        assert_eq!(listed(&f.fs, "/"), vec![b.clone(), "d".to_string()]);
    }

    #[test]
    fn many_renames_keep_entry_id() {
        let f = fx64();
        f.fs.mkdir(&p("sub"), 0o755).unwrap();
        conflict_copy(&f, "c.txt", b"other file");
        let data = b"the content that moves around";
        write_file(&f.fs, "f", data);
        let targets = [
            long('a'),
            "s1".to_string(),
            "sub/s2".to_string(),
            format!("sub/{}", long('b')),
            long('c'),
            "s3".to_string(),
            "c (conflict 1).txt".to_string(),
            "s4".to_string(),
            "sub/x (conflict 1).txt".to_string(),
            "s5".to_string(),
            long('d'),
            "sub/s6".to_string(),
            "s7".to_string(),
            format!("sub/{}", long('e')),
            long('f'),
            "sub/s8".to_string(),
            "s9".to_string(),
            long('g'),
            "s10".to_string(),
            "final".to_string(),
        ];
        assert_eq!(targets.len(), 20);
        let mut from = "f".to_string();
        for to in targets {
            f.fs.rename(&p(&from), &p(&to)).unwrap();
            assert_eq!(read_file(&f.fs, &to), data, "after rename to {to}");
            assert!(matches!(f.fs.getattr(&p(&from)), Err(Error::NotFound)));
            from = to;
        }
        assert_eq!(listed(&f.fs, "/"), vec!["c.txt", "final", "sub"]);
        assert!(listed(&f.fs, "sub").is_empty());
        assert_eq!(read_file(&f.fs, "c.txt"), b"other file");
        let v = open_with_master_key(&f.root, &f.mk).unwrap();
        let findings = crate::check::check_vault(&v).unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// Plants an entry "from another device" with the clear name `name` and
    /// the content `data` in the root: a file made through the drive (so
    /// content and entry id match) whose real file is renamed from outside
    /// to the encrypted `name` under its own entry id. Tries new files until
    /// that real name sorts before `before`. Returns the planted real name.
    fn plant_same_name(f: &Fx, name: &str, data: &[u8], before: &str) -> String {
        for _ in 0..64 {
            write_file(&f.fs, "plant.tmp", data);
            let tmp = f.real("plant.tmp");
            let (_, entry_id, _) = f.names.decrypt_any(&f.vault_id, &tmp).unwrap();
            let new = f.names.encrypt_write(&f.vault_id, &entry_id, name).unwrap();
            if new.as_str() < before {
                std::fs::rename(f.root.join(&tmp), f.root.join(&new)).unwrap();
                f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
                return new;
            }
            f.fs.unlink(&p("plant.tmp")).unwrap();
        }
        panic!("no planted name sorts before {before}");
    }

    /// `notes.txt` with "A", then a planted `notes.txt` with "B" that sorts
    /// first. Returns the real names of A and B.
    fn notes_with_arrived_copy(f: &Fx) -> (String, String) {
        write_file(&f.fs, "notes.txt", b"A");
        let a = f.real("notes.txt");
        // The drive has shown the directory before the copy arrives.
        assert!(listed(&f.fs, "/").contains(&"notes.txt".to_owned()));
        let b = plant_same_name(f, "notes.txt", b"B", &a);
        (a, b)
    }

    #[test]
    fn plain_name_stays_when_copy_arrives() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(
            listed(&f.fs, "/"),
            vec!["notes (conflict 1).txt", "notes.txt"]
        );
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        assert_eq!(read_file(&f.fs, "notes (conflict 1).txt"), b"B");
    }

    #[test]
    fn own_save_replaces_own_entry_not_the_arrived_one() {
        let f = fx();
        let (_, b) = notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        // An editor saves through a temporary file and a rename.
        write_file(&f.fs, "tmp", b"A2");
        f.fs.rename(&p("tmp"), &p("notes.txt")).unwrap();
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A2");
        assert_eq!(read_file(&f.fs, "notes (conflict 1).txt"), b"B");
        assert!(f.root.join(&b).exists(), "the other device's entry is gone");
    }

    #[test]
    fn plain_name_stays_after_racy_rebuild() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        // An own change, then the listing is built again after the window.
        write_file(&f.fs, "other", b"x");
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        assert_eq!(read_file(&f.fs, "notes (conflict 1).txt"), b"B");
    }

    #[test]
    fn conflict_numbers_stay_after_one_is_removed() {
        let f = fx();
        let (a, b) = notes_with_arrived_copy(&f);
        let c = plant_same_name(&f, "notes.txt", b"C", &a);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        let one = read_file(&f.fs, "notes (conflict 1).txt");
        let two = read_file(&f.fs, "notes (conflict 2).txt");
        let real_one = if one == b"B" { &b } else { &c };
        std::fs::remove_file(f.root.join(real_one)).unwrap();
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(
            listed(&f.fs, "/"),
            vec!["notes (conflict 2).txt", "notes.txt"]
        );
        assert_eq!(read_file(&f.fs, "notes (conflict 2).txt"), two);
    }

    #[test]
    fn freed_plain_name_is_not_taken_by_copy() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        f.fs.unlink(&p("notes.txt")).unwrap();
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(listed(&f.fs, "/"), vec!["notes (conflict 1).txt"]);
        assert_eq!(read_file(&f.fs, "notes (conflict 1).txt"), b"B");
    }

    #[test]
    fn names_follow_sort_order_after_remount() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        let fs = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
        assert_eq!(read_file(&fs, "notes.txt"), b"B");
        assert_eq!(read_file(&fs, "notes (conflict 1).txt"), b"A");
    }

    #[test]
    fn previous_survives_unkept_listing() {
        let f = fx();
        write_file(&f.fs, "other", b"x");
        let other = f.real("other");
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        // One unreadable entry: the next listing is used but not kept.
        crate::fs::listing::fail_stat_of(Some(other));
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        std::fs::write(f.root.join(".touch"), b"").unwrap();
        f.fs.advance_clock(crate::fs::dirstate::RACY_WINDOW);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        crate::fs::listing::fail_stat_of(None);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
    }

    #[test]
    fn rename_over_entry_with_conflict_copy_warns() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        let before = super::replace_warnings();
        write_file(&f.fs, "tmp", b"A2");
        f.fs.rename(&p("tmp"), &p("notes.txt")).unwrap();
        assert_eq!(super::replace_warnings(), before + 1);
        // A name without conflict copies: no warning.
        write_file(&f.fs, "other.txt", b"o");
        write_file(&f.fs, "tmp2", b"o2");
        f.fs.rename(&p("tmp2"), &p("other.txt")).unwrap();
        assert_eq!(super::replace_warnings(), before + 1);
    }

    #[test]
    fn renaming_the_copy_over_the_plain_name_does_not_warn() {
        let f = fx();
        notes_with_arrived_copy(&f);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"A");
        let before = super::replace_warnings();
        // The user keeps the copy: the documented way to resolve a conflict.
        f.fs.rename(&p("notes (conflict 1).txt"), &p("notes.txt"))
            .unwrap();
        assert_eq!(listed(&f.fs, "/"), vec!["notes.txt"]);
        assert_eq!(read_file(&f.fs, "notes.txt"), b"B");
        assert_eq!(super::replace_warnings(), before);
    }
}
