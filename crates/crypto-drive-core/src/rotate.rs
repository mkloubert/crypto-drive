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

//! Master key rotation (HS 9). The run is offline (it holds the vault lock)
//! and can be resumed after a crash at any point.
//!
//! Every write step builds the new state before it removes the old one, so
//! a crash leaves at most a duplicate (both entries readable) or a leftover
//! temporary file. The next run cleans these up and goes on.

use crate::backing::{DirHandle, stat_file};
use crate::conflict::{long_candidate, rotation_conflict_name, short_candidates};
use crate::content::CHUNK_SIZE;
use crate::error::{Error, Result};
use crate::file::{OpenFile, header_epoch};
use crate::fs::dirs::{MODE_MASK, ok_if_missing, remove_file_entry};
use crate::fs::dirstate::{EntryRef, NAME_TMP_FILE, read_dir_ids};
use crate::fs::listing::{Layout, long_layout, open_entry_dir, read_long_name};
use crate::fs::rename::{move_entry, move_into_long_file, write_name};
use crate::keyfile::{Argon2Params, KeyFile};
use crate::keys::{DirId, EntryId, Epoch, KeySet, MasterKey, random_entry_id};
use crate::names::{BackingName, NameKeys, long_entry_name, to_backing_name, validate_name};
use crate::recovery::encode_recovery_key;
use crate::vault::{
    CONTENT_FILE, KEY_FILE, NAME_FILE, VaultKeys, VaultMarker, key_file_path, lock_vault,
    open_with_key_set, write_marker,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The temporary file of a re-encrypted file, in the file's real directory.
pub const ROT_TMP_FILE: &str = ".cd-rot.tmp";
/// Highest N looked at for an existing rotation conflict copy.
const MAX_ROTATION_CONFLICTS: u32 = 64;
/// Mode of the temporary file until it gets the mode of the old file.
const TMP_MODE: u32 = 0o600;

pub struct RotateOptions {
    /// Key file outside the vault; `None` means `<vault>/.cd-key`.
    pub key_file: Option<PathBuf>,
    /// New Argon2 parameters; `None` keeps the ones of the key file.
    pub argon2: Option<Argon2Params>,
}

pub struct RotateReport {
    /// The recovery key of the new epoch. `Some` only in the run that
    /// started the rotation.
    pub new_recovery_key: Option<String>,
    /// Entries that use the new epoch after this run's walk.
    pub entries_done: u64,
    pub new_epoch: Epoch,
    /// Always true in a returned report: leftovers give an error.
    pub finished: bool,
}

#[cfg(any(test, feature = "test-util"))]
thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test hook: after `n` more write steps in this thread, the next step
/// fails with `Error::Io(Interrupted)` and nothing of it is written.
/// `None` turns the hook off.
#[cfg(any(test, feature = "test-util"))]
pub fn set_fail_after_steps(n: Option<u64>) {
    FAIL_AFTER.with(|c| c.set(n));
}

/// Called before each write step (see `set_fail_after_steps`).
fn step() -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    {
        let fail = FAIL_AFTER.with(|c| match c.get() {
            Some(0) => true,
            Some(n) => {
                c.set(Some(n - 1));
                false
            }
            None => false,
        });
        if fail {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
        }
    }
    Ok(())
}

/// Rotates the master key (HS 9.2): starts a new rotation if the key set has
/// one key, otherwise continues the unfinished one. Takes the vault lock for
/// the whole run. `on_new_recovery_key` is called once, right after the run
/// that starts a rotation has written the key file with the new key.
pub fn rotate_key(
    vault_dir: &Path,
    password: &[u8],
    opts: &RotateOptions,
    progress: &mut dyn FnMut(u64),
    on_new_recovery_key: &mut dyn FnMut(&str),
) -> Result<RotateReport> {
    let _lock = lock_vault(vault_dir)?;
    let key_path = key_file_path(vault_dir, opts.key_file.as_deref());
    let mut key_file = KeyFile::load(&key_path)?;
    let keys = key_file.unlock(password)?;
    let params = match opts.argon2 {
        Some(p) => {
            p.validate()?;
            p
        }
        None => key_file.password_params().ok_or(Error::WrongPassword)?,
    };
    let vault = open_with_key_set(vault_dir, &keys)?;
    let marker = vault.marker;
    let bad_key_set = || Error::InvalidFormat {
        what: KEY_FILE.to_owned(),
    };

    let (both, new_recovery_key) = match keys.epochs()[..] {
        // A key set with one key always starts a new rotation. Unlock
        // checked that its epoch is the marker epoch.
        [_] => {
            let mk = MasterKey::generate()?;
            let recovery = encode_recovery_key(&mk);
            let both = keys.with_next(mk)?;
            key_file.set_password(&both, password, params)?;
            step()?;
            key_file.save_replace(&key_path)?;
            // The key must reach the caller even if a later step fails.
            on_new_recovery_key(&recovery);
            (both, Some(recovery))
        }
        [old, new] if old.checked_add(1) == Some(new) => {
            if marker.epoch == new {
                // A crash after the marker was written: only the key file
                // is left.
                finish_key_file(&mut key_file, &keys, new, password, params, &key_path)?;
                return Ok(RotateReport {
                    new_recovery_key: None,
                    entries_done: 0,
                    new_epoch: new,
                    finished: true,
                });
            }
            if marker.epoch != old {
                return Err(bad_key_set());
            }
            (keys, None)
        }
        _ => return Err(bad_key_set()),
    };

    let old = marker.epoch;
    let new = both.write_epoch();
    let vault_keys = VaultKeys::new(&marker.vault_id, &both);
    let mut rot = Rotation {
        names: NameKeys::new(&vault_keys),
        keys: vault_keys,
        old,
        new,
        padded: marker.pad_sizes,
        max_name_length: marker.max_name_length,
        done: 0,
        progress,
    };
    let root = DirHandle::open_root(vault_dir)?;
    let root_ids = [marker.vault_id];
    rot.walk_dir(&root, &root_ids)?;

    let mut hidden = Vec::new();
    let left = rot.count_old(&root, &root_ids, "", &mut hidden)?;
    if left > 0 {
        return Err(Error::RotationNotFinished { left, hidden });
    }
    let new_marker = VaultMarker {
        epoch: new,
        ..marker
    };
    let check_key = rot.keys.get(new).ok_or(Error::WrongKey)?.check();
    step()?;
    write_marker(vault_dir, &new_marker, check_key)?;
    // The marker file was replaced, so the lock is on the old file; lock
    // the new one for the last write.
    let _lock = lock_vault(vault_dir)?;
    finish_key_file(&mut key_file, &both, new, password, params, &key_path)?;
    Ok(RotateReport {
        new_recovery_key,
        entries_done: rot.done,
        new_epoch: new,
        finished: true,
    })
}

/// Writes the key file with only the key of `new`. Unknown slots stay.
fn finish_key_file(
    key_file: &mut KeyFile,
    keys: &KeySet,
    new: Epoch,
    password: &[u8],
    params: Argon2Params,
    key_path: &Path,
) -> Result<()> {
    key_file.set_password(&keys.only(new)?, password, params)?;
    step()?;
    key_file.save_replace(key_path)
}

/// A real entry whose name decrypted.
struct Found {
    real: String,
    /// `None` for a long entry without `.cd-content` and `.cd-dir`.
    layout: Option<Layout>,
    /// The epoch of the name key that decrypted the name.
    epoch: Epoch,
    entry_id: EntryId,
    clear: String,
    /// The directory id the name decrypted under.
    parent_id: DirId,
    /// The sync conflict suffix of the real name (often empty).
    suffix: String,
    /// False for a long entry whose real name is not the hash of its
    /// `.cd-name`. It is not shown by a mount and the walk does not touch it.
    name_matches: bool,
}

impl Found {
    fn entry_ref(&self, layout: Layout) -> EntryRef {
        EntryRef {
            real: self.real.clone(),
            layout,
            entry_id: self.entry_id,
            epoch: self.epoch,
        }
    }
}

/// The real name of a backing name.
fn real_of(backing: &BackingName) -> &str {
    match backing {
        BackingName::Short(s) => s,
        BackingName::Long { entry, .. } => entry,
    }
}

/// The temporary file as a short file entry, for the move helpers.
fn tmp_ref(entry_id: EntryId, epoch: Epoch) -> EntryRef {
    EntryRef {
        real: ROT_TMP_FILE.to_owned(),
        layout: Layout::ShortFile,
        entry_id,
        epoch,
    }
}

/// Removes a long entry that holds only its name. An entry that holds
/// anything else is left as it is and the result is false.
fn remove_name_only_entry(dir: &DirHandle, real: &str) -> Result<bool> {
    let entry = dir.open_dir(real)?;
    if !entry
        .list()?
        .iter()
        .all(|n| n == NAME_FILE || n == NAME_TMP_FILE)
    {
        return Ok(false);
    }
    ok_if_missing(entry.unlink(NAME_TMP_FILE))?;
    ok_if_missing(entry.unlink(NAME_FILE))?;
    dir.rmdir(real)?;
    Ok(true)
}

struct Rotation<'a> {
    names: NameKeys,
    keys: VaultKeys,
    old: Epoch,
    new: Epoch,
    padded: bool,
    max_name_length: u16,
    done: u64,
    progress: &'a mut dyn FnMut(u64),
}

impl Rotation<'_> {
    fn count_done(&mut self) {
        self.done += 1;
        (self.progress)(self.done);
    }

    fn decrypt(&self, ids: &[DirId], encoded: &str) -> Option<(Epoch, EntryId, String, DirId)> {
        ids.iter().find_map(|id| {
            let (epoch, entry_id, clear) = self.names.decrypt_any(id, encoded)?;
            validate_name(&clear).ok()?;
            Some((epoch, entry_id, clear, *id))
        })
    }

    /// The real name of `f` under the new epoch, with the same parent id,
    /// entry id and conflict suffix. AES-SIV is deterministic, so this is
    /// the same name in every run.
    fn new_backing(&self, f: &Found) -> Result<BackingName> {
        let encoded = self
            .names
            .encrypt_write(&f.parent_id, &f.entry_id, &f.clear)?;
        Ok(match to_backing_name(encoded, self.max_name_length) {
            BackingName::Short(s) => BackingName::Short(s + &f.suffix),
            BackingName::Long { entry, full } => BackingName::Long {
                entry: entry + &f.suffix,
                full,
            },
        })
    }

    /// Classifies one real entry. Foreign entries give `None`. With
    /// `repair`, a long directory whose rename to the new epoch stopped
    /// before its new `.cd-name` was written gets that name now.
    fn classify(
        &self,
        dir: &DirHandle,
        ids: &[DirId],
        real: &str,
        repair: bool,
    ) -> Result<Option<Found>> {
        if let Some((entry, suffix)) = long_candidate(real) {
            let Some(entry_dir) = open_entry_dir(dir, real)? else {
                return Ok(None);
            };
            let Some(full) = read_long_name(&entry_dir)? else {
                // Only the final rmdir of a removal was left.
                if repair && entry_dir.list()?.is_empty() {
                    dir.rmdir(real)?;
                }
                return Ok(None);
            };
            let Some((epoch, entry_id, clear, parent_id)) = self.decrypt(ids, &full) else {
                return Ok(None);
            };
            let layout = long_layout(&entry_dir)?;
            let mut found = Found {
                real: real.to_owned(),
                layout,
                epoch,
                entry_id,
                clear,
                parent_id,
                suffix: suffix.to_owned(),
                name_matches: long_entry_name(&full) == entry,
            };
            if !found.name_matches
                && repair
                && epoch == self.old
                && layout == Some(Layout::LongDir)
                && let BackingName::Long {
                    entry: new_entry,
                    full: new_full,
                } = self.new_backing(&found)?
                && new_entry == real
            {
                write_name(dir, real, &new_full)?;
                found.epoch = self.new;
                found.name_matches = true;
            }
            return Ok(Some(found));
        }
        if real.starts_with('.') {
            return Ok(None);
        }
        let Some(((epoch, entry_id, clear, parent_id), suffix)) = short_candidates(real)
            .into_iter()
            .find_map(|(prefix, suffix)| Some((self.decrypt(ids, prefix)?, suffix)))
        else {
            return Ok(None);
        };
        let layout = match dir.stat(real) {
            Ok(st) => match st.kind {
                crate::backing::Kind::File => Layout::ShortFile,
                crate::backing::Kind::Dir => Layout::ShortDir,
                crate::backing::Kind::Other => return Ok(None),
            },
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(Found {
            real: real.to_owned(),
            layout: Some(layout),
            epoch,
            entry_id,
            clear,
            parent_id,
            suffix: suffix.to_owned(),
            name_matches: true,
        }))
    }

    /// All entries of `dir` whose name decrypts, sorted by real name.
    fn list(&self, dir: &DirHandle, ids: &[DirId], repair: bool) -> Result<Vec<Found>> {
        let mut names = dir.list()?;
        names.sort();
        let mut found = Vec::new();
        for real in &names {
            if let Some(f) = self.classify(dir, ids, real, repair)? {
                found.push(f);
            }
        }
        Ok(found)
    }

    /// Opens the real directory of a directory entry and reads its ids.
    /// `None` if it has no `.cd-dir` (its children cannot be read).
    fn open_child(&self, dir: &DirHandle, real: &str) -> Result<Option<(DirHandle, Vec<DirId>)>> {
        let child = dir.open_dir(real)?;
        let names = child.list()?;
        match read_dir_ids(&child, real, &names) {
            Ok(ids) => Ok(Some((child, ids))),
            Err(Error::NotFound | Error::InvalidFormat { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Re-encrypts every entry of `dir` and below (HS 9.2 step 2).
    fn walk_dir(&mut self, dir: &DirHandle, ids: &[DirId]) -> Result<()> {
        ok_if_missing(dir.unlink(ROT_TMP_FILE))?;
        let entries = self.list(dir, ids, true)?;
        let complete: HashSet<&str> = entries
            .iter()
            .filter(|f| f.name_matches && f.layout.is_some())
            .map(|f| f.real.as_str())
            .collect();
        // Real names handled as the new half of a duplicate.
        let mut handled: HashSet<String> = HashSet::new();
        // Clear names in use, for the name of a rotation conflict copy.
        let mut used: HashSet<String> = entries.iter().map(|f| f.clear.clone()).collect();
        for f in &entries {
            if !f.name_matches || f.epoch != self.old || handled.contains(&f.real) {
                continue;
            }
            let backing = self.new_backing(f)?;
            let new_real = real_of(&backing).to_owned();
            match f.layout {
                // A long entry that only holds its old name: the rest of a
                // removal that stopped after the new entry was made.
                None => {
                    if complete.contains(new_real.as_str())
                        && !remove_name_only_entry(dir, &f.real)?
                    {
                        log::warn!(
                            "leaving the incomplete entry {}: it holds other files",
                            f.real
                        );
                    }
                }
                Some(layout) if layout.is_dir() => {
                    if dir.stat(&new_real).is_ok() {
                        return Err(Error::InvalidFormat { what: new_real });
                    }
                    step()?;
                    move_entry(dir, &f.entry_ref(layout), dir, &backing)?;
                    dir.sync()?;
                    self.count_done();
                    self.walk_child(dir, &new_real)?;
                }
                Some(layout) => {
                    if let Some(dup) = entries
                        .iter()
                        .find(|d| d.real == new_real && d.name_matches && d.layout.is_some())
                    {
                        handled.insert(new_real.clone());
                        self.resolve_duplicate(dir, f, layout, dup, &mut used, &entries)?;
                    } else {
                        self.clear_target(dir, &new_real)?;
                        self.move_file(dir, f, layout, &backing, f.entry_id)?;
                    }
                    self.count_done();
                }
            }
        }
        for f in &entries {
            if !f.name_matches || f.epoch != self.new || handled.contains(&f.real) {
                continue;
            }
            match f.layout {
                None => {}
                Some(layout) if layout.is_dir() => {
                    self.count_done();
                    self.walk_child(dir, &f.real)?;
                }
                Some(layout) => {
                    self.convert_content_in_place(dir, f, layout)?;
                    self.count_done();
                }
            }
        }
        dir.sync()
    }

    fn walk_child(&mut self, dir: &DirHandle, real: &str) -> Result<()> {
        match self.open_child(dir, real)? {
            Some((child, ids)) => self.walk_dir(&child, &ids),
            None => Ok(()),
        }
    }

    /// Removes an incomplete long entry left at `new_real` by an
    /// interrupted step, so the new entry can be made there.
    fn clear_target(&self, dir: &DirHandle, new_real: &str) -> Result<()> {
        match dir.stat(new_real) {
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => {
                let leftover = long_candidate(new_real).is_some()
                    && match open_entry_dir(dir, new_real)? {
                        Some(entry) => long_layout(&entry)?.is_none(),
                        None => false,
                    };
                if !leftover || !remove_name_only_entry(dir, new_real)? {
                    return Err(Error::InvalidFormat {
                        what: new_real.to_owned(),
                    });
                }
                Ok(())
            }
        }
    }

    /// Where the content of a file entry lives.
    fn content_of(&self, dir: &DirHandle, f: &Found, layout: Layout) -> Result<ContentAt> {
        Ok(if layout == Layout::LongFile {
            ContentAt::Long(dir.open_dir(&f.real)?)
        } else {
            ContentAt::Short(f.real.clone())
        })
    }

    /// Re-encrypts the file `f` into a new entry with the new name, then
    /// removes the old entry (three steps).
    fn move_file(
        &mut self,
        dir: &DirHandle,
        f: &Found,
        layout: Layout,
        backing: &BackingName,
        file_id: EntryId,
    ) -> Result<()> {
        step()?;
        self.write_tmp(dir, f, layout, file_id)?;
        step()?;
        move_entry(dir, &tmp_ref(file_id, self.new), dir, backing)?;
        if let BackingName::Long { entry, .. } = backing {
            dir.open_dir(entry)?.sync()?;
        }
        dir.sync()?;
        step()?;
        remove_file_entry(dir, &f.entry_ref(layout))
    }

    /// A file with a name of the new epoch whose content is still of the
    /// old one (renamed during a mount): the new content replaces the old
    /// one atomically under the same name (two steps).
    fn convert_content_in_place(
        &mut self,
        dir: &DirHandle,
        f: &Found,
        layout: Layout,
    ) -> Result<()> {
        let at = self.content_of(dir, f, layout)?;
        if at.header_epoch(dir)? != Some(self.old) {
            return Ok(());
        }
        step()?;
        self.write_tmp(dir, f, layout, f.entry_id)?;
        step()?;
        match &at {
            ContentAt::Short(real) => dir.rename(ROT_TMP_FILE, dir, real)?,
            ContentAt::Long(entry) => {
                move_into_long_file(dir, &tmp_ref(f.entry_id, self.new), dir, &f.real)?;
                entry.sync()?;
            }
        }
        dir.sync()
    }

    /// The old entry `f` and the new entry `dup` have the same name, entry
    /// id and conflict suffix: a crash after the new entry was made, maybe
    /// followed by a mount that changed one of them. Both are read fully:
    /// - the new one does not authenticate: it is removed and the file is
    ///   done again;
    /// - the old one does not authenticate: it is removed;
    /// - the same content: the old one is removed;
    /// - other content: the new one keeps the name, the old one becomes a
    ///   new file "<stem> (rotation conflict N)<.ext>" (no change is lost).
    fn resolve_duplicate(
        &mut self,
        dir: &DirHandle,
        f: &Found,
        layout: Layout,
        dup: &Found,
        used: &mut HashSet<String>,
        entries: &[Found],
    ) -> Result<()> {
        let dup_layout = match dup.layout {
            Some(l) if !l.is_dir() => l,
            _ => {
                return Err(Error::InvalidFormat {
                    what: dup.real.clone(),
                });
            }
        };
        let cmp = self.compare(dir, f, layout, dup, dup_layout)?;
        if !cmp.new_ok {
            log::warn!(
                "the re-encrypted copy {} is not valid; making it again",
                dup.real
            );
            step()?;
            remove_file_entry(dir, &dup.entry_ref(dup_layout))?;
            dir.sync()?;
            let backing = self.new_backing(f)?;
            return self.move_file(dir, f, layout, &backing, f.entry_id);
        }
        if !cmp.old_ok || cmp.equal {
            if !cmp.old_ok {
                log::warn!("the old copy {} is not valid; keeping the new one", f.real);
            }
            step()?;
            return remove_file_entry(dir, &f.entry_ref(layout));
        }
        // A rotation conflict copy made before a crash already holds the
        // old content: only the old entry is left to remove.
        for c in entries {
            if let Some(c_layout) = c.layout
                && !c_layout.is_dir()
                && c.name_matches
                && c.epoch == self.new
                && c.suffix.is_empty()
                && c.parent_id == f.parent_id
                && is_rotation_conflict_of(&c.clear, &f.clear)
                && self.compare(dir, f, layout, c, c_layout)?.equal
            {
                step()?;
                return remove_file_entry(dir, &f.entry_ref(layout));
            }
        }
        let name = (1..)
            .map(|n| rotation_conflict_name(&f.clear, n))
            .find(|n| !used.contains(n))
            .ok_or(Error::InvalidArgument)?;
        log::warn!("both copies of {} were changed; keeping both", f.real);
        let file_id = random_entry_id()?;
        let encoded = self.names.encrypt_write(&f.parent_id, &file_id, &name)?;
        let backing = to_backing_name(encoded, self.max_name_length);
        used.insert(name);
        self.move_file(dir, f, layout, &backing, file_id)
    }

    /// Reads the old file `old` and the new file `new` fully and compares
    /// their clear content. Every chunk of both is authenticated, also
    /// after a difference was found.
    fn compare(
        &self,
        dir: &DirHandle,
        old: &Found,
        old_layout: Layout,
        new: &Found,
        new_layout: Layout,
    ) -> Result<Comparison> {
        let mut a = self.open_checked(dir, old, old_layout, None)?;
        let mut b = self.open_checked(dir, new, new_layout, Some(self.new))?;
        let mut equal = matches!((&a, &b), (Some(x), Some(y)) if x.len() == y.len());
        let end = [&a, &b]
            .iter()
            .filter_map(|f| f.as_ref().map(OpenFile::len))
            .max()
            .unwrap_or(0);
        let mut offset = 0;
        while offset < end {
            let ca = read_checked(&mut a, offset)?;
            let cb = read_checked(&mut b, offset)?;
            if ca != cb {
                equal = false;
            }
            offset += CHUNK_SIZE;
        }
        Ok(Comparison {
            old_ok: a.is_some(),
            new_ok: b.is_some(),
            equal: equal && a.is_some() && b.is_some(),
        })
    }

    /// Opens the file `f`; `None` if it does not authenticate, does not
    /// belong to its name, or is not of `epoch` (when given).
    fn open_checked(
        &self,
        dir: &DirHandle,
        f: &Found,
        layout: Layout,
        epoch: Option<Epoch>,
    ) -> Result<Option<OpenFile>> {
        let file = match self
            .content_of(dir, f, layout)?
            .open(dir, &self.keys, self.padded)
        {
            Ok(file) => file,
            Err(Error::AuthFailed { .. } | Error::InvalidFormat { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let ok = file.file_id() == f.entry_id && epoch.is_none_or(|e| file.epoch() == e);
        Ok(ok.then_some(file))
    }

    /// Writes the clear content of `f` into `ROT_TMP_FILE` in `dir` with the
    /// new epoch and the file id `file_id` (the same one, except for a
    /// rotation conflict copy), with the mode and times of the old file,
    /// and syncs it. Removes the temporary file on error.
    fn write_tmp(
        &self,
        dir: &DirHandle,
        f: &Found,
        layout: Layout,
        file_id: EntryId,
    ) -> Result<()> {
        let at = self.content_of(dir, f, layout)?;
        let src = at.open_raw(dir)?;
        let st = stat_file(&src)?;
        let mut old = OpenFile::open(src, &self.keys, self.padded)?;
        // The content must belong to this name (HS 3.2).
        if old.file_id() != f.entry_id {
            return Err(Error::AuthFailed {
                what: f.real.clone(),
            });
        }
        let tmp = dir.create_file(ROT_TMP_FILE, TMP_MODE)?;
        let result = (|| {
            let mut new = OpenFile::create(tmp, &self.keys, file_id, self.padded)?;
            let mut offset = 0;
            while offset < old.len() {
                let chunk = old.read(offset, CHUNK_SIZE as usize)?;
                if chunk.is_empty() {
                    return Err(Error::InvalidFormat {
                        what: f.real.clone(),
                    });
                }
                new.write(offset, &chunk)?;
                offset += chunk.len() as u64;
            }
            new.flush()?;
            let file = new.into_file();
            dir.set_mode(ROT_TMP_FILE, st.mode & MODE_MASK)?;
            dir.set_times(ROT_TMP_FILE, Some(st.atime), Some(st.mtime))?;
            file.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = dir.unlink(ROT_TMP_FILE);
        }
        result
    }

    /// True if `real` is a long entry without a valid `.cd-name` (missing,
    /// not readable, or it does not decrypt) that still holds `.cd-dir` or
    /// `.cd-content`. A crashed rename can leave one; its data would be
    /// lost with the old key, so it blocks the finish (HS 9.4).
    fn is_hidden_data(&self, dir: &DirHandle, ids: &[DirId], real: &str) -> Result<bool> {
        if long_candidate(real).is_none() {
            return Ok(false);
        }
        let Some(entry) = open_entry_dir(dir, real)? else {
            return Ok(false);
        };
        if long_layout(&entry)?.is_none() {
            return Ok(false);
        }
        Ok(match read_long_name(&entry) {
            Ok(Some(full)) => self.decrypt(ids, &full).is_none(),
            Ok(None) | Err(Error::InvalidFormat { .. }) => true,
            Err(e) => return Err(e),
        })
    }

    /// Counts the entries of `dir` and below whose name or content still
    /// uses the old epoch (HS 9.2 step 3), and long entries that hide data
    /// (their real paths go to `hidden`). `path` is the real path of `dir`
    /// below the root. Writes nothing.
    fn count_old(
        &self,
        dir: &DirHandle,
        ids: &[DirId],
        path: &str,
        hidden: &mut Vec<String>,
    ) -> Result<u64> {
        let join = |real: &str| {
            if path.is_empty() {
                real.to_owned()
            } else {
                format!("{path}/{real}")
            }
        };
        let mut left = 0;
        let mut names = dir.list()?;
        names.sort();
        for real in &names {
            if self.is_hidden_data(dir, ids, real)? {
                hidden.push(join(real));
                left += 1;
            }
        }
        for f in self.list(dir, ids, false)? {
            let Some(layout) = f.layout else {
                continue;
            };
            // A long entry with a wrong hash is never converted, but if it
            // holds data under a name of the old key, removing that key
            // would lose it.
            if !f.name_matches {
                left += u64::from(f.epoch == self.old);
            } else if f.epoch == self.old {
                left += 1;
            } else if layout.is_dir() {
                if let Some((child, ids)) = self.open_child(dir, &f.real)? {
                    left += self.count_old(&child, &ids, &join(&f.real), hidden)?;
                }
            } else if self.content_of(dir, &f, layout)?.header_epoch(dir)? == Some(self.old) {
                left += 1;
            }
        }
        Ok(left)
    }
}

/// The content file of a file entry.
enum ContentAt {
    /// The short real name in the parent directory.
    Short(String),
    /// The `.cd-cdl` directory that holds `.cd-content`.
    Long(DirHandle),
}

impl ContentAt {
    fn open_raw(&self, parent: &DirHandle) -> Result<std::fs::File> {
        match self {
            ContentAt::Short(real) => parent.open_file(real, false),
            ContentAt::Long(entry) => entry.open_file(CONTENT_FILE, false),
        }
    }

    fn open(&self, parent: &DirHandle, keys: &VaultKeys, padded: bool) -> Result<OpenFile> {
        OpenFile::open(self.open_raw(parent)?, keys, padded)
    }

    fn header_epoch(&self, parent: &DirHandle) -> Result<Option<Epoch>> {
        match self {
            ContentAt::Short(real) => header_epoch(parent, real),
            ContentAt::Long(entry) => header_epoch(entry, CONTENT_FILE),
        }
    }
}

/// What `Rotation::compare` found.
struct Comparison {
    old_ok: bool,
    new_ok: bool,
    /// Both authenticate and hold the same clear content.
    equal: bool,
}

/// The clear chunk at `offset` of `file` (empty past its end). A chunk that
/// does not authenticate sets `file` to `None`.
fn read_checked(file: &mut Option<OpenFile>, offset: u64) -> Result<Vec<u8>> {
    let Some(f) = file else {
        return Ok(Vec::new());
    };
    match f.read(offset, CHUNK_SIZE as usize) {
        Ok(chunk) => Ok(chunk),
        Err(Error::AuthFailed { .. } | Error::InvalidFormat { .. }) => {
            *file = None;
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
}

/// True if `name` is "<stem> (rotation conflict N)<.ext>" of `clear`.
fn is_rotation_conflict_of(name: &str, clear: &str) -> bool {
    (1..=MAX_ROTATION_CONFLICTS).any(|n| rotation_conflict_name(clear, n) == name)
}
