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

//! Integrity check of a whole vault (spec 7, `check`).
//!
//! The check walks the real tree by itself and does not use the caches of
//! `CryptoFs`. It only reads; it never writes, renames or deletes anything.

use crate::backing::{DirHandle, Kind};
use crate::conflict::{long_candidate, short_candidates};
use crate::content::{
    CHUNK_OVERHEAD, CHUNK_SIZE, ChunkCipher, FileHeader, HEADER_LEN, chunk_count, chunk_offset,
};
use crate::error::{Error, Result};
use crate::file::read_file_meta;
use crate::keys::{DirId, EntryId};
use crate::names::{MAX_ENCODED_NAME_LEN, NameKeys, long_entry_name, validate_name};
use crate::vault::{
    CONTENT_FILE, DIR_FILE, KEY_FILE, NAME_FILE, UnlockedVault, VAULT_FILE, VaultKeys,
};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const DIR_ID_LEN: usize = 16;
/// Written by `mkdir` before it is renamed to `.cd-dir`.
const DIR_TMP_FILE: &str = ".cd-dir.tmp";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// A directory has no valid `.cd-dir`.
    MissingDirId,
    /// A directory has more than one `.cd-dir` (sync conflict copy).
    MultipleDirIds,
    /// A `.cd-cdl` entry without `.cd-name`, or without `.cd-content` and `.cd-dir`.
    IncompleteLongEntry,
    /// An entry with a sync conflict suffix.
    ConflictCopy,
    /// An entry that does not belong to the vault, for example `.DS_Store`.
    ForeignEntry,
    /// A name that does not authenticate.
    UndecryptableName,
    /// The size of an encrypted file is not possible.
    InvalidFileSize,
    /// The header of an encrypted file is invalid.
    HeaderInvalid,
    /// A chunk does not authenticate.
    ChunkAuthFailed { index: u64 },
    /// The hash in a `.cd-cdl` entry name does not match its `.cd-name`.
    LongNameMismatch,
    /// An entry that could not be read (for example no read permission).
    /// A directory's contents are skipped.
    Unreadable,
    /// The name and the file header (or `.cd-dir`) carry different entry ids.
    EntryIdMismatch,
    /// A file header uses an epoch that is not in the key set.
    UnknownKeyEpoch,
    /// The key set has two epochs (a key rotation is not finished).
    RotationInProgress,
    /// In a padded vault: the file length is not the stage of its size, or
    /// the size block does not authenticate.
    InvalidPadding,
}

impl FindingKind {
    pub fn severity(&self) -> Severity {
        match self {
            FindingKind::ConflictCopy
            | FindingKind::ForeignEntry
            | FindingKind::MultipleDirIds
            | FindingKind::RotationInProgress => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    /// Relative to the vault root, with real (encrypted) names only.
    pub real_path: PathBuf,
    pub kind: FindingKind,
}

/// Checks all names, directory ids and chunks of the vault.
pub fn check_vault(vault: &UnlockedVault) -> Result<Vec<Finding>> {
    let root = DirHandle::open_root(&vault.root_path)?;
    let mut checker = Checker {
        names: NameKeys::new(&vault.keys),
        keys: &vault.keys,
        padded: vault.marker.pad_sizes,
        findings: Vec::new(),
    };
    if vault.keys.epochs_desc().len() > 1 {
        checker.report(PathBuf::from(KEY_FILE), FindingKind::RotationInProgress);
    }
    checker.check_dir(
        &root,
        Path::new(""),
        &[vault.marker.vault_id],
        DirRole::Root,
    )?;
    Ok(checker.findings)
}

/// 0 if there are no findings, 1 for warnings only, 2 for any error.
pub fn exit_code(findings: &[Finding]) -> i32 {
    match findings.iter().map(|f| f.severity).max() {
        None => 0,
        Some(Severity::Warning) => 1,
        Some(Severity::Error) => 2,
    }
}

/// What a real directory is, which decides the control files it may hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DirRole {
    /// The vault root: `.cd-vault` and `.cd-key`, no `.cd-dir`.
    Root,
    /// A short directory or a long directory: `.cd-dir`, and for a long one
    /// also `.cd-name`.
    Dir { long: bool },
}

struct Checker<'a> {
    names: NameKeys,
    keys: &'a VaultKeys,
    padded: bool,
    findings: Vec<Finding>,
}

/// Maps "the entry is gone or is not what we expected" to `None`.
fn optional<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotFound | Error::NotADirectory | Error::InvalidFormat { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

fn kind_of(dir: &DirHandle, name: &str) -> Result<Option<Kind>> {
    Ok(optional(dir.stat(name))?.map(|st| st.kind))
}

/// Reads a 16 byte directory id; `None` if it is missing or has another size.
fn read_dir_id(dir: &DirHandle, name: &str) -> Result<Option<DirId>> {
    if kind_of(dir, name)? != Some(Kind::File) {
        return Ok(None);
    }
    Ok(optional(dir.read_small(name, DIR_ID_LEN))?.and_then(|b| b.try_into().ok()))
}

/// True for a sync conflict copy of `.cd-dir` (spec 5.3).
fn is_dir_id_copy(name: &str) -> bool {
    name != DIR_FILE && name != DIR_TMP_FILE && name.starts_with(DIR_FILE)
}

impl Checker<'_> {
    fn report(&mut self, real_path: PathBuf, kind: FindingKind) {
        self.findings.push(Finding {
            severity: kind.severity(),
            real_path,
            kind,
        });
    }

    /// Reports an entry that could not be read; the walk goes on.
    fn unreadable(&mut self, real_path: PathBuf, e: &Error) {
        log::debug!("cannot read {}: {e}", real_path.display());
        self.report(real_path, FindingKind::Unreadable);
    }

    /// The entry id of the name, if it authenticates under one of the
    /// directory ids.
    fn decrypts(&self, dir_ids: &[DirId], encoded: &str) -> Option<EntryId> {
        dir_ids.iter().find_map(|id| {
            let (_, entry_id, clear) = self.names.decrypt_any(id, encoded)?;
            validate_name(&clear).ok().map(|()| entry_id)
        })
    }

    /// Opens the real directory `name` in `parent` and checks its contents.
    /// `long` is true for a `.cd-cdl` directory entry.
    fn enter_dir(
        &mut self,
        parent: &DirHandle,
        name: &str,
        rel: &Path,
        long: bool,
        entry_id: EntryId,
    ) -> Result<()> {
        let Some(dir) = optional(parent.open_dir(name))? else {
            return Ok(());
        };
        let id = match read_dir_id(&dir, DIR_FILE) {
            Ok(Some(id)) => id,
            Ok(None) => {
                self.report(rel.to_path_buf(), FindingKind::MissingDirId);
                return Ok(());
            }
            Err(e) => {
                self.unreadable(rel.join(DIR_FILE), &e);
                return Ok(());
            }
        };
        if id != entry_id {
            self.report(rel.to_path_buf(), FindingKind::EntryIdMismatch);
        }
        self.check_dir(&dir, rel, &[id], DirRole::Dir { long })
    }

    /// Checks every entry of a real directory. `dir_ids` holds the canonical
    /// id; conflict copies of `.cd-dir` are added here.
    fn check_dir(
        &mut self,
        dir: &DirHandle,
        rel: &Path,
        dir_ids: &[DirId],
        role: DirRole,
    ) -> Result<()> {
        let mut names = dir.list()?;
        names.sort();
        let mut ids = dir_ids.to_vec();
        let mut entries = Vec::new();
        for name in names {
            let path = rel.join(&name);
            let is_control = match role {
                DirRole::Root => name == VAULT_FILE || name == KEY_FILE,
                // A short directory may hold a stray `.cd-name` from an
                // interrupted rename to a long name (HS 9.4).
                DirRole::Dir { .. } => name == DIR_FILE || name == NAME_FILE,
            };
            if is_control {
                continue;
            }
            if matches!(role, DirRole::Dir { .. }) && is_dir_id_copy(&name) {
                match read_dir_id(dir, &name) {
                    Ok(Some(id)) => {
                        if !ids.contains(&id) {
                            ids.push(id);
                        }
                        self.report(path, FindingKind::MultipleDirIds);
                    }
                    Ok(None) => self.report(path, FindingKind::ForeignEntry),
                    Err(e) => self.unreadable(path, &e),
                }
                continue;
            }
            entries.push((name, path));
        }
        for (name, path) in entries {
            // An entry (or a subtree) that cannot be read must not stop the
            // check of the others.
            if let Err(e) = self.check_entry(dir, &name, &path, &ids) {
                self.unreadable(path, &e);
            }
        }
        Ok(())
    }

    fn check_entry(
        &mut self,
        dir: &DirHandle,
        name: &str,
        path: &Path,
        dir_ids: &[DirId],
    ) -> Result<()> {
        if let Some((entry, suffix)) = long_candidate(name) {
            return self.check_long_entry(dir, name, entry, !suffix.is_empty(), path, dir_ids);
        }
        if name.starts_with('.') {
            // Unknown control files and foreign dot files.
            self.report(path.to_path_buf(), FindingKind::ForeignEntry);
            return Ok(());
        }
        let Some((entry_id, conflict)) =
            short_candidates(name)
                .into_iter()
                .find_map(|(prefix, suffix)| {
                    self.decrypts(dir_ids, prefix)
                        .map(|id| (id, !suffix.is_empty()))
                })
        else {
            self.report(path.to_path_buf(), FindingKind::UndecryptableName);
            return Ok(());
        };
        let kind = match kind_of(dir, name)? {
            Some(Kind::Other) => {
                self.report(path.to_path_buf(), FindingKind::ForeignEntry);
                return Ok(());
            }
            Some(kind) => kind,
            // Removed while we were checking.
            None => return Ok(()),
        };
        if conflict {
            self.report(path.to_path_buf(), FindingKind::ConflictCopy);
        }
        if kind == Kind::Dir {
            self.enter_dir(dir, name, path, false, entry_id)
        } else {
            self.check_content(dir, name, path, path, entry_id)
        }
    }

    fn check_long_entry(
        &mut self,
        dir: &DirHandle,
        name: &str,
        entry: &str,
        conflict: bool,
        path: &Path,
        dir_ids: &[DirId],
    ) -> Result<()> {
        let incomplete = |c: &mut Self| {
            c.report(path.to_path_buf(), FindingKind::IncompleteLongEntry);
            Ok(())
        };
        if kind_of(dir, name)? != Some(Kind::Dir) {
            return incomplete(self);
        }
        let Some(entry_dir) = optional(dir.open_dir(name))? else {
            return incomplete(self);
        };
        let full = match kind_of(&entry_dir, NAME_FILE)? {
            Some(Kind::File) => optional(entry_dir.read_small(NAME_FILE, MAX_ENCODED_NAME_LEN))?
                .and_then(|b| String::from_utf8(b).ok()),
            _ => None,
        };
        let Some(full) = full else {
            return incomplete(self);
        };
        if long_entry_name(&full) != entry {
            self.report(path.to_path_buf(), FindingKind::LongNameMismatch);
            return Ok(());
        }
        let Some(entry_id) = self.decrypts(dir_ids, &full) else {
            self.report(path.to_path_buf(), FindingKind::UndecryptableName);
            return Ok(());
        };
        let content = kind_of(&entry_dir, CONTENT_FILE)? == Some(Kind::File);
        let is_dir = kind_of(&entry_dir, DIR_FILE)? == Some(Kind::File);
        if !content && !is_dir {
            return incomplete(self);
        }
        if conflict {
            self.report(path.to_path_buf(), FindingKind::ConflictCopy);
        }
        if content {
            self.check_content(
                &entry_dir,
                CONTENT_FILE,
                &path.join(CONTENT_FILE),
                path,
                entry_id,
            )?;
            self.check_long_file_extras(&entry_dir, path)
        } else {
            self.enter_dir(dir, name, path, true, entry_id)
        }
    }

    /// A long file entry holds only `.cd-name` and `.cd-content`.
    fn check_long_file_extras(&mut self, entry_dir: &DirHandle, path: &Path) -> Result<()> {
        let mut names = entry_dir.list()?;
        names.sort();
        for n in names {
            if n != NAME_FILE && n != CONTENT_FILE {
                self.report(path.join(n), FindingKind::ForeignEntry);
            }
        }
        Ok(())
    }

    /// Checks the size, the header and every chunk of an encrypted file.
    /// `entry_path` is the path of the entry that holds the name (the file
    /// itself, or its overflow entry).
    fn check_content(
        &mut self,
        dir: &DirHandle,
        name: &str,
        path: &Path,
        entry_path: &Path,
        entry_id: EntryId,
    ) -> Result<()> {
        let Some(file) = optional(dir.open_file(name, false))? else {
            return Ok(());
        };
        // An epoch outside the key set is its own finding.
        let mut head = [0u8; HEADER_LEN as usize];
        if read_at(&file, &mut head, 0)?
            && let Ok(h) = FileHeader::parse(&head)
            && self.keys.get(h.epoch).is_none()
        {
            self.report(path.to_path_buf(), FindingKind::UnknownKeyEpoch);
            return Ok(());
        }
        let (header, plain_len) = match read_file_meta(&file, self.keys, self.padded) {
            Ok(meta) => meta,
            Err(Error::InvalidFormat { what }) if what == "file size" => {
                let kind = if self.padded {
                    FindingKind::InvalidPadding
                } else {
                    FindingKind::InvalidFileSize
                };
                self.report(path.to_path_buf(), kind);
                return Ok(());
            }
            // The header parsed and its epoch is known, so in a padded vault
            // only the size block can fail here.
            Err(Error::AuthFailed { .. }) if self.padded => {
                self.report(path.to_path_buf(), FindingKind::InvalidPadding);
                return Ok(());
            }
            Err(Error::InvalidFormat { .. } | Error::AuthFailed { .. }) => {
                self.report(path.to_path_buf(), FindingKind::HeaderInvalid);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if header.file_id != entry_id {
            self.report(entry_path.to_path_buf(), FindingKind::EntryIdMismatch);
        }
        let Some(keys) = self.keys.get(header.epoch) else {
            self.report(path.to_path_buf(), FindingKind::UnknownKeyEpoch);
            return Ok(());
        };
        let cipher = ChunkCipher::new(keys.content(), &header);
        let count = chunk_count(plain_len);
        for index in 0..count {
            let clear_len = (plain_len - index * CHUNK_SIZE).min(CHUNK_SIZE);
            // At most one chunk, so the cast is lossless.
            let mut sealed = vec![0u8; (clear_len + CHUNK_OVERHEAD) as usize];
            let ok = read_at(&file, &mut sealed, chunk_offset(index, self.padded))?
                && cipher.open(index, index + 1 == count, &sealed).is_ok();
            if !ok {
                self.report(path.to_path_buf(), FindingKind::ChunkAuthFailed { index });
            }
        }
        Ok(())
    }
}

/// Fills `buf` from `offset`; false if the file ended first.
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> Result<bool> {
    match file.read_exact_at(buf, offset) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::chunk_offset;
    use crate::fs::{CryptoFs, VPath};
    use crate::keys::{DirId, MasterKey};
    use crate::names::{LONG_PREFIX, NameKeys};
    use crate::testutil::{real_name_of, test_vault_opts};
    use crate::vault::{CONTROL_PREFIX, DIR_FILE, NAME_FILE, open_with_master_key};
    use std::collections::BTreeMap;
    use std::path::Path;

    struct Fx {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        mk: MasterKey,
        names: NameKeys,
        vault_id: DirId,
    }

    fn p(s: &str) -> VPath {
        VPath::parse(s).unwrap()
    }

    fn write_file(fs: &CryptoFs, path: &str, data: &[u8]) {
        let (_, h) = fs.create(&p(path), 0o644).unwrap();
        fs.write(h, 0, data).unwrap();
        fs.release(h).unwrap();
    }

    /// A vault with `max_name_length` 64, filled by `fill`.
    fn fx(fill: impl FnOnce(&CryptoFs)) -> Fx {
        fx_opts(false, fill)
    }

    /// Like `fx`, with or without size padding.
    fn fx_opts(padded: bool, fill: impl FnOnce(&CryptoFs)) -> Fx {
        let (tmp, v, mk) = test_vault_opts(64, padded);
        let names = NameKeys::new(&v.keys);
        let root = v.root_path.clone();
        let vault_id = v.marker.vault_id;
        let fs = CryptoFs::new(v).unwrap();
        fill(&fs);
        drop(fs);
        Fx {
            _tmp: tmp,
            root,
            mk,
            names,
            vault_id,
        }
    }

    impl Fx {
        fn check(&self) -> Vec<Finding> {
            let v = open_with_master_key(&self.root, &self.mk).unwrap();
            check_vault(&v).unwrap()
        }

        /// The real name of an existing entry in the root.
        fn real(&self, name: &str) -> String {
            real_name_of(&self.names, &self.vault_id, &self.root, name)
        }
    }

    fn kinds(findings: &[Finding]) -> Vec<FindingKind> {
        findings.iter().map(|f| f.kind.clone()).collect()
    }

    /// Real entry names of `dir` that are not control files.
    fn user_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with(CONTROL_PREFIX) || n.starts_with(LONG_PREFIX))
            .collect();
        v.sort();
        v
    }

    fn long_name() -> String {
        "a-very-long-clear-name-that-does-not-fit-".repeat(2)
    }

    fn clean_fill(fs: &CryptoFs) {
        write_file(fs, "a.txt", b"hello");
        write_file(fs, "empty", b"");
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        write_file(fs, "big.bin", &big);
        fs.mkdir(&p("dir"), 0o755).unwrap();
        write_file(fs, "dir/inner.txt", b"inner");
        let long = long_name();
        write_file(fs, &format!("dir/{long}"), b"long file");
        fs.mkdir(&p(&format!("{long}.d")), 0o755).unwrap();
        write_file(fs, &format!("{long}.d/x"), b"x");
        fs.mkdir(&p("empty-dir"), 0o755).unwrap();
    }

    /// Every path and its bytes (or `None` for a directory).
    fn snapshot(dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let path = e.unwrap().path();
            if path.is_dir() {
                out.insert(path.clone(), None);
                snapshot(&path, out);
            } else {
                out.insert(path.clone(), Some(std::fs::read(&path).unwrap()));
            }
        }
    }

    fn flip(path: &Path, offset: u64) {
        let mut bytes = std::fs::read(path).unwrap();
        bytes[offset as usize] ^= 0x01;
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn clean_vault_has_no_findings() {
        let f = fx(clean_fill);
        let findings = f.check();
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(exit_code(&findings), 0);
    }

    #[test]
    fn padded_clean_vault_has_no_findings() {
        let f = fx_opts(true, clean_fill);
        let findings = f.check();
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn padded_chunk_auth_failed() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let f = fx_opts(true, |fs| write_file(fs, "big.bin", &big));
        let real = f.real("big.bin");
        flip(&f.root.join(&real), chunk_offset(2, true) + 20);
        assert_eq!(
            kinds(&f.check()),
            vec![FindingKind::ChunkAuthFailed { index: 2 }]
        );
    }

    #[test]
    fn padded_wrong_length_is_invalid_padding() {
        let f = fx_opts(true, |fs| write_file(fs, "a.txt", b"hello"));
        let path = f.root.join(f.real("a.txt"));
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(4097).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::InvalidPadding]);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn padded_bad_size_block_is_invalid_padding() {
        let f = fx_opts(true, |fs| write_file(fs, "a.txt", b"hello"));
        // Inside the size block (bytes 53..89).
        flip(&f.root.join(f.real("a.txt")), 60);
        assert_eq!(kinds(&f.check()), vec![FindingKind::InvalidPadding]);
    }

    #[test]
    fn padded_check_never_writes() {
        let f = fx_opts(true, clean_fill);
        std::fs::write(f.root.join(".DS_Store"), b"x").unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.root.join(f.real("a.txt")))
            .unwrap();
        file.set_len(4097).unwrap();
        let mut before = BTreeMap::new();
        snapshot(&f.root, &mut before);
        assert!(!f.check().is_empty());
        let mut after = BTreeMap::new();
        snapshot(&f.root, &mut after);
        assert_eq!(before, after);
    }

    #[test]
    fn swapped_file_content_is_entry_id_mismatch() {
        let f = fx(|fs| {
            write_file(fs, "a.txt", b"hello");
            write_file(fs, "b.txt", b"world");
        });
        let (a, b) = (f.root.join(f.real("a.txt")), f.root.join(f.real("b.txt")));
        let tmp = f.root.join("swap");
        std::fs::rename(&a, &tmp).unwrap();
        std::fs::rename(&b, &a).unwrap();
        std::fs::rename(&tmp, &b).unwrap();
        let findings = f.check();
        let mut got: Vec<_> = findings
            .iter()
            .map(|x| (x.real_path.clone(), x.kind.clone(), x.severity))
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        let mut want = vec![
            (
                PathBuf::from(f.real("a.txt")),
                FindingKind::EntryIdMismatch,
                Severity::Error,
            ),
            (
                PathBuf::from(f.real("b.txt")),
                FindingKind::EntryIdMismatch,
                Severity::Error,
            ),
        ];
        want.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, want);
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn swapped_dir_id_is_entry_id_mismatch() {
        let f = fx(|fs| {
            fs.mkdir(&p("d1"), 0o755).unwrap();
            fs.mkdir(&p("d2"), 0o755).unwrap();
        });
        let (d1, d2) = (f.root.join(f.real("d1")), f.root.join(f.real("d2")));
        let id1 = std::fs::read(d1.join(DIR_FILE)).unwrap();
        let id2 = std::fs::read(d2.join(DIR_FILE)).unwrap();
        std::fs::write(d1.join(DIR_FILE), id2).unwrap();
        std::fs::write(d2.join(DIR_FILE), id1).unwrap();
        let findings = f.check();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|x| x.kind == FindingKind::EntryIdMismatch)
        );
    }

    #[test]
    fn unknown_key_epoch() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let real = f.real("a.txt");
        let path = f.root.join(&real);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[1..5].copy_from_slice(&9u32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::UnknownKeyEpoch]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].real_path, PathBuf::from(real));
    }

    #[test]
    fn two_epochs_report_rotation_in_progress() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let two = crate::keys::KeySet::single(1, MasterKey::from_bytes(*f.mk.expose()))
            .with_next(MasterKey::generate().unwrap())
            .unwrap();
        let v = crate::vault::open_with_key_set(&f.root, &two).unwrap();
        let findings = check_vault(&v).unwrap();
        assert_eq!(kinds(&findings), vec![FindingKind::RotationInProgress]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].real_path, PathBuf::from(".cd-key"));
        assert_eq!(exit_code(&findings), 1);
    }

    #[test]
    fn check_never_writes() {
        let f = fx(clean_fill);
        std::fs::write(f.root.join(".DS_Store"), b"x").unwrap();
        std::fs::write(f.root.join("AAAAAAAAAAAAAAAAAAAAAAAA"), b"y").unwrap();
        let mut before = BTreeMap::new();
        snapshot(&f.root, &mut before);
        assert!(!f.check().is_empty());
        let mut after = BTreeMap::new();
        snapshot(&f.root, &mut after);
        assert_eq!(before, after);
    }

    #[test]
    fn exit_codes() {
        let w = Finding {
            severity: Severity::Warning,
            real_path: PathBuf::from("x"),
            kind: FindingKind::ForeignEntry,
        };
        let e = Finding {
            severity: Severity::Error,
            real_path: PathBuf::from("y"),
            kind: FindingKind::MissingDirId,
        };
        assert_eq!(exit_code(&[]), 0);
        assert_eq!(exit_code(std::slice::from_ref(&w)), 1);
        assert_eq!(exit_code(&[w, e]), 2);
    }

    #[test]
    fn severities() {
        for k in [
            FindingKind::ConflictCopy,
            FindingKind::ForeignEntry,
            FindingKind::MultipleDirIds,
            FindingKind::RotationInProgress,
        ] {
            assert_eq!(k.severity(), Severity::Warning);
        }
        for k in [
            FindingKind::MissingDirId,
            FindingKind::IncompleteLongEntry,
            FindingKind::UndecryptableName,
            FindingKind::InvalidFileSize,
            FindingKind::HeaderInvalid,
            FindingKind::ChunkAuthFailed { index: 0 },
            FindingKind::LongNameMismatch,
            FindingKind::Unreadable,
            FindingKind::EntryIdMismatch,
            FindingKind::UnknownKeyEpoch,
            FindingKind::InvalidPadding,
        ] {
            assert_eq!(k.severity(), Severity::Error);
        }
    }

    #[test]
    fn foreign_entry() {
        let f = fx(clean_fill);
        std::fs::write(f.root.join(".DS_Store"), b"x").unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::ForeignEntry]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].real_path, PathBuf::from(".DS_Store"));
        assert_eq!(exit_code(&findings), 1);
    }

    #[test]
    fn conflict_copy() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let real = f.real("a.txt");
        std::fs::copy(f.root.join(&real), f.root.join(format!("{real} (1)"))).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::ConflictCopy]);
        assert_eq!(findings[0].real_path, PathBuf::from(format!("{real} (1)")));
        assert_eq!(exit_code(&findings), 1);
    }

    #[test]
    fn long_conflict_copy() {
        let long = long_name();
        let f = fx(|fs| write_file(fs, &long, b"hello"));
        let entry = user_names(&f.root).remove(0);
        let copy = format!("{entry}.sync-conflict-20261031-123456-ABCDEFG");
        std::fs::rename(f.root.join(&entry), f.root.join(&copy)).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::ConflictCopy]);
        assert_eq!(findings[0].real_path, PathBuf::from(copy));
    }

    #[test]
    fn multiple_dir_ids() {
        let f = fx(|fs| {
            fs.mkdir(&p("dir"), 0o755).unwrap();
            write_file(fs, "dir/x", b"x");
        });
        let dir = f.real("dir");
        let copy = PathBuf::from(&dir).join(".cd-dir (1)");
        std::fs::write(f.root.join(&copy), [9u8; 16]).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::MultipleDirIds]);
        assert_eq!(findings[0].real_path, copy);
        assert_eq!(exit_code(&findings), 1);
    }

    #[test]
    fn missing_dir_id() {
        let f = fx(|fs| {
            fs.mkdir(&p("dir"), 0o755).unwrap();
            write_file(fs, "dir/x", b"x");
        });
        let dir = f.real("dir");
        std::fs::remove_file(f.root.join(&dir).join(DIR_FILE)).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::MissingDirId]);
        assert_eq!(findings[0].real_path, PathBuf::from(dir));
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn long_entry_without_name_file() {
        let long = long_name();
        let f = fx(|fs| write_file(fs, &long, b"hello"));
        let entry = user_names(&f.root).remove(0);
        std::fs::remove_file(f.root.join(&entry).join(NAME_FILE)).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::IncompleteLongEntry]);
        assert_eq!(findings[0].real_path, PathBuf::from(entry));
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn long_entry_without_content_or_dir_id() {
        let long = long_name();
        let f = fx(|fs| write_file(fs, &long, b"hello"));
        let entry = user_names(&f.root).remove(0);
        std::fs::remove_file(f.root.join(&entry).join(".cd-content")).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::IncompleteLongEntry]);
    }

    #[test]
    fn long_name_mismatch() {
        let long = long_name();
        let f = fx(|fs| write_file(fs, &long, b"hello"));
        let entry = user_names(&f.root).remove(0);
        let other = f
            .names
            .encrypt_write(&f.vault_id, &[0u8; 16], &format!("{long}-other"))
            .unwrap();
        std::fs::write(f.root.join(&entry).join(NAME_FILE), other).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::LongNameMismatch]);
        assert_eq!(findings[0].real_path, PathBuf::from(entry));
    }

    #[test]
    fn invalid_file_size() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let real = f.real("a.txt");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.root.join(&real))
            .unwrap();
        file.set_len(40).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::InvalidFileSize]);
        assert_eq!(findings[0].real_path, PathBuf::from(real));
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn header_invalid() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let path = f.root.join(f.real("a.txt"));
        flip(&path, 0);
        assert_eq!(kinds(&f.check()), vec![FindingKind::HeaderInvalid]);
    }

    #[test]
    fn chunk_auth_failed() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let f = fx(|fs| write_file(fs, "big.bin", &big));
        let real = f.real("big.bin");
        flip(&f.root.join(&real), chunk_offset(2, false) + 20);
        let findings = f.check();
        assert_eq!(
            kinds(&findings),
            vec![FindingKind::ChunkAuthFailed { index: 2 }]
        );
        assert_eq!(findings[0].real_path, PathBuf::from(real));
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn chunk_auth_failed_in_long_file() {
        let long = long_name();
        let f = fx(|fs| write_file(fs, &format!("{long}x"), b"hello"));
        let entry = user_names(&f.root).remove(0);
        let content = PathBuf::from(&entry).join(".cd-content");
        flip(&f.root.join(&content), chunk_offset(0, false) + 13);
        let findings = f.check();
        assert_eq!(
            kinds(&findings),
            vec![FindingKind::ChunkAuthFailed { index: 0 }]
        );
        assert_eq!(findings[0].real_path, content);
    }

    #[test]
    fn undecryptable_name() {
        let f = fx(|fs| write_file(fs, "a.txt", b"hello"));
        let real = f.real("a.txt");
        let bad = "AAAAAAAAAAAAAAAAAAAAAAAA";
        std::fs::rename(f.root.join(&real), f.root.join(bad)).unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::UndecryptableName]);
        assert_eq!(findings[0].real_path, PathBuf::from(bad));
        assert_eq!(exit_code(&findings), 2);
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn unreadable_entries_are_reported_and_the_walk_goes_on() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: root can read everything");
            return;
        }
        let f = fx(|fs| {
            write_file(fs, "a.txt", b"hello");
            write_file(fs, "b.txt", b"world");
            fs.mkdir(&p("dir"), 0o755).unwrap();
            write_file(fs, "dir/x", b"x");
            fs.mkdir(&p("z"), 0o755).unwrap();
        });
        let file = f.real("a.txt");
        let dir = f.real("dir");
        let z = f.real("z");
        std::fs::write(f.root.join(&z).join(".DS_Store"), b"x").unwrap();
        set_mode(&f.root.join(&file), 0o000);
        set_mode(&f.root.join(&dir), 0o000);
        let findings = f.check();
        set_mode(&f.root.join(&file), 0o644);
        set_mode(&f.root.join(&dir), 0o755);
        let mut got: Vec<(PathBuf, FindingKind)> = findings
            .iter()
            .map(|f| (f.real_path.clone(), f.kind.clone()))
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        let mut want = vec![
            (PathBuf::from(&file), FindingKind::Unreadable),
            (PathBuf::from(&dir), FindingKind::Unreadable),
            (
                PathBuf::from(&z).join(".DS_Store"),
                FindingKind::ForeignEntry,
            ),
        ];
        want.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, want);
        assert_eq!(FindingKind::Unreadable.severity(), Severity::Error);
        assert_eq!(exit_code(&findings), 2);
    }

    #[test]
    fn nested_findings_use_real_paths() {
        let f = fx(|fs| {
            fs.mkdir(&p("dir"), 0o755).unwrap();
            fs.mkdir(&p("dir/sub"), 0o755).unwrap();
        });
        let dir = f.real("dir");
        let sub_real = user_names(&f.root.join(&dir)).remove(0);
        let foreign = PathBuf::from(&dir).join(&sub_real).join("Thumbs.db");
        std::fs::write(f.root.join(&foreign), b"x").unwrap();
        let findings = f.check();
        assert_eq!(kinds(&findings), vec![FindingKind::UndecryptableName]);
        assert_eq!(findings[0].real_path, foreign);
    }
}
