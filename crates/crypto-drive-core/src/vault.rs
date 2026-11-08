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

//! Vault marker `.cd-vault`, init, unlock and the mount lock (spec 4.1, 4.4).

use crate::backing::{DirHandle, Kind};
use crate::conflict::{long_candidate, short_candidates};
use crate::content::CHUNK_SIZE;
use crate::error::{Error, Result};
use crate::file::{OpenFile, header_epoch};
use crate::fs::dirstate::read_dir_id;
use crate::fs::listing::{long_layout, open_entry_dir, read_long_name};
use crate::keyfile::{Argon2Params, KeyFile};
use crate::keys::{DirId, Epoch, KeySet, MasterKey, SubKeys, VaultId};
use crate::names::NameKeys;
use crate::secret::random_bytes;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub const VAULT_FILE: &str = ".cd-vault";
pub const KEY_FILE: &str = ".cd-key";
pub const DIR_FILE: &str = ".cd-dir";
pub const NAME_FILE: &str = ".cd-name";
pub const CONTENT_FILE: &str = ".cd-content";
pub const CONTROL_PREFIX: &str = ".cd-";
pub const DEFAULT_MAX_NAME_LENGTH: u16 = 220;

const MAGIC: &[u8; 8] = b"CD-VAULT";
const FORMAT_VERSION: u16 = 1;
pub const MARKER_LEN: usize = 66;
const BODY_LEN: usize = 34;
const FLAG_PAD_SIZES: u16 = 1;
const FIRST_EPOCH: Epoch = 1;
const MIN_NAME_LENGTH: u16 = 64;
const MAX_NAME_LENGTH: u16 = 255;

type HmacSha256 = Hmac<Sha256>;

fn invalid() -> Error {
    Error::InvalidFormat {
        what: VAULT_FILE.into(),
    }
}

/// The content of `.cd-vault` without the tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultMarker {
    pub format_version: u16,
    pub max_name_length: u16,
    pub pad_sizes: bool,
    pub vault_id: VaultId,
    /// The vault's current epoch.
    pub epoch: Epoch,
}

impl VaultMarker {
    fn body(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        b[10..12].copy_from_slice(&self.max_name_length.to_le_bytes());
        b[12..14].copy_from_slice(&u16::from(self.pad_sizes).to_le_bytes());
        b[14..30].copy_from_slice(&self.vault_id);
        b[30..34].copy_from_slice(&self.epoch.to_le_bytes());
        b
    }

    fn mac(check_key: &[u8; 32], body: &[u8]) -> HmacSha256 {
        // HMAC accepts keys of any length, so this cannot fail.
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(check_key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(body);
        mac
    }

    /// Serializes the marker and appends the tag (`K_check` of the marker epoch).
    pub fn to_bytes(&self, check_key: &[u8; 32]) -> [u8; MARKER_LEN] {
        let body = self.body();
        let tag = Self::mac(check_key, &body).finalize().into_bytes();
        let mut out = [0u8; MARKER_LEN];
        out[..BODY_LEN].copy_from_slice(&body);
        out[BODY_LEN..].copy_from_slice(&tag);
        out
    }

    /// Checks magic, length, version, name length and flags. Does not check the tag.
    pub fn parse_unverified(b: &[u8]) -> Result<VaultMarker> {
        if b.len() != MARKER_LEN || &b[0..8] != MAGIC {
            return Err(invalid());
        }
        let format_version = u16::from_le_bytes([b[8], b[9]]);
        if format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: format_version,
            });
        }
        let max_name_length = u16::from_le_bytes([b[10], b[11]]);
        if !(MIN_NAME_LENGTH..=MAX_NAME_LENGTH).contains(&max_name_length) {
            return Err(invalid());
        }
        let flags = u16::from_le_bytes([b[12], b[13]]);
        if flags & !FLAG_PAD_SIZES != 0 {
            return Err(Error::InvalidFormat {
                what: ".cd-vault flags".into(),
            });
        }
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&b[14..30]);
        let epoch = u32::from_le_bytes([b[30], b[31], b[32], b[33]]);
        Ok(VaultMarker {
            format_version,
            max_name_length,
            pad_sizes: flags & FLAG_PAD_SIZES != 0,
            vault_id,
            epoch,
        })
    }

    /// Checks the tag in constant time; `WrongKey` if it does not match.
    pub fn verify(b: &[u8], check_key: &[u8; 32]) -> Result<()> {
        if b.len() != MARKER_LEN {
            return Err(invalid());
        }
        Self::mac(check_key, &b[..BODY_LEN])
            .verify_slice(&b[BODY_LEN..])
            .map_err(|_| Error::WrongKey)
    }
}

/// The derived keys of every epoch the vault can use.
pub struct VaultKeys {
    vault_id: VaultId,
    by_epoch: BTreeMap<Epoch, SubKeys>,
}

impl VaultKeys {
    /// Derives the sub keys of every epoch in the key set.
    pub fn new(vault_id: &VaultId, keys: &KeySet) -> VaultKeys {
        let by_epoch = keys
            .epochs()
            .into_iter()
            .filter_map(|e| keys.get(e).map(|mk| (e, mk.derive(vault_id, e))))
            .collect();
        VaultKeys {
            vault_id: *vault_id,
            by_epoch,
        }
    }

    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    pub fn get(&self, epoch: Epoch) -> Option<&SubKeys> {
        self.by_epoch.get(&epoch)
    }

    /// The highest epoch. A key set is never empty.
    pub fn write_epoch(&self) -> Epoch {
        self.by_epoch.keys().next_back().copied().unwrap_or(0)
    }

    /// All epochs, highest first.
    pub fn epochs_desc(&self) -> Vec<Epoch> {
        self.by_epoch.keys().rev().copied().collect()
    }
}

pub struct InitOptions {
    pub max_name_length: u16,
    pub argon2: Argon2Params,
    /// Key file outside the vault; `None` means `<vault>/.cd-key`.
    pub key_file: Option<PathBuf>,
    pub pad_sizes: bool,
}

pub fn key_file_path(vault_dir: &Path, key_file: Option<&Path>) -> PathBuf {
    match key_file {
        Some(p) => p.to_path_buf(),
        None => vault_dir.join(KEY_FILE),
    }
}

/// Creates a new vault (epoch 1). The directory must not exist (its parent
/// must) or must be empty. Returns the master key so the caller can show the
/// recovery key.
pub fn init_vault(vault_dir: &Path, password: &[u8], opts: &InitOptions) -> Result<MasterKey> {
    if !(MIN_NAME_LENGTH..=MAX_NAME_LENGTH).contains(&opts.max_name_length) {
        return Err(Error::InvalidArgument);
    }
    opts.argon2.validate()?;

    let created = match std::fs::symlink_metadata(vault_dir) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(vault_dir)?;
            true
        }
        Err(e) => return Err(e.into()),
    };
    let result = init_in_dir(vault_dir, password, opts, created);
    if result.is_err() && created {
        let _ = std::fs::remove_dir(vault_dir);
    }
    result
}

fn init_in_dir(
    vault_dir: &Path,
    password: &[u8],
    opts: &InitOptions,
    created: bool,
) -> Result<MasterKey> {
    let root = DirHandle::open_root(vault_dir)?;
    if !created && !root.list()?.is_empty() {
        return Err(Error::AlreadyExists);
    }
    let mk = MasterKey::generate()?;
    let marker = VaultMarker {
        format_version: FORMAT_VERSION,
        max_name_length: opts.max_name_length,
        pad_sizes: opts.pad_sizes,
        vault_id: random_bytes::<16>()?,
        epoch: FIRST_EPOCH,
    };
    let keys = mk.derive(&marker.vault_id, FIRST_EPOCH);
    let key_file = KeyFile::new(
        &KeySet::single(FIRST_EPOCH, MasterKey::from_bytes(*mk.expose())),
        password,
        opts.argon2,
    )?;
    root.write_atomic(VAULT_FILE, &marker.to_bytes(keys.check()), 0o600)?;
    let key_path = key_file_path(vault_dir, opts.key_file.as_deref());
    if let Err(e) = key_file.save_new(&key_path) {
        let _ = root.unlink(VAULT_FILE);
        return Err(e);
    }
    Ok(mk)
}

/// Writes the marker atomically (used at the end of a rotation; `init`
/// writes its marker itself).
pub fn write_marker(vault_dir: &Path, marker: &VaultMarker, check_key: &[u8; 32]) -> Result<()> {
    let root = DirHandle::open_root(vault_dir)?;
    root.write_atomic(VAULT_FILE, &marker.to_bytes(check_key), 0o600)
}

/// A vault whose keys are known. It is not `Clone` because it holds keys.
pub struct UnlockedVault {
    pub root_path: PathBuf,
    pub marker: VaultMarker,
    pub keys: VaultKeys,
}

fn read_marker(vault_dir: &Path) -> Result<(VaultMarker, Vec<u8>)> {
    let root = DirHandle::open_root(vault_dir)?;
    let bytes = root.read_small(VAULT_FILE, MARKER_LEN)?;
    let marker = VaultMarker::parse_unverified(&bytes)?;
    Ok((marker, bytes))
}

fn open_checked(
    vault_dir: &Path,
    marker: VaultMarker,
    bytes: &[u8],
    key_set: &KeySet,
) -> Result<UnlockedVault> {
    let keys = VaultKeys::new(&marker.vault_id, key_set);
    let check = keys.get(marker.epoch).ok_or(Error::WrongKey)?.check();
    VaultMarker::verify(bytes, check)?;
    Ok(UnlockedVault {
        root_path: vault_dir.to_path_buf(),
        marker,
        keys,
    })
}

/// Opens a vault with a known key set.
pub fn open_with_key_set(vault_dir: &Path, keys: &KeySet) -> Result<UnlockedVault> {
    let (marker, bytes) = read_marker(vault_dir)?;
    open_checked(vault_dir, marker, &bytes, keys)
}

/// Opens a vault with the master key of the marker epoch (for example from a
/// recovery key).
pub fn open_with_master_key(vault_dir: &Path, mk: &MasterKey) -> Result<UnlockedVault> {
    let (marker, bytes) = read_marker(vault_dir)?;
    let keys = KeySet::single(marker.epoch, MasterKey::from_bytes(*mk.expose()));
    open_checked(vault_dir, marker, &bytes, &keys)
}

/// Unlocks a vault with a password. Writes nothing.
pub fn unlock_vault(
    vault_dir: &Path,
    key_file: Option<&Path>,
    password: &[u8],
) -> Result<(UnlockedVault, KeySet)> {
    let (marker, bytes) = read_marker(vault_dir)?;
    let kf = KeyFile::load(&key_file_path(vault_dir, key_file))?;
    let keys = kf.unlock(password)?;
    let vault = open_checked(vault_dir, marker, &bytes, &keys)?;
    Ok((vault, keys))
}

/// The kind of `name`; `None` if it is gone.
fn kind_of(dir: &DirHandle, name: &str) -> Result<Option<Kind>> {
    match dir.stat(name) {
        Ok(st) => Ok(Some(st.kind)),
        Err(Error::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The encrypted names that the real entry `name` may stand for: the
/// prefix candidates of a short name, or the `.cd-name` of a long entry.
/// Empty for foreign and control entries (as the listing skips them), for
/// a long entry without a readable `.cd-name`, and for a long entry that
/// holds no data (no `.cd-content` and no `.cd-dir`): such a leftover of
/// an interrupted create holds nothing that a key could lose, and a
/// rotation leaves it alone.
fn encoded_names(dir: &DirHandle, name: &str, kind: Kind) -> Result<Vec<String>> {
    if long_candidate(name).is_some() {
        if kind != Kind::Dir {
            return Ok(Vec::new());
        }
        let Some(entry) = open_entry_dir(dir, name)? else {
            return Ok(Vec::new());
        };
        if long_layout(&entry)?.is_none() {
            return Ok(Vec::new());
        }
        return Ok(read_long_name(&entry)?.into_iter().collect());
    }
    Ok(short_candidates(name)
        .into_iter()
        .map(|(prefix, _)| prefix.to_owned())
        .collect())
}

/// True if one of `encoded` decrypts with `keys` under the directory id
/// `id` (never under the id of a `.cd-dir` copy).
fn decrypts(keys: &NameKeys, id: &DirId, encoded: &[String]) -> bool {
    encoded.iter().any(|e| keys.decrypt_any(id, e).is_some())
}

/// True for a real file that holds encrypted content: `.cd-content`, or a
/// short name that may be an encrypted name.
fn is_content_file(name: &str, kind: Kind) -> bool {
    kind == Kind::File && (name == CONTENT_FILE || !short_candidates(name).is_empty())
}

/// The header epoch of a content file; `None` if it is not valid or gone.
fn content_epoch(dir: &DirHandle, name: &str) -> Result<Option<Epoch>> {
    match header_epoch(dir, name) {
        Ok(e) => Ok(e),
        Err(Error::NotFound | Error::InvalidFormat { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Called by `walk_tree` with the real directory, its id, an entry name
/// and its kind; true stops the walk.
type Visit<'a> = dyn FnMut(&DirHandle, Option<&DirId>, &str, Kind) -> Result<bool> + 'a;

/// Visits every real entry of `dir` and below, depth first, without
/// following links. `id` is the id in the `.cd-dir` of `dir` (`None` if it
/// has none; copies are never used). Every real directory is entered, also one whose name
/// does not decrypt. Stops as soon as `visit` returns true.
fn walk_tree(dir: &DirHandle, id: Option<&DirId>, visit: &mut Visit<'_>) -> Result<bool> {
    for name in dir.list()? {
        let Some(kind) = kind_of(dir, &name)? else {
            continue;
        };
        if visit(dir, id, &name, kind)? {
            return Ok(true);
        }
        if kind == Kind::Dir {
            let child = dir.open_dir(&name)?;
            let found = match read_dir_id(&child, &name, &child.list()?) {
                Ok(ids) => walk_tree(&child, Some(&ids.id), visit)?,
                Err(Error::NotFound | Error::InvalidFormat { .. }) => {
                    walk_tree(&child, None, visit)?
                }
                Err(e) => return Err(e),
            };
            if found {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// True if a key rotation did not finish (HS 7). `vault` was opened with
/// the key of its marker epoch `e` only. Unfinished means: a real name
/// that should be an encrypted name does not decrypt with `K_names[e]`
/// under its parent's id, or a file header has another epoch than `e`.
/// Foreign and control entries are skipped as the listing skips them.
pub fn rotation_unfinished(vault: &UnlockedVault) -> Result<bool> {
    let epoch = vault.marker.epoch;
    let names = NameKeys::new(&vault.keys);
    let root = DirHandle::open_root(&vault.root_path)?;
    walk_tree(
        &root,
        Some(&vault.marker.vault_id),
        &mut |dir, id, name, kind| {
            if let Some(id) = id {
                let encoded = encoded_names(dir, name, kind)?;
                if !encoded.is_empty() && !decrypts(&names, id, &encoded) {
                    return Ok(true);
                }
            }
            Ok(
                is_content_file(name, kind)
                    && content_epoch(dir, name)?.is_some_and(|e| e != epoch),
            )
        },
    )
}

/// Checks that `mk` is the master key of the epoch after the marker epoch
/// of `vault` (an unfinished rotation, HS 7): a name must decrypt with it,
/// or a file of the next epoch must authenticate with it (header and first
/// chunk). Otherwise `WrongKey`.
pub fn verify_next_key(vault: &UnlockedVault, mk: &MasterKey) -> Result<()> {
    let next = vault
        .marker
        .epoch
        .checked_add(1)
        .ok_or(Error::InvalidArgument)?;
    let keys = VaultKeys::new(
        &vault.marker.vault_id,
        &KeySet::single(next, MasterKey::from_bytes(*mk.expose())),
    );
    let names = NameKeys::new(&keys);
    let padded = vault.marker.pad_sizes;
    let root = DirHandle::open_root(&vault.root_path)?;
    let proven = walk_tree(
        &root,
        Some(&vault.marker.vault_id),
        &mut |dir, id, name, kind| {
            if let Some(id) = id
                && decrypts(&names, id, &encoded_names(dir, name, kind)?)
            {
                return Ok(true);
            }
            if !is_content_file(name, kind) || content_epoch(dir, name)? != Some(next) {
                return Ok(false);
            }
            let result = dir
                .open_file(name, false)
                .and_then(|f| OpenFile::open(f, &keys, padded))
                .and_then(|mut f| f.read(0, CHUNK_SIZE as usize));
            match result {
                Ok(_) => Ok(true),
                Err(Error::AuthFailed { .. } | Error::InvalidFormat { .. } | Error::NotFound) => {
                    Ok(false)
                }
                Err(e) => Err(e),
            }
        },
    )?;
    if proven { Ok(()) } else { Err(Error::WrongKey) }
}

/// Holds the exclusive lock on `.cd-vault`; released on drop.
pub struct VaultLock {
    _file: File,
}

/// Takes the mount lock; `AlreadyMounted` if another holder has it.
pub fn lock_vault(vault_dir: &Path) -> Result<VaultLock> {
    let root = DirHandle::open_root(vault_dir)?;
    let file = root.open_file(VAULT_FILE, false)?;
    DirHandle::lock_exclusive_nonblocking(&file)?;
    Ok(VaultLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;
    use crate::testutil::{TEST_PASSWORD, test_vault, test_vault_padded};

    fn opts(max: u16) -> InitOptions {
        InitOptions {
            max_name_length: max,
            argon2: Argon2Params::MIN,
            key_file: None,
            pad_sizes: false,
        }
    }

    fn snapshot(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    m.len(),
                    m.modified().unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn init_then_unlock_works() {
        let (_t, v, _mk) = test_vault();
        assert_eq!(v.marker.max_name_length, 220);
        assert_eq!(v.marker.format_version, 1);
    }

    #[test]
    fn wrong_password() {
        let (_t, v, _mk) = test_vault();
        let r = unlock_vault(&v.root_path, None, b"nope");
        assert!(matches!(r, Err(Error::WrongPassword)));
    }

    #[test]
    fn init_into_non_empty_dir_fails() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("x"), b"1").unwrap();
        let r = init_vault(t.path(), b"pw", &opts(220));
        assert!(matches!(r, Err(Error::AlreadyExists)));
        assert_eq!(snapshot(t.path()).len(), 1);
    }

    #[test]
    fn init_into_empty_dir_works_and_missing_parent_fails() {
        let t = tempfile::tempdir().unwrap();
        init_vault(t.path(), b"pw", &opts(220)).unwrap();
        let r = init_vault(&t.path().join("a/b"), b"pw", &opts(220));
        assert!(matches!(r, Err(Error::Io(_))));
    }

    #[test]
    fn key_file_outside_vault() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("v");
        let kf = t.path().join("my.key");
        let mut o = opts(220);
        o.key_file = Some(kf.clone());
        init_vault(&dir, b"pw", &o).unwrap();
        assert_eq!(snapshot(&dir).len(), 1);
        assert_eq!(snapshot(&dir)[0].0, VAULT_FILE);
        unlock_vault(&dir, Some(&kf), b"pw").unwrap();
    }

    #[test]
    fn key_file_of_other_vault_is_wrong_key() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        init_vault(&a, b"pw", &opts(220)).unwrap();
        init_vault(&b, b"pw", &opts(220)).unwrap();
        let r = unlock_vault(&a, Some(&b.join(KEY_FILE)), b"pw");
        assert!(matches!(r, Err(Error::WrongKey)));
    }

    #[test]
    fn failed_key_file_save_cleans_up() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("v");
        let kf = t.path().join("exists.key");
        std::fs::write(&kf, b"x").unwrap();
        let mut o = opts(220);
        o.key_file = Some(kf);
        assert!(matches!(
            init_vault(&dir, b"pw", &o),
            Err(Error::AlreadyExists)
        ));
        assert!(!dir.exists());
    }

    #[test]
    fn marker_is_66_bytes_and_tag_bit_flip_is_wrong_key() {
        let (_t, v, mk) = test_vault();
        let check = *v.keys.get(1).unwrap().check();
        let mut b = std::fs::read(v.root_path.join(VAULT_FILE)).unwrap();
        assert_eq!(b.len(), MARKER_LEN);
        assert_eq!(b.len(), 66);
        assert_eq!(&b[30..34], &1u32.to_le_bytes());
        assert!(VaultMarker::verify(&b, &check).is_ok());
        b[40] ^= 1;
        assert!(matches!(
            VaultMarker::verify(&b, &check),
            Err(Error::WrongKey)
        ));
        std::fs::write(v.root_path.join(VAULT_FILE), &b).unwrap();
        assert!(matches!(
            open_with_master_key(&v.root_path, &mk),
            Err(Error::WrongKey)
        ));
        assert!(matches!(
            unlock_vault(&v.root_path, None, TEST_PASSWORD),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn unsupported_version_changes_nothing() {
        let (_t, v, _mk) = test_vault();
        let path = v.root_path.join(VAULT_FILE);
        let mut b = std::fs::read(&path).unwrap();
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(&path, &b).unwrap();
        let before = snapshot(&v.root_path);
        let r = unlock_vault(&v.root_path, None, b"wrong password too");
        assert!(matches!(r, Err(Error::UnsupportedVersion { found: 2 })));
        assert_eq!(before, snapshot(&v.root_path));
    }

    #[test]
    fn bad_marker_is_invalid_format() {
        assert!(matches!(
            VaultMarker::parse_unverified(&[0; 65]),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(matches!(
            VaultMarker::parse_unverified(&[0; 66]),
            Err(Error::InvalidFormat { .. })
        ));
        let (_t, v, _mk) = test_vault();
        let mut b = std::fs::read(v.root_path.join(VAULT_FILE)).unwrap();
        b[10..12].copy_from_slice(&63u16.to_le_bytes());
        assert!(matches!(
            VaultMarker::parse_unverified(&b),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn max_name_length_bounds() {
        let t = tempfile::tempdir().unwrap();
        for bad in [63u16, 256] {
            let r = init_vault(&t.path().join("v"), b"pw", &opts(bad));
            assert!(matches!(r, Err(Error::InvalidArgument)));
        }
        assert!(!t.path().join("v").exists());
        for ok in [64u16, 255] {
            init_vault(&t.path().join(format!("v{ok}")), b"pw", &opts(ok)).unwrap();
        }
    }

    #[test]
    fn bad_argon2_params_write_nothing() {
        let t = tempfile::tempdir().unwrap();
        let mut o = opts(220);
        o.argon2.m_kib = 1;
        assert!(matches!(
            init_vault(&t.path().join("v"), b"pw", &o),
            Err(Error::InvalidArgument)
        ));
        assert!(!t.path().join("v").exists());
    }

    #[test]
    fn lock_twice_is_already_mounted() {
        let (_t, v, _mk) = test_vault();
        let first = lock_vault(&v.root_path).unwrap();
        assert!(matches!(
            lock_vault(&v.root_path),
            Err(Error::AlreadyMounted)
        ));
        drop(first);
        lock_vault(&v.root_path).unwrap();
    }

    fn key_set(epochs: &[u32], seed: u8) -> KeySet {
        let mut it = epochs.iter();
        let first = *it.next().unwrap();
        let mut ks = KeySet::single(first, MasterKey::from_bytes([seed + first as u8; 32]));
        for e in it {
            ks = ks
                .with_next(MasterKey::from_bytes([seed + *e as u8; 32]))
                .unwrap();
        }
        ks
    }

    /// A vault whose marker has the given epoch and whose keys are `base`.
    fn vault_with_marker_epoch(epoch: u32) -> (tempfile::TempDir, VaultMarker, KeySet) {
        let t = tempfile::tempdir().unwrap();
        let ks = key_set(&[1, 2], 10);
        let marker = VaultMarker {
            format_version: 1,
            max_name_length: 220,
            pad_sizes: false,
            vault_id: [7; 16],
            epoch,
        };
        let vk = VaultKeys::new(&marker.vault_id, &ks);
        write_marker(t.path(), &marker, vk.get(epoch).unwrap().check()).unwrap();
        (t, marker, ks)
    }

    #[test]
    fn flag_bit_one_is_invalid_format_and_pad_flag_roundtrips() {
        let (_t, v, _mk) = test_vault();
        let check = *v.keys.get(1).unwrap().check();
        let mut b = v.marker.to_bytes(&check);
        assert_eq!(&b[12..14], &[0, 0]);
        b[12] = 2;
        assert!(matches!(
            VaultMarker::parse_unverified(&b),
            Err(Error::InvalidFormat { what }) if what == ".cd-vault flags"
        ));
        b[12] = 0;
        b[13] = 1;
        assert!(matches!(
            VaultMarker::parse_unverified(&b),
            Err(Error::InvalidFormat { what }) if what == ".cd-vault flags"
        ));
        let mut m = v.marker;
        m.pad_sizes = true;
        let b = m.to_bytes(&check);
        assert_eq!(b[12], 1);
        assert_eq!(VaultMarker::parse_unverified(&b).unwrap(), m);
    }

    #[test]
    fn bad_flags_change_nothing_on_unlock() {
        let (_t, v, _mk) = test_vault();
        let path = v.root_path.join(VAULT_FILE);
        let mut b = std::fs::read(&path).unwrap();
        b[12] = 0x80;
        std::fs::write(&path, &b).unwrap();
        let before = snapshot(&v.root_path);
        let r = unlock_vault(&v.root_path, None, b"wrong password too");
        assert!(matches!(r, Err(Error::InvalidFormat { .. })));
        assert_eq!(before, snapshot(&v.root_path));
    }

    #[test]
    fn init_with_pad_sizes_sets_flag_and_epoch_one() {
        let (_t, v, _mk) = test_vault_padded();
        assert!(v.marker.pad_sizes);
        assert_eq!(v.marker.epoch, 1);
        let b = std::fs::read(v.root_path.join(VAULT_FILE)).unwrap();
        assert_eq!(b[12], 1);
        let (_t2, v2, _mk2) = test_vault();
        assert!(!v2.marker.pad_sizes);
    }

    #[test]
    fn key_set_with_two_epochs_opens_with_either_marker_epoch() {
        for epoch in [1, 2] {
            let (t, marker, ks) = vault_with_marker_epoch(epoch);
            let v = open_with_key_set(t.path(), &ks).unwrap();
            assert_eq!(v.marker, marker);
            assert_eq!(v.keys.epochs_desc(), vec![2, 1]);
            assert_eq!(v.keys.write_epoch(), 2);
        }
    }

    #[test]
    fn key_set_without_the_marker_epoch_is_wrong_key() {
        let (t, _marker, ks) = vault_with_marker_epoch(1);
        let only2 = ks.only(2).unwrap();
        assert!(matches!(
            open_with_key_set(t.path(), &only2),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn open_with_master_key_uses_the_marker_epoch() {
        let (t, _marker, ks) = vault_with_marker_epoch(2);
        let mk2 = MasterKey::from_bytes(*ks.get(2).unwrap().expose());
        let v = open_with_master_key(t.path(), &mk2).unwrap();
        assert_eq!(v.keys.epochs_desc(), vec![2]);
        let mk1 = MasterKey::from_bytes(*ks.get(1).unwrap().expose());
        assert!(matches!(
            open_with_master_key(t.path(), &mk1),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn unlock_returns_the_key_set() {
        let (_t, v, mk) = test_vault();
        let (_v2, ks) = unlock_vault(&v.root_path, None, TEST_PASSWORD).unwrap();
        assert_eq!(ks.epochs(), vec![1]);
        assert_eq!(ks.get(1).unwrap().expose(), mk.expose());
    }

    #[test]
    fn write_marker_is_atomic_and_leaves_no_temp_file() {
        let (_t, v, _mk) = test_vault();
        let mut m = v.marker;
        m.pad_sizes = true;
        write_marker(&v.root_path, &m, v.keys.get(1).unwrap().check()).unwrap();
        let names: Vec<_> = snapshot(&v.root_path).into_iter().map(|e| e.0).collect();
        assert_eq!(names, vec![KEY_FILE.to_string(), VAULT_FILE.to_string()]);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(v.root_path.join(VAULT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        unlock_vault(&v.root_path, None, TEST_PASSWORD).unwrap();
    }
}
