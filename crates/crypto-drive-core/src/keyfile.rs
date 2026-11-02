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

//! Password-protected key file `.cd-key` (spec 4.3).

use crate::error::{Error, Result};
use crate::keys::KeySet;
use crate::secret::{SecretBytes, random_bytes};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"CD-KEY\0\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 12;
const SLOT_PASSWORD: u8 = 1;
/// Password payload lengths for a key set with one or two keys.
const PAYLOAD_LEN_ONE: usize = 93;
const PAYLOAD_LEN_TWO: usize = 129;
/// Payload bytes that are part of the AD (Argon2 params, salt, nonce).
const PAYLOAD_AD_LEN: usize = 40;
const WHAT: &str = ".cd-key";

/// Most slots a reader accepts in one key file. A writer writes one (or a
/// few); a crafted file with thousands of slots, each with the highest
/// Argon2 values, would keep `unlock` busy for hours.
pub const MAX_SLOTS: u16 = 16;

/// Largest key file a reader reads (64 KiB). A real one is 108 or 144
/// bytes; the limit keeps a huge file from filling the memory.
pub const MAX_KEY_FILE_LEN: u64 = 64 * 1024;

fn invalid() -> Error {
    Error::InvalidFormat { what: WHAT.into() }
}

/// Argon2id cost parameters of a password slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 262144,
            t: 3,
            p: 4,
        }
    }
}

impl Argon2Params {
    /// Lowest values that are accepted.
    pub const MIN: Argon2Params = Argon2Params {
        m_kib: 19456,
        t: 2,
        p: 1,
    };

    /// Highest values that are accepted. They protect against a damaged or
    /// hostile key file that would make `unlock` allocate huge memory or run
    /// for hours.
    pub const MAX: Argon2Params = Argon2Params {
        m_kib: 1 << 20,
        t: 64,
        p: 64,
    };

    /// Returns `InvalidArgument` if any value is below `MIN` or above `MAX`.
    pub fn validate(&self) -> Result<()> {
        if self.m_kib < Self::MIN.m_kib || self.t < Self::MIN.t || self.p < Self::MIN.p {
            return Err(Error::InvalidArgument);
        }
        if self.is_above_max() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    fn is_above_max(&self) -> bool {
        self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p
    }

    /// True if any value is below the default (the CLI prints a warning).
    pub fn is_below_default(&self) -> bool {
        let d = Self::default();
        self.m_kib < d.m_kib || self.t < d.t || self.p < d.p
    }
}

enum Slot {
    Password {
        params: Argon2Params,
        salt: [u8; 16],
        nonce: [u8; 12],
        wrapped: Vec<u8>,
    },
    /// A slot type this version does not know. Kept unchanged.
    Unknown { slot_type: u8, payload: Vec<u8> },
}

impl Slot {
    fn type_byte(&self) -> u8 {
        match self {
            Slot::Password { .. } => SLOT_PASSWORD,
            Slot::Unknown { slot_type, .. } => *slot_type,
        }
    }

    fn payload(&self) -> Vec<u8> {
        match self {
            Slot::Password {
                params,
                salt,
                nonce,
                wrapped,
            } => {
                let mut v = Vec::with_capacity(PAYLOAD_AD_LEN + wrapped.len());
                v.extend_from_slice(&params.m_kib.to_le_bytes());
                v.extend_from_slice(&params.t.to_le_bytes());
                v.extend_from_slice(&params.p.to_le_bytes());
                v.extend_from_slice(salt);
                v.extend_from_slice(nonce);
                v.extend_from_slice(wrapped);
                v
            }
            Slot::Unknown { payload, .. } => payload.clone(),
        }
    }
}

/// The additional data of a password slot (spec 4.3).
fn slot_ad(payload_head: &[u8], payload_len: usize) -> Vec<u8> {
    let mut ad = Vec::with_capacity(10 + 1 + 2 + PAYLOAD_AD_LEN);
    ad.extend_from_slice(MAGIC);
    ad.extend_from_slice(&VERSION.to_le_bytes());
    ad.push(SLOT_PASSWORD);
    ad.extend_from_slice(&(payload_len as u16).to_le_bytes());
    ad.extend_from_slice(&payload_head[..PAYLOAD_AD_LEN]);
    ad
}

fn derive_kek(password: &[u8], params: Argon2Params, salt: &[u8; 16]) -> Option<SecretBytes<32>> {
    if params.is_above_max() {
        return None;
    }
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32)).ok()?;
    // Own the working memory so that it is wiped when it is dropped.
    let mut blocks = Zeroizing::new(vec![Block::default(); argon_params.block_count()]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(password, salt, &mut *out, &mut *blocks)
        .ok()?;
    Some(SecretBytes::new(*out))
}

fn cipher(kek: &SecretBytes<32>) -> Aes256Gcm {
    Aes256Gcm::new(kek.expose().into())
}

fn new_password_slot(keys: &KeySet, password: &[u8], params: Argon2Params) -> Result<Slot> {
    new_password_slot_raw(&keys.encode(), password, params)
}

/// Wraps already encoded key set bytes (valid or not) in a password slot.
fn new_password_slot_raw(plain: &[u8], password: &[u8], params: Argon2Params) -> Result<Slot> {
    params.validate()?;
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<12>()?;
    let kek = derive_kek(password, params, &salt).ok_or(Error::InvalidArgument)?;
    let payload_len = PAYLOAD_AD_LEN + plain.len() + 16;
    let mut head = Vec::with_capacity(PAYLOAD_AD_LEN);
    head.extend_from_slice(&params.m_kib.to_le_bytes());
    head.extend_from_slice(&params.t.to_le_bytes());
    head.extend_from_slice(&params.p.to_le_bytes());
    head.extend_from_slice(&salt);
    head.extend_from_slice(&nonce);
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + 16));
    buf.extend_from_slice(plain);
    cipher(&kek)
        .encrypt_in_place(&nonce.into(), &slot_ad(&head, payload_len), &mut *buf)
        .map_err(|_| Error::InvalidArgument)?;
    Ok(Slot::Password {
        params,
        salt,
        nonce,
        wrapped: buf.to_vec(),
    })
}

/// The key file: the key set wrapped in one or more slots.
pub struct KeyFile {
    slots: Vec<Slot>,
}

impl KeyFile {
    /// Creates a key file with one password slot.
    pub fn new(keys: &KeySet, password: &[u8], params: Argon2Params) -> Result<Self> {
        Ok(Self {
            slots: vec![new_password_slot(keys, password, params)?],
        })
    }

    /// Wraps arbitrary bytes as the key set with the real KEK and AD, so
    /// tests can build broken key sets. Not part of normal builds.
    #[cfg(feature = "test-util")]
    pub fn with_raw_key_set_for_tests(
        raw: &[u8],
        password: &[u8],
        params: Argon2Params,
    ) -> Result<Self> {
        Ok(Self {
            slots: vec![new_password_slot_raw(raw, password, params)?],
        })
    }

    /// Tries every password slot. Returns `WrongPassword` if none opens.
    pub fn unlock(&self, password: &[u8]) -> Result<KeySet> {
        for slot in &self.slots {
            let Slot::Password {
                params,
                salt,
                nonce,
                wrapped,
            } = slot
            else {
                continue;
            };
            let Some(kek) = derive_kek(password, *params, salt) else {
                continue;
            };
            let payload = slot.payload();
            let mut buf = Zeroizing::new(wrapped.clone());
            if cipher(&kek)
                .decrypt_in_place(
                    &(*nonce).into(),
                    &slot_ad(&payload, payload.len()),
                    &mut *buf,
                )
                .is_err()
            {
                continue;
            }
            return KeySet::decode(&buf);
        }
        Err(Error::WrongPassword)
    }

    /// The Argon2 parameters of the first password slot.
    pub fn password_params(&self) -> Option<Argon2Params> {
        self.slots.iter().find_map(|s| match s {
            Slot::Password { params, .. } => Some(*params),
            Slot::Unknown { .. } => None,
        })
    }

    /// Removes all password slots and adds one new slot. Unknown slots stay.
    pub fn set_password(
        &mut self,
        keys: &KeySet,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<()> {
        let slot = new_password_slot(keys, password, params)?;
        self.slots.retain(|s| matches!(s, Slot::Unknown { .. }));
        self.slots.insert(0, slot);
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(self.slots.len() as u16).to_le_bytes());
        for slot in &self.slots {
            let payload = slot.payload();
            out.push(slot.type_byte());
            out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            out.extend_from_slice(&payload);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(Error::UnsupportedVersion { found: version });
        }
        let count = u16::from_le_bytes([bytes[10], bytes[11]]);
        if count == 0 || count > MAX_SLOTS {
            return Err(invalid());
        }
        let mut pos = HEADER_LEN;
        let mut slots = Vec::new();
        for _ in 0..count {
            let head = bytes.get(pos..pos + 3).ok_or_else(invalid)?;
            let slot_type = head[0];
            let len = u16::from_le_bytes([head[1], head[2]]) as usize;
            pos += 3;
            let payload = bytes.get(pos..pos + len).ok_or_else(invalid)?;
            pos += len;
            slots.push(if slot_type == SLOT_PASSWORD {
                parse_password_payload(payload)?
            } else {
                Slot::Unknown {
                    slot_type,
                    payload: payload.to_vec(),
                }
            });
        }
        if pos != bytes.len() {
            return Err(invalid());
        }
        Ok(Self { slots })
    }

    /// Reads and parses a key file. Refuses anything but a regular file of
    /// at most `MAX_KEY_FILE_LEN` bytes before it reads the content, so a
    /// FIFO cannot block and a huge file cannot fill the memory (a key
    /// file in the vault is under the control of the cloud).
    pub fn load(path: &Path) -> Result<Self> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: opening a FIFO for reading would wait for a writer.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > MAX_KEY_FILE_LEN {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        // The file may grow after the check; never read more than allowed.
        file.take(MAX_KEY_FILE_LEN + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_KEY_FILE_LEN {
            return Err(invalid());
        }
        Self::from_bytes(&bytes)
    }

    /// Writes a new file. Never overwrites: `AlreadyExists` if `path` exists.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        if path.symlink_metadata().is_ok() {
            return Err(Error::AlreadyExists);
        }
        let tmp = self.write_tmp(path)?;
        // hard_link fails if `path` appeared in the meantime.
        let linked = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => sync_parent(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::AlreadyExists),
            Err(e) if no_hard_links(&e) => self.write_exclusive(path),
            Err(e) => Err(e.into()),
        }
    }

    /// Fallback for file systems without hard links (FAT, some network
    /// file systems). Not atomic (a crash can leave a partial file), but it
    /// never overwrites: the final path is opened with `O_EXCL`.
    fn write_exclusive(&self, path: &Path) -> Result<()> {
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::AlreadyExists);
            }
            Err(e) => return Err(e.into()),
        };
        let written = file
            .write_all(&self.to_bytes())
            .and_then(|()| file.sync_all());
        if let Err(e) = written {
            let _ = std::fs::remove_file(path);
            return Err(e.into());
        }
        sync_parent(path)
    }

    /// Atomically replaces the file at `path`.
    pub fn save_replace(&self, path: &Path) -> Result<()> {
        let tmp = self.write_tmp(path)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_parent(path)
    }

    /// Writes `<name>.tmp` (mode 0600) and fsyncs it. Removes it on error.
    fn write_tmp(&self, path: &Path) -> Result<PathBuf> {
        let mut name = path.file_name().ok_or(Error::InvalidArgument)?.to_owned();
        name.push(".tmp");
        let tmp = path.with_file_name(name);
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&self.to_bytes())?;
            file.sync_all()
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(tmp)
    }
}

fn parse_password_payload(payload: &[u8]) -> Result<Slot> {
    if payload.len() != PAYLOAD_LEN_ONE && payload.len() != PAYLOAD_LEN_TWO {
        return Err(invalid());
    }
    let u32_at =
        |i: usize| u32::from_le_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&payload[12..28]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&payload[28..40]);
    let wrapped = payload[PAYLOAD_AD_LEN..].to_vec();
    Ok(Slot::Password {
        params: Argon2Params {
            m_kib: u32_at(0),
            t: u32_at(4),
            p: u32_at(8),
        },
        salt,
        nonce,
        wrapped,
    })
}

/// True if `hard_link` failed because the file system cannot do it.
fn no_hard_links(e: &std::io::Error) -> bool {
    use rustix::io::Errno;
    matches!(
        Errno::from_io_error(e),
        Some(Errno::PERM | Errno::NOTSUP | Errno::XDEV | Errno::NOSYS)
    )
}

fn sync_parent(path: &Path) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;
    use std::os::unix::fs::PermissionsExt;

    fn p() -> Argon2Params {
        Argon2Params::MIN
    }

    fn mk() -> MasterKey {
        MasterKey::from_bytes([42; 32])
    }

    fn ks() -> KeySet {
        KeySet::single(1, mk())
    }

    fn ks2() -> KeySet {
        ks().with_next(MasterKey::from_bytes([43; 32])).unwrap()
    }

    #[test]
    fn unlock_round_trip() {
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        assert_eq!(
            kf.unlock(b"pw").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
        let again = KeyFile::from_bytes(&kf.to_bytes()).unwrap();
        assert_eq!(
            again.unlock(b"pw").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
    }

    #[test]
    fn unlock_returns_key_set() {
        let kf = KeyFile::new(&ks2(), b"pw", p()).unwrap();
        let again = KeyFile::from_bytes(&kf.to_bytes()).unwrap();
        let keys = again.unlock(b"pw").unwrap();
        assert_eq!(keys.epochs(), vec![1, 2]);
        assert_eq!(keys.write_epoch(), 2);
        assert_eq!(keys.get(1).unwrap().expose(), &[42; 32]);
        assert_eq!(keys.get(2).unwrap().expose(), &[43; 32]);
    }

    #[test]
    fn bad_payload_len() {
        let mut b = KeyFile::new(&ks(), b"pw", p()).unwrap().to_bytes();
        b.push(0);
        b[13..15].copy_from_slice(&94u16.to_le_bytes());
        assert!(matches!(
            KeyFile::from_bytes(&b),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn wrong_password() {
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        assert!(matches!(kf.unlock(b"nope"), Err(Error::WrongPassword)));
    }

    #[test]
    fn serialized_size() {
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        assert_eq!(kf.to_bytes().len(), 12 + 3 + 93);
        let kf2 = KeyFile::new(&ks2(), b"pw", p()).unwrap();
        assert_eq!(kf2.to_bytes().len(), 12 + 3 + 129);
        assert_eq!(&kf.to_bytes()[..8], b"CD-KEY\0\0");
    }

    #[test]
    fn changed_argon2_params_fail() {
        let mut b = KeyFile::new(&ks(), b"pw", p()).unwrap().to_bytes();
        b[12 + 3] ^= 1;
        let kf = KeyFile::from_bytes(&b).unwrap();
        assert!(matches!(kf.unlock(b"pw"), Err(Error::WrongPassword)));
    }

    #[test]
    fn any_bit_flip_fails() {
        let good = KeyFile::new(&ks(), b"pw", p()).unwrap().to_bytes();
        for i in 12..good.len() {
            let mut b = good.clone();
            b[i] ^= 0x01;
            let ok = KeyFile::from_bytes(&b)
                .and_then(|kf| kf.unlock(b"pw"))
                .is_ok();
            assert!(!ok, "flip at offset {i} was not detected");
        }
    }

    #[test]
    fn header_errors() {
        let good = KeyFile::new(&ks(), b"pw", p()).unwrap().to_bytes();
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            KeyFile::from_bytes(&bad_magic),
            Err(Error::InvalidFormat { .. })
        ));
        let mut bad_version = good.clone();
        bad_version[8] = 2;
        assert!(matches!(
            KeyFile::from_bytes(&bad_version),
            Err(Error::UnsupportedVersion { found: 2 })
        ));
        assert!(matches!(
            KeyFile::from_bytes(&good[..good.len() - 1]),
            Err(Error::InvalidFormat { .. })
        ));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            KeyFile::from_bytes(&trailing),
            Err(Error::InvalidFormat { .. })
        ));
        let mut zero_slots = good.clone();
        zero_slots[10] = 0;
        assert!(matches!(
            KeyFile::from_bytes(&zero_slots),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(matches!(
            KeyFile::from_bytes(&good[..5]),
            Err(Error::InvalidFormat { .. })
        ));
    }

    fn with_unknown_slot(kf: &KeyFile) -> Vec<u8> {
        let mut b = kf.to_bytes();
        b.extend_from_slice(&[9, 3, 0, b'x', b'y', b'z']);
        b[10] = 2;
        b
    }

    /// A key file with `extra` unknown slots after its password slot.
    fn with_unknown_slots(kf: &KeyFile, extra: u16) -> Vec<u8> {
        let mut b = kf.to_bytes();
        for _ in 0..extra {
            b.extend_from_slice(&[9, 1, 0, b'x']);
        }
        b[10..12].copy_from_slice(&(1 + extra).to_le_bytes());
        b
    }

    /// A crafted key file with thousands of slots (each could ask for the
    /// highest Argon2 values) must be refused before any slot is tried.
    #[test]
    fn more_than_max_slots_are_refused() {
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        let at_max = with_unknown_slots(&kf, MAX_SLOTS - 1);
        assert!(KeyFile::from_bytes(&at_max).unwrap().unlock(b"pw").is_ok());
        assert!(matches!(
            KeyFile::from_bytes(&with_unknown_slots(&kf, MAX_SLOTS)),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(matches!(
            KeyFile::from_bytes(&with_unknown_slots(&kf, u16::MAX - 1)),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn load_refuses_a_file_over_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        // Valid by format: a password slot and one unknown slot with the
        // largest payload (65535 bytes), together over the limit.
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        let mut big = kf.to_bytes();
        big.extend_from_slice(&[9, 0xff, 0xff]);
        big.resize(big.len() + 0xffff, b'x');
        big[10] = 2;
        assert!(big.len() as u64 > MAX_KEY_FILE_LEN);
        assert!(KeyFile::from_bytes(&big).is_ok());
        std::fs::write(&path, &big).unwrap();
        assert!(matches!(
            KeyFile::load(&path),
            Err(Error::InvalidFormat { .. })
        ));
    }

    /// A FIFO in place of the key file must not block the command.
    #[test]
    fn load_refuses_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(matches!(
            KeyFile::load(&path),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn unknown_slot_is_kept_and_skipped() {
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        let mut loaded = KeyFile::from_bytes(&with_unknown_slot(&kf)).unwrap();
        assert_eq!(
            loaded.unlock(b"pw").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
        assert_eq!(loaded.to_bytes(), with_unknown_slot(&kf));
        loaded.set_password(&ks(), b"new", p()).unwrap();
        let out = loaded.to_bytes();
        assert_eq!(out.len(), 12 + 3 + 93 + 6);
        assert_eq!(&out[out.len() - 6..], &[9, 3, 0, b'x', b'y', b'z']);
        assert_eq!(out[10], 2);
        let reloaded = KeyFile::from_bytes(&out).unwrap();
        assert_eq!(
            reloaded.unlock(b"new").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
    }

    #[test]
    fn unlock_tries_every_password_slot() {
        let a = KeyFile::new(&ks(), b"first", p()).unwrap().to_bytes();
        let b = KeyFile::new(&ks(), b"second", p()).unwrap().to_bytes();
        let mut both = a.clone();
        both.extend_from_slice(&b[12..]);
        both[10] = 2;
        let kf = KeyFile::from_bytes(&both).unwrap();
        assert!(kf.unlock(b"first").is_ok());
        assert!(kf.unlock(b"second").is_ok());
        assert!(matches!(kf.unlock(b"third"), Err(Error::WrongPassword)));
    }

    #[test]
    fn set_password_replaces_old() {
        let mut kf = KeyFile::new(&ks(), b"old", p()).unwrap();
        kf.set_password(&ks(), b"new", p()).unwrap();
        assert!(matches!(kf.unlock(b"old"), Err(Error::WrongPassword)));
        assert_eq!(
            kf.unlock(b"new").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
    }

    #[test]
    fn params_below_minimum_rejected() {
        assert!(
            Argon2Params {
                m_kib: 1024,
                t: 2,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                m_kib: 19456,
                t: 1,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                m_kib: 19456,
                t: 2,
                p: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                m_kib: (1 << 20) + 1,
                t: 2,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                m_kib: 19456,
                t: 65,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                m_kib: 19456,
                t: 2,
                p: 65
            }
            .validate()
            .is_err()
        );
        assert!(Argon2Params::MIN.validate().is_ok());
        assert!(Argon2Params::default().validate().is_ok());
        assert!(Argon2Params::MIN.is_below_default());
        assert!(!Argon2Params::default().is_below_default());
        assert!(matches!(
            KeyFile::new(
                &ks(),
                b"pw",
                Argon2Params {
                    m_kib: 1024,
                    t: 2,
                    p: 1
                }
            ),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn save_new_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        kf.save_new(&path).unwrap();
        assert!(matches!(kf.save_new(&path), Err(Error::AlreadyExists)));
        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(
            loaded.unlock(b"pw").unwrap().get(1).unwrap().expose(),
            mk().expose()
        );
        assert!(!dir.path().join(".cd-key.tmp").exists());
    }

    #[test]
    fn save_replace_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        let mut kf = KeyFile::new(&ks(), b"old", p()).unwrap();
        kf.save_new(&path).unwrap();
        kf.set_password(&ks(), b"new", p()).unwrap();
        kf.save_replace(&path).unwrap();
        let loaded = KeyFile::load(&path).unwrap();
        assert!(loaded.unlock(b"old").is_err());
        assert!(loaded.unlock(b"new").is_ok());
        assert!(!dir.path().join(".cd-key.tmp").exists());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn exclusive_fallback_creates_and_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        let kf = KeyFile::new(&ks(), b"pw", p()).unwrap();
        kf.write_exclusive(&path).unwrap();
        assert!(matches!(
            kf.write_exclusive(&path),
            Err(Error::AlreadyExists)
        ));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(KeyFile::load(&path).unwrap().unlock(b"pw").is_ok());
    }

    #[test]
    fn hard_link_error_codes() {
        use rustix::io::Errno;
        for errno in [Errno::PERM, Errno::NOTSUP, Errno::XDEV, Errno::NOSYS] {
            assert!(no_hard_links(&std::io::Error::from_raw_os_error(
                errno.raw_os_error()
            )));
        }
        assert!(!no_hard_links(&std::io::Error::from_raw_os_error(
            Errno::ACCESS.raw_os_error()
        )));
    }

    #[test]
    fn saved_file_mode_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cd-key");
        KeyFile::new(&ks(), b"pw", p())
            .unwrap()
            .save_new(&path)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
