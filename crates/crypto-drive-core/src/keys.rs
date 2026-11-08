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

//! Key hierarchy: master key, sub keys and per-file keys (spec 4.2).

use crate::error::{Error, Result};
use crate::secret::{SecretBytes, random_bytes};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

pub type VaultId = [u8; 16];
pub type DirId = [u8; 16];
pub type Epoch = u32;
pub type EntryId = [u8; 16];

const LABEL_NAMES: &[u8] = b"crypto-drive v1 names";
const LABEL_CONTENT: &[u8] = b"crypto-drive v1 content";
const LABEL_CHECK: &[u8] = b"crypto-drive v1 check";
const LABEL_FILE: &[u8] = b"crypto-drive v1 file";
const LABEL_SIZE: &[u8] = b"crypto-drive v1 size";

/// The random master key of a vault.
pub struct MasterKey(SecretBytes<32>);

impl MasterKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretBytes::random()?))
    }

    /// The caller must zeroize its own copy of `b`.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(SecretBytes::new(b))
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    /// Derives the sub keys for one vault and key epoch.
    /// The HKDF salt is `vault_id || epoch (u32 LE)`.
    pub fn derive(&self, vault_id: &VaultId, epoch: Epoch) -> SubKeys {
        let mut salt = [0u8; 20];
        salt[..16].copy_from_slice(vault_id);
        salt[16..].copy_from_slice(&epoch.to_le_bytes());
        let hk = Hkdf::<Sha512>::new(Some(&salt), self.expose());
        SubKeys {
            names: expand(&hk, LABEL_NAMES),
            content: expand(&hk, LABEL_CONTENT),
            check: expand(&hk, LABEL_CHECK),
        }
    }
}

pub struct SubKeys {
    names: SecretBytes<64>,
    content: SecretBytes<32>,
    check: SecretBytes<32>,
}

impl SubKeys {
    /// Key for AES-256-SIV (names).
    pub fn names(&self) -> &[u8; 64] {
        self.names.expose()
    }

    pub fn content(&self) -> &[u8; 32] {
        self.content.expose()
    }

    /// Key for HMAC-SHA-256 (key check).
    pub fn check(&self) -> &[u8; 32] {
        self.check.expose()
    }
}

/// One or two master keys, each with its epoch. Sorted ascending by epoch.
pub struct KeySet {
    entries: Vec<(Epoch, MasterKey)>,
}

impl KeySet {
    pub fn single(epoch: Epoch, mk: MasterKey) -> KeySet {
        KeySet {
            entries: vec![(epoch, mk)],
        }
    }

    /// Adds `mk` as epoch `write_epoch() + 1`.
    pub fn with_next(&self, mk: MasterKey) -> Result<KeySet> {
        if self.entries.len() >= 2 {
            return Err(Error::InvalidArgument);
        }
        let next = self
            .write_epoch()
            .checked_add(1)
            .ok_or(Error::InvalidArgument)?;
        let mut entries: Vec<(Epoch, MasterKey)> = self
            .entries
            .iter()
            .map(|(e, k)| (*e, MasterKey::from_bytes(*k.expose())))
            .collect();
        entries.push((next, mk));
        Ok(KeySet { entries })
    }

    /// Keeps only the key of `epoch`.
    pub fn only(&self, epoch: Epoch) -> Result<KeySet> {
        let mk = self.get(epoch).ok_or(Error::InvalidArgument)?;
        Ok(KeySet::single(epoch, MasterKey::from_bytes(*mk.expose())))
    }

    /// The highest epoch.
    pub fn write_epoch(&self) -> Epoch {
        self.entries[self.entries.len() - 1].0
    }

    pub fn epochs(&self) -> Vec<Epoch> {
        self.entries.iter().map(|(e, _)| *e).collect()
    }

    pub fn get(&self, epoch: Epoch) -> Option<&MasterKey> {
        self.entries
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, k)| k)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Layout: `count (u8) || (epoch u32 LE || MK 32)*`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(1 + self.entries.len() * 36));
        out.push(self.entries.len() as u8);
        for (epoch, mk) in &self.entries {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(mk.expose());
        }
        out
    }

    /// Every broken rule gives `Error::WrongPassword`.
    pub fn decode(bytes: &[u8]) -> Result<KeySet> {
        let count = match bytes.first() {
            Some(&c @ (1 | 2)) => c as usize,
            _ => return Err(Error::WrongPassword),
        };
        if bytes.len() != 1 + count * 36 {
            return Err(Error::WrongPassword);
        }
        let mut entries: Vec<(Epoch, MasterKey)> = Vec::with_capacity(count);
        let (chunks, _) = bytes[1..].as_chunks::<36>();
        for chunk in chunks {
            let epoch = Epoch::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&chunk[4..]);
            let key = MasterKey::from_bytes(mk);
            zeroize::Zeroize::zeroize(&mut mk);
            if epoch == 0 || entries.last().is_some_and(|(prev, _)| *prev >= epoch) {
                return Err(Error::WrongPassword);
            }
            entries.push((epoch, key));
        }
        Ok(KeySet { entries })
    }
}

/// A random 16 byte entry id.
pub fn random_entry_id() -> Result<EntryId> {
    random_bytes::<16>()
}

/// Derives the key of one file from the content key, the file nonce and the
/// file id.
pub fn derive_file_key(
    content_key: &[u8; 32],
    file_nonce: &[u8; 32],
    file_id: &EntryId,
) -> SecretBytes<32> {
    derive_with_id(content_key, file_nonce, LABEL_FILE, file_id)
}

/// Derives the key that seals the size block of one file.
pub fn derive_size_key(
    content_key: &[u8; 32],
    file_nonce: &[u8; 32],
    file_id: &EntryId,
) -> SecretBytes<32> {
    derive_with_id(content_key, file_nonce, LABEL_SIZE, file_id)
}

/// HKDF with salt `file_nonce` and info `label ‖ file_id`.
fn derive_with_id(
    content_key: &[u8; 32],
    file_nonce: &[u8; 32],
    label: &[u8],
    file_id: &EntryId,
) -> SecretBytes<32> {
    let mut info = Zeroizing::new(Vec::with_capacity(label.len() + file_id.len()));
    info.extend_from_slice(label);
    info.extend_from_slice(file_id);
    let hk = Hkdf::<Sha512>::new(Some(file_nonce), content_key);
    expand(&hk, &info)
}

fn expand<const N: usize>(hk: &Hkdf<Sha512>, label: &[u8]) -> SecretBytes<N> {
    let mut okm = [0u8; N];
    // Cannot fail: N is at most 64 and far below the HKDF limit of 255 * 64.
    let ok = hk.expand(label, &mut okm).is_ok();
    debug_assert!(ok);
    let secret = SecretBytes::new(okm);
    zeroize::Zeroize::zeroize(&mut okm);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn hmac_states_are_wiped_on_drop() {
        // `Hkdf<Sha512>` keeps an `Hmac<Sha512>` keyed with the epoch PRK
        // (or the per-file PRK); `vault` uses `Hmac<Sha256>` with the check
        // key (review S3). `Hmac` has no `ZeroizeOnDrop` marker itself, but
        // it holds only two hash cores and a block buffer, and with the
        // `zeroize` feature of `sha2` / `hmac` (digest, block-buffer) each of
        // them wipes itself on drop. The buffered hashes prove the buffer.
        use hmac::digest::block_api::CoreProxy;
        wiped_on_drop::<<Sha512 as CoreProxy>::Core>();
        wiped_on_drop::<<sha2::Sha256 as CoreProxy>::Core>();
        wiped_on_drop::<Sha512>();
        wiped_on_drop::<sha2::Sha256>();
    }

    #[test]
    fn derive_is_deterministic() {
        let mk = MasterKey::from_bytes([7; 32]);
        assert_eq!(
            mk.derive(&[1; 16], 1).names(),
            mk.derive(&[1; 16], 1).names()
        );
    }

    #[test]
    fn subkeys_differ_per_label_and_vault() {
        let mk = MasterKey::from_bytes([7; 32]);
        let a = mk.derive(&[1; 16], 1);
        let b = mk.derive(&[2; 16], 1);
        assert_ne!(a.content(), a.check());
        assert_ne!(&a.names()[..32], a.content());
        assert_ne!(a.content(), b.content());
    }

    #[test]
    fn file_keys_differ_per_nonce() {
        assert_ne!(
            derive_file_key(&[3; 32], &[0; 32], &[9; 16]).expose(),
            derive_file_key(&[3; 32], &[1; 32], &[9; 16]).expose()
        );
    }

    #[test]
    fn file_keys_depend_on_id_and_label() {
        let a = derive_file_key(&[3; 32], &[0; 32], &[1; 16]);
        let b = derive_file_key(&[3; 32], &[0; 32], &[2; 16]);
        let s = derive_size_key(&[3; 32], &[0; 32], &[1; 16]);
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), s.expose());
    }

    #[test]
    fn generated_master_keys_differ() {
        assert_ne!(
            MasterKey::generate().unwrap().expose(),
            MasterKey::generate().unwrap().expose()
        );
    }

    #[test]
    fn derive_depends_on_epoch() {
        let mk = MasterKey::from_bytes([7; 32]);
        let a = mk.derive(&[1; 16], 1);
        let b = mk.derive(&[1; 16], 2);
        assert_ne!(a.names(), b.names());
        assert_ne!(a.content(), b.content());
        assert_ne!(a.check(), b.check());
    }

    fn mk(b: u8) -> MasterKey {
        MasterKey::from_bytes([b; 32])
    }

    #[test]
    fn key_set_round_trip() {
        let one = KeySet::single(1, mk(1));
        let enc = one.encode();
        assert_eq!(enc.len(), 37);
        let back = KeySet::decode(&enc).unwrap();
        assert_eq!(back.epochs(), vec![1]);
        assert_eq!(back.get(1).unwrap().expose(), &[1; 32]);

        let two = one.with_next(mk(2)).unwrap();
        assert_eq!(two.epochs(), vec![1, 2]);
        assert_eq!(two.write_epoch(), 2);
        assert_eq!(two.len(), 2);
        let enc = two.encode();
        assert_eq!(enc.len(), 73);
        let back = KeySet::decode(&enc).unwrap();
        assert_eq!(back.epochs(), vec![1, 2]);
        assert_eq!(back.get(2).unwrap().expose(), &[2; 32]);
    }

    #[test]
    fn key_set_rules() {
        let wrong = |b: &[u8]| matches!(KeySet::decode(b), Err(Error::WrongPassword));
        assert!(wrong(&[]));
        assert!(wrong(&[0]));
        let mut three = vec![3u8];
        three.extend_from_slice(&[0; 108]);
        assert!(wrong(&three));

        let entry = |epoch: u32| {
            let mut v = epoch.to_le_bytes().to_vec();
            v.extend_from_slice(&[9; 32]);
            v
        };
        let build = |epochs: &[u32]| {
            let mut v = vec![epochs.len() as u8];
            for e in epochs {
                v.extend(entry(*e));
            }
            v
        };
        assert!(!wrong(&build(&[1, 2])));
        assert!(wrong(&build(&[2, 2])));
        assert!(wrong(&build(&[2, 1])));
        assert!(wrong(&build(&[0])));
        let mut trailing = build(&[1]);
        trailing.push(0);
        assert!(wrong(&trailing));
        let mut short = build(&[1, 2]);
        short.pop();
        assert!(wrong(&short));

        let two = KeySet::single(1, mk(1)).with_next(mk(2)).unwrap();
        assert!(matches!(two.with_next(mk(3)), Err(Error::InvalidArgument)));
    }

    #[test]
    fn only_keeps_one() {
        let two = KeySet::single(1, mk(1)).with_next(mk(2)).unwrap();
        let kept = two.only(2).unwrap();
        assert_eq!(kept.epochs(), vec![2]);
        assert_eq!(kept.get(2).unwrap().expose(), &[2; 32]);
        assert!(matches!(two.only(5), Err(Error::InvalidArgument)));
    }

    #[test]
    fn entry_ids_differ() {
        assert_ne!(random_entry_id().unwrap(), random_entry_id().unwrap());
    }
}
