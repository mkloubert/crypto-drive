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

//! Name encryption (AES-256-SIV) and overflow names for long entries.

use std::sync::Mutex;

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};
use crate::keys::{DirId, EntryId, Epoch};
use crate::vault::VaultKeys;

/// Maximum length of a clear name in bytes.
pub const MAX_CLEAR_NAME_BYTES: usize = 1024;
/// Length of the SIV tag in front of an encrypted name.
const SIV_TAG_LEN: usize = 16;
/// Length of the entry id in front of the clear name (HS 3.1).
const ENTRY_ID_LEN: usize = 16;
/// Length of the Base64 of a 16-byte entry id.
const ENTRY_ID_B64_LEN: usize = 22;
/// Longest valid `.cd-name`: the Base64 (no padding) of the longest name
/// without entry id, plus the encoded entry id (HS 3.1).
pub const MAX_ENCODED_NAME_LEN: usize =
    ((MAX_CLEAR_NAME_BYTES + SIV_TAG_LEN) * 4).div_ceil(3) + ENTRY_ID_B64_LEN;
/// Prefix of overflow entries for names that are too long.
pub const LONG_PREFIX: &str = ".cd-cdl";

/// Checks a clear name (before NFC normalization).
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(Error::InvalidName);
    }
    if name.len() > MAX_CLEAR_NAME_BYTES {
        return Err(Error::NameTooLong);
    }
    Ok(())
}

/// Encrypts and decrypts names. The key is wiped on drop by `aes-siv`.
pub struct NameCipher {
    siv: Mutex<Aes256Siv>,
}

impl NameCipher {
    pub fn new(names_key: &[u8; 64]) -> Self {
        let mut key = aes_siv::Key::<Aes256Siv>::from(*names_key);
        let siv = Aes256Siv::new(&key);
        // The Array type has no zeroize support, so wipe the copy by hand.
        key.as_mut_slice().fill(0);
        Self {
            siv: Mutex::new(siv),
        }
    }

    /// Validates and normalizes the name to NFC, then encrypts
    /// `entry_id ‖ name` and encodes it as Base64url (HS 3.1).
    pub fn encrypt(&self, dir_id: &DirId, entry_id: &EntryId, name: &str) -> Result<String> {
        validate_name(name)?;
        let nfc: String = name.nfc().collect();
        if nfc.len() > MAX_CLEAR_NAME_BYTES {
            return Err(Error::NameTooLong);
        }
        let mut plain = Vec::with_capacity(ENTRY_ID_LEN + nfc.len());
        plain.extend_from_slice(entry_id);
        plain.extend_from_slice(nfc.as_bytes());
        let enc = self
            .siv
            .lock()
            .expect("name cipher lock poisoned")
            .encrypt([dir_id.as_slice()], &plain)
            .map_err(|_| Error::InvalidArgument)?;
        Ok(URL_SAFE_NO_PAD.encode(enc))
    }

    /// Decodes and decrypts a name. Returns the entry id and the NFC clear
    /// name. A plaintext without at least one name byte is `AuthFailed`.
    pub fn decrypt(&self, dir_id: &DirId, encoded: &str) -> Result<(EntryId, String)> {
        let enc = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::InvalidFormat {
                what: encoded.to_string(),
            })?;
        let auth_failed = || Error::AuthFailed {
            what: encoded.to_string(),
        };
        let clear = self
            .siv
            .lock()
            .expect("name cipher lock poisoned")
            .decrypt([dir_id.as_slice()], &enc)
            .map_err(|_| auth_failed())?;
        if clear.len() <= ENTRY_ID_LEN {
            return Err(auth_failed());
        }
        let (id, name) = clear.split_at(ENTRY_ID_LEN);
        let entry_id: EntryId = id.try_into().map_err(|_| auth_failed())?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| auth_failed())?;
        Ok((entry_id, name))
    }
}

/// The name ciphers of every epoch in the key set, highest epoch first.
pub struct NameKeys {
    /// Never empty: a key set holds at least one epoch.
    ciphers: Vec<(Epoch, NameCipher)>,
}

impl NameKeys {
    pub fn new(keys: &VaultKeys) -> NameKeys {
        let ciphers = keys
            .epochs_desc()
            .into_iter()
            .filter_map(|e| keys.get(e).map(|k| (e, NameCipher::new(k.names()))))
            .collect();
        NameKeys { ciphers }
    }

    /// Encrypts a new name with the key of the write epoch.
    pub fn encrypt_write(&self, dir_id: &DirId, entry_id: &EntryId, name: &str) -> Result<String> {
        let (_, cipher) = self.ciphers.first().ok_or(Error::WrongKey)?;
        cipher.encrypt(dir_id, entry_id, name)
    }

    /// Tries the key of every epoch, highest first (a real name holds no
    /// epoch). Returns the epoch that authenticated, the entry id and the
    /// clear name.
    pub fn decrypt_any(&self, dir_id: &DirId, encoded: &str) -> Option<(Epoch, EntryId, String)> {
        self.ciphers.iter().find_map(|(epoch, cipher)| {
            let (entry_id, name) = cipher.decrypt(dir_id, encoded).ok()?;
            Some((*epoch, entry_id, name))
        })
    }
}

/// How an encrypted name is stored in the backing directory.
#[derive(Debug, PartialEq, Eq)]
pub enum BackingName {
    /// The encoded name fits and is used directly.
    Short(String),
    /// The name is too long. `entry` is the overflow entry, `full` is the encoded name
    /// that goes into `.cd-name`.
    Long { entry: String, full: String },
}

/// Length of the encoded name of a clear (NFC) name of `nfc_len` bytes:
/// Base64 without padding of tag, entry id and name.
pub fn encoded_name_len(nfc_len: usize) -> usize {
    ((SIV_TAG_LEN + ENTRY_ID_LEN + nfc_len) * 4).div_ceil(3)
}

/// True if a clear (NFC) name of `nfc_len` bytes gets an overflow entry
/// (the same rule as `to_backing_name`).
pub fn needs_long_entry(nfc_len: usize, max_name_length: u16) -> bool {
    encoded_name_len(nfc_len) > usize::from(max_name_length)
}

/// Picks the backing name. A name of exactly `max_name_length` characters still fits.
pub fn to_backing_name(encoded: String, max_name_length: u16) -> BackingName {
    if encoded.len() <= usize::from(max_name_length) {
        BackingName::Short(encoded)
    } else {
        BackingName::Long {
            entry: long_entry_name(&encoded),
            full: encoded,
        }
    }
}

/// Returns `.cd-cdl` followed by the Base64url of the SHA-256 of the encoded name.
pub fn long_entry_name(encoded: &str) -> String {
    let hash = Sha256::digest(encoded.as_bytes());
    format!("{LONG_PREFIX}{}", URL_SAFE_NO_PAD.encode(hash))
}

/// True for characters of the Base64url alphabet (without padding).
pub fn is_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeySet, MasterKey};

    const E: EntryId = [5u8; 16];

    fn cipher() -> NameCipher {
        NameCipher::new(&[7u8; 64])
    }

    #[test]
    fn round_trip_unicode() {
        let c = cipher();
        let d = [1u8; 16];
        let name = "Rechnung März 🧾.pdf";
        let enc = c.encrypt(&d, &E, name).unwrap();
        assert_eq!(c.decrypt(&d, &enc).unwrap(), (E, name.to_string()));
    }

    #[test]
    fn round_trip_returns_the_entry_id() {
        let c = cipher();
        let d = [1u8; 16];
        for id in [[0u8; 16], [0xffu8; 16], [9u8; 16]] {
            let enc = c.encrypt(&d, &id, "a").unwrap();
            assert_eq!(c.decrypt(&d, &enc).unwrap(), (id, "a".to_string()));
        }
    }

    #[test]
    fn other_entry_id_gives_other_real_name() {
        let c = cipher();
        let d = [1u8; 16];
        assert_ne!(
            c.encrypt(&d, &[1u8; 16], "a.txt").unwrap(),
            c.encrypt(&d, &[2u8; 16], "a.txt").unwrap()
        );
    }

    #[test]
    fn short_plaintext_is_auth_failed() {
        let key = [7u8; 64];
        let c = NameCipher::new(&key);
        let d = [1u8; 16];
        for len in [0, 1, 16] {
            let mut siv = Aes256Siv::new(&aes_siv::Key::<Aes256Siv>::from(key));
            let enc = siv.encrypt([d.as_slice()], &vec![b'x'; len]).unwrap();
            assert!(matches!(
                c.decrypt(&d, &URL_SAFE_NO_PAD.encode(enc)),
                Err(Error::AuthFailed { .. })
            ));
        }
    }

    #[test]
    fn decrypt_any_finds_the_epoch() {
        let vault_id = [3u8; 16];
        let set = KeySet::single(1, MasterKey::from_bytes([1u8; 32]))
            .with_next(MasterKey::from_bytes([2u8; 32]))
            .unwrap();
        let keys = NameKeys::new(&VaultKeys::new(&vault_id, &set));
        let d = [1u8; 16];
        let new = keys.encrypt_write(&d, &E, "new").unwrap();
        assert_eq!(keys.decrypt_any(&d, &new), Some((2, E, "new".to_string())));
        let old_keys = VaultKeys::new(&vault_id, &set.only(1).unwrap());
        let old = NameKeys::new(&old_keys)
            .encrypt_write(&d, &E, "old")
            .unwrap();
        assert_eq!(keys.decrypt_any(&d, &old), Some((1, E, "old".to_string())));
        assert_eq!(keys.decrypt_any(&[2u8; 16], &old), None);
        assert_eq!(keys.decrypt_any(&d, "not base64!"), None);
    }

    #[test]
    fn nfd_and_nfc_encrypt_the_same() {
        let c = cipher();
        let d = [1u8; 16];
        assert_eq!(
            c.encrypt(&d, &E, "e\u{301}").unwrap(),
            c.encrypt(&d, &E, "\u{e9}").unwrap()
        );
        let enc = c.encrypt(&d, &E, "e\u{301}").unwrap();
        assert_eq!(c.decrypt(&d, &enc).unwrap().1, "\u{e9}");
    }

    #[test]
    fn depends_on_dir_id() {
        let c = cipher();
        assert_ne!(
            c.encrypt(&[1u8; 16], &E, "a.txt").unwrap(),
            c.encrypt(&[2u8; 16], &E, "a.txt").unwrap()
        );
    }

    #[test]
    fn wrong_dir_id_fails_auth() {
        let c = cipher();
        let enc = c.encrypt(&[1u8; 16], &E, "a.txt").unwrap();
        assert!(matches!(
            c.decrypt(&[2u8; 16], &enc),
            Err(Error::AuthFailed { .. })
        ));
    }

    #[test]
    fn bad_base64_is_invalid_format() {
        assert!(matches!(
            cipher().decrypt(&[1u8; 16], "not base64!"),
            Err(Error::InvalidFormat { .. })
        ));
    }

    #[test]
    fn output_has_no_dot_and_only_b64() {
        let c = cipher();
        for n in ["a", ".cd-vault", "x.y.z", "Rechnung März 🧾.pdf"] {
            let enc = c.encrypt(&[1u8; 16], &E, n).unwrap();
            assert!(!enc.contains('.'));
            assert!(enc.chars().all(is_b64_char));
        }
    }

    #[test]
    fn invalid_names() {
        for n in ["", ".", "..", "a/b", "a\0b"] {
            assert!(matches!(validate_name(n), Err(Error::InvalidName)));
            assert!(matches!(
                cipher().encrypt(&[1u8; 16], &E, n),
                Err(Error::InvalidName)
            ));
        }
    }

    #[test]
    fn too_long() {
        assert!(matches!(
            validate_name(&"a".repeat(1025)),
            Err(Error::NameTooLong)
        ));
        assert!(validate_name(&"a".repeat(1024)).is_ok());
    }

    #[test]
    fn longest_name_fits_the_name_file_limit() {
        let enc = cipher().encrypt(&[1u8; 16], &E, &"a".repeat(1024)).unwrap();
        assert!(enc.len() <= MAX_ENCODED_NAME_LEN);
    }

    #[test]
    fn too_long_after_nfc_is_rejected() {
        // U+0344 is 2 bytes. NFC turns it into U+0308 U+0301, which is 4 bytes.
        let name = "\u{344}".repeat(400); // 800 bytes before NFC, 1600 bytes after
        assert!(validate_name(&name).is_ok());
        assert!(matches!(
            cipher().encrypt(&[1u8; 16], &E, &name),
            Err(Error::NameTooLong)
        ));
    }

    #[test]
    fn encoded_name_len_matches_encrypt() {
        let c = cipher();
        for len in [1, 2, 3, 10, 31, 32, 33, 100, 1024] {
            let name = "a".repeat(len);
            let enc = c.encrypt(&[1u8; 16], &E, &name).unwrap();
            assert_eq!(encoded_name_len(len), enc.len(), "{len}");
            let long = matches!(to_backing_name(enc, 64), BackingName::Long { .. });
            assert_eq!(needs_long_entry(len, 64), long, "{len}");
        }
    }

    #[test]
    fn overflow_limit_is_inclusive() {
        let e220 = "A".repeat(220);
        assert!(matches!(to_backing_name(e220, 220), BackingName::Short(_)));
        let e221 = "A".repeat(221);
        match to_backing_name(e221.clone(), 220) {
            BackingName::Long { entry, full } => {
                assert_eq!(entry.len(), 50);
                assert!(entry.starts_with(".cd-cdl"));
                assert_eq!(full, e221);
            }
            _ => panic!("expected a long entry"),
        }
    }

    #[test]
    fn cd_prefixed_clear_name_is_fine() {
        let c = cipher();
        let d = [3u8; 16];
        let enc = c.encrypt(&d, &E, ".cd-vault").unwrap();
        assert!(!enc.contains('.'));
        assert_eq!(c.decrypt(&d, &enc).unwrap().1, ".cd-vault");
    }
}
