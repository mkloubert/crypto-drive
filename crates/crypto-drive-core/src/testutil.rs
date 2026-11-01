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

//! Helpers for tests of this and later crates (feature `test-util`).

use crate::keyfile::Argon2Params;
use crate::keys::{DirId, MasterKey};
use crate::names::{LONG_PREFIX, NameKeys};
use crate::vault::{
    DEFAULT_MAX_NAME_LENGTH, InitOptions, NAME_FILE, UnlockedVault, init_vault, unlock_vault,
};
use std::path::Path;

pub const TEST_PASSWORD: &[u8] = b"test-password";

/// Creates a vault with the default maximum name length.
pub fn test_vault() -> (tempfile::TempDir, UnlockedVault, MasterKey) {
    test_vault_with(DEFAULT_MAX_NAME_LENGTH)
}

/// Creates a vault with size padding and the default maximum name length.
pub fn test_vault_padded() -> (tempfile::TempDir, UnlockedVault, MasterKey) {
    test_vault_opts(DEFAULT_MAX_NAME_LENGTH, true)
}

/// Creates a vault without size padding.
pub fn test_vault_with(max_name_length: u16) -> (tempfile::TempDir, UnlockedVault, MasterKey) {
    test_vault_opts(max_name_length, false)
}

/// Creates a vault in the sub directory `vault` of a new temporary
/// directory. The key file is `vault/.cd-key`. Uses the lowest Argon2 values.
pub fn test_vault_opts(
    max_name_length: u16,
    pad_sizes: bool,
) -> (tempfile::TempDir, UnlockedVault, MasterKey) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("vault");
    let opts = InitOptions {
        max_name_length,
        argon2: Argon2Params::MIN,
        key_file: None,
        pad_sizes,
    };
    init_vault(&dir, TEST_PASSWORD, &opts).expect("init vault");
    let (vault, keys) = unlock_vault(&dir, None, TEST_PASSWORD).expect("unlock vault");
    let mk = keys
        .get(vault.marker.epoch)
        .map(|k| MasterKey::from_bytes(*k.expose()))
        .expect("key for the marker epoch");
    (tmp, vault, mk)
}

/// The real entry name of the clear name `name` in the real directory `dir`
/// whose id is `dir_id`: a short name or a `.cd-cdl` entry. Real names hold a
/// random entry id, so they are found by decrypting. Panics if none matches.
pub fn real_name_of(names: &NameKeys, dir_id: &DirId, dir: &Path, name: &str) -> String {
    let mut found = Vec::new();
    for e in std::fs::read_dir(dir).expect("read real directory") {
        let real = e
            .expect("real directory entry")
            .file_name()
            .into_string()
            .expect("real names are UTF-8");
        let encoded = if real.starts_with(LONG_PREFIX) {
            match std::fs::read_to_string(dir.join(&real).join(NAME_FILE)) {
                Ok(full) => full,
                Err(_) => continue,
            }
        } else {
            real.clone()
        };
        if names
            .decrypt_any(dir_id, &encoded)
            .is_some_and(|(_, _, clear)| clear == name)
        {
            found.push(real);
        }
    }
    assert_eq!(found.len(), 1, "real names for one clear name: {found:?}");
    found.remove(0)
}
