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

//! Fresh test vaults for the structured targets, without Argon2 per input.

use crypto_drive_core::keys::MasterKey;
use crypto_drive_core::testutil::test_vault_opts;
use crypto_drive_core::vault::{KEY_FILE, UnlockedVault, VAULT_FILE, open_with_master_key};
use std::sync::LazyLock;

/// Small, so that names of 34 characters and more get overflow entries.
pub const MAX_NAME_LENGTH: u16 = 64;

/// A vault made once with `test_vault_opts`: its directory and master key.
struct Template {
    _tmp: tempfile::TempDir,
    dir: std::path::PathBuf,
    mk: [u8; 32],
}

fn template(pad_sizes: bool) -> Template {
    let (tmp, vault, mk) = test_vault_opts(MAX_NAME_LENGTH, pad_sizes);
    Template {
        dir: vault.root_path.clone(),
        _tmp: tmp,
        mk: *mk.expose(),
    }
}

static PLAIN: LazyLock<Template> = LazyLock::new(|| template(false));
static PADDED: LazyLock<Template> = LazyLock::new(|| template(true));

/// Repeats `f` while it fails with `Interrupted`. The libFuzzer timer
/// signal can interrupt a system call of the harness (seen with
/// `std::fs::copy`, which uses `copy_file_range`).
fn retry<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// A fresh, empty vault: a copy of the template's `.cd-vault` and `.cd-key`
/// in a new temporary directory. Making a vault per input with
/// `test_vault_opts` runs Argon2 twice and is far too slow for fuzzing.
pub fn fresh_vault(pad_sizes: bool) -> (tempfile::TempDir, UnlockedVault, MasterKey) {
    let t = if pad_sizes { &*PADDED } else { &*PLAIN };
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("vault");
    std::fs::create_dir(&dir).expect("vault dir");
    for name in [VAULT_FILE, KEY_FILE] {
        let bytes = retry(|| std::fs::read(t.dir.join(name))).expect("read vault file");
        retry(|| std::fs::write(dir.join(name), &bytes)).expect("write vault file");
    }
    let mk = MasterKey::from_bytes(t.mk);
    let vault = open_with_master_key(&dir, &mk).expect("open vault copy");
    (tmp, vault, mk)
}
