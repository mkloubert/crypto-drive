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

//! Tamper tests (spec 9). Every change to the real files must give an error
//! on unlock or read, never other bytes.

use crypto_drive_core::Error;
use crypto_drive_core::content::{
    CHUNK_OVERHEAD, CHUNK_SIZE, HEADER_LEN, PADDED_HEADER_LEN, chunk_offset, stage,
};
use crypto_drive_core::fs::{CryptoFs, VPath};
use crypto_drive_core::keyfile::{Argon2Params, KeyFile};
use crypto_drive_core::keys::KeySet;
use crypto_drive_core::keys::{DirId, MasterKey};
use crypto_drive_core::names::NameKeys;
use crypto_drive_core::testutil::{TEST_PASSWORD, real_name_of, test_vault, test_vault_padded};
use crypto_drive_core::vault::{
    DIR_FILE, KEY_FILE, VAULT_FILE, open_with_master_key, unlock_vault,
};
use std::path::{Path, PathBuf};

/// Three chunks: two full ones and a short last one.
const BIG_LEN: usize = 2 * CHUNK_SIZE as usize + 1000;

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

fn big_data() -> Vec<u8> {
    (0..BIG_LEN).map(|i| (i % 251) as u8).collect()
}

fn write_file(fs: &CryptoFs, path: &str, data: &[u8]) {
    let (_, h) = fs.create(&p(path), 0o644).unwrap();
    fs.write(h, 0, data).unwrap();
    fs.release(h).unwrap();
}

fn read_file(fs: &CryptoFs, path: &str) -> Result<Vec<u8>, Error> {
    let h = fs.open(&p(path), false, false)?;
    let data = fs.read(h, 0, 1 << 24);
    fs.release(h)?;
    data
}

/// A vault with `big.bin`, `small.txt` and `dir/inner.txt`.
fn fx() -> Fx {
    fx_with(test_vault())
}

/// The same files in a vault with size padding.
fn fx_padded() -> Fx {
    fx_with(test_vault_padded())
}

fn fx_with(
    (tmp, v, mk): (
        tempfile::TempDir,
        crypto_drive_core::vault::UnlockedVault,
        MasterKey,
    ),
) -> Fx {
    let names = NameKeys::new(&v.keys);
    let root = v.root_path.clone();
    let vault_id = v.marker.vault_id;
    let fs = CryptoFs::new(v).unwrap();
    write_file(&fs, "big.bin", &big_data());
    write_file(&fs, "small.txt", b"small file");
    write_file(&fs, "other.txt", b"other file");
    fs.mkdir(&p("dir"), 0o755).unwrap();
    write_file(&fs, "dir/inner.txt", b"inner");
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
    /// A new `CryptoFs`, so no cache hides a change.
    fn fs(&self) -> CryptoFs {
        CryptoFs::new(open_with_master_key(&self.root, &self.mk).unwrap()).unwrap()
    }

    /// The real path of an existing entry in the root.
    fn real(&self, name: &str) -> PathBuf {
        self.root
            .join(real_name_of(&self.names, &self.vault_id, &self.root, name))
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        read_file(&self.fs(), path)
    }
}

fn flip(path: &Path, offset: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[offset as usize] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
}

fn cut(path: &Path, len: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(len).unwrap();
}

fn assert_auth_failed(r: Result<Vec<u8>, Error>) {
    assert!(matches!(r, Err(Error::AuthFailed { .. })), "{r:?}");
}

#[test]
fn untouched_vault_reads_back() {
    let f = fx();
    assert_eq!(f.read("big.bin").unwrap(), big_data());
    assert_eq!(f.read("small.txt").unwrap(), b"small file");
    assert_eq!(f.read("dir/inner.txt").unwrap(), b"inner");
}

#[test]
fn bit_flip_in_header_version() {
    let f = fx();
    flip(&f.real("small.txt"), 0);
    let r = f.read("small.txt");
    assert!(matches!(r, Err(Error::InvalidFormat { .. })), "{r:?}");
}

#[test]
fn bit_flip_in_header_nonce() {
    let f = fx();
    flip(&f.real("small.txt"), 10);
    assert_auth_failed(f.read("small.txt"));
}

#[test]
fn bit_flip_in_each_chunk() {
    for index in 0..3u64 {
        let f = fx();
        // One byte in the nonce, in the ciphertext and in the last byte of
        // the tag of the short last chunk (1000 + 28 bytes).
        for delta in [3, 40, 1027] {
            let path = f.real("big.bin");
            let offset = chunk_offset(index, false) + delta;
            flip(&path, offset);
            assert_auth_failed(f.read("big.bin"));
            // Reading only the changed chunk fails too.
            let fs = f.fs();
            let h = fs.open(&p("big.bin"), false, false).unwrap();
            let r = fs.read(h, index * CHUNK_SIZE, 10);
            assert!(matches!(r, Err(Error::AuthFailed { .. })), "{r:?}");
            fs.release(h).unwrap();
            flip(&path, offset);
        }
        assert_eq!(f.read("big.bin").unwrap(), big_data());
    }
}

#[test]
fn bit_flip_in_real_name() {
    let f = fx();
    let real = f.real("small.txt");
    let name = real.file_name().unwrap().to_str().unwrap().to_owned();
    // Change one character to another Base64 character.
    let mut chars: Vec<char> = name.chars().collect();
    chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
    let changed: String = chars.into_iter().collect();
    std::fs::rename(&real, f.root.join(&changed)).unwrap();
    let fs = f.fs();
    assert!(matches!(read_file(&fs, "small.txt"), Err(Error::NotFound)));
    let listed: Vec<String> = fs
        .readdir(&VPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(listed, vec!["big.bin", "dir", "other.txt"]);
}

#[test]
fn bit_flip_in_dir_id() {
    let f = fx();
    flip(&f.real("dir").join(DIR_FILE), 7);
    let fs = f.fs();
    // The directory id no longer matches the entry id in its name.
    assert!(matches!(
        read_file(&fs, "dir/inner.txt"),
        Err(Error::AuthFailed { .. })
    ));
    assert!(matches!(
        fs.readdir(&p("dir")),
        Err(Error::AuthFailed { .. })
    ));
}

#[test]
fn bit_flip_in_vault_marker() {
    for offset in [0, 8, 10, 12, 20, 27, 28, 59] {
        let f = fx();
        flip(&f.root.join(VAULT_FILE), offset);
        let r = unlock_vault(&f.root, None, TEST_PASSWORD);
        assert!(
            matches!(
                r,
                Err(Error::WrongKey
                    | Error::InvalidFormat { .. }
                    | Error::UnsupportedVersion { .. })
            ),
            "offset {offset}: {:?}",
            r.err()
        );
        assert!(open_with_master_key(&f.root, &f.mk).is_err());
    }
}

#[test]
fn bit_flip_in_key_file() {
    let f = fx();
    let path = f.root.join(KEY_FILE);
    let len = std::fs::metadata(&path).unwrap().len();
    // Header, slot head, Argon2 parameters, salt, nonce, wrapped key and tag.
    for offset in [0, 8, 10, 12, 13, 15, 19, 23, 30, 45, 55, 70, len - 1] {
        flip(&path, offset);
        let r = unlock_vault(&f.root, None, TEST_PASSWORD);
        assert!(
            matches!(
                r,
                Err(Error::WrongPassword
                    | Error::InvalidFormat { .. }
                    | Error::UnsupportedVersion { .. })
            ),
            "offset {offset}: {:?}",
            r.err()
        );
        flip(&path, offset);
    }
    unlock_vault(&f.root, None, TEST_PASSWORD).unwrap();
}

#[test]
fn swapped_chunks() {
    let f = fx();
    let path = f.real("big.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    let full = (CHUNK_SIZE + CHUNK_OVERHEAD) as usize;
    let start = HEADER_LEN as usize;
    let (c0, c1) = bytes[start..start + 2 * full].split_at_mut(full);
    c0.swap_with_slice(c1);
    std::fs::write(&path, bytes).unwrap();
    assert_auth_failed(f.read("big.bin"));
}

#[test]
fn cut_at_chunk_boundary() {
    let f = fx();
    cut(&f.real("big.bin"), HEADER_LEN + CHUNK_SIZE + CHUNK_OVERHEAD);
    assert_auth_failed(f.read("big.bin"));
}

#[test]
fn cut_to_header() {
    let f = fx();
    cut(&f.real("big.bin"), HEADER_LEN);
    let r = f.read("big.bin");
    assert!(matches!(r, Err(Error::InvalidFormat { .. })), "{r:?}");
}

#[test]
fn file_moved_to_another_directory() {
    let f = fx();
    let real = f.real("small.txt");
    let target = f.real("dir").join(real.file_name().unwrap());
    std::fs::rename(&real, &target).unwrap();
    let fs = f.fs();
    // The moved file does not appear in `dir`, and no path reads it.
    let listed: Vec<String> = fs
        .readdir(&p("dir"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(listed, vec!["inner.txt"]);
    assert!(matches!(read_file(&fs, "small.txt"), Err(Error::NotFound)));
    assert!(matches!(
        read_file(&fs, "dir/small.txt"),
        Err(Error::NotFound)
    ));
}

/// Swaps the bytes of two real files (a rename of the content only).
fn swap_files(a: &Path, b: &Path) {
    let bytes_a = std::fs::read(a).unwrap();
    let bytes_b = std::fs::read(b).unwrap();
    std::fs::write(a, bytes_b).unwrap();
    std::fs::write(b, bytes_a).unwrap();
}

fn assert_err(r: Result<Vec<u8>, Error>) {
    assert!(r.is_err(), "tampered read must fail, got {r:?}");
}

#[test]
fn files_swapped_in_same_directory() {
    for padded in [false, true] {
        let f = if padded { fx_padded() } else { fx() };
        swap_files(&f.real("small.txt"), &f.real("other.txt"));
        assert_auth_failed(f.read("small.txt"));
        assert_auth_failed(f.read("other.txt"));
        // Untouched files still read.
        assert_eq!(f.read("dir/inner.txt").unwrap(), b"inner");
    }
}

#[test]
fn files_swapped_across_directories() {
    for padded in [false, true] {
        let f = if padded { fx_padded() } else { fx() };
        let dir = f.real("dir");
        let inner = dir.join(real_name_of(
            &f.names,
            &read_dir_id(&dir),
            &dir,
            "inner.txt",
        ));
        swap_files(&f.real("small.txt"), &inner);
        assert_auth_failed(f.read("small.txt"));
        assert_auth_failed(f.read("dir/inner.txt"));
    }
}

fn read_dir_id(dir: &Path) -> DirId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&std::fs::read(dir.join(DIR_FILE)).unwrap()[..16]);
    id
}

/// Lists a real directory as sorted names.
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

#[test]
fn directories_swapped() {
    let f = fx();
    let fs = f.fs();
    fs.mkdir(&p("dir2"), 0o755).unwrap();
    write_file(&fs, "dir2/second.txt", b"second");
    drop(fs);
    let a = f.real("dir");
    let b = f.real("dir2");
    let (names_a, names_b) = (names_in(&a), names_in(&b));
    // Swap the real contents, `.cd-dir` included.
    let tmp = f.root.join("swap-tmp");
    std::fs::create_dir(&tmp).unwrap();
    for n in &names_a {
        std::fs::rename(a.join(n), tmp.join(n)).unwrap();
    }
    for n in &names_b {
        std::fs::rename(b.join(n), a.join(n)).unwrap();
    }
    for n in &names_a {
        std::fs::rename(tmp.join(n), b.join(n)).unwrap();
    }
    std::fs::remove_dir(&tmp).unwrap();
    let fs = f.fs();
    for path in ["dir", "dir2"] {
        let r = fs.readdir(&p(path));
        assert!(r.is_err(), "{path}: {r:?}");
    }
    assert_err(read_file(&fs, "dir/second.txt"));
    assert_err(read_file(&fs, "dir2/inner.txt"));
    // Nothing was deleted.
    assert_eq!(names_in(&a), names_b);
    assert_eq!(names_in(&b), names_a);
}

#[test]
fn header_file_id_changed() {
    for padded in [false, true] {
        let f = if padded { fx_padded() } else { fx() };
        // The file id is the last 16 header bytes.
        flip(&f.real("small.txt"), 40);
        assert_auth_failed(f.read("small.txt"));
    }
}

#[test]
fn header_epoch_changed() {
    for padded in [false, true] {
        let f = if padded { fx_padded() } else { fx() };
        // Epoch 1 becomes 0 (bit flip) and then 3 (no key for it).
        let path = f.real("small.txt");
        flip(&path, 1);
        assert_err(f.read("small.txt"));
        flip(&path, 1);
        flip(&path, 2);
        assert_err(f.read("small.txt"));
        flip(&path, 2);
        assert_eq!(f.read("small.txt").unwrap(), b"small file");
    }
}

#[test]
fn size_block_changed() {
    let f = fx_padded();
    let path = f.real("small.txt");
    // Nonce, ciphertext and tag of the size block.
    for offset in [HEADER_LEN, HEADER_LEN + 14, PADDED_HEADER_LEN - 1] {
        flip(&path, offset);
        assert_auth_failed(f.read("small.txt"));
        flip(&path, offset);
    }
    assert_eq!(f.read("small.txt").unwrap(), b"small file");
}

#[test]
fn padded_file_cut_and_grown() {
    let len = stage(10 + CHUNK_OVERHEAD + PADDED_HEADER_LEN);
    // Cut to the header, to one byte less and to a part of the header;
    // grown by one byte and by one stage. Each case has its own vault.
    for new_len in [PADDED_HEADER_LEN, len - 1, 10, len + 1, len * 2] {
        let f = fx_padded();
        let path = f.real("small.txt");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        cut(&path, new_len);
        let r = f.read("small.txt");
        assert!(
            matches!(r, Err(Error::InvalidFormat { .. })),
            "{new_len}: {r:?}"
        );
    }
}

fn key_set_bytes(entries: &[(u32, u8)]) -> Vec<u8> {
    let mut v = vec![entries.len() as u8];
    for (epoch, fill) in entries {
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(&[*fill; 32]);
    }
    v
}

#[test]
fn bad_key_sets_are_wrong_password() {
    let bad = [
        ("count 0", key_set_bytes(&[])),
        ("count 3", key_set_bytes(&[(1, 1), (2, 2), (3, 3)])),
        ("equal epochs", key_set_bytes(&[(2, 1), (2, 2)])),
        ("falling epochs", key_set_bytes(&[(3, 1), (2, 2)])),
        ("epoch 0", key_set_bytes(&[(0, 1)])),
        ("cut", key_set_bytes(&[(1, 1)])[..30].to_vec()),
    ];
    for (what, raw) in bad {
        let kf =
            KeyFile::with_raw_key_set_for_tests(&raw, TEST_PASSWORD, Argon2Params::MIN).unwrap();
        let r = kf.unlock(TEST_PASSWORD);
        assert!(
            matches!(r, Err(Error::WrongPassword)),
            "{what}: {:?}",
            r.err()
        );
    }
    // The helper itself wraps a good key set so that it opens.
    let good = key_set_bytes(&[(1, 1), (2, 2)]);
    let kf = KeyFile::with_raw_key_set_for_tests(&good, TEST_PASSWORD, Argon2Params::MIN).unwrap();
    let keys: KeySet = kf.unlock(TEST_PASSWORD).unwrap();
    assert_eq!(keys.epochs(), vec![1, 2]);
}

#[test]
fn wrong_key_file() {
    let f = fx();
    let (_tmp, other, _mk) = test_vault();
    let other_key = other.root_path.join(KEY_FILE);
    let r = unlock_vault(&f.root, Some(&other_key), TEST_PASSWORD);
    assert!(matches!(r, Err(Error::WrongKey)), "{:?}", r.err());
}

#[test]
fn changed_argon2_parameters() {
    let f = fx();
    let path = f.root.join(KEY_FILE);
    let original = std::fs::read(&path).unwrap();
    // The payload starts at 15: m (4 bytes), t (4 bytes), p (4 bytes).
    let changes: [(usize, u32); 3] = [
        (15, Argon2Params::MIN.m_kib + 1024),
        (19, Argon2Params::MIN.t + 1),
        (23, Argon2Params::MIN.p + 1),
    ];
    for (offset, value) in changes {
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(KeyFile::from_bytes(&bytes).is_ok());
        std::fs::write(&path, &bytes).unwrap();
        let r = unlock_vault(&f.root, None, TEST_PASSWORD);
        assert!(matches!(r, Err(Error::WrongPassword)), "{:?}", r.err());
    }
}
