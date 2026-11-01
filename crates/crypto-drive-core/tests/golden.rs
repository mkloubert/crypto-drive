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

//! The golden vaults (spec 9, hardening spec 13): two committed vaults of
//! format version 1 with a known password and fixed contents, one without
//! and one with size padding. Every future version must read them.
//!
//! The files under `tests/golden/v1/plain/` and `tests/golden/v1/padded/`
//! were made once with
//! `CRYPTO_DRIVE_WRITE_GOLDEN=1 cargo test -p crypto-drive-core --test golden -- --ignored generate_golden_v1`
//! (run only the generator; running the readers at the same time races).
//! Never make them again: they freeze the on-disk format.

use crypto_drive_core::check::check_vault;
use crypto_drive_core::content::stage;
use crypto_drive_core::fs::{CryptoFs, DirEntry, FileKind, VPath};
use crypto_drive_core::keyfile::Argon2Params;
use crypto_drive_core::keys::MasterKey;
use crypto_drive_core::vault::{InitOptions, init_vault, open_with_master_key, unlock_vault};
use std::path::{Path, PathBuf};

const PASSWORD: &[u8] = b"golden-password";

/// The two variants: directory name and the `pad_sizes` flag.
const VARIANTS: [(&str, bool); 2] = [("plain", false), ("padded", true)];

fn golden_dir(variant: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/v1")
        .join(variant)
}

fn p(s: &str) -> VPath {
    VPath::parse(s).unwrap()
}

fn long_name() -> String {
    format!("long-name-{}.txt", "x".repeat(200))
}

fn big_data() -> Vec<u8> {
    (0..200_000u32).map(|i| (i % 251) as u8).collect()
}

/// The file that is created as `DRAFT` and then renamed once to `RENAMED`,
/// so its entry id comes from the creation and not from the rename.
const DRAFT: &str = "draft.txt";
const RENAMED: &str = "docs/renamed.txt";

fn renamed_data() -> Vec<u8> {
    b"renamed once after creation\n".to_vec()
}

/// The clear files of the golden vaults and their contents.
fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("hello.txt".into(), b"Hello, crypto-drive!\n".to_vec()),
        ("empty.bin".into(), Vec::new()),
        ("docs/big.bin".into(), big_data()),
        (format!("docs/{}", long_name()), b"long\n".to_vec()),
        (RENAMED.into(), renamed_data()),
    ]
}

fn write_file(fs: &CryptoFs, path: &str, data: &[u8]) {
    let (_, h) = fs.create(&p(path), 0o644).unwrap();
    assert_eq!(fs.write(h, 0, data).unwrap() as usize, data.len());
    fs.release(h).unwrap();
}

fn generate(variant: &str, pad_sizes: bool) {
    let dir = golden_dir(variant);
    let vault_dir = dir.join("vault");
    let key = dir.join("key");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    let opts = InitOptions {
        max_name_length: 220,
        argon2: Argon2Params::MIN,
        key_file: Some(key.clone()),
        pad_sizes,
    };
    init_vault(&vault_dir, PASSWORD, &opts).unwrap();
    let (vault, _keys) = unlock_vault(&vault_dir, Some(&key), PASSWORD).unwrap();
    let fs = CryptoFs::new(vault).unwrap();
    fs.mkdir(&p("docs"), 0o755).unwrap();
    fs.mkdir(&p("empty-dir"), 0o755).unwrap();
    for (path, data) in files() {
        if path == RENAMED {
            continue;
        }
        write_file(&fs, &path, &data);
    }
    write_file(&fs, DRAFT, &renamed_data());
    fs.rename(&p(DRAFT), &p(RENAMED)).unwrap();
}

#[test]
#[ignore = "makes the committed golden vaults; run only once"]
fn generate_golden_v1() {
    // `cargo test -- --include-ignored` would otherwise replace the frozen
    // files. Only write them when this is asked for on purpose.
    if std::env::var_os("CRYPTO_DRIVE_WRITE_GOLDEN").is_none() {
        eprintln!("skipped: set CRYPTO_DRIVE_WRITE_GOLDEN=1 to write the golden vaults");
        return;
    }
    for (variant, pad_sizes) in VARIANTS {
        generate(variant, pad_sizes);
    }
}

/// Copies a directory tree, so the test never changes the committed files.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), &target).unwrap();
        }
    }
}

/// Every real file that holds encrypted content: B64 named files and
/// `.cd-content` files. Control files (`.cd-vault`, `.cd-dir`, `.cd-name`)
/// are left out.
fn content_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        if e.file_type().unwrap().is_dir() {
            content_files(&e.path(), out);
        } else if name == ".cd-content" || !name.starts_with('.') {
            out.push(e.path());
        }
    }
}

fn entry(name: &str, kind: FileKind) -> DirEntry {
    DirEntry {
        name: name.into(),
        kind,
    }
}

fn check_variant(variant: &str, pad_sizes: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let key = tmp.path().join("key");
    copy_tree(&golden_dir(variant).join("vault"), &vault_dir);
    std::fs::copy(golden_dir(variant).join("key"), &key).unwrap();

    let (vault, keys) = unlock_vault(&vault_dir, Some(&key), PASSWORD).unwrap();
    assert_eq!(keys.epochs(), vec![1]);
    let mk = MasterKey::from_bytes(*keys.get(vault.marker.epoch).unwrap().expose());
    assert_eq!(vault.marker.format_version, 1);
    assert_eq!(vault.marker.max_name_length, 220);
    assert_eq!(vault.marker.epoch, 1);
    assert_eq!(vault.marker.pad_sizes, pad_sizes);
    let findings = check_vault(&vault).unwrap();
    assert!(findings.is_empty(), "{variant}: {findings:?}");

    let fs = CryptoFs::new(vault).unwrap();
    assert_eq!(
        fs.readdir(&VPath::root()).unwrap(),
        vec![
            entry("docs", FileKind::Directory),
            entry("empty-dir", FileKind::Directory),
            entry("empty.bin", FileKind::File),
            entry("hello.txt", FileKind::File),
        ]
    );
    assert_eq!(
        fs.readdir(&p("docs")).unwrap(),
        vec![
            entry("big.bin", FileKind::File),
            entry(&long_name(), FileKind::File),
            entry("renamed.txt", FileKind::File),
        ]
    );
    assert!(fs.readdir(&p("empty-dir")).unwrap().is_empty());
    for (path, data) in files() {
        assert_eq!(
            fs.getattr(&p(&path)).unwrap().size,
            data.len() as u64,
            "{variant}: {path}"
        );
        let h = fs.open(&p(&path), false, false).unwrap();
        assert_eq!(fs.read(h, 0, 1 << 20).unwrap(), data, "{variant}: {path}");
        fs.release(h).unwrap();
    }
    drop(fs);

    let mut real = Vec::new();
    content_files(&vault_dir, &mut real);
    assert_eq!(real.len(), files().len(), "{variant}: {real:?}");
    if pad_sizes {
        for f in &real {
            let len = std::fs::metadata(f).unwrap().len();
            assert_eq!(len, stage(len), "{variant}: {}", f.display());
        }
    }

    // The recovery key path (master key only) opens it as well.
    open_with_master_key(&vault_dir, &mk).unwrap();
}

#[test]
fn golden_v1_plain_is_readable() {
    check_variant(VARIANTS[0].0, VARIANTS[0].1);
}

#[test]
fn golden_v1_padded_is_readable() {
    check_variant(VARIANTS[1].0, VARIANTS[1].1);
}
