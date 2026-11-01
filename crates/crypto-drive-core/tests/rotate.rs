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

//! Master key rotation (HS 9): full runs, a crash after every write step,
//! and a mount between two runs.

use crypto_drive_core::Error;
use crypto_drive_core::check::{FindingKind, Severity, check_vault};
use crypto_drive_core::content::stage;
use crypto_drive_core::file::OpenFile;
use crypto_drive_core::fs::{CryptoFs, FileKind, VPath};
use crypto_drive_core::keyfile::{Argon2Params, KeyFile};
use crypto_drive_core::keys::{Epoch, KeySet, MasterKey};
use crypto_drive_core::names::{LONG_PREFIX, NameKeys, long_entry_name};
use crypto_drive_core::recovery::{decode_recovery_key, encode_recovery_key};
use crypto_drive_core::rotate::{RotateOptions, RotateReport, rotate_key, set_fail_after_steps};
use crypto_drive_core::testutil::{TEST_PASSWORD, real_name_of, test_vault, test_vault_padded};
use crypto_drive_core::vault::{
    CONTENT_FILE, CONTROL_PREFIX, KEY_FILE, NAME_FILE, UnlockedVault, lock_vault,
    open_with_key_set, open_with_master_key, rotation_unfinished, unlock_vault, verify_next_key,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Display path → content (`None` for a directory).
type Model = BTreeMap<String, Option<Vec<u8>>>;

const LONG_FILE: &str = "a-file-with-a-very-long-name-that-needs-an-overflow-entry-\
    0123456789-0123456789-0123456789-0123456789-0123456789-0123456789-0123456789.txt";
const LONG_DIR: &str = "a-directory-with-a-very-long-name-that-needs-an-overflow-entry-\
    0123456789-0123456789-0123456789-0123456789-0123456789-0123456789-0123456789";
/// The file that gets a fixed mode and mtime.
const TIMED: &str = "one.bin";
const TIMED_MODE: u32 = 0o640;

fn timed_mtime() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn p(s: &str) -> VPath {
    VPath::parse(s).unwrap()
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(31))
        .collect()
}

fn write_file(fs: &CryptoFs, path: &str, bytes: &[u8]) {
    let (_, h) = fs.create(&p(path), 0o644).unwrap();
    fs.write(h, 0, bytes).unwrap();
    fs.release(h).unwrap();
}

fn read_file(fs: &CryptoFs, path: &str) -> Vec<u8> {
    let h = fs.open(&p(path), false, false).unwrap();
    let bytes = fs.read(h, 0, 1 << 24).unwrap();
    fs.release(h).unwrap();
    bytes
}

/// Every directory and file below `dir`, with content.
fn model_of(fs: &CryptoFs) -> Model {
    let mut model = Model::new();
    let mut todo = vec![String::new()];
    while let Some(dir) = todo.pop() {
        let path = if dir.is_empty() {
            "/".to_owned()
        } else {
            dir.clone()
        };
        for e in fs.readdir(&p(&path)).unwrap() {
            let child = if dir.is_empty() {
                e.name.clone()
            } else {
                format!("{dir}/{}", e.name)
            };
            match e.kind {
                FileKind::Directory => {
                    model.insert(child.clone(), None);
                    todo.push(child);
                }
                FileKind::File => {
                    let content = read_file(fs, &child);
                    model.insert(child, Some(content));
                }
            }
        }
    }
    model
}

struct Fx {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    old_mk: MasterKey,
    model: Model,
    padded: bool,
}

/// A vault with the fixed tree of the brief: files of 0, 1, 70_000 and
/// 200_000 bytes, a long-name file, a long-name directory, nested
/// directories and a conflict copy.
fn fx_from((tmp, v, mk): (tempfile::TempDir, UnlockedVault, MasterKey)) -> Fx {
    let dir = v.root_path.clone();
    let padded = v.marker.pad_sizes;
    let names = NameKeys::new(&v.keys);
    let vault_id = v.marker.vault_id;
    let fs = CryptoFs::new(v).unwrap();
    write_file(&fs, "empty.bin", b"");
    write_file(&fs, "one.bin", b"1");
    write_file(&fs, "mid.bin", &data(70_000, 1));
    write_file(&fs, "big.bin", &data(200_000, 2));
    write_file(&fs, LONG_FILE, &data(5_000, 3));
    fs.mkdir(&p(LONG_DIR), 0o755).unwrap();
    write_file(
        &fs,
        &format!("{LONG_DIR}/inside.txt"),
        b"inside the long dir",
    );
    fs.mkdir(&p("a"), 0o755).unwrap();
    fs.mkdir(&p("a/b"), 0o700).unwrap();
    fs.mkdir(&p("a/b/empty"), 0o755).unwrap();
    write_file(&fs, "a/x.txt", b"x in a");
    write_file(&fs, "a/b/c.txt", &data(66_000, 4));
    fs.set_mode(&p(TIMED), TIMED_MODE).unwrap();
    fs.set_times(&p(TIMED), None, Some(timed_mtime())).unwrap();
    drop(fs);
    // A sync client's conflict copy of mid.bin.
    let real = real_name_of(&names, &vault_id, &dir, "mid.bin");
    std::fs::copy(
        dir.join(&real),
        dir.join(format!("{real} (conflicted copy)")),
    )
    .unwrap();

    let fs = CryptoFs::new(open_with_master_key(&dir, &mk).unwrap()).unwrap();
    let model = model_of(&fs);
    assert!(
        model.contains_key("mid (conflict 1).bin"),
        "{:?}",
        model.keys()
    );
    assert_eq!(model.len(), 13, "{:?}", model.keys());
    Fx {
        _tmp: tmp,
        dir,
        old_mk: mk,
        model,
        padded,
    }
}

fn fx() -> Fx {
    fx_from(test_vault())
}

fn rotate(dir: &Path) -> Result<RotateReport, Error> {
    let opts = RotateOptions {
        key_file: None,
        argon2: None,
    };
    rotate_key(dir, TEST_PASSWORD, &opts, &mut |_| {}, &mut |_| {})
}

fn key_set_epochs(dir: &Path) -> Vec<Epoch> {
    KeyFile::load(&dir.join(KEY_FILE))
        .unwrap()
        .unlock(TEST_PASSWORD)
        .unwrap()
        .epochs()
}

fn is_interrupted(r: &Result<RotateReport, Error>) -> bool {
    matches!(r, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::Interrupted)
}

/// Real files that hold encrypted content (not control files).
fn content_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        let path = e.path();
        if e.file_type().unwrap().is_dir() {
            content_files(&path, out);
        } else if !name.starts_with(CONTROL_PREFIX) || name == ".cd-content" {
            out.push(path);
        }
    }
}

/// Only conflict copy warnings, no error.
fn assert_check_clean(vault: &UnlockedVault) {
    let findings = check_vault(vault).unwrap();
    assert!(
        findings.iter().all(|f| f.kind == FindingKind::ConflictCopy),
        "{findings:?}"
    );
}

/// The vault is at `epoch` only, the old key is useless, the new recovery
/// key works, all content is equal and `check` is clean.
fn assert_rotated(f: &Fx, epoch: Epoch, model: &Model) {
    // One unlock only: Argon2 is slow in debug builds.
    let keys = KeyFile::load(&f.dir.join(KEY_FILE))
        .unwrap()
        .unlock(TEST_PASSWORD)
        .unwrap();
    assert_eq!(keys.epochs(), vec![epoch]);
    let vault = open_with_key_set(&f.dir, &keys).unwrap();
    assert_eq!(vault.marker.epoch, epoch);
    assert!(matches!(
        open_with_master_key(&f.dir, &f.old_mk),
        Err(Error::WrongKey)
    ));
    let recovery = encode_recovery_key(keys.get(epoch).unwrap());
    let new_mk = decode_recovery_key(&recovery).unwrap();
    open_with_master_key(&f.dir, &new_mk).unwrap();

    assert_check_clean(&vault);
    let fs = CryptoFs::new(vault).unwrap();
    assert_model_eq(&model_of(&fs), model);
    if model.contains_key(TIMED) {
        let attr = fs.getattr(&p(TIMED)).unwrap();
        assert_eq!(attr.mode, TIMED_MODE);
        assert_eq!(attr.mtime, timed_mtime());
    }

    let mut files = Vec::new();
    content_files(&f.dir, &mut files);
    let file_count = model.values().filter(|c| c.is_some()).count();
    assert_eq!(files.len(), file_count, "{files:?}");
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        let header_epoch = Epoch::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(header_epoch, epoch, "{}", file.display());
        if f.padded {
            let len = bytes.len() as u64;
            assert_eq!(stage(len), len, "{}", file.display());
        }
    }
}

/// While a rotation is not finished, every file is still there with its
/// content (a duplicate may show up as a conflict copy) and `check` finds
/// no error.
fn assert_readable_midway(f: &Fx) {
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    let findings = check_vault(&vault).unwrap();
    assert!(
        findings.iter().all(|f| f.severity == Severity::Warning),
        "{findings:?}"
    );
    let fs = CryptoFs::new(vault).unwrap();
    assert_model_contains(&model_of(&fs), &f.model);
}

/// Every entry of `expected` is in `seen` with the same content.
fn assert_model_contains(seen: &Model, expected: &Model) {
    for (path, content) in expected {
        assert!(seen.get(path) == Some(content), "{path}: {:?}", seen.keys());
    }
}

/// Both models are equal (without printing all content on failure).
fn assert_model_eq(seen: &Model, expected: &Model) {
    assert_eq!(
        seen.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    assert_model_contains(seen, expected);
}

#[test]
fn full_rotation() {
    let f = fx();
    let mut progress = Vec::new();
    let opts = RotateOptions {
        key_file: None,
        argon2: None,
    };
    let mut keys_seen = Vec::new();
    let report = rotate_key(
        &f.dir,
        TEST_PASSWORD,
        &opts,
        &mut |n| progress.push(n),
        &mut |k| keys_seen.push(k.to_owned()),
    )
    .unwrap();
    assert_eq!(
        Some(keys_seen),
        report.new_recovery_key.clone().map(|k| vec![k])
    );
    assert!(report.finished);
    assert_eq!(report.new_epoch, 2);
    assert_eq!(report.entries_done, 13);
    assert_eq!(progress.last(), Some(&13));
    let (_, keys) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(
        report.new_recovery_key,
        Some(encode_recovery_key(keys.get(2).unwrap()))
    );
    assert_rotated(&f, 2, &f.model);
}

#[test]
fn rotation_of_padded_vault() {
    let f = fx_from(test_vault_padded());
    let report = rotate(&f.dir).unwrap();
    assert!(report.finished);
    assert_rotated(&f, 2, &f.model);
}

/// Copies the real tree `from` to the new directory `to`, with the mode
/// and mtime of each file.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), &target).unwrap();
            let mtime = e.metadata().unwrap().modified().unwrap();
            let file = std::fs::OpenOptions::new()
                .append(true)
                .open(&target)
                .unwrap_or_else(|_| std::fs::File::open(&target).unwrap());
            file.set_modified(mtime).unwrap();
        }
    }
}

#[test]
fn crash_after_every_step() {
    let template = fx();
    let mut total_steps = None;
    for n in 0..1000u64 {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        copy_tree(&template.dir, &dir);
        let f = Fx {
            _tmp: tmp,
            dir,
            old_mk: MasterKey::from_bytes(*template.old_mk.expose()),
            model: template.model.clone(),
            padded: false,
        };
        set_fail_after_steps(Some(n));
        let first = rotate(&f.dir);
        set_fail_after_steps(None);
        if first.is_ok() {
            // All steps of a full run passed.
            assert_rotated(&f, 2, &f.model);
            total_steps = Some(n);
            break;
        }
        assert!(
            is_interrupted(&first),
            "step {n}: {:?}",
            first.as_ref().err()
        );
        assert_readable_midway(&f);
        let second = rotate(&f.dir).unwrap_or_else(|e| panic!("resume after step {n}: {e}"));
        assert!(second.finished);
        assert_eq!(second.new_recovery_key.is_some(), n == 0, "step {n}");
        assert_rotated(&f, 2, &f.model);
    }
    // Key file, 4 directory renames, 3 steps for each of the 9 files,
    // marker and final key file.
    assert_eq!(total_steps, Some(1 + 4 + 27 + 2));
}

/// The header epoch of the real file of the root entry `name`.
fn header_epoch(dir: &Path, names: &NameKeys, vault_id: &[u8; 16], name: &str) -> Epoch {
    let real = real_name_of(names, vault_id, dir, name);
    let bytes = std::fs::read(dir.join(real)).unwrap();
    Epoch::from_le_bytes(bytes[1..5].try_into().unwrap())
}

#[test]
fn interrupt_mount_edit_resume() {
    let f = fx();
    // Stop right after the key file: a known state (every entry is old, no
    // duplicate). A stop inside the walk depends on the random real names;
    // `mount_edits_a_duplicate_then_resume` covers a stop after a new entry.
    stop_after(&f.dir, 1);
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);

    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(vault.marker.epoch, 1);
    let names = NameKeys::new(&vault.keys);
    let vault_id = vault.marker.vault_id;
    let old: Vec<&str> = ["empty.bin", "one.bin", "mid.bin", "big.bin"]
        .into_iter()
        .filter(|n| header_epoch(&f.dir, &names, &vault_id, n) == 1)
        .collect();
    assert_eq!(old.len(), 4, "{old:?}");
    let fs = CryptoFs::new(vault).unwrap();
    let mut model = f.model.clone();

    // Edit an old file: it keeps epoch 1 until the next run.
    let h = fs.open(&p(old[0]), true, false).unwrap();
    fs.write(h, 0, b"EDIT").unwrap();
    fs.release(h).unwrap();
    model.insert(old[0].to_owned(), Some(read_file(&fs, old[0])));
    assert_eq!(&model[old[0]].as_ref().unwrap()[..4], b"EDIT");
    // A new file is written at epoch 2.
    write_file(&fs, "new.txt", b"made during the rotation");
    model.insert(
        "new.txt".to_owned(),
        Some(b"made during the rotation".to_vec()),
    );
    // A renamed old file gets a name of epoch 2 but keeps content of epoch 1.
    fs.rename(&p(old[1]), &p("renamed.bin")).unwrap();
    let moved = model.remove(old[1]).unwrap();
    model.insert("renamed.bin".to_owned(), moved);
    // A duplicate of an interrupted step may show up as a conflict copy.
    assert_model_contains(&model_of(&fs), &model);
    drop(fs);

    let report = rotate(&f.dir).unwrap();
    assert!(report.finished);
    assert_eq!(report.new_recovery_key, None);
    let (vault, keys) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(keys.epochs(), vec![2]);
    assert_eq!(vault.marker.epoch, 2);
    assert_check_clean(&vault);
    let fs = CryptoFs::new(vault).unwrap();
    assert_model_eq(&model_of(&fs), &model);
    let mut files = Vec::new();
    content_files(&f.dir, &mut files);
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        assert_eq!(Epoch::from_le_bytes(bytes[1..5].try_into().unwrap()), 2);
    }
}

#[test]
fn two_rotations_give_epoch_3() {
    let f = fx();
    let first = rotate(&f.dir).unwrap();
    assert_eq!(first.new_epoch, 2);
    assert!(first.new_recovery_key.is_some());
    let second = rotate(&f.dir).unwrap();
    assert_eq!(second.new_epoch, 3);
    assert!(second.new_recovery_key.is_some());
    assert_ne!(first.new_recovery_key, second.new_recovery_key);
    assert_rotated(&f, 3, &f.model);
}

#[test]
fn locked_vault_is_refused() {
    let f = fx();
    let lock = lock_vault(&f.dir).unwrap();
    assert!(matches!(rotate(&f.dir), Err(Error::AlreadyMounted)));
    drop(lock);
    assert_eq!(key_set_epochs(&f.dir), vec![1]);
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(vault.marker.epoch, 1);
    assert_check_clean(&vault);
}

/// A vault that holds only what `build` makes.
fn small_fx(build: impl FnOnce(&CryptoFs)) -> Fx {
    let (tmp, v, mk) = test_vault();
    let dir = v.root_path.clone();
    let fs = CryptoFs::new(v).unwrap();
    build(&fs);
    let model = model_of(&fs);
    drop(fs);
    Fx {
        _tmp: tmp,
        dir,
        old_mk: mk,
        model,
        padded: false,
    }
}

/// Runs the rotation until `n` write steps are done.
fn stop_after(dir: &Path, n: u64) {
    set_fail_after_steps(Some(n));
    let r = rotate(dir);
    set_fail_after_steps(None);
    assert!(is_interrupted(&r), "{:?}", r.as_ref().err());
}

/// The single real entry of the root that starts with `prefix` and whose
/// content (or `.cd-content`) has header epoch `epoch`.
fn root_entry_of_epoch(dir: &Path, epoch: Epoch) -> PathBuf {
    let mut found = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name.starts_with(CONTROL_PREFIX) && !name.starts_with(LONG_PREFIX) {
            continue;
        }
        let content = if path.is_dir() {
            path.join(CONTENT_FILE)
        } else {
            path.clone()
        };
        let Ok(bytes) = std::fs::read(&content) else {
            continue;
        };
        if Epoch::from_le_bytes(bytes[1..5].try_into().unwrap()) == epoch {
            found.push(path);
        }
    }
    assert_eq!(found.len(), 1, "{found:?}");
    found.remove(0)
}

/// The `.cd-cdl` entry and `.cd-name` the long root entry `real` gets
/// under the write epoch of the vault's current key set.
fn new_long_name(dir: &Path, real: &Path) -> (String, String) {
    let (vault, _) = unlock_vault(dir, None, TEST_PASSWORD).unwrap();
    let names = NameKeys::new(&vault.keys);
    let id = vault.marker.vault_id;
    let full = std::fs::read_to_string(real.join(NAME_FILE)).unwrap();
    let (epoch, entry_id, clear) = names.decrypt_any(&id, &full).unwrap();
    assert_eq!(epoch, 1);
    let new_full = names.encrypt_write(&id, &entry_id, &clear).unwrap();
    (long_entry_name(&new_full), new_full)
}

fn finish_and_check(f: &Fx) {
    let report = rotate(&f.dir).unwrap();
    assert!(report.finished);
    assert_rotated(f, 2, &f.model);
}

#[test]
fn damaged_new_copy_of_a_duplicate_is_made_again() {
    let f = small_fx(|fs| write_file(fs, "f.bin", &data(100_000, 5)));
    // Key file, tmp written, new entry made: old and new entry both exist.
    stop_after(&f.dir, 3);
    let new = root_entry_of_epoch(&f.dir, 2);
    root_entry_of_epoch(&f.dir, 1);
    let len = std::fs::metadata(&new).unwrap().len();
    let mut bytes = std::fs::read(&new).unwrap();
    bytes[(len - 5) as usize] ^= 1;
    std::fs::write(&new, bytes).unwrap();
    finish_and_check(&f);
}

#[test]
fn removal_of_old_long_file_stopped_after_its_content() {
    let f = small_fx(|fs| write_file(fs, LONG_FILE, b"long"));
    stop_after(&f.dir, 3);
    // The crash came between unlinking `.cd-content` and the rest.
    let old = root_entry_of_epoch(&f.dir, 1);
    std::fs::remove_file(old.join(CONTENT_FILE)).unwrap();
    finish_and_check(&f);
}

#[test]
fn removal_of_old_long_file_stopped_before_rmdir() {
    let f = small_fx(|fs| write_file(fs, LONG_FILE, b"long"));
    stop_after(&f.dir, 3);
    let old = root_entry_of_epoch(&f.dir, 1);
    std::fs::remove_file(old.join(CONTENT_FILE)).unwrap();
    std::fs::remove_file(old.join(NAME_FILE)).unwrap();
    finish_and_check(&f);
}

#[test]
fn new_long_entry_stopped_before_its_content() {
    let f = small_fx(|fs| write_file(fs, LONG_FILE, b"long"));
    // Key file and tmp written.
    stop_after(&f.dir, 2);
    let old = root_entry_of_epoch(&f.dir, 1);
    let (entry, full) = new_long_name(&f.dir, &old);
    std::fs::create_dir(f.dir.join(&entry)).unwrap();
    std::fs::write(f.dir.join(&entry).join(NAME_FILE), full).unwrap();
    finish_and_check(&f);
}

#[test]
fn long_dir_rename_stopped_before_its_new_name() {
    let f = small_fx(|fs| {
        fs.mkdir(&p(LONG_DIR), 0o755).unwrap();
        write_file(fs, &format!("{LONG_DIR}/in.txt"), b"in");
    });
    stop_after(&f.dir, 1);
    let old = std::fs::read_dir(&f.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(LONG_PREFIX)
        })
        .unwrap();
    // The directory got its new real name but still holds the old `.cd-name`.
    let (entry, _) = new_long_name(&f.dir, &old);
    std::fs::rename(&old, f.dir.join(entry)).unwrap();
    finish_and_check(&f);
}

#[test]
fn final_check_refuses_an_old_entry_it_cannot_convert() {
    let f = small_fx(|fs| write_file(fs, "f.bin", b"data"));
    let real = root_entry_of_epoch(&f.dir, 1);
    // The header says epoch 1, but the content does not authenticate.
    let mut bytes = std::fs::read(&real).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&real, bytes).unwrap();
    assert!(matches!(rotate(&f.dir), Err(Error::AuthFailed { .. })));
    // The key set keeps both keys and the marker the old epoch.
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(vault.marker.epoch, 1);
}

#[test]
fn final_check_finds_an_old_long_entry_with_a_wrong_hash() {
    let f = small_fx(|fs| write_file(fs, LONG_FILE, b"long"));
    let old = root_entry_of_epoch(&f.dir, 1);
    // Another valid looking hash: a mount does not show it, and the walk
    // does not touch it.
    let name = old.file_name().unwrap().to_str().unwrap();
    let other = format!(
        "{LONG_PREFIX}{}",
        "A".repeat(name.len() - LONG_PREFIX.len())
    );
    std::fs::rename(&old, f.dir.join(other)).unwrap();
    assert!(matches!(
        rotate(&f.dir),
        Err(Error::RotationNotFinished { left: 1, .. })
    ));
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(vault.marker.epoch, 1);
}

fn rotate_with_key_callback(
    dir: &Path,
    keys_seen: &mut Vec<String>,
) -> Result<RotateReport, Error> {
    let opts = RotateOptions {
        key_file: None,
        argon2: None,
    };
    rotate_key(dir, TEST_PASSWORD, &opts, &mut |_| {}, &mut |k| {
        keys_seen.push(k.to_owned())
    })
}

#[test]
fn new_recovery_key_reaches_the_caller_of_a_failed_run() {
    let f = small_fx(|fs| write_file(fs, "f.bin", b"data"));
    let mut keys_seen = Vec::new();
    set_fail_after_steps(Some(1));
    let first = rotate_with_key_callback(&f.dir, &mut keys_seen);
    set_fail_after_steps(None);
    assert!(is_interrupted(&first), "{:?}", first.as_ref().err());
    assert_eq!(keys_seen.len(), 1);
    // A resumed run does not make a new key.
    let mut later = Vec::new();
    let report = rotate_with_key_callback(&f.dir, &mut later).unwrap();
    assert!(later.is_empty());
    assert_eq!(report.new_recovery_key, None);
    let mk = decode_recovery_key(&keys_seen[0]).unwrap();
    let vault = open_with_master_key(&f.dir, &mk).unwrap();
    assert_eq!(vault.marker.epoch, 2);
    assert_rotated(&f, 2, &f.model);
}

/// Changes the real file `real` of a mounted vault (key set {1, 2}) as a
/// mount would: writes `bytes` at `offset`, keeping its epoch.
fn edit_real_file(dir: &Path, real: &Path, offset: u64, bytes: &[u8]) {
    let (vault, _) = unlock_vault(dir, None, TEST_PASSWORD).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(real)
        .unwrap();
    let mut open = OpenFile::open(file, &vault.keys, vault.marker.pad_sizes).unwrap();
    open.write(offset, bytes).unwrap();
    open.sync().unwrap();
}

const DUP_NAME: &str = "f.bin";
const DUP_CONFLICT: &str = "f (rotation conflict 1).bin";

/// A vault with one file, stopped right after its new entry was made: an
/// old and a new copy of it exist.
fn duplicate_fx() -> (Fx, Vec<u8>) {
    let original = data(100_000, 5);
    let f = small_fx(|fs| write_file(fs, DUP_NAME, &original));
    stop_after(&f.dir, 3);
    root_entry_of_epoch(&f.dir, 1);
    root_entry_of_epoch(&f.dir, 2);
    (f, original)
}

fn with_entries(entries: &[(&str, &[u8])]) -> Model {
    entries
        .iter()
        .map(|(n, c)| ((*n).to_owned(), Some(c.to_vec())))
        .collect()
}

#[test]
fn duplicate_with_equal_copies_keeps_one() {
    let (f, original) = duplicate_fx();
    finish_and_check(&f);
    assert_rotated(&f, 2, &with_entries(&[(DUP_NAME, &original)]));
}

#[test]
fn duplicate_whose_old_copy_was_edited_keeps_both() {
    let (f, original) = duplicate_fx();
    let old = root_entry_of_epoch(&f.dir, 1);
    edit_real_file(&f.dir, &old, 10, b"EDIT");
    let mut edited = original.clone();
    edited[10..14].copy_from_slice(b"EDIT");
    rotate(&f.dir).unwrap();
    assert_rotated(
        &f,
        2,
        &with_entries(&[(DUP_NAME, &original), (DUP_CONFLICT, &edited)]),
    );
}

#[test]
fn duplicate_whose_new_copy_was_edited_with_other_length_keeps_both() {
    let (f, original) = duplicate_fx();
    let new = root_entry_of_epoch(&f.dir, 2);
    edit_real_file(&f.dir, &new, original.len() as u64, b"MORE");
    let mut edited = original.clone();
    edited.extend_from_slice(b"MORE");
    rotate(&f.dir).unwrap();
    assert_rotated(
        &f,
        2,
        &with_entries(&[(DUP_NAME, &edited), (DUP_CONFLICT, &original)]),
    );
}

#[test]
fn crash_while_making_a_rotation_conflict_copy_makes_no_second_one() {
    let (f, original) = duplicate_fx();
    let old = root_entry_of_epoch(&f.dir, 1);
    edit_real_file(&f.dir, &old, 0, b"EDIT");
    let mut edited = original.clone();
    edited[..4].copy_from_slice(b"EDIT");
    // The conflict copy is made (tmp, new entry), the old one stays.
    stop_after(&f.dir, 2);
    rotate(&f.dir).unwrap();
    assert_rotated(
        &f,
        2,
        &with_entries(&[(DUP_NAME, &original), (DUP_CONFLICT, &edited)]),
    );
}

#[test]
fn mount_edits_a_duplicate_then_resume() {
    let (f, original) = duplicate_fx();
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    let fs = CryptoFs::new(vault).unwrap();
    // The mount shows both copies; one of them is a conflict entry.
    assert_eq!(
        model_of(&fs).keys().collect::<Vec<_>>(),
        vec!["f (conflict 1).bin", DUP_NAME]
    );
    let h = fs.open(&p(DUP_NAME), true, false).unwrap();
    fs.write(h, 0, b"EDIT").unwrap();
    fs.release(h).unwrap();
    drop(fs);
    let mut edited = original.clone();
    edited[..4].copy_from_slice(b"EDIT");

    rotate(&f.dir).unwrap();
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_check_clean(&vault);
    let model = model_of(&CryptoFs::new(vault).unwrap());
    assert_eq!(
        model.keys().collect::<Vec<_>>(),
        vec![DUP_CONFLICT, DUP_NAME]
    );
    let mut contents: Vec<&Vec<u8>> = model.values().map(|c| c.as_ref().unwrap()).collect();
    contents.sort();
    let mut expected = vec![&original, &edited];
    expected.sort();
    assert!(contents == expected, "both versions must survive");
    // Which copy the mount picked decides the names; the content is exact.
    let expected_model = if model[DUP_NAME].as_ref() == Some(&edited) {
        with_entries(&[(DUP_NAME, &edited), (DUP_CONFLICT, &original)])
    } else {
        with_entries(&[(DUP_NAME, &original), (DUP_CONFLICT, &edited)])
    };
    assert_rotated(&f, 2, &expected_model);
}

#[test]
fn leftover_target_with_other_files_is_an_error() {
    let f = small_fx(|fs| write_file(fs, LONG_FILE, b"long"));
    stop_after(&f.dir, 2);
    let old = root_entry_of_epoch(&f.dir, 1);
    let (entry, full) = new_long_name(&f.dir, &old);
    let target = f.dir.join(&entry);
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join(NAME_FILE), full).unwrap();
    std::fs::write(target.join("junk"), b"not ours").unwrap();
    match rotate(&f.dir) {
        Err(Error::InvalidFormat { what }) => assert_eq!(what, entry),
        r => panic!("{:?}", r.err()),
    }
    // Nothing of it was removed.
    assert!(target.join("junk").exists());
    assert!(target.join(NAME_FILE).exists());
}

#[test]
fn duplicate_whose_old_copy_is_damaged_keeps_the_new_one() {
    let (f, original) = duplicate_fx();
    let old = root_entry_of_epoch(&f.dir, 1);
    let mut bytes = std::fs::read(&old).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&old, bytes).unwrap();
    rotate(&f.dir).unwrap();
    assert_rotated(&f, 2, &with_entries(&[(DUP_NAME, &original)]));
}

/// Like `stop_after`, but returns the master key of the new epoch.
fn stop_after_with_key(dir: &Path, n: u64) -> MasterKey {
    let mut keys_seen = Vec::new();
    set_fail_after_steps(Some(n));
    let r = rotate_with_key_callback(dir, &mut keys_seen);
    set_fail_after_steps(None);
    assert!(is_interrupted(&r), "{:?}", r.as_ref().err());
    assert_eq!(keys_seen.len(), 1);
    decode_recovery_key(&keys_seen[0]).unwrap()
}

/// What `recover` does with both keys: a new key file with the key set
/// {1, 2} and the test password.
fn recover_both(f: &Fx, new_mk: &MasterKey) {
    let keys = KeySet::single(1, MasterKey::from_bytes(*f.old_mk.expose()))
        .with_next(MasterKey::from_bytes(*new_mk.expose()))
        .unwrap();
    let path = f.dir.join(KEY_FILE);
    let _ = std::fs::remove_file(&path);
    KeyFile::new(&keys, TEST_PASSWORD, Argon2Params::MIN)
        .unwrap()
        .save_new(&path)
        .unwrap();
}

fn verify_next(f: &Fx, mk: &MasterKey) -> Result<(), Error> {
    let vault = open_with_master_key(&f.dir, &f.old_mk).unwrap();
    verify_next_key(&vault, mk)
}

/// What `recover` sees with the recovery key `mk` of the marker epoch.
fn unfinished(f: &Fx, mk: &MasterKey) -> bool {
    rotation_unfinished(&open_with_master_key(&f.dir, mk).unwrap()).unwrap()
}

#[test]
fn no_rotation_is_not_unfinished() {
    let f = fx();
    assert!(!unfinished(&f, &f.old_mk));
    // Nothing uses epoch 2, so no key can be shown to be its key.
    assert!(matches!(
        verify_next(&f, &MasterKey::generate().unwrap()),
        Err(Error::WrongKey)
    ));
}

#[test]
fn a_name_only_long_entry_is_not_an_unfinished_rotation() {
    // A crash in a long-name create leaves a long entry with a `.cd-name`
    // and no data. A rotation leaves it alone, so its name may be of any
    // epoch; it must not make `recover` ask for a key that cannot exist.
    let f = small_fx(|fs| write_file(fs, "a.bin", b"a"));
    let orphan = f.dir.join(format!("{LONG_PREFIX}{}", "C".repeat(43)));
    std::fs::create_dir(&orphan).unwrap();
    std::fs::write(orphan.join(".cd-name"), "A".repeat(300)).unwrap();
    assert!(!unfinished(&f, &f.old_mk));
}

#[test]
fn recover_during_rotation_with_new_files_needs_the_new_key() {
    let f = small_fx(|fs| {
        write_file(fs, "a.bin", b"a");
        write_file(fs, "b.bin", &data(70_000, 6));
    });
    // Key file, then the three steps of the first file.
    let new_mk = stop_after_with_key(&f.dir, 4);
    root_entry_of_epoch(&f.dir, 2);
    std::fs::remove_file(f.dir.join(KEY_FILE)).unwrap();
    assert!(unfinished(&f, &f.old_mk));

    assert!(matches!(verify_next(&f, &f.old_mk), Err(Error::WrongKey)));
    assert!(matches!(
        verify_next(&f, &MasterKey::generate().unwrap()),
        Err(Error::WrongKey)
    ));
    verify_next(&f, &new_mk).unwrap();

    recover_both(&f, &new_mk);
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);
    finish_and_check(&f);
}

#[test]
fn recover_during_rotation_with_only_renamed_dirs_needs_the_new_key() {
    let f = small_fx(|fs| {
        fs.mkdir(&p("d1"), 0o755).unwrap();
        fs.mkdir(&p("d2"), 0o755).unwrap();
        write_file(fs, "d1/in.txt", b"in d1");
        write_file(fs, "d2/in.txt", b"in d2");
    });
    // Key file and the rename of one directory; no file was moved yet.
    let new_mk = stop_after_with_key(&f.dir, 2);
    let mut files = Vec::new();
    content_files(&f.dir, &mut files);
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        assert_eq!(Epoch::from_le_bytes(bytes[1..5].try_into().unwrap()), 1);
    }
    std::fs::remove_file(f.dir.join(KEY_FILE)).unwrap();
    // Only the name of the renamed directory shows it.
    assert!(unfinished(&f, &f.old_mk));
    assert!(matches!(
        verify_next(&f, &MasterKey::generate().unwrap()),
        Err(Error::WrongKey)
    ));
    verify_next(&f, &new_mk).unwrap();
    recover_both(&f, &new_mk);
    finish_and_check(&f);
}

#[test]
fn recover_right_after_the_rotation_began_needs_only_the_old_key() {
    let f = small_fx(|fs| write_file(fs, "a.bin", b"a"));
    stop_after_with_key(&f.dir, 1);
    // The key file holds two keys, but nothing uses epoch 2 yet.
    assert!(!unfinished(&f, &f.old_mk));
    let path = f.dir.join(KEY_FILE);
    std::fs::remove_file(&path).unwrap();
    KeyFile::new(
        &KeySet::single(1, MasterKey::from_bytes(*f.old_mk.expose())),
        TEST_PASSWORD,
        Argon2Params::MIN,
    )
    .unwrap()
    .save_new(&path)
    .unwrap();
    // A later rotation starts again and finishes.
    finish_and_check(&f);
}

#[test]
fn recover_after_a_crash_before_the_last_key_file_write_needs_only_the_new_key() {
    let f = small_fx(|fs| write_file(fs, "a.bin", b"a"));
    // Key file, three file steps, marker; the final key file write fails.
    let new_mk = stop_after_with_key(&f.dir, 5);
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);
    let vault = open_with_master_key(&f.dir, &new_mk).unwrap();
    assert_eq!(vault.marker.epoch, 2);
    assert!(!rotation_unfinished(&vault).unwrap());
    let path = f.dir.join(KEY_FILE);
    std::fs::remove_file(&path).unwrap();
    KeyFile::new(
        &KeySet::single(2, MasterKey::from_bytes(*new_mk.expose())),
        TEST_PASSWORD,
        Argon2Params::MIN,
    )
    .unwrap()
    .save_new(&path)
    .unwrap();
    assert_rotated(&f, 2, &f.model);
}

/// A crash in the old order of a mount rename of a short directory to a
/// long name: the directory got its long real name, but no `.cd-name`.
fn hide_short_dir_as_long_entry(f: &Fx) -> String {
    let real = std::fs::read_dir(&f.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.join(".cd-dir").is_file())
        .unwrap();
    let entry = format!("{LONG_PREFIX}{}", "B".repeat(43));
    std::fs::rename(&real, f.dir.join(&entry)).unwrap();
    entry
}

#[test]
fn final_check_refuses_a_long_entry_without_name_that_holds_data() {
    let f = small_fx(|fs| {
        fs.mkdir(&p("d"), 0o755).unwrap();
        write_file(fs, "d/in.txt", b"in");
        write_file(fs, "top.txt", b"top");
    });
    let entry = hide_short_dir_as_long_entry(&f);
    match rotate(&f.dir) {
        Err(e @ Error::RotationNotFinished { left: 1, .. }) => {
            assert!(e.to_string().contains(&entry), "{e}");
        }
        r => panic!("{:?}", r.err()),
    }
    // The old key stays, so the hidden entry can still be repaired.
    assert_eq!(key_set_epochs(&f.dir), vec![1, 2]);
    let (vault, _) = unlock_vault(&f.dir, None, TEST_PASSWORD).unwrap();
    assert_eq!(vault.marker.epoch, 1);
    assert!(f.dir.join(&entry).join(".cd-dir").is_file());
}

#[test]
fn long_entry_without_name_and_without_data_does_not_block() {
    let f = small_fx(|fs| write_file(fs, "top.txt", b"top"));
    let entry = f.dir.join(format!("{LONG_PREFIX}{}", "B".repeat(43)));
    std::fs::create_dir(&entry).unwrap();
    std::fs::write(entry.join("junk"), b"not ours").unwrap();
    rotate(&f.dir).unwrap();
}
