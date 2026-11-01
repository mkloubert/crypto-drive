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

//! An arbitrary tree of real entries (also `.cd-*` names, broken and valid
//! encrypted names, overflow entries, broken and valid file contents) is
//! written into a fresh test vault. Then `check_vault`, `readdir` of every
//! reachable directory, `getattr` of every entry and a full read of every
//! file must not panic and must finish in time. Errors are fine.

#![no_main]

use arbitrary::Arbitrary;
use crypto_drive_core::check::check_vault;
use crypto_drive_core::content::{ChunkCipher, FileHeader, ciphertext_size, seal_size};
use crypto_drive_core::fs::{CryptoFs, FileKind, VPath};
use crypto_drive_core::keys::{DirId, EntryId, derive_size_key};
use crypto_drive_core::names::{BackingName, NameKeys, to_backing_name};
use crypto_drive_core::vault::{CONTENT_FILE, DIR_FILE, NAME_FILE};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

mod common;
use common::{MAX_NAME_LENGTH, fresh_vault};

const MAX_ENTRIES: usize = 32;
const MAX_BYTES: usize = 4096;

/// Real names the core treats in a special way.
const CONTROL_NAMES: [&str; 12] = [
    ".cd-dir",
    ".cd-name",
    ".cd-content",
    ".cd-vault",
    ".cd-key",
    ".cd-dir.tmp",
    ".cd-dir (1)",
    ".cd-dir-conflict",
    ".cd-cdl",
    ".cd-cdlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ".cd-rot.tmp",
    ".cd-x",
];

#[derive(Arbitrary, Debug)]
enum Name {
    /// Any text as the real name.
    Raw(String),
    /// One of `CONTROL_NAMES`.
    Control(u8),
    /// A correctly encrypted name in the parent directory. If it is too
    /// long, or if `force_long` is set, it becomes an overflow entry.
    Encrypted {
        clear: String,
        entry_id: EntryId,
        force_long: bool,
    },
}

#[derive(Arbitrary, Debug)]
enum Content {
    /// Any bytes.
    Raw(Vec<u8>),
    /// A correctly sealed file of one chunk. `bind` uses the entry id of
    /// the name as the file id, otherwise `file_id` is used.
    Sealed {
        plain: Vec<u8>,
        bind: bool,
        file_id: EntryId,
        /// Bytes appended after the sealed file.
        tail: Vec<u8>,
    },
}

#[derive(Arbitrary, Debug)]
enum Kind {
    /// A directory. With `dir_id`, a `.cd-dir` file with it is written.
    Dir {
        dir_id: Option<DirId>,
    },
    File(Content),
}

#[derive(Arbitrary, Debug)]
struct Entry {
    /// Index into the directories made so far (0 is the root).
    parent: u8,
    name: Name,
    kind: Kind,
}

#[derive(Arbitrary, Debug)]
struct Input {
    padded: bool,
    entries: Vec<Entry>,
}

/// A real directory that was made, and its id if known.
struct Made {
    real: PathBuf,
    id: Option<DirId>,
}

/// Turns any text into a name the host file system accepts, if possible.
fn host_name(s: &str) -> Option<String> {
    let s: String = s.chars().filter(|c| *c != '/' && *c != '\0').collect();
    let ok = !s.is_empty() && s != "." && s != ".." && s.len() <= 255;
    ok.then_some(s)
}

fn sealed_file(
    vault: &crypto_drive_core::vault::UnlockedVault,
    padded: bool,
    plain: &[u8],
    file_id: EntryId,
    tail: &[u8],
) -> Option<Vec<u8>> {
    let epoch = vault.keys.write_epoch();
    let content_key = vault.keys.get(epoch)?.content();
    let header = FileHeader::random(epoch, file_id).ok()?;
    let header_bytes = header.to_bytes();
    let mut out = header_bytes.to_vec();
    if padded {
        let size_key = derive_size_key(content_key, &header.file_nonce, &header.file_id);
        let block = seal_size(size_key.expose(), &header_bytes, plain.len() as u64).ok()?;
        out.extend_from_slice(&block);
    }
    let cipher = ChunkCipher::new(content_key, &header);
    out.extend_from_slice(&cipher.seal(0, true, plain).ok()?);
    if padded {
        out.resize(ciphertext_size(plain.len() as u64, true) as usize, 0);
    }
    out.extend_from_slice(tail);
    Some(out)
}

fn build(input: &Input) -> Option<(tempfile::TempDir, CryptoFs)> {
    let (tmp, vault, _mk) = fresh_vault(input.padded);
    let names = NameKeys::new(&vault.keys);
    let mut dirs = vec![Made {
        real: vault.root_path.clone(),
        id: Some(vault.marker.vault_id),
    }];
    for entry in input.entries.iter().take(MAX_ENTRIES) {
        let parent = &dirs[usize::from(entry.parent) % dirs.len()];
        let parent_real = parent.real.clone();
        let parent_id = parent.id.unwrap_or([0; 16]);
        // The real path of the entry, and the path of its `.cd-name` if it
        // is an overflow entry.
        let (real, entry_id, long) = match &entry.name {
            Name::Raw(s) => {
                let Some(name) = host_name(s) else {
                    continue;
                };
                (parent_real.join(name), None, None)
            }
            Name::Control(i) => {
                let name = CONTROL_NAMES[usize::from(*i) % CONTROL_NAMES.len()];
                (parent_real.join(name), None, None)
            }
            Name::Encrypted {
                clear,
                entry_id,
                force_long,
            } => {
                let Ok(encoded) = names.encrypt_write(&parent_id, entry_id, clear) else {
                    continue;
                };
                let max = if *force_long { 0 } else { MAX_NAME_LENGTH };
                match to_backing_name(encoded, max) {
                    BackingName::Short(s) => (parent_real.join(s), Some(*entry_id), None),
                    BackingName::Long { entry, full } => {
                        (parent_real.join(entry), Some(*entry_id), Some(full))
                    }
                }
            }
        };
        if real.exists() {
            continue;
        }
        // Write errors (for example a name the host does not accept) only
        // skip the entry.
        if let Some(full) = &long {
            if std::fs::create_dir(&real).is_err() {
                continue;
            }
            let _ = std::fs::write(real.join(NAME_FILE), full);
        }
        match &entry.kind {
            Kind::Dir { dir_id } => {
                if long.is_none() && std::fs::create_dir(&real).is_err() {
                    continue;
                }
                if let Some(id) = dir_id {
                    let _ = std::fs::write(real.join(DIR_FILE), id);
                }
                dirs.push(Made { real, id: *dir_id });
            }
            Kind::File(content) => {
                let bytes = match content {
                    Content::Raw(b) => b[..b.len().min(MAX_BYTES)].to_vec(),
                    Content::Sealed {
                        plain,
                        bind,
                        file_id,
                        tail,
                    } => {
                        let id = if *bind {
                            entry_id.unwrap_or(*file_id)
                        } else {
                            *file_id
                        };
                        let plain = &plain[..plain.len().min(MAX_BYTES)];
                        let tail = &tail[..tail.len().min(MAX_BYTES)];
                        let Some(b) = sealed_file(&vault, input.padded, plain, id, tail) else {
                            continue;
                        };
                        b
                    }
                };
                let path = if long.is_some() {
                    real.join(CONTENT_FILE)
                } else {
                    real
                };
                let _ = std::fs::write(path, bytes);
            }
        }
    }
    // Errors are fine; only panics and hangs count.
    let _ = check_vault(&vault);
    let fs = CryptoFs::new(vault).ok()?;
    Some((tmp, fs))
}

/// Reads a whole file through the drive, in steps of one chunk.
fn read_all(fs: &CryptoFs, path: &VPath) {
    let Ok(h) = fs.open(path, false, false) else {
        return;
    };
    let mut offset = 0u64;
    // A file of the tree holds at most a few KiB; stop after 64 steps.
    for _ in 0..64 {
        match fs.read(h, offset, 65536) {
            Ok(data) if !data.is_empty() => offset += data.len() as u64,
            _ => break,
        }
    }
    let _ = fs.release(h);
}

fn walk(fs: &CryptoFs) {
    let mut todo = vec![VPath::root()];
    // The real tree is finite, and every directory is listed once.
    while let Some(dir) = todo.pop() {
        let _ = fs.getattr(&dir);
        let Ok(entries) = fs.readdir(&dir) else {
            continue;
        };
        for e in entries {
            let Ok(path) = dir.join(&e.name) else {
                continue;
            };
            let _ = fs.getattr(&path);
            match e.kind {
                FileKind::Directory => todo.push(path),
                FileKind::File => read_all(fs, &path),
            }
        }
    }
}

fuzz_target!(|input: Input| {
    if let Some((tmp, fs)) = build(&input) {
        walk(&fs);
        drop(fs);
        drop(tmp);
    }
});
