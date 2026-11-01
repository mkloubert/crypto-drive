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

//! Model test (spec 9): random operation sequences run against the core and
//! against a simple in-memory model. Both must give the same results, also
//! after the vault is closed and opened again.

use crypto_drive_core::Error;
use crypto_drive_core::fs::{CryptoFs, FileKind, VPath};
use crypto_drive_core::keys::MasterKey;
use crypto_drive_core::testutil::test_vault_opts;
use crypto_drive_core::vault::open_with_master_key;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// With `max_name_length` 64 the 34 character name gives a long entry; the
/// others are short.
const DIRS: [&str; 3] = ["Ördner", "Verzeichnis-mit-einem-langen-Namen", "Ördner/sub"];

/// The clear paths of the files. The 150 character name gives a long entry.
static FILES: LazyLock<[String; 4]> = LazyLock::new(|| {
    [
        "a.txt".to_owned(),
        "Größe.md".to_owned(),
        "Ördner/日本語 ファイル 🧾".to_owned(),
        format!("{}/{}.txt", DIRS[1], "x".repeat(146)),
    ]
});

/// Files first, then directories; used by `Rename`.
fn any_path(i: usize) -> String {
    if i < FILES.len() {
        FILES[i].clone()
    } else {
        DIRS[i - FILES.len()].to_owned()
    }
}

#[derive(Clone, Debug)]
enum Op {
    Write {
        file: usize,
        offset: u64,
        len: usize,
        seed: u8,
    },
    Read {
        file: usize,
    },
    Truncate {
        file: usize,
        len: u64,
    },
    Mkdir {
        dir: usize,
    },
    Rename {
        from: usize,
        to: usize,
    },
    Unlink {
        file: usize,
    },
    Rmdir {
        dir: usize,
    },
    Reopen,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..4usize, 0..300_000u64, 0..70_000usize, any::<u8>()).prop_map(
            |(file, offset, len, seed)| Op::Write { file, offset, len, seed }
        ),
        2 => (0..4usize).prop_map(|file| Op::Read { file }),
        1 => (0..4usize, 0..300_000u64).prop_map(|(file, len)| Op::Truncate { file, len }),
        3 => (0..3usize).prop_map(|dir| Op::Mkdir { dir }),
        2 => (0..7usize, 0..7usize).prop_map(|(from, to)| Op::Rename { from, to }),
        1 => (0..4usize).prop_map(|file| Op::Unlink { file }),
        1 => (0..3usize).prop_map(|dir| Op::Rmdir { dir }),
        1 => Just(Op::Reopen),
    ]
}

/// The error kinds both sides may give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    NotFound,
    AlreadyExists,
    NotEmpty,
    IsADirectory,
    NotADirectory,
    InvalidArgument,
    /// Any other error; never expected from the model.
    Other,
}

fn kind(e: &Error) -> Kind {
    match e {
        Error::NotFound => Kind::NotFound,
        Error::AlreadyExists => Kind::AlreadyExists,
        Error::NotEmpty => Kind::NotEmpty,
        Error::IsADirectory => Kind::IsADirectory,
        Error::NotADirectory => Kind::NotADirectory,
        Error::InvalidArgument => Kind::InvalidArgument,
        _ => Kind::Other,
    }
}

/// The result of one operation: read bytes or nothing, or an error kind.
type Outcome = Result<Option<Vec<u8>>, Kind>;

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

fn is_under(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

/// Clear files and directories. Paths are NFC and relative to the root.
#[derive(Default)]
struct Model {
    files: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
}

impl Model {
    /// Checks that every parent of `path` is an existing directory.
    fn check_parents(&self, path: &str) -> Result<(), Kind> {
        let mut end = 0;
        while let Some(i) = path[end..].find('/') {
            let dir = &path[..end + i];
            if self.files.contains_key(dir) {
                return Err(Kind::NotADirectory);
            }
            if !self.dirs.contains(dir) {
                return Err(Kind::NotFound);
            }
            end += i + 1;
        }
        Ok(())
    }

    fn is_empty_dir(&self, dir: &str) -> bool {
        !self.files.keys().any(|f| is_under(f, dir)) && !self.dirs.iter().any(|d| is_under(d, dir))
    }

    /// The file at `path`, or the error for a missing file or a directory.
    fn file(&mut self, path: &str) -> Result<&mut Vec<u8>, Kind> {
        self.check_parents(path)?;
        if self.dirs.contains(path) {
            return Err(Kind::IsADirectory);
        }
        self.files.get_mut(path).ok_or(Kind::NotFound)
    }

    fn apply(&mut self, op: &Op) -> Outcome {
        match *op {
            Op::Write {
                file,
                offset,
                len,
                seed,
            } => {
                let path = &FILES[file];
                self.check_parents(path)?;
                if self.dirs.contains(path) {
                    return Err(Kind::IsADirectory);
                }
                let content = self.files.entry(path.clone()).or_default();
                if len > 0 {
                    let start = offset as usize;
                    if content.len() < start + len {
                        content.resize(start + len, 0);
                    }
                    content[start..start + len].copy_from_slice(&data(len, seed));
                }
                Ok(None)
            }
            Op::Read { file } => Ok(Some(self.file(&FILES[file])?.clone())),
            Op::Truncate { file, len } => {
                self.file(&FILES[file])?.resize(len as usize, 0);
                Ok(None)
            }
            Op::Mkdir { dir } => {
                let path = DIRS[dir];
                self.check_parents(path)?;
                if self.dirs.contains(path) || self.files.contains_key(path) {
                    return Err(Kind::AlreadyExists);
                }
                self.dirs.insert(path.to_owned());
                Ok(None)
            }
            Op::Rename { from, to } => self.rename(&any_path(from), &any_path(to)),
            Op::Unlink { file } => {
                let path = &FILES[file];
                self.file(path)?;
                self.files.remove(path);
                Ok(None)
            }
            Op::Rmdir { dir } => {
                let path = DIRS[dir];
                self.check_parents(path)?;
                if self.files.contains_key(path) {
                    return Err(Kind::NotADirectory);
                }
                if !self.dirs.contains(path) {
                    return Err(Kind::NotFound);
                }
                if !self.is_empty_dir(path) {
                    return Err(Kind::NotEmpty);
                }
                self.dirs.remove(path);
                Ok(None)
            }
            Op::Reopen => Ok(None),
        }
    }

    /// The same order of checks as `CryptoFs::rename`.
    fn rename(&mut self, from: &str, to: &str) -> Outcome {
        if from == to {
            return Ok(None);
        }
        if is_under(to, from) {
            return Err(Kind::InvalidArgument);
        }
        self.check_parents(from)?;
        let from_is_dir = self.dirs.contains(from);
        if !from_is_dir && !self.files.contains_key(from) {
            return Err(Kind::NotFound);
        }
        self.check_parents(to)?;
        let to_is_dir = self.dirs.contains(to);
        let to_is_file = self.files.contains_key(to);
        match (from_is_dir, to_is_dir, to_is_file) {
            (true, false, true) => return Err(Kind::NotADirectory),
            (false, true, _) => return Err(Kind::IsADirectory),
            (true, true, _) if !self.is_empty_dir(to) => return Err(Kind::NotEmpty),
            _ => {}
        }
        if from_is_dir {
            self.dirs.remove(to);
            let moved_dirs: Vec<String> = self
                .dirs
                .iter()
                .filter(|d| *d == from || is_under(d, from))
                .cloned()
                .collect();
            for d in moved_dirs {
                self.dirs.remove(&d);
                self.dirs.insert(format!("{to}{}", &d[from.len()..]));
            }
            let moved_files: Vec<String> = self
                .files
                .keys()
                .filter(|f| is_under(f, from))
                .cloned()
                .collect();
            for f in moved_files {
                let content = self.files.remove(&f).unwrap_or_default();
                self.files
                    .insert(format!("{to}{}", &f[from.len()..]), content);
            }
        } else {
            let content = self.files.remove(from).unwrap_or_default();
            self.files.insert(to.to_owned(), content);
        }
        Ok(None)
    }

    /// Clear names and kinds directly in `dir` ("" is the root).
    fn listing(&self, dir: &str) -> Vec<(String, FileKind)> {
        let child = |p: &String| -> Option<String> {
            let rest = if dir.is_empty() {
                p.as_str()
            } else {
                p.strip_prefix(dir)?.strip_prefix('/')?
            };
            (!rest.contains('/')).then(|| rest.to_owned())
        };
        let mut v: Vec<(String, FileKind)> = self
            .files
            .keys()
            .filter_map(|p| child(p).map(|n| (n, FileKind::File)))
            .chain(
                self.dirs
                    .iter()
                    .filter_map(|p| child(p).map(|n| (n, FileKind::Directory))),
            )
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

fn vp(s: &str) -> VPath {
    VPath::parse(s).unwrap()
}

fn outcome<T>(r: Result<T, Error>) -> Result<T, Kind> {
    r.map_err(|e| kind(&e))
}

struct Real {
    root: PathBuf,
    mk: MasterKey,
    fs: Option<CryptoFs>,
}

impl Real {
    fn open(root: &Path, mk: MasterKey) -> Real {
        let fs = CryptoFs::new(open_with_master_key(root, &mk).unwrap()).unwrap();
        Real {
            root: root.to_path_buf(),
            mk,
            fs: Some(fs),
        }
    }

    fn fs(&self) -> &CryptoFs {
        self.fs.as_ref().unwrap()
    }

    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<(), Error> {
        let fs = self.fs();
        let h = match fs.open(&vp(path), true, false) {
            Ok(h) => h,
            Err(Error::NotFound) => fs.create(&vp(path), 0o644)?.1,
            Err(e) => return Err(e),
        };
        let written = fs.write(h, offset, data);
        fs.release(h)?;
        assert_eq!(written? as usize, data.len());
        Ok(())
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        let fs = self.fs();
        let h = fs.open(&vp(path), false, false)?;
        let data = fs.read(h, 0, 1 << 20);
        fs.release(h)?;
        data
    }

    fn apply(&mut self, op: &Op) -> Outcome {
        match *op {
            Op::Write {
                file,
                offset,
                len,
                seed,
            } => outcome(self.write(&FILES[file], offset, &data(len, seed))).map(|()| None),
            Op::Read { file } => outcome(self.read(&FILES[file])).map(Some),
            Op::Truncate { file, len } => {
                outcome(self.fs().truncate(&vp(&FILES[file]), len)).map(|()| None)
            }
            Op::Mkdir { dir } => outcome(self.fs().mkdir(&vp(DIRS[dir]), 0o755)).map(|_| None),
            Op::Rename { from, to } => {
                outcome(self.fs().rename(&vp(&any_path(from)), &vp(&any_path(to)))).map(|()| None)
            }
            Op::Unlink { file } => outcome(self.fs().unlink(&vp(&FILES[file]))).map(|()| None),
            Op::Rmdir { dir } => outcome(self.fs().rmdir(&vp(DIRS[dir]))).map(|()| None),
            Op::Reopen => {
                self.fs = None;
                let vault = open_with_master_key(&self.root, &self.mk).unwrap();
                self.fs = Some(CryptoFs::new(vault).unwrap());
                Ok(None)
            }
        }
    }

    fn listing(&self, dir: &str) -> Vec<(String, FileKind)> {
        let path = if dir.is_empty() {
            VPath::root()
        } else {
            vp(dir)
        };
        let mut v: Vec<(String, FileKind)> = self
            .fs()
            .readdir(&path)
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

fn run(ops: &[Op], pad_sizes: bool) -> Result<(), TestCaseError> {
    // Max name length 64, so that the 34 character name is a long entry.
    let (tmp, vault, mk) = test_vault_opts(64, pad_sizes);
    let root = vault.root_path.clone();
    drop(vault);
    let mut real = Real::open(&root, mk);
    let mut model = Model::default();
    for (step, op) in ops.iter().enumerate() {
        let expected = model.apply(op);
        let got = real.apply(op);
        prop_assert_eq!(&got, &expected, "step {} {:?}", step, op);
        // The whole tree must look the same after every step.
        let mut dirs: Vec<String> = model.dirs.iter().cloned().collect();
        dirs.push(String::new());
        for dir in dirs {
            prop_assert_eq!(
                real.listing(&dir),
                model.listing(&dir),
                "listing of {:?} after step {} {:?}",
                dir,
                step,
                op
            );
        }
    }
    // Every file reads back after the last step.
    for (path, content) in &model.files {
        prop_assert_eq!(&outcome(real.read(path)), &Ok(content.clone()), "{}", path);
    }
    drop(real);
    drop(tmp);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn core_matches_model(ops in prop::collection::vec(op(), 1..=40)) {
        run(&ops, false)?;
    }
}

// The same operations on a vault with size padding.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn core_matches_model_padded(ops in prop::collection::vec(op(), 1..=40)) {
        run(&ops, true)?;
    }
}
