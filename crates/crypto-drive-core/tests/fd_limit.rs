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

//! The directory cache must fit the open-file limit of the process
//! (review 2026-11-01, NEXT-STEPS item 1). Each cached directory holds an
//! open file descriptor. With a low soft limit (macOS terminals often
//! start with 256) a full cache made every later open fail with EMFILE.
//!
//! This test lowers the limit of its own process, so it lives in its own
//! test binary with no other tests.

use crypto_drive_core::fs::{CryptoFs, VPath};
use crypto_drive_core::testutil::test_vault;
use nix::sys::resource::{Resource, getrlimit, setrlimit};

/// The soft limit for this test, far below the old cache size of 1024.
const LOW_LIMIT: u64 = 128;
/// More directories than the limit allows open at once.
const DIRS: usize = 300;

fn path(s: &str) -> VPath {
    VPath::parse(s).unwrap()
}

#[test]
fn visiting_many_directories_stays_within_the_open_file_limit() {
    let (_soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    setrlimit(Resource::RLIMIT_NOFILE, LOW_LIMIT.min(hard), hard).unwrap();

    let (_tmp, vault, _mk) = test_vault();
    let fs = CryptoFs::new(vault).unwrap();
    for i in 0..DIRS {
        fs.mkdir(&path(&format!("/d{i}")), 0o755).unwrap();
    }
    // A listing of each directory puts its state (and its fd) in the cache.
    for i in 0..DIRS {
        fs.readdir(&path(&format!("/d{i}")))
            .unwrap_or_else(|e| panic!("readdir of directory {i}: {e}"));
    }
    // Files can still be created and written after that.
    let (_, fh) = fs.create(&path("/d0/file.txt"), 0o644).unwrap();
    fs.write(fh, 0, b"hello").unwrap();
    fs.release(fh).unwrap();
}
