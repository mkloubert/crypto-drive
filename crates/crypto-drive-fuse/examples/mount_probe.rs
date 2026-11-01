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

//! Diagnostic tool: tries to mount an empty FUSE file system with different
//! mount options and mount point places, and prints what works.
//!
//! Run: `cargo run -p crypto-drive-fuse --example mount_probe`
//! It never touches a vault. Each mount is unmounted again after one second.

use std::path::{Path, PathBuf};
use std::time::Duration;

use fuser::{Config, Filesystem, MountOption};

/// A file system that answers every request with the fuser defaults.
struct Empty;

impl Filesystem for Empty {}

const OPTION_SETS: &[&[&str]] = &[
    &[],
    &["fsname=crypto-drive"],
    &["default_permissions"],
    &["noappledouble"],
    &["volname=probe"],
    &[
        "fsname=crypto-drive",
        "default_permissions",
        "noappledouble",
        "volname=probe",
    ],
];

fn try_mount(base: &Path, index: usize, options: &[&str]) {
    let mountpoint = base.join(format!("mp-{index}"));
    if let Err(e) = std::fs::create_dir_all(&mountpoint) {
        println!("  [{index}] cannot create {}: {e}", mountpoint.display());
        return;
    }
    let mut config = Config::default();
    config.mount_options = options
        .iter()
        .map(|o| MountOption::CUSTOM((*o).to_string()))
        .collect();
    config.n_threads = Some(1);
    let shown = if options.is_empty() {
        "(no options)".to_string()
    } else {
        options.join(",")
    };
    match fuser::spawn_mount(Empty, &mountpoint, &config) {
        Ok(session) => {
            println!("  [{index}] OK    {shown}");
            std::thread::sleep(Duration::from_secs(1));
            drop(session);
        }
        Err(e) => println!("  [{index}] ERROR {shown}: {e} (kind {:?})", e.kind()),
    }
    let _ = std::fs::remove_dir(&mountpoint);
}

fn main() {
    let tmp = std::env::temp_dir().join("cd-probe");
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cd-probe");
    for base in [tmp, home] {
        println!("mount points under {}", base.display());
        for (index, options) in OPTION_SETS.iter().enumerate() {
            try_mount(&base, index, options);
        }
        let _ = std::fs::remove_dir(&base);
    }
}
