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

//! On macOS, src/macos_mount.rs links libfuse 2 from macFUSE itself
//! (`#[link(name = "fuse")]`). The linker does not search /usr/local/lib by
//! default, so add it (or FUSE_LIB_DIR, if set) to the search path.

fn main() {
    println!("cargo::rerun-if-env-changed=FUSE_LIB_DIR");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        let dir = std::env::var("FUSE_LIB_DIR").unwrap_or_else(|_| "/usr/local/lib".to_string());
        println!("cargo::rustc-link-search=native={dir}");
    }
}
