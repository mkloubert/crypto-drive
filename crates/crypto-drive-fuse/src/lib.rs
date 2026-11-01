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

//! FUSE adapter: maps kernel requests to the path based core `CryptoFs`.

mod adapter;
mod errno;
mod inodes;
mod macos_mount;
mod mount;
mod xattrs;

pub use adapter::FuseFs;
pub use errno::to_errno;
pub use inodes::InodeTable;
pub use mount::{MountRequest, StopReason, mount_and_wait, mount_options, unmount_command};
