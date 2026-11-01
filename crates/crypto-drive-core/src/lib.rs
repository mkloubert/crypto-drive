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

//! Core library of crypto-drive.

pub mod backing;
pub mod check;
pub mod conflict;
pub mod content;
pub mod error;
pub mod file;
pub mod fs;
pub mod keyfile;
pub mod keys;
pub mod names;
pub mod recovery;
pub mod rotate;
pub mod secret;
#[cfg(feature = "test-util")]
pub mod testutil;
pub mod vault;

pub use error::{Error, Result};
