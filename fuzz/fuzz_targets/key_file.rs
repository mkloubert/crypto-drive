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

//! `KeyFile::from_bytes` never panics. A parsed file serializes and parses
//! again to the same bytes. No Argon2 run (too slow).

#![no_main]

use crypto_drive_core::keyfile::KeyFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = KeyFile::from_bytes(data) {
        let bytes = file.to_bytes();
        let again = KeyFile::from_bytes(&bytes).expect("own output must parse");
        assert_eq!(again.to_bytes(), bytes);
    }
});
