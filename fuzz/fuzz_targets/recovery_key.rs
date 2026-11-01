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

//! `decode_recovery_key` never panics. A decoded key encodes to a string
//! that decodes to the same key.

#![no_main]

use crypto_drive_core::recovery::{decode_recovery_key, encode_recovery_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Ok(key) = decode_recovery_key(text) {
        let encoded = encode_recovery_key(&key);
        let again = decode_recovery_key(&encoded).expect("own output must decode");
        assert_eq!(again.expose(), key.expose());
    }
});
