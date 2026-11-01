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

//! `NameCipher::decrypt` never panics on any text. For a valid clear name,
//! `decrypt(encrypt(x))` gives the entry id and the NFC form of `x`.

#![no_main]

use crypto_drive_core::keys::MasterKey;
use crypto_drive_core::names::{NameCipher, validate_name};
use libfuzzer_sys::fuzz_target;
use unicode_normalization::UnicodeNormalization;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    dir_id: [u8; 16],
    entry_id: [u8; 16],
    text: String,
}

fuzz_target!(|input: Input| {
    let sub = MasterKey::from_bytes([7; 32]).derive(&[2; 16], 1);
    let cipher = NameCipher::new(sub.names());
    let _ = cipher.decrypt(&input.dir_id, &input.text);

    // Keep the name short, so that its NFC form is still within the limit.
    if input.text.len() <= 300 && validate_name(&input.text).is_ok() {
        let encoded = cipher
            .encrypt(&input.dir_id, &input.entry_id, &input.text)
            .expect("a valid short name must encrypt");
        let (id, name) = cipher
            .decrypt(&input.dir_id, &encoded)
            .expect("own output must decrypt");
        assert_eq!(id, input.entry_id);
        let nfc: String = input.text.nfc().collect();
        assert_eq!(name, nfc);
        let encoded2 = cipher
            .encrypt(&input.dir_id, &input.entry_id, &name)
            .expect("an NFC name must encrypt");
        assert_eq!(encoded2, encoded);
    }
});
