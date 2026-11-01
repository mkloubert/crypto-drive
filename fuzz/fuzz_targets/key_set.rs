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

//! `KeySet::decode` never panics and accepts only 1 or 2 keys with strictly
//! ascending epochs above 0.

#![no_main]

use crypto_drive_core::keys::KeySet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(set) = KeySet::decode(data) {
        let epochs = set.epochs();
        assert!(epochs.len() == 1 || epochs.len() == 2);
        assert!(epochs[0] > 0);
        assert!(epochs.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(set.write_epoch(), *epochs.last().unwrap());
        assert_eq!(&set.encode()[..], data);
    }
});
