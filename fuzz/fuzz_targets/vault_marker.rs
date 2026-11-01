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

//! `parse_unverified` and `verify` never panic. A parsed marker serializes
//! back to the same bytes (the tag is checked with `verify`).

#![no_main]

use crypto_drive_core::keys::MasterKey;
use crypto_drive_core::vault::VaultMarker;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let sub = MasterKey::from_bytes([7; 32]).derive(&[2; 16], 1);
    let check = sub.check();
    let verified = VaultMarker::verify(data, check);
    if let Ok(marker) = VaultMarker::parse_unverified(data) {
        let bytes = marker.to_bytes(check);
        // The body (without the tag) must be identical.
        assert_eq!(&bytes[..34], &data[..34]);
        if verified.is_ok() {
            assert_eq!(&bytes[..], data);
        }
    }
});
