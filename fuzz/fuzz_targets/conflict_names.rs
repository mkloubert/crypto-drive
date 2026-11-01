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

//! The conflict name helpers never panic. Every candidate prefix holds only
//! Base64 characters and is at least `MIN_ENCODED_LEN` long.

#![no_main]

use crypto_drive_core::conflict::{
    MIN_ENCODED_LEN, conflict_display_name, long_candidate, rotation_conflict_name,
    short_candidates,
};
use crypto_drive_core::names::is_b64_char;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    for (prefix, suffix) in short_candidates(text) {
        assert!(prefix.len() >= MIN_ENCODED_LEN);
        assert!(prefix.chars().all(is_b64_char));
        assert_eq!(format!("{prefix}{suffix}"), text);
    }
    if let Some((entry, suffix)) = long_candidate(text) {
        assert_eq!(format!("{entry}{suffix}"), text);
        let hash = entry.strip_prefix(".cd-cdl").expect("long prefix");
        assert_eq!(hash.chars().count(), 43);
        assert!(hash.chars().all(is_b64_char));
    }
    let _ = conflict_display_name(text, 1);
    let _ = conflict_display_name(text, u32::MAX);
    let _ = rotation_conflict_name(text, 1);
    let _ = rotation_conflict_name(text, u32::MAX);
});
