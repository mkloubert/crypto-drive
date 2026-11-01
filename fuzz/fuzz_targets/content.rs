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

//! The content functions never panic. `stage(L) >= L` and `stage` grows with
//! `L`. A sealed chunk opens again to the same bytes.

#![no_main]

use crypto_drive_core::content::{
    CHUNK_SIZE, ChunkCipher, FileHeader, ciphertext_size, open_size, plaintext_size, seal_size,
    stage,
};
use crypto_drive_core::keys::{MasterKey, derive_size_key};
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    n: u64,
    m: u64,
}

fuzz_target!(|input: Input| {
    let Input { data, n, m } = input;
    let sub = MasterKey::from_bytes([7; 32]).derive(&[2; 16], 1);

    // Sizes.
    assert!(stage(n) >= n);
    assert!(stage(n) <= stage(n.saturating_add(1)));
    let (lo, hi) = (n.min(m), n.max(m));
    assert!(stage(lo) <= stage(hi));
    if let Ok(plain) = plaintext_size(n) {
        assert_eq!(ciphertext_size(plain, false), n);
    }
    let _ = ciphertext_size(n, true);
    let _ = ciphertext_size(n, false);

    // Header and size block. Bad headers fall back to a fixed one.
    let parsed = FileHeader::parse(&data);
    if let Ok(h) = &parsed {
        assert_eq!(h.to_bytes()[..], data[..53]);
    }
    let header = parsed.unwrap_or(FileHeader {
        epoch: 1,
        file_nonce: [3; 32],
        file_id: [9; 16],
    });
    let header_bytes = header.to_bytes();
    let size_key = derive_size_key(sub.content(), &header.file_nonce, &header.file_id);
    let _ = open_size(size_key.expose(), &header_bytes, &data);
    if let Some(block) = data.get(53..) {
        let _ = open_size(size_key.expose(), &header_bytes, block);
    }
    let block = seal_size(size_key.expose(), &header_bytes, n).expect("seal size");
    assert_eq!(
        open_size(size_key.expose(), &header_bytes, &block).ok(),
        Some(n)
    );

    // Chunks.
    let cipher = ChunkCipher::new(sub.content(), &header);
    let is_last = n & 1 == 1;
    let _ = cipher.open(n, is_last, &data);
    let plain = &data[..data.len().min(CHUNK_SIZE as usize)];
    let sealed = cipher.seal(n, is_last, plain).expect("seal chunk");
    assert_eq!(
        cipher.open(n, is_last, &sealed).expect("open own chunk"),
        plain
    );
});
