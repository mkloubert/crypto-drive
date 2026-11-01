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

//! Encrypted file content format (hardening spec sections 5 to 5.2).
//!
//! A file is a 53 byte header followed by chunks. Padded files have a 36
//! byte size block after the header and are rounded up to a stage size. Each
//! chunk holds up to `CHUNK_SIZE` clear bytes and is sealed with AES-256-GCM.
//! The chunk index and the "last chunk" flag are part of the associated data.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};

use crate::error::{Error, Result};
use crate::keys::{EntryId, Epoch, derive_file_key};
use crate::secret::random_bytes;

/// Clear size of a full chunk.
pub const CHUNK_SIZE: u64 = 65536;
/// Size of the file header.
pub const HEADER_LEN: u64 = 53;
/// Size of the size block of a padded file.
pub const SIZE_BLOCK_LEN: u64 = 36;
/// Header plus size block.
pub const PADDED_HEADER_LEN: u64 = HEADER_LEN + SIZE_BLOCK_LEN;
/// Nonce (12 bytes) plus tag (16 bytes) of each chunk.
pub const CHUNK_OVERHEAD: u64 = 28;
/// Size of an empty file without padding: header plus one empty chunk.
pub const EMPTY_FILE_LEN: u64 = HEADER_LEN + CHUNK_OVERHEAD;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const FULL_SEALED: u64 = CHUNK_SIZE + CHUNK_OVERHEAD;
const STAGE_MIN: u64 = 4096;
const STAGE_STEP: u64 = 1_048_576;

fn invalid(what: &str) -> Error {
    Error::InvalidFormat {
        what: what.to_string(),
    }
}

/// Number of chunks for a clear size. An empty file has one empty chunk.
pub fn chunk_count(plain_len: u64) -> u64 {
    plain_len.div_ceil(CHUNK_SIZE).max(1)
}

/// Size of the header (with the size block if the file is padded).
pub fn header_len(padded: bool) -> u64 {
    if padded {
        PADDED_HEADER_LEN
    } else {
        HEADER_LEN
    }
}

/// Rounds a size up to its stage: 4096, then powers of two up to 1 MiB, then
/// multiples of 1 MiB. Saturates at `u64::MAX`.
pub fn stage(len: u64) -> u64 {
    if len <= STAGE_MIN {
        STAGE_MIN
    } else if len <= STAGE_STEP {
        len.next_power_of_two()
    } else {
        len.div_ceil(STAGE_STEP).saturating_mul(STAGE_STEP)
    }
}

/// Size of the encrypted file for a clear size (saturates on overflow).
pub fn ciphertext_size(plain_len: u64, padded: bool) -> u64 {
    let used = chunk_count(plain_len)
        .saturating_mul(CHUNK_OVERHEAD)
        .saturating_add(plain_len)
        .saturating_add(header_len(padded));
    if padded { stage(used) } else { used }
}

/// Clear size for the size of an encrypted file without padding.
pub fn plaintext_size(cipher_len: u64) -> Result<u64> {
    if cipher_len < EMPTY_FILE_LEN {
        return Err(invalid("file size"));
    }
    let body = cipher_len - HEADER_LEN;
    let n = body.div_ceil(FULL_SEALED);
    let last = body - (n - 1) * FULL_SEALED;
    if last < CHUNK_OVERHEAD || (last == CHUNK_OVERHEAD && n > 1) {
        return Err(invalid("file size"));
    }
    n.checked_mul(CHUNK_OVERHEAD)
        .and_then(|o| body.checked_sub(o))
        .ok_or_else(|| invalid("file size"))
}

/// Offset of chunk `index` in the encrypted file (saturates on overflow).
pub fn chunk_offset(index: u64, padded: bool) -> u64 {
    index
        .saturating_mul(FULL_SEALED)
        .saturating_add(header_len(padded))
}

/// The file header: epoch, random per-file nonce and file id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub epoch: Epoch,
    pub file_nonce: [u8; 32],
    pub file_id: EntryId,
}

impl FileHeader {
    /// Creates a header with a new random file nonce.
    pub fn random(epoch: Epoch, file_id: EntryId) -> Result<Self> {
        Ok(Self {
            epoch,
            file_nonce: random_bytes::<32>()?,
            file_id,
        })
    }

    pub fn to_bytes(&self) -> [u8; 53] {
        let mut out = [0u8; 53];
        out[0] = VERSION;
        out[1..5].copy_from_slice(&self.epoch.to_le_bytes());
        out[5..37].copy_from_slice(&self.file_nonce);
        out[37..53].copy_from_slice(&self.file_id);
        out
    }

    /// Parses a header. At least 53 bytes are needed, extra bytes are ignored.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let Some(head) = b.get(..HEADER_LEN as usize) else {
            return Err(invalid("file header"));
        };
        if head[0] != VERSION {
            return Err(invalid("file header"));
        }
        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&head[1..5]);
        let mut file_nonce = [0u8; 32];
        file_nonce.copy_from_slice(&head[5..37]);
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&head[37..53]);
        Ok(Self {
            epoch: Epoch::from_le_bytes(epoch),
            file_nonce,
            file_id,
        })
    }
}

/// Seals the clear size into a 36 byte size block. The header bytes are the
/// associated data, so the block is bound to its file.
pub fn seal_size(size_key: &[u8; 32], header: &[u8; 53], plain_len: u64) -> Result<[u8; 36]> {
    let cipher = Aes256Gcm::new(size_key.into());
    let nonce = random_bytes::<NONCE_LEN>()?;
    let mut buf = plain_len.to_le_bytes().to_vec();
    cipher
        .encrypt_in_place(&nonce.into(), header, &mut buf)
        .map_err(|_| Error::InvalidArgument)?;
    let mut out = [0u8; 36];
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..].copy_from_slice(&buf);
    Ok(out)
}

/// Opens a size block. Fails with `AuthFailed` if anything differs.
pub fn open_size(size_key: &[u8; 32], header: &[u8; 53], block: &[u8]) -> Result<u64> {
    if block.len() as u64 != SIZE_BLOCK_LEN {
        return Err(invalid("size block"));
    }
    let cipher = Aes256Gcm::new(size_key.into());
    let (nonce, rest) = block.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let mut buf = rest.to_vec();
    cipher
        .decrypt_in_place(&nonce_arr.into(), header, &mut buf)
        .map_err(|_| Error::AuthFailed {
            what: "size block".to_string(),
        })?;
    let bytes: [u8; 8] = buf
        .as_slice()
        .try_into()
        .map_err(|_| invalid("size block"))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Seals and opens the chunks of one file with its file key.
pub struct ChunkCipher {
    cipher: Aes256Gcm,
}

fn chunk_ad(index: u64, is_last: bool) -> [u8; 9] {
    let mut ad = [0u8; 9];
    ad[..8].copy_from_slice(&index.to_be_bytes());
    ad[8] = u8::from(is_last);
    ad
}

impl ChunkCipher {
    pub fn new(content_key: &[u8; 32], header: &FileHeader) -> Self {
        let key = derive_file_key(content_key, &header.file_nonce, &header.file_id);
        Self {
            cipher: Aes256Gcm::new(key.expose().into()),
        }
    }

    /// Returns `nonce ‖ ciphertext ‖ tag` with a fresh random nonce.
    pub fn seal(&self, index: u64, is_last: bool, plain: &[u8]) -> Result<Vec<u8>> {
        if plain.len() as u64 > CHUNK_SIZE {
            return Err(Error::InvalidArgument);
        }
        let nonce = random_bytes::<NONCE_LEN>()?;
        let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let mut buf = out.split_off(NONCE_LEN);
        self.cipher
            .encrypt_in_place(&nonce.into(), &chunk_ad(index, is_last), &mut buf)
            .map_err(|_| Error::InvalidArgument)?;
        out.append(&mut buf);
        Ok(out)
    }

    /// Opens a sealed chunk. Fails with `AuthFailed` if anything differs.
    pub fn open(&self, index: u64, is_last: bool, sealed: &[u8]) -> Result<Vec<u8>> {
        if (sealed.len() as u64) < CHUNK_OVERHEAD || sealed.len() as u64 > FULL_SEALED {
            return Err(invalid("chunk size"));
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce);
        let mut buf = rest.to_vec();
        self.cipher
            .decrypt_in_place(&nonce_arr.into(), &chunk_ad(index, is_last), &mut buf)
            .map_err(|_| Error::AuthFailed {
                what: format!("chunk {index}"),
            })?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> FileHeader {
        FileHeader::random(1, [9; 16]).unwrap()
    }

    fn cipher(key: u8, header: &FileHeader) -> ChunkCipher {
        ChunkCipher::new(&[key; 32], header)
    }

    #[test]
    fn stage_table() {
        assert_eq!(stage(0), 4096);
        assert_eq!(stage(1), 4096);
        assert_eq!(stage(4096), 4096);
        assert_eq!(stage(4097), 8192);
        assert_eq!(stage(1_048_576), 1_048_576);
        assert_eq!(stage(1_048_577), 2_097_152);
        assert_eq!(stage(3_000_000), 3_145_728);
        assert_eq!(stage(u64::MAX), u64::MAX);
        let mut last = 0;
        for n in (0..200_000).step_by(997) {
            let s = stage(n);
            assert!(s >= last && s >= n);
            last = s;
        }
    }

    #[test]
    fn sizes_not_padded() {
        assert_eq!(ciphertext_size(0, false), 81);
        assert_eq!(ciphertext_size(1, false), 53 + 28 + 1);
        assert_eq!(ciphertext_size(65537, false), 53 + 2 * 28 + 65537);
        for n in [0, 1, 65535, 65536, 65537, 10 * 65536 + 7] {
            assert_eq!(plaintext_size(ciphertext_size(n, false)).unwrap(), n);
        }
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(65537), 2);
        assert_eq!(chunk_offset(0, false), 53);
        assert_eq!(chunk_offset(2, false), 53 + 2 * (65536 + 28));
    }

    #[test]
    fn sizes_padded() {
        assert_eq!(ciphertext_size(0, true), 4096);
        assert_eq!(ciphertext_size(5000, true), 8192);
        assert_eq!(chunk_offset(0, true), 89);
        assert_eq!(chunk_offset(1, true), 89 + 65536 + 28);
        assert_eq!(header_len(false), 53);
        assert_eq!(header_len(true), 89);
    }

    #[test]
    fn invalid_sizes() {
        for c in [0, 53, 80] {
            assert!(plaintext_size(c).is_err());
        }
        assert!(plaintext_size(53 + 65536 + 28 + 28).is_err());
        assert!(plaintext_size(53 + 65536 + 28 + 27).is_err());
    }

    #[test]
    fn max_size_does_not_panic() {
        if let Ok(p) = plaintext_size(u64::MAX) {
            assert!(p < u64::MAX);
        }
        for padded in [false, true] {
            let _ = ciphertext_size(u64::MAX, padded);
            let _ = chunk_offset(u64::MAX, padded);
        }
    }

    #[test]
    fn seal_open_round_trip_and_fresh_nonce() {
        let h = header();
        let c = cipher(1, &h);
        let a = c.seal(0, true, b"hello").unwrap();
        let b = c.seal(0, true, b"hello").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 5 + 28);
        assert_eq!(c.open(0, true, &a).unwrap(), b"hello");
        assert_eq!(c.open(0, true, &b).unwrap(), b"hello");
        let e = c.seal(0, true, b"").unwrap();
        assert_eq!(c.open(0, true, &e).unwrap(), b"");
    }

    #[test]
    fn index_and_last_flag_are_bound() {
        let h = header();
        let c = cipher(1, &h);
        let s = c.seal(3, false, b"data").unwrap();
        assert!(matches!(
            c.open(4, false, &s),
            Err(Error::AuthFailed { what }) if what == "chunk 4"
        ));
        assert!(matches!(c.open(3, true, &s), Err(Error::AuthFailed { .. })));
    }

    #[test]
    fn other_file_key_fails() {
        let h1 = header();
        let h2 = header();
        let s = cipher(1, &h1).seal(0, true, b"x").unwrap();
        assert!(matches!(
            cipher(1, &h2).open(0, true, &s),
            Err(Error::AuthFailed { .. })
        ));
        assert!(matches!(
            cipher(2, &h1).open(0, true, &s),
            Err(Error::AuthFailed { .. })
        ));
    }

    #[test]
    fn file_id_is_bound() {
        let a = FileHeader::random(1, [1; 16]).unwrap();
        let b = FileHeader {
            file_id: [2; 16],
            ..a.clone()
        };
        let s = cipher(1, &a).seal(0, true, b"x").unwrap();
        assert!(matches!(
            cipher(1, &b).open(0, true, &s),
            Err(Error::AuthFailed { .. })
        ));
    }

    #[test]
    fn short_and_oversized_input_is_rejected() {
        let h = header();
        let c = cipher(1, &h);
        assert!(c.open(0, true, &[0; 27]).is_err());
        assert!(c.open(0, true, &[]).is_err());
        assert!(c.seal(0, true, &vec![0; 65537]).is_err());
        let full = c.seal(0, true, &vec![7; 65536]).unwrap();
        assert_eq!(c.open(0, true, &full).unwrap().len(), 65536);
    }

    #[test]
    fn header_round_trip_and_version() {
        let h = FileHeader::random(7, [5; 16]).unwrap();
        let mut b = h.to_bytes();
        assert_eq!(b[0], 1);
        assert_eq!(b[1..5], 7u32.to_le_bytes());
        assert_eq!(b[5..37], h.file_nonce);
        assert_eq!(b[37..53], [5; 16]);
        assert_eq!(FileHeader::parse(&b).unwrap(), h);
        b[0] = 2;
        assert!(matches!(
            FileHeader::parse(&b),
            Err(Error::InvalidFormat { .. })
        ));
        assert!(FileHeader::parse(&b[..52]).is_err());
    }

    #[test]
    fn size_block_round_trip_and_binding() {
        let h = header().to_bytes();
        let key = [4u8; 32];
        let block = seal_size(&key, &h, 123_456).unwrap();
        assert_eq!(block.len(), 36);
        assert_eq!(open_size(&key, &h, &block).unwrap(), 123_456);
        let mut h2 = h;
        h2[20] ^= 1;
        assert!(matches!(
            open_size(&key, &h2, &block),
            Err(Error::AuthFailed { what }) if what == "size block"
        ));
        let mut b2 = block;
        b2[30] ^= 1;
        assert!(matches!(
            open_size(&key, &h, &b2),
            Err(Error::AuthFailed { .. })
        ));
        assert!(matches!(
            open_size(&[5; 32], &h, &block),
            Err(Error::AuthFailed { .. })
        ));
        assert!(open_size(&key, &h, &block[..35]).is_err());
    }
}
