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

//! Known-answer tests for the on-disk format (format hardening spec
//! sections 2-7).
//!
//! The expected values come from `scripts/kat/gen_vectors.py`, which builds
//! them from the spec formulas with the Python `cryptography` package and
//! without any crypto-drive code. They must never change: a change here
//! means the on-disk format changed.

use crypto_drive_core::Error;
use crypto_drive_core::content::{ChunkCipher, FileHeader, open_size, seal_size};
use crypto_drive_core::keyfile::KeyFile;
use crypto_drive_core::keys::{KeySet, MasterKey, derive_file_key, derive_size_key};
use crypto_drive_core::names::{NameCipher, long_entry_name};
use crypto_drive_core::recovery::encode_recovery_key;
use crypto_drive_core::vault::VaultMarker;

const MK1: [u8; 32] = [0x01; 32];
const MK2: [u8; 32] = [0x08; 32];
const VAULT_ID: [u8; 16] = [0x02; 16];
const FILE_NONCE: [u8; 32] = [0x03; 32];
const DIR_ID: [u8; 16] = [0x04; 16];
const FILE_ID: [u8; 16] = [0x09; 16];
const ENTRY_ID: [u8; 16] = [0x09; 16];
const PLAIN_LEN: u64 = 123456;

// Printed by scripts/kat/gen_vectors.py.
const K_NAMES_1: &str = "d88534c8a11e95df6a899f4a191f45137cedc59a79ceac24dd820c70f8b3b41742ea709b659d2b79ab7596fe80c950e9b56e980103a12a58c7d406812be9280c";
const K_CONTENT_1: &str = "d422e25ebd074f13674bc6b0118ec66bf65c40702357fedb5d223fd1d80f7d03";
const K_CHECK_1: &str = "bb146bb210483617b8f2e0d92647209d1a67b557bfe3d1f79d777eb28d7e3aea";
const K_NAMES_2: &str = "c05debd3eb5691231706b5cf894932b8f202ceaa96dfdbfa5ec894bc46497189e71e9ca549ff2073dc54f8c77ca50454219a15201a8484826950bdb8babeb212";
const K_CONTENT_2: &str = "8c65daa4c2aa759e6798fcbae30a8ba5d7e2f4bc71b82bcae6cb8dafb697ad09";
const K_CHECK_2: &str = "79ed67a5511ffbbb5d5ef4b2bb1932c97a12fffb0b0c971a3f73a3bebfa3558e";
const K_FILE: &str = "39a79ec744379e78e17420d70dfe77b714c27c6c7fec4ef87fd173965850c2f6";
const K_SIZE: &str = "0d91866e8c127a30988dc76e0809616f0001a7419478392444c220e8539d10ba";
const NAME: &str = "tVIb7rR-M9mttlKvhTSh8qFNfW3DORVpA1sdRuCR7NhFUftKkaYaeCIF_-xSnNZnPbg";
const LONG_ENTRY: &str = ".cd-cdlUN7BULD-N6UP7UPjDek3bmAE5Ot6rU1IevHiFkzw_Xw";
const FILE_HEADER: &str = "0101000000030303030303030303030303030303030303030303030303030303030303030309090909090909090909090909090909";
const CHUNK: &str =
    "050505050505050505050505dfd387228a28c936a9514873b0b88734631fdadd15b6b65c4ce6fd";
const SIZE_BLOCK: &str = "0a0a0a0a0a0a0a0a0a0a0a0ad5d8f8690771ea5b824fc77c159cbd86f4fa85d260e709bb";
const VAULT_MARKER_FLAGS_0: &str = "43442d5641554c540100dc00000002020202020202020202020202020202010000007e0deb1387e7485f9c1a590639bbb395f5d6c33ea54143655a6bd74532573bec";
const VAULT_MARKER_FLAGS_1: &str = "43442d5641554c540100dc000100020202020202020202020202020202020100000051b13df2532f93d4109f9f317be4bc1946b61d0e827b26a3bb68c0fc3f8d51ef";
const KEY_SET_1: &str =
    "01010000000101010101010101010101010101010101010101010101010101010101010101";
const KEY_SET_1_2: &str = "02010000000101010101010101010101010101010101010101010101010101010101010101020000000808080808080808080808080808080808080808080808080808080808080808";
const KEY_FILE_1: &str = "43442d4b4559000001000100015d00004c00000200000001000000060606060606060606060606060606060707070707070707070707071e77fbbfbee299af6418a6f4ef74ae56854f8435d5a1fe60154015adb64684843d2ab805600f963aac07feb38f4952d679aaec73a9";
const KEY_FILE_1_2: &str = "43442d4b4559000001000100018100004c00000200000001000000060606060606060606060606060606060707070707070707070707071d77fbbfbee299af6418a6f4ef74ae56854f8435d5a1fe60154015adb64684843d2ab8056057ca9ab9ffe4febb62c30da0f91501956dfa7eaeb902c1a2a57836484be93b6f89b73964f8ca4719ecdfffeb7666af1f322c20f8";
const RECOVERY_KEY: &str = "040G2-08104-0G208-1040G-20810-40G20-81040-G2081-040G2-08104-0QV28";

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn header() -> FileHeader {
    FileHeader {
        epoch: 1,
        file_nonce: FILE_NONCE,
        file_id: FILE_ID,
    }
}

#[test]
fn hkdf_sub_keys() {
    let k1 = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    assert_eq!(k1.names().as_slice(), hex(K_NAMES_1));
    assert_eq!(k1.content().as_slice(), hex(K_CONTENT_1));
    assert_eq!(k1.check().as_slice(), hex(K_CHECK_1));
    let k2 = MasterKey::from_bytes(MK2).derive(&VAULT_ID, 2);
    assert_eq!(k2.names().as_slice(), hex(K_NAMES_2));
    assert_eq!(k2.content().as_slice(), hex(K_CONTENT_2));
    assert_eq!(k2.check().as_slice(), hex(K_CHECK_2));
}

#[test]
fn file_and_size_keys() {
    let keys = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    let file_key = derive_file_key(keys.content(), &FILE_NONCE, &FILE_ID);
    assert_eq!(file_key.expose().as_slice(), hex(K_FILE));
    let size_key = derive_size_key(keys.content(), &FILE_NONCE, &FILE_ID);
    assert_eq!(size_key.expose().as_slice(), hex(K_SIZE));
}

#[test]
fn name_encryption() {
    let keys = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    let names = NameCipher::new(keys.names());
    assert_eq!(
        names
            .encrypt(&DIR_ID, &ENTRY_ID, "Rechnung März.pdf")
            .unwrap(),
        NAME
    );
    // The NFD form gives the same name.
    assert_eq!(
        names
            .encrypt(&DIR_ID, &ENTRY_ID, "Rechnung Ma\u{308}rz.pdf")
            .unwrap(),
        NAME
    );
    assert_eq!(
        names.decrypt(&DIR_ID, NAME).unwrap(),
        (ENTRY_ID, "Rechnung März.pdf".to_string())
    );
    // Another directory id does not open it.
    assert!(matches!(
        names.decrypt(&VAULT_ID, NAME),
        Err(Error::AuthFailed { .. })
    ));
}

#[test]
fn long_entry() {
    let encoded = "abcdefghij".repeat(23);
    assert_eq!(encoded.len(), 230);
    assert_eq!(long_entry_name(&encoded), LONG_ENTRY);
}

#[test]
fn file_header_bytes() {
    let expected = hex(FILE_HEADER);
    assert_eq!(header().to_bytes().as_slice(), expected);
    assert_eq!(FileHeader::parse(&expected).unwrap(), header());
}

#[test]
fn chunk_opens() {
    let keys = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    let cipher = ChunkCipher::new(keys.content(), &header());
    let sealed = hex(CHUNK);
    assert_eq!(cipher.open(3, true, &sealed).unwrap(), b"hello chunk");
    assert!(matches!(
        cipher.open(3, false, &sealed),
        Err(Error::AuthFailed { .. })
    ));
    assert!(matches!(
        cipher.open(2, true, &sealed),
        Err(Error::AuthFailed { .. })
    ));
    // A chunk sealed by Rust opens again (fresh nonce each time).
    let resealed = cipher.seal(3, true, b"hello chunk").unwrap();
    assert_eq!(cipher.open(3, true, &resealed).unwrap(), b"hello chunk");
}

#[test]
fn size_block_opens() {
    let keys = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    let size_key = derive_size_key(keys.content(), &FILE_NONCE, &FILE_ID);
    let head = header().to_bytes();
    let block = hex(SIZE_BLOCK);
    assert_eq!(
        open_size(size_key.expose(), &head, &block).unwrap(),
        PLAIN_LEN
    );
    // The block is bound to the header (AD = header bytes 0-52).
    let mut other = head;
    other[1] = 2;
    assert!(open_size(size_key.expose(), &other, &block).is_err());
    // A block sealed by Rust opens again.
    let resealed = seal_size(size_key.expose(), &head, PLAIN_LEN).unwrap();
    assert_eq!(
        open_size(size_key.expose(), &head, &resealed).unwrap(),
        PLAIN_LEN
    );
}

#[test]
fn vault_marker() {
    let keys = MasterKey::from_bytes(MK1).derive(&VAULT_ID, 1);
    for (pad_sizes, bytes) in [(false, VAULT_MARKER_FLAGS_0), (true, VAULT_MARKER_FLAGS_1)] {
        let marker = VaultMarker {
            format_version: 1,
            max_name_length: 220,
            pad_sizes,
            vault_id: VAULT_ID,
            epoch: 1,
        };
        let expected = hex(bytes);
        assert_eq!(marker.to_bytes(keys.check()).as_slice(), expected);
        VaultMarker::verify(&expected, keys.check()).unwrap();
        assert_eq!(VaultMarker::parse_unverified(&expected).unwrap(), marker);
    }
}

#[test]
fn key_set_encoding() {
    let one = KeySet::single(1, MasterKey::from_bytes(MK1));
    assert_eq!(one.encode().as_slice(), hex(KEY_SET_1));
    let two = one.with_next(MasterKey::from_bytes(MK2)).unwrap();
    assert_eq!(two.encode().as_slice(), hex(KEY_SET_1_2));
    let decoded = KeySet::decode(&hex(KEY_SET_1_2)).unwrap();
    assert_eq!(decoded.epochs(), two.epochs());
}

#[test]
fn key_file_one_epoch_unlocks() {
    let bytes = hex(KEY_FILE_1);
    let kf = KeyFile::from_bytes(&bytes).unwrap();
    assert_eq!(kf.to_bytes(), bytes);
    let keys = kf.unlock(b"kat-password").unwrap();
    assert_eq!(keys.epochs(), vec![1]);
    assert_eq!(keys.get(1).unwrap().expose(), &MK1);
    assert!(matches!(kf.unlock(b"other"), Err(Error::WrongPassword)));
}

#[test]
fn key_file_two_epochs_unlocks() {
    let bytes = hex(KEY_FILE_1_2);
    let kf = KeyFile::from_bytes(&bytes).unwrap();
    assert_eq!(kf.to_bytes(), bytes);
    let keys = kf.unlock(b"kat-password").unwrap();
    assert_eq!(keys.epochs(), vec![1, 2]);
    assert_eq!(keys.write_epoch(), 2);
    assert_eq!(keys.get(1).unwrap().expose(), &MK1);
    assert_eq!(keys.get(2).unwrap().expose(), &MK2);
    assert!(matches!(kf.unlock(b"other"), Err(Error::WrongPassword)));
}

#[test]
fn recovery_key() {
    assert_eq!(
        encode_recovery_key(&MasterKey::from_bytes(MK1)),
        RECOVERY_KEY
    );
}
