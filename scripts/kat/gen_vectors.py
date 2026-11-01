# crypto-drive
# Copyright (C) 2026  Marcel Joachim Kloubert
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Prints known-answer test vectors for the on-disk format (format hardening
# spec sections 2-7, docs/superpowers/specs/2026-10-31-format-hardening-design.md).
#
# This script builds every value from the spec formulas with the Python
# "cryptography" package. It does not call any crypto-drive code. The Rust
# test crates/crypto-drive-core/tests/kat.rs contains the printed values and
# checks that the Rust code gives the same bytes.
#
# Run it with a Python that has cryptography 44 installed:
#   python -I scripts/kat/gen_vectors.py

import hashlib
import hmac
import struct
import unicodedata
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# Fixed inputs.
MK1 = bytes([0x01]) * 32  # master key of epoch 1
MK2 = bytes([0x08]) * 32  # master key of epoch 2
VAULT_ID = bytes([0x02]) * 16
FILE_NONCE = bytes([0x03]) * 32
DIR_ID = bytes([0x04]) * 16
CHUNK_NONCE = bytes([0x05]) * 12
SALT = bytes([0x06]) * 16
SLOT_NONCE = bytes([0x07]) * 12
FILE_ID = bytes([0x09]) * 16
ENTRY_ID = bytes([0x09]) * 16
SIZE_NONCE = bytes([0x0A]) * 12
PASSWORD = b"kat-password"
M_KIB, T, P = 19456, 2, 1
CLEAR_NAME = "Rechnung März.pdf"
LONG_ENCODED = "abcdefghij" * 23  # 230 B64 characters
CHUNK_PLAIN = b"hello chunk"
CHUNK_INDEX = 3
PLAIN_LEN = 123456


def b64(data):
    # Base64url without padding.
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def show(label, value):
    if isinstance(value, bytes):
        value = value.hex()
    print(f"{label} = {value}")


# Section 2: key hierarchy per epoch.
# PRK_e = HKDF-SHA-512-Extract(salt = vault_id || e (u32 LE), ikm = MK_e)
def sub_keys(mk, epoch):
    salt = VAULT_ID + struct.pack("<I", epoch)
    prk = hmac.new(salt, mk, hashlib.sha512).digest()

    def expand(info, length):
        return HKDFExpand(hashes.SHA512(), length, info).derive(prk)

    return (
        expand(b"crypto-drive v1 names", 64),
        expand(b"crypto-drive v1 content", 32),
        expand(b"crypto-drive v1 check", 32),
    )


k_names_1, k_content_1, k_check_1 = sub_keys(MK1, 1)
k_names_2, k_content_2, k_check_2 = sub_keys(MK2, 2)
show("K_names_1", k_names_1)
show("K_content_1", k_content_1)
show("K_check_1", k_check_1)
show("K_names_2", k_names_2)
show("K_content_2", k_content_2)
show("K_check_2", k_check_2)

# K_file = HKDF-SHA-512(salt = file_nonce, ikm = K_content[1],
#                       info = "crypto-drive v1 file" || file_id, 32)
# K_size = the same with info = "crypto-drive v1 size" || file_id.
k_file = HKDF(hashes.SHA512(), 32, FILE_NONCE, b"crypto-drive v1 file" + FILE_ID).derive(
    k_content_1
)
k_size = HKDF(hashes.SHA512(), 32, FILE_NONCE, b"crypto-drive v1 size" + FILE_ID).derive(
    k_content_1
)
show("K_file", k_file)
show("K_size", k_size)

# Section 3.1: names. Plaintext = entry_id || NFC(name), AD = [dir_id].
# The SIV tag comes first, then the ciphertext.
nfc = unicodedata.normalize("NFC", CLEAR_NAME).encode("utf-8")
enc_name = AESSIV(k_names_1).encrypt(ENTRY_ID + nfc, [DIR_ID])
show("name", b64(enc_name))
# Long entry: ".cd-cdl" + B64(SHA-256(name)) (base spec 4.6, unchanged).
show("long_entry", ".cd-cdl" + b64(hashlib.sha256(LONG_ENCODED.encode("ascii")).digest()))

# Section 5: file header (53 B) = version 1 || epoch (u32 LE) || file_nonce || file_id.
header = bytes([1]) + struct.pack("<I", 1) + FILE_NONCE + FILE_ID
assert len(header) == 53
show("file_header", header)

# One sealed chunk = nonce || ciphertext || tag,
# AD = chunk_index (u64 BE) || is_last (u8).
chunk_ad = struct.pack(">Q", CHUNK_INDEX) + bytes([1])
sealed = CHUNK_NONCE + AESGCM(k_file).encrypt(CHUNK_NONCE, CHUNK_PLAIN, chunk_ad)
show("chunk", sealed)

# Size block (36 B) = nonce || AES-256-GCM(K_size, plain_len (u64 LE),
# AD = header bytes 0-52) || tag.
size_block = SIZE_NONCE + AESGCM(k_size).encrypt(
    SIZE_NONCE, struct.pack("<Q", PLAIN_LEN), header
)
assert len(size_block) == 36
show("size_block", size_block)


# Section 4: vault marker (66 B), format 1, max_name_length 220, epoch 1.
# tag = HMAC-SHA-256(K_check[epoch], bytes 0-33).
def marker(flags):
    body = b"CD-VAULT" + struct.pack("<HHH", 1, 220, flags) + VAULT_ID + struct.pack("<I", 1)
    assert len(body) == 34
    out = body + hmac.new(k_check_1, body, hashlib.sha256).digest()
    assert len(out) == 66
    return out


show("vault_marker_flags_0", marker(0))
show("vault_marker_flags_1", marker(1))

# Section 6: key file with one password slot. The payload holds the key set
# count (u8) || count x (epoch (u32 LE) || MK), wrapped with the KEK.
kek = Argon2id(salt=SALT, length=32, iterations=T, lanes=P, memory_cost=M_KIB).derive(PASSWORD)


def key_file(key_set):
    plain = bytes([len(key_set)]) + b"".join(
        struct.pack("<I", epoch) + mk for epoch, mk in key_set
    )
    file_head = b"CD-KEY\0\0" + struct.pack("<H", 1)
    slot_type = 1
    payload_len = 40 + 1 + 36 * len(key_set) + 16
    payload_head = struct.pack("<III", M_KIB, T, P) + SALT + SLOT_NONCE
    key_ad = file_head + bytes([slot_type]) + struct.pack("<H", payload_len) + payload_head
    payload = payload_head + AESGCM(kek).encrypt(SLOT_NONCE, plain, key_ad)
    assert len(payload) == payload_len
    out = (
        file_head
        + struct.pack("<H", 1)  # slot_count
        + bytes([slot_type])
        + struct.pack("<H", payload_len)
        + payload
    )
    return plain, out


key_set_1, key_file_1 = key_file([(1, MK1)])
key_set_12, key_file_12 = key_file([(1, MK1), (2, MK2)])
show("key_set_1", key_set_1)
show("key_set_1_2", key_set_12)
show("key_file_1", key_file_1)
show("key_file_1_2", key_file_12)

# Section 7: recovery key (base spec 4.8), Crockford Base32 (upper case, no padding).
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
raw = MK1 + hashlib.sha256(MK1 + b"crypto-drive v1 recovery").digest()[:2]
bits = "".join(f"{byte:08b}" for byte in raw)
bits += "0" * (-len(bits) % 5)
symbols = "".join(CROCKFORD[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))
assert len(symbols) == 55
show("recovery_key", "-".join(symbols[i : i + 5] for i in range(0, 55, 5)))
