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

//! Recovery key: the master key as a printable Base32 string (spec 4.8).

use crate::error::{Error, Result};
use crate::keys::MasterKey;
use data_encoding::{Encoding, Specification};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SYMBOLS: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CONTEXT: &[u8] = b"crypto-drive v1 recovery";
/// 32 key bytes plus 2 checksum bytes.
const RAW_LEN: usize = 34;
const SYMBOL_COUNT: usize = 55;
const GROUP_LEN: usize = 5;

fn encoding() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(SYMBOLS);
    spec.check_trailing_bits = true;
    // The specification is a constant, so this cannot fail.
    spec.encoding().unwrap_or_else(|_| unreachable!())
}

fn checksum(key: &[u8; 32]) -> [u8; 2] {
    let digest = Sha256::new()
        .chain_update(key)
        .chain_update(CONTEXT)
        .finalize();
    [digest[0], digest[1]]
}

fn invalid() -> Error {
    Error::InvalidFormat {
        what: "recovery key".into(),
    }
}

/// Encodes the master key as 11 groups of 5 Base32 symbols joined with `-`.
pub fn encode_recovery_key(mk: &MasterKey) -> String {
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    raw[..32].copy_from_slice(mk.expose());
    raw[32..].copy_from_slice(&checksum(mk.expose()));
    let text = Zeroizing::new(encoding().encode(&raw[..]));
    let groups: Vec<&str> = text
        .as_bytes()
        .chunks(GROUP_LEN)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    groups.join("-")
}

/// Decodes a recovery key. Case, spaces and dashes are ignored, `I` and `L`
/// are read as `1`, and `O` is read as `0`. The checksum is verified.
pub fn decode_recovery_key(input: &str) -> Result<MasterKey> {
    let clean: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect(),
    );
    if clean.len() != SYMBOL_COUNT {
        return Err(invalid());
    }
    let raw = Zeroizing::new(encoding().decode(clean.as_bytes()).map_err(|_| invalid())?);
    if raw.len() != RAW_LEN {
        return Err(invalid());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw[..32]);
    if checksum(&key) != raw[32..] {
        return Err(invalid());
    }
    Ok(MasterKey::from_bytes(*key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &str = SYMBOLS;

    #[test]
    fn format_is_11_groups_of_5() {
        let s = encode_recovery_key(&MasterKey::from_bytes([0xAB; 32]));
        assert_eq!(s.len(), 65);
        assert!(s.split('-').all(|g| g.len() == 5));
        assert!(s.chars().all(|c| c == '-' || ALPHABET.contains(c)));
    }

    #[test]
    fn round_trip_with_sloppy_input() {
        let mk = MasterKey::from_bytes([0x5C; 32]);
        let s = encode_recovery_key(&mk).to_lowercase().replace('-', " ");
        assert_eq!(decode_recovery_key(&s).unwrap().expose(), mk.expose());
    }

    #[test]
    fn confusable_letters_are_mapped() {
        // Use a key whose text contains both '1' and '0'.
        let mk = MasterKey::from_bytes([0x01; 32]);
        let s = encode_recovery_key(&mk);
        assert!(s.contains('1') && s.contains('0'));
        let sloppy = s.replace('1', "l").replace('0', "O");
        assert!(!sloppy.contains('1') && !sloppy.contains('0'));
        assert_eq!(decode_recovery_key(&sloppy).unwrap().expose(), mk.expose());
        let sloppy = s.replace('1', "I").replace('0', "o");
        assert_eq!(decode_recovery_key(&sloppy).unwrap().expose(), mk.expose());
    }

    #[test]
    fn single_symbol_change_is_rejected() {
        let mk = MasterKey::from_bytes([0x5C; 32]);
        let s = encode_recovery_key(&mk);
        // Change the symbol at index 20 (not a dash) to every other symbol.
        let mut changed = 0;
        for alt in ALPHABET.chars() {
            let mut chars: Vec<char> = s.chars().collect();
            let idx = 20;
            assert_ne!(chars[idx], '-');
            if chars[idx] == alt {
                continue;
            }
            chars[idx] = alt;
            let bad: String = chars.into_iter().collect();
            assert!(matches!(
                decode_recovery_key(&bad),
                Err(Error::InvalidFormat { .. })
            ));
            changed += 1;
        }
        assert_eq!(changed, 31);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(decode_recovery_key("ABCDE").is_err());
    }
}
