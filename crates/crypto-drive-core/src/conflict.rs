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

//! Helpers for sync conflict copies (spec §5.3 step 3).
//!
//! Sync clients rename a file to a conflict copy by adding a suffix to the
//! real (encrypted) name. These pure string helpers find the possible splits
//! into (encrypted name, suffix). The caller tries to decrypt the candidates.

use crate::names::{LONG_PREFIX, MAX_CLEAR_NAME_BYTES, is_b64_char};

/// Length of a 16-byte SIV tag in unpadded Base64.
pub const MIN_ENCODED_LEN: usize = 22;

/// Length of the Base64 hash in a long entry name.
const LONG_HASH_LEN: usize = 43;

/// Returns (prefix, suffix) pairs for a real entry name that does not start
/// with '.', longest prefix first. Prefixes only hold Base64 characters and
/// are at least `MIN_ENCODED_LEN` long. The first pair is the whole Base64
/// run and the rest.
pub fn short_candidates(real: &str) -> Vec<(&str, &str)> {
    if real.starts_with('.') {
        return Vec::new();
    }
    // Base64 characters are ASCII, so the run length is a char boundary.
    let run_len = real.chars().take_while(|c| is_b64_char(*c)).count();
    if run_len < MIN_ENCODED_LEN {
        return Vec::new();
    }
    (MIN_ENCODED_LEN..=run_len)
        .rev()
        .map(|k| real.split_at(k))
        .collect()
}

/// For ".cd-cdl" + 43 Base64 characters + suffix, returns (entry, suffix).
/// The suffix may be empty.
pub fn long_candidate(real: &str) -> Option<(&str, &str)> {
    let end = LONG_PREFIX.len() + LONG_HASH_LEN;
    let head = real.get(..end)?;
    let hash = head.strip_prefix(LONG_PREFIX)?;
    if !hash.chars().all(is_b64_char) {
        return None;
    }
    Some(real.split_at(end))
}

/// Builds the display name "<stem> (conflict N)<.ext>". The extension starts
/// at the last '.' that is not at index 0.
pub fn conflict_display_name(clear: &str, n: u32) -> String {
    name_with_note(clear, &format!("conflict {n}"))
}

/// Longest rotation conflict name: the name limit of most file systems
/// (and of a mount), and never more than a valid clear name.
const MAX_ROTATION_CONFLICT_NAME_BYTES: usize = if MAX_CLEAR_NAME_BYTES < 255 {
    MAX_CLEAR_NAME_BYTES
} else {
    255
};

/// Builds the clear name "<stem> (rotation conflict N)<.ext>" of a file
/// that was changed in both copies during an unfinished key rotation. A
/// stem that would make the name longer than 255 bytes is cut on a char
/// boundary; the extension stays if it fits with the note.
pub fn rotation_conflict_name(clear: &str, n: u32) -> String {
    let note = format!(" (rotation conflict {n})");
    let max = MAX_ROTATION_CONFLICT_NAME_BYTES;
    let (stem, ext) = match split_ext(clear) {
        (stem, ext) if note.len() + ext.len() < max => (stem, ext),
        _ => (clear, ""),
    };
    let room = max.saturating_sub(note.len() + ext.len());
    let stem = &stem[..stem.floor_char_boundary(room)];
    format!("{stem}{note}{ext}")
}

/// Splits off the extension: it starts at the last '.' that is not at
/// index 0. The extension may be empty.
fn split_ext(clear: &str) -> (&str, &str) {
    match clear.rfind('.') {
        Some(i) if i > 0 => clear.split_at(i),
        _ => (clear, ""),
    }
}

/// "<stem> (<note>)<.ext>".
fn name_with_note(clear: &str, note: &str) -> String {
    let (stem, ext) = split_ext(clear);
    format!("{stem} ({note}){ext}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn rotation_conflict_names() {
        assert_eq!(
            super::rotation_conflict_name("a.txt", 1),
            "a (rotation conflict 1).txt"
        );
        assert_eq!(
            super::rotation_conflict_name(".rc", 2),
            ".rc (rotation conflict 2)"
        );
    }

    use super::*;

    /// A rotation conflict name of a long clear name keeps its extension and
    /// at most 255 bytes, cut on a char boundary.
    #[test]
    fn rotation_conflict_names_of_long_names_fit() {
        for stem_len in [246, 1016] {
            // Two-byte chars, so a cut in the middle of one would show.
            let stem = "ä".repeat(stem_len / 2);
            let clear = format!("{stem}.txt");
            assert_eq!(clear.len(), stem_len + 4);
            for n in [1, 64] {
                let name = rotation_conflict_name(&clear, n);
                assert!(name.len() <= 255, "{}", name.len());
                assert!(name.len() <= crate::names::MAX_CLEAR_NAME_BYTES);
                let tail = format!(" (rotation conflict {n}).txt");
                assert!(name.ends_with(&tail), "{name}");
                let kept = &name[..name.len() - tail.len()];
                assert!(stem.starts_with(kept));
                assert!(name.len() > 250, "{}", name.len());
                crate::names::validate_name(&name).unwrap();
            }
        }
        // A name that already fits is not changed.
        assert_eq!(
            rotation_conflict_name(&format!("{}.txt", "a".repeat(200)), 1),
            format!("{} (rotation conflict 1).txt", "a".repeat(200))
        );
        // An extension too long to keep is cut like the stem.
        let name = rotation_conflict_name(&format!("a.{}", "b".repeat(300)), 2);
        assert!(name.len() <= 255 && name.ends_with(" (rotation conflict 2)"));
    }

    #[test]
    fn suffixes_of_real_clients() {
        let t = "AbCdEfGhIjKlMnOpQrStUvWxYz0123";
        for (real, suffix) in [
            (
                format!("{t}.sync-conflict-20261031-123456-ABCDEFG"),
                ".sync-conflict-20261031-123456-ABCDEFG",
            ), // Syncthing
            (
                format!("{t} (conflicted copy 2026-10-31 123456)"),
                " (conflicted copy 2026-10-31 123456)",
            ), // Nextcloud
            (
                format!("{t} (Marcel's conflicted copy 2026-10-31)"),
                " (Marcel's conflicted copy 2026-10-31)",
            ), // Dropbox
            (format!("{t} 2"), " 2"),     // iCloud
            (format!("{t} (1)"), " (1)"), // Google Drive
        ] {
            assert!(short_candidates(&real).contains(&(t, suffix)));
        }
    }

    #[test]
    fn b64_only_suffix_gives_all_prefixes() {
        let real = "AbCdEfGhIjKlMnOpQrStUvWxYz0123-DESKTOP1"; // OneDrive
        let c = short_candidates(real);
        assert_eq!(c[0], (real, ""));
        assert!(c.contains(&("AbCdEfGhIjKlMnOpQrStUvWxYz0123", "-DESKTOP1")));
        assert!(c.windows(2).all(|w| w[0].0.len() > w[1].0.len()));
        assert_eq!(c.last().map(|p| p.0.len()), Some(MIN_ENCODED_LEN));
    }

    #[test]
    fn short_tokens_are_ignored() {
        assert!(short_candidates("abc (1)").is_empty());
        assert!(short_candidates(".AbCdEfGhIjKlMnOpQrStUvWxYz0123").is_empty());
    }

    #[test]
    fn long_candidate_works() {
        let body = "A".repeat(43);
        let real = format!("{LONG_PREFIX}{body} (1)");
        assert_eq!(long_candidate(&real), Some((&real[..50], " (1)")));
        let exact = format!("{LONG_PREFIX}{body}");
        assert_eq!(long_candidate(&exact), Some((exact.as_str(), "")));
        let short = format!("{LONG_PREFIX}{} (1)", "A".repeat(42));
        assert_eq!(long_candidate(&short), None);
        let bad = format!("{LONG_PREFIX}{}!{}", "A".repeat(20), "A".repeat(22));
        assert_eq!(long_candidate(&bad), None);
        assert_eq!(long_candidate(&format!("x{body}")), None);
    }

    #[test]
    fn display_names() {
        assert_eq!(
            conflict_display_name("Report.pdf", 1),
            "Report (conflict 1).pdf"
        );
        assert_eq!(conflict_display_name("README", 2), "README (conflict 2)");
        assert_eq!(conflict_display_name(".bashrc", 1), ".bashrc (conflict 1)");
        assert_eq!(
            conflict_display_name("a.tar.gz", 1),
            "a.tar (conflict 1).gz"
        );
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        for s in [
            "ä€💥",
            ".cd-cdlä",
            ".cd-cdl€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€",
        ] {
            let _ = short_candidates(s);
            let _ = long_candidate(s);
        }
        let t = "AbCdEfGhIjKlMnOpQrStUvWxYz0123";
        assert!(short_candidates(&format!("{t}ä€💥")).contains(&(t, "ä€💥")));
        let long = format!("{LONG_PREFIX}{}ä", "A".repeat(43));
        assert_eq!(long_candidate(&long), Some((&long[..50], "ä")));
    }
}
