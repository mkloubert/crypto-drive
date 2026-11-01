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

//! Where key files live when `--key-file` is not given.
//!
//! `init` and `recover` write a new key file to
//! `$HOME/.crypto-drive/keys/<YYYYMMDDhhmmsszzz>_<VAULT_NAME>.cd-key`
//! (UTC time, `zzz` = milliseconds), so it is not synced with the vault.
//! All other commands need `--key-file`, except for an old vault that still
//! has its key file `.cd-key` inside the vault directory.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crypto_drive_core::vault::KEY_FILE;

use crate::CliError;

/// The directory of new key files, below `$HOME`.
pub const KEYS_DIR: &str = ".crypto-drive/keys";

/// The message when no key file is given and none is in the vault.
pub const NO_KEY_FILE: &str = "no key file given; pass it with --key-file (init printed its path; new key files are in ~/.crypto-drive/keys)";

/// The key file of an existing vault: the given one, else the old
/// `.cd-key` inside the vault. `None` if neither is there.
pub fn existing_key_file(vault_dir: &Path, key_file: Option<&Path>) -> Option<PathBuf> {
    match key_file {
        Some(p) => Some(p.to_path_buf()),
        None => {
            let legacy = vault_dir.join(KEY_FILE);
            legacy.is_file().then_some(legacy)
        }
    }
}

/// `$HOME/.crypto-drive/keys`, created with mode 0700 if needed.
pub fn keys_dir() -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| {
            CliError::Usage(
                "HOME is not set (or not an absolute path); pass the key file with --key-file"
                    .into(),
            )
        })?;
    let dir = home.join(KEYS_DIR);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    Ok(dir)
}

/// A new key file path in `keys_dir()` for the vault at `vault_dir`.
pub fn new_key_file(vault_dir: &Path, now: SystemTime) -> Result<PathBuf, CliError> {
    Ok(keys_dir()?.join(key_file_name(&vault_name(vault_dir), now)))
}

/// `<YYYYMMDDhhmmsszzz>_<name>.cd-key` in UTC.
pub fn key_file_name(name: &str, now: SystemTime) -> String {
    format!("{}_{}.cd-key", utc_stamp(now), name)
}

/// The last part of the vault path, with every character other than
/// ASCII letters, digits, `-` and `_` replaced by `_`. `vault` if the path
/// has no usable last part.
pub fn vault_name(vault_dir: &Path) -> String {
    let abs = std::path::absolute(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf());
    let name: String = abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() || name.chars().all(|c| c == '_') {
        "vault".to_string()
    } else {
        name
    }
}

/// `YYYYMMDDhhmmsszzz` (UTC, milliseconds). Times before 1970 count as
/// 1970-01-01.
pub fn utc_stamp(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let millis = since.subsec_millis();
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rest = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}{millis:03}",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// The proleptic Gregorian date of a day count since 1970-01-01
/// (algorithm "civil_from_days" by Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64, millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis)
    }

    #[test]
    fn stamp_of_known_times() {
        assert_eq!(utc_stamp(at(0, 0)), "19700101000000000");
        // 2000-02-29 23:59:59.999 UTC (a leap day).
        assert_eq!(utc_stamp(at(951_868_799, 999)), "20000229235959999");
        // 2026-11-01 14:30:52.123 UTC.
        assert_eq!(utc_stamp(at(1_793_543_452, 123)), "20261101143052123");
        // 2100-03-01 00:00:00.000 UTC (2100 is no leap year).
        assert_eq!(utc_stamp(at(4_107_542_400, 0)), "21000301000000000");
    }

    #[test]
    fn stamp_before_1970_is_clamped() {
        let before = UNIX_EPOCH - Duration::from_secs(10);
        assert_eq!(utc_stamp(before), "19700101000000000");
    }

    #[test]
    fn civil_date_matches_every_day_of_four_centuries() {
        // Walks day by day and checks against a simple month table.
        let (mut y, mut m, mut d) = (1970i64, 1u32, 1u32);
        for days in 0..(400 * 366) {
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let len = [
                31,
                if leap { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ][(m - 1) as usize];
            d += 1;
            if d > len {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    #[test]
    fn file_name_format() {
        assert_eq!(
            key_file_name("vault", at(1_793_543_452, 123)),
            "20261101143052123_vault.cd-key"
        );
    }

    #[test]
    fn vault_name_is_sanitized() {
        assert_eq!(vault_name(Path::new("/x/my-vault_1")), "my-vault_1");
        assert_eq!(vault_name(Path::new("/x/My Vault.2")), "My_Vault_2");
        assert_eq!(vault_name(Path::new("/x/Tresor-ä")), "Tresor-_");
        assert_eq!(vault_name(Path::new("/x/äö")), "vault");
        assert_eq!(vault_name(Path::new("/")), "vault");
        assert_eq!(vault_name(Path::new("/x/v/")), "v");
    }

    #[test]
    fn existing_key_file_prefers_the_given_one() {
        let dir = tempfile::tempdir().unwrap();
        let given = dir.path().join("k");
        assert_eq!(
            existing_key_file(dir.path(), Some(&given)),
            Some(given.clone())
        );
        assert_eq!(existing_key_file(dir.path(), None), None);
        std::fs::write(dir.path().join(KEY_FILE), b"x").unwrap();
        assert_eq!(
            existing_key_file(dir.path(), None),
            Some(dir.path().join(KEY_FILE))
        );
    }
}
