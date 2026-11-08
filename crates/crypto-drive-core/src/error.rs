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

//! Error type shared by the whole core.

/// All errors the core can return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("directory is not empty")]
    NotEmpty,
    #[error("is a directory")]
    IsADirectory,
    #[error("not a directory")]
    NotADirectory,
    /// `what` is the real (encrypted) relative path or object name.
    #[error("authentication failed for {what}")]
    AuthFailed { what: String },
    /// `what` is the real (encrypted) relative path or object name.
    #[error("invalid format in {what}")]
    InvalidFormat { what: String },
    #[error("wrong password or damaged key file")]
    WrongPassword,
    #[error("the key does not belong to this vault")]
    WrongKey,
    #[error("unknown format version {found}")]
    UnsupportedVersion { found: u16 },
    #[error("name is too long")]
    NameTooLong,
    #[error("invalid name")]
    InvalidName,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("not supported")]
    Unsupported,
    #[error("not permitted")]
    NotPermitted,
    #[error("vault is already mounted")]
    AlreadyMounted,
    /// The final check of a key rotation found entries of the old epoch.
    /// `hidden` are the real paths of long entries without a valid
    /// `.cd-name` that still hold data (they are counted in `left`).
    /// `foreign_copies` are the real paths of `.cd-dir` copies with another
    /// id: entries named under them would be lost with the old key (spec
    /// 2026-11-08 one dir id).
    #[error("{}", rotation_not_finished(*left, hidden, foreign_copies))]
    RotationNotFinished {
        left: u64,
        hidden: Vec<String>,
        foreign_copies: Vec<String>,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

fn rotation_not_finished(left: u64, hidden: &[String], foreign_copies: &[String]) -> String {
    let mut parts = Vec::new();
    if left > 0 {
        let mut text = format!("{left} entries still use the old key; run rotate-key again");
        if !hidden.is_empty() {
            text.push_str(&format!(
                ". These long entries have no valid .cd-name but hold data, so the old key is kept: {}. Repair or remove them first",
                hidden.join(", ")
            ));
        }
        parts.push(text);
    }
    if !foreign_copies.is_empty() {
        parts.push(format!(
            "these .cd-dir copies hold another directory id, so entries named under them were not converted and the old key is kept: {}. Run crypto-drive check (foreign-dir-id) and remove the copies first",
            foreign_copies.join(", ")
        ));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_texts_are_exact() {
        assert_eq!(
            Error::WrongPassword.to_string(),
            "wrong password or damaged key file"
        );
        assert_eq!(
            Error::WrongKey.to_string(),
            "the key does not belong to this vault"
        );
        assert_eq!(
            Error::UnsupportedVersion { found: 9 }.to_string(),
            "unknown format version 9"
        );
        assert_eq!(
            Error::AlreadyMounted.to_string(),
            "vault is already mounted"
        );
    }

    #[test]
    fn rotation_not_finished_names_hidden_entries() {
        let plain = Error::RotationNotFinished {
            left: 2,
            hidden: Vec::new(),
            foreign_copies: Vec::new(),
        };
        assert_eq!(
            plain.to_string(),
            "2 entries still use the old key; run rotate-key again"
        );
        let hidden = Error::RotationNotFinished {
            left: 1,
            hidden: vec!["a/.cd-cdlX".into()],
            foreign_copies: Vec::new(),
        };
        assert!(hidden.to_string().contains(": a/.cd-cdlX. Repair"));
    }

    #[test]
    fn rotation_not_finished_names_foreign_copies() {
        let only = Error::RotationNotFinished {
            left: 0,
            hidden: Vec::new(),
            foreign_copies: vec!["b/.cd-dir 2".into()],
        };
        assert_eq!(
            only.to_string(),
            "these .cd-dir copies hold another directory id, so entries named under them were not converted and the old key is kept: b/.cd-dir 2. Run crypto-drive check (foreign-dir-id) and remove the copies first"
        );
        let both = Error::RotationNotFinished {
            left: 2,
            hidden: Vec::new(),
            foreign_copies: vec!["b/.cd-dir 2".into()],
        };
        assert!(both.to_string().starts_with(
            "2 entries still use the old key; run rotate-key again; these .cd-dir copies"
        ));
    }

    #[test]
    fn io_error_converts() {
        let e: Error = std::io::Error::other("x").into();
        assert!(matches!(e, Error::Io(_)));
    }
}
