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

//! `crypto-drive check`.

use std::io::Write;
use std::path::PathBuf;

use crypto_drive_core::check::{Finding, FindingKind, Severity, check_vault, exit_code};
use crypto_drive_core::vault::unlock_vault;
use secrecy::ExposeSecret;

use crate::CliError;
use crate::password::{PASSWORD_ENV, PasswordArgs, read_password};

#[derive(clap::Args, Debug)]
pub struct CheckArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub password_fd: Option<i32>,
}

fn kind_text(kind: &FindingKind) -> String {
    match kind {
        FindingKind::MissingDirId => "missing-dir-id".into(),
        FindingKind::MultipleDirIds => "multiple-dir-ids".into(),
        FindingKind::ForeignDirId => "foreign-dir-id".into(),
        FindingKind::IncompleteLongEntry => "incomplete-long-entry".into(),
        FindingKind::ConflictCopy => "conflict-copy".into(),
        FindingKind::ForeignEntry => "foreign-entry".into(),
        FindingKind::UndecryptableName => "undecryptable-name".into(),
        FindingKind::InvalidFileSize => "invalid-file-size".into(),
        FindingKind::HeaderInvalid => "header-invalid".into(),
        FindingKind::ChunkAuthFailed { index } => format!("chunk-auth-failed:{index}"),
        FindingKind::LongNameMismatch => "long-name-mismatch".into(),
        FindingKind::Unreadable => "unreadable".into(),
        FindingKind::EntryIdMismatch => "entry-id-mismatch".into(),
        FindingKind::UnknownKeyEpoch => "unknown-key-epoch".into(),
        FindingKind::RotationInProgress => "rotation-in-progress".into(),
        FindingKind::InvalidPadding => "invalid-padding".into(),
    }
}

fn line(f: &Finding) -> String {
    let severity = match f.severity {
        Severity::Warning => "warning",
        Severity::Error => "error",
    };
    format!(
        "{severity}: {}: {}",
        f.real_path.display(),
        kind_text(&f.kind)
    )
}

/// Returns the exit code of the check.
pub fn run(args: &CheckArgs) -> Result<i32, CliError> {
    let key_file = super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    let password = read_password(
        &PasswordArgs {
            fd: args.password_fd,
            env_var: PASSWORD_ENV,
        },
        "Password: ",
    )?;
    let (vault, _keys) = unlock_vault(
        &args.vault_dir,
        Some(key_file.as_path()),
        password.expose_secret().as_bytes(),
    )?;
    let findings = check_vault(&vault)?;
    let code = exit_code(&findings);
    let mut out = std::io::stdout().lock();
    for f in &findings {
        match writeln!(out, "{}", line(f)) {
            Ok(()) => {}
            // The reader closed the pipe (for example `| head`): stop writing.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_auth_failed_is_one_token() {
        assert_eq!(
            kind_text(&FindingKind::ChunkAuthFailed { index: 3 }),
            "chunk-auth-failed:3"
        );
    }

    #[test]
    fn new_kind_texts() {
        assert_eq!(
            kind_text(&FindingKind::EntryIdMismatch),
            "entry-id-mismatch"
        );
        assert_eq!(
            kind_text(&FindingKind::UnknownKeyEpoch),
            "unknown-key-epoch"
        );
        assert_eq!(
            kind_text(&FindingKind::RotationInProgress),
            "rotation-in-progress"
        );
        assert_eq!(kind_text(&FindingKind::InvalidPadding), "invalid-padding");
    }

    #[test]
    fn foreign_dir_id_text() {
        assert_eq!(kind_text(&FindingKind::ForeignDirId), "foreign-dir-id");
    }

    #[test]
    fn unreadable_text() {
        assert_eq!(kind_text(&FindingKind::Unreadable), "unreadable");
    }
}
