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

//! `crypto-drive recovery-key`.

use std::path::PathBuf;

use crypto_drive_core::recovery::encode_recovery_key;
use crypto_drive_core::vault::unlock_vault;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::print_recovery_key;
use crate::CliError;
use crate::password::{PASSWORD_ENV, PasswordArgs, read_password};
use crypto_drive_core::error::Error;

#[derive(clap::Args, Debug)]
pub struct RecoveryKeyArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub password_fd: Option<i32>,
}

pub fn run(args: &RecoveryKeyArgs) -> Result<(), CliError> {
    let key_file = super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    let password = read_password(
        &PasswordArgs {
            fd: args.password_fd,
            env_var: PASSWORD_ENV,
        },
        "Password: ",
    )?;
    let (vault, keys) = unlock_vault(
        &args.vault_dir,
        Some(key_file.as_path()),
        password.expose_secret().as_bytes(),
    )?;
    let mk = keys.get(vault.marker.epoch).ok_or(Error::WrongKey)?;
    let key = Zeroizing::new(encode_recovery_key(mk));
    print_recovery_key(&key);
    Ok(())
}
