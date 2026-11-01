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

//! `crypto-drive passwd`.

use std::path::PathBuf;

use crypto_drive_core::keyfile::KeyFile;
use crypto_drive_core::vault::unlock_vault;
use secrecy::ExposeSecret;

use super::Argon2Args;
use crate::CliError;
use crate::password::{
    NEW_PASSWORD_ENV, PASSWORD_ENV, PasswordArgs, read_new_password, read_password,
};

#[derive(clap::Args, Debug)]
pub struct PasswdArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub password_fd: Option<i32>,
    #[arg(long)]
    pub new_password_fd: Option<i32>,
    #[command(flatten)]
    pub argon2: Argon2Args,
}

pub fn run(args: &PasswdArgs) -> Result<(), CliError> {
    if args.password_fd.is_some() && args.password_fd == args.new_password_fd {
        return Err(CliError::Usage(
            "--password-fd and --new-password-fd must differ".into(),
        ));
    }
    let path = super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    let params = args.argon2.params()?;
    let old = read_password(
        &PasswordArgs {
            fd: args.password_fd,
            env_var: PASSWORD_ENV,
        },
        "Password: ",
    )?;
    // Checks that the key file belongs to this vault, then releases it.
    let (vault, keys) = unlock_vault(
        &args.vault_dir,
        Some(path.as_path()),
        old.expose_secret().as_bytes(),
    )?;
    drop(vault);
    let mut key_file = KeyFile::load(&path)?;
    let new = read_new_password(&PasswordArgs {
        fd: args.new_password_fd,
        env_var: NEW_PASSWORD_ENV,
    })?;
    key_file.set_password(&keys, new.expose_secret().as_bytes(), params)?;
    key_file.save_replace(&path)?;
    Ok(())
}
