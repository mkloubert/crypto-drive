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

//! `crypto-drive init`.

use std::path::PathBuf;
use std::time::SystemTime;

use crypto_drive_core::recovery::encode_recovery_key;
use crypto_drive_core::vault::{InitOptions, init_vault};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::{Argon2Args, print_key_file_note, print_recovery_key};
use crate::CliError;
use crate::keypath;
use crate::password::{NEW_PASSWORD_ENV, PasswordArgs, read_new_password};

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub new_password_fd: Option<i32>,
    #[arg(long, default_value_t = crypto_drive_core::vault::DEFAULT_MAX_NAME_LENGTH)]
    pub max_name_length: u16,
    /// Hide file sizes by padding the content.
    #[arg(long)]
    pub pad_sizes: bool,
    #[command(flatten)]
    pub argon2: Argon2Args,
}

pub fn run(args: &InitArgs) -> Result<(), CliError> {
    if !(64..=255).contains(&args.max_name_length) {
        return Err(CliError::Usage(
            "--max-name-length must be between 64 and 255".into(),
        ));
    }
    let params = args.argon2.params()?;
    // Without --key-file the key file goes to ~/.crypto-drive/keys, so it is
    // not synced with the vault (keypath).
    let key_file = match &args.key_file {
        Some(p) => p.clone(),
        None => keypath::new_key_file(&args.vault_dir, SystemTime::now())?,
    };
    let password = read_new_password(&PasswordArgs {
        fd: args.new_password_fd,
        env_var: NEW_PASSWORD_ENV,
    })?;
    let opts = InitOptions {
        max_name_length: args.max_name_length,
        argon2: params,
        key_file: Some(key_file.clone()),
        pad_sizes: args.pad_sizes,
    };
    let mk = init_vault(&args.vault_dir, password.expose_secret().as_bytes(), &opts)?;
    let key = Zeroizing::new(encode_recovery_key(&mk));
    print_recovery_key(&key);
    print_key_file_note(&key_file);
    Ok(())
}
