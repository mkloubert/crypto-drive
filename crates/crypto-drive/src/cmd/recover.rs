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

//! `crypto-drive recover`.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::SystemTime;

use crypto_drive_core::error::Error;
use crypto_drive_core::keyfile::KeyFile;
use crypto_drive_core::keys::KeySet;
use crypto_drive_core::recovery::decode_recovery_key;
use crypto_drive_core::vault::{
    lock_vault, open_with_master_key, rotation_unfinished, verify_next_key,
};
use secrecy::ExposeSecret;

use super::Argon2Args;
use crate::CliError;
use crate::keypath;
use crate::password::{
    NEW_PASSWORD_ENV, PasswordArgs, read_key_text, read_new_password, read_recovery_key,
};

/// The error when a rotation is unfinished and only one key was given.
const BOTH_KEYS_NEEDED: &str = "a key rotation is unfinished: give both recovery keys (old and new), or finish the rotation first";

#[derive(clap::Args, Debug)]
pub struct RecoverArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    /// Replace an existing key file.
    #[arg(long)]
    pub overwrite: bool,
    #[arg(long)]
    pub recovery_key_fd: Option<i32>,
    /// The recovery key of an unfinished key rotation (the new one). Read
    /// only if a rotation is unfinished.
    #[arg(long)]
    pub new_recovery_key_fd: Option<i32>,
    #[arg(long)]
    pub new_password_fd: Option<i32>,
    #[command(flatten)]
    pub argon2: Argon2Args,
}

/// True if two of the given descriptors are the same.
fn same_fd_twice(fds: &[Option<i32>]) -> bool {
    let given: Vec<i32> = fds.iter().flatten().copied().collect();
    (1..given.len()).any(|i| given[..i].contains(&given[i]))
}

pub fn run(args: &RecoverArgs) -> Result<(), CliError> {
    if same_fd_twice(&[
        args.recovery_key_fd,
        args.new_recovery_key_fd,
        args.new_password_fd,
    ]) {
        return Err(CliError::Usage(
            "--recovery-key-fd, --new-recovery-key-fd and --new-password-fd must differ".into(),
        ));
    }
    super::require_vault(&args.vault_dir)?;
    let params = args.argon2.params()?;
    // The given key file, else the old `.cd-key` of the vault, else a new
    // file in ~/.crypto-drive/keys (keypath).
    let path = match keypath::existing_key_file(&args.vault_dir, args.key_file.as_deref()) {
        Some(p) => p,
        None => keypath::new_key_file(&args.vault_dir, SystemTime::now())?,
    };
    if path.exists() && !args.overwrite {
        return Err(CliError::Usage(
            "key file exists; use --overwrite to replace it".into(),
        ));
    }
    let text = read_recovery_key(args.recovery_key_fd)?;
    let mk = decode_recovery_key(text.expose_secret())?;
    // The decision below depends on the state of the tree, so no mount or
    // rotation may change it before the key file is written.
    let _lock = match lock_vault(&args.vault_dir) {
        Ok(lock) => lock,
        Err(Error::AlreadyMounted) => {
            return Err(CliError::Usage(
                "the vault is in use (mounted, or a key rotation runs); stop it first".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    // Checks the vault tag, so a key of another vault is refused.
    let vault = match open_with_master_key(&args.vault_dir, &mk) {
        Ok(vault) => vault,
        Err(Error::WrongKey) => {
            return Err(CliError::Usage(
                "the recovery key does not belong to this vault, or it is from before the last key rotation".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let mut keys = KeySet::single(vault.marker.epoch, mk);
    // During an unfinished rotation the key set needs the new key too, or
    // everything already written with it is lost (HS 7).
    if rotation_unfinished(&vault)? {
        // Without the flag the second key is asked only on a terminal, so
        // a script gets the error and does not wait.
        if args.new_recovery_key_fd.is_none() && !std::io::stdin().is_terminal() {
            return Err(CliError::Usage(BOTH_KEYS_NEEDED.into()));
        }
        let text = read_key_text(
            args.new_recovery_key_fd,
            "Recovery key of the unfinished rotation: ",
            BOTH_KEYS_NEEDED,
        )?;
        let next = decode_recovery_key(text.expose_secret())?;
        match verify_next_key(&vault, &next) {
            Ok(()) => {}
            Err(Error::WrongKey) => {
                return Err(CliError::Usage(
                    "the new recovery key does not belong to the unfinished key rotation of this vault".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
        keys = keys.with_next(next)?;
    } else if args.new_recovery_key_fd.is_some() {
        eprintln!("note: no unfinished key rotation found; the second recovery key is not needed");
    }
    let new = read_new_password(&PasswordArgs {
        fd: args.new_password_fd,
        env_var: NEW_PASSWORD_ENV,
    })?;
    let key_file = KeyFile::new(&keys, new.expose_secret().as_bytes(), params)?;
    if path.exists() {
        key_file.save_replace(&path)?;
    } else {
        key_file.save_new(&path)?;
    }
    super::print_key_file_note(&path);
    Ok(())
}
