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

//! `crypto-drive rotate-key`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use crypto_drive_core::keyfile::Argon2Params;
use crypto_drive_core::rotate::{RotateOptions, rotate_key};
use secrecy::ExposeSecret;

use super::{Argon2Args, write_recovery_key_line};
use crate::CliError;
use crate::password::{PASSWORD_ENV, PasswordArgs, read_password};

/// Printed on stderr before any work (HS 9.1).
const WARNING: &str = "Do not use this vault on any other device until the rotation has finished. Afterwards every device needs the new key file. Your sync client will upload the whole vault again.";

#[derive(clap::Args, Debug)]
pub struct RotateArgs {
    pub vault_dir: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub password_fd: Option<i32>,
    /// Argon2 memory cost in KiB (default: keep the key file's value).
    #[arg(long = "argon2-memory")]
    pub memory: Option<u32>,
    /// Argon2 iterations (default: keep the key file's value).
    #[arg(long = "argon2-iterations")]
    pub iterations: Option<u32>,
    /// Argon2 parallelism (default: keep the key file's value).
    #[arg(long = "argon2-parallelism")]
    pub parallelism: Option<u32>,
    /// Do not ask for confirmation.
    #[arg(long)]
    pub yes: bool,
}

impl RotateArgs {
    /// `None` if no Argon2 flag was given, so the key file keeps its values.
    fn argon2(&self) -> Result<Option<Argon2Params>, CliError> {
        if self.memory.is_none() && self.iterations.is_none() && self.parallelism.is_none() {
            return Ok(None);
        }
        let d = Argon2Params::default();
        Argon2Args {
            memory: self.memory.unwrap_or(d.m_kib),
            iterations: self.iterations.unwrap_or(d.t),
            parallelism: self.parallelism.unwrap_or(d.p),
        }
        .params()
        .map(Some)
    }
}

/// Asks `Continue? [y/N]` on a TTY; without a TTY `--yes` is needed.
fn confirm(yes: bool) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "add --yes to confirm the key rotation".into(),
        ));
    }
    eprint!("Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Usage("the key rotation was not confirmed".into()))
    }
}

pub fn run(args: &RotateArgs) -> Result<(), CliError> {
    let key_file = super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    let argon2 = args.argon2()?;
    eprintln!("{WARNING}");
    confirm(args.yes)?;
    let password = read_password(
        &PasswordArgs {
            fd: args.password_fd,
            env_var: PASSWORD_ENV,
        },
        "Password: ",
    )?;
    let opts = RotateOptions {
        key_file: Some(key_file),
        argon2,
    };
    let tty = std::io::stderr().is_terminal();
    let mut progress = |done: u64| {
        if tty {
            eprint!("\r{done} entries done");
        }
    };
    // Shown at once, so it is not lost if a later step fails.
    let mut on_key = |key: &str| {
        write_recovery_key_line(key);
        eprintln!("Keep the old recovery key until the rotation has finished.");
    };
    let result = rotate_key(
        &args.vault_dir,
        password.expose_secret().as_bytes(),
        &opts,
        &mut progress,
        &mut on_key,
    );
    if tty {
        eprintln!();
    }
    let report = result?;
    if !tty {
        eprintln!("{} entries done", report.entries_done);
    }
    Ok(())
}
