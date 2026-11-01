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

//! Subcommands.

pub mod check;
pub mod init;
pub mod mount;
pub mod passwd;
pub mod recover;
pub mod recovery;
pub mod rotate;
pub mod unmount;

use std::io::Write;
use std::path::{Path, PathBuf};

use crypto_drive_core::keyfile::Argon2Params;
use crypto_drive_core::vault::VAULT_FILE;
use zeroize::Zeroizing;

use crate::CliError;
use crate::keypath::{NO_KEY_FILE, existing_key_file};

/// Argon2 flags shared by `init`, `passwd` and `recover`.
#[derive(clap::Args, Debug)]
pub struct Argon2Args {
    /// Argon2 memory cost in KiB.
    #[arg(long = "argon2-memory", default_value_t = Argon2Params::default().m_kib)]
    pub memory: u32,
    /// Argon2 iterations.
    #[arg(long = "argon2-iterations", default_value_t = Argon2Params::default().t)]
    pub iterations: u32,
    /// Argon2 parallelism.
    #[arg(long = "argon2-parallelism", default_value_t = Argon2Params::default().p)]
    pub parallelism: u32,
}

impl Argon2Args {
    /// Validates the values and warns if they are below the defaults.
    pub fn params(&self) -> Result<Argon2Params, CliError> {
        let params = Argon2Params {
            m_kib: self.memory,
            t: self.iterations,
            p: self.parallelism,
        };
        params.validate()?;
        if params.is_below_default() {
            eprintln!("warning: Argon2 parameters are below the recommended defaults");
        }
        Ok(params)
    }
}

/// Checks that `vault_dir` is a vault, before any password is asked, so a
/// missing directory or marker gives a clear message.
pub fn require_vault(vault_dir: &Path) -> Result<(), CliError> {
    let shown = vault_dir.display();
    if !vault_dir.is_dir() {
        return Err(CliError::Usage(format!(
            "{shown} does not exist; create a vault with: crypto-drive init {shown}"
        )));
    }
    if !vault_dir.join(VAULT_FILE).is_file() {
        return Err(CliError::Usage(format!(
            "{shown} is not a crypto-drive vault (no {VAULT_FILE} file); create one with: crypto-drive init {shown}"
        )));
    }
    Ok(())
}

/// Checks that the vault and its key file exist (see `require_vault`) and
/// returns the key file: the given one, else the old `.cd-key` inside the
/// vault (`keypath`).
pub fn require_vault_and_key_file(
    vault_dir: &Path,
    key_file: Option<&Path>,
) -> Result<PathBuf, CliError> {
    require_vault(vault_dir)?;
    let Some(path) = existing_key_file(vault_dir, key_file) else {
        return Err(CliError::Usage(NO_KEY_FILE.into()));
    };
    if !path.is_file() {
        return Err(CliError::Usage(format!(
            "key file {} not found; give the right --key-file, or write a new one with: crypto-drive recover {}",
            path.display(),
            vault_dir.display()
        )));
    }
    Ok(path)
}

/// Tells where the key file is (stderr, so stdout keeps only the recovery
/// key line).
pub fn print_key_file_note(key_file: &Path) {
    eprintln!("Key file: {}", key_file.display());
    eprintln!(
        "Keep it safe and pass it with --key-file to mount, check, passwd, recovery-key and rotate-key."
    );
}

/// Writes `RECOVERY KEY: <key>` to stdout. If that fails (for example a
/// closed pipe), the line goes to stderr, so the key is never lost. Never
/// panics.
pub fn write_recovery_key_line(key: &str) {
    let line = Zeroizing::new(format!("RECOVERY KEY: {key}\n"));
    let mut out = std::io::stdout().lock();
    if out
        .write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .is_err()
    {
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
}

/// Prints the recovery key (stdout) and the note (stderr).
pub fn print_recovery_key(key: &str) {
    write_recovery_key_line(key);
    eprintln!(
        "Write this recovery key down and keep it offline. Anyone with it can open the vault."
    );
}
