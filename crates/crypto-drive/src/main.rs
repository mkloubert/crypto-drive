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

//! The `crypto-drive` command line tool.

mod cmd;
mod hardening;
mod keypath;
mod limits;
mod password;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Core(#[from] crypto_drive_core::Error),
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Parser, Debug)]
#[command(name = "crypto-drive", version, about = "Encrypted drive")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new vault.
    Init(cmd::init::InitArgs),
    /// Mount a vault.
    Mount(cmd::mount::MountArgs),
    /// Unmount a drive.
    Unmount(cmd::unmount::UnmountArgs),
    /// Change the password.
    Passwd(cmd::passwd::PasswdArgs),
    /// Print the recovery key.
    RecoveryKey(cmd::recovery::RecoveryKeyArgs),
    /// Write a new key file from a recovery key.
    Recover(cmd::recover::RecoverArgs),
    /// Replace the master key and re-encrypt the vault.
    RotateKey(cmd::rotate::RotateArgs),
    /// Check the vault for problems.
    Check(cmd::check::CheckArgs),
}

/// Printed when key memory could not be locked (spec 8).
pub(crate) const MLOCK_WARNING: &str = "could not lock key memory; keys may be swapped to disk";

fn run(command: &Command) -> Result<i32, CliError> {
    match command {
        Command::Init(a) => cmd::init::run(a).map(|()| 0),
        Command::Passwd(a) => cmd::passwd::run(a).map(|()| 0),
        Command::RecoveryKey(a) => cmd::recovery::run(a).map(|()| 0),
        Command::Recover(a) => cmd::recover::run(a).map(|()| 0),
        Command::RotateKey(a) => cmd::rotate::run(a).map(|()| 0),
        Command::Check(a) => cmd::check::run(a),
        Command::Mount(a) => cmd::mount::run(a),
        Command::Unmount(a) => cmd::unmount::run(a).map(|()| 0),
    }
}

/// `--debug` forces the level `debug`; otherwise `RUST_LOG` or `warn`.
/// Starts no thread, so `mount --daemon` can still fork.
fn init_logger(debug: bool) {
    if debug {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }
    // Also for `RUST_LOG=debug`: debug messages may hold clear names.
    if log::max_level() >= log::LevelFilter::Debug {
        eprintln!("warning: debug logging shows clear file names");
    }
}

fn main() -> ExitCode {
    hardening::disable_core_dumps();
    hardening::deny_debugging();
    let cli = Cli::parse();
    init_logger(matches!(&cli.command, Command::Mount(a) if a.debug));
    limits::raise_open_file_limit();
    let result = run(&cli.command);
    // `mount` warns once the drive is mounted (see cmd/mount.rs).
    if !matches!(cli.command, Command::Mount(_)) && crypto_drive_core::secret::mlock_failed() {
        eprintln!("warning: {MLOCK_WARNING}");
    }
    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
