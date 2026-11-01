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

//! `crypto-drive unmount`.

use std::path::PathBuf;

use crypto_drive_fuse::unmount_command;

use crate::CliError;

#[derive(clap::Args, Debug)]
pub struct UnmountArgs {
    pub mountpoint: PathBuf,
    /// Unmount even if the drive is busy.
    #[arg(long)]
    pub force: bool,
}

/// The error message for a failed unmount tool.
fn failure_message(stderr: &str, program: &str) -> String {
    let text = stderr.trim_end();
    let mut message = if text.is_empty() {
        format!("{program} failed")
    } else {
        text.to_string()
    };
    if text.to_lowercase().contains("busy") {
        message.push_str("\nthe drive is busy; close open files or use --force");
    }
    message
}

pub fn run(args: &UnmountArgs) -> Result<(), CliError> {
    let mut cmd = unmount_command(&args.mountpoint, args.force);
    let program = cmd.get_program().to_string_lossy().into_owned();
    let out = cmd
        .output()
        .map_err(|e| CliError::Usage(format!("could not run {program}: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(CliError::Usage(failure_message(
        &String::from_utf8_lossy(&out.stderr),
        &program,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_message_passes_stderr_through() {
        assert_eq!(
            failure_message("fusermount3: entry not found\n", "fusermount3"),
            "fusermount3: entry not found"
        );
    }

    #[test]
    fn busy_gets_a_hint() {
        assert_eq!(
            failure_message("umount: /mnt/x: Resource Busy\n", "umount"),
            "umount: /mnt/x: Resource Busy\nthe drive is busy; close open files or use --force"
        );
    }

    #[test]
    fn empty_stderr_names_the_tool() {
        assert_eq!(failure_message("", "umount"), "umount failed");
    }
}
