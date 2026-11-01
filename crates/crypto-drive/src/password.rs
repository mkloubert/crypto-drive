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

//! Password and recovery key input.

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::CliError;

/// Where a password can come from.
pub struct PasswordArgs {
    pub fd: Option<i32>,
    pub env_var: &'static str,
}

/// Environment variable for the (old) password.
pub const PASSWORD_ENV: &str = "CRYPTO_DRIVE_PASSWORD";
/// Environment variable for the new password.
pub const NEW_PASSWORD_ENV: &str = "CRYPTO_DRIVE_NEW_PASSWORD";

/// Removes one trailing `\n` or `\r\n`.
pub fn strip_one_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

fn no_source_message(args: &PasswordArgs) -> String {
    let fd_flag = if args.env_var == NEW_PASSWORD_ENV {
        "--new-password-fd"
    } else {
        "--password-fd"
    };
    format!(
        "no password source: use a TTY, {fd_flag} or {}",
        args.env_var
    )
}

/// Reads a whole file descriptor. The descriptor is closed afterwards.
fn read_fd(fd: i32) -> Result<SecretString, CliError> {
    if fd < 0 {
        return Err(CliError::Usage(format!("invalid file descriptor {fd}")));
    }
    // SAFETY: the user hands this descriptor to the process on purpose and it
    // is used only here, so taking ownership (and closing it) is sound.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut file = std::fs::File::from(owned);
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)?;
    strip_one_newline(&mut text);
    Ok(SecretString::from(std::mem::take(&mut *text)))
}

fn non_empty(secret: SecretString) -> Result<SecretString, CliError> {
    if secret.expose_secret().is_empty() {
        return Err(CliError::Usage("the password must not be empty".into()));
    }
    Ok(secret)
}

fn from_fd_or_env(args: &PasswordArgs) -> Result<Option<SecretString>, CliError> {
    if let Some(fd) = args.fd {
        return read_fd(fd).map(Some);
    }
    if let Some(value) = std::env::var_os(args.env_var) {
        eprintln!(
            "warning: reading the password from {}; other processes of the same user may see it",
            args.env_var
        );
        let text = value
            .into_string()
            .map_err(|_| CliError::Usage(format!("{} is not valid UTF-8", args.env_var)))?;
        return Ok(Some(SecretString::from(text)));
    }
    Ok(None)
}

/// Reads a password: fd, then environment variable, then the TTY.
pub fn read_password(args: &PasswordArgs, prompt: &str) -> Result<SecretString, CliError> {
    if let Some(secret) = from_fd_or_env(args)? {
        return non_empty(secret);
    }
    let text = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|_| CliError::Usage(no_source_message(args)))?,
    );
    non_empty(SecretString::from(text.to_string()))
}

/// Like `read_password`, but at the TTY the password is asked twice.
pub fn read_new_password(args: &PasswordArgs) -> Result<SecretString, CliError> {
    if let Some(secret) = from_fd_or_env(args)? {
        return non_empty(secret);
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("New password: ")
            .map_err(|_| CliError::Usage(no_source_message(args)))?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Repeat new password: ")
            .map_err(|_| CliError::Usage(no_source_message(args)))?,
    );
    if *first != *second {
        return Err(CliError::Usage("the passwords do not match".into()));
    }
    non_empty(SecretString::from(first.to_string()))
}

/// Reads the recovery key from `--recovery-key-fd` or the TTY.
pub fn read_recovery_key(fd: Option<i32>) -> Result<SecretString, CliError> {
    read_key_text(
        fd,
        "Recovery key: ",
        "no recovery key source: use a TTY or --recovery-key-fd",
    )
}

/// Reads a key from `fd` or, without one, asks `prompt` on the TTY. Without
/// a TTY the error is `no_source`.
pub fn read_key_text(
    fd: Option<i32>,
    prompt: &str,
    no_source: &str,
) -> Result<SecretString, CliError> {
    if let Some(fd) = fd {
        return read_fd(fd);
    }
    let text = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|_| CliError::Usage(no_source.into()))?,
    );
    Ok(SecretString::from(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;

    #[test]
    fn strips_exactly_one_newline() {
        for (input, want) in [
            ("pw\n", "pw"),
            ("pw\r\n", "pw"),
            ("pw\n\n", "pw\n"),
            ("pw", "pw"),
        ] {
            let mut s = input.to_string();
            strip_one_newline(&mut s);
            assert_eq!(s, want);
        }
    }

    fn pipe_with(data: &[u8]) -> i32 {
        let (r, w) = nix::unistd::pipe().unwrap();
        let mut file = std::fs::File::from(w);
        file.write_all(data).unwrap();
        drop(file);
        r.into_raw_fd()
    }

    #[test]
    fn read_password_from_fd() {
        let args = PasswordArgs {
            fd: Some(pipe_with(b"secret\n")),
            env_var: PASSWORD_ENV,
        };
        let pw = read_password(&args, "x").unwrap();
        assert_eq!(pw.expose_secret(), "secret");
    }

    #[test]
    fn empty_password_is_rejected() {
        let args = PasswordArgs {
            fd: Some(pipe_with(b"\n")),
            env_var: PASSWORD_ENV,
        };
        assert!(matches!(
            read_password(&args, "x"),
            Err(CliError::Usage(m)) if m == "the password must not be empty"
        ));
    }

    #[test]
    fn negative_fd_is_rejected() {
        assert!(matches!(
            read_recovery_key(Some(-1)),
            Err(CliError::Usage(_))
        ));
    }
}
