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

//! `crypto-drive mount`.

use std::cell::RefCell;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crypto_drive_core::fs::CryptoFs;
use crypto_drive_core::secret::mlock_failed;
use crypto_drive_core::vault::{lock_vault, unlock_vault};
use crypto_drive_fuse::{MountRequest, mount_and_wait};
use nix::unistd::{ForkResult, fork, pipe, setsid};
use secrecy::ExposeSecret;

use crate::password::{PASSWORD_ENV, PasswordArgs, read_password};
use crate::{CliError, MLOCK_WARNING};

#[derive(clap::Args, Debug)]
pub struct MountArgs {
    pub vault_dir: PathBuf,
    pub mountpoint: PathBuf,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub password_fd: Option<i32>,
    /// Run in the background after the drive is mounted.
    #[arg(long)]
    pub daemon: bool,
    /// Extra mount option (repeatable).
    #[arg(short = 'o', value_name = "OPT")]
    pub options: Vec<String>,
    /// Detailed logs, including clear file names.
    #[arg(long)]
    pub debug: bool,
}

const NESTED: &str = "the mount point must not be inside the vault, and the vault must not be inside the mount point";

/// Checks the paths before anything else happens (no password is asked).
pub fn validate_mount_paths(vault_dir: &Path, mountpoint: &Path) -> Result<(), CliError> {
    let vault = vault_dir.canonicalize().map_err(|e| {
        CliError::Usage(format!(
            "the vault directory does not exist: {}: {e}",
            vault_dir.display()
        ))
    })?;
    let mp = mountpoint
        .canonicalize()
        .map_err(|e| CliError::Usage(mount_point_error(mountpoint, &e)))?;
    if mp.starts_with(&vault) || vault.starts_with(&mp) {
        return Err(CliError::Usage(NESTED.into()));
    }
    if !mp.is_dir() {
        return Err(CliError::Usage("the mount point is not a directory".into()));
    }
    if std::fs::read_dir(&mp)?.next().is_some() {
        return Err(CliError::Usage("the mount point is not empty".into()));
    }
    Ok(())
}

/// The message for a mount point that cannot be resolved. A drive whose
/// process ended without an unmount (killed, crashed) leaves a dead mount:
/// Linux reports ENOTCONN ("Transport endpoint is not connected"), macOS
/// ENXIO ("Device not configured"). Then the message names the way out.
fn mount_point_error(mountpoint: &Path, e: &std::io::Error) -> String {
    let mut message = format!(
        "the mount point does not exist: {}: {e}",
        mountpoint.display()
    );
    let dead = [nix::errno::Errno::ENOTCONN, nix::errno::Errno::ENXIO]
        .iter()
        .any(|errno| e.raw_os_error() == Some(*errno as i32));
    if dead {
        message.push_str(&format!(
            "\nthe mount point looks like a drive that was not unmounted cleanly; \
             run `crypto-drive unmount --force {}`",
            mountpoint.display()
        ));
    }
    message
}

/// The volume name: the vault directory's name without `,` and `=`.
fn volume_name(vault_dir: &Path) -> String {
    vault_dir
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .map(|n| n.replace([',', '='], "_"))
        .unwrap_or_else(|| "crypto-drive".to_string())
}

/// The status line the daemon child sends to the parent.
#[derive(Debug, PartialEq, Eq)]
enum Status {
    /// `ok\n`: the drive is mounted.
    Mounted,
    /// `err <message>\n`: the mount failed.
    Failed(String),
    /// `warn <text>\n`: a warning; more lines follow.
    Warning(String),
    /// No (complete) line: the child ended without a result.
    Ended,
}

fn parse_status_line(line: &str) -> Status {
    if line == "ok\n" {
        return Status::Mounted;
    }
    if let Some(text) = line
        .strip_prefix("warn ")
        .and_then(|t| t.strip_suffix('\n'))
    {
        return Status::Warning(text.to_string());
    }
    match line.strip_prefix("err ").and_then(|m| m.strip_suffix('\n')) {
        Some(message) => Status::Failed(message.to_string()),
        None => Status::Ended,
    }
}

/// Reads status lines up to the final one; returns the warnings before it.
fn read_status(mut reader: impl BufRead) -> std::io::Result<(Vec<String>, Status)> {
    let mut warnings = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        match parse_status_line(&line) {
            Status::Warning(text) => warnings.push(text),
            status => return Ok((warnings, status)),
        }
    }
}

/// What the child sends once the drive is mounted: warnings, then `ok`.
fn ready_report(mlock_failed: bool) -> String {
    let mut report = String::new();
    if mlock_failed {
        report.push_str(&format!("warn {MLOCK_WARNING}\n"));
    }
    report.push_str("ok\n");
    report
}

/// The `err` line for a message; newlines become spaces.
fn error_line(message: &str) -> String {
    format!("err {}\n", message.replace('\n', " "))
}

/// The message for a failed `mount_and_wait`, with a hint if the drive is busy.
fn mount_error_message(e: &std::io::Error, mountpoint: &Path) -> String {
    if e.kind() == std::io::ErrorKind::ResourceBusy {
        format!(
            "{e}\nthe drive is busy; close open files and run `crypto-drive unmount --force {}`",
            mountpoint.display()
        )
    } else {
        e.to_string()
    }
}

/// Returns the exit code.
pub fn run(args: &MountArgs) -> Result<i32, CliError> {
    super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    validate_mount_paths(&args.vault_dir, &args.mountpoint)?;
    if args.daemon {
        return daemon(args);
    }
    mount(args, || {
        // Checked here: after the mount ends nobody would read it in time.
        if mlock_failed() {
            eprintln!("warning: {MLOCK_WARNING}");
        }
        eprintln!(
            "Mounted {} at {}. Press Ctrl+C to unmount.",
            args.vault_dir.display(),
            args.mountpoint.display()
        );
    })
}

/// Locks, unlocks and mounts; blocks until the drive is unmounted.
fn mount(args: &MountArgs, ready: impl FnOnce()) -> Result<i32, CliError> {
    let key_file = super::require_vault_and_key_file(&args.vault_dir, args.key_file.as_deref())?;
    // Fail fast, before the password is asked.
    let _lock = lock_vault(&args.vault_dir)?;
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
    drop(password);
    drop(keys);
    let fs = Arc::new(CryptoFs::new(vault)?);
    let req = MountRequest {
        mountpoint: args.mountpoint.clone(),
        volume_name: volume_name(&args.vault_dir),
        extra_options: args.options.clone(),
    };
    match mount_and_wait(fs, &req, ready) {
        Ok(_) => Ok(0),
        Err(e) => Err(CliError::Usage(mount_error_message(&e, &args.mountpoint))),
    }
}

/// Forks. The parent waits for the status line, the child mounts.
fn daemon(args: &MountArgs) -> Result<i32, CliError> {
    let (read_end, write_end) = pipe().map_err(std::io::Error::from)?;
    // SAFETY: no thread has been started yet (main only set up the logger,
    // which starts none), so the child is a full copy of a single-threaded
    // process and may run any code.
    match unsafe { fork() }.map_err(std::io::Error::from)? {
        ForkResult::Parent { .. } => {
            drop(write_end);
            parent(File::from(read_end), args)
        }
        ForkResult::Child => {
            drop(read_end);
            Ok(child(File::from(write_end), args))
        }
    }
}

fn parent(pipe: File, args: &MountArgs) -> Result<i32, CliError> {
    // A short limit: the child sends a few short lines.
    let (warnings, status) = read_status(BufReader::new(pipe.take(4096)))?;
    for text in warnings {
        eprintln!("warning: {text}");
    }
    match status {
        Status::Mounted => {
            eprintln!(
                "Mounted {} at {}.",
                args.vault_dir.display(),
                args.mountpoint.display()
            );
            Ok(0)
        }
        Status::Failed(message) => Err(CliError::Usage(message)),
        Status::Ended | Status::Warning(_) => Err(CliError::Usage(
            "the mount process ended without a result".into(),
        )),
    }
}

/// Runs in the forked child. Returns the exit code.
fn child(pipe: File, args: &MountArgs) -> i32 {
    let pipe = RefCell::new(Some(pipe));
    let result = mount(args, || {
        if let Some(mut p) = pipe.borrow_mut().take()
            && let Err(e) = p.write_all(ready_report(mlock_failed()).as_bytes())
        {
            log::warn!("could not report the mount to the parent: {e}");
        }
        detach();
    });
    match (result, pipe.borrow_mut().take()) {
        (Ok(code), _) => code,
        // Before `ready`: the parent prints the error.
        (Err(e), Some(mut p)) => {
            let _ = p.write_all(error_line(&e.to_string()).as_bytes());
            2
        }
        // After `ready` stderr is /dev/null; the log is all that is left.
        (Err(e), None) => {
            log::error!("{e}");
            2
        }
    }
}

/// Leaves the terminal: new session, stdio on /dev/null.
fn detach() {
    if let Err(e) = setsid() {
        log::warn!("setsid failed: {e}");
    }
    let null = match File::options().read(true).write(true).open("/dev/null") {
        Ok(f) => f,
        Err(e) => {
            log::warn!("could not open /dev/null: {e}");
            return;
        }
    };
    for (name, result) in [
        ("stdin", nix::unistd::dup2_stdin(&null)),
        ("stdout", nix::unistd::dup2_stdout(&null)),
        ("stderr", nix::unistd::dup2_stderr(&null)),
    ] {
        if let Err(e) = result {
            log::warn!("could not redirect {name}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const NESTED: &str = "the mount point must not be inside the vault, and the vault must not be inside the mount point";

    fn usage(r: Result<(), CliError>) -> String {
        match r {
            Err(CliError::Usage(m)) => m,
            other => panic!("unexpected result: {other:?}"),
        }
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let mnt = dir.path().join("mnt");
        std::fs::create_dir(&vault).unwrap();
        std::fs::write(vault.join(".cd-vault"), b"x").unwrap();
        std::fs::create_dir(&mnt).unwrap();
        (dir, vault, mnt)
    }

    #[test]
    fn separate_empty_directories_are_ok() {
        let (_dir, vault, mnt) = setup();
        validate_mount_paths(&vault, &mnt).unwrap();
    }

    #[test]
    fn mountpoint_inside_the_vault_fails() {
        let (_dir, vault, _mnt) = setup();
        let inner = vault.join("inner");
        std::fs::create_dir(&inner).unwrap();
        assert_eq!(usage(validate_mount_paths(&vault, &inner)), NESTED);
    }

    #[test]
    fn vault_inside_the_mountpoint_fails() {
        let (dir, vault, _mnt) = setup();
        assert_eq!(usage(validate_mount_paths(&vault, dir.path())), NESTED);
    }

    #[test]
    fn the_same_path_fails() {
        let (_dir, vault, _mnt) = setup();
        assert_eq!(usage(validate_mount_paths(&vault, &vault)), NESTED);
        // Also when spelled differently.
        let other = vault.join("..").join("vault");
        assert_eq!(usage(validate_mount_paths(&vault, &other)), NESTED);
    }

    #[test]
    fn similar_prefix_is_not_nested() {
        let (dir, vault, _mnt) = setup();
        let sibling = dir.path().join("vault2");
        std::fs::create_dir(&sibling).unwrap();
        validate_mount_paths(&vault, &sibling).unwrap();
    }

    #[test]
    fn non_empty_mountpoint_fails() {
        let (_dir, vault, mnt) = setup();
        std::fs::write(mnt.join("f"), b"x").unwrap();
        assert_eq!(
            usage(validate_mount_paths(&vault, &mnt)),
            "the mount point is not empty"
        );
    }

    #[test]
    fn missing_mountpoint_fails() {
        let (dir, vault, _mnt) = setup();
        let m = usage(validate_mount_paths(&vault, &dir.path().join("nope")));
        assert!(m.starts_with("the mount point does not exist"), "{m}");
    }

    #[test]
    fn dead_mount_point_gets_a_hint() {
        let mp = Path::new("/mnt/x");
        let hint = "\nthe mount point looks like a drive that was not unmounted \
                    cleanly; run `crypto-drive unmount --force /mnt/x`";
        for errno in [libc_errno::ENOTCONN, libc_errno::ENXIO] {
            let e = std::io::Error::from_raw_os_error(errno);
            let m = mount_point_error(mp, &e);
            assert!(
                m.starts_with("the mount point does not exist: /mnt/x: "),
                "{m}"
            );
            assert!(m.ends_with(hint), "{m}");
        }
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(!mount_point_error(mp, &missing).contains("unmount"));
    }

    /// Errno values without a `libc` dependency on Linux.
    mod libc_errno {
        pub const ENOTCONN: i32 = nix::errno::Errno::ENOTCONN as i32;
        pub const ENXIO: i32 = nix::errno::Errno::ENXIO as i32;
    }

    #[test]
    fn mountpoint_that_is_a_file_fails() {
        let (dir, vault, _mnt) = setup();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            usage(validate_mount_paths(&vault, &file)),
            "the mount point is not a directory"
        );
    }

    #[test]
    fn missing_vault_fails() {
        let (dir, _vault, mnt) = setup();
        let m = usage(validate_mount_paths(&dir.path().join("nope"), &mnt));
        assert!(m.starts_with("the vault directory does not exist"), "{m}");
    }

    #[test]
    fn volume_name_replaces_comma_and_equals() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("my,vault=1");
        std::fs::create_dir(&vault).unwrap();
        assert_eq!(volume_name(&vault), "my_vault_1");
        assert_eq!(volume_name(Path::new("/")), "crypto-drive");
    }

    #[test]
    fn status_lines() {
        assert_eq!(parse_status_line("ok\n"), Status::Mounted);
        assert_eq!(
            parse_status_line("err wrong password\n"),
            Status::Failed("wrong password".into())
        );
        assert_eq!(parse_status_line(""), Status::Ended);
        assert_eq!(parse_status_line("ok"), Status::Ended);
        assert_eq!(parse_status_line("garbage\n"), Status::Ended);
    }

    #[test]
    fn warn_status_lines() {
        assert_eq!(
            parse_status_line("warn some text\n"),
            Status::Warning("some text".into())
        );
        assert_eq!(parse_status_line("warn some text"), Status::Ended);
    }

    #[test]
    fn ready_report_holds_warnings_before_ok() {
        assert_eq!(ready_report(false), "ok\n");
        assert_eq!(ready_report(true), format!("warn {MLOCK_WARNING}\nok\n"));
    }

    #[test]
    fn read_status_collects_warnings() {
        let input = format!("warn {MLOCK_WARNING}\nwarn b\nok\n");
        let (warnings, status) = read_status(std::io::Cursor::new(input)).unwrap();
        assert_eq!(warnings, vec![MLOCK_WARNING.to_string(), "b".into()]);
        assert_eq!(status, Status::Mounted);
        let (warnings, status) = read_status(std::io::Cursor::new("warn a\n")).unwrap();
        assert_eq!(warnings, vec!["a".to_string()]);
        assert_eq!(status, Status::Ended);
        let (warnings, status) = read_status(std::io::Cursor::new("err x\n")).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(status, Status::Failed("x".into()));
    }

    #[test]
    fn error_line_is_one_line() {
        assert_eq!(error_line("a\nb"), "err a b\n");
        assert_eq!(
            parse_status_line(&error_line("a\nb")),
            Status::Failed("a b".into())
        );
    }

    #[test]
    fn busy_error_gets_a_hint() {
        let mp = Path::new("/mnt/x");
        let busy = std::io::Error::from(std::io::ErrorKind::ResourceBusy);
        let m = mount_error_message(&busy, mp);
        assert!(m.ends_with(
            "\nthe drive is busy; close open files and run `crypto-drive unmount --force /mnt/x`"
        ), "{m}");
        let other = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(!mount_error_message(&other, mp).contains("busy"));
    }
}
