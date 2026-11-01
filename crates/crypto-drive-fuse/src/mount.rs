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

//! Mounting and unmounting.

use crate::FuseFs;
use crypto_drive_core::fs::CryptoFs;
use fuser::{Config, MountOption};
use nix::sys::signal::{SigSet, Signal};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};

/// Number of FUSE worker threads on this OS.
///
/// fuser 0.18 supports more than one worker thread only on Linux. On other
/// systems `Session::run` fails with "n_threads != 1 is only supported on
/// Linux" after the mount already exists, so the mount would hang. We do not
/// set `clone_fd` (also Linux only); it stays at its default `false`.
fn fuse_threads() -> usize {
    if cfg!(target_os = "linux") { 4 } else { 1 }
}

/// What to mount and how.
#[derive(Debug, Clone)]
pub struct MountRequest {
    pub mountpoint: PathBuf,
    pub volume_name: String,
    pub extra_options: Vec<String>,
}

/// Why `mount_and_wait` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// SIGINT, SIGTERM or SIGHUP arrived; the drive was unmounted by us.
    Signal,
    /// Somebody else unmounted the drive.
    Unmounted,
}

/// The FUSE mount options for a request.
pub fn mount_options(req: &MountRequest) -> Vec<MountOption> {
    let mut options = vec![
        MountOption::FSName("crypto-drive".to_string()),
        MountOption::DefaultPermissions,
    ];
    // No `noappledouble` on macOS: it makes the kernel refuse `.DS_Store`
    // (and `._*`) files, and Finder aborts a whole folder copy when it
    // cannot write the `.DS_Store` of the source (error -8062). Such files
    // are stored encrypted like any other file. The drive supports xattrs
    // (in memory), so macOS needs no `._*` files for them.
    #[cfg(target_os = "macos")]
    options.push(MountOption::CUSTOM(format!("volname={}", req.volume_name)));
    options.extend(req.extra_options.iter().cloned().map(MountOption::CUSTOM));
    options
}

/// The libfuse `-o` text of one of our mount options.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn option_text(option: &MountOption) -> io::Result<String> {
    match option {
        MountOption::FSName(name) => Ok(format!("fsname={name}")),
        MountOption::DefaultPermissions => Ok("default_permissions".to_string()),
        MountOption::CUSTOM(text) => Ok(text.clone()),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported mount option: {other:?}"),
        )),
    }
}

/// Mounts and starts serving requests in the background.
#[cfg(not(target_os = "macos"))]
fn start(fs: FuseFs, req: &MountRequest, config: &Config) -> io::Result<Running> {
    Ok(Running {
        session: fuser::spawn_mount(fs, &req.mountpoint, config)?,
    })
}

/// Mounts with libfuse's `fuse_mount()` (see `macos_mount`) and starts
/// serving requests in the background.
#[cfg(target_os = "macos")]
fn start(fs: FuseFs, req: &MountRequest, config: &Config) -> io::Result<Running> {
    let options = config
        .mount_options
        .iter()
        .map(option_text)
        .collect::<io::Result<Vec<_>>>()?;
    let (fd, mount) = crate::macos_mount::mount(&req.mountpoint, &options)?;
    let session = match fuser::Session::from_fd(fs, fd, config.acl, config.clone()) {
        Ok(session) => session,
        Err(e) => {
            if let Err(u) = mount.unmount() {
                log::warn!("could not unmount after a failed start: {u}");
            }
            return Err(e);
        }
    };
    Ok(Running {
        session: session.spawn()?,
        mount,
    })
}

/// A mounted drive whose requests are served in the background.
struct Running {
    session: fuser::BackgroundSession,
    #[cfg(target_os = "macos")]
    mount: crate::macos_mount::MacMount,
}

impl Running {
    /// Unmounts the drive and waits until the background thread has ended.
    fn unmount_and_join(self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // fuser did not mount, so it would not unmount: do it here. If
            // this fails (busy), the session keeps running in the background.
            self.mount.unmount()?;
            self.session.join()
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.session.umount_and_join()
        }
    }

    /// Waits until the background thread has ended (after an outside unmount).
    fn join(self) -> io::Result<()> {
        self.session.join()
    }
}

fn sig_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// The signals that unmount the drive cleanly. SIGHUP comes when the
/// terminal of a mount in the foreground is closed; without it the process
/// would end at once, without unmount and without writing its buffers.
fn stop_signals() -> SigSet {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    signals.add(Signal::SIGHUP);
    signals
}

/// Mounts the drive, calls `ready` once the mount exists and blocks until
/// SIGINT/SIGTERM/SIGHUP or an outside unmount.
///
/// These signals are blocked in the calling thread (and so in all threads
/// started from it) and are taken by a waiter thread. That thread stays
/// blocked in `sigwait` after this function returns, so call this function
/// only from a process that ends afterwards (the CLI does).
pub fn mount_and_wait(
    fs: Arc<CryptoFs>,
    req: &MountRequest,
    ready: impl FnOnce(),
) -> Result<StopReason, io::Error> {
    let signals = stop_signals();
    // Block before any thread is started, so all of them inherit the mask.
    signals.thread_block().map_err(sig_err)?;

    let (stop_tx, stop_rx) = channel::<StopReason>();
    let (destroy_tx, destroy_rx) = channel::<()>();

    let mut config = Config::default();
    config.mount_options = mount_options(req);
    config.n_threads = Some(fuse_threads());
    let running = start(FuseFs::new(Arc::clone(&fs), Some(destroy_tx)), req, &config)?;

    forward(stop_tx.clone(), StopReason::Signal, move || {
        signals.wait().is_ok()
    });
    forward(stop_tx, StopReason::Unmounted, move || {
        destroy_rx.recv().is_ok()
    });
    ready();

    let reason = stop_rx.recv().unwrap_or(StopReason::Unmounted);
    match reason {
        StopReason::Signal => {
            let unmounted = running.unmount_and_join();
            if let Err(e) = fs.flush_all() {
                log::warn!("could not write all buffers after unmount: {e}");
            }
            unmounted?;
        }
        StopReason::Unmounted => running.join()?,
    }
    Ok(reason)
}

/// Runs `wait` in a thread; when it returns true, sends `reason`.
fn forward(
    tx: Sender<StopReason>,
    reason: StopReason,
    wait: impl FnOnce() -> bool + Send + 'static,
) {
    std::thread::spawn(move || {
        if wait() {
            // The receiver is gone when the mount loop has ended.
            let _ = tx.send(reason);
        }
    });
}

/// The command that unmounts a mountpoint. The caller runs it.
pub fn unmount_command(mountpoint: &Path, force: bool) -> Command {
    #[cfg(target_os = "macos")]
    let (program, force_flag) = ("umount", "-f");
    #[cfg(not(target_os = "macos"))]
    let (program, force_flag) = ("fusermount3", "-z");

    let mut cmd = Command::new(program);
    #[cfg(not(target_os = "macos"))]
    cmd.arg("-u");
    if force {
        cmd.arg(force_flag);
    }
    cmd.arg(mountpoint);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    fn req(extra: &[&str]) -> MountRequest {
        MountRequest {
            mountpoint: "/mnt/x".into(),
            volume_name: "My Vault".into(),
            extra_options: extra.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn option_text_matches_libfuse_syntax() {
        let texts: Vec<String> = mount_options(&req(&["backend=x"]))
            .iter()
            .map(|o| option_text(o).unwrap())
            .collect();
        assert_eq!(texts[0], "fsname=crypto-drive");
        assert_eq!(texts[1], "default_permissions");
        assert_eq!(texts.last().unwrap(), "backend=x");
        assert!(option_text(&MountOption::RO).is_err());
    }

    #[test]
    fn stop_signals_include_hangup() {
        let s = stop_signals();
        for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
            assert!(s.contains(sig), "{sig:?} missing");
        }
        assert!(!s.contains(Signal::SIGQUIT));
    }

    #[test]
    fn fuse_threads_per_os() {
        let n = fuse_threads();
        if cfg!(target_os = "linux") {
            assert_eq!(n, 4);
        } else {
            assert_eq!(n, 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn options_on_linux() {
        let o = mount_options(&req(&["allow_other"]));
        assert_eq!(
            o,
            vec![
                fuser::MountOption::FSName("crypto-drive".into()),
                fuser::MountOption::DefaultPermissions,
                fuser::MountOption::CUSTOM("allow_other".into()),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn options_on_macos() {
        let o = mount_options(&req(&["x"]));
        assert_eq!(
            o,
            vec![
                fuser::MountOption::FSName("crypto-drive".into()),
                fuser::MountOption::DefaultPermissions,
                fuser::MountOption::CUSTOM("volname=My Vault".into()),
                fuser::MountOption::CUSTOM("x".into()),
            ]
        );
    }

    fn parts(force: bool) -> (String, Vec<String>) {
        let c = unmount_command(Path::new("/mnt/x"), force);
        let args = c
            .get_args()
            .map(OsStr::to_string_lossy)
            .map(|s| s.into_owned())
            .collect();
        (c.get_program().to_string_lossy().into_owned(), args)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unmount_command_on_linux() {
        assert_eq!(
            parts(false),
            ("fusermount3".into(), vec!["-u".into(), "/mnt/x".into()])
        );
        assert_eq!(
            parts(true),
            (
                "fusermount3".into(),
                vec!["-u".into(), "-z".into(), "/mnt/x".into()]
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unmount_command_on_macos() {
        assert_eq!(parts(false), ("umount".into(), vec!["/mnt/x".into()]));
        assert_eq!(
            parts(true),
            ("umount".into(), vec!["-f".into(), "/mnt/x".into()])
        );
    }
}
