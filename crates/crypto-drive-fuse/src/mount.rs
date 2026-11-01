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
use crypto_drive_core::fs::{CryptoFs, IDLE_FLUSH_AFTER, IDLE_FLUSH_TICK, MAX_DIRTY_AGE};
use fuser::{Config, MountOption};
use nix::sys::signal::{SigSet, Signal};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

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
    /// Tries a normal (not forced) unmount. A busy drive gives an error and
    /// stays mounted; the background thread keeps serving it.
    ///
    /// macOS: `unmount(2)` without flags (EBUSY when busy).
    /// Linux: `fusermount3 -u` without `-z`. fuser's own unmount would
    /// detach the drive lazily (`-z`): the process then waited, without a
    /// word, until the last program left the drive.
    #[cfg(target_os = "macos")]
    fn try_unmount(&self, _mountpoint: &Path) -> io::Result<()> {
        self.mount.unmount()
    }

    /// See the macOS variant.
    #[cfg(not(target_os = "macos"))]
    fn try_unmount(&self, mountpoint: &Path) -> io::Result<()> {
        let out = unmount_command(mountpoint, false).output()?;
        if out.status.success() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            if text.is_empty() {
                format!("fusermount3 failed: {}", out.status)
            } else {
                text
            },
        ))
    }

    /// Waits until the background thread has ended (after an unmount).
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
/// SIGINT/SIGTERM/SIGHUP or an outside unmount. A signal while the drive
/// is busy writes the buffers, logs a warning and keeps the drive mounted
/// (see `wait_for_stop`); the next signal tries again.
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
    let idle_flusher = start_idle_flusher(
        Arc::clone(&fs),
        IDLE_FLUSH_TICK,
        IDLE_FLUSH_AFTER,
        MAX_DIRTY_AGE,
    );

    forward(stop_tx.clone(), StopReason::Signal, move || {
        signals.wait().is_ok()
    });
    forward(stop_tx, StopReason::Unmounted, move || {
        destroy_rx.recv().is_ok()
    });
    ready();

    let reason = wait_for_stop(
        &stop_rx,
        || running.try_unmount(&req.mountpoint),
        |e| {
            // Keep the data safe in case the process is killed while busy.
            if let Err(e) = fs.flush_all() {
                log::warn!("could not write all buffers: {e}");
            }
            log::warn!("{}", busy_message(&req.mountpoint, e));
        },
    );
    drop(idle_flusher);
    running.join()?;
    if reason == StopReason::Signal
        && let Err(e) = fs.flush_all()
    {
        log::warn!("could not write all buffers after unmount: {e}");
    }
    Ok(reason)
}

/// Starts a thread that writes the buffered changes of open files once
/// they rested for `idle` or are older than `max_age`; it looks every
/// `tick`. Without it, changes of a file that stays open (a log, a VM
/// image) stayed in memory until close or fsync. Dropping the returned
/// sender stops the thread.
fn start_idle_flusher(
    fs: Arc<CryptoFs>,
    tick: Duration,
    idle: Duration,
    max_age: Duration,
) -> Sender<()> {
    let (stop_tx, stop_rx) = channel::<()>();
    std::thread::spawn(move || {
        while let Err(RecvTimeoutError::Timeout) = stop_rx.recv_timeout(tick) {
            fs.flush_idle(Instant::now(), idle, max_age);
        }
    });
    stop_tx
}

/// Waits for the end of the mount. A stop signal tries `try_unmount`; if
/// that fails (the drive is busy), `on_busy` is told and the drive stays
/// mounted until the next signal or an outside unmount. Before, the
/// process ended anyway and left a dead mount ("Device not configured" on
/// macOS, "Transport endpoint is not connected" on Linux). A closed
/// channel counts as an outside unmount.
fn wait_for_stop(
    stop_rx: &Receiver<StopReason>,
    mut try_unmount: impl FnMut() -> io::Result<()>,
    mut on_busy: impl FnMut(&io::Error),
) -> StopReason {
    loop {
        match stop_rx.recv().unwrap_or(StopReason::Unmounted) {
            StopReason::Unmounted => return StopReason::Unmounted,
            StopReason::Signal => match try_unmount() {
                Ok(()) => return StopReason::Signal,
                Err(e) => on_busy(&e),
            },
        }
    }
}

/// The note for a stop signal that could not unmount a busy drive.
fn busy_message(mountpoint: &Path, e: &io::Error) -> String {
    format!(
        "the drive is busy and stays mounted ({e}); close the programs that use {mp} \
         and stop again, or run `crypto-drive unmount --force {mp}`",
        mp = mountpoint.display()
    )
}

/// Runs `wait` in a thread and sends `reason` each time it returns true,
/// until it returns false or the receiver is gone (the mount loop ended).
/// A loop, so a second stop signal after a busy unmount is seen too.
fn forward(
    tx: Sender<StopReason>,
    reason: StopReason,
    mut wait: impl FnMut() -> bool + Send + 'static,
) {
    std::thread::spawn(move || {
        while wait() {
            if tx.send(reason).is_err() {
                break;
            }
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

    /// Sizes of the real files of a vault (control files left out).
    fn real_file_sizes(root: &Path) -> Vec<u64> {
        let mut sizes: Vec<u64> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| !e.file_name().to_string_lossy().starts_with(".cd-"))
            .map(|e| e.metadata().unwrap().len())
            .collect();
        sizes.sort();
        sizes
    }

    #[test]
    fn idle_flusher_writes_resting_changes_and_stops_when_dropped() {
        use crypto_drive_core::content::ciphertext_size;
        use crypto_drive_core::fs::VPath;
        use std::time::{Duration, Instant};

        let (_tmp, vault, _mk) = crypto_drive_core::testutil::test_vault();
        let root = vault.root_path.clone();
        let fs = Arc::new(CryptoFs::new(vault).unwrap());
        let (_, fh) = fs.create(&VPath::parse("/log").unwrap(), 0o644).unwrap();
        fs.write(fh, 0, b"line 1\n").unwrap();
        let ms = Duration::from_millis;
        let stop = start_idle_flusher(Arc::clone(&fs), ms(10), ms(50), ms(500));
        let want = vec![ciphertext_size(7, false)];
        let deadline = Instant::now() + Duration::from_secs(10);
        while real_file_sizes(&root) != want && Instant::now() < deadline {
            std::thread::sleep(ms(10));
        }
        assert_eq!(real_file_sizes(&root), want);
        drop(stop);
        // The thread has stopped: it no longer holds the drive.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&fs) > 1 && Instant::now() < deadline {
            std::thread::sleep(ms(10));
        }
        assert_eq!(Arc::strong_count(&fs), 1);
        fs.release(fh).unwrap();
    }

    fn busy() -> io::Error {
        io::Error::from(io::ErrorKind::ResourceBusy)
    }

    /// Runs `wait_for_stop` on `events` with unmount results taken from
    /// `unmounts` in order; returns the reason, the number of unmount
    /// tries and the number of busy reports.
    fn stop_with(
        events: &[StopReason],
        unmounts: Vec<io::Result<()>>,
    ) -> (StopReason, usize, usize) {
        let (tx, rx) = channel();
        for e in events {
            tx.send(*e).unwrap();
        }
        drop(tx);
        let mut results = unmounts.into_iter();
        let (mut tries, mut busy_reports) = (0, 0);
        let reason = wait_for_stop(
            &rx,
            || {
                tries += 1;
                results.next().expect("unexpected unmount try")
            },
            |_| busy_reports += 1,
        );
        (reason, tries, busy_reports)
    }

    #[test]
    fn signal_with_a_free_drive_unmounts_once() {
        assert_eq!(
            stop_with(&[StopReason::Signal], vec![Ok(())]),
            (StopReason::Signal, 1, 0)
        );
    }

    #[test]
    fn signal_with_a_busy_drive_keeps_it_mounted_until_the_next_signal() {
        let events = [StopReason::Signal, StopReason::Signal];
        assert_eq!(
            stop_with(&events, vec![Err(busy()), Ok(())]),
            (StopReason::Signal, 2, 1)
        );
    }

    #[test]
    fn busy_drive_unmounted_from_outside_stops_without_a_new_try() {
        let events = [StopReason::Signal, StopReason::Unmounted];
        assert_eq!(
            stop_with(&events, vec![Err(busy())]),
            (StopReason::Unmounted, 1, 1)
        );
    }

    #[test]
    fn outside_unmount_or_a_closed_channel_needs_no_try() {
        assert_eq!(
            stop_with(&[StopReason::Unmounted], vec![]),
            (StopReason::Unmounted, 0, 0)
        );
        assert_eq!(stop_with(&[], vec![]), (StopReason::Unmounted, 0, 0));
    }

    #[test]
    fn busy_message_names_the_way_out() {
        let m = busy_message(Path::new("/mnt/x"), &busy());
        assert!(
            m.starts_with("the drive is busy and stays mounted ("),
            "{m}"
        );
        assert!(
            m.ends_with(
                "close the programs that use /mnt/x and stop again, or run \
                 `crypto-drive unmount --force /mnt/x`"
            ),
            "{m}"
        );
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
