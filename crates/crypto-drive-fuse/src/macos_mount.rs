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

//! Mounting on macOS through libfuse2's `fuse_mount()`.
//!
//! fuser 0.18 mounts on macOS with `fuse_mount_compat25()`. In macFUSE 5.5
//! that function always fails (it returns -1 and sets no errno). The normal
//! libfuse 2.6 API `fuse_mount()` still works, so on macOS we mount with it
//! ourselves and hand the FUSE device fd to `fuser::Session::from_fd`.
//! Because fuser did not mount, it does not unmount either: we do that with
//! `unmount(2)`.
//!
//! `libfuse_argv` has no platform code, so its tests run everywhere.

use std::ffi::CString;
use std::io;

/// Program name passed to libfuse as argv[0].
const PROGRAM: &str = "crypto-drive";

/// The argument vector for libfuse: the program name, then one `-o <opt>`
/// pair per option. Options with a NUL byte are rejected.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn libfuse_argv(options: &[String]) -> io::Result<Vec<CString>> {
    let to_c = |s: &str| {
        CString::new(s).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mount option contains a NUL byte",
            )
        })
    };
    let mut argv = vec![to_c(PROGRAM)?];
    for option in options {
        argv.push(to_c("-o")?);
        argv.push(to_c(option)?);
    }
    Ok(argv)
}

#[cfg(target_os = "macos")]
pub(crate) use imp::{MacMount, mount};

#[cfg(target_os = "macos")]
mod imp {
    use super::libfuse_argv;
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// `struct fuse_args` from libfuse 2 (`fuse_opt.h`).
    #[repr(C)]
    struct FuseArgs {
        argc: c_int,
        argv: *mut *mut c_char,
        allocated: c_int,
    }

    #[link(name = "fuse")]
    unsafe extern "C" {
        fn fuse_mount(mountpoint: *const c_char, args: *mut FuseArgs) -> *mut c_void;
        fn fuse_chan_fd(ch: *mut c_void) -> c_int;
        fn fuse_opt_free_args(args: *mut FuseArgs);
    }

    /// A mount made by `mount`. Unmount it with `unmount`.
    #[derive(Debug)]
    pub(crate) struct MacMount {
        mountpoint: CString,
    }

    impl MacMount {
        /// Unmounts the drive with `unmount(2)`.
        pub(crate) fn unmount(&self) -> io::Result<()> {
            nix::mount::unmount(self.mountpoint.as_c_str(), nix::mount::MntFlags::empty())
                .map_err(|e| io::Error::from_raw_os_error(e as i32))
        }
    }

    /// Mounts `mountpoint` with `fuse_mount()` and returns the FUSE device fd.
    pub(crate) fn mount(mountpoint: &Path, options: &[String]) -> io::Result<(OwnedFd, MacMount)> {
        let mp = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mount point contains a NUL byte",
            )
        })?;
        let argv = libfuse_argv(options)?;
        let mut ptrs: Vec<*mut c_char> = argv.iter().map(|s| s.as_ptr().cast_mut()).collect();
        ptrs.push(std::ptr::null_mut());
        let mut args = FuseArgs {
            argc: (ptrs.len() - 1) as c_int,
            argv: ptrs.as_mut_ptr(),
            allocated: 0,
        };
        // SAFETY: `mp` and every string in `argv` are NUL terminated and live
        // until the end of this function; `ptrs` is a NULL terminated array
        // of them. With `allocated == 0` libfuse copies the arguments before
        // it changes them, so it never writes into our strings.
        let ch = unsafe { fuse_mount(mp.as_ptr(), &mut args) };
        let os_err = io::Error::last_os_error();
        // SAFETY: `args` is the struct passed above; this frees only memory
        // libfuse allocated for its own copy (nothing when `allocated == 0`).
        unsafe { fuse_opt_free_args(&mut args) };
        if ch.is_null() {
            return Err(match os_err.raw_os_error() {
                Some(0) | None => io::Error::other("macFUSE could not mount the drive"),
                Some(_) => os_err,
            });
        }
        // SAFETY: `ch` is a valid, non-NULL channel just returned by
        // `fuse_mount`.
        let fd = unsafe { fuse_chan_fd(ch) };
        if fd < 0 {
            return Err(io::Error::other("macFUSE gave no device file descriptor"));
        }
        // SAFETY: `fd` is the open FUSE device fd of the channel. We never
        // destroy the channel (it is leaked on purpose), so nobody else
        // closes this fd; fuser becomes its only owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok((fd, MacMount { mountpoint: mp }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_has_program_and_option_pairs() {
        let argv = libfuse_argv(&["fsname=crypto-drive".into(), "noappledouble".into()]).unwrap();
        let shown: Vec<&str> = argv.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            shown,
            [
                "crypto-drive",
                "-o",
                "fsname=crypto-drive",
                "-o",
                "noappledouble"
            ]
        );
    }

    #[test]
    fn argv_without_options_is_only_the_program() {
        let argv = libfuse_argv(&[]).unwrap();
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0].to_str().unwrap(), "crypto-drive");
    }

    #[test]
    fn nul_byte_in_option_is_rejected() {
        let err = libfuse_argv(&["a\0b".into()]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
