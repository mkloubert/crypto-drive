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

//! Process hardening.

/// Turns core dumps off (`RLIMIT_CORE = 0`). Prints a warning on failure.
pub fn disable_core_dumps() {
    if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0) {
        eprintln!("warning: could not disable core dumps: {e}");
    }
}

/// Stops other processes of the same user from reading the memory of this
/// process (where the keys are while the drive is mounted). Root can still
/// do it. Prints a warning on failure.
///
/// Linux: `prctl(PR_SET_DUMPABLE, 0)`. The process can then not be traced
/// with ptrace by the same user, and `/proc/<pid>/mem` belongs to root.
/// The flag is kept across `fork` (`mount --daemon`).
#[cfg(target_os = "linux")]
pub fn deny_debugging() {
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        eprintln!("warning: could not protect the process memory: {e}");
    }
}

/// Stops other processes of the same user from reading the memory of this
/// process (where the keys are while the drive is mounted). Prints a
/// warning on failure.
///
/// macOS: `ptrace(PT_DENY_ATTACH)`. A debugger can then not attach to the
/// process.
#[cfg(target_os = "macos")]
pub fn deny_debugging() {
    // SAFETY: PT_DENY_ATTACH takes no pointer and changes only this process.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc != 0 {
        eprintln!(
            "warning: could not protect the process memory: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Other systems: nothing to do.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn deny_debugging() {}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn deny_debugging_clears_dumpable() {
        super::deny_debugging();
        assert!(!nix::sys::prctl::get_dumpable().unwrap());
    }
}
