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

//! Process resource limits (review 2026-11-01, NEXT-STEPS item 1).
//!
//! The drive keeps directories and files open (one file descriptor each).
//! The soft open-file limit is often low (macOS terminals: 256, Linux:
//! 1024), while the hard limit is much higher. Raising the soft limit at
//! start lets the core keep its full directory cache. If raising fails,
//! the core sizes its cache from the lower limit (see `crypto-drive-core`
//! `fs`), so the drive still works, only with fewer cached directories.

use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};

/// macOS refuses a soft `RLIMIT_NOFILE` above `OPEN_MAX` (10240,
/// `<sys/syslimits.h>`), even when the hard limit is "unlimited".
#[cfg(target_os = "macos")]
const OS_MAX_OPEN_FILES: Option<rlim_t> = Some(10240);

/// Linux takes any value up to the hard limit.
#[cfg(not(target_os = "macos"))]
const OS_MAX_OPEN_FILES: Option<rlim_t> = None;

/// The new soft limit, or `None` when the current one is already as high
/// as allowed. `RLIM_INFINITY` stands for "no limit" in all arguments.
fn raised_soft_limit(soft: rlim_t, hard: rlim_t, os_max: Option<rlim_t>) -> Option<rlim_t> {
    let target = match os_max {
        Some(max) if hard == RLIM_INFINITY || hard > max => max,
        _ => hard,
    };
    let higher = soft != RLIM_INFINITY && (target == RLIM_INFINITY || target > soft);
    higher.then_some(target)
}

/// Raises the soft open-file limit to the hard limit (macOS: at most
/// `OPEN_MAX`). A failure is only logged: the core adapts to the limit.
pub fn raise_open_file_limit() {
    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(l) => l,
        Err(e) => {
            log::debug!("could not read the open-file limit: {e}");
            return;
        }
    };
    let Some(new_soft) = raised_soft_limit(soft, hard, OS_MAX_OPEN_FILES) else {
        return;
    };
    match setrlimit(Resource::RLIMIT_NOFILE, new_soft, hard) {
        Ok(()) => log::debug!("open-file limit raised from {soft} to {new_soft}"),
        Err(e) => log::debug!("could not raise the open-file limit from {soft}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raises_to_the_hard_limit() {
        assert_eq!(raised_soft_limit(1024, 524_288, None), Some(524_288));
        assert_eq!(
            raised_soft_limit(256, RLIM_INFINITY, None),
            Some(RLIM_INFINITY)
        );
    }

    #[test]
    fn respects_the_os_maximum() {
        assert_eq!(
            raised_soft_limit(256, RLIM_INFINITY, Some(10240)),
            Some(10240)
        );
        assert_eq!(raised_soft_limit(256, 50_000, Some(10240)), Some(10240));
        assert_eq!(raised_soft_limit(256, 4096, Some(10240)), Some(4096));
    }

    #[test]
    fn never_lowers_the_limit() {
        assert_eq!(raised_soft_limit(4096, 4096, None), None);
        assert_eq!(raised_soft_limit(RLIM_INFINITY, RLIM_INFINITY, None), None);
        assert_eq!(raised_soft_limit(20_000, RLIM_INFINITY, Some(10240)), None);
        assert_eq!(raised_soft_limit(10240, RLIM_INFINITY, Some(10240)), None);
    }

    #[test]
    fn raise_open_file_limit_keeps_soft_at_most_hard() {
        raise_open_file_limit();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert!(hard == RLIM_INFINITY || soft <= hard);
    }
}
