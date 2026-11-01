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

//! Maps core errors to errno values (spec section 8).

use crypto_drive_core::Error;

/// The errno for a core error, as in the table of spec section 8.
pub fn to_errno(e: &Error) -> i32 {
    match e {
        Error::NotFound => libc::ENOENT,
        Error::AlreadyExists => libc::EEXIST,
        Error::NotEmpty => libc::ENOTEMPTY,
        Error::IsADirectory => libc::EISDIR,
        Error::NotADirectory => libc::ENOTDIR,
        Error::AuthFailed { .. } | Error::InvalidFormat { .. } => libc::EIO,
        Error::NameTooLong => libc::ENAMETOOLONG,
        Error::InvalidName | Error::InvalidArgument => libc::EINVAL,
        Error::Unsupported => libc::ENOTSUP,
        Error::NotPermitted => libc::EPERM,
        Error::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
        // These only happen at unlock, mount or key rotation, never in a
        // mounted drive.
        Error::AlreadyMounted => libc::EBUSY,
        Error::WrongPassword
        | Error::RotationNotFinished { .. }
        | Error::WrongKey
        | Error::UnsupportedVersion { .. } => libc::EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_drive_core::Error;

    #[test]
    fn table_of_spec_section_8() {
        assert_eq!(to_errno(&Error::NotFound), libc::ENOENT);
        assert_eq!(to_errno(&Error::AlreadyExists), libc::EEXIST);
        assert_eq!(to_errno(&Error::NotEmpty), libc::ENOTEMPTY);
        assert_eq!(to_errno(&Error::IsADirectory), libc::EISDIR);
        assert_eq!(to_errno(&Error::NotADirectory), libc::ENOTDIR);
        assert_eq!(to_errno(&Error::AuthFailed { what: "x".into() }), libc::EIO);
        assert_eq!(
            to_errno(&Error::InvalidFormat { what: "x".into() }),
            libc::EIO
        );
        assert_eq!(to_errno(&Error::NameTooLong), libc::ENAMETOOLONG);
        assert_eq!(to_errno(&Error::InvalidName), libc::EINVAL);
        assert_eq!(to_errno(&Error::InvalidArgument), libc::EINVAL);
        assert_eq!(to_errno(&Error::Unsupported), libc::ENOTSUP);
        assert_eq!(to_errno(&Error::NotPermitted), libc::EPERM);
    }

    #[test]
    fn io_error_keeps_its_errno() {
        let e = Error::Io(std::io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(to_errno(&e), libc::ENOSPC);
    }

    #[test]
    fn io_error_without_errno_gives_eio() {
        let e = Error::Io(std::io::Error::other("x"));
        assert_eq!(to_errno(&e), libc::EIO);
    }

    #[test]
    fn errors_that_cannot_happen_after_mount() {
        assert_eq!(to_errno(&Error::AlreadyMounted), libc::EBUSY);
        assert_eq!(to_errno(&Error::WrongKey), libc::EIO);
        assert_eq!(to_errno(&Error::WrongPassword), libc::EIO);
        assert_eq!(to_errno(&Error::UnsupportedVersion { found: 2 }), libc::EIO);
    }
}
