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

//! Secret memory: zeroized on drop and locked in RAM on a best-effort basis.

use crate::error::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

static MLOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Returns true if any `mlock` call failed (the CLI prints one warning).
pub fn mlock_failed() -> bool {
    MLOCK_FAILED.load(Ordering::Relaxed)
}

/// Returns `N` random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    Ok(out)
}

/// `N` secret bytes on the heap. Zeroized on drop, locked in memory if possible.
pub struct SecretBytes<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// Moves `bytes` to the heap. The caller must zeroize its own copy.
    pub fn new(bytes: [u8; N]) -> Self {
        let boxed = Box::new(bytes);
        let ptr = boxed.as_ptr() as *mut std::ffi::c_void;
        // SAFETY: `ptr` points to `N` valid bytes owned by `boxed`, which stays
        // alive and is not moved on the heap. mlock only changes paging.
        if unsafe { rustix::mm::mlock(ptr, N) }.is_err() {
            MLOCK_FAILED.store(true, Ordering::Relaxed);
        }
        Self(boxed)
    }

    /// Fills the secret with random bytes from the operating system.
    pub fn random() -> Result<Self> {
        let mut bytes = random_bytes::<N>()?;
        let secret = Self::new(bytes);
        bytes.zeroize();
        Ok(secret)
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        // No munlock here: mlock works per page and does not nest, so unlocking
        // could unlock the page of another live secret. The kernel drops the
        // lock when the memory is freed. We only wipe the bytes.
        self.0.zeroize();
    }
}

impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_expose() {
        let s = SecretBytes::new([5; 8]);
        assert_eq!(s.expose(), &[5; 8]);
    }

    #[test]
    fn random_values_differ() {
        let a = SecretBytes::<32>::random().unwrap();
        let b = SecretBytes::<32>::random().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(random_bytes::<16>().unwrap(), random_bytes::<16>().unwrap());
    }
}
