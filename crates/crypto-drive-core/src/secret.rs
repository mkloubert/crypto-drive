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
use zeroize::{Zeroize, ZeroizeOnDrop};

static MLOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Returns true if any `mlock` call failed (the CLI prints one warning).
pub fn mlock_failed() -> bool {
    MLOCK_FAILED.load(Ordering::Relaxed)
}

#[cfg(test)]
thread_local! {
    /// Bytes this thread asked `mlock` to lock.
    static LOCKED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Bytes this thread asked `mlock` to lock (tests only).
#[cfg(test)]
pub(crate) fn locked_bytes() -> usize {
    LOCKED_BYTES.with(std::cell::Cell::get)
}

/// Locks the heap memory of `value` in RAM, best effort. A failure is
/// remembered for `mlock_failed`.
fn lock_memory<T>(value: &T) {
    let len = std::mem::size_of::<T>();
    if len == 0 {
        return;
    }
    #[cfg(test)]
    LOCKED_BYTES.with(|n| n.set(n.get() + len));
    let ptr = (value as *const T).cast_mut().cast::<std::ffi::c_void>();
    // SAFETY: `ptr` points to `len` valid bytes of a value owned by a `Box`
    // that stays alive and is not moved on the heap. mlock only changes
    // paging, it does not touch the bytes.
    if unsafe { rustix::mm::mlock(ptr, len) }.is_err() {
        MLOCK_FAILED.store(true, Ordering::Relaxed);
    }
}

/// A value with secret state (for example an expanded cipher key) on the
/// heap, locked in RAM if possible. `T` must wipe itself on drop.
///
/// The value is built on the stack and then moved into the box; that stack
/// copy is not wiped (Rust has no in-place construction). It is short-lived,
/// but this is weaker than `SecretBytes`.
pub struct LockedBox<T: ZeroizeOnDrop>(Box<T>);

impl<T: ZeroizeOnDrop> LockedBox<T> {
    pub fn new(value: T) -> Self {
        let boxed = Box::new(value);
        lock_memory(&*boxed);
        Self(boxed)
    }
}

impl<T: ZeroizeOnDrop> std::ops::Deref for LockedBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ZeroizeOnDrop> std::ops::DerefMut for LockedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ZeroizeOnDrop> std::fmt::Debug for LockedBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedBox(..)")
    }
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
        lock_memory(&*boxed);
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
    fn locked_box_keeps_the_value_and_locks_it() {
        let before = locked_bytes();
        let b = LockedBox::new(zeroize::Zeroizing::new([3u8; 100]));
        assert_eq!(b[..], [3u8; 100]);
        assert_eq!(locked_bytes() - before, 100);
        assert_eq!(format!("{b:?}"), "LockedBox(..)");
    }

    #[test]
    fn secret_bytes_are_locked() {
        let before = locked_bytes();
        let _s = SecretBytes::new([5; 8]);
        assert_eq!(locked_bytes() - before, 8);
    }

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
