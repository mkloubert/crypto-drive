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

//! Random access to one encrypted file (spec 4.7, 5.4; hardening spec 5).
//!
//! Clear chunks are cached in memory. Changed chunks stay in a dirty buffer
//! until `flush`. Until then `len()` is the size in memory.
//!
//! In a padded vault the header holds a sealed size block and the real file
//! is padded with random bytes to `stage(L)`. The padding is never read.

use crate::backing::DirHandle;
use crate::content::{
    CHUNK_OVERHEAD, CHUNK_SIZE, ChunkCipher, FileHeader, HEADER_LEN, PADDED_HEADER_LEN,
    chunk_count, chunk_offset, ciphertext_size, header_len, open_size, plaintext_size, seal_size,
};
use crate::error::{Error, Result};
use crate::keys::{EntryId, Epoch, derive_size_key};
use crate::secret::SecretBytes;
use crate::vault::VaultKeys;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::os::unix::fs::FileExt;

/// Clean chunks kept in the cache after a flush or a read.
const MAX_CLEAN_CHUNKS: usize = 8;

/// Random padding is written in blocks of at most this size.
const PADDING_BLOCK: usize = 65536;

/// One open encrypted file. All handles of a real file share one.
pub struct OpenFile {
    file: File,
    /// False if the real file could only be opened for reading.
    writable: bool,
    header: FileHeader,
    cipher: ChunkCipher,
    /// The key of the size block; only in a padded vault.
    size_key: Option<SecretBytes<32>>,
    /// Clear size in memory.
    plain_len: u64,
    /// Clear size of the real file on disk.
    disk_len: u64,
    /// Clear chunks by index. A cached chunk may be shorter than its clear
    /// length; the missing bytes are zeros.
    chunks: BTreeMap<u64, Vec<u8>>,
    /// Chunks changed since the last flush.
    dirty: BTreeSet<u64>,
    /// When each cached chunk was last used (a value of `clock`), so the
    /// cache drops the least recently used clean chunk first. A chunk
    /// without an entry counts as the oldest.
    last_use: HashMap<u64, u64>,
    clock: u64,
}

fn invalid(what: &str) -> Error {
    Error::InvalidFormat {
        what: what.to_owned(),
    }
}

fn last_index(len: u64) -> u64 {
    chunk_count(len) - 1
}

/// Clear length of chunk `index` in a file of `len` clear bytes.
fn chunk_len(len: u64, index: u64) -> usize {
    // At most CHUNK_SIZE, so the cast is lossless.
    len.saturating_sub(index.saturating_mul(CHUNK_SIZE))
        .min(CHUNK_SIZE) as usize
}

/// Length of header and chunks without padding.
fn used_len(len: u64, padded: bool) -> u64 {
    ciphertext_size(len, false) - HEADER_LEN + header_len(padded)
}

/// The content key of the header's epoch.
fn content_key<'a>(keys: &'a VaultKeys, header: &FileHeader) -> Result<&'a [u8; 32]> {
    keys.get(header.epoch)
        .map(|k| k.content())
        .ok_or_else(|| Error::AuthFailed {
            what: "unknown key epoch".into(),
        })
}

fn size_key(content_key: &[u8; 32], header: &FileHeader) -> SecretBytes<32> {
    derive_size_key(content_key, &header.file_nonce, &header.file_id)
}

/// Reads exactly `buf.len()` bytes at `offset`; a short file is `what`.
fn read_exact(file: &File, buf: &mut [u8], offset: u64, what: &str) -> Result<()> {
    file.read_exact_at(buf, offset).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            invalid(what)
        } else {
            Error::Io(e)
        }
    })
}

/// Writes random bytes into `from..to` of `file`.
fn write_padding(file: &File, from: u64, to: u64) -> Result<()> {
    let mut buf = vec![0u8; PADDING_BLOCK];
    let mut pos = from;
    while pos < to {
        // At most PADDING_BLOCK, so the cast is lossless.
        let n = (to - pos).min(PADDING_BLOCK as u64) as usize;
        getrandom::fill(&mut buf[..n]).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        file.write_all_at(&buf[..n], pos)?;
        pos += n as u64;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test hook: after `n` more chunk writes in this thread, the next chunk
/// write fails with `ENOSPC`. `None` turns the hook off.
#[cfg(test)]
fn fail_chunk_writes_after(n: Option<u64>) {
    FAIL_AFTER.with(|c| c.set(n));
}

/// Called before each chunk write of a flush (see `fail_chunk_writes_after`).
fn fail_point() -> Result<()> {
    #[cfg(test)]
    {
        let fail = FAIL_AFTER.with(|c| match c.get() {
            Some(0) => true,
            Some(n) => {
                c.set(Some(n - 1));
                false
            }
            None => false,
        });
        if fail {
            return Err(Error::Io(std::io::Error::from(rustix::io::Errno::NOSPC)));
        }
    }
    Ok(())
}

/// Refuses sizes whose encrypted file would not fit in an `i64` offset.
fn check_len(len: u64, padded: bool) -> Result<()> {
    if ciphertext_size(len, padded) > i64::MAX as u64 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Reads and opens chunk `index` from disk. Chunks after the last chunk on
/// disk are zeros (an empty vector). The result is cut to `plain_len`.
fn load_chunk(f: &OpenFile, index: u64) -> Result<Vec<u8>> {
    let old_last = last_index(f.disk_len);
    if index > old_last {
        return Ok(Vec::new());
    }
    let mut sealed = vec![0u8; chunk_len(f.disk_len, index) + CHUNK_OVERHEAD as usize];
    read_exact(
        &f.file,
        &mut sealed,
        chunk_offset(index, f.padded()),
        &format!("chunk {index}"),
    )?;
    let mut data = f.cipher.open(index, index == old_last, &sealed)?;
    data.truncate(chunk_len(f.plain_len, index));
    Ok(data)
}

/// The header epoch of the content file `name` in `dir`; `None` if the
/// header is not valid. Reads only the plain header, so it needs no key.
pub(crate) fn header_epoch(dir: &DirHandle, name: &str) -> Result<Option<Epoch>> {
    let file = dir.open_file(name, false)?;
    let mut head = [0u8; HEADER_LEN as usize];
    match file.read_exact_at(&mut head, 0) {
        Ok(()) => Ok(FileHeader::parse(&head).ok().map(|h| h.epoch)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Reads only the header (and the size block of a padded file) and returns
/// it with the clear size. Used for getattr and binding checks.
///
/// Without padding the size comes from the real length. With padding it
/// comes from the size block, and the real length must be its stage.
pub fn read_file_meta(file: &File, keys: &VaultKeys, padded: bool) -> Result<(FileHeader, u64)> {
    let real_len = file.metadata()?.len();
    let plain_unpadded = if padded {
        None
    } else {
        Some(plaintext_size(real_len)?)
    };
    let mut head = [0u8; PADDED_HEADER_LEN as usize];
    let head = &mut head[..header_len(padded) as usize];
    read_exact(file, head, 0, "file header")?;
    let header = FileHeader::parse(head)?;
    let key = content_key(keys, &header)?;
    let len = match plain_unpadded {
        Some(len) => len,
        None => {
            // The AD is the 53 header bytes exactly as read from disk.
            let (ad, block) = head.split_at(HEADER_LEN as usize);
            let ad: &[u8; HEADER_LEN as usize] =
                ad.try_into().map_err(|_| invalid("file header"))?;
            let len = open_size(size_key(key, &header).expose(), ad, block)?;
            if real_len != ciphertext_size(len, true) {
                return Err(invalid("file size"));
            }
            len
        }
    };
    Ok((header, len))
}

impl OpenFile {
    /// Most dirty chunks before `write` flushes (4 MiB).
    pub const MAX_DIRTY_CHUNKS: usize = 64;

    /// Makes `file` an empty encrypted file of the write epoch: 81 bytes,
    /// or 4096 bytes in a padded vault.
    pub fn create(
        file: File,
        keys: &VaultKeys,
        file_id: EntryId,
        padded: bool,
    ) -> Result<OpenFile> {
        let header = FileHeader::random(keys.write_epoch(), file_id)?;
        let key = content_key(keys, &header)?;
        let cipher = ChunkCipher::new(key, &header);
        let size_key = padded.then(|| size_key(key, &header));
        let mut bytes = header.to_bytes().to_vec();
        if let Some(k) = &size_key {
            bytes.extend_from_slice(&seal_size(k.expose(), &header.to_bytes(), 0)?);
        }
        bytes.extend_from_slice(&cipher.seal(0, true, &[])?);
        file.write_all_at(&bytes, 0)?;
        let used = bytes.len() as u64;
        let real_len = ciphertext_size(0, padded);
        file.set_len(real_len)?;
        write_padding(&file, used, real_len)?;
        Ok(Self::new(file, header, cipher, size_key, 0))
    }

    /// Opens an existing encrypted file. The epoch comes from the header.
    /// Only the header and the size are checked here; chunks are
    /// authenticated when they are read.
    pub fn open(file: File, keys: &VaultKeys, padded: bool) -> Result<OpenFile> {
        let (header, len) = read_file_meta(&file, keys, padded)?;
        let key = content_key(keys, &header)?;
        let cipher = ChunkCipher::new(key, &header);
        let size_key = padded.then(|| size_key(key, &header));
        Ok(Self::new(file, header, cipher, size_key, len))
    }

    fn new(
        file: File,
        header: FileHeader,
        cipher: ChunkCipher,
        size_key: Option<SecretBytes<32>>,
        len: u64,
    ) -> OpenFile {
        OpenFile {
            file,
            writable: true,
            header,
            cipher,
            size_key,
            plain_len: len,
            disk_len: len,
            chunks: BTreeMap::new(),
            dirty: BTreeSet::new(),
            last_use: HashMap::new(),
            clock: 0,
        }
    }

    /// Opens a file whose real file is open only for reading.
    pub(crate) fn open_read_only(file: File, keys: &VaultKeys, padded: bool) -> Result<OpenFile> {
        let mut f = Self::open(file, keys, padded)?;
        f.writable = false;
        Ok(f)
    }

    pub fn file_id(&self) -> EntryId {
        self.header.file_id
    }

    pub fn epoch(&self) -> Epoch {
        self.header.epoch
    }

    fn padded(&self) -> bool {
        self.size_key.is_some()
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.writable
    }

    /// Replaces a read-only real file with `file`, opened for writing on
    /// the same real file. The caller checks that it is the same file.
    pub(crate) fn set_writable_file(&mut self, file: File) {
        self.file = file;
        self.writable = true;
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn into_file(self) -> File {
        self.file
    }

    /// The clear size, including writes that are not flushed yet.
    pub fn len(&self) -> u64 {
        self.plain_len
    }

    pub fn is_empty(&self) -> bool {
        self.plain_len == 0
    }

    fn check_writable(&self) -> Result<()> {
        if self.writable {
            Ok(())
        } else {
            Err(Error::NotPermitted)
        }
    }

    /// The cached chunk `index`, loaded from disk first if needed.
    fn chunk_mut(&mut self, index: u64) -> Result<&mut Vec<u8>> {
        self.touch(index);
        if !self.chunks.contains_key(&index) {
            let data = load_chunk(self, index)?;
            self.chunks.insert(index, data);
        }
        Ok(self.chunks.entry(index).or_default())
    }

    /// Marks chunk `index` as just used.
    fn touch(&mut self, index: u64) {
        self.clock += 1;
        self.last_use.insert(index, self.clock);
    }

    /// Drops the least recently used clean chunks until at most
    /// `MAX_CLEAN_CHUNKS` are left.
    fn trim_cache(&mut self) {
        let mut clean: Vec<(u64, u64)> = self
            .chunks
            .keys()
            .filter(|i| !self.dirty.contains(i))
            .map(|i| (self.last_use.get(i).copied().unwrap_or(0), *i))
            .collect();
        let excess = clean.len().saturating_sub(MAX_CLEAN_CHUNKS);
        if excess > 0 {
            clean.sort_unstable();
            for &(_, i) in &clean[..excess] {
                self.chunks.remove(&i);
            }
        }
        // Forget chunks that are gone, also those dropped elsewhere.
        let chunks = &self.chunks;
        self.last_use.retain(|i, _| chunks.contains_key(i));
    }

    /// Reads up to `size` bytes at `offset`. Reads past the end return fewer.
    pub fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if offset >= self.plain_len || size == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .saturating_add(u64::try_from(size).unwrap_or(u64::MAX))
            .min(self.plain_len);
        // The result is held in memory, so its size fits in usize.
        let mut out = Vec::with_capacity(usize::try_from(end - offset).unwrap_or(0));
        let mut pos = offset;
        while pos < end {
            let index = pos / CHUNK_SIZE;
            let base = index * CHUNK_SIZE;
            let start = (pos - base) as usize;
            let stop = (end - base).min(CHUNK_SIZE) as usize;
            let chunk = self.chunk_mut(index)?;
            let have = &chunk[start.min(chunk.len())..stop.min(chunk.len())];
            out.extend_from_slice(have);
            out.resize(out.len() + (stop - start - have.len()), 0);
            pos = base + stop as u64;
        }
        self.trim_cache();
        Ok(out)
    }

    /// Writes `data` at `offset`. A gap after the old end reads as zeros.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable()?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Error::InvalidArgument)?)
            .ok_or(Error::InvalidArgument)?;
        check_len(end, self.padded())?;
        let mut pos = offset;
        let mut src = 0usize;
        while pos < end {
            let index = pos / CHUNK_SIZE;
            let base = index * CHUNK_SIZE;
            let start = (pos - base) as usize;
            let stop = (end - base).min(CHUNK_SIZE) as usize;
            let part = &data[src..src + (stop - start)];
            if start == 0 && stop >= chunk_len(self.plain_len, index) {
                // The whole chunk is replaced; no need to read it.
                self.touch(index);
                self.chunks.insert(index, part.to_vec());
            } else {
                let chunk = self.chunk_mut(index)?;
                if chunk.len() < stop {
                    chunk.resize(stop, 0);
                }
                chunk[start..stop].copy_from_slice(part);
            }
            self.dirty.insert(index);
            src += part.len();
            pos = base + stop as u64;
        }
        self.plain_len = self.plain_len.max(end);
        if self.dirty.len() > Self::MAX_DIRTY_CHUNKS {
            self.flush()?;
        }
        Ok(data.len())
    }

    /// Sets the clear size and writes the result to disk.
    pub fn truncate(&mut self, new_len: u64) -> Result<()> {
        self.check_writable()?;
        check_len(new_len, self.padded())?;
        if new_len < self.plain_len {
            let new_last = last_index(new_len);
            self.chunks.retain(|&i, _| i <= new_last);
            self.dirty.retain(|&i| i <= new_last);
            if let Some(chunk) = self.chunks.get_mut(&new_last) {
                chunk.truncate(chunk_len(new_len, new_last));
            }
        }
        let old_len = self.plain_len;
        self.plain_len = new_len;
        let result = self.flush();
        if result.is_err() && new_len > old_len {
            // A failed grow changes nothing: the file keeps its old size.
            self.forget_growth(old_len);
        }
        result
    }

    /// Sets the size in memory back to `len` after a failed grow.
    fn forget_growth(&mut self, len: u64) {
        let last = last_index(len);
        self.chunks.retain(|&i, _| i <= last);
        self.dirty.retain(|&i| i <= last);
        if let Some(chunk) = self.chunks.get_mut(&last) {
            chunk.truncate(chunk_len(len, last));
        }
        self.plain_len = len;
    }

    /// Writes all dirty chunks and sets the real file size.
    ///
    /// In a padded vault a size change then writes a new size block and
    /// sets the real length to the new stage; new padding bytes are random.
    ///
    /// A grow first checks that the free space of the real file system is
    /// enough (`ENOSPC` if not). If a grow fails partway, the real file is
    /// set back to its old size, so it stays readable; the changes stay in
    /// memory and a later flush tries again.
    pub fn flush(&mut self) -> Result<()> {
        if self.dirty.is_empty() && self.plain_len == self.disk_len {
            return Ok(());
        }
        self.check_writable()?;
        if self.plain_len <= self.disk_len {
            return self.write_out();
        }
        self.check_space()?;
        let result = self.write_out();
        if result.is_err()
            && let Err(e) = self.undo_grow()
        {
            log::warn!("could not undo a failed grow of a file: {e}");
        }
        result
    }

    /// Fails with `ENOSPC` if growing the real file to the size in memory
    /// needs more than the free space. A file system that reports no sizes
    /// is not checked.
    fn check_space(&self) -> Result<()> {
        let need = ciphertext_size(self.plain_len, self.padded())
            .saturating_sub(self.file.metadata()?.len());
        if need == 0 {
            return Ok(());
        }
        let st = match rustix::fs::fstatvfs(&self.file) {
            Ok(st) => st,
            Err(e) => {
                log::debug!("could not read the free space: {e}");
                return Ok(());
            }
        };
        if st.f_blocks == 0 {
            return Ok(());
        }
        let unit = if st.f_frsize > 0 {
            st.f_frsize
        } else {
            st.f_bsize
        };
        if need > st.f_bavail.saturating_mul(unit) {
            return Err(Error::Io(std::io::Error::from(rustix::io::Errno::NOSPC)));
        }
        Ok(())
    }

    /// Sets the real file back to the size on disk after a failed grow: the
    /// old last chunk gets its "last" flag again, a padded file its old size
    /// block, and the real length is cut to the old length.
    fn undo_grow(&mut self) -> Result<()> {
        let padded = self.padded();
        let old_last = last_index(self.disk_len);
        // Not cached means the grow failed before it changed this chunk.
        if let Some(chunk) = self.chunks.get(&old_last) {
            let len = chunk_len(self.disk_len, old_last);
            let mut plain = chunk[..len.min(chunk.len())].to_vec();
            plain.resize(len, 0);
            let sealed = self.cipher.seal(old_last, true, &plain)?;
            self.file
                .write_all_at(&sealed, chunk_offset(old_last, padded))?;
        }
        self.write_size_block(self.disk_len)?;
        self.file.set_len(ciphertext_size(self.disk_len, padded))?;
        Ok(())
    }

    /// Writes the dirty chunks, the zero chunks of a grow and the new size.
    fn write_out(&mut self) -> Result<()> {
        let padded = self.padded();
        let growing = padded && self.plain_len > self.disk_len;
        if growing {
            // Grow order: first extend the real file to the new stage and
            // fill the new range with random bytes, then write the chunks
            // (they overwrite part of it), then the size block. So the real
            // length is never the exact size and no zero run is on disk.
            let old_real_len = self.file.metadata()?.len();
            let real_len = ciphertext_size(self.plain_len, true);
            if real_len > old_real_len {
                self.file.set_len(real_len)?;
                write_padding(&self.file, old_real_len, real_len)?;
            }
        }
        let old_last = last_index(self.disk_len);
        let new_last = last_index(self.plain_len);
        if self.plain_len != self.disk_len {
            // The new last chunk changes its length or its "last" flag; when
            // the file grows, the old last chunk loses its flag.
            self.chunk_mut(new_last)?;
            self.dirty.insert(new_last);
            if old_last < new_last {
                self.chunk_mut(old_last)?;
                self.dirty.insert(old_last);
            }
        }
        // The chunks between the old and the new last chunk that are not
        // dirty are zeros. They are written one by one in index order with
        // the dirty chunks and never collected, so a grow of any size needs
        // no memory per chunk.
        let gap_end = new_last;
        let mut gap_next = old_last.saturating_add(1);
        let zeros = if gap_next < gap_end {
            vec![0u8; CHUNK_SIZE as usize]
        } else {
            Vec::new()
        };
        let write_zeros = |from: u64, to: u64| -> Result<()> {
            for index in from..to {
                fail_point()?;
                let sealed = self.cipher.seal(index, false, &zeros)?;
                self.file
                    .write_all_at(&sealed, chunk_offset(index, padded))?;
            }
            Ok(())
        };
        for &index in &self.dirty {
            write_zeros(gap_next, gap_end.min(index))?;
            gap_next = gap_next.max(index.saturating_add(1));
            fail_point()?;
            let len = chunk_len(self.plain_len, index);
            let sealed = match self.chunks.get_mut(&index) {
                Some(chunk) => {
                    chunk.resize(len, 0);
                    self.cipher.seal(index, index == new_last, chunk)?
                }
                None => self
                    .cipher
                    .seal(index, index == new_last, &vec![0u8; len])?,
            };
            self.file
                .write_all_at(&sealed, chunk_offset(index, padded))?;
        }
        write_zeros(gap_next, gap_end)?;
        if !padded {
            self.file.set_len(ciphertext_size(self.plain_len, false))?;
        } else if self.plain_len != self.disk_len {
            self.write_size_block(self.plain_len)?;
            let real_len = ciphertext_size(self.plain_len, true);
            // A grow already has its length (this only cuts a longer file
            // left by a crash). A shrink cuts now and then replaces the old
            // chunk bytes after the last chunk with random bytes.
            self.file.set_len(real_len)?;
            if !growing {
                write_padding(&self.file, used_len(self.plain_len, true), real_len)?;
            }
        }
        self.disk_len = self.plain_len;
        self.dirty.clear();
        self.trim_cache();
        Ok(())
    }

    /// Writes a new size block (fresh nonce) for the clear size `len`.
    /// Does nothing in a vault without padding.
    fn write_size_block(&self, len: u64) -> Result<()> {
        let Some(key) = &self.size_key else {
            return Ok(());
        };
        let block = seal_size(key.expose(), &self.header.to_bytes(), len)?;
        self.file.write_all_at(&block, HEADER_LEN)?;
        Ok(())
    }

    /// Flushes and then syncs the real file to the storage device.
    pub fn sync(&mut self) -> Result<()> {
        self.flush()?;
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{CHUNK_SIZE, PADDED_HEADER_LEN, ciphertext_size};
    use crate::error::Error;
    use crate::keys::{KeySet, MasterKey};
    use std::fs::{File, OpenOptions};
    use std::path::{Path, PathBuf};

    const CS: usize = CHUNK_SIZE as usize;
    const FILE_ID: EntryId = [5; 16];

    fn key_set(mk: u8) -> KeySet {
        KeySet::single(1, MasterKey::from_bytes([mk; 32]))
    }

    fn vault_keys(ks: &KeySet) -> VaultKeys {
        VaultKeys::new(&[3; 16], ks)
    }

    fn keys() -> VaultKeys {
        vault_keys(&key_set(7))
    }

    /// Runs `case` without and with size padding.
    fn both(case: impl Fn(bool)) {
        for padded in [false, true] {
            case(padded);
        }
    }

    struct Tmp {
        _dir: tempfile::TempDir,
        path: PathBuf,
        padded: bool,
    }

    fn tmp(padded: bool) -> Tmp {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        Tmp {
            _dir: dir,
            path,
            padded,
        }
    }

    fn rw(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap()
    }

    fn new_file(t: &Tmp) -> OpenFile {
        OpenFile::create(rw(&t.path), &keys(), FILE_ID, t.padded).unwrap()
    }

    fn try_open(t: &Tmp, keys: &VaultKeys) -> Result<OpenFile> {
        OpenFile::open(rw(&t.path), keys, t.padded)
    }

    fn reopen(t: &Tmp) -> OpenFile {
        try_open(t, &keys()).unwrap()
    }

    fn disk_len(t: &Tmp) -> u64 {
        std::fs::metadata(&t.path).unwrap().len()
    }

    fn size(t: &Tmp, len: u64) -> u64 {
        ciphertext_size(len, t.padded)
    }

    fn flip(t: &Tmp, offset: u64) {
        let mut bytes = std::fs::read(&t.path).unwrap();
        bytes[usize::try_from(offset).unwrap()] ^= 1;
        std::fs::write(&t.path, bytes).unwrap();
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn read_all(f: &mut OpenFile) -> Vec<u8> {
        let n = usize::try_from(f.len()).unwrap();
        f.read(0, n + 10).unwrap()
    }

    /// True if `open` fails or reading the first bytes fails.
    fn open_or_read_fails(t: &Tmp, keys: &VaultKeys) -> bool {
        match try_open(t, keys) {
            Err(_) => true,
            Ok(mut f) => f.read(0, 16).is_err(),
        }
    }

    #[test]
    fn empty_file_size() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            assert_eq!(disk_len(&t), if padded { 4096 } else { 81 });
            assert_eq!(f.len(), 0);
            assert!(f.read(0, 10).unwrap().is_empty());
            assert_eq!(f.file_id(), FILE_ID);
            assert_eq!(f.epoch(), 1);
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 0);
            assert_eq!(g.file_id(), FILE_ID);
            assert!(g.read(0, 10).unwrap().is_empty());
        });
    }

    #[test]
    fn write_read_across_chunks() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(200_000);
            let mut f = new_file(&t);
            assert_eq!(f.write(0, &data).unwrap(), 200_000);
            assert_eq!(read_all(&mut f), data);
            f.flush().unwrap();
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 200_000);
            assert_eq!(read_all(&mut g), data);
            assert_eq!(g.read(65_000, 1000).unwrap(), &data[65_000..66_000]);
            assert_eq!(g.read(199_990, 100).unwrap(), &data[199_990..]);
            assert!(g.read(200_000, 100).unwrap().is_empty());
            assert_eq!(disk_len(&t), size(&t, 200_000));
        });
    }

    #[test]
    fn partial_overwrite_inside_chunk() {
        both(|padded| {
            let t = tmp(padded);
            let mut data = pattern(200_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            drop(f);
            let mut g = reopen(&t);
            g.write(65_530, &[0xAA; 100]).unwrap();
            data[65_530..65_630].fill(0xAA);
            assert_eq!(read_all(&mut g), data);
            g.flush().unwrap();
            drop(g);
            assert_eq!(read_all(&mut reopen(&t)), data);
            assert_eq!(disk_len(&t), size(&t, 200_000));
        });
    }

    #[test]
    fn write_past_end_fills_zeros() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(150_000, b"x").unwrap();
            assert_eq!(f.len(), 150_001);
            let mut expected = vec![0u8; 150_000];
            expected.push(b'x');
            assert_eq!(read_all(&mut f), expected);
            f.flush().unwrap();
            drop(f);
            assert_eq!(read_all(&mut reopen(&t)), expected);
            assert_eq!(disk_len(&t), size(&t, 150_001));
        });
    }

    #[test]
    fn grow_rewrites_old_last_chunk() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, &pattern(100)).unwrap();
            f.flush().unwrap();
            drop(f);
            let mut g = reopen(&t);
            g.write(200_000, b"end").unwrap();
            g.flush().unwrap();
            drop(g);
            let mut expected = pattern(100);
            expected.resize(200_000, 0);
            expected.extend_from_slice(b"end");
            assert_eq!(read_all(&mut reopen(&t)), expected);
            assert_eq!(disk_len(&t), size(&t, 200_003));
        });
    }

    #[test]
    fn truncate_shrink_and_grow() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(200_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            f.truncate(70_000).unwrap();
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 70_000);
            assert_eq!(read_all(&mut g), &data[..70_000]);
            assert_eq!(disk_len(&t), size(&t, 70_000));
            g.truncate(140_000).unwrap();
            let mut expected = data[..70_000].to_vec();
            expected.resize(140_000, 0);
            assert_eq!(read_all(&mut g), expected);
            drop(g);
            let mut h = reopen(&t);
            assert_eq!(h.len(), 140_000);
            assert_eq!(read_all(&mut h), expected);
        });
    }

    #[test]
    fn truncate_unflushed_data() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(200_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.truncate(70_000).unwrap();
            f.truncate(140_000).unwrap();
            let mut expected = data[..70_000].to_vec();
            expected.resize(140_000, 0);
            assert_eq!(read_all(&mut f), expected);
            drop(f);
            assert_eq!(read_all(&mut reopen(&t)), expected);
        });
    }

    #[test]
    fn truncate_to_zero_is_empty_size() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, &pattern(100_000)).unwrap();
            f.flush().unwrap();
            f.truncate(0).unwrap();
            assert_eq!(disk_len(&t), if padded { 4096 } else { 81 });
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 0);
            assert!(g.read(0, 10).unwrap().is_empty());
        });
    }

    #[test]
    fn exact_chunk_multiple() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(131_072);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            drop(f);
            let expected = if padded {
                262_144
            } else {
                53 + 2 * (65_536 + 28)
            };
            assert_eq!(disk_len(&t), expected);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 131_072);
            assert_eq!(read_all(&mut g), data);
        });
    }

    #[test]
    fn dirty_limit_triggers_flush() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            let chunk = vec![1u8; CS];
            for i in 0..70u64 {
                f.write(i * CHUNK_SIZE, &chunk).unwrap();
            }
            assert!(disk_len(&t) > size(&t, 0));
            f.flush().unwrap();
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), 70 * CHUNK_SIZE);
            assert_eq!(g.read(69 * CHUNK_SIZE, CS).unwrap(), chunk);
        });
    }

    #[test]
    fn tampered_chunk_fails_auth() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, b"secret").unwrap();
            f.flush().unwrap();
            drop(f);
            flip(&t, chunk_offset(0, padded) + 14);
            let mut g = reopen(&t);
            assert!(matches!(g.read(0, 6), Err(Error::AuthFailed { .. })));
        });
    }

    #[test]
    fn open_rejects_bad_files() {
        both(|padded| {
            let t = tmp(padded);
            for bytes in [vec![1u8; 40], vec![2u8; 81], vec![2u8; 4096]] {
                std::fs::write(&t.path, bytes).unwrap();
                assert!(matches!(
                    try_open(&t, &keys()),
                    Err(Error::InvalidFormat { .. })
                ));
            }
        });
    }

    #[test]
    fn wrong_key_fails_auth() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, b"secret").unwrap();
            f.flush().unwrap();
            drop(f);
            let other = vault_keys(&key_set(8));
            let result = try_open(&t, &other).and_then(|mut g| g.read(0, 6));
            assert!(matches!(result, Err(Error::AuthFailed { .. })));
        });
    }

    #[test]
    fn epoch_from_header() {
        both(|padded| {
            let t = tmp(padded);
            let one = key_set(7);
            let two = one.with_next(MasterKey::from_bytes([9; 32])).unwrap();
            let both_keys = vault_keys(&two);
            // A file of epoch 1, then a key set {1, 2}.
            let mut f = OpenFile::create(rw(&t.path), &keys(), FILE_ID, padded).unwrap();
            f.write(0, b"old").unwrap();
            f.flush().unwrap();
            drop(f);
            let mut g = try_open(&t, &both_keys).unwrap();
            assert_eq!(g.epoch(), 1);
            assert_eq!(read_all(&mut g), b"old");
            drop(g);
            // Only {2}: the epoch 1 file has no key.
            let only_two = vault_keys(&two.only(2).unwrap());
            assert!(matches!(
                try_open(&t, &only_two),
                Err(Error::AuthFailed { what }) if what == "unknown key epoch"
            ));
            // New files use the write epoch.
            let t2 = tmp(padded);
            let mut h = OpenFile::create(rw(&t2.path), &both_keys, FILE_ID, padded).unwrap();
            assert_eq!(h.epoch(), 2);
            h.write(0, b"new").unwrap();
            h.flush().unwrap();
            drop(h);
            let mut h = try_open(&t2, &only_two).unwrap();
            assert_eq!(h.epoch(), 2);
            assert_eq!(read_all(&mut h), b"new");
        });
    }

    #[test]
    fn header_epoch_is_bound() {
        both(|padded| {
            for offset in 1..5u64 {
                for bit in [0u8, 7] {
                    let t = tmp(padded);
                    let mut f = new_file(&t);
                    f.write(0, b"secret").unwrap();
                    f.flush().unwrap();
                    drop(f);
                    let mut bytes = std::fs::read(&t.path).unwrap();
                    bytes[usize::try_from(offset).unwrap()] ^= 1 << bit;
                    std::fs::write(&t.path, bytes).unwrap();
                    assert!(open_or_read_fails(&t, &keys()), "offset {offset} bit {bit}");
                }
            }
        });
    }

    #[test]
    fn epoch_zero_is_unknown() {
        both(|padded| {
            let t = tmp(padded);
            drop(new_file(&t));
            let mut bytes = std::fs::read(&t.path).unwrap();
            bytes[1..5].copy_from_slice(&0u32.to_le_bytes());
            std::fs::write(&t.path, bytes).unwrap();
            assert!(matches!(
                try_open(&t, &keys()),
                Err(Error::AuthFailed { what }) if what == "unknown key epoch"
            ));
        });
    }

    #[test]
    fn read_file_meta_reads_header_and_size() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, &pattern(70_000)).unwrap();
            f.flush().unwrap();
            drop(f);
            let (header, len) = read_file_meta(&rw(&t.path), &keys(), padded).unwrap();
            assert_eq!(len, 70_000);
            assert_eq!(header.epoch, 1);
            assert_eq!(header.file_id, FILE_ID);
        });
    }

    /// Grows and shrinks one padded file across the stage borders.
    #[test]
    fn padded_stage_edges() {
        let t = tmp(true);
        drop(new_file(&t));
        let sizes: [u64; 9] = [
            0,
            4096 - 89 - 28,
            4096 - 89 - 27,
            65536,
            1_048_576 - 89 - 28 * 16,
            1_048_577,
            3_000_000,
            10,
            0,
        ];
        for &len in &sizes {
            let mut f = reopen(&t);
            let cur = f.len();
            if len > cur {
                let all = pattern(usize::try_from(len).unwrap());
                f.write(cur, &all[usize::try_from(cur).unwrap()..]).unwrap();
            } else {
                f.truncate(len).unwrap();
            }
            f.flush().unwrap();
            drop(f);
            let mut g = reopen(&t);
            assert_eq!(g.len(), len, "len {len}");
            assert!(
                read_all(&mut g) == pattern(usize::try_from(len).unwrap()),
                "bytes at len {len}"
            );
            assert_eq!(
                disk_len(&t),
                ciphertext_size(len, true),
                "real len at {len}"
            );
        }
    }

    #[test]
    fn padded_length_mismatch() {
        let t = tmp(true);
        let mut f = new_file(&t);
        f.write(0, b"data").unwrap();
        f.flush().unwrap();
        drop(f);
        let mut bytes = std::fs::read(&t.path).unwrap();
        bytes.push(0);
        std::fs::write(&t.path, bytes).unwrap();
        assert!(matches!(
            try_open(&t, &keys()),
            Err(Error::InvalidFormat { what }) if what == "file size"
        ));
    }

    #[test]
    fn padded_size_block_is_bound() {
        let t = tmp(true);
        let mut f = new_file(&t);
        f.write(0, b"data").unwrap();
        f.flush().unwrap();
        drop(f);
        flip(&t, HEADER_LEN + 20);
        assert!(matches!(
            try_open(&t, &keys()),
            Err(Error::AuthFailed { .. })
        ));
    }

    #[test]
    fn padding_is_random_and_never_read() {
        let t = tmp(true);
        let mut f = new_file(&t);
        f.write(0, &pattern(5000)).unwrap();
        f.flush().unwrap();
        f.truncate(100).unwrap();
        drop(f);
        let used = usize::try_from(PADDED_HEADER_LEN + 28 + 100).unwrap();
        let mut bytes = std::fs::read(&t.path).unwrap();
        assert_eq!(bytes.len(), 4096);
        let zeros = bytes[used..].iter().filter(|&&b| b == 0).count();
        assert!(zeros < 200, "padding has {zeros} zero bytes");
        for b in &mut bytes[used..] {
            *b ^= 0x55;
        }
        std::fs::write(&t.path, bytes).unwrap();
        assert_eq!(read_all(&mut reopen(&t)), pattern(100));
    }

    #[test]
    fn grow_flush_sets_stage_and_random_tail() {
        let t = tmp(true);
        let mut f = new_file(&t);
        f.write(0, &pattern(300_000)).unwrap();
        f.flush().unwrap();
        assert_eq!(disk_len(&t), 524_288);
        let used = usize::try_from(used_len(300_000, true)).unwrap();
        let bytes = std::fs::read(&t.path).unwrap();
        let tail = &bytes[used..];
        assert!(!tail.is_empty());
        let zeros = tail.iter().filter(|&&b| b == 0).count();
        assert!(zeros < tail.len() / 100, "padding has {zeros} zero bytes");
        drop(f);
        assert_eq!(read_all(&mut reopen(&t)), pattern(300_000));
    }

    #[test]
    fn growth_fills_new_padding_with_random_bytes() {
        let t = tmp(true);
        let mut f = new_file(&t);
        f.write(0, &pattern(10)).unwrap();
        f.flush().unwrap();
        f.write(0, &pattern(9000)).unwrap();
        f.flush().unwrap();
        drop(f);
        let used = usize::try_from(PADDED_HEADER_LEN + 28 + 9000).unwrap();
        let bytes = std::fs::read(&t.path).unwrap();
        assert_eq!(bytes.len(), 16384);
        let zeros = bytes[used..].iter().filter(|&&b| b == 0).count();
        assert!(zeros < 200, "padding has {zeros} zero bytes");
    }

    fn is_enospc(r: &Result<()>) -> bool {
        matches!(r, Err(Error::Io(e)) if e.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()))
    }

    /// True if the file system of `t` reports its sizes (else the free
    /// space check is skipped and a huge grow would really be written).
    fn reports_free_space(t: &Tmp) -> bool {
        rustix::fs::statvfs(t.path.parent().unwrap()).is_ok_and(|st| st.f_blocks > 0)
    }

    /// A file of `n` full chunks, flushed and opened again (empty cache).
    fn file_of_chunks(t: &Tmp, n: usize) -> OpenFile {
        let mut f = new_file(t);
        f.write(0, &pattern(n * CS)).unwrap();
        f.flush().unwrap();
        drop(f);
        reopen(t)
    }

    fn cached(f: &OpenFile) -> Vec<u64> {
        f.chunks.keys().copied().collect()
    }

    #[test]
    fn cache_keeps_a_chunk_that_is_used_again() {
        let t = tmp(false);
        let mut f = file_of_chunks(&t, 20);
        for i in 1..20u64 {
            f.read(0, 10).unwrap();
            f.read(i * CS as u64, 10).unwrap();
        }
        let c = cached(&f);
        assert_eq!(c.len(), MAX_CLEAN_CHUNKS);
        assert_eq!(c[0], 0, "chunk 0 was dropped: {c:?}");
        // The others are the most recent ones.
        assert_eq!(&c[1..], &[13, 14, 15, 16, 17, 18, 19]);
    }

    #[test]
    fn cache_keeps_the_chunk_read_last_when_reading_backwards() {
        let t = tmp(false);
        let mut f = file_of_chunks(&t, 20);
        for i in (0..20u64).rev() {
            f.read(i * CS as u64, 10).unwrap();
        }
        assert_eq!(cached(&f), (0..MAX_CLEAN_CHUNKS as u64).collect::<Vec<_>>());
        assert!(f.last_use.keys().all(|i| f.chunks.contains_key(i)));
    }

    #[test]
    fn cache_never_drops_dirty_chunks() {
        let t = tmp(false);
        let mut f = file_of_chunks(&t, 30);
        f.write(0, b"changed").unwrap();
        for i in 1..30u64 {
            f.read(i * CS as u64, 10).unwrap();
        }
        assert!(f.chunks.contains_key(&0));
        assert_eq!(f.chunks.len(), MAX_CLEAN_CHUNKS + 1);
        f.flush().unwrap();
        drop(f);
        assert_eq!(reopen(&t).read(0, 7).unwrap(), b"changed");
    }

    #[test]
    fn huge_grow_fails_at_once_and_changes_nothing() {
        both(|padded| {
            let t = tmp(padded);
            if !reports_free_space(&t) {
                return;
            }
            let data = pattern(100_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            let start = std::time::Instant::now();
            // 1 PiB: more than any test machine has free.
            assert!(is_enospc(&f.truncate(1 << 50)));
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            assert_eq!(f.len(), 100_000);
            assert_eq!(disk_len(&t), size(&t, 100_000));
            assert_eq!(read_all(&mut f), data);
            // A write far past the end fails at its flush the same way.
            f.write(1 << 50, b"x").unwrap();
            assert!(is_enospc(&f.flush()));
            assert_eq!(disk_len(&t), size(&t, 100_000));
            drop(f);
            assert_eq!(read_all(&mut reopen(&t)), data);
        });
    }

    #[test]
    fn failed_grow_by_truncate_is_undone() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(100_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            fail_chunk_writes_after(Some(3));
            let r = f.truncate(20 * CHUNK_SIZE);
            fail_chunk_writes_after(None);
            assert!(is_enospc(&r));
            assert_eq!(f.len(), 100_000);
            assert_eq!(disk_len(&t), size(&t, 100_000));
            assert_eq!(read_all(&mut f), data);
            assert_eq!(read_all(&mut reopen(&t)), data);
            // The file still works: the same grow succeeds now.
            f.truncate(20 * CHUNK_SIZE).unwrap();
            drop(f);
            let mut want = data.clone();
            want.resize(20 * CS, 0);
            assert_eq!(read_all(&mut reopen(&t)), want);
        });
    }

    #[test]
    fn failed_flush_of_a_write_past_the_end_keeps_it_for_a_retry() {
        both(|padded| {
            let t = tmp(padded);
            let data = pattern(100_000);
            let mut f = new_file(&t);
            f.write(0, &data).unwrap();
            f.flush().unwrap();
            f.write(10 * CHUNK_SIZE, b"tail").unwrap();
            fail_chunk_writes_after(Some(1));
            let r = f.flush();
            fail_chunk_writes_after(None);
            assert!(is_enospc(&r));
            // On disk: the old file. In memory: the write.
            assert_eq!(disk_len(&t), size(&t, 100_000));
            assert_eq!(read_all(&mut reopen(&t)), data);
            assert_eq!(f.len(), 10 * CHUNK_SIZE + 4);
            f.flush().unwrap();
            drop(f);
            let mut want = data.clone();
            want.resize(10 * CS, 0);
            want.extend_from_slice(b"tail");
            assert_eq!(read_all(&mut reopen(&t)), want);
        });
    }

    #[test]
    fn grow_writes_zero_gaps_around_dirty_chunks() {
        both(|padded| {
            let t = tmp(padded);
            let mut f = new_file(&t);
            f.write(0, b"head").unwrap();
            f.flush().unwrap();
            f.write(3 * CHUNK_SIZE + 10, b"mid").unwrap();
            f.write(7 * CHUNK_SIZE + 5, b"end").unwrap();
            f.flush().unwrap();
            drop(f);
            let mut want = vec![0u8; 7 * CS + 8];
            want[..4].copy_from_slice(b"head");
            want[3 * CS + 10..3 * CS + 13].copy_from_slice(b"mid");
            want[7 * CS + 5..].copy_from_slice(b"end");
            assert_eq!(read_all(&mut reopen(&t)), want);
            assert_eq!(disk_len(&t), size(&t, 7 * CHUNK_SIZE + 8));
        });
    }
}
