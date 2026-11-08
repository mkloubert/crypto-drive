# crypto-drive – New file key on a cut to size 0

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: scope A "cut to
  size 0 only", epoch A "write epoch"). Implemented 2026-11-08, tested in
  the Linux container only
- **Author:** Marcel Joachim Kloubert
- **Source:** review 2026-11-08 (`REPORT.md`), finding SEC-4; README
  "Threat model", gap "Mixing old and new chunks of the same file"

## 1. Problem

The header of a file, and with it the file key `K_file` (and `K_size` in
a padded vault), is written only once, in `OpenFile::create`
(`crates/crypto-drive-core/src/file.rs`). `OpenFile::truncate` keeps the
header, also for a cut to size 0. So every version of a file uses the
same key for its whole life, also when an app saves by opening the file
with `O_TRUNC` (shell `>`, many editors and tools) and writes it again
from the start.

Two results:

1. **Chunk mixing.** Someone who can change the vault (for example the
   cloud provider, from its version history) can put chunk `i` of an
   older version at the place of chunk `i` of the current version. The
   chunk authenticates, because index, "is last" flag and key are the
   same. The file then holds parts of two versions, a state that never
   existed, and no error is given. With the old last chunk the file can
   also be cut back to an old length.
2. **Nonce budget (SEC-4).** Every chunk write takes a new random 96-bit
   nonce under the same key. The usual limit for random nonces is 2^32
   encryptions per key. A collision gives away the GHASH key of that file
   and allows forged chunks.

Rotation (`rotate-key`) already writes a new `file_nonce` with the same
`file_id` for every file, so a header change of this kind is valid
format v1.

## 2. Goals

1. After a cut to size 0 (`truncate(0)`, `ftruncate(0)`, `open` with
   `O_TRUNC`), no chunk of a version from before the cut authenticates in
   the file any more. Putting one in gives an authentication error on
   read, never mixed plaintext.
2. The nonce budget of a file starts again at every cut to size 0.
3. No format version change: readers of format v1 (also release v0.1.2)
   read such files. Golden vaults and KAT vectors stay as they are.
4. Crash safety stays as it is today for a shrink.

Not a goal:

- Files written in place without a cut to size 0 (databases, VM images,
  `dd conv=notrunc`). They keep one key; for them only a per-flush file
  key (a format change, open item) helps. A full rewrite without a cut
  does **not** get a new key (owner decision, see section 6).
- Rollback of a whole file to an older version (header and all chunks).
  It stays undetected (`docs/format.md` section 8).

## 3. Design

### 3.1 Rule

When `OpenFile::truncate` is called with `new_len == 0`, it always makes a
new header:

- `FileHeader::random(keys.write_epoch(), file_id)`: a new random
  `file_nonce`, the same `file_id`, the write epoch of the key set (owner
  decision, section 6; during a rotation this is `e + 1`),
- a new `ChunkCipher` from the new header,
- in a padded vault a new size key.

The old cipher and size key are dropped and so wiped (`ZeroizeOnDrop` /
`SecretBytes`).

"Always" means also when the file is already empty: one header write of
81 bytes (89 bytes padded) is cheap, and the rule stays simple and
testable. A file that is empty now may have had content under the same key
in an older version.

### 3.2 Interface

`OpenFile::truncate(&mut self, new_len: u64, keys: &VaultKeys)`: an
`OpenFile` does not hold the key set, so the caller passes it. Callers:
`CryptoFs::truncate` and `CryptoFs::truncate_handle`
(`crates/crypto-drive-core/src/fs/files.rs`) pass `self.keys`. The FUSE
adapter does not change: `open` with `O_TRUNC` and `setattr` with a size
already go through `CryptoFs::truncate` / `truncate_handle`.

### 3.3 Writing

New field `header_dirty: bool` in `OpenFile`: a new header is in memory
but not on disk yet. `has_unwritten_changes` is true while it is set.

`write_out` with `header_dirty`:

- Not padded: write chunk 0 (empty, "is last"), then the 53 header bytes
  at offset 0, then cut the real file to 81 bytes.
- Padded (order of `docs/format.md` 7.2 for a shrink): write chunk 0,
  then the header and the new size block (89 bytes at offset 0), then cut
  to the stage length, then fill the bytes after the last chunk with
  random bytes.
- After success: `header_dirty = false`.

`space_needed` adds the header length (53 or 89) while `header_dirty` is
set (copy-on-write file systems need new blocks for it).

### 3.4 Errors and crashes

- A failed write (I/O error, `ENOSPC`) keeps the new header and
  `header_dirty` in memory. While it is set, the clear size on disk counts
  as 0 (`disk_len`): no chunk on disk opens with the new key, so reads load
  nothing from disk, and the next flush (or the orphan handling of review
  R1) writes every chunk up to the new end under the new key (written data
  or zeros), then the header and the length. In a padded vault the bytes
  after the last chunk get new random padding, so no old chunk stays
  behind.
- A grow that fails after a failed cut (the undo of review R2) leaves the
  cut file on disk: an empty file with the new header, readable. The old
  content is gone at that point, because the grow already wrote chunks
  under the new key.
- A crash in the middle (new chunk 0 or new header on disk, old chunks
  behind it) makes this one file unreadable: the length does not fit the
  "is last" chunk, or the header does not fit the chunks. This is the same
  risk as for every shrink today (`docs/format.md` 7.2, "A crash in the
  middle can make this one file unreadable"); `check` reports it. The
  data was being thrown away at this moment anyway.
- An in-place write is used, not a temporary file plus rename: the real
  file keeps its inode, all open handles (one shared `OpenFile`) stay
  valid, and `ftruncate` after `unlink` works.

### 3.5 Rotation

A file of epoch `e` that is cut to size 0 during a rotation gets epoch
`e + 1`. `rotate-key` counts an entry as done only if its name **and** its
header use `e + 1`. If the name still uses `e`, the rotation writes the
content again with a new `file_nonce`; that is correct, only a bit of
extra work.

## 4. Docs

- `docs/format.md` section 7: new rule "A writer SHOULD write a new
  header (new random `file_nonce`, same `file_id`, the write epoch) when it
  cuts a file to size 0, so chunks of earlier versions no longer
  authenticate." SHOULD, not MUST: readers are not affected.
- `docs/format.md` section 11: the sentence "A changed file of epoch `e`
  keeps epoch `e` until the next rotation run" gets the exception "except
  after a cut to size 0: then it gets the write epoch (section 7)".
- README "Threat model": the paragraph "Mixing old and new chunks of the
  same file" is narrowed to files written in place without a cut to size 0
  (databases, VM images); apps that save with `O_TRUNC` or through a new
  file are not affected. One sentence on the nonce budget of such files.
- `site/index.html`: the list item "Mixing old and new chunks of the same
  file" (section "not protected") gets the same narrowing.
- `CLAUDE-new.md`: `file` module row, status section 11, test count.

## 5. Tests (TDD: tests 1, 2 and 4 fail without the change)

In `crates/crypto-drive-core/src/file.rs`, each padded and not padded:

1. `old_chunk_after_cut_to_zero_fails`: write version 1 (about 200 KiB,
   4 chunks), flush, save the raw bytes of chunk 1; `truncate(0)`; write
   version 2 of the same size, flush; write the saved bytes back at the
   place of chunk 1; reopen; reading chunk 1 must fail with
   `AuthFailed`. Today it returns version 1 data without an error.
2. `cut_to_zero_writes_new_header`: after `truncate(0)` the `file_nonce`
   on disk is new, the `file_id` is the same; with a key set of two epochs
   the header epoch is the write epoch.
3. `cut_to_zero_retries_after_failed_write` (guards the new error path;
   it may pass today): the write fails
   (`fake_free_space` or `fail_chunk_writes_after`), the file stays size 0
   in memory, the next flush works, a reopen reads an empty file, and
   data written after it reads back.

In `crates/crypto-drive-core/tests/tamper.rs`:

4. `old_chunk_after_truncate_fails`: the same as test 1 through
   `CryptoFs` (`truncate(path, 0)`, the path of `O_TRUNC`).

Existing tests that call `OpenFile::truncate` get the extra `keys`
argument. Platforms: core code only, no `cfg(target_os)` code, so the
container checks of CLAUDE.md section 7 are enough; no mount test is
needed because the adapter does not change.

## 6. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | New key also for a full rewrite without a cut to size 0? | No (A). A crash in the middle would make the whole file unreadable instead of leaving readable mixed data; owner chose cut to size 0 only. |
| 2 | Epoch of the new header during a rotation | The write epoch (A), as for a new file. |
| 3 | In place or temporary file + rename? | In place: keeps the inode, open handles and `ftruncate` after `unlink`. |
| 4 | New header also when the file is already empty? | Yes, always on `truncate(0)`: simple rule, an older version may have content under the same key. |
