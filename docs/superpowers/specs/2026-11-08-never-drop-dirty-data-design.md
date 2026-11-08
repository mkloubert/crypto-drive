# crypto-drive – Never drop buffered data (review R1 + R2)

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08)
- **Author:** Marcel Joachim Kloubert
- **Source:** review report 2026-11-02, findings R1 and R2

## 1. Problem

Writes are buffered in memory (`OpenFile`, up to `MAX_DIRTY_CHUNKS` dirty
chunks of 64 KiB) and reach the real file at a flush: when the buffer is
full, after an idle time, at `flush` (close), `fsync` or `release`.

- **R1:** `CryptoFs::release` removes the handle and flushes. If the flush
  fails, the last handle drops the `OpenFile` and its dirty chunks are
  gone. The kernel ignores the release error, and the adapter logs `Io`
  errors only at debug level. A program that ignores the error of
  `close()` thinks the data is saved.
- **R2:** the free-space check runs only when a file grows. On
  copy-on-write file systems (APFS, btrfs) an overwrite needs free blocks
  too. A short write with `ENOSPC` leaves a half-new chunk: the whole
  64 KiB chunk reads as an error until a later flush writes it again, and
  R1 throws that retry away. Also, `OpenFile::write` takes the data into
  the dirty set and then flushes; a failed flush returns an error for data
  that was taken, and a writer that ignores errors grows the dirty set
  without a limit.

## 2. Goals

1. Buffered data is never dropped while the process runs. It is written
   as soon as the real file system allows it.
2. Write errors of buffered data are visible without `--debug`.
3. A flush does not start when the free space is clearly too small, so no
   chunk is left half written by a full disk in the normal case.
4. A write that returns an error has not changed anything; memory per
   open file stays bounded.
5. The drive is not unmounted, and the process does not end, while
   buffered data could not be written.

Non-goals: crash safety (copy-on-write chunks, journal), detecting a
replaced real file (R3), a format change.

## 3. Design

### 3.1 Orphans (core, `fs/files.rs`)

- `CryptoFs` gets `orphans: Mutex<Vec<Shared>>`: strong references to
  `OpenFile`s that have no handle any more but still have unwritten
  changes.
- `release` (and the path based `truncate`, which also drops its own
  reference) hand the shared state to `keep_if_unwritten`: if no other
  handle holds it and it still has unwritten changes, it goes into
  `orphans`, and an error is logged at `error` level (no clear name).
- The entry in `open_files` (a `Weak`) stays valid, so a new `open` of the
  same real file finds the orphan and works on its buffered state.
- `flush_idle` already walks `open_files`, so it retries orphans (with the
  `MAX_DIRTY_AGE` back-off after a failure). `flush_idle` and `flush_all`
  then drop orphans that have nothing left to write.
- `unwritten_files()` returns how many open files (orphans included) still
  have unwritten changes.

### 3.2 Free space before every flush (core, `file.rs`)

- `check_space` runs before every flush with unwritten changes, not only
  before a grow. The need is the growth of the real file plus the stored
  size of every dirty chunk (`CHUNK_SIZE + CHUNK_OVERHEAD`), plus the size
  block in a padded vault. This is an upper bound: on file systems that
  overwrite in place (ext4) it can refuse a flush that would have worked.
  The data then stays in memory and is retried, so this costs no data.
- A file system that reports no sizes is not checked (as before).

### 3.3 Write takes data only if it can (core, `file.rs`)

- `OpenFile::write` flushes **before** it takes the data, when the new
  chunks would push the dirty set over `MAX_DIRTY_CHUNKS`. If that flush
  fails, the write returns the error and changes nothing.
- So the dirty set is at most `MAX_DIRTY_CHUNKS` plus the chunks of one
  write call, and a failed write is really not done.

### 3.4 Logging (fuse adapter)

- `core_err` logs `Io` errors of `write`, `flush`, `fsync` and `release`
  at `error` level. `Io` texts carry no names.

### 3.5 Stop and unmount wait for unwritten data (fuse `mount.rs`)

- On a stop signal, `wait_for_stop` first writes all buffers
  (`flush_all`). If that fails, the drive stays mounted, an error names
  the reason and says to free space and stop again. The next signal tries
  again. Only after a full write it tries the unmount (busy handling as
  before).
- After the session ended (signal or an outside unmount, which the
  process cannot refuse), `wait_for_written` retries `flush_all` every
  `UNWRITTEN_RETRY` (5 s) until it works. It logs an error on the first
  failure and again on each stop signal. The process (and the vault lock)
  stays until then. `kill -9` is the only way to give up the data.

## 4. Decisions

| Topic | Decision |
|---|---|
| What happens at unmount with data that cannot be written | **Wait** (owner, 2026-11-08): the drive stays mounted on a stop signal, and after an outside unmount the process keeps trying until the data is written. |
| Free-space check on every flush | Accepted as an upper bound; a refused flush keeps its data and is retried. |
| Format | No change. |

## 5. Tests

- Core: a failed flush at release keeps the data (orphan); it is written
  by a later `flush_idle` / `flush_all` and readable after reopen; a new
  `open` sees the buffered data; `unwritten_files` counts it.
- Core: an overwrite without enough free space fails before any chunk is
  written (test hook for the free space).
- Core: a write whose pre-flush fails returns the error and changes
  neither the size nor the content; the dirty set stays bounded.
- Fuse: `wait_for_stop` does not try the unmount while `flush_all` fails;
  `wait_for_written` retries until it works.
