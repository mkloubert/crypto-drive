# crypto-drive – Fewer directory syncs (review P4-a, P5-b)

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: "F_FULLFSYNC bleibt,
  mache P4-a und P5-b")
- **Author:** Marcel Joachim Kloubert
- **Source:** review report 2026-11-02, findings P4 and P5

## 1. Problem

- **P4:** every `fsync` of a file with a path also syncs the real directory
  of its entry (and the `.cd-cdl` directory of a long name), also when the
  entry did not change since the last sync. SQLite and git call `fsync`
  often.
- **P5:** `mkdir` writes `.cd-dir` with `write_atomic`: `fsync` of the
  temporary file, `rename`, `fsync` of the new directory. npm, cargo, unzip
  and git create many directories and most of them never call `fsync`.

## 2. Goals

1. A directory is synced only if one of its entries changed through this
   process since its last sync (P4-a). No guarantee is weaker than before.
2. `mkdir` of a short-name directory does no `fsync` (P5-b). Before anything
   in that directory is synced (`fsync` of a file in it, `fsyncdir`), its
   `.cd-dir`, the directory and its entry in the parent are synced first,
   up the path while directories are new.
3. A crash before that leaves a directory that is incomplete in the sense of
   `docs/format.md` section 9, never a directory that gives an error
   although nothing in it was synced.

Not changed: `F_FULLFSYNC` for file syncs on macOS (owner decision), the
eager `write_atomic` of every other control file, long-name directories
(`.cd-name` + `.cd-dir` stay eager; they are rare), renames.

## 3. Design

### 3.1 Tracking (`fs/unsynced.rs`)

`Unsynced` holds two sets of real directories by `(dev, ino)`:

- `changed`: own entry changes since the last sync. Marked in `end_change`
  (create, mkdir, unlink, rmdir, rename all end there).
- `new`: directories made by a deferred `mkdir` whose `.cd-dir` is not
  synced.

Both sets are capped (`MAX_UNSYNCED_DIRS` 65 536). When a set is full, the
change is synced at once instead (the old behavior), so memory stays
bounded and nothing is lost. A mark is taken out **before** the sync and put
back if the sync fails, so a change made during the sync is not lost.

Stale marks (a removed directory, a reused inode) only cost one extra sync.

### 3.2 Sync chain

`sync_dir_chain(path, state)`: for the directory at `path`, sync `.cd-dir`
if it is new, then the directory if it is changed or new; if it was new,
continue with its parent (its entry there must be durable too), else stop.

- `fsync(fh, Some(path))`: file sync as before, then the long entry
  directory (always, as before), then `sync_dir_chain(parent)`.
- `fsyncdir(path)`: always syncs the directory (explicit request), then the
  chain as above.

### 3.3 Deferred `mkdir`

For a short name and when `Unsynced` has room: `.cd-dir` is written with a
temporary file and `rename` but without `fsync` (`write_new_unsynced`), and
the new directory is marked `new` and `changed`. The parent is marked
`changed` by `end_change`. If the mark does not fit after all, the
directory and `.cd-dir` are synced at once.

### 3.4 Reader (crash after a deferred `mkdir`)

The rename of an unsynced file can survive a crash while its data does not:
`.cd-dir` may be empty. `load_child` treats an **empty** `.cd-dir` like a
missing one: if the directory holds only control or temporary files, it is
incomplete (`NotFound`, removed when older than 60 s); otherwise
`InvalidFormat` as before. A `.cd-dir` with any other wrong length stays
`InvalidFormat`.

## 4. Measured (Linux ARM64 container, core only, no FUSE)

`cargo bench -p crypto-drive-core --bench throughput -- "fs_mkdir|fs_fsync_loop"`:

| Benchmark | Before | After |
|---|---|---|
| `fs_mkdir/100_dirs` | 52.2 ms | 4.1 ms (−92 %) |
| `fs_fsync_loop/write_4KiB_fsync` | 0.20–2.20 ms (median 1.35 ms, very noisy) | 0.30 ms; change not significant (p = 0.24) |

The fsync loop needs a measurement on the Mac (`F_FULLFSYNC`, APFS).

## 5. Known residual risk

A crash or power cut shortly after a program filled a new directory
without any `fsync` can leave the entries on disk but `.cd-dir` empty: the
whole directory then gives `InvalidFormat` (before: only the unsynced files
were broken). The data was never promised. The `dir_id` is also the entry
id in the parent name, so a later repair can rebuild `.cd-dir` without
loss (follow-up, needs an owner decision). Documented in README "Limits".

## 6. Decisions

| Topic | Decision |
|---|---|
| `F_FULLFSYNC` on macOS | Stays (owner, 2026-11-08). |
| Directory sync on `fsync` | Only after an own entry change (P4-a). |
| `mkdir` | Deferred sync of `.cd-dir` for short names (P5-b). Long names stay eager. |
| Empty `.cd-dir` | Counts as missing (incomplete directory), matching `docs/format.md` 9 "without a valid `.cd-dir`". |
| Format | No change of the bytes on disk; `docs/format.md` 5 allows the deferred sync. |

## 7. Tests

- A second `fsync` without an entry change syncs no directory; after a
  rename / create / unlink it does again (failed before).
- `mkdir` does no `fsync` (failed before).
- `fsync` of a file in new nested directories syncs every new `.cd-dir`,
  the new directories and their parents; a second `fsync` syncs none.
- `fsyncdir` of a new directory syncs its `.cd-dir` and its parent.
- A full `Unsynced` falls back to syncing at once.
- An empty `.cd-dir` in an otherwise empty directory is incomplete (young:
  not found; old: removed); with other entries `InvalidFormat`.
- Benchmark `fs_mkdir` (many `mkdir`, no `fsync`) and `fs_fsync_loop`.
