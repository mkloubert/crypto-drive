# crypto-drive – Keep listings outside the fd cache (review P1)

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: "mache P1")
- **Author:** Marcel Joachim Kloubert
- **Source:** review report 2026-11-02, finding P1

## 1. Problem

Every cached `DirState` holds an open fd of its real directory, so the
directory cache is small: a quarter of the soft open-file limit, 16 to
1024 states (`fs/mod.rs`). The decrypted listing (name index) lives in the
`SharedDir` of the real directory, which only states held (`Weak` in
`shared_dirs`). A state that left the cache took its listing with it. A
tree with more directories than the cache (node_modules, a git checkout,
an IDE index run) built every listing again on every pass: one `stat` and
one name decryption per entry.

## 2. Design

- `KeptDirs` (`fs/dirstate.rs`): an LRU of `Arc<SharedDir>` by
  `SharedKey` (device, inode, canonical id), without fds. Bounded by
  listing entries: the weight of a directory is 1 plus its entries; the
  budget `KEPT_DIR_ENTRIES` is 131 072 (about 200 bytes per entry, so
  about 25 MiB at most).
- `store` uses `LruCache::push`; a state that leaves the fd cache hands its
  `SharedDir` to `KeptDirs` (`keep_shared`). The weight is read with
  `try_lock`, so this never waits behind a listing that is being built.
- The next state of the same real directory finds the kept `SharedDir`
  through `shared_dirs` as before. `shared_dir` still compares the stored
  mtime with the real one and drops the listing on a change, so a kept
  listing is used under the same rule as a cached state. Nothing else in
  the validity rules changes (parent generation, `is_current`,
  `with_change`, `invalidate`).
- `shared_dirs` prunes unused entries when it reaches a mark that is
  `max(4096, 2 × size after the last prune)`; with kept directories a fixed
  mark would prune on every new directory.

Not changed: `load_child` still opens the directory, lists it and reads
`.cd-dir` on every reload, so the binding check of the directory id keeps
running. Skipping that would save more time but touches the check; it is
left for a separate decision.

## 3. Measured (Linux ARM64 container, core only, no FUSE)

`cargo bench -p crypto-drive-core --bench throughput -- fs_tree_walk`:
one pass lists every directory and stats every entry; 10 files per
directory, fd cache 1024.

| Tree | Before | After | Change |
|---|---|---|---|
| 500 directories (fit in the cache) | 7.46 ms | 7.19 ms | −9 % (noise range) |
| 1500 directories | 74.5 ms (49.7 µs/dir) | 43.8 ms (29.2 µs/dir) | −41 % |

## 4. Decisions

| Topic | Decision |
|---|---|
| Bound | By listing entries (`KEPT_DIR_ENTRIES` 131 072, about 25 MiB), not by directories. |
| Reload of a kept directory | Still lists the directory and reads `.cd-dir` (binding check stays). |
| Format | No change. |

## 5. Tests

- `directories_out_of_the_fd_cache_keep_their_listing`: 40 directories,
  fd cache of 16; a second pass builds no listing (failed before).
- `a_kept_listing_sees_outside_changes`: changes from a second instance in
  directories that left the fd cache are seen.
- `KeptDirs` unit tests: budget, order, re-keep, too heavy, freeing.
- Benchmark `fs_tree_walk` (500 / 1500 directories).
