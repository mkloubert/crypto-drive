# crypto-drive – Outside changes on coarse mtimes

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: approach 1 only,
  window 2 s). Implemented 2026-11-08; tested in the Linux container (also
  with a simulated 100 ms mtime tick) and by the owner on Debian 13 (kernel
  6.12, ARM64): `cargo test --workspace`, the real-mount tests and
  `scripts/smoke-test.sh` pass
- **Author:** Marcel Joachim Kloubert
- **Source:** first `cargo test --workspace` on Debian 13 (Linux
  6.12.115+deb13.1-arm64), 9 failed core tests

## 1. Problem

The running drive finds outside changes (a sync client, a second
instance) only through the mtime of the real directory (HS 3.3): a state
is current while `stat().mtime` equals the stored mtime. After an own
change, `refresh_mtime` stores the new mtime of the directory.

The mtime of a directory moves in ticks. Linux before 6.13 (no multigrain
timestamps) uses the coarse kernel clock: 4 ms on the Debian 13 ARM64 kernel
(measured: five `touch` in a row gave two distinct times, 4 ms apart). FAT
has 2 s, HFS+ 1 s. An outside change in the same tick as an own change,
or as the read of the mtime, leaves the mtime unchanged. It stays unseen
until the next outside change of that directory, maybe forever.

On Debian 13, eight core tests fail for this reason (each makes an own
change and an outside change right after it):
`many_renames_keep_entry_id`, `rename_conflict_copy_gets_a_clean_name`,
`rename_over_conflict_copy_moves_first_then_removes_it`,
`conflict_copies_are_shown`,
`conflict_display_name_collision_takes_next_number`,
`outside_rename_of_cached_dir_is_seen`, `second_instance_changes_are_seen`,
`two_dir_ids_are_both_used`. The container (Linux 7.0) has fine-grained
timestamps, so they pass there.

A ninth failure, `read_only_mode_file_can_be_opened_for_reading`, has
another cause: the tests ran as root, and root may open a 0o400 file for
writing. It is fixed in the test (section 5).

## 2. Goals

1. Every outside change that does not change the stored mtime is seen
   about `RACY_WINDOW` (2 s) after the last change of that directory (own
   changes less than 2 s apart postpone the check), on every file system whose
   timestamps come from the clock of this machine.
2. No measurable cost for normal work: a loop of creates in one directory
   still builds its index once (the test `create_many_files_builds_index_once`
   stays as it is); at most one extra listing per directory after a phase
   of own changes.
3. All core tests pass on file systems with coarse mtimes.

Not a goal: seeing such a change at once (that would need a listing on
every access, quadratic in a create loop). Not changed: outside edits that
never change the mtime of the parent directory (second limit of HS 3.3).

## 3. Design (approach 1: "racy" mtimes, as git does)

### 3.1 Rule

A stored mtime `M` that was read at the wall time `T` is **safe** if
`T - M >= RACY_WINDOW`. Then every later change of the directory gets an
mtime other than `M` (its tick is after `M`), so the mtime check is exact.
Otherwise `M` is **racy**: a change in the same tick may follow without a
new mtime. A mtime in the future counts as racy.

`T` is read before the `stat` that gives `M`, so `T - M` is never too big.

### 3.2 State

`Index` (`fs/dirstate.rs`) gets one field `racy: bool`, next to `mtime`.

- `SharedDir::new` and a version bump in `shared_dir` (outside change seen):
  `racy = is_racy(M, T)`.
- `refresh_mtime` after an own change: `racy |= is_racy(M, T)`. The flag is
  sticky: an outside change in the same tick as an earlier own change must
  still be found, even when later own changes came.
- `with_listing`, when it stores a listing it just built: if
  `T_build - mtime >= RACY_WINDOW` (`T_build` read before the listing),
  `racy = false`. The listing was read after the stored mtime became safe,
  so it holds every change of that tick.

### 3.3 Check

- `is_current` returns false if `racy` is set and the window has passed
  (`!is_racy(mtime, now)`).
- `shared_dir` then treats this like an outside change: version + 1,
  listing dropped, `racy` set again from the current mtime. The next use
  builds the listing again; it is stored with `racy = false`.
- While the window has not passed, a racy state is still used as before.

The version bump makes every cached state below that directory load again
(open the real directory, list it raw, read `.cd-dir`), because each reload
gives a new generation; their listings stay (their mtimes did not change).
After an own change in the vault root this is the whole cached tree (at most
the fd cache size), once per rest phase. `KeptDirs` goes through `shared_dir`, so a kept listing gets
the same check.

### 3.4 Clock

`CryptoFs::now()` gives the wall time. Unit tests can move it forward
(`#[cfg(test)]` hook `advance_clock(Duration)`), so the tests do not sleep
2 s. `RACY_WINDOW` is a constant (`Duration::from_secs(2)`, covers FAT).

## 4. Known limits (stay documented)

- An outside change in the same tick is seen up to about 2 s later, not at
  once. The FUSE adapter already keeps entries and attributes in the kernel
  for 1 s (TTL), so the drive is already not exact at that scale.
- A vault on a network file system whose server clock is behind this
  machine: a fresh mtime looks old, so it counts as safe, and the old limit
  holds. A server clock ahead only delays the extra check.
- Outside edits that do not change the parent directory's mtime (a change
  inside a long-name entry, a `chmod` of an entry) stay unseen, as before.

## 5. Tests

- New test (fails without the fix): own create, outside create in another
  instance, then the real mtime of the directory is set back to the stored
  value with `set_modified` (as `second_state_sees_own_create_coarse_mtime`
  does), so it looks like one tick on every file system. Before the window:
  the outside entry may be missing. After `advance_clock(RACY_WINDOW)`: it
  is listed and found.
- New test: the flag is sticky: own change, outside change in the same
  (simulated) tick, more own changes, then after the window the outside
  change is seen.
- New test: a directory without own changes and with an old mtime does not
  build its listing again (counter `listing::listings_built`).
- `create_many_files_builds_index_once` stays unchanged and must pass.
- The eight failing tests call `advance_clock(RACY_WINDOW)` before they
  look at the outside change. They then pass with coarse and fine mtimes.
- `read_only_mode_file_can_be_opened_for_reading`: checks the
  `NotPermitted` result only if the test does not run as root (`geteuid`).
- Checked on Debian 13 by the owner (coarse mtimes): `cargo test --workspace` passes.

## 6. Docs

- README "Limits": an outside change in the same time tick as an own change
  is seen at the latest about 2 seconds later (no longer "can stay unseen").
- HS 3.3 limit line: points to this spec.
- `docs/superpowers/plans/2026-10-31-crypto-drive-mvp-followups.md`: no
  entry needed.
- GitHub page: does not mention this limit; no change.
- CLAUDE-new.md: status, test count, note that the tests ran on Debian 13.

## 7. Decisions

| Question | Decision |
|---|---|
| Approach | 1: racy mtimes with one later check (not size / link count, not a listing on every access) |
| Window | 2 s (`RACY_WINDOW`, covers FAT) |
| Root test | skip the permission check as root, do not change the code |
