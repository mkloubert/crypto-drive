# Outside changes on coarse mtimes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An outside change in the same mtime tick as an own change is seen at the latest `RACY_WINDOW` (2 s) later; all core tests pass on coarse-mtime file systems.

**Architecture:** `Index` in `fs/dirstate.rs` gets a sticky `racy` flag. A mtime read less than 2 s after it was set is racy; once the window has passed, `is_current` fails and `shared_dir` bumps the version, so the listing is built once again. A test clock hook avoids sleeps.

**Tech Stack:** Rust 1.99.1, crate `crypto-drive-core`, `rustix`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-11-08-coarse-mtime-design.md`

## Global Constraints

- `RACY_WINDOW = Duration::from_secs(2)`, a `pub(crate) const` in `fs/dirstate.rs`.
- A mtime in the future counts as racy. `T` (wall time) is read **before** the `stat` that gives the mtime.
- Git is read-only for Claude (CLAUDE.md 0.2): no commits; propose a message at the end.
- All code, comments, docs in simple English; doc comments name "spec 2026-11-08 coarse mtime" or "HS 3.3".
- Every shell command starts with `export PATH="$HOME/.cargo/bin:$PATH";` and runs in `/workspace`.
- Definition of done: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `scripts/check-license-headers.sh` green.

## Review Focus

1. A busy directory (own changes all the time) must still be checked once it rests – the flag must survive `refresh_mtime` (sticky test in Task 2).
2. A create loop must not build the index more than once (`create_many_files_builds_index_once` unchanged).
3. A directory nobody changed must not be listed again after the window (no-relist test in Task 2).
4. A kept listing (`KeptDirs`) of a racy directory must get the same check – covered because it goes through `shared_dir`; the sticky test is run once more with the directory pushed out of the fd cache (Task 2, step 1, third test).
5. A mtime in the future must not panic (`duration_since` error) and counts as racy (unit test of `is_racy` in Task 2).

---

### Task 1: Root-safe read-only test

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/files.rs:938-947` (`read_only_mode_file_can_be_opened_for_reading`)

- [ ] **Step 1:** Wrap the `NotPermitted` assertion in `if !rustix::process::geteuid().is_root() { … }` with a comment "root may open a 0o444 file for writing", like `files.rs:736`.
- [ ] **Step 2:** Run `cargo test -p crypto-drive-core --lib read_only_mode_file` → PASS (container runs as uid 1000, so the check still runs here).

### Task 2: Racy mtimes (core fix, TDD)

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/dirstate.rs` (`Index`, `SharedDir::new`, `is_current`, `shared_dir`, `refresh_mtime`, new `is_racy`, `RACY_WINDOW`)
- Modify: `crates/crypto-drive-core/src/fs/listing.rs` (`with_listing`)
- Modify: `crates/crypto-drive-core/src/fs/mod.rs` (`CryptoFs` clock field, `now`, `advance_clock`; new tests)

**Interfaces:**
- Produces: `pub(crate) const RACY_WINDOW: Duration`; `fn is_racy(mtime: SystemTime, now: SystemTime) -> bool` in `dirstate.rs`; `CryptoFs::now(&self) -> SystemTime`; `#[cfg(test)] CryptoFs::advance_clock(&self, by: Duration)` (field `#[cfg(test)] clock_offset: Mutex<Duration>`).

- [ ] **Step 1: Write the failing tests** in `fs/mod.rs` `mod tests`:

```rust
/// Sets the real mtime of `dir` back to `m`: the outside change looks
/// like it landed in the same tick (coarse mtime) on every file system.
fn same_tick(dir: &std::path::Path, m: SystemTime) {
    std::fs::File::open(dir).unwrap().set_modified(m).unwrap();
}

#[test]
fn outside_change_in_the_same_tick_is_seen_after_the_window() {
    let f = fx();
    f.fs.mkdir(&p("d"), 0o755).unwrap();
    assert!(listed(&f.fs, "d").is_empty());
    let real_d = f.real("d");
    let m = std::fs::metadata(&real_d).unwrap().modified().unwrap();
    let fs2 = CryptoFs::new(open_with_master_key(&f.root, &f.mk).unwrap()).unwrap();
    let (_, h) = fs2.create(&p("d/x"), 0o644).unwrap();
    fs2.release(h).unwrap();
    same_tick(&real_d, m);
    f.fs.advance_clock(dirstate::RACY_WINDOW);
    assert_eq!(listed(&f.fs, "d"), vec!["x"]);
    assert_eq!(f.fs.getattr(&p("d/x")).unwrap().kind, FileKind::File);
}

#[test]
fn racy_mark_survives_later_own_changes() {
    // as above up to same_tick, then:
    // own create "y" through f.fs, then advance_clock(RACY_WINDOW)
    // assert_eq!(listed(&f.fs, "d"), vec!["x", "y"]);
}

#[test]
fn racy_kept_listing_is_checked_after_the_window() {
    // as `outside_change_in_the_same_tick_is_seen_after_the_window`, but
    // before advance_clock push "d" out of the fd cache the way
    // `a_kept_listing_sees_outside_changes` does (list enough other
    // directories made with `many_dirs`), so its listing lives only in
    // `KeptDirs`.
    // assert_eq!(listed(&f.fs, "d"), vec!["x"]);
}

#[test]
fn a_resting_directory_is_not_listed_again() {
    let f = fx();
    f.fs.mkdir(&p("d"), 0o755).unwrap();
    f.fs.advance_clock(dirstate::RACY_WINDOW);
    assert!(listed(&f.fs, "d").is_empty()); // settles root and d
    let built = listing::listings_built();
    f.fs.advance_clock(dirstate::RACY_WINDOW);
    for _ in 0..3 {
        assert!(listed(&f.fs, "d").is_empty());
    }
    assert_eq!(listing::listings_built(), built);
}
```

And in `fs/dirstate.rs` `mod tests`:

```rust
#[test]
fn racy_rule() {
    let now = SystemTime::now();
    assert!(is_racy(now, now));
    assert!(is_racy(now - Duration::from_millis(1999), now));
    assert!(!is_racy(now - RACY_WINDOW, now));
    assert!(is_racy(now + Duration::from_secs(60), now)); // future
}
```

- [ ] **Step 2:** Run `cargo test -p crypto-drive-core --lib racy outside_change_in_the_same_tick resting_directory` → compile errors (`advance_clock`, `RACY_WINDOW`, `is_racy` missing). After stubs (`advance_clock` only moves the offset, `is_racy` returns false): the three outside-change tests FAIL with a missing `"x"`; `racy_rule` FAILS.
- [ ] **Step 3: Implement** per spec 3.1–3.4:
  - `is_racy`: `now.duration_since(mtime).map_or(true, |age| age < RACY_WINDOW)`.
  - `CryptoFs::now()`: `SystemTime::now()` plus `clock_offset` under `#[cfg(test)]`.
  - `Index.racy: bool`. Set in `SharedDir::new(mtime, now)` (new parameter) and in the version bump of `shared_dir`; `refresh_mtime` does `racy |= is_racy(..)`; read `now` before each `stat_self` that gives the mtime (`load_child`, `root_state`, `refresh_mtime`, `is_current`) and pass it in.
  - `is_current`: also false if `index.racy && !is_racy(index.mtime, now)`.
  - `shared_dir`: bump if `index.mtime != st.mtime || (index.racy && !is_racy(index.mtime, now))`; after the bump `racy = is_racy(st.mtime, now)`.
  - `with_listing`: read `now` before `build_listing`; when the listing is stored and `!is_racy(index.mtime, now)`, set `index.racy = false`.
  - Update the doc comments of `refresh_mtime` and `Index` (the old "stays unseen" limit becomes "seen after `RACY_WINDOW`").
- [ ] **Step 4:** Run `cargo test -p crypto-drive-core --lib` → the 5 new tests PASS, plus `create_many_files_builds_index_once`, `repeated_lookups_build_the_index_once`, `second_state_sees_own_create_*`, `outside_changes_are_seen`, `a_kept_listing_sees_outside_changes` still PASS.

### Task 3: Tests that depend on fine mtimes

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/mod.rs` (`second_instance_changes_are_seen`, `outside_rename_of_cached_dir_is_seen`, `two_dir_ids_are_both_used`, `conflict_copies_are_shown`, `conflict_display_name_collision_takes_next_number`)
- Modify: `crates/crypto-drive-core/src/fs/rename.rs` (`many_renames_keep_entry_id`, `rename_conflict_copy_gets_a_clean_name`, `rename_over_conflict_copy_moves_first_then_removes_it`)

**Interfaces:**
- Consumes: `CryptoFs::advance_clock`, `dirstate::RACY_WINDOW` (Task 2).

- [ ] **Step 1:** In each test, call `f.fs.advance_clock(RACY_WINDOW)` after the last outside change (a `std::fs` write / a second `CryptoFs`) and before the first assertion or call that must see it. Check `many_renames_keep_entry_id` first: its failure is a `check` finding `ConflictCopy` on a real name `… (1)`; find out with the test whether that comes from an outside change made in the test (then the clock call fixes it) or from the code (then stop and report to the owner, do not guess).
- [ ] **Step 2: Prove the change is needed** (coarse mtime is not available in the container): temporarily wrap `stat_self` in `backing.rs` so that `mtime` is truncated to 100 ms ticks; run `cargo test -p crypto-drive-core --lib` → without step 1 the eight tests fail, with step 1 all pass. Remove the wrapper afterwards and confirm `git diff crates/crypto-drive-core/src/backing.rs` is empty.
- [ ] **Step 3:** Run `cargo test --workspace` → all pass (expected 553 passed = 548 + 5 new, 10 ignored).

### Task 4: Docs and wrap-up

**Files:**
- Modify: `README.md:419-424` (Limits)
- Modify: `docs/superpowers/specs/2026-11-08-coarse-mtime-design.md` (status line)
- Create/Modify: `/workspace/CLAUDE-new.md` (full content per CLAUDE.md 0.1)

- [ ] **Step 1:** README: replace "A change in the same time tick as your own change (FAT: 2 seconds) can stay unseen until the directory changes again." with "A change in the same time tick as your own change (Linux before 6.13: a few milliseconds, FAT: 2 seconds) is seen at the latest about 2 seconds later." Keep the second sentence about edits without a parent mtime change.
- [ ] **Step 2:** Spec status: "Implemented 2026-11-08, Linux container only; Debian 13 run by the owner pending".
- [ ] **Step 3:** CLAUDE-new.md: section 7 test count, section 8 Linux note (Debian 13: `cargo test --workspace` ran, 6.12 has 4 ms mtime ticks; mount tests still pending), section 11 status entry, "Last change" line.
- [ ] **Step 4:** Run the definition-of-done checks (Global Constraints) and show the output.
- [ ] **Step 5:** Propose the commit message to the owner:

```
fix(fs): see outside changes in the same mtime tick

Linux before 6.13 and FAT set directory mtimes in coarse ticks (4 ms on
Debian 13 ARM64). An outside change in the same tick as an own change
stayed unseen until the next outside change. A mtime younger than 2 s
is now marked racy and the directory is listed once more after that
window. Eight core tests failed on Debian 13 for this reason; one more
failed only as root.
```
