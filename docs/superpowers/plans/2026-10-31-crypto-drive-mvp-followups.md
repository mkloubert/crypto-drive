# crypto-drive MVP – follow-ups

Small findings from the task and final reviews that were deferred (not blocking the MVP). Grouped by the task that found them. Items that the format hardening plan (docs/superpowers/plans/2026-10-31-format-hardening.md) solved were removed: the known-answer tests of the key derivation and the wire format now exist (`crates/crypto-drive-core/tests/kat.rs`). Its own open findings are in the last section.

## Before the first release

- Done 2026-10-31 on macOS 26.6.2 with macFUSE 5.5.0 (kernel extension): all tests incl. the 3 real-mount tests and `scripts/smoke-test.sh` pass.
- Still to run on a Linux machine with /dev/fuse: the 3 real-mount tests and `scripts/smoke-test.sh`.
- macOS: libfuse prints "fuse: forking a threaded process is unsafe" because it forks its mount helper after threads exist (rayon from Argon2, test threads). Consider mounting before any thread starts, or a fork-free mount (macFUSE MFMount.framework).
- Extended attributes are kept in memory only (2026-11-01). History: `ENOTSUP` made Finder fail with `-8062` and `cp` leave 0-byte files (copy tools abort on any xattr error); dropping them still failed in Finder, because Finder reads its own `com.apple.finder.copy.source` back. The final cause of -8062 was the `noappledouble` mount option: the kernel refused the source's `.DS_Store` (Finder log: "Error -8062 at path: …/.DS_Store on write"), so the option was removed. Check after a Finder copy that no `._*` files appear. Possible later: store them encrypted (a control file per entry was the preferred design: cheap "no xattrs" check, atomic updates, no download of cloud placeholder files). This keeps the quarantine flag, Finder tags and custom icons. Run the real-mount tests `copy_tools_ignore_extended_attributes` and `extended_attributes_read_back_while_mounted` on macOS 14+ and on Linux.
- macOS FSKit backend: `fuse_mount()` with `-o backend=fskit` gives ENOTSUP via libfuse 2; needs libfuse 3 or MFMount.framework.
- Incomplete-directory cleanup uses the directory mtime (older than 60 s). Sync clients that copy remote mtimes (e.g. Syncthing) can defeat this; consider ctime.

## Deferred minor findings

- **Task 1:** header script `-name target -prune` prunes any dir named target; `! -name Cargo.lock` dead code
- **Task 1:** deny.toml has no explicit [bans]/[sources]
- **Task 2:** expand() only debug_assert; add const assert N <= 255*64
- **Task 2:** SecretBytes::new leaves param copy unwiped; Io error displays message twice with #[from]; getrandom error mapping; no test for redacting Debug
- **Task 3:** recovery.rs:32 unwrap_or_else(unreachable!) + Specification rebuilt per call (use LazyLock); :62 unwrap_or_default on from_utf8 silent fallback
- **Task 3:** format test uses own SYMBOLS const; tests missing invalid symbol / trailing bits / exact variant on wrong length
- **Task 4:** slot_count u16 wrap on 65535 slots; unbounded number of password slots tried; small stack copies of secrets; concurrent saves removing each other's tmp
- **Task 5:** NameCipher Mutex serializes all name ops (perf, consider per-call cipher/pool); key hand-wipe via fill(0) may be elided, use zeroize; encrypt failure mapped to InvalidArgument without comment
- **Task 6:** b64 run length via chars().count relies on ASCII-only is_b64_char; no display-name test for "a." / ".a.b"
- **Task 7:** open uses what "chunk size" (not in ruled list, drops index); ciphertext_size/chunk_offset saturate silently; seal does ~3 copies per chunk (perf); FileHeader lacks Clone/Debug; u64::MAX test asserts nothing
- **Task 8:** stale <name>.tmp reused with O_TRUNC (keeps old mode / hard link); read_to_end errors bypass map_errno; st_dev sign-extension on macOS (consistent per process); missing symlink/pre-epoch/tmp-cleanup tests; statvfs test tacked on lock test
- **Task 9:** vault.rs:63 unreachable! in non-test code; testutil expect (feature-gated, ok); symlink-to-dir vault path untested; swallowed cleanup errors without comment; duplicated name-length bounds check
- **Task 10:** broad invalidation of descendants on any change (perf); conflict display name may exceed 1024 B and be unreachable; VPath length checked before NFC; VPath Debug prints clear names (doc + never log outside --debug); with_listing closure re-entrancy hazard (document); two_dir_ids test weak on .cd-dir.tmp exclusion; symlinked .cd-dir gives Io(ELOOP) not InvalidFormat
- **Task 10:** stale comment fs/dirs.rs:131 about control-file cleanup; per-entry EIO now shows as NotFound
- **Task 11:** stale bytes after shrink whose flush failed then grow (zero_from watermark); EROFS not treated like EACCES for RDONLY fallback; partial apply of a failing multi-chunk write; release drops dirty data on flush error (T16: FUSE flush callback must surface flush errors); tests missing for shrink to chunk boundary, 65536→65537 grow, create rollback, mid-file is_last chunk
- **Task 12:** rmdir exact names .cd-dir/.cd-dir.tmp/.cd-name allowed without kind check (dir/symlink with that name → half-stripped + IsADirectory); tests missing for wrong-size/non-regular .cd-dir*, LongDir with foreign file, leftover .cd-dir.tmp; scan-then-delete race comment
- **Task 13:** from==to on missing path returns Ok (POSIX ENOENT); invalidate(root) clears whole cache; undo/partial-failure paths untested
- **Task 14:** check_vault aborts on first I/O error (EACCES/EIO) without path — fails closed (exit 2) but loses findings; consider Unreadable finding or path in error
- **Task 14:** non-UTF-8 foreign names not reported by check; tamper flips of .cd-vault/.cd-key accept union of errors per offset; full-chunk tag never flipped; model mirrors non-POSIX rename (from==to missing → Ok; to-under-from before existence); model doesn't compare getattr size; small comment errors
- **Task 15:** env-var secret stays in environ; read_to_string realloc not zeroized; non-UTF-8 password unclear message; tests missing for max-name-length bounds, below-default warning on passwd/recover, invalid/foreign recovery key
- **Task 16:** readdir paging trait path untested; statfs test checks core not adapter; O_TRUNC in open redundant on Linux (comment); chunk AuthFailed `what` lacks file name (core)
- **Task 16:** fchmod/futimens after unlink still ENOENT (by path); unknown handle maps to InvalidArgument (no EBADF variant)
- **Task 16:** open(O_RDONLY|O_TRUNC) now EPERM via truncate_handle; double listing on opendir+readdir(0); stale opendir doc comment; out-of-scope: do_open/getattr/setattr path fallbacks and chmod/utimens not under rename_lock (O_TRUNC/chmod could hit a file newly created at old path during a rename)
- **Task 17:** signal mask not restored on spawn_mount error; leaked sigwait thread; macOS umount of /var/folders symlinked mountpoint in ignored tests may need canonical path
- **Task 18:** status pipe fds not CLOEXEC (helper could inherit write end → parent hang); --password-fd colliding with pipe fd numbers (check fd open before pipe()); mlock warning lost in daemon mode (send to parent before ok); CRYPTO_DRIVE_PASSWORD stays in daemon environ (remove_var in child before threads)
- **Task 18:** errors after detach go to /dev/null (comment misleading; document); unmount CLI test weak
- **Task 19:** post-remount check doesn't re-verify renamed dir/rsync copy; relative CRYPTO_DRIVE_BIN resolved after cd; read bench depends on write bench; format.md omits non-normative notes
- **Final:** no test for future mtime; README line on incomplete entries slightly inaccurate (incomplete short dirs are listed); mlock sampled once at ready.

## Deferred minor findings of the format hardening plan

Found by the task and final reviews of the format hardening plan and not fixed in its final fix wave.

### Recover and key rotation

- `recover` counts any epoch other than the marker epoch in a file header, and any encrypted-looking name that does not decrypt, as an unfinished rotation. Leftover entries of a removed epoch (another device wrote during an earlier rotation; `check` reports `unknown-key-epoch`) or a foreign file with a long Base64-like name therefore make `recover` ask for a new key that cannot be shown to be right. Way out today: remove those entries first.
- **Known gap (repair tool):** a `.cd-cdl` entry whose real name is not the hash of its `.cd-name` (a crash between the rename and the `.cd-name` write of a long-to-long move, in a mount rename or in the rotation) is hidden by the listing and blocks every later rotation. After such a crash in the first step of a rotation, `recover` with only the old key cannot see the rotation and writes `{e}`; nothing is lost, but the entry stays hidden. Needs a repair command that re-hashes the entry (with the new key, if any) and a hint in `check`.
- `print_recovery_key` and the `rotate-key` `on_key` callback still use `eprintln!` for the note on stderr; a closed stderr panics after the key was already written.
- `is_rotation_conflict_of` may match a shortened conflict name of another long clear name with the same prefix (only when a rotation is resumed).
- A crash inside the move of a long rotation conflict copy can leave a name-only orphan of the new epoch (`check` reports it as an incomplete long entry; no data is lost).
- The vault lock has a short window when the marker file is replaced (harmless). `set_password` drops extra password slots (not reachable yet).
- The conflict copy lookup of a rotation decrypts many candidates (slow, but rare).
- No test for a stop right at the marker step together with new Argon2 flags; no test for missing or partial `rotate-key` Argon2 flags; no CLI test for the TTY prompt or for a resumed run. The Argon2 flags are parsed before the warning is printed.
- Directory mtimes change during a rotation and long entries get `LONG_ENTRY_MODE`; this is documented only briefly.

### Keys, key file and marker

- `KeySet` encode test has no literal byte check (the KAT covers it); `with_next` overflow is not tested.
- `bad_payload_len` only tests the length 94; `set_password` with a two-epoch key set is not tested on its own.
- `MasterKey::from_bytes(*mk.expose())` makes stack copies of keys that are not wiped (several places).
- `unlock` returns at the first slot that authenticates, even if its key set is not valid.
- `passwd` loads the key file twice (use load, unlock and `open_with_key_set`).
- No test for a changed epoch field without a new tag; stale "base" doc in a test helper; import grouping in `recovery.rs`; test fixtures hard-code `keys.get(1)`.

### Content and padding

- The sizes test lost the asserts at the 65536 boundary; the `open_size` buffer is not wiped; a short size block gives `InvalidFormat` but the test checks only `is_err`; `file.rs` doc cites "spec 4.7".
- No test for a shrink inside one padding stage; `write_padding` allocates even when there is nothing to write; the size key is derived twice; a padded `getattr` can race with a flush; `chunk_mut` with `or_default` reads oddly.

### Names, binding and index

- Which duplicate `find()` returns is not fixed (document it with the crash note of base spec §5.5).
- No test for the live-state binding through a hard link; no cross-epoch rename test of its own (the rotation tests cover it).
- `with_change` and index helpers repeat code in `dirs.rs` and `files.rs`; `index_remove` keeps the old conflict numbers; `index_insert` returns a `Result` that never fails.
- The coarse-mtime test passes through the version bump (add a comment); `invalidate()` clears the shared listing of a directory that was only moved (slow).

### Check

- An unreachable unknown-epoch branch in `check_content` (the epoch is read twice); a tampered padded header is reported as `InvalidPadding` (add a comment).
- Tests missing for a long entry with `EntryIdMismatch`, an epoch-2 file in a two-epoch vault, a padded file of an unknown epoch, and CLI exit codes of the new finding kinds.

### Format vectors and tamper tests

- Running the golden generator and the readers at the same time with `CRYPTO_DRIVE_WRITE_GOLDEN=1` can race (`--test-threads=1` avoids it; the doc command in `golden.rs` runs them in parallel).
- The golden padded check asserts only `len == stage(len)`, not `stage(L)`; the KAT size block tamper test checks only `is_err`.
- `header_epoch_changed` and `directories_swapped` accept any error, not the exact variant; small style issues in the imports of `tamper.rs`.

### Fuzzing

- `vault_marker`: assert that a marker that verifies also parses; `names` uses a magic number 300; `seeds.sh` should fail loudly when the KAT extraction is empty.
- The core does not retry `EINTR` on rustix calls (no call hit it so far; signals are blocked in FUSE threads). `fs_ops` can report a false mismatch on such an `EINTR`.
- `hostile_tree` is weak on conflict suffixes on encrypted names and on a damaged `.cd-name`; template temp dirs are not removed; a replay is not deterministic (a new random vault per process).

### Docs

- README: the note that the recovery key is printed "even if it fails later" could be more exact.
- The smoke test helper drops stderr on success.
