# Plan – Never drop buffered data (R1 + R2)

Spec: `docs/superpowers/specs/2026-11-08-never-drop-dirty-data-design.md`.
TDD: each task starts with a test that fails without the change.

1. **Write takes data only if it can** (`file.rs`): pre-flush in
   `OpenFile::write`; tests for a failed pre-flush (nothing changed) and the
   bound of the dirty set.
2. **Free space before every flush** (`file.rs`): `check_space` with the
   dirty chunks; test hook for the free space; test that an overwrite on a
   "full" disk fails before any chunk write and keeps the old content
   readable.
3. **Orphans** (`fs/mod.rs`, `fs/files.rs`): `orphans`,
   `keep_if_unwritten` in `release` and `truncate`, cleanup in
   `flush_idle` / `flush_all`, `unwritten_files`; tests with the chunk write
   hook.
4. **Logging** (`adapter.rs`): `core_err` at `error` for `Io` of
   write / flush / fsync / release; unit test of the level choice.
5. **Stop waits** (`mount.rs`): `wait_for_stop` with a flush step,
   `wait_for_written` after the session; unit tests with fakes.
6. **Docs**: README (Limits: full disk, unmount waits), GitHub page if
   relevant, `CLAUDE-new.md`.
7. **Checks**: fmt, clippy (+ macOS cross-check), header check, all tests.
