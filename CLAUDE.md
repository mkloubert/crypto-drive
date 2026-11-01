# CLAUDE.md – crypto-drive

Guide for Claude Code sessions in this repository. Read it fully at the start
of every session. Last full project scan: 2026-11-01 (branch `main`,
commit `34a0dee`, plus the open-file limit work).

## 0. Rules for Claude (always)

### 0.1 This file is read-only – use `CLAUDE-new.md`

- `/workspace/CLAUDE.md` is not writable for Claude. Never try to edit it.
- When this guide needs an update, write the **complete new content** (not a
  diff, not only the changed part) to `/workspace/CLAUDE-new.md`. The owner
  copies it over `CLAUDE.md` by hand.
- Start from the current `CLAUDE.md` (or from an existing `CLAUDE-new.md`, if
  it is newer and not yet copied) so no content gets lost.
- After every write to `CLAUDE-new.md`, tell the user in the chat:
  "CLAUDE-new.md was updated: <short list of changes>. Please copy it to
  CLAUDE.md."
- Update it when it makes sense: a new crate, module, command, script,
  format change, new convention, changed test commands, a finished or new
  open item, or a rule the owner states. Do not update it for small code
  changes that the code itself documents.
- Keep the "last full project scan" line and section 11 (status) current.
- `CLAUDE-new.md` is in `.gitignore`.

### 0.2 Git: read-only

- Never run a git command that writes: no `commit`, `add`, `rm`, `mv`,
  `restore`, `reset`, `checkout`/`switch`, `branch -d/-m`, `merge`, `rebase`,
  `cherry-pick`, `revert`, `stash`, `tag`, `push`, `pull`, `fetch`, `clean`,
  `config` writes, `gc`, `worktree add`, and no `git apply` to the index.
  Also no skill or tool that does this for you (commit skills, PR skills,
  worktree skills).
- Allowed: `status`, `log`, `show`, `diff`, `blame`, `branch` (list),
  `ls-files`, `rev-parse`, `grep`, `shortlog`, `describe`, `cat-file`.
- When work is ready to commit, say so and propose a commit message (style
  in section 6.6). The owner commits.
- The working tree may be changed with normal file edits (this is not a git
  operation).

### 0.3 Paths and environment

- The project is always at `/workspace`. The `.git` folder is at the root of
  the project (`/workspace/.git`).
- `/workspace` is owned by root and the shell runs as uid 1000 (`node`), so
  git reports "dubious ownership". Run git as
  `git -c safe.directory=/workspace <read-only command>`. Never change the
  git config to fix it.
- The Rust tools are in `~/.cargo/bin`, which is not on the `PATH` of
  non-interactive shells. Prefix commands with
  `export PATH="$HOME/.cargo/bin:$PATH";` (installed: rustup, cargo, clippy,
  rustfmt, cargo-deny, cargo-fuzz, rust-analyzer).
- The container is Linux ARM64 without root and without `/dev/fuse`: real
  mounts are impossible here. Mount tests and the smoke test run on the
  owner's Mac (macFUSE) or a Linux machine with FUSE.
- Use the session scratchpad for temporary files, never the repository.

### 0.4 Language and communication

- Chat with the owner in **German**.
- Everything in the repository is in **simple English**: code, identifiers,
  comments, CLI messages, docs, specs, plans, commit messages. No German.
- When the owner must run something (for example on the Mac), give **one
  command per code block**. They copy text literally.
- Do not guess. Diagnose from logs, test output or the code first (macOS:
  Finder / unified log). The owner objects to guesses.
- Report test results honestly. Say which platform a fix was tested on
  (Linux container only, or verified by the owner on the Mac).

## 1. What the project is

`crypto-drive` is a Rust CLI that shows a normal directory (the **vault**)
as a readable and writable drive through FUSE. In the vault, file contents
and all names are encrypted. The vault is safe to put in a cloud sync folder
(Dropbox, Nextcloud, Syncthing, iCloud, …).

- Author and copyright: Marcel Joachim Kloubert. License: AGPL-3.0-or-later.
- Later public repository: <https://github.com/mkloubert/crypto-drive>
  (no git remote is set yet).
- Platforms: macOS (macFUSE, main target of the MVP) and Linux (fuse3).
  Windows (WinFsp) is a later feature.
- Only symmetric crypto with 256-bit keys (post-quantum by design):
  AES-256-GCM (content, 64 KiB chunks), AES-256-SIV (names), HKDF-SHA-512,
  HMAC-SHA-256, Argon2id (password).
- Control files never change after creation (sync safe). Sync conflict copies
  are shown in the drive as `<name> (conflict N)<.ext>`.

User docs: `README.md`. Normative format: `docs/format.md`.

## 2. Repository layout

```
/workspace
├── Cargo.toml              workspace: members crates/*, fuzz excluded, resolver 3,
│                           edition 2024, rust-version 1.99, all dependency versions
├── Cargo.lock              committed, pins exact versions
├── rust-toolchain.toml     stable 1.99.1 + rustfmt + clippy
├── deny.toml               cargo-deny: advisories + allowed licenses
├── LICENSE                 AGPL-3.0
├── README.md               install, usage, threat model, limits, tests, fuzzing
├── CLAUDE.md               this guide (read-only for Claude, see 0.1)
├── crates/
│   ├── crypto-drive-core/  library: format, crypto, file system logic (no FUSE)
│   ├── crypto-drive-fuse/  fuser adapter, mount/unmount (macOS + Linux)
│   └── crypto-drive/       binary: CLI, password input, daemon, hardening
├── docs/
│   ├── format.md           normative on-disk format v1 (RFC 2119 words)
│   └── superpowers/
│       ├── specs/          design specs (base MVP spec, format hardening spec)
│       └── plans/          implementation plans + follow-ups list
├── fuzz/                   cargo-fuzz crate, own workspace, pinned nightly
├── scripts/
│   ├── check-license-headers.sh
│   ├── set-version.sh      sets the crate version (release workflow, from the tag)
│   ├── smoke-test.sh       real-mount end-to-end test (needs FUSE + release build)
│   ├── fuzz.sh             runs fuzz targets
│   ├── kat/gen_vectors.py  independent Python implementation for test vectors
│   └── diag/               macOS FUSE probes (C) – diagnostics only
├── site/                   GitHub Pages project site (see section 10)
└── .github/workflows/      pages.yml (GitHub Pages), release.yml (binaries on tag vX.Y.Z)
```

Not in git (`.gitignore`): `/target`, `.env`, `/c.sh` (local copy timing
helper), `/CLAUDE-new.md`. `.superpowers/` holds local skill state and ignores
itself. `fuzz/` has its own `.gitignore` (only `seed-*` corpus files are
committed).

## 3. Architecture

Dependency direction: `crypto-drive` (CLI) → `crypto-drive-fuse` →
`crypto-drive-core`. The core never depends on FUSE and is fully testable
without a mount.

### 3.1 `crypto-drive-core`

| Module | Role |
|---|---|
| `backing` | The only place with syscalls on the real (encrypted) directory. Directory handles (`openat`, `renameat`, `unlinkat`, `mkdirat`) via `rustix`, so `PATH_MAX` does not apply. The part to port for Windows. |
| `vault` | `.cd-vault` marker, `init_vault`, `unlock_vault`, `open_with_master_key`, mount lock. |
| `keyfile` | `.cd-key` format, password slots, Argon2 limits (`Argon2Params::MIN` for tests). |
| `keys` | Key hierarchy: `MasterKey`, `KeySet` (1 or 2 epochs), HKDF sub keys, per-file keys, `DirId`. |
| `names` | AES-256-SIV names with entry id, NFC, overflow names `.cd-cdl<hash>`, `NameKeys::decrypt_any`. |
| `content` | File header, chunks, size block, padding stages (`stage`). |
| `file` | Random access to one encrypted file: LRU chunk cache, dirty buffer (64 chunks), grow/shrink, padded flush order. |
| `fs/` | `CryptoFs`, the path-based file system (the directory cache size follows the soft `RLIMIT_NOFILE`: a quarter of it, 16 to 1024, because every cached directory holds an fd): `mod.rs` (struct, caches, handles), `path.rs` (`VPath`), `dirstate.rs` (dir handle, ids, name index), `listing.rs` (readdir + conflict copies), `dirs.rs`, `files.rs`, `rename.rs`. |
| `conflict` | Detection of sync conflict suffixes. |
| `check` | Read-only check of a whole vault; walks the real tree without the caches. |
| `rotate` | Offline, resumable master key rotation. |
| `recovery` | Recovery key (Crockford Base32, 55 chars, checksum). |
| `secret` | `SecretBytes<N>`: heap, zeroized on drop, best-effort `mlock`. `random_bytes`. |
| `error` | One `Error` enum (thiserror) + `Result<T>`. Display texts are tested exactly. |
| `testutil` | Feature `test-util`: `test_vault*()`, `real_name_of()`, `TEST_PASSWORD`. |

Key runtime structures in `CryptoFs`: an LRU cache clear path → `DirState`
(dropped when the real directory mtime changes), shared dir states, one
shared `Arc<Mutex<OpenFile>>` per real file for all handles, handle table.

### 3.2 `crypto-drive-fuse`

| Module | Role |
|---|---|
| `adapter` | `FuseFs`: `fuser::Filesystem` on top of `CryptoFs`. `do_*` methods hold the logic. A `rename_lock: RwLock<()>`: rename takes the write side; open and setattr take the read side from lookup to the end. Open flags: Linux `FOPEN_KEEP_CACHE` for unchanged files, macOS `FOPEN_PURGE_UBC | FOPEN_PURGE_ATTR`. TTL 1 s. |
| `inodes` | `InodeTable`: inode ↔ clear path, lookup counts, `forget`, rename of subtrees by range (sorted map). |
| `xattrs` | In-memory xattrs per clear path (never on disk). 1 MiB per entry, 64 MiB total; values over the limit are accepted but dropped. Linux keeps only `user.*`. |
| `errno` | `to_errno`: core error → errno (spec section 8 table). |
| `mount` | `MountRequest`, `mount_and_wait`, `mount_options`, `unmount_command`, `StopReason`. A stop signal tries a normal unmount (`Running::try_unmount`: macOS `unmount(2)`, Linux `fusermount3 -u` without `-z`); if busy, `wait_for_stop` writes the buffers, logs a warning and keeps the drive mounted until the next signal or an outside unmount. |
| `macos_mount` | macOS only: mounts through libfuse 2 `fuse_mount()` (fuser's own `fuse_mount_compat25` fails with macFUSE 5.5). `build.rs` adds `/usr/local/lib` or `FUSE_LIB_DIR` to the link path. |

fuser features: macOS `macos-no-mount` + `macfuse-4-compat`; Linux default
(talks to the kernel directly, `fusermount3` mounts). Mount options: always
`default_permissions`, `fsname=crypto-drive`; macOS `volname=<vault name>`.
**Never add `noappledouble`** (Finder copies fail with -8062).

### 3.3 `crypto-drive` (CLI)

- `main.rs`: clap derive, `Command` enum, `CliError` (Core / Usage / Io),
  exit codes (0 ok, 1 warnings from `check`, 2 errors), `init_logger`
  (`--debug` or `RUST_LOG`; warns that debug logs show clear names).
- `hardening.rs`: `RLIMIT_CORE = 0`, Linux `PR_SET_DUMPABLE 0`, macOS
  `PT_DENY_ATTACH`. Called first in `main`.
- `limits.rs`: raises the soft `RLIMIT_NOFILE` to the hard limit (macOS: at
  most `OPEN_MAX` 10240). Called in `main` after the logger; a failure is
  only logged at debug level (the core adapts its cache).
- `password.rs`: password / recovery key input from fd, env var (with
  warning) or TTY (`rpassword`).
- `keypath.rs`: default key file path
  `~/.crypto-drive/keys/<YYYYMMDDhhmmsszzz>_<VAULT_NAME>.cd-key`.
- `cmd/*.rs`: one file per subcommand: `init`, `mount` (incl. `--daemon`:
  fork before any thread, status pipe, `setsid`, stdio to `/dev/null`;
  SIGINT/SIGTERM/SIGHUP unmount cleanly, a busy drive stays mounted; a dead
  mount point (ENOTCONN / ENXIO) gets an `unmount --force` hint), `unmount`, `passwd`, `rotate-key`,
  `recovery-key`, `recover`, `check`.

Environment variables: `CRYPTO_DRIVE_PASSWORD`, `CRYPTO_DRIVE_NEW_PASSWORD`,
`RUST_LOG`; tests/scripts: `CRYPTO_DRIVE_BIN`, `CRYPTO_DRIVE_TEST_MOUNT_OPTS`,
`CRYPTO_DRIVE_WRITE_GOLDEN`, `SMOKE_BIG_MB`, `SMOKE_MOUNT_OPTS`,
`FUZZ_SANITIZER`, `FUSE_LIB_DIR` (build).

## 4. On-disk format essentials (v1)

Full rules: `docs/format.md`. Summary for orientation:

- Vault root: `.cd-vault` (66 B marker, changes only at the end of a key
  rotation), maybe a legacy `.cd-key`, encrypted entries.
- Each directory has `.cd-dir` (16 random bytes, never changes). The root's
  dir id is the `vault_id`.
- Names: `B64url(AES-256-SIV(K_names[e], AD=[parent_dir_id], entry_id || NFC(name)))`.
  Names longer than `max_name_length` (default 220) become a directory
  `.cd-cdl<B64(SHA-256(name))>` with `.cd-name` and `.cd-content` / `.cd-dir`.
- File: header (53 B: version, epoch, file_nonce, file_id; padded +36 B size
  block = 89 B), then chunks of 64 KiB clear data:
  `nonce(12) || AES-GCM(K_file, AD = index (u64 BE) || is_last) || tag(16)`.
- The entry id binds content / `.cd-dir` to the name (swap detection).
- Key epochs: the key set has 1 key, or 2 during a rotation. Writers use the
  highest epoch.
- All control files start with `.cd-`. Other dot files are foreign: hidden
  in the drive, reported by `check`.

### 4.1 Format invariants – never break them

- **Golden vaults** in `crates/crypto-drive-core/tests/golden/v1/{plain,padded}`
  freeze format v1. Never regenerate them. Every version must read them.
- **KAT vectors** (`tests/kat.rs`) must keep matching
  `scripts/kat/gen_vectors.py`. A change to a formula needs both sides and a
  format version discussion with the owner.
- Any format change needs: an owner decision, a spec, `docs/format.md`
  update, new KATs and golden handling. Do not do it on the side.
- Unauthenticated plaintext never leaves the core, not even in parts.
- Control files and key files are written atomically: temp file, `fsync`,
  `rename`, `fsync` of the directory.
- New random nonce for every chunk write. All random values from the OS
  (`getrandom`).

## 5. Security rules for code

- Keys and passwords live in `SecretBytes`, `Zeroizing` or `SecretBox`.
  Wipe temporary copies (`zeroize`). No `Debug` output of secrets (custom
  `Debug` that prints `..`).
- Compare tags and secrets in constant time (`subtle`).
- Logs must not contain clear names unless the level is `debug`. Errors
  name the **real (encrypted)** path (`AuthFailed { what }`).
- Every `unsafe` block has a `// SAFETY:` comment. `unsafe` is limited to
  FFI and syscalls (`mlock`, `ptrace`, `fork`, `fuse_mount`, `from_raw_fd`).
- The core never panics on hostile vault data. Return `InvalidFormat` /
  `AuthFailed`. The fuzz targets check this.
- Fail closed: if in doubt, return an error, never possibly wrong plaintext.
- The owner rejected weakening integrity for speed or space (for example
  sparse holes). Ask before any trade-off of this kind.

## 6. Code conventions and patterns

### 6.1 License header

Every own `.rs`, `.c`, `.sh`, `.py`, `.toml` file starts with the 15-line
AGPL header (`//` in Rust and C, `#` elsewhere; in shell scripts after the
`#!/usr/bin/env bash` line). Copy it from an existing file of the same kind.
Check: `scripts/check-license-headers.sh`.

### 6.2 Rust style

- Edition 2024, rustfmt defaults, `cargo clippy --all-targets -- -D warnings`
  must be clean. Narrow `#[allow(...)]` only with a reason.
- Every module starts with a `//!` doc comment that names the spec section
  it implements (for example "spec 5.4", "hardening spec 5", "HS 9").
- Doc comments on public items, in plain English. Comments explain *why*,
  and mention platform differences (macOS vs Linux).
- Errors: core uses `crate::Error` / `crate::Result`; new error variants
  need an errno mapping in `crypto-drive-fuse/src/errno.rs` and an exact
  Display test. The CLI wraps them in `CliError`.
- Dependencies: add the version only in the root `[workspace.dependencies]`
  and use `{ workspace = true }` in the crate. Stable crates, licenses
  allowed by `deny.toml`. Some are pinned with `=` (`rustix`, `log`, `lru`)
  on purpose.
- Constants instead of magic numbers; names like `NAME_FILE`,
  `LONG_PREFIX`, `DEFAULT_MAX_NAME_LENGTH`.
- Locks: `std::sync::Mutex` / `RwLock`, `.expect("<name> poisoned")`.
- Platform code with `#[cfg(target_os = "macos")]` /
  `#[cfg(target_os = "linux")]`.
- The CLI writes the recovery key to stdout, notes and progress to stderr,
  and must not panic on a closed stdout.

### 6.3 Tests

- Unit tests in `#[cfg(test)] mod tests` at the end of each file.
- Integration tests in `crates/*/tests/`. Use `crypto-drive-core` with
  feature `test-util` (`test_vault()`, `test_vault_padded()`, `real_name_of`).
- Tests use the lowest Argon2 values (`Argon2Params::MIN`;
  CLI: `--argon2-memory 19456 --argon2-iterations 2 --argon2-parallelism 1`)
  and passwords through `--password-fd`.
- Core test files: `golden.rs` (frozen vaults), `kat.rs` (known answers),
  `tamper.rs` (every change gives an error), `model.rs` (proptest against an
  in-memory model, also after reopen), `rotate.rs` (crash after every write
  step), `fd_limit.rs` (lowers the process open-file limit, so it must stay
  the only test in its binary). CLI: `crates/crypto-drive/tests/cli.rs`. Mount: 
  `crates/crypto-drive-fuse/tests/mount.rs` (`#[ignore = "needs FUSE"]`;
  checks behind the kernel through the shared `CryptoFs` in `Mounted::fs`).
- A bug fix gets a test that fails without the fix (TDD is the usual way of
  work in this project).
- CLI tests feed stdin through `write_input()` in `tests/cli.rs`, which
  accepts a broken pipe (a command that fails early does not read its
  input). Fast CI runners hit this race; never `unwrap()` a stdin write.
- CI (GitHub runners) is faster than the container: timing races show up
  there first. Run a suspect test in a loop locally before saying it is fine.
- Fuzz targets in `fuzz/fuzz_targets/` (see README "Fuzzing"). A new parser
  gets a fuzz target and seeds in `fuzz/seeds.sh`.

### 6.4 Docs to keep in sync

| Change | Update |
|---|---|
| CLI flag, behavior, limit | `README.md` (and spec section 7 when it is a design decision) |
| On-disk format | `docs/format.md` + spec + KAT + owner decision |
| Threat model / known gap | `README.md` "Threat model" / "Limits", `docs/format.md` |
| Deferred finding | `docs/superpowers/plans/2026-10-31-crypto-drive-mvp-followups.md` |
| Structure, commands, conventions, status | `CLAUDE-new.md` (see 0.1) |
| Anything a visitor of the project page cares about (see below) | `site/index.html` (GitHub page, section 10) |

GitHub page rule: after every change, ask "does a visitor of
<https://mkloubert.github.io/crypto-drive/> need to know this?" If yes,
update `site/index.html` in the same piece of work and say so to the owner.
Relevant: new or removed commands and flags, install steps, supported
systems and release downloads, threat model and limits, status (pre-release,
audit), big user-visible features. Not relevant: internal refactors, tests,
CI internals, small fixes. If unsure, ask the owner.

### 6.5 Workflow

- Bigger work follows the superpowers flow: brainstorm → spec in
  `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` → plan in
  `docs/superpowers/plans/YYYY-MM-DD-<topic>.md` → TDD implementation →
  review. Specs record owner decisions in a "Decisions" table.
- Reviews may be written to an untracked `REPORT.md` at the root.
- Before saying "done", run the checks of section 7 and show the result.

### 6.6 Commit messages (for proposals only, see 0.2)

Conventional commits in simple English, imperative, lower case:
`<type>(<scope>): <summary>`. Types: `feat`, `fix`, `perf`, `test`,
`docs`, `chore`. Scopes in use: `core`, `fuse`, `cli`, `fs`, `macos`,
`rotate`, `recover`, `check`, `fuzz`, `smoke-test`, `readme`. The body
explains why, with measured numbers for `perf`. Author:
`Marcel Joachim Kloubert <marcel@kloubert.dev>`.

## 7. Commands

Always first: `export PATH="$HOME/.cargo/bin:$PATH"`

| Purpose | Command |
|---|---|
| Build | `cargo build --workspace` / `cargo build --release` |
| All tests (no mount) | `cargo test --workspace` |
| One crate / test | `cargo test -p crypto-drive-core --test tamper` |
| Format check | `cargo fmt --all -- --check` |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| macOS cross-check (no link) | `cargo clippy --workspace --target aarch64-apple-darwin -- -D warnings` and `cargo clippy -p crypto-drive-fuse -p crypto-drive --tests --target aarch64-apple-darwin -- -D warnings` (`--all-targets` fails: criterion's `alloca` needs a mac C compiler) |
| Licenses / advisories | `cargo deny check` (advisories need network) |
| License headers | `scripts/check-license-headers.sh` |
| Benchmarks | `cargo bench -p crypto-drive-core --bench throughput` |
| Mount tests (FUSE host only) | `cargo test -p crypto-drive-fuse --test mount -- --include-ignored` |
| Smoke test (FUSE host only) | `cargo build --release && scripts/smoke-test.sh` |
| Fuzzing | `fuzz/seeds.sh` then `scripts/fuzz.sh all 300` (nightly-2026-10-15, cargo-fuzz 0.13.2) |
| KAT cross-check | `python -I scripts/kat/gen_vectors.py` (needs `cryptography` 44) |

Definition of done for code changes: fmt, clippy, all workspace tests and
the header check are green in the container; after changes to
`#[cfg(target_os = "macos")]` code also the macOS cross-check. If FUSE code changed, ask the
owner to run the mount tests and the smoke test on the Mac (one command per
block).

State at the last scan (2026-11-01): fmt clean, clippy clean, header check
clean, `cargo test --workspace`: 499 passed, 0 failed, 10 ignored (9 mount
tests + the golden generator).

## 8. Platform notes

- **macOS**: macFUSE 5.5 with the kernel extension (Apple Silicon needs
  "Reduced Security" + allowing the kext; load with
  `sudo kmutil load -p /Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext`).
  FSKit backend (`-o backend=fskit`) does not work with libfuse 2 yet.
  Finder writes `.DS_Store` into the drive (stored encrypted) and reads its
  own xattr copy markers back.
- **Linux**: needs `fuse3` (`fusermount3`), no libfuse at build time.
  Real-mount tests and the smoke test have **never run on Linux** yet.
- **Daemon mode**: logs go to `/dev/null` after detach.

## 9. Known limits (by design, documented)

No rollback detection; chunk mixing between versions of the same file is
not detected; an extra `.cd-dir` copy allows undetected moves between
directories (warning + `check` finding `multiple-dir-ids`); xattrs in memory
only; no symlinks / hard links / chown; rename replace is not atomic; `check`
does not repair. Details: README "Threat model" and "Limits".

## 10. GitHub Pages site

- Source: `site/index.html` (one static page, small inline vanilla JS) and
  `site/favicon.svg`. Tailwind CSS v4 browser build from jsDelivr, pinned to
  `@tailwindcss/browser@4.3.3/dist/index.global.js` with an SRI hash. A new
  version needs a new hash (command is in the HTML comment). No build step,
  no npm. Theme tokens live in `<style type="text/tailwindcss">` `@theme`.
- Deployment: `.github/workflows/pages.yml` (checkout v7, configure-pages
  v6, upload-pages-artifact v5 with `path: site`, deploy-pages v5) on push
  to `main` when `site/**` changes. In the repo settings, Pages source must
  be "GitHub Actions". `site/` is used instead of `docs/` so the internal
  specs and plans are not published.
- URL: <https://mkloubert.github.io/crypto-drive/>.
- Content must match the README (commands, flags, limits, threat model,
  "pre-release, no audit"). Do not promise features that do not exist.
  Simple English.
- Design (inspired by c64-dev/es-theme-epicnoir and storytold/craft-launcher):
  noir monochrome (`ink #0b0b0c`, `coal #121316`, `line #1c1c1c`, `smoke
  #585858`, `ash #888888`, warm `paper #f2f1ee`) with one ember accent
  (`#e0662f` / `#f0a46f`). Fonts: Bebas Neue (display), Instrument Serif
  italic (accent words), Inter (body), Geist Mono (labels, code). Glass
  cards, faint grid, film grain, uppercase tracked mono labels, numbered
  sections. Respect `prefers-reduced-motion`. Keep this style.
- No browser is installed in the container: check the page with a static
  HTML/JS check here and ask the owner to look at it locally
  (`python3 -m http.server -d site`).

## 10a. Releases

- `.github/workflows/release.yml` runs on a pushed tag `vX.Y.Z`
  (for example `v0.1.2`).
- The git tag is the single source of truth for the version. The repository
  holds only the placeholder `version = "0.0.0"` in `[workspace.package]`
  of the root `Cargo.toml`; the crates use `version.workspace = true`.
  Never bump the version by hand and never commit a real version.
- `scripts/set-version.sh <X.Y.Z|vX.Y.Z>` writes the version into
  `Cargo.toml` and into the three workspace entries of `Cargo.lock` (perl,
  no network), so `--locked` builds keep working. Every CI job runs it with
  the tag first. Local builds report `crypto-drive 0.0.0`.
- Job `check`: set the version, then fmt, clippy, the header check and
  `cargo test --workspace --locked`.
- Job `build` (matrix): `x86_64`/`aarch64-unknown-linux-gnu`,
  `x86_64`/`aarch64-unknown-linux-musl` (static) on `ubuntu-24.04` /
  `ubuntu-24.04-arm`, `aarch64-apple-darwin` on `macos-26`,
  `x86_64-apple-darwin` on `macos-26-intel`. macOS installs macFUSE with
  brew (link library only). Each target gives
  `crypto-drive-<tag>-<target>.tar.gz` (binary, LICENSE, README.md,
  docs/format.md) plus a `.sha256` file. A smoke step fails if
  `crypto-drive --version` is not `crypto-drive <tag without v>`.
- Job `release`: `gh release create` (or `upload --clobber` on a re-run)
  with `SHA256SUMS` and generated notes. `v0.*` is a pre-release.
- No Windows or BSD builds: there is no FUSE backend for them.
- To release: the owner creates and pushes the tag (`git tag vX.Y.Z`,
  `git push origin vX.Y.Z`). Nothing has to change in the repository.
- Rules for workflows: use the latest major version of each action, as a
  major tag only (`@v7`, not `@v7.0.1`). Look the version up live
  (`curl -s https://api.github.com/repos/<owner>/<action>/releases/latest`),
  never from memory. Pin runner images (`ubuntu-24.04`, not
  `ubuntu-latest`). Prefer the `gh` CLI over third-party actions. Pass
  `${{ }}` values to `run:` through `env:`.
- Action versions at the last check (2026-11-01): checkout v7,
  upload-artifact v7, download-artifact v8, configure-pages v6,
  upload-pages-artifact v5, deploy-pages v5.

## 11. Current status (update with every bigger change)

- Git: only `main` (history was squashed into a new start:
  `6c91912 chore: initial commit`). Remotes: `origin`
  (github.com/mkloubert/crypto-drive) and `gitea`. Tags `v0.1.0` (first run failed
  on a CLI test race, fixed in the test helper), `v0.1.1` (failed on the old
  tag/version check, replaced by the tag-driven version) and `v0.1.2` (first
  release with binaries for all six targets; README and the GitHub page
  describe the download). Repository version placeholder: 0.0.0.
- MVP done: all eight commands, format hardening (entry binding, key epochs,
  `rotate-key`, `recover` with two keys, `--pad-sizes`, name index), fuzzing,
  in-memory xattrs, LRU chunk cache, fsyncdir.
- Verified by the owner on macOS 26.6.2 + macFUSE 5.5.0: all tests, real
  mount tests, smoke test, Finder copies.
- Review 2026-11-01, Linux container tested only, not yet committed:
  open-file limit fixed (CLI raises `RLIMIT_NOFILE`, core sizes the
  directory cache from it); `set_times` on an open file flushes its buffer
  first, so `cp -p` / copyfile keep the mtime (new mount test
  `mtime_set_before_close_is_kept`, to run on the Mac); a stop signal with a
  busy drive keeps it mounted instead of leaving a dead mount (smoke test
  step 11 "busy stop", to run on the Mac). Next: `lock_vault` in `passwd`.
- Open: Linux real-mount run; per-flush file key (format change, would fix
  chunk mixing); copy-on-write / journal for crash safety; stable inode
  numbers; macOS "forking a threaded process" warning; daemon log target;
  encrypted persistent xattrs; `check --repair`; Windows backend.
- Deferred small findings: `docs/superpowers/plans/2026-10-31-crypto-drive-mvp-followups.md`.
