# crypto-drive

Author: Marcel Joachim Kloubert. License: AGPL-3.0-or-later (see
[LICENSE](LICENSE)).

## What it is

`crypto-drive` shows a normal directory (the vault) as a readable and
writable drive. You work in the drive like in any folder. In the vault, the
contents and the names of all files and directories are encrypted. The vault
is safe to put in a cloud sync folder.

- Each file is encrypted on its own, in chunks of 64 KiB (AES-256-GCM).
- Names are encrypted with AES-256-SIV.
- Control files never change after they are created, so sync clients can
  handle them. Conflict copies from sync clients are shown in the drive.
- Only symmetric crypto with 256-bit keys is used.

The exact format is in [docs/format.md](docs/format.md).

## Install

Prebuilt binaries are on the
[releases page](https://github.com/mkloubert/crypto-drive/releases)
(pre-releases). Each archive `crypto-drive-<tag>-<target>.tar.gz` holds the
binary, `LICENSE`, `README.md` and `docs/format.md`, and has a `.sha256`
file next to it. Targets:

- macOS: `aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin` (Intel)
- Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and the
  static `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`

Check and unpack (example):

```
shasum -a 256 -c crypto-drive-<tag>-<target>.tar.gz.sha256
tar -xzf crypto-drive-<tag>-<target>.tar.gz
```

Then put `crypto-drive` into your `PATH`. You still need macFUSE or FUSE 3
(see below). The macOS binary is not signed; if you downloaded it with a
browser, remove the quarantine flag once with
`xattr -d com.apple.quarantine crypto-drive`.

To build from source you need Rust 1.99.1 (the repository pins it in
`rust-toolchain.toml`).

macOS:

```
brew install --cask macfuse
```

macFUSE needs its kernel extension. On Apple Silicon you must first allow
kernel extensions of known developers in the Startup Security Utility
(recovery mode, "Reduced Security"), then allow macFUSE in System Settings,
Privacy & Security, and restart. If `kmutil showloaded | grep macfuse` shows
nothing after that, load it once with
`sudo kmutil load -p /Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext`
(use the folder of your macOS version).

crypto-drive mounts through libfuse 2 (`/usr/local/lib/libfuse.2.dylib` from
macFUSE). If macFUSE put its libraries somewhere else, build with
`FUSE_LIB_DIR=<dir> cargo build --release`. The FSKit backend (`-o backend=fskit`) does not work reliably with
libfuse 2 and macFUSE 5.5 yet, so the kernel extension is required for now.

Linux:

```
sudo apt install fuse3    # or the same package of your distribution
```

On Linux the drive talks to the kernel directly and needs no libfuse; the
`fuse3` package gives `fusermount3`, which mounts and unmounts it.

Build:

```
cargo build --release
```

The binary is `target/release/crypto-drive`.

## Quick start

```
crypto-drive init  ~/vault                    # asks for a new password, prints the recovery key and the key file path
mkdir ~/drive
crypto-drive mount ~/vault ~/drive --key-file ~/.crypto-drive/keys/20261101143052123_vault.cd-key
# ... work in ~/drive ...
crypto-drive unmount ~/drive
```

- `init --pad-sizes` hides exact file sizes (see "Size padding"). It can only
  be chosen at `init`.
- `init` needs an empty or missing directory. It prints the recovery key
  once on stdout. Write it down and keep it offline.
- The mountpoint must exist, must be empty and must not overlap the vault. A
  vault can only be mounted once at a time.
- `mount --daemon` runs in the background after a successful mount. Errors
  that happen later are not shown.
- Ctrl+C, SIGTERM and closing the terminal (SIGHUP) unmount the drive
  cleanly and write all buffers first. If the drive is busy (a program has
  a file open, or a terminal is inside it), it stays mounted and keeps
  working: the buffers are written and a warning tells you to close those
  programs and stop again, or to run `crypto-drive unmount --force <mountpoint>`.
  (In daemon mode the warning is not shown.)
- If a drive process was killed without an unmount, the mount point is left
  dead ("Transport endpoint is not connected" on Linux, "Device not
  configured" on macOS). `mount` then points to
  `crypto-drive unmount --force <mountpoint>`.
- `-o OPT` passes a FUSE option to macFUSE or Linux FUSE.
- `unmount` uses `umount` on macOS and `fusermount3 -u` on Linux. Use
  `--force` for a busy drive.
- Use `--debug` to get detailed logs. They contain clear file names.

Other commands:

| Command | What it does |
|---|---|
| `passwd <vault>` | Change the password. The master key stays the same. |
| `rotate-key <vault>` | Replace the master key and re-encrypt the whole vault (see "Key rotation"). |
| `recovery-key <vault>` | Print the recovery key again (of the vault's current key). |
| `recover <vault>` | Write a new key file from the recovery key (`--overwrite` to replace one). |
| `check <vault>` | Check the whole vault. Prints `<warning\|error>: <real_path>: <kind>` per finding. Exit code 0 = fine, 1 = warnings, 2 = errors. It does not repair. |

### Passwords

- `init` and `recover` read the new password from `--new-password-fd N`,
  or `CRYPTO_DRIVE_NEW_PASSWORD`, or the terminal (asked twice).
- `passwd` and `rotate-key` read the current password from `--password-fd N`,
  `CRYPTO_DRIVE_PASSWORD` or the terminal, and the new one as above.
- `mount`, `check` and `recovery-key` read the current password from
  `--password-fd N`, `CRYPTO_DRIVE_PASSWORD` or the terminal.
- `recover` reads the recovery key from `--recovery-key-fd N` or the terminal,
  and the second key of an unfinished rotation from `--new-recovery-key-fd N`
  or the terminal. The vault must not be mounted while `recover` runs.
- `--password-fd` and `--new-password-fd` must be different descriptors.
- Environment variables are less safe (other programs can read them). A
  warning is printed. Prefer a file descriptor:

```
crypto-drive mount ~/vault ~/drive --password-fd 3 3< password.txt
```

- Empty passwords are rejected.
- Argon2 cost: `--argon2-memory` (KiB), `--argon2-iterations`,
  `--argon2-parallelism`. Default 262144 / 3 / 4. Lower limits are 19456 / 2 / 1
  and the upper limits are 1048576 / 64 / 64. Values below the default print a
  warning.

## Key file

The key file holds the master key, wrapped with a key made from your password
(Argon2id). Without `--key-file`, `init` writes it to

```
~/.crypto-drive/keys/<YYYYMMDDhhmmsszzz>_<VAULT_NAME>.cd-key
```

(UTC time, `zzz` = milliseconds; `VAULT_NAME` is the vault directory name,
every character other than letters, digits, `-` and `_` becomes `_`). The
folders get mode 0700 and the file 0600. `init` prints the path on stderr.
So the key file is not inside the vault and is not synced with it: an
attacker who only has the vault (for example from your cloud storage)
cannot run an offline attack on your password.

All other commands need the key file with `--key-file PATH`:

```
crypto-drive mount ~/vault ~/drive --key-file ~/.crypto-drive/keys/20261101143052123_vault.cd-key
```

- Copy the key file to every device that opens the vault, and back it up.
  Without it you need the recovery key (`recover`).
- `--key-file PATH` at `init` stores it somewhere else, for example on a USB
  stick.
- Vaults made before this change have their key file `.cd-key` in the vault
  root. The commands still find it there without `--key-file`.
- `recover` without `--key-file` writes a new key file to
  `~/.crypto-drive/keys` (or replaces the old `.cd-key` of the vault with
  `--overwrite`) and prints its path.
- `init` never overwrites an existing key file.

## Recovery key

The recovery key is 55 characters in 11 groups of 5. It is as powerful as the
master key. Keep it offline (for example on paper). If you lose the key file or
forget the password, `crypto-drive recover <vault>` makes a new key file with a
new password. Case, spaces and dashes are ignored when you type it.

If a key rotation did not finish, `recover` needs both recovery keys: the old
one and the new one that `rotate-key` printed. `recover` finds this itself
(some names or files already use the new key). It then asks for the second key
on a terminal ("Recovery key of the unfinished rotation"), or reads it from
`--new-recovery-key-fd N`. With only the old key it stops and writes nothing,
because a key file with only the old key would lose everything that the
rotation already re-encrypted. After `recover` run `rotate-key` to finish the
rotation. If the rotation had already re-encrypted everything (for example it
stopped at its very last step), the new recovery key alone is enough.

## Size padding

`crypto-drive init <vault> --pad-sizes` rounds every file up to a size stage:
4 KiB, then powers of two up to 1 MiB, then multiples of 1 MiB. The extra bytes
are random. An attacker sees only the stage, not the exact size.

- Cost: disk space and sync traffic (every file takes at least 4 KiB, up to
  about twice its size below 1 MiB, up to 1 MiB more above), and reading the
  size of a file (for example in a directory listing) reads its first 89 bytes.
- A padded file that grows is written about twice: first random padding up to
  the next stage, then the data over it.
- It does not hide the number of files, the tree shape or timestamps.
- You cannot turn it on or off after `init`.

## Key rotation

`crypto-drive rotate-key <vault>` makes a new master key and re-encrypts the
whole vault. Afterwards old key files, old passwords and old recovery keys no
longer open the vault. Your password stays the same. You can set new Argon2
costs with `--argon2-memory`, `--argon2-iterations` and
`--argon2-parallelism`.

Rules, especially when you use the vault on more than one device:

- Stop all other devices first. Do not mount or write the vault anywhere else
  until the rotation has finished. An entry that another device writes during
  the rotation with the old key can become unreadable.
- The command runs offline. It fails if the vault is mounted.
- Your sync client uploads the whole vault again.
- Afterwards every device needs the new key file (the old one gives "wrong
  key"). Wait until your sync client has finished before you use another
  device.
- The command prints a new recovery key at the start as `RECOVERY KEY: <key>`.
  Write it down. Keep the old recovery key until the rotation has finished.
  Until then `recover` may need both keys, the old one and the new one (see
  "Recovery key").
- It asks `Continue? [y/N]` on a terminal. Without a terminal use `--yes`.
- If it stops (crash, power loss, an error), run it again. It continues. While
  it is unfinished, the vault can still be mounted and `check` reports
  `rotation-in-progress`.
- If you changed a file in a mount between two runs and a crash left both
  copies, the rotation keeps both. The older one shows as
  `<name> (rotation conflict N)<.ext>`.
- An old file that cannot be decrypted stops the rotation at that file with
  "authentication failed". Remove or restore it (`check` lists it) and run
  it again.
- A long-name entry whose `.cd-name` is missing or damaged but which still
  holds data blocks the end of the rotation: the error names it. Repair or
  remove it, then run it again. A mount renames a directory to a long name
  so that a crash cannot leave such an entry. Foreign entries and incomplete
  entries without data are left alone.
- A directory in the vault that you cannot write (for example mode 555)
  stops the rotation with "permission denied". Make it writable and run it
  again.
- File modes and times are kept. Modification times of directories change.
- Rotation does not undo past leaks. Whoever already has a copy of old
  ciphertext together with an old key can still read that old copy.

## Sync clients and conflict copies

You can put the vault in a folder of Dropbox, Nextcloud, Syncthing, OneDrive,
iCloud Drive or similar. Every file is one real file, and control files never
change. Do not mount the same vault on two machines at the same time, but
sequential use is fine.

If a sync client makes a conflict copy (for example `name (conflict copy)`),
the drive shows it as `<name> (conflict N)<.ext>`. You can read and write it
like any file. Rename it to resolve the conflict. If two devices create the
same directory at the same time, the vault can get more than one `.cd-dir`.
It still works. `check` reports it, and the mounted drive logs a warning. To
clean it up, move the entries of that directory to a new directory in the
drive (this names them under one id) and remove the old one.

## Threat model

Protected against an attacker who can read and change the vault (cloud
provider, stolen disk, backup):

- Confidentiality of file contents and of file and directory names.
- Integrity: a change is detected on read and gives an error, never wrong
  plaintext. This covers bit flips, swapped or cut chunks, chunks mixed
  between files, and files moved between directories. Two gaps remain; see
  "Not protected against" (older versions, extra `.cd-dir` copies).
- File and directory swaps are detected. The content of a file is bound to its
  name through a random entry id. If someone replaces the encrypted file `B`
  with a copy of another file `A`, you get an error, not A's content under B's
  name. The same holds for directories.
- With `--key-file` outside the vault, no offline password attack is possible
  without the key file.

Post-quantum: only symmetric primitives with 256-bit keys are used (AES-256,
HMAC-SHA-256, HKDF-SHA-512, Argon2id), so Grover's algorithm leaves about 128
bits.

What stays visible from the outside: rough file sizes (plus 28 bytes per 64
KiB), the number of files and directories, the tree shape and nesting depth,
and timestamps and times of changes. With `--pad-sizes` the exact size is
hidden, but the size stage, the number of files, the tree shape and the
timestamps stay visible.

Not protected against:

- An attacker on the running, unlocked system (malware, root, the same user
  while the drive is mounted).
  The process makes this harder: on Linux it sets `PR_SET_DUMPABLE` to 0,
  so other processes of the same user cannot trace it or read its memory
  (root still can); on macOS it uses `PT_DENY_ATTACH` against debuggers.
- Rollback of a single file (or a name) to an older valid version, for
  example from the version history of a cloud. It is not detected. There is no
  write counter.
- Mixing old and new chunks of the same file. All versions of a file use the
  same file key, so a 64 KiB chunk from an older version of the file can
  replace the chunk at the same place in the current version. The file then
  holds parts of two versions, and no error is given. Chunks from other files
  or other places in the file are still detected.
- Moves between directories with a planted `.cd-dir` copy. Extra `.cd-dir`
  files are allowed so that sync conflicts keep working (see "Cloud sync").
  Someone who can change the vault can move files or directories from
  directory A to directory B and put a copy of A's `.cd-dir` into B: the
  entries then show up in B without an error. A mounted drive logs a warning
  for such a directory (once per mount), and `check` reports it as
  `multiple-dir-ids`. If you did not expect a sync conflict there, look at
  the entries of that directory.
- Past leaks. `rotate-key` makes old key files, old passwords and old recovery
  keys useless for the vault as it is afterwards. It cannot take back a copy
  of old ciphertext plus an old key that someone already has. Until you run
  `rotate-key`, `passwd` does not change the master key: someone with an old
  copy of `.cd-key` and the old password can still open the vault.

## Limits

- No symlinks, no hard links, no special files and no `chown`.
- Extended attributes (xattrs) are kept in memory only, while the drive is
  mounted. They are never written to disk, so they are gone after an
  unmount. Setting one never fails, so Finder, `cp`, `ditto` and `rsync`
  can always copy: a value over 1 MiB per entry (names plus values) or over
  64 MiB for all entries is accepted but not kept, and on Linux only the
  `user.` namespace is kept. Content, names, permissions (`chmod`) and
  timestamps are not affected. What is lost after an unmount:
  - the quarantine flag (`com.apple.quarantine`): an app or script
    downloaded from the internet starts from the drive without the
    Gatekeeper warning after the next mount,
  - Finder tags and colors, "Where from" (`kMDItemWhereFroms`) and custom
    icons (resource forks),
  - other app data in xattrs (for example a text encoding or "exclude from
    Time Machine").
  Entries that a sync client deletes or renames outside the drive keep
  their in-memory xattrs under the old name until the unmount.
- Finder writes `.DS_Store` files (view settings) into the drive. They are
  stored encrypted like any other file.
- Names are case sensitive.
- File sizes, counts, tree shape and timestamps are visible (see above).
- Rollback of single files is not detected.
- Old key files keep working after `passwd` (use `rotate-key`).
- The running drive finds outside changes (from a sync client) through the
  modification time of the real directory. A change in the same time tick as
  your own change (FAT: 2 seconds) can stay unseen until the directory changes
  again. The same holds for outside edits that do not change the modification
  time of the parent directory (inside a long-name entry, or a `chmod` of an
  entry).
- The kernel keeps its cache of a file's content across opens while the
  real file is unchanged (same inode, size, mtime and ctime). An outside
  change in the same ctime tick (a few milliseconds) that keeps the size can
  stay unseen until the file changes again.
- With `--pad-sizes`, the size of a file that you cannot open (permission
  denied) is shown as an upper bound: real size minus 117 bytes.
- Replacing a file by rename is not one atomic step inside the drive (the
  new entry needs its own real name). Editors that save through a temporary
  file and a rename are therefore not atomic inside the drive. A crash can
  leave a duplicate that shows as a conflict copy, but no data is lost.
- Creates, renames and removes reach the disk of the vault when the system
  writes them, not at once. An app that calls `fsync` on a file or a
  directory (databases, careful editors) gets them written: `fsync` of a file
  also syncs the real directory of its entry, and `fsync` of a directory
  syncs its real directory. A file that is being overwritten during a crash
  can still be left part old and part new.
- If two entries in a directory have the same clear name, it is not defined
  which one gets the plain name. The other shows as `(conflict N)`.
- An unreadable long-name entry is hidden from the listing and blocks creating
  other names in that directory that also need a long entry. An unreadable
  short entry blocks only its own name.
- Entries left incomplete by an interrupted sync are hidden. `check` reports
  them.
- A foreign file inside a real directory (for example `.DS_Store` after you
  browse the vault folder in Finder) makes the matching drive directory
  impossible to remove (`ENOTEMPTY`), although it looks empty in the drive.
  Run `crypto-drive check` to find such files.
- With `CRYPTO_DRIVE_PASSWORD`, a daemon keeps the variable visible in its
  process environment for its whole life. Prefer `--password-fd` or the
  terminal.
- Growing a file (`truncate`, or a write past the end) writes every new
  chunk, also the zero ones. The file takes its full size on disk and is
  uploaded in full. A grow that needs more than the free space of the vault
  disk fails at once with "no space left on device", and the file keeps its
  old size. If a grow fails partway, the file is set back to its old size.
- `check` only reports. There is no repair yet.
- No GUI, no keychain, no sharing with more users, no Windows backend.

## Tests and tools

```
cargo test --workspace
scripts/smoke-test.sh                        # needs FUSE and a release build
cargo bench -p crypto-drive-core --bench throughput
```

The smoke test reads `CRYPTO_DRIVE_BIN` (binary path), `SMOKE_BIG_MB` (size
of the big file, default 300) and `SMOKE_MOUNT_OPTS` (extra FUSE options).
The real-mount tests (`cargo test -p crypto-drive-fuse --test mount --
--include-ignored`) read `CRYPTO_DRIVE_TEST_MOUNT_OPTS` the same way.

## Fuzzing

The fuzz targets live in `fuzz/`, a separate crate on a pinned nightly
toolchain (the main workspace stays on stable). Install the tools once:

```
rustup toolchain install nightly-2026-10-15
cargo install cargo-fuzz --version 0.13.2 --locked
```

Then copy the seed inputs and run the targets:

```
fuzz/seeds.sh                    # seed corpus from the golden files and KATs
scripts/fuzz.sh all 300          # every target for 300 seconds
scripts/fuzz.sh hostile_tree 60  # one target
```

The parser targets are `key_file`, `key_set`, `vault_marker`,
`recovery_key`, `names`, `conflict_names` and `content`. `hostile_tree`
writes arbitrary real entries into a fresh vault and lists, checks and reads
it. `fs_ops` runs operation lists against the drive and an in-memory model.
The script uses AddressSanitizer; set `FUZZ_SANITIZER=none` if it cannot be
linked on your machine. The corpus grows in `fuzz/corpus/<target>/`, and
crashing inputs go to `fuzz/artifacts/<target>/`. Replay one with
`cargo +nightly-2026-10-15 fuzz run <target> <file>` in `fuzz/`.

## License

AGPL-3.0-or-later. Copyright (C) 2026 Marcel Joachim Kloubert. See
[LICENSE](LICENSE).
