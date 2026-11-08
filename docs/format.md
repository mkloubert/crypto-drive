# crypto-drive on-disk format, version 1 (hardened)

This document is the normative description of format version 1. The words
MUST, MUST NOT, SHOULD and MAY have their usual meaning (RFC 2119). It is the
source for any second implementation. The design reasons are in
`docs/superpowers/specs/2026-10-31-crypto-drive-design.md`.

Conventions:

- All integers are little endian, unless the text says "big endian".
- "B64" means Base64url without padding. The alphabet is `A-Z a-z 0-9 - _`.
- `||` means concatenation. `u8`, `u16`, `u32`, `u64` are unsigned integers.
- All random values MUST come from the operating system random generator.

## 1. Vault layout

```
<vault>/
├── .cd-vault                    marker, changes only on key rotation
├── .cd-key                      key file of older vaults (the CLI now stores it outside the vault by default)
├── <B64 name>                   encrypted file
├── <B64 name>/                  encrypted directory
│   ├── .cd-dir                  directory ID, never changes
│   └── ...
└── .cd-cdl<B64 hash>/           overflow entry (file or directory)
    ├── .cd-name                 full B64 name (ASCII)
    ├── .cd-content              only for a file: encrypted content
    └── .cd-dir                  only for a directory: directory ID
```

- An encrypted name MUST NOT contain a dot.
- An entry whose name starts with `.cd-` is a control file.
- Any other entry that starts with a dot (for example `.DS_Store`) is
  foreign. It MUST be hidden in the drive. A checker SHOULD report it.
- The children of an overflow directory are stored next to its `.cd-dir`.
- `.cd-rot.tmp` is a temporary file of `rotate-key`. A reader MUST ignore it.
  `rotate-key` removes leftovers.
- Extended attributes (xattrs) are not part of the format. The drive keeps
  them in memory only, so no file stores them.

## 2. Key epochs and key hierarchy

Every master key belongs to a key epoch, a `u32`. The first epoch is 1. Each
rotation adds 1.

```
KEK          = Argon2id(password, salt, m, t, p) -> 32 bytes
key set      = AES-256-GCM-unwrap(KEK, ...)   1 or 2 entries (epoch, MK), MK 32 random bytes

For each epoch e in the key set:
PRK_e        = HKDF-SHA-512-Extract(salt = vault_id || e (u32), ikm = MK_e)
K_names[e]   = HKDF-SHA-512-Expand(PRK_e, "crypto-drive v1 names",   64)   AES-256-SIV key
K_content[e] = HKDF-SHA-512-Expand(PRK_e, "crypto-drive v1 content", 32)
K_check[e]   = HKDF-SHA-512-Expand(PRK_e, "crypto-drive v1 check",   32)   HMAC-SHA-256 key

K_file       = HKDF-SHA-512(salt = file_nonce, ikm = K_content[file_epoch],
                            info = "crypto-drive v1 file" || file_id, 32)
K_size       = HKDF-SHA-512(salt = file_nonce, ikm = K_content[file_epoch],
                            info = "crypto-drive v1 size" || file_id, 32)
```

- The labels are ASCII, with no terminating zero byte.
- `K_size` is used only in a padded vault (section 7.2).
- Argon2 is Argon2id, version 0x13, output length 32, no secret, no
  associated data.
- `file_nonce`, `file_id` and `file_epoch` come from the file header
  (section 7).
- The write epoch is the highest epoch in the key set. A writer MUST use it
  for every new name and new file.
- Outside a rotation the key set has exactly one entry.

## 3. Key file `.cd-key`

```
offset  length  field
0       8       magic = "CD-KEY\0\0"
8       2       version = 1
10      2       slot_count (at least 1)
12      ...     slots
```

Slot:

```
0       1       slot_type (1 = password)
1       2       payload_len
3       ...     payload
```

Payload of slot type 1 (password). It is 93 bytes (one key) or 129 bytes
(two keys):

```
0       4       argon2_m_kib
4       4       argon2_t
8       4       argon2_p
12      16      salt
28      12      nonce
40      ...     wrapped = AES-256-GCM(KEK, nonce, key_set, AD)   (key_set + 16 byte tag)

key_set = count (u8, 1 or 2) || count * ( epoch (u32) || MK (32 bytes) )
```

- `payload_len` MUST be 40 + 1 + 36 * count + 16.
- After decryption a reader MUST check: `count` is 1 or 2, every epoch is
  greater than 0, and the epochs are in strictly ascending order. A reader
  MUST reject any other order. A failed check is treated like a wrong
  password.

Rules:

- `AD` = file bytes 0 to 9 (magic and version) `||` `slot_type` `||`
  `payload_len` (2 bytes) `||` payload bytes 0 to 39. So the version and the
  Argon2 parameters are authenticated. `slot_count` MUST NOT be part of `AD`.
- Unlock: a reader MUST try all password slots. It MUST skip slots of an
  unknown type and MUST keep them unchanged when it writes the file again.
- The key file is not bound to one vault. The marker (section 4) checks that
  key and vault belong together.
- A writer MUST write the key file atomically: a temporary file in the target
  directory, `fsync`, `rename`, `fsync` of the directory. The file mode MUST be
  `0600`. An existing key file MUST NOT be overwritten by `init`.

### 3.1 Argon2 limits

| Parameter | Minimum | Default | Maximum |
|---|---|---|---|
| `m` (KiB) | 19456 | 262144 | 1048576 (1 GiB) |
| `t` | 2 | 3 | 64 |
| `p` | 1 | 4 | 64 |

- A writer MUST NOT write values below the minimum or above the maximum.
- A writer SHOULD warn when a value is below the default.
- A reader MUST skip a password slot whose parameters are above the maximum,
  without running Argon2. This protects against a
  memory or time attack with a crafted key file. If no usable slot is left, the
  unlock fails like a wrong password.
- A reader MUST refuse a key file with more than 16 slots, a key file larger
  than 65536 bytes, and anything that is not a regular file (for example a
  FIFO), before it tries any slot. A real key file has one slot and 108 or
  144 bytes; the limits protect against a crafted file that would fill the
  memory, block, or need Argon2 for thousands of slots.

## 4. Vault marker `.cd-vault` (66 bytes)

```
offset  length  field
0       8       magic = "CD-VAULT"
8       2       format_version = 1
10      2       max_name_length (64 to 255, default 220)
12      2       flags: bit 0 = pad_sizes; all other bits MUST be 0
14      16      vault_id (random)
30      4       epoch (u32) = the vault's current epoch
34      32      tag = HMAC-SHA-256(K_check[epoch], bytes 0 to 33)
```

- A reader MUST refuse a marker with an unknown flag bit
  (`".cd-vault flags"`) before any key work.
- A reader MUST verify the tag in constant time with `K_check[epoch]`. If the
  key set has no key for `epoch`, the unlock fails as a wrong key. If the tag is
  wrong, it MUST refuse to mount ("the key does not belong to this vault").
- A reader MUST refuse an unknown `format_version`.
- The file is written by `init` and by the last step of `rotate-key`
  (section 11) only. A writer MUST write it atomically (temporary file,
  `fsync`, `rename`, `fsync` of the directory). It MUST NOT change at any
  other time.
- `pad_sizes` is chosen at `init` and MUST NOT change later.

## 5. Directory ID `.cd-dir` (16 bytes)

- The file holds 16 random bytes, the `dir_id`.
- The root directory has no `.cd-dir`. Its `dir_id` is the `vault_id`.
- A writer MUST write it through a temporary file (`.cd-dir.tmp`, then
  `rename`) when it creates the directory, so no reader sees a partial
  file. It MUST NOT change it afterwards.
- A writer MAY defer the `fsync` of `.cd-dir` and of the new directory
  until something in that directory is synced. It MUST sync `.cd-dir`, the
  directory and the entry of the directory in its parent before it reports
  a sync of anything inside that directory as done.
- A directory without `.cd-dir` is incomplete (see section 9).
- Non-normative note: the `dir_id` is also the entry id in the encrypted
  name of the directory (section 6), so a lost `.cd-dir` can be rebuilt
  from the parent.

## 6. Names and entry binding

Every entry has a 16 byte entry id: for a file its `file_id` (section 7), for
a directory its `dir_id`.

```
enc   = AES-256-SIV(K_names[e], AD = [parent_dir_id], entry_id || NFC(clear_name))   16 byte tag || ciphertext
name  = B64(enc)
```

- The AES-256-SIV key is the 64 byte `K_names[e]`. The associated data is a
  single item: the 16 byte `dir_id` of the parent directory. The children of
  the root use the `vault_id`.
- A reader decrypts to the entry id (first 16 bytes) and the clear name. If
  there are fewer than 17 plaintext bytes, it MUST fail with an
  authentication error.
- A real name carries no epoch. A reader MUST try `K_names[e]` for every epoch
  in the key set, highest first.
- A clear name MUST be normalized to Unicode NFC before encryption.
- A clear name MUST NOT be empty, `.` or `..`, MUST NOT contain `/` or NUL,
  and MUST NOT be longer than 1024 bytes (after NFC).
- A clear name that starts with `.cd-` is allowed. After encryption it has no
  dot, so it cannot clash with control files.
- The drive is case sensitive.

### 6.1 Binding checks

- File: the `file_id` in the file header MUST equal the entry id in the name.
  If not, a reader MUST fail with an authentication error.
- Directory: the canonical `.cd-dir` MUST hold the entry id in the name. If
  not, a reader MUST fail with an authentication error. Extra `.cd-dir`
  conflict copies (section 10) stay readable for children, but the canonical
  one decides the binding. Because of this, a move of entries from directory
  A to directory B is not detected if a copy of A's `.cd-dir` is put into B.
  A reader SHOULD warn when a name only decrypts under an extra ID.
- Rename and move MUST encrypt the name again with the same entry id. They
  MUST NOT change content or `.cd-dir`.
- A copy MUST get a new `file_id`.
- This detects a file's content under another file's name and a directory's
  subtree under another directory's name. It does not detect rollback.

### 6.2 Overflow rule

- If `len(name) <= max_name_length`, the entry is called `name`.
- Otherwise the entry MUST be a directory called
  `".cd-cdl" || B64(SHA-256(name))` (50 characters). The file `.cd-name` inside
  holds `name` as ASCII. A reader MUST check that the hash in the entry name
  matches `.cd-name`.
- Because of the 16 byte entry id, a name goes to an overflow entry from about
  135 clear bytes on (default `max_name_length` 220).

## 7. File content

A file, or `.cd-content` inside an overflow directory:

```
header, not padded (53 bytes):
    version (1 byte) = 1 || epoch (u32) || file_nonce (32 bytes, random) || file_id (16 bytes, random)
header, padded vault (89 bytes):
    the 53 bytes above || size block (36 bytes)
size block:
    nonce (12 bytes, random) || AES-256-GCM(K_size, nonce, plain_len (u64), AD = header bytes 0 to 52) || tag (16 bytes)
chunks:             chunk_0 || chunk_1 || ... || chunk_{n-1}
chunk_i:            nonce (12 bytes, random) || ciphertext || tag (16 bytes)
                    = nonce || AES-256-GCM(K_file, nonce, P_i, AD_i)
AD_i:               chunk_index (u64, BIG endian) || is_last (u8)
padding:            random bytes (padded vault only)
```

- `H` is the header length (53 or 89).
- `is_last` is 1 for the last chunk (`i = n - 1`) and 0 for all others.
- The clear chunk size is `S = 65536`. All chunks except the last MUST hold
  exactly `S` bytes. The last chunk holds 1 to `S` bytes. It is empty only for
  an empty file (`n = 1`, `P_0` empty). So an empty file has `H + 28` bytes
  before padding (81 bytes in a vault without padding).
- A writer MUST use a new random nonce for every chunk it writes.
- The `epoch` in the header selects `K_content[epoch]`. It is also part of the
  size block `AD`.
- A reader MUST NOT return any plaintext of a chunk that fails authentication.
- Content and name are independent. Rename and move MUST NOT change the content.

### 7.1 Not padded

Size without decryption, with `C` the ciphertext size:
`n = ceil((C - 53) / (S + 28))` and clear size `= C - 53 - 28 * n`.

A reader MUST treat these as invalid: `C < 81`, a last chunk with fewer than
29 bytes when `n > 1`, an unknown `version`.

### 7.2 Padded (`pad_sizes` flag set)

`L = 89 + (size of all chunks for plain_len)` is the unpadded length. The real
file length MUST be `stage(L)`:

| `L` | `stage(L)` |
|---|---|
| up to 4096 | 4096 |
| up to 1048576 (1 MiB) | the next power of two, not below `L` |
| above 1 MiB | the next multiple of 1048576, not below `L` |

- The clear size `plain_len` comes from the size block (decrypt with `K_size`).
  A reader MUST treat a file whose length is not `stage(L)` as invalid.
- The bytes between `L` and `stage(L)` MUST be random. A reader MUST NOT read
  them. Changing them has no effect and is not detected.
- Every change of `plain_len` MUST write a new size block with a fresh nonce.
- Flush order of a writer:
  - Grow past the current stage: first extend the file to the new stage length
    and fill `[old real length, new stage)` with random bytes; then write the
    chunks; then write the header and the size block.
  - Shrink: write the chunks, then the header and size block, then cut the file
    to the new stage length, then fill the bytes after the end of the last
    chunk with random bytes.
  - A crash in the middle can make this one file unreadable (an I/O error). A
    checker reports it.
- To get the clear size of a padded file, a reader needs the first 89 bytes. If
  the file cannot be opened (permission denied), an implementation MAY report
  the upper bound `real length - 89 - 28`.

## 8. Rollback

Format version 1 does not detect rollback. A reader accepts an older valid
version of a file, or of a name, because there is no write counter and no
local state. A rotation (section 11) makes old versions unreadable only if
they were encrypted under a removed epoch.

Non-normative notes on what format version 1 does not hide or detect:

- No directory listing is authenticated. Removing entries, or putting back
  a deleted entry (an older valid real name with its content), is not
  detected.
- The length of a real name gives the exact byte length of the NFC clear
  name (section 6); for a long name, the size of `.cd-name` gives it.
- `file_id` (section 7) and the directory id (section 5) are stored in clear
  and are kept by renames, moves and rotations, so copies of a vault taken
  at different times can be linked entry by entry.
- AES-SIV is deterministic: the same parent directory id, entry id and name
  give the same real name, so renaming an entry back gives its old real name.
- A chunk is rewritten in place with a new nonce; which chunk indexes
  changed between two copies of a file is visible.
- File system metadata of the real entries (mode bits, owner, times) is not
  part of the format and is not authenticated. An implementation that shows
  mode bits in the drive SHOULD drop setuid, setgid and sticky bits and
  SHOULD NOT treat the `rwx` bits as a security boundary between local
  users.

## 9. Directory rules

- A directory is empty when it holds only control files. Any other entry,
  also a foreign one, makes it non-empty.
- A directory without a valid `.cd-dir` is incomplete. An empty `.cd-dir`
  (what a crash after a deferred sync can leave, section 5) counts as a
  missing one. If the directory is empty and its modification time is more
  than 60 seconds old, a reader MAY remove it.
  A younger one MUST NOT be removed (a sync client may not have written its
  `.cd-dir` yet); it is not found. Otherwise access fails with an I/O error.
- Entries left by an interrupted sync are hidden and SHOULD be reported by a
  checker.

## 10. Sync conflict copies (spec section 5.3)

A sync client can add a suffix to a name when two devices change the same file.
A reader MUST handle this as follows:

1. List the real directory. Skip control files that start with `.cd-`, but not
   `.cd-cdl` entries.
2. Classify each entry:
   - A valid B64 name: decrypt it.
   - `.cd-cdl<hash>`: read and decrypt its `.cd-name`.
   - A conflict copy: the entry name is a valid B64 name (or `.cd-cdl` and 43
     characters) followed by a suffix. A reader MUST try the prefixes from the
     longest to the shortest until one authenticates (some suffixes use only
     B64 characters). If it finds one, it MUST show the entry as
     `<stem> (conflict N)<.ext>`. `N` starts at 1 and follows the sort order
     of the real names. No pattern per sync client is used.
   - Anything else is foreign and MUST be hidden.
3. More than one `.cd-dir`: a control file whose name starts with `.cd-dir`
   and that is 16 bytes long (except `.cd-dir.tmp`) is a conflict copy of the
   directory ID. A reader MUST try the canonical ID and the IDs of the first
   15 copies in byte order of their names (16 distinct IDs at most) when it
   decrypts names. It MUST ignore further copies, so that planted copies
   cannot make a listing try every name with thousands of IDs; names under
   them are not shown. A check tool SHOULD report every copy. A writer MUST
   use the canonical `.cd-dir` for new entries.

Conflict copies are normal files. Renaming one encrypts its name again with a
clean name and so resolves the conflict.

## 11. Key rotation

`rotate-key` replaces the master key. It runs offline, under the vault lock,
and can be run again after a crash. Let `e` be the epoch of the marker.

1. Begin (key set has one key): a writer MUST make `MK_{e+1}` and write the
   key file atomically with the key set `{e, e+1}`. If the key set already has
   two keys, the run continues the unfinished rotation.
2. Re-encrypt, depth first, one entry at a time. A leftover `.cd-rot.tmp` is
   removed first.
   - A directory: encrypt its name with `K_names[e+1]` and the same `dir_id`,
     then rename the real entry. `.cd-dir` MUST NOT change.
   - A file: write the content again into `.cd-rot.tmp` in the same real
     directory with a header of epoch `e+1`, a new `file_nonce`, the same
     `file_id`, all chunks, and padding if the vault is padded. `fsync`. Then
     make the new entry with the name under `K_names[e+1]` and remove the old
     one.
   - An entry that is already done (name and, for a file, header at `e+1`) is
     skipped.
   - Duplicates after a crash: two entries with the same clear name and entry
     id, one at `e`, one at `e+1`. A writer MUST authenticate both copies
     fully and compare their plaintext. Equal: remove the old copy. Different:
     keep both; the old copy becomes a new file (new entry id) called
     `<stem> (rotation conflict N)<.ext>`. A copy that fails authentication is
     removed.
3. Finish: walk the tree again. If any name, file or overflow entry still uses
   `e`, stop with an error and change nothing else. Old-epoch long entries
   with a wrong hash block this step, and so does a long entry without a
   valid `.cd-name` that still holds `.cd-dir` or `.cd-content`. Foreign
   entries and incomplete entries without data are left alone and do not
   block. (An old-epoch file that does not authenticate already stops step 2
   with an error.) Then write
   `.cd-vault` with epoch `e+1`, then the key file with the key set `{e+1}`.
   If a crash happens between the two writes, the next run sees the marker at
   `e+1` and only writes the key file.

- While the key set has two epochs, a reader reads names and files of both
  epochs. New names and new files use epoch `e+1`. A changed file of epoch `e`
  keeps epoch `e` until the next rotation run.
- File mode and times are kept. Directory modification times change.
- Rotation does not undo past leaks.

## 12. Recovery key

```
bytes   = MK (32 bytes) || SHA-256(MK || "crypto-drive v1 recovery")[0..2]   (34 bytes)
text    = Base32 (Crockford alphabet, upper case, no padding), 55 characters,
          in 11 groups of 5, joined with "-"
```

- On input, a reader MUST ignore case, spaces and dashes, and read `I` and
  `L` as `1` and `O` as `0`. It MUST verify the 2 byte checksum.
- The recovery key holds one MK: the one of the vault's current epoch (the
  epoch in the marker).
- `recover` builds the key set `{ (marker epoch, MK) }` and MUST verify the
  marker tag. If it does not match, nothing is written.
- During a rotation the marker still has the old epoch, so the old recovery
  key is the one checked against the marker.
- Unfinished rotation: after the marker tag is verified (epoch `e`),
  `recover` MUST walk the real tree (also into directories whose names do
  not decrypt). The rotation is unfinished if a real name that should be an
  encrypted name (short names not starting with `.`, with conflict prefix
  candidates, and the `.cd-name` of `.cd-cdl` entries) does not decrypt with
  `K_names[e]` under its parent's id, or a file header has an epoch other
  than `e`. Then `recover` MUST also get the new recovery key, MUST check it
  (a name decrypts with it, or a file of epoch `e+1` authenticates with it)
  and MUST write the key set `{e, e+1}`. Otherwise it writes `{e}`, also if
  the old key file held two keys.
- The recovery key is as powerful as the master key.

## 13. Test vectors

- `crates/crypto-drive-core/tests/kat.rs` holds known answer tests for the
  key derivation (with epoch and entry id), names, chunks, size block, key
  file, marker and recovery key.
- `scripts/kat/gen_vectors.py` is an independent Python implementation that
  creates the vectors. Use it to cross-check another implementation.
- `crates/crypto-drive-core/tests/golden/v1/plain/` and
  `crates/crypto-drive-core/tests/golden/v1/padded/` are two committed vaults
  (a `vault/` directory and a `key` file each) with a known password, one
  without and one with size padding. Every later version MUST be able to read
  both.
