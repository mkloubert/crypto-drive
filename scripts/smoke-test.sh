#!/usr/bin/env bash
# crypto-drive
# Copyright (C) 2026  Marcel Joachim Kloubert
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# Smoke test on a real mount. Needs FUSE (macFUSE on macOS, fuse3 on Linux).
# Works with bash 3.2 (macOS) and newer.
#
# Usage:   scripts/smoke-test.sh
# Options (environment variables):
#   CRYPTO_DRIVE_BIN  path to the binary (default: target/release/crypto-drive)
#   SMOKE_BIG_MB      size of the big file in MiB (default: 300)
#   SMOKE_MOUNT_OPTS  extra mount options (comma separated FUSE options)

set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${CRYPTO_DRIVE_BIN:-target/release/crypto-drive}"
BIG_MB="${SMOKE_BIG_MB:-300}"
PASSWORD="smoke-test-password"
# Cheapest allowed Argon2 values, so the test stays fast.
ARGON=(--argon2-memory 19456 --argon2-iterations 2 --argon2-parallelism 1)
MOUNT_OPTS=()
if [ -n "${SMOKE_MOUNT_OPTS:-}" ]; then
    MOUNT_OPTS=(-o "$SMOKE_MOUNT_OPTS")
fi

if [ ! -x "$BIN" ]; then
    echo "Binary not found: $BIN (run: cargo build --release, or set CRYPTO_DRIVE_BIN)" >&2
    exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/crypto-drive-smoke.XXXXXX")"
VAULT="$WORK/vault"
# Without --key-file, init would write to ~/.crypto-drive/keys.
KEY="$WORK/vault.cd-key"
MNT="$WORK/mnt"
SRC="$WORK/src"
OUT="$WORK/out"
MOUNTED=0

cleanup() {
    status=$?
    set +e
    if [ "$MOUNTED" = 1 ]; then
        if ! "$BIN" unmount "$MNT" >/dev/null 2>&1 && ! "$BIN" unmount --force "$MNT" >/dev/null 2>&1; then
            echo "Could not unmount $MNT. Unmount it by hand, then remove $WORK" >&2
            exit "$([ "$status" -ne 0 ] && echo "$status" || echo 1)"
        fi
    fi
    rm -rf "$WORK"
    if [ "$status" -ne 0 ]; then
        echo "FAIL (exit code $status)" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

ok() {
    echo "OK $1"
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
    else
        sha256sum "$@"
    fi
}

# Prints "<hash>  <relative path>" for every file below $1, in a stable order.
manifest() {
    (
        cd "$1"
        find . -type f | LC_ALL=C sort | while IFS= read -r f; do
            sha256 "$f"
        done
    )
}

mount_vault() {
    "$BIN" mount "$VAULT" "$MNT" --key-file "$KEY" --daemon ${MOUNT_OPTS[@]+"${MOUNT_OPTS[@]}"} --password-fd 3 3<<<"$PASSWORD" || return 1
    MOUNTED=1
}

unmount_vault() {
    "$BIN" unmount "$MNT"
    MOUNTED=0
}

# Runs "$BIN" with the arguments, the password on fd 3. After an unmount the
# old daemon may still hold the vault lock while it exits, so the command is
# tried again (up to 20 times) as long as it fails with "already mounted". Any
# other error stops the test at once.
run_when_unlocked() {
    tries=0
    while :; do
        if "$BIN" "$@" 3<<<"$PASSWORD" 2>"$WORK/lock.err"; then
            return 0
        fi
        if grep -q "already mounted" "$WORK/lock.err"; then
            tries=$((tries + 1))
            if [ "$tries" -lt 20 ]; then
                sleep 0.5
                continue
            fi
        fi
        cat "$WORK/lock.err" >&2
        echo "Command failed: $1 (after $tries lock retries)" >&2
        return 1
    done
}

run_round() {
    PAD_FLAG="$1"
    if [ -n "$PAD_FLAG" ]; then
        echo "== round: pad=on =="
    else
        echo "== round: pad=off =="
    fi
    rm -rf "$VAULT" "$SRC" "$OUT"
    mkdir -p "$MNT" "$SRC" "$OUT"

    # 1. Create the vault.
    rm -f "$KEY"
    "$BIN" init "$VAULT" --key-file "$KEY" $PAD_FLAG ${ARGON[@]+"${ARGON[@]}"} --new-password-fd 3 3<<<"$PASSWORD" >/dev/null
    ok "init $PAD_FLAG"

    # 2. Mount it in the background.
    mount_vault
    ok mount

    # 3. Source tree outside the drive: 100 small files and one big file.
    mkdir -p "$SRC/small"
    i=1
    while [ "$i" -le 100 ]; do
        n="$(printf '%03d' "$i")"
        printf 'small file %s\n' "$n" >"$SRC/small/file-$n.txt"
        i=$((i + 1))
    done
    dd if=/dev/urandom of="$SRC/big.bin" bs=1048576 count="$BIG_MB" 2>/dev/null
    LONG="$(printf '%0200d' 0 | tr 0 a)"
    mkdir -p "$SRC/deep/$LONG/level2/level3"
    printf 'deep content\n' >"$SRC/deep/$LONG/level2/level3/deep.txt"

    # 4. Write them into the drive.
    mkdir "$MNT/small"
    for f in "$SRC"/small/*; do
        cp "$f" "$MNT/small/"
    done
    ok create-100-small-files

    cp "$SRC/big.bin" "$MNT/big.bin"
    ok create-big-file

    mkdir -p "$MNT/deep/$LONG/level2/level3"
    cp "$SRC/deep/$LONG/level2/level3/deep.txt" "$MNT/deep/$LONG/level2/level3/"
    ok create-deep-tree-with-long-name

    # 5. Rename a directory (on both sides).
    mv "$MNT/deep" "$MNT/deep-renamed"
    mv "$SRC/deep" "$SRC/deep-renamed"
    ok rename-directory

    # 6. Compare checksums.
    manifest "$SRC" >"$WORK/expected.txt"
    manifest "$MNT" >"$WORK/actual.txt"
    diff "$WORK/expected.txt" "$WORK/actual.txt"
    ok checksums-after-write

    # 7. rsync in and out.
    if ! command -v rsync >/dev/null 2>&1; then
        echo "rsync is required for this test but was not found" >&2
        exit 1
    fi
    {
        mkdir -p "$MNT/rsync-copy"
        rsync -a --exclude big.bin "$SRC/" "$MNT/rsync-copy/"
        rsync -a "$MNT/rsync-copy/" "$OUT/"
        # The round trip must match the source (without the big file).
        diff -r -x big.bin "$SRC" "$OUT"
        rm -rf "$OUT"
        ok rsync-in-and-out
    }

    # 7b. Copy a file that has an extended attribute. The drive keeps
    # xattrs in memory only; copy tools must copy the whole content, and a
    # set xattr must be readable again (Finder reads its own markers back).
    XSRC="$WORK/xattr-src"
    rm -rf "$XSRC"
    mkdir -p "$XSRC" "$MNT/xattr-copy"
    dd if=/dev/urandom of="$XSRC/x.bin" bs=1024 count=300 2>/dev/null
    if [ "$(uname)" = Darwin ]; then
        xattr -w com.apple.quarantine "0081;00000000;smoke-test;" "$XSRC/x.bin"
    fi
    want="$(sha256 "$XSRC/x.bin" | cut -d' ' -f1)"
    cp "$XSRC/x.bin" "$MNT/xattr-copy/cp.bin"
    [ "$(sha256 "$MNT/xattr-copy/cp.bin" | cut -d' ' -f1)" = "$want" ]
    if [ "$(uname)" = Darwin ]; then
        ditto "$XSRC/x.bin" "$MNT/xattr-copy/ditto.bin"
        [ "$(sha256 "$MNT/xattr-copy/ditto.bin" | cut -d' ' -f1)" = "$want" ]
    fi
    if [ "$(uname)" = Darwin ]; then
        xattr -w com.apple.finder.copy.source marker "$MNT/xattr-copy"
        [ "$(xattr -p com.apple.finder.copy.source "$MNT/xattr-copy")" = marker ]
        # macOS may rewrite the quarantine value while copying, so only
        # check that it arrived.
        xattr -p com.apple.quarantine "$MNT/xattr-copy/ditto.bin" >/dev/null
    elif command -v setfattr >/dev/null 2>&1; then
        setfattr -n user.smoke -v marker "$MNT/xattr-copy/cp.bin"
        [ "$(getfattr --only-values -n user.smoke "$MNT/xattr-copy/cp.bin")" = marker ]
    fi
    # Finder aborts a folder copy if it cannot write the .DS_Store of the
    # source, so it must be writable. The drive supports xattrs, so macOS
    # must not create ._ files for them.
    printf 'view settings' >"$MNT/xattr-copy/.DS_Store"
    [ "$(cat "$MNT/xattr-copy/.DS_Store")" = "view settings" ]
    [ -z "$(find "$MNT/xattr-copy" -name '._*')" ]
    rm -rf "$MNT/xattr-copy" "$XSRC"
    ok copy-with-xattrs

    # 8. Unmount, mount again, verify again.
    unmount_vault
    ok unmount
    # The old daemon may still hold the vault lock while it exits.
    tries=0
    until mount_vault 2>"$WORK/remount.err"; do
        tries=$((tries + 1))
        if [ "$tries" -ge 20 ]; then
            cat "$WORK/remount.err" >&2
            echo "Could not mount again after $tries tries" >&2
            exit 1
        fi
        sleep 0.5
    done
    ok mount-again
    manifest "$MNT/small" >"$WORK/actual-small.txt"
    manifest "$SRC/small" >"$WORK/expected-small.txt"
    diff "$WORK/expected-small.txt" "$WORK/actual-small.txt"
    want="$(sha256 "$SRC/big.bin" | cut -d' ' -f1)"
    have="$(sha256 "$MNT/big.bin" | cut -d' ' -f1)"
    [ "$want" = "$have" ]
    ok checksums-after-remount
    unmount_vault

    # 9. The vault must be healthy.
    run_when_unlocked check "$VAULT" --key-file "$KEY" --password-fd 3
    ok check

    # 10. Rotate the master key (unmounted), then compare everything again.
    run_when_unlocked rotate-key "$VAULT" --key-file "$KEY" --yes --password-fd 3 >/dev/null
    ok rotate-key
    "$BIN" check "$VAULT" --key-file "$KEY" --password-fd 3 3<<<"$PASSWORD"
    ok check-after-rotation
    tries=0
    until mount_vault 2>"$WORK/remount.err"; do
        tries=$((tries + 1))
        if [ "$tries" -ge 20 ]; then
            cat "$WORK/remount.err" >&2
            echo "Could not mount after the rotation ($tries tries)" >&2
            exit 1
        fi
        sleep 0.5
    done
    ok mount-after-rotation
    manifest "$MNT/small" >"$WORK/actual-small.txt"
    diff "$WORK/expected-small.txt" "$WORK/actual-small.txt"
    have="$(sha256 "$MNT/big.bin" | cut -d' ' -f1)"
    [ "$want" = "$have" ]
    manifest "$MNT/deep-renamed" >"$WORK/actual-deep.txt"
    manifest "$SRC/deep-renamed" >"$WORK/expected-deep.txt"
    diff "$WORK/expected-deep.txt" "$WORK/actual-deep.txt"
    ok checksums-after-rotation
    unmount_vault
}

# Run everything twice: a normal vault and one made with --pad-sizes.
for PAD in "" "--pad-sizes"; do
    run_round "$PAD"
done

echo "All smoke tests passed."
