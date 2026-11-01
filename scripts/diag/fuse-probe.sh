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

# Diagnostic only (macOS): builds scripts/diag/fuse_probe.c against libfuse2
# and libfuse3 and tries to mount it with the kernel backend and with
# -o backend=fskit. Prints MOUNTED / NOT MOUNTED and the first lines of the
# libfuse debug output for each case. Needs a C compiler (Xcode command line
# tools) and pkg-config. Does not touch any vault.

set -u
cd "$(dirname "$0")/../.."

SRC=scripts/diag/fuse_probe.c
DIR=$(mktemp -d "$HOME/cd-fuse-probe.XXXXXX")
trap 'umount "$DIR/mp" 2>/dev/null; rm -rf "$DIR"' EXIT

for v in 2; do
    pc=fuse
    if [ "$v" = 3 ]; then pc=fuse3; fi
    echo "### build against libfuse$v ($(pkg-config --modversion "$pc" 2>/dev/null || echo 'not found'))"
    # shellcheck disable=SC2046
    if ! cc -DPROBE_FUSE="$v" "$SRC" $(pkg-config --cflags --libs "$pc") -o "$DIR/probe$v"; then
        echo "build failed"
        continue
    fi
    for backend in kext fskit; do
        opts=""
        if [ "$backend" = fskit ]; then opts="-o backend=fskit"; fi
        mkdir -p "$DIR/mp"
        echo "=== libfuse$v, backend $backend ==="
        # shellcheck disable=SC2086
        "$DIR/probe$v" -f -d $opts "$DIR/mp" >"$DIR/log" 2>&1 &
        pid=$!
        sleep 3
        if mount | grep -q "cd-fuse-probe"; then
            echo "MOUNTED"
            umount "$DIR/mp" 2>/dev/null
        else
            echo "NOT MOUNTED"
        fi
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        echo "--- libfuse output (first 25 lines) ---"
        head -25 "$DIR/log"
        echo
    done
done

echo "### direct mount API calls (libfuse2), the way fuser mounts"
if cc -DPROBE_FUSE=2 scripts/diag/mount_api_probe.c $(pkg-config --cflags --libs fuse) -o "$DIR/apiprobe"; then
    for mode in compat25 mount; do
        for backend in kext fskit; do
            mkdir -p "$DIR/mp"
            echo "=== $mode, backend $backend ==="
            if [ "$backend" = fskit ]; then
                "$DIR/apiprobe" "$mode" "$DIR/mp" -o backend=fskit 2>&1 | head -15
            else
                "$DIR/apiprobe" "$mode" "$DIR/mp" 2>&1 | head -15
            fi
            umount "$DIR/mp" 2>/dev/null
        done
    done
else
    echo "build failed"
fi
