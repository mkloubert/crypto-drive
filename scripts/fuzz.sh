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

# Runs one fuzz target (or all of them) with cargo-fuzz.
# Usage: scripts/fuzz.sh <target|all> [seconds=60]
# Needs the pinned nightly toolchain and cargo-fuzz (see README, "Fuzzing").

set -eu
cd "$(dirname "$0")/../fuzz" || exit 1

TOOLCHAIN="nightly-2026-10-15"
TARGETS="key_file key_set vault_marker recovery_key names conflict_names content hostile_tree fs_ops"
# AddressSanitizer is the cargo-fuzz default. Set FUZZ_SANITIZER=none if it
# cannot be linked on your machine (Rust is memory safe; we fuzz mostly for
# panics, hangs and memory blow-ups).
SANITIZER="${FUZZ_SANITIZER:-address}"

target="${1:-}"
seconds="${2:-60}"
if [ -z "$target" ]; then
  echo "usage: scripts/fuzz.sh <target|all> [seconds=60]" >&2
  exit 2
fi
if [ "$target" = all ]; then
  list="$TARGETS"
else
  list="$target"
fi

for t in $list; do
  mkdir -p "corpus/$t"
  echo "== fuzzing $t for ${seconds}s"
  cargo "+$TOOLCHAIN" fuzz run --sanitizer "$SANITIZER" "$t" "corpus/$t" -- \
    "-max_total_time=$seconds" -rss_limit_mb=2048 -timeout=10
done
