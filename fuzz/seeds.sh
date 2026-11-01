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

# Copies the seed inputs into fuzz/corpus/<target>/seed-*: the golden vault
# files and the known-answer hex strings of crates/crypto-drive-core/tests/kat.rs.
# Only the seed-* files are committed.

set -eu
cd "$(dirname "$0")" || exit 1

GOLDEN="../crates/crypto-drive-core/tests/golden/v1"
KAT="../crates/crypto-drive-core/tests/kat.rs"

# kat_hex NAME: prints the hex string of `const NAME: &str = "...";`
# (the string may be on the next line).
kat_hex() {
  tr -d '\n' < "$KAT" | sed -E "s/.*const $1: &str =[[:space:]]*\"([0-9a-f]+)\".*/\1/"
}

# put TARGET NAME: reads bytes from stdin into corpus/TARGET/seed-NAME.
put() {
  mkdir -p "corpus/$1"
  cat > "corpus/$1/seed-$2"
}

# put_hex TARGET NAME HEX
put_hex() {
  local hex=$3 i
  for ((i = 0; i < ${#hex}; i += 2)); do
    printf "\\x${hex:i:2}"
  done | put "$1" "$2"
}

for kind in plain padded; do
  put key_file "golden-$kind" < "$GOLDEN/$kind/key"
  put vault_marker "golden-$kind" < "$GOLDEN/$kind/vault/.cd-vault"
done

put_hex key_file kat-1 "$(kat_hex KEY_FILE_1)"
put_hex key_file kat-1-2 "$(kat_hex KEY_FILE_1_2)"
put_hex key_set kat-1 "$(kat_hex KEY_SET_1)"
put_hex key_set kat-1-2 "$(kat_hex KEY_SET_1_2)"
put_hex vault_marker kat-flags-0 "$(kat_hex VAULT_MARKER_FLAGS_0)"
put_hex vault_marker kat-flags-1 "$(kat_hex VAULT_MARKER_FLAGS_1)"
put_hex content kat-header "$(kat_hex FILE_HEADER)"
put_hex content kat-chunk "$(kat_hex CHUNK)"
put_hex content kat-size-block "$(kat_hex SIZE_BLOCK)"
sed -nE 's/^const RECOVERY_KEY: &str = "([^"]+)";.*/\1/p' "$KAT" | tr -d '\n' | put recovery_key kat
sed -nE 's/^const NAME: &str = "([^"]+)";.*/\1/p' "$KAT" | tr -d '\n' | put names kat
sed -nE 's/^const LONG_ENTRY: &str = "([^"]+)";.*/\1/p' "$KAT" | tr -d '\n' | put conflict_names kat-long
for kind in plain padded; do
  # Real entry names of the golden vaults (short and long form) as text.
  n=0
  while IFS= read -r -d '' f; do
    n=$((n + 1))
    printf '%s' "$(basename "$f")" | put conflict_names "golden-$kind-$n"
  done < <(find "$GOLDEN/$kind/vault" -type f ! -name '.cd-dir' ! -name '.cd-vault' -print0 | sort -z)
  # Encrypted names (the .cd-name files) as text, file contents as bytes.
  n=0
  while IFS= read -r -d '' f; do
    n=$((n + 1))
    tr -d '\n' < "$f" | put names "golden-$kind-$n"
  done < <(find "$GOLDEN/$kind/vault" -type f -name '.cd-name' -print0 | sort -z)
  n=0
  while IFS= read -r -d '' f; do
    n=$((n + 1))
    put content "golden-$kind-$n" < "$f"
  done < <(find "$GOLDEN/$kind/vault" -type f ! -name '.cd-*' -print0 -o -type f -name '.cd-content' -print0 | sort -z)
done
