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

# Checks that every own .rs, .c, .sh, .py and .toml file starts with the AGPL header.

set -u
cd "$(dirname "$0")/.." || exit 1

HEADER='crypto-drive
Copyright (C) 2026  Marcel Joachim Kloubert

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.'

expected_for() {
  local marker=$1
  printf '%s\n' "$HEADER" | sed -E "s|^(.+)\$|${marker} \1|; s|^\$|${marker}|"
}

bad=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.rs | *.c) marker='//' ;;
    *) marker='#' ;;
  esac
  expected=$(expected_for "$marker")
  if [ "$file" != "${file%.sh}" ] && [ "$(head -n 1 "$file")" = '#!/usr/bin/env bash' ]; then
    actual=$(sed -n '2,16p' "$file")
  else
    actual=$(head -n 15 "$file")
  fi
  if [ "$actual" != "$expected" ]; then
    echo "bad license header: $file"
    bad=1
  fi
done < <(find . \( -name target -o -name .git -o -name .superpowers \) -prune -o \
  -path ./fuzz/target -prune -o -path ./fuzz/corpus -prune -o \
  -type f \( -name '*.rs' -o -name '*.c' -o -name '*.sh' -o -name '*.py' -o -name '*.toml' \) ! -name Cargo.lock -print0)

exit "$bad"
