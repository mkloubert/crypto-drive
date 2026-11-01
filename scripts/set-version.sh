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

# Sets the version of all workspace crates, for example from a git tag.
# The git tag is the single source of truth for the version; the value in
# the repository is only a placeholder for local builds.
#
# Usage: scripts/set-version.sh <X.Y.Z | vX.Y.Z>
#
# Changes `version` in [workspace.package] of Cargo.toml and the entries of
# the workspace crates in Cargo.lock, so `cargo build --locked` still works
# without network access. Works with bash 3.2 (macOS) and newer.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <X.Y.Z | vX.Y.Z>" >&2
    exit 2
fi

VERSION="${1#v}"
if ! printf '%s' "$VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "error: not a version of the form X.Y.Z: $1" >&2
    exit 2
fi

# Cargo.toml: only the `version` line inside [workspace.package].
VERSION="$VERSION" perl -0pi -e '
    s/(\[workspace\.package\][^\[]*?\nversion = ")[^"]*(")/${1}$ENV{VERSION}${2}/
        or die "no version in [workspace.package]\n"
' Cargo.toml

# Cargo.lock: the entries of the workspace crates (no registry source).
for crate in crypto-drive crypto-drive-core crypto-drive-fuse; do
    CRATE="$crate" VERSION="$VERSION" perl -0pi -e '
        s/(\[\[package\]\]\nname = "\Q$ENV{CRATE}\E"\nversion = ")[^"]*(")/${1}$ENV{VERSION}${2}/
            or die "no entry for $ENV{CRATE} in Cargo.lock\n"
    ' Cargo.lock
done

echo "version set to $VERSION"
