// crypto-drive
// Copyright (C) 2026  Marcel Joachim Kloubert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Clear paths inside the drive.

use crate::error::Result;
use crate::names::validate_name;
use unicode_normalization::UnicodeNormalization;

/// A clear path relative to the drive root. Every component is a valid name
/// in Unicode NFC, so two spellings of the same path are equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VPath(Vec<String>);

fn component(name: &str) -> Result<String> {
    validate_name(name)?;
    Ok(name.nfc().collect())
}

impl VPath {
    pub fn root() -> Self {
        VPath(Vec::new())
    }

    /// Parses "/a/b" or "a/b". "" and "/" are the root. Empty components
    /// (as in "a//b" or "a/") give `InvalidName`.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s.strip_prefix('/').unwrap_or(s);
        if rest.is_empty() {
            return Ok(Self::root());
        }
        rest.split('/')
            .map(component)
            .collect::<Result<Vec<_>>>()
            .map(VPath)
    }

    pub fn join(&self, name: &str) -> Result<Self> {
        let mut parts = self.0.clone();
        parts.push(component(name)?);
        Ok(VPath(parts))
    }

    pub fn parent(&self) -> Option<VPath> {
        let (_, head) = self.0.split_last()?;
        Some(VPath(head.to_vec()))
    }

    pub fn name(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// True if `other` is this path or one of its ancestors.
    pub fn starts_with(&self, other: &VPath) -> bool {
        self.0.starts_with(&other.0)
    }

    /// Replaces the leading `from` with `to`; `None` if `from` is no prefix.
    pub fn replace_prefix(&self, from: &VPath, to: &VPath) -> Option<VPath> {
        let rest = self.0.strip_prefix(from.0.as_slice())?;
        let mut parts = to.0.clone();
        parts.extend_from_slice(rest);
        Some(VPath(parts))
    }
}
