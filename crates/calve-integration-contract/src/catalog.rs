//! Signed-catalog package layout shared by the publisher (calve-extensions `xtask publish`) and
//! the host installer, so neither side carries its own copy of the format (ADR 0006).
//!
//! `<id>/package.json`:
//! `{"schema":"calve.package/1","id","versions":[{"version","kind",
//! "native":{"<target triple>":{"file","sha256"}},"cic"?,"metadata"?,"ui"?}]}`.
//! Native builds live at `<id>/<version>/<target triple>/<file>`, so builds for different
//! platforms never share a target path even when their file names are equal; every other file
//! lives at `<id>/<version>/<file>`.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const PACKAGE_SCHEMA: &str = "calve.package/1";

/// The exact Rust target triple this build runs on (e.g. `x86_64-unknown-linux-gnu`,
/// `x86_64-pc-windows-gnu`): the only key the installer selects a native build by.
pub const HOST_TARGET: &str = env!("CALVE_HOST_TARGET");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    OpenaevcOnly,
    CicCapable,
}

/// One native build: its file name and the sha256 of the executable. The installer requires the
/// TUF target hash, this digest and the handshake's `artifact_digest` to be equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuild {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionEntry {
    pub version: String,
    pub kind: Kind,
    /// Keyed by exact target triple.
    pub native: BTreeMap<String, NativeBuild>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIndex {
    pub schema: String,
    pub id: String,
    pub versions: Vec<VersionEntry>,
}

/// Target path of the native build for `target`.
pub fn native_path(id: &str, version: &str, target: &str, file: &str) -> String {
    format!("{id}/{version}/{target}/{file}")
}

/// Target triples: `[a-z0-9_.-]`, at least three `-`-separated parts, one path segment.
pub fn valid_target(t: &str) -> bool {
    t.len() <= 64
        && t.split('-').count() >= 3
        && t.split('-').all(|p| !p.is_empty())
        && t.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
        && !t.starts_with('.')
}

/// Lowercase hex sha256.
pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_target_is_a_valid_triple() {
        assert!(valid_target(HOST_TARGET), "{HOST_TARGET}");
        for bad in [
            "x86_64-linux",
            "../x-y-z",
            "a-b-C",
            "a--b-c",
            ".a-b-c",
            "a-b-c/d",
        ] {
            assert!(!valid_target(bad), "{bad}");
        }
    }

    #[test]
    fn native_builds_of_two_targets_never_share_a_path() {
        let a = native_path("org.x", "1.0.0", "x86_64-unknown-linux-gnu", "calve_ext_x");
        let b = native_path("org.x", "1.0.0", "x86_64-apple-darwin", "calve_ext_x");
        assert_ne!(a, b);
    }
}
