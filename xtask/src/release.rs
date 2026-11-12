//! Release foundation (rev 12 §51, ADR 0021; M5 F): deterministic archives without the
//! platform's `tar`, per-target SBOMs with licenses, a license allowlist, combined checksums,
//! signed attestations and release verification.
//!
//! - Archives are ustar + gzip written in-process: sorted entries, fixed mode/owner/mtime
//!   (`SOURCE_DATE_EPOCH`), no gzip timestamp or name (R9: no GNU tar).
//! - `calve-<version>-<triple>.cdx.json` covers exactly the dependencies compiled into that
//!   target's binaries (feature-resolved `cargo tree`, normal dependencies; R7).
//! - Every shipped dependency's SPDX license expression must be satisfiable from [`ALLOWED`]
//!   (R13); `THIRD-PARTY-LICENSES.txt` in each archive lists them.
//! - An attestation is an in-toto v1 Statement (the subjects of one `SHA256SUMS-<triple>`, the
//!   source revision, `Cargo.lock` digest, toolchain and epoch) in a DSSE envelope signed with
//!   an ed25519 release key that never lives in a repository. Keyless (Sigstore/GitHub)
//!   provenance is added by the release workflow on top.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://calve.dev/release/v1";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// SPDX license identifiers a shipped dependency may use (with `OR` any satisfiable
/// alternative suffices; `AND` needs all).
pub const ALLOWED: &[&str] = &[
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "OpenSSL",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
];

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---- archives -------------------------------------------------------------------------------

/// One ustar header block for `path` (relative, `/`-separated, at most 100 bytes).
fn ustar_header(path: &str, size: u64, mode: u32, dir: bool, mtime: u64) -> Result<[u8; 512]> {
    if path.len() > 100 {
        return Err(format!("archive path too long: {path}").into());
    }
    let mut h = [0u8; 512];
    let octal = |h: &mut [u8; 512], at: usize, len: usize, v: u64| {
        let s = format!("{v:0w$o}\0", w = len - 1);
        h[at..at + len].copy_from_slice(s.as_bytes());
    };
    h[..path.len()].copy_from_slice(path.as_bytes());
    octal(&mut h, 100, 8, u64::from(mode));
    octal(&mut h, 108, 8, 0);
    octal(&mut h, 116, 8, 0);
    octal(&mut h, 124, 12, size);
    octal(&mut h, 136, 12, mtime);
    h[156] = if dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    Ok(h)
}

/// A deterministic `.tar.gz`: `name/` then each file (sorted) under it; binaries 0755, other
/// files 0644, owner 0, mtime `epoch`; gzip with no timestamp or file name.
pub fn archive(
    dist: &Path,
    name: &str,
    files: &[(PathBuf, String, bool)],
    epoch: u64,
) -> Result<PathBuf> {
    let mut sorted: Vec<&(PathBuf, String, bool)> = files.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    let mut tar = Vec::new();
    tar.extend_from_slice(&ustar_header(&format!("{name}/"), 0, 0o755, true, epoch)?);
    for (source, file, executable) in sorted {
        let bytes = fs::read(source).map_err(|e| format!("{}: {e}", source.display()))?;
        let mode = if *executable { 0o755 } else { 0o644 };
        tar.extend_from_slice(&ustar_header(
            &format!("{name}/{file}"),
            bytes.len() as u64,
            mode,
            false,
            epoch,
        )?);
        tar.extend_from_slice(&bytes);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), flate2::Compression::best());
    gz.write_all(&tar)?;
    let path = dist.join(format!("{name}.tar.gz"));
    fs::write(&path, gz.finish()?)?;
    Ok(path)
}

/// Unpacks an archive written by [`archive`] into `into` (verification only).
pub fn unpack(archive: &Path, into: &Path) -> Result {
    let mut tar = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(fs::File::open(archive)?),
        &mut tar,
    )?;
    let mut at = 0;
    while at + 512 <= tar.len() && tar[at..at + 512].iter().any(|b| *b != 0) {
        let h = &tar[at..at + 512];
        let name = std::str::from_utf8(&h[..100])?.trim_end_matches('\0');
        if name.split('/').any(|c| c == "..") || name.starts_with('/') {
            return Err(format!("unsafe archive path {name}").into());
        }
        let field = |r: std::ops::Range<usize>| -> Result<u64> {
            let s = std::str::from_utf8(&h[r])?.trim_matches(|c| c == '\0' || c == ' ');
            Ok(u64::from_str_radix(s, 8)?)
        };
        let size = field(124..136)? as usize;
        let mode = field(100..108)? as u32;
        at += 512;
        let out = into.join(name);
        if h[156] == b'5' {
            fs::create_dir_all(&out)?;
        } else {
            fs::write(&out, &tar[at..at + size])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out, fs::Permissions::from_mode(mode))?;
            }
            let _ = mode;
            at += size.div_ceil(512) * 512;
        }
    }
    Ok(())
}

// ---- dependencies, SBOM, licenses -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub source: String,
    pub checksum: Option<String>,
}

/// The packages compiled into `root_package`'s binaries for `target`: its normal dependencies
/// in the feature-resolved graph (`cargo tree -e normal,no-proc-macro`), i.e. exactly what the
/// build links. (`cargo metadata`'s resolve also lists optional dependencies no enabled feature
/// activates, e.g. ratatui's termwiz backend, so it over-reports.) Proc macros run only at
/// build time and are excluded; workspace crates are recorded with source `workspace`, never a
/// local path.
pub fn shipped_packages(
    workspace: &Path,
    root_package: &str,
    target: &str,
) -> Result<Vec<Package>> {
    let out = std::process::Command::new("cargo")
        .current_dir(workspace)
        .args([
            "tree",
            "--locked",
            "-p",
            root_package,
            "-e",
            "normal,no-proc-macro",
            "--target",
            target,
            "--prefix",
            "none",
            "--format",
            "{p}|{l}",
        ])
        .output()?;
    if !out.status.success() {
        return Err(format!("cargo tree: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    let lock: toml::Value = fs::read_to_string(workspace.join("Cargo.lock"))?.parse()?;
    let locked: BTreeMap<(String, String), (String, Option<String>)> = lock["package"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            Some((
                (
                    p.get("name")?.as_str()?.to_owned(),
                    p.get("version")?.as_str()?.to_owned(),
                ),
                (
                    p.get("source")
                        .and_then(|s| s.as_str())
                        .unwrap_or("workspace")
                        .to_owned(),
                    p.get("checksum")
                        .and_then(|c| c.as_str())
                        .map(str::to_owned),
                ),
            ))
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut packages = Vec::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        let line = line.trim_end_matches(" (*)").trim();
        let Some((pkg, license)) = line.rsplit_once('|') else {
            continue;
        };
        let mut parts = pkg.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let version = version.trim_start_matches('v').to_owned();
        if name == root_package || !seen.insert((name.to_owned(), version.clone())) {
            continue;
        }
        let (source, checksum) = locked
            .get(&(name.to_owned(), version.clone()))
            .cloned()
            .ok_or_else(|| format!("{name} {version} is not in Cargo.lock"))?;
        packages.push(Package {
            name: name.to_owned(),
            version,
            license: (!license.trim().is_empty()).then(|| license.trim().to_owned()),
            source,
            checksum,
        });
    }
    packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(packages)
}

/// Whether an SPDX expression (`/` read as `OR`, as old Cargo manifests use it) is satisfiable
/// from `allowed`.
pub fn license_allowed(expression: &str, allowed: &[&str]) -> bool {
    let spaced = expression
        .replace('/', " OR ")
        .replace('(', " ( ")
        .replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    fn expr(t: &[&str], i: &mut usize, allowed: &[&str]) -> Option<bool> {
        let mut v = term(t, i, allowed)?;
        while t.get(*i) == Some(&"OR") {
            *i += 1;
            let r = term(t, i, allowed)?;
            v = v || r;
        }
        Some(v)
    }
    fn term(t: &[&str], i: &mut usize, allowed: &[&str]) -> Option<bool> {
        let mut v = factor(t, i, allowed)?;
        while t.get(*i) == Some(&"AND") {
            *i += 1;
            let r = factor(t, i, allowed)?;
            v = v && r;
        }
        Some(v)
    }
    fn factor(t: &[&str], i: &mut usize, allowed: &[&str]) -> Option<bool> {
        let tok = *t.get(*i)?;
        *i += 1;
        if tok == "(" {
            let v = expr(t, i, allowed)?;
            (t.get(*i) == Some(&")")).then(|| *i += 1)?;
            return Some(v);
        }
        if matches!(tok, ")" | "AND" | "OR" | "WITH") {
            return None;
        }
        // `X WITH exception`: an exception only adds permissions to X.
        if t.get(*i) == Some(&"WITH") {
            *i += 2;
        }
        Some(allowed.contains(&tok))
    }
    let mut i = 0;
    expr(&tokens, &mut i, allowed).is_some_and(|v| v) && i == tokens.len()
}

/// Shipped packages whose license is missing or not satisfiable from [`ALLOWED`].
pub fn license_violations(packages: &[Package]) -> Vec<String> {
    packages
        .iter()
        .filter(|p| {
            !p.license
                .as_deref()
                .is_some_and(|l| license_allowed(l, ALLOWED))
        })
        .map(|p| {
            format!(
                "{} {}: {}",
                p.name,
                p.version,
                p.license.as_deref().unwrap_or("no license expression")
            )
        })
        .collect()
}

/// CycloneDX 1.5 SBOM of the packages shipped for one target.
pub fn sbom(packages: &[Package], version: &str, target: &str) -> Value {
    let components: Vec<Value> = packages
        .iter()
        .map(|p| {
            let mut c = json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": format!("pkg:cargo/{}@{}", p.name, p.version),
                "properties": [{"name": "cargo:source", "value": p.source}],
            });
            if let Some(l) = &p.license {
                c["licenses"] = json!([{"expression": l}]);
            }
            if let Some(sum) = &p.checksum {
                c["hashes"] = json!([{"alg": "SHA-256", "content": sum}]);
            }
            c
        })
        .collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "calve", "version": version},
            "properties": [{"name": "calve:target", "value": target}],
        },
        "components": components,
    })
}

pub fn license_inventory(packages: &[Package]) -> String {
    let mut out = String::from(
        "Third-party packages compiled into this build (name, version, SPDX license, source).\n\n",
    );
    for p in packages {
        out.push_str(&format!(
            "{} {}\t{}\t{}\n",
            p.name,
            p.version,
            p.license.as_deref().unwrap_or("?"),
            p.source
        ));
    }
    out
}

// ---- checksums, attestations ----------------------------------------------------------------

/// Parses a `SHA256SUMS` file into `file → digest`.
pub fn parse_sums(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (digest, file) = line
            .split_once("  ")
            .ok_or_else(|| format!("bad checksum line: {line}"))?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("bad digest in: {line}").into());
        }
        if file.contains('/') || file.contains('\\') || file.starts_with('.') {
            return Err(format!("bad file name in: {line}").into());
        }
        if out.insert(file.to_owned(), digest.to_owned()).is_some() {
            return Err(format!("{file} listed twice").into());
        }
    }
    Ok(out)
}

pub fn render_sums(sums: &BTreeMap<String, String>) -> String {
    sums.iter().map(|(f, d)| format!("{d}  {f}\n")).collect()
}

/// DSSE pre-authentication encoding.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

pub fn key_id(key: &VerifyingKey) -> String {
    sha256_hex(key.as_bytes())
}

/// A DSSE envelope over an in-toto Statement for `subjects` (`file → sha256`).
pub fn attest(key: &SigningKey, subjects: &BTreeMap<String, String>, predicate: Value) -> Value {
    let statement = json!({
        "_type": STATEMENT_TYPE,
        "subject": subjects.iter().map(|(name, digest)| json!({"name": name, "digest": {"sha256": digest}})).collect::<Vec<_>>(),
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    });
    let payload = serde_json::to_vec(&statement).expect("statement serializes");
    let sig = key.sign(&pae(PAYLOAD_TYPE, &payload));
    json!({
        "payloadType": PAYLOAD_TYPE,
        "payload": b64(&payload),
        "signatures": [{"keyid": key_id(&key.verifying_key()), "sig": b64(&sig.to_bytes())}],
    })
}

/// Verifies `envelope` with `key`; returns its Statement.
pub fn verify_attestation(envelope: &Value, key: &VerifyingKey) -> Result<Value> {
    if envelope["payloadType"] != PAYLOAD_TYPE {
        return Err("attestation: unexpected payload type".into());
    }
    let payload = unb64(envelope["payload"].as_str().ok_or("attestation: payload")?)?;
    let message = pae(PAYLOAD_TYPE, &payload);
    let ok = envelope["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| {
            s["keyid"] == key_id(key)
                && s["sig"]
                    .as_str()
                    .and_then(|sig| unb64(sig).ok())
                    .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                    .is_some_and(|sig| key.verify(&message, &sig).is_ok())
        });
    if !ok {
        return Err("attestation: no valid signature by the release key".into());
    }
    let statement: Value = serde_json::from_slice(&payload)?;
    if statement["_type"] != STATEMENT_TYPE || statement["predicateType"] != PREDICATE_TYPE {
        return Err("attestation: not a Calve release statement".into());
    }
    Ok(statement)
}

pub fn read_hex_key(path: &Path) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path)?;
    let bytes = hex_decode(text.trim())?;
    bytes
        .try_into()
        .map_err(|_| format!("{} is not 32 bytes of hex", path.display()).into())
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_expressions() {
        let ok = |e| license_allowed(e, ALLOWED);
        assert!(ok("MIT"));
        assert!(ok("MIT OR Apache-2.0"));
        assert!(ok("MIT/Apache-2.0"));
        assert!(ok("Apache-2.0 WITH LLVM-exception"));
        assert!(ok("(MIT OR Apache-2.0) AND Unicode-3.0"));
        assert!(ok("GPL-3.0 OR MIT"));
        assert!(!ok("GPL-3.0"));
        assert!(!ok("MIT AND GPL-2.0"));
        assert!(!ok("MIT OR"));
        assert!(!ok("(MIT"));
        assert!(!ok(""));
    }

    #[test]
    fn archives_are_deterministic_and_round_trip() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("b"), b"bee").unwrap();
        fs::write(d.path().join("a"), vec![7u8; 1000]).unwrap();
        let files = vec![
            (d.path().join("b"), "b".to_owned(), true),
            (d.path().join("a"), "a.txt".to_owned(), false),
        ];
        let out1 = tempfile::tempdir().unwrap();
        let out2 = tempfile::tempdir().unwrap();
        let a1 = archive(out1.path(), "pkg-1", &files, 1_700_000_000).unwrap();
        let mut rev = files.clone();
        rev.reverse();
        let a2 = archive(out2.path(), "pkg-1", &rev, 1_700_000_000).unwrap();
        assert_eq!(fs::read(&a1).unwrap(), fs::read(&a2).unwrap());
        let x = tempfile::tempdir().unwrap();
        unpack(&a1, x.path()).unwrap();
        assert_eq!(fs::read(x.path().join("pkg-1/b")).unwrap(), b"bee");
        assert_eq!(
            fs::read(x.path().join("pkg-1/a.txt")).unwrap(),
            vec![7u8; 1000]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = |p: &str| fs::metadata(x.path().join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!((m("pkg-1/b"), m("pkg-1/a.txt")), (0o755, 0o644));
        }
        // The system tar reads it too (when present).
        if let Ok(o) = std::process::Command::new("tar")
            .arg("-tzf")
            .arg(&a1)
            .output()
            && o.status.success()
        {
            let listing = String::from_utf8_lossy(&o.stdout);
            assert_eq!(
                listing.lines().collect::<Vec<_>>(),
                ["pkg-1/", "pkg-1/a.txt", "pkg-1/b"]
            );
        }
    }

    #[test]
    fn attestations_verify_and_refuse_tampering() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let subjects = BTreeMap::from([("calve.tar.gz".to_owned(), "ab".repeat(32))]);
        let env = attest(&key, &subjects, json!({"target": "x"}));
        let st = verify_attestation(&env, &key.verifying_key()).unwrap();
        assert_eq!(st["subject"][0]["digest"]["sha256"], "ab".repeat(32));
        assert!(verify_attestation(&env, &other.verifying_key()).is_err());
        let mut tampered = env.clone();
        let mut payload: Value =
            serde_json::from_slice(&unb64(env["payload"].as_str().unwrap()).unwrap()).unwrap();
        payload["subject"][0]["digest"]["sha256"] = json!("cd".repeat(32));
        tampered["payload"] = json!(b64(&serde_json::to_vec(&payload).unwrap()));
        assert!(verify_attestation(&tampered, &key.verifying_key()).is_err());
    }

    #[test]
    fn checksum_files_are_strict() {
        let d = "a".repeat(64);
        assert!(parse_sums(&format!("{d}  calve.tar.gz\n")).is_ok());
        assert!(parse_sums(&format!("{d}  ../x\n")).is_err());
        assert!(parse_sums(&format!("{d}  x\n{d}  x\n")).is_err());
        assert!(parse_sums("abc  x\n").is_err());
    }
}

/// Environment names that only debug builds may read.
const TEST_HOOKS: &[&str] = &[
    "CALVE_TEST_RUNTIME_PROTOCOL",
    "CALVE_TEST_ENOSPC",
    "CALVE_TEST_PAUSE",
    "CALVE_TEST_WRITE",
    "CALVE_FAULT",
    "CALVE_FS_PRIMITIVES",
    "CALVE_REPLAY_WINDOW_MS",
    "CALVE_HELPER_DELAY_MS",
    "CALVE_TEST_NAMESPACE",
    "CALVE_TEST_DATA_ROOT",
    "CALVE_TEST_CONFIG_ROOT",
    "CALVE_KEEP_SPAWN_RECORDS",
    "CALVE_TEST_NO_LEASE_KEEPER",
    "CALVE_JSON_RECORD",
    "CALVE_SANDBOX_PROGRAM",
];

/// The first test hook named in a binary.
pub fn forbidden_hook(binary: &[u8]) -> Option<&'static str> {
    TEST_HOOKS
        .iter()
        .find(|hook| binary.windows(hook.len()).any(|w| w == hook.as_bytes()))
        .copied()
}

#[cfg(test)]
mod hook_tests {
    use super::forbidden_hook;

    #[test]
    fn a_binary_naming_a_test_hook_is_refused() {
        assert_eq!(forbidden_hook(b"plain binary"), None);
        assert_eq!(
            forbidden_hook(b"x\0CALVE_TEST_RUNTIME_PROTOCOL\0y"),
            Some("CALVE_TEST_RUNTIME_PROTOCOL")
        );
    }
}
