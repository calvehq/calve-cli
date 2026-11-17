//! tuf-conformance client-under-test for Calve's production catalog transport
//! (`calve_app::catalog::tuf::Mirror`) and verifier (sigstore-tuf =0.15.0),
//! not the crate's reqwest client. Calve's catalog policy is NOT applied here (the suite uses
//! key types and repositories the policy forbids); policy is tested separately (tests/policy.rs).
//! Mirrors the CLI protocol of sigstore-tuf's own conformance example.

use std::path::{Path, PathBuf};

use calve_app::catalog::tuf::{DEFAULT_TIMEOUT, Mirror, sha};
use sigstore_tuf::cache::MetadataStore;
use sigstore_tuf::{Error, Result, Updater};

struct Store(PathBuf);

impl MetadataStore for Store {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.0.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::transport(format!("reading {name}: {e}"))),
        }
    }
    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        // The harness inspects exactly the trusted set under canonical names.
        let stem = name.split('.').next().unwrap_or("");
        if name.contains('/') || (!stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit())) {
            return Ok(());
        }
        std::fs::write(self.0.join(name), bytes)
            .map_err(|e| Error::transport(format!("writing {name}: {e}")))
    }
}

fn main() {
    let mut a = std::env::args().skip(1);
    let (mut dir, mut url, mut tdir, mut tbase, mut names, mut pos) =
        (None, None, None, None, vec![], vec![]);
    while let Some(t) = a.next() {
        match t.as_str() {
            "--metadata-dir" => dir = a.next(),
            "--metadata-url" => url = a.next(),
            "--target-dir" => tdir = a.next(),
            "--target-base-url" => tbase = a.next(),
            "--target-name" => names.push(a.next().unwrap_or_default()),
            "-v" | "--verbose" => {}
            _ => pos.push(t),
        }
    }
    let r = run(
        dir.map(PathBuf::from),
        url,
        tdir.map(PathBuf::from),
        tbase,
        names,
        pos,
    );
    if let Err(e) = r {
        eprintln!("conformance-client: {e}");
        std::process::exit(1);
    }
}

fn run(
    dir: Option<PathBuf>,
    url: Option<String>,
    tdir: Option<PathBuf>,
    tbase: Option<String>,
    names: Vec<String>,
    pos: Vec<String>,
) -> Result<()> {
    let dir = dir.ok_or_else(|| Error::transport("--metadata-dir required"))?;
    match pos.first().map(String::as_str) {
        Some("init") => {
            let b = std::fs::read(pos.get(1).ok_or_else(|| Error::transport("init ROOT"))?)
                .map_err(|e| Error::transport(e.to_string()))?;
            sigstore_tuf::TrustedMetadataSet::from_root(&b)?;
            std::fs::write(dir.join("root.json"), b).map_err(|e| Error::transport(e.to_string()))
        }
        Some(cmd @ ("refresh" | "download")) => {
            let url = url.ok_or_else(|| Error::transport("--metadata-url required"))?;
            let root = std::fs::read(dir.join("root.json"))
                .map_err(|e| Error::transport(e.to_string()))?;
            let m = Mirror::http(
                &url,
                tbase
                    .as_deref()
                    .unwrap_or(&format!("{}/targets/", url.trim_end_matches('/'))),
                DEFAULT_TIMEOUT,
            );
            let mut u = Updater::new(m, &root)?.with_store(Store(dir));
            let now = jiff::Timestamp::now();
            futures_executor::block_on(u.refresh(now))?;
            if cmd == "refresh" {
                return Ok(());
            }
            let tdir = tdir.ok_or_else(|| Error::transport("--target-dir required"))?;
            for n in &names {
                let info = futures_executor::block_on(u.get_target_info(n, now))?
                    .ok_or_else(|| Error::TargetNotFound(n.clone()))?;
                let out = tdir.join(safe(n));
                if std::fs::read(&out).is_ok_and(|b| {
                    b.len() as u64 == info.length
                        && info
                            .hashes
                            .get("sha256")
                            .is_some_and(|h| h.eq_ignore_ascii_case(&sha(&b)))
                }) {
                    continue; // artifact cache
                }
                let bytes = futures_executor::block_on(u.download_target(&info, n))?;
                if let Some(p) = out.parent() {
                    std::fs::create_dir_all(p).map_err(|e| Error::transport(e.to_string()))?;
                }
                std::fs::write(out, bytes).map_err(|e| Error::transport(e.to_string()))?;
            }
            Ok(())
        }
        other => Err(Error::transport(format!("unknown command {other:?}"))),
    }
}

fn safe(n: &str) -> PathBuf {
    let rel = Path::new(n.trim_start_matches('/'));
    if rel
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return PathBuf::from(rel.file_name().unwrap_or(rel.as_os_str()));
    }
    rel.to_path_buf()
}
