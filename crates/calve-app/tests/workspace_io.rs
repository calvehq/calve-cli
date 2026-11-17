//! Workspace I/O containment (rev 10 §15, ADR 0014; FG5 promoted): nothing is read, hashed or
//! written through a symlink, `.calve` is never scanned, writes are atomic, and a scan records
//! symlinks by target. Symlink cases report SKIP where the OS refuses to create links
//! (approved Windows limitation).

use std::fs;
use std::path::Path;

use calve_app::workspace_io::{IoError, Workspace};
use calve_integration_contract::wire::EntryKind;

fn link(target: &Path, at: &Path, dir: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let _ = dir;
        std::os::unix::fs::symlink(target, at)
    }
    #[cfg(windows)]
    {
        if dir {
            std::os::windows::fs::symlink_dir(target, at)
        } else {
            std::os::windows::fs::symlink_file(target, at)
        }
    }
}

fn tree() -> (tempfile::TempDir, tempfile::TempDir, bool) {
    let t = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"outside").unwrap();
    fs::create_dir_all(t.path().join("real/sub")).unwrap();
    fs::write(t.path().join("real/f"), b"inside").unwrap();
    fs::write(t.path().join("real/sub/g"), b"deep").unwrap();
    fs::create_dir_all(t.path().join(".calve/cache")).unwrap();
    fs::write(t.path().join(".calve/cache/x"), b"private").unwrap();
    let links = link(outside.path(), &t.path().join("escape"), true)
        .and_then(|()| link(Path::new("real"), &t.path().join("alias"), true))
        .and_then(|()| {
            link(
                &Path::new("real").join("f"),
                &t.path().join("filelink"),
                false,
            )
        });
    if let Err(e) = &links {
        println!("SKIP symlink cases: {e} (approved Windows limitation)");
    }
    (t, outside, links.is_ok())
}

#[test]
fn reads_and_hashes_never_follow_symlinks() {
    let (t, _o, links) = tree();
    let w = Workspace::open(t.path()).unwrap();
    assert_eq!(w.read("real/f", 100).unwrap(), b"inside");
    let e = w.hash("real/sub/g").unwrap();
    assert_eq!(
        e.digest.as_deref(),
        Some(calve_app::workspace_io::sha256_hex(b"deep").as_str())
    );
    assert_eq!(e.size, Some(4));
    assert!(matches!(w.read("real/f", 3), Err(IoError::TooLarge(_))));
    if links {
        for loc in ["escape/secret", "alias/f", "filelink"] {
            assert!(
                matches!(w.read(loc, 100), Err(IoError::NotFollowed(_))),
                "{loc}"
            );
            assert!(w.hash(loc).is_err(), "{loc}");
        }
        assert_eq!(
            w.symlink("filelink").unwrap().target.as_deref(),
            Some("real/f")
        );
    }
    for bad in ["../x", "/etc/passwd", ".calve/cache/x", "real//f"] {
        assert!(
            matches!(w.read(bad, 100), Err(IoError::Locator(_))),
            "{bad}"
        );
    }
}

#[test]
fn writes_are_atomic_and_never_through_symlinks() {
    let (t, o, links) = tree();
    let w = Workspace::open(t.path()).unwrap();
    w.write_atomic("new/dir/file.txt", b"hello").unwrap();
    assert_eq!(
        fs::read(t.path().join("new/dir/file.txt")).unwrap(),
        b"hello"
    );
    w.write_atomic("real/f", b"replaced").unwrap();
    assert_eq!(fs::read(t.path().join("real/f")).unwrap(), b"replaced");
    let leftovers: Vec<_> = fs::read_dir(t.path().join("real"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".calve-tmp")
        })
        .collect();
    assert!(leftovers.is_empty());
    if links {
        assert!(w.write_atomic("escape/secret", b"pwned").is_err());
        assert!(w.write_atomic("filelink", b"pwned").is_err());
        assert!(w.write_atomic("alias/f", b"pwned").is_err());
        assert_eq!(fs::read(o.path().join("secret")).unwrap(), b"outside");
        assert_eq!(fs::read(t.path().join("real/f")).unwrap(), b"replaced");
    }
}

#[test]
fn scan_skips_calve_and_records_symlinks_by_target() {
    let (t, _o, links) = tree();
    let w = Workspace::open(t.path()).unwrap();
    let mut seen = vec![];
    let mut errors = vec![];
    w.scan(
        |loc, _| loc == "real/sub",
        |e| {
            seen.push((e.path.clone(), e.kind, e.target.clone()));
            Ok(())
        },
        |loc, e| errors.push(format!("{loc}: {e}")),
    )
    .unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(
        seen.iter().all(|(p, _, _)| !p.starts_with(".calve")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|(p, k, _)| p == "real/f" && *k == EntryKind::File)
    );
    assert!(
        !seen.iter().any(|(p, _, _)| p.starts_with("real/sub")),
        "skipped directory"
    );
    if links {
        assert!(
            seen.iter()
                .any(|(p, k, _)| p == "escape" && *k == EntryKind::Symlink)
        );
        assert!(
            !seen
                .iter()
                .any(|(p, _, _)| p.starts_with("escape/") || p.starts_with("alias/")),
            "never descends a symlink"
        );
    }
}

#[test]
fn rehash_after_replacement_sees_the_new_file() {
    // A file replaced by rename gets a new identity; each hash is internally consistent (the
    // in-flight race is covered by the identity comparison, exercised in FG5).
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("f"), b"one").unwrap();
    let w = Workspace::open(t.path()).unwrap();
    let a = w.hash("f").unwrap();
    fs::write(t.path().join("f.new"), b"two!").unwrap();
    fs::rename(t.path().join("f.new"), t.path().join("f")).unwrap();
    let b = w.hash("f").unwrap();
    assert_ne!(a.digest, b.digest);
    assert_eq!(b.size, Some(4));
}
