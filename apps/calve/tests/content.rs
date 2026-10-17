//! Durable chunked content (rev 10 §13, N13/N26): the inline boundary, chunk upload through the
//! capture saga, byte-for-byte materialization, corruption and absence failing closed, and
//! portable history reconstructed at a clean destination without the extension.
use std::fs;
use std::path::Path;

use calve_app::Project;
use calve_integration_contract::content::{CHUNK_MAX, FILE_MAX, INLINE_MAX};

/// The machine data directory must be private to this test, so the body runs in a child process.
#[test]
fn chunked_content_is_durable_and_portable() {
    if std::env::var_os("CALVE_ISOLATED_TEST").is_some() {
        return tokio::runtime::Runtime::new().unwrap().block_on(body());
    }
    let data = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "chunked_content_is_durable_and_portable",
            "--exact",
            "--nocapture",
        ])
        .env("CALVE_ISOLATED_TEST", "1")
        .env("XDG_DATA_HOME", data.path())
        .env("CALVE_SANDBOX_PROGRAM", env!("CARGO_BIN_EXE_calve"))
        .status()
        .unwrap();
    assert!(status.success());
}

/// Deterministic, incompressible-looking bytes.
fn bytes(n: u64, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn code(e: calve_app::Error) -> String {
    e.to_string()
}

async fn body() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("p");
    fs::create_dir(&root).unwrap();
    let project = Project::init(&root, Some("Content")).await.unwrap();
    let mut repo = calve_testkit::tuf::Repo::new();
    repo.add_package("targets", calve_testkit::fixture_package());
    repo.publish();
    let pin = repo.root_bytes(1);
    let pin_file = temp.path().join("root.json.pin");
    fs::write(&pin_file, &pin).unwrap();
    calve_app::extensions::catalog_add(
        "test",
        repo.path().to_str().unwrap(),
        &pin_file,
        &calve_testkit::tuf::sha(&pin),
    )
    .unwrap();
    project
        .enable_extension("org.example.toy", &[], true)
        .await
        .unwrap();

    let files = [
        ("below.bin", bytes(INLINE_MAX - 1, 1)),
        ("at.bin", bytes(INLINE_MAX, 2)),
        ("above.bin", bytes(INLINE_MAX + 1, 3)),
        ("big.bin", bytes(9 << 20, 4)),
    ];
    for (name, content) in &files {
        fs::write(root.join(name), content).unwrap();
    }
    let id = project
        .create_pack_with_verification("Large files", None, true)
        .await
        .unwrap()
        .to_string();
    // Above the largest chunked file (a sparse file: the size check needs no bytes).
    let huge = fs::File::create(root.join("huge.bin")).unwrap();
    huge.set_len(FILE_MAX + 1).unwrap();
    drop(huge);
    match project
        .capture_tree(&id, 1, Path::new("."), false, true)
        .await
    {
        Err(calve_app::Error::Detailed { code, detail, .. }) => {
            assert_eq!(code, "FILE_TOO_LARGE");
            assert_eq!(detail["path"], "huge.bin");
            assert_eq!(detail["limit"], FILE_MAX);
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    fs::remove_file(root.join("huge.bin")).unwrap();
    project
        .capture_tree(&id, 1, Path::new("."), false, true)
        .await
        .unwrap();
    let pack = project.pack(&id).await.unwrap();
    let effect = |path: &str| {
        pack.candidate_effects
            .iter()
            .rev()
            .find(|e| e.target.locator == path)
            .unwrap()
            .clone()
    };
    assert_eq!(effect("below.bin").kind, "org.example.toy.put");
    assert_eq!(effect("at.bin").kind, "org.example.toy.put");
    assert_eq!(effect("above.bin").kind, "org.example.toy.put-chunked");
    let big = effect("big.bin");
    assert_eq!(big.kind, "org.example.toy.put-chunked");
    let chunks = big.payload["chunks"].as_array().unwrap();
    assert_eq!(chunks.len() as u64, (9u64 << 20).div_ceil(CHUNK_MAX));
    assert!(big.payload.get("content").is_none());

    let generation = project.pack(&id).await.unwrap().generation;
    project.seal(&id, generation).await.unwrap();
    let verified = project
        .verify_snapshots(&id, generation, None)
        .await
        .unwrap();
    assert_eq!(verified["status"], "PASS", "{verified}");
    project.qualify(&id, generation).await.unwrap();
    let promoted = project.promote(&id, generation).await.unwrap();
    let (baseline, _) = project.create_baseline("v1", vec![promoted]).await.unwrap();
    let baseline = baseline.to_string();

    // Byte-for-byte materialization from chunk blobs.
    for (name, _) in &files {
        fs::remove_file(root.join(name)).unwrap();
    }
    let applied = project
        .materialize_baseline(&baseline, &[], true, false, false)
        .await
        .unwrap();
    assert_eq!(applied["applied"], true, "{applied}");
    for (name, content) in &files {
        assert!(fs::read(root.join(name)).unwrap() == *content, "{name}");
    }
    assert!(project.historical_file(promoted, "big.bin").await.unwrap() == files[3].1);

    // Adopt-copy carries the closure and its refs documents; the copy reconstructs the bytes
    // with the extension binary and the machine refs store gone.
    let copy = temp.path().join("copy");
    calve_testkit::copy_tree(&root, &copy);
    let (adopted, summary) = calve_app::adopt::adopt_copy(&copy, Some("Fork"))
        .await
        .unwrap();
    assert!(
        summary["refs_documents"].as_u64().unwrap() >= 1,
        "{summary}"
    );
    let data = std::path::PathBuf::from(std::env::var_os("XDG_DATA_HOME").unwrap()).join("calve");
    // Installed packages are read-only; moving them aside retires the binary just the same.
    fs::rename(data.join("packages"), data.join("packages.retired")).unwrap();
    fs::rename(data.join("refs"), data.join("refs.retired")).unwrap();
    for (name, content) in &files {
        assert!(
            adopted.historical_file(promoted, name).await.unwrap() == *content,
            "{name}"
        );
    }
    drop(adopted);

    // Without the refs document the transfer fails closed and leaves the copy as it was.
    let copy2 = temp.path().join("copy2");
    calve_testkit::copy_tree(&root, &copy2);
    let Err(e) = calve_app::adopt::adopt_copy(&copy2, None).await else {
        panic!("adopted without its refs document")
    };
    let err = code(e);
    assert!(err.starts_with("CLOSURE_UNCLASSIFIED"), "{err}");
    assert!(copy2.join(".calve").is_dir());

    // A corrupted chunk is CONTENT_CORRUPT; a missing one is MATERIALIZE_CONFLICT and leaves no
    // partial file.
    let blob: openaevc::protocol::Digest =
        chunks[1]["blob_digest"].as_str().unwrap().parse().unwrap();
    let hex = blob.to_string().trim_start_matches("sha256:").to_owned();
    let object = root
        .join(".calve/openaevc/objects/sha256")
        .join(&hex[..2])
        .join(&hex);
    let original = fs::read(&object).unwrap();
    let mut bad = original.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xff;
    fs::write(&object, &bad).unwrap();
    let err = code(
        project
            .historical_file(promoted, "big.bin")
            .await
            .unwrap_err(),
    );
    assert!(err.contains("CONTENT_CORRUPT"), "{err}");
    fs::rename(data.join("packages.retired"), data.join("packages")).unwrap();
    fs::rename(data.join("refs.retired"), data.join("refs")).unwrap();
    fs::remove_file(root.join("big.bin")).unwrap();
    // Bytes gone from an indexed object: a store-integrity failure.
    fs::remove_file(&object).unwrap();
    let err = code(
        project
            .materialize_baseline(&baseline, &[], true, false, false)
            .await
            .unwrap_err(),
    );
    assert!(err.starts_with("CONTENT_CORRUPT"), "{err}");
    assert!(!root.join("big.bin").exists());
    fs::write(&object, &original).unwrap();
    // An object absent from the namespace: content unavailable.
    let db = rusqlite::Connection::open(root.join(".calve/openaevc/runtime.sqlite3")).unwrap();
    let indexed: Vec<(String, String)> = db
        .prepare("SELECT namespace, kind FROM object_index WHERE digest=?1")
        .unwrap()
        .query_map([blob.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    db.execute(
        "DELETE FROM object_index WHERE digest=?1",
        [blob.to_string()],
    )
    .unwrap();
    let err = project
        .materialize_baseline(&baseline, &[], true, false, false)
        .await
        .unwrap_err();
    match err {
        calve_app::Error::Detailed { code, detail, .. } => {
            assert_eq!(code, "MATERIALIZE_CONFLICT");
            assert_eq!(detail["reason"], "content_unavailable");
        }
        other => panic!("{other}"),
    }
    assert!(!root.join("big.bin").exists());
    for (ns, kind) in indexed {
        db.execute(
            "INSERT INTO object_index VALUES (?1, ?2, ?3)",
            [ns, blob.to_string(), kind],
        )
        .unwrap();
    }
    assert!(project.historical_file(promoted, "big.bin").await.unwrap() == files[3].1);
}
