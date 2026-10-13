use std::fs;
use std::path::Path;

use calve_app::Project;
use openaevc_crypto::sha256;
use openaevc_protocol::{ExecutionState, PackState, RevisionRelation};

/// Enabling an extension writes the machine-wide package cache, so the body runs in a child
/// process whose data directory is private to this test.
#[test]
fn file_capture_is_an_openaevc_effect() {
    if std::env::var_os("CALVE_ISOLATED_TEST").is_some() {
        return tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(file_capture_body());
    }
    let data = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "file_capture_is_an_openaevc_effect",
            "--exact",
            "--nocapture",
        ])
        .env("CALVE_ISOLATED_TEST", "1")
        .env("XDG_DATA_HOME", data.path())
        .status()
        .unwrap();
    assert!(status.success());
}

async fn file_capture_body() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), Some("Capture fixture"))
        .await
        .unwrap();
    let extension = Path::new(env!("CARGO_BIN_EXE_calve_ext_software"));
    let enabled = project
        .enable_extension(extension.to_str().unwrap(), &[])
        .await
        .unwrap();
    assert_eq!(enabled["id"], "org.calve.software");
    assert_eq!(project.list_extensions().await.unwrap()[0]["active"], true);

    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("src/example.txt"), b"hello, Calve\n").unwrap();
    let pack_id = project
        .create_pack_with_verification("Capture a file", None, true)
        .await
        .unwrap()
        .to_string();
    let captured = project
        .capture_file(&pack_id, 1, Path::new("src/example.txt"))
        .await
        .unwrap();
    assert_eq!(captured["unchanged"], false);
    let execution_id = captured["execution"].as_str().unwrap();
    let executions = project
        .list_executions(Some(&pack_id), Some(ExecutionState::Succeeded))
        .await
        .unwrap();
    assert_eq!(executions.as_array().unwrap().len(), 1);
    assert_eq!(
        project.execution(execution_id).await.unwrap()["state"],
        "SUCCEEDED"
    );
    assert!(
        project
            .cancel_execution(execution_id, Some("too late"))
            .await
            .is_err()
    );
    let pack = project.pack(&pack_id).await.unwrap();
    assert_eq!(pack.required_policies.len(), 1);
    assert_eq!(pack.candidate_effects.len(), 1);
    assert_eq!(pack.candidate_effects[0].target.locator, "src/example.txt");
    assert_eq!(
        pack.candidate_effects[0].kind,
        "org.calve.software.snapshot"
    );
    assert_eq!(
        pack.candidate_effects[0].payload["digest"],
        captured["digest"]
    );
    let repeat = project
        .capture_file(&pack_id, pack.generation, Path::new("src/example.txt"))
        .await
        .unwrap();
    assert_eq!(repeat["unchanged"], true);
    assert_eq!(
        project
            .pack(&pack_id)
            .await
            .unwrap()
            .candidate_effects
            .len(),
        1
    );
    fs::write(
        temp.path().join(".calveignore"),
        "*.tmp\n!keep.tmp\nsrc/cache/\n",
    )
    .unwrap();
    fs::write(temp.path().join("scratch.tmp"), b"ignore me").unwrap();
    fs::write(temp.path().join("keep.tmp"), b"keep me").unwrap();
    fs::create_dir(temp.path().join("src/cache")).unwrap();
    fs::write(temp.path().join("src/cache/generated.txt"), b"ignore me").unwrap();
    assert_eq!(
        project.check_ignore(Path::new("scratch.tmp")).unwrap()["line"],
        1
    );
    assert_eq!(
        project.check_ignore(Path::new("keep.tmp")).unwrap()["ignored"],
        false
    );
    assert_eq!(
        project
            .check_ignore(Path::new(".calve/project.toml"))
            .unwrap()["source"],
        "hard safety"
    );
    let resources = project.list_resources().unwrap();
    assert!(
        !resources
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "scratch.tmp" || item["path"] == "src/cache/generated.txt")
    );
    assert!(
        resources
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "keep.tmp")
    );
    assert!(
        resources
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "src/example.txt" && item["captureable"] == true)
    );
    assert!(
        !resources
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"].as_str().unwrap().starts_with(".calve/"))
    );
    assert_eq!(
        project.show_resource(Path::new("src/example.txt")).unwrap()["text"],
        "hello, Calve\n"
    );
    assert_eq!(
        project
            .diff_resource(&pack_id, Path::new("src/example.txt"))
            .await
            .unwrap()["state"],
        "unchanged"
    );
    fs::write(temp.path().join("src/second.txt"), b"second file\n").unwrap();
    assert!(
        project
            .capture_tree(&pack_id, pack.generation, Path::new("src"))
            .await
            .is_err()
    );
    let pack_id = project
        .create_pack_with_verification("Capture a tree", None, true)
        .await
        .unwrap()
        .to_string();
    let tree = project
        .capture_tree(&pack_id, 1, Path::new("src"))
        .await
        .unwrap();
    assert_eq!(tree["captured"].as_array().unwrap().len(), 2);
    assert!(
        tree["captured"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "src/second.txt")
    );
    assert_eq!(tree["unchanged"].as_array().unwrap().len(), 0);
    let pack = project.pack(&pack_id).await.unwrap();
    assert_eq!(tree["generation"], pack.generation);
    assert_eq!(pack.candidate_effects.len(), 2);
    let repeat_tree = project
        .capture_tree(&pack_id, pack.generation, Path::new("src"))
        .await
        .unwrap();
    assert_eq!(repeat_tree["captured"].as_array().unwrap().len(), 0);
    assert_eq!(repeat_tree["unchanged"].as_array().unwrap().len(), 2);
    assert!(
        project
            .capture_tree(&pack_id, pack.generation, Path::new("src/cache"))
            .await
            .is_err()
    );
    fs::write(temp.path().join("src/example.txt"), b"hello, changed\n").unwrap();
    let diff = project
        .diff_resource(&pack_id, Path::new("src/example.txt"))
        .await
        .unwrap();
    assert_eq!(diff["state"], "modified");
    assert_eq!(diff["changes"][0]["kind"], "remove");
    assert_eq!(diff["changes"][1]["kind"], "add");
    assert!(
        project
            .capture_file(&pack_id, pack.generation, Path::new("src/example.txt"))
            .await
            .is_err()
    );
    fs::remove_file(temp.path().join("src/example.txt")).unwrap();
    assert_eq!(
        project
            .diff_resource(&pack_id, Path::new("src/example.txt"))
            .await
            .unwrap()["state"],
        "deleted"
    );
    assert!(
        project
            .capture_file(&pack_id, pack.generation, Path::new(".calve/project.toml"))
            .await
            .is_err()
    );
    assert!(
        project
            .capture_file(&pack_id, pack.generation, Path::new("../outside"))
            .await
            .is_err()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("src/example.txt", temp.path().join("link.txt")).unwrap();
        assert!(
            project
                .capture_file(&pack_id, pack.generation, Path::new("link.txt"))
                .await
                .is_err()
        );
    }

    project.seal(&pack_id, pack.generation).await.unwrap();
    let evaluated = project
        .evaluate_change_size(&pack_id, pack.generation, None, None)
        .await
        .unwrap();
    assert_eq!(evaluated["verdict"], "ALLOW");
    assert_eq!(evaluated["metrics"]["org.calve.software.changed_files"], 2);
    assert_eq!(evaluated["metrics"]["org.calve.software.changed_bytes"], 25);
    let warned = project
        .evaluate_change_size(&pack_id, pack.generation, Some(0), Some(0))
        .await
        .unwrap();
    assert_eq!(warned["verdict"], "WARN");
    let failed = project
        .verify_snapshots(
            &pack_id,
            pack.generation,
            Some((Path::new("src/example.txt"), sha256(b"different"))),
        )
        .await
        .unwrap();
    assert_eq!(failed["status"], "FAIL");
    assert_eq!(
        failed["findings"][0]["code"],
        "org.calve.software.digest_mismatch"
    );
    project.qualify(&pack_id, pack.generation).await.unwrap();
    assert_eq!(
        project.pack(&pack_id).await.unwrap().state,
        PackState::Sealed
    );
    let verified = project
        .verify_snapshots(
            &pack_id,
            pack.generation,
            Some((Path::new("src/example.txt"), sha256(b"hello, Calve\n"))),
        )
        .await
        .unwrap();
    assert_eq!(verified["status"], "PASS");
    project.qualify(&pack_id, pack.generation).await.unwrap();
    assert_eq!(
        project.pack(&pack_id).await.unwrap().state,
        PackState::Qualified
    );
    let promoted = project.promote(&pack_id, pack.generation).await.unwrap();
    let (baseline, _) = project
        .create_baseline("Captured", vec![promoted])
        .await
        .unwrap();
    project
        .activate_baseline(&baseline.to_string())
        .await
        .unwrap();
    assert_eq!(
        project.active_baseline().unwrap(),
        Some(baseline.to_string())
    );
    fs::write(temp.path().join("src/second.txt"), b"revised file\n").unwrap();
    let revision = project
        .create_revision_pack(
            "Revise second",
            None,
            RevisionRelation::Amends,
            vec![promoted],
        )
        .await
        .unwrap();
    let revision_id = revision.to_string();
    let revised = project
        .capture_file(&revision_id, 1, Path::new("src/second.txt"))
        .await
        .unwrap();
    let generation = revised["generation"].as_u64().unwrap();
    project.seal(&revision_id, generation).await.unwrap();
    assert_eq!(
        project
            .verify_snapshots(
                &revision_id,
                generation,
                Some((Path::new("src/second.txt"), sha256(b"revised file\n")))
            )
            .await
            .unwrap()["status"],
        "PASS"
    );
    project.qualify(&revision_id, generation).await.unwrap();
    let revision_digest = project.promote(&revision_id, generation).await.unwrap();
    let (revised_baseline, _) = project
        .create_baseline("Revised", vec![promoted, revision_digest])
        .await
        .unwrap();
    project
        .validate_baseline(&revised_baseline.to_string())
        .await
        .unwrap();
    assert_eq!(
        project
            .compare_baselines(&baseline.to_string(), &revised_baseline.to_string())
            .await
            .unwrap()["only_right_members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
