use calve_testkit::Isolated;
use std::fs;
use std::path::Path;
use std::process::Command;

use openaevc_sdk::TypedClient;
use serde_json::Value;

fn run_cli(data_home: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(data_home, data_home.parent().unwrap().join("config"))
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    calve_testkit::json_data(&output.stdout)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &target);
        } else {
            fs::copy(item.path(), target).unwrap();
        }
    }
}

#[test]
fn cli_intent_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    run_cli(&data_home, &["init", root]);
    let created = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "intent",
            "create",
            "Release",
            "--description",
            "Ship it",
            "--tag",
            "v1",
        ],
    );
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        run_cli(&data_home, &["--project", root, "intent", "show", id])["tags"],
        serde_json::json!(["v1"])
    );
    let edited = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "intent",
            "edit",
            id,
            "--title",
            "Launch",
            "--clear-tags",
        ],
    );
    assert_eq!(edited["title"], "Launch");
    assert_eq!(edited["tags"], serde_json::json!([]));
    assert_eq!(
        run_cli(
            &data_home,
            &["--project", root, "intent", "close", id, "--cancelled"]
        )["state"],
        "CANCELLED"
    );
    assert_eq!(
        run_cli(&data_home, &["--project", root, "intent", "reopen", id])["state"],
        "OPEN"
    );
    let pack = run_cli(
        &data_home,
        &["--project", root, "pack", "create", "Release pack"],
    );
    let pack_id = pack["id"].as_str().unwrap();
    let linked = run_cli(
        &data_home,
        &["--project", root, "intent", "link-pack", id, pack_id],
    );
    assert_eq!(linked["intent"]["org.calve.intent"], id);
    assert_eq!(linked["generation"], 2);
    assert_eq!(
        run_cli(&data_home, &["--project", root, "intent", "show", id])["linked_packs"][0]["id"],
        pack_id
    );
    let unlinked = run_cli(
        &data_home,
        &["--project", root, "intent", "unlink-pack", id, pack_id],
    );
    assert_eq!(unlinked["intent"], serde_json::json!({}));
    assert_eq!(unlinked["generation"], 3);
    assert_eq!(
        run_cli(&data_home, &["--project", root, "intent", "show", id])["linked_packs"],
        serde_json::json!([])
    );
    let task = run_cli(
        &data_home,
        &["--project", root, "task", "create", id, "Follow up"],
    );
    let task_id = task["id"].as_str().unwrap();
    run_cli(
        &data_home,
        &["--project", root, "task", "link-pack", task_id, pack_id],
    );
    let identity = run_cli(&data_home, &["project", "identity", root]);
    let actor = identity["created_by"].as_str().unwrap();
    let bound = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "intent",
            "create",
            "Bound",
            "--actor",
            actor,
            "--graph-node",
            pack_id,
        ],
    );
    let bound_id = bound["id"].as_str().unwrap();
    let shown = run_cli(&data_home, &["--project", root, "intent", "show", bound_id]);
    assert_eq!(shown["actors"], serde_json::json!([actor]));
    assert_eq!(shown["graph_node"], pack_id);
    let cleared = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "intent",
            "edit",
            bound_id,
            "--clear-actors",
            "--clear-graph-node",
        ],
    );
    assert_eq!(cleared["actors"], serde_json::json!([]));
    assert!(cleared["graph_node"].is_null());
}

#[test]
fn cli_task_lifecycle_and_pack_link() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    run_cli(&data_home, &["init", root]);
    let intent = run_cli(&data_home, &["--project", root, "intent", "create", "Ship"]);
    let intent_id = intent["id"].as_str().unwrap();
    let task = run_cli(
        &data_home,
        &["--project", root, "task", "create", intent_id, "Publish"],
    );
    let task_id = task["id"].as_str().unwrap();
    assert_eq!(
        run_cli(&data_home, &["--project", root, "task", "start", task_id])["state"],
        "IN_PROGRESS"
    );
    assert_eq!(
        run_cli(
            &data_home,
            &[
                "--project",
                root,
                "task",
                "block",
                task_id,
                "--reason",
                "Waiting"
            ]
        )["blocked_reason"],
        "Waiting"
    );
    assert_eq!(
        run_cli(&data_home, &["--project", root, "task", "unblock", task_id])["state"],
        "OPEN"
    );
    let pack = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "pack",
            "create",
            "Candidate",
            "--intent",
            intent_id,
        ],
    );
    let pack_id = pack["id"].as_str().unwrap();
    let linked = run_cli(
        &data_home,
        &["--project", root, "task", "link-pack", task_id, pack_id],
    );
    assert_eq!(linked["linked_packs"][0], pack_id);
    run_cli(
        &data_home,
        &["--project", root, "task", "complete", task_id],
    );
    assert_eq!(
        run_cli(&data_home, &["--project", root, "task", "reopen", task_id])["state"],
        "OPEN"
    );
}

#[test]
fn cli_links_openaevc_work_unit_to_task() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    run_cli(&data_home, &["init", root]);
    let intent = run_cli(&data_home, &["--project", root, "intent", "create", "Ship"]);
    let intent_id = intent["id"].as_str().unwrap();
    let task = run_cli(
        &data_home,
        &["--project", root, "task", "create", intent_id, "Execute"],
    );
    let task_id = task["id"].as_str().unwrap();
    let pack = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "pack",
            "create",
            "Candidate",
            "--intent",
            intent_id,
        ],
    );
    let pack_id = pack["id"].as_str().unwrap();
    calve_app::authority::use_data_root(&data_home.join("calve"));
    let project = calve_app::Project::open(&root_path).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let work_unit = runtime
        .block_on(
            project
                .client
                .add_work_unit(pack_id.parse().unwrap(), 1, "org.calve.test.work"),
        )
        .unwrap();
    drop(project);
    let linked = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "task",
            "link-work-unit",
            task_id,
            &work_unit.to_string(),
        ],
    );
    assert_eq!(linked["linked_work_units"], serde_json::json!([work_unit]));
    assert_eq!(linked["linked_packs"], serde_json::json!([pack_id]));
    assert_eq!(linked["work_unit_states"][0]["state"], "OPEN");
}

#[test]
fn cli_authority_uses_protocol_decisions_and_grants() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    run_cli(&data_home, &["init", root]);
    calve_app::authority::use_data_root(&data_home.join("calve"));
    let project = calve_app::Project::open(&root_path).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let actor = runtime
        .block_on(
            project
                .client
                .register_principal(openaevc::protocol::NewPrincipal {
                    kind: openaevc::protocol::PrincipalKind::Actor,
                    public_key: None,
                    linked_to: Some(project.identity.created_by),
                    attributes: Default::default(),
                }),
        )
        .unwrap()
        .to_string();
    drop(project);
    let principals = run_cli(&data_home, &["--project", root, "authority", "principals"]);
    assert!(
        principals
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == actor)
    );
    let action = "org.calve.test.read";
    let denied = run_cli(
        &data_home,
        &[
            "--project",
            root,
            "authority",
            "explain",
            action,
            "--principal",
            &actor,
        ],
    );
    assert_eq!(denied["decision"]["allowed"], false);
    let current = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let expiry =
        openaevc::protocol::Timestamp::from_unix_nanos(current as i128 + 3_600_000_000_000)
            .to_string();
    let grant_args = [
        "--project",
        root,
        "authority",
        "grant",
        &actor,
        "--action",
        action,
        "--expires-at",
        &expiry,
    ];
    let preview = run_cli(&data_home, &[&grant_args[..], &["--preview"]].concat());
    assert_eq!(preview["preview"], true);
    assert_eq!(
        run_cli(&data_home, &["--project", root, "authority", "grants"]),
        serde_json::json!([])
    );
    let issued = run_cli(&data_home, &[&grant_args[..], &["--apply"]].concat());
    let grant_id = issued["grant_id"].as_str().unwrap();
    assert_eq!(
        run_cli(
            &data_home,
            &["--project", root, "authority", "show", grant_id]
        )["revoked"],
        false
    );
    assert_eq!(
        run_cli(
            &data_home,
            &[
                "--project",
                root,
                "authority",
                "explain",
                action,
                "--principal",
                &actor
            ]
        )["decision"]["allowed"],
        true
    );
    run_cli(
        &data_home,
        &["--project", root, "authority", "revoke", grant_id, "--yes"],
    );
    assert_eq!(
        run_cli(
            &data_home,
            &["--project", root, "authority", "show", grant_id]
        )["revoked"],
        true
    );
}

#[test]
fn cli_project_rename_and_health_cover_copies_and_moves() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let calve = |args: &[&str]| run_cli(&data_home, args);
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    let init = calve(&["init", root, "--name", "Original"]);
    let id = init["project_id"].as_str().unwrap();
    assert_eq!(calve(&["project", "health", id])["status"], "healthy");
    assert_eq!(
        calve(&["project", "rename", id, "Updated"])["name"],
        "Updated"
    );
    assert_eq!(
        calve(&["--project", root, "status"])["project"]["name"],
        "Updated"
    );
    assert!(calve(&["project", "identity", id]).get("name").is_none());
    calve_app::authority::use_data_root(&data_home.join("calve"));
    let mut opened = calve_app::Project::open(&root_path).unwrap();
    opened.rename("Diverged").unwrap();
    drop(opened);
    assert_eq!(
        calve(&["project", "health", id])["status"],
        "name_out_of_sync"
    );
    calve(&["project", "rename", id, "Updated"]);
    assert_eq!(calve(&["project", "health", id])["status"], "healthy");
    let copy = temp.path().join("copy");
    copy_tree(&root_path, &copy);
    assert_eq!(
        calve(&["project", "health", copy.to_str().unwrap()])["status"],
        "duplicate_copy"
    );
    let moved = temp.path().join("moved");
    fs::rename(&root_path, &moved).unwrap();
    assert_eq!(calve(&["project", "health", id])["status"], "missing_path");
    assert_eq!(
        calve(&["project", "health", moved.to_str().unwrap()])["status"],
        "relocation_needed"
    );
    calve(&["project", "relocate", id, moved.to_str().unwrap()]);
    assert_eq!(calve(&["project", "health", id])["status"], "healthy");
    assert_eq!(calve(&["project", "show", id])["name"], "Updated");
}

#[test]
fn cli_inbox_tracks_quarantine() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let calve = |args: &[&str]| run_cli(&data_home, args);
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    calve(&["init", root]);
    let pack = calve(&["--project", root, "pack", "create", "Needs inspection"]);
    let id = pack["id"].as_str().unwrap();
    calve(&[
        "--project",
        root,
        "pack",
        "quarantine",
        id,
        "--reason",
        "Inspect",
    ]);
    let items = calve(&["--project", root, "inbox", "list"]);
    let key = items[0]["source_key"].as_str().unwrap();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["needs_attention"], true);
    calve(&["--project", root, "inbox", "acknowledge", key]);
    assert_eq!(
        calve(&["--project", root, "inbox", "list"])[0]["needs_attention"],
        false
    );
    calve(&["--project", root, "pack", "release", id]);
    assert!(
        calve(&["--project", root, "inbox", "list"])
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(calve(&["--project", root, "inbox", "list", "--all"])[0]["resolved_at"].is_number());
}

#[test]
fn cli_workflow() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let calve = |args: &[&str]| run_cli(&data_home, args);
    let root_path = temp.path().join("project");
    let root = root_path.to_str().unwrap();
    let init = calve(&["init", root, "--name", "CLI fixture"]);
    // The root is reported canonical (macOS /private/var, a Windows long name), as registered.
    let canonical = std::fs::canonicalize(&root_path).unwrap();
    assert_eq!(init["root"], canonical.to_str().unwrap());
    let version = calve(&["version"]);
    assert_eq!(version["openaevc_tag"], "v0.1.0");
    assert_eq!(
        version["openaevc_revision"],
        "5720d3ec15bee6c49630b2cec5a21afd357dedf8"
    );
    let doctor = calve(&["--project", root, "doctor"]);
    assert!(doctor["compatibility"]["protocol"].is_string());
    assert_eq!(doctor["compatibility"]["openaevc_tag"], "v0.1.0");
    let intent = calve(&["--project", root, "intent", "create", "Ship a change"]);
    let intent_id = intent["id"].as_str().unwrap();
    let prerequisite = calve(&["--project", root, "task", "create", intent_id, "Prepare"]);
    let dependent = calve(&[
        "--project",
        root,
        "task",
        "create",
        intent_id,
        "Ship",
        "--priority",
        "high",
        "--assignee",
        "alex",
    ]);
    let prerequisite_id = prerequisite["id"].as_str().unwrap();
    let dependent_id = dependent["id"].as_str().unwrap();
    calve(&[
        "--project",
        root,
        "task",
        "update",
        dependent_id,
        "--description",
        "Release the candidate",
    ]);
    calve(&[
        "--project",
        root,
        "task",
        "depend",
        dependent_id,
        prerequisite_id,
    ]);
    let tasks = calve(&["--project", root, "task", "list"]);
    let dependent_task = tasks
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["id"] == dependent_id)
        .unwrap();
    assert_eq!(dependent_task["blocked_by"][0], prerequisite_id);
    assert_eq!(dependent_task["priority"], "high");
    assert_eq!(dependent_task["assignee"], "alex");
    assert_eq!(dependent_task["description"], "Release the candidate");
    assert_eq!(
        calve(&["--project", root, "task", "show", dependent_id])["blocked_by"][0],
        prerequisite_id
    );
    calve(&["--project", root, "task", "complete", prerequisite_id]);
    calve(&["--project", root, "task", "complete", dependent_id]);
    let pack = calve(&[
        "--project",
        root,
        "pack",
        "create",
        "Candidate",
        "--intent",
        intent_id,
    ]);
    let pack_id = pack["id"].as_str().unwrap();
    let receipts = calve(&["--project", root, "receipt", "list"]);
    let receipt_digest = receipts["items"][0]["digest"].as_str().unwrap();
    assert_eq!(
        calve(&["--project", root, "receipt", "show", receipt_digest])["envelope"]["kind"],
        "receipt"
    );
    let sealed = calve(&[
        "--project",
        root,
        "pack",
        "seal",
        pack_id,
        "--generation",
        "1",
    ]);
    assert!(sealed["candidate_digest"].is_string());
    fs::write(root_path.join("evidence.txt"), "review note").unwrap();
    let evidence = calve(&[
        "--project",
        root,
        "evidence",
        "add",
        pack_id,
        "--generation",
        "1",
        "--kind",
        "org.calve.note",
        "--file",
        "evidence.txt",
        "--media-type",
        "text/plain",
    ]);
    let evidence_digest = evidence["digest"].as_str().unwrap();
    assert!(calve(&["--project", root, "evidence", "show", evidence_digest]).is_object());
    assert_eq!(
        calve(&["--project", root, "evidence", "list", pack_id, "--current"])["items"][0]["digest"],
        evidence_digest
    );
    calve(&[
        "--project",
        root,
        "pack",
        "qualify",
        pack_id,
        "--generation",
        "1",
    ]);
    let review = calve(&[
        "--project",
        root,
        "review",
        "approve",
        pack_id,
        "--generation",
        "1",
    ]);
    assert!(review["id"].is_string());
    let promoted = calve(&[
        "--project",
        root,
        "pack",
        "promote",
        pack_id,
        "--generation",
        "1",
    ]);
    let digest = promoted["promoted_digest"].as_str().unwrap();
    let revision = calve(&[
        "--project",
        root,
        "revision",
        "create",
        "Amend candidate",
        "--of",
        digest,
        "--relation",
        "amends",
        "--require-review",
    ]);
    let revision_id = revision["id"].as_str().unwrap();
    assert_eq!(
        calve(&["--project", root, "revision", "show", revision_id])["revision"]["relation"],
        "AMENDS"
    );
    assert_eq!(
        calve(&["--project", root, "revision", "list"])[0]["id"],
        revision_id
    );
    assert_eq!(
        calve(&["--project", root, "revision", "show", revision_id])["required_policies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let reviewed = calve(&[
        "--project",
        root,
        "pack",
        "create",
        "Review gated",
        "--require-review",
    ]);
    let reviewed_id = reviewed["id"].as_str().unwrap();
    calve(&[
        "--project",
        root,
        "pack",
        "seal",
        reviewed_id,
        "--generation",
        "1",
    ]);
    calve(&[
        "--project",
        root,
        "pack",
        "qualify",
        reviewed_id,
        "--generation",
        "1",
    ]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", reviewed_id])["state"],
        "SEALED"
    );
    calve(&[
        "--project",
        root,
        "review",
        "approve",
        reviewed_id,
        "--generation",
        "1",
    ]);
    assert!(
        calve(&["--project", root, "review", "list", reviewed_id])[0]["evidence_digest"]
            .is_string()
    );
    calve(&[
        "--project",
        root,
        "pack",
        "qualify",
        reviewed_id,
        "--generation",
        "1",
    ]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", reviewed_id])["state"],
        "QUALIFIED"
    );
    let disposable = calve(&["--project", root, "pack", "create", "Disposable"]);
    let disposable_id = disposable["id"].as_str().unwrap();
    calve(&[
        "--project",
        root,
        "pack",
        "set-intent",
        disposable_id,
        intent_id,
        "--generation",
        "1",
    ]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", disposable_id])["intent"]["org.calve.intent"],
        intent_id
    );
    calve(&[
        "--project",
        root,
        "pack",
        "quarantine",
        disposable_id,
        "--reason",
        "Check later",
    ]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", disposable_id])["state"],
        "QUARANTINED"
    );
    calve(&["--project", root, "pack", "release", disposable_id]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", disposable_id])["state"],
        "OPEN"
    );
    calve(&[
        "--project",
        root,
        "pack",
        "abandon",
        disposable_id,
        "--generation",
        "2",
        "--yes",
    ]);
    assert_eq!(
        calve(&["--project", root, "pack", "show", disposable_id])["state"],
        "ABANDONED"
    );
    let baseline = calve(&["--project", root, "baseline", "create", "accepted", digest]);
    let baseline_id = baseline["id"].as_str().unwrap();
    let alias = calve(&[
        "--project",
        root,
        "baseline",
        "alias",
        "set",
        "accepted",
        baseline_id,
    ]);
    assert_eq!(alias["baseline_id"], baseline_id);
    assert_eq!(
        calve(&["--project", root, "baseline", "alias", "list"])[0]["alias"],
        "accepted"
    );
    assert!(calve(&["--project", root, "baseline", "validate", "accepted"]).is_object());
    assert!(calve(&["--project", root, "baseline", "graph", "accepted"]).is_object());
    assert!(
        calve(&[
            "--project",
            root,
            "baseline",
            "compare",
            baseline_id,
            "accepted"
        ])["only_left_members"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    calve(&["--project", root, "baseline", "activate", baseline_id]);
    let status = calve(&["--project", root, "status"]);
    assert_eq!(status["active_baseline"]["id"], baseline_id);
    // Counts of open/sealed/qualified work; promoted packs are history, not listed.
    assert!(status["packs"]["open"].is_u64(), "{status}");
    assert!(status["packs"]["items"].get("promoted").is_none());
    let workspaces = calve(&["workspace", "list"]);
    assert_eq!(workspaces[0]["name"], "default");
    let copy = temp.path().join("copy");
    copy_tree(&root_path, &copy);
    let blocked = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(&data_home, temp.path().join("config"))
        .args([
            "--project",
            copy.to_str().unwrap(),
            "intent",
            "create",
            "Should fail",
        ])
        .output()
        .unwrap();
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("PROJECT_IDENTITY_CONFLICT"));
}

#[test]
fn cli_config_scopes_and_validation() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let calve = |args: &[&str]| run_cli(&data_home, args);
    let root = temp.path().join("project");
    let root_str = root.to_str().unwrap();
    calve(&["init", root_str]);
    calve(&["config", "set", "ui.color", "never", "--scope", "global"]);
    calve(&[
        "config",
        "set",
        "ui.color",
        "always",
        "--scope",
        "workspace",
    ]);
    assert_eq!(
        calve(&["--project", root_str, "config", "get", "ui.color"]),
        "always"
    );
    calve(&["--project", root_str, "config", "set", "ui.color", "auto"]);
    assert_eq!(
        calve(&["--project", root_str, "config", "get", "ui.color"]),
        "auto"
    );
    calve(&["--project", root_str, "config", "unset", "ui.color"]);
    assert_eq!(
        calve(&["--project", root_str, "config", "get", "ui.color"]),
        "always"
    );
    calve(&["config", "set", "ui.page_size", "1", "--scope", "global"]);
    calve(&["--project", root_str, "intent", "create", "One"]);
    calve(&["--project", root_str, "intent", "create", "Two"]);
    let activity = calve(&["--project", root_str, "activity"]);
    assert_eq!(activity.as_array().unwrap().len(), 1);
    assert_eq!(activity[0]["source"], "calve");
    let filtered = calve(&[
        "--project",
        root_str,
        "activity",
        "--source",
        "calve",
        "--type",
        "intent.created",
    ]);
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["kind"], "intent.created");
    assert_eq!(calve(&["config", "validate"])["valid"], true);
}

#[test]
fn cli_captures_a_file_with_the_file_extension() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root = temp.path().join("project");
    let root_str = root.to_str().unwrap();
    let calve = |args: &[&str]| run_cli(&data_home, args);
    calve(&["init", root_str]);
    let catalog = calve_testkit::ToyCatalog::new();
    calve(
        &catalog
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let enabled = calve(&[&["--project", root_str][..], &calve_testkit::ENABLE_TOY[..]].concat());
    assert_eq!(enabled["id"], "org.example.toy");
    fs::write(root.join("note.txt"), "captured through CLI\n").unwrap();
    let pack = calve(&[
        "--project",
        root_str,
        "pack",
        "create",
        "File change",
        "--require-snapshot-verification",
    ]);
    let id = pack["id"].as_str().unwrap();
    let capture = calve(&[
        "--project",
        root_str,
        "pack",
        "capture",
        id,
        "note.txt",
        "--generation",
        "1",
    ]);
    assert_eq!(capture["path"], "note.txt");
    let shown = calve(&["--project", root_str, "pack", "show", id]);
    assert_eq!(
        shown["candidate_effects"][0]["payload"]["digest"],
        capture["digest"]
    );
    assert_eq!(shown["generation"], capture["generation"]);
    let listed = calve(&["--project", root_str, "resource", "list"]);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "note.txt")
    );
    assert_eq!(
        calve(&["--project", root_str, "resource", "show", "note.txt"])["text"],
        "captured through CLI\n"
    );
    assert_eq!(
        calve(&["--project", root_str, "resource", "diff", id, "note.txt"])["state"],
        "unchanged"
    );
    fs::write(root.join("second.txt"), "another capture\n").unwrap();
    let tree_pack = calve(&[
        "--project",
        root_str,
        "pack",
        "create",
        "Tree change",
        "--require-snapshot-verification",
    ]);
    let id = tree_pack["id"].as_str().unwrap();
    let tree = calve(&[
        "--project",
        root_str,
        "pack",
        "capture-tree",
        "--accept-deletions",
        id,
        ".",
        "--generation",
        "1",
    ]);
    assert_eq!(tree["captured"].as_array().unwrap().len(), 2);
    let execution_id = tree["execution"].as_str().unwrap();
    assert_eq!(
        calve(&["--project", root_str, "execution", "show", execution_id])["state"],
        "SUCCEEDED"
    );
    assert_eq!(
        calve(&["--project", root_str, "execution", "wait", execution_id])["state"],
        "SUCCEEDED"
    );
    assert_eq!(
        calve(&[
            "--project",
            root_str,
            "execution",
            "list",
            "--pack",
            id,
            "--state",
            "succeeded"
        ])[0]["id"],
        execution_id
    );
    assert_eq!(tree["unchanged"].as_array().unwrap().len(), 0);
    let generation = tree["generation"].as_u64().unwrap().to_string();
    calve(&[
        "--project",
        root_str,
        "pack",
        "seal",
        id,
        "--generation",
        &generation,
    ]);
    let evaluation = calve(&[
        "--project",
        root_str,
        "pack",
        "evaluate",
        id,
        "--generation",
        &generation,
        "--warn-after-files",
        "0",
    ]);
    assert_eq!(evaluation["verdict"], "WARN");
    assert_eq!(evaluation["metrics"]["org.example.toy.changed_files"], 2);
    let verified = calve(&[
        "--project",
        root_str,
        "pack",
        "verify",
        id,
        "--generation",
        &generation,
        "--path",
        "note.txt",
        "--digest",
        capture["digest"].as_str().unwrap(),
    ]);
    assert_eq!(verified["status"], "PASS");
    calve(&[
        "--project",
        root_str,
        "pack",
        "qualify",
        id,
        "--generation",
        &generation,
    ]);
    assert_eq!(
        calve(&["--project", root_str, "pack", "show", id])["state"],
        "QUALIFIED"
    );
}

#[test]
fn workspace_commands_select_and_share_a_project() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let calve = |args: &[&str]| run_cli(&data_home, args);
    let team = calve(&["workspace", "create", "team"]);
    assert_eq!(team["name"], "team");
    calve(&["workspace", "select", "team"]);
    let root = temp.path().join("project");
    let root_str = root.to_str().unwrap();
    let created = calve(&["init", root_str]);
    let id = created["project_id"].as_str().unwrap();
    assert_eq!(calve(&["workspace", "show"])["default_project_id"], id);
    // With no cwd project, commands resolve the selected Workspace's default Project.
    assert_eq!(calve(&["status"])["project"]["project_id"], id);
    calve(&["workspace", "add-project", "default", id]);
    assert_eq!(
        calve(&["workspace", "show", "default"])["projects"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    calve(&["workspace", "delete", "team", "--force", "--yes"]);
    assert_eq!(calve(&["workspace", "show"])["name"], "default");
    assert_eq!(calve(&["status"])["project"]["project_id"], id);
}

#[test]
fn cli_operations_surface() {
    let temp = tempfile::tempdir().unwrap();
    let data_home = temp.path().join("data");
    let root = temp.path().join("project");
    let root_str = root.to_str().unwrap();
    let calve = |args: &[&str]| run_cli(&data_home, &[&["--project", root_str], args].concat());
    run_cli(&data_home, &["init", root_str]);
    let catalog = calve_testkit::ToyCatalog::new();
    run_cli(
        &data_home,
        &catalog
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    calve(&calve_testkit::ENABLE_TOY);
    let info = calve(&["extension", "info", "org.example.toy"]);
    assert_eq!(info["extension"]["active"], true);
    assert_eq!(
        calve(&["extension", "health"])[0]["healthy"],
        serde_json::json!(true)
    );
    calve(&["extension", "permissions", "org.example.toy"]);

    fs::write(root.join("a.txt"), "one\n").unwrap();
    fs::write(root.join("skip.log"), "noise\n").unwrap();
    assert_eq!(calve(&["ignore", "add", "*.log"])["added"], true);
    assert!(
        calve(&["ignore", "list"])
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["pattern"] == "*.log")
    );
    let pack = calve(&["pack", "create", "Ops"]);
    let id = pack["id"].as_str().unwrap();
    let capture = calve(&["pack", "capture", id, "a.txt", "--generation", "1"]);
    let edited = calve(&["pack", "edit", id, "--title", "Renamed"]);
    assert_eq!(edited["title"], "Renamed");
    fs::write(root.join("a.txt"), "two\n").unwrap();
    let diff = calve(&["pack", "diff", id]);
    assert_eq!(diff["files"][0]["state"], "modified");
    let scan = calve(&["resource", "scan"]);
    let uncaptured = scan["uncaptured"].as_array().unwrap();
    assert!(
        uncaptured
            .iter()
            .any(|f| f["path"] == "a.txt" && f["state"] == "modified")
    );
    assert!(!uncaptured.iter().any(|f| f["path"] == "skip.log"));
    assert_eq!(
        calve(&["resource", "history", "a.txt"])["history"][0]["digest"],
        capture["digest"]
    );
    calve(&["ignore", "remove", "*.log"]);

    let execution = capture["execution"].as_str().unwrap();
    assert!(
        !calve(&["execution", "logs", execution])["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let receipts = calve(&["receipt", "list", "--limit", "1"]);
    let digest = receipts["items"][0]["digest"].as_str().unwrap();
    assert_eq!(calve(&["receipt", "verify", digest])["valid"], true);

    assert_eq!(calve(&["maintenance", "check"])["ok"], true);
    assert_eq!(calve(&["maintenance", "gc", "--dry-run"])["dry_run"], true);
    calve(&["maintenance", "compact"]);
    calve(&["maintenance", "rebuild-projections"]);
    calve(&["inbox", "clear-resolved", "--yes"]);

    let stale = root.join(".calve-init-stale");
    fs::create_dir(&stale).unwrap();
    // Fresh staging may belong to a running init, so it is not offered for removal.
    assert_eq!(
        calve(&["recover", "plan"])["actions"],
        serde_json::json!([])
    );
    let refused = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(&data_home, data_home.join("config"))
        .args(["--project", root_str, "recover", "apply"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let inspected = calve(&["recover", "inspect"]);
    assert_eq!(inspected["read_only"], true, "{inspected}");
    assert_eq!(inspected["product_db"]["state"], "ok", "{inspected}");
}
