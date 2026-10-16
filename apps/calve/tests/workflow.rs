use calve_app::compatibility;
use calve_app::{ActivityFilter, GrantOptions, Project};
use openaevc::protocol::{
    Command, ExecutionRequest, ExecutionState, NewPrincipal, PackState, PrincipalKind,
    ProviderDescriptor, RevisionRelation, WorkUnitState,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use std::collections::BTreeMap;

#[tokio::test]
async fn authority_preview_grant_explain_and_revoke_use_openaevc() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let actor = project
        .client
        .register_principal(NewPrincipal {
            kind: PrincipalKind::Actor,
            public_key: None,
            linked_to: Some(project.identity.created_by),
            attributes: BTreeMap::new(),
        })
        .await
        .unwrap();
    let principals = project.authority_principals().await.unwrap();
    assert!(
        principals
            .iter()
            .any(|principal| principal["id"] == actor.to_string())
    );
    let action = "org.calve.test.read";
    assert_eq!(
        project
            .authority_explain(action, Some(&actor.to_string()), None)
            .await
            .unwrap()["decision"]["allowed"],
        false
    );
    let current = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let options = GrantOptions {
        subject: actor.to_string(),
        actions: vec![action.into()],
        expires_at: openaevc::protocol::Timestamp::from_unix_nanos(
            current as i128 + 3_600_000_000_000,
        )
        .to_string(),
        not_before: None,
        resource_kind: None,
        locator_prefix: None,
        delegation_depth: 0,
        parent: None,
        preview: true,
        apply: false,
    };
    let preview = project.authority_grant(&options).await.unwrap();
    assert_eq!(preview["preview"], true);
    assert_eq!(preview["issuer_permission"]["allowed"], true);
    assert!(project.authority_grants().await.unwrap().is_empty());
    let issued = project
        .authority_grant(&GrantOptions {
            preview: false,
            apply: true,
            ..options
        })
        .await
        .unwrap();
    let grant_id = issued["grant_id"].as_str().unwrap();
    assert_eq!(
        project.authority_show(grant_id).await.unwrap()["revoked"],
        false
    );
    assert_eq!(project.authority_grants().await.unwrap().len(), 1);
    let allowed = project
        .authority_explain(action, Some(&actor.to_string()), None)
        .await
        .unwrap();
    assert_eq!(allowed["decision"]["allowed"], true);
    assert_eq!(allowed["matching_grants"].as_array().unwrap().len(), 1);
    assert_eq!(
        allowed["grant_limits"][0]["actions"],
        serde_json::json!([action])
    );
    let revoked = project
        .authority_revoke(grant_id, Some("done"))
        .await
        .unwrap();
    assert_eq!(revoked["record"]["revoked"], true);
    let denied_after_revoke = project
        .authority_explain(action, Some(&actor.to_string()), None)
        .await
        .unwrap();
    assert_eq!(denied_after_revoke["decision"]["allowed"], false);
    assert_eq!(
        denied_after_revoke["revocations"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn activity_merges_recent_protocol_and_product_events() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let intent = project.create_intent("Ship").unwrap();
    let pack = project.create_pack("Candidate", None).await.unwrap();
    let all_protocol = project
        .client
        .query(openaevc::protocol::Query::ListEvents {
            after: 0,
            limit: Some(1000),
            kinds: vec![],
        })
        .await
        .unwrap();
    let latest = project.protocol_activity(1).await.unwrap();
    assert_eq!(latest.as_array().unwrap().len(), 1);
    assert_eq!(
        latest[0]["sequence"],
        all_protocol.as_array().unwrap().last().unwrap()["sequence"]
    );
    let merged = project.activity(100).await.unwrap();
    assert!(merged.iter().any(|item| item["source"] == "calve"));
    assert!(merged.iter().any(|item| item["source"] == "openaevc"));
    assert!(merged.iter().all(|item| item["source_event_id"].is_string()
        && item["project_id"] == project.identity.project_id
        && item["namespace_id"] == serde_json::json!(project.identity.namespace_id)));
    for pair in merged.windows(2) {
        let newer: openaevc::protocol::Timestamp =
            pair[0]["timestamp"].as_str().unwrap().parse().unwrap();
        let older: openaevc::protocol::Timestamp =
            pair[1]["timestamp"].as_str().unwrap().parse().unwrap();
        assert!(newer >= older);
    }
    assert_eq!(project.activity(1).await.unwrap()[0]["id"], merged[0]["id"]);
    assert!(project.activity(0).await.is_err());

    let filtered = project
        .activity_with_filter(
            1,
            &ActivityFilter {
                source: Some("calve".into()),
                event_type: Some("intent.created".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["kind"], "intent.created");
    assert_eq!(filtered[0]["subject"], intent);
    let protocol_only = project
        .activity_with_filter(
            100,
            &ActivityFilter {
                source: Some("openaevc".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(protocol_only.iter().all(|row| row["source"] == "openaevc"));
    assert!(!protocol_only.is_empty());
    let cutoff = filtered[0]["timestamp"].as_str().unwrap();
    let after = project
        .activity_with_filter(
            100,
            &ActivityFilter {
                source: Some("calve".into()),
                since: Some(cutoff.into()),
                until: Some(cutoff.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(after.iter().any(|row| row["id"] == filtered[0]["id"]));
    assert!(
        project
            .activity_with_filter(
                1,
                &ActivityFilter {
                    source: Some("unknown".into()),
                    ..Default::default()
                },
            )
            .await
            .is_err()
    );
    let task = project.create_task(&intent, "Implement").unwrap();
    project
        .link_task_pack(&task, &pack.to_string())
        .await
        .unwrap();
    let linked = project
        .activity_with_filter(
            10,
            &ActivityFilter {
                source: Some("calve".into()),
                object_kind: Some("task".into()),
                task: Some(task),
                pack: Some(pack.to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0]["kind"], "task.pack.linked");
}

#[tokio::test]
async fn revision_targets_promoted_pack_and_composes_in_a_new_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let original = project.create_pack("Original", None).await.unwrap();
    project.seal(&original.to_string(), 1).await.unwrap();
    project.qualify(&original.to_string(), 1).await.unwrap();
    let original_digest = project.promote(&original.to_string(), 1).await.unwrap();
    let (before, _) = project
        .create_baseline("Before", vec![original_digest])
        .await
        .unwrap();
    let revision = project
        .create_revision_pack(
            "Amend original",
            None,
            RevisionRelation::Amends,
            vec![original_digest],
        )
        .await
        .unwrap();
    let revision_id = revision.to_string();
    let shown = project.revision(&revision_id).await.unwrap();
    assert_eq!(
        shown.revision.as_ref().unwrap().relation,
        RevisionRelation::Amends
    );
    assert_eq!(
        shown.revision.as_ref().unwrap().targets,
        vec![original_digest]
    );
    assert_eq!(project.list_revisions().await.unwrap().len(), 1);
    assert!(project.revision(&original.to_string()).await.is_err());
    project.seal(&revision_id, 1).await.unwrap();
    project.qualify(&revision_id, 1).await.unwrap();
    let revision_digest = project.promote(&revision_id, 1).await.unwrap();
    let (after, _) = project
        .create_baseline("After", vec![original_digest, revision_digest])
        .await
        .unwrap();
    project.validate_baseline(&after.to_string()).await.unwrap();
    let comparison = project
        .compare_baselines(&before.to_string(), &after.to_string())
        .await
        .unwrap();
    assert_eq!(
        comparison["only_right_members"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        project.pack(&original.to_string()).await.unwrap().state,
        PackState::Promoted
    );
}

#[tokio::test]
async fn quarantine_release_and_generation_checked_abandon() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let id = project
        .create_pack("Isolated change", None)
        .await
        .unwrap()
        .to_string();
    assert!(project.quarantine_pack(&id, " ").await.is_err());
    project
        .quarantine_pack(&id, "Needs investigation")
        .await
        .unwrap();
    let quarantined = project.pack(&id).await.unwrap();
    assert_eq!(quarantined.state, PackState::Quarantined);
    assert_eq!(
        quarantined.quarantine.as_ref().unwrap().reason,
        "Needs investigation"
    );
    project.release_quarantine(&id).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Open);
    assert!(project.abandon_pack(&id, 2).await.is_err());
    project.abandon_pack(&id, 1).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Abandoned);
    assert!(project.release_quarantine(&id).await.is_err());
}

#[tokio::test]
async fn pack_intent_edit_is_generation_checked() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let first = project.create_intent("First goal").unwrap();
    let second = project.create_intent("Second goal").unwrap();
    let id = project
        .create_pack("Candidate", Some(&first))
        .await
        .unwrap()
        .to_string();
    assert!(project.set_pack_intent(&id, 2, &second).await.is_err());
    assert_eq!(project.pack(&id).await.unwrap().generation, 1);
    let result = project.set_pack_intent(&id, 1, &second).await.unwrap();
    assert_eq!(result["result"]["generation"], 2);
    let pack = project.pack(&id).await.unwrap();
    assert_eq!(pack.generation, 2);
    assert_eq!(pack.intent.unwrap()["org.calve.intent"], second);
    assert!(project.set_pack_intent(&id, 1, &first).await.is_err());
}

#[tokio::test]
async fn intent_metadata_lifecycle_and_task_guard_survive_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let id = project
        .create_intent_with_metadata(
            "Ship release",
            Some("Prepare public artifacts"),
            &["release".into(), "release".into()],
        )
        .unwrap();
    assert_eq!(
        project.intent(&id).unwrap()["tags"],
        serde_json::json!(["release"])
    );
    project
        .update_intent(&id, Some("Ship v1"), Some(""), Some(&["v1".into()]))
        .unwrap();
    project.set_intent_state(&id, "CANCELLED").unwrap();
    assert_eq!(project.intent(&id).unwrap()["state"], "CANCELLED");
    assert!(project.create_task(&id, "New work").is_err());
    assert!(project.set_intent_state(&id, "COMPLETED").is_err());
    drop(project);
    let project = Project::open(temp.path()).unwrap();
    assert_eq!(project.intent(&id).unwrap()["title"], "Ship v1");
    assert!(project.intent(&id).unwrap()["description"].is_null());
    project.set_intent_state(&id, "OPEN").unwrap();
    assert!(project.create_task(&id, "New work").is_ok());
    project.set_intent_state(&id, "COMPLETED").unwrap();
    assert_eq!(project.intent(&id).unwrap()["closed"], true);
}

#[tokio::test]
async fn intent_references_validate_protocol_objects_and_survive_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let pack = project.create_pack("Graph target", None).await.unwrap();
    let actor = project.identity.created_by.to_string();
    let id = project
        .create_intent_with_references(
            "Coordinate",
            None,
            &[],
            &[actor.clone(), actor.clone()],
            Some(&pack.to_string()),
        )
        .await
        .unwrap();
    let shown = project.intent(&id).unwrap();
    assert_eq!(shown["actors"], serde_json::json!([actor]));
    assert_eq!(shown["graph_node"], pack.to_string());
    assert!(
        project
            .update_intent_with_references(&id, None, None, None, None, Some(Some("bad-node")))
            .await
            .is_err()
    );
    assert_eq!(project.intent(&id).unwrap()["graph_node"], pack.to_string());
    assert!(
        project
            .create_intent_with_references("Bad", None, &[], &["bad-actor".into()], None)
            .await
            .is_err()
    );
    let unknown_actor =
        openaevc::protocol::PrincipalId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
            .unwrap()
            .to_string();
    assert!(
        project
            .create_intent_with_references("Unknown", None, &[], &[unknown_actor], None)
            .await
            .is_err()
    );
    drop(project);
    let project = Project::open(temp.path()).unwrap();
    assert_eq!(
        project.intent(&id).unwrap()["actors"],
        serde_json::json!([actor])
    );
    assert_eq!(project.intent(&id).unwrap()["graph_node"], pack.to_string());
    project
        .update_intent_with_references(&id, None, None, None, Some(&[]), Some(None))
        .await
        .unwrap();
    drop(project);
    let reopened = Project::open(temp.path()).unwrap();
    let shown = reopened.intent(&id).unwrap();
    assert_eq!(shown["actors"], serde_json::json!([]));
    assert!(shown["graph_node"].is_null());
}

#[tokio::test]
async fn task_work_unit_link_reads_authoritative_state_and_reconciles_completion() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let intent = project.create_intent("Ship").unwrap();
    let task = project.create_task(&intent, "Run work").unwrap();
    let other = project.create_intent("Other").unwrap();
    let other_task = project.create_task(&other, "Unrelated").unwrap();
    let pack = project
        .create_pack("Candidate", Some(&intent))
        .await
        .unwrap();
    let work_unit = project
        .client
        .add_work_unit(pack, 1, "org.calve.test.work")
        .await
        .unwrap();
    assert!(
        project
            .link_task_work_unit(&other_task, &work_unit.to_string())
            .await
            .is_err()
    );
    project
        .link_task_work_unit(&task, &work_unit.to_string())
        .await
        .unwrap();
    project
        .link_task_work_unit(&task, &work_unit.to_string())
        .await
        .unwrap();
    let shown = project.task_with_protocol(&task).await.unwrap();
    assert_eq!(shown["linked_work_units"], serde_json::json!([work_unit]));
    assert_eq!(shown["linked_packs"], serde_json::json!([pack]));
    assert_eq!(shown["work_unit_states"][0]["state"], "OPEN");
    project.complete_task(&task).unwrap();
    let shown = project.task_with_protocol(&task).await.unwrap();
    assert!(
        shown["inconsistencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("open work unit"))
    );
    project
        .client
        .command(Command::UpdateWorkUnit {
            pack,
            expected_generation: 2,
            work_unit,
            spec: None,
            state: Some(WorkUnitState::Cancelled),
        })
        .await
        .unwrap();
    let shown = project.task_with_protocol(&task).await.unwrap();
    assert_eq!(shown["work_unit_states"][0]["state"], "CANCELLED");
    assert!(
        shown["inconsistencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("cancelled work unit"))
    );
    drop(project);
    let project = Project::open(temp.path()).unwrap();
    assert_eq!(
        project.task(&task).unwrap()["linked_work_units"],
        serde_json::json!([work_unit])
    );
}

#[tokio::test]
async fn evidence_binds_to_the_exact_sealed_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let id = project
        .create_pack("Evidence candidate", None)
        .await
        .unwrap()
        .to_string();
    assert!(
        project
            .register_evidence(&id, 1, "org.calve.note", "text/plain", b"note".to_vec())
            .await
            .is_err()
    );
    project.seal(&id, 1).await.unwrap();
    assert!(
        project
            .register_evidence(&id, 2, "org.calve.note", "text/plain", b"note".to_vec())
            .await
            .is_err()
    );
    let digest = project
        .register_evidence(&id, 1, "org.calve.note", "text/plain", b"note".to_vec())
        .await
        .unwrap();
    assert!(project.evidence(digest).await.unwrap().is_object());
    let listed = project.list_evidence(&id, None, 100, true).await.unwrap();
    assert_eq!(listed["items"][0]["digest"], serde_json::json!(digest));
    assert_eq!(listed["items"][0]["stale"], false);
    project.reopen(&id, 1).await.unwrap();
    assert!(
        project.list_evidence(&id, None, 100, true).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        project.list_evidence(&id, None, 100, false).await.unwrap()["items"][0]["stale"],
        true
    );
}

#[tokio::test]
async fn receipts_are_browsable_from_the_protocol_object_index() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    project
        .create_pack("Receipt candidate", None)
        .await
        .unwrap();
    let page = project.list_receipts(None, 100).await.unwrap();
    let created = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["receipt"]["command"] == "CreateChangePack")
        .unwrap();
    let digest = created["digest"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        project.receipt(digest).await.unwrap()["envelope"]["kind"],
        "receipt"
    );
    assert!(project.list_receipts(None, 0).await.is_err());
}

#[tokio::test]
async fn starting_execution_can_be_inspected_and_cancelled() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let pack = project.create_pack("Cancellable work", None).await.unwrap();
    let worker_kind = "org.calve.test.worker";
    let harness = "org.calve.test.harness";
    let provider = "org.calve.test.provider";
    project
        .client
        .command(Command::RegisterProvider {
            provider: ProviderDescriptor {
                id: provider.into(),
                version: "0.1.0".into(),
                worker_kinds: vec![worker_kind.into()],
                harnesses: vec![harness.into()],
                required_actions: vec![],
                cancellation: true,
                resumable: false,
                heartbeat: false,
                limits: BTreeMap::new(),
                provenance_fields: vec![],
                principal: project.identity.created_by,
            },
        })
        .await
        .unwrap();
    let work_unit = project
        .client
        .add_work_unit(pack, 1, worker_kind)
        .await
        .unwrap();
    let generation = project.pack(&pack.to_string()).await.unwrap().generation;
    let (execution, _) = project
        .client
        .start_execution(ExecutionRequest {
            pack,
            expected_generation: generation,
            work_unit,
            provider: provider.into(),
            harness: harness.into(),
            worker: None,
            allowed_resources: vec![],
            allowed_effects: vec![],
            context: vec![],
            timeout_ms: 60_000,
            budget: BTreeMap::new(),
            max_attempts: 1,
            idempotency_key: uuid::Uuid::now_v7().to_string(),
            retry_of: None,
        })
        .await
        .unwrap();
    let id = execution.to_string();
    assert_eq!(
        project
            .list_executions(Some(&pack.to_string()), Some(ExecutionState::Starting))
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(project.wait_execution(&id, 20).await.is_err());
    project
        .cancel_execution(&id, Some("No longer needed"))
        .await
        .unwrap();
    assert_eq!(project.execution(&id).await.unwrap()["state"], "CANCELLED");
    assert_eq!(
        project.wait_execution(&id, 20).await.unwrap()["state"],
        "CANCELLED"
    );
    assert!(project.cancel_execution(&id, None).await.is_err());
    let generation = project.pack(&pack.to_string()).await.unwrap().generation;
    let second = project
        .client
        .add_work_unit(pack, generation, worker_kind)
        .await
        .unwrap();
    let generation = project.pack(&pack.to_string()).await.unwrap().generation;
    let (failed, lease) = project
        .client
        .start_execution(ExecutionRequest {
            pack,
            expected_generation: generation,
            work_unit: second,
            provider: provider.into(),
            harness: harness.into(),
            worker: None,
            allowed_resources: vec![],
            allowed_effects: vec![],
            context: vec![],
            timeout_ms: 60_000,
            budget: BTreeMap::new(),
            max_attempts: 1,
            idempotency_key: uuid::Uuid::now_v7().to_string(),
            retry_of: None,
        })
        .await
        .unwrap();
    project
        .client
        .command(Command::FailExecution {
            execution: failed,
            lease: lease.id,
            reason: "Worker failed".into(),
        })
        .await
        .unwrap();
    let inbox = project.inbox(false).await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0]["source_key"], format!("execution:{failed}:FAILED"));
}

#[tokio::test]
async fn review_policy_gates_promotion_and_old_decisions_do_not_cross_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let id = project
        .create_pack_with_requirements("Review gated", None, false, true)
        .await
        .unwrap()
        .to_string();
    assert!(
        project
            .register_evidence(
                &id,
                1,
                "org.calve.review.approval/v1",
                "text/plain",
                b"fake approval".to_vec(),
            )
            .await
            .is_err()
    );
    project.seal(&id, 1).await.unwrap();
    project.qualify(&id, 1).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Sealed);
    assert!(project.promote(&id, 1).await.is_err());
    project.review(&id, 1, "APPROVE", "Reviewed").await.unwrap();
    let review_evidence = project.reviews(&id).await.unwrap()[0]["evidence_digest"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(project.evidence(review_evidence).await.is_ok());
    project.qualify(&id, 1).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Qualified);
    project
        .review(&id, 1, "REJECT", "Needs work")
        .await
        .unwrap();
    project.qualify(&id, 1).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Sealed);
    assert!(project.promote(&id, 1).await.is_err());
    project.reopen(&id, 1).await.unwrap();
    project.seal(&id, 2).await.unwrap();
    project.qualify(&id, 2).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Sealed);
    assert!(
        project
            .reviews(&id)
            .await
            .unwrap()
            .iter()
            .all(|review| review["stale"] == true)
    );
    project.review(&id, 2, "APPROVE", "Fixed").await.unwrap();
    project.qualify(&id, 2).await.unwrap();
    assert_eq!(project.pack(&id).await.unwrap().state, PackState::Qualified);
    let original = project.promote(&id, 2).await.unwrap();
    let revision = project
        .create_revision_pack_with_requirements(
            "Reviewed amendment",
            None,
            openaevc::protocol::RevisionRelation::Amends,
            vec![original],
            true,
        )
        .await
        .unwrap()
        .to_string();
    project.seal(&revision, 1).await.unwrap();
    project.qualify(&revision, 1).await.unwrap();
    assert_eq!(
        project.pack(&revision).await.unwrap().state,
        PackState::Sealed
    );
    project
        .review(&revision, 1, "APPROVE", "Amendment reviewed")
        .await
        .unwrap();
    project.qualify(&revision, 1).await.unwrap();
    assert!(project.promote(&revision, 1).await.is_ok());
}

#[tokio::test]
async fn cross_intent_task_dependencies_block_completion_and_reject_cycles() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let first_intent = project.create_intent("First").unwrap();
    let second_intent = project.create_intent("Second").unwrap();
    let first = project.create_task(&first_intent, "Prerequisite").unwrap();
    let second = project.create_task(&second_intent, "Dependent").unwrap();
    project.add_task_dependency(&second, &first).unwrap();
    assert!(project.add_task_dependency(&first, &second).is_err());
    assert!(project.add_task_dependency(&first, &first).is_err());
    assert!(project.complete_task(&second).is_err());
    let tasks = project.list_tasks().unwrap();
    let dependent = tasks.iter().find(|task| task["id"] == second).unwrap();
    assert_eq!(dependent["blocked_by"][0], first);
    project.complete_task(&first).unwrap();
    let tasks = project.list_tasks().unwrap();
    let dependent = tasks.iter().find(|task| task["id"] == second).unwrap();
    assert!(dependent["blocked_by"].as_array().unwrap().is_empty());
    project.complete_task(&second).unwrap();
    project.remove_task_dependency(&second, &first).unwrap();
    assert!(project.remove_task_dependency(&second, &first).is_err());
    let third = project.create_task(&first_intent, "Later").unwrap();
    assert!(project.add_task_dependency(&second, &third).is_err());
}

#[tokio::test]
async fn project_pack_baseline_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), Some("Example")).await.unwrap();
    assert!(
        !compatibility::query(&project.client)
            .await
            .unwrap()
            .protocol
            .is_empty()
    );
    let project_id = project.identity.project_id.clone();
    let intent = project.create_intent("Describe the change").unwrap();
    let task = project.create_task(&intent, "Do the work").unwrap();
    project.complete_task(&task).unwrap();

    let pack = project
        .create_pack("First change", Some(&intent))
        .await
        .unwrap();
    let sealed = project.seal(&pack.to_string(), 1).await.unwrap();
    assert!(!sealed.to_string().is_empty());
    project.qualify(&pack.to_string(), 1).await.unwrap();
    assert_eq!(
        project.pack(&pack.to_string()).await.unwrap().state,
        PackState::Qualified
    );
    let promoted = project.promote(&pack.to_string(), 1).await.unwrap();
    let (baseline, digest) = project
        .create_baseline("accepted", vec![promoted])
        .await
        .unwrap();
    project
        .activate_baseline(&baseline.to_string())
        .await
        .unwrap();
    assert!(!digest.to_string().is_empty());
    drop(project);

    let reopened = Project::open(temp.path()).unwrap();
    assert_eq!(reopened.identity.project_id, project_id);
    assert_eq!(
        reopened.pack(&pack.to_string()).await.unwrap().state,
        PackState::Promoted
    );
    assert_eq!(
        reopened.active_baseline().unwrap().as_deref(),
        Some(baseline.to_string().as_str())
    );
    assert_eq!(reopened.list_intents().unwrap().len(), 1);
    assert_eq!(reopened.list_tasks().unwrap().len(), 1);
    assert_eq!(reopened.list_baselines().await.unwrap().len(), 1);
    assert!(reopened.baseline(&baseline.to_string()).await.is_ok());
}

#[tokio::test]
async fn stale_generation_cannot_seal_after_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let pack = project.create_pack("Change", None).await.unwrap();
    project.seal(&pack.to_string(), 1).await.unwrap();
    project
        .review(&pack.to_string(), 1, "APPROVE", "looks good")
        .await
        .unwrap();
    assert!(project.reviews(&pack.to_string()).await.unwrap()[0]["evidence_digest"].is_null());
    assert!(
        !project.reviews(&pack.to_string()).await.unwrap()[0]["stale"]
            .as_bool()
            .unwrap()
    );
    project.reopen(&pack.to_string(), 1).await.unwrap();
    assert!(project.seal(&pack.to_string(), 1).await.is_err());
    assert_eq!(
        project.pack(&pack.to_string()).await.unwrap().state,
        PackState::Open
    );
    assert!(
        project.reviews(&pack.to_string()).await.unwrap()[0]["stale"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn inbox_deduplicates_sources_and_tracks_attention_without_changing_them() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let quarantined = project
        .create_pack("Quarantined", None)
        .await
        .unwrap()
        .to_string();
    project
        .quarantine_pack(&quarantined, "Inspect")
        .await
        .unwrap();
    let reviewed = project
        .create_pack("Reviewed", None)
        .await
        .unwrap()
        .to_string();
    project.seal(&reviewed, 1).await.unwrap();
    project
        .review(&reviewed, 1, "APPROVE", "Looks good")
        .await
        .unwrap();
    project.reopen(&reviewed, 1).await.unwrap();
    let items = project.inbox(false).await.unwrap();
    assert_eq!(items.len(), 2);
    let quarantine_key = format!("pack:{quarantined}:quarantined");
    let item = items
        .iter()
        .find(|item| item["source_key"] == quarantine_key)
        .unwrap();
    assert_eq!(item["needs_attention"], true);
    assert_eq!(project.inbox(false).await.unwrap().len(), 2);
    project
        .update_inbox_item(&quarantine_key, "read", None)
        .await
        .unwrap();
    project
        .update_inbox_item(&quarantine_key, "acknowledge", None)
        .await
        .unwrap();
    let acknowledged = project.inbox(false).await.unwrap();
    let item = acknowledged
        .iter()
        .find(|item| item["source_key"] == quarantine_key)
        .unwrap();
    assert_eq!(item["needs_attention"], false);
    assert!(item["acknowledged_at"].is_number());
    assert_eq!(
        project.pack(&quarantined).await.unwrap().state.as_str(),
        "QUARANTINED"
    );
    let until = 2_000_000_000u64;
    project
        .update_inbox_item(&quarantine_key, "snooze", Some(until))
        .await
        .unwrap();
    let snoozed = project.inbox(false).await.unwrap();
    assert_eq!(
        snoozed
            .iter()
            .find(|item| item["source_key"] == quarantine_key)
            .unwrap()["snoozed_until"],
        until
    );
    project.release_quarantine(&quarantined).await.unwrap();
    assert_eq!(project.inbox(false).await.unwrap().len(), 1);
    let history = project.inbox(true).await.unwrap();
    assert_eq!(history.len(), 2);
    assert!(
        history
            .iter()
            .find(|item| item["source_key"] == quarantine_key)
            .unwrap()["resolved_at"]
            .is_number()
    );
    project
        .quarantine_pack(&quarantined, "Inspect again")
        .await
        .unwrap();
    let reopened = project.inbox(false).await.unwrap();
    let item = reopened
        .iter()
        .find(|item| item["source_key"] == quarantine_key)
        .unwrap();
    assert_eq!(item["needs_attention"], true);
    assert!(item["acknowledged_at"].is_null());
    assert!(item["snoozed_until"].is_null());
}

#[tokio::test]
async fn task_metadata_can_be_created_updated_and_cleared() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let intent = project.create_intent("Ship").unwrap();
    let task = project
        .create_task_with_metadata(&intent, "Draft", Some("First draft"), "high", Some("alex"))
        .unwrap();
    let created = project.list_tasks().unwrap();
    assert_eq!(created[0]["description"], "First draft");
    assert_eq!(created[0]["priority"], "high");
    assert_eq!(created[0]["assignee"], "alex");
    project
        .update_task(
            &task,
            Some("Final draft"),
            Some(""),
            Some("urgent"),
            Some(""),
        )
        .unwrap();
    let updated = project.list_tasks().unwrap();
    assert_eq!(updated[0]["title"], "Final draft");
    assert_eq!(updated[0]["description"], serde_json::Value::Null);
    assert_eq!(updated[0]["priority"], "urgent");
    assert_eq!(updated[0]["assignee"], serde_json::Value::Null);
    assert!(project.update_task(&task, None, None, None, None).is_err());
    assert!(
        project
            .update_task(&task, None, None, Some("critical"), None)
            .is_err()
    );
}

#[tokio::test]
async fn task_lifecycle_and_pack_links_are_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let intent = project.create_intent("Deliver").unwrap();
    let other_intent = project.create_intent("Other").unwrap();
    let first = project.create_task(&intent, "Prepare").unwrap();
    let second = project.create_task(&intent, "Ship").unwrap();
    project.add_task_dependency(&second, &first).unwrap();
    assert!(project.start_task(&second).is_err());
    project.start_task(&first).unwrap();
    project.block_task(&first, "Waiting for review").unwrap();
    assert!(project.complete_task(&first).is_err());
    assert_eq!(
        project.task(&first).unwrap()["blocked_reason"],
        "Waiting for review"
    );
    project.unblock_task(&first).unwrap();
    project.complete_task(&first).unwrap();
    project.start_task(&second).unwrap();
    project.complete_task(&second).unwrap();
    assert!(project.reopen_task(&first).is_err());
    project.reopen_task(&second).unwrap();
    project.reopen_task(&first).unwrap();
    let pack = project
        .create_pack("Candidate", Some(&intent))
        .await
        .unwrap()
        .to_string();
    project.link_task_pack(&first, &pack).await.unwrap();
    project.link_task_pack(&first, &pack).await.unwrap();
    let other_task = project.create_task(&other_intent, "Other task").unwrap();
    assert!(project.link_task_pack(&other_task, &pack).await.is_err());
    assert_eq!(
        project.task(&first).unwrap()["linked_packs"],
        serde_json::json!([pack.clone()])
    );
    project
        .set_pack_intent(&pack, 1, &other_intent)
        .await
        .unwrap();
    assert!(
        project.task_with_protocol(&first).await.unwrap()["inconsistencies"][0]
            .as_str()
            .unwrap()
            .contains("another Intent")
    );
    drop(project);
    let project = Project::open(temp.path()).unwrap();
    assert_eq!(project.task(&first).unwrap()["state"], "OPEN");
    assert_eq!(
        project.task(&first).unwrap()["linked_packs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn completed_task_surfaces_cancelled_linked_execution() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let intent = project.create_intent("Run worker").unwrap();
    let task = project.create_task(&intent, "Execute").unwrap();
    let pack = project.create_pack("Work", Some(&intent)).await.unwrap();
    let worker_kind = "org.calve.test.worker";
    let harness = "org.calve.test.harness";
    let provider = "org.calve.test.provider";
    project
        .client
        .command(Command::RegisterProvider {
            provider: ProviderDescriptor {
                id: provider.into(),
                version: "0.1.0".into(),
                worker_kinds: vec![worker_kind.into()],
                harnesses: vec![harness.into()],
                required_actions: vec![],
                cancellation: true,
                resumable: false,
                heartbeat: false,
                limits: BTreeMap::new(),
                provenance_fields: vec![],
                principal: project.identity.created_by,
            },
        })
        .await
        .unwrap();
    let work_unit = project
        .client
        .add_work_unit(pack, 1, worker_kind)
        .await
        .unwrap();
    let generation = project.pack(&pack.to_string()).await.unwrap().generation;
    let (execution, _) = project
        .client
        .start_execution(ExecutionRequest {
            pack,
            expected_generation: generation,
            work_unit,
            provider: provider.into(),
            harness: harness.into(),
            worker: None,
            allowed_resources: vec![],
            allowed_effects: vec![],
            context: vec![],
            timeout_ms: 60_000,
            budget: BTreeMap::new(),
            max_attempts: 1,
            idempotency_key: uuid::Uuid::now_v7().to_string(),
            retry_of: None,
        })
        .await
        .unwrap();
    let execution_id = execution.to_string();
    project
        .link_task_execution(&task, &execution_id)
        .await
        .unwrap();
    project
        .cancel_execution(&execution_id, Some("Cancelled for test"))
        .await
        .unwrap();
    project.complete_task(&task).unwrap();
    let shown = project.task_with_protocol(&task).await.unwrap();
    assert_eq!(shown["linked_packs"], serde_json::json!([pack.to_string()]));
    assert_eq!(shown["execution_states"][0]["state"], "CANCELLED");
    assert!(
        shown["inconsistencies"][0]
            .as_str()
            .unwrap()
            .contains("cancelled execution")
    );
    assert_eq!(
        project.status().await.unwrap()["tasks"][0]["inconsistencies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let inbox = project.inbox(false).await.unwrap();
    assert!(
        inbox
            .iter()
            .any(|item| item["source_key"] == format!("task:{task}:inconsistent"))
    );
    project.reopen_task(&task).unwrap();
    assert!(
        project
            .inbox(false)
            .await
            .unwrap()
            .iter()
            .all(|item| item["kind"] != "task_inconsistency")
    );
}

#[tokio::test]
async fn project_database_migration_is_versioned() {
    fn remove_pack_index_v13(db: &rusqlite::Connection) {
        db.execute_batch(
            "DROP TABLE pack_files; DROP TABLE pack_summaries; DROP TABLE projection_checkpoints;",
        )
        .unwrap();
    }
    fn remove_extension_grants_v11(db: &rusqlite::Connection) {
        remove_pack_index_v13(db);
        db.execute_batch("DROP TABLE extension_grants; DROP TABLE adoptions;")
            .unwrap();
    }
    fn remove_task_work_units_v10(db: &rusqlite::Connection) {
        remove_extension_grants_v11(db);
        db.execute_batch("DROP TABLE task_work_units;").unwrap();
    }
    fn remove_intent_references_v9(db: &rusqlite::Connection) {
        remove_task_work_units_v10(db);
        db.execute_batch(
            "ALTER TABLE intents DROP COLUMN actors;
             ALTER TABLE intents DROP COLUMN graph_node;",
        )
        .unwrap();
    }
    fn remove_activity_v8(db: &rusqlite::Connection) {
        remove_intent_references_v9(db);
        db.execute_batch("ALTER TABLE product_events DROP COLUMN created_at_ns;")
            .unwrap();
    }
    fn remove_intent_v6(db: &rusqlite::Connection) {
        db.execute_batch(
            "ALTER TABLE intents DROP COLUMN description;
            ALTER TABLE intents DROP COLUMN tags;
            ALTER TABLE intents DROP COLUMN state;
            ALTER TABLE intents DROP COLUMN updated_at;",
        )
        .unwrap();
    }
    fn remove_task_v7(db: &rusqlite::Connection) {
        remove_activity_v8(db);
        db.execute_batch("DROP TABLE task_links; ALTER TABLE tasks DROP COLUMN blocked_reason;")
            .unwrap();
    }
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let old_intent = project.create_intent("Legacy closed goal").unwrap();
    drop(project);
    let path = temp.path().join(".calve/product.sqlite3");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("DROP TABLE store_binding; ALTER TABLE product_events DROP COLUMN actor;")
        .unwrap();
    remove_task_v7(&db);
    remove_intent_v6(&db);
    db.execute("UPDATE intents SET closed=1 WHERE id=?1", [&old_intent])
        .unwrap();
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DROP TABLE inbox_items; ALTER TABLE tasks DROP COLUMN description; ALTER TABLE tasks DROP COLUMN priority; ALTER TABLE tasks DROP COLUMN assignee; ALTER TABLE tasks DROP COLUMN updated_at; ALTER TABLE reviews DROP COLUMN evidence_digest; DROP TABLE task_dependencies; DELETE FROM schema_migrations WHERE version>=2; PRAGMA user_version=0").unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    assert_eq!(migrated.intent(&old_intent).unwrap()["state"], "COMPLETED");
    let old_event = migrated
        .product_activity(10)
        .unwrap()
        .into_iter()
        .find(|item| item["kind"] == "intent.created")
        .unwrap();
    assert_eq!(
        old_event["created_at_ns"].as_i64().unwrap(),
        old_event["created_at"].as_i64().unwrap() * 1_000_000_000
    );
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    db.prepare("SELECT actors,graph_node FROM intents").unwrap();
    db.prepare("SELECT task_id,work_unit_id FROM task_work_units")
        .unwrap();
    db.prepare("SELECT created_at_ns FROM product_events")
        .unwrap();
    db.prepare("SELECT task_id,kind,object_id FROM task_links")
        .unwrap();
    db.prepare("SELECT blocked_reason FROM tasks").unwrap();
    db.prepare("SELECT evidence_digest FROM reviews").unwrap();
    db.prepare("SELECT description,priority,assignee,updated_at FROM tasks")
        .unwrap();
    db.prepare("SELECT source_key,resolved_at FROM inbox_items")
        .unwrap();
    db.prepare("SELECT description,tags,state,updated_at FROM intents")
        .unwrap();
    remove_task_v7(&db);
    remove_intent_v6(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DROP TABLE inbox_items; ALTER TABLE tasks DROP COLUMN description; ALTER TABLE tasks DROP COLUMN priority; ALTER TABLE tasks DROP COLUMN assignee; ALTER TABLE tasks DROP COLUMN updated_at; ALTER TABLE reviews DROP COLUMN evidence_digest; DELETE FROM schema_migrations WHERE version>=3; PRAGMA user_version=2").unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_task_v7(&db);
    remove_intent_v6(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DROP TABLE inbox_items; ALTER TABLE tasks DROP COLUMN description; ALTER TABLE tasks DROP COLUMN priority; ALTER TABLE tasks DROP COLUMN assignee; ALTER TABLE tasks DROP COLUMN updated_at; DELETE FROM schema_migrations WHERE version>=4; PRAGMA user_version=3").unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_task_v7(&db);
    remove_intent_v6(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DROP TABLE inbox_items; DELETE FROM schema_migrations WHERE version>=5; PRAGMA user_version=4").unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_task_v7(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DELETE FROM schema_migrations WHERE version>=7; PRAGMA user_version=6")
        .unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_activity_v8(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DELETE FROM schema_migrations WHERE version>=8; PRAGMA user_version=7")
        .unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_intent_references_v9(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DELETE FROM schema_migrations WHERE version>=9; PRAGMA user_version=8")
        .unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    assert_eq!(
        migrated.intent(&old_intent).unwrap()["actors"],
        serde_json::json!([])
    );
    assert!(migrated.intent(&old_intent).unwrap()["graph_node"].is_null());
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_task_work_units_v10(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DELETE FROM schema_migrations WHERE version>=10; PRAGMA user_version=9")
        .unwrap();
    drop(db);
    let migrated = Project::open(temp.path()).unwrap();
    assert_eq!(migrated.list_tasks().unwrap().len(), 0);
    drop(migrated);
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    remove_extension_grants_v11(&db);
    db.execute_batch("DROP TABLE IF EXISTS store_binding;")
        .unwrap();
    let _ = db.execute_batch("ALTER TABLE product_events DROP COLUMN actor;");
    db.execute_batch("DELETE FROM schema_migrations WHERE version>=11; PRAGMA user_version=10")
        .unwrap();
    drop(db);
    drop(Project::open(temp.path()).unwrap());
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, calve_app::PRODUCT_SCHEMA);
    db.prepare("SELECT capability FROM extension_grants")
        .unwrap();
    db.execute_batch("PRAGMA user_version=99").unwrap();
    drop(db);
    assert!(Project::open(temp.path()).is_err());
}

#[tokio::test]
async fn baseline_alias_validation_and_comparison_use_protocol_objects() {
    let temp = tempfile::tempdir().unwrap();
    let project = Project::init(temp.path(), None).await.unwrap();
    let first = project.create_pack("First", None).await.unwrap();
    project.seal(&first.to_string(), 1).await.unwrap();
    project.qualify(&first.to_string(), 1).await.unwrap();
    let first_digest = project.promote(&first.to_string(), 1).await.unwrap();
    let second = project.create_pack("Second", None).await.unwrap();
    project.seal(&second.to_string(), 1).await.unwrap();
    project.qualify(&second.to_string(), 1).await.unwrap();
    let second_digest = project.promote(&second.to_string(), 1).await.unwrap();
    let (a, _) = project
        .create_baseline("A", vec![first_digest])
        .await
        .unwrap();
    let (b, _) = project
        .create_baseline("B", vec![first_digest, second_digest])
        .await
        .unwrap();
    let a = a.to_string();
    let b = b.to_string();

    assert_eq!(project.set_baseline_alias("current", &b).await.unwrap(), b);
    assert_eq!(
        project.list_baseline_aliases().unwrap()[0]["alias"],
        "current"
    );
    assert_eq!(project.activate_baseline("current").await.unwrap(), b);
    assert_eq!(
        project.active_baseline().unwrap().as_deref(),
        Some(b.as_str())
    );
    assert!(project.baseline("current").await.is_ok());
    assert!(project.validate_baseline("current").await.is_ok());
    assert!(project.baseline_graph("current").await.is_ok());
    let comparison = project.compare_baselines(&a, "current").await.unwrap();
    assert_eq!(comparison["shared_members"].as_array().unwrap().len(), 1);
    assert_eq!(
        comparison["only_right_members"].as_array().unwrap().len(),
        1
    );
    assert!(
        comparison["only_left_members"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        comparison["left_missing_objects"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        comparison["right_missing_objects"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(project.set_baseline_alias("../bad", &a).await.is_err());
    project.remove_baseline_alias("current").unwrap();
    assert!(project.baseline("current").await.is_err());
    assert_eq!(
        project.active_baseline().unwrap().as_deref(),
        Some(b.as_str())
    );
}
