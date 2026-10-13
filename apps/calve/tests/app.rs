use calve_app::app::{
    Action, Actor, OperationKind, Outcome, Request, RequestScope, WorkspaceCommand, execute,
};
use uuid::Uuid;

fn scope() -> RequestScope {
    RequestScope {
        project: None,
        workspace: None,
        config_file: None,
        actor: None,
    }
}

#[tokio::test]
async fn application_envelope_correlates_success_and_version_error() {
    let request = Request::local(scope(), Action::Version);
    let id = request.request_id;
    let encoded = serde_json::to_vec(&request).unwrap();
    let decoded: Request = serde_json::from_slice(&encoded).unwrap();
    let response = execute(decoded).await;
    assert_eq!(response.request_id, id);
    assert_eq!(response.api_version, 1);
    match response.outcome {
        Outcome::Ok { value } => assert_eq!(value["api_version"], 1),
        Outcome::Error { error } => panic!("unexpected error: {}", error.message),
    }

    let invalid = Request {
        api_version: 999,
        payload_version: 1,
        request_id: Uuid::now_v7(),
        correlation_id: None,
        actor: Actor::LocalUser,
        scope: scope(),
        operation_kind: OperationKind::Command,
        action: Action::Workspace {
            command: WorkspaceCommand::Create {
                name: "must not run".into(),
            },
        },
    };
    let id = invalid.request_id;
    let response = execute(invalid).await;
    assert_eq!(response.request_id, id);
    match response.outcome {
        Outcome::Error { error } => assert_eq!(error.code, "UNSUPPORTED_API_VERSION"),
        Outcome::Ok { .. } => panic!("unsupported API version was accepted"),
    }
}
