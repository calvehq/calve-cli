//! Test-only third-party extension. Tests copy this binary and append
//! `CALVE-FIXTURE:{"version":"1.1.0","caps":["clock.read"]}` to create distinct artifacts.
#![forbid(unsafe_code)]

use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
use openaevc::extension::wire::{Operation, WireError};
use openaevc::protocol::*;
use serde_json::Value;

struct Fixture {
    version: String,
    caps: Vec<HostCapability>,
}

fn trailer() -> Value {
    let bytes = std::env::current_exe()
        .and_then(std::fs::read)
        .unwrap_or_default();
    let marker = b"CALVE-FIXTURE:";
    bytes
        .windows(marker.len())
        .rposition(|window| window == marker)
        .and_then(|at| serde_json::from_slice(&bytes[at + marker.len()..]).ok())
        .unwrap_or(Value::Null)
}

impl Extension for Fixture {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: "org.example.fixture".into(),
            version: self.version.clone(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![],
            effect_kinds: vec![],
            verifier_kinds: vec![],
            evaluator_kinds: vec![],
            composition_validators: vec![],
            host_capabilities: self.caps.clone(),
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "fixture_ext".into(),
                args: vec![],
            },
        }
    }

    fn handle(
        &mut self,
        operation: Operation,
        _: &mut HostContext<'_>,
    ) -> Result<Value, WireError> {
        Err(WireError::new("unsupported", operation.name()))
    }
}

fn main() -> std::process::ExitCode {
    let trailer = trailer();
    serve(Fixture {
        version: trailer["version"].as_str().unwrap_or("1.0.0").into(),
        caps: serde_json::from_value(trailer["caps"].clone()).unwrap_or_default(),
    })
}
