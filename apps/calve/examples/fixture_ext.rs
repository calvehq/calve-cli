//! Test-only third-party extension. Tests copy this binary and append
//! `CALVE-FIXTURE:{"version":"1.1.0","caps":["clock.read"]}` to create distinct artifacts.
#![forbid(unsafe_code)]

use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
use openaevc::extension::wire::{Operation, WireError};
use openaevc::protocol::*;
use serde_json::Value;

const RECORD: &str = "org.example.fixture.record";
const RECORD_SET: &str = "org.example.fixture.record.set";

struct Fixture {
    version: String,
    caps: Vec<HostCapability>,
    /// The protocol range to advertise, for Scenario P: `[[major, minor], [major, minor]]`.
    protocol: Option<VersionRange>,
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
            protocol: self.protocol.unwrap_or(SUPPORTED_PROTOCOL),
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: RECORD.into(),
                description: Some("a third-party record".into()),
            }],
            effect_kinds: vec![EffectKindDecl {
                kind: RECORD_SET.into(),
                resource_kind: RECORD.into(),
                required_actions: vec!["org.example.fixture.write".into()],
            }],
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
        match operation {
            Operation::ValidateEffect { effect, .. } => {
                let valid = effect.kind == RECORD_SET && effect.payload.is_object();
                serde_json::to_value(openaevc::extension::wire::ValidateOutput {
                    valid,
                    reason: (!valid).then(|| "a record is a JSON object".to_owned()),
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            Operation::ApplyEffect { effect, .. } => {
                serde_json::to_value(openaevc::extension::wire::ApplyOutput {
                    outcome: effect.payload,
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            other => Err(WireError::new("unsupported", other.name())),
        }
    }
}

fn main() -> std::process::ExitCode {
    let trailer = trailer();
    serve(Fixture {
        version: trailer["version"].as_str().unwrap_or("1.0.0").into(),
        caps: serde_json::from_value(trailer["caps"].clone()).unwrap_or_default(),
        protocol: trailer["protocol"].as_array().map(|r| {
            let version = |i: usize| {
                ProtocolVersion::new(
                    r[i][0].as_u64().unwrap_or(0) as u32,
                    r[i][1].as_u64().unwrap_or(0) as u32,
                    0,
                )
            };
            VersionRange::new(version(0), version(1))
        }),
    })
}
