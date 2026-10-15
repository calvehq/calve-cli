//! Supported public OpenAEVC contract for this Calve build.

use openaevc::protocol::{
    PROTOCOL_VERSION, RuntimeInfo, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL, VersionRange,
};
use openaevc_sdk::OpenAevcClient;
use serde::Serialize;

use crate::Result;

/// The OpenAEVC release this build is pinned to (ADR 0003). `xtask check-architecture`
/// asserts that Cargo.lock resolves both `openaevc` and `openaevc-sdk` to exactly this tag and
/// commit.
pub const OPENAEVC_TAG: &str = "v0.1.0";
pub const OPENAEVC_REVISION: &str = "5720d3ec15bee6c49630b2cec5a21afd357dedf8";
pub const OPENAEVC_CRATE_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize)]
pub struct Compatibility {
    pub openaevc_tag: &'static str,
    pub openaevc_revision: &'static str,
    pub openaevc_crate_version: &'static str,
    pub runtime_name: String,
    pub runtime_version: String,
    pub protocol: String,
    pub extension_contract: String,
}

pub fn check(info: &RuntimeInfo) -> Result<Compatibility> {
    let protocol = check_range("protocol", &SUPPORTED_PROTOCOL, &info.protocol)?;
    let contract = check_range("extension contract", &SUPPORTED_CONTRACT, &info.contract)?;
    Ok(Compatibility {
        openaevc_tag: OPENAEVC_TAG,
        openaevc_revision: OPENAEVC_REVISION,
        openaevc_crate_version: OPENAEVC_CRATE_VERSION,
        runtime_name: info.implementation.name.clone(),
        runtime_version: info.implementation.version.clone(),
        protocol,
        extension_contract: contract,
    })
}

pub(crate) fn check_range(
    label: &str,
    supported: &VersionRange,
    runtime: &VersionRange,
) -> Result<String> {
    supported.negotiate(runtime).map(|version| version.to_string()).ok_or_else(|| {
        crate::coded("OPENAEVC_INCOMPATIBLE", format!(
            "OpenAEVC {label} is incompatible: runtime {}..={}, Calve SDK {}..={} (built for {})",
            runtime.min, runtime.max, supported.min, supported.max, PROTOCOL_VERSION
        ))
    })
}

pub async fn query(client: &impl OpenAevcClient) -> Result<Compatibility> {
    let value = client
        .query(openaevc::protocol::Query::GetRuntimeInfo {})
        .await?;
    let info: RuntimeInfo = serde_json::from_value(value)?;
    check(&info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc::protocol::ProtocolVersion;

    #[test]
    fn incompatible_protocol_range_is_rejected() {
        let newer = VersionRange::new(ProtocolVersion::new(9, 0, 0), ProtocolVersion::new(9, 0, 1));
        assert!(check_range("protocol", &SUPPORTED_PROTOCOL, &newer).is_err());
    }
}
