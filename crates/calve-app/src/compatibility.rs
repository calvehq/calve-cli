//! Supported public OpenAEVC contract for this Calve build.

use openaevc_protocol::{
    PROTOCOL_VERSION, RuntimeInfo, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL, VersionRange,
};
use openaevc_sdk::OpenAevcClient;
use serde::Serialize;

use crate::{Error, Result};

/// Tracks calvehq/openaevc `main` until a release tag exists; matches Cargo.lock.
pub const OPENAEVC_REVISION: &str = "288b804fc2b7d178de9dd2de20d13e615aed02c8";
pub const OPENAEVC_CRATE_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize)]
pub struct Compatibility {
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
        Error::Message(format!(
            "OpenAEVC {label} is incompatible: runtime {}..={}, Calve SDK {}..={} (built for {})",
            runtime.min, runtime.max, supported.min, supported.max, PROTOCOL_VERSION
        ))
    })
}

pub async fn query(client: &impl OpenAevcClient) -> Result<Compatibility> {
    let value = client
        .query(openaevc_protocol::Query::GetRuntimeInfo {})
        .await?;
    let info: RuntimeInfo = serde_json::from_value(value)?;
    check(&info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::ProtocolVersion;

    #[test]
    fn incompatible_protocol_range_is_rejected() {
        let newer = VersionRange::new(ProtocolVersion::new(9, 0, 0), ProtocolVersion::new(9, 0, 1));
        assert!(check_range("protocol", &SUPPORTED_PROTOCOL, &newer).is_err());
    }
}
