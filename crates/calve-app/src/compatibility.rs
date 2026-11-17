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

/// §46.4 step 4: every extension registered (active) in the Namespace speaks a contract this
/// build supports. `query` runs one OpenAEVC query.
pub fn check_enabled_extensions(
    query: &dyn Fn(openaevc::protocol::Query) -> Result<serde_json::Value>,
) -> Result<()> {
    let listed = query(openaevc::protocol::Query::ListExtensions {})?;
    for e in listed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["active"] == true)
    {
        let Ok(digest) = serde_json::from_value(e["manifest"].clone()) else {
            continue;
        };
        let manifest = query(openaevc::protocol::Query::GetObject { digest })?;
        let protocol: VersionRange =
            serde_json::from_value(manifest["envelope"]["body"]["protocol"].clone())?;
        if SUPPORTED_PROTOCOL.negotiate(&protocol).is_none() {
            return Err(crate::coded(
                "EXTENSION_INCOMPATIBLE",
                format!(
                    "enabled extension {} speaks protocol {}..={}, this Calve supports {}..={}; disable or update it",
                    e["id"].as_str().unwrap_or("?"),
                    protocol.min,
                    protocol.max,
                    SUPPORTED_PROTOCOL.min,
                    SUPPORTED_PROTOCOL.max
                ),
            ));
        }
        let contract: VersionRange =
            serde_json::from_value(manifest["envelope"]["body"]["contract"].clone())?;
        if SUPPORTED_CONTRACT.negotiate(&contract).is_none() {
            return Err(crate::coded(
                "EXTENSION_INCOMPATIBLE",
                format!(
                    "enabled extension {} speaks contract {}..={}, this Calve supports {}..={}; disable it or upgrade",
                    e["id"].as_str().unwrap_or("?"),
                    contract.min,
                    contract.max,
                    SUPPORTED_CONTRACT.min,
                    SUPPORTED_CONTRACT.max
                ),
            ));
        }
    }
    Ok(())
}

/// Debug builds: `CALVE_TEST_RUNTIME_PROTOCOL` simulates a runtime speaking another protocol, as
/// `<major>.<minor>` or `<major>.<minor>-<major>.<minor>`, because only one OpenAEVC can be linked
/// (§57 P). It simulates; it is not a second implementation. Release builds do not contain it,
/// which `xtask dist` verifies on every archive.
#[cfg(debug_assertions)]
fn simulated_protocol() -> Option<Result<VersionRange>> {
    use openaevc::protocol::ProtocolVersion;
    let raw = std::env::var("CALVE_TEST_RUNTIME_PROTOCOL").ok()?;
    let version = |s: &str| -> Option<ProtocolVersion> {
        let (major, minor) = s.split_once('.').unwrap_or((s, "0"));
        Some(ProtocolVersion::new(
            major.parse().ok()?,
            minor.parse().ok()?,
            0,
        ))
    };
    let (min, max) = raw.split_once('-').unwrap_or((raw.as_str(), raw.as_str()));
    Some(match (version(min), version(max)) {
        (Some(min), Some(max)) if min <= max => Ok(VersionRange::new(min, max)),
        _ => Err(crate::coded(
            "OPENAEVC_INCOMPATIBLE",
            format!("OpenAEVC reported a malformed protocol range {raw:?}"),
        )),
    })
}

pub fn check(info: &RuntimeInfo) -> Result<Compatibility> {
    #[cfg(debug_assertions)]
    let reported = match simulated_protocol() {
        Some(simulated) => simulated?,
        None => info.protocol,
    };
    #[cfg(not(debug_assertions))]
    let reported = info.protocol;
    let protocol = check_range("protocol", &SUPPORTED_PROTOCOL, &reported)?;
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
