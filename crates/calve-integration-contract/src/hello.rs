//! `hello/0` (frozen forever) and negotiation over the four version axes (rev 10 §6.1, §25).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One CIC wire major with its minor range. A range never spans majors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CicRange {
    pub major: u32,
    pub min_minor: u32,
    pub max_minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    pub abi: Vec<u32>,
    pub cic: Vec<CicRange>,
    pub capabilities: Vec<String>,
    pub schemas: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestHello {
    pub abi: u32,
    pub cic: Vec<CicRange>,
    pub capabilities: Capabilities,
    pub schema: u32,
    pub extension_id: String,
    pub version: String,
}

/// Frozen `hello/0` request: `{"hello":0,"host":{…}}`. `x` is reserved and ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloRequest {
    pub hello: u32,
    pub host: HostHello,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<serde_json::Value>,
}

/// Frozen `hello/0` reply: `{"hello":0,"guest":{…}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub hello: u32,
    pub guest: GuestHello,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub abi: u32,
    pub major: u32,
    pub minor: u32,
    pub capabilities: BTreeSet<String>,
}

impl Negotiated {
    pub fn wire(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    Abi,
    Wire,
    Capability(String),
    Schema(u32),
    /// The guest's hello disagrees with its signed metadata.
    MetadataMismatch(&'static str),
}

/// Declared (signed metadata) values the guest's hello must equal exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub abi: u32,
    pub cic: Vec<CicRange>,
    pub capabilities: Capabilities,
    pub schema: u32,
}

/// Negotiates per rev 10 §6.1: exact ABI; highest common wire major with intersecting minors;
/// capabilities = host ∩ advertised, all required present; schema supported; and the guest's
/// advertised values equal its signed declaration.
pub fn negotiate(
    host: &HostHello,
    guest: &GuestHello,
    declared: &Declared,
) -> Result<Negotiated, NegotiationError> {
    if guest.abi != declared.abi {
        return Err(NegotiationError::MetadataMismatch("abi"));
    }
    if guest.cic != declared.cic {
        return Err(NegotiationError::MetadataMismatch("cic"));
    }
    if guest.capabilities != declared.capabilities {
        return Err(NegotiationError::MetadataMismatch("capabilities"));
    }
    if guest.schema != declared.schema {
        return Err(NegotiationError::MetadataMismatch("schema"));
    }
    if !host.abi.contains(&guest.abi) {
        return Err(NegotiationError::Abi);
    }
    if !host.schemas.contains(&guest.schema) {
        return Err(NegotiationError::Schema(guest.schema));
    }
    let mut best: Option<(u32, u32)> = None;
    for h in &host.cic {
        for g in guest.cic.iter().filter(|g| g.major == h.major) {
            let lo = h.min_minor.max(g.min_minor);
            let hi = h.max_minor.min(g.max_minor);
            if lo <= hi && best.is_none_or(|(m, _)| h.major > m) {
                best = Some((h.major, hi));
            }
        }
    }
    let (major, minor) = best.ok_or(NegotiationError::Wire)?;
    let host_caps: BTreeSet<&String> = host.capabilities.iter().collect();
    let advertised = guest
        .capabilities
        .required
        .iter()
        .chain(&guest.capabilities.optional);
    let capabilities: BTreeSet<String> = advertised
        .filter(|c| host_caps.contains(c))
        .cloned()
        .collect();
    if let Some(missing) = guest
        .capabilities
        .required
        .iter()
        .find(|c| !capabilities.contains(*c))
    {
        return Err(NegotiationError::Capability(missing.clone()));
    }
    Ok(Negotiated {
        abi: guest.abi,
        major,
        minor,
        capabilities,
    })
}
