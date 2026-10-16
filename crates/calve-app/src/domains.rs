//! Domain declarations of the active packages (rev 10 §4 INV-022, §8): the host learns every
//! resource and effect kind, verifier and evaluator from the signed `calve-integration.json` of
//! the packages enabled in this Project, and reaches domain semantics only through CIC
//! sessions in the supervised sandbox. No first-party domain literal lives in the host.

use calve_integration_contract::driver::{Driver, HostError, Session};
use calve_integration_contract::metadata::{ChecksDecl, FilesDecl, Metadata, ResourceDecl};
use openaevc::protocol::AppliedEffect;
use serde_json::Value;

use crate::catalog::install::PackageRecord;
use crate::sandbox::{HostConfig, SandboxDriver, sandbox_program};
use crate::{Error, Project, Result};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

pub(crate) fn cic_error(e: HostError) -> Error {
    invalid(format!("{}: CIC session failed: {e}", e.code()))
}

/// How a file-domain effect changes file state (`calve.file/1` payloads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileOp {
    /// `{digest, size, content}`.
    Put,
    /// `{previous_digest}`.
    Delete,
    /// History only: `{from, digest, size, content}`.
    Move,
}

/// The file domain of this Project (exactly one active package declares `files`).
#[derive(Debug, Clone)]
pub(crate) struct FileDomain {
    pub extension: String,
    pub decl: FilesDecl,
    pub record: PackageRecord,
}

impl FileDomain {
    /// The largest file capture accepts: chunked content when the domain declares it (rev 10
    /// §13), the inline limit otherwise (`FILE_TOO_LARGE` above it).
    pub fn capture_limit(&self) -> u64 {
        use calve_integration_contract::content::{FILE_MAX, INLINE_MAX};
        if self.decl.put_chunked.is_some() {
            FILE_MAX
        } else {
            INLINE_MAX
        }
    }

    pub fn op(&self, kind: &str) -> Option<FileOp> {
        if kind == self.decl.put || self.decl.put_chunked.as_deref() == Some(kind) {
            Some(FileOp::Put)
        } else if kind == self.decl.delete {
            Some(FileOp::Delete)
        } else if self.decl.history.iter().any(|k| k == kind) {
            Some(FileOp::Move)
        } else {
            None
        }
    }

    pub fn is_file_effect(&self, e: &AppliedEffect) -> bool {
        e.target.extension == self.extension
            && e.target.kind == self.decl.resource_kind
            && self.op(&e.kind).is_some()
    }

    pub fn capture_harness(&self) -> String {
        format!("{}.capture", self.extension)
    }

    pub fn materialize_harness(&self) -> String {
        format!("{}.materialize", self.extension)
    }

    pub fn provider(&self) -> String {
        format!("{}.local", self.extension)
    }

    pub fn captured_observation(&self) -> String {
        format!("{}.captured", self.extension)
    }
}

/// A package's CIC module, signed metadata and supervised session.
pub(crate) fn open_session(r: &PackageRecord) -> Result<Session<Box<dyn Driver>>> {
    let meta: &Metadata = r
        .metadata
        .as_ref()
        .ok_or_else(|| invalid(format!("{} has no CIC module", r.id)))?;
    let paths = crate::extensions::machine_paths()?;
    let wasm = paths
        .extension_dir
        .join(&r.id)
        .join(r.native_digest())
        .join("cic.wasm");
    let program = sandbox_program().map_err(cic_error)?;
    let driver: Box<dyn Driver> = Box::new(
        SandboxDriver::spawn(&program, &wasm, &r.digests["cic"], &HostConfig::default())
            .map_err(cic_error)?,
    );
    Session::open(driver, &crate::integration::host_hello(), meta).map_err(cic_error)
}

/// One stateless request on a fresh session.
pub(crate) fn request(r: &PackageRecord, op: &str, body: Value) -> Result<Value> {
    open_session(r)?.request(op, body).map_err(cic_error)
}

impl Project {
    pub(crate) async fn file_domain(&self) -> Result<FileDomain> {
        let mut found: Vec<FileDomain> = self
            .active_packages()
            .await?
            .into_iter()
            .filter_map(|r| {
                let decl = r.metadata.as_ref()?.files.clone()?;
                Some(FileDomain {
                    extension: r.id.clone(),
                    decl,
                    record: r,
                })
            })
            .collect();
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err(invalid(
                "enable an extension that declares a file domain (e.g. the software extension) first",
            )),
            _ => Err(invalid(format!(
                "several enabled extensions declare a file domain ({}); disable all but one",
                found
                    .iter()
                    .map(|d| d.extension.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// `(extension, declaration)` of every non-file resource kind of the active packages.
    pub(crate) async fn resource_domains(&self) -> Result<Vec<(String, ResourceDecl)>> {
        Ok(self
            .active_packages()
            .await?
            .into_iter()
            .flat_map(|r| {
                let id = r.id.clone();
                r.metadata
                    .map(|m| m.resources)
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |d| (id.clone(), d))
            })
            .collect())
    }

    /// Active packages that run language checks.
    pub(crate) async fn check_domains(&self) -> Result<Vec<(PackageRecord, ChecksDecl)>> {
        Ok(self
            .active_packages()
            .await?
            .into_iter()
            .filter_map(|r| {
                let c = r.metadata.as_ref()?.checks.clone()?;
                Some((r, c))
            })
            .collect())
    }
}

impl Project {
    /// The checks package that plans checks for `language` (asked through `check_plan`).
    pub(crate) async fn language_owner(
        &self,
        language: &str,
    ) -> Result<(PackageRecord, ChecksDecl)> {
        for (r, decl) in self.check_domains().await? {
            let plan: calve_integration_contract::wire::CheckPlanOut =
                serde_json::from_value(request(
                    &r,
                    "check_plan",
                    serde_json::json!({"languages": [language], "markers": []}),
                )?)
                .map_err(|e| invalid(format!("ABI_VIOLATION: check_plan: {e}")))?;
            if plan.checks.iter().any(|c| c.language == language) {
                return Ok((r, decl));
            }
        }
        Err(invalid(format!(
            "unknown language {language}: no enabled checks package plans it"
        )))
    }
}
