//! Local identities: additional OpenAEVC key principals (for example reviewers or agents)
//! whose private keys stay in the Project. `--as <name>` runs a request as one of them.

use std::collections::BTreeMap;
use std::fs;

use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::{NewPrincipal, PrincipalId, PrincipalKind};
use openaevc_sdk::{EmbeddedClient, Session, TypedClient};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, GrantOptions, Project, Result, event};

/// What a new identity may do unless `--action` says otherwise: read, and record review,
/// verification and evaluation results. It cannot create, seal or promote packs.
pub const DEFAULT_ACTIONS: &[&str] = &[
    "namespace.read",
    "object.read",
    "evidence.append",
    "verification.run",
    "evaluation.run",
];

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    principal: PrincipalId,
    seed: Vec<u8>,
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Project {
    fn identity_path(&self, name: &str) -> std::path::PathBuf {
        self.root
            .join(".calve/identities")
            .join(format!("{name}.toml"))
    }

    fn read_identity(&self, name: &str) -> Result<IdentityFile> {
        if !name_ok(name) {
            return Err(invalid(format!("invalid identity name {name:?}")));
        }
        let path = self.identity_path(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path)
                .map_err(|_| invalid(format!("no local identity named {name}")))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(invalid(format!(
                    "{} must not be readable by group or others",
                    path.display()
                )));
            }
        }
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    /// A handle on the same runtime that acts as `name`, with its own product-DB connection so
    /// concurrent requests in the daemon never share a session.
    pub fn acting_as(&self, name: &str) -> Result<Project> {
        let file = self.read_identity(name)?;
        let key = crate::signing_key(&file.seed)?;
        let client = EmbeddedClient::new(
            self.runtime.clone(),
            Session::new(key, file.principal, Some(self.identity.namespace_id)),
        );
        Ok(Project {
            root: self.root.clone(),
            identity: self.identity.clone(),
            display_name: self.display_name.clone(),
            client,
            db: crate::init_db(&self.root.join(".calve/product.sqlite3"), false)?,
            runtime: self.runtime.clone(),
            immutable_packs: Default::default(),
        })
    }

    pub async fn add_identity(&self, name: &str, actions: &[String], days: u32) -> Result<Value> {
        if !name_ok(name) {
            return Err(invalid(
                "identity names are lowercase letters, digits and '-', up to 40",
            ));
        }
        let path = self.identity_path(name);
        if path.exists() {
            return Err(invalid(format!("identity {name} already exists")));
        }
        if days == 0 || days > 3650 {
            return Err(invalid("--days must be 1..=3650"));
        }
        let key = SigningKey::generate();
        let principal = self
            .client
            .register_principal(NewPrincipal {
                kind: PrincipalKind::Key,
                public_key: Some(key.public_key()),
                linked_to: None,
                attributes: BTreeMap::from([("calve.identity".to_owned(), name.to_owned())]),
            })
            .await?;
        let dir = path.parent().expect("identity dir");
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let file = IdentityFile {
            name: name.to_owned(),
            principal,
            seed: key.seed().to_vec(),
        };
        crate::write_private(&path, &toml::to_string(&file)?)?;
        let actions: Vec<String> = if actions.is_empty() {
            DEFAULT_ACTIONS.iter().map(|a| (*a).to_owned()).collect()
        } else {
            actions.to_vec()
        };
        let expires = openaevc_protocol::Timestamp::from_unix_nanos(
            (i128::from(crate::now()?) + i128::from(days) * 86_400) * 1_000_000_000,
        );
        let grant = self
            .authority_grant(&GrantOptions {
                subject: principal.to_string(),
                actions: actions.clone(),
                expires_at: expires.to_string(),
                not_before: None,
                resource_kind: None,
                locator_prefix: None,
                delegation_depth: 0,
                parent: None,
                preview: false,
                apply: true,
            })
            .await?;
        event(&self.db, "identity.added", name, &principal.to_string())?;
        Ok(
            json!({"name":name,"principal":principal,"actions":actions,"grant":grant["grant_id"],"expires_at":expires}),
        )
    }

    pub fn list_identities(&self) -> Result<Value> {
        let dir = self.root.join(".calve/identities");
        let mut items = Vec::new();
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.path().file_stem().and_then(|n| n.to_str()) {
                    let file = self.read_identity(name)?;
                    items.push(json!({"name":file.name,"principal":file.principal}));
                }
            }
        }
        items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(json!(items))
    }

    /// Revokes every active grant held by the identity, then forgets its key.
    pub async fn remove_identity(&self, name: &str) -> Result<Value> {
        let file = self.read_identity(name)?;
        let mut revoked = Vec::new();
        for grant in self.authority_grants().await? {
            if grant["grant"]["body"]["subject"] == file.principal.to_string()
                && grant["revoked"] != true
                && let Some(id) = grant["grant"]["body"]["id"].as_str()
            {
                self.authority_revoke(id, Some(&format!("identity {name} removed")))
                    .await?;
                revoked.push(id.to_owned());
            }
        }
        fs::remove_file(self.identity_path(name))?;
        event(
            &self.db,
            "identity.removed",
            name,
            &file.principal.to_string(),
        )?;
        Ok(json!({"removed":name,"principal":file.principal,"revoked_grants":revoked}))
    }

    /// Pack-level review rule stored as Calve product metadata. OpenAEVC policy cannot compare
    /// principals, so Calve enforces it at review time and shows it in explanations.
    pub fn forbid_self_review(&self, pack: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO preferences(key,value) VALUES (?1,'true') ON CONFLICT(key) DO UPDATE SET value='true'",
            [format!("pack.{pack}.forbid_self_review")],
        )?;
        Ok(())
    }

    pub fn self_review_forbidden(&self, pack: &str) -> Result<bool> {
        use rusqlite::OptionalExtension;
        Ok(self
            .db
            .query_row(
                "SELECT value FROM preferences WHERE key=?1",
                [format!("pack.{pack}.forbid_self_review")],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .is_some())
    }
}
