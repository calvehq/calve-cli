//! The OpenAEVC client of every Project: the embedded runtime, with a crash-injection point
//! right after each command OpenAEVC accepted (`CALVE_FAULT=openaevc.<Command>`, debug builds).
//! That instant is the boundary between OpenAEVC's store and Calve's own (product DB, journals,
//! working tree), so one hook covers every cross-store step (P25).
use openaevc::core::ImmutableObject;
use openaevc::protocol::{Command, CommandReceipt, Digest, EventFilter, Query};
use openaevc_sdk::{EmbeddedClient, EventStream, OpenAevcClient, Result, Session};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct Client(EmbeddedClient);

impl Client {
    pub fn new(rt: std::sync::Arc<openaevc::runtime::Runtime>, session: Session) -> Self {
        Client(EmbeddedClient::new(rt, session))
    }
}

impl OpenAevcClient for Client {
    fn session(&self) -> &Session {
        self.0.session()
    }

    async fn command(&self, command: Command) -> Result<CommandReceipt> {
        let name = command.name();
        let r = self.0.command(command).await;
        if r.is_ok() {
            crate::journal::fault(&format!("openaevc.{name}"));
        }
        r
    }

    async fn query(&self, query: Query) -> Result<Value> {
        self.0.query(query).await
    }

    async fn subscribe(&self, filter: EventFilter) -> Result<EventStream> {
        self.0.subscribe(filter).await
    }

    async fn get_object(&self, digest: Digest) -> Result<ImmutableObject> {
        self.0.get_object(digest).await
    }
}
