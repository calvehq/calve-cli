//! Versioned Calve product API: request/response envelopes and the typed actions shared by
//! the CLI, the daemon and the console. Free of terminal and persistence types.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Subcommand;
use openaevc::protocol::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Console actions whose single key may be remapped, with their defaults.
pub const CONSOLE_KEYS: &[(&str, char)] = &[
    ("help", '?'),
    ("actions", 'a'),
    ("explain", 'x'),
    ("filter", '/'),
    ("refresh", 'r'),
    ("fullscreen", 'z'),
    ("copy", 'y'),
    ("goto", 'g'),
    ("quit", 'q'),
    ("command", ':'),
    ("sort", 's'),
];

pub const API_VERSION: u16 = 1;
pub const PAYLOAD_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Command,
    Query,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestScope {
    pub project: Option<PathBuf>,
    pub workspace: Option<String>,
    pub config_file: Option<PathBuf>,
    /// Local identity to act as (`--as`); the Project root principal when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Actor {
    LocalUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub api_version: u16,
    pub payload_version: u16,
    pub request_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub actor: Actor,
    pub scope: RequestScope,
    pub operation_kind: OperationKind,
    pub action: Action,
}

impl Request {
    pub fn local(scope: RequestScope, action: Action) -> Self {
        Self {
            api_version: API_VERSION,
            payload_version: PAYLOAD_VERSION,
            request_id: Uuid::now_v7(),
            correlation_id: None,
            actor: Actor::LocalUser,
            scope,
            operation_kind: action.kind(),
            action,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub api_version: u16,
    pub request_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Ok { value: Value },
    Error { error: Fault },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fault {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum Action {
    /// Create a Project here (or at a path) with its own OpenAEVC Namespace.
    Init {
        path: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        /// Do not add the new Project to the selected Workspace.
        #[arg(long)]
        no_register: bool,
        /// Allow creating a Project inside another Project's directory tree.
        #[arg(long)]
        nested: bool,
    },
    /// Show Calve, OpenAEVC and API versions.
    Version,
    /// Summarize packs, tasks, executions, uncaptured changes and attention.
    Status,
    /// Organize Projects on this machine.
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    /// Register, relocate, rename, adopt and check Projects.
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Read and change layered configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage Intents: the goals changes serve.
    Intent {
        #[command(subcommand)]
        command: IntentCommand,
    },
    /// Manage Tasks under Intents.
    Task {
        #[command(subcommand)]
        command: TaskCommand,
    },
    /// Attention items projected from Project state.
    Inbox {
        #[command(subcommand)]
        command: InboxCommand,
    },
    /// ChangePack lifecycle: capture, seal, verify, review, promote.
    Pack {
        #[command(subcommand)]
        command: PackCommand,
    },
    /// RevisionPacks that amend, supersede or revert promoted packs.
    Revision {
        #[command(subcommand)]
        command: RevisionCommand,
    },
    /// Candidate-bound evidence objects.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Browse and verify OpenAEVC command receipts.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    /// Start, inspect, cancel and retry executions.
    Execution {
        #[command(subcommand)]
        command: ExecutionCommand,
    },
    /// Catalogs, installation, enablement and permissions.
    Extension {
        #[command(subcommand)]
        command: ExtensionCommand,
    },
    /// Browse, diff and materialize Project resources.
    Resource {
        #[command(subcommand)]
        command: ResourceCommand,
    },
    /// Manage .calveignore resource rules.
    Ignore {
        #[command(subcommand)]
        command: IgnoreCommand,
    },
    /// Record review decisions on sealed candidates.
    Review {
        #[command(subcommand)]
        command: ReviewCommand,
    },
    /// Accepted compositions: create, compare, activate, materialize.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Merged Calve and OpenAEVC event timeline.
    Activity {
        #[command(flatten)]
        filter: ActivityFilter,
    },
    /// Principals, grants and permission explanations.
    Authority {
        #[command(subcommand)]
        command: AuthorityCommand,
    },
    /// Diagnose the Project and suggest fixes.
    Doctor {
        /// Write a redacted diagnostic bundle directory here.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Create the bundle; without it the files are only listed.
        #[arg(long, requires = "bundle")]
        yes: bool,
    },
    /// Integrity checks, compaction and garbage collection.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    /// Inspect and clean up after interrupted operations.
    Recover {
        #[command(subcommand)]
        command: RecoverCommand,
    },
    /// Run and control the local calved service.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Worker provider profiles.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Harness definitions that drive executions.
    Harness {
        #[command(subcommand)]
        command: HarnessCommand,
    },
    /// Read models for interactive frontends.
    #[command(hide = true)]
    View {
        #[command(subcommand)]
        view: ViewQuery,
    },
    /// Open the interactive terminal console.
    Console,
}

/// Purpose-built, presentation-neutral read models (console-ux §63).
#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ViewQuery {
    /// Overview read model.
    Overview,
    /// ChangePack list read model.
    Packs,
    /// ChangePack workstation read model.
    Pack { id: String },
    /// One file diff read model.
    PackDiff { id: String, path: String },
    /// Change graph read model.
    ChangeGraph {
        #[arg(long)]
        intent: Option<String>,
    },
    /// Baseline detail read model.
    Baseline { id: String },
    /// Execution detail read model.
    Execution { id: String },
    /// Evidence catalog read model.
    Evidence,
    /// Long-poll: returns when the Project changes past the cursor or after `wait_ms`.
    Changes {
        #[arg(long, default_value_t = 0)]
        protocol: u64,
        #[arg(long, default_value_t = 0)]
        product: i64,
        #[arg(long, default_value_t = 25_000)]
        wait_ms: u64,
    },
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize, Default)]
pub struct ProviderFields {
    #[arg(long, value_parser = ["local-process", "stdio-agent"])]
    pub kind: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub executable: Option<String>,
    /// Replaces the argument list (repeatable).
    #[arg(long = "arg", allow_hyphen_values = true)]
    pub args: Vec<String>,
    /// Replaces the inherited-environment allowlist (repeatable).
    #[arg(long = "env")]
    pub env: Vec<String>,
    /// NAME=REF secret reference, e.g. API_KEY=env:MY_KEY (repeatable).
    #[arg(long = "secret")]
    pub secrets: Vec<String>,
    #[arg(long)]
    pub default_harness: Option<String>,
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    #[arg(long)]
    pub max_output_bytes: Option<u64>,
    /// Restrict to these Project IDs (repeatable).
    #[arg(long = "allow-project")]
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ProviderCommand {
    /// List provider profiles.
    List,
    /// Show a provider profile and its harnesses.
    Show { id: String },
    /// Add a provider profile.
    Add {
        id: String,
        #[command(flatten)]
        fields: ProviderFields,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Change a provider profile.
    Edit {
        id: String,
        #[command(flatten)]
        fields: ProviderFields,
    },
    /// Check executable, secrets and references without running.
    Test { id: String },
    /// Enable a provider.
    Enable { id: String },
    /// Disable a provider.
    Disable { id: String },
    /// Remove a provider profile.
    Remove { id: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum HarnessCommand {
    /// List built-in and configured harnesses.
    List,
    /// Show a harness definition.
    Show { id: String },
    /// Validate a harness and resolve its command.
    Test { id: String },
}

/// Daemon lifecycle is handled by the frontend; it never travels over the daemon API.
#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum DaemonCommand {
    /// Start calved in the background.
    Start,
    /// Run the daemon in the foreground.
    Serve,
    /// Report whether calved is running.
    Status,
    /// Stop calved.
    Stop,
    /// Restart calved.
    Restart,
    /// Show the calved log.
    Logs {
        #[arg(long, default_value_t = 200)]
        lines: usize,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum MaintenanceCommand {
    /// Check product database, store integrity and leftovers.
    Check,
    /// Collect unreferenced OpenAEVC objects (never accepted history).
    Gc {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 86_400)]
        grace_secs: u64,
    },
    /// Checkpoint and vacuum the product database.
    Compact,
    /// Rebuild derived projections such as the inbox.
    RebuildProjections,
    /// Verify the OpenAEVC store journal and objects.
    VerifyStore,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum RecoverCommand {
    /// Report whether the Project opens and what was left behind.
    Inspect,
    /// List the exact recovery actions.
    Plan,
    /// Perform the planned recovery actions.
    Apply {
        /// Acknowledge removal of the listed disposable leftovers.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum WorkspaceCommand {
    /// List Workspaces.
    List,
    /// Show a Workspace and its Projects.
    Show { workspace: Option<String> },
    /// Create a Workspace.
    Create { name: String },
    /// Rename a Workspace.
    Rename { workspace: String, name: String },
    /// Make a Workspace the default.
    Select { workspace: String },
    /// Add a registered Project to a Workspace.
    AddProject { workspace: String, project: String },
    /// Remove a Project from a Workspace.
    RemoveProject { workspace: String, project: String },
    /// Choose the Project used outside Project directories.
    SetDefaultProject { workspace: String, project: String },
    /// Delete an empty Workspace.
    Delete { workspace: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ProjectCommand {
    /// List registered Projects.
    List,
    /// Show a Project registration.
    Show { project: String },
    /// Register an existing Project directory.
    Register { path: PathBuf },
    /// Forget a Project registration (keeps its files).
    Unregister { project: String },
    /// Point a registration at a moved Project.
    Relocate { project: String, path: PathBuf },
    /// Make a copied Project directory a new Project with its own identity and Namespace.
    AdoptCopy {
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Change the Project display name.
    Rename { project: String, name: String },
    /// Show immutable Project identity.
    Identity { project: String },
    /// Explain missing, moved, copied or invalid Project roots.
    Health { project: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ConfigCommand {
    /// Show effective configuration and its sources.
    List,
    /// Read one configuration key.
    Get { key: String },
    /// Set a configuration key in a scope.
    Set {
        key: String,
        value: String,
        #[arg(long, default_value = "project")]
        scope: String,
    },
    /// Remove a configuration key from a scope.
    Unset {
        key: String,
        #[arg(long, default_value = "project")]
        scope: String,
    },
    /// Validate every configuration file in scope.
    Validate,
    /// Print the file path for a scope.
    EditPath {
        #[arg(long, default_value = "project")]
        scope: String,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum IntentCommand {
    /// Create an Intent.
    Create {
        title: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long = "actor")]
        actors: Vec<String>,
        #[arg(long)]
        graph_node: Option<String>,
    },
    /// List Intents.
    List,
    /// Show an Intent with its packs.
    Show { id: String },
    /// Edit Intent metadata.
    Edit {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "tag", conflicts_with = "clear_tags")]
        tags: Vec<String>,
        #[arg(long)]
        clear_tags: bool,
        #[arg(long = "actor", conflicts_with = "clear_actors")]
        actors: Vec<String>,
        #[arg(long)]
        clear_actors: bool,
        #[arg(long, conflicts_with = "clear_graph_node")]
        graph_node: Option<String>,
        #[arg(long)]
        clear_graph_node: bool,
    },
    /// Complete or cancel an Intent.
    Close {
        id: String,
        #[arg(long)]
        cancelled: bool,
    },
    /// Reopen a closed Intent.
    Reopen { id: String },
    /// Link a ChangePack to an Intent.
    LinkPack { intent: String, pack: String },
    /// Unlink a ChangePack from an Intent.
    UnlinkPack { intent: String, pack: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum TaskCommand {
    /// Create a Task under an Intent.
    Create {
        intent: String,
        title: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, value_parser = ["low", "normal", "high", "urgent"], default_value = "normal")]
        priority: String,
        #[arg(long)]
        assignee: Option<String>,
    },
    /// List Tasks with dependency and link state.
    List,
    /// Show a Task with authoritative linked states.
    Show { id: String },
    /// Edit Task metadata.
    #[command(name = "edit", alias = "update")]
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, value_parser = ["low", "normal", "high", "urgent"])]
        priority: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
    },
    /// Complete a Task.
    Complete { id: String },
    /// Start a Task.
    Start { id: String },
    /// Block a Task with a reason.
    Block {
        id: String,
        #[arg(long)]
        reason: String,
    },
    /// Unblock a Task.
    Unblock { id: String },
    /// Reopen a completed Task.
    Reopen { id: String },
    /// Link a ChangePack.
    LinkPack { id: String, pack: String },
    /// Link an OpenAEVC execution.
    LinkExecution { id: String, execution: String },
    /// Link an OpenAEVC work unit.
    LinkWorkUnit { id: String, work_unit: String },
    /// Assign a Task.
    Assign { id: String, assignee: String },
    /// Add a prerequisite Task (any Intent).
    #[command(name = "depends-on", alias = "depend")]
    Depend { id: String, on: String },
    /// Remove a prerequisite.
    #[command(name = "remove-dependency", alias = "undepend")]
    Undepend { id: String, on: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum InboxCommand {
    /// List attention items.
    List {
        #[arg(long)]
        all: bool,
    },
    /// Show one attention item.
    Show { source_key: String },
    /// Mark an item read.
    Read { source_key: String },
    /// Acknowledge items.
    #[command(name = "ack", alias = "acknowledge")]
    Acknowledge {
        #[arg(required = true)]
        source_keys: Vec<String>,
    },
    /// Remove acknowledgements.
    Unack {
        #[arg(required = true)]
        source_keys: Vec<String>,
    },
    /// Forget resolved items (audit history is untouched).
    ClearResolved,
    /// Hide an item until a time.
    Snooze {
        source_key: String,
        /// RFC 3339 time, Unix seconds, or a duration from now such as 30m, 2h, 1d.
        #[arg(long, value_parser = parse_until)]
        until: u64,
    },
    /// Unsnooze an item.
    Unsnooze { source_key: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum AuthorityCommand {
    /// List principals.
    Principals,
    /// List capability grants.
    Grants,
    /// Show one grant.
    Show { id: String },
    /// Explain an authorization decision.
    Explain {
        action: String,
        #[arg(long)]
        principal: Option<String>,
        #[arg(long)]
        resource_kind: Option<String>,
        #[arg(long)]
        resource_locator: Option<String>,
        #[arg(long)]
        extension: Option<String>,
    },
    /// Preview or issue a capability grant (--apply issues).
    Grant {
        #[command(flatten)]
        options: GrantOptions,
    },
    /// Revoke a capability grant.
    Revoke {
        grant: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Create a local identity: an OpenAEVC key principal with a scoped grant (default: read and record review/verification results).
    IdentityAdd {
        name: String,
        /// OpenAEVC action to grant (repeatable); replaces the default set.
        #[arg(long = "action")]
        actions: Vec<String>,
        #[arg(long, default_value_t = 365)]
        days: u32,
    },
    /// List local identities.
    Identities,
    /// Revoke an identity's grants and forget its key.
    IdentityRemove { name: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum PackCommand {
    /// Create a ChangePack.
    Create {
        title: String,
        #[arg(long)]
        intent: Option<String>,
        #[arg(long)]
        require_snapshot_verification: bool,
        #[arg(long)]
        require_review: bool,
        /// Require a passing language check verifier, e.g. rust (repeatable).
        #[arg(long = "require-check")]
        require_checks: Vec<String>,
        /// Refuse approval by the principal that created the pack.
        #[arg(long)]
        forbid_self_review: bool,
    },
    /// List ChangePacks.
    List,
    /// Show the authoritative pack record.
    Show { id: String },
    /// Set the pack Intent (advances the generation).
    SetIntent {
        id: String,
        intent: String,
        #[arg(long)]
        generation: u64,
    },
    /// Change the pack title.
    Edit {
        id: String,
        #[arg(long)]
        title: String,
    },
    /// Capture every discoverable file under a directory.
    CaptureTree {
        id: String,
        #[arg(default_value = ".")]
        directory: PathBuf,
        #[arg(long)]
        generation: u64,
    },
    /// Ask OpenAEVC to evaluate promotion policy.
    Qualify {
        id: String,
        #[arg(long)]
        generation: u64,
    },
    /// Reopen a sealed pack as a new generation.
    Reopen {
        id: String,
        #[arg(long)]
        generation: u64,
    },
    /// Quarantine a pack with a reason.
    Quarantine {
        id: String,
        #[arg(long)]
        reason: String,
    },
    /// Release a quarantined pack.
    #[command(name = "release-quarantine", alias = "release")]
    Release { id: String },
    /// Abandon a pack.
    Abandon {
        id: String,
        #[arg(long)]
        generation: u64,
    },
    #[command(flatten)]
    Lifecycle(LifecycleCommand),
}

/// Candidate lifecycle shared by ChangePacks and RevisionPacks; OpenAEVC enforces the rules.
#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum LifecycleCommand {
    /// Capture one file into the candidate.
    Capture {
        id: String,
        path: PathBuf,
        #[arg(long)]
        generation: u64,
    },
    /// Diff captured files against the working copy.
    Diff {
        id: String,
        /// Show the line diff of one captured file instead of the pack summary.
        path: Option<PathBuf>,
    },
    /// Run snapshot verification on the sealed candidate.
    Verify {
        id: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, requires = "digest")]
        path: Option<PathBuf>,
        #[arg(long, requires = "path")]
        digest: Option<Digest>,
    },
    /// Evaluate change size on the sealed candidate.
    Evaluate {
        id: String,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        warn_after_bytes: Option<u64>,
        #[arg(long)]
        warn_after_files: Option<u64>,
    },
    /// Seal the candidate.
    Seal {
        id: String,
        #[arg(long)]
        generation: u64,
    },
    /// Run language checks on the sealed candidate and verify their evidence.
    Check {
        id: String,
        #[arg(long)]
        generation: u64,
        /// Language key (rust, go, python, ...); detected when omitted (repeatable).
        #[arg(long = "language")]
        languages: Vec<String>,
        /// Only these check names (repeatable).
        #[arg(long = "check")]
        only: Vec<String>,
        /// Approve the commands of the packages' check plans shown by a previous refusal
        /// (they run with your permissions); recorded per extension artifact.
        #[arg(long)]
        approve_plan: bool,
    },
    /// List reviews recorded against the pack.
    Review { id: String },
    /// Approve the sealed candidate.
    Approve {
        id: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Reject the sealed candidate.
    Reject {
        id: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Promote a qualified pack into accepted history.
    Promote {
        id: String,
        #[arg(long)]
        generation: u64,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum EvidenceCommand {
    /// Register a file as candidate-bound evidence.
    Add {
        pack: String,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "application/octet-stream")]
        media_type: String,
    },
    /// Show an evidence object.
    Show { digest: Digest },
    /// List a pack evidence.
    List {
        pack: String,
        #[arg(long)]
        after: Option<Digest>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long)]
        current: bool,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ReceiptCommand {
    /// List command receipts.
    List {
        #[arg(long)]
        after: Option<Digest>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Show a receipt.
    Show { digest: Digest },
    /// Verify a receipt digest, Namespace and journal range.
    Verify { digest: Digest },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ExecutionCommand {
    /// List executions.
    List {
        #[arg(long)]
        pack: Option<String>,
        #[arg(long, value_parser = ["pending", "admitted", "starting", "running", "succeeded", "failed", "cancelled", "lost"])]
        state: Option<String>,
    },
    /// Show an execution.
    Show { id: String },
    /// Wait for an execution to finish.
    Wait {
        id: String,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Cancel a running execution.
    Cancel {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Journal events for an execution.
    Logs { id: String },
    /// Start the protocol successor of a failed attempt.
    Retry { id: String },
    /// Run a configured harness as an OpenAEVC execution against an open pack.
    Start {
        pack: String,
        #[arg(long)]
        harness: String,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        task: Option<String>,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum RevisionCommand {
    /// Create a RevisionPack targeting promoted packs.
    Create {
        title: String,
        #[arg(long = "of", required = true, num_args = 1..)]
        of: Vec<String>,
        #[arg(long, default_value = "amends", value_parser = ["amends", "supersedes", "reverts"])]
        relation: String,
        #[arg(long)]
        intent: Option<String>,
        #[arg(long)]
        require_review: bool,
    },
    /// List RevisionPacks.
    List,
    /// Show a RevisionPack.
    Show { id: String },
    #[command(flatten)]
    Lifecycle(LifecycleCommand),
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum CatalogCommand {
    /// Trust a signed TUF catalog; its root is pinned by SHA-256 (obtained out of band).
    Add {
        name: String,
        /// `https://…` base URL, or a local directory with `metadata/` and `targets/`.
        url: String,
        /// The catalog's initial root.json, from the publisher.
        #[arg(long)]
        root: PathBuf,
        /// SHA-256 of that root.json, from the publisher (the repository identity).
        #[arg(long)]
        root_digest: String,
    },
    /// Trusted catalogs with their state (fresh, stale, expired, recovery required).
    List,
    /// Refresh one catalog or all of them.
    Refresh { name: Option<String> },
    /// Audited privileged reset to a new pinned root (never automatic).
    Reset {
        name: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        root_digest: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        i_understand_rollback_risk: bool,
    },
    /// Stop trusting a catalog (installed packages stay).
    Remove { name: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ExtensionCommand {
    /// Extensions registered in this Project; `--installed` lists installed packages instead.
    List {
        #[arg(long)]
        installed: bool,
    },
    /// Signed extension catalogs.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// Search trusted catalogs.
    Search { query: Option<String> },
    /// Show an enabled extension and its manifest.
    Info { id: String },
    /// Install a package from a trusted catalog (verified, immutable, content-addressed).
    Install {
        id: String,
        #[arg(long)]
        version: Option<String>,
        /// Catalog to install from (required when several offer the id).
        #[arg(long)]
        catalog: Option<String>,
        /// Acknowledge that the package runs native code with your user permissions.
        #[arg(long)]
        acknowledge_native: bool,
    },
    /// Move an id's pinned publisher to another catalog (audited).
    SwitchPublisher {
        id: String,
        #[arg(long)]
        catalog: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        acknowledge_native: bool,
    },
    /// Install and switch to the newest version (widening needs --grant).
    Update {
        id: String,
        /// Accept a newly requested host capability (repeatable).
        #[arg(long = "grant")]
        grants: Vec<String>,
        #[arg(long)]
        acknowledge_native: bool,
    },
    /// Remove installed versions that no Project uses.
    Uninstall {
        id: String,
        #[arg(long)]
        version: Option<String>,
    },
    /// Enable an installed (or installable) extension in this Project.
    Enable {
        id: String,
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// Acknowledge that the package runs native code with your user permissions.
        #[arg(long)]
        acknowledge_native: bool,
    },
    /// Unregister an extension from this Project.
    Disable { id: String },
    /// Requested versus granted host capabilities.
    Permissions { id: String },
    /// Grant requested host capabilities.
    Grant {
        id: String,
        #[arg(required = true)]
        capabilities: Vec<String>,
    },
    /// Revoke host capabilities.
    Revoke {
        id: String,
        #[arg(required = true)]
        capabilities: Vec<String>,
    },
    /// Check enabled extensions.
    Health,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ResourceCommand {
    /// List Project resources.
    List {
        #[arg(long, default_value = "software", value_parser = ["software", "general"])]
        domain: String,
    },
    /// A Project file path, or a general resource as kind:name (note:plan).
    Show { target: String },
    /// Record general-project resource changes in one execution.
    Set {
        pack: String,
        #[arg(long)]
        generation: u64,
        /// kind:name=JSON, e.g. note:plan='{"text":"..."}' (repeatable).
        #[arg(long = "set")]
        sets: Vec<String>,
        /// kind:name to remove (repeatable).
        #[arg(long = "remove")]
        removes: Vec<String>,
    },
    /// Plan (default) or apply writing one captured file from a pack into the working tree.
    Materialize {
        path: String,
        #[arg(long = "from")]
        pack: String,
        #[arg(long)]
        discard: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Diff one captured file against the working copy.
    Diff { pack: String, path: PathBuf },
    /// List files changed since their last capture.
    Scan,
    /// Captured versions of a file across packs.
    History { path: PathBuf },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum IgnoreCommand {
    /// List effective ignore rules.
    List,
    /// Add a .calveignore pattern.
    Add { pattern: String },
    /// Remove a .calveignore pattern.
    Remove { pattern: String },
    /// Explain which rule matches a path.
    Check { path: PathBuf },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ReviewCommand {
    /// Approve a sealed candidate.
    Approve {
        pack: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Reject a sealed candidate.
    Reject {
        pack: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Comment on a sealed candidate.
    Comment {
        pack: String,
        #[arg(long)]
        generation: u64,
        reason: String,
    },
    /// List reviews for a pack.
    List { pack: String },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum BaselineCommand {
    /// Compose promoted packs into a Baseline.
    Create { label: String, members: Vec<String> },
    /// List Baselines.
    List,
    /// Show a Baseline.
    Show { id: String },
    /// Validate a Baseline through OpenAEVC.
    Validate { id: String },
    /// Compare two Baselines.
    Compare { left: String, right: String },
    /// Show the Baseline object closure.
    Graph { id: String },
    /// Manage Baseline aliases.
    Alias {
        #[command(subcommand)]
        command: BaselineAliasCommand,
    },
    /// Point Calve at a Baseline.
    Activate { id: String },
    /// Plan (default) or apply writing a Baseline's accepted files into the working tree.
    Materialize {
        id: String,
        /// Overwrite this path despite uncaptured local changes; the old content is backed up.
        #[arg(long = "discard")]
        discard: Vec<String>,
        #[arg(long)]
        apply: bool,
        /// Make the Baseline active after a successful apply.
        #[arg(long)]
        activate: bool,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum BaselineAliasCommand {
    /// List aliases.
    List,
    /// Point an alias at a Baseline.
    Set { alias: String, baseline: String },
    /// Remove an alias.
    Remove { alias: String },
}

/// Parses a snooze deadline into Unix seconds.
fn parse_until(text: &str) -> std::result::Result<u64, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(seconds);
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    if let Ok(amount) = number.parse::<u64>() {
        let scale = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 604_800,
            _ => 0,
        };
        if scale > 0 {
            return amount
                .checked_mul(scale)
                .and_then(|delta| now.checked_add(delta))
                .ok_or_else(|| "duration is too large".into());
        }
    }
    let stamp: openaevc::protocol::Timestamp = text
        .parse()
        .map_err(|_| format!("{text:?} is not RFC 3339, Unix seconds, or a duration like 2h"))?;
    u64::try_from(stamp.unix_nanos() / 1_000_000_000).map_err(|_| "time is before 1970".into())
}

impl LifecycleCommand {
    fn kind(&self) -> OperationKind {
        match self {
            Self::Diff { .. } | Self::Review { .. } => OperationKind::Query,
            _ => OperationKind::Command,
        }
    }
}

impl Action {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Init { .. } => OperationKind::Command,
            Self::Workspace { command } => match command {
                WorkspaceCommand::List | WorkspaceCommand::Show { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Project { command } => match command {
                ProjectCommand::List
                | ProjectCommand::Show { .. }
                | ProjectCommand::Identity { .. }
                | ProjectCommand::Health { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Config { command } => match command {
                ConfigCommand::Set { .. } | ConfigCommand::Unset { .. } => OperationKind::Command,
                _ => OperationKind::Query,
            },
            Self::Intent { command } => match command {
                IntentCommand::List | IntentCommand::Show { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Task { command } => match command {
                TaskCommand::List | TaskCommand::Show { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Inbox { .. } => OperationKind::Command,
            Self::Authority { command } => match command {
                AuthorityCommand::Grant { options } if options.apply => OperationKind::Command,
                AuthorityCommand::Revoke { .. }
                | AuthorityCommand::IdentityAdd { .. }
                | AuthorityCommand::IdentityRemove { .. } => OperationKind::Command,
                _ => OperationKind::Query,
            },
            Self::Pack { command } => match command {
                PackCommand::List | PackCommand::Show { .. } => OperationKind::Query,
                PackCommand::Lifecycle(command) => command.kind(),
                _ => OperationKind::Command,
            },
            Self::Revision { command } => match command {
                RevisionCommand::Create { .. } => OperationKind::Command,
                RevisionCommand::List | RevisionCommand::Show { .. } => OperationKind::Query,
                RevisionCommand::Lifecycle(command) => command.kind(),
            },
            Self::Evidence { command } => match command {
                EvidenceCommand::Add { .. } => OperationKind::Command,
                EvidenceCommand::Show { .. } | EvidenceCommand::List { .. } => OperationKind::Query,
            },
            Self::Receipt { .. } => OperationKind::Query,
            Self::Execution { command } => match command {
                ExecutionCommand::List { .. }
                | ExecutionCommand::Show { .. }
                | ExecutionCommand::Wait { .. }
                | ExecutionCommand::Logs { .. } => OperationKind::Query,
                ExecutionCommand::Cancel { .. }
                | ExecutionCommand::Retry { .. }
                | ExecutionCommand::Start { .. } => OperationKind::Command,
            },
            Self::Extension { command } => match command {
                ExtensionCommand::List { .. }
                | ExtensionCommand::Catalog {
                    command: CatalogCommand::List,
                }
                | ExtensionCommand::Search { .. }
                | ExtensionCommand::Info { .. }
                | ExtensionCommand::Permissions { .. }
                | ExtensionCommand::Health => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Resource { command } => match command {
                ResourceCommand::Set { .. } | ResourceCommand::Materialize { apply: true, .. } => {
                    OperationKind::Command
                }
                _ => OperationKind::Query,
            },
            Self::Ignore { command } => match command {
                IgnoreCommand::Add { .. } | IgnoreCommand::Remove { .. } => OperationKind::Command,
                _ => OperationKind::Query,
            },
            Self::Maintenance { command } => match command {
                MaintenanceCommand::Check
                | MaintenanceCommand::VerifyStore
                | MaintenanceCommand::Gc { dry_run: true, .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Recover { command } => match command {
                RecoverCommand::Apply { .. } => OperationKind::Command,
                _ => OperationKind::Query,
            },
            Self::Review { command } => match command {
                ReviewCommand::List { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Baseline { command } => match command {
                BaselineCommand::List
                | BaselineCommand::Show { .. }
                | BaselineCommand::Validate { .. }
                | BaselineCommand::Compare { .. }
                | BaselineCommand::Graph { .. }
                | BaselineCommand::Alias {
                    command: BaselineAliasCommand::List,
                }
                | BaselineCommand::Materialize { apply: false, .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Provider { command } => match command {
                ProviderCommand::List
                | ProviderCommand::Show { .. }
                | ProviderCommand::Test { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Harness { .. } | Self::View { .. } => OperationKind::Query,
            Self::Daemon { command } => match command {
                DaemonCommand::Status | DaemonCommand::Logs { .. } => OperationKind::Query,
                _ => OperationKind::Command,
            },
            Self::Version
            | Self::Status
            | Self::Activity { .. }
            | Self::Doctor { .. }
            | Self::Console => OperationKind::Query,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, clap::Args)]
pub struct ActivityFilter {
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long)]
    pub actor: Option<String>,
    #[arg(long = "object-kind")]
    pub object_kind: Option<String>,
    #[arg(long)]
    pub pack: Option<String>,
    #[arg(long)]
    pub task: Option<String>,
    #[arg(long)]
    pub execution: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long)]
    pub severity: Option<String>,
    #[arg(long = "type")]
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, clap::Args)]
pub struct GrantOptions {
    pub subject: String,
    #[arg(long = "action", required = true)]
    pub actions: Vec<String>,
    #[arg(long)]
    pub expires_at: String,
    #[arg(long)]
    pub not_before: Option<String>,
    #[arg(long)]
    pub resource_kind: Option<String>,
    #[arg(long)]
    pub locator_prefix: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub delegation_depth: u32,
    #[arg(long)]
    pub parent: Option<String>,
    #[arg(long, conflicts_with = "apply")]
    pub preview: bool,
    #[arg(long)]
    pub apply: bool,
}
