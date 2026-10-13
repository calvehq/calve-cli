//! Versioned product configuration. No resolved secret value is stored here.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, Result};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UiConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<ColorMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// Runs a local executable; its exit status decides the execution outcome.
    LocalProcess,
    /// Speaks the framed JSON-lines stdio agent contract (see `providers.rs`).
    StdioAgent,
}

fn enabled_default() -> bool {
    true
}

/// A worker profile. Secrets are references (`env:` / `keyring:`), never values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: ProviderKind,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variables inherited from Calve's environment; everything else is cleared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Child environment variable name -> secret reference resolved at launch.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
    /// Project IDs allowed to use this profile; empty allows every Project.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessMode {
    /// Observations only; no candidate effects.
    Check,
    /// Files the worker changes inside `paths` become snapshot effects.
    Change,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessDefinition {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Arguments appended after the provider executable, or the full argv when the provider
    /// has no executable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    pub mode: HarnessMode,
    /// Project-relative path prefixes the worker may affect; empty means the whole Project.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Harmless console preferences (console-ux §74–75).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mouse: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unicode: Option<bool>,
    /// Single-key remaps, action name -> key (e.g. `explain = "e"`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, String>,
}

pub use calve_api::CONSOLE_KEYS;

fn validate_console_keys(keys: &BTreeMap<String, String>) -> Result<()> {
    let mut used = std::collections::BTreeSet::new();
    for (action, key) in keys {
        if !CONSOLE_KEYS.iter().any(|(name, _)| name == action) {
            return Err(invalid(format!("console.keys: unknown action {action}")));
        }
        let mut chars = key.chars();
        let (Some(c), None) = (chars.next(), chars.next()) else {
            return Err(invalid(format!(
                "console.keys.{action} must be one character"
            )));
        };
        if c.is_control() || c.is_whitespace() || !used.insert(c) {
            return Err(invalid(format!(
                "console.keys: key {key:?} is invalid or bound twice"
            )));
        }
    }
    // A remapped key must not collide with another action's unchanged default.
    for (action, default) in CONSOLE_KEYS {
        if !keys.contains_key(*action) && used.contains(default) {
            return Err(invalid(format!(
                "console.keys: {default:?} is already the {action} key"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub format_version: u32,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub integrations: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<String, ProviderProfile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub harnesses: BTreeMap<String, HarnessDefinition>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, toml::Value>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            format_version: 1,
            ui: UiConfig::default(),
            secrets: BTreeMap::new(),
            integrations: BTreeMap::new(),
            console: ConsoleConfig::default(),
            providers: BTreeMap::new(),
            harnesses: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfig {
    pub color: ColorMode,
    pub page_size: u16,
    pub secrets: BTreeMap<String, String>,
    pub integrations: BTreeMap<String, toml::Value>,
    pub console: ConsoleConfig,
    pub providers: BTreeMap<String, ProviderProfile>,
    pub harnesses: BTreeMap<String, HarnessDefinition>,
    /// Scope file that last defined each provider, so edits land in the same file.
    pub provider_sources: BTreeMap<String, PathBuf>,
    pub sources: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self {
            color: ColorMode::Auto,
            page_size: 100,
            secrets: BTreeMap::new(),
            integrations: BTreeMap::new(),
            console: ConsoleConfig::default(),
            providers: BTreeMap::new(),
            harnesses: BTreeMap::new(),
            provider_sources: BTreeMap::new(),
            sources: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Global,
    Workspace,
    Project,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Global => "global",
            Self::Workspace => "workspace",
            Self::Project => "project",
        })
    }
}

impl std::str::FromStr for Scope {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "global" => Ok(Self::Global),
            "workspace" => Ok(Self::Workspace),
            "project" => Ok(Self::Project),
            _ => Err(invalid("scope must be global, workspace, or project")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub global: PathBuf,
    pub workspace: PathBuf,
    pub project: Option<PathBuf>,
    pub override_file: Option<PathBuf>,
}

pub fn default_config_root() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        return Ok(PathBuf::from(home).join("Library/Application Support/Calve"));
    }
    #[cfg(windows)]
    {
        let home = std::env::var_os("APPDATA").ok_or_else(|| invalid("APPDATA is not set"))?;
        return Ok(PathBuf::from(home).join("Calve"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
            let path = PathBuf::from(config);
            if !path.is_absolute() {
                return Err(invalid("XDG_CONFIG_HOME must be an absolute path"));
            }
            return Ok(path.join("calve"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        Ok(PathBuf::from(home).join(".config/calve"))
    }
}

impl ConfigPaths {
    pub fn for_context(
        workspace_id: &str,
        project_root: Option<&Path>,
        override_file: Option<PathBuf>,
    ) -> Result<Self> {
        let root = default_config_root()?;
        Ok(Self {
            global: root.join("config.toml"),
            workspace: root.join("workspaces").join(format!("{workspace_id}.toml")),
            project: project_root.map(|p| p.join(".calve/config.toml")),
            override_file,
        })
    }

    pub fn path(&self, scope: Scope) -> Result<&Path> {
        match scope {
            Scope::Global => Ok(&self.global),
            Scope::Workspace => Ok(&self.workspace),
            Scope::Project => self
                .project
                .as_deref()
                .ok_or_else(|| invalid("project scope requires a Project")),
        }
    }

    pub fn load(&self) -> Result<EffectiveConfig> {
        let mut result = EffectiveConfig::default();
        for path in [&self.global, &self.workspace]
            .into_iter()
            .chain(self.project.iter())
            .chain(self.override_file.iter())
        {
            if let Some(file) = read_file(path)? {
                result.apply(file, path)?;
            }
        }
        Ok(result)
    }

    pub fn set(&self, scope: Scope, key: &str, value: &str) -> Result<()> {
        let path = self.path(scope)?;
        let mut file = read_file(path)?.unwrap_or_default();
        match key {
            "ui.color" => {
                file.ui.color = Some(match value {
                    "auto" => ColorMode::Auto,
                    "always" => ColorMode::Always,
                    "never" => ColorMode::Never,
                    _ => return Err(invalid("ui.color must be auto, always, or never")),
                })
            }
            "console.theme" => {
                if !["dark", "light", "high-contrast", "mono"].contains(&value) {
                    return Err(invalid(
                        "console.theme must be dark, light, high-contrast or mono",
                    ));
                }
                file.console.theme = Some(value.to_owned());
            }
            "console.mouse" | "console.unicode" => {
                let flag = match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid(format!("{key} must be true or false"))),
                };
                if key == "console.mouse" {
                    file.console.mouse = Some(flag);
                } else {
                    file.console.unicode = Some(flag);
                }
            }
            "ui.page_size" => {
                let size: u16 = value
                    .parse()
                    .map_err(|_| invalid("ui.page_size must be an integer"))?;
                if !(1..=1000).contains(&size) {
                    return Err(invalid("ui.page_size must be between 1 and 1000"));
                }
                file.ui.page_size = Some(size);
            }
            key if key.starts_with("secrets.") => {
                let name = key.trim_start_matches("secrets.");
                if name.is_empty() || name.contains('.') {
                    return Err(invalid("secret name must be one nonempty segment"));
                }
                validate_secret_ref(value)?;
                file.secrets.insert(name.to_owned(), value.to_owned());
            }
            _ => return Err(invalid(format!("unsupported config key {key}"))),
        }
        validate(&file)?;
        write_file(path, &file)
    }

    pub fn unset(&self, scope: Scope, key: &str) -> Result<()> {
        let path = self.path(scope)?;
        let mut file = read_file(path)?.unwrap_or_default();
        match key {
            "ui.color" => file.ui.color = None,
            "ui.page_size" => file.ui.page_size = None,
            "console.theme" => file.console.theme = None,
            "console.mouse" => file.console.mouse = None,
            "console.unicode" => file.console.unicode = None,
            key if key.starts_with("secrets.") => {
                file.secrets.remove(key.trim_start_matches("secrets."));
            }
            _ => return Err(invalid(format!("unsupported config key {key}"))),
        }
        write_file(path, &file)
    }

    /// Writes one provider profile into a scope file, replacing any previous definition.
    pub fn put_provider(&self, scope: Scope, id: &str, profile: ProviderProfile) -> Result<()> {
        validate_profile(id, &profile)?;
        let path = self.path(scope)?;
        let mut file = read_file(path)?.unwrap_or_default();
        file.providers.insert(id.to_owned(), profile);
        validate(&file)?;
        write_file(path, &file)
    }

    pub fn remove_provider(&self, scope: Scope, id: &str) -> Result<()> {
        let path = self.path(scope)?;
        let mut file = read_file(path)?.unwrap_or_default();
        if file.providers.remove(id).is_none() {
            return Err(invalid(format!(
                "provider {id} is not defined in {scope} config"
            )));
        }
        write_file(path, &file)
    }

    /// Scope whose file currently defines the provider (highest precedence wins).
    pub fn provider_scope(&self, id: &str) -> Result<Scope> {
        let mut found = None;
        for (scope, path) in [
            (Scope::Global, Some(self.global.as_path())),
            (Scope::Workspace, Some(self.workspace.as_path())),
            (Scope::Project, self.project.as_deref()),
        ] {
            if let Some(path) = path
                && read_file(path)?.is_some_and(|file| file.providers.contains_key(id))
            {
                found = Some(scope);
            }
        }
        found.ok_or_else(|| invalid(format!("provider {id} is not configured")))
    }

    pub fn get(&self, key: &str) -> Result<Value> {
        let config = self.load()?;
        match key {
            "ui.color" => Ok(json!(config.color)),
            "ui.page_size" => Ok(json!(config.page_size)),
            "console.theme" => Ok(json!(config.console.theme)),
            "console.mouse" => Ok(json!(config.console.mouse)),
            "console.unicode" => Ok(json!(config.console.unicode)),
            key if key.starts_with("secrets.") => {
                let name = key.trim_start_matches("secrets.");
                config
                    .secrets
                    .get(name)
                    .map(|value| json!(value))
                    .ok_or_else(|| invalid(format!("config key {key} is not set")))
            }
            _ => Err(invalid(format!("unsupported config key {key}"))),
        }
    }
}

fn validate_secret_ref(value: &str) -> Result<()> {
    let name = value
        .strip_prefix("env:")
        .or_else(|| value.strip_prefix("keyring:"))
        .ok_or_else(|| invalid("secrets must be references beginning with env: or keyring:"))?;
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/'))
    {
        return Err(invalid("invalid secret reference name"));
    }
    Ok(())
}

/// Provider and harness identifiers: lowercase slugs, optionally dotted.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with(['.', '-'])
        && !id.ends_with(['.', '-'])
        && id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '.'))
}

fn env_name_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|ch: char| ch.is_ascii_digit())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub fn validate_profile(id: &str, profile: &ProviderProfile) -> Result<()> {
    if !valid_id(id) {
        return Err(invalid(format!("invalid provider id {id:?}")));
    }
    if let Some(executable) = &profile.executable
        && (executable.trim().is_empty() || executable.contains('\0'))
    {
        return Err(invalid(format!(
            "provider {id}: executable must be a path or name"
        )));
    }
    for name in &profile.env {
        if !env_name_ok(name) || name.starts_with("CALVE_") {
            return Err(invalid(format!(
                "provider {id}: invalid env allowlist entry {name}"
            )));
        }
    }
    for (name, reference) in &profile.secrets {
        if !env_name_ok(name) || name.starts_with("CALVE_") {
            return Err(invalid(format!(
                "provider {id}: invalid secret variable {name}"
            )));
        }
        validate_secret_ref(reference)?;
    }
    if profile
        .timeout_ms
        .is_some_and(|ms| ms == 0 || ms > 86_400_000)
    {
        return Err(invalid(format!(
            "provider {id}: timeout_ms must be 1..=86400000"
        )));
    }
    if profile
        .max_output_bytes
        .is_some_and(|bytes| bytes == 0 || bytes > 64 * 1024 * 1024)
    {
        return Err(invalid(format!(
            "provider {id}: max_output_bytes must be 1..=64 MiB"
        )));
    }
    if let Some(harness) = &profile.default_harness
        && !valid_id(harness)
    {
        return Err(invalid(format!(
            "provider {id}: invalid default harness {harness}"
        )));
    }
    Ok(())
}

pub fn validate_harness(id: &str, harness: &HarnessDefinition) -> Result<()> {
    if !valid_id(id) {
        return Err(invalid(format!("invalid harness id {id:?}")));
    }
    if !valid_id(&harness.provider) {
        return Err(invalid(format!("harness {id}: invalid provider id")));
    }
    for path in &harness.paths {
        let relative = Path::new(path);
        if path.contains('\\')
            || relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || path.split('/').next() == Some(".calve")
        {
            return Err(invalid(format!(
                "harness {id}: path {path:?} must be Project-relative and outside .calve"
            )));
        }
    }
    if harness.command.iter().any(|arg| arg.contains('\0')) {
        return Err(invalid(format!(
            "harness {id}: arguments may not contain NUL"
        )));
    }
    if harness
        .timeout_ms
        .is_some_and(|ms| ms == 0 || ms > 86_400_000)
    {
        return Err(invalid(format!(
            "harness {id}: timeout_ms must be 1..=86400000"
        )));
    }
    Ok(())
}

fn validate(file: &ConfigFile) -> Result<()> {
    if file.format_version != 1 {
        return Err(invalid(format!(
            "unsupported config format version {}",
            file.format_version
        )));
    }
    if let Some(size) = file.ui.page_size
        && !(1..=1000).contains(&size)
    {
        return Err(invalid("ui.page_size must be between 1 and 1000"));
    }
    for value in file.secrets.values() {
        validate_secret_ref(value)?;
    }
    validate_console_keys(&file.console.keys)?;
    for (id, profile) in &file.providers {
        validate_profile(id, profile)?;
    }
    for (id, harness) in &file.harnesses {
        validate_harness(id, harness)?;
    }
    for name in file.integrations.keys() {
        if !name.contains('.') || name.starts_with('.') || name.ends_with('.') {
            return Err(invalid(format!(
                "integration key {name} must be namespaced"
            )));
        }
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Option<ConfigFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let file: ConfigFile = toml::from_str(&fs::read_to_string(path)?)?;
    validate(&file)?;
    Ok(Some(file))
}

fn write_file(path: &Path, file: &ConfigFile) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("config path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temp = parent.join(format!(".config-{}.tmp", uuid::Uuid::now_v7()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&temp)?;
    let bytes = toml::to_string_pretty(file)?;
    output.write_all(bytes.as_bytes())?;
    output.sync_all()?;
    drop(output);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

impl EffectiveConfig {
    fn apply(&mut self, file: ConfigFile, path: &Path) -> Result<()> {
        validate(&file)?;
        if let Some(color) = file.ui.color {
            self.color = color;
        }
        if let Some(page_size) = file.ui.page_size {
            self.page_size = page_size;
        }
        self.secrets.extend(file.secrets);
        self.integrations.extend(file.integrations);
        if file.console.theme.is_some() {
            self.console.theme = file.console.theme;
        }
        if file.console.mouse.is_some() {
            self.console.mouse = file.console.mouse;
        }
        if file.console.unicode.is_some() {
            self.console.unicode = file.console.unicode;
        }
        self.console.keys.extend(file.console.keys);
        for id in file.providers.keys() {
            self.provider_sources.insert(id.clone(), path.to_path_buf());
        }
        self.providers.extend(file.providers);
        self.harnesses.extend(file.harnesses);
        for key in file.unknown.keys() {
            self.warnings
                .push(format!("{}: unknown Calve key {key}", path.display()));
        }
        for key in file.ui.unknown.keys() {
            self.warnings
                .push(format!("{}: unknown UI key {key}", path.display()));
        }
        self.sources.push(path.to_path_buf());
        Ok(())
    }
}
