use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const STATE_DIR: &str = r"C:\ProgramData\HHJ\AgentSetup";
pub const STATE_FILE: &str = r"C:\ProgramData\HHJ\AgentSetup\state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupState {
    pub schema_version: u32,
    pub first_configured_utc: Option<String>,
    pub last_updated_utc: Option<String>,
    pub open_ssh_installed_by_hhj: bool,
    pub sshd_original_start_type: Option<String>,
    pub default_shell_changed_by_hhj: bool,
    pub default_shell_previously_existed: bool,
    pub default_shell_previous_value: Option<String>,
    pub tailscale_installed_by_hhj: bool,
    pub firewall_rule_created_by_hhj: bool,
    pub disabled_firewall_rules: Vec<DisabledRuleRecord>,
    pub added_authorized_keys: Vec<AddedKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisabledRuleRecord {
    pub name: String,
    pub was_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedKeyRecord {
    pub file_path: String,
    pub fingerprint_sha256: String,
    pub username: String,
}

impl SetupState {
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| Self {
                schema_version: 1,
                ..Default::default()
            }),
            Err(_) => Self {
                schema_version: 1,
                ..Default::default()
            },
        }
    }

    pub fn save(&mut self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create state dir: {e}"))?;
        }
        let now = chrono::Utc::now().to_rfc3339();
        if self.first_configured_utc.is_none() {
            self.first_configured_utc = Some(now.clone());
        }
        self.last_updated_utc = Some(now);
        self.schema_version = 1;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }
}
