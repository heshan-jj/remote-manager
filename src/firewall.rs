use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;

pub const HHJ_RULE_NAME: &str = "HHJ Remote Manager - OpenSSH (Tailscale only)";
pub const HHJ_RULE_GROUP: &str = "HHJ Remote Manager";
pub const TAILSCALE_CIDRS: &[&str] = &["100.64.0.0/10", "fd7a:115c:a1e0::/48"];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FirewallRuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub action: String,
    pub protocol: Option<String>,
    pub local_port: Option<String>,
    pub remote_address: Option<String>,
    pub program: Option<String>,
    pub interface_alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Create,
    UpdateInPlace,
    NoChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadRuleFinding {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct FirewallPlan {
    pub action: RuleAction,
    pub port: u16,
    pub program_path: String,
    pub interface_alias: Option<String>,
    pub broad_rules: Vec<BroadRuleFinding>,
}

pub fn reconcile(
    existing: &[FirewallRuleSnapshot],
    port: u16,
    program_path: &str,
    tailscale_alias: Option<&str>,
) -> FirewallPlan {
    let alias = tailscale_alias
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let hhj = existing
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(HHJ_RULE_NAME));

    let action = match hhj {
        None => RuleAction::Create,
        Some(rule) if matches_desired(rule, port, program_path, alias.as_deref()) => {
            RuleAction::NoChange
        }
        Some(_) => RuleAction::UpdateInPlace,
    };

    let port_str = port.to_string();
    let mut broad_rules = Vec::new();
    for r in existing {
        if r.name.eq_ignore_ascii_case(HHJ_RULE_NAME) || !r.enabled {
            continue;
        }
        if !r.direction.eq_ignore_ascii_case("Inbound") || !r.action.eq_ignore_ascii_case("Allow") {
            continue;
        }
        let affects_port = r.local_port.as_deref().is_some_and(|p| {
            p.eq_ignore_ascii_case(&port_str) || p.eq_ignore_ascii_case("Any")
        });
        let affects_prog = r
            .program
            .as_deref()
            .is_some_and(|p| p.to_ascii_lowercase().ends_with("sshd.exe"));
        if !affects_port && !affects_prog {
            continue;
        }
        let any_remote = r
            .remote_address
            .as_deref()
            .is_none_or(|a| a.trim().is_empty() || a.eq_ignore_ascii_case("Any") || a == "*");
        if any_remote {
            broad_rules.push(BroadRuleFinding {
                name: r.name.clone(),
                reason: format!(
                    "Inbound Allow rule '{}' permits ANY remote IP on port {}",
                    r.name,
                    r.local_port.as_deref().unwrap_or("Any")
                ),
            });
        }
    }

    FirewallPlan {
        action,
        port,
        program_path: program_path.to_string(),
        interface_alias: alias,
        broad_rules,
    }
}

fn matches_desired(
    rule: &FirewallRuleSnapshot,
    port: u16,
    program_path: &str,
    alias: Option<&str>,
) -> bool {
    if !rule.enabled
        || !rule.direction.eq_ignore_ascii_case("Inbound")
        || !rule.action.eq_ignore_ascii_case("Allow")
        || !rule.protocol.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("TCP"))
        || !rule.local_port.as_deref().is_some_and(|p| p == port.to_string())
        || !rule.program.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(program_path))
        || !rule.interface_alias.as_deref().unwrap_or("").eq_ignore_ascii_case(alias.unwrap_or(""))
    {
        return false;
    }

    let mut actual: Vec<String> = rule
        .remote_address
        .as_deref()
        .unwrap_or("")
        .split(&[',', ';', ' '][..])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    actual.sort();

    let mut desired: Vec<String> = TAILSCALE_CIDRS.iter().map(|s| s.to_string()).collect();
    desired.sort();
    actual == desired
}

pub fn ps_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

pub fn encode_powershell(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    STANDARD.encode(utf16)
}

pub fn build_apply_script(plan: &FirewallPlan) -> String {
    let name = ps_literal(HHJ_RULE_NAME);
    let group = ps_literal(HHJ_RULE_GROUP);
    let prog = ps_literal(&plan.program_path);
    let addrs = TAILSCALE_CIDRS
        .iter()
        .map(|c| ps_literal(c))
        .collect::<Vec<_>>()
        .join(",");
    let iface = match &plan.interface_alias {
        Some(a) => format!("-InterfaceAlias {}", ps_literal(a)),
        None => "-InterfaceAlias Any".to_string(),
    };
    format!(
        "$ErrorActionPreference='Stop'; \
         $e=Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; \
         if($e){{Remove-NetFirewallRule -DisplayName {name}}}; \
         New-NetFirewallRule -Name {name} -DisplayName {name} -Group {group} \
         -Direction Inbound -Action Allow -Enabled True -Protocol TCP \
         -LocalPort {} -Program {prog} -RemoteAddress @({addrs}) {iface} -Profile Any | Out-Null",
        plan.port
    )
}

pub fn build_disable_rule_script(rule_name: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; Disable-NetFirewallRule -DisplayName {}",
        ps_literal(rule_name)
    )
}

pub fn build_enable_rule_script(rule_name: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; Enable-NetFirewallRule -DisplayName {}",
        ps_literal(rule_name)
    )
}

pub fn build_remove_hhj_rule_script() -> String {
    format!(
        "$ErrorActionPreference='SilentlyContinue'; Remove-NetFirewallRule -DisplayName {}",
        ps_literal(HHJ_RULE_NAME)
    )
}
