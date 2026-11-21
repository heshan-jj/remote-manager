use serde_json::Value;

pub const OFFICIAL_TAILSCALE_MSI_URL: &str =
    "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi";
pub const EXPECTED_TAILSCALE_ORG: &str = "Tailscale Inc.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleStatus {
    pub backend_state: String,
    pub self_dns_name: Option<String>,
    pub self_ips: Vec<String>,
    pub tailnet_name: Option<String>,
    pub logged_in_user: Option<String>,
    pub auth_url: Option<String>,
}

pub fn parse_status_json(json: &str) -> Result<TailscaleStatus, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("Invalid Tailscale JSON: {e}"))?;

    let backend_state = v
        .get("BackendState")
        .and_then(|x| x.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let auth_url = v
        .get("AuthURL")
        .and_then(|x| x.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());

    let self_obj = v.get("Self");
    let self_dns_name = self_obj
        .and_then(|s| s.get("DNSName"))
        .and_then(|d| d.as_str())
        .map(|d| d.trim_end_matches('.').to_string());

    let mut self_ips = Vec::new();
    if let Some(arr) = self_obj.and_then(|s| s.get("TailscaleIPs")).and_then(|a| a.as_array()) {
        for item in arr {
            if let Some(ip) = item.as_str() {
                if !ip.trim().is_empty() {
                    self_ips.push(ip.to_string());
                }
            }
        }
    }

    let tailnet_name = v
        .get("CurrentTailnet")
        .and_then(|t| t.get("Name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());

    let self_uid = self_obj.and_then(|s| s.get("UserID")).and_then(|u| u.as_i64());
    let logged_in_user = self_uid.and_then(|uid| {
        v.get("User")
            .and_then(|u| u.get(uid.to_string()))
            .and_then(|u| u.get("LoginName"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string())
    });

    Ok(TailscaleStatus {
        backend_state,
        self_dns_name,
        self_ips,
        tailnet_name,
        logged_in_user,
        auth_url,
    })
}

pub fn extract_auth_url(output: &str) -> Option<String> {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("https://login.tailscale.com/") {
            let trimmed = token.trim_end_matches(&['.', ',', ';', ')', '"', '\''][..]);
            return Some(trimmed.to_string());
        }
    }
    None
}

pub fn is_valid_tailscale_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn mask_secret(text: &str, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() => text.replace(s, "***REDACTED***"),
        _ => text.to_string(),
    }
}
