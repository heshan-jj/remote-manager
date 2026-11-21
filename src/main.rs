mod firewall;
mod pubkey;
mod sshd;
mod state;
mod tailscale;
mod win;

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

const SSHD_EXE: &str = r"C:\Windows\System32\OpenSSH\sshd.exe";
const SSHD_CONFIG: &str = r"C:\ProgramData\ssh\sshd_config";
const TAILSCALE_EXE: &str = r"C:\Program Files\Tailscale\tailscale.exe";
const ADMIN_AUTH_KEYS: &str = r"C:\ProgramData\ssh\administrators_authorized_keys";
const DOWNLOADS_DIR: &str = r"C:\ProgramData\HHJ\AgentSetup\downloads";

#[derive(Parser)]
#[command(
    name = "hhj-ssh-setup",
    version,
    about = "Simple Windows SSH + Tailscale service installer for authorized remote terminal access"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Guided setup (default when run with no arguments)
    Install {
        /// Confirm ownership/authorization without interactive prompt
        #[arg(long)]
        yes: bool,
        /// OpenSSH public key line (or use --pubkey-file)
        #[arg(long)]
        pubkey: Option<String>,
        /// Path to a .pub file containing the OpenSSH public key
        #[arg(long)]
        pubkey_file: Option<String>,
        /// Target Windows username (defaults to current user)
        #[arg(long)]
        user: Option<String>,
        /// Optional one-time Tailscale auth key (never logged)
        #[arg(long)]
        auth_key: Option<String>,
        /// Optional Tailscale machine hostname
        #[arg(long)]
        hostname: Option<String>,
        /// Keep PowerShell as default OpenSSH shell (default: true)
        #[arg(long, default_value_t = true)]
        powershell_shell: bool,
    },
    /// Show current sshd, Tailscale, firewall, and authorized key status
    Status,
    /// Stop sshd, remove HHJ firewall rule, revoke HHJ SSH keys, and restore defaults
    Disable {
        /// Also log out of Tailscale
        #[arg(long)]
        logout_tailscale: bool,
    },
    /// Revoke HHJ-managed SSH keys (all or by SHA256 fingerprint)
    Revoke {
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        None => run_install(false, None, None, None, None, None, true),
        Some(Commands::Install {
            yes,
            pubkey,
            pubkey_file,
            user,
            auth_key,
            hostname,
            powershell_shell,
        }) => run_install(yes, pubkey, pubkey_file, user, auth_key, hostname, powershell_shell),
        Some(Commands::Status) => run_status(),
        Some(Commands::Disable { logout_tailscale }) => run_disable(logout_tailscale),
        Some(Commands::Revoke { fingerprint, user }) => run_revoke(fingerprint, user),
    };

    if let Err(e) = res {
        eprintln!("\n[ERROR] {e}");
        std::process::exit(1);
    }
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

fn require_windows_admin() -> Result<(), String> {
    if !cfg!(windows) {
        return Err("This installer must be run on Windows 10/11.".into());
    }
    if !win::is_elevated() {
        return Err("Administrator privileges are required. Right-click -> 'Run as administrator'.".into());
    }
    Ok(())
}

fn run_install(
    yes: bool,
    pubkey_arg: Option<String>,
    pubkey_file: Option<String>,
    user_arg: Option<String>,
    auth_key: Option<String>,
    hostname: Option<String>,
    powershell_shell: bool,
) -> Result<(), String> {
    println!("============================================================");
    println!("  HHJ SSH Setup — Windows OpenSSH + Tailscale Installer");
    println!("============================================================");
    println!("This tool configures native Windows services for authorized SSH access:");
    println!("  1. Windows OpenSSH Server (sshd service, Automatic startup)");
    println!("  2. Tailscale VPN (official signed MSI, unattended service)");
    println!("  3. Your SSH public key (authorized_keys with strict Windows ACLs)");
    println!("  4. Windows Defender Firewall (Tailscale-only rule on SSH port)");
    println!("All components remain visible in Windows Services, Firewall, and Settings.\n");

    require_windows_admin()?;

    if !yes {
        let ans = prompt("Do you own or have explicit authorization to administer this PC? (yes/no): ")?;
        if !ans.eq_ignore_ascii_case("yes") {
            return Err("Consent not granted. Exiting without making changes.".into());
        }
    }

    let state_path = Path::new(state::STATE_FILE);
    let mut st = state::SetupState::load(state_path);

    // 1. OpenSSH Server
    println!("\n[1/4] Configuring Windows OpenSSH Server...");
    if !Path::new(SSHD_EXE).exists() {
        println!("  Installing OpenSSH.Server capability (this may take a minute)...");
        let cap_res = win::run_powershell(
            "$ErrorActionPreference='Stop'; \
             $c=(Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1).Name; \
             if(-not $c){$c='OpenSSH.Server~~~~0.0.1.0'}; \
             Add-WindowsCapability -Online -Name $c | Out-Null",
        )?;
        if cap_res.code != 0 {
            return Err(format!("Failed to install OpenSSH Server: {}", cap_res.stderr.trim()));
        }
        st.open_ssh_installed_by_hhj = true;
    }

    if st.sshd_original_start_type.is_none() {
        let q = win::run_powershell("(Get-Service -Name sshd).StartType")?;
        let orig = q.stdout.trim();
        if !orig.is_empty() {
            st.sshd_original_start_type = Some(orig.to_string());
        }
    }

    let svc_res = win::run_powershell(
        "$ErrorActionPreference='Stop'; \
         Set-Service -Name sshd -StartupType Automatic; \
         if((Get-Service -Name sshd).Status -ne 'Running'){ Start-Service -Name sshd }",
    )?;
    if svc_res.code != 0 {
        return Err(format!("Failed to start sshd: {}", svc_res.stderr.trim()));
    }

    if powershell_shell {
        let prev = win::run_powershell(
            "$p=(Get-ItemProperty 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue).DefaultShell; \
             if($p){Write-Output $p}",
        )?;
        let prev_val = prev.stdout.trim().to_string();
        if !st.default_shell_changed_by_hhj {
            st.default_shell_previously_existed = !prev_val.is_empty();
            st.default_shell_previous_value = if prev_val.is_empty() { None } else { Some(prev_val) };
            st.default_shell_changed_by_hhj = true;
        }
        let set_shell = win::run_powershell(
            "$ErrorActionPreference='Stop'; \
             New-Item -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Force | Out-Null; \
             Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
        )?;
        if set_shell.code != 0 {
            eprintln!("  [WARN] Could not set DefaultShell: {}", set_shell.stderr.trim());
        }
    }

    let cfg_text = std::fs::read_to_string(SSHD_CONFIG).unwrap_or_default();
    let cfg = sshd::parse_sshd_config(&cfg_text);
    let banner = sshd::probe_ssh_banner("127.0.0.1", cfg.port, Duration::from_secs(5))
        .unwrap_or_else(|| "(no banner)".into());
    println!("  sshd running on port {} — banner: {}", cfg.port, banner);

    // 2. Tailscale
    println!("\n[2/4] Configuring Tailscale...");
    if !Path::new(TAILSCALE_EXE).exists() {
        println!("  Downloading official Tailscale MSI...");
        let msi_path = Path::new(DOWNLOADS_DIR).join("tailscale-setup-latest-amd64.msi");
        win::download_file(tailscale::OFFICIAL_TAILSCALE_MSI_URL, &msi_path)?;

        println!("  Verifying Authenticode signature...");
        let signer = win::verify_authenticode_publisher(&msi_path, tailscale::EXPECTED_TAILSCALE_ORG)?;
        println!("  Verified signature: {signer}");

        println!("  Installing Tailscale (unattended mode)...");
        let msi_str = msi_path.to_string_lossy().to_string();
        let install_res = win::run_cmd(
            "msiexec.exe",
            &["/i", &msi_str, "/qn", "/norestart", "TS_UNATTENDEDMODE=always"],
        )?;
        if install_res.code != 0 && install_res.code != 3010 {
            return Err(format!("Tailscale MSI failed with exit code {}.", install_res.code));
        }
        st.tailscale_installed_by_hhj = true;
    }

    let mut ts_status = query_tailscale_status();
    if ts_status.as_ref().is_none_or(|s| s.backend_state != "Running") {
        if let Some(ref h) = hostname {
            if !tailscale::is_valid_tailscale_hostname(h) {
                return Err("Hostname must be 1-63 lowercase letters, digits, or hyphens.".into());
            }
        }
        let mut args = vec!["up", "--unattended", "--timeout=5s"];
        let h_val;
        if let Some(ref h) = hostname {
            args.push("--hostname");
            h_val = h.clone();
            args.push(&h_val);
        }
        let ak_arg;
        if let Some(ref ak) = auth_key {
            ak_arg = format!("--auth-key={}", ak.trim());
            args.push(&ak_arg);
        }
        let up_res = win::run_cmd(TAILSCALE_EXE, &args)?;
        let combined = tailscale::mask_secret(&format!("{}\n{}", up_res.stdout, up_res.stderr), auth_key.as_deref());
        if let Some(url) = tailscale::extract_auth_url(&combined) {
            println!("\n  Open this URL in a browser to sign in to your tailnet:\n  {url}\n");
        }
        println!("  Waiting for Tailscale connection (up to 3 minutes)...");
        for _ in 0..90 {
            std::thread::sleep(Duration::from_secs(2));
            ts_status = query_tailscale_status();
            if ts_status.as_ref().is_some_and(|s| s.backend_state == "Running") {
                break;
            }
        }
    }

    let ts = ts_status.ok_or_else(|| "Tailscale did not reach Running state.".to_string())?;
    if ts.backend_state != "Running" {
        return Err(format!("Tailscale is in state '{}'. Complete login and re-run.", ts.backend_state));
    }
    println!(
        "  Connected to tailnet '{}' as {} ({})",
        ts.tailnet_name.as_deref().unwrap_or("unknown"),
        ts.logged_in_user.as_deref().unwrap_or("unknown"),
        ts.self_dns_name.as_deref().unwrap_or_else(|| ts.self_ips.first().map(|s| s.as_str()).unwrap_or("no-ip"))
    );
    if !yes {
        let ok = prompt("  Confirm this is your intended tailnet? (yes/no): ")?;
        if !ok.eq_ignore_ascii_case("yes") {
            let _ = win::run_cmd(TAILSCALE_EXE, &["logout"]);
            return Err("Tailnet rejected; logged out of Tailscale.".into());
        }
    }

    // 3. SSH Public Key
    println!("\n[3/4] Authorizing SSH public key...");
    let target_user = match user_arg {
        Some(u) => u,
        None => {
            let current = std::env::var("USERNAME").unwrap_or_else(|_| "Administrator".into());
            if yes {
                current
            } else {
                let entered = prompt(&format!("  Target Windows username [{current}]: "))?;
                if entered.is_empty() { current } else { entered }
            }
        }
    };

    let raw_key = match (pubkey_arg, pubkey_file) {
        (Some(k), _) => k,
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|e| format!("Could not read '{path}': {e}"))?,
        (None, None) => prompt("  Paste your OpenSSH public key (.pub, single line): ")?,
    };
    let parsed_key = pubkey::parse_public_key(&raw_key)?;
    println!("  Validated {} key (SHA256:{})", parsed_key.key_type, parsed_key.fingerprint_sha256);

    let is_admin = is_user_in_administrators(&target_user)?;
    let auth_keys_path = if is_admin {
        Path::new(ADMIN_AUTH_KEYS).to_path_buf()
    } else {
        Path::new(r"C:\Users").join(&target_user).join(".ssh").join("authorized_keys")
    };
    if let Some(parent) = auth_keys_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create ssh dir: {e}"))?;
    }

    let existing_keys = std::fs::read_to_string(&auth_keys_path).unwrap_or_default();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let hhj_line = pubkey::format_hhj_line(&parsed_key, &today, "admin");
    let (updated, added) = pubkey::merge_authorized_keys(&existing_keys, &hhj_line, &parsed_key);
    if added || !auth_keys_path.exists() {
        std::fs::write(&auth_keys_path, updated)
            .map_err(|e| format!("Failed to write {}: {e}", auth_keys_path.display()))?;
    }
    if is_admin {
        win::apply_admin_authorized_keys_acl(&auth_keys_path)?;
    } else {
        win::apply_user_authorized_keys_acl(&auth_keys_path, &target_user)?;
    }
    if !st
        .added_authorized_keys
        .iter()
        .any(|k| k.fingerprint_sha256 == parsed_key.fingerprint_sha256)
    {
        st.added_authorized_keys.push(state::AddedKeyRecord {
            file_path: auth_keys_path.to_string_lossy().to_string(),
            fingerprint_sha256: parsed_key.fingerprint_sha256.clone(),
            username: target_user.clone(),
        });
    }
    println!(
        "  Authorized key at {} (admin={is_admin}, added={added})",
        auth_keys_path.display()
    );

    // 4. Firewall
    println!("\n[4/4] Configuring Windows Defender Firewall (Tailscale-only)...");
    let (existing_rules, ts_alias) = query_firewall_and_alias()?;
    let plan = firewall::reconcile(&existing_rules, cfg.port, SSHD_EXE, ts_alias.as_deref());
    if plan.action != firewall::RuleAction::NoChange {
        let apply_res = win::run_powershell(&firewall::build_apply_script(&plan))?;
        if apply_res.code != 0 {
            return Err(format!("Firewall update failed: {}", apply_res.stderr.trim()));
        }
        st.firewall_rule_created_by_hhj = true;
    }
    println!("  Firewall rule '{}' -> {:?}", firewall::HHJ_RULE_NAME, plan.action);

    for broad in &plan.broad_rules {
        let disable = if yes {
            true
        } else {
            let a = prompt(&format!("  [WARN] {}\n  Disable this broad rule? (yes/no) [yes]: ", broad.reason))?;
            a.is_empty() || a.eq_ignore_ascii_case("yes")
        };
        if disable {
            let res = win::run_powershell(&firewall::build_disable_rule_script(&broad.name))?;
            if res.code == 0
                && !st.disabled_firewall_rules.iter().any(|r| r.name.eq_ignore_ascii_case(&broad.name))
            {
                st.disabled_firewall_rules.push(state::DisabledRuleRecord {
                    name: broad.name.clone(),
                    was_enabled: true,
                });
            }
        }
    }

    st.save(state_path)?;

    let connect_host = ts
        .self_dns_name
        .as_deref()
        .or_else(|| ts.self_ips.first().map(|s| s.as_str()))
        .unwrap_or("<tailscale-ip>");

    println!("\n============================================================");
    println!("  Setup Complete!");
    println!("  Connect from any terminal with:");
    if cfg.port == 22 {
        println!("    ssh {target_user}@{connect_host}");
    } else {
        println!("    ssh -p {} {target_user}@{connect_host}", cfg.port);
    }
    println!("============================================================");
    Ok(())
}

fn run_status() -> Result<(), String> {
    let st = state::SetupState::load(Path::new(state::STATE_FILE));
    let ts = query_tailscale_status();
    let sshd_info = if cfg!(windows) {
        win::run_powershell("(Get-Service -Name sshd -ErrorAction SilentlyContinue | Select-Object Status,StartType | ConvertTo-Json -Compress)")
            .map(|r| r.stdout.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    println!("State file: {}", state::STATE_FILE);
    println!("sshd: {}", if sshd_info.is_empty() { "unknown" } else { &sshd_info });
    if let Some(t) = ts {
        println!("Tailscale: {} ({:?})", t.backend_state, t.self_dns_name);
    } else {
        println!("Tailscale: not installed or not running");
    }
    println!("Managed keys recorded: {}", st.added_authorized_keys.len());
    println!("Firewall rule managed: {}", st.firewall_rule_created_by_hhj);
    Ok(())
}

fn run_disable(logout_tailscale: bool) -> Result<(), String> {
    require_windows_admin()?;
    let state_path = Path::new(state::STATE_FILE);
    let mut st = state::SetupState::load(state_path);

    let _ = win::run_powershell(&firewall::build_remove_hhj_rule_script());
    st.firewall_rule_created_by_hhj = false;

    for r in st.disabled_firewall_rules.drain(..) {
        if r.was_enabled {
            let _ = win::run_powershell(&firewall::build_enable_rule_script(&r.name));
        }
    }

    let mut paths: Vec<String> = st.added_authorized_keys.iter().map(|k| k.file_path.clone()).collect();
    paths.push(ADMIN_AUTH_KEYS.to_string());
    paths.sort();
    paths.dedup();
    for p in paths {
        let path = Path::new(&p);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                let (updated, removed) = pubkey::revoke_hhj_keys(&content, None);
                if removed > 0 {
                    let _ = std::fs::write(path, updated);
                }
            }
        }
    }
    st.added_authorized_keys.clear();

    if st.default_shell_changed_by_hhj {
        if st.default_shell_previously_existed {
            if let Some(prev) = &st.default_shell_previous_value {
                let _ = win::run_powershell(&format!(
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value {}",
                    firewall::ps_literal(prev)
                ));
            }
        } else {
            let _ = win::run_powershell(
                "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue",
            );
        }
        st.default_shell_changed_by_hhj = false;
    }

    let orig_start = st.sshd_original_start_type.as_deref().unwrap_or("Manual");
    let _ = win::run_powershell(&format!(
        "Stop-Service -Name sshd -ErrorAction SilentlyContinue; Set-Service -Name sshd -StartupType {}",
        firewall::ps_literal(orig_start)
    ));

    if logout_tailscale && Path::new(TAILSCALE_EXE).exists() {
        let _ = win::run_cmd(TAILSCALE_EXE, &["logout"]);
    }

    st.save(state_path)?;
    println!("HHJ remote SSH access has been disabled and changes rolled back.");
    Ok(())
}

fn run_revoke(fingerprint: Option<String>, user: Option<String>) -> Result<(), String> {
    require_windows_admin()?;
    let mut targets = vec![Path::new(ADMIN_AUTH_KEYS).to_path_buf()];
    if let Some(u) = user {
        targets.push(Path::new(r"C:\Users").join(u).join(".ssh").join("authorized_keys"));
    }
    let mut total = 0usize;
    for path in targets {
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let (updated, removed) = pubkey::revoke_hhj_keys(&content, fingerprint.as_deref());
            if removed > 0 {
                std::fs::write(&path, updated).map_err(|e| e.to_string())?;
                total += removed;
            }
        }
    }
    println!("Revoked {total} HHJ-managed SSH key(s).");
    Ok(())
}

fn query_tailscale_status() -> Option<tailscale::TailscaleStatus> {
    if !Path::new(TAILSCALE_EXE).exists() {
        return None;
    }
    let out = win::run_cmd(TAILSCALE_EXE, &["status", "--json"]).ok()?;
    tailscale::parse_status_json(&out.stdout).ok()
}

fn is_user_in_administrators(username: &str) -> Result<bool, String> {
    let script = format!(
        "$u={}; $g=[ADSI]'WinNT://./Administrators,group'; \
         $m=@($g.Invoke('Members') | ForEach-Object {{$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)}}); \
         if($m -contains $u){{Write-Output 'true'}}else{{Write-Output 'false'}}",
        firewall::ps_literal(username)
    );
    let res = win::run_powershell(&script)?;
    Ok(res.stdout.trim().eq_ignore_ascii_case("true"))
}

fn query_firewall_and_alias() -> Result<(Vec<firewall::FirewallRuleSnapshot>, Option<String>), String> {
    let script = r#"
        $ErrorActionPreference='SilentlyContinue'
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object { $_.Enabled -eq 'True' -or $_.DisplayName -like 'HHJ Remote Manager*' -or $_.DisplayName -like '*OpenSSH*' } | ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $ap = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            $if = $_ | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue
            [ordered]@{
                Name=$_.DisplayName; Enabled=($_.Enabled -eq 'True');
                Direction=[string]$_.Direction; Action=[string]$_.Action;
                Protocol=[string]$pf.Protocol; LocalPort=[string]$pf.LocalPort;
                RemoteAddress=(@($af.RemoteAddress) -join ',');
                Program=[string]$ap.Program;
                InterfaceAlias=(@($if.InterfaceAlias) -join ',')
            }
        })
        $ts = (Get-NetAdapter | Where-Object { $_.InterfaceDescription -like 'Tailscale*' } | Select-Object -First 1).Name
        [ordered]@{ rules=$rules; tsAlias=$ts } | ConvertTo-Json -Depth 4 -Compress
    "#;
    let res = win::run_powershell(script)?;
    if res.code != 0 || res.stdout.trim().is_empty() {
        return Ok((Vec::new(), None));
    }
    let val: serde_json::Value = serde_json::from_str(res.stdout.trim()).unwrap_or_default();
    let alias = val.get("tsAlias").and_then(|v| v.as_str()).map(|s| s.to_string());
    let rules = val
        .get("rules")
        .and_then(|r| serde_json::from_value::<Vec<firewall::FirewallRuleSnapshot>>(r.clone()).ok())
        .unwrap_or_default();
    Ok((rules, alias))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJb3RuOxfhHyV+FBuoBwhdnUqVrz8qNafJZvLABnrvq4 test@hhj";
    const EXPECTED_FP: &str = "YV1vhAodcl6w9Yr/dIOFx/jun0+gMqNOUoLEzJoSguA";

    #[test]
    fn pubkey_parse_fingerprint_merge_and_revoke() {
        let parsed = pubkey::parse_public_key(REAL_ED25519).unwrap();
        assert_eq!(parsed.fingerprint_sha256, EXPECTED_FP);
        assert!(pubkey::parse_public_key("-----BEGIN OPENSSH PRIVATE KEY-----").is_err());

        let line = pubkey::format_hhj_line(&parsed, "2026-11-21", "laptop");
        let existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockOtherUserKey1234567890 user-own\r\n";
        let (merged1, added1) = pubkey::merge_authorized_keys(existing, &line, &parsed);
        assert!(added1);
        let (merged2, added2) = pubkey::merge_authorized_keys(&merged1, &line, &parsed);
        assert!(!added2);
        assert_eq!(merged1, merged2);

        let (revoked, count) = pubkey::revoke_hhj_keys(&merged2, Some(EXPECTED_FP));
        assert_eq!(count, 1);
        assert!(revoked.contains("user-own"));
        assert!(!revoked.contains("hhj-remote-manager"));
    }

    #[test]
    fn sshd_config_parser_works() {
        let cfg = "port 2222\nPubkeyAuthentication yes\nPasswordAuthentication no\nMatch Group administrators\n  AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n";
        let s = sshd::parse_sshd_config(cfg);
        assert_eq!(s.port, 2222);
        assert_eq!(s.pubkey_authentication, Some(true));
        assert_eq!(s.password_authentication, Some(false));
        assert!(s.has_match_administrators);
    }

    #[test]
    fn firewall_reconcile_detects_broad_rules_and_idempotency() {
        let broad = firewall::FirewallRuleSnapshot {
            name: "OpenSSH-Server-In-TCP".into(),
            enabled: true,
            direction: "Inbound".into(),
            action: "Allow".into(),
            protocol: Some("TCP".into()),
            local_port: Some("22".into()),
            remote_address: Some("Any".into()),
            program: Some(SSHD_EXE.into()),
            interface_alias: Some("Any".into()),
        };
        let plan = firewall::reconcile(&[broad], 22, SSHD_EXE, Some("Tailscale"));
        assert_eq!(plan.action, firewall::RuleAction::Create);
        assert_eq!(plan.broad_rules.len(), 1);
    }

    #[test]
    fn tailscale_json_and_masking() {
        let json = r#"{"BackendState":"Running","Self":{"UserID":7,"DNSName":"pc.tail.ts.net.","TailscaleIPs":["100.64.0.5"]},"CurrentTailnet":{"Name":"heshan@x"},"User":{"7":{"LoginName":"heshan@x"}}}"#;
        let st = tailscale::parse_status_json(json).unwrap();
        assert_eq!(st.backend_state, "Running");
        assert_eq!(st.self_dns_name.as_deref(), Some("pc.tail.ts.net"));
        assert_eq!(st.logged_in_user.as_deref(), Some("heshan@x"));
        assert_eq!(
            tailscale::mask_secret("up --auth-key=tskey-123", Some("tskey-123")),
            "up --auth-key=***REDACTED***"
        );
    }
}
