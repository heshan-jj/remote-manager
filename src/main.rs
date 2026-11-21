mod firewall;
mod pubkey;
mod sshd;
mod state;
mod tunnel;
mod win;

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

const SSHD_EXE: &str = r"C:\Windows\System32\OpenSSH\sshd.exe";
const SSHD_CONFIG: &str = r"C:\ProgramData\ssh\sshd_config";
const SSH_KEYSCAN_EXE: &str = r"C:\Windows\System32\OpenSSH\ssh-keyscan.exe";
const ADMIN_AUTH_KEYS: &str = r"C:\ProgramData\ssh\administrators_authorized_keys";

#[derive(Parser)]
#[command(
    name = "hhj-ssh-setup",
    version,
    about = "Fast Windows OpenSSH + VPS reverse-tunnel service installer"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Guided or one-shot setup (default when run with no arguments)
    Install {
        /// Confirm authorization without interactive prompts
        #[arg(long)]
        yes: bool,
        /// VPS hostname or public IP
        #[arg(long)]
        vps_host: Option<String>,
        /// VPS SSH port (default: 22)
        #[arg(long, default_value_t = 22)]
        vps_port: u16,
        /// Restricted VPS tunnel username (default: hhj-tunnel)
        #[arg(long, default_value = "hhj-tunnel")]
        vps_user: String,
        /// Port on VPS 127.0.0.1 forwarded to this PC's SSH (default: 2222)
        #[arg(long, default_value_t = 2222)]
        remote_port: u16,
        /// Path to the shared tunnel private key for hhj-tunnel@vps
        #[arg(long)]
        tunnel_key: Option<String>,
        /// Your admin OpenSSH public key line (or use --pubkey-file)
        #[arg(long)]
        pubkey: Option<String>,
        /// Path to your admin .pub key file
        #[arg(long)]
        pubkey_file: Option<String>,
        /// Target Windows username (defaults to current user)
        #[arg(long)]
        user: Option<String>,
        /// Disable broad Any-IP OpenSSH firewall rules if found
        #[arg(long, default_value_t = true)]
        harden_firewall: bool,
    },
    /// Show sshd, hhj-tunnel service, and authorized key status
    Status,
    /// Stop hhj-tunnel & sshd, remove service, revoke HHJ SSH keys, and restore defaults
    Disable,
    /// Revoke HHJ-managed SSH keys (all or by SHA256 fingerprint)
    Revoke {
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    /// Internal entrypoint used by Windows Service Control Manager
    #[command(hide = true)]
    ServiceRun,
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        None => run_install(InstallArgs::default()),
        Some(Commands::Install {
            yes,
            vps_host,
            vps_port,
            vps_user,
            remote_port,
            tunnel_key,
            pubkey,
            pubkey_file,
            user,
            harden_firewall,
        }) => run_install(InstallArgs {
            yes,
            vps_host,
            vps_port,
            vps_user,
            remote_port,
            tunnel_key,
            pubkey,
            pubkey_file,
            user,
            harden_firewall,
        }),
        Some(Commands::Status) => run_status(),
        Some(Commands::Disable) => run_disable(),
        Some(Commands::Revoke { fingerprint, user }) => run_revoke(fingerprint, user),
        Some(Commands::ServiceRun) => tunnel::run_windows_service(),
    };

    if let Err(e) = res {
        eprintln!("\n[ERROR] {e}");
        std::process::exit(1);
    }
}

struct InstallArgs {
    yes: bool,
    vps_host: Option<String>,
    vps_port: u16,
    vps_user: String,
    remote_port: u16,
    tunnel_key: Option<String>,
    pubkey: Option<String>,
    pubkey_file: Option<String>,
    user: Option<String>,
    harden_firewall: bool,
}

impl Default for InstallArgs {
    fn default() -> Self {
        Self {
            yes: false,
            vps_host: None,
            vps_port: 22,
            vps_user: "hhj-tunnel".into(),
            remote_port: 2222,
            tunnel_key: None,
            pubkey: None,
            pubkey_file: None,
            user: None,
            harden_firewall: true,
        }
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

fn run_install(args: InstallArgs) -> Result<(), String> {
    println!("============================================================");
    println!("  HHJ SSH Setup — Fast OpenSSH + VPS Reverse Tunnel");
    println!("============================================================");

    require_windows_admin()?;

    if !args.yes {
        let ans = prompt("Authorize enabling OpenSSH + VPS reverse tunnel on this PC? (yes/no): ")?;
        if !ans.eq_ignore_ascii_case("yes") {
            return Err("Consent not granted. Exiting.".into());
        }
    }

    let state_path = Path::new(state::STATE_FILE);
    let mut st = state::SetupState::load(state_path);

    // 1. Windows OpenSSH Server
    println!("\n[1/4] Configuring Windows OpenSSH Server...");
    if !Path::new(SSHD_EXE).exists() {
        println!("  Installing OpenSSH.Server capability...");
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

    // Set PowerShell as default OpenSSH shell
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
    let _ = win::run_powershell(
        "New-Item -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Force | Out-Null; \
         Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
    );

    let cfg_text = std::fs::read_to_string(SSHD_CONFIG).unwrap_or_default();
    let cfg = sshd::parse_sshd_config(&cfg_text);
    let banner = sshd::probe_ssh_banner("127.0.0.1", cfg.port, Duration::from_secs(3))
        .unwrap_or_else(|| "(no banner)".into());
    println!("  sshd Running on port {} — {}", cfg.port, banner);

    // 2. Optionally authorize admin SSH public key (if skipped, Windows password auth works)
    println!("\n[2/4] Configuring SSH authentication...");
    let target_user = match args.user {
        Some(u) => u,
        None => {
            let current = std::env::var("USERNAME").unwrap_or_else(|_| "Administrator".into());
            if args.yes {
                current
            } else {
                let entered = prompt(&format!("  Target Windows username [{current}]: "))?;
                if entered.is_empty() { current } else { entered }
            }
        }
    };

    let raw_key_opt = match (args.pubkey, args.pubkey_file) {
        (Some(k), _) => Some(k),
        (None, Some(path)) => Some(
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Could not read '{path}': {e}"))?,
        ),
        (None, None) if args.yes => None,
        (None, None) => {
            let entered = prompt("  Admin OpenSSH public key (.pub, or Enter to use Windows password): ")?;
            if entered.is_empty() { None } else { Some(entered) }
        }
    };

    if let Some(raw_key) = raw_key_opt {
        let parsed_key = pubkey::parse_public_key(&raw_key)?;

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
        let (updated, _) = pubkey::merge_authorized_keys(&existing_keys, &hhj_line, &parsed_key);
        std::fs::write(&auth_keys_path, updated)
            .map_err(|e| format!("Failed to write {}: {e}", auth_keys_path.display()))?;
        if is_admin {
            win::apply_admin_only_acl(&auth_keys_path)?;
        } else {
            win::apply_user_authorized_keys_acl(&auth_keys_path, &target_user)?;
        }
        if !st.added_authorized_keys.iter().any(|k| k.fingerprint_sha256 == parsed_key.fingerprint_sha256) {
            st.added_authorized_keys.push(state::AddedKeyRecord {
                file_path: auth_keys_path.to_string_lossy().to_string(),
                fingerprint_sha256: parsed_key.fingerprint_sha256.clone(),
                username: target_user.clone(),
            });
        }
        println!("  Authorized SHA256:{} for {} (admin={is_admin})", parsed_key.fingerprint_sha256, target_user);
    } else {
        println!("  Using standard Windows password authentication for '{target_user}'.");
    }

    // 3. Configure & start VPS reverse-tunnel Windows service (Option 1)
    println!("\n[3/4] Installing '{}' Windows service...", tunnel::SERVICE_NAME);
    let vps_host = match args.vps_host {
        Some(h) => h,
        None => prompt("  VPS IP or hostname: ")?,
    };
    if !tunnel::is_valid_host(&vps_host) {
        return Err("Invalid VPS host.".into());
    }
    if !tunnel::is_valid_unix_user(&args.vps_user) {
        return Err("Invalid VPS username.".into());
    }

    let tunnel_key_src = match args.tunnel_key {
        Some(p) => p,
        None => prompt("  Path to shared tunnel private key: ")?,
    };
    let tunnel_key_bytes = std::fs::read(&tunnel_key_src)
        .map_err(|e| format!("Could not read tunnel key '{tunnel_key_src}': {e}"))?;

    std::fs::create_dir_all(tunnel::INSTALL_DIR)
        .map_err(|e| format!("Failed to create {}: {e}", tunnel::INSTALL_DIR))?;

    std::fs::write(tunnel::TUNNEL_KEY_PATH, tunnel_key_bytes)
        .map_err(|e| format!("Failed to write tunnel_key: {e}"))?;
    win::apply_admin_only_acl(Path::new(tunnel::TUNNEL_KEY_PATH))?;

    // Pin VPS host key via ssh-keyscan, or fall back to ssh.exe (Windows OpenSSH 9.5 ssh-keyscan
    // can fail on sntrup761x25519 KEX against Ubuntu 24.04 OpenSSH 9.6+).
    let port_str = args.vps_port.to_string();
    let scan = win::run_cmd(SSH_KEYSCAN_EXE, &["-p", &port_str, &vps_host])?;
    if scan.code == 0 && !scan.stdout.trim().is_empty() {
        std::fs::write(tunnel::KNOWN_HOSTS_PATH, &scan.stdout)
            .map_err(|e| format!("Failed to write known_hosts: {e}"))?;
    } else {
        let _ = std::fs::remove_file(tunnel::KNOWN_HOSTS_PATH);
        let kh_opt = format!("UserKnownHostsFile={}", tunnel::KNOWN_HOSTS_PATH);
        let target = format!("{}@{}", args.vps_user, vps_host);
        let _ = win::run_cmd(
            tunnel::SSH_EXE,
            &[
                "-T",
                "-i",
                tunnel::TUNNEL_KEY_PATH,
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                &kh_opt,
                "-p",
                &port_str,
                &target,
            ],
        );
        let kh = std::fs::read_to_string(tunnel::KNOWN_HOSTS_PATH).unwrap_or_default();
        if kh.trim().is_empty() {
            return Err(format!(
                "Could not obtain SSH host key from {vps_host}:{}: {}",
                args.vps_port,
                scan.stderr.trim()
            ));
        }
    }

    let tcfg = tunnel::TunnelConfig {
        vps_host: vps_host.clone(),
        vps_port: args.vps_port,
        vps_user: args.vps_user.clone(),
        remote_port: args.remote_port,
        local_ssh_port: cfg.port,
    };
    tcfg.save(Path::new(tunnel::TUNNEL_CONFIG_PATH))?;

    // Copy current exe to ProgramData so deleting the downloaded exe won't break the service
    let self_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if !self_exe.eq(Path::new(tunnel::INSTALLED_EXE)) {
        let _ = win::run_cmd("sc.exe", &["stop", tunnel::SERVICE_NAME]);
        std::thread::sleep(Duration::from_millis(500));
        std::fs::copy(&self_exe, tunnel::INSTALLED_EXE)
            .map_err(|e| format!("Failed to copy exe to {}: {e}", tunnel::INSTALLED_EXE))?;
    }

    let bin_path = format!("\"{}\" service-run", tunnel::INSTALLED_EXE);
    let _ = win::run_cmd("sc.exe", &["delete", tunnel::SERVICE_NAME]);
    std::thread::sleep(Duration::from_millis(300));
    let create_res = win::run_cmd(
        "sc.exe",
        &[
            "create",
            tunnel::SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            "HHJ SSH Reverse Tunnel",
        ],
    )?;
    if create_res.code != 0 {
        return Err(format!("sc.exe create failed: {} {}", create_res.stdout, create_res.stderr));
    }
    let _ = win::run_cmd(
        "sc.exe",
        &["failure", tunnel::SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000"],
    );
    let start_res = win::run_cmd("sc.exe", &["start", tunnel::SERVICE_NAME])?;
    if start_res.code != 0 {
        return Err(format!("sc.exe start failed: {} {}", start_res.stdout, start_res.stderr));
    }
    println!("  Service '{}' started (auto-start on boot).", tunnel::SERVICE_NAME);

    // 4. Optional firewall hardening (disable broad Any-IP OpenSSH rules)
    println!("\n[4/4] Checking Windows Firewall exposure...");
    if args.harden_firewall {
        let rules = query_inbound_allow_rules()?;
        let plan = firewall::reconcile(&rules, cfg.port, SSHD_EXE, None);
        for broad in &plan.broad_rules {
            let res = win::run_powershell(&firewall::build_disable_rule_script(&broad.name))?;
            if res.code == 0
                && !st.disabled_firewall_rules.iter().any(|r| r.name.eq_ignore_ascii_case(&broad.name))
            {
                st.disabled_firewall_rules.push(state::DisabledRuleRecord {
                    name: broad.name.clone(),
                    was_enabled: true,
                });
                println!("  Disabled broad firewall rule '{}'.", broad.name);
            }
        }
    }

    st.save(state_path)?;

    println!("\n============================================================");
    println!("  Done! Connect from any terminal with:");
    println!("    ssh -J <your-vps-user>@{vps_host} {target_user}@127.0.0.1 -p {}", args.remote_port);
    println!("============================================================");
    Ok(())
}

fn run_status() -> Result<(), String> {
    let st = state::SetupState::load(Path::new(state::STATE_FILE));
    if cfg!(windows) {
        let out = win::run_powershell(
            "Get-Service -Name sshd,hhj-tunnel -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | ConvertTo-Json -Compress",
        )?;
        println!("Services: {}", out.stdout.trim());
    }
    if let Ok(tcfg) = tunnel::TunnelConfig::load(Path::new(tunnel::TUNNEL_CONFIG_PATH)) {
        println!(
            "Tunnel: {}@{}:{} -> 127.0.0.1:{} (local :{})",
            tcfg.vps_user, tcfg.vps_host, tcfg.vps_port, tcfg.remote_port, tcfg.local_ssh_port
        );
    }
    println!("Authorized keys recorded: {}", st.added_authorized_keys.len());
    Ok(())
}

fn run_disable() -> Result<(), String> {
    require_windows_admin()?;
    let state_path = Path::new(state::STATE_FILE);
    let mut st = state::SetupState::load(state_path);

    let _ = win::run_cmd("sc.exe", &["stop", tunnel::SERVICE_NAME]);
    let _ = win::run_cmd("sc.exe", &["delete", tunnel::SERVICE_NAME]);
    let _ = std::fs::remove_file(tunnel::TUNNEL_KEY_PATH);
    let _ = std::fs::remove_file(tunnel::KNOWN_HOSTS_PATH);
    let _ = std::fs::remove_file(tunnel::TUNNEL_CONFIG_PATH);

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

    st.save(state_path)?;
    println!("HHJ SSH + tunnel service disabled and cleaned up.");
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

fn query_inbound_allow_rules() -> Result<Vec<firewall::FirewallRuleSnapshot>, String> {
    let script = r#"
        $ErrorActionPreference='SilentlyContinue'
        @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_.DisplayName -like '*OpenSSH*' } | ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $ap = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            [ordered]@{
                Name=$_.DisplayName; Enabled=$true;
                Direction=[string]$_.Direction; Action=[string]$_.Action;
                Protocol=[string]$pf.Protocol; LocalPort=[string]$pf.LocalPort;
                RemoteAddress=(@($af.RemoteAddress) -join ',');
                Program=[string]$ap.Program
            }
        }) | ConvertTo-Json -Depth 4 -Compress
    "#;
    let res = win::run_powershell(script)?;
    let trimmed = res.stdout.trim();
    if res.code != 0 || trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('{') {
        Ok(serde_json::from_str::<firewall::FirewallRuleSnapshot>(trimmed).into_iter().collect())
    } else {
        Ok(serde_json::from_str::<Vec<firewall::FirewallRuleSnapshot>>(trimmed).unwrap_or_default())
    }
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
    fn firewall_reconcile_detects_broad_rules() {
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
        let plan = firewall::reconcile(&[broad], 22, SSHD_EXE, None);
        assert_eq!(plan.broad_rules.len(), 1);
    }

    #[test]
    fn tunnel_config_builds_strict_ssh_args() {
        let cfg = tunnel::TunnelConfig {
            vps_host: "203.0.113.10".into(),
            vps_port: 22,
            vps_user: "hhj-tunnel".into(),
            remote_port: 2222,
            local_ssh_port: 22,
        };
        let args = cfg.build_ssh_args();
        assert!(args.contains(&"127.0.0.1:2222:127.0.0.1:22".to_string()));
        assert!(args.contains(&"hhj-tunnel@203.0.113.10".to_string()));
        assert!(args.contains(&"StrictHostKeyChecking=yes".to_string()));
    }
}
