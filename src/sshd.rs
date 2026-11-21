use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshdConfigSummary {
    pub port: u16,
    pub password_authentication: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub has_match_administrators: bool,
    pub admin_authorized_keys_file: Option<String>,
}

pub fn parse_sshd_config(content: &str) -> SshdConfigSummary {
    let mut port = 22u16;
    let mut password_authentication = None;
    let mut pubkey_authentication = None;
    let mut has_match_administrators = false;
    let mut in_match_admin = false;
    let mut admin_authorized_keys_file = None;

    for raw in content.replace("\r\n", "\n").split('\n') {
        let no_comment = raw.split('#').next().unwrap_or("").trim();
        if no_comment.is_empty() {
            continue;
        }
        let mut parts = no_comment.splitn(2, |c: char| c == ' ' || c == '\t');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        if key.is_empty() || val.is_empty() {
            continue;
        }

        if key.eq_ignore_ascii_case("Match") {
            let lower = val.to_ascii_lowercase();
            in_match_admin = lower.contains("group") && lower.contains("administrators");
            if in_match_admin {
                has_match_administrators = true;
            }
            continue;
        }

        if in_match_admin {
            if key.eq_ignore_ascii_case("AuthorizedKeysFile") {
                admin_authorized_keys_file = Some(val.to_string());
            }
            continue;
        }

        if key.eq_ignore_ascii_case("Port") {
            if let Ok(p) = val.parse::<u16>() {
                if p >= 1 {
                    port = p;
                }
            }
        } else if key.eq_ignore_ascii_case("PasswordAuthentication") {
            password_authentication = parse_yes_no(val);
        } else if key.eq_ignore_ascii_case("PubkeyAuthentication") {
            pubkey_authentication = parse_yes_no(val);
        }
    }

    SshdConfigSummary {
        port,
        password_authentication,
        pubkey_authentication,
        has_match_administrators,
        admin_authorized_keys_file,
    }
}

fn parse_yes_no(val: &str) -> Option<bool> {
    if val.eq_ignore_ascii_case("yes") {
        Some(true)
    } else if val.eq_ignore_ascii_case("no") {
        Some(false)
    } else {
        None
    }
}

pub fn probe_ssh_banner(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr: SocketAddr = format!("{host}:{port}").parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
    }
}
