use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

pub const HHJ_MARKER_PREFIX: &str = "hhj-remote-manager:";
pub const MIN_RSA_BITS: usize = 3072;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPublicKey {
    pub key_type: String,
    pub base64_blob: String,
    pub fingerprint_sha256: String,
    pub rsa_bits: Option<usize>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKeyEntry {
    pub raw_line: String,
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub date: String,
    pub label: String,
}

pub fn parse_public_key(input: &str) -> Result<ParsedPublicKey, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Please provide an OpenSSH public key.".into());
    }
    if trimmed.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err("This looks like a PRIVATE key. Never paste a private key — paste the .pub public key line instead.".into());
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("A public key must be a single line.".into());
    }

    let mut parts = trimmed.splitn(3, |c: char| c == ' ' || c == '\t');
    let key_type = parts.next().unwrap_or("");
    let b64 = parts.next().unwrap_or("").trim_start();
    let comment = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    if key_type.is_empty() || b64.is_empty() {
        return Err("Invalid OpenSSH public key format. Expected '<type> <base64> [comment]'.".into());
    }

    let supported = matches!(
        key_type,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
    );
    if !supported {
        return Err(format!(
            "Unsupported key type '{key_type}'. Supported: ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa."
        ));
    }

    // Re-split cleanly to ignore extra whitespace between key_type and b64
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return Err("Invalid OpenSSH public key format.".into());
    }
    let key_type = tokens[0];
    let b64 = tokens[1];

    let blob = STANDARD
        .decode(b64)
        .map_err(|_| "The public key base64 payload is invalid.".to_string())?;

    let (embedded_type_bytes, mut offset) = read_ssh_string(&blob, 0)
        .ok_or_else(|| "Malformed SSH wire-format public key blob.".to_string())?;
    let embedded_type = std::str::from_utf8(embedded_type_bytes)
        .map_err(|_| "Malformed key type in SSH blob.".to_string())?;
    if embedded_type != key_type {
        return Err(format!(
            "Key type mismatch: line starts with '{key_type}' but blob contains '{embedded_type}'."
        ));
    }

    let mut rsa_bits = None;
    if key_type == "ssh-rsa" {
        let (_, next) = read_ssh_string(&blob, offset)
            .ok_or_else(|| "Malformed ssh-rsa exponent.".to_string())?;
        offset = next;
        let (modulus, _) = read_ssh_string(&blob, offset)
            .ok_or_else(|| "Malformed ssh-rsa modulus.".to_string())?;
        let bits = count_modulus_bits(modulus);
        if bits < MIN_RSA_BITS {
            return Err(format!(
                "RSA key is {bits} bits; at least {MIN_RSA_BITS} bits are required."
            ));
        }
        rsa_bits = Some(bits);
    }

    let digest = Sha256::digest(&blob);
    let fp = STANDARD_NO_PAD.encode(digest);

    Ok(ParsedPublicKey {
        key_type: key_type.to_string(),
        base64_blob: b64.to_string(),
        fingerprint_sha256: fp,
        rsa_bits,
        comment,
    })
}

pub fn format_hhj_line(key: &ParsedPublicKey, date_yyyy_mm_dd: &str, label: &str) -> String {
    let clean_label: String = label
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    let final_label = if clean_label.is_empty() { "admin" } else { &clean_label };
    format!(
        "{} {} {HHJ_MARKER_PREFIX}{date_yyyy_mm_dd}:{final_label}",
        key.key_type, key.base64_blob
    )
}

pub fn merge_authorized_keys(
    existing: &str,
    formatted_hhj_line: &str,
    parsed: &ParsedPublicKey,
) -> (String, bool) {
    let mut lines: Vec<String> = if existing.is_empty() {
        Vec::new()
    } else {
        existing
            .replace("\r\n", "\n")
            .split('\n')
            .map(|s| s.to_string())
            .collect()
    };

    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }

    for line in &lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = t.split_whitespace().collect();
        if tokens.len() >= 2 && tokens[0] == parsed.key_type && tokens[1] == parsed.base64_blob {
            return (normalize_crlf(&lines), false);
        }
    }

    lines.push(formatted_hhj_line.to_string());
    (normalize_crlf(&lines), true)
}

pub fn list_hhj_keys(content: &str) -> Vec<ManagedKeyEntry> {
    let mut out = Vec::new();
    for raw in content.replace("\r\n", "\n").split('\n') {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Ok(parsed) = parse_public_key(t) {
            if let Some(comment) = &parsed.comment {
                if let Some(rest) = comment.strip_prefix(HHJ_MARKER_PREFIX) {
                    let (date, label) = match rest.split_once(':') {
                        Some((d, l)) => (d.to_string(), l.to_string()),
                        None => (rest.to_string(), String::new()),
                    };
                    out.push(ManagedKeyEntry {
                        raw_line: t.to_string(),
                        key_type: parsed.key_type,
                        fingerprint_sha256: parsed.fingerprint_sha256,
                        date,
                        label,
                    });
                }
            }
        }
    }
    out
}

pub fn revoke_hhj_keys(content: &str, fingerprint: Option<&str>) -> (String, usize) {
    let target_fp = fingerprint.map(|f| f.strip_prefix("SHA256:").unwrap_or(f));
    let mut kept = Vec::new();
    let mut removed = 0usize;

    for raw in content.replace("\r\n", "\n").split('\n') {
        let t = raw.trim();
        if !t.is_empty() && !t.starts_with('#') {
            if let Ok(parsed) = parse_public_key(t) {
                let is_hhj = parsed
                    .comment
                    .as_deref()
                    .is_some_and(|c| c.starts_with(HHJ_MARKER_PREFIX));
                if is_hhj
                    && target_fp.is_none_or(|fp| fp == parsed.fingerprint_sha256)
                {
                    removed += 1;
                    continue;
                }
            }
        }
        kept.push(raw.to_string());
    }

    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    (normalize_crlf(&kept), removed)
}

fn read_ssh_string(blob: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset + 4 > blob.len() {
        return None;
    }
    let len = u32::from_be_bytes(blob[offset..offset + 4].try_into().ok()?) as usize;
    let end = offset.checked_add(4)?.checked_add(len)?;
    if end > blob.len() {
        return None;
    }
    Some((&blob[offset + 4..end], end))
}

fn count_modulus_bits(mpint: &[u8]) -> usize {
    let trimmed = match mpint.iter().position(|&b| b != 0) {
        Some(idx) => &mpint[idx..],
        None => return 0,
    };
    let leading_bits = 8 - trimmed[0].leading_zeros() as usize;
    (trimmed.len() - 1) * 8 + leading_bits
}

fn normalize_crlf(lines: &[String]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        let mut s = lines.join("\r\n");
        s.push_str("\r\n");
        s
    }
}
