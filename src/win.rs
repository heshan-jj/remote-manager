use crate::firewall::encode_powershell;
use std::path::Path;
use std::process::Command;

#[derive(Debug)]
pub struct CmdOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cmd(program: &str, args: &[&str]) -> Result<CmdOutput, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run '{program}': {e}"))?;
    Ok(CmdOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

pub fn run_powershell(script: &str) -> Result<CmdOutput, String> {
    let encoded = encode_powershell(script);
    run_cmd(
        "powershell.exe",
        &["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded],
    )
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

pub fn apply_admin_only_acl(path: &Path) -> Result<(), String> {
    let p = path.to_string_lossy();
    let res = run_cmd(
        "icacls.exe",
        &[&p, "/inheritance:r", "/grant", "*S-1-5-32-544:F", "/grant", "*S-1-5-18:F"],
    )?;
    if res.code != 0 {
        return Err(format!("icacls failed: {} {}", res.stdout, res.stderr));
    }
    Ok(())
}

pub fn apply_user_authorized_keys_acl(path: &Path, username: &str) -> Result<(), String> {
    let p = path.to_string_lossy();
    let user_grant = format!("{username}:F");
    let res = run_cmd(
        "icacls.exe",
        &[
            &p,
            "/inheritance:r",
            "/grant",
            &user_grant,
            "/grant",
            "*S-1-5-32-544:F",
            "/grant",
            "*S-1-5-18:F",
        ],
    )?;
    if res.code != 0 {
        return Err(format!("icacls failed: {} {}", res.stdout, res.stderr));
    }
    Ok(())
}
