use crate::firewall::encode_powershell;
use std::fs::File;
use std::io;
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

pub fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create dir failed: {e}"))?;
    }
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("Download failed: {e}"))?;
    let mut reader = resp.into_reader();
    let tmp = dest.with_extension("part");
    let mut file = File::create(&tmp).map_err(|e| format!("Create file failed: {e}"))?;
    io::copy(&mut reader, &mut file).map_err(|e| format!("Write failed: {e}"))?;
    drop(file);
    std::fs::rename(&tmp, dest).map_err(|e| format!("Rename failed: {e}"))?;
    Ok(())
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

#[cfg(windows)]
pub fn verify_authenticode_publisher(file_path: &Path, expected_org: &str) -> Result<String, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
        CryptQueryObject, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide: Vec<u16> = OsStr::new(file_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = GUID {
        data1: 0x00AAC56B,
        data2: 0xCD44,
        data3: 0x11d0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    let hr = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut trust_data as *mut _ as *mut _) };
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut trust_data as *mut _ as *mut _) };

    if hr != 0 {
        return Err(format!("WinVerifyTrust failed (0x{:08X}).", hr as u32));
    }

    // Inspect embedded signer certificate
    unsafe {
        let mut store = std::ptr::null_mut();
        let mut msg = std::ptr::null_mut();
        let ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut store,
            &mut msg,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            return Err("Could not query Authenticode signer certificate.".into());
        }

        // Enumerate certificates in embedded store and match expected_org
        let mut ctx = windows_sys::Win32::Security::Cryptography::CertEnumCertificatesInStore(store, std::ptr::null());
        let mut matched = None;
        while !ctx.is_null() {
            let mut buf = [0u16; 256];
            let len = CertGetNameStringW(
                ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            );
            if len > 1 {
                let name = String::from_utf16_lossy(&buf[..(len as usize - 1)]);
                if name.to_ascii_lowercase().contains(&expected_org.to_ascii_lowercase()) {
                    matched = Some(name);
                    CertFreeCertificateContext(ctx);
                    break;
                }
            }
            ctx = windows_sys::Win32::Security::Cryptography::CertEnumCertificatesInStore(store, ctx);
        }
        if !msg.is_null() {
            CryptMsgClose(msg);
        }
        if !store.is_null() {
            CertCloseStore(store, 0);
        }
        let _ = CMSG_SIGNER_INFO_PARAM;
        matched.ok_or_else(|| format!("Signer does not match expected organization '{expected_org}'."))
    }
}

#[cfg(not(windows))]
pub fn verify_authenticode_publisher(_file_path: &Path, _expected_org: &str) -> Result<String, String> {
    Err("Authenticode verification is only supported on Windows.".into())
}

pub fn apply_admin_authorized_keys_acl(path: &Path) -> Result<(), String> {
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
