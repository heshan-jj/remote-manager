use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SERVICE_NAME: &str = "hhj-tunnel";
pub const INSTALL_DIR: &str = r"C:\ProgramData\HHJ\SshSetup";
pub const INSTALLED_EXE: &str = r"C:\ProgramData\HHJ\SshSetup\hhj-ssh-setup.exe";
pub const TUNNEL_KEY_PATH: &str = r"C:\ProgramData\HHJ\SshSetup\tunnel_key";
pub const KNOWN_HOSTS_PATH: &str = r"C:\ProgramData\HHJ\SshSetup\known_hosts";
pub const TUNNEL_CONFIG_PATH: &str = r"C:\ProgramData\HHJ\SshSetup\tunnel.json";
pub const SSH_EXE: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfig {
    pub vps_host: String,
    pub vps_port: u16,
    pub vps_user: String,
    pub remote_port: u16,
    pub local_ssh_port: u16,
}

impl TunnelConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&s).map_err(|e| format!("Invalid tunnel config: {e}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    pub fn build_ssh_args(&self) -> Vec<String> {
        vec![
            "-N".into(),
            "-T".into(),
            "-i".into(),
            TUNNEL_KEY_PATH.into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-o".into(),
            "ServerAliveInterval=30".into(),
            "-o".into(),
            "ServerAliveCountMax=3".into(),
            "-o".into(),
            format!("UserKnownHostsFile={KNOWN_HOSTS_PATH}"),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-p".into(),
            self.vps_port.to_string(),
            "-R".into(),
            format!("127.0.0.1:{}:127.0.0.1:{}", self.remote_port, self.local_ssh_port),
            format!("{}@{}", self.vps_user, self.vps_host),
        ]
    }
}

pub fn is_valid_host(host: &str) -> bool {
    let h = host.trim();
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
}

pub fn is_valid_unix_user(user: &str) -> bool {
    let u = user.trim();
    !u.is_empty()
        && u.len() <= 64
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[cfg(windows)]
pub fn run_windows_service() -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = std::ptr::null_mut();

    unsafe extern "system" fn ctrl_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP_REQUESTED.store(true, Ordering::SeqCst);
                set_status(STATUS_HANDLE, SERVICE_STOP_PENDING, 0);
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => NO_ERROR,
        }
    }

    unsafe fn set_status(handle: SERVICE_STATUS_HANDLE, state: u32, exit_code: u32) {
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 5000,
        };
        SetServiceStatus(handle, &status);
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name_wide: Vec<u16> = OsStr::new(SERVICE_NAME)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = RegisterServiceCtrlHandlerExW(
            name_wide.as_ptr(),
            Some(ctrl_handler),
            std::ptr::null_mut(),
        );
        STATUS_HANDLE = handle;
        set_status(handle, SERVICE_START_PENDING, 0);

        let cfg = match TunnelConfig::load(Path::new(TUNNEL_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                set_status(handle, SERVICE_STOPPED, 1);
                return;
            }
        };

        set_status(handle, SERVICE_RUNNING, 0);
        let args = cfg.build_ssh_args();

        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            if let Ok(mut child) = Command::new(SSH_EXE).args(&args).spawn() {
                while !STOP_REQUESTED.load(Ordering::SeqCst) {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => std::thread::sleep(Duration::from_millis(500)),
                        Err(_) => break,
                    }
                }
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
            // Wait 5s before reconnecting (checking stop flag every 250ms)
            for _ in 0..20 {
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        set_status(handle, SERVICE_STOPPED, 0);
    }

    let mut name_wide: Vec<u16> = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name_wide.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        Err("Failed to start Windows Service dispatcher (run via Service Control Manager).".into())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn run_windows_service() -> Result<(), String> {
    Err("Windows Service mode only runs on Windows.".into())
}
