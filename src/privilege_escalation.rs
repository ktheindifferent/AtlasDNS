use std::env;
use std::io::IsTerminal;
use std::process::{Command, exit};

#[cfg(unix)]
use sudo::RunningAs;

/// Check if the current process has administrative privileges
pub fn has_admin_privileges() -> bool {
    #[cfg(unix)]
    {
        // On Unix systems, check if running as root (uid 0)
        matches!(sudo::check(), RunningAs::Root)
    }
    
    #[cfg(windows)]
    {
        // On Windows, check if running as administrator
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        
        unsafe {
            let mut token_handle = HANDLE::default();
            let process_handle = GetCurrentProcess();
            
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_ok() {
                let mut elevation = TOKEN_ELEVATION::default();
                let mut return_length = 0u32;
                let elevation_ptr = &mut elevation as *mut _ as *mut std::ffi::c_void;
                
                if GetTokenInformation(
                    token_handle,
                    TokenElevation,
                    Some(elevation_ptr),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut return_length
                ).is_ok() {
                    return elevation.TokenIsElevated != 0;
                }
            }
        }
        false
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        // For other platforms, assume we don't have privileges
        false
    }
}

/// Attempt to restart the current process with elevated privileges
pub fn escalate_privileges() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    
    #[cfg(unix)]
    {
        // First check if we're in a TTY environment where sudo can prompt for password
        let is_tty = std::io::stdin().is_terminal();
        
        if !is_tty {
            return Err("Not running in a terminal - cannot prompt for sudo password".to_string());
        }
        
        // Try the sudo crate's automatic escalation first
        match sudo::escalate_if_needed() {
            Ok(_) => Ok(()),
            Err(e) => {
                // If automatic escalation fails, try manual sudo execution
                log::debug!("Sudo crate escalation failed: {}. Attempting manual sudo...", e);
                
                let mut cmd = Command::new("sudo");
                cmd.arg(program);
                for arg in &args[1..] {
                    cmd.arg(arg);
                }
                
                // Execute sudo and replace current process
                match cmd.status() {
                    Ok(status) => {
                        if status.success() {
                            // The sudo command succeeded, exit this process
                            exit(0);
                        } else {
                            Err("Sudo command failed or was cancelled".to_string())
                        }
                    }
                    Err(e) => Err(format!("Failed to execute sudo: {}", e))
                }
            }
        }
    }
    
    #[cfg(windows)]
    {
        // On Windows, use PowerShell to restart with admin privileges
        let ps_script = format!(
            "Start-Process '{}' -ArgumentList '{}' -Verb RunAs",
            program,
            args[1..].join(" ")
        );
        
        let output = Command::new("powershell")
            .args(&["-Command", &ps_script])
            .output();
            
        match output {
            Ok(_) => {
                log::info!("Restarting with administrator privileges...");
                exit(0);
            }
            Err(e) => Err(format!("Failed to restart with admin privileges: {}", e))
        }
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        Err("Privilege escalation not supported on this platform".to_string())
    }
}

/// Check if a port requires administrative privileges
pub fn port_requires_privileges(port: u16) -> bool {
    #[cfg(unix)]
    {
        // On Unix systems, ports below 1024 require root privileges
        port < 1024
    }
    
    #[cfg(not(unix))]
    {
        // On other systems, be conservative and assume privileged ports need admin
        port < 1024
    }
}