// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Windows driver setup: detect a missing TUN/TAP driver, ask the user, and
//! download + install the official package with a pinned SHA-256 checksum.
//!
//! TUN needs `wintun.dll` beside the executable (Wintun, WireGuard LLC).
//! TAP needs the OpenVPN tap-windows6 driver (service `tap0901`).
//! The URLs and hashes mirror `contrib/windows/vpncloud.nsi` so the NSIS setup
//! and the CLI/GUI/wizard offer the same, verified downloads.

use std::{env, io, io::Write, path::PathBuf, process::Command, ptr};

use windows_sys::Win32::{
    System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ},
    UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONQUESTION, MB_YESNO}
};

use crate::{device::Type, error::Error};

pub const WINTUN_VERSION: &str = "0.14.1";
pub const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
pub const WINTUN_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
/// Hashes of the DLLs inside the pinned Wintun archive, so extraction cannot
/// be tampered with after the archive itself was verified.
pub const WINTUN_DLL_SHA256_AMD64: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
pub const WINTUN_DLL_SHA256_ARM64: &str = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";
pub const TAP_VERSION: &str = "9.24.7-I601";
pub const TAP_URL: &str = "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe";
pub const TAP_SHA256: &str = "1C44E77AB148DDFB174DE8041100EFC38C4F23500183FAFF88F9BADAC5782E3C";
const TAP_SERVICE: &str = "SYSTEM\\CurrentControlSet\\Services\\tap0901";

/// How to ask the user for permission to download the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ui {
    /// Console prompt (CLI and wizard). No prompt when stdin is not a TTY.
    Console,
    /// Native Yes/No dialog (desktop GUI, which has no console).
    MessageBox
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// PowerShell string literal (single-quoted, with embedded quotes doubled).
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn current_exe_dir() -> Result<PathBuf, Error> {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .ok_or_else(|| Error::FileIo("current_exe", io::Error::other("no executable directory")))
}

/// Wintun archive directory for this architecture.
pub fn wintun_arch() -> Result<&'static str, Error> {
    match env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => {
            Err(Error::FileIo("Wintun architecture", io::Error::other(format!("unsupported architecture: {}", other))))
        }
    }
}

/// The DLL path tun-rs loads first (the application directory).
pub fn wintun_dll_path() -> Option<PathBuf> {
    current_exe_dir().ok().map(|dir| dir.join("wintun.dll"))
}

fn wintun_in_system32() -> bool {
    env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("System32").join("wintun.dll").is_file())
        .unwrap_or(false)
}

fn tap_service_installed() -> bool {
    let subkey = wide(TAP_SERVICE);
    let mut handle: *mut std::ffi::c_void = ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut handle) };
    if rc == 0 {
        unsafe { RegCloseKey(handle) };
        true
    } else {
        false
    }
}

/// True when the driver for this device type is already available.
pub fn is_installed(type_: Type) -> bool {
    match type_ {
        Type::Tun => wintun_dll_path().map(|p| p.is_file()).unwrap_or(false) || wintun_in_system32(),
        Type::Tap => tap_service_installed()
    }
}

/// Message shown when the driver is missing.
pub fn missing_message(type_: Type) -> String {
    match type_ {
        Type::Tun => {
            format!(
                "TUN mode needs the Wintun driver (wintun.dll), which was not found next to vpncloud.exe. \
             Download and install Wintun {} from www.wintun.net now? (Requires Administrator)",
                WINTUN_VERSION
            )
        }
        Type::Tap => {
            format!(
                "TAP/L2 mode needs the OpenVPN tap-windows6 driver (tap0901), which is not installed. \
             Download and install tap-windows {} from build.openvpn.net now? (Requires Administrator)",
                TAP_VERSION
            )
        }
    }
}

fn confirm_console(prompt: &str) -> io::Result<bool> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{} [Y/n] ", prompt);
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes"))
}

fn confirm_message_box(prompt: &str) -> bool {
    let text = wide(prompt);
    let caption = wide("VpnCloud driver");
    unsafe { MessageBoxW(ptr::null_mut(), text.as_ptr(), caption.as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

/// SHA-256 of the DLL for this architecture inside the pinned archive.
pub fn wintun_dll_sha256() -> Result<&'static str, Error> {
    match wintun_arch()? {
        "amd64" => Ok(WINTUN_DLL_SHA256_AMD64),
        "arm64" => Ok(WINTUN_DLL_SHA256_ARM64),
        _ => Err(Error::InvalidConfig("unsupported architecture for Wintun"))
    }
}

/// PowerShell script that downloads the Wintun ZIP, verifies its SHA-256, and
/// extracts the architecture-specific DLL next to the running executable.
///
/// Both the archive and the extracted DLL are pinned: a local attacker who
/// writes into TEMP after the archive check cannot plant a different DLL. The
/// temp directory is random and the archive handle is held open across the
/// extraction, and the final copy is re-verified before an atomic move.
fn wintun_script() -> Result<String, Error> {
    let dest = wintun_dll_path()
        .ok_or_else(|| Error::FileIo("Wintun destination", io::Error::other("no executable directory")))?;
    let arch = wintun_arch()?;
    let dll_sha = wintun_dll_sha256()?;
    Ok(format!(
        r#"$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dir = Join-Path $env:TEMP ('vpncloud-wintun-' + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
$zip = Join-Path $dir 'wintun.zip'
$extract = Join-Path $dir 'extract'
$handle = $null
try {{
  Invoke-WebRequest -UseBasicParsing -Uri {url} -OutFile $zip
  if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ine {sha}) {{ throw 'Wintun archive checksum mismatch' }}
  $handle = [System.IO.File]::Open($zip, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
  $dll = Join-Path $extract 'wintun/bin/{arch}/wintun.dll'
  if (-not (Test-Path -LiteralPath $dll)) {{ throw 'wintun.dll missing from archive' }}
  if ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash -ine {dll_sha}) {{ throw 'wintun.dll checksum mismatch' }}
  $tmpdest = '{dest}.vpncloud-tmp'
  Copy-Item -LiteralPath $dll -Destination $tmpdest -Force
  if ((Get-FileHash -LiteralPath $tmpdest -Algorithm SHA256).Hash -ine {dll_sha}) {{ throw 'copied wintun.dll checksum mismatch' }}
  Move-Item -LiteralPath $tmpdest -Destination {dest} -Force
  Write-Output 'ok'
}} finally {{
  if ($handle -ne $null) {{ $handle.Dispose() }}
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}}
"#,
        url = ps_quote(WINTUN_URL),
        sha = ps_quote(WINTUN_SHA256),
        arch = arch,
        dll_sha = ps_quote(dll_sha),
        dest = ps_quote(&dest.display().to_string())
    ))
}

/// PowerShell script that downloads the signed OpenVPN tap-windows6 installer,
/// verifies its SHA-256, and runs it (elevating through UAC when needed).
/// Uses a random temp directory and holds the verified file open so it cannot
/// be replaced between verification and the elevated `Start-Process`.
fn tap_script() -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dir = Join-Path $env:TEMP ('vpncloud-tap-' + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
$tmp = Join-Path $dir 'tap.exe'
$handle = $null
try {{
  Invoke-WebRequest -UseBasicParsing -Uri {url} -OutFile $tmp
  if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ine {sha}) {{ throw 'tap-windows6 checksum mismatch' }}
  $handle = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ine {sha}) {{ throw 'tap-windows6 checksum changed' }}
  $proc = Start-Process -FilePath $tmp -Verb RunAs -Wait -PassThru
  if ($proc.ExitCode -ne 0) {{ throw "tap-windows6 installer exit code $($proc.ExitCode)" }}
  Write-Output 'ok'
}} finally {{
  if ($handle -ne $null) {{ $handle.Dispose() }}
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}}
"#,
        url = ps_quote(TAP_URL),
        sha = ps_quote(TAP_SHA256)
    )
}

fn install(type_: Type) -> Result<(), Error> {
    let script = match type_ {
        Type::Tun => wintun_script()?,
        Type::Tap => tap_script()
    };
    info!("Downloading and installing the {} driver (this may take a moment)…", type_);
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| Error::FileIo("start PowerShell for driver install", e))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        let message = if detail.is_empty() {
            format!("{} installer exited with {}", type_, output.status)
        } else {
            format!("{} installer failed: {}", type_, detail)
        };
        return Err(Error::FileIo("driver install", io::Error::other(message)));
    }
    info!("{} driver install completed", type_);
    Ok(())
}

/// Check for the driver, ask the user when it is missing, and download it on
/// approval. Returns `true` when the driver is available afterwards, `false`
/// when the user declined (or there was no interactive console for the CLI).
pub fn ensure(type_: Type, ui: Ui) -> Result<bool, Error> {
    if is_installed(type_) {
        return Ok(true);
    }
    let prompt = missing_message(type_);
    let approved = match ui {
        Ui::Console => confirm_console(&prompt).map_err(|e| Error::FileIo("driver prompt", e))?,
        Ui::MessageBox => confirm_message_box(&prompt)
    };
    if !approved {
        info!("User skipped the {} driver download", type_);
        return Ok(false);
    }
    install(type_)?;
    Ok(is_installed(type_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wintun_script_has_pinned_artifact() {
        let script = wintun_script().unwrap();
        assert!(script.contains(WINTUN_URL));
        assert!(script.contains(WINTUN_SHA256));
        assert!(script.contains(&format!("wintun/bin/{}/wintun.dll", wintun_arch().unwrap())));
        assert!(script.contains(WINTUN_DLL_SHA256_AMD64) || script.contains(WINTUN_DLL_SHA256_ARM64));
        assert!(script.contains("GetRandomFileName"));
        assert!(script.contains("wintun.dll"));
        assert!(script.contains("Get-FileHash"));
    }

    #[test]
    fn tap_script_has_pinned_artifact() {
        let script = tap_script();
        assert!(script.contains(TAP_URL));
        assert!(script.contains(TAP_SHA256));
        assert!(!script.contains("tap0901")); // service is detected, not named in the script
        assert!(script.contains("Start-Process"));
        assert!(script.contains("Get-FileHash"));
    }

    #[test]
    fn missing_messages_name_the_driver() {
        assert!(missing_message(Type::Tun).contains("wintun.dll"));
        assert!(missing_message(Type::Tun).contains("www.wintun.net"));
        assert!(missing_message(Type::Tap).contains("tap-windows6"));
        assert!(missing_message(Type::Tap).contains("build.openvpn.net"));
    }

    #[test]
    fn powershell_quotes_are_escaped() {
        assert_eq!(ps_quote("C:\\a'b.dll"), "'C:\\a''b.dll'");
    }

    #[test]
    fn wintun_arch_matches_target() {
        let arch = wintun_arch().unwrap();
        assert!(arch == "amd64" || arch == "arm64");
    }
}
