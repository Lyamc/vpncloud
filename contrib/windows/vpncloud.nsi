; NSIS installer for VpnCloud. Built by contrib/windows/package.sh
;   makensis -DVERSION=x.y.z -DSTAGE=/path -DOUTFILE=/path/setup.exe this.nsi
;
; Payload: vpncloud.exe, vpncloud-gui.exe, wintun.dll (TUN), licenses, example
; config. TAP (tap-windows6) is not shipped: an optional component downloads
; OpenVPN's signed installer at install time.

!ifndef VERSION
  !error "Define VERSION (e.g. -DVERSION=2.4.3)"
!endif
!ifndef STAGE
  !error "Define STAGE (directory containing vpncloud.exe, wintun.dll, ...)"
!endif
!ifndef OUTFILE
  !error "Define OUTFILE"
!endif

; Official OpenVPN tap-windows6 NSIS installer (Win10+ signature). Not bundled.
; Newest standalone .exe on build.openvpn.net as of 2026-08; later GitHub tags
; ship .msm / dist zips only.
!define TAP6_VERSION "9.24.7-I601"
!define TAP6_URL "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe"
!define TAP6_SHA256 "1C44E77AB148DDFB174DE8041100EFC38C4F23500183FAFF88F9BADAC5782E3C"
!define TAP6_PAGE "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe"
!define TAP6_ARM64_PAGE "https://github.com/OpenVPN/tap-windows6/releases/tag/9.27.0"

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma
RequestExecutionLevel admin
SetOverwrite on

Name "VpnCloud ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\VpnCloud"
InstallDirRegKey HKLM "Software\VpnCloud" "InstallDir"
BrandingText "VpnCloud ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "VpnCloud"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "VpnCloud installer"
VIAddVersionKey "FileVersion" "${VERSION}.0"
VIAddVersionKey "LegalCopyright" "GPL-3.0. Wintun prebuilt DLL: WireGuard LLC"

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "WordFunc.nsh"
!include "StrFunc.nsh"
${StrStr}
!insertmacro WordReplace
!insertmacro un.WordReplace

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\vpncloud-gui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch VpnCloud GUI"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_LICENSE "${STAGE}/LICENSE.md"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  SetRegView 64
  ${If} ${RunningX64}
    StrCpy $INSTDIR "$PROGRAMFILES64\VpnCloud"
  ${EndIf}
FunctionEnd

Section "VpnCloud (required)" SecCore
  SectionIn RO
  SetOutPath $INSTDIR
  File "${STAGE}/vpncloud.exe"
  File "${STAGE}/wintun.dll"
  File "${STAGE}/LICENSE.md"
  File "${STAGE}/WINTUN-LICENSE.txt"
  File "${STAGE}/README.txt"
  File "${STAGE}/example.net.disabled"

  CreateDirectory "$SMPROGRAMS\VpnCloud"
  CreateShortCut "$SMPROGRAMS\VpnCloud\Uninstall VpnCloud.lnk" "$INSTDIR\Uninstall.exe"

  WriteRegStr HKLM "Software\VpnCloud" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "DisplayName" "VpnCloud ${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "Publisher" "Lyamc"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "URLInfoAbout" "https://github.com/Lyamc/vpncloud"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud" "NoRepair" 1
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Desktop GUI" SecGui
  SetOutPath $INSTDIR
  File "${STAGE}/vpncloud-gui.exe"
  CreateShortCut "$SMPROGRAMS\VpnCloud\VpnCloud.lnk" "$INSTDIR\vpncloud-gui.exe"
SectionEnd

Section "Add VpnCloud to PATH" SecPath
  Push $INSTDIR
  Call AddToPath
SectionEnd

Section /o "TAP driver (download tap-windows6)" SecTap
  ; TUN (default) uses bundled wintun.dll. TAP/L2 needs OpenVPN's signed
  ; kernel driver; we download it rather than shipping a .sys.
  Call InstallTapWindows6
SectionEnd

Section /o "Windows service (LocalSystem, auto-start)" SecService
  ; Registers the service but does not start it: edit
  ; %ProgramData%\VpnCloud\vpncloud.yaml first (password / peers / --ip).
  ReadEnvStr $R9 ProgramData
  ${If} $R9 == ""
    StrCpy $R9 "$WINDIR\..\ProgramData"
  ${EndIf}
  CreateDirectory "$R9\VpnCloud"
  ${If} ${FileExists} "$R9\VpnCloud\vpncloud.yaml"
  ${Else}
    FileOpen $0 "$R9\VpnCloud\vpncloud.yaml" w
    FileWrite $0 "# Generated by VpnCloud setup$\r$\n"
    FileWrite $0 "listen: 3210$\r$\n"
    FileWrite $0 "tray: false$\r$\n"
    FileClose $0
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\vpncloud.exe" service install --config "$R9\VpnCloud\vpncloud.yaml"'
SectionEnd

LangString DESC_SecCore ${LANG_ENGLISH} "CLI, Wintun TUN driver DLL, licenses, and an example config. Required."
LangString DESC_SecGui ${LANG_ENGLISH} "Iced desktop GUI (vpncloud-gui.exe) and a Start Menu shortcut."
LangString DESC_SecPath ${LANG_ENGLISH} "Prepend the install folder to the machine PATH so vpncloud is on the command line."
LangString DESC_SecTap ${LANG_ENGLISH} "Optional TAP/L2. Downloads OpenVPN's tap-windows6 installer (~600 KB) and runs it. Not needed for TUN. Unchecked by default."
LangString DESC_SecService ${LANG_ENGLISH} "Register a LocalSystem auto-start service. Does not start the VPN until you edit C:\ProgramData\VpnCloud\vpncloud.yaml."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecGui} $(DESC_SecGui)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} $(DESC_SecPath)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTap} $(DESC_SecTap)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function TapAlreadyInstalled
  ; Driver service tap0901 is created by tap-windows6 (and OpenVPN).
  Push $0
  SetRegView 64
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\tap0901" "ImagePath"
  ${If} $0 != ""
    Pop $0
    Push 1
    Return
  ${EndIf}
  SetRegView 32
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\tap0901" "ImagePath"
  SetRegView 64
  ${If} $0 != ""
    Pop $0
    Push 1
    Return
  ${EndIf}
  Pop $0
  Push 0
FunctionEnd

Function OpenTapDownloadPage
  ${If} ${IsNativeARM64}
    ExecShell "open" "${TAP6_ARM64_PAGE}"
  ${Else}
    ExecShell "open" "${TAP6_PAGE}"
  ${EndIf}
FunctionEnd

Function InstallTapWindows6
  Call TapAlreadyInstalled
  Pop $0
  ${If} $0 == 1
    DetailPrint "tap-windows6 already present (service tap0901); skipping download."
    MessageBox MB_OK "TAP-Windows (tap0901) is already installed. Skipping the OpenVPN tap-windows6 download."
    Return
  ${EndIf}

  ${If} ${IsNativeARM64}
    MessageBox MB_YESNO|MB_ICONQUESTION \
      "TAP/L2 needs OpenVPN's tap-windows6 kernel driver. There is no standalone TAP installer for ARM64; the 9.27.0 GitHub release has the ARM64 driver files.$\r$\n$\r$\nOpen that page now? (TUN/Wintun is already installed and does not need TAP.)" \
      IDNO tap_skip_arm
    Call OpenTapDownloadPage
    tap_skip_arm:
    Return
  ${EndIf}

  MessageBox MB_OKCANCEL|MB_ICONQUESTION \
    "TAP/L2 needs OpenVPN's tap-windows6 kernel driver (not bundled).$\r$\n$\r$\nVpnCloud will download tap-windows ${TAP6_VERSION} (~600 KB) from build.openvpn.net, verify SHA-256, and run OpenVPN's installer.$\r$\n$\r$\nTUN/Wintun is already included and does not need this.$\r$\n$\r$\nDownload and install TAP now?" \
    IDOK tap_download
  DetailPrint "User skipped tap-windows6 download."
  Return

  tap_download:
  StrCpy $R1 "$TEMP\vpncloud-tap-windows6.exe"
  DetailPrint "Downloading ${TAP6_URL}"
  nsExec::ExecToLog '"$SYSDIR\curl.exe" --fail --location --silent --show-error -o "$R1" "${TAP6_URL}"'
  Pop $0
  ${If} $0 != 0
    ${If} ${FileExists} "$R1"
    ${Else}
      DetailPrint "curl.exe failed ($0); trying PowerShell Invoke-WebRequest"
      nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri ''${TAP6_URL}'' -OutFile ''$R1''"'
      Pop $0
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$R1"
  ${Else}
    DetailPrint "tap-windows6 download failed"
    MessageBox MB_YESNO|MB_ICONEXCLAMATION \
      "Could not download tap-windows6 (network?).$\r$\n$\r$\nOpen the OpenVPN download in your browser instead?" \
      IDNO tap_fail
    Call OpenTapDownloadPage
    tap_fail:
    Return
  ${EndIf}

  DetailPrint "Verifying SHA-256 ${TAP6_SHA256}"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if ((Get-FileHash -LiteralPath ''$R1'' -Algorithm SHA256).Hash -ieq ''${TAP6_SHA256}'') { exit 0 }; exit 1"'
  Pop $0
  ${If} $0 != 0
    Delete "$R1"
    DetailPrint "tap-windows6 checksum mismatch; not running installer"
    MessageBox MB_YESNO|MB_ICONSTOP \
      "Downloaded tap-windows6 did not match the expected SHA-256. The file was deleted.$\r$\n$\r$\nOpen the official OpenVPN download page instead?" \
      IDNO tap_badhash
    Call OpenTapDownloadPage
    tap_badhash:
    Return
  ${EndIf}

  DetailPrint "Running OpenVPN tap-windows6 installer"
  ExecWait '"$R1"' $0
  Delete "$R1"
  DetailPrint "tap-windows6 installer exit code $0"
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "OpenVPN tap-windows6 installer exited with code $0. You can install TAP later from ${TAP6_PAGE}"
  ${EndIf}
FunctionEnd

Function AddToPath
  Exch $0
  Push $1
  Push $2
  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${StrStr} $2 $1 $0
  ${If} $2 == ""
    ${If} $1 == ""
      StrCpy $1 $0
    ${Else}
      StrCpy $1 "$1;$0"
    ${EndIf}
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" $1
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  ${EndIf}
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function un.RemoveFromPath
  Exch $0
  Push $1
  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${un.WordReplace} "$1" ";$0" "" "+" $1
  ${un.WordReplace} "$1" "$0;" "" "+" $1
  ${un.WordReplace} "$1" "$0" "" "+" $1
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" $1
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  Pop $1
  Pop $0
FunctionEnd

Section "Uninstall"
  SetRegView 64
  nsExec::ExecToLog '"$INSTDIR\vpncloud.exe" service uninstall'
  Push $INSTDIR
  Call un.RemoveFromPath
  Delete "$SMPROGRAMS\VpnCloud\VpnCloud.lnk"
  Delete "$SMPROGRAMS\VpnCloud\Uninstall VpnCloud.lnk"
  RMDir "$SMPROGRAMS\VpnCloud"
  Delete "$INSTDIR\vpncloud.exe"
  Delete "$INSTDIR\vpncloud-gui.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\LICENSE.md"
  Delete "$INSTDIR\WINTUN-LICENSE.txt"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\example.net.disabled"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VpnCloud"
  DeleteRegKey HKLM "Software\VpnCloud"
SectionEnd
