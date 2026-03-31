; KeePassXC TCP Bridge — NSIS Installer
; Installs kpxc-bridge.exe as a system tray app with firewall rule and user startup

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

; --- Build-time defines (can be overridden with -D on makensis command line) ---
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef OUTFILE
  !define OUTFILE "kpxc-bridge-setup.exe"
!endif

; --- General ---
Name "KeePassXC TCP Bridge"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\KeePassXC Bridge"
InstallDirRegKey HKLM "Software\KeePassXC Bridge" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; --- Version info embedded in the installer exe ---
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "KeePassXC TCP Bridge"
VIAddVersionKey "FileDescription" "KeePassXC TCP Bridge Installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "BSD-2-Clause"

; --- MUI settings ---
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_ABORTWARNING

; --- Pages ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page custom PortPageCreate PortPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Variables ---
Var PortInput
Var Port

; --- Custom port page ---
Function PortPageCreate
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 24u "TCP listen port for the bridge.$\nDefault: 19455. Change only if you have a conflict."
  Pop $0

  ${NSD_CreateNumber} 0 30u 80u 14u "19455"
  Pop $PortInput

  nsDialogs::Show
FunctionEnd

Function PortPageLeave
  ${NSD_GetText} $PortInput $Port
  ${If} $Port == ""
    StrCpy $Port "19455"
  ${EndIf}
FunctionEnd

; --- Installer section ---
Section "Install"
  SetOutPath "$INSTDIR"

  ; Remove old service if upgrading from service-based version (silent)
  nsExec::Exec 'sc stop KeePassXCBridge'
  nsExec::Exec 'sc delete KeePassXCBridge'
  Sleep 1000

  ; Kill any running tray instance
  nsExec::ExecToLog 'taskkill /F /IM kpxc-bridge.exe'
  Sleep 500

  ; Copy files
  File "kpxc-bridge.exe"

  ; Register in user startup (runs as tray app on login)
  nsExec::ExecToLog '"$INSTDIR\kpxc-bridge.exe" -port $Port install'

  ; Add firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="KeePassXC TCP Bridge"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="KeePassXC TCP Bridge" dir=in action=allow protocol=TCP localport=$Port program="$INSTDIR\kpxc-bridge.exe" enable=yes'

  ; Start the tray app now
  Exec '"$INSTDIR\kpxc-bridge.exe"'

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Registry for Add/Remove Programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "DisplayName" "KeePassXC TCP Bridge"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "Publisher" "Daniel Morante"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "DisplayIcon" '"$INSTDIR\kpxc-bridge.exe",0'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge" \
    "NoRepair" 1

  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\KeePassXC Bridge"
  CreateShortcut "$SMPROGRAMS\KeePassXC Bridge\KeePassXC Bridge.lnk" "$INSTDIR\kpxc-bridge.exe"
  CreateShortcut "$SMPROGRAMS\KeePassXC Bridge\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Remember install dir
  WriteRegStr HKLM "Software\KeePassXC Bridge" "InstallDir" "$INSTDIR"
SectionEnd

; --- Uninstaller section ---
Section "Uninstall"
  ; Kill running tray app
  nsExec::ExecToLog 'taskkill /F /IM kpxc-bridge.exe'
  Sleep 500

  ; Remove from startup registry
  nsExec::ExecToLog '"$INSTDIR\kpxc-bridge.exe" uninstall'

  ; Remove old service if present (silent — only matters for upgrades from v0.1.x)
  nsExec::Exec 'sc stop KeePassXCBridge'
  nsExec::Exec 'sc delete KeePassXCBridge'

  ; Remove firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="KeePassXC TCP Bridge"'

  ; Remove files
  Delete "$INSTDIR\kpxc-bridge.exe"
  Delete "$INSTDIR\kpxc-bridge.log"
  Delete "$INSTDIR\kpxc-bridge.pdb"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  ; Remove Start Menu shortcuts
  Delete "$SMPROGRAMS\KeePassXC Bridge\KeePassXC Bridge.lnk"
  Delete "$SMPROGRAMS\KeePassXC Bridge\Uninstall.lnk"
  RMDir "$SMPROGRAMS\KeePassXC Bridge"

  ; Clean registry
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassXCBridge"
  DeleteRegKey HKLM "Software\KeePassXC Bridge"

  ; Clean old service registry (if upgrading)
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\KeePassXCBridge"
SectionEnd

; --- Silent install defaults ---
Function .onInit
  StrCpy $Port "19455"
FunctionEnd
