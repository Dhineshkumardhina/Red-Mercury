; Red Mercury NSIS Installer / Upgrader / Uninstaller Customization
; Ensures clean upgrades (terminating running desktop engine binaries in $INSTDIR)
; and preserves user data (%APPDATA%\Red Mercury) unless explicitly purged on uninstall.

!macro customInit
  ; Ensure clean upgrade if an older Red Mercury process is running
  nsExec::ExecToLog 'taskkill /F /IM "Red Mercury.exe" /T'
!macroend

!macro customUnInit
  nsExec::ExecToLog 'taskkill /F /IM "Red Mercury.exe" /T'
!macroend

!macro customRemoveFiles
  ; Application binaries in $INSTDIR are removed by electron-builder;
  ; %APPDATA%\Red Mercury (SQLite DB, workspaces, encrypted keys, logs) is preserved by default
  ; for safe upgrades and audit retention.
!macroend
