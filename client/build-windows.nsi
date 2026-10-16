; Compile with NSIS 3 after build-windows-data.py and the native Data verifier.
; Required defines: APP_DIR, GPG_DIR, LICENSE_DIR, DATA_INCLUDE, DATA_VERIFIER, OUTPUT_EXE.
Target amd64-unicode
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef APP_DIR
  !error "APP_DIR must contain OnionDesk.exe and its _internal directory"
!endif
!ifndef GPG_DIR
  !error "GPG_DIR must contain the verified native GnuPG distribution"
!endif
!ifndef LICENSE_DIR
  !error "LICENSE_DIR must contain the bundled component licenses"
!endif
!ifndef OUTPUT_EXE
  !error "OUTPUT_EXE must name the resulting setup executable"
!endif

!ifndef DATA_INCLUDE
  !error "DATA_INCLUDE must name the generated source-pinned Data file list"
!endif
!ifndef DATA_VERIFIER
  !error "DATA_VERIFIER must name the compiled source-pinned SHA256 verifier"
!endif
!include "${DATA_INCLUDE}"

Var SourceData

Name "OnionDesk"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\OnionDesk"
RequestExecutionLevel admin
ManifestDPIAware true
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Установка OnionDesk"
!define MUI_WELCOMEPAGE_TEXT "Мастер установит OnionDesk и встроенную проверку подписи Tails.$\r$\n$\r$\nPython, GnuPG и команды устанавливать отдельно не нужно.$\r$\n$\r$\nРазрешение Windows требуется только для защищённой установки в Program Files. При записи флешки Windows запросит разрешение отдельно."
!define MUI_FINISHPAGE_TITLE "OnionDesk установлен"
!define MUI_FINISHPAGE_TEXT "Закройте этот мастер и откройте значок OnionDesk на рабочем столе.$\r$\n$\r$\nПрограмма откроется в вашем обычном браузере. Для выхода нажмите «Закрыть приложение» в самом OnionDesk.$\r$\n$\r$\nДля сетевых действий запустите Tor Browser."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "Нужна Windows 10/11 x64."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "Нужна Windows 10/11 x64."
    Abort
  ${EndIf}
FunctionEnd

Section "OnionDesk" Main
  SetRegView 64
  ; Only the release's sibling hidden folder is an installation source.
  StrCpy $SourceData "$EXEDIR\.oniondesk\OnionDesk-Data"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=OnionDesk-Data-Check.exe "${DATA_VERIFIER}"
  ClearErrors
  ExecWait '"$PLUGINSDIR\OnionDesk-Data-Check.exe" "$SourceData"' $0
  IfErrors source_failed
  StrCmp $0 0 source_verified source_failed
  source_failed:
    SetErrorLevel 2
    MessageBox MB_OK|MB_ICONSTOP "Не найден полный проверенный комплект OnionDesk. Распакуйте весь архив и оставьте папку .oniondesk рядом с установщиком. Изменённые или неполные файлы устанавливать нельзя." /SD IDOK
    Abort
  source_verified:
  ; The attribute affects this release folder only, never Explorer settings.
  SetFileAttributes "$EXEDIR\.oniondesk" HIDDEN
  System::Call 'kernel32::GetDiskFreeSpaceExW(w "$PROGRAMFILES64", *l .r0, p 0, p 0) i .r1'
  StrCmp $1 0 space_failed
  System::Int64Op $0 >= ${ONIONDESK_REQUIRED_BYTES}
  Pop $1
  StrCmp $1 1 enough_space
  space_failed:
    SetErrorLevel 2
    MessageBox MB_OK|MB_ICONSTOP "Недостаточно свободного места для OnionDesk и файлов комплекта либо Windows не смогла проверить диск. Освободите место на системном диске и повторите установку." /SD IDOK
    Abort
  enough_space:
  ; The destination is fixed even if a caller supplies /D on the command line.
  StrCpy $INSTDIR "$PROGRAMFILES64\OnionDesk"
  SetShellVarContext all
  IfFileExists "$INSTDIR" 0 fresh_install
    MessageBox MB_OK|MB_ICONSTOP "Папка Program Files\OnionDesk уже существует. Сначала удалите прежнюю версию через «Установленные приложения», затем повторите установку." /SD IDOK
    Abort
  fresh_install:
  ClearErrors
  CreateDirectory "$INSTDIR"
  IfErrors create_failed
  SetOutPath "$INSTDIR"
  File /r "${APP_DIR}/*"
  IfErrors install_failed
  SetOutPath "$INSTDIR\tools\gpg"
  File /r "${GPG_DIR}/*"
  IfErrors install_failed
  SetOutPath "$INSTDIR\LICENSES"
  File /r "${LICENSE_DIR}/*"
  IfErrors install_failed
  !insertmacro CopyPinnedData
  ClearErrors
  ExecWait '"$PLUGINSDIR\OnionDesk-Data-Check.exe" "$INSTDIR\OnionDesk-Data"' $0
  IfErrors install_failed
  StrCmp $0 0 copied_data_verified install_failed
  copied_data_verified:
  SetOutPath "$INSTDIR"
  ClearErrors
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  IfErrors install_failed
  CreateShortCut "$DESKTOP\OnionDesk.lnk" "$INSTDIR\OnionDesk.exe"
  CreateDirectory "$SMPROGRAMS\OnionDesk"
  CreateShortCut "$SMPROGRAMS\OnionDesk\OnionDesk.lnk" "$INSTDIR\OnionDesk.exe"
  CreateShortCut "$SMPROGRAMS\OnionDesk\Удалить OnionDesk.lnk" "$INSTDIR\Uninstall.exe"
  IfErrors install_failed
  ClearErrors
  WriteRegStr HKLM "Software\OnionDesk" "DataRoot" "$INSTDIR\OnionDesk-Data"
  IfErrors install_failed
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "DisplayName" "OnionDesk"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "DisplayVersion" "1.0.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "Publisher" "OnionDesk"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk" "NoRepair" 1
  IfErrors install_failed
  Goto install_done
  install_failed:
    ; $INSTDIR did not exist before this fresh installation. Never touch AppData,
    ; user-selected folders, wallets, or another existing installation.
    SetOutPath "$TEMP"
    Delete "$DESKTOP\OnionDesk.lnk"
    RMDir /r "$SMPROGRAMS\OnionDesk"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk"
    DeleteRegKey HKLM "Software\OnionDesk"
    RMDir /r "$INSTDIR"
  create_failed:
    SetErrorLevel 2
    MessageBox MB_OK|MB_ICONSTOP "Установка не завершена: Windows не смогла скопировать или проверить все файлы. Освободите место, проверьте права доступа и повторите установку. Ваши кошельки и личные файлы не изменены." /SD IDOK
    Abort
  install_done:
SectionEnd

Section "Uninstall"
  StrCpy $INSTDIR "$PROGRAMFILES64\OnionDesk"
  SetShellVarContext all
  delete_application:
  ClearErrors
  Delete "$INSTDIR\OnionDesk.exe"
  IfErrors 0 delete_runtime
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Закройте OnionDesk через «Закрыть приложение», затем нажмите «Повторить». Программа ещё используется или Windows не разрешает удаление." /SD IDCANCEL IDRETRY delete_application
    Abort
  delete_runtime:
  ClearErrors
  RMDir /r "$INSTDIR\_internal"
  IfErrors 0 delete_tools
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Закройте OnionDesk и другие программы, использующие его файлы, затем нажмите «Повторить»." /SD IDCANCEL IDRETRY delete_runtime
    Abort
  delete_tools:
  ClearErrors
  RMDir /r "$INSTDIR\tools"
  IfErrors 0 delete_licenses
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Дождитесь окончания проверки подписи Tails, затем нажмите «Повторить»." /SD IDCANCEL IDRETRY delete_tools
    Abort
  delete_licenses:
  ClearErrors
  RMDir /r "$INSTDIR\LICENSES"
  IfErrors 0 delete_registration
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Windows не разрешает удалить файлы лицензий. Закройте использующие их программы и нажмите «Повторить»." /SD IDCANCEL IDRETRY delete_licenses
    Abort
  delete_registration:
  ; Remove the installed code-pinned distribution only; preserve user state.
  ClearErrors
  RMDir /r "$INSTDIR\OnionDesk-Data"
  IfErrors 0 delete_shortcuts
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Закройте программы, использующие файлы комплекта OnionDesk, затем нажмите «Повторить»." /SD IDCANCEL IDRETRY delete_registration
    Abort
  delete_shortcuts:
  Delete "$INSTDIR\.oniondesk-windows-build"
  Delete "$DESKTOP\OnionDesk.lnk"
  RMDir /r "$SMPROGRAMS\OnionDesk"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  SetRegView 64
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk"
  DeleteRegKey HKLM "Software\OnionDesk"
SectionEnd
