[Setup]
AppName=SentinelML
AppVersion=3.0.0
VersionInfoVersion=3.0.0.0
DefaultDirName={autopf}\SentinelML
DefaultGroupName=SentinelML
UninstallDisplayIcon={app}\SentinelML.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.\Installer
OutputBaseFilename=SentinelML_Setup
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\SentinelML\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SentinelML"; Filename: "{app}\SentinelML.exe"
Name: "{group}\{cm:UninstallProgram,SentinelML}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SentinelML"; Filename: "{app}\SentinelML.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SentinelML.exe"; Description: "{cm:LaunchProgram,SentinelML}"; Flags: nowait postinstall skipifsilent
