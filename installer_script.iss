[Setup]
AppName=AI-Driven Cyber Threat Prevention System
AppVersion=1.0.0
DefaultDirName={pf}\AI_Cyber_Threat_Prevention
DefaultGroupName=AI-Driven Cyber Threat Prevention System
OutputBaseFilename=AI_Cyber_Threat_Prevention_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "dist\AI-Driven_Cyber_Threat_Prevention_System.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\icons\app_icon.ico"; DestDir: "{app}\assets\icons"; Flags: ignoreversion
Source: "assets\themes\cyber.qss"; DestDir: "{app}\assets\themes"; Flags: ignoreversion

[Icons]
Name: "{group}\AI-Driven Cyber Threat Prevention System"; Filename: "{app}\AI-Driven_Cyber_Threat_Prevention_System.exe"
Name: "{commondesktop}\AI-Driven Cyber Threat Prevention System"; Filename: "{app}\AI-Driven_Cyber_Threat_Prevention_System.exe"

[Run]
Filename: "{app}\AI-Driven_Cyber_Threat_Prevention_System.exe"; Description: "Launch application"; Flags: nowait postinstall skipifsilent
