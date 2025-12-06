# Elastic Lucene Detection Rules for Sysmon & Windows Events
*Полный перевод правил из MITRE_ATTACK_Keywords.md в формат Elastic Lucene*

---

## 📊 Структура индексов и полей

### Индексы Elastic для Windows мониторинга:
```
logs-windows.sysmon_operational-*          # Sysmon события
logs-windows.powershell_operational-*      # PowerShell события
logs-windows.security-*                    # Windows Security события
logs-windows.application-*                 # Application события
logs-system.auth-*                         # Аутентификация
logs-endpoint.events.*                     # Endpoint события
```

### Ключевые поля для запросов:
```json
{
  "process.name": "Имя процесса",
  "process.command_line": "Командная строка",
  "process.parent.name": "Родительский процесс",
  "process.executable": "Полный путь к исполняемому файлу",
  "file.path": "Путь к файлу",
  "file.name": "Имя файла",
  "registry.path": "Путь в реестре",
  "registry.value": "Значение реестра",
  "dns.question.name": "DNS запрос",
  "destination.ip": "IP назначения",
  "destination.port": "Порт назначения",
  "event.code": "Код события (Sysmon: 1,3,7,8,10,11,13,22)",
  "winlog.event_data": "Данные Windows событий"
}
```

---

## 🎯 Ключ к событиям Sysmon:
```
1  = Process Create (Создание процесса)
2  = File creation time changed (Изменение времени создания файла)
3  = Network connection (Сетевое соединение)
5  = Process terminated (Завершение процесса)
6  = Driver loaded (Загрузка драйвера)
7  = Image loaded (Загрузка образа DLL)
8  = CreateRemoteThread (Создание удаленного потока)
10 = ProcessAccess (Доступ к процессу)
11 = FileCreate (Создание файла)
12 = RegistryEvent (Событие реестра)
13 = RegistryEvent (Изменение реестра)
15 = FileCreateStreamHash (Создание ADS)
17 = PipeEvent (Событие именованного канала)
22 = DNS query (DNS запрос)
```

---

## 📁 COLLECTION (Сбор информации)

### 📧 Email Collection via COM
```lucene
(event.dataset: "windows.sysmon_operational" AND event.code: "1") AND (
  (
    process.name: ("rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "regsvr32.exe", "cscript.exe", "wscript.exe") AND
    (process.code_signature.trusted: false OR NOT process.code_signature.exists: true)
  ) OR
  (process.name: "OUTLOOK.EXE" AND NOT process.parent.name: "explorer.exe")
)
```

### 📧 PowerShell Exchange Mailbox Access
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") AND 
process.command_line: ("*MailboxExportRequest*", "*-Mailbox*-ContentFilter*")
```

### 📧 Mailbox Export via PowerShell Script
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: "*New-MailboxExportRequest*"
```

### 🎤 Audio Capture via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*Get-MicrophoneAudio*", "*WindowsAudioDevice*", "*waveInGetNumDevs*", "*mciSendStringA*") AND
NOT script_block_text: ("*sentinelbreakpoints*", "*Set-PSBreakpoint*") AND
NOT user.id: "S-1-5-18"
```

### 📋 Clipboard Capture via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
(
  (script_block_text: ("*Windows.Clipboard*", "*Windows.Forms.Clipboard*") AND script_block_text: ("*GetText*", "*Paste()*")) OR
  script_block_text: "*Get-Clipboard*"
) AND
NOT script_block_text: ("*sentinelbreakpoints*", "*Set-PSBreakpoint*") AND
NOT user.id: "S-1-5-18" AND
NOT (file.path: "*\\WindowsPowerShell\\Modules\\*.ps1" AND file.name: ("Convert-ExcelRangeToImage.ps1", "Read-Clipboard.ps1"))
```

### ⌨️ Keylogger via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
(
  script_block_text: ("*GetAsyncKeyState*", "*NtUserGetAsyncKeyState*", "*GetKeyboardState*", "*Get-Keystrokes*") OR
  (script_block_text: ("*SetWindowsHook*", "*SetWindowsHookEx*") AND script_block_text: ("*GetForegroundWindow*", "*GetWindowText*", "*WM_KEYBOARD_LL*"))
) AND
NOT user.id: "S-1-5-18" AND
NOT script_block_text: ("*sentinelbreakpoints*", "*Set-PSBreakpoint*")
```

### 📧 PowerShell Mailbox Access
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
(
  (
    script_block_text: ("*Microsoft.Office.Interop.Outlook*", "*Interop.Outlook.olDefaultFolders*", "*olFolderInBox*", "*Outlook.Application*") AND
    script_block_text: ("*MAPI*", "*GetDefaultFolder*", "*GetNamespace*", "*Session*", "*GetSharedDefaultFolder*")
  ) OR
  (
    script_block_text: ("*Microsoft.Exchange.WebServices.Data.Folder*", "*Microsoft.Exchange.WebServices.Data.FileAttachment*", "*Microsoft.Exchange.WebServices.Data.ExchangeService*") AND
    script_block_text: ("*FindItems*", "*Bind*", "*WellKnownFolderName*", "*FolderId*", "*ItemView*", "*PropertySet*", "*SearchFilter*", "*Attachments*")
  )
)
```

### 🖥️ Screen Capture via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*CopyFromScreen*", "*System.Drawing.Bitmap*", "*Drawing.Bitmap*") AND
NOT user.id: "S-1-5-18"
```

### 📷 Webcam Capture via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*NewFrameEventHandler*", "*VideoCaptureDevice*", "*DirectX.Capture.Filters*", "*VideoCompressors*", "*Start-WebcamRecorder*", "*capCreateCaptureWindow*", "*avicap32.dll*")
```

### 🔐 WinRAR/RAR/7-Zip with Password
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  (
    (process.name: ("rar.exe", "WinRAR.exe") OR process.code_signature.subject_name: "win.rar GmbH" OR process.pe.original_file_name: "WinRAR.exe") AND
    process.args: "a" AND process.command_line: ("*-hp*", "*-p*", "*/hp*", "*/p*")
  ) OR
  (
    (process.name: ("7z.exe", "7za.exe") OR process.pe.original_file_name: ("7z.exe", "7za.exe")) AND
    process.args: "a" AND process.command_line: "*-p*"
  )
) AND
NOT process.parent.executable: ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe", "*\\ManageEngine\\*\\jre\\bin\\java.exe", "*\\Nox\\bin\\Nox.exe")
```

---

## 🌐 COMMAND & CONTROL

### 🔄 CertReq C2 with POST
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "CertReq.exe" OR process.pe.original_file_name: "CertReq.exe") AND
process.command_line: "*-Post*"
```

### 🤖 LLM API C2 Communication
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
(
  process.name: ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe", "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe", "node.exe", "javaw.exe", "java.exe") OR
  process.code_signature.subject_name: ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") OR
  (process.executable: ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") AND (process.code_signature.trusted: false OR NOT process.code_signature.exists: true))
) AND
dns.question.name: (
  "api.openai.com", "*.openai.azure.com", "api.anthropic.com", "api.mistral.ai", "api.cohere.ai", "api.ai21.com", "api.groq.com", "api.perplexity.ai",
  "api.x.ai", "api.deepseek.com", "api.gemini.google.com", "generativelanguage.googleapis.com", "api.azure.com", "api.bedrock.aws", "bedrock-runtime.amazonaws.com",
  "api-inference.huggingface.co", "inference-endpoint.huggingface.cloud", "*.hf.space", "*.replicate.com", "api.replicate.com", "api.runpod.ai", "*.runpod.io",
  "chat.openai.com", "chatgpt.com", "copilot.microsoft.com", "bard.google.com", "gemini.google.com", "claude.ai", "perplexity.ai", "poe.com"
) AND
NOT process.executable: (
  "?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe", "?:\\Windows\\System32\\svchost.exe", "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
  "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe", "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
  "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe", "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe"
) AND
NOT (process.code_signature.trusted: true AND process.code_signature.subject_name: ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc."))
```

### 🌍 Common C2 Web Services
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
dns.question.name: * AND process.name: * AND
NOT user.id: ("S-1-5-18", "S-1-5-19", "S-1-5-20") AND
NOT user.domain: "NT AUTHORITY" AND
dns.question.name: (
  "raw.githubusercontent.*", "pastebin.*", "paste4btc.com", "paste.ee", "ghostbin.com", "drive.google.com", "*.docs.live.net",
  "api.dropboxapi.*", "content.dropboxapi.*", "dl.dropboxusercontent.*", "api.onedrive.com", "*.onedrive.org", "onedrive.live.com",
  "filebin.net", "*.ngrok.io", "ngrok.com", "*.portmap.*", "*serveo.net", "*localtunnel.me", "*pagekite.me", "*localxpose.io",
  "notabug.org", "rawcdn.githack.*", "paste.nrecom.net", "zerobin.net", "controlc.com", "requestbin.net", "slack.com", "api.slack.com",
  "slack-redir.net", "slack-files.com", "cdn.discordapp.com", "discordapp.com", "discord.com", "apis.azureedge.net", "cdn.sql.gg",
  "*.top4top.io", "top4top.io", "www.uplooder.net", "*.cdnmegafiles.com", "transfer.sh", "gofile.io", "updates.peer2profit.com",
  "api.telegram.org", "t.me", "meacz.gq", "rwrd.org", "*.publicvm.com", "*.blogspot.com", "api.mylnikov.org", "file.io",
  "stackoverflow.com", "*files.1drv.com", "api.anonfile.com", "*hosting-profi.de", "ipbase.com", "ipfs.io", "*up.freeo*.space",
  "script.google.com", "script.googleusercontent.com", "api.notion.com", "graph.microsoft.com", "*.sharepoint.com", "mbasic.facebook.com",
  "login.live.com", "api.gofile.io", "api.anonfiles.com", "api.trello.com", "gist.githubusercontent.com", "files.pythonhosted.org",
  "g.live.com", "*.zulipchat.com", "webhook.site", "run.mocky.io", "mockbin.org", "www.googleapis.com", "googleapis.com",
  "global.rel.tunnels.api.visualstudio.com", "*.devtunnels.ms", "api.github.com"
) AND
NOT process.executable: (
  "?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe", "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
  "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe", "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
  "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
  "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe", "?:\\Users\\*\\AppData\\Local\\PowerToys\\PowerToys.exe",
  "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe", "?:\\Users\\*\\AppData\\Local\\Zen Browser\\zen.exe",
  "?:\\Users\\*\\Wavesor Software\\WaveBrowser\\wavebrowser.exe", "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
  "?:\\Windows\\system32\\mobsync.exe", "?:\\Windows\\SysWOW64\\mobsync.exe", "?:\\Windows\\system32\\svchost.exe",
  "?:\\Windows\\System32\\smartscreen.exe", "?:\\Windows\\System32\\wsl.exe", "?:\\Windows\\System32\\WWAHost.exe"
)
```

### 🎯 Suspicious TLDs for C2
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
(
  process.name: ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
                "bitsadmin.exe", "InstallUtil.exe", "python.exe", "regsvr32.exe", "dllhost.exe", "node.exe",
                "java.exe", "javaw.exe", "*.pif", "*.com", "*.scr") OR
  (process.code_signature.trusted: false OR NOT process.code_signature.exists: true) OR
  process.code_signature.subject_name: ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") OR
  process.executable: ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe")
) AND
dns.question.name: /.*\.(top|buzz|xyz|rest|ml|cf|gq|ga|onion|monster|cyou|quest|cc|bar|cfd|click|cam|surf|tk|shop|club|icu|pw|ws|online|fun|life|boats|store|hair|skin|motorcycles|christmas|lol|makeup|mom|bond|beauty|biz|live|work|zip|country|accountant|date|party|science|loan|win|men|faith|review|racing|download|host)/
```

### 🔍 DNS Tunneling via nslookup
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "nslookup.exe" AND 
process.command_line: ("*-querytype=*", "*-qt=*", "*-q=*", "*-type=*")
```

### 🛡️ Free SSL Certificate Requests
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
dns.question.name: ("*letsencrypt.org", "*.sslforfree.com", "*.zerossl.com", "*.freessl.org") AND
process.executable: (
  "C:\\Windows\\System32\\*.exe", "C:\\Windows\\System\\*.exe", "C:\\Windows\\SysWOW64\\*.exe",
  "C:\\Windows\\Microsoft.NET\\Framework*\\*.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\notepad.exe"
) AND
NOT process.name: ("svchost.exe", "MicrosoftEdge*.exe", "msedge.exe")
```

### 🚀 Headless Browser C2
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe") AND
process.command_line: ("*--headless*", "*--disable-gpu*", "*--dump-dom*", "*http*", "*data:text/html*") AND
process.parent.name: (
  "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "conhost.exe", "msiexec.exe",
  "explorer.exe", "rundll32.exe", "winword.exe", "excel.exe", "onenote.exe", "hh.exe", "powerpnt.exe", "forfiles.exe"
) AND
NOT process.executable: ("*\\inetpub\\wwwroot\\*\\ext\\modules\\html2pdf\\bin\\chrome\\*\\chrome-win64\\chrome.exe")
```

### 🔄 IE via COM C2
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
process.name: "iexplore.exe" AND
process.parent.args: "-Embedding" AND
NOT dns.question.name: (
  "*.microsoft.com", "*.digicert.com", "*.msocsp.com", "*.windowsupdate.com", "*.bing.com",
  "*.identrust.com", "*.sharepoint.com", "*.office365.com", "*.office.com"
)
```

### 📥 BITS Transfer for C2
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "2" AND 
process.name: "svchost.exe" AND 
file.name: "BIT*.tmp" AND 
(file.extension: ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") OR
 file.header_bytes: "4d5a*") AND
NOT file.path: ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\*", "?:\\ProgramData\\*\\*") AND
NOT file.name.length > 30
```

### 🐀 Common RAT Software Execution
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  process.code_signature.subject_name: (
    "Action1 Corporation", "AeroAdmin LLC", "Ammyy LLC", "Atera Networks Ltd", "AWERAY PTE. LTD.",
    "BeamYourScreen GmbH", "Bomgar Corporation", "DUC FABULOUS CO.,LTD", "DOMOTZ INC.", "DWSNET OÜ",
    "FleetDeck Inc", "GlavSoft LLC", "Hefei Pingbo Network Technology Co. Ltd", "IDrive, Inc.",
    "IMPERO SOLUTIONS LIMITED", "Instant Housecall", "ISL Online Ltd.", "LogMeIn, Inc.", "Monitoring Client",
    "MMSOFT Design Ltd.", "Nanosystems S.r.l.", "NetSupport Ltd", "NinjaRMM, LLC", "Parallels International GmbH",
    "philandro Software GmbH", "Pro Softnet Corporation", "RealVNC", "RealVNC Limited", "BreakingSecurity.net",
    "Remote Utilities LLC", "Rocket Software, Inc.", "SAFIB", "Servably, Inc.", "ShowMyPC INC",
    "Splashtop Inc.", "Superops Inc.", "TeamViewer", "TeamViewer Germany GmbH", "Techinline Limited",
    "uvnc bvba", "Yakhnovets Denis Aleksandrovich IP", "Zhou Huabing"
  ) OR
  process.name: (
    "AA_v*.exe", "AeroAdmin.exe", "AnyDesk.exe", "apc_Admin.exe", "apc_host.exe", "AteraAgent.exe",
    "aweray_remote*.exe", "AweSun.exe", "B4-Service.exe", "BASupSrvc.exe", "bomgar-scc.exe",
    "domotzagent.exe", "domotz-windows-x64-10.exe", "dwagsvc.exe", "DWRCC.exe", "ImperoClientSVC.exe",
    "ImperoServerSVC.exe", "ISLLight.exe", "ISLLightClient.exe", "fleetdeck_commander*.exe",
    "getscreen.exe", "LMIIgnition.exe", "LogMeIn.exe", "ManageEngine_Remote_Access_Plus.exe",
    "Mikogo-Service.exe", "NinjaRMMAgent.exe", "NinjaRMMAgenPatcher.exe", "ninjarmm-cli.exe",
    "r_server.exe", "radmin.exe", "radmin3.exe", "RCClient.exe", "RCService.exe",
    "RemoteDesktopManager.exe", "RemotePC.exe", "RemotePCDesktop.exe", "RemotePCService.exe",
    "rfusclient.exe", "ROMServer.exe", "ROMViewer.exe", "RPCSuite.exe", "rserver3.exe",
    "rustdesk.exe", "rutserv.exe", "rutview.exe", "saazapsc.exe", "ScreenConnect*.exe",
    "smpcview.exe", "spclink.exe", "Splashtop-streamer.exe", "SRService.exe", "strwinclt.exe",
    "Supremo.exe", "SupremoService.exe", "teamviewer.exe", "TiClientCore.exe", "TSClient.exe",
    "tvn.exe", "tvnserver.exe", "tvnviewer.exe", "UltraVNC*.exe", "UltraViewer*.exe",
    "vncserver.exe", "vncviewer.exe", "winvnc.exe", "winwvc.exe", "Zaservice.exe", "ZohoURS.exe"
  )
) AND
NOT (process.pe.original_file_name: ("G2M.exe", "Updater.exe", "powershell.exe") AND process.code_signature.subject_name: "LogMeIn, Inc.")
```

### 🏠 Outlook Home Page Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "URL" AND
registry.path: ("*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\*", "*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Today\\*") AND
registry.data.strings: ("*://*", "*:\\*")
```

### 🔄 Port Forwarding Registry Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.path: "*\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*" AND
registry.data.strings: *
```

### 🔗 RDP Tunneling via plink
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.command_line: "*:3389" AND
process.command_line: ("*-L*", "*-P*", "*-R*", "*-pw*", "*-ssh*")
```

### 🎭 Remcos RAT Indicators
```lucene
(event.dataset: "windows.sysmon_operational" AND (
  (event.code: "11" AND file.path: "C:\\Users\\*\\AppData\\Local\\Temp\\TH????.tmp") OR
  (event.code: "11" AND file.path: "?:\\Users\\*\\AppData\\Roaming\\remcos\\logs.dat") OR
  (event.code: "13" AND registry.value: ("Remcos", "Rmc-??????", "licence") AND registry.path: (
      "*\\Windows\\CurrentVersion\\Run\\Remcos", "*\\Windows\\CurrentVersion\\Run\\Rmc-??????",
      "*\\SOFTWARE\\Remcos-*\\licence", "*\\Software\\Rmc-??????\\licence"
  ))
))
```

### 📥 desktopimgdownldr File Download
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "desktopimgdownldr.exe" OR process.pe.original_file_name: "desktopimgdownldr.exe") AND
process.command_line: "*/lockscreenurl:http*"
```

### 📥 MpCmdRun File Download
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "MpCmdRun.exe" OR process.pe.original_file_name: "MpCmdRun.exe") AND
process.command_line: ("*-DownloadFile*", "*-url*", "*-path*")
```

### ⚡ PowerShell File Download
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "22" AND 
process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") AND
NOT dns.question.name: (
  "*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com", "*.windowsupdate.com",
  "metadata.google.internal", "dist.nuget.org", "artifacts.elastic.co", "*.digicert.com",
  "*.chocolatey.org", "outlook.office365.com", "cdn.oneget.org", "ci.dot.net",
  "packages.icinga.com", "login.microsoftonline.com", "*.gov", "*.azure.com", "*.python.org",
  "dl.google.com", "sensor.cloud.tenable.com", "*.azurefd.net", "*.office.net", "*.anac*",
  "aka.ms", "dot.net", "*.visualstudio.com", "*.local"
) AND
NOT user.id: "S-1-5-18" AND
dns.question.name: /.*\.[a-zA-Z]{2,5}/
```

### 📜 Script File Download
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: ("wscript.exe", "cscript.exe") AND
network.direction: ("outgoing", "egress") AND
destination.ip != "127.0.0.1"
```

### 🛠️ NetSupport Suspicious Path
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "client32.exe" OR process.pe.original_file_name: "client32.exe" OR process.parent.name: "client32.exe") AND
(
  process.executable: ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") OR
  process.parent.executable: ("?:\\Users\\*\\client32.exe", "?:\\ProgramData\\*\\client32.exe")
)
```

### 🖥️ ScreenConnect Child Processes
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: (
  "ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe",
  "ScreenConnect.WindowsBackstageShell.exe", "ScreenConnect.WindowsFileManager.exe"
) AND
(
  (process.name: "powershell.exe" AND process.command_line: ("*-enc*", "*-ec*", "*downloadstring*", "*Reflection.Assembly*", "*http*")) OR
  (process.name: "cmd.exe" AND process.command_line: "*/c*") OR
  (process.name: "net.exe" AND process.command_line: "*/add*") OR
  (process.name: "schtasks.exe" AND process.command_line: ("*/create*", "*-create*")) OR
  (process.name: "sc.exe" AND process.command_line: "*create*") OR
  (process.name: "rundll32.exe" AND NOT process.command_line: "*url.dll,FileProtocolHandler*") OR
  (process.name: "msiexec.exe" AND process.command_line: ("*/i*", "*-i*", "*/q*", "*/quiet*", "*/qn*")) OR
  process.name: ("mshta.exe", "certutil.exe", "bitsadmin.exe", "certreq.exe", "wscript.exe", "cscript.exe",
                "curl.exe", "ssh.exe", "scp.exe", "wevtutil.exe", "wget.exe", "wmic.exe")
)
```

### ☀️ Sunburst C2 Activity
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: (
  "ConfigurationWizard.exe", "NetFlowService.exe", "NetflowDatabaseMaintenance.exe",
  "SolarWinds.Administration.exe", "SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe",
  "SolarWinds.Collector.Service.exe", "SolarwindsDiagnostics.exe"
) AND
(
  (http.request.body: "*/swip/Upload.ashx*" AND http.request.method: ("POST", "PUT")) OR
  (http.request.body: ("*/swip/SystemDescription*", "*/swip/Events*") AND http.request.method: ("GET", "HEAD"))
) AND
NOT http.request.body: "*solarwinds.com*"
```

### 📁 TeamViewer File Creation
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
process.name: "TeamViewer.exe" AND
file.extension: ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta") AND
NOT (
  file.path: (
    "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*.js",
    "?:\\Users\\*\\AppData\\Local\\Temp\\TeamViewer\\update.exe",
    "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer_Resource_??.dll"
  ) AND process.code_signature.trusted: true
)
```

### ⚡ Curl Tool Transfer
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.executable: ("?:\\Windows\\System32\\curl.exe", "?:\\Windows\\SysWOW64\\curl.exe") AND
process.command_line: "*http*" AND
process.parent.name: (
  "cmd.exe", "powershell.exe", "rundll32.exe", "explorer.exe", "conhost.exe", "forfiles.exe",
  "wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "mmc.exe"
) AND
NOT user.id: "S-1-5-18"
```

### 🔄 VSCode Tunneling
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.command_line: "*tunnel*" AND
(process.command_line: "*--accept-server-license-terms*" OR process.name: "code*.exe") AND
NOT (process.name: "code-tunnel.exe" AND process.command_line: "*status*" AND process.parent.name: "Code.exe")
```

---

## 🔐 CREDENTIAL ACCESS

### 🎯 ADIDNS Wildcard Record Creation
```lucene
event.dataset: "windows.security" AND 
event.code: "5137" AND 
winlog.event_data.ObjectDN: "DC=*"
```

### 🎯 WPAD Record Creation
```lucene
event.dataset: "windows.security" AND 
event.code: "5137" AND 
winlog.event_data.ObjectDN: "DC=wpad*"
```

### 💥 Brute Force Admin Account
```lucene
event.dataset: "windows.security" AND 
event.code: "4625" AND 
winlog.logon.type: "3" AND 
user.name: "*admin*" AND
source.ip != "127.0.0.1" AND source.ip != "::1" AND
NOT winlog.event_data.Status: ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")
```

### 💥 Multiple Logon Failures Followed by Success
```lucene
event.dataset: "windows.security" AND 
(
  (event.code: "4625" AND winlog.logon.type: "3" AND source.ip != "127.0.0.1" AND NOT user.name: ("ANONYMOUS LOGON", "-", "*$")) OR
  (event.code: "4624" AND winlog.logon.type: "3" AND source.ip != "127.0.0.1" AND NOT user.name: ("ANONYMOUS LOGON", "-", "*$"))
)
```

### 🗂️ Credential Dumping Tools
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  ((process.name: "procdump.exe" OR process.pe.original_file_name: "procdump") AND process.command_line: "*-ma*") OR
  (process.name: "ProcessDump.exe" AND NOT process.parent.executable: "*Cisco Systems*") OR
  (process.name: "WriteMiniDump.exe" AND NOT process.parent.executable: "*Steam*") OR
  (process.name: "rundll32.exe" AND process.command_line: ("*MiniDump*", "*comsvcs*#*24*")) OR
  (process.name: "RdrLeakDiag.exe" AND process.command_line: "*/fullmemdmp*") OR
  (process.name: "SqlDumper.exe" AND process.command_line: "*0x01100*") OR
  (process.name: "TTTracer.exe" AND process.command_line: ("*-dumpFull*", "*-attach*")) OR
  (process.name: "ntdsutil.exe" AND process.command_line: "*cr*fu*") OR
  (process.name: "diskshadow.exe" AND process.command_line: "*/s*")
)
```

### 📁 NTDS/SAM Copy via Volume Shadow
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  ((process.name: ("cmd.exe", "powershell.exe", "xcopy.exe") OR process.pe.original_file_name: ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE")) AND
   process.command_line: ("*copy*", "*xcopy*", "*Copy-Item*", "*move*", "*cp*", "*mv*")) OR
  ((process.name: "esentutl.exe" OR process.pe.original_file_name: "esentutl.exe") AND process.command_line: ("*/y*", "*/vss*", "*/d*"))
) AND
process.command_line: ("*\\ntds.dit*", "*\\config\\SAM*", "*\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*", "*/system32/config/SAM*")
```

### 🔄 DCSync Replication Rights
```lucene
event.dataset: "windows.security" AND 
event.code: "4662" AND 
winlog.event_data.Properties: ("*DS-Replication-Get-Changes*", "*DS-Replication-Get-Changes-All*", "*DS-Replication-Get-Changes-In-Filtered-Set*") AND
winlog.event_data.AccessMask: "0x100" AND
NOT winlog.event_data.SubjectUserName: ("*$", "MSOL_*")
```

### 🚫 Disable Kerberos Preauth
```lucene
event.dataset: "windows.security" AND 
event.code: "4738" AND 
winlog.event_data.NewUACList: "USER_DONT_REQUIRE_PREAUTH"
```

### 🏷️ DNS Node Creation
```lucene
event.dataset: "windows.security" AND 
event.code: "5137" AND 
winlog.event_data.ObjectClass: "dnsNode" AND
NOT winlog.event_data.SubjectUserName: "*$"
```

### 💾 DPAPI Private Keys Backup
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.name: ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```

### 🗃️ Registry Hive Dumping
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "reg.exe" OR process.pe.original_file_name: "reg.exe") AND
process.command_line: ("*save*", "*export*") AND
process.command_line: ("*hklm\\sam*", "*hklm\\security*")
```

### 🗂️ IIS Connection Strings Dumping
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "aspnet_regiis.exe" OR process.pe.original_file_name: "aspnet_regiis.exe") AND
process.command_line: ("*connectionStrings*", "*-pdf*")
```

### 🏷️ Kerberoasting Detection
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
destination.port: "88" AND
source.port >= 49152 AND
process.pid != 4 AND
destination.ip != "127.0.0.1" AND destination.ip != "::1" AND
NOT process.executable: (
  "*\\Program Files*\\*.exe", "*\\Program Files (x86)\\*.exe", "*\\Windows\\System32\\lsass.exe",
  "*\\Windows\\System32\\svchost.exe", "*\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
)
```

### 🎭 Mimikatz PowerShell Module
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*sekurlsa::logonpasswords*", "*crypto::certificates*", "*CERT_SYSTEM_STORE_LOCAL_MACHINE*")
```

### 🔧 WDigest Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "UseLogonCredential" AND
registry.path: "*\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" AND
registry.data.strings: ("1", "0x00000001") AND
NOT (process.executable: "*\\Windows\\System32\\svchost.exe" AND user.id: "S-1-5-18")
```

### 🔗 Network Provider Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "ProviderPath" AND
registry.path: "*\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath" AND
registry.data.strings: * AND
NOT registry.data.strings: (
  "%SystemRoot%\\System32\\ntlanman.dll", "%SystemRoot%\\System32\\drprov.dll",
  "%SystemRoot%\\System32\\davclnt.dll", "%SystemRoot%\\System32\\vmhgfs.dll"
)
```

### 📜 PowerShell NinjaCopy
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*StealthReadFile*", "*StealthOpenFile*", "*StealthCloseFile*", "*Invoke-NinjaCopy*") AND
NOT user.id: "S-1-5-18"
```

### 🎫 PowerShell Kerberos Ticket Dump
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: "*LsaCallAuthenticationPackage*" AND
script_block_text: ("*KerbRetrieveEncodedTicketMessage*", "*KerbQueryTicketCacheMessage*", "*KerbRetrieveTicketMessage*")
```

### 🗂️ PowerShell MiniDump
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*MiniDumpWriteDump*", "*MiniDumpWithFullMemory*", "*pmuDetirWpmuDiniM*") AND
NOT user.id: "S-1-5-18"
```

### 🔄 NTLM Relay Tools
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*NTLMSSPNegotiate*", "*4E544C4D53535000*", "*0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50*") AND
NOT file.directory: "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Downloads"
```

### 🎫 PowerShell Request Ticket
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: "*KerberosRequestorSecurityToken*" AND
NOT user.id: ("S-1-5-18", "S-1-5-20")
```

### 💾 Veeam SQL Credential Access
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*[dbo].[Credentials]*", "*Veeam*", "*VeeamBackup*", "*ProtectedStorage]::GetLocalString*")
```

### 📊 Remote SAM Secrets Dump
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
process.name: "svchost.exe" AND
file.header_bytes: "72656766*" AND
file.size >= 30000 AND
user.id: ("S-1-5-21-*", "S-1-12-1-*") AND
file.path: ("?:\\Windows\\system32\\*.tmp", "?:\\WINDOWS\\Temp\\*.tmp")
```

### 🔐 Vault Credential Access
```lucene
event.dataset: "windows.security" AND 
event.code: "5382" AND 
winlog.event_data.SchemaFriendlyName: "Windows Web Password Credential" AND
winlog.event_data.Resource: "http*" AND
NOT winlog.event_data.Resource: "http://localhost/"
```

### 🛡️ SeEnableDelegationPrivilege Assignment
```lucene
event.dataset: "windows.security" AND 
event.code: "4704" AND 
winlog.event_data.PrivilegeList: "*SeEnableDelegationPrivilege*"
```

### 🔑 Shadow Credentials
```lucene
event.dataset: "windows.security" AND 
event.code: "5136" AND 
winlog.event_data.AttributeLDAPDisplayName: "msDS-KeyCredentialLink" AND
winlog.event_data.AttributeValue: "B:828*" AND
NOT winlog.event_data.SubjectUserName: "MSOL_*"
```

### 🏷️ SPN Attribute Modified
```lucene
event.dataset: "windows.security" AND 
event.code: "5136" AND 
winlog.event_data.OperationType: "%%14674" AND
winlog.event_data.ObjectClass: "user" AND
winlog.event_data.AttributeLDAPDisplayName: "servicePrincipalName"
```

### 🗂️ Suspicious LSASS Access
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "10" AND 
TargetImage: "*\\lsass.exe" AND
NOT GrantedAccess: ("0x1000", "0x1400", "0x101400", "0x101000", "0x3200") AND
NOT process.name: ("procexp64.exe", "procmon.exe", "procexp.exe") AND
NOT process.executable: (
  "*\\ProgramData\\Microsoft\\Windows Defender\\platform\\*",
  "*\\Program Files*\\*",
  "*\\Windows\\CCM\\CcmExec.exe",
  "*\\Windows\\Sysmon*.exe"
)
```

### 🔐 SeBackupPrivilege Access to Registry
```lucene
event.dataset: "windows.security" AND 
(
  (event.code: "4672" AND winlog.event_data.PrivilegeList: "*SeBackupPrivilege*" AND NOT winlog.event_data.PrivilegeList: "*SeDebugPrivilege*") OR
  (event.code: "5145" AND winlog.event_data.RelativeTargetName: "*winreg*")
)
```

### 💾 Veeam DLL Load
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
(file.name: "Veeam.Backup.Common.dll" OR file.pe.original_file_name: "Veeam.Backup.Common.dll") AND
(process.code_signature.trusted: false OR NOT process.code_signature.exists: true OR process.name: ("powershell.exe", "pwsh.exe"))
```

### 💾 Veeam SQL Commands
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  (process.name: "sqlcmd.exe" OR process.pe.original_file_name: "sqlcmd.exe") OR
  process.command_line: ("*Invoke-Sqlcmd*", "*Invoke-SqlExecute*", "*Invoke-DbaQuery*")
) AND
process.command_line: "*[VeeamBackup].[dbo].[Credentials]*"
```

### 📊 wbadmin NTDS Backup
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "wbadmin.exe" OR process.pe.original_file_name: "wbadmin.exe") AND
process.command_line: ("*recovery*", "*ntds.dit*")
```

### 🌐 Web Config File Access
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "10" AND 
file.name: "web.config" AND
file.path: "*VirtualDirectories*"
```

### 📡 Wireless Credentials Dumping
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "netsh.exe" OR process.pe.original_file_name: "netsh.exe") AND
process.command_line: ("*wlan*", "*key*clear*")
```

---

## 🛡️ DEFENSE EVASION

### 🎭 Hidden File Attribute via attrib.exe
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "attrib.exe" OR process.pe.original_file_name: "ATTRIB.EXE") AND
process.command_line: "*+h*" AND
NOT (process.parent.name: "cmd.exe" AND process.command_line: "*attrib  +R +H +S +A *.cui*")
```

### 🚫 AMSI Bypass via DLL Hijack
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.name: ("amsi.dll", "amsi") AND
NOT file.path: (
  "*\\Windows\\system32\\amsi.dll", "*\\Windows\\Syswow64\\amsi.dll", "*\\Windows\\WinSxS\\*\\amsi.dll",
  "*\\$SysReset\\CloudImage\\Package_for_RollupFix*\\amsi.dll", "*\\$WINDOWS.~BT\\*\\amsi.dll",
  "*\\Windows\\SoftwareDistribution\\Download\\*", "*\\Windows\\servicing\\*\\amsi.dll"
)
```

### 🚫 AMSI Bypass via PowerShell
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
(
  script_block_text: (
    "*System.Management.Automation.AmsiUtils*", "*amsiInitFailed*", "*Invoke-AmsiBypass*",
    "*Bypass.AMSI*", "*amsi.dll*", "*AntimalwareProvider*", "*amsiSession*", "*amsiContext*",
    "*AmsiInitialize*", "*unloadobfuscated*", "*unloadsilent*", "*AmsiX64*", "*AmsiX32*",
    "*FindAmsiFun*", "*AllocHGlobal((9076*", "*[cHAr](65)+[cHaR]([byTe]0x6d)*"
  ) OR
  (script_block_text: "*[Ref].Assembly.GetType(('System.Management.Automation*" AND script_block_text: "*.SetValue(*") OR
  (script_block_text: "*::AllocHGlobal(*" AND script_block_text: "*.SetValue(*" AND script_block_text: "*-replace*" AND script_block_text: "*.NoRMALiZe(*")
) AND
NOT script_block_text: ("*sentinelbreakpoints*", "*Set-PSBreakpoint*")
```

### 🔧 AMSI Registry Disable
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "AmsiEnable" AND
registry.data.strings: ("0", "0x00000000")
```

### 🚫 Audit Policy Disabled
```lucene
event.dataset: "windows.security" AND 
event.code: "4719" AND 
winlog.event_data.AuditPolicyChangesDescription: "Success removed" AND
winlog.event_data.SubCategory: ("Logon", "Audit Policy Change", "Process Creation", "Audit Other System Events")
```

### 🧹 Clearing Console History
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") OR process.pe.original_file_name: ("PowerShell.EXE", "pwsh.dll")) AND
process.command_line: ("*Clear-History*", "*Remove-Item*ConsoleHost_history.txt*", "*Set-PSReadlineOption*SaveNothing*")
```

### 🧹 Clearing Event Logs
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  ((process.name: "wevtutil.exe" OR process.pe.original_file_name: "wevtutil.exe") AND process.command_line: ("*/e:false*", "*cl*", "*clear-log*")) OR
  (process.name: ("powershell.exe", "pwsh.exe") AND process.command_line: "*Clear-EventLog*")
)
```

### 🚫 Code Signing Policy Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "bcdedit.exe" OR process.pe.original_file_name: "bcdedit.exe") AND
process.command_line: ("*-set*", "*/set*") AND
process.command_line: ("*TESTSIGNING*", "*nointegritychecks*", "*DISABLE_INTEGRITY_CHECKS*")
```

### 🚫 Defender Exclusion via PowerShell
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("powershell.exe", "pwsh.exe") AND
process.command_line: ("*Add-MpPreference*", "*Set-MpPreference*") AND
process.command_line: ("*-Exclusion*")
```

### 🗑️ Delete USN Journal with fsutil
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "fsutil.exe" OR process.pe.original_file_name: "fsutil.exe") AND
process.command_line: ("*deletejournal*", "*usn*")
```

### 🚫 Disable NLA
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "UserAuthentication" AND
registry.path: "*\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication" AND
registry.data.strings: ("0", "0x00000000")
```

### 🚫 Disable PowerShell Script Block Logging
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "EnableScriptBlockLogging" AND
registry.data.strings: ("0", "0x00000000") AND
NOT process.executable: ("*\\Windows\\System32\\svchost.exe", "*\\Windows\\System32\\DeviceEnroller.exe")
```

### 🚫 Disable Windows Firewall
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "netsh.exe" AND
process.command_line: ("*firewall*disable*", "*advfirewall*off*state*")
```

### 🚫 Disable Windows Defender via PowerShell
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("powershell.exe", "pwsh.exe") AND
process.command_line: "*Set-MpPreference*" AND
process.command_line: ("*-Disable*", "*NeverSend*", "*-Exclusion*")
```

### 🚫 Disable Windows Logs
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  ((process.name: "logman.exe" OR process.pe.original_file_name: "Logman.exe") AND process.command_line: ("*EventLog-*", "*stop*", "*delete*")) OR
  (process.name: ("powershell.exe", "pwsh.exe") AND process.command_line: "*Set-Service*EventLog*Disabled*") OR
  ((process.name: "auditpol.exe" OR process.pe.original_file_name: "AUDITPOL.EXE") AND process.command_line: "*/success:disable*")
)
```

### 🌐 DNS over HTTPS Enabled
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
(
  (registry.path: "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" AND registry.data.strings: ("1", "0x00000001")) OR
  (registry.path: "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" AND registry.data.strings: "secure") OR
  (registry.path: "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" AND registry.data.strings: ("1", "0x00000001"))
)
```

### ⚡ .NET Compiler from Suspicious Parent
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("csc.exe", "vbc.exe") AND
process.parent.name: ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe")
```

### 🔓 Enable Inbound RDP
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "netsh.exe" OR process.pe.original_file_name: "netsh.exe") AND
process.command_line: ("*localport=3389*", "*RemoteDesktop*", "*group=\"remote desktop\"*") AND
process.command_line: ("*action=allow*", "*enable=Yes*")
```

### 🔍 Enable Network Discovery
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "netsh.exe" AND
process.command_line: ("*firewall*", "*advfirewall*") AND
process.command_line: "*group=Network Discovery*" AND
process.command_line: "*enable=Yes*"
```

### 🖥️ Control Panel with Suspicious Arguments
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "control.exe" AND
process.command_line: ("*.jpg*", "*.png*", "*.gif*", "*.bmp*", "*.inf*", "*.cpl:*/*", "*../../..*", "*/AppData/Local/*")
```

### 🚀 wuauclt LOLBAS Execution
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "wuauclt.exe" OR process.pe.original_file_name: "wuauclt.exe") AND
process.command_line: ("*/RunHandlerComServer*", "*/UpdateDeploymentProvider*") AND
process.command_line: ("C:\\Users\\*.dll", "C:\\ProgramData\\*.dll", "C:\\Windows\\Temp\\*.dll")
```

### ⚡ MSBuild Started by Office
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "MSBuild.exe" AND
process.parent.name: ("eqnedt32.exe", "excel.exe", "msaccess.exe", "outlook.exe", "powerpnt.exe", "winword.exe")
```

### ⚡ MSBuild Started by Script
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "MSBuild.exe" AND
process.parent.name: ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe")
```

### ⚡ MSBuild Started by System Process
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "MSBuild.exe" AND
process.parent.name: ("explorer.exe", "wmiprvse.exe")
```

### 🎭 Renamed MSBuild Execution
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.pe.original_file_name: "MSBuild.exe" AND
NOT process.name: "MSBuild.exe"
```

### 🎭 Suspicious Explorer/WinWord
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: ("WinWord.exe", "EXPLORER.EXE", "w3wp.exe", "DISM.EXE") OR process.pe.original_file_name: ("WinWord.exe", "EXPLORER.EXE")) AND
NOT process.executable: (
  "*\\Program Files\\Microsoft Office\\*\\winword.exe", "*\\Program Files (x86)\\Microsoft Office\\*\\winword.exe",
  "*\\Windows\\explorer.exe", "*\\Windows\\System32\\Dism.exe", "*\\Windows\\System32\\inetsrv\\w3wp.exe"
)
```

### 🛡️ Windows Defender Unusual Path
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  (process.pe.original_file_name: "MsMpEng.exe" AND NOT process.name: "MsMpEng.exe") OR
  (process.name: "MsMpEng.exe" AND NOT process.executable: ("*\\ProgramData\\Microsoft\\Windows Defender\\*.exe", "*\\Program Files\\Windows Defender\\*.exe"))
)
```

### 📁 File with Multiple Extensions
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.name: /.*\.(vbs|vbe|bat|js|cmd|ps1|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso)\.exe$/ AND
NOT process.name: "msiexec.exe"
```

### 🏃 Execution from Unusual Directory
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.executable: (
  "C:\\PerfLogs\\*.exe", "C:\\Users\\Public\\*.exe", "C:\\Windows\\Tasks\\*.exe", "C:\\Intel\\*.exe",
  "C:\\Windows\\AppReadiness\\*.exe", "C:\\Windows\\ServiceState\\*.exe", "C:\\Windows\\security\\*.exe",
  "C:\\Windows\\IdentityCRL\\*.exe", "C:\\Windows\\Branding\\*.exe", "C:\\Windows\\csc\\*.exe",
  "C:\\Windows\\DigitalLocker\\*.exe", "C:\\Windows\\en-US\\*.exe", "C:\\Windows\\wlansvc\\*.exe",
  "C:\\Windows\\Prefetch\\*.exe", "C:\\Windows\\Fonts\\*.exe", "C:\\Windows\\diagnostics\\*.exe",
  "C:\\Windows\\TAPI\\*.exe", "C:\\Windows\\INF\\*.exe", "C:\\windows\\tracing\\*.exe",
  "C:\\windows\\IME\\*.exe", "C:\\Windows\\Performance\\*.exe", "C:\\windows\\intel\\*.exe",
  "C:\\windows\\ms\\*.exe", "C:\\Windows\\dot3svc\\*.exe", "C:\\Windows\\panther\\*.exe",
  "C:\\Windows\\RemotePackages\\*.exe", "C:\\Windows\\OCR\\*.exe", "C:\\Windows\\appcompat\\*.exe",
  "C:\\Windows\\apppatch\\*.exe", "C:\\Windows\\addins\\*.exe", "C:\\Windows\\Setup\\*.exe",
  "C:\\Windows\\Help\\*.exe", "C:\\Windows\\SKB\\*.exe", "C:\\Windows\\Vss\\*.exe",
  "C:\\Windows\\servicing\\*.exe", "C:\\Windows\\CbsTemp\\*.exe", "C:\\Windows\\Logs\\*.exe",
  "C:\\Windows\\WaaS\\*.exe", "C:\\Windows\\ShellExperiences\\*.exe", "C:\\Windows\\ShellComponents\\*.exe",
  "C:\\Windows\\PLA\\*.exe", "C:\\Windows\\Migration\\*.exe", "C:\\Windows\\debug\\*.exe",
  "C:\\Windows\\Cursors\\*.exe", "C:\\Windows\\Containers\\*.exe", "C:\\Windows\\Boot\\*.exe",
  "C:\\Windows\\bcastdvr\\*.exe", "C:\\Windows\\TextInput\\*.exe", "C:\\Windows\\schemas\\*.exe",
  "C:\\Windows\\SchCache\\*.exe", "C:\\Windows\\Resources\\*.exe", "C:\\Windows\\rescache\\*.exe",
  "C:\\Windows\\Provisioning\\*.exe", "C:\\Windows\\PrintDialog\\*.exe", "C:\\Windows\\PolicyDefinitions\\*.exe",
  "C:\\Windows\\media\\*.exe", "C:\\Windows\\Globalization\\*.exe", "C:\\Windows\\L2Schemas\\*.exe",
  "C:\\Windows\\LiveKernelReports\\*.exe", "C:\\Windows\\ModemLogs\\*.exe", "C:\\Windows\\ImmersiveControlPanel\\*.exe"
) AND
NOT process.name: ("SpeechUXWiz.exe", "SystemSettings.exe", "TrustedInstaller.exe", "PrintDialog.exe")
```

### 🔒 Encoded Executable in Registry
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.data.strings: "TVqQAAMAAAAEAAAA*"
```

### ⚡ forfiles Indirect Execution
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "forfiles.exe" OR process.pe.original_file_name: "forfiles.exe") AND
process.command_line: ("*/c*", "*-c*")
```

### 💉 MSBuild Injection
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "8" AND 
process.name: "MSBuild.exe"
```

### ⚡ InstallUtil Beacon
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: "installutil.exe" AND
network.direction: ("outgoing", "egress")
```

### 🎭 Masquerading as Elastic Endpoint
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("esensor.exe", "elastic-endpoint.exe") AND
NOT process.parent.executable: ("*\\Program Files\\Elastic\\*", "*\\Windows\\System32\\services.exe", "*\\Windows\\explorer.exe")
```

### 🎭 Masquerading Business Apps Installer
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.executable: "?:\\Users\\*\\Downloads\\*" AND
(
  (process.name: "*slack*.exe" AND NOT (process.code_signature.subject_name: "Slack Technologies*" AND process.code_signature.trusted: true)) OR
  (process.name: "*webex*.exe" AND NOT (process.code_signature.subject_name: "Cisco*" AND process.code_signature.trusted: true)) OR
  (process.name: "teams*.exe" AND NOT (process.code_signature.subject_name: "Microsoft Corporation" AND process.code_signature.trusted: true)) OR
  (process.name: "*discord*.exe" AND NOT (process.code_signature.subject_name: "Discord Inc." AND process.code_signature.trusted: true)) OR
  (process.name: "*whatsapp*.exe" AND NOT (process.code_signature.subject_name: "WhatsApp*" AND process.code_signature.trusted: true)) OR
  (process.name: "*zoom*.exe" AND NOT (process.code_signature.subject_name: "Zoom Video Communications*" AND process.code_signature.trusted: true))
)
```

### 🎭 Masquerading in Trusted Directory
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.executable: /[A-Z]:\\\*Program\*Files\*\\\.*\.exe/ AND
NOT process.executable: ("*\\Program Files\\*.exe", "*\\Program Files (x86)\\*.exe", "*\\Users\\*.exe", "*\\ProgramData\\*.exe")
```

### ⚡ LOLBIN Connecting to Internet
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: ("expand.exe", "extrac32.exe", "ieexec.exe", "makecab.exe") AND
NOT cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")
```

### 🔧 Modify OS File Ownership
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  (process.name: "icacls.exe" AND process.command_line: "*/reset*") OR
  (process.name: "takeown.exe" AND process.command_line: "*/f*") OR
  (process.name: "icacls.exe" AND process.command_line: "*/grant*Everyone:F*")
) AND
process.command_line: "*C:\\Windows\\*"
```

### 🌐 MSBuild Network Connections
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: "MSBuild.exe" AND
NOT user.id: "S-1-5-18" AND
destination.ip != "127.0.0.1" AND destination.ip != "::1" AND
NOT dns.question.name: ("localhost", "dc.services.visualstudio.com", "api.nuget.org")
```

### 🕸️ MSHTA Beacon
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.name: "mshta.exe" AND
NOT process.parent.name: "Microsoft.ConfigurationManagement.exe"
```

### ⚡ MSHTA Suspicious Child
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: "mshta.exe" AND
(
  process.name: ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "msiexec.exe") OR
  process.executable: "C:\\Users\\*\\*.exe"
)
```

### ⚡ msiexec Child Process Network
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "3" AND 
process.parent.name: "msiexec.exe" AND
process.parent.command_line: "*/v*" AND
NOT process.executable: ("*\\Windows\\System32\\msiexec.exe", "*\\Program Files\\*.exe", "*\\Program Files (x86)\\*.exe")
```

### 🔄 NTLM Downgrade
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "13" AND 
registry.value: "LmCompatibilityLevel" AND
registry.data.strings: ("2", "1", "0", "0x00000002", "0x00000001", "0x00000000")
```

### 🎭 Parent Process PID Spoofing
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.pid > 0 AND
process.parent.executable != null AND
process.name: ("winword.exe", "excel.exe", "outlook.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe") AND
NOT process.executable: ("*\\Windows\\System32\\WerFault*.exe")
```

### 📦 PowerShell Assembly Load
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: ("*[System.Reflection.Assembly]::Load*", "*[Reflection.Assembly]::Load*", "*Assembly.Load(*") AND
NOT user.id: "S-1-5-18"
```

### 🔒 PowerShell Encryption
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: (
  "*Cryptography.AESManaged*", "*Cryptography.RijndaelManaged*", "*Cryptography.SHA*Managed*",
  "*PasswordDeriveBytes*", "*Rfc2898DeriveBytes*", "*CipherMode*", "*PaddingMode*",
  "*.CreateEncryptor*", "*.CreateDecryptor*"
) AND
NOT user.id: "S-1-5-18"
```

### 🎨 PowerShell Obfuscation - Backtick Variables
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: /\$\{(\w++`){2,}\w++\}/ AND
script_block_text.length > 500
```

### 🎨 PowerShell Obfuscation - Environment Variables
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: /(\$(?:\w+|\w+\:\w+)\[\d++\]\+\$(?:\w+|\w+\:\w+)\[\d++\]\+['"]x['"]|\$(?:\w+\:\w+)\[\d++,\d++,\d++\]|\.name\[\d++,\d++,\d++\])/i AND
script_block_text.length > 500
```

### 🎨 PowerShell Obfuscation - Reverse Keywords
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: /(rahc|metsys|stekcos|tcejboimw|ecalper|ecnerferpe|noitcennoc|nioj|eman\.|:vne$|gnirts|tcejbo-wen|_23niw|noisserpxe|ekovni|daolnwod)/i
```

### 💉 PowerShell Process Injection
```lucene
event.dataset: "windows.powershell_operational" AND 
event.code: "4104" AND 
script_block_text: (
  "*VirtualAlloc*", "*VirtualAllocEx*", "*VirtualProtect*", "*LdrLoadDll*", "*LoadLibrary*",
  "*GetProcAddress*", "*OpenProcess*", "*WriteProcessMemory*", "*CreateRemoteThread*",
  "*NtCreateThreadEx*", "*CreateThread*", "*QueueUserAPC*", "*SuspendThread*", "*ResumeThread*"
)
```

### 🗑️ Process Termination Followed by Deletion
```lucene
event.dataset: "windows.sysmon_operational" AND 
(
  (event.code: "5" AND process.code_signature.trusted: false AND NOT process.executable: "*\\Windows\\SoftwareDistribution\\*.exe") OR
  (event.code: "11" AND file.extension: ("exe", "scr", "com") AND event.action: "deletion" AND NOT file.path: "*\\Program Files\\*.exe")
)
```

### 📂 Root Directory ADS Creation
```lucene
event.dataset: "windows.sysmon_operational" AND 
(event.code: "11" OR event.code: "1") AND 
(file.path: /[A-Z]:\\:.+/ OR process.executable: /[A-Z]:\\:.+/)
```

### 🏃 Rundll32 with No Arguments
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "rundll32.exe" AND
process.args_count: 1 AND
NOT process.command_line: /".*\.exe[^"].*/
```

### 🛠️ SCCM SCNotification DLL Hijack
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
process.name: "SCNotification.exe" AND
file.Ext.relative_file_creation_time < 86400 AND
file.code_signature.trusted: false
```

### 📜 Script via HTML Application
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("rundll32.exe", "mshta.exe") AND
(
  process.command_line: ("*script*eval(*", "*script*GetObject*", "*.run(*", "*).Exec()*", "*mshta*http*") OR
  (process.name: "mshta.exe" AND NOT process.command_line: ("*.hta*", "*.htm*", "-Embedding")) OR
  process.command_line: "*\\Users\\*\\Downloads\\*.hta*" OR
  process.command_line: ("*\\Temp\\7z*", "*\\Temp\\Rar$*", "*\\Temp\\Temp?_*", "*\\Temp\\BNZ.*")
)
```

### 🗑️ SDelete-like Filename Rename
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "2" AND 
file.name: "*AAA.AAA"
```

### ⚡ Suspicious CertUtil Commands
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "certutil.exe" OR process.pe.original_file_name: "CertUtil.exe") AND
process.command_line: ("*-decode*", "*-encode*", "*-urlcache*", "*-verifyctl*", "*-encodehex*", "*-decodehex*", "*-exportPFX*")
```

### 🕵️ Direct Syscall Detection
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "10" AND 
CallTrace: * AND
NOT CallTrace: ("*\\ntdll.dll*", "*\\wow64cpu.dll*", "*\\wow64win.dll*", "*\\win32u.dll*") AND
NOT TargetImage: ("*\\Malwarebytes Anti-Exploit\\*", "*\\Cisco\\AMP\\*")
```

### 📜 Suspicious scrobj.dll Load
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
file.name: "scrobj.dll" AND
process.executable: ("*\\Windows\\System32\\*.exe", "*\\Windows\\SysWOW64\\*.exe") AND
NOT process.name: ("cscript.exe", "msiexec.exe", "smartscreen.exe", "wscript.exe", "mshta.exe", "cmd.exe", "powershell.exe")
```

### ⚡ Suspicious WMI Script
```lucene
event.dataset: "windows.sysmon_operational" AND 
(
  (event.code: "1" AND process.name: "WMIC.exe" AND process.command_line: ("*format*:*", "*/format*:*") AND NOT process.command_line: ("* /format:table *", "* /format:table")) OR
  (event.code: "7" AND file.name: ("jscript.dll", "vbscript.dll"))
)
```

### ⚡ System Critical Process File Activity
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.extension: ("exe", "dll") AND
process.name: ("smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe")
```

### ⏰ Timestomping Detection
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "2" AND 
NOT process.executable: ("*\\Program Files\\*", "*\\Program Files (x86)\\*", "*\\Windows\\system32\\svchost.exe") AND
NOT file.extension: ("temp", "tmp", "xml", "newcfg") AND
NOT user.name: ("SYSTEM", "Local Service", "Network Service")
```

### 🚫 Untrusted DLL Loaded from Suspicious Directory
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
process.code_signature.trusted: true AND
(file.Ext.relative_file_creation_time <= 500 OR file.Ext.relative_file_name_modify_time <= 500) AND
file.code_signature.trusted: false AND
file.path: (
  "?:\\PerfLogs\\*.dll", "?:\\Users\\*\\Pictures\\*.dll", "?:\\Users\\Public\\*.dll",
  "?:\\Windows\\Tasks\\*.dll", "?:\\Intel\\*.dll", "?:\\AMD\\Temp\\*.dll",
  "?:\\Windows\\AppReadiness\\*.dll", "?:\\Windows\\ServiceState\\*.dll",
  "?:\\Windows\\security\\*.dll", "?:\\Windows\\System\\*.dll",
  "?:\\Windows\\IdentityCRL\\*.dll", "?:\\Windows\\Branding\\*.dll",
  "?:\\Windows\\csc\\*.dll", "?:\\Windows\\DigitalLocker\\*.dll",
  "?:\\Windows\\en-US\\*.dll", "?:\\Windows\\wlansvc\\*.dll"
)
```

### 🚫 Untrusted Driver Loaded
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "6" AND 
process.pid: 4 AND
(file.code_signature.trusted: false OR NOT file.code_signature.exists: true) AND
NOT file.code_signature.status: ("errorExpired", "errorRevoked")
```

### 📁 Unusual ADS File Creation
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.path: "C:\\*:*" AND
file.extension: ("pdf", "dll", "exe", "dat", "com", "bat", "ps1", "vbs", "hta", "docx", "xlsx", "pptx") AND
NOT file.path: ("C:\\*:zone.identifier*", "C:\\users\\*\\appdata\\roaming\\microsoft\\teams\\old_weblogs_*:$DATA") AND
NOT process.executable: (
  "*\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe", "*\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "*\\Program Files\\Microsoft Office\\*\\EXCEL.EXE", "*\\Windows\\explorer.exe",
  "*\\Windows\\System32\\svchost.exe"
)
```

### ⚡ Unusual System Child Process
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.pid: 4 AND
process.executable: * AND
NOT process.executable: ("Registry", "MemCompression", "*\\Windows\\System32\\smss.exe", "HotPatch")
```

### 🔧 Filter Manager Unload
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "fltMC.exe" AND
process.command_line: "*unload*" AND
NOT process.parent.executable: ("*\\ManageEngine\\UEMS_Agent\\bin\\DCFAService64.exe", "*\\Bitdefender\\Endpoint Security\\*")
```

### 🛡️ WDAC Policy Modification
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "11" AND 
file.extension: ("p7b", "cip") AND
file.path: ("*\\Windows\\System32\\CodeIntegrity\\*.p7b", "*\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip") AND
NOT process.executable: "*\\Windows\\System32\\poqexec.exe"
```

### 🐧 WSL Child Process
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: ("wsl.exe", "wslhost.exe") AND
NOT process.executable: ("*\\Program Files*\\*", "*\\Windows\\System32\\conhost.exe", "*\\Windows\\System32\\WerFault.exe")
```

### 📁 WSL Filesystem Activity
```lucene
event.dataset: "windows.sysmon_operational" AND 
(
  (event.code: "1" AND process.name: "dllhost.exe" AND process.command_line: "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*") OR
  (event.code: "11" AND process.name: "dllhost.exe" AND NOT file.path: ("*\\Users\\*\\Downloads\\*", "*\\Windows\\Prefetch\\DLLHOST.exe-*.pf"))
)
```

---

## 🔍 DISCOVERY

### 🏢 Active Directory Web Service
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
file.name: ("System.DirectoryServices*.dll", "System.IdentityModel*.dll") AND
NOT user.id: ("S-1-5-18", "S-1-5-19", "S-1-5-20") AND
NOT process.executable: ("*\\windows\\system32\\dsac.exe", "*\\powershell\\*\\pwsh.exe", "*\\windows\\adws\\*")
```

### 🔍 AdFind Tool Activity
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "AdFind*.exe" OR process.pe.original_file_name: "AdFind.exe") AND
process.command_line: (
  "*objectcategory=computer*", "*objectcategory=person*", "*objectcategory=subnet*",
  "*objectcategory=group*", "*domainlist*", "*dcmodes*", "*adinfo*", "*dclist*"
)
```

### 👥 Admin Reconnaissance
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(
  ((process.name: "net.exe" OR process.pe.original_file_name: "net.exe") AND process.command_line: ("*group*admin*", "*user*admin*", "*Domain Admins*", "*Remote Desktop Users*")) OR
  (process.name: "wmic.exe" AND process.command_line: ("*group*", "*useraccount*"))
) AND
NOT user.id: ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```

### 🆔 System Account Discovery
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.Ext.token.integrity_level_name: "System" OR winlog.event_data.IntegrityLevel: "System") AND
(
  process.name: "whoami.exe" OR
  (process.name: "net1.exe" AND NOT process.parent.name: "net.exe" AND NOT process.command_line: ("*start*", "*stop*"))
) AND
NOT process.parent.executable: (
  "*\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe", "*\\Dell\\SupportAssistAgent\\SRE\\SRE.exe",
  "*\\Obkio Agent\\main.dist\\ObkioAgentSoftware.exe"
)
```

### 📊 Group Policy Discovery
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
(process.name: "gpresult.exe" OR process.pe.original_file_name: "gprslt.exe") AND
process.command_line: ("*/z*", "*/v*", "*/r*", "*/x*")
```

### 🆔 whoami Command Activity
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "whoami.exe" AND
(
  (user.domain: ("NT *", "* NT", "IIS APPPOOL") AND user.id: ("S-1-5-18", "S-1-5-19", "S-1-5-20")) OR
  (process.Ext.token.integrity_level_name: "System" OR winlog.event_data.IntegrityLevel: "System") OR
  process.parent.name: ("wsmprovhost.exe", "w3wp.exe", "wmiprvse.exe", "rundll32.exe", "regsvr32.exe")
) AND
NOT (process.parent.name: "cmd.exe" AND process.parent.command_line: "*chcp 437*") AND
NOT process.parent.executable: "*\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe"
```

---

## ⚡ EXECUTION

### ☀️ SolarWinds Backdoor Child Processes
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("cmd.exe", "powershell.exe") AND
process.parent.name: (
  "ConfigurationWizard*.exe", "NetflowDatabaseMaintenance*.exe", "NetFlowService*.exe",
  "SolarWinds.Administration*.exe", "SolarWinds.Collector.Service*.exe", "SolarwindsDiagnostics*.exe"
)
```

### ⚡ SolarWinds Unusual Child Processes
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: ("SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe") AND
NOT (
  process.name: (
    "APMServiceControl*.exe", "ExportToPDFCmd*.Exe", "SolarWinds.Credentials.Orion.WebApi*.exe",
    "SolarWinds.Orion.Topology.Calculator*.exe", "Database-Maint.exe", "WerFault.exe"
  ) AND process.code_signature.trusted: true
)
```

### 🏃 Command Shell Started by svchost
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: "svchost.exe" AND
process.name: "cmd.exe" AND
NOT process.command_line: "\"cmd.exe\" /C sc control hptpsmarthealthservice 211"
```

### 🏃 Command Shell Started by Unusual Process
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "cmd.exe" AND
process.parent.name: (
  "lsass.exe", "csrss.exe", "epad.exe", "regsvr32.exe", "dllhost.exe", "LogonUI.exe",
  "wermgr.exe", "spoolsv.exe", "jucheck.exe", "GoogleUpdate.exe", "sppsvc.exe",
  "sihost.exe", "SearchIndexer.exe", "WerFault.exe"
)
```

### 🏃 Command Shell via Rundll32
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("cmd.exe", "powershell.exe") AND
process.parent.name: "rundll32.exe" AND
NOT process.parent.command_line: ("*SHELL32.dll,RunAsNewUser_RunDLL*", "*.tmp,zzzzInvokeManagedCustomActionOutOfProc*")
```

### 🏃 Execution from Unusual Path
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: (
  "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "cmstp.exe",
  "RegAsm.exe", "installutil.exe", "mshta.exe", "RegSvcs.exe", "powershell.exe", "cmd.exe"
) AND
process.command_line: (
  "C:\\PerfLogs\\*", "C:\\Users\\Public\\*", "C:\\Windows\\Tasks\\*", "C:\\Intel\\*",
  "C:\\AMD\\Temp\\*", "C:\\Windows\\AppReadiness\\*", "C:\\Windows\\ServiceState\\*",
  "C:\\Windows\\security\\*", "C:\\Windows\\IdentityCRL\\*", "C:\\Windows\\Branding\\*",
  "C:\\Windows\\csc\\*", "C:\\Windows\\DigitalLocker\\*", "C:\\Windows\\en-US\\*",
  "C:\\Windows\\wlansvc\\*", "C:\\Windows\\Prefetch\\*", "C:\\Windows\\Fonts\\*",
  "C:\\Windows\\diagnostics\\*", "C:\\Windows\\TAPI\\*", "C:\\Windows\\INF\\*",
  "C:\\windows\\tracing\\*", "c:\\windows\\IME\\*", "c:\\Windows\\Performance\\*",
  "c:\\windows\\intel\\*", "c:\\windows\\ms\\*", "C:\\Windows\\dot3svc\\*",
  "C:\\Windows\\panther\\*", "C:\\Windows\\RemotePackages\\*", "C:\\Windows\\OCR\\*",
  "C:\\Windows\\appcompat\\*", "C:\\Windows\\apppatch\\*", "C:\\Windows\\addins\\*",
  "C:\\Windows\\Setup\\*", "C:\\Windows\\Help\\*", "C:\\Windows\\SKB\\*",
  "C:\\Windows\\Vss\\*", "C:\\Windows\\servicing\\*", "C:\\Windows\\CbsTemp\\*",
  "C:\\Windows\\Logs\\*", "C:\\Windows\\WaaS\\*", "C:\\Windows\\twain_32\\*",
  "C:\\Windows\\ShellExperiences\\*", "C:\\Windows\\ShellComponents\\*",
  "C:\\Windows\\PLA\\*", "C:\\Windows\\Migration\\*", "C:\\Windows\\debug\\*",
  "C:\\Windows\\Cursors\\*", "C:\\Windows\\Containers\\*", "C:\\Windows\\Boot\\*",
  "C:\\Windows\\bcastdvr\\*", "C:\\Windows\\TextInput\\*", "C:\\Windows\\schemas\\*",
  "C:\\Windows\\SchCache\\*", "C:\\Windows\\Resources\\*", "C:\\Windows\\rescache\\*",
  "C:\\Windows\\Provisioning\\*", "C:\\Windows\\PrintDialog\\*", "C:\\Windows\\PolicyDefinitions\\*",
  "C:\\Windows\\media\\*", "C:\\Windows\\Globalization\\*", "C:\\Windows\\L2Schemas\\*",
  "C:\\Windows\\LiveKernelReports\\*", "C:\\Windows\\ModemLogs\\*", "C:\\Windows\\ImmersiveControlPanel\\*",
  "C:\\$Recycle.Bin\\*"
)
```

### 📁 Initial Access via MSC File
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.executable: "*\\Windows\\System32\\mmc.exe" AND
process.parent.command_line: "*.msc" AND
NOT process.parent.command_line: ("*\\Windows\\System32\\*.msc", "*\\Program files\\*.msc") AND
NOT process.executable: (
  "*\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "*\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "*\\Windows\\System32\\vmconnect.exe", "*\\Windows\\System32\\WerFault.exe"
)
```

### ⚡ PowerShell Suspicious Arguments via WinScript
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("powershell.exe", "pwsh.exe", "cmd.exe") AND
process.parent.name: ("wscript.exe", "mshta.exe")
```

### 🚀 PsExec Lateral Movement
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "PsExec.exe" AND
process.command_line: "*-accepteula*" AND
NOT process.executable: ("*\\Docusnap\\*\\psexec.exe", "*\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe")
```

### 🐚 Reverse Shell via Netcat
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: ("cmd.exe", "powershell.exe") AND
process.parent.command_line: "*-e*" AND
(
  process.parent.args_count: 5 AND process.parent.command_line: /.*[0-9]{1,3}(\.[0-9]{1,3}){3}.*/ OR
  (process.parent.command_line: ("*-l*", "*-p*") AND process.parent.command_line: ("*cmd.exe*", "*powershell.exe*"))
)
```

### 📜 Scripts from Archive Files
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "wscript.exe" AND
process.parent.name: ("explorer.exe", "winrar.exe", "7zFM.exe") AND
process.command_line: (
  "*\\Users\\*\\AppData\\Local\\Temp\\7z*\\*",
  "*\\Users\\*\\AppData\\Local\\Temp\\*.zip.*\\*",
  "*\\Users\\*\\AppData\\Local\\Temp\\Rar$*\\*",
  "*\\Users\\*\\AppData\\Local\\Temp\\Temp?_*\\*",
  "*\\Users\\*\\AppData\\Local\\Temp\\BNZ.*"
)
```

### ⚡ Suspicious CMD via WMI
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.parent.name: "WmiPrvSE.exe" AND
process.name: "cmd.exe" AND
process.command_line: ("*/c*", "*/Q*", "*2>&1*", "*1>*") AND
process.command_line: ("*C:\\windows\\temp\\*.txt*", "*\\Windows\\Temp\\*", "*-encodehex*")
```

### ⚡ Suspicious PowerShell Image Load
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "7" AND 
file.name: ("System.Management.Automation.dll", "System.Management.Automation.ni.dll") AND
NOT (
  process.code_signature.subject_name: ("Microsoft Corporation", "Microsoft Dynamic Code Publisher") AND
  process.code_signature.trusted: true
) AND
NOT process.executable: (
  "*\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "*\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
)
```

### ⚡ Windows CMD Shell Suspicious Arguments
```lucene
event.dataset: "windows.sysmon_operational" AND 
event.code: "1" AND 
process.name: "cmd.exe" AND
(
  process.command_line: (
    "*).Run(*", "*GetObject*", "* curl*regsvr32*", "*echo*wscript*", "*echo*ZONE.identifier*",
    "*ActiveXObject*", "*dir /s /b *echo*", "*unescape(*", "*findstr*TVNDRgAAAA*", "*findstr*passw*",
    "*start*\\\\*\\DavWWWRoot\\*", "* explorer*%CD%*", "*%cd%\\*.js*", "*/?cMD<*",
    "*/AutoIt3ExecuteScript*..*", "*&cls&cls&cls&cls&cls&*", "*&#*;&#*;&#*;&#*;*",
    "* &&s^eT*", "*& ChrW(*", "*&explorer /root*", "*start __ & __\\*",
    "*=wscri& set *", "*http*!COmpUternaME!*", "*pip install*System.Net.WebClient*",
    "*Invoke-WebReques*Start-Process*", "*-command (Invoke-webrequest*", "*copy /b *\\\\* ping *-n*"
  ) OR
  (process.command_line: "*echo*" AND process.parent.name: ("wscript.exe", "mshta.exe")) OR
  process.command_line: ("*1>?:\\*.vbs*", "*1>?:\\*.js*") OR
  (process.command_line: "*explorer.exe*" AND process.command_line: "*type*" AND process.command_line: "*>*" AND process.command_line: "*start*")
)
```

## 📈 DASHBOARD ВИДЖЕТЫ

### Рекомендуемые визуализации:

1. **Top Process Names by Count**
   ```lucene
   event.dataset: "windows.sysmon_operational" AND event.code: "1"
   Aggregation: Terms, Field: process.name, Size: 10
   ```

2. **Network Connections by Destination Port**
   ```lucene
   event.dataset: "windows.sysmon_operational" AND event.code: "3"
   Aggregation: Terms, Field: destination.port, Size: 20
   ```

3. **DNS Queries by Domain**
   ```lucene
   event.dataset: "windows.sysmon_operational" AND event.code: "22"
   Aggregation: Terms, Field: dns.question.name, Size: 15
   ```

4. **File Creation Events by Extension**
   ```lucene
   event.dataset: "windows.sysmon_operational" AND event.code: "11"
   Aggregation: Terms, Field: file.extension, Size: 10
   ```

5. **Registry Modifications by Path**
   ```lucene
   event.dataset: "windows.sysmon_operational" AND event.code: "13"
   Aggregation: Terms, Field: registry.path, Size: 15
   ```