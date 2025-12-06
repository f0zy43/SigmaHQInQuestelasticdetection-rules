# Elastic Lucene Queries для Sysmon и Windows Events

Преобразованные запросы из MITRE ATT&CK синтаксиса в Elastic Lucene для использования в Elasticsearch.

---

## Collection (Сбор информации)

### Доступ к почтовому ящику Outlook через COM
```lucene
(process.name:"rundll32.exe" OR process.name:"mshta.exe" OR process.name:"powershell.exe" OR 
 process.name:"pwsh.exe" OR process.name:"cmd.exe" OR process.name:"regsvr32.exe" OR 
 process.name:"cscript.exe" OR process.name:"wscript.exe") AND 
process.parent.name:"OUTLOOK.EXE"
```

### Export Mailbox через PowerShell (Exchange)
```lucene
(process.name:"powershell.exe" OR process.name:"pwsh.exe" OR process.name:"powershell_ise.exe") AND
(process.command_line:"*MailboxExportRequest*" OR process.command_line:"*-Mailbox*-ContentFilter*")
```

### Audio Capture (Захват звука)
```lucene
powershell.script_block_text:("Get-MicrophoneAudio" OR "WindowsAudioDevice-Powershell-Cmdlet" OR 
("waveInGetNumDevs" AND "mciSendStringA")) AND 
NOT user.id:"S-1-5-18"
```

### Clipboard Capture (Захват буфера обмена)
```lucene
(powershell.script_block_text:("Windows.Clipboard" OR "Windows.Forms.Clipboard" OR "Windows.Forms.TextBox") AND
(powershell.script_block_text:"]:GetText" OR powershell.script_block_text:".Paste()")) OR
powershell.script_block_text:"Get-Clipboard" AND NOT user.id:"S-1-5-18"
```

### Keylogger Detection (Обнаружение кейлоггера)
```lucene
powershell.script_block_text:(GetAsyncKeyState OR NtUserGetAsyncKeyState OR GetKeyboardState OR "Get-Keystrokes") OR
(powershell.script_block_text:(SetWindowsHookA OR SetWindowsHookW OR SetWindowsHookEx OR SetWindowsHookExA OR NtUserSetWindowsHookEx) AND
(powershell.script_block_text:(GetForegroundWindow OR GetWindowTextA OR GetWindowTextW OR "WM_KEYBOARD_LL" OR "WH_MOUSE_LL"))) AND
NOT user.id:"S-1-5-18"
```

### Screen Grabber (Захват экрана)
```lucene
powershell.script_block_text:("CopyFromScreen" AND ("System.Drawing.Bitmap" OR "Drawing.Bitmap")) AND 
NOT user.id:"S-1-5-18"
```

### Webcam Capture (Захват с веб-камеры)
```lucene
powershell.script_block_text:("NewFrameEventHandler" OR "VideoCaptureDevice" OR "DirectX.Capture.Filters" OR
"VideoCompressors" OR "Start-WebcamRecorder" OR 
(("capCreateCaptureWindowA" OR "capCreateCaptureWindow" OR "capGetDriverDescription") AND
("avicap32.dll" OR "avicap32")))
```

### Encryption with WinRAR
```lucene
(process.name:"rar.exe" OR process.name:"WinRAR.exe") AND
process.args:"a" AND (process.args:"-hp*" OR process.args:"-p*" OR process.args:"/hp*" OR process.args:"/p*")
```

---

## Command and Control (Командование и Контроль)

### CertReq POST Data Exfiltration
```lucene
process.name:"CertReq.exe" AND process.args:"-Post"
```

### LLM API Endpoints Detection
```lucene
network.protocol:"dns" AND
(process.name:"MSBuild.exe" OR process.name:"mshta.exe" OR process.name:"wscript.exe" OR 
 process.name:"powershell.exe" OR process.name:"pwsh.exe" OR process.name:"msiexec.exe" OR 
 process.name:"rundll32.exe" OR process.name:"bitsadmin.exe" OR process.name:"python.exe" OR
 process.name:"regsvr32.exe" OR process.name:"dllhost.exe") AND
(dns.question.name:"api.openai.com" OR dns.question.name:"*.openai.azure.com" OR 
 dns.question.name:"api.anthropic.com" OR dns.question.name:"api.mistral.ai" OR
 dns.question.name:"api.cohere.ai" OR dns.question.name:"chat.openai.com" OR
 dns.question.name:"copilot.microsoft.com" OR dns.question.name:"claude.ai")
```

### Common Webservices Used for C2
```lucene
network.protocol:"dns" AND
(process.name:"MSBuild.exe" OR process.name:"mshta.exe" OR process.name:"wscript.exe" OR
 process.name:"powershell.exe" OR process.name:"pwsh.exe" OR process.name:"python.exe") AND
(dns.question.name:"raw.githubusercontent.*" OR dns.question.name:"pastebin.*" OR 
 dns.question.name:"ghostbin.com" OR dns.question.name:"drive.google.com" OR
 dns.question.name:"api.dropboxapi.*" OR dns.question.name:"api.telegram.org" OR
 dns.question.name:"slack.com" OR dns.question.name:"discord.com" OR
 dns.question.name:"graph.microsoft.com") AND
NOT process.executable:"?:\\Program Files*"
```

### Suspicious TLD Resolution
```lucene
network.protocol:"dns" AND
(process.name:"MSBuild.exe" OR process.name:"mshta.exe" OR process.name:"powershell.exe" OR
 process.name:"pwsh.exe" OR process.name:"msiexec.exe" OR process.name:"rundll32.exe" OR
 process.name:"python.exe" OR process.name:"regsvr32.exe") AND
dns.question.name:/.*\.(top|buzz|xyz|rest|ml|cf|gq|ga|onion|monster|cyou|quest)/
```

### DNS Tunneling Detection
```lucene
process.name:"nslookup.exe" AND 
(process.args:"-querytype=*" OR process.args:"-qt=*" OR process.args:"-q=*" OR process.args:"-type=*")
```

### RDP Tunnel via Plink
```lucene
process.command_line:"*:3389*" AND 
(process.args:"-L" OR process.args:"-P" OR process.args:"-R" OR process.args:"-pw" OR process.args:"-ssh")
```

### Headless Browser Detection
```lucene
(process.name:"chrome.exe" OR process.name:"msedge.exe" OR process.name:"brave.exe") AND
process.args:"--headless*" AND 
(process.args:"--disable-gpu" OR process.args:"--dump-dom" OR process.args:"*http*" OR process.args:"data:text/html*") AND
(process.parent.name:"cmd.exe" OR process.parent.name:"powershell.exe" OR process.parent.name:"wscript.exe")
```

### ScreenConnect Child Process Detection
```lucene
(process.parent.name:"ScreenConnect.ClientService.exe" OR 
 process.parent.name:"ScreenConnect.WindowsClient.exe") AND
((process.name:"powershell.exe" AND (process.args:"-enc" OR process.args:"*downloadstring*" OR process.args:"*http*")) OR
 (process.name:"cmd.exe" AND process.args:"/c") OR
 (process.name:"msiexec.exe" AND process.args:"/i") OR
 process.name:"mshta.exe" OR process.name:"certutil.exe" OR process.name:"wscript.exe")
```

### Suspicious PowerShell Obfuscation
```lucene
process.command_line:/(\w+`(\w+|-|\.)`[\w+|\s])|("(\{\d\}){2,}".*-f)|(\\$\{`?e`?n`?v`?:`?p`?a`?t`?h`?\})/
```

### PowerShell Encoded Command Detection
```lucene
process.name:"powershell.exe" AND
(process.args:"-enc" OR process.args:"-ec" OR process.args:"/e" OR process.args:"/enc" OR
 process.command_line:"*Base64String*" OR process.command_line:"*[Convert]*" OR
 process.command_line:"*-Outfile*Start*" OR process.command_line:"*-bxor*")
```

### LOLBins Network Activity
```lucene
(process.name:"msiexec.exe" OR process.name:"rundll32.exe" OR process.name:"certreq.exe" OR
 process.name:"bitsadmin.exe") AND 
(network.protocol:"dns" OR network.protocol:"tcp") AND
destination.port:(80 OR 443 OR 53)
```

---

## Execution (Выполнение)

### Windows Script From Internet
```lucene
(file.extension:"js" OR file.extension:"jse" OR file.extension:"vbs" OR 
 file.extension:"vbe" OR file.extension:"wsh" OR file.extension:"hta") AND
(file.origin_url:* OR file.origin_referrer_url:*) AND
(process.name:"chrome.exe" OR process.name:"msedge.exe" OR process.name:"explorer.exe" OR process.name:"winrar.exe")
```

### Script Execution from Browser
```lucene
(process.parent.name:"chrome.exe" OR process.parent.name:"msedge.exe" OR 
 process.parent.name:"firefox.exe" OR process.parent.name:"explorer.exe") AND
(process.name:"wscript.exe" OR process.name:"mshta.exe" OR 
 (process.name:"cmd.exe" AND (process.command_line:"*.cmd*" OR process.command_line:"*.bat*")))
```

### Remote Thread Creation - LoadLibrary
```lucene
event.action:"CreateRemoteThread" AND
thread.dll.name:"*kernel32.dll" AND
(thread.function:"LoadLibraryA" OR thread.function:"LoadLibraryW")
```

### PowerShell Remote Thread
```lucene
event.action:"CreateRemoteThread" AND
(process.name:"powershell.exe" OR process.name:"pwsh.exe") AND
NOT process.parent.name:"CompatTelRunner.exe"
```

### Remote Thread to Shell
```lucene
event.action:"CreateRemoteThread" AND
(target_process.name:"cmd.exe" OR target_process.name:"powershell.exe" OR target_process.name:"pwsh.exe") AND
NOT source_process.path:"C:\\Windows\\System32\\*"
```

---

## Persistence (Сохранение доступа)

### Firewall Rule Modification
```lucene
(event_id:2005 OR event_id:2073) AND
NOT (process.name:"teams.exe" OR process.name:"keybase.exe" OR process.name:"Messenger.exe")
```

### Scheduled Task Deletion
```lucene
event_id:4699 AND
NOT (task_name:"*\\Microsoft\\Windows\\RemovalTools\\MRT_ERROR_HB" OR 
     task_name:"*\\Mozilla\\Firefox Default Browser Agent*")
```

### Suspicious Scheduled Task Creation
```lucene
event.action:"process_create" AND
process.name:"schtasks.exe" AND
(process.args:"/create" OR process.args:"-create") AND
NOT user.id:"S-1-5-18"
```

### Registry Run Key Modification
```lucene
registry.action:"modification" AND
(registry.path:"*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR
 registry.path:"*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*") AND
NOT (process.name:"explorer.exe" OR process.name:"svchost.exe" OR process.name:"msiexec.exe")
```

---

## Privilege Escalation (Повышение привилегий)

### LSASS Memory Access
```lucene
event.action:"ProcessAccessDetected" AND
target_process.name:"lsass.exe" AND
(source_process.name:"powershell.exe" OR source_process.name:"pwsh.exe")
```

### Suspicious LSASS Access
```lucene
event.action:"ProcessAccessDetected" AND
target_process.name:"lsass.exe" AND
granted_access:/10|30|50|70|90|B0|D0|F0|18|38|58|78|98|B8|D8|F8|1A|3A|5A|7A|9A|BA|DA|FA|FF/ AND
(source_process.path:"*\\Temp\\*" OR source_process.path:"*\\Users\\Public\\*" OR 
 source_process.path:"*\\AppData\\*" OR source_process.path:"*\\Temporary*")
```

### Uncommon LSASS Access Flag
```lucene
event.action:"ProcessAccessDetected" AND
target_process.name:"lsass.exe" AND
granted_access:"0x10" AND
NOT (source_process.name:"lsass.exe" OR source_process.name:"svchost.exe" OR 
     source_process.name:"taskhostw.exe" OR source_process.name:"perfmon.exe")
```

---

## Defense Evasion (Обход защиты)

### AMSI Bypass via DLL Load
```lucene
event.action:"ImageLoaded" AND
image_loaded:"*amsi.dll" AND
NOT (process.name:"explorer.exe" OR process.name:"Sysmon64.exe" OR
     process.path:"C:\\Program Files*" OR process.path:"C:\\Windows\\System32\\*")
```

### WMI Module Load
```lucene
event.action:"ImageLoaded" AND
(image_loaded:"*fastprox.dll" OR image_loaded:"*wbemcomn.dll" OR image_loaded:"*wbemprox.dll" OR
 image_loaded:"*wbemsvc.dll" OR image_loaded:"*WmiApRpl.dll" OR image_loaded:"*wmiprov.dll") AND
NOT (process.path:"C:\\Program Files*" OR process.path:"C:\\Windows\\System32\\*" OR 
     process.name:"explorer.exe")
```

### Dbghelp/Dbgcore Load by Suspicious Process
```lucene
event.action:"ImageLoaded" AND
(image_loaded:"*dbghelp.dll" OR image_loaded:"*dbgcore.dll") AND
(process.name:"bash.exe" OR process.name:"cmd.exe" OR process.name:"cscript.exe" OR
 process.name:"powershell.exe" OR process.name:"rundll32.exe" OR process.name:"wscript.exe")
```

### Suspicious DLL Load - System.Drawing
```lucene
event.action:"ImageLoaded" AND
image_loaded:"*System.Drawing.ni.dll"
```

### Office XLL/WLL Add-in Load
```lucene
(event.action:"ImageLoaded" AND process.name:"excel.exe" AND image_loaded:"*.xll") OR
(event.action:"ImageLoaded" AND process.name:"winword.exe" AND image_loaded:"*.wll")
```

---

## Credential Access (Доступ к учетным данным)

### Browser Credential File Access
```lucene
event.action:"FileAccess" AND
(file.name:"WebCacheV01.dat" OR file.name:"cookies.sqlite" OR file.name:"places.sqlite" OR
 file.name:"key3.db" OR file.name:"key4.db" OR file.name:"logins.json" OR
 file.path:"*\\User Data\\Default\\Login Data" OR file.path:"*\\User Data\\Local State") AND
NOT (process.name:"System" OR process.path:"C:\\Program Files*" OR process.path:"C:\\Windows\\System32\\*")
```

### Chromium Browser Sensitive File Access
```lucene
event.action:"FileAccess" AND
(file.path:"*\\User Data\\Default\\Cookies" OR file.path:"*\\User Data\\Default\\History" OR
 file.path:"*\\User Data\\Default\\Network\\Cookies" OR file.path:"*\\User Data\\Default\\Web Data") AND
NOT (process.name:"System" OR process.path:"C:\\Program Files*")
```

### Firefox Credentials Access
```lucene
event.action:"FileAccess" AND
(file.name:"cookies.sqlite" OR file.name:"places.sqlite" OR file.name:"key3.db" OR
 file.name:"key4.db" OR file.name:"logins.json") AND
NOT (process.name:"firefox.exe" OR process.path:"C:\\Program Files*")
```

### Outlook Mail Access
```lucene
event.action:"FileAccess" AND
(file.path:"*\\AppData\\Local\\Comms\\Unistore\\data*" OR 
 file.path:"*\\AppData\\Local\\Comms\\UnistoreDB\\store.vol") AND
NOT (process.name:"outlook.exe" OR process.path:"C:\\Program Files*")
```

---

## Discovery (Разведка)

### File and Registry Access for GPO Discovery
```lucene
event.action:"FileAccess" AND
file.path:"\\\\*\\sysvol\\*\\Policies\\*" AND
NOT (process.path:"C:\\Program Files*" OR process.path:"C:\\Windows\\*" OR process.name:"explorer.exe")
```

### Registry and Hive File Access
```lucene
event.action:"FileAccess" AND
(file.extension:"hive" OR file.extension:"reg") AND
NOT process.path:"C:\\Program Files*"
```

### Unattend.xml Access
```lucene
event.action:"FileAccess" AND
file.path:"*\\Panther\\unattend.xml"
```

### Network Share Discovery
```lucene
process.command_line:("net view*" OR "net share*" OR "Get-NetShare*" OR "nbtstat*") AND
(process.name:"cmd.exe" OR process.name:"powershell.exe")
```

---

## Impact (Воздействие)

### Backup File Deletion
```lucene
event.action:"FileDelete" AND
(file.extension:"VBK" OR file.extension:"VIB" OR file.extension:"VBM" OR file.extension:"BKF") AND
NOT (process.name:"Backup Exec*" OR process.path:"*\\Veeam\\*" OR process.path:"*\\Veritas\\*")
```

### Critical OS File Modification
```lucene
event.action:"FileModified" AND
(file.name:"winload.exe" OR file.name:"winload.efi" OR file.name:"ntoskrnl.exe" OR file.name:"bootmgr") AND
file.path:"C:\\Windows\\*" AND
NOT process.name:"tiworker.exe"
```

### Zone.Identifier ADS Deletion
```lucene
event.action:"FileDelete" AND
file.path:"*:Zone.Identifier"
```

### Suspicious Binary Dropper
```lucene
event.action:"FileCreate" AND
process.name:"*.exe" AND
file.extension:"exe" AND
NOT (process.path:"C:\\Windows\\System32\\*" OR process.path:"C:\\Program Files*" OR
     process.name:"explorer.exe" OR process.name:"msiexec.exe")
```

---

## Lateral Movement (Боковое движение)

### Psexec Pipe Detection
```lucene
event.action:"PipeCreated" AND
pipe_name:"\\\\PSEXESVC"
```

### WMI Remote Execution via Scrcons
```lucene
event_id:4624 AND
logon_type:3 AND
process.name:"scrcons.exe" AND
NOT target_logon_id:"0x3e7"
```

### Remote File Copy via BITS
```lucene
event.action:"FileCreate" AND
process.name:"svchost.exe" AND
file.name:"BIT*.tmp" AND
(file.extension:"exe" OR file.extension:"zip" OR file.extension:"rar" OR 
 file.extension:"bat" OR file.extension:"dll" OR file.extension:"ps1")
```

### Suspicious Network Share Access
```lucene
event.action:"FileAccess" AND
network.protocol:"smb" AND
file.path:"\\\\*" AND
(process.name:"cmd.exe" OR process.name:"powershell.exe" OR process.name:"explorer.exe")
```

---

## General Sysmon Event Mappings

### Process Creation (Sysmon Event 1)
```lucene
winlog.event_id:1 AND
(process.command_line:"*powershell*" OR process.command_line:"*cmd.exe*" OR process.command_line:"*rundll32*")
```

### File Created Time Changed (Sysmon Event 2)
```lucene
winlog.event_id:2 AND file.name:"*.exe"
```

### Network Connection Initiated (Sysmon Event 3)
```lucene
winlog.event_id:3 AND
(destination.port:53 OR destination.port:80 OR destination.port:443) AND
process.name:"powershell.exe"
```

### Sysmon Image Loaded (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
(image_loaded:"*.dll" OR image_loaded:"*.sys")
```

### CreateRemoteThread (Sysmon Event 8)
```lucene
winlog.event_id:8 AND
NOT source_process.path:"C:\\Windows\\System32\\*"
```

### Process Terminated (Sysmon Event 5)
```lucene
winlog.event_id:5 AND
process.name:"powershell.exe"
```

---

## Windows Security Event Mappings

### Logon Event (Event ID 4624)
```lucene
event_id:4624 AND
(logon_type:3 OR logon_type:10) AND
NOT user.domain:"NT AUTHORITY"
```

### Account Modification (Event ID 4720-4730)
```lucene
(event_id:4720 OR event_id:4722 OR event_id:4725 OR event_id:4726 OR event_id:4738) AND
NOT user.id:"S-1-5-18"
```

### Process Creation (Event ID 4688)
```lucene
event_id:4688 AND
(process.name:"cmd.exe" OR process.name:"powershell.exe" OR process.name:"rundll32.exe")
```

### Object Access - File (Event ID 4663)
```lucene
event_id:4663 AND
object.type:"File" AND
(object.name:"*credential*" OR object.name:"*password*" OR object.name:"*.pst")
```

### Registry Modification (Event ID 4657)
```lucene
event_id:4657 AND
(registry.key:"*\\Run" OR registry.key:"*\\RunOnce") AND
NOT user.id:"S-1-5-18"
```

### Scheduled Task Registered (Event ID 4698)
```lucene
event_id:4698 AND
(task.name:"*\\Microsoft\\Windows\\*" OR task.name:"*Scheduled\\*")
```

---

## Additional Detection Rules

### Suspicious File Extension Changes
```lucene
event.action:"FileRename" AND
(file.extension:"dll" OR file.extension:"exe" OR file.extension:"bat" OR file.extension:"ps1") AND
NOT source_file.extension:"exe"
```

### Python Path Configuration Exploitation
```lucene
event.action:"FileCreate" AND
file.path:"/venv/*/lib/site-packages/*.pth" OR
file.path:"/python*/lib/site-packages/*.pth" AND
NOT process.name:"python.exe"
```

### VSCode Tunnel Indicator
```lucene
event.action:"FileCreate" AND
file.name:"code_tunnel.json"
```

### WebDAV Temp File Suspicious Activity
```lucene
event.action:"FileCreate" AND
file.path:"*\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\\*" AND
(file.extension:"7z" OR file.extension:"bat" OR file.extension:"js" OR file.extension:"ps1" OR
 file.extension:"rar" OR file.extension:"vbs" OR file.extension:"zip")
```

### PFX Certificate File Creation
```lucene
event.action:"FileCreate" AND
file.extension:"pfx" AND
NOT (process.name:"OneDrive.exe" OR 
     process.path:"C:\\Program Files\\Microsoft Visual Studio\\*" OR
     process.path:"C:\\Program Files\\CMake\\*")
```

### WDAC Policy Creation
```lucene
event.action:"FileCreate" AND
file.path:"C:\\Windows\\System32\\CodeIntegrity\\*" AND
(file.extension:"cip" OR file.extension:"p7b") AND
integrity_level:"High"
```

### Dump File Creation
```lucene
event.action:"FileCreate" AND
(file.extension:"dmp" OR file.extension:"dump" OR file.extension:"hdmp")
```

---

## Notes (Примечания)

- Запросы адаптированы для использования в **Kibana Query Language (KQL)** и **Elasticsearch Query DSL**
- Временные диапазоны и условия могут быть скорректированы в зависимости от вашей инфраструктуры
- Рекомендуется тестировать все запросы в тестовой среде перед применением в production
- Используйте поле `host.os.type:"windows"` для фильтрации только Windows событий
- Поле `event_id` или `winlog.event_id` зависит от конфигурации Filebeat/Winlogbeat
