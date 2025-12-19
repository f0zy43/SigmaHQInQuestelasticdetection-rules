# Elastic Lucene Queries для Sysmon
## Отфильтрованные для тактик Initial Access, Execution, Persistence

Преобразованные запросы из MITRE ATT&CK синтаксиса в Elastic Lucene для использования в Elasticsearch с **Sysmon событиями**.

---

## Initial Access (TA0001) - Начальный доступ

### Windows Script From Internet (Sysmon Event 1 - Process Creation)
```lucene
winlog.event_id:1 AND
(process.command_line:\"*.js\" OR process.command_line:\"*.jse\" OR process.command_line:\"*.vbs\" OR 
 process.command_line:\"*.vbe\" OR process.command_line:\"*.wsh\" OR process.command_line:\"*.hta\") AND
(process.parent.name:\"chrome.exe\" OR process.parent.name:\"msedge.exe\" OR 
 process.parent.name:\"explorer.exe\" OR process.parent.name:\"winrar.exe\")
```

Обнаружение загрузки и выполнения скриптов Windows, загруженных с интернета через браузеры.

---

## Execution (TA0002) - Выполнение

### Script Execution from Browser (Sysmon Event 1 - Process Creation)
```lucene
winlog.event_id:1 AND
(process.parent.name:\"chrome.exe\" OR process.parent.name:\"msedge.exe\" OR 
 process.parent.name:\"firefox.exe\" OR process.parent.name:\"explorer.exe\") AND
(process.name:\"wscript.exe\" OR process.name:\"mshta.exe\" OR process.name:\"cscript.exe\" OR
 (process.name:\"cmd.exe\" AND (process.command_line:\"*.cmd*\" OR process.command_line:\"*.bat*\")))
```

Выполнение скриптов и команд, инициированное из браузера или файлового менеджера.

### Remote Thread Creation - LoadLibrary (Sysmon Event 8)
```lucene
winlog.event_id:8 AND
thread.dll.name:\"*kernel32.dll\" AND
(thread.function:\"LoadLibraryA\" OR thread.function:\"LoadLibraryW\")
```

Обнаружение создания удалённых потоков для загрузки библиотек (внедрение кода).

### PowerShell Remote Thread (Sysmon Event 8)
```lucene
winlog.event_id:8 AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"pwsh.exe\") AND
NOT source_process.parent.name:\"CompatTelRunner.exe\"
```

PowerShell создание удалённых потоков для внедрения кода в другие процессы.

### Remote Thread to Shell (Sysmon Event 8)
```lucene
winlog.event_id:8 AND
(target_process.name:\"cmd.exe\" OR target_process.name:\"powershell.exe\" OR target_process.name:\"pwsh.exe\") AND
NOT source_process.path:\"C:\\\\Windows\\\\System32\\\\*\"
```

Внедрение кода в процессы командной оболочки из подозрительных источников.

### Process Creation with Suspicious Commands (Sysmon Event 1)
```lucene
winlog.event_id:1 AND
(process.command_line:\"*powershell*\" OR process.command_line:\"*cmd.exe*\" OR process.command_line:\"*rundll32*\" OR
 process.command_line:\"*regsvcs*\" OR process.command_line:\"*regasm*\" OR process.command_line:\"*wmic*\" OR
 process.command_line:\"*msiexec*\" OR process.command_line:\"*bitsadmin*\")
```

Мониторинг создания процессов с подозрительными командными строками и LOLBins.

### File Created Time Changed (Sysmon Event 2)
```lucene
winlog.event_id:2 AND 
(file.name:\"*.exe\" OR file.name:\"*.dll\" OR file.name:\"*.sys\" OR file.name:\"*.bat\" OR file.name:\"*.ps1\")
```

Обнаружение изменения времени создания исполняемых файлов (маскировка активности).

### Network Connection - PowerShell (Sysmon Event 3)
```lucene
winlog.event_id:3 AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"pwsh.exe\") AND
(destination.port:80 OR destination.port:443 OR destination.port:53)
```

Мониторинг сетевых соединений из PowerShell на стандартные HTTP/HTTPS/DNS порты.

### DLL/Module Load by Suspicious Process (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
(process.name:\"powershell.exe\" OR process.name:\"pwsh.exe\" OR process.name:\"cmd.exe\" OR
 process.name:\"wscript.exe\" OR process.name:\"cscript.exe\" OR process.name:\"mshta.exe\" OR
 process.name:\"rundll32.exe\" OR process.name:\"regsvr32.exe\") AND
(image_loaded:\"*.dll\" OR image_loaded:\"*.sys\")
```

Обнаружение загрузки DLL файлов подозрительными процессами.

### Dbghelp/Dbgcore Load by Suspicious Process (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
(image_loaded:\"*dbghelp.dll\" OR image_loaded:\"*dbgcore.dll\") AND
(process.name:\"bash.exe\" OR process.name:\"cmd.exe\" OR process.name:\"cscript.exe\" OR
 process.name:\"powershell.exe\" OR process.name:\"rundll32.exe\" OR process.name:\"wscript.exe\")
```

Обнаружение загрузки отладочных библиотек для манипуляции памятью (кража учетных данных).

### WMI Module Load (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
(image_loaded:\"*fastprox.dll\" OR image_loaded:\"*wbemcomn.dll\" OR image_loaded:\"*wbemprox.dll\" OR
 image_loaded:\"*wbemsvc.dll\" OR image_loaded:\"*WmiApRpl.dll\" OR image_loaded:\"*wmiprov.dll\") AND
NOT (process.path:\"C:\\\\Program Files*\" OR process.path:\"C:\\\\Windows\\\\System32\\\\*\")
```

Обнаружение использования WMI для выполнения команд из подозрительных процессов.

### AMSI Bypass via DLL Load (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
image_loaded:\"*amsi.dll\" AND
NOT (process.name:\"explorer.exe\" OR process.name:\"Sysmon64.exe\" OR
     process.path:\"C:\\\\Program Files*\" OR process.path:\"C:\\\\Windows\\\\System32\\\\*\")
```

Обнаружение загрузки AMSI библиотеки подозрительными процессами (попытка обхода защиты).

### Office XLL/WLL Add-in Load (Sysmon Event 7)
```lucene
winlog.event_id:7 AND
((process.name:\"excel.exe\" AND image_loaded:\"*.xll\") OR
 (process.name:\"winword.exe\" AND image_loaded:\"*.wll\"))
```

Обнаружение загрузки вредоносных расширений в Office приложениях.

### Process Accessed - Credential Dumping (Sysmon Event 10)
```lucene
winlog.event_id:10 AND
target_process.name:\"lsass.exe\" AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"cmd.exe\" OR 
 source_process.name:\"mimikatz.exe\" OR source_process.path:\"*\\\\Temp\\\\*\")
```

Обнаружение попыток доступа к процессу lsass.exe для извлечения учетных данных.

### Process Terminated - Suspicious (Sysmon Event 5)
```lucene
winlog.event_id:5 AND
process.name:\"powershell.exe\"
```

Контроль завершения PowerShell процессов для анализа сессий.

---

## Persistence (TA0003) - Сохранение доступа

### Registry Run Key Modification (Sysmon Event 12/13 - Registry Events)
```lucene
winlog.event_id:(12 OR 13) AND
(registry.path:\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*\" OR
 registry.path:\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*\" OR
 registry.path:\"*\\\\Software\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*\") AND
NOT (process.name:\"explorer.exe\" OR process.name:\"svchost.exe\" OR process.name:\"msiexec.exe\" OR
     process.path:\"C:\\\\Program Files*\" OR process.path:\"C:\\\\Windows\\\\System32\\\\*\")
```

Обнаружение изменений в ключах реестра Run и RunOnce для автозапуска вредоноса.

### Registry Run Key Set (Sysmon Event 13)
```lucene
winlog.event_id:13 AND
(registry.path:\"*\\\\Services\\\\*\" OR registry.path:\"*\\\\Drivers\\\\*\") AND
registry.value.type:\"REG_SZ\" OR registry.value.type:\"REG_EXPAND_SZ\"
```

Обнаружение создания сервисов и драйверов через реестр для персистентности.

### File Created in System Directories (Sysmon Event 11)
```lucene
winlog.event_id:11 AND
(file.path:\"C:\\\\Windows\\\\System32\\\\*\" OR file.path:\"C:\\\\Windows\\\\SysWOW64\\\\*\" OR
 file.path:\"C:\\\\ProgramData\\\\*\") AND
(file.extension:\"exe\" OR file.extension:\"dll\" OR file.extension:\"sys\" OR file.extension:\"scr\" OR
 file.extension:\"bat\" OR file.extension:\"ps1\" OR file.extension:\"vbs\") AND
NOT (process.name:\"svchost.exe\" OR process.name:\"System\" OR process.path:\"C:\\\\Windows\\\\System32\\\\*\")
```

Обнаружение создания подозрительных файлов в системных директориях.

### File Creation in Startup Directory (Sysmon Event 11)
```lucene
winlog.event_id:11 AND
(file.path:\"*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\*\" OR
 file.path:\"*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\StartMenu\\\\Programs\\\\Startup\\\\*\" OR
 file.path:\"*\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\*\") AND
(file.extension:\"exe\" OR file.extension:\"dll\" OR file.extension:\"bat\" OR file.extension:\"ps1\" OR file.extension:\"vbs\")
```

Обнаружение создания вредоносных файлов в папке Startup для автозапуска.

### Scheduled Task Creation (Sysmon Event 1)
```lucene
winlog.event_id:1 AND
process.name:\"schtasks.exe\" AND
(process.command_line:\"*/create*\" OR process.command_line:\"-create\") AND
NOT user.id:\"S-1-5-18\"
```

Обнаружение создания запланированных задач для выполнения вредоноса.

### Scheduled Task Deletion (Sysmon Event 1)
```lucene
winlog.event_id:1 AND
process.name:\"schtasks.exe\" AND
(process.command_line:\"*/delete*\" OR process.command_line:\"-delete\") AND
NOT user.id:\"S-1-5-18\"
```

Обнаружение удаления запланированных задач для скрытия своей деятельности.

### WMI Event Subscription for Persistence (Sysmon Event 1)
```lucene
winlog.event_id:1 AND
(process.name:\"powershell.exe\" OR process.name:\"pwsh.exe\" OR process.name:\"cmd.exe\") AND
(process.command_line:\"*New-WmiEvent*\" OR process.command_line:\"*Register-WmiEvent*\" OR
 process.command_line:\"*wmic.exe*\" AND process.command_line:\"*eventconsumer*\")
```

Обнаружение использования WMI для создания постоянных событий (персистентность).

### Network Connection for C2 (Sysmon Event 3)
```lucene
winlog.event_id:3 AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"pwsh.exe\" OR source_process.name:\"cmd.exe\" OR
 source_process.name:\"mshta.exe\" OR source_process.name:\"rundll32.exe\" OR source_process.name:\"regsvr32.exe\") AND
destination.port:(80 OR 443 OR 8080 OR 8443 OR 8888)
```

Мониторинг сетевых соединений из подозрительных процессов на стандартные веб-порты (C2).

### Process Injection for Persistence (Sysmon Event 8)
```lucene
winlog.event_id:8 AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"cmd.exe\" OR 
 source_process.path:\"*\\\\Temp\\\\*\" OR source_process.path:\"*\\\\AppData\\\\*\") AND
NOT (target_process.name:\"explorer.exe\" OR target_process.name:\"svchost.exe\")
```

Обнаружение внедрения кода в процессы для персистентности.

### Suspicious Registry Operations (Sysmon Event 12)
```lucene
winlog.event_id:12 AND
(registry.path:\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\policies\\\\*\" OR
 registry.path:\"*\\\\System\\\\CurrentControlSet\\\\Services\\\\*\" OR
 registry.path:\"*\\\\Software\\\\Policies\\\\*\") AND
NOT process.path:\"C:\\\\Windows\\\\System32\\\\*\"
```

Обнаружение попыток изменения системных политик и служб через реестр.

### File Rename/Move for Persistence (Sysmon Event 26)
```lucene
winlog.event_id:26 AND
(previous_filename:\"*.bat\" OR previous_filename:\"*.ps1\" OR previous_filename:\"*.vbs\" OR
 previous_filename:\"*.exe\" OR previous_filename:\"*.dll\") AND
(file.name:\"*.txt\" OR file.name:\"*.tmp\" OR file.name:\"*.log\" OR file.name:\"*.ini\")
```

Обнаружение переименования вредоносных файлов для скрытия их истинного назначения.

### DNS Query for C2 (Sysmon Event 22)
```lucene
winlog.event_id:22 AND
(source_process.name:\"powershell.exe\" OR source_process.name:\"pwsh.exe\" OR source_process.name:\"cmd.exe\" OR
 source_process.name:\"rundll32.exe\" OR source_process.name:\"regsvr32.exe\" OR source_process.name:\"mshta.exe\") AND
(query_name:/.*\\.(top|buzz|xyz|rest|ml|cf|gq|ga|cyou|quest|onion)/ OR
 dns.question.name:\"*dga*\" OR dns.question.name:\"*c2*\" OR dns.question.name:\"*malware*\")
```

Обнаружение DNS запросов к подозрительным доменам для C2 коммуникации.

### Pipe Created for C2 Communication (Sysmon Event 17)
```lucene
winlog.event_id:17 AND
(pipe_name:\"\\\\*\\\\psexec*\" OR pipe_name:\"\\\\*\\\\lsass*\" OR 
 pipe_name:\"\\\\*\\\\mimikatz*\" OR pipe_name:\"\\\\*\\\\mojo*\") AND
NOT source_process.name:\"svchost.exe\"
```

Обнаружение создания именованных каналов для коммуникации между процессами (в т.ч. C2).

### Suspicious File Deletion (Sysmon Event 23)
```lucene
winlog.event_id:23 AND
(file.extension:\"VBK\" OR file.extension:\"VIB\" OR file.extension:\"VBM\" OR file.extension:\"BKF\" OR
 file.name:\"*backup*\" OR file.name:\"*recovery*\" OR file.name:\"*shadow*\") AND
NOT (process.name:\"Backup Exec*\" OR process.path:\"*\\\\Veeam\\\\*\" OR process.path:\"*\\\\Veritas\\\\*\")
```

Обнаружение удаления файлов резервного копирования для предотвращения восстановления.

---

## Notes (Примечания)

- Все события отфильтрованы для использования **Sysmon (System Monitor)** событий
- Sysmon Event ID:
  - **Event 1**: Process Creation
  - **Event 2**: A process changed a file creation time
  - **Event 3**: Network connection detected
  - **Event 5**: Process terminated
  - **Event 7**: Image loaded (DLL)
  - **Event 8**: CreateRemoteThread detected
  - **Event 10**: Process accessed
  - **Event 11**: FileCreate detected
  - **Event 12**: Registry object added or deleted
  - **Event 13**: Registry value set
  - **Event 17**: Pipe Created
  - **Event 22**: DNSEvent (DNS query)
  - **Event 23**: FileDelete detected
  - **Event 26**: ClipboardChange detected

- Рекомендуется использовать с **Filebeat** или **Winlogbeat** для сбора Sysmon событий
- Временные диапазоны и условия могут быть скорректированы в зависимости от вашей инфраструктуры
- Тестируйте все запросы в тестовой среде перед применением в production
- Используйте `host.os.type:"windows"` и `source.provider.name:"Sysmon"` для точной фильтрации
