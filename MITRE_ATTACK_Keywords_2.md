# https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows

## windows/builtin/firewall_as/win_firewall_as_change_rule
```
detection:
    selection:
        EventID:
            - 2005 # A rule has been modified in the Windows Defender Firewall exception list (Windows 10)
            - 2073 # A rule has been modified in the Windows Defender Firewall exception list. (Windows 11)
    filter_optional_teams:
        ApplicationPath|endswith: '\AppData\local\microsoft\teams\current\teams.exe'
    filter_optional_keybase:
        ApplicationPath|endswith: '\AppData\Local\Keybase\keybase.exe'
    filter_optional_messenger:
        ApplicationPath|endswith: '\AppData\Local\Programs\Messenger\Messenger.exe'
    filter_optional_opera:
        ApplicationPath|contains|all:
            - ':\Users\'
            - '\AppData\Local\Programs\Opera\'
            - '\opera.exe'
    filter_optional_brave:
        ApplicationPath|contains|all:
            - ':\Users\'
            - '\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe'
    condition: selection and not 1 of filter_optional_*
```

## windows/builtin/security/account_management/win_security_scrcons_remote_wmi_scripteventconsumer
```
detection:
    selection:
        EventID: 4624
        LogonType: 3
        ProcessName|endswith: 'scrcons.exe'
    filter_main_local_system:
        TargetLogonId: '0x3e7' # Local System
    condition: selection and not 1 of filter_main_*
```

## windows/builtin/security/win_security_file_access_browser_credential
```
detection:
    selection_eid:
        EventID: 4663
        ObjectType: 'File'
        # Note: This AccessMask requires enhancements. As this access can be combined with other requests. It should include all possible outcomes where READ access and similar are part of it.
        AccessMask: '0x1'
    selection_browser_chromium:
        ObjectName|contains:
            - '\User Data\Default\Login Data'
            - '\User Data\Local State'
            - '\User Data\Default\Network\Cookies'
    selection_browser_firefox:
        FileName|endswith:
            - '\cookies.sqlite'
            - '\places.sqlite'
            - 'release\key3.db'  # Firefox
            - 'release\key4.db'  # Firefox
            - 'release\logins.json' # Firefox
    filter_main_system:
        ProcessName: System
    filter_main_generic:
        # This filter is added to avoid large amount of FP with 3rd party software. You should remove this in favour of specific filter per-application
        ProcessName|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
    filter_optional_defender:
        ProcessName|startswith: 'C:\ProgramData\Microsoft\Windows Defender\'
        ProcessName|endswith:
            - '\MpCopyAccelerator.exe'
            - '\MsMpEng.exe'
```

## windows/builtin/security/win_security_scheduled_task_deletion
```
detection:
    selection:
        EventID: 4699
    filter_main_generic:
        TaskName: '\Microsoft\Windows\RemovalTools\MRT_ERROR_HB' # Triggered by ParentCommandLine=C:\WINDOWS\system32\MRT.exe /EHB /HeartbeatFailure ErrorStack,Previous=ErrorStack,Previous=ErrorStack,Previous=ErrorStack,Previous=ErrorStack,Previous=SubmitHeartbeatReportData,Hr=0x80072f8f,Hr=0x80072f8f,Hr=0x80072f8f,Hr=0x80072f8f,Hr=0x80072f8f /HeartbeatError 0x80072f8f
    filter_main_firefox:
        TaskName|contains: '\Mozilla\Firefox Default Browser Agent ' # Triggered by firefox updates
```

## windows/create_remote_thread/create_remote_thread_win_loadlibrary
```
detection:
    selection:
        StartModule|endswith: '\kernel32.dll'
        StartFunction: 'LoadLibraryA'
```

## windows/create_remote_thread/create_remote_thread_win_powershell_generic
```
detection:
    selection:
        SourceImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_compattelrunner:
        SourceParentImage|endswith: ':\Windows\System32\CompatTelRunner.exe'
```

## windows/create_remote_thread/create_remote_thread_win_susp_target_shell_application
```
detection:
    selection:
        TargetImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
    filter_optional_defender:
        SourceImage|endswith: '\MsMpEng.exe'
```

## windows/file/file_access/file_access_win_browsers_chromium_sensitive_files
```
detection:
    selection:
        FileName|contains:
            - '\User Data\Default\Cookies'
            - '\User Data\Default\History'
            - '\User Data\Default\Network\Cookies'
            - '\User Data\Default\Web Data'
    filter_main_system:
        Image: System
    filter_main_generic:
        # This filter is added to avoid large amount of FP with 3rd party software. You should remove this in favour of specific filter per-application
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
    filter_optional_defender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\'
        Image|endswith:
            - '\MpCopyAccelerator.exe'
            - '\MsMpEng.exe'
```

## windows/file/file_access/file_access_win_browsers_credential
```
detection:
    selection_ie:
        FileName|endswith: '\Appdata\Local\Microsoft\Windows\WebCache\WebCacheV01.dat'
    selection_firefox:
        FileName|endswith:
            - '\cookies.sqlite'
            - '\places.sqlite'
            - 'release\key3.db'  # Firefox
            - 'release\key4.db'  # Firefox
            - 'release\logins.json' # Firefox
    selection_chromium:
        FileName|contains:
            - '\User Data\Default\Login Data'
            - '\User Data\Local State'
    filter_main_system:
        Image: System
    filter_main_generic:
        # This filter is added to avoid large amount of FP with 3rd party software. You should remove this in favour of specific filter per-application
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
    filter_optional_defender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\'
        Image|endswith:
            - '\MpCopyAccelerator.exe'
            - '\MsMpEng.exe'
    filter_optional_thor:
        Image|endswith:
            - '\thor.exe'
            - '\thor64.exe'
```

## windows/file/file_access/file_access_win_office_outlook_mail_credential
```
etection:
    selection_unistore:
        FileName|contains: '\AppData\Local\Comms\Unistore\data'
    selection_unistoredb:
        FileName|endswith: '\AppData\Local\Comms\UnistoreDB\store.vol'
    filter_main_system:
        Image: 'System'
    filter_main_generic:
        # This filter is added to avoid large amount of FP with 3rd party software. You should remove this in favour of specific filter per-application
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
    filter_optional_defender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\'
        Image|endswith:
            - '\MpCopyAccelerator.exe'
            - '\MsMpEng.exe'
    filter_optional_thor:
        Image|endswith:
            - '\thor64.exe'
            - '\thor.exe'
```

## windows/file/file_access/file_access_win_susp_gpo_access_uncommon_process
```
detection:
    selection:
        FileName|startswith: '\\'
        FileName|contains|all:
            - '\sysvol\'
            - '\Policies\'
    filter_main_generic:
        Image|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\explorer.exe'
            - ':\Windows\system32\'
            - ':\Windows\SysWOW64\'
```

## windows/file/file_access/file_access_win_susp_reg_and_hive
```
detection:
    selection:
        FileName|endswith:
            - '.hive'
            - '.reg'
    filter_main_generic:
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
```

## windows/file/file_access/file_access_win_susp_unattend_xml
```
detection:
    selection:
        FileName|endswith: '\Panther\unattend.xml'
```

## windows/file/file_delete/file_delete_win_zone_identifier_ads
```
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
```

## windows/file/file_event/file_event_win_dump_file_creation
```
detection:
    selection:
        TargetFilename|endswith:
            - '.dmp'
            - '.dump'
            - '.hdmp'
```

## windows/file/file_event/file_event_win_pfx_file_creation
```
detection:
    selection:
        TargetFilename|endswith: '.pfx'
    filter_optional_onedrive:
        Image:
            - 'C:\Program Files\Microsoft OneDrive\OneDrive.exe'
            - 'C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe'
        TargetFilename|endswith: '\OneDrive\CodeSigning.pfx'
    filter_optional_visual_studio:
        TargetFilename|startswith:
            - 'C:\Program Files (x86)\Microsoft Visual Studio\'
            - 'C:\Program Files\Microsoft Visual Studio\'
    filter_optional_cmake:
        TargetFilename|startswith: 'C:\Program Files\CMake\'
```

## windows/file/file_event/file_event_win_python_path_configuration_files
```
detection:
    selection:
        TargetFilename|re: '(?i)\\(venv|python(.+)?)\\lib\\site-packages\\' # Covers both Virtual envs and default paths
        TargetFilename|endswith: '.pth'
    filter_main_python:
        Image|endswith: '\python.exe'
        TargetFilename|endswith:
            - '\pywin32.pth' # VS Studio Python extension
            - '\distutils-precedence.pth'
```

## windows/file/file_event/file_event_win_scheduled_task_creation
```
detection:
    selection:
        TargetFilename|contains:
            - ':\Windows\System32\Tasks\'
            - ':\Windows\SysWOW64\Tasks\'
            - ':\Windows\Tasks\'
```

## windows/file/file_event/file_event_win_susp_binary_dropper
```
detection:
    selection:
        Image|endswith: '.exe'
        TargetFilename|endswith: '.exe'
    filter_main_generic_1:
        Image|endswith:
            - ':\Windows\System32\msiexec.exe'
            - ':\Windows\system32\cleanmgr.exe'
            - ':\Windows\explorer.exe'
            - ':\WINDOWS\system32\dxgiadaptercache.exe'
            - ':\WINDOWS\system32\Dism.exe'
            - ':\Windows\System32\wuauclt.exe'
    filter_main_update:
        # Security_UserID: S-1-5-18
        # Example:
        #   TargetFilename: C:\Windows\SoftwareDistribution\Download\803d1df4c931df4f3e50a022cda56e88\WindowsUpdateBox.exe
        Image|endswith: ':\WINDOWS\system32\svchost.exe'
        TargetFilename|contains: ':\Windows\SoftwareDistribution\Download\'
    filter_main_upgrade:
        Image|endswith: ':\Windows\system32\svchost.exe'
        TargetFilename|contains|all:
            # Example:
            #   This example was seen during windows upgrade
            #   TargetFilename: :\WUDownloadCache\803d1df4c931df4f3e50a022cda56e29\WindowsUpdateBox.exe
            - ':\WUDownloadCache\'
            - '\WindowsUpdateBox.exe'
    filter_main_windows_update_box:
        # This FP was seen during Windows Upgrade
        # ParentCommandLine: C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s wuauserv
        Image|contains: ':\WINDOWS\SoftwareDistribution\Download\'
        Image|endswith: '\WindowsUpdateBox.Exe'
        TargetFilename|contains: ':\$WINDOWS.~BT\Sources\'
    filter_main_tiworker:
        Image|contains: ':\Windows\WinSxS\'
        Image|endswith: '\TiWorker.exe'
    filter_main_programfiles:
        - Image|contains:
              - ':\Program Files\'
              - ':\Program Files (x86)\'
        - TargetFilename|contains:
              - ':\Program Files\'
              - ':\Program Files (x86)\'
    filter_main_defender:
        Image|contains:
            - ':\ProgramData\Microsoft\Windows Defender\'
            - ':\Program Files\Windows Defender\'
    filter_main_windows_apps:
        TargetFilename|contains: '\AppData\Local\Microsoft\WindowsApps\'
    filter_main_teams:
        Image|endswith: '\AppData\Local\Microsoft\Teams\Update.exe'
        TargetFilename|endswith:
            - '\AppData\Local\Microsoft\Teams\stage\Teams.exe'
            - '\AppData\Local\Microsoft\Teams\stage\Squirrel.exe'
            - '\AppData\Local\Microsoft\SquirrelTemp\tempb\'
    filter_main_mscorsvw:
        # Example:
        #   ParentCommandLine: "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe" ExecuteQueuedItems /LegacyServiceBehavior
        #   Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
        #       TargetFilename: C:\Windows\assembly\NativeImages_v4.0.30319_32\Temp\4f8c-0\MSBuild.exe
        #       TargetFilename: C:\Windows\assembly\NativeImages_v4.0.30319_32\Temp\49bc-0\testhost.net47.x86.exe
        #       TargetFilename: C:\Windows\assembly\NativeImages_v4.0.30319_32\Temp\39d8-0\fsc.exe
        Image|contains:
            - ':\Windows\Microsoft.NET\Framework\'
            - ':\Windows\Microsoft.NET\Framework64\'
            - ':\Windows\Microsoft.NET\FrameworkArm\'
            - ':\Windows\Microsoft.NET\FrameworkArm64\'
        Image|endswith: '\mscorsvw.exe'
        TargetFilename|contains: ':\Windows\assembly\NativeImages_'
    filter_main_vscode:
        Image|contains: '\AppData\Local\'
        Image|endswith: '\Microsoft VS Code\Code.exe'
        TargetFilename|contains: '\.vscode\extensions\'
    filter_main_githubdesktop:
        Image|endswith: '\AppData\Local\GitHubDesktop\Update.exe'
        # Example TargetFileName:
        #   \AppData\Local\SquirrelTemp\tempb\lib\net45\GitHubDesktop_ExecutionStub.exe
        #   \AppData\Local\SquirrelTemp\tempb\lib\net45\squirrel.exe
        TargetFilename|contains: '\AppData\Local\SquirrelTemp\'
    filter_main_windows_temp:
        - Image|contains: ':\WINDOWS\TEMP\'
        - TargetFilename|contains: ':\WINDOWS\TEMP\'
    filter_optional_python:
        Image|contains: '\Python27\python.exe'
        TargetFilename|contains:
            - '\Python27\Lib\site-packages\'
            - '\Python27\Scripts\'
            - '\AppData\Local\Temp\'
    filter_optional_squirrel:
        Image|contains: '\AppData\Local\SquirrelTemp\Update.exe'
        TargetFilename|contains: '\AppData\Local'
    filter_main_temp_installers:
        - Image|contains: '\AppData\Local\Temp\'
        - TargetFilename|contains: '\AppData\Local\Temp\'
    filter_optional_chrome:
        Image|endswith: '\ChromeSetup.exe'
        TargetFilename|contains: '\Google'
    filter_main_dot_net:
        Image|contains: ':\Windows\Microsoft.NET\Framework'
        Image|endswith: '\mscorsvw.exe'
        TargetFilename|contains: ':\Windows\assembly'
```

## windows/file/file_event/file_event_win_vscode_tunnel_indicators
```
detection:
    selection:
        TargetFilename|endswith: '\code_tunnel.json'
```

## windows/file/file_event/file_event_win_wdac_policy_creation_in_codeintegrity_folder
```
detection:
    selection:
        TargetFilename|contains: ':\Windows\System32\CodeIntegrity\'
        TargetFilename|endswith:
            - '.cip'
            - '.p7b'
        IntegrityLevel: 'High'
```

## windows/file/file_event/file_event_win_webdav_tmpfile_creation
```
detection:
    selection:
        TargetFilename|contains: '\AppData\Local\Temp\TfsStore\Tfs_DAV\'
        TargetFilename|endswith:
            - '.7z'
            - '.bat'
            - '.dat'
            - '.ico'
            - '.js'
            - '.lnk'
            - '.ps1'
            - '.rar'
            - '.vbe'
            - '.vbs'
            - '.zip'
```

## windows/file/file_rename/file_rename_win_non_dll_to_dll_ext
```
detection:
    selection:
        TargetFilename|endswith: '.dll'
    filter_main_dll:
        # Note: To avoid file renames
        SourceFilename|endswith: '.dll'
    filter_main_installers:
        SourceFilename|endswith: '.tmp'
    filter_main_empty_source:
        SourceFilename: ''
    filter_main_null_source:
        SourceFilename: null
    filter_main_tiworker:
        Image|contains: ':\Windows\WinSxS\'
        Image|endswith: '\TiWorker.exe'
    filter_main_upgrade:
        - Image|endswith: ':\Windows\System32\wuauclt.exe'
        - TargetFilename|contains: ':\$WINDOWS.~BT\Sources\'
    filter_main_generic:
        Image|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
    filter_optional_squirrel:
        SourceFilename|contains: '\SquirrelTemp\temp'
```

## windows/image_load/image_load_dll_amsi_uncommon_process
```
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
    filter_main_exact:
        Image|endswith:
            - ':\Windows\explorer.exe'
            - ':\Windows\Sysmon64.exe'
    filter_main_generic:
        Image|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
    filter_optional_defender:
        Image|contains: ':\ProgramData\Microsoft\Windows Defender\Platform\'
        Image|endswith: '\MsMpEng.exe'
    filter_main_dotnet:
        Image|contains:
            - ':\Windows\Microsoft.NET\Framework\'
            - ':\Windows\Microsoft.NET\Framework64\'
            - ':\Windows\Microsoft.NET\FrameworkArm\'
            - ':\Windows\Microsoft.NET\FrameworkArm64\'
        Image|endswith: '\ngentask.exe'
    filter_main_null:
        Image: null
    filter_main_empty:
        Image: ''
    condition: selection and n
```

## windows/image_load/image_load_dll_bitsproxy_load_by_uncommon_process
```
detection:
    selection:
        ImageLoaded|endswith: '\BitsProxy.dll'
    filter_main_system:
        Image:
            - 'C:\Windows\System32\aitstatic.exe'
            - 'C:\Windows\System32\bitsadmin.exe'
            - 'C:\Windows\System32\desktopimgdownldr.exe'
            - 'C:\Windows\System32\DeviceEnroller.exe'
            - 'C:\Windows\System32\MDMAppInstaller.exe'
            - 'C:\Windows\System32\ofdeploy.exe'
            - 'C:\Windows\System32\RecoveryDrive.exe'
            - 'C:\Windows\System32\Speech_OneCore\common\SpeechModelDownload.exe'
            # - 'C:\Windows\System32\svchost.exe' # BITS Service - If you collect CommandLine info. Apply a filter for the specific BITS service.
            - 'C:\Windows\SysWOW64\bitsadmin.exe'
            - 'C:\Windows\SysWOW64\OneDriveSetup.exe'
            - 'C:\Windows\SysWOW64\Speech_OneCore\Common\SpeechModelDownload.exe'
    filter_optional_chrome:
        Image: 'C:\Program Files\Google\Chrome\Application\chrome.exe'
```

## windows/image_load/image_load_dll_dbghelp_dbgcore_susp_load
```
detection:
    selection:
        ImageLoaded|endswith:
            - '\dbghelp.dll'
            - '\dbgcore.dll'
        Image|endswith:
            - '\bash.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\dnx.exe'
            - '\excel.exe'
            - '\monitoringhost.exe'
            - '\msbuild.exe'
            - '\mshta.exe'
            - '\outlook.exe'
            - '\powerpnt.exe'
            - '\regsvcs.exe'
            - '\rundll32.exe'
            - '\sc.exe'
            - '\scriptrunner.exe'
            - '\winword.exe'
            - '\wmic.exe'
            - '\wscript.exe'
            # - '\powershell.exe' # Note: Triggered by installing common software
            # - '\regsvr32.exe'  # Note: triggered by installing common software
            # - '\schtasks.exe'  # Note: triggered by installing software
            # - '\svchost.exe'  # Note: triggered by some services
    filter_main_tiworker:
        # Note: This filter requires "CommandLine" field enrichment
        CommandLine|startswith: 'C:\WINDOWS\WinSxS\'
        CommandLine|endswith: '\TiWorker.exe -Embedding'
    filter_main_generic:
        # Note: This filter requires "CommandLine" field enrichment
        Image|endswith: '\svchost.exe'
        CommandLine|endswith:
            - '-k LocalServiceNetworkRestricted'
            - '-k WerSvcGroup'
    filter_main_rundll32:
        # Note: This filter requires "CommandLine" field enrichment
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - '/d srrstr.dll,ExecuteScheduledSPPCreation'
            - 'aepdu.dll,AePduRunUpdate'
            - 'shell32.dll,OpenAs_RunDL'
            - 'Windows.Storage.ApplicationData.dll,CleanupTemporaryState'
```

## windows/image_load/image_load_dll_system_drawing_load
```
detection:
    selection:
        ImageLoaded|endswith: '\System.Drawing.ni.dll'
```

## windows/image_load/image_load_dll_taskschd_by_process_in_potentially_suspicious_location
```
detection:
    selection_dll:
        - ImageLoaded|endswith: '\taskschd.dll'
        - OriginalFileName: 'taskschd.dll'
    selection_paths:
        Image|contains:
            - ':\Temp\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\Desktop\'
            - '\Downloads\'
```

## windows/image_load/image_load_office_excel_xll_load
```
detection:
    selection:
        Image|endswith: '\excel.exe'
        ImageLoaded|endswith: '.xll'
```

## windows/image_load/image_load_office_word_wll_load
```
detection:
    selection:
        Image|endswith: '\winword.exe'
        ImageLoaded|endswith: '.wll'
```

## windows/image_load/image_load_wmi_module_load_by_uncommon_process
```
detection:
    selection:
        ImageLoaded|endswith:
            - '\fastprox.dll'
            - '\wbemcomn.dll'
            - '\wbemprox.dll'
            - '\wbemsvc.dll'
            - '\WmiApRpl.dll'
            - '\wmiclnt.dll'
            - '\WMINet_Utils.dll'
            - '\wmiprov.dll'
            - '\wmiutils.dll'
    filter_main_generic:
        Image|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\explorer.exe'
            - ':\Windows\Microsoft.NET\Framework\'
            - ':\Windows\Microsoft.NET\FrameworkArm\'
            - ':\Windows\Microsoft.NET\FrameworkArm64\'
            - ':\Windows\Microsoft.NET\Framework64\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
    filter_optional_other:
        Image|endswith:
            - '\WindowsAzureGuestAgent.exe'
            - '\WaAppAgent.exe'
    filter_optional_thor:
        Image|endswith:
            - '\thor.exe'
            - '\thor64.exe'
    filter_optional_defender:
        Image|endswith: '\MsMpEng.exe'
    filter_optional_teams:
        Image|contains:
            - '\Microsoft\Teams\current\Teams.exe'
            - '\Microsoft\Teams\Update.exe'
    filter_optional_sysmon:
        Image|endswith:
            - ':\Windows\Sysmon.exe'
            - ':\Windows\Sysmon64.exe'
```

## windows/network_connection/net_connection_win_dfsvc_non_local_ip
```
detection:
    selection:
        Image|endswith: '\dfsvc.exe'
        Initiated: 'true'
    filter_main_local_ip:
        DestinationIp|cidr: # Ranges excluded based on https://github.com/SigmaHQ/sigma/blob/0f176092326ab9d1e19384d30224e5f29f760d82/rules/windows/network_connection/net_connection_win_dllhost_net_connections.yml
            - '127.0.0.0/8'
            - '10.0.0.0/8'
            - '169.254.0.0/16'  # link-local address
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '::1/128'  # IPv6 loopback
            - 'fe80::/10'  # IPv6 link-local addresses
            - 'fc00::/7'  # IPv6 private addresses
```

## windows/network_connection/net_connection_win_dfsvc_uncommon_ports
```
detection:
    selection:
        Image|contains: ':\Windows\Microsoft.NET\'
        Image|endswith: '\dfsvc.exe'
        Initiated: 'true'
    filter_main_known_ports:
        DestinationPort:
            - 80
            - 443
    filter_optional_dns_ipv6:
        # Based on VT. More than 140 binaries made communication over DNS
        DestinationIsIpv6: 'true'
        DestinationPort: 53
```

## windows/network_connection/net_connection_win_dllhost_non_local_ip
```
detection:
    selection:
        Image|endswith: '\dllhost.exe'
        Initiated: 'true'
    filter_main_local_ranges:
        DestinationIp|cidr:
            - '::1/128'  # IPv6 loopback
            - '10.0.0.0/8'
            - '127.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '169.254.0.0/16'
            - 'fc00::/7'  # IPv6 private addresses
            - 'fe80::/10'  # IPv6 link-local addresses
    filter_main_msrange:
        DestinationIp|cidr:
            - '20.184.0.0/13' # Microsoft Corporation
            - '20.192.0.0/10' # Microsoft Corporation
            - '23.72.0.0/13'  # Akamai International B.V.
            - '51.10.0.0/15'  # Microsoft Corporation
            - '51.103.0.0/16' # Microsoft Corporation
            - '51.104.0.0/15' # Microsoft Corporation
            - '52.224.0.0/11'  # Microsoft Corporation
            - '150.171.0.0/19'  # Microsoft Corporation
            - '204.79.197.0/24' # Microsoft Corporation'
```

## windows/network_connection/net_connection_win_hh_http_connection
```
detection:
    selection:
        Image|endswith: '\hh.exe'
        Initiated: 'true'
        DestinationPort:
            - 80
            - 443
```

## windows/network_connection/net_connection_win_msiexec_http
```
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\msiexec.exe'
        DestinationPort:
            - 80
            - 443
```

## windows/network_connection/net_connection_win_powershell_network_connection
```
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        Initiated: 'true'
    filter_main_local_ip:
        DestinationIp|cidr:
            - '127.0.0.0/8'
            - '10.0.0.0/8'
            - '169.254.0.0/16'  # link-local address
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '::1/128'  # IPv6 loopback
            - 'fe80::/10'  # IPv6 link-local addresses
            - 'fc00::/7'  # IPv6 private addresses
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    filter_main_msrange:
        DestinationIp|cidr:
            - '20.184.0.0/13'
            - '51.103.210.0/23'
```

## windows/network_connection/net_connection_win_susp_azurefd_connection
```
detection:
    selection:
        DestinationHostname|contains: 'azurefd.net'
    filter_main_web_browsers:
        Image|endswith:
            - 'brave.exe'
            - 'chrome.exe'
            - 'chromium.exe'
            - 'firefox.exe'
            - 'msedge.exe'
            - 'msedgewebview2.exe'
            - 'opera.exe'
            - 'vivaldi.exe'
    filter_main_common_talkers:
        Image|endswith: 'searchapp.exe' # Windows search service uses signifcant amount of Azure FD
    filter_main_known_benign_domains:
        DestinationHostname|contains:
            - 'afdxtest.z01.azurefd.net' # used by Cortana; Cisco Umbrella top 1m
            - 'fp-afd.azurefd.net' # used by Cortana; Cisco Umbrella top 1m
            - 'fp-afdx-bpdee4gtg6frejfd.z01.azurefd.net' # used by Cortana; Cisco Umbrella top 1m
            - 'roxy.azurefd.net' # used by Cortana; Cisco Umbrella top 1m
            - 'powershellinfraartifacts-gkhedzdeaghdezhr.z01.azurefd.net' # Used by VS Code; Cisco Umbrella top 1m
            - 'storage-explorer-publishing-feapcgfgbzc2cjek.b01.azurefd.net' # Used by Azure Storage Explorer; Cisco Umbrella top 1m
            - 'graph.azurefd.net' # MS Graph; Cisco Umbrella top 1m
```

## windows/network_connection/net_connection_win_susp_initaited_public_folder
```
detection:
    selection:
        Initiated: 'true'
        Image|contains: ':\Users\Public\'
    filter_optional_ibm:
        Image|contains: ':\Users\Public\IBM\ClientSolutions\Start_Programs\' # IBM Client Solutions Default Location (Added by Tim Shelton - https://github.com/SigmaHQ/sigma/pull/3053/files)
```

## windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe
```
detection:
    selection:
        PipeName: '\PSEXESVC'
```

## windows/powershell/powershell_classic/posh_pc_alternate_powershell_hosts
```
detection:
    selection:
        Data|contains: 'HostApplication='
    # Note: Powershell Logging Data is localized. Meaning that "HostApplication" field will be translated to a different field on a non english layout. This rule doesn't take this into account due to the sheer ammount of possibilities. It's up to the user to add these cases.
    filter_main_ps:
        Data|contains:
            - 'HostApplication=?:/Windows/System32/WindowsPowerShell/v1.0/powershell' # In some cases powershell was invoked with inverted slashes
            - 'HostApplication=?:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell' # In some cases powershell was invoked with inverted slashes
            - 'HostApplication=?:\Windows\System32\sdiagnhost.exe'
            - 'HostApplication=?:\Windows\System32\WindowsPowerShell\v1.0\powershell'
            - 'HostApplication=?:\Windows\SysWOW64\sdiagnhost.exe'
            - 'HostApplication=?:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell'
            - 'HostApplication=powershell'
    filter_optional_citrix:
        Data|contains: 'Citrix\ConfigSync\ConfigSync.ps1'
    filter_optional_hexnode:
        Data|contains: 'HostApplication=C:\Hexnode\Hexnode Agent\Current\HexnodeAgent.exe'
```

## windows/powershell/powershell_classic/posh_pc_bxor_operator_usage
```
detection:
    selection:
        Data|contains|all:
            - 'HostName=ConsoleHost'
            - ' -bxor '
```

## windows/powershell/powershell_module/posh_pm_susp_netfirewallrule_recon
```
detection:
    selection_payload:
        Payload|contains:
            - 'Get-NetFirewallRule'
            - 'Show-NetFirewallRule'
    selection_contextinfo:
        ContextInfo|contains:
            - 'Get-NetFirewallRule'
            - 'Show-NetFirewallRule'
```

## windows/powershell/powershell_script/posh_ps_compress_archive_usage
```
detection:
    selection:
        ScriptBlockText|contains: 'Compress-Archive'
```

## windows/powershell/powershell_script/posh_ps_mailbox_access
```
detection:
    selection:
        ScriptBlockText|contains: '\Comms\Unistore\data'
```

## windows/powershell/powershell_script/posh_ps_new_netfirewallrule_allow
```
detection:
    selection:
        ScriptBlockText|contains: 'New-NetFirewallRule*-Action*Allow'
```

## windows/powershell/powershell_script/posh_ps_new_smbmapping_quic
```
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'New-SmbMapping'
            - '-TransportType QUIC'
```

## windows/powershell/powershell_script/posh_ps_registry_reconnaissance
```
detection:
    selection:
        # TODO: switch to |re|i: after sigma specification v2 is released
        ScriptBlockText|re: '(Get-Item|gci|Get-ChildItem).{1,64}-Path.{1,64}\\(currentcontrolset\\services|CurrentVersion\\Policies\\Explorer\\Run|CurrentVersion\\Run|CurrentVersion\\ShellServiceObjectDelayLoad|CurrentVersion\\Windows\winlogon)\\'
```

## windows/powershell/powershell_script/posh_ps_remove_item_path
```
detection:
    selection:
        ScriptBlockText|contains:
            - 'Remove-Item -Path '
            - 'del -Path '
            - 'erase -Path '
            - 'rd -Path '
            - 'ri -Path '
            - 'rm -Path '
            - 'rmdir -Path '
```

## windows/powershell/powershell_script/posh_ps_send_mailmessage
```
detection:
    selection:
        ScriptBlockText|contains: 'Send-MailMessage*-Attachments'
```

## windows/powershell/powershell_script/posh_ps_token_obfuscation
```
detection:
    selection:
        # Examples:
        #   IN`V`o`Ke-eXp`ResSIOn (Ne`W-ob`ject Net.WebClient).DownloadString
        #   &('In'+'voke-Expressi'+'o'+'n') (.('New-Ob'+'jec'+'t') Net.WebClient).DownloadString
        #   &("{2}{3}{0}{4}{1}"-f 'e','Expression','I','nvok','-') (&("{0}{1}{2}"-f'N','ew-O','bject') Net.WebClient).DownloadString
        - ScriptBlockText|re: '\w+`(\w+|-|.)`[\w+|\s]'
        # - ScriptBlockText|re: '\((\'(\w|-|\.)+\'\+)+\'(\w|-|\.)+\'\)' TODO: fixme
        - ScriptBlockText|re: '"(\{\d\}){2,}"\s*-f'  # trigger on at least two placeholders. One might be used for legitimate string formatting
        #   ${e`Nv:pATh}
        - ScriptBlockText|re: '(?i)\$\{`?e`?n`?v`?:`?p`?a`?t`?h`?\}'
    filter_envpath:
        ScriptBlockText|contains: '${env:path}' # TODO: Fix this. See https://github.com/SigmaHQ/sigma/pull/4964
    filter_chocolatey:
        ScriptBlockText|contains:
            - 'it will return true or false instead'  # Chocolatey install script https://github.com/chocolatey/chocolatey
            - 'The function also prevents `Get-ItemProperty` from failing' # https://docs.chocolatey.org/en-us/create/functions/get-uninstallregistrykey
    filter_exchange:
        Path|startswith: 'C:\Program Files\Microsoft\Exchange Server\'
        Path|endswith: '\bin\servicecontrol.ps1'
        ScriptBlockText|contains: '`r`n'
```

## windows/powershell/powershell_script/posh_ps_win_api_functions_access
```
detection:
    selection:
        ScriptBlockText|contains:
            - 'Advapi32.dll'
            - 'kernel32.dll'
            - 'KernelBase.dll'
            - 'ntdll.dll'
            - 'secur32.dll'
            - 'user32.dll'
```

## windows/powershell/powershell_script/posh_ps_win_api_library_access
```
detection:
    selection:
        ScriptBlockText|contains:
            - 'AddSecurityPackage'
            - 'AdjustTokenPrivileges'
            - 'CloseHandle'
            - 'CreateProcessWithToken'
            - 'CreateRemoteThread'
            - 'CreateThread'
            - 'CreateUserThread'
            - 'DangerousGetHandle'
            - 'DuplicateTokenEx'
            - 'EnumerateSecurityPackages'
            - 'FreeLibrary'
            - 'GetDelegateForFunctionPointer'
            - 'GetLogonSessionData'
            - 'GetModuleHandle'
            - 'GetProcAddress'
            - 'GetProcessHandle'
            - 'GetTokenInformation'
            - 'ImpersonateLoggedOnUser'
            - 'LoadLibrary'
            - 'memcpy'
            - 'MiniDumpWriteDump'
            - 'OpenDesktop'
            - 'OpenProcess'
            - 'OpenProcessToken'
            - 'OpenThreadToken'
            - 'OpenWindowStation'
            - 'QueueUserApc'
            - 'ReadProcessMemory'
            - 'RevertToSelf'
            - 'RtlCreateUserThread'
            - 'SetThreadToken'
            - 'VirtualAlloc'
            - 'VirtualFree'
            - 'VirtualProtect'
            - 'WaitForSingleObject'
            - 'WriteInt32'
            - 'WriteProcessMemory'
            - 'ZeroFreeGlobalAllocUnicode'
```

## windows/process_access/proc_access_win_lsass_powershell_access
```
detection:
    selection:
        SourceImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetImage|endswith: '\lsass.exe'
```

## windows/process_access/proc_access_win_lsass_susp_source_process
```
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith:
            - '10'
            - '30'
            - '50'
            - '70'
            - '90'
            - 'B0'
            - 'D0'
            - 'F0'
            - '18'
            - '38'
            - '58'
            - '78'
            - '98'
            - 'B8'
            - 'D8'
            - 'F8'
            - '1A'
            - '3A'
            - '5A'
            - '7A'
            - '9A'
            - 'BA'
            - 'DA'
            - 'FA'
            - '0x14C2'  # https://github.com/b4rtik/ATPMiniDump/blob/76304f93b390af3bb66e4f451ca16562a479bdc9/ATPMiniDump/ATPMiniDump.c
            - 'FF'
        SourceImage|contains:
            - '\Temp\'
            - '\Users\Public\'
            - '\PerfLogs\'
            - '\AppData\'
            - '\Temporary'
    filter_optional_generic_appdata:
        SourceImage|contains|all:
            - ':\Users\'
            - '\AppData\Local\'
        SourceImage|endswith:
            - '\Microsoft VS Code\Code.exe'
            - '\software_reporter_tool.exe'
            - '\DropboxUpdate.exe'
            - '\MBAMInstallerService.exe'
            - '\WebexMTA.exe'
            - '\Meetings\WebexMTAV2.exe'
            - '\WebEx\WebexHost.exe'
            - '\JetBrains\Toolbox\bin\jetbrains-toolbox.exe'
        GrantedAccess: '0x410'
    filter_optional_dropbox_1:
        SourceImage|contains: ':\Windows\Temp\'
        SourceImage|endswith: '.tmp\DropboxUpdate.exe'
        GrantedAccess:
            - '0x410'
            - '0x1410'
    filter_optional_dropbox_2:
        SourceImage|contains|all:
            - ':\Users\'
            - '\AppData\Local\Temp\'
        SourceImage|endswith: '.tmp\DropboxUpdate.exe'
        GrantedAccess: '0x1410'
    filter_optional_dropbox_3:
        SourceImage|contains:
            - ':\Program Files (x86)\Dropbox\'
            - ':\Program Files\Dropbox\'
        SourceImage|endswith: '\DropboxUpdate.exe'
        GrantedAccess: '0x1410'
    filter_optional_nextron:
        SourceImage|contains:
            - ':\Windows\Temp\asgard2-agent\'
            - ':\Windows\Temp\asgard2-agent-sc\'
        SourceImage|endswith:
            - '\thor64.exe'
            - '\thor.exe'
            - '\aurora-agent-64.exe'
            - '\aurora-agent.exe'
        GrantedAccess:
            - '0x1fffff'
            - '0x1010'
            - '0x101010'
    filter_optional_ms_products:
        SourceImage|contains|all:
            - ':\Users\'
            - '\AppData\Local\Temp\'
            - '\vs_bootstrapper_'
        GrantedAccess: '0x1410'
    filter_optional_chrome_update:
        SourceImage|contains: ':\Program Files (x86)\Google\Temp\'
        SourceImage|endswith: '.tmp\GoogleUpdate.exe'
        GrantedAccess:
            - '0x410'
            - '0x1410'
    filter_optional_keybase:
        SourceImage|contains: ':\Users\'
        SourceImage|endswith: \AppData\Local\Keybase\keybase.exe
        GrantedAccess: '0x1fffff'
    filter_optional_avira:
        SourceImage|contains: '\AppData\Local\Temp\is-'
        SourceImage|endswith: '.tmp\avira_system_speedup.tmp'
        GrantedAccess: '0x1410'
    filter_optional_viberpc_updater:
        SourceImage|contains: '\AppData\Roaming\ViberPC\'
        SourceImage|endswith: '\updater.exe'
        TargetImage|endswith: '\winlogon.exe'
        GrantedAccess: '0x1fffff'
    filter_optional_adobe_arm_helper:
        SourceImage|contains:  # Example path: 'C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\Temp\2092867405\AdobeARMHelper.exe'
            - ':\Program Files\Common Files\Adobe\ARM\'
            - ':\Program Files (x86)\Common Files\Adobe\ARM\'
        SourceImage|endswith: '\AdobeARMHelper.exe'
        GrantedAccess: '0x1410'
```

## windows/process_access/proc_access_win_lsass_uncommon_access_flag
```
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith: '10'
    # Absolute paths to programs that cause false positives
    filter1:
        SourceImage:
            - 'C:\Program Files\Common Files\McAfee\MMSSHost\MMSSHOST.exe'
            - 'C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe'
            - 'C:\Program Files\Windows Defender\MsMpEng.exe'
            - 'C:\PROGRAMDATA\MALWAREBYTES\MBAMSERVICE\ctlrupdate\mbupdatr.exe'
            - 'C:\Windows\System32\lsass.exe'
            - 'C:\Windows\System32\msiexec.exe'
            - 'C:\WINDOWS\System32\perfmon.exe'
            - 'C:\WINDOWS\system32\taskhostw.exe'
            - 'C:\WINDOWS\system32\taskmgr.exe'
            - 'C:\WINDOWS\system32\wbem\wmiprvse.exe'
            - 'C:\Windows\SysWOW64\msiexec.exe'
            - 'C:\Windows\sysWOW64\wbem\wmiprvse.exe'
    # Windows Defender
    filter2:
        SourceImage|startswith: 'C:\ProgramData\Microsoft\Windows Defender\'
        SourceImage|endswith: '\MsMpEng.exe'
    # Microsoft Gaming Services
    filter3:
        SourceImage|startswith: 'C:\Program Files\WindowsApps\'
        SourceImage|endswith: '\GamingServices.exe'
    # Process Explorer
    filter4:
        SourceImage|endswith:
            - '\PROCEXP64.EXE'
            - '\PROCEXP.EXE'
    # VMware Tools
    filter5:
        SourceImage|startswith: 'C:\ProgramData\VMware\VMware Tools\'
        SourceImage|endswith: '\vmtoolsd.exe'
    # Antivirus and EDR agents
    filter6:
        SourceImage|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
        SourceImage|contains: 'Antivirus'
    filter_nextron:
        # SourceImage|startswith: 'C:\Windows\Temp\asgard2-agent\'  # Can be a manual THOR installation
        SourceImage|endswith:
            - '\thor64.exe'
            - '\thor.exe'
            - '\aurora-agent-64.exe'
            - '\aurora-agent.exe'
    filter_ms_products:
        SourceImage|contains|all:
            - '\AppData\Local\Temp\'
            - '\vs_bootstrapper_'
        GrantedAccess: '0x1410'
    # Generic Filter for 0x1410 filter (caused by so many programs like DropBox updates etc.)
    filter_generic:
        SourceImage|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
            - 'C:\WINDOWS\system32\'
    filter_wer:
        SourceCommandLine: 'C:\WINDOWS\system32\wermgr.exe -upload'
    filter_localappdata:
        SourceImage|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\'
        SourceImage|endswith:
            - '\Microsoft VS Code\Code.exe'
            - '\software_reporter_tool.exe'
            - '\DropboxUpdate.exe'
            - '\MBAMInstallerService.exe'
            - '\WebEx\WebexHost.exe'
            - '\Programs\Microsoft VS Code\Code.exe'
            - '\JetBrains\Toolbox\bin\jetbrains-toolbox.exe'
    filter_xampp:
        SourceImage|endswith: '\xampp-control.exe'
        GrantedAccess: '0x410'
    filter_games:
        SourceImage|contains: '\SteamLibrary\steamapps\'
        GrantedAccess:
            - '0x410'
            - '0x10'
```

## windows/process_access/proc_access_win_susp_potential_shellcode_injection
```
detection:
    selection:
        GrantedAccess:
            - '0x147a'
            - '0x1f3fff'
        CallTrace|contains: 'UNKNOWN'
    filter_main_wmiprvse:
        SourceImage: 'C:\Windows\System32\Wbem\Wmiprvse.exe'
        TargetImage: 'C:\Windows\system32\lsass.exe'
    filter_optional_dell_folders:
        # If dell software is installed we get matches like these
        # Example 1:
        #   SourceImage: C:\Program Files\Dell\SupportAssistAgent\bin\SupportAssistAgent.exe
        #   TargetImage: C:\Program Files\Dell\TechHub\Dell.TechHub.exe
        #   GrantedAccess: 0x1F3FFF
        # Example 2:
        #   SourceImage: C:\Program Files (x86)\Dell\UpdateService\DCF\Dell.DCF.UA.Bradbury.API.SubAgent.exe
        #   TargetImage: C:\Program Files\Dell\TechHub\Dell.TechHub.exe
        #   GrantedAccess: 0x1F3FFF
        # Example 3:
        #   SourceImage: C:\Program Files\Dell\TechHub\Dell.TechHub.exe
        #   TargetImage: C:\Program Files (x86)\Dell\UpdateService\DCF\Dell.DCF.UA.Bradbury.API.SubAgent.exe
        #   GrantedAccess: 0x1F3FFF
        SourceImage|startswith:
            - 'C:\Program Files\Dell\'
            - 'C:\Program Files (x86)\Dell\'
        TargetImage|startswith:
            - 'C:\Program Files\Dell\'
            - 'C:\Program Files (x86)\Dell\'
    filter_optional_dell_specifc:
        SourceImage: 'C:\Program Files (x86)\Dell\UpdateService\ServiceShell.exe'
        TargetImage: 'C:\Windows\Explorer.EXE'
    filter_optional_visual_studio:
        SourceImage|startswith: 'C:\Program Files\Microsoft Visual Studio\'
        TargetImage|startswith: 'C:\Program Files\Microsoft Visual Studio\'
```

## windows/process_creation/proc_creation_win_7zip_password_extraction
```
detection:
    selection_img:
        - Description|contains: '7-Zip'
        - Image|endswith:
              - '\7z.exe'
              - '\7zr.exe'
              - '\7za.exe'
        - OriginalFileName:
              - '7z.exe'
              - '7za.exe'
    selection_password:
        CommandLine|contains|all:
            - ' -p'
            - ' x '
            - ' -o'
```

## windows/process_creation/proc_creation_win_attrib_system
```
detection:
    selection_img:
        - Image|endswith: '\attrib.exe'
        - OriginalFileName: 'ATTRIB.EXE'
    selection_cli:
        CommandLine|contains: ' +s '
```