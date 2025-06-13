# wtfdav - WebDAV Forensic Tool

param(
    [Parameter(HelpMessage="Minutes to search before service start")]
    [int]$BeforeMinutes = 2,
    
    [Parameter(HelpMessage="Minutes to search after service start")]
    [int]$AfterMinutes = 1,
    
    [Parameter(HelpMessage="Skip administrative privilege check")]
    [switch]$SkipAdminCheck
)

& {
    # Check for administrative privileges
    if (-not $SkipAdminCheck) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host "`nERROR: This script requires administrative privileges to read security event logs." -ForegroundColor Red
            Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
            Write-Host "`nAlternatively, use -SkipAdminCheck parameter to skip this check (some features may not work)." -ForegroundColor Gray
            return
        }
    }
    
	# Clear screen and display header
	Clear-Host
	Write-Host "`n`n"
	Write-Host "=================================================================================" -ForegroundColor Cyan
	Write-Host "                           wtfdav - WebDAV Forensic Tool                         " -ForegroundColor Yellow
	Write-Host "=================================================================================" -ForegroundColor Cyan
	Write-Host ""
	Write-Host "This script checks whether your Windows WebDAV client service is running" -ForegroundColor White
	Write-Host "and performs a forensic analysis to determine:" -ForegroundColor White
	Write-Host ""
	Write-Host "  • When the service started" -ForegroundColor Gray
	Write-Host "  • What process tree initiated it" -ForegroundColor Gray
	Write-Host "  • Related system events around the start time" -ForegroundColor Gray
	Write-Host "  • Possible triggers (Office, licensing, network changes, etc.)" -ForegroundColor Gray
	Write-Host ""
	Write-Host "This analysis helps identify why WebClient started, which is particularly" -ForegroundColor White
	Write-Host "relevant given the recent CVE-2025-33053 WebDAV vulnerability." -ForegroundColor Yellow
	Write-Host ""
	Write-Host "Event Search Window:" -ForegroundColor Cyan
	Write-Host "  • 2 minutes before service start" -ForegroundColor Gray
	Write-Host "  • 1 minute after service start" -ForegroundColor Gray
	Write-Host ""
	Write-Host "Note: This is a read-only analysis tool. No changes will be made to your system." -ForegroundColor DarkGray
	Write-Host ""
	Write-Host "WebDAV? More like wtfDAV amirite? :)" -ForegroundColor DarkCyan
	Write-Host "=================================================================================" -ForegroundColor Cyan
	Write-Host ""

    # Display system information
    Write-Host "System Information:" -ForegroundColor Cyan
    Write-Host "  Computer Name: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "  Windows Version: $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor Gray
    Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host ""
    
    # User input y/n
    $response = Read-Host "Do you want to continue? (Y/N)"
    if ($response -notmatch '^[Yy]') {
        Write-Host "`nAnalysis cancelled by user." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n`n"
    Write-Host "=== WebClient Service Forensic Analysis ===" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""

    # Check if WebClient service exists and get status
    try {
        $webClientService = Get-Service WebClient -ErrorAction Stop
    } catch {
        Write-Host "ERROR: WebClient service not found on this system." -ForegroundColor Red
        Write-Host "Details: $_" -ForegroundColor DarkGray
        return
    }

    Write-Host "WebClient Service Status: $($webClientService.Status)" -ForegroundColor $(if ($webClientService.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    Write-Host "Service Start Type: $($webClientService.StartType)" -ForegroundColor Gray

    if ($webClientService.Status -ne 'Running') {
        Write-Host "`nWebClient service is not currently running." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Note: Even though the service is stopped, it can be triggered to start by:" -ForegroundColor DarkGray
        Write-Host "  - Office applications accessing cloud documents" -ForegroundColor DarkGray
        Write-Host "  - Windows Explorer accessing WebDAV shares" -ForegroundColor DarkGray
        Write-Host "  - Various UWP apps requiring network file access" -ForegroundColor DarkGray
        Write-Host "  - Certain Windows features like Work Folders" -ForegroundColor DarkGray
        return
    }

    # Get process information using CIM (more compatible than WMI)
    try {
        $webClientCim = Get-CimInstance Win32_Service -Filter "Name='WebClient'" -ErrorAction Stop
        $processId = $webClientCim.ProcessId
    } catch {
        Write-Host "ERROR: Unable to query service information via CIM." -ForegroundColor Red
        Write-Host "Falling back to WMI..." -ForegroundColor Yellow
        try {
            $webClientWmi = Get-WmiObject Win32_Service -Filter "Name='WebClient'" -ErrorAction Stop
            $processId = $webClientWmi.ProcessId
        } catch {
            Write-Host "ERROR: Unable to query service information." -ForegroundColor Red
            return
        }
    }

    if ($processId -eq 0 -or -not $processId) {
        Write-Host "ERROR: Unable to determine WebClient process ID." -ForegroundColor Red
        return
    }

    # Get process start time
    $startTime = $null
    
    # Try CIM first (newer, more compatible)
    try {
        $processCim = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
        if ($processCim -and $processCim.CreationDate) {
            $startTime = $processCim.CreationDate
        }
    } catch {
        # Fallback to WMI
        try {
            $processWmi = Get-WmiObject Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
            if ($processWmi -and $processWmi.CreationDate) {
                $startTime = $processWmi.ConvertToDateTime($processWmi.CreationDate)
            }
        } catch {}
    }
    
    # Final fallback to Get-Process
    if (-not $startTime) {
        try {
            $process = Get-Process -Id $processId -ErrorAction Stop
            if ($process -and $process.StartTime) {
                $startTime = $process.StartTime
            }
        } catch {}
    }

    if (-not $startTime) {
        Write-Host "ERROR: Unable to determine process start time." -ForegroundColor Red
        Write-Host "Process ID: $processId" -ForegroundColor Yellow
        return
    }

    Write-Host "Process ID: $processId" -ForegroundColor Green
    Write-Host "Start Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
    
    # Calculate duration
    try {
        $duration = (Get-Date) - $startTime
        $durationStr = "{0} days, {1} hours, {2} minutes" -f $duration.Days, $duration.Hours, $duration.Minutes
        Write-Host "Running Duration: $durationStr" -ForegroundColor Green
    } catch {
        Write-Host "Running Duration: Unable to calculate" -ForegroundColor Yellow
    }
    Write-Host ""

    # Trace process tree
    function Get-ProcessTree {
        param($ProcessId, $Indent = 0, $Visited = @())
        
        # Prevent infinite loops
        if ($ProcessId -in $Visited) {
            return
        }
        $Visited += $ProcessId
        
        try {
            # Try CIM first
            $proc = $null
            try {
                $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
            } catch {
                # Fallback to WMI
                $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
            }
            
            if ($proc) {
                $spacing = "  " * $Indent
                $arrow = if ($Indent -gt 0) { "└─> " } else { "" }
                
                Write-Host "$spacing$arrow$($proc.Name) (PID: $ProcessId)" -ForegroundColor White
                
                # Get process details
                $owner = "Unknown"
                if ($proc -is [Microsoft.Management.Infrastructure.CimInstance]) {
                    # CIM method
                    try {
                        $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
                        if ($ownerInfo.ReturnValue -eq 0) {
                            $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                        }
                    } catch {}
                } else {
                    # WMI method
                    try {
                        $ownerInfo = $proc.GetOwner()
                        if ($ownerInfo.ReturnValue -eq 0) {
                            $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                        }
                    } catch {}
                }
                
                # Truncate long command lines
                $cmdLine = if ($proc.CommandLine) {
                    if ($proc.CommandLine.Length -gt 200) {
                        $proc.CommandLine.Substring(0, 197) + "..."
                    } else {
                        $proc.CommandLine
                    }
                } else {
                    "[No command line available]"
                }
                
                Write-Host "$spacing    Command: $cmdLine" -ForegroundColor Gray
                Write-Host "$spacing    Owner: $owner" -ForegroundColor Gray
                
                # Recurse to parent
                if ($proc.ParentProcessId -and $proc.ParentProcessId -ne 0 -and $Indent -lt 10) {
                    Get-ProcessTree -ProcessId $proc.ParentProcessId -Indent ($Indent + 1) -Visited $Visited
                }
            }
        } catch {
            Write-Host "$spacing    [Process information unavailable: $_]" -ForegroundColor DarkGray
        }
    }

    Write-Host "=== Process Tree ===" -ForegroundColor Yellow
    Get-ProcessTree -ProcessId $processId
    Write-Host ""

    # Define time windows for event search
    $searchStart = $startTime.AddMinutes(-$BeforeMinutes)
    $searchEnd = $startTime.AddMinutes($AfterMinutes)

    Write-Host "=== Related Events ($BeforeMinutes min before to $AfterMinutes min after start) ===" -ForegroundColor Yellow
    Write-Host "Time Window: $($searchStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($searchEnd.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host ""

    # Helper function to safely get events
    function Get-SafeEvents {
        param($LogName, $FilterHashtable)
        try {
            # Check if log exists
            $log = Get-WinEvent -ListLog $FilterHashtable.LogName -ErrorAction Stop
            if ($log.RecordCount -eq 0) {
                return @()
            }
            Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop
        } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
            Write-Host "  Log not found: $LogName" -ForegroundColor DarkGray
            @()
        } catch [System.UnauthorizedAccessException] {
            Write-Host "  Access denied to log: $LogName (requires admin rights)" -ForegroundColor DarkYellow
            @()
        } catch {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-Host "  Error reading $LogName : $($_.Exception.Message)" -ForegroundColor DarkGray
            }
            @()
        }
    }

    # System events
    Write-Host "--- System Events ---" -ForegroundColor Cyan
    $systemEvents = Get-SafeEvents -FilterHashtable @{
        LogName='System'
        StartTime=$searchStart
        EndTime=$searchEnd
    } | Where-Object { $_.Id -ne 10016 }  # Exclude DCOM errors

    if ($systemEvents) {
        $relevantSystemEvents = $systemEvents | Where-Object {
            $_.Id -in @(7036, 7035, 7040, 7045) -or  # Service events
            $_.ProviderName -match "Service Control Manager|Microsoft-Windows-DistributedCOM"
        }
        
        if ($relevantSystemEvents) {
            $relevantSystemEvents | Select-Object TimeCreated, Id, 
                @{n='Provider';e={$_.ProviderName.Split('-')[-1]}}, 
                @{n='Message';e={
                    $msg = $_.Message -replace '\r?\n', ' '
                    if ($msg.Length -gt 100) { $msg.Substring(0, 97) + "..." } else { $msg }
                }} |
                Sort-Object TimeCreated | Format-Table -AutoSize
        } else {
            Write-Host "  No relevant system events found." -ForegroundColor DarkGray
        }
    }

    # Application events
    Write-Host "`n--- Application Events ---" -ForegroundColor Cyan
    $appEvents = Get-SafeEvents -FilterHashtable @{
        LogName='Application'
        StartTime=$searchStart
        EndTime=$searchEnd
    }

    if ($appEvents) {
        $relevantAppEvents = $appEvents | Where-Object {
            $_.ProviderName -match "Security-SPP|Office|MsiInstaller|Microsoft-Windows-User Profiles Service" -or
            $_.Id -in @(1033, 1040, 11707, 16394, 1003, 1530, 1531)
        }
        
        if ($relevantAppEvents) {
            $relevantAppEvents | Select-Object TimeCreated, Id, 
                @{n='Provider';e={
                    $p = $_.ProviderName -replace 'Microsoft-Windows-', ''
                    if ($p.Length -gt 30) { $p.Substring(0, 27) + "..." } else { $p }
                }}, 
                @{n='Message';e={
                    $msg = $_.Message -replace '\r?\n', ' '
                    if ($msg.Length -gt 100) { $msg.Substring(0, 97) + "..." } else { $msg }
                }} |
                Sort-Object TimeCreated | Format-Table -AutoSize
        } else {
            Write-Host "  No relevant application events found." -ForegroundColor DarkGray
        }
    }

    # Security events (for logons)
    Write-Host "`n--- Security Events (Logons) ---" -ForegroundColor Cyan
    $securityEvents = Get-SafeEvents -FilterHashtable @{
        LogName='Security'
        StartTime=$searchStart
        EndTime=$searchEnd
        ID=4624
    }

    if ($securityEvents) {
        $logonTypes = @{
            2 = "Interactive"
            3 = "Network"
            4 = "Batch"
            5 = "Service"
            7 = "Unlock"
            8 = "NetworkCleartext"
            9 = "NewCredentials"
            10 = "RemoteInteractive"
            11 = "CachedInteractive"
        }
        
        $securityEvents | Select-Object TimeCreated, 
            @{n='LogonType';e={
                try {
                    [xml]$xml = $_.ToXml()
                    $typeNum = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
                    "$typeNum-$($logonTypes[[int]$typeNum])"
                } catch { "Unknown" }
            }},
            @{n='Account';e={
                try {
                    [xml]$xml = $_.ToXml()
                    $domain = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'
                    $user = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    "$domain\$user"
                } catch { "Unknown" }
            }},
            @{n='Process';e={
                try {
                    [xml]$xml = $_.ToXml()
                    ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessName'}).'#text' -replace '.*\\', ''
                } catch { "Unknown" }
            }} | Format-Table -AutoSize
    } else {
        Write-Host "  No logon events found (may require admin rights)." -ForegroundColor DarkGray
    }

    # Network events
    Write-Host "`n--- Network Events ---" -ForegroundColor Cyan
    $networkLogs = @(
        'Microsoft-Windows-NetworkProfile/Operational',
        'Microsoft-Windows-NCSI/Operational',
        'Microsoft-Windows-Dhcp-Client/Operational'
    )

    $foundNetworkEvents = $false
    foreach ($log in $networkLogs) {
        $netEvents = Get-SafeEvents -FilterHashtable @{
            LogName=$log
            StartTime=$searchStart
            EndTime=$searchEnd
        }
        
        if ($netEvents) {
            $foundNetworkEvents = $true
            Write-Host "  From $log :" -ForegroundColor Gray
            $netEvents | Select-Object TimeCreated, Id, 
                @{n='Message';e={
                    $msg = $_.Message -replace '\r?\n', ' '
                    if ($msg.Length -gt 100) { $msg.Substring(0, 97) + "..." } else { $msg }
                }} |
                Sort-Object TimeCreated | Format-Table -AutoSize
        }
    }
    
    if (-not $foundNetworkEvents) {
        Write-Host "  No network events found." -ForegroundColor DarkGray
    }

    # Task Scheduler events
    Write-Host "`n--- Task Scheduler Events ---" -ForegroundColor Cyan
    $taskEvents = Get-SafeEvents -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'
        StartTime=$searchStart
        EndTime=$searchEnd
    }

    if ($taskEvents) {
        $relevantTaskEvents = $taskEvents | Where-Object { $_.Id -in @(106, 107, 108, 119, 140, 141, 200, 201) }
        
        if ($relevantTaskEvents) {
            $relevantTaskEvents | Select-Object TimeCreated, Id, 
                @{n='Action';e={
                    switch($_.Id) {
                        106 {"Task Registered"}
                        107 {"Task Triggered"} 
                        108 {"Task Started"}
                        119 {"Task Queued"}
                        140 {"Task Updated"}
                        141 {"Task Deleted"}
                        200 {"Action Started"}
                        201 {"Action Completed"}
                        default {"Event $($_.Id)"}
                    }
                }},
                @{n='Task';e={
                    if ($_.Message -match 'Task[^"]*"([^"]+)"') { $matches[1] }
                    elseif ($_.Message -match '\\([^\\]+)$') { $matches[1] }
                    else { "Unknown" }
                }} | Sort-Object TimeCreated | Format-Table -AutoSize
        } else {
            Write-Host "  No relevant task scheduler events found." -ForegroundColor DarkGray
        }
    }

    # Office-specific events
    Write-Host "`n--- Office/OneDrive Events ---" -ForegroundColor Cyan
    $officeLogNames = @(
        'Microsoft Office Alerts',
        'OAlerts'
    )
    
    $foundOfficeEvents = $false
    foreach ($logName in $officeLogNames) {
        $officeEvents = Get-SafeEvents -FilterHashtable @{
            LogName=$logName
            StartTime=$searchStart
            EndTime=$searchEnd
        }
        
        if ($officeEvents) {
            $foundOfficeEvents = $true
            $officeEvents | Select-Object TimeCreated, Id, 
                @{n='Source';e={$_.ProviderName}},
                @{n='Message';e={
                    $msg = $_.Message -replace '\r?\n', ' '
                    if ($msg.Length -gt 100) { $msg.Substring(0, 97) + "..." } else { $msg }
                }} | Format-Table -AutoSize
        }
    }
    
    if (-not $foundOfficeEvents) {
        Write-Host "  No Office/OneDrive specific events found." -ForegroundColor DarkGray
    }

    # Summary
    Write-Host "`n=== Analysis Summary ===" -ForegroundColor Yellow
    Write-Host "WebClient has been running since: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green

    # Check for common triggers
    $triggers = @()
    $triggerDetails = @()
    
    if ($appEvents | Where-Object {$_.ProviderName -match "Security-SPP"}) {
        $triggers += "Software Protection Platform (licensing check)"
        $triggerDetails += "Windows or Office license validation occurred"
    }
    if ($appEvents | Where-Object {$_.ProviderName -match "Office"}) {
        $triggers += "Microsoft Office activity"
        $triggerDetails += "Office application accessed cloud resources"
    }
    if ($systemEvents | Where-Object {$_.Message -match "OneDrive|SharePoint"}) {
        $triggers += "Cloud storage service"
        $triggerDetails += "OneDrive or SharePoint sync activity"
    }
    if ($foundNetworkEvents) {
        $triggers += "Network connectivity change"
        $triggerDetails += "Network profile changed or connection established"
    }
    if ($taskEvents | Where-Object {$_.Message -match "Office|OneDrive|Update"}) {
        $triggers += "Scheduled task execution"
        $triggerDetails += "Scheduled task related to Office/OneDrive ran"
    }

    if ($triggers.Count -gt 0) {
        Write-Host "`nPossible triggers detected:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $triggers.Count; $i++) {
            Write-Host "  - $($triggers[$i])" -ForegroundColor Green
            Write-Host "    $($triggerDetails[$i])" -ForegroundColor Gray
        }
    } else {
        Write-Host "`nNo obvious triggers detected in the time window." -ForegroundColor Yellow
        Write-Host "Consider expanding the search window with -BeforeMinutes and -AfterMinutes parameters." -ForegroundColor Gray
    }

    # Additional recommendations
    Write-Host "`n=== Recommendations ===" -ForegroundColor Yellow
    Write-Host "1. If WebClient is not needed, consider disabling it:" -ForegroundColor White
    Write-Host "   Set-Service -Name WebClient -StartupType Disabled" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. To stop the service immediately:" -ForegroundColor White
    Write-Host "   Stop-Service -Name WebClient" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. For CVE-2025-33053 mitigation, check for patches:" -ForegroundColor White
    Write-Host "   https://msrc.microsoft.com/update-guide/" -ForegroundColor Gray

    Write-Host "`nScript completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}
