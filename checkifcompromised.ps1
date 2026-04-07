<#
.SYNOPSIS
    Incident response script for checking whether a Windows Server shows signs of compromise.

.DESCRIPTION
    This script is designed for incident response and ransomware investigations.
    It can be adjusted or expanded with incident-specific checks as needed.
    The default focus is to determine whether a Windows Server is also compromised
    during an active incident response case.

.USAGE
    Optionally pass target IPs and usernames:
        .\checkifcompromised.ps1 -TargetIPs "10.0.0.10","10.0.0.11" -TargetUsers "alice","bob"

    If no target IPs or usernames are provided, the script will prompt for them.
    If you leave them empty, the script continues and runs all other checks.
#>

# IR Script for Compromise Assessment - Enterprise Edition v3.0
# Merges Deep Forensics with High-Performance Auditing
# Features: Wildcard Account Search, RMM Log Analysis, Process Correlation, PS History, Scheduled Tasks

param(
    [string[]]$TargetIPs,
    [string[]]$TargetUsers
)

$compromised = $false
$lookbackDays = 30
$lookbackStart = (Get-Date).AddDays(-$lookbackDays)
$ErrorActionPreference = "SilentlyContinue"
$executingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$executingUserShort = ($executingUser -split '\\')[-1]

# --- CONFIGURATION ---
# Azure Storage Account Configuration
$STORAGE_ACCOUNT = "<STORAGE_ACCOUNT>"
$CONTAINER = "<CONTAINER_NAME>"
$SAS_TOKEN = "<SAS_TOKEN>"
$BLOB_NAME = "$env:COMPUTERNAME-result-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
$OUTPUT_FILE = "$env:TEMP\$BLOB_NAME"

$maliciousIPs = if ($TargetIPs -and $TargetIPs.Count -gt 0) { @($TargetIPs | Where-Object { $_ -and $_.Trim() }) } else { @() }
if (-not $maliciousIPs -or $maliciousIPs.Count -eq 0) {
    $promptIPs = Read-Host "Enter suspicious or malicious IPs separated by commas, or press Enter to skip"
    $maliciousIPs = if ($promptIPs) {
        @($promptIPs -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else {
        @()
    }
}

$targetUsers = if ($TargetUsers -and $TargetUsers.Count -gt 0) { @($TargetUsers | Where-Object { $_ -and $_.Trim() }) } else { @() }
if (-not $targetUsers -or $targetUsers.Count -eq 0) {
    $promptUsers = Read-Host "Enter usernames or UPN fragments separated by commas, or press Enter to skip"
    $targetUsers = if ($promptUsers) {
        @($promptUsers -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else {
        @()
    }
}

# Streamlined wildcard patterns derived from supplied usernames. Empty means account-focused checks are skipped.
$targetPatterns = @()
foreach ($u in $targetUsers) {
    $targetPatterns += "*$u*"
}

# RMM Tools to hunt for
$rmmProcesses = @("TeamViewer", "AnyDesk", "Ammyy", "ScreenConnect", "ConnectWise", "LogMeIn", "Atera", "NinjaOne", "Splashtop")

function Write-IRResult {
    param([string]$Message, [bool]$Found, [string]$Level="Info")
    
    $outputLine = ""
    if ($Found) {
        $outputLine = " [!] $Message"
        Write-Host $outputLine -ForegroundColor Red
    } else {
        if ($Level -eq "Info") {
            $outputLine = " [i] $Message"
            Write-Host $outputLine -ForegroundColor DarkGray
        } else {
            $outputLine = " [+] $Message"
            Write-Host $outputLine -ForegroundColor Green
        }
    }
    try {
        $outputLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Suppress errors if file cannot be written (e.g., network issue)
    }
}

function Write-Section {
    param([string]$Title)
    $sectionLine = "`n--- $Title ---"
    Write-Host $sectionLine -ForegroundColor Cyan
    try {
        $sectionLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Suppress errors if file cannot be written (e.g., network issue)
    }
}

function Resolve-Shortcut {
    param($Path)
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($Path)
        return @{
            TargetPath = $sc.TargetPath
            Arguments  = $sc.Arguments
        }
    } catch {
        return @{
            TargetPath = "ERROR"
            Arguments  = "ERROR"
        }
    }
}

function Get-BinaryLastWrite {
    param($Path)

    if (-not $Path) { return $null }

    if ($Path -match '^"([^"]+)"') {
        $bin = $matches[1]
    } else {
        $bin = $Path -split '\s+' | Select-Object -First 1
    }

    if (Test-Path $bin) {
        try {
            return (Get-Item $bin).LastWriteTime
        } catch {
            return $null
        }
    }

    return $null
}

function Get-EventDataValue {
    param(
        [xml]$Xml,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($node -and $node.'#text') {
            return $node.'#text'
        }
    }

    return $null
}

function Get-LogonProtocol {
    param([string]$LogonType)

    switch ($LogonType) {
        "2"  { "Interactive" }
        "3"  { "Network" }
        "4"  { "Batch" }
        "5"  { "Service" }
        "7"  { "Unlock" }
        "8"  { "NetworkCleartext" }
        "9"  { "NewCredentials" }
        "10" { "RDP" }
        "11" { "CachedInteractive" }
        default { if ($LogonType) { "LogonType $LogonType" } else { $null } }
    }
}

function Get-SourceDeviceLabel {
    param([string]$DeviceName, [string]$WorkstationName, [string]$IpAddress)

    if ($DeviceName) { return $DeviceName }
    if ($WorkstationName) { return $WorkstationName }
    if ($IpAddress) { return $IpAddress }
    return $null
}

function Get-MatchSnippet {
    param(
        [string]$Text,
        [string]$Pattern,
        [int]$MaxLength = 180
    )

    if (-not $Text -or -not $Pattern) { return $null }

    try {
        $match = [regex]::Match($Text, $Pattern)
        if ($match.Success) {
            $snippet = $match.Value
            if ($snippet.Length -gt $MaxLength) {
                return $snippet.Substring(0, $MaxLength) + "..."
            }
            return $snippet
        }
    } catch {
        return $null
    }

    return $null
}

function Get-CurrentUserPaths {
    $result = @()
    $candidates = @(
        $executingUserShort,
        ($executingUser -split '\\')[-1]
    ) | Select-Object -Unique

    foreach ($candidate in $candidates) {
        if ($candidate) { $result += $candidate }
    }

    return $result
}

function Test-IsExecutingUserProfile {
    param([string]$Path)

    if (-not $Path) { return $false }

    $leaf = Split-Path $Path -Leaf
    foreach ($candidate in (Get-CurrentUserPaths)) {
        if ($leaf -ieq $candidate) { return $true }
    }

    return $false
}

Write-Host "==============================================" -ForegroundColor Cyan
"==============================================" | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
Write-Host "   INCIDENT RESPONSE FORENSICS - v3.0" -ForegroundColor White
"   INCIDENT RESPONSE FORENSICS - v3.0" | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
Write-Host "   Lookback Period: $lookbackDays days | Start: $lookbackStart" -ForegroundColor Gray
"   Lookback Period: $lookbackDays days | Start: $lookbackStart" | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
Write-Host "==============================================" -ForegroundColor Cyan
"==============================================" | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue

# Incident response flow:
# 1) Check for remote access, suspicious logons, and lateral movement.
# 2) Review PowerShell activity and user history for command evidence.
# 3) Look for persistence, autostart changes, and file-based indicators.
# 4) Capture log integrity and anti-forensics signals before final summary.

# --- 1. AMMY & RMM Service Check ---
# RMM services are checked first because remote admin tools often indicate
# unauthorized access, helpdesk abuse, or attacker-controlled remote sessions.
Write-Section "Checking RMM Services"
try {
    $foundSvcs = Get-Service | Where-Object { 
        $n = $_.Name; $d = $_.DisplayName; 
        $rmmProcesses | ForEach-Object { if ($n -like "*$_*" -or $d -like "*$_*") { return $true } }
    }
    
    if ($foundSvcs) {
        foreach ($s in $foundSvcs) {
            Write-IRResult "Suspicious Service Found: $($s.Name) ($($s.DisplayName)) - Status: $($s.Status)" $true
            $compromised = $true
        }
    } else {
        Write-IRResult "No malicious RMM services detected in Service Control Manager." $false "Success"
    }
} catch { Write-Host "Error accessing Service Manager." -ForegroundColor Red }

# --- 2. Network Connection Check (Malicious IPs) ---
# Active connections to known bad IPs can confirm C2 traffic or live access
# from tooling already present on the host.
Write-Section "Network Connection Analysis"
if ($maliciousIPs.Count -gt 0) {
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $maliciousIPs -contains $_.RemoteAddress }
    if ($conns) {
        $conns | ForEach-Object { 
            Write-IRResult "ACTIVE CONNECTION TO C2/MALICIOUS IP: $($_.RemoteAddress) (State: $($_.State))" $true
            $compromised = $true 
        }
    } else { 
        Write-IRResult "No active connections to known malicious IPs." $false "Success" 
    }
} else {
    Write-IRResult "Skipping IP-based connection analysis because no target IPs were provided." $false "Success"
}
# --- 3. Account Logon & Lateral Movement Indicators ---
# This section extracts exact logon evidence for targeted accounts and keeps
# the output focused on the real username, source device, and source IP.
Write-Section "Logon Audit & Lateral Movement"
Write-Host " [i] Executing user excluded from investigation scope: $executingUser" -ForegroundColor DarkGray
" [i] Executing user excluded from investigation scope: $executingUser" | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
if ($targetUsers.Count -eq 0) {
    Write-Host " [i] No target usernames provided. Account-focused checks will be skipped." -ForegroundColor DarkGray
    " [i] No target usernames provided. Account-focused checks will be skipped." | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}
if ($maliciousIPs.Count -eq 0) {
    Write-Host " [i] No target IPs provided. IP-based checks will be skipped." -ForegroundColor DarkGray
    " [i] No target IPs provided. IP-based checks will be skipped." | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}
$logonFindings = @()

function Test-TargetAccount {
    param([string]$User)

    if (-not $User) { return $false }
    if (-not $targetPatterns -or $targetPatterns.Count -eq 0) { return $false }
    foreach ($p in $targetPatterns) {
        $needle = $p.Replace("*", "")
        if ($needle -and $User -like "*$needle*") {
            return $true
        }
    }
    return $false
}

# 3.1 Security Log (4624) - exact event details
$securityLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
foreach ($log in $securityLogs) {
    $xml = [xml]$log.ToXml()
    $user = Get-EventDataValue -Xml $xml -Names @("TargetUserName","SubjectUserName","AccountName")
    $domain = Get-EventDataValue -Xml $xml -Names @("TargetDomainName","SubjectDomainName")
    $ip = Get-EventDataValue -Xml $xml -Names @("IpAddress","SourceNetworkAddress")
    $workstation = Get-EventDataValue -Xml $xml -Names @("WorkstationName","ClientName","SourceWorkstation")
    $logonType = Get-EventDataValue -Xml $xml -Names @("LogonType")
    $protocol = Get-LogonProtocol $logonType

    if (-not $user -or $user -in @("SYSTEM","ANONYMOUS LOGON","LOCAL SERVICE","NETWORK SERVICE","-")) { continue }
    if ($domain -and $user -and $user -notmatch '\\' -and $domain -ne "-" -and $domain -ne "NT AUTHORITY") {
        $displayUser = "$domain\$user"
    } else {
        $displayUser = $user
    }

    if ($displayUser -and $displayUser -like "*$executingUserShort*") { continue }
    if (-not (Test-TargetAccount $displayUser)) { continue }

    $sourceDevice = $workstation
    $logonFindings += [PSCustomObject]@{
        Time         = $log.TimeCreated
        Username     = $displayUser
        Protocol     = $protocol
        SourceDevice = $sourceDevice
        SourceIP     = $ip
        LogonType    = $logonType
        EventID      = 4624
        SourceLog    = "Security"
    }

    if ($log.Message -match "PSEXESVC.exe") {
        Write-IRResult "Lateral Movement Indicator: PSEXESVC.exe detected in Security Log! | Time: $($log.TimeCreated)" $true
        $compromised = $true
    }
}

# 3.2 RDP Operational Log (1149) - exact event details
$rdpLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
foreach ($ev in $rdpLogs) {
    $xml = [xml]$ev.ToXml()
    $user = Get-EventDataValue -Xml $xml -Names @("User","TargetUserName","Param1")
    $ip = Get-EventDataValue -Xml $xml -Names @("SourceNetworkAddress","Param2","Param3")
    $device = Get-EventDataValue -Xml $xml -Names @("WorkstationName","ClientName","Param3")

    if ($user -and $user -like "*$executingUserShort*") { continue }
    if (-not (Test-TargetAccount $user)) { continue }

    $logonFindings += [PSCustomObject]@{
        Time         = $ev.TimeCreated
        Username     = $user
        Protocol     = "RDP"
        SourceDevice = $device
        SourceIP     = $ip
        LogonType    = "1149"
        EventID      = 1149
        SourceLog    = "TerminalServices-RemoteConnectionManager/Operational"
    }
}

# --- 3. High-Performance Logon Audit ---
# Secondary logon view used as the consolidated incident overview. It is
# intended for analysts who want a quick read of who logged on, from where,
# and by which protocol.
Write-Section "Detailed Logon Audit (Security, RDP, WinRM)"

if ($logonFindings.Count -gt 0) {
    Write-IRResult "Logon activity detected for targeted accounts:" $true
    $logonFindings |
        Sort-Object Time -Descending |
        Select-Object -Unique Time, Username, Protocol, SourceDevice, SourceIP, LogonType, EventID, SourceLog |
        ForEach-Object {
            $sourceDevice = if ($_.SourceDevice) { $_.SourceDevice } else { "-" }
            $sourceIP = if ($_.SourceIP) { $_.SourceIP } else { "-" }
            $logonDetailLine = "    [$($_.Time)] User: $($_.Username) | Protocol: $($_.Protocol) | Device: $sourceDevice | IP: $sourceIP | EventID: $($_.EventID)"
            Write-Host $logonDetailLine -ForegroundColor Yellow
            $logonDetailLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    $compromised = $true
} else {
    Write-IRResult "No logon activity for target accounts found." $false "Success"
}

# --- 4. RMM Process & Log Analysis ---
# Process-level checks correlate running RMM tools with live connections and
# vendor-specific logs so persistence and remote control are not missed.
Write-Section "Advanced RMM Analysis (Process & Logs)"

# 4.1 Active Process Correlation
foreach ($rmm in $rmmProcesses) {
    $procs = Get-CimInstance Win32_Process -Filter "Name LIKE '%$rmm%'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $owner = ($p | Invoke-CimMethod -MethodName GetOwner).User
        if ($owner -like "*$executingUser*") { continue }
        $pConns = Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $p.ProcessId -and $_.State -eq "Established" }
        if ($pConns) {
            $ips = ($pConns.RemoteAddress | Select-Object -Unique) -join ", "
            Write-IRResult "ACTIVE REMOTE SESSION: $rmm (PID: $($p.ProcessId), User: $owner) -> Connected to: $ips" $true
            $compromised = $true
        } else {
            Write-IRResult "RMM Process running: $rmm (PID: $($p.ProcessId)) - No active network connection." $false "Info"
        }
    }
}

# 4.2 File Log Analysis (AnyDesk/TeamViewer)
$tvPaths = @("C:\Program Files (x86)\TeamViewer\Connections_incoming.txt", "C:\Program Files\TeamViewer\Connections_incoming.txt")
foreach ($path in $tvPaths) {
    if (Test-Path $path) {
        try {
            $lines = Get-Content $path -ErrorAction SilentlyContinue | Where-Object { $_ -match "\d{2}-\d{2}-\d{4}" }
            $recent = $lines | Where-Object { [DateTime]::ParseExact(($_.Split("`t")[2].Trim()), "dd-MM-yyyy HH:mm:ss", $null) -ge $lookbackStart }
            if ($recent) {
                Write-IRResult "TeamViewer Incoming Connections (Last $lookbackDays days) found in $path" $true
                $recent | Select-Object -Last 5 | ForEach-Object { 
                    $tvLine = "    > $_"
                    Write-Host $tvLine -ForegroundColor Yellow 
                    $tvLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                }
                $compromised = $true
            }
        } catch {}
    }
}

$adTrace = "$env:ProgramData\AnyDesk\ad.trace"
if (Test-Path $adTrace) {
    $matches = Select-String -Path $adTrace -Pattern "connection","accepted" -Context 0,1 | Select-Object -Last 5
    if ($matches) {
        Write-IRResult "AnyDesk Trace Log Activity ($adTrace)" $true
        $matches | ForEach-Object { 
            $adLine = "    > $($_.Line.Trim())"
            Write-Host $adLine -ForegroundColor Yellow 
            $adLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        $compromised = $true
    }
}

# --- 5. PowerShell Forensics (Events & History Files) ---
# PowerShell activity often contains attacker tradecraft. This block checks
# script-block events, legacy payload indicators, and command history files.
Write-Section "PowerShell Forensics"

# 5.1 Event Log Indicators (uTox & Shellcode Patterns)
$psEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
$suspiciousBlocks = $psEvents | Where-Object { 
    $_.Message -match "blueclouds8666/uTox_XP" -or 
    $_.Message -match "raw.github" -or 
    ($_.Message -match "VA\(" -and $_.Message -match "OP\(") 
}
if ($suspiciousBlocks) {
    Write-IRResult "Suspicious Script Block Execution (uTox/Shellcode) detected!" $true
    $suspiciousBlocks | Select-Object -First 5 | ForEach-Object { 
        $evLine = "    [!] $($_.TimeCreated) | ID: $($_.Id)"
        Write-Host $evLine -ForegroundColor Red 
        $evLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    $compromised = $true
} else {
    Write-IRResult "No suspicious script blocks (uTox patterns) in Event Logs." $false "Success"
}

# 5.2 Legacy PowerShell Indicators From Old Script
$legacyPowershellIndicators = @(
    @{
        Label = "Legacy uTox download indicator"
        Pattern = "https://raw.githubusercontent.com/blueclouds8666/uTox_XP/"
        Message = "Suspicious PowerShell script used to download the uTox client."
    },
    @{
        Label = "Legacy shellcode injector indicator"
        Pattern = 'if\(\$x\)\{\$h=\$i::OP\(0x1F0FFF,0,\$x\);if\(\$h\)\{\$m=\$i::VA\(\$h,0,\$S.Length,0x3000,0x40\);'
        Message = "Suspicious PowerShell script with the targeted shellcode pattern."
    }
)

foreach ($indicator in $legacyPowershellIndicators) {
    $matches = $psEvents | Where-Object { $_.Message -match $indicator.Pattern }
    if ($matches) {
        if ($indicator.Label -eq "Legacy uTox download indicator") {
            if (Test-Path "C:\Windows\utox.exe") {
                Write-IRResult $indicator.Message $true
                $matches | Select-Object -First 3 | ForEach-Object {
                    $line = "    [!] $($_.TimeCreated) | ID: $($_.Id) | $($indicator.Label) | Binary present: C:\Windows\utox.exe"
                    Write-Host $line -ForegroundColor Red
                    $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                }
                $compromised = $true
            }
        } else {
            Write-IRResult $indicator.Message $true
            $matches | Select-Object -First 3 | ForEach-Object {
                $snippet = Get-MatchSnippet -Text $_.Message -Pattern $indicator.Pattern -MaxLength 180
                if (-not $snippet) { $snippet = "Matched targeted shellcode pattern." }
                $line = "    [!] $($_.TimeCreated) | ID: $($_.Id) | $($indicator.Label) | Snippet: $snippet"
                Write-Host $line -ForegroundColor Red
                $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            $compromised = $true
        }
    } else {
        if ($indicator.Label -eq "Legacy uTox download indicator") {
            Write-IRResult "No uTox download script detected in PowerShell event logs." $false "Success"
        } else {
            Write-IRResult "No targeted shellcode-style PowerShell script detected in PowerShell event logs." $false "Success"
        }
    }
}

# 5.3 Per-User PSReadLine History Collection
# Read each profile's PSReadLine history and exclude the executing account to
# avoid mixing investigator activity with incident evidence.
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
$historyPaths = @()

foreach ($profile in $userProfiles) {
    if (Test-IsExecutingUserProfile $profile.FullName) { continue }
    $profileName = $profile.Name
    $historyPaths += [PSCustomObject]@{
        User = $profileName
        Path = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
    $historyPaths += [PSCustomObject]@{
        User = $profileName
        Path = Join-Path $profile.FullName "AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
}

$historySeen = @{}
$historyFoundCount = 0

foreach ($entry in $historyPaths) {
    if ($historySeen.ContainsKey($entry.Path)) { continue }
    $historySeen[$entry.Path] = $true

    if (Test-Path $entry.Path) {
        $historyFoundCount++
        try {
            $item = Get-Item $entry.Path
            $header = "History File: $($entry.Path) | LastWriteTime: $($item.LastWriteTime)"
            Write-Host $header -ForegroundColor Yellow
            $header | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue

            $content = Get-Content -Path $entry.Path -ErrorAction SilentlyContinue
            if ($content) {
                $allLines = @($content)
                $totalCommands = $allLines.Count
                $displayLines = $allLines
                $startLineNr = 1

                if ($totalCommands -gt 100) {
                    $displayLines = $allLines | Select-Object -Last 100
                    $startLineNr = $totalCommands - $displayLines.Count + 1
                    $truncLine = "    ... truncated to latest 100 commands (total: $totalCommands)"
                    Write-Host $truncLine -ForegroundColor DarkYellow
                    $truncLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                }

                $lineNr = $startLineNr
                foreach ($line in $displayLines) {
                    $historyLine = "    [$($lineNr.ToString('0000'))] $line"
                    Write-Host $historyLine -ForegroundColor Gray
                    $historyLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                    $lineNr++
                }
            } else {
                $emptyLine = "    (File is empty)"
                Write-Host $emptyLine -ForegroundColor DarkGray
                $emptyLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        } catch {
            $errorLine = "History File: $($entry.Path) | Access denied or unreadable"
            Write-Host $errorLine -ForegroundColor Red
            $errorLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    }
}

if ($historyFoundCount -eq 0) {
    Write-IRResult "No user PSReadLine ConsoleHost history files found under C:\Users." $false "Success"
}

# 5.4 Transcript Search For Any Existing Users
# PowerShell transcripts can preserve commands that never reached the event
# log, so this complements the PSReadLine history review.
$transcriptRoots = $userProfiles.FullName
foreach ($root in $transcriptRoots) {
    if (Test-IsExecutingUserProfile $root) { continue }
    $transcriptPath = Join-Path $root "Documents\PowerShell\Transcripts"
    if (Test-Path $transcriptPath) {
        $transcripts = Get-ChildItem $transcriptPath -Filter "*.txt" -ErrorAction SilentlyContinue
        foreach ($file in $transcripts) {
            $item = Get-Item $file.FullName -ErrorAction SilentlyContinue
            if ($item) {
                $line = "Transcript File: $($item.FullName) | LastWriteTime: $($item.LastWriteTime)"
                Write-Host $line -ForegroundColor DarkGray
                $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
    }
}

# 5.5 Suspicious Process Creation Review (Security 4688)
# High-risk process creation is a strong local signal for LOLBin abuse,
# payload staging, or credential-theft tooling.
Write-Section "Suspicious Process Creation Review (Security 4688)"
$procCreateEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
$procFindings = @()
$highRiskProcessNames = @(
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "schtasks.exe",
    "vssadmin.exe",
    "wevtutil.exe",
    "procdump.exe",
    "mimikatz.exe",
    "rclone.exe",
    "curl.exe",
    "wget.exe",
    "wscript.exe",
    "cscript.exe",
    "nc.exe",
    "netcat.exe"
)
$highRiskCommandPatterns = @(
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-webrequest",
    "start-bitstransfer",
    "comsvcs.dll",
    "minidump",
    "sekurlsa",
    "lsass",
    "mimikatz",
    "procdump"
)

foreach ($ev in $procCreateEvents) {
    $xml = [xml]$ev.ToXml()
    $creatorUser = Get-EventDataValue -Xml $xml -Names @("SubjectUserName","TargetUserName")
    $creatorDomain = Get-EventDataValue -Xml $xml -Names @("SubjectDomainName","TargetDomainName")
    $newProcess = Get-EventDataValue -Xml $xml -Names @("NewProcessName","ProcessName")
    $cmdLine = Get-EventDataValue -Xml $xml -Names @("CommandLine")
    $parentProcess = Get-EventDataValue -Xml $xml -Names @("ParentProcessName","CreatorProcessName")

    if ($creatorUser -and $creatorUser -like "*$executingUserShort*") { continue }
    if (-not $newProcess) { continue }

    $displayUser = if ($creatorDomain -and $creatorUser -and $creatorDomain -ne "-" -and $creatorDomain -ne "NT AUTHORITY") {
        "$creatorDomain\$creatorUser"
    } else {
        $creatorUser
    }

    $newProcessLower = $newProcess.ToLowerInvariant()
    $cmdLower = if ($cmdLine) { $cmdLine.ToLowerInvariant() } else { "" }
    $highRiskMatch = $false

    foreach ($name in $highRiskProcessNames) {
        if ($newProcessLower -like "*$name*") {
            $highRiskMatch = $true
            break
        }
    }

    if (-not $highRiskMatch) {
        foreach ($pattern in $highRiskCommandPatterns) {
            if ($cmdLower -match [regex]::Escape($pattern)) {
                $highRiskMatch = $true
                break
            }
        }
    }

    if ($highRiskMatch) {
        $procFindings += [PSCustomObject]@{
            Time        = $ev.TimeCreated
            User        = $displayUser
            Process     = $newProcess
            Parent      = $parentProcess
            CommandLine = $cmdLine
            EventID     = 4688
        }
    }
}

if ($procFindings.Count -gt 0) {
    Write-IRResult "Suspicious process creation detected:" $true
    $procFindings |
        Sort-Object Time -Descending |
        Select-Object -Unique Time, User, Process, Parent, CommandLine |
        ForEach-Object {
            $parent = if ($_.Parent) { $_.Parent } else { "-" }
            $cmd = if ($_.CommandLine) { $_.CommandLine } else { "-" }
            $line = "    [$($_.Time)] User: $($_.User) | Process: $($_.Process) | Parent: $parent"
            Write-Host $line -ForegroundColor Yellow
            $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            $cmdLine = "      CommandLine: $cmd"
            Write-Host $cmdLine -ForegroundColor DarkGray
            $cmdLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    $compromised = $true
} else {
    Write-IRResult "No suspicious process creation events found in Security 4688." $false "Success"
}

# 5.6 Defender Tamper Review
# Local Defender settings are checked for disabled protections or added
# exclusions that can support payload execution and AV bypass.
Write-Section "Defender Tamper Review"
$defenderFindings = @()

try {
    $mp = Get-MpPreference

    $defenderFlags = @(
        @{ Name = "DisableRealtimeMonitoring"; Value = $mp.DisableRealtimeMonitoring },
        @{ Name = "DisableBehaviorMonitoring"; Value = $mp.DisableBehaviorMonitoring },
        @{ Name = "DisableIOAVProtection"; Value = $mp.DisableIOAVProtection },
        @{ Name = "DisableScriptScanning"; Value = $mp.DisableScriptScanning }
    )

    foreach ($flag in $defenderFlags) {
        if ($flag.Value -eq $true) {
            $defenderFindings += [PSCustomObject]@{
                Type  = "DefenderSetting"
                Name  = $flag.Name
                Value = $flag.Value
            }
        }
    }

    $exclusionLists = @(
        @{ Name = "ExclusionPath"; Values = $mp.ExclusionPath },
        @{ Name = "ExclusionProcess"; Values = $mp.ExclusionProcess },
        @{ Name = "ExclusionExtension"; Values = $mp.ExclusionExtension },
        @{ Name = "ExclusionIpAddress"; Values = $mp.ExclusionIpAddress },
        @{ Name = "AttackSurfaceReductionOnlyExclusions"; Values = $mp.AttackSurfaceReductionOnlyExclusions },
        @{ Name = "ControlledFolderAccessAllowedApplications"; Values = $mp.ControlledFolderAccessAllowedApplications }
    )

    foreach ($list in $exclusionLists) {
        foreach ($item in @($list.Values)) {
            if ($item) {
                $defenderFindings += [PSCustomObject]@{
                    Type  = "DefenderExclusion"
                    Name  = $list.Name
                    Value = $item
                }
            }
        }
    }
} catch {
    # Defender module may be unavailable or access can be restricted.
}

$policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (Test-Path $policyKey) {
    $policyProps = Get-ItemProperty $policyKey -ErrorAction SilentlyContinue
    foreach ($prop in $policyProps.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" }) {
        if ($prop.Value -in @($true, 1, "1")) {
            $defenderFindings += [PSCustomObject]@{
                Type  = "DefenderPolicy"
                Name  = $prop.Name
                Value = $prop.Value
            }
        }
    }
}

if ($defenderFindings.Count -gt 0) {
    Write-IRResult "Defender tamper indicators found:" $true
    $defenderFindings |
        Sort-Object Type, Name, Value -Unique |
        ForEach-Object {
            $line = "    [$($_.Type)] $($_.Name) = $($_.Value)"
            Write-Host $line -ForegroundColor Yellow
            $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    $compromised = $true
} else {
    Write-IRResult "No obvious Defender tamper settings or exclusions found." $false "Success"
}

# --- 6. Scheduled Task Persistence ---
# Scheduled tasks are a common persistence mechanism. This checks for newly
# created tasks within the shared lookback window and filters out routine system noise.
Write-Section "Scheduled Task Analysis (Last $lookbackDays Days)"
$taskEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"; ID=106; StartTime=$lookbackStart} -ErrorAction SilentlyContinue

if ($taskEvents) {
    # Extract task names and filter out UpdateOrchestrator
    $tasks = $taskEvents | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $name = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"} | Select-Object -ExpandProperty "#text"
        if ($name -notlike "*\Microsoft\Windows\UpdateOrchestrator\*") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                TaskName = $name
            }
        }
    } | Where-Object { $_ -ne $null }

    if ($tasks) {
        $totalFound = $tasks.Count
        $displayTasks = $tasks | Select-Object -First 10
        foreach ($t in $displayTasks) {
            Write-IRResult "New Task Created: $($t.TimeCreated) -> $($t.TaskName)" $true
            $compromised = $true
        }
        if ($totalFound -gt 10) {
            $taskCountLine = "    ... and $($totalFound - 10) more tasks were created in this period."
            Write-Host $taskCountLine -ForegroundColor Gray
            $taskCountLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } else {
         Write-IRResult "No new (non-system) scheduled tasks registered in the last $lookbackDays days." $false "Success"
    }
} else {
    Write-IRResult "No new scheduled tasks registered in the last $lookbackDays days." $false "Success"
}

# --- 7. File System Indicators ---
# File checks catch concrete artifacts from compromise, ransomware, or remote
# admin tooling that may not show up cleanly in logs.
Write-Section "File System Indicators"
$indicators = @("C:\Windows\utox.exe", "C:\Windows\PSEXESVC.exe")
foreach ($i in $indicators) { 
    if (Test-Path $i) { Write-IRResult "Malicious Artifact Found: $i" $true; $compromised = $true } 
}

# Targeted Ransomware Search (HTA and .wait files)
$searchFolders = @("C:\", "C:\Users")
foreach ($folder in $searchFolders) {
    $htaFiles = Get-ChildItem -Path $folder -Filter "help.hta" -Recurse -Depth 5 -ErrorAction SilentlyContinue
    $waitFiles = Get-ChildItem -Path $folder -Filter "*.wait" -Recurse -Depth 5 -ErrorAction SilentlyContinue
    
    foreach ($f in $htaFiles) { Write-IRResult "Ransomware Note Found: $($f.FullName)" $true; $compromised = $true }
    foreach ($f in $waitFiles) { Write-IRResult "Encrypted File Pattern (*.wait) Found: $($f.FullName)" $true; $compromised = $true }
}

# 7.1 Credential Dump Artifact Review
# LSASS and credential-dump filenames are strong local evidence of memory
# theft activity, especially when they appear in temp or staging locations.
Write-Section "Credential Dump Artifact Review"
$dumpRoots = @(
    $env:TEMP,
    "$env:WINDIR\Temp",
    "$env:ProgramData"
)

foreach ($profile in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
    if (Test-IsExecutingUserProfile $profile.FullName) { continue }
    $dumpRoots += (Join-Path $profile.FullName "AppData\Local\Temp")
}

$dumpPatterns = @(
    "*lsass*.dmp",
    "*sam*.dmp",
    "*sekurlsa*",
    "*mimikatz*",
    "*procdump*",
    "*cred*dump*",
    "*dump*.dmp"
)

$dumpFindings = @()
foreach ($root in ($dumpRoots | Select-Object -Unique)) {
    if (-not $root -or -not (Test-Path $root)) { continue }
    foreach ($pattern in $dumpPatterns) {
        $matches = Get-ChildItem -Path $root -Filter $pattern -File -Recurse -Depth 4 -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $lookbackStart }
        foreach ($item in $matches) {
            $dumpFindings += [PSCustomObject]@{
                Time  = $item.LastWriteTime
                Path  = $item.FullName
                Size  = $item.Length
                Name  = $item.Name
            }
        }
    }
}

if ($dumpFindings.Count -gt 0) {
    Write-IRResult "Credential dump artifacts found:" $true
    $dumpFindings |
        Sort-Object Time -Descending |
        Select-Object -Unique Time, Path, Size, Name |
        ForEach-Object {
            $line = "    [$($_.Time)] $($_.Path) | Size: $($_.Size)"
            Write-Host $line -ForegroundColor Yellow
            $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    $compromised = $true
} else {
    Write-IRResult "No credential dump artifacts found in local temp or staging paths." $false "Success"
}

# --- 7.5 Autostart Paths Analysis (Lookback Window) ---
# Autostart locations are reviewed across user profiles, registry Run keys,
# tasks, and services to detect persistence added within the shared lookback window.
Write-Section "Autostart Paths Analysis (Last $lookbackDays Days)"
$autostartResults = @()

# USER STARTUP FOLDERS
foreach ($profile in (Get-CimInstance Win32_UserProfile | Where-Object {
    $_.LocalPath -and -not $_.Special -and (Test-Path $_.LocalPath)
})) {
    $userPath = $profile.LocalPath
    $username = Split-Path $userPath -Leaf
    $startupPath = Join-Path $userPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

    if (Test-Path $startupPath) {
        Get-ChildItem $startupPath -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -ge $lookbackStart -and
                $_.Name -ne "desktop.ini"
            } |
            ForEach-Object {
                $lnk = $null
                if ($_.Extension -eq ".lnk") {
                    $lnk = Resolve-Shortcut $_.FullName
                }

                $autostartResults += [PSCustomObject]@{
                    Scope         = "UserStartup"
                    Username      = $username
                    Location      = $startupPath
                    Name          = $_.Name
                    Path          = $_.FullName
                    LastWriteTime = $_.LastWriteTime
                    TargetPath    = $lnk.TargetPath
                    Arguments     = $lnk.Arguments
                }
            }
    }
}

# SYSTEM STARTUP FOLDER
$commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $commonStartup) {
    Get-ChildItem $commonStartup -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $lookbackStart } |
        ForEach-Object {
            $lnk = $null
            if ($_.Extension -eq ".lnk") {
                $lnk = Resolve-Shortcut $_.FullName
            }

            $autostartResults += [PSCustomObject]@{
                Scope         = "SystemStartupFolder"
                Username      = "ALL"
                Location      = $commonStartup
                Name          = $_.Name
                Path          = $_.FullName
                LastWriteTime = $_.LastWriteTime
                TargetPath    = $lnk.TargetPath
                Arguments     = $lnk.Arguments
            }
        }
}

# HKLM RUN / RUNONCE
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $keyLastWrite = (Get-Item $key).LastWriteTime
        if ($keyLastWrite -ge $lookbackStart) {
            $props = Get-ItemProperty $key
            foreach ($p in $props.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" }) {
                $autostartResults += [PSCustomObject]@{
                    Scope         = "Registry"
                    Username      = "SYSTEM"
                    Location      = $key
                    Name          = $p.Name
                    Path          = $p.Value
                    LastWriteTime = $keyLastWrite
                    TargetPath    = $p.Value
                    Arguments     = $null
                }
            }
        }
    }
}

# SCHEDULED TASKS (ENRICHED WITH BINARY TIMESTAMP)
Get-ScheduledTask | ForEach-Object {
    $task = $_
    foreach ($action in $task.Actions) {
        if ($action.Execute) {
            $lw = Get-BinaryLastWrite $action.Execute
            if ($lw -and $lw -ge $lookbackStart) {
                $autostartResults += [PSCustomObject]@{
                    Scope         = "ScheduledTask"
                    Username      = $task.Principal.UserId
                    Location      = $task.TaskPath
                    Name          = $task.TaskName
                    Path          = $action.Execute
                    LastWriteTime = $lw
                    TargetPath    = $action.Execute
                    Arguments     = $action.Arguments
                }
            }
        }
    }
}

# SERVICES (AUTOSTART ONLY + TIMESTAMP FILTER)
Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq "Auto" } |
    ForEach-Object {
        $lw = Get-BinaryLastWrite $_.PathName
        if ($lw -and $lw -ge $lookbackStart) {
            $autostartResults += [PSCustomObject]@{
                Scope         = "Service-AutoStart"
                Username      = $_.StartName
                Location      = "ServiceControlManager"
                Name          = $_.Name
                Path          = $_.PathName
                LastWriteTime = $lw
                TargetPath    = $_.PathName
                Arguments     = $null
            }
        }
    }

if ($autostartResults.Count -gt 0) {
    $autostartResults |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object {
            $line = "[$($_.Scope)] $($_.LastWriteTime) | $($_.Username) | $($_.Name) | $($_.Path)"
            Write-Host $line -ForegroundColor Yellow
            $line | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($_.TargetPath) {
                $detail = "    TargetPath: $($_.TargetPath) | Arguments: $($_.Arguments)"
                Write-Host $detail -ForegroundColor DarkGray
                $detail | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
    $compromised = $true
} else {
    Write-IRResult "No autostart artifacts newer than $lookbackDays days found in startup folders, registry Run keys, scheduled tasks, or services." $false "Success"
}

# --- 8. Event Log Integrity Check ---
# Log-clearing activity is treated as anti-forensics because it often follows
# intrusion, privilege abuse, or an attempt to hide lateral movement.
Write-Section "Event Log Integrity Check"

# 8.1 Security Log Cleared (ID 1102)
$clearedSec = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
foreach ($ev in $clearedSec) {
    $user = $ev.Properties[1].Value
    if ($user -like "*$executingUser*") { continue } # Noise reduction
    Write-IRResult "Security Log CLEARED! | Time: $($ev.TimeCreated) | User: $user | ID: 1102" $true
    $compromised = $true
}

# 8.2 System/Other Logs Cleared (ID 104)
$clearedSys = Get-WinEvent -FilterHashtable @{LogName='System'; ID=104; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
foreach ($ev in $clearedSys) {
    $logName = $ev.Properties[0].Value
    $user = $ev.Properties[1].Value
    if ($user -like "*$executingUser*") { continue } # Noise reduction
    Write-IRResult "Log '$logName' CLEARED! | Time: $($ev.TimeCreated) | User: $user | ID: 104" $true
    $compromised = $true
}

# 8.3 Event Log Service Shutdown (ID 1100)
$svcShutdown = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Eventlog/Operational'; ID=1100; StartTime=$lookbackStart} -ErrorAction SilentlyContinue
foreach ($ev in $svcShutdown) {
    Write-IRResult "Event Log Service SHUTDOWN (Possible Anti-Forensics)! | Time: $($ev.TimeCreated) | ID: 1100" $true
    $compromised = $true
}

# 8.4 Command Line Indicators (wevtutil / Clear-EventLog)
# Filtered to exclude the IR script itself (checks for Write-IRResult inside the block)
$cmdCleared = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=$lookbackStart} -ErrorAction SilentlyContinue | 
    Where-Object { 
        ($_.Message -match "wevtutil\s+cl" -or $_.Message -match "Clear-EventLog" -or $_.Message -match "Remove-EventLog") -and
        ($_.Message -notmatch "Write-IRResult") 
    }
foreach ($ev in $cmdCleared) {
    Write-IRResult "PowerShell Clear-Log Command Detected! | Time: $($ev.TimeCreated) | ID: 4104" $true
    $compromised = $true
}

# --- FINAL SUMMARY ---
$summaryLine = "`n" + ("="*50)
Write-Host $summaryLine -ForegroundColor Cyan
$summaryLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue

if ($compromised) {
    $compromisedMsg1 = " [!] Indications of compromise found, detailed investigation should be done."
    $compromisedMsg2 = " Review the Red/Yellow alerts above immediately."
    Write-Host $compromisedMsg1 -ForegroundColor White -BackgroundColor Red
    Write-Host $compromisedMsg2 -ForegroundColor Red
    $compromisedMsg1 | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    $compromisedMsg2 | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
} else {
    $successMsg = " [OK] No clear compromise indicators found in examined scope."
    Write-Host $successMsg -ForegroundColor Black -BackgroundColor Green
    $successMsg | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}
$finalLine = "=============================================="
Write-Host $finalLine -ForegroundColor Cyan
$finalLine | Out-File -FilePath $OUTPUT_FILE -Append -Encoding UTF8 -ErrorAction SilentlyContinue

# --- UPLOAD TO AZURE ---
Write-Host "`n[i] Uploading results to Azure Storage..." -ForegroundColor Cyan
try {
    if ($STORAGE_ACCOUNT -eq "<STORAGE_ACCOUNT>" -or $CONTAINER -eq "<CONTAINER_NAME>" -or $SAS_TOKEN -eq "<SAS_TOKEN>") {
        Write-Host " [i] Azure upload skipped because storage placeholders are still set." -ForegroundColor DarkGray
    } else {
        $uploadUrl = "https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER/$BLOB_NAME`??$SAS_TOKEN"
        $fileBytes = [System.IO.File]::ReadAllBytes($OUTPUT_FILE)
        $headers = @{
            "x-ms-blob-type" = "BlockBlob"
        }
        Invoke-RestMethod -Uri $uploadUrl -Method Put -Body $fileBytes -Headers $headers -ContentType "text/plain"
        Write-Host " [OK] Upload successful: $BLOB_NAME" -ForegroundColor Green
    }
} catch {
    Write-Host " [!] Upload failed: $_" -ForegroundColor Red
} finally {
    if (Test-Path $OUTPUT_FILE) { Remove-Item $OUTPUT_FILE -Force }
}
