<#
.SYNOPSIS
  WinCLI - lightweight interactive toolbox for Windows (stage 3).
.DESCRIPTION
  Core framework containing initialisation, logging, ASCII banner, the main menu and the "System Management" sub‑menu.
  Each time a menu is entered the console is cleared, the banner is printed, and the relevant options are shown.

  One‑liner launch after publishing to GitHub:
      irm https://raw.githubusercontent.com/Zaruun/wincli/refs/heads/main/wincli.ps1 | iex
      irm mmucha.pl/wincli | iex

.VERSION
  v1-20250624
.AUTHOR
  Mateusz Mucha
#>

#region Initialisation
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
# Ensure console uses UTF‑8 so both ASCII and Unicode characters render correctly
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$ErrorActionPreference = "Stop"

# Daily log file e.g. %LOCALAPPDATA%\WinCLI\Logs\wincli_YYYYMMDD.txt
$WinCliDate  = Get-Date -Format "yyyyMMdd"
$LogRoot     = Join-Path $env:LOCALAPPDATA "WinCLI\Logs"
$LogFilePath = Join-Path $LogRoot "wincli_${WinCliDate}.txt"

# Ensure folder & file exist
if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $LogFilePath)) {
    New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
}
$Global:WinCli = @{
    Version = "v1-20250624"
    LogPath = $LogFilePath
    GithubRepoScript = "https://raw.githubusercontent.com/Zaruun/wincli/refs/heads/main/wincli.ps1"
}
#endregion Initialisation

#region Helper Functions
function Write-Log {
    <#  Appends a timestamped entry to the daily WinCLI log  #>
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line      = "$timestamp [$Level] $Message"
    Add-Content -Path $Global:WinCli.LogPath -Value $line
}

function Ensure-RunningAsAdministrator {
<#
.SYNOPSIS
    Makes sure the current task runs with administrative privileges.
    If the session is not elevated, it offers to relaunch an elevated
    PowerShell instance that downloads and executes the target script
    with Invoke-RestMethod (irm).

.DESCRIPTION
    • Returns $true if the session is already elevated or after the
      elevated instance is successfully started (the current process
      immediately exits).
    • Returns $false if the user declines elevation or if the elevated
      instance cannot be started.

.PARAMETER ScriptUrl
    Raw GitHub (or other) URL pointing to the script that must be run in
    the elevated session.  
    Example (default below):  
    https://raw.githubusercontent.com/<YourRepo>/wincli/main/wincli.ps1

.PARAMETER KeepWindowOpen
    When this switch is set the ­NoExit flag is added so the elevated
    console window stays open after the script completes.
#>
    [CmdletBinding()]
    param (
        [string] $ScriptUrl       = $Global:WinCli.GithubRepoScript,
        [switch] $KeepWindowOpen
    )

    # 1) Check current privilege level
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
               [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { return $true }

    # 2) Ask the user
    Write-Warning 'This action requires administrator privileges.'
    if ((Read-Host 'Relaunch with elevated rights? (Y/N)') -notmatch '^[Yy]') {
        return $false
    }

    # 3) Build the command that the elevated shell will run
    if ([string]::IsNullOrWhiteSpace($ScriptUrl)) {
        Write-Error 'ScriptUrl is empty – nothing to run in the elevated session.'
        return $false
    }

    if ($ScriptUrl -notmatch '^https?://') {
        Write-Error "ScriptUrl must start with http:// or https:// : '$ScriptUrl'"
        return $false
    }

    $command  = "irm '$ScriptUrl' | iex"

    $encoded  = [Convert]::ToBase64String(
                   [Text.Encoding]::Unicode.GetBytes($command)
               )

    $argLine  = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
    if ($KeepWindowOpen) { $argLine = "-NoExit $argLine" }

    try {
        Start-Process -FilePath  'powershell.exe' `
                      -ArgumentList $argLine `
                      -Verb      RunAs `
                      -WindowStyle Normal | Out-Null
    }
    catch {
        Write-Error "Failed to launch elevated session: $($_.Exception.Message)"
        return $false
    }

    Exit   # terminate the non-admin process 
}



function Show-Banner {
    <#  Clears the console and prints the ASCII banner and version  #>
    Clear-Host
    $banner = @"
 _       ___       ________    ____   __________  ____  __   _____    __ __ __________   
| |     / (_)___  / ____/ /   /  _/  /_  __/ __ \/ __ \/ /  / ___/   / //_//  _/_  __/   
| | /| / / / __ \/ /   / /    / /     / / / / / / / / / /   \__ \   / ,<   / /  / /      
| |/ |/ / / / / / /___/ /____/ /     / / / /_/ / /_/ / /______/ /  / /| |_/ /  / /       
|__/|__/_/_/ /_/\____/_____/___/    /_/  \____/\____/_____/____/  /_/ |_/___/ /_/        
                                                                                         
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ("WinCLI " + $Global:WinCli.Version) -ForegroundColor Cyan
    Write-Host ('-' * 85) -ForegroundColor Cyan
    Write-Host ""
}

function Initialize-WinCli {
    <#  Logs script launch and displays the banner  #>
    $currentUser = $env:USERNAME
    Write-Log -Message "Script launched by $currentUser" -Level "INFO"
    Show-Banner
}

function Show-SystemManagementMenu {
    <#  "System Management" sub‑menu  #>
    do {
        Show-Banner
        Write-Host "SYSTEM MANAGEMENT" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] System information" -ForegroundColor Yellow
        Write-Host "[2] Windows Update" -ForegroundColor Yellow
        Write-Host "[3] Storage / Cleanup" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[B] Back" -ForegroundColor Yellow
        Write-Host ""

        $subChoice = Read-Host "Select an option"
        switch ($subChoice.ToUpper()) {
            "1" {
                Write-Log -Message "User selected System information" -Level "INFO"
                Show-SystemInformation
            }
            "2" {
                Write-Log -Message "User selected Windows Update" -Level "INFO"
                Invoke-WindowsUpdateInteractive
            }
            "3" {
                Write-Log -Message "User selected Storage / Cleanup" -Level "INFO"
                Invoke-StorageCleanup
            }
            "B" {
                Write-Log -Message "User returned to main menu" -Level "INFO"
                return
            }
            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Red
                Pause
            }
        }
    } while ($true)
}

function Show-SystemInformation {
    <#
      .SYNOPSIS
        Collects and displays key information about the local system.
    #>
    try {
        Clear-Host
        Show-Banner
        Write-Host "SYSTEM INFORMATION`n" -ForegroundColor Yellow

        # --- Basic system data ---
        $os        = Get-CimInstance -ClassName Win32_OperatingSystem
        $computer  = Get-ComputerInfo
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($cs.PartOfDomain) {
            $domainOrWorkgroup = "Domain:   $($cs.Domain)"        
        } else {
            $domainOrWorkgroup = "Workgroup: $($cs.Workgroup)"     
        }
        $uptime    = (Get-Date) - $os.LastBootUpTime
        $cpu       = Get-CimInstance -ClassName Win32_Processor
        $totalMem  = [math]::Round($os.TotalVisibleMemorySize / 1MB,2)
        $freeMem   = [math]::Round($os.FreePhysicalMemory     / 1MB,2)
        $biosSerial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

        Write-Host "Hostname:  $($env:COMPUTERNAME)" -ForegroundColor Cyan
        Write-Host "OS:        $($os.Caption)  Build $($os.BuildNumber)" -ForegroundColor Cyan
        Write-Host "$($domainOrWorkgroup)" -ForegroundColor Cyan
        Write-Host "SN:        $($biosSerial)" -ForegroundColor Cyan
        Write-Host ("Uptime:    {0}d {1}h {2}m" -f $uptime.Days,$uptime.Hours,$uptime.Minutes) -ForegroundColor Cyan
        Write-Host ""

        # --- CPU ---
        Write-Host "CPU" -ForegroundColor Yellow
        Write-Host "  Model:  $($cpu.Name.Trim())"
        Write-Host "  Cores:  $($cpu.NumberOfCores)  Threads: $($cpu.NumberOfLogicalProcessors)"
        Write-Host ""

        # --- Memory ---
        $usedMem = [math]::Round($totalMem - $freeMem,2)
        $pctMem  = [math]::Round(($usedMem / $totalMem)*100,1)
        Write-Host "Memory" -ForegroundColor Yellow
        Write-Host "  Total:  ${totalMem} GB"
        Write-Host "  Used:   ${usedMem} GB  ($pctMem`%)"
        Write-Host ""

        # --- Disks ---
        Write-Host "Disks" -ForegroundColor Yellow
        Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object DriveType -EQ 3 |
            ForEach-Object {
                $size  = [math]::Round($_.Size / 1GB,2)
                $free  = [math]::Round($_.FreeSpace / 1GB,2)
                $used  = [math]::Round($size - $free,2)
                $pct   = [math]::Round(($used / $size)*100,1)
                Write-Host "  $($_.DeviceID): $used GB / $size GB ($pct`%)"
            }
        Write-Host ""

        # --- Network ---
        Write-Host "Network" -ForegroundColor Yellow
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -eq $true |
            ForEach-Object {
                Write-Host "  $($_.Description)"
                Write-Host "    IP:    $($_.IPAddress[0])"
                if ($_.IPSubnet) {
                    Write-Host "    Mask:  $($_.IPSubnet[0])"
                }
                if ($_.DefaultIPGateway) {
                    Write-Host "    GW:    $($_.DefaultIPGateway[0])"
                }
                if ($_.DNSServerSearchOrder) {
                    Write-Host "    DNS:   $($_.DNSServerSearchOrder -join ', ')"
                }
                # Adapter speed (only if property populated)
                $nic = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "Index = $($_.Index)"
                if ($nic.Speed) {
                    if ($nic.Speed -ge 1e9) {         # 1 000 000 000 b/s  ==  1 Gb/s
                        $speedGbps = [math]::Round($nic.Speed / 1e9, 1)   # jeden miejsc po przecinku
                        Write-Host "    Speed: $speedGbps Gb/s"
                    }
                    else {
                        $speedMbps = [math]::Round($nic.Speed / 1e6)      # całe Mb/s
                        Write-Host "    Speed: $speedMbps Mb/s"
                    }
                }
            }
        Write-Host ""

        Write-Log "System information collected successfully." "INFO"
        Pause "Press any key to return..." | Out-Null
    }
    catch {
        Write-Log "Error collecting system information: $($_.Exception.Message)" "ERROR"
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Pause
    }
}

function Show-MainMenu {
    <#  Main CLI menu  #>
    do {
        Show-Banner
        Write-Host "MAIN MENU" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] System Management" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[L] Open log file" -ForegroundColor Yellow
        Write-Host "[Q] Exit" -ForegroundColor Yellow
        Write-Host ""

        $choice = Read-Host "Select an option"
        switch ($choice.ToUpper()) {
            "1" {
                Write-Log -Message "User entered System Management menu" -Level "INFO"
                Show-SystemManagementMenu
            }
            "L" {
                Start-Process notepad.exe -ArgumentList $Global:WinCli.LogPath
                Write-Log -Message "User opended log file" -Level "INFO"
                Show-MainMenu
            }
            "Q" {
                Write-Log -Message "User exited WinCLI" -Level "INFO"
                return
            }
            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Red
                Pause
            }
        }
    } while ($true)
}

function Invoke-WindowsUpdateInteractive {
<#
.SYNOPSIS
    Searches for pending Windows Updates and, if any are found,
    asks the user whether to download & install them.

.DESCRIPTION
    • Ensures the session is running elevated (calls Ensure-RunningAsAdministrator).
    • Uses the Microsoft Update COM API – no external modules required.
    • Logs every major step with Write-Log, mirrors status to the console.
    • After installation informs the user if a reboot is required.

.NOTES
    Fits the coding style of wincli.ps1 (logging, colours, Pause, etc.).
#>
    [CmdletBinding()]
    param()

    Clear-Host
    Show-Banner
    Write-Host "WINDOWS UPDATES`n" -ForegroundColor Yellow

    # -- make sure we are running as Administrator --------------------------
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
               [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        if (-not (Ensure-RunningAsAdministrator)) { return }   # user declined
        return                                                # new elevated session will relaunch the script
    }

    try {
        Write-Host "Checking for available Windows Updates..." -ForegroundColor Yellow
        Write-Log  "Checking for Windows Updates" "INFO"

        # ---------- search --------------------------------------------------
        $session     = New-Object -ComObject Microsoft.Update.Session
        $searcher    = $session.CreateUpdateSearcher()
        $criteria    = "IsInstalled=0 and IsHidden=0"
        $searchResult = $searcher.Search($criteria)
        $updates      = $searchResult.Updates
        $count        = $updates.Count

        if ($count -eq 0) {
            Write-Host "No updates available." -ForegroundColor Green
            Write-Log  "No updates found" "INFO"
            Pause "Press any key to return..." | Out-Null
            return
        }

        # ---------- list updates -------------------------------------------
        Write-Host ""
        Write-Host "$count update(s) found:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $count; $i++) {
            $title = $updates.Item($i).Title
            Write-Host (" [{0}] {1}" -f ($i + 1), $title)
        }
        Write-Host ""

        # ---------- ask user ------------------------------------------------
        $install = Read-Host "Download and install all updates now? (Y/N)"
        if ($install -notmatch '^[Yy]') {
            Write-Log "User declined update installation." "WARNING"
            return
        }

        # ---------- download -----------------------------------------------
        Write-Host "`nDownloading updates…" -ForegroundColor Yellow
        $downloader            = $session.CreateUpdateDownloader()
        $downloader.Updates    = $updates
        $downloadResult        = $downloader.Download()

        if ($downloadResult.ResultCode -ne 2) {   # 2 = Succeeded
            Write-Error "Download failed (result code $($downloadResult.ResultCode))."
            Write-Log   "Update download failed, code $($downloadResult.ResultCode)" "ERROR"
            return
        }

        # ---------- install -------------------------------------------------
        Write-Host "`nInstalling updates…" -ForegroundColor Yellow
        $installer          = $session.CreateUpdateInstaller()
        $installer.Updates  = $updates
        $installResult      = $installer.Install()
        $code               = $installResult.ResultCode

        switch ($code) {
            2 {   # Succeeded
                Write-Host "`nUpdates installed successfully." -ForegroundColor Green
                Write-Log  "Updates installed successfully" "INFO"
            }
            3 {   # Succeeded with errors
                Write-Host "`nUpdates installed with warnings." -ForegroundColor Yellow
                Write-Log  "Updates installed with warnings" "WARNING"
            }
            default {
                Write-Error "Installation failed or aborted (code $code)."
                Write-Log   "Update installation ended with code $code" "ERROR"
                return
            }
        }

        if ($installResult.RebootRequired) {
            Write-Host "A restart is required to complete installation." -ForegroundColor Yellow
            Write-Log  "Restart required after updates" "INFO"
        }

    } catch {
        Write-Error "Windows Update error: $($_.Exception.Message)"
        Write-Log   "Windows Update error: $($_.Exception.Message)" "ERROR"
    }

    Pause "Press any key to return..." | Out-Null
}

function Invoke-StorageCleanup {
<#
.SYNOPSIS
    Prints a “before–cleanup” snapshot (total / used / free of the system
    drive + size of the main junk areas).  
    Later you can extend the function with actual deletion steps.

.PARAMETER AnalyzeOnly
    Show the snapshot and exit without deleting anything.

.PARAMETER Aggressive
    Placeholder for heavy-duty steps (WinSxS / DriverStore / CompactOS).

.PARAMETER Silent
    Suppress Pause / Read-Host prompts; log only.

.NOTES
    Designed to drop into wincli.ps1 (uses Write-Log & colour scheme).
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch] $AnalyzeOnly,
        [switch] $Aggressive,
        [switch] $Silent
    )

    function Pause {
        param([string]$Message = "Press any key to continue...")
        Read-Host $Message | Out-Null
    }

    # ───────────────── helpers ────────────────────────────────────────────
    function ConvertTo-Readable {
        param([UInt64]$Bytes)
        switch ($Bytes) {
            { $_ -ge 1TB * 1024 } { return '{0:N2} PB' -f ($Bytes / (1TB * 1024)) }
            { $_ -ge 1TB }        { return '{0:N2} TB' -f ($Bytes / 1TB) }
            { $_ -ge 1GB }        { return '{0:N2} GB' -f ($Bytes / 1GB) }
            { $_ -ge 1MB }        { return '{0:N2} MB' -f ($Bytes / 1MB) }
            { $_ -ge 1KB }        { return '{0:N2} KB' -f ($Bytes / 1KB) }
            default               { return "$Bytes B" }
        }
    }

    function Get-FolderSize {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return 0 }
        try {
            (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
             Measure-Object Length -Sum).Sum
        } catch { 0 }
    }

    # ───────────────── STEP 0 – snapshot ─────────────────────────────────
    Clear-Host
    Show-Banner
    Write-Host "STORAGE CLEANUP`n" -ForegroundColor Yellow
    Write-Log  "Storage snapshot started" "INFO"

    $sysRoot  = [IO.Path]::GetPathRoot($env:SystemRoot)
    $sysDrive = $sysRoot.TrimEnd('\')

    $driveInfo = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" |
                  Select-Object -First 1)

    $total   = [UInt64]$driveInfo.Size
    $free    = [UInt64]$driveInfo.FreeSpace
    $used    = $total - $free
    $pctFree = [math]::Round(($free / $total)*100,1)

    Write-Host ("Drive {0}:  Total {1}   Used {2}   Free {3} ({4}%)" -f 
        $sysDrive,
        (ConvertTo-Readable $total),
        (ConvertTo-Readable $used),
        (ConvertTo-Readable $free),
        $pctFree) -ForegroundColor Cyan

    $targets = [ordered]@{
        'Restore points'        = 0
        'WinSxS'                = "$env:SystemRoot\WinSxS"
        'User Temp'             = $env:TEMP
        'System Temp'           = "$env:SystemRoot\Temp"
        'Recycle Bin'           = Join-Path $sysDrive '$Recycle.Bin'
        'WU cache'              = "$env:SystemRoot\SoftwareDistribution\Download"
        'Delivery Optimization' = "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization"
        'Old logs (>30 d)'      = "$env:SystemRoot\Logs"
    }

    try {
        $shadow = Get-CimInstance Win32_ShadowStorage -ErrorAction Stop |
                  Where-Object { $_.PSObject.Properties['VolumeName'] -and
                                 $_.VolumeName -eq $sysRoot }
        if ($shadow) { $targets['Restore points'] = [UInt64]$shadow.UsedSpace }
    } catch { }

    try {
        $targets['Old logs (>30 d)'] = (
            Get-ChildItem -LiteralPath $targets['Old logs (>30 d)'] -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
            Measure-Object Length -Sum
        ).Sum
    } catch { $targets['Old logs (>30 d)'] = 0 }

    $keyList = @($targets.Keys)
    foreach ($k in $keyList) {
        if ($k -match 'Restore points|Old logs') { continue }
        $targets[$k] = Get-FolderSize $targets[$k]
    }

    Write-Host ''
    foreach ($pair in $targets.GetEnumerator()) {
        $nice = ConvertTo-Readable $pair.Value
        Write-Host ("{0,-25} {1,12}" -f ($pair.Key + ':'), $nice)
    }
    Write-Host ''

    if ($AnalyzeOnly) {
        Write-Log "AnalyzeOnly – no cleanup executed" "INFO"
        if (-not $Silent) { Pause }
        return
    }

    # ─────────────── future cleanup steps go here ─────────────────────────
    # e.g. Clear-RecycleBin, Remove-Item temp, DISM cleanup, etc.
    # ────── Prompt user for cleanup decisions ──────
    $cleanupDecisions = @{}

    foreach ($pair in $targets.GetEnumerator()) {
        $areaName = $pair.Key
        $sizeReadable = ConvertTo-Readable $pair.Value

        if ($pair.Value -eq 0) {
            $cleanupDecisions[$areaName] = $false
            continue
        }

        $response = Read-Host "Do you want to clean '$areaName' (${sizeReadable})? (y/n)"
        $cleanupDecisions[$areaName] = $response -match '^[Yy]'
    }

    # ────── Final summary of selected options ──────
    Write-Host "`nCleanup selections:" -ForegroundColor Yellow
    foreach ($key in $cleanupDecisions.Keys) {
        $action = if ($cleanupDecisions[$key]) { "Yes" } else { "No" }
        Write-Host ("{0,-25} {1}" -f ($key + ':'), $action)
    }
    Write-Host ''

# ────── Cleanup execution based on selection ──────
Write-Host "`nStarting cleanup..." -ForegroundColor Green
Write-Log "Cleanup process started" "INFO"

foreach ($key in $cleanupDecisions.Keys) {
    if (-not $cleanupDecisions[$key]) {
        Write-Log "Skipped: $key (user chose No)" "INFO"
        continue
    }

    Write-Host ("Cleaning: {0}..." -f $key) -ForegroundColor Cyan
    Write-Log "Cleaning started: $key" "INFO"

    try {
        switch ($key) {

            'Restore points' {
                Write-Host "Skipping: Restore points require advanced handling (use vssadmin or Cleanmgr)." -ForegroundColor DarkYellow
                Write-Log "Restore points skipped – not supported via script" "WARN"
            }

            'WinSxS' {
                Ensure-RunningAsAdministrator
                Write-Host "Cleaning WinSxS with DISM..."
                Write-Log "DISM StartComponentCleanup initiated" "INFO"
                Start-Process -Wait -FilePath "dism.exe" -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/Quiet" -NoNewWindow
                Write-Log "DISM cleanup finished for WinSxS" "INFO"
            }

            'User Temp' {
                Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "User Temp cleaned."
                Write-Log "User Temp cleaned" "INFO"
            }

            'System Temp' {
                Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "System Temp cleaned."
                Write-Log "System Temp cleaned" "INFO"
            }

            'Recycle Bin' {
                Write-Host "Emptying Recycle Bin..."
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                Write-Log "Recycle Bin emptied" "INFO"
            }

            'WU cache' {
                Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Windows Update cache cleaned."
                Write-Log "Windows Update cache cleaned" "INFO"
            }

            'Delivery Optimization' {
                Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Delivery Optimization cache cleaned."
                Write-Log "Delivery Optimization cache cleaned" "INFO"
            }

            'Old logs (>30 d)' {
                $logPath = "$env:SystemRoot\Logs"
                $oldLogs = Get-ChildItem -Path $logPath -Recurse -Force -ErrorAction SilentlyContinue |
                           Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }

                $oldLogs | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Host "Old logs removed."
                Write-Log "Old logs (older than 30 days) removed" "INFO"
            }

            default {
                Write-Host "No cleanup routine defined for: $key" -ForegroundColor DarkGray
                Write-Log "No defined cleanup for $key" "WARN"
            }
        }
    } catch {
        Write-Host "Error while cleaning $key\: $_" -ForegroundColor Red
        Write-Log "Error while cleaning $key\: $_" "ERROR"
    }
}

Write-Host "`nCleanup process completed." -ForegroundColor Green
Write-Log "Cleanup process completed" "INFO"


    if (-not $Silent) { Pause "Press any key to finish..." }
}

#endregion Helper Functions

#region Entry Point
try {
    Initialize-WinCli
    Show-MainMenu
}
catch {
    Write-Log -Message "Unhandled exception: $($_.Exception.Message)" -Level "ERROR"
    throw
}
#endregion Entry Point
