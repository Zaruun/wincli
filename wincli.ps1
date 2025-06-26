<#
.SYNOPSIS
  WinCLI - lightweight interactive toolbox for Windows (stage 3).
.DESCRIPTION
  Core framework containing initialisation, logging, ASCII banner, the main menu and the "System Management" sub‑menu.
  Each time a menu is entered the console is cleared, the banner is printed, and the relevant options are shown.

  One‑liner launch after publishing to GitHub:
      irm https://raw.githubusercontent.com/Zaruun/wincli/refs/heads/main/wincli.ps1 | iex

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

# Daily log file e.g. %TEMP%\wincli_log\wincli_data_20250624.txt
$WinCliDate  = Get-Date -Format "yyyyMMdd"
$LogRoot     = Join-Path $env:TEMP "wincli_log"
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
    Write-Host ('-' * 40) -ForegroundColor Cyan
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
        Write-Host ""
        Write-Host "[B] Back" -ForegroundColor Yellow

        $subChoice = Read-Host "Select an option"
        switch ($subChoice.ToUpper()) {
            "1" {
                Write-Log -Message "User selected System information" -Level "INFO"
                Show-SystemInformation
            }
            "2" {
                Write-Log -Message "User selected Windows Update" -Level "INFO"
                Ensure-RunningAsAdministrator
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
        Write-Host "[Q] Exit" -ForegroundColor Yellow

        $choice = Read-Host "Select an option"
        switch ($choice.ToUpper()) {
            "1" {
                Write-Log -Message "User entered System Management menu" -Level "INFO"
                Show-SystemManagementMenu
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
