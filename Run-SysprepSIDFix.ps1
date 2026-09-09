<#
.SYNOPSIS
    Automates the Sysprep SID fix process for remote execution.

.DESCRIPTION
    This script handles the entire sysprep /generalize workflow to fix duplicate SIDs:
      1. Checks current SID
      2. Copies unattend.xml to the Sysprep directory
      3. Verifies TeamViewer is set to allow incoming LAN connections
      4. Disables BitLocker if enabled (and waits for decryption)
      5. Pauses Windows Update to prevent reserved storage conflicts
      6. Removes known conflicting Appx packages
      7. Runs sysprep, automatically retrying and removing any additional
         conflicting packages that appear in the error log
      8. Machine reboots with a new SID; OOBE is fully bypassed via unattend.xml

.NOTES
    Must be run as Administrator.
    Must be run from the directory containing unattend.xml.
    Compatible with Windows 10 Pro and Windows 11 Pro.
#>

#Requires -RunAsAdministrator

param(
    # Maximum number of sysprep retry attempts (each attempt removes newly found conflicting packages)
    [int]$MaxRetries = 10,

    # Skip the confirmation prompt and run immediately
    [switch]$Force,

    # Path to unattend.xml (defaults to same directory as this script)
    [string]$UnattendPath,

    # Network configuration overrides (auto-captured from current config if not specified)
    # Pass these to override the current network settings after sysprep
    [string]$IPAddress,
    [string]$SubnetPrefix,
    [string]$Gateway,
    [string[]]$DNS,

    # Skip network config restore after sysprep (leave on DHCP)
    [switch]$SkipNetworkRestore
)

$ErrorActionPreference = "Stop"

# ============================================================
# Helper functions
# ============================================================

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] " -ForegroundColor DarkGray -NoNewline
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor White
}

# ============================================================
# Pre-flight checks
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Sysprep SID Fix - Automated Remote Workflow" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Determine unattend.xml location
if (-not $UnattendPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $UnattendPath = Join-Path $scriptDir "unattend.xml"
}

if (-not (Test-Path $UnattendPath)) {
    Write-Fail "unattend.xml not found at: $UnattendPath"
    Write-Fail "Place unattend.xml next to this script, or use -UnattendPath to specify its location."
    exit 1
}

# ============================================================
# Step 1: Show current SID
# ============================================================

Write-Step "Step 1: Current machine SID"

$sidOutput = whoami /user /fo csv | ConvertFrom-Csv
$currentSID = $sidOutput.SID
# Machine SID is the user SID minus the last RID (the -500, -1001, etc.)
$machineSID = $currentSID -replace '-\d+$', ''
Write-Info "Current user SID : $currentSID"
Write-Info "Machine SID      : $machineSID"
Write-Info "Hostname         : $env:COMPUTERNAME"

# ============================================================
# Confirmation
# ============================================================

if (-not $Force) {
    Write-Host ""
    Write-Host "  WARNING: This will run sysprep /generalize on this machine." -ForegroundColor Yellow
    Write-Host "  The machine will:" -ForegroundColor Yellow
    Write-Host "    - Get a NEW SID, hostname, and IP address" -ForegroundColor Yellow
    Write-Host "    - Reboot automatically" -ForegroundColor Yellow
    Write-Host "    - Auto-logon once to the Administrator account" -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "  Type YES to continue"
    if ($confirm -ne "YES") {
        Write-Host "  Aborted." -ForegroundColor Red
        exit 0
    }
}

# ============================================================
# Step 2: Capture network configuration
# ============================================================

Write-Step "Step 2: Network configuration"

$networkRestoreScript = $null

if (-not $SkipNetworkRestore) {
    # Find the active network adapter (the one with a default gateway)
    $activeAdapter = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric |
        Select-Object -First 1

    if ($activeAdapter) {
        $ifIndex = $activeAdapter.InterfaceIndex
        $adapterName = (Get-NetAdapter -InterfaceIndex $ifIndex).Name
        $currentIP = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1
        $currentGateway = $activeAdapter.NextHop
        $currentDNS = (Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).ServerAddresses

        # Use manual overrides if provided, otherwise use captured values
        $restoreIP = if ($IPAddress) { $IPAddress } elseif ($currentIP) { $currentIP.IPAddress } else { $null }
        $restorePrefix = if ($SubnetPrefix) { $SubnetPrefix } elseif ($currentIP) { $currentIP.PrefixLength.ToString() } else { $null }
        $restoreGateway = if ($Gateway) { $Gateway } elseif ($currentGateway) { $currentGateway } else { $null }
        $restoreDNS = if ($DNS) { $DNS } elseif ($currentDNS) { $currentDNS } else { $null }

        if ($restoreIP) {
            Write-Info "Adapter          : $adapterName"
            Write-Info "IP Address       : $restoreIP/$restorePrefix"
            Write-Info "Gateway          : $restoreGateway"
            Write-Info "DNS              : $($restoreDNS -join ', ')"

            if ($IPAddress -or $SubnetPrefix -or $Gateway -or $DNS) {
                Write-Info "(Using manual overrides where specified)"
            } else {
                Write-Info "(Auto-captured from current config)"
            }

            if (-not $Force) {
                Write-Host ""
                $response = Read-Host "  Restore this network config after sysprep? (Y/N)"
                if ($response -ne "Y" -and $response -ne "y") {
                    Write-Info "Network config will NOT be restored. Machine will use DHCP."
                    $restoreIP = $null
                }
            }

            if ($restoreIP) {
                # Build the restore script
                $dnsCommands = ""
                if ($restoreDNS -and $restoreDNS.Count -gt 0) {
                    $dnsList = ($restoreDNS | ForEach-Object { "'$_'" }) -join ","
                    $dnsCommands = "Set-DnsClientServerAddress -InterfaceAlias `$adapter -ServerAddresses @($dnsList)"
                }

                $networkRestoreScript = @"
`$adapter = '$adapterName'
# Remove existing IP config
Get-NetIPAddress -InterfaceAlias `$adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:`$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceAlias `$adapter -AddressFamily IPv4 -Confirm:`$false -ErrorAction SilentlyContinue
# Apply saved config
New-NetIPAddress -InterfaceAlias `$adapter -IPAddress '$restoreIP' -PrefixLength $restorePrefix -DefaultGateway '$restoreGateway' -ErrorAction Stop
$dnsCommands
"@

                # Save the restore script to the Sysprep directory (survives reboot)
                $restoreScriptPath = Join-Path $env:SystemRoot "System32\Sysprep\RestoreNetwork.ps1"
                $networkRestoreScript | Out-File -FilePath $restoreScriptPath -Encoding UTF8 -Force
                Write-Success "Network restore script saved to $restoreScriptPath"
            }
        } else {
            Write-Info "No static IP detected. Machine appears to be on DHCP."
            Write-Info "Network config will not be modified after sysprep."
        }
    } else {
        Write-Warn "Could not detect active network adapter."
        Write-Info "Network config will not be modified after sysprep."
    }
} else {
    Write-Info "Network restore skipped (-SkipNetworkRestore)."
}

# ============================================================
# Step 3: Copy unattend.xml to Sysprep directory
# ============================================================

Write-Step "Step 3: Deploying unattend.xml"

$sysprepDir = Join-Path $env:SystemRoot "System32\Sysprep"
$destPath = Join-Path $sysprepDir "unattend.xml"

Copy-Item -Path $UnattendPath -Destination $destPath -Force
Write-Success "Copied unattend.xml to $destPath"

# ============================================================
# Step 4: Verify TeamViewer LAN connections setting
# ============================================================

Write-Step "Step 4: Checking TeamViewer configuration"

$tvRegPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\TeamViewer",
    "HKLM:\SOFTWARE\TeamViewer"
)

$tvFound = $false
foreach ($tvPath in $tvRegPaths) {
    if (Test-Path $tvPath) {
        $tvFound = $true
        try {
            $tvProps = Get-ItemProperty $tvPath -ErrorAction Stop

            if ($tvProps.PSObject.Properties.Name -contains "ClientID") {
                Write-Info "TeamViewer Client ID: $($tvProps.ClientID)"
            }

            # Check Security_AcceptIncomingLAN - value of 1 means enabled
            if ($tvProps.PSObject.Properties.Name -contains "Security_AcceptIncomingLAN") {
                if ($tvProps.Security_AcceptIncomingLAN -eq 1) {
                    Write-Success "Incoming LAN connections: Enabled"
                } else {
                    Write-Warn "Incoming LAN connections is NOT enabled."
                    Write-Warn "You should enable this in TeamViewer > Settings > Advanced > Accept incoming LAN connections."
                    Write-Warn "Continuing anyway - you can reconnect via RDP if needed."
                }
            } else {
                Write-Warn "Could not verify LAN connection setting. Check TeamViewer settings manually."
            }
        } catch {
            Write-Warn "Could not read TeamViewer registry: $_"
        }
        break
    }
}

if (-not $tvFound) {
    Write-Warn "TeamViewer not found in registry. If installed, verify LAN connections is enabled."
}

# ============================================================
# Step 5: Handle BitLocker
# ============================================================

Write-Step "Step 5: Checking BitLocker status"

try {
    $blStatus = manage-bde -status C: 2>&1
    $blStatusText = $blStatus | Out-String

    # Check if BitLocker needs attention — protection on OR not fully decrypted
    $needsDecrypt = $false

    if ($blStatusText -match "Protection Status:\s+Protection On") {
        Write-Info "BitLocker protection is ON - disabling..."
        manage-bde -off C: | Out-Null
        $needsDecrypt = $true
    }
    elseif ($blStatusText -match "Conversion Status:\s+Fully Decrypted") {
        Write-Success "BitLocker is fully off."
    }
    elseif ($blStatusText -match "Protection Status:\s+Protection Off") {
        # Protection is off but drive may still be encrypted/decrypting
        if ($blStatusText -match "Percentage Encrypted:\s+(\d+(\.\d+)?)%" -and [double]$Matches[1] -gt 0) {
            Write-Info "BitLocker protection is off but drive is still encrypted ($($Matches[1])%)."
            manage-bde -off C: 2>&1 | Out-Null
            $needsDecrypt = $true
        } else {
            Write-Success "BitLocker is already off."
        }
    }
    else {
        Write-Success "BitLocker does not appear to be active."
    }

    if ($needsDecrypt) {
        Write-Info "Waiting for BitLocker decryption to complete..."
        $decrypting = $true
        while ($decrypting) {
            Start-Sleep -Seconds 10
            $status = manage-bde -status C: | Out-String
            if ($status -match "Percentage Encrypted:\s+(\d+(\.\d+)?)%") {
                $pct = $Matches[1]
                Write-Host "`r  Decryption progress: $pct% remaining...    " -NoNewline -ForegroundColor White
                if ([double]$pct -eq 0) {
                    $decrypting = $false
                }
            }
            if ($status -match "Conversion Status:\s+Fully Decrypted") {
                $decrypting = $false
            }
        }
        Write-Host ""
        Write-Success "BitLocker decryption complete."
    }
} catch {
    Write-Warn "Could not check BitLocker status: $_"
    Write-Warn "If sysprep fails with error 0x80310039, run: manage-bde -off C:"
}

# ============================================================
# Step 6: Pause Windows Update
# ============================================================

Write-Step "Step 6: Pausing Windows Update"

try {
    # Pause updates for 7 days by setting the pause feature update start date
    $pauseDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesStartTime" -Value $pauseDate
    Set-ItemProperty -Path $regPath -Name "PauseQualityUpdatesStartTime" -Value $pauseDate
    Set-ItemProperty -Path $regPath -Name "PauseUpdatesStartTime" -Value $pauseDate

    # Also calculate the expiry date (7 days from now)
    $expiryDate = (Get-Date).AddDays(7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Set-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesEndTime" -Value $expiryDate
    Set-ItemProperty -Path $regPath -Name "PauseQualityUpdatesEndTime" -Value $expiryDate
    Set-ItemProperty -Path $regPath -Name "PauseUpdatesExpiryTime" -Value $expiryDate

    # Stop the Windows Update service to release any reserved storage locks
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Write-Success "Windows Update paused for 7 days and service stopped."
} catch {
    Write-Warn "Could not fully pause Windows Update: $_"
    Write-Warn "If sysprep fails with error 0x800F0975, pause updates manually in Settings."
}

# ============================================================
# Step 7: Run Sysprep with automatic retry
# ============================================================

Write-Step "Step 7: Running Sysprep"

$sysprepExe = Join-Path $sysprepDir "sysprep.exe"
$pantherDir = Join-Path $sysprepDir "Panther"
$setupActLog = Join-Path $pantherDir "setupact.log"
$setupErrLog = Join-Path $pantherDir "setuperr.log"
$attempt = 0
$sysprepSuccess = $false
$reservedStorageAttempted = $false

while ($attempt -lt $MaxRetries -and -not $sysprepSuccess) {
    $attempt++
    Write-Info "Attempt $attempt of $MaxRetries..."

    # Clear old logs so we only parse fresh errors
    foreach ($log in @($setupActLog, $setupErrLog)) {
        if (Test-Path $log) {
            Remove-Item $log -Force -ErrorAction SilentlyContinue
        }
    }

    # Run sysprep
    $process = Start-Process -FilePath $sysprepExe `
        -ArgumentList "/generalize", "/oobe", "/reboot", "/unattend:$destPath" `
        -Wait -PassThru -NoNewWindow

    Write-Info "Sysprep exited with code: $($process.ExitCode)"

    # Don't trust exit code alone — check the logs for errors regardless,
    # because sysprep can return 0 even when it fails (after clicking OK on the error dialog)
    Start-Sleep -Seconds 3

    # Read log files from the Sysprep Panther directory only
    # (C:\Windows\Panther\ contains stale logs from previous runs — do not read those)
    $logContent = ""
    $logSources = @()
    foreach ($log in @($setupActLog, $setupErrLog)) {
        if (Test-Path $log) {
            $logContent += (Get-Content $log -Raw) + "`n"
            $logSources += $log
        }
    }

    if ($logSources.Count -gt 0) {
        Write-Info "Log files found: $($logSources -join ', ')"
    } else {
        Write-Info "No log files found"
    }

    # Check if logs contain errors
    $hasErrors = $logContent -match 'SYSPRP.*Error|Error.*SYSPRP'

    if (-not $hasErrors -and $process.ExitCode -eq 0) {
        Write-Success "Sysprep started successfully! The machine will reboot shortly."
        Write-Host ""
        Write-Host "  =========================================" -ForegroundColor Green
        Write-Host "  SYSPREP SUCCEEDED" -ForegroundColor Green
        Write-Host "  The PC will reboot with a new SID." -ForegroundColor Green
        Write-Host "  After reboot:" -ForegroundColor Green
        Write-Host "    - It will auto-logon once as Administrator" -ForegroundColor Green
        Write-Host "    - A SysprepResult.txt will appear on the desktop" -ForegroundColor Green
        Write-Host "    - Find the PC by its new IP on the network" -ForegroundColor Green
        Write-Host "  =========================================" -ForegroundColor Green
        $sysprepSuccess = $true
    } else {
        Write-Warn "Sysprep failed. Analyzing logs..."

        if ($logContent.Length -gt 0) {
            # Look for conflicting Appx package errors using multiple patterns
            $packageMatches = [regex]::Matches($logContent, 'SYSPRP\s+Package\s+([\w\.\-]+_[\d\.]+_[\w]+__[\w]+)\s+was installed')
            if ($packageMatches.Count -eq 0) {
                $packageMatches = [regex]::Matches($logContent, 'SYSPRP\s+.*?remove\s+.*?([\w\.\-]+_[\d\.]+_[\w]+__[\w]+)')
            }
            if ($packageMatches.Count -eq 0) {
                $packageMatches = [regex]::Matches($logContent, 'Error\s+.*?([\w\.\-]+_[\d\.]+_[\w]+__[\w]+)')
            }

            $newPackagesFound = $false
            $foundPackageNames = @()

            foreach ($match in $packageMatches) {
                $pkgName = $match.Groups[1].Value
                if ($pkgName -and $pkgName -notin $foundPackageNames) {
                    $foundPackageNames += $pkgName
                }
            }

            if ($foundPackageNames.Count -gt 0) {
                Write-Host ""
                Write-Host "  Sysprep is blocked by the following package(s):" -ForegroundColor Yellow
                Write-Host ""
                foreach ($pkgName in $foundPackageNames) {
                    $baseName = ($pkgName -split '_')[0]
                    Write-Host "    - $baseName" -ForegroundColor White
                }
                Write-Host ""

                $doRemove = $true
                if (-not $Force) {
                    $response = Read-Host "  Remove and retry? (Y/N)"
                    if ($response -ne "Y" -and $response -ne "y") {
                        Write-Warn "Skipping removal. Sysprep cannot continue with these packages installed."
                        break
                    }
                }

                foreach ($pkgName in $foundPackageNames) {
                    Write-Info "Removing: $pkgName"
                    try {
                        $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -eq $pkgName }
                        if (-not $pkg) {
                            $baseName = ($pkgName -split '_')[0]
                            $pkg = Get-AppxPackage -AllUsers -Name "*$baseName*"
                        }
                        foreach ($p in $pkg) {
                            Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop
                            Write-Success "Removed $($p.Name)"
                            $newPackagesFound = $true
                        }
                    } catch {
                        try {
                            Remove-AppxPackage -Package $pkgName -AllUsers -ErrorAction Stop
                            Write-Success "Removed $pkgName"
                            $newPackagesFound = $true
                        } catch {
                            Write-Warn "Could not remove package: $_"
                        }
                    }
                }
            }

            # Check for BitLocker error
            if ($logContent -match "0x80310039") {
                Write-Warn "BitLocker is blocking sysprep."

                # Kick off decryption if not already started
                manage-bde -off C: 2>&1 | Out-Null

                # Poll until fully decrypted
                Write-Info "Waiting for BitLocker decryption to complete..."
                $decrypting = $true
                while ($decrypting) {
                    Start-Sleep -Seconds 10
                    $blStatus = manage-bde -status C: | Out-String
                    if ($blStatus -match "Percentage Encrypted:\s+(\d+(\.\d+)?)%") {
                        $pct = $Matches[1]
                        Write-Host "`r  Decryption progress: $pct% remaining...    " -NoNewline -ForegroundColor White
                        if ([double]$pct -eq 0) {
                            $decrypting = $false
                        }
                    }
                    if ($blStatus -match "Conversion Status:\s+Fully Decrypted") {
                        $decrypting = $false
                    }
                }
                Write-Host ""
                Write-Success "BitLocker decryption complete."
                $newPackagesFound = $true  # Trigger a retry
            }

            # Check for reserved storage error
            if ($logContent -match "0x800F0975") {
                if ($reservedStorageAttempted) {
                    Write-Fail "Reserved storage conflict persists after mitigation."
                    Write-Info "Try these manual steps, then re-run the script:"
                    Write-Host ""
                    Write-Host "    1. Open Settings > Windows Update > Pause updates for 1 week" -ForegroundColor White
                    Write-Host "    2. Run: DISM /Online /Set-ReserveStorageState /State:Disabled" -ForegroundColor White
                    Write-Host "    3. Reboot the machine" -ForegroundColor White
                    Write-Host "    4. Re-run this script" -ForegroundColor White
                    Write-Host ""
                    break
                }

                Write-Warn "Reserved storage conflict detected. Applying mitigations..."

                # Stop all Windows Update related services
                foreach ($svc in @("wuauserv", "TrustedInstaller", "bits", "dosvc", "UsoSvc")) {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                }
                Write-Info "Stopped Windows Update services."

                # Disable reserved storage via DISM (more reliable than registry)
                try {
                    $dismResult = & DISM /Online /Set-ReserveStorageState /State:Disabled 2>&1
                    Write-Info "DISM: Reserved storage disabled."
                } catch {
                    Write-Warn "DISM failed: $_"
                }

                # Also set the registry key as a fallback
                try {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "ShippedWithReserves" -Value 0 -ErrorAction Stop
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "PassedPolicy" -Value 0 -ErrorAction SilentlyContinue
                } catch {
                    Write-Warn "Could not modify reserved storage registry setting."
                }

                # Clear Windows Update cache
                $wuCache = Join-Path $env:SystemRoot "SoftwareDistribution\Download"
                if (Test-Path $wuCache) {
                    Remove-Item "$wuCache\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Info "Cleared Windows Update download cache."
                }

                Write-Info "Waiting 10 seconds for services to fully stop..."
                Start-Sleep -Seconds 10

                $reservedStorageAttempted = $true
                $newPackagesFound = $true  # Trigger a retry
            }

            if (-not $newPackagesFound) {
                Write-Fail "Could not identify removable conflicting packages from the log."
                Write-Info "Dumping recent error lines from logs:"
                Write-Host ""
                foreach ($log in @($setupActLog, $setupErrLog)) {
                    if (Test-Path $log) {
                        Get-Content $log -Tail 30 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
                    }
                }
                Write-Host ""
                Write-Fail "Manual intervention may be required. Review the log output above."
                break
            }
        } else {
            Write-Fail "No sysprep log files found in $pantherDir"
            break
        }
    }
}

if (-not $sysprepSuccess) {
    Write-Host ""
    Write-Host "  =========================================" -ForegroundColor Red
    Write-Host "  SYSPREP FAILED after $attempt attempt(s)" -ForegroundColor Red
    Write-Host "  Review: $setupActLog" -ForegroundColor Red
    Write-Host "  =========================================" -ForegroundColor Red
    exit 1
}
