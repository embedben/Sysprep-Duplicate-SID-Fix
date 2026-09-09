# Sysprep Duplicate SID Fix - Usage Guide

## Overview

Automates the Windows Sysprep `/generalize` process to fix duplicate SIDs across machines. Designed for fully remote execution with no on-site intervention required.

**Compatible with:** Windows 10 Pro and Windows 11 Pro

## Prerequisites

- Administrator access on the target machine
- Remote access (TeamViewer, RDP, etc.) to the target machine
- Copy the script files to the target machine

## Quick Start

1. Copy `Run-SysprepSIDFix.ps1` and `Run-SysprepSIDFix.bat` to the target machine
2. Right-click `Run-SysprepSIDFix.bat` and select **Run as administrator**
3. Enter the Administrator password when prompted
4. Confirm the settings and let the script run
5. The machine will reboot automatically when complete
6. Reconnect via RDP or TeamViewer and check `SysprepResult.txt` on the desktop

## Parameters

All parameters are optional. The script auto-captures hostname, timezone, and network config from the current machine.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-AdminPassword` | Administrator password after sysprep | Prompted at runtime |
| `-Hostname` | Computer name to assign | Current hostname |
| `-TimeZone` | Timezone ID (e.g. `Eastern Standard Time`) | Current timezone |
| `-IPAddress` | Static IP address to restore | Auto-captured |
| `-SubnetPrefix` | Subnet prefix length (e.g. `24`) | Auto-captured |
| `-Gateway` | Default gateway | Auto-captured |
| `-DNS` | DNS server(s) | Auto-captured |
| `-SkipNetworkRestore` | Leave network on DHCP after sysprep | `$false` |
| `-MaxRetries` | Max sysprep retry attempts | `10` |
| `-Force` | Skip confirmation prompts | `$false` |

## Examples

**Basic usage (recommended):**
```powershell
.\Run-SysprepSIDFix.ps1
```

**Pre-specify password (no prompt):**
```powershell
.\Run-SysprepSIDFix.ps1 -AdminPassword "YourPassword"
```

**Override network config:**
```powershell
.\Run-SysprepSIDFix.ps1 -IPAddress "192.168.1.100" -SubnetPrefix "24" -Gateway "192.168.1.1" -DNS "8.8.8.8","8.8.4.4"
```

**Skip network restore (use DHCP):**
```powershell
.\Run-SysprepSIDFix.ps1 -SkipNetworkRestore
```

## What the Script Does

1. **Captures machine identity** - Hostname, timezone, SID, and network config
2. **Saves network config** - Creates a restore script for after reboot
3. **Generates unattend.xml** - Deploys answer file to bypass all OOBE screens
4. **Checks TeamViewer** - Verifies remote access is configured
5. **Handles BitLocker** - Decrypts the drive if BitLocker is enabled (waits for completion)
6. **Pauses Windows Update** - Prevents reserved storage conflicts during sysprep
7. **Runs Sysprep** - Executes with automatic retry loop that removes conflicting packages as reported in the sysprep log

## After Reboot

- The machine boots straight to the desktop (auto-logon runs once)
- Network config is restored automatically
- RDP is enabled
- `SysprepResult.txt` on the desktop contains the new SID, hostname, IP, and TeamViewer ID
- Auto-logon is disabled after first boot

## Notes

- **TeamViewer ID will change** after sysprep. Use RDP or check the TeamViewer management console to reconnect.
- **BitLocker** must fully decrypt before sysprep can run. The script handles this automatically but large drives may take time.
- **Conflicting packages** (Store apps) are removed only when sysprep specifically reports them as blockers. You will be prompted before removal unless `-Force` is used.
