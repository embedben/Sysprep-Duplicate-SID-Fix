# Sysprep Duplicate SID Fix

Automates the Windows Sysprep `/generalize` process to fix duplicate SIDs across machines that were cloned without proper image preparation. Designed for **fully remote execution** with no on-site intervention required.

## The Problem

Windows updates released August 29, 2025 and later introduced security protections that enforce SID (Security Identifier) uniqueness checks during Kerberos and NTLM authentication:

- **[KB5064081](https://support.microsoft.com/en-us/topic/kerberos-and-ntlm-authentication-failures-due-to-duplicate-sids-76f7394d-c460-4882-9ed1-d27e0960f949)** (August 29, 2025) — Preview update, OS Build 26100.5074
- **[KB5065426](https://support.microsoft.com/en-us/topic/kerberos-and-ntlm-authentication-failures-due-to-duplicate-sids-76f7394d-c460-4882-9ed1-d27e0960f949)** (September 9, 2025) — General availability, OS Build 26100.6584

Machines cloned or imaged without running `sysprep /generalize` share the same machine SID. After these updates, authentication between machines with duplicate SIDs fails — users are repeatedly prompted for credentials, file shares break, and network resources become inaccessible. Failed requests are logged as **Event ID 6167** (lsasrv.dll) in the System event log.

**Affected systems:** Windows 11 24H2, Windows 11 25H2, Windows Server 2025

## What This Tool Does

The script handles the entire sysprep workflow in a single run:

1. **Captures machine identity** — Hostname, timezone, current SID, and network configuration
2. **Saves network config** — Creates a restore script so static IPs survive the reboot
3. **Generates unattend.xml** — Dynamically builds the answer file to bypass all OOBE screens
4. **Checks remote access** — Verifies TeamViewer LAN connection settings
5. **Handles BitLocker** — Decrypts the drive if BitLocker is enabled (waits for full decryption)
6. **Pauses Windows Update** — Prevents reserved storage conflicts during sysprep
7. **Runs Sysprep with auto-retry** — Automatically removes conflicting packages reported in the sysprep error log and retries

After reboot, the machine comes back online with a new unique SID, the original hostname and timezone, restored network config, and RDP enabled. A `SysprepResult.txt` file is placed on the desktop with the new SID, IP addresses, and TeamViewer ID.

## Requirements

- Windows 10 Pro or Windows 11 Pro
- Administrator access on the target machine
- Remote access (TeamViewer, RDP, etc.)

## Quick Start

1. Copy `Run-SysprepSIDFix.ps1` and `Run-SysprepSIDFix.bat` to the target machine
2. Right-click `Run-SysprepSIDFix.bat` and select **Run as administrator**
3. Enter the Administrator password when prompted
4. Confirm the settings and let the script run
5. The machine reboots automatically — reconnect and check `SysprepResult.txt` on the desktop

## Usage

```powershell
# Basic — auto-captures hostname, timezone, network config; prompts for password
.\Run-SysprepSIDFix.ps1

# Pre-specify password
.\Run-SysprepSIDFix.ps1 -AdminPassword "YourPassword"

# Override network config
.\Run-SysprepSIDFix.ps1 -IPAddress "192.168.1.100" -SubnetPrefix "24" -Gateway "192.168.1.1" -DNS "8.8.8.8","8.8.4.4"

# Skip network restore (use DHCP after reboot)
.\Run-SysprepSIDFix.ps1 -SkipNetworkRestore
```

See [USAGE.md](USAGE.md) for the full parameter reference.

## How to Verify Duplicate SIDs

Before running, confirm the machines actually share a SID:

```powershell
# Run on each machine — if the output matches, the SIDs are duplicated
(whoami /user /fo csv | ConvertFrom-Csv).SID -replace '-\d+$', ''
```

## Notes

- **TeamViewer ID will change** after sysprep — use RDP or the TeamViewer management console to reconnect
- **BitLocker** must fully decrypt before sysprep runs; the script handles this but large drives may take time
- **Conflicting packages** (Store apps) are only removed when sysprep specifically reports them as blockers; you are prompted before removal unless `-Force` is used
- The static `unattend.xml` in the repo is a reference template — the script generates it dynamically at runtime

## References

- [Microsoft: Kerberos and NTLM authentication failures due to duplicate SIDs](https://support.microsoft.com/en-us/topic/kerberos-and-ntlm-authentication-failures-due-to-duplicate-sids-76f7394d-c460-4882-9ed1-d27e0960f949)
- [Microsoft Q&A: Duplicate SIDs discussion](https://learn.microsoft.com/en-us/answers/questions/5596430/kerberos-and-ntlm-authentication-failures-due-to-d)
