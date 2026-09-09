@echo off
:: Launches Run-SysprepSIDFix.ps1 as Administrator
:: Place this file in the same directory as the .ps1 script and unattend.xml

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-SysprepSIDFix.ps1"
pause
