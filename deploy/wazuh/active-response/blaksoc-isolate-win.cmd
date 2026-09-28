@echo off
:: Wazuh runs .cmd active-response scripts on Windows; delegate to PowerShell.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0blaksoc-isolate-win.ps1" isolate
