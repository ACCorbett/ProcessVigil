# Uninstall.ps1 — ProcessVigil uninstaller
# Removes the Start Menu shortcut and scheduled task created by Install.ps1.
# Must be run from an elevated PowerShell session.

#Requires -RunAsAdministrator

# ── Remove Start Menu shortcut ────────────────────────────────────────────────
$startMenu = [Environment]::GetFolderPath('CommonPrograms')
$shortcut  = Join-Path $startMenu 'ProcessVigil.lnk'
if (Test-Path $shortcut) {
    Remove-Item $shortcut -Force
    Write-Host "Start Menu shortcut removed." -ForegroundColor Green
} else {
    Write-Host "Start Menu shortcut not found (already removed)." -ForegroundColor DarkGray
}

# ── Remove scheduled task ─────────────────────────────────────────────────────
$taskName = 'ProcessVigil'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Scheduled task '$taskName' removed." -ForegroundColor Green
} else {
    Write-Host "Scheduled task '$taskName' not found (already removed)." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "ProcessVigil uninstalled." -ForegroundColor Cyan
