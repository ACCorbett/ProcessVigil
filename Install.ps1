# Install.ps1 — ProcessVigil installer
# Creates a Start Menu shortcut and optionally a logon scheduled task.
# Must be run from an elevated PowerShell session.

#Requires -RunAsAdministrator

$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $scriptDir 'ProcessVigil.ps1'

if (-not (Test-Path $scriptPath)) {
    Write-Error "ProcessVigil.ps1 not found in $scriptDir"
    exit 1
}

# ── Start Menu shortcut ───────────────────────────────────────────────────────
$startMenu  = [Environment]::GetFolderPath('CommonPrograms')
$shortcut   = Join-Path $startMenu 'ProcessVigil.lnk'
$shell      = New-Object -ComObject WScript.Shell
$lnk        = $shell.CreateShortcut($shortcut)
$lnk.TargetPath       = 'pwsh.exe'
$lnk.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$lnk.WorkingDirectory = $scriptDir
$lnk.Description      = 'ProcessVigil — Security context overlays'
$lnk.Save()
Write-Host "Start Menu shortcut created: $shortcut" -ForegroundColor Green

# ── Optional logon task ───────────────────────────────────────────────────────
$createTask = Read-Host "Create a scheduled task to run ProcessVigil at logon? [y/N]"
if ($createTask -match '^[Yy]') {
    $taskName   = 'ProcessVigil'
    $taskAction = New-ScheduledTaskAction `
        -Execute 'pwsh.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $taskTrigger  = New-ScheduledTaskTrigger -AtLogOn
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -RunLevel Highest `
        -LogonType Interactive

    Register-ScheduledTask `
        -TaskName  $taskName `
        -Action    $taskAction `
        -Trigger   $taskTrigger `
        -Settings  $taskSettings `
        -Principal $taskPrincipal `
        -Force | Out-Null

    Write-Host "Scheduled task '$taskName' registered (runs at logon, elevated)." -ForegroundColor Green
}

Write-Host ""
Write-Host "ProcessVigil installed. Run it from the Start Menu or:" -ForegroundColor Cyan
Write-Host "  pwsh -ExecutionPolicy Bypass -File `"$scriptPath`"" -ForegroundColor White
