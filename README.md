# ProcessVigil

**Real-time security context overlays for Windows processes.**

ProcessVigil draws colored borders and identity tabs around windows running under elevated or non-standard security contexts — giving you an at-a-glance visual indicator of which windows are running as SYSTEM, elevated (Admin/UAC), or under a different user account.

\---

## What it does

|Color|Meaning|
|-|-|
|🔴 Red|Window is running under the **SYSTEM** account|
|🟠 Orange|Window is running **elevated (UAC Admin)** as the current user|
|🟡 Yellow|Window is running as a **different user** (RunAs / impersonation)|

Each flagged window gets a colored border ring and a tab showing the account name and context label. The tab automatically repositions itself if the window is maximized or snapped to the top edge of the screen.

\---

## Requirements

* Windows 10 or Windows 11
* PowerShell 7.2 or later
* Must be run from an **elevated (Administrator) PowerShell session**

\---

## Quick start

```powershell
.\\ProcessVigil.ps1
```

Press **Ctrl+C** to exit.

\---

## Parameters

|Parameter|Type|Description|
|-|-|-|
|`-RefreshMs`|`int`|Overlay refresh interval in milliseconds. Default: `50`|
|`-ShowWindowTitle`|`switch`|Adds the window title as a second row in the tab|
|`-ShowToastNotifications`|`switch`|Shows a balloon notification whenever a new elevated process is detected via the Security event log|
|`-Diag`|`switch`|Writes detailed detection diagnostics to `%TEMP%\\ocw\_debug.txt`|

```powershell
# Show window titles in the tab
.\\ProcessVigil.ps1 -ShowWindowTitle

# Toast notifications for new elevated processes
.\\ProcessVigil.ps1 -ShowToastNotifications

# All options combined
.\\ProcessVigil.ps1 -ShowWindowTitle -ShowToastNotifications
```

\---

## Installation

### Option 1 — Run directly

No installation required. Run `ProcessVigil.ps1` from any elevated PowerShell session.

### Option 2 — Install script

```powershell
.\\Install.ps1
```

Creates a Start Menu shortcut and optionally registers a scheduled task to launch ProcessVigil at logon. To remove:

```powershell
.\\Uninstall.ps1
```

### Enable Process Creation auditing (recommended)

For reliable detection of short-lived elevated processes (including browser launches), enable Security event 4688 logging:

```
auditpol /set /subcategory:"Process Creation" /success:enable
```

This is required for Chrome/Edge detection and for `-ShowToastNotifications` to work.

\---

## How it works

ProcessVigil runs a WinForms message pump with a 50ms timer. On each tick it:

1. Enumerates all visible, non-minimized windows using `EnumWindows`
2. Inspects each process token — checking integrity level (RID), elevation status (`TokenElevation`), and user SID (`TokenUser`)
3. Rebuilds the full process tree every \~10 seconds using a `CreateToolhelp32Snapshot`, cascading elevated status to child processes
4. Reads Security event log 4688 for processes that were elevated at creation time but have since exited or modified their token
5. Draws a Region-clipped, click-through (`WS\_EX\_TRANSPARENT | WS\_EX\_NOACTIVATE`) WinForms overlay for each flagged window

Overlays are positioned directly into the correct desktop z-slot using `DeferWindowPos` with `SWP\_SHOWWINDOW`, so they never flash to the top on creation.

\---

## Known limitations

### Chrome and Edge — sandbox architecture

Google Chrome and Microsoft Edge use a **multi-process sandboxed architecture**. When launched as Administrator, the browser creates an initial elevated broker process (recorded in Security event log as `%%1937`). This broker process exits within seconds and spawns sandboxed renderer, GPU, and utility child processes.

These child processes run with **deliberately restricted tokens** — Chrome/Edge's sandbox de-privileges them to Medium integrity with no elevation flag. Standard token inspection correctly reports them as non-elevated. The elevated broker has already exited before ProcessVigil's \~10-second tree rebuild runs.

ProcessVigil attempts to mitigate this by reading event 4688 and cascading the Admin classification to surviving child processes. This works in many cases but is not guaranteed because:

* The broker PID may be recycled before detection
* Chrome's multi-process tree is deep and the parent-child relationship can span multiple levels
* Some child processes use intermediate non-elevated launcher PIDs

**This is a fundamental limitation of observing sandboxed processes from outside the sandbox.** Detection of Chrome/Edge when run as admin remains best-effort.

### Windows Terminal

Windows Terminal's WinUI/UWP compositor renders above the Win32 z-order. ProcessVigil cannot place overlays on top of Windows Terminal windows regardless of their security context.

\---

## Code structure

```
ProcessVigil.ps1      Main script
Install.ps1           Installer
Uninstall.ps1         Uninstaller
README.md             This file
CHANGELOG.md          Version history
LICENSE               MIT License
.gitignore            Standard PowerShell gitignore
```

### Language breakdown

|Language|Lines|%|
|-|-|-|
|PowerShell|680|77%|
|C# (inline `Add-Type`)|202|23%|

The C# block provides Win32 P/Invoke declarations (user32, kernel32, advapi32, toolhelp32) and the window enumerator. All overlay rendering, detection logic, and control flow is PowerShell.

\---

## Contributing

Issues and pull requests are welcome. Please open an issue before starting significant work.

Areas that would benefit most from contribution:

* Reliable Chrome/Edge sandboxed process detection
* High-DPI / per-monitor DPI awareness
* Packaging as a signed MSIX or portable executable

\---

## License

MIT — see [LICENSE](LICENSE).

