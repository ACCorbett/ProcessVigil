# Changelog

All notable changes to ProcessVigil will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-04-20

### Initial release

- Colored border overlays: Red (SYSTEM), Orange (Admin/Elevated), Yellow (RunAs/different user)
- Chrome-style tab showing account name and context label
- Tab auto-flips inside title bar when window is maximized or top-snapped
- `-ShowWindowTitle` — adds window title as a second row in the tab
- `-ShowToastNotifications` — balloon tip via system tray when a new elevated process is detected via Security event 4688
- `-Diag` — writes full detection diagnostics to `%TEMP%\ocw_debug.txt`
- Process tree cascade: Admin classification propagates to child processes of elevated parents
- Security event log integration (event 4688, `%%1937`) for short-lived elevated processes
- Correct z-order from first frame via `DeferWindowPos` with `SWP_SHOWWINDOW`
- Skip list for known system UI hosts (TextInputHost, ShellExperienceHost, etc.)
- Multiple re-runs supported in the same PowerShell session
- Multi-monitor aware with correct snap/maximize detection per monitor
