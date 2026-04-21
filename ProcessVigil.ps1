# ProcessVigil.ps1  v1.0.0
# https://github.com/YOUR_USERNAME/ProcessVigil
#
# Draws colored security-context overlays on Windows:
#   Red    — SYSTEM context
#   Orange — Elevated / Admin (same user, UAC-elevated)
#   Yellow — Different user (RunAs / impersonation)
#
# Requires: PowerShell 7+, Windows 10/11, elevated (admin) session
# Optional: Security audit policy for Chrome/Edge detection
#           auditpol /set /subcategory:"Process Creation" /success:enable

param([int]$RefreshMs = 50, [switch]$Diag, [switch]$ShowWindowTitle, [switch]$ShowToastNotifications)

Set-StrictMode -Off

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ── Win32 + token helpers ─────────────────────────────────────────────────────
if (-not ([System.Management.Automation.PSTypeName]'WinApiOCW28').Type) {
Add-Type @"
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;

public static class WinApiOCW28 {

    // ── Structs ───────────────────────────────────────────────────────────────
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    public struct MONITORINFO {
        public int  cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    // ── user32 ────────────────────────────────────────────────────────────────
    [DllImport("user32.dll")] public static extern bool   EnumWindows(EnumWindowsProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool   GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern int    GetWindowLong(IntPtr h, int n);
    [DllImport("user32.dll")] public static extern int    SetWindowLong(IntPtr h, int n, int v);
    [DllImport("user32.dll")] public static extern bool   SetWindowPos(IntPtr h, IntPtr after,
                                  int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool   ShowWindow(IntPtr h, int cmd);
    public const int SW_SHOWNOACTIVATE = 4;
    [DllImport("user32.dll")] public static extern IntPtr BeginDeferWindowPos(int n);
    [DllImport("user32.dll")] public static extern IntPtr DeferWindowPos(IntPtr hdwp, IntPtr h,
                                  IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool   EndDeferWindowPos(IntPtr hdwp);
    [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint cmd);
    [DllImport("user32.dll")] public static extern int    GetSystemMetrics(int n);
    [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
    [DllImport("user32.dll")] public static extern bool   GetMonitorInfo(IntPtr mon, ref MONITORINFO mi);
    [DllImport("user32.dll")] public static extern bool   IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool   IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern bool   IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern int    GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern int    GetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] public static extern int    GetClassName(IntPtr h, StringBuilder cls, int n);
    [DllImport("user32.dll")] public static extern uint   GetWindowThreadProcessId(IntPtr h, out uint pid);

    // ── kernel32 / advapi32 ───────────────────────────────────────────────────
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint acc, bool inh, uint pid);
    [DllImport("kernel32.dll")] public static extern bool   CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern bool   GetProcessTimes(IntPtr h,
        out long created, out long exited, out long kernel, out long user);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr proc, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupAccountSid(string sys, IntPtr sid,
        StringBuilder name, ref uint nl, StringBuilder dom, ref uint dl, out int use);

    // ── Constants ─────────────────────────────────────────────────────────────
    public const int   GWL_EXSTYLE              = -20;
    public const int   GWL_STYLE                = -16;
    public const int   WS_POPUP                 = unchecked((int)0x80000000);
    public const int   WS_EX_TOOLWINDOW         = 0x00000080;
    public const int   WS_EX_NOACTIVATE_FLAG    = 0x08000000;
    public const int   WS_EX_TRANSPARENT        = 0x00000020;
    public const int   WS_EX_NOACTIVATE         = 0x08000000;
    public const uint  SWP_NOMOVE               = 0x0002;
    public const uint  SWP_NOSIZE               = 0x0001;
    public const uint  SWP_NOACTIVATE           = 0x0010;
    public const uint  SWP_NOSENDCHANGING       = 0x0400;
    public const uint  GW_HWNDPREV              = 3;
    public const uint  GW_HWNDNEXT              = 2;
    public const int   SM_CXSIZE                = 30;
    public const uint  MONITOR_DEFAULTTONEAREST = 0x00000002;
    public const int   MONITORINFO_SIZE         = 40;
    public const uint  PROCESS_QUERY_LIMITED    = 0x1000;
    public const uint  TOKEN_QUERY              = 0x0008;
    public const int   TOK_USER                 = 1;
    public const int   TOK_ELEVATION            = 20;
    public const int   TOK_INTEGRITY            = 25;

    // Toolhelp32 — used to walk the process parent chain
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
    public struct PROCESSENTRY32 {
        public uint  dwSize, cntUsage, th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint  th32ModuleID, cntThreads, th32ParentProcessID;
        public int   pcPriClassBase;
        public uint  dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
        public string szExeFile;
    }
    [DllImport("kernel32.dll")] public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint pid);
    [DllImport("kernel32.dll")] public static extern bool   Process32First(IntPtr snap, ref PROCESSENTRY32 pe);
    [DllImport("kernel32.dll")] public static extern bool   Process32Next(IntPtr snap,  ref PROCESSENTRY32 pe);
    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint INVALID_HANDLE_VALUE_UINT = 0xFFFFFFFF;

    // Returns ALL (pid, parentPid) pairs as a flat interleaved uint[]:
    // [pid0, parent0, pid1, parent1, ...]
    // Takes ONE snapshot so callers don't need to snapshot per-PID.
    public static uint[] GetProcessParentMap() {
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if ((uint)(ulong)snap == INVALID_HANDLE_VALUE_UINT) return new uint[0];
        var list = new System.Collections.ArrayList();
        try {
            var pe = new PROCESSENTRY32();
            pe.dwSize = (uint)Marshal.SizeOf(pe);
            if (!Process32First(snap, ref pe)) return new uint[0];
            do {
                list.Add(pe.th32ProcessID);
                list.Add(pe.th32ParentProcessID);
                pe.dwSize = (uint)Marshal.SizeOf(pe);
            } while (Process32Next(snap, ref pe));
        } finally { CloseHandle(snap); }
        var result = new uint[list.Count];
        for (int i = 0; i < list.Count; i++) result[i] = (uint)list[i];
        return result;
    }

    // ── Token helpers (called from PS) ────────────────────────────────────────
    public static int GetIntegrityRid(IntPtr tok) {
        int r; GetTokenInformation(tok, TOK_INTEGRITY, IntPtr.Zero, 0, out r);
        if (r <= 0) return -1;
        IntPtr p = Marshal.AllocHGlobal(r);
        try {
            if (!GetTokenInformation(tok, TOK_INTEGRITY, p, r, out r)) return -1;
            IntPtr sid = Marshal.ReadIntPtr(p);
            byte sc = Marshal.ReadByte(sid, 1);
            return Marshal.ReadInt32(sid, 8 + 4 * (sc - 1));
        } finally { Marshal.FreeHGlobal(p); }
    }

    public static string GetTokenUser(IntPtr tok) {
        int r; GetTokenInformation(tok, TOK_USER, IntPtr.Zero, 0, out r);
        if (r <= 0) return null;
        IntPtr p = Marshal.AllocHGlobal(r);
        try {
            if (!GetTokenInformation(tok, TOK_USER, p, r, out r)) return null;
            IntPtr sid = Marshal.ReadIntPtr(p);
            var name = new StringBuilder(256); uint nl = 256;
            var dom  = new StringBuilder(256); uint dl = 256; int use;
            if (!LookupAccountSid(null, sid, name, ref nl, dom, ref dl, out use)) return null;
            return dom + "\\" + name;
        } finally { Marshal.FreeHGlobal(p); }
    }

    public static bool GetElevated(IntPtr tok) {
        int r; IntPtr p = Marshal.AllocHGlobal(4);
        try {
            return GetTokenInformation(tok, TOK_ELEVATION, p, 4, out r)
                   && Marshal.ReadInt32(p) != 0;
        } finally { Marshal.FreeHGlobal(p); }
    }

    // Enumerate visible non-minimised titled windows.
    // Defined in a separate class (WinEnum_OCW28 below) because calling
    // [DllImport] extern methods from another static method in the same
    // static class fails to resolve in .NET 10 Roslyn (CS0103).
}

// Separate class so WinApiOCW28 P/Invoke calls are fully qualified.
public static class WinEnum_OCW28 {
    public static IntPtr[] GetAll() {
        var list = new System.Collections.ArrayList();
        WinApiOCW28.EnumWindowsProc cb = (h, lp) => {
            if (!WinApiOCW28.IsWindowVisible(h) || WinApiOCW28.IsIconic(h) ||
                WinApiOCW28.GetWindowTextLength(h) == 0)
                return true;
            // Skip shell desktop and wallpaper windows — these span full monitors
            // and are owned by the system but carry no user-meaningful context.
            var cls = new StringBuilder(256);
            WinApiOCW28.GetClassName(h, cls, 256);
            string c = cls.ToString();
            if (c == "Progman" || c == "WorkerW" || c == "Shell_TrayWnd" ||
                c == "Shell_SecondaryTrayWnd" || c == "DV2ControlHost" ||
                c == "#32768" ||   // menu
                c == "#32771" ||   // Alt+Tab switcher
                c == "tooltips_class32" || c == "BaseBar")
                return true;
            // Skip popup windows that are tool/menu windows — these are context menus,
            // dropdowns, tooltips etc. drawn by apps like Chrome as owned popup windows.
            // A real application window has WS_OVERLAPPED (0) or WS_OVERLAPPEDWINDOW,
            // not WS_POPUP alone combined with WS_EX_TOOLWINDOW or WS_EX_NOACTIVATE.
            int style   = WinApiOCW28.GetWindowLong(h, WinApiOCW28.GWL_STYLE);
            int exStyle = WinApiOCW28.GetWindowLong(h, WinApiOCW28.GWL_EXSTYLE);
            bool isPopup      = (style   & WinApiOCW28.WS_POPUP)               != 0;
            bool isToolWindow = (exStyle & WinApiOCW28.WS_EX_TOOLWINDOW)       != 0;
            bool isNoActivate = (exStyle & WinApiOCW28.WS_EX_NOACTIVATE_FLAG)  != 0;
            if (isPopup && (isToolWindow || isNoActivate))
                return true;
            list.Add(h);
            return true;
        };
        WinApiOCW28.EnumWindows(cb, IntPtr.Zero);
        return (IntPtr[])list.ToArray(typeof(IntPtr));
    }
}
"@
}

# ── Identity of the running user ──────────────────────────────────────────────
# Use env vars so the format matches LookupAccountSid (DOMAIN\user).
$currentUser = "$env:USERDOMAIN\$env:USERNAME"

# ── Context detection via full process tree ───────────────────────────────────
# Build the entire pid->kind and pid->parentPid maps once per flush interval.
# This is more reliable than per-window parent-chain lookups because:
#   - One snapshot captures all processes atomically
#   - Chrome/Edge renderers run with de-elevated tokens; we find the elevated
#     browser parent by walking the cached tree rather than retrying OpenProcess
$pidKindMap      = @{}   # [uint32] pid  -> kind string or $null
$pidParentMap    = @{}   # [uint32] pid  -> [uint32] parentPid
$windowKindCache = @{}   # IntPtr hwnd  -> kind string or $null

function Get-EventLogElevatedPids {
    # Query Security event log for event 4688 (Process Creation).
    # TokenElevationType %%1937 = TokenElevationTypeFull = elevated via UAC.
    # Returns a hashtable: [uint32]pid -> [long]eventFileTime
    # The FileTime lets callers compare with process creation time to detect PID reuse.
    $elevated  = @{}
    $dbgLines  = @()
    $evCount   = 0
    $elevCount = 0
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id      = 4688
        } -MaxEvents 5000 -ErrorAction Stop

        $evCount = $events.Count
        foreach ($ev in $events) {
            try {
                $xml      = [xml]$ev.ToXml()
                $data     = $xml.Event.EventData.Data
                $elevType = ($data | Where-Object { $_.Name -eq 'TokenElevationType' }).'#text'
                $procName = ($data | Where-Object { $_.Name -eq 'NewProcessName'     }).'#text'
                $pidStr   = ($data | Where-Object { $_.Name -eq 'NewProcessId'       }).'#text'
                if (-not $pidStr) { continue }
                $pidDec = $pidStr -replace '^0x', ''
                $newPid = [uint32]([Convert]::ToUInt64($pidDec, 16))
                if ($newPid -eq 0) { continue }

                if ($elevType -eq '%%1937') {
                    $elevated[[uint32]$newPid] = @{
                        Name = $procName
                        Time = $ev.TimeCreated.ToFileTime()
                    }
                    $elevCount++
                    if ($script:Diag) {
                        $dbgLines += ("EVT4688 ELEVATED  PID={0,-6} time={1} {2}" -f $newPid, $ev.TimeCreated.ToString('HH:mm:ss'), $procName)
                    }
                } elseif ($script:Diag) {
                    $typeStr = switch ($elevType) {
                        '%%1936' { 'default' } '%%1938' { 'limited' } default { $elevType }
                    }
                    $dbgLines += ("EVT4688 {0,-8} PID={1,-6} {2}" -f $typeStr.ToUpper(), $newPid, $procName)
                }
            } catch { }
        }
    } catch {
        if ($script:Diag) {
            $dbgLines += "EVT4688 ERROR: $($_.Exception.Message)"
            $dbgLines += "(Audit Process Creation may not be enabled — run: auditpol /set /subcategory:'Process Creation' /success:enable)"
        }
    }

    if ($script:Diag -and $script:DiagFile) {
        "" | Out-File -Append $script:DiagFile
        "=== Event Log (4688) ===" | Out-File -Append $script:DiagFile
        ("Total 4688 events read: {0}   Elevated (%%1937): {1}" -f $evCount, $elevCount) | Out-File -Append $script:DiagFile
        foreach ($l in $dbgLines) { $l | Out-File -Append $script:DiagFile }
    }
    return $elevated
}

function Rebuild-ProcessTree {
    # One snapshot for the entire parent-map
    $raw = [WinApiOCW28]::GetProcessParentMap()
    $newParents = @{}
    for ($i = 0; $i -lt $raw.Length - 1; $i += 2) {
        $newParents[[uint32]$raw[$i]] = [uint32]$raw[$i+1]
    }
    $script:pidParentMap = $newParents

    # Primary: inspect every process token
    $newKinds    = @{}
    $tokenDbg    = @()
    foreach ($procId in $newParents.Keys) {
        if ($procId -eq 0) { continue }
        $hProc = [WinApiOCW28]::OpenProcess([WinApiOCW28]::PROCESS_QUERY_LIMITED, $false, $procId)
        if ($hProc -eq [IntPtr]::Zero) {
            if ($script:Diag) { $tokenDbg += ("TOK PID={0,-6} OpenProcess FAILED" -f $procId) }
            continue
        }
        try {
            $hTok = [IntPtr]::Zero
            if (-not [WinApiOCW28]::OpenProcessToken($hProc, [WinApiOCW28]::TOKEN_QUERY, [ref]$hTok)) {
                if ($script:Diag) { $tokenDbg += ("TOK PID={0,-6} OpenProcessToken FAILED" -f $procId) }
                continue
            }
            try {
                $elev = [WinApiOCW28]::GetElevated($hTok)
                $rid  = [WinApiOCW28]::GetIntegrityRid($hTok)
                $user = [WinApiOCW28]::GetTokenUser($hTok)
                $diff = $user -and (-not $user.Equals($script:currentUser,
                            [System.StringComparison]::OrdinalIgnoreCase))

                $kind = if     ($rid -ge 0x4000)           { 'System' } `
                        elseif ($diff)                      { 'RunAs'  } `
                        elseif ($elev -or $rid -ge 0x3000) { 'Admin'  } `
                        else                               { $null    }

                $newKinds[[uint32]$procId] = $kind

                if ($script:Diag -and ($kind -or -not $user)) {
                    $procName = try { (Get-Process -Id $procId -EA Stop).ProcessName } catch { '?' }
                    $tokenDbg += ("TOK PID={0,-6} kind={1,-8} elev={2} rid=0x{3:X4} user={4} proc={5}" `
                        -f $procId, "$kind", $elev, $rid, $user, $procName)
                }
            } finally { [void][WinApiOCW28]::CloseHandle($hTok) }
        } finally { [void][WinApiOCW28]::CloseHandle($hProc) }
    }

    # Secondary: merge Security event log elevated PIDs.
    # Chrome/Edge launch an elevated browser process briefly, then it exits.
    # By the time our rebuild runs, the PID is already dead — so we must add it
    # to the map even when OpenProcess fails, so the cascade can still mark its
    # surviving child renderer/GPU processes.
    # PID reuse guard: if the PID IS still running, verify the process name
    # matches the event-log entry before applying Admin.
    $eventElevated = Get-EventLogElevatedPids
    foreach ($ePid in $eventElevated.Keys) {
        $pidU   = [uint32]$ePid
        $evInfo = $eventElevated[$pidU]   # hashtable: Name, Time
        $evName = [System.IO.Path]::GetFileName($evInfo.Name).ToLower()

        $existing = if ($newKinds.ContainsKey($pidU)) { $newKinds[$pidU] } else { $null }
        if ($existing -eq 'System' -or $existing -eq 'RunAs') { continue }

        $hProc = [WinApiOCW28]::OpenProcess([WinApiOCW28]::PROCESS_QUERY_LIMITED, $false, $pidU)
        if ($hProc -eq [IntPtr]::Zero) {
            # Process already exited — safe to apply; PID reuse within the event
            # log window (~minutes) is extremely unlikely.
            $newKinds[$pidU] = 'Admin'
        } else {
            try {
                # PID still running — verify name matches to guard against reuse
                $curName = try { [System.IO.Path]::GetFileName(
                    (Get-Process -Id $pidU -EA Stop).Path).ToLower() } catch { '' }
                if (-not $curName -or $curName -eq $evName) {
                    $newKinds[$pidU] = 'Admin'
                }
            } finally { [void][WinApiOCW28]::CloseHandle($hProc) }
        }
    }

    # Cascade: mark all direct children of elevated processes as the same kind.
    # Chrome/Edge: GetWindowThreadProcessId often returns a renderer/GPU subprocess
    # rather than the browser process.  The browser is the parent; by pre-marking
    # every child of an elevated process we ensure the subprocess lookup hits too.
    # Use a copy of Keys to avoid modifying the dictionary mid-iteration.
    $elevatedPids = @($newKinds.Keys | Where-Object { $newKinds[$_] })
    foreach ($elevPid in $elevatedPids) {
        $kind = $newKinds[$elevPid]
        foreach ($childPid in $newParents.Keys) {
            if ($newParents[$childPid] -eq $elevPid -and -not $newKinds.ContainsKey([uint32]$childPid)) {
                $newKinds[[uint32]$childPid] = $kind
            }
        }
    }

    $script:pidKindMap      = $newKinds
    $script:windowKindCache = @{}

    if ($script:Diag -and $script:DiagFile) {
        "" | Out-File -Append $script:DiagFile
        "=== Token Inspection (notable entries) ===" | Out-File -Append $script:DiagFile
        foreach ($l in $tokenDbg) { $l | Out-File -Append $script:DiagFile }
        "" | Out-File -Append $script:DiagFile
        ("=== pidKindMap: {0} elevated entries ===" -f ($newKinds.Values | Where-Object { $_ } | Measure-Object).Count) | Out-File -Append $script:DiagFile
        foreach ($kv in ($newKinds.GetEnumerator() | Where-Object { $_.Value })) {
            $procName = try { (Get-Process -Id $kv.Key -EA Stop).ProcessName } catch { '?' }
            ("PID={0,-6} kind={1,-8} proc={2}" -f $kv.Key, $kv.Value, $procName) | Out-File -Append $script:DiagFile
        }
        "--- Rebuild complete $(Get-Date) ---" | Out-File -Append $script:DiagFile
        Write-Host "  [DIAG] Rebuild complete — see $($script:DiagFile)" -ForegroundColor Magenta
    }
}

function Get-WindowKind($hwnd) {
    if ($script:windowKindCache.ContainsKey($hwnd)) { return $script:windowKindCache[$hwnd] }

    $procId = [uint32]0
    [void][WinApiOCW28]::GetWindowThreadProcessId($hwnd, [ref]$procId)
    if ($procId -eq 0) { $script:windowKindCache[$hwnd] = $null; return $null }

    # Skip known Windows system UI host processes that are legitimately SYSTEM
    # but carry no user-actionable security context (input, shell chrome, etc.)
    $skipProcs = @('TextInputHost','ShellExperienceHost','StartMenuExperienceHost',
                   'SearchHost','SearchApp','LockApp','LogonUI','fontdrvhost')
    $procName = try { (Get-Process -Id $procId -EA Stop).ProcessName } catch { '' }
    if ($skipProcs -contains $procName) {
        $script:windowKindCache[$hwnd] = $null
        return $null
    }

    # Level 1: check the window's direct owning process.
    $kind = if ($script:pidKindMap.ContainsKey($procId)) { $script:pidKindMap[$procId] } else { $null }

    # Level 2: if direct process is Normal or missing, check its parent.
    # This is the confirmed Chrome/Edge pattern: GetWindowThreadProcessId returns a
    # renderer/GPU subprocess; the elevated browser process is its direct parent and
    # matches the event-log PID.
    if (-not $kind) {
        $parentPid = if ($script:pidParentMap.ContainsKey($procId)) { $script:pidParentMap[$procId] } else { [uint32]0 }
        if ($parentPid -ne 0) {
            $kind = if ($script:pidKindMap.ContainsKey($parentPid)) { $script:pidKindMap[$parentPid] } else { $null }
        }
    }

    if ($script:Diag -and $kind) {
        $procName   = try { (Get-Process -Id $procId   -EA Stop).ProcessName } catch { '?' }
        $parentPid2 = if ($script:pidParentMap.ContainsKey($procId)) { $script:pidParentMap[$procId] } else { 0 }
        $parentName = try { (Get-Process -Id $parentPid2 -EA Stop).ProcessName } catch { '?' }
        $len = [WinApiOCW28]::GetWindowTextLength($hwnd)
        $sb  = New-Object System.Text.StringBuilder($len + 1)
        [void][WinApiOCW28]::GetWindowText($hwnd, $sb, $sb.Capacity)
        ("WIN hwnd={0} pid={1}({2}) ppid={3}({4}) kind={5} title='{6}'" `
            -f $hwnd, $procId, $procName, $parentPid2, $parentName, $kind, $sb.ToString()) |
            Out-File -Append $script:DiagFile
    }

    $script:windowKindCache[$hwnd] = $kind
    return $kind
}

# ── Colors per context ────────────────────────────────────────────────────────
function Get-ContextColor($kind) {
    switch ($kind) {
        'System' { return [System.Drawing.Color]::FromArgb(200,  30,  30) }  # Red
        'Admin'  { return [System.Drawing.Color]::FromArgb(210, 100,   0) }  # Orange
        'RunAs'  { return [System.Drawing.Color]::FromArgb(180, 160,   0) }  # Yellow
        default  { return [System.Drawing.Color]::Gray }
    }
}

function Get-ContextLabel($kind) {
    switch ($kind) {
        'System' { return 'SYSTEM' }
        'Admin'  { return 'ADMIN'  }
        'RunAs'  { return 'RUNAS'  }
        default  { return ''       }
    }
}

# ── Tuning (verbatim from blue_border.ps1) ────────────────────────────────────
$thick           = 5
$borderRadius    = 12
$titleRadius     = 7
$flairR          = 8
$edgeInset       = 8
$titlePad        = 6
$captionBtnWidth = [WinApiOCW28]::GetSystemMetrics([WinApiOCW28]::SM_CXSIZE)
if ($captionBtnWidth -lt 40) { $captionBtnWidth = 46 }

$HWND_TOPMOST   = [IntPtr]::new(-1)
$HWND_NOTOPMOST = [IntPtr]::new(-2)
$swpZ  = [WinApiOCW28]::SWP_NOMOVE -bor [WinApiOCW28]::SWP_NOSIZE -bor [WinApiOCW28]::SWP_NOACTIVATE
$swpZs = $swpZ -bor [WinApiOCW28]::SWP_NOSENDCHANGING

# ── Enable-AtomicPaint (verbatim) ─────────────────────────────────────────────
function Enable-AtomicPaint($form) {
    $m = [System.Windows.Forms.Control].GetMethod(
            'SetStyle', [System.Reflection.BindingFlags]'NonPublic,Instance')
    $s = [System.Windows.Forms.ControlStyles]'AllPaintingInWmPaint,UserPaint,OptimizedDoubleBuffer'
    $m.Invoke($form, @($s, $true))
}

# ── Geometry helpers (verbatim from blue_border.ps1) ─────────────────────────
function New-RoundedPath([float]$x,[float]$y,[float]$w,[float]$h,[float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $p.AddArc($x,         $y,         $r*2,$r*2, 180, 90)
    $p.AddArc($x+$w-$r*2, $y,         $r*2,$r*2, 270, 90)
    $p.AddArc($x+$w-$r*2, $y+$h-$r*2, $r*2,$r*2,   0, 90)
    $p.AddArc($x,         $y+$h-$r*2, $r*2,$r*2,  90, 90)
    $p.CloseFigure()
    return $p
}

function New-TabPath([float]$w,[float]$h,[float]$r,[float]$flair,[bool]$flipped=$false) {
    $tabH = $h - $flair
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $p.AddArc($flair,          0, $r*2, $r*2, 180,  90)
    $p.AddArc($w-$flair-$r*2,  0, $r*2, $r*2, 270,  90)
    $p.AddArc($w-$flair, $tabH-$flair, $flair*2, $flair*2, 180, -90)
    $p.AddArc(-$flair,   $tabH-$flair, $flair*2, $flair*2,  90, -90)
    $p.CloseFigure()
    if ($flipped) {
        $m = New-Object System.Drawing.Drawing2D.Matrix(1, 0, 0, -1, 0, $h)
        $p.Transform($m)
        $m.Dispose()
    }
    return $p
}

# Per-form variants — take the form as a parameter instead of using $borderForm/$titleForm globals
function Set-BorderRegionOn($form, [int]$w, [int]$h, [System.Drawing.Color]$col) {
    if ($w -lt 10 -or $h -lt 10) { return }
    $form.BackColor = $col
    $ro     = $borderRadius
    $ri     = [Math]::Max(2, $ro - $thick)
    $outer  = New-RoundedPath 0 0 $w $h $ro
    $inner  = New-RoundedPath $thick $thick ($w-$thick*2) ($h-$thick*2) $ri
    $region = New-Object System.Drawing.Region($outer)
    $region.Exclude($inner)
    if ($form.Region) { $form.Region.Dispose() }
    $form.Region = $region
    $outer.Dispose(); $inner.Dispose()
}

function Set-TitleRegionOn($form, [int]$w, [int]$h, [bool]$flipped=$false) {
    $path   = New-TabPath $w $h $titleRadius $flairR $flipped
    $region = New-Object System.Drawing.Region($path)
    $path.Dispose()
    if ($form.Region) { $form.Region.Dispose() }
    $form.Region = $region
}

# ── Get-AdjustedRect (verbatim from blue_border.ps1) ─────────────────────────
function Get-AdjustedRect($hwnd) {
    $r = New-Object WinApiOCW28+RECT
    [void][WinApiOCW28]::GetWindowRect($hwnd, [ref]$r)

    $mon = [WinApiOCW28]::MonitorFromWindow($hwnd, [WinApiOCW28]::MONITOR_DEFAULTTONEAREST)
    $mi  = New-Object WinApiOCW28+MONITORINFO
    $mi.cbSize = [WinApiOCW28]::MONITORINFO_SIZE
    [void][WinApiOCW28]::GetMonitorInfo($mon, [ref]$mi)
    $m  = $mi.rcMonitor
    $mw = $mi.rcWork

    if ($r.Left   -lt $m.Left)   { $r.Left   += $edgeInset }
    if ($r.Top    -lt $m.Top)    { $r.Top    += $edgeInset }
    if ($r.Right  -gt $m.Right)  { $r.Right  -= $edgeInset }
    if ($r.Bottom -gt $m.Bottom) { $r.Bottom -= $edgeInset }

    $r.Left   = [Math]::Max($r.Left,   $mw.Left)
    $r.Right  = [Math]::Min($r.Right,  $mw.Right)
    $r.Bottom = [Math]::Min($r.Bottom, $mw.Bottom)

    $snapTop = ($m.Top -le $r.Top) -and ($r.Top - $m.Top -le $edgeInset + 2)

    return @{ Rect = $r; TopSnapped = $snapTop; MonitorTop = $m.Top; WorkTop = $mw.Top }
}

# ── Sync-ZOrder (verbatim logic from blue_border.ps1, parameterised) ─────────
function Sync-ZOrder($borderHandle, $tabHandle, $targetHwnd, [bool]$force = $false) {
    if (-not $force) {
        $bNext = [WinApiOCW28]::GetWindow($borderHandle, [WinApiOCW28]::GW_HWNDNEXT)
        $tNext = [WinApiOCW28]::GetWindow($tabHandle,    [WinApiOCW28]::GW_HWNDNEXT)
        $bOk   = ($bNext -eq $targetHwnd -or $bNext -eq $tabHandle)
        $tOk   = ($tNext -eq $targetHwnd -or $tNext -eq $borderHandle)
        if ($bOk -and $tOk) { return }
    }

    if ([WinApiOCW28]::GetForegroundWindow() -eq $targetHwnd) {
        $h = [WinApiOCW28]::BeginDeferWindowPos(2)
        $h = [WinApiOCW28]::DeferWindowPos($h,$borderHandle,$script:HWND_TOPMOST,  0,0,0,0,$script:swpZ)
        $h = [WinApiOCW28]::DeferWindowPos($h,$tabHandle,   $script:HWND_TOPMOST,  0,0,0,0,$script:swpZ)
        [void][WinApiOCW28]::EndDeferWindowPos($h)
        $h = [WinApiOCW28]::BeginDeferWindowPos(2)
        $h = [WinApiOCW28]::DeferWindowPos($h,$borderHandle,$script:HWND_NOTOPMOST,0,0,0,0,$script:swpZ)
        $h = [WinApiOCW28]::DeferWindowPos($h,$tabHandle,   $script:HWND_NOTOPMOST,0,0,0,0,$script:swpZ)
        [void][WinApiOCW28]::EndDeferWindowPos($h)
    } else {
        $above = [WinApiOCW28]::GetWindow($targetHwnd, [WinApiOCW28]::GW_HWNDPREV)
        while ($above -ne [IntPtr]::Zero -and
               ($above -eq $borderHandle -or $above -eq $tabHandle)) {
            $above = [WinApiOCW28]::GetWindow($above, [WinApiOCW28]::GW_HWNDPREV)
        }
        $h = [WinApiOCW28]::BeginDeferWindowPos(2)
        $h = [WinApiOCW28]::DeferWindowPos($h,$borderHandle,$above,0,0,0,0,$script:swpZs)
        $h = [WinApiOCW28]::DeferWindowPos($h,$tabHandle,   $above,0,0,0,0,$script:swpZs)
        [void][WinApiOCW28]::EndDeferWindowPos($h)
    }
}

# ── Per-window state ──────────────────────────────────────────────────────────
$borderForms = @{}   # IntPtr → Form
$tabForms    = @{}   # IntPtr → Form
$tabFlipped  = @{}   # IntPtr → bool
$tabPrevW    = @{}   # IntPtr → int
$tabPrevH    = @{}   # IntPtr → int

# Tab paint data stored at script scope keyed by hwnd string.
# The titleForm.Add_Paint handler reads this via $script:tabPaintData[$s.Tag].
$tabPaintData = @{}  # string(hwnd) → hashtable

function New-OverlayPair($hwnd, $kind) {
    $col   = Get-ContextColor $kind
    $label = Get-ContextLabel $kind

    # Measure text for this window's user
    $procId = [uint32]0
    [void][WinApiOCW28]::GetWindowThreadProcessId($hwnd, [ref]$procId)
    $hProc = [WinApiOCW28]::OpenProcess([WinApiOCW28]::PROCESS_QUERY_LIMITED, $false, $procId)
    $userName = $script:currentUser
    if ($hProc -ne [IntPtr]::Zero) {
        $hTok = [IntPtr]::Zero
        if ([WinApiOCW28]::OpenProcessToken($hProc, [WinApiOCW28]::TOKEN_QUERY, [ref]$hTok)) {
            $u = [WinApiOCW28]::GetTokenUser($hTok)
            if ($u) { $userName = $u }
            [void][WinApiOCW28]::CloseHandle($hTok)
        }
        [void][WinApiOCW28]::CloseHandle($hProc)
    }

    # Shorten long usernames
    if ($userName.Length -gt 32) {
        $b = $userName.LastIndexOf('\')
        $userName = if ($b -ge 0) { $userName.Substring($b+1) } else { $userName.Substring(0,29)+'...' }
    }

    # Get window title for optional second row
    $winTitle = ''
    if ($script:ShowWindowTitle) {
        $winTitleSb = New-Object System.Text.StringBuilder 256
        [void][WinApiOCW28]::GetWindowText($hwnd, $winTitleSb, 256)
        $winTitle = $winTitleSb.ToString()
        if ($winTitle.Length -gt 50) { $winTitle = $winTitle.Substring(0,47) + '...' }
    }

    $bmp  = New-Object System.Drawing.Bitmap(1,1)
    $gfx  = [System.Drawing.Graphics]::FromImage($bmp)
    $userSz    = $gfx.MeasureString($userName, $script:titleFont,  [int]::MaxValue, $script:sf)
    $labelSz   = $gfx.MeasureString("  $label  ", $script:titleFont, [int]::MaxValue, $script:sf)
    $row1W     = [int]($userSz.Width + $labelSz.Width) + $titlePad*2 + 6
    $titleBodyW = $row1W
    $row1H      = [System.Windows.Forms.TextRenderer]::MeasureText($userName, $script:titleFont).Height
    $row2H      = 0
    if ($script:ShowWindowTitle -and $winTitle) {
        $winTitleSz  = $gfx.MeasureString($winTitle, $script:titleFont2, [int]::MaxValue, $script:sf)
        $row2W       = [int]$winTitleSz.Width + $titlePad*2 + 6
        $titleBodyW  = [Math]::Max($row1W, $row2W)
        $row2H       = [System.Windows.Forms.TextRenderer]::MeasureText($winTitle, $script:titleFont2).Height
    }
    $gfx.Dispose(); $bmp.Dispose()

    $titleRowGap = if ($row2H -gt 0) { 2 } else { 0 }
    $titleW = $titleBodyW + $flairR * 2
    $titleH = $row1H + $row2H + $titlePad*2 + $flairR + $titleRowGap

    # Store paint data at script scope — readable by the Add_Paint handler
    $key = $hwnd.ToString()
    $script:tabPaintData[$key] = @{
        BgColor   = $col
        UserText  = $userName
        Label     = "  $label  "
        WinTitle  = $winTitle
        UserSzW   = [int]$userSz.Width
        Row1H     = $row1H
        TitlePad  = $titlePad
        FlairR    = $flairR
        TitleW    = $titleW
        TitleH    = $titleH
        Flipped   = $false
    }

    # ── Border form ───────────────────────────────────────────────────────────
    $bf = New-Object System.Windows.Forms.Form
    $bf.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $bf.BackColor       = $col
    $bf.ShowInTaskbar   = $false
    $bf.Location        = [System.Drawing.Point]::new(-32000,-32000)
    $bf.Size            = [System.Drawing.Size]::new(10,10)
    Enable-AtomicPaint $bf
    $bf.Add_Paint({ param($s,$e) $e.Graphics.Clear($s.BackColor) })
    $bf.Add_FormClosing({ param($s,$e)
        if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) { $e.Cancel = $true }
    })

    # ── Title form ────────────────────────────────────────────────────────────
    $tf = New-Object System.Windows.Forms.Form
    $tf.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $tf.BackColor       = $col
    $tf.ShowInTaskbar   = $false
    $tf.Width           = $titleW
    $tf.Height          = $titleH
    $tf.Tag             = $key    # key into $script:tabPaintData
    Enable-AtomicPaint $tf
    $tf.Add_FormClosing({ param($s,$e)
        if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) { $e.Cancel = $true }
    })

    # Paint handler — reads from $script:tabPaintData[$s.Tag]
    $tf.Add_Paint({
        param($s,$e)
        $d = $script:tabPaintData[$s.Tag]
        if (-not $d) { return }
        $g = $e.Graphics
        $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $w   = $s.Width
        $h   = $s.Height
        $ox  = $d.FlairR
        $ty0 = if ($d.Flipped) { $d.FlairR + $d.TitlePad } else { $d.TitlePad }
        $g.Clear($d.BgColor)
        # Highlight line
        $hlY = if ($d.Flipped) { $h - 2 } else { 1 }
        $hlPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(80,255,255,255), 1)
        $g.DrawLine($hlPen, ($ox + $script:titleRadius), $hlY, ($w - $ox - $script:titleRadius), $hlY)
        $hlPen.Dispose()
        # Row 1: user text + label badge
        $sh = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(100,0,0,0))
        $g.DrawString($d.UserText, $script:titleFont, $sh, ($ox + $d.TitlePad + 1), ($ty0 + 1))
        $sh.Dispose()
        $g.DrawString($d.UserText, $script:titleFont, [System.Drawing.Brushes]::White, ($ox + $d.TitlePad), $ty0)
        $bx = $ox + $d.UserSzW + $d.TitlePad
        $bb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0,0,0,60))
        $g.FillRectangle($bb, [System.Drawing.Rectangle]::new($bx, 0, ($w-$bx), $h))
        $bb.Dispose()
        $bs = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(100,0,0,0))
        $g.DrawString($d.Label, $script:titleFont, $bs, ($bx+1), ($ty0+1))
        $bs.Dispose()
        $g.DrawString($d.Label, $script:titleFont, [System.Drawing.Brushes]::White, $bx, $ty0)
        # Row 2: window title in smaller font (only when -ShowWindowTitle is set)
        if ($script:ShowWindowTitle -and $d.WinTitle) {
            $ty1 = $ty0 + $d.Row1H + 2
            $divPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60,255,255,255), 1)
            $g.DrawLine($divPen, ($ox + $d.TitlePad), ($ty0 + $d.Row1H + 1), ($w - $ox - $d.TitlePad), ($ty0 + $d.Row1H + 1))
            $divPen.Dispose()
            $ts = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(100,0,0,0))
            $g.DrawString($d.WinTitle, $script:titleFont2, $ts, ($ox + $d.TitlePad + 1), ($ty1 + 1))
            $ts.Dispose()
            $tg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(220,255,255,255))
            $g.DrawString($d.WinTitle, $script:titleFont2, $tg, ($ox + $d.TitlePad), $ty1)
            $tg.Dispose()
        }
    })

    # Set empty title BEFORE creating handles so WinEnum never picks these up.
    $bf.Text = ""
    $tf.Text = ""

    # Calculate initial position and flip — same logic as the tick loop.
    $adj = Get-AdjustedRect $hwnd
    $r   = $adj.Rect
    $bw  = $r.Right - $r.Left
    $bh  = $r.Bottom - $r.Top

    # 1. Force handle creation BEFORE setting anything.
    #    Accessing .Handle creates the Win32 window invisibly.
    $bfHandle = $bf.Handle
    $tfHandle = $tf.Handle

    # 2. Set exstyle on live handles.
    $bfEx = [WinApiOCW28]::GetWindowLong($bfHandle, [WinApiOCW28]::GWL_EXSTYLE)
    [void][WinApiOCW28]::SetWindowLong($bfHandle, [WinApiOCW28]::GWL_EXSTYLE,
        $bfEx -bor [WinApiOCW28]::WS_EX_TRANSPARENT -bor [WinApiOCW28]::WS_EX_NOACTIVATE)
    $tfEx = [WinApiOCW28]::GetWindowLong($tfHandle, [WinApiOCW28]::GWL_EXSTYLE)
    [void][WinApiOCW28]::SetWindowLong($tfHandle, [WinApiOCW28]::GWL_EXSTYLE,
        $tfEx -bor [WinApiOCW28]::WS_EX_TRANSPARENT -bor [WinApiOCW28]::WS_EX_NOACTIVATE)

    # 3. Calculate position and flip using actual post-handle dimensions.
    $tx = $r.Left + $borderRadius - $flairR
    $ty = $r.Top - $tf.Height
    $monTopInRange = $adj.MonitorTop -le $r.Top
    $initFlipped   = $adj.TopSnapped -or ($monTopInRange -and $ty -lt $adj.MonitorTop)
    if ($initFlipped) {
        $tx = $r.Right - $captionBtnWidth*3 - $tf.Width - 4
        $ty = $r.Top + $thick
    }

    $bf.SetBounds($r.Left, $r.Top, $bw, $bh)
    $tf.Location = [System.Drawing.Point]::new($tx, $ty)

    # 4. Set regions on live handles with the correct flip state.
    Set-BorderRegionOn $bf $bw $bh $col
    Set-TitleRegionOn  $tf $tf.Width $tf.Height $initFlipped

    # 5. Stamp flip into paint data.
    $script:tabPaintData[$key].Flipped = $initFlipped

    # Register in dictionaries BEFORE Show() so the tick loop never double-creates.
    $script:borderForms[$hwnd] = $bf
    $script:tabForms[$hwnd]    = $tf
    $script:tabFlipped[$hwnd]  = $initFlipped
    $script:tabPrevW[$hwnd]    = 0
    $script:tabPrevH[$hwnd]    = 0

    # 6. Show both forms atomically at the correct z-slot via SWP_SHOWWINDOW.
    $above   = [WinApiOCW28]::GetWindow($hwnd, [WinApiOCW28]::GW_HWNDPREV)
    $swpShow = [WinApiOCW28]::SWP_NOACTIVATE -bor 0x0040  # SWP_SHOWWINDOW
    $h = [WinApiOCW28]::BeginDeferWindowPos(2)
    $h = [WinApiOCW28]::DeferWindowPos($h, $bfHandle, $above, 0, 0, 0, 0,
             $swpShow -bor [WinApiOCW28]::SWP_NOMOVE -bor [WinApiOCW28]::SWP_NOSIZE)
    $h = [WinApiOCW28]::DeferWindowPos($h, $tfHandle, $above, 0, 0, 0, 0,
             $swpShow -bor [WinApiOCW28]::SWP_NOMOVE -bor [WinApiOCW28]::SWP_NOSIZE)
    [void][WinApiOCW28]::EndDeferWindowPos($h)
}

function Remove-OverlayPair($hwnd) {
    # Also evict from window kind cache so a recycled HWND gets re-evaluated
    $script:windowKindCache.Remove($hwnd)
    $key = $hwnd.ToString()
    foreach ($d in @($script:borderForms, $script:tabForms)) {
        if ($d.ContainsKey($hwnd)) {
            $f = $d[$hwnd]
            if (-not $f.IsDisposed) { $f.Hide(); $f.Close() }
        }
    }
    $script:borderForms.Remove($hwnd)
    $script:tabForms.Remove($hwnd)
    $script:tabFlipped.Remove($hwnd)
    $script:tabPrevW.Remove($hwnd)
    $script:tabPrevH.Remove($hwnd)
    $script:tabPaintData.Remove($key)
}

# ── Timer tick (scriptblock defined once; timer recreated each run) ───────────
$timerTick = {
    try {
    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
            $timer.Stop()
            foreach ($hwnd in @($script:borderForms.Keys)) { Remove-OverlayPair $hwnd }
            $hostForm.Add_FormClosing({ param($s,$e) $e.Cancel = $false })
            $hostForm.Close()
            return
        }
    }

    $script:tickCount++
    # Rebuild process tree on startup (tick 1) and every ~10 s
    if ($script:tickCount -eq 1 -or $script:tickCount % 200 -eq 0) { Rebuild-ProcessTree }
    # Check for new elevated processes every ~2 s for toast notifications
    if ($script:tickCount % 40 -eq 0) { Check-NewElevatedProcesses }

    # ── Build current set of windows that need overlays ───────────────────────
    $wanted = @{}
    foreach ($hwnd in [WinEnum_OCW28]::GetAll()) {
        $kind = Get-WindowKind $hwnd
        if ($kind) { $wanted[$hwnd] = $kind }
    }

    # Remove overlays for windows that closed or dropped back to Normal
    foreach ($hwnd in @($script:borderForms.Keys)) {
        if (-not $wanted.ContainsKey($hwnd) -or -not [WinApiOCW28]::IsWindow($hwnd)) {
            Remove-OverlayPair $hwnd
        }
    }

    # Create or update each overlay pair
    foreach ($hwnd in $wanted.Keys) {
        $kind = $wanted[$hwnd]

        if (-not $script:borderForms.ContainsKey($hwnd)) {
            New-OverlayPair $hwnd $kind
        }

        $bf  = $script:borderForms[$hwnd]
        $tf  = $script:tabForms[$hwnd]
        $key = $hwnd.ToString()
        $adj = Get-AdjustedRect $hwnd
        $r   = $adj.Rect
        $w   = $r.Right  - $r.Left
        $h   = $r.Bottom - $r.Top
        if ($w -lt 20 -or $h -lt 20) { continue }

        $col = Get-ContextColor $kind
        $bf.BackColor = $col
        if ($script:tabPaintData.ContainsKey($key)) {
            $script:tabPaintData[$key].BgColor = $col
            # Refresh window title when -ShowWindowTitle is active
            if ($script:ShowWindowTitle) {
                $wtSb = New-Object System.Text.StringBuilder 256
                [void][WinApiOCW28]::GetWindowText($hwnd, $wtSb, 256)
                $wt = $wtSb.ToString()
                if ($wt.Length -gt 50) { $wt = $wt.Substring(0,47) + '...' }
                $script:tabPaintData[$key].WinTitle = $wt
            }
        }

        # Border: rebuild region on resize, then move/size
        if ($bf.Width -ne $w -or $bf.Height -ne $h) {
            Set-BorderRegionOn $bf $w $h $col
        }
        if ($bf.Width -ne $w -or $bf.Height -ne $h) {
            $bf.SetBounds($r.Left, $r.Top, $w, $h)
        } elseif ($bf.Left -ne $r.Left -or $bf.Top -ne $r.Top) {
            $bf.Location = [System.Drawing.Point]::new($r.Left, $r.Top)
        }

        # Tab: position + flip logic (verbatim from blue_border.ps1 timer tick)
        $tx = $r.Left + $borderRadius - $flairR
        $ty = $r.Top - $tf.Height
        $monTopInRange = $adj.MonitorTop -le $r.Top
        $newFlipped    = $adj.TopSnapped -or ($monTopInRange -and $ty -lt $adj.MonitorTop)
        if ($newFlipped) {
            $tx = $r.Right - $captionBtnWidth*3 - $tf.Width - 4
            $ty = $r.Top + $thick
        }
        if ($newFlipped -ne $script:tabFlipped[$hwnd]) {
            $script:tabFlipped[$hwnd] = $newFlipped
            if ($script:tabPaintData.ContainsKey($key)) { $script:tabPaintData[$key].Flipped = $newFlipped }
            Set-TitleRegionOn $tf $tf.Width $tf.Height $newFlipped
            $tf.Invalidate()
        }
        if ($tf.Left -ne $tx -or $tf.Top -ne $ty) {
            $tf.Location = [System.Drawing.Point]::new($tx, $ty)
        }

        Sync-ZOrder $bf.Handle $tf.Handle $hwnd
    }
    } catch {
        $errFile = "$env:TEMP\ocw_error.txt"
        "TICK ERROR at $(Get-Date -Format 'HH:mm:ss'): $($_.Exception.Message)" | Out-File -Append $errFile
        "$($_.ScriptStackTrace)" | Out-File -Append $errFile
    }
}   # end $timerTick scriptblock

# ── DebugOutput flag at script scope (readable from all functions) ───────────
$script:Diag                  = $Diag.IsPresent
$script:ShowWindowTitle       = $ShowWindowTitle.IsPresent
$script:ShowToastNotifications = $ShowToastNotifications.IsPresent

# ── Toast notifications ───────────────────────────────────────────────────────
function Send-ElevatedProcessToast($procName, $procPid, $userName) {
    if (-not $script:notifyIcon) { return }
    try {
        $shortName = [System.IO.Path]::GetFileName($procName)
        $script:notifyIcon.ShowBalloonTip(
            5000,
            "Elevated Process Started",
            "$shortName  (PID: $procPid)`nUser: $userName",
            [System.Windows.Forms.ToolTipIcon]::Warning
        )
    } catch { }
}

function Check-NewElevatedProcesses {
    # Query Security log for 4688 events newer than our last check time.
    # Only fires when -ShowToastNotifications is active.
    if (-not $script:ShowToastNotifications) { return }
    try {
        $filter = @{
            LogName   = 'Security'
            Id        = 4688
            StartTime = $script:lastToastCheck
        }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -EA Stop
        foreach ($ev in $events) {
            try {
                $xml      = [xml]$ev.ToXml()
                $data     = $xml.Event.EventData.Data
                $elevType = ($data | Where-Object Name -eq 'TokenElevationType').'#text'
                if ($elevType -ne '%%1937') { continue }
                $procName = ($data | Where-Object Name -eq 'NewProcessName').'#text'
                $pidStr   = ($data | Where-Object Name -eq 'NewProcessId').'#text'
                $subj     = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
                $subjDom  = ($data | Where-Object Name -eq 'SubjectDomainName').'#text'
                $pidDec   = [uint32]([Convert]::ToUInt64(($pidStr -replace '^0x',''), 16))
                $userName = if ($subjDom -and $subj) { "$subjDom\$subj" } else { $subj }
                Send-ElevatedProcessToast $procName $pidDec $userName
            } catch { }
        }
    } catch { }   # no events or audit not enabled — silently skip
    $script:lastToastCheck = (Get-Date)
}

# ── Legend ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Window Context Overlay" -ForegroundColor White
Write-Host "  Running as: $currentUser" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Red    = SYSTEM" -ForegroundColor Red
Write-Host "  Orange = Admin / Elevated" -ForegroundColor DarkYellow
Write-Host "  Yellow = Different user (RunAs)" -ForegroundColor Yellow
Write-Host ""
if ($script:Diag) {
    $script:DiagFile = "$env:TEMP\ocw_debug.txt"
    $null = New-Item -Force -ItemType File $script:DiagFile
    Write-Host "  DIAG MODE — writing to: $($script:DiagFile)" -ForegroundColor Magenta
    Write-Host ""
    "=== WindowContextOverlay Diagnostic ===" | Out-File $script:DiagFile
    "Started: $(Get-Date)" | Out-File -Append $script:DiagFile
    "Running as: $script:currentUser" | Out-File -Append $script:DiagFile
}
Write-Host "  Ctrl+C to exit." -ForegroundColor DarkGray
if ($script:ShowToastNotifications) {
    Write-Host "  Toast notifications ON — monitoring for elevated processes." -ForegroundColor DarkCyan
}
Write-Host ""

# ── Run ───────────────────────────────────────────────────────────────────────
# All per-run objects created here so the script can be re-run in the same
# PS session without stale disposed objects or double-registered event handlers.
$script:borderForms   = @{}
$script:tabForms      = @{}
$script:tabFlipped    = @{}
$script:tabPrevW      = @{}
$script:tabPrevH      = @{}
$script:tabPaintData  = @{}
$script:pidKindMap    = @{}
$script:pidParentMap  = @{}
$script:windowKindCache = @{}
$script:tickCount     = 0
$script:lastToastCheck = (Get-Date)

# NotifyIcon for balloon notifications (only created when -ShowToastNotifications)
$script:notifyIcon = $null
if ($script:ShowToastNotifications) {
    $script:notifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:notifyIcon.Icon    = [System.Drawing.SystemIcons]::Shield
    $script:notifyIcon.Text    = "Window Context Overlay"
    $script:notifyIcon.Visible = $true
}

$script:titleFont  = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:titleFont2 = New-Object System.Drawing.Font('Segoe UI', 7, [System.Drawing.FontStyle]::Regular)
$script:sf         = [System.Drawing.StringFormat]::GenericTypographic

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $RefreshMs
$timer.Add_Tick($timerTick)

[Console]::TreatControlCAsInput = $true
while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }

$hostForm = New-Object System.Windows.Forms.Form
$hostForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$hostForm.ShowInTaskbar   = $false
$hostForm.Opacity         = 0
$hostForm.Text            = ""
$hostForm.Size            = [System.Drawing.Size]::new(1,1)
$hostForm.Location        = [System.Drawing.Point]::new(-32000,-32000)
$hostForm.Add_FormClosing({ param($s,$e)
    if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) { $e.Cancel = $true }
})
$hostForm.Add_Load({ $timer.Start() })
$hostForm.Show()

# Manual message pump — avoids Application.Run which permanently marks itself
# as exited after the first Application.Exit() call, causing instant return
# on subsequent runs in the same PS session.
try {
    while (-not $hostForm.IsDisposed) {
        [System.Windows.Forms.Application]::DoEvents()
        [System.Threading.Thread]::Sleep(10)
    }
} finally {
    $timer.Stop()
    $timer.Dispose()
    if (-not $hostForm.IsDisposed) { $hostForm.Close() }
    [Console]::TreatControlCAsInput = $false
    foreach ($hwnd in @($script:borderForms.Keys)) { Remove-OverlayPair $hwnd }
    $script:titleFont.Dispose()
    $script:titleFont2.Dispose()
    if ($script:notifyIcon) { $script:notifyIcon.Visible = $false; $script:notifyIcon.Dispose() }
    Write-Host "  Overlay stopped." -ForegroundColor DarkGray
}
