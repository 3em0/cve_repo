# real_terminal_shot.ps1 - drive a REAL terminal window and capture REAL window screenshots
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File real_terminal_shot.ps1 `
#       -Scenario shot_scenario.json -OutDir ..\screenshots
#
# scenario.json:
# {
#   "shell": "powershell",                 // powershell | cmd
#   "workingDir": "%TEMP%\\poc-work",      // cd'ed first (%VAR% is expanded)
#   "initCommands": ["wsl -d kali-linux"], // sent before the first step, never captured
#   "windowWidth": 1400, "windowHeight": 680,
#   "settleMs": 1200,                      // default wait after every command
#   "typing": false,                       // false = clipboard paste (IME-proof), true = per-key
#   "steps": [
#     { "command": "python --version" },
#     { "wait": 1500 },
#     { "keys": "^-" },
#     { "shot": "01-version.png" }
#   ]
# }
#
# Local adaptations to the skill's script, needed because several agents share this desktop
# (Windows Terminal was hosting every new shell as a tab of one window, so a run could claim a
# stale console window another session had left behind -- the first attempt of this
# reproduction did exactly that and captured somebody else's old scrollback):
#   1. the terminal is started as an explicitly launched classic conhost window
#      (`conhost.exe <shell> ...`), never as a Windows Terminal tab;
#   2. the window title carries a unique random tag which is used to claim, re-claim, and
#      re-verify the window (the scenario can keep re-pinning it with %TITLE_TAG%);
#   3. every keystroke is preceded by a check that our own window is really in the foreground;
#   4. screenshots are rendered from the window handle (PrintWindow + PW_RENDERFULLCONTENT),
#      so a window of another session overlapping ours cannot be captured by mistake; screen
#      grabbing is only a fallback when the handle render returns a blank frame.
#   5. the shell name is normalised to an .exe name, because `conhost.exe powershell ...`
#      needs a resolvable executable.

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutDir = "screenshots",
    [string]$TitleTag = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class WinApi {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint nFlags);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);

    public static List<IntPtr> VisibleWindows() {
        var result = new List<IntPtr>();
        EnumWindows((h, l) => { if (IsWindowVisible(h)) result.Add(h); return true; }, IntPtr.Zero);
        return result;
    }
    public static string ProcNameOf(IntPtr h) {
        uint pid;
        GetWindowThreadProcessId(h, out pid);
        if (pid == 0) return "";
        try { return System.Diagnostics.Process.GetProcessById((int)pid).ProcessName; }
        catch { return ""; }
    }
}
"@

[WinApi]::SetProcessDPIAware() | Out-Null

function Get-WindowTitle {
    param([IntPtr]$h)
    $sb = New-Object System.Text.StringBuilder 512
    [WinApi]::GetWindowTextW($h, $sb, $sb.Capacity) | Out-Null
    return $sb.ToString()
}

function Get-WindowPid {
    param([IntPtr]$h)
    $ownerPid = 0
    [WinApi]::GetWindowThreadProcessId($h, [ref]$ownerPid) | Out-Null
    return [int]$ownerPid
}

function Find-TaggedWindow {
    # The tag is a random string this run wrote into the window title, so "title contains the
    # tag" means "this is the console window we just started". Matching by process name instead
    # grabs whatever terminal another concurrent session opened at the same moment.
    param([string]$Tag, [int]$TimeoutSec = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            if ((Get-WindowTitle $h) -notlike "*$Tag*") { continue }
            $r = New-Object WinApi+RECT
            [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
            if (($r.Right - $r.Left) -gt 200 -and ($r.Bottom - $r.Top) -gt 150) { return $h }
        }
        Start-Sleep -Milliseconds 300
    }
    return [IntPtr]::Zero
}

function Get-TargetWindow {
    # Re-claim by tag when the handle goes stale; fall back to "owner process is our shell",
    # which still holds after a shell inside the window rewrites the title (bash does that
    # as soon as WSL starts).
    param([string]$Tag, [IntPtr]$Current, [int]$OwnerPid = 0)
    if ($Current -ne [IntPtr]::Zero -and [WinApi]::IsWindowVisible($Current) -and
        (((Get-WindowTitle $Current) -like "*$Tag*") -or
         ($OwnerPid -gt 0 -and (Get-WindowPid $Current) -eq $OwnerPid))) {
        return $Current
    }
    $h = Find-TaggedWindow -Tag $Tag -TimeoutSec 6
    if ($h -ne [IntPtr]::Zero) { return $h }
    if ($OwnerPid -gt 0) {
        $deadline = (Get-Date).AddSeconds(6)
        while ((Get-Date) -lt $deadline) {
            foreach ($w in [WinApi]::VisibleWindows()) {
                if ((Get-WindowPid $w) -eq $OwnerPid) { return $w }
            }
            Start-Sleep -Milliseconds 300
        }
    }
    return [IntPtr]::Zero
}

function Assert-TargetWindow {
    # SendKeys types into whatever window is in the foreground, so nothing is sent before our
    # own console window is confirmed to be the foreground window. Abort instead of typing into
    # somebody else's session.
    param([IntPtr]$h, [string]$Tag, [int]$OwnerPid = 0)
    if ($h -eq [IntPtr]::Zero -or -not [WinApi]::IsWindowVisible($h)) {
        throw "target console window is gone; aborting before sending any keystroke"
    }
    $owned = ($OwnerPid -gt 0 -and (Get-WindowPid $h) -eq $OwnerPid)
    if (-not $owned -and ((Get-WindowTitle $h) -notlike "*$Tag*")) {
        throw "target window is neither tagged '$Tag' nor owned by our shell pid=$OwnerPid (title '$(Get-WindowTitle $h)'); aborting"
    }
    for ($i = 0; $i -lt 8; $i++) {
        Focus-Window $h
        Start-Sleep -Milliseconds 200
        if ([WinApi]::GetForegroundWindow() -eq $h) { return }
    }
    throw "our console window is not in the foreground (hwnd=$h); aborting before sending any keystroke"
}

function Focus-Window {
    param([IntPtr]$h)
    # tap ALT first to release the SetForegroundWindow foreground lock
    [WinApi]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
    [WinApi]::SetForegroundWindow($h) | Out-Null
    [WinApi]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
}

function Set-ClipboardWithRetry {
    param([string]$Text)
    for ($i = 0; $i -lt 6; $i++) {
        try { Set-Clipboard -Value $Text; return } catch {}
        try {
            [System.Windows.Forms.Clipboard]::SetText($Text)
            return
        } catch {}
        Start-Sleep -Milliseconds 400
    }
    throw "clipboard stayed locked after 6 attempts; paste aborted"
}

function Send-CommandText {
    # Paste by default (an active CJK IME cannot hijack the paste); typing = per-key SendKeys.
    param([string]$Text, [bool]$Typing)
    if ($Typing) {
        # Human-speed typing: a console drops or reorders keys when they arrive faster than
        # ~20/s, so keep a steady 60-90 ms cadence and give the window a moment to settle first.
        Start-Sleep -Milliseconds 400
        foreach ($ch in $Text.ToCharArray()) {
            $s = "$ch"
            if ($ch -match '[+^%~(){}\[\]]') { $s = "{$ch}" }
            [System.Windows.Forms.SendKeys]::SendWait($s)
            Start-Sleep -Milliseconds (Get-Random -Minimum 60 -Maximum 90)
        }
    }
    else {
        Set-ClipboardWithRetry -Text $Text
        Start-Sleep -Milliseconds 120
        [System.Windows.Forms.SendKeys]::SendWait("^v")
        Start-Sleep -Milliseconds 250
    }
    # look at it once more, like a human would, then press ENTER
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 450)
    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

function Get-WindowBoundsPixels {
    param([IntPtr]$h)
    $r = New-Object WinApi+RECT
    $hr = [WinApi]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][WinApi+RECT]))
    if ($hr -ne 0) { [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null }
    return $r
}

function Save-WindowShot {
    # Render the window from its own handle first: when another session's terminal sits on the
    # same pixels, grabbing the screen captures that window instead of ours.
    param([IntPtr]$h, [string]$Path)
    Focus-Window $h
    Start-Sleep -Milliseconds 250
    $r = Get-WindowBoundsPixels $h
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = $false
    try { $ok = [WinApi]::PrintWindow($h, $hdc, 2) } catch { $ok = $false }
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    if ($ok) {
        $colors = @{}
        for ($x = 5; $x -lt $w; $x += 40) {
            for ($y = 5; $y -lt $ht; $y += 40) { $colors[$bmp.GetPixel($x, $y).ToArgb()] = 1 }
        }
        if ($colors.Count -lt 3) { $ok = $false }
    }
    if (-not $ok) {
        Write-Output ("PrintWindow returned a blank frame for hwnd=$h; falling back to screen capture")
        $g2 = [System.Drawing.Graphics]::FromImage($bmp)
        $g2.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
        $g2.Dispose()
    }
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

function Expand-PathVars {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return ([regex]::Replace($Text, '%([A-Za-z_][A-Za-z0-9_]*)%', {
        param($m)
        $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        if ([string]::IsNullOrEmpty($v)) { $m.Value } else { $v }
    }))
}

# ============================== main ==============================

$cfg = Get-Content -Raw -Encoding UTF8 $Scenario | ConvertFrom-Json
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path

if ($cfg.workingDir) { $cfg.workingDir = Expand-PathVars ([string]$cfg.workingDir) }

$shellName = if ($cfg.shell) { $cfg.shell } else { "powershell" }
if ($shellName -notmatch '\.exe$') { $shellName = "$shellName.exe" }
$typing = [bool]$cfg.typing

$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

try {
    if (-not $TitleTag) { $TitleTag = "dsh-poc-" + ([guid]::NewGuid().ToString("N").Substring(0, 10)) }

    # Start our own tagged console window.
    #   terminal = "wt" (scenario flag): a Windows Terminal window/tab.  Needed when a command
    #     inside the window switches the console into VT input mode (docker run -it does), which
    #     turns conhost's Ctrl+V paste off; Windows Terminal pastes itself, so it keeps working.
    #   default: a classic conhost window, which cannot be confused with another session's tab.
    $inner = if ($shellName -match 'cmd') { "title $TitleTag" } else { "`$Host.UI.RawUI.WindowTitle='$TitleTag'" }
    $shellArgs = if ($shellName -match 'cmd') { @("/k", $inner) } else { @("-NoExit", "-Command", $inner) }
    if ($cfg.terminal -eq 'wt') {
        $proc = Start-Process $shellName -ArgumentList $shellArgs -PassThru
    }
    elseif ($cfg.terminal -eq 'wtnew') {
        # -w new: force a brand-new Windows Terminal window instead of a tab in somebody
        # else's window (several sessions share this desktop)
        $proc = Start-Process wt.exe -ArgumentList (@('-w', 'new', $shellName) + $shellArgs) -PassThru
    }
    else {
        $proc = Start-Process conhost.exe -ArgumentList (@($shellName) + $shellArgs) -PassThru
    }

    $hwnd = Find-TaggedWindow -Tag $TitleTag
    if ($hwnd -eq [IntPtr]::Zero) { throw "could not find the console window we just started (tag=$TitleTag)" }
    $shellPid = Get-WindowPid $hwnd
    Write-Output ("target window: hwnd=$hwnd shell-pid=$shellPid title-tag=$TitleTag")

    # Bring it to the front and give it a sensible size.
    Start-Sleep -Milliseconds 800
    [WinApi]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
    Focus-Window $hwnd
    Start-Sleep -Milliseconds 300
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1000 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 640 }
    [WinApi]::MoveWindow($hwnd, 80, 80, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 500

    # init commands (never captured); %TITLE_TAG% lets the scenario re-pin the window title
    $hwnd = Get-TargetWindow -Tag $TitleTag -Current $hwnd -OwnerPid $shellPid
    Assert-TargetWindow -h $hwnd -Tag $TitleTag -OwnerPid $shellPid
    if ($cfg.workingDir) {
        Send-CommandText -Text ("cd " + $cfg.workingDir) -Typing $typing
        Start-Sleep -Milliseconds 2500
    }
    if ($cfg.initCommands) {
        foreach ($c in $cfg.initCommands) {
            $hwnd = Get-TargetWindow -Tag $TitleTag -Current $hwnd -OwnerPid $shellPid
            Assert-TargetWindow -h $hwnd -Tag $TitleTag -OwnerPid $shellPid
            Send-CommandText -Text ([string]$c).Replace('%TITLE_TAG%', $TitleTag) -Typing $typing
            Start-Sleep -Milliseconds 2500
        }
    }

    # one command -> wait for it -> capture when asked
    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            $hwnd = Get-TargetWindow -Tag $TitleTag -Current $hwnd -OwnerPid $shellPid
            Assert-TargetWindow -h $hwnd -Tag $TitleTag -OwnerPid $shellPid
            Send-CommandText -Text ([string]$step.command).Replace('%TITLE_TAG%', $TitleTag) -Typing $typing
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            [System.Windows.Forms.SendKeys]::SendWait([string]$step.keys)
            Start-Sleep -Milliseconds 600
        }
        elseif ($step.PSObject.Properties["wait"]) {
            Start-Sleep -Milliseconds ([int]$step.wait)
        }
        elseif ($step.PSObject.Properties["shot"]) {
            $hwnd = Get-TargetWindow -Tag $TitleTag -Current $hwnd -OwnerPid $shellPid
            Assert-TargetWindow -h $hwnd -Tag $TitleTag -OwnerPid $shellPid
            $p = Join-Path $OutDir ([string]$step.shot)
            Save-WindowShot -h $hwnd -Path $p
            $shots += $p
        }
    }

    Write-Output ("DONE " + ($shots -join "; "))
}
finally {
    if ($null -ne $savedClip) { try { Set-Clipboard -Value $savedClip } catch {} }
}
