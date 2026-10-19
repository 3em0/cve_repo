# shot_capture.ps1 - drive a real terminal like a human and screenshot the real window.
#
# Hardened variant of the cve-report skill's real_terminal_shot.ps1 for capture
# hosts where several tasks run at once on the same desktop:
#
#   * OUR terminal is launched with a unique window title and is located BY THAT
#     TITLE, never by the "newest visible terminal window" heuristic - that
#     heuristic makes concurrent agents drive each other's terminals.
#   * the window is made TOPMOST for the duration of the run, so a window that
#     steals the foreground cannot end up inside our screenshots;
#   * the foreground is VERIFIED (GetForegroundWindow == our hwnd) before every
#     single paste and before every capture, and the run aborts loudly if the
#     focus cannot be held.
#
# ASCII only on purpose: Windows PowerShell 5.1 parses BOM-less files as ANSI,
# so non-ASCII comments would break the script.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File shot_capture.ps1 -Scenario s.json -OutDir shots

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutDir = "screenshots"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public static class Cap32 {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextLengthW(IntPtr hWnd);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);

    public static List<IntPtr> VisibleWindows() {
        var result = new List<IntPtr>();
        EnumWindows((h, l) => { if (IsWindowVisible(h)) result.Add(h); return true; }, IntPtr.Zero);
        return result;
    }
    public static string TitleOf(IntPtr h) {
        int len = GetWindowTextLengthW(h);
        if (len <= 0) return "";
        var sb = new StringBuilder(len + 2);
        GetWindowTextW(h, sb, sb.Capacity);
        return sb.ToString();
    }
}
"@

[Cap32]::SetProcessDPIAware() | Out-Null

$HWND_TOPMOST = [IntPtr](-1)
$HWND_NOTOPMOST = [IntPtr](-2)
$SWP_NOMOVE = 0x0002
$SWP_NOSIZE = 0x0001

function Find-WindowByTitle {
    param([string]$Title)
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [Cap32]::VisibleWindows()) {
            if ([Cap32]::TitleOf($h) -eq $Title) { return $h }
        }
        Start-Sleep -Milliseconds 250
    }
    return [IntPtr]::Zero
}

function Assert-Focus {
    # Returns only when OUR window really owns the foreground; aborts otherwise.
    param([IntPtr]$h, [string]$What)
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline) {
        # other tasks on this desktop also keep their windows always-on-top, so
        # re-raising ours is part of taking the foreground, not just focusing it
        [Cap32]::SetWindowPos($h, $HWND_TOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE)) | Out-Null
        if ([Cap32]::GetForegroundWindow() -eq $h) { return }
        [Cap32]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
        [Cap32]::SetForegroundWindow($h) | Out-Null
        [Cap32]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 150
    }
    throw "foreground could not be held on our terminal window before $What - aborting instead of capturing another window"
}

function Set-ClipboardWithRetry {
    param([string]$Text)
    for ($i = 0; $i -lt 6; $i++) {
        try { Set-Clipboard -Value $Text; return } catch {}
        try { [System.Windows.Forms.Clipboard]::SetText($Text); return } catch {}
        Start-Sleep -Milliseconds 400
    }
    throw "clipboard write failed 6 times"
}

function Send-CommandText {
    param([IntPtr]$h, [string]$Text)
    Assert-Focus -h $h -What "pasting '$Text'"
    Set-ClipboardWithRetry -Text $Text
    Start-Sleep -Milliseconds 150
    [System.Windows.Forms.SendKeys]::SendWait("^v")
    Start-Sleep -Milliseconds 300
    Assert-Focus -h $h -What "pressing ENTER for '$Text'"
    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

function Get-WindowBoundsPixels {
    param([IntPtr]$h)
    $r = New-Object Cap32+RECT
    $hr = [Cap32]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][Cap32+RECT]))
    if ($hr -ne 0) { [Cap32]::GetWindowRect($h, [ref]$r) | Out-Null }
    return $r
}

function Save-WindowShot {
    param([IntPtr]$h, [string]$Path)
    # Re-raise and re-verify immediately before the screen grab: another task's
    # always-on-top window can rise above ours between focus and capture.
    $owned = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        Assert-Focus -h $h -What "capturing $Path"
        [Cap32]::SetWindowPos($h, $HWND_TOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE)) | Out-Null
        Start-Sleep -Milliseconds 120
        if ([Cap32]::GetForegroundWindow() -eq $h) { $owned = $true; break }
    }
    if (-not $owned) { throw "lost the foreground while capturing $Path" }
    $r = Get-WindowBoundsPixels $h
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
    $g.Dispose()
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

$cfg = Get-Content -Raw -Encoding UTF8 $Scenario | ConvertFrom-Json
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
if ($cfg.workingDir) { $cfg.workingDir = Expand-PathVars ([string]$cfg.workingDir) }

$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

$hwnd = [IntPtr]::Zero
$title = "LTPPOC-" + ([guid]::NewGuid().ToString('N').Substring(0, 10))
Write-Output ("window title: " + $title)

try {
    $argList = @('-NoExit', '-NoProfile', '-Command', "`$Host.UI.RawUI.WindowTitle='$title'")
    $proc = Start-Process powershell -ArgumentList $argList -PassThru

    $hwnd = Find-WindowByTitle -Title $title
    if ($hwnd -eq [IntPtr]::Zero) { throw "our terminal window (title '$title') never appeared" }

    Start-Sleep -Milliseconds 900
    [Cap32]::ShowWindow($hwnd, 9) | Out-Null
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1400 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 680 }
    $wx = if ($cfg.windowX) { [int]$cfg.windowX } else { 80 }
    $wy = if ($cfg.windowY) { [int]$cfg.windowY } else { 80 }
    [Cap32]::MoveWindow($hwnd, $wx, $wy, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 600
    [Cap32]::SetWindowPos($hwnd, $HWND_TOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE)) | Out-Null
    Assert-Focus -h $hwnd -What "starting the scenario"

    # Let our window age before typing anything: concurrent tasks locate "their"
    # terminal by picking the newest visible console window, and a window that
    # already existed when they took their snapshot is not a candidate.
    $preRun = if ($cfg.preRunSettleSeconds) { [int]$cfg.preRunSettleSeconds } else { 0 }
    if ($preRun -gt 0) {
        Write-Output ("holding the window idle for " + $preRun + "s before driving it")
        Start-Sleep -Seconds $preRun
        Assert-Focus -h $hwnd -What "starting the scenario after the idle period"
    }

    if ($cfg.workingDir) {
        Send-CommandText -h $hwnd -Text ("cd " + $cfg.workingDir)
        Start-Sleep -Milliseconds 900
    }
    if ($cfg.initCommands) {
        foreach ($c in $cfg.initCommands) {
            Send-CommandText -h $hwnd -Text $c
            Start-Sleep -Milliseconds 900
        }
    }

    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-CommandText -h $hwnd -Text ([string]$step.command)
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            Assert-Focus -h $hwnd -What "sending keys"
            [System.Windows.Forms.SendKeys]::SendWait([string]$step.keys)
            Start-Sleep -Milliseconds 600
        }
        elseif ($step.PSObject.Properties["wait"]) {
            Start-Sleep -Milliseconds ([int]$step.wait)
        }
        elseif ($step.PSObject.Properties["shot"]) {
            $p = Join-Path $OutDir ([string]$step.shot)
            Save-WindowShot -h $hwnd -Path $p
            $shots += $p
        }
    }

    Write-Output ("DONE " + ($shots -join "; "))
}
finally {
    if ($hwnd -ne [IntPtr]::Zero) {
        try { [Cap32]::SetWindowPos($hwnd, $HWND_NOTOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE)) | Out-Null } catch {}
    }
    if ($null -ne $savedClip) { try { Set-Clipboard -Value $savedClip } catch {} }
}
