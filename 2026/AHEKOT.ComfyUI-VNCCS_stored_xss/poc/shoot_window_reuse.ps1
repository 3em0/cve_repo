# shoot_window_reuse.ps1 -- drive ONE existing terminal window and screenshot it.
#
# Why this exists next to real_terminal_shot.ps1:
#   real_terminal_shot.ps1 opens a BRAND NEW terminal window for every run and
#   leaves SendKeys dependent on whichever window currently has the foreground.
#   On a shared desktop with another automation agent running the same trick,
#   two drivers can paste into each other's window (observed here: a foreign
#   "dir C:\out -Name" landed in this window mid-run). This variant
#     * attaches to a window that already exists (found by title), so the other
#       driver's "new window" search cannot claim it, and
#     * minimises the window while a command runs and restores it only for the
#       screenshot, so foreign Ctrl+V presses land somewhere else.
#   Nothing about the evidence changes: same real window, same real commands,
#   same real console output.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File shoot_window_reuse.ps1 `
#       -Scenario scenario.json -OutDir screenshots -TitleMatch "VNCCS-XSS-DRIVE"

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutDir = "screenshots",
    [string]$TitleMatch = "VNCCS-XSS-DRIVE",
    [switch]$CreateIfMissing
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class W2 {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);

    public static List<IntPtr> FindByTitle(string needle) {
        var res = new List<IntPtr>();
        EnumWindows((h, l) => {
            if (!IsWindowVisible(h)) return true;
            var sb = new StringBuilder(512);
            GetWindowTextW(h, sb, 512);
            if (sb.ToString().IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) res.Add(h);
            return true;
        }, IntPtr.Zero);
        return res;
    }
}
"@

[W2]::SetProcessDPIAware() | Out-Null

function Focus-Window2 { param([IntPtr]$h)
    [W2]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
    [W2]::SetForegroundWindow($h) | Out-Null
    [W2]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
}

function Set-ClipboardChecked { param([string]$Text)
    for ($i = 0; $i -lt 12; $i++) {
        try { Set-Clipboard -Value $Text } catch {
            try { [System.Windows.Forms.Clipboard]::SetText($Text) } catch {}
        }
        Start-Sleep -Milliseconds 220
        $back = $null
        try { $back = Get-Clipboard -Raw } catch { $back = $null }
        if ($null -ne $back -and $back.TrimEnd("`r", "`n") -eq $Text.TrimEnd("`r", "`n")) { return }
        Start-Sleep -Milliseconds 300
    }
    throw "clipboard write could not be verified"
}

function Send-Line { param([IntPtr]$h, [string]$Text, [bool]$Typing)
    [W2]::ShowWindow($h, 9) | Out-Null          # SW_RESTORE (we minimise between steps)
    Start-Sleep -Milliseconds 250
    Focus-Window2 $h
    Start-Sleep -Milliseconds 250
    if ($Typing) {
        foreach ($ch in $Text.ToCharArray()) {
            $s = "$ch"
            if ($ch -match '[+^%~(){}\[\]]') { $s = "{$ch}" }
            [System.Windows.Forms.SendKeys]::SendWait($s)
            Start-Sleep -Milliseconds (Get-Random -Minimum 8 -Maximum 30)
        }
    }
    else {
        Set-ClipboardChecked -Text $Text
        Start-Sleep -Milliseconds 150
        [System.Windows.Forms.SendKeys]::SendWait("^v")
        Start-Sleep -Milliseconds 450
    }
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 400)
    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

function Save-Shot { param([IntPtr]$h, [string]$Path)
    [W2]::ShowWindow($h, 9) | Out-Null          # SW_RESTORE
    Start-Sleep -Milliseconds 300
    Focus-Window2 $h
    Start-Sleep -Milliseconds 400
    $r = New-Object W2+RECT
    $hr = [W2]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][W2+RECT]))
    if ($hr -ne 0) { [W2]::GetWindowRect($h, [ref]$r) | Out-Null }
    $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
    $g.Dispose()
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

function Expand-PathVars2 { param([string]$Text)
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

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    $found = [W2]::FindByTitle($TitleMatch)
    if ($found.Count -gt 0) { $hwnd = $found[0]; break }
    Start-Sleep -Milliseconds 400
}
if ($hwnd -eq [IntPtr]::Zero) {
    if (-not $CreateIfMissing) { throw "no window whose title contains '$TitleMatch'" }
    $proc = Start-Process cmd -ArgumentList "/k", "title $TitleMatch" -PassThru
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and $hwnd -eq [IntPtr]::Zero) {
        $found = [W2]::FindByTitle($TitleMatch)
        if ($found.Count -gt 0) { $hwnd = $found[0] }
        Start-Sleep -Milliseconds 400
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "created window not found" }
}

$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

try {
    [W2]::ShowWindow($hwnd, 9) | Out-Null
    Focus-Window2 $hwnd
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1400 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 860 }
    [W2]::MoveWindow($hwnd, 80, 60, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 600

    if ($cfg.workingDir) {
        Send-Line -h $hwnd -Text ("cd " + (Expand-PathVars2 ([string]$cfg.workingDir))) -Typing $false
        Start-Sleep -Milliseconds 900
    }

    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1200 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-Line -h $hwnd -Text ([string]$step.command) -Typing $false
            # step out of the way while the command runs so a foreign Ctrl+V
            # cannot land in this console
            [W2]::ShowWindow($hwnd, 6) | Out-Null      # SW_MINIMIZE
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            Focus-Window2 $hwnd
            Start-Sleep -Milliseconds 200
            [System.Windows.Forms.SendKeys]::SendWait([string]$step.keys)
            Start-Sleep -Milliseconds 600
        }
        elseif ($step.PSObject.Properties["wait"]) {
            Start-Sleep -Milliseconds ([int]$step.wait)
        }
        elseif ($step.PSObject.Properties["shot"]) {
            $p = Join-Path $OutDir ([string]$step.shot)
            Save-Shot -h $hwnd -Path $p
            $shots += $p
            [W2]::ShowWindow($hwnd, 6) | Out-Null
        }
    }
    [W2]::ShowWindow($hwnd, 9) | Out-Null
    Focus-Window2 $hwnd
    Write-Output ("DONE " + ($shots -join "; "))
}
finally {
    if ($null -ne $savedClip) { try { Set-Clipboard -Value $savedClip } catch {} }
}
