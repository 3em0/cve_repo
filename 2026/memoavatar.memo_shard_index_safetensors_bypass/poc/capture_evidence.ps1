# Evidence capture monitor for the MEMO shard-index PoC.
#
# Watches for the console window whose title starts with "MEMO-POC-EVIDENCE"
# (opened by poc\runner_evidence.bat) and captures that real window every time
# its title changes, i.e. at every step boundary of the runner. The window is
# NEVER focused, moved, typed into or closed; it is briefly forced top-most
# WITHOUT activation so nothing occludes the captured region, then top-most is
# dropped again. This keeps concurrent desktop activity untouched - this desktop
# is shared with other automation sessions.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File capture_evidence.ps1 -OutDir screenshots
param([string]$OutDir = "screenshots")
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Dpi {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@
[Dpi]::SetProcessDPIAware() | Out-Null

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Cap {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hWnd, ref POINT pt);
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }

    public static List<IntPtr> FindByTitlePrefix(string prefix) {
        var result = new List<IntPtr>();
        EnumWindows((h, l) => {
            if (IsWindowVisible(h)) {
                var sb = new System.Text.StringBuilder(256);
                GetWindowText(h, sb, 256);
                if (sb.ToString().StartsWith(prefix, StringComparison.Ordinal)) result.Add(h);
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }

    public static string TitleOf(IntPtr h) {
        var sb = new System.Text.StringBuilder(256);
        GetWindowText(h, sb, 256);
        return sb.ToString();
    }

    public static int ClientWidth(IntPtr h) { RECT r; GetClientRect(h, out r); return r.Right; }
    public static int ClientHeight(IntPtr h) { RECT r; GetClientRect(h, out r); return r.Bottom; }
}
"@

function Capture-Window {
    param([IntPtr]$h, [string]$Path)
    $w = [Cap]::ClientWidth($h)
    $ht = [Cap]::ClientHeight($h)
    if ($w -le 10 -or $ht -le 10) { return $false }
    $HWND_TOPMOST = [IntPtr](-1); $HWND_NOTOPMOST = [IntPtr](-2)
    $SWP_NOMOVE = 2; $SWP_NOSIZE = 1; $SWP_NOACTIVATE = 0x10
    [Cap]::SetWindowPos($h, $HWND_TOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE -bor $SWP_NOACTIVATE)) | Out-Null
    Start-Sleep -Milliseconds 600
    $r = New-Object Cap+RECT
    [Cap]::GetClientRect($h, [ref]$r) | Out-Null
    $pt = New-Object Cap+POINT
    [Cap]::ClientToScreen($h, [ref]$pt) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($pt.X, $pt.Y, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
    $g.Dispose()
    [Cap]::SetWindowPos($h, $HWND_NOTOPMOST, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE -bor $SWP_NOACTIVATE)) | Out-Null
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return $true
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$deadline = (Get-Date).AddMinutes(20)
$lastTitle = ""
while ((Get-Date) -lt $deadline) {
    $hits = [Cap]::FindByTitlePrefix("MEMO-POC-EVIDENCE")
    if ($hits.Count -gt 0) {
        $h = $hits[$hits.Count - 1]
        $title = [Cap]::TitleOf($h)
        if ($title -ne $lastTitle) {
            # let the step's output finish landing, then capture the real window
            Start-Sleep -Milliseconds 4000
            $hits = [Cap]::FindByTitlePrefix("MEMO-POC-EVIDENCE")
            if ($hits.Count -gt 0) {
                $h = $hits[$hits.Count - 1]
                $title = [Cap]::TitleOf($h)
                $step = $title.Substring("MEMO-POC-EVIDENCE ".Length).Trim()
                $p = Join-Path $OutDir ($step + ".png")
                if (Capture-Window -h $h -Path $p) {
                    Write-Output ("SHOT " + $step)
                }
                $lastTitle = $title
                if ($step -eq "99-done") {
                    Write-Output "DONE"
                    exit 0
                }
            }
        }
    }
    Start-Sleep -Milliseconds 1000
}
Write-Output "TIMEOUT"
exit 2
