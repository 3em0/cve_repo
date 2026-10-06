# One-shot capture of the live evidence window (diagnostic / manual use).
param([string]$OutPath = "screenshots\snap_now.png")
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Snap {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder sb, int m);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
    public static List<IntPtr> FindByPrefix(string prefix) {
        var r = new List<IntPtr>();
        EnumWindows((h, l) => {
            if (IsWindowVisible(h)) {
                var sb = new System.Text.StringBuilder(256);
                GetWindowText(h, sb, 256);
                if (sb.ToString().StartsWith(prefix)) r.Add(h);
            }
            return true;
        }, IntPtr.Zero);
        return r;
    }
}
"@
$hits = [Snap]::FindByPrefix("VITA-POC-EVIDENCE")
if ($hits.Count -eq 0) { Write-Output "NO-WINDOW"; exit 1 }
$h = $hits[$hits.Count - 1]
$r = New-Object Snap+RECT
[Snap]::GetClientRect($h, [ref]$r) | Out-Null
$w = $r.Right; $ht = $r.Bottom
$pt = New-Object Snap+POINT
[Snap]::ClientToScreen($h, [ref]$pt) | Out-Null
$HWND_TOPMOST = [IntPtr](-1); $HWND_NOTOPMOST = [IntPtr](-2)
[Snap]::SetWindowPos($h, $HWND_TOPMOST, 0, 0, 0, 0, 0x13) | Out-Null
Start-Sleep -Milliseconds 600
$bmp = New-Object System.Drawing.Bitmap($w, $ht)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($pt.X, $pt.Y, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
$g.Dispose()
[Snap]::SetWindowPos($h, $HWND_NOTOPMOST, 0, 0, 0, 0, 0x13) | Out-Null
$bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output ("SNAP " + $OutPath)
