# locked_frames_shot.ps1 — 每个证据帧用**新开的真实终端窗口**执行并截图
#
# 背景:会话锁定时 conhost 窗口在存在几分钟后会停止重绘(PrintWindow/BitBlt 都只能拿到旧帧),
# 因此把 shot_scenario 拆成若干"帧",每帧开一个新的 conhost 控制台、跑完这一帧的命令、
# 用 PrintWindow 取回该窗口自身的真实渲染内容,然后关掉它。窗口与输出都是真实的。
#
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File locked_frames_shot.ps1 -Plan frames.json -OutDir screenshots
#
# frames.json:
# {
#   "pocDir":  "<脚本所在目录>",                         // 省略则用脚本所在目录
#   "workDir": "%TEMP%\\poc-work\\diff-svc-236de77-cve-report",
#   "windowWidth": 1400, "windowHeight": 760, "settleMs": 1500,
#   "modeCon": "mode con: cols=168 lines=58",
#   "frames": [
#     { "dir": "poc",  "steps": [ {"command": "..."}, {"wait": 1000}, {"shot": "01-x.png"} ] },
#     { "dir": "work", "steps": [ ... ] }
#   ]
# }

param(
    [Parameter(Mandatory = $true)][string]$Plan,
    [string]$OutDir = "screenshots"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class FShot {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    public static List<IntPtr> Windows() {
        var res = new List<IntPtr>();
        EnumWindows((h, l) => { res.Add(h); return true; }, IntPtr.Zero);
        return res;
    }
    public static string Cls(IntPtr h) { var sb = new System.Text.StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString(); }
}
"@

function Expand-PathVars {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return ([regex]::Replace($Text, '%([A-Za-z_][A-Za-z0-9_]*)%', {
        param($m)
        $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        if ([string]::IsNullOrEmpty($v)) { $m.Value } else { $v }
    }))
}

$cfg = Get-Content -Raw -Encoding UTF8 $Plan | ConvertFrom-Json
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pocDir = if ($cfg.pocDir) { Expand-PathVars ([string]$cfg.pocDir) } else { $scriptDir }
$workDir = Expand-PathVars ([string]$cfg.workDir)
$ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1400 }
$wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 760 }
$settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1500 }

function Start-Console {
    $before = @([FShot]::Windows())
    $proc = Start-Process conhost.exe -ArgumentList 'powershell.exe -NoExit -NoLogo' -PassThru
    $hwnd = [IntPtr]::Zero
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and $hwnd -eq [IntPtr]::Zero) {
        Start-Sleep -Milliseconds 400
        foreach ($h in [FShot]::Windows()) {
            if ($before -contains $h) { continue }
            if ([FShot]::Cls($h) -ne 'ConsoleWindowClass') { continue }
            if (-not [FShot]::IsWindowVisible($h)) { continue }
            $hwnd = $h
            break
        }
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的控制台窗口" }
    Start-Sleep -Milliseconds 1200
    [FShot]::MoveWindow($hwnd, 80, 80, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 600
    return [pscustomobject]@{ Hwnd = $hwnd; Proc = $proc }
}

function Close-Console {
    param($Pkg)
    try { Stop-Process -Id $Pkg.Proc.Id -Force -ErrorAction SilentlyContinue } catch {}
}

function Send-Command {
    param([IntPtr]$Hwnd, [string]$Text)
    foreach ($ch in $Text.ToCharArray()) {
        [FShot]::PostMessage($Hwnd, 0x0102, [IntPtr][int][char]$ch, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds (Get-Random -Minimum 12 -Maximum 26)
    }
    Start-Sleep -Milliseconds 200
    [FShot]::PostMessage($Hwnd, 0x0100, [IntPtr]13, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 40
    [FShot]::PostMessage($Hwnd, 0x0101, [IntPtr]13, [IntPtr]::Zero) | Out-Null
}

function Save-Shot {
    param([IntPtr]$Hwnd, [string]$Path)
    $r = New-Object FShot+RECT
    [FShot]::GetWindowRect($Hwnd, [ref]$r) | Out-Null
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [FShot]::PrintWindow($Hwnd, $hdc, 2)
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    if (-not $ok) { Write-Output "WARN PrintWindow returned false for $Path" }
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

$shots = @()
$frameNo = 0
foreach ($frame in $cfg.frames) {
    $frameNo++
    $dir = if ($frame.dir -eq 'work') { $workDir } else { $pocDir }
    Write-Output ("--- frame {0} (dir={1}) ---" -f $frameNo, $dir)
    $pkg = Start-Console
    $hwnd = $pkg.Hwnd
    if ($cfg.modeCon) {
        Send-Command -Hwnd $hwnd -Text ([string]$cfg.modeCon)
        Start-Sleep -Milliseconds 1800
    }
    Send-Command -Hwnd $hwnd -Text ("cd " + $dir)
    Start-Sleep -Milliseconds 1200
    foreach ($step in $frame.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-Command -Hwnd $hwnd -Text ([string]$step.command)
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["enter"]) {
            # 像人一样空敲几次回车:把证据行从窗口最底边往上顶几行(锁定会话下最底部若干行常常没被画出来)
            $n = [int]$step.enter
            for ($i = 0; $i -lt $n; $i++) {
                Send-Command -Hwnd $hwnd -Text ""
                Start-Sleep -Milliseconds 350
            }
        }
        elseif ($step.PSObject.Properties["wait"]) {
            Start-Sleep -Milliseconds ([int]$step.wait)
        }
        elseif ($step.PSObject.Properties["shot"]) {
            $p = Join-Path $OutDir ([string]$step.shot)
            Save-Shot -Hwnd $hwnd -Path $p
            $shots += $p
            Write-Output ("    shot: " + [string]$step.shot)
        }
    }
    Close-Console -Pkg $pkg
    Start-Sleep -Milliseconds 600
}

Write-Output ("DONE " + $shots.Count + " shots: " + ($shots -join "; "))
