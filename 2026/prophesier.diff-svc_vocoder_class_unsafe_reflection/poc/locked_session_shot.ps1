# locked_session_shot.ps1 — 在真实 conhost 终端里逐条执行命令并截取真实窗口内容
#
# 用途:当交互会话处于锁定/不可见桌面(CopyFromScreen 只能拿到锁屏、剪贴板被系统拒绝)时,
# 用 WM_CHAR 直接向真实控制台窗口投递按键、用 PrintWindow 取回该窗口自身的真实渲染内容。
# 截到的仍然是**真实终端窗口的真实内容**,不是渲染示意图。
#
# 用法(与 real_terminal_shot.ps1 共用同一份 scenario):
#   powershell -NoProfile -ExecutionPolicy Bypass -File locked_session_shot.ps1 -Scenario shot_scenario.json -OutDir screenshots
#
# 支持的 scenario 字段与 real_terminal_shot.ps1 相同:
#   workingDir / initCommands / windowWidth / windowHeight / settleMs / steps(command|wait|shot)
# 注:锁定会话下窗口不投屏,最终视口大小由 scenario 的 initCommands 里那条
#     `mode con: cols=168 lines=58` 决定(比 conhost 默认视口能看到更多输出行)。

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutDir = "screenshots"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class LShot {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder s, int n);
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
    public static string Title(IntPtr h) { var sb = new System.Text.StringBuilder(512); GetWindowTextW(h, sb, 512); return sb.ToString(); }
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

$cfg = Get-Content -Raw -Encoding UTF8 $Scenario | ConvertFrom-Json
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
if ($cfg.workingDir) { $cfg.workingDir = Expand-PathVars ([string]$cfg.workingDir) }

$before = @([LShot]::Windows())

# 真实终端:conhost 直接托管 Windows PowerShell(经典控制台窗口,支持 WM_CHAR 投递与 PrintWindow)
$proc = Start-Process conhost.exe -ArgumentList 'powershell.exe -NoExit -NoLogo' -PassThru

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline -and $hwnd -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 400
    foreach ($h in [LShot]::Windows()) {
        if ($before -contains $h) { continue }
        if ([LShot]::Cls($h) -ne 'ConsoleWindowClass') { continue }
        if (-not [LShot]::IsWindowVisible($h)) { continue }
        $hwnd = $h
        break
    }
}
if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的控制台窗口" }
Start-Sleep -Milliseconds 1200

$ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1000 }
$wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 640 }
[LShot]::MoveWindow($hwnd, 80, 80, $ww, $wh, $true) | Out-Null
Start-Sleep -Milliseconds 800
Write-Output ("console window: hwnd={0} title='{1}' requested={2}x{3}" -f $hwnd, [LShot]::Title($hwnd), $ww, $wh)

function Send-Char {
    param([int]$Code)
    [LShot]::PostMessage($hwnd, 0x0102, [IntPtr]$Code, [IntPtr]::Zero) | Out-Null
}
function Send-Text {
    param([string]$Text)
    foreach ($ch in $Text.ToCharArray()) {
        Send-Char -Code ([int][char]$ch)
        Start-Sleep -Milliseconds (Get-Random -Minimum 12 -Maximum 28)
    }
}
function Send-Enter {
    [LShot]::PostMessage($hwnd, 0x0100, [IntPtr]13, [IntPtr]::Zero) | Out-Null   # WM_KEYDOWN VK_RETURN
    Start-Sleep -Milliseconds 40
    [LShot]::PostMessage($hwnd, 0x0101, [IntPtr]13, [IntPtr]::Zero) | Out-Null   # WM_KEYUP   VK_RETURN
}
function Send-Command {
    param([string]$Text)
    Send-Text -Text $Text
    Start-Sleep -Milliseconds (Get-Random -Minimum 150 -Maximum 350)
    Send-Enter
}
function Save-Shot {
    param([string]$Path)
    $r = New-Object LShot+RECT
    [LShot]::GetWindowRect($hwnd, [ref]$r) | Out-Null
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [LShot]::PrintWindow($hwnd, $hdc, 2)   # PW_RENDERFULLCONTENT
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    if (-not $ok) { Write-Output "WARN PrintWindow returned false for $Path" }
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

$settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1200 }

if ($cfg.workingDir) {
    Send-Command -Text ("cd " + $cfg.workingDir)
    Start-Sleep -Milliseconds 1200
}
if ($cfg.initCommands) {
    foreach ($c in $cfg.initCommands) {
        Send-Command -Text $c
        Start-Sleep -Milliseconds 1500
    }
}

$shots = @()
foreach ($step in $cfg.steps) {
    if ($step.PSObject.Properties["command"]) {
        Send-Command -Text ([string]$step.command)
        Start-Sleep -Milliseconds $settleMs
    }
    elseif ($step.PSObject.Properties["wait"]) {
        Start-Sleep -Milliseconds ([int]$step.wait)
    }
    elseif ($step.PSObject.Properties["shot"]) {
        $p = Join-Path $OutDir ([string]$step.shot)
        Save-Shot -Path $p
        $shots += $p
    }
}
Write-Output ("DONE " + ($shots -join "; "))
Write-Output ("console host pid=" + $proc.Id + " (window left open)")
