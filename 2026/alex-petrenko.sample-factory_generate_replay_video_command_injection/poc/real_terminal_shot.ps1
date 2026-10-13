# real_terminal_shot.ps1 — 在真实终端里逐条执行命令,并截取真实终端窗口 PNG
#
# 本文件是 cve-report skill 的 scripts/real_terminal_shot.ps1 的本地副本。因为采集这台机器上
# 同时有多个 agent 在跑同一个截图流程(都在抢前台窗口 + 用剪贴板/SendKeys 打字),原版会出现
# 「自己的命令打进别人窗口 / 截到别人窗口 / 别人键盘输入混进自己窗口」三种串扰。本地副本做了
# 三处【抗并发】改动,证据本身(真实终端、真实执行、真实输出、真实窗口截图)不变:
#
#   1) 终端宿主固定用经典 conhost(conhost.exe powershell.exe),并给它一个唯一标题,按标题认领窗口;
#   2) 不再抢前台、不再用剪贴板/SendKeys:命令通过 PostMessage(WM_CHAR) 直接投递到自己的控制台
#      窗口(回车用 WM_KEYDOWN/WM_KEYUP VK_RETURN,交给控制台自己 TranslateMessage),
#      所以别人抢焦点、别人按键盘都不会影响本窗口,本窗口也不会把命令打进别人窗口;
#   3) 截图用 PrintWindow(hwnd, PW_RENDERFULLCONTENT=2) 抓自己的窗口句柄,与窗口前后顺序无关。
#
# 行为与 skill 原版一致:一次只送一条命令 → 等它跑完 → 需要就截当前窗口;命令文本按日常手敲样式写。
#
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File real_terminal_shot.ps1 -Scenario scenario.json -OutDir screenshots
#
# scenario.json:
# {
#   "shell": "powershell",               // 固定 conhost + powershell
#   "windowTitle": "sf-cve-repro",       // 本终端窗口的唯一标题
#   "workingDir": "%TEMP%\\poc-work\\x",  // 终端启动后先 cd 过去(可选,%VAR% 自动展开)
#   "initCommands": ["wsl -d kali-linux"],// 截图前静默执行的命令(可选)
#   "windowWidth": 1400, "windowHeight": 900,
#   "settleMs": 1000,                    // 每条命令后的默认等待
#   "charDelayMs": 18,                   // 逐字符投递间隔(像人打字,单位 ms)
#   "steps": [ { "command": "..." }, { "wait": 1500 }, { "shot": "01-x.png" } ]
# }

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutDir = "screenshots"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class TermShot {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);

    // WM_CHAR 逐字符投递:只发 WM_CHAR,不要再发 WM_KEYDOWN,否则控制台的
    // TranslateMessage 会把每个字符再翻一遍(实测会变成 "eecccchhooo")。
    public static void TypeText(IntPtr h, string s, int delayMs) {
        foreach (char c in s) {
            PostMessageW(h, 0x0102, (IntPtr)c, IntPtr.Zero);
            System.Threading.Thread.Sleep(delayMs);
        }
    }
    public static void PressEnter(IntPtr h) {
        System.Threading.Thread.Sleep(250);
        PostMessageW(h, 0x0100, (IntPtr)0x0D, IntPtr.Zero);  // VK_RETURN down
        System.Threading.Thread.Sleep(60);
        PostMessageW(h, 0x0101, (IntPtr)0x0D, IntPtr.Zero);  // VK_RETURN up
    }
    // 翻看历史输出:直接给控制台窗口发 WM_VSCROLL(等于人拖/点滚动条)。
    // 实测 PostMessage(VK_PRIOR/VK_NEXT) 在未获焦点的经典控制台上不生效,WM_VSCROLL 可靠。
    public static void Scroll(IntPtr h, int sbCode) {
        SendMessageW(h, 0x0115 /* WM_VSCROLL */, (IntPtr)sbCode, IntPtr.Zero);
    }

    public static IntPtr Found = IntPtr.Zero;
    public static string Needle = "";
    public static IntPtr FindByTitle(string t) {
        Found = IntPtr.Zero; Needle = t;
        EnumWindows((h, l) => {
            if (!IsWindowVisible(h)) return true;
            var sb = new StringBuilder(512);
            GetWindowTextW(h, sb, 512);
            if (sb.ToString().Contains(Needle)) { Found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return Found;
    }
    public static string TitleOf(IntPtr h) {
        var sb = new StringBuilder(512);
        GetWindowTextW(h, sb, 512);
        return sb.ToString();
    }
}
"@

[TermShot]::SetProcessDPIAware() | Out-Null

function Expand-PathVars {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return ([regex]::Replace($Text, '%([A-Za-z_][A-Za-z0-9_]*)%', {
        param($m)
        $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        if ([string]::IsNullOrEmpty($v)) { $m.Value } else { $v }
    }))
}

function Find-TerminalByTitle {
    param([string]$Title, [int]$TimeoutSec = 25)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $h = [TermShot]::FindByTitle($Title)
        if ($h -ne [IntPtr]::Zero) {
            $r = New-Object TermShot+RECT
            [TermShot]::GetWindowRect($h, [ref]$r) | Out-Null
            if (($r.Right - $r.Left) -gt 200 -and ($r.Bottom - $r.Top) -gt 150) { return $h }
        }
        Start-Sleep -Milliseconds 250
    }
    return [IntPtr]::Zero
}

function Get-WindowBoundsPixels {
    param([IntPtr]$h)
    $r = New-Object TermShot+RECT
    $hr = [TermShot]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][TermShot+RECT]))
    if ($hr -ne 0) { [TermShot]::GetWindowRect($h, [ref]$r) | Out-Null }
    return $r
}

$cfg = Get-Content -Raw -Encoding UTF8 $Scenario | ConvertFrom-Json
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
if ($cfg.workingDir) { $cfg.workingDir = Expand-PathVars ([string]$cfg.workingDir) }

$windowTitle = if ($cfg.windowTitle) { [string]$cfg.windowTitle } else { "sf-cve-repro-terminal" }
$charDelay = if ($cfg.charDelayMs) { [int]$cfg.charDelayMs } else { 18 }
$settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }

function Send-CommandText {
    param([string]$Text)
    [TermShot]::TypeText($script:TargetHwnd, $Text, $charDelay)
    [TermShot]::PressEnter($script:TargetHwnd)
}

# ============================== 主流程 ==============================

# 经典 conhost 承载的 PowerShell,带唯一窗口标题(不抢前台)
$proc = Start-Process conhost -PassThru -ArgumentList @(
    'powershell.exe', '-NoExit', '-Command', "`$host.ui.RawUI.WindowTitle='$windowTitle'"
)

$hwnd = Find-TerminalByTitle -Title $windowTitle -TimeoutSec 25
if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的终端窗口(标题 $windowTitle)" }
$script:TargetHwnd = $hwnd

# 摆好尺寸(不需要前台权限);位置固定左上,避免被任务栏/屏幕边缘裁掉
$ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1400 }
$wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 900 }
Start-Sleep -Milliseconds 900
[TermShot]::MoveWindow($hwnd, 60, 40, $ww, $wh, $true) | Out-Null
Start-Sleep -Milliseconds 700

# 初始化命令(不截图)
if ($cfg.workingDir) {
    Send-CommandText -Text ("cd " + $cfg.workingDir)
    Start-Sleep -Milliseconds 800
}
if ($cfg.initCommands) {
    foreach ($c in $cfg.initCommands) {
        Send-CommandText -Text $c
        Start-Sleep -Milliseconds 1500
    }
}

$shots = @()
foreach ($step in $cfg.steps) {
    if ($step.PSObject.Properties["command"]) {
        Send-CommandText -Text ([string]$step.command)
        Start-Sleep -Milliseconds $settleMs
    }
    elseif ($step.PSObject.Properties["wait"]) {
        Start-Sleep -Milliseconds ([int]$step.wait)
    }
    elseif ($step.PSObject.Properties["scroll"]) {
        # 翻看历史输出:WM_VSCROLL 的 SB_* 代码
        $sb = switch ([string]$step.scroll) {
            "up" { 2 }
            "down" { 3 }
            "top" { 6 }
            "bottom" { 7 }
            "lineup" { 0 }
            "linedown" { 1 }
            default { 2 }
        }
        $times = if ($step.PSObject.Properties["times"]) { [int]$step.times } else { 1 }
        for ($i = 0; $i -lt $times; $i++) {
            [TermShot]::Scroll($hwnd, $sb)
            Start-Sleep -Milliseconds 250
        }
    }
    elseif ($step.PSObject.Properties["shot"]) {
        $p = Join-Path $OutDir ([string]$step.shot)
        $r = Get-WindowBoundsPixels $hwnd
        $w = $r.Right - $r.Left
        $ht = $r.Bottom - $r.Top
        $bmp = New-Object System.Drawing.Bitmap($w, $ht)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $hdc = $g.GetHdc()
        $null = [TermShot]::PrintWindow($hwnd, $hdc, 2)   # PW_RENDERFULLCONTENT
        $g.ReleaseHdc($hdc)
        $g.Dispose()
        $bmp.Save($p, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        $shots += $p
    }
}

Write-Output ("DONE " + ($shots -join "; "))
