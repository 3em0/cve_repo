# real_terminal_shot.ps1 — 在真实终端里像真人一样执行命令,并截取真实终端窗口 PNG
#
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File real_terminal_shot.ps1 -Scenario scenario.json -OutDir screenshots
#
# scenario.json 结构:
# {
#   "shell": "powershell",              // powershell | cmd
#   "workingDir": "%TEMP%\\poc-work\\x", // 终端启动后先 cd 过去(可选,%VAR% 会自动展开)
#   "windowTitle": "R1OMNI-POC",        // 可选:给本次终端设唯一标题,并按标题认窗口
#   "initCommands": [],                 // 截图前静默执行的命令(可选)
#   "windowWidth": 1000, "windowHeight": 640,  // 终端窗口尺寸(像素,可选)
#   "settleMs": 1000,                   // 每条命令后的默认等待(可选,默认 1000)
#   "typing": false,                    // true=逐字键入(仅纯英文键盘环境);默认粘贴
#   "steps": [
#     { "command": "python --version" },   // 执行一条命令
#     { "wait": 1500 },                    // 额外等待(编译/运行慢时)
#     { "keys": "^-" },                    // 原样击键(如缩小字号)
#     { "shot": "01-version.png" }         // 截当前终端窗口
#   ]
# }
#
# 设计约定(真人风格):
#   - 一次只执行一条命令,跑完、看结果,再执行下一条;不用管道、不用 && 串联
#   - 命令文本按日常手敲的样子写(短、直接、不炫技)
#   - 输入默认走剪贴板粘贴:中文输入法开着也不会被劫持;typing=true 才逐字敲
#   - 窗口先激活、拉好尺寸再操作;敲完回车到截图之间留人眼可读的间隔
#
# 本地改动(仅一处,2026-10-13):新增可选字段 windowTitle。同一台机器上可能有别的
# 会话同时在开终端窗口,按进程名找"新窗口"会认错窗口;给了 windowTitle 就改为
# 启动时先设标题,并只认标题匹配的窗口。其余逻辑与 skill 原版一致。

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
using System.Runtime.InteropServices;
using System.Text;
public static class WinApi {
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
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hWnd, uint flags);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X, Y; public POINT(int x, int y) { X = x; Y = y; } }

    // 目标窗口此刻是否真的在最上层:前台窗口是它,且窗口中心点命中的根窗口也是它。
    // 同机其它会话可能同时在弹终端窗口并抢焦点,不校验就会截到别人的窗口。
    public static bool IsOnTop(IntPtr target, int centerX, int centerY) {
        if (GetForegroundWindow() != target) return false;
        IntPtr under = GetAncestor(WindowFromPoint(new POINT(centerX, centerY)), 2 /* GA_ROOT */);
        return under == target;
    }

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
    public static string TitleOf(IntPtr h) {
        var sb = new StringBuilder(512);
        GetWindowText(h, sb, sb.Capacity);
        return sb.ToString();
    }
}
"@

[WinApi]::SetProcessDPIAware() | Out-Null

function Find-NewTerminalWindow {
    param($BeforeSet, $ProcessNames, [string]$TitleMatch)
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            # 必须是本次新开的窗口:上一次运行留下的同名窗口会把命令吃进去
            if ($BeforeSet -contains $h) { continue }
            if ($TitleMatch) {
                if ([WinApi]::TitleOf($h) -notlike "*$TitleMatch*") { continue }
            }
            else {
                $pname = [WinApi]::ProcNameOf($h)
                if ($ProcessNames -notcontains $pname) { continue }
            }
            $r = New-Object WinApi+RECT
            [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
            if (($r.Right - $r.Left) -gt 200 -and ($r.Bottom - $r.Top) -gt 150) { return $h }
        }
        Start-Sleep -Milliseconds 250
    }
    return [IntPtr]::Zero
}

function Focus-Window {
    param([IntPtr]$h)
    # 先敲一下 ALT,解除 SetForegroundWindow 的前台锁
    [WinApi]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
    [WinApi]::SetForegroundWindow($h) | Out-Null
    [WinApi]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
}

function Set-ClipboardWithRetry {
    # 剪贴板偶发被占(云剪贴板/输入法/其它窗口 OpenClipboard):重试 6 次,
    # 每次先试 Set-Clipboard 再试 WinForms Clipboard.SetText,全失败才抛错。
    param([string]$Text)
    for ($i = 0; $i -lt 6; $i++) {
        try { Set-Clipboard -Value $Text; return } catch {}
        try {
            [System.Windows.Forms.Clipboard]::SetText($Text)
            return
        } catch {}
        Start-Sleep -Milliseconds 400
    }
    throw "剪贴板连续 6 次写入失败(可能被其它进程长期占用),本次粘贴中止"
}

function Ensure-Foreground {
    # 键盘输入只会进前台窗口。同机别的会话可能正在抢焦点,粘贴前必须确认前台是本窗口,
    # 否则命令会被送进别人的终端。
    param([IntPtr]$h, [int]$Tries = 30)
    for ($i = 0; $i -lt $Tries; $i++) {
        if ([WinApi]::GetForegroundWindow() -eq $h) { return $true }
        Focus-Window $h
        Start-Sleep -Milliseconds 300
    }
    return ([WinApi]::GetForegroundWindow() -eq $h)
}

function Send-CommandText {
    # 把一条命令送进终端。默认剪贴板粘贴(绕开中文输入法);
    # typing=true 时逐字 SendKeys(需要系统处于英文输入状态)。
    param([string]$Text, [bool]$Typing, [IntPtr]$Target = [IntPtr]::Zero)
    if ($Target -ne [IntPtr]::Zero -and -not (Ensure-Foreground $Target)) {
        throw "粘贴前无法把终端窗口拉到前台,拒绝把命令送进不确定的窗口:$Text"
    }
    if ($Typing) {
        $n = 0
        foreach ($ch in $Text.ToCharArray()) {
            # 边敲边确认前台还是本窗口。抢走了只等它回来,绝不在这里敲 ALT 抢焦点
            # (ALT 组合键会打进正在输入的命令行,把命令打乱)。
            if ($Target -ne [IntPtr]::Zero -and ($n % 8) -eq 0) {
                if ([WinApi]::GetForegroundWindow() -ne $Target) {
                    for ($w = 0; $w -lt 10; $w++) {
                        Start-Sleep -Milliseconds 200
                        if ([WinApi]::GetForegroundWindow() -eq $Target) { break }
                    }
                    if ([WinApi]::GetForegroundWindow() -ne $Target) {
                        throw "输入过程中终端失去前台,放弃本条命令(避免敲进别人的窗口):$Text"
                    }
                }
            }
            $n++
            $s = "$ch"
            if ($ch -match '[+^%~(){}\[\]]') { $s = "{$ch}" }
            [System.Windows.Forms.SendKeys]::SendWait($s)
            Start-Sleep -Milliseconds (Get-Random -Minimum 12 -Maximum 40)
        }
    }
    else {
        Set-ClipboardWithRetry -Text $Text
        Start-Sleep -Milliseconds 120
        if ($Target -ne [IntPtr]::Zero -and -not (Ensure-Foreground $Target 10)) {
            throw "粘贴瞬间终端窗口失去前台,放弃本次输入:$Text"
        }
        [System.Windows.Forms.SendKeys]::SendWait("^v")
        Start-Sleep -Milliseconds 250
    }
    # 像人一样:敲完看一眼再回车
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 450)
    if ($Target -ne [IntPtr]::Zero) { Ensure-Foreground $Target 10 | Out-Null }
    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

function Get-WindowBoundsPixels {
    param([IntPtr]$h)
    $r = New-Object WinApi+RECT
    # DWM 扩展边界 = 去掉 Win11 不可见缩放边框;失败则退回 GetWindowRect
    $hr = [WinApi]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][WinApi+RECT]))
    if ($hr -ne 0) { [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null }
    return $r
}

function Save-WindowShot {
    param([IntPtr]$h, [string]$Path)
    # 只把窗口拉到前台让画面正常(不要求成功);实际取像走 PrintWindow,
    # 由窗口自己渲染内容,不受别的窗口遮挡、不依赖焦点。
    Focus-Window $h
    Start-Sleep -Milliseconds 400
    $r = Get-WindowBoundsPixels $h
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top

    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [WinApi]::PrintWindow($h, $hdc, 2)   # 2 = PW_RENDERFULLCONTENT
    $g.ReleaseHdc($hdc)
    if (-not $ok) {
        Write-Warning "PrintWindow 失败,退回屏幕拷贝(可能被遮挡):$Path"
        $g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
    }
    $g.Dispose()
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

# ============================== 主流程 ==============================


# 展开 %VAR%:scenario 里一律用 %TEMP%\... 写临时路径,不写死盘符与个人目录
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

# 归一化 scenario 里的路径字段(workingDir 只用于拼 `cd`,不参与 IO 校验)
if ($cfg.workingDir) { $cfg.workingDir = Expand-PathVars ([string]$cfg.workingDir) }

$shellName = if ($cfg.shell) { $cfg.shell } else { "powershell" }
$typing = [bool]$cfg.typing
$windowTitle = if ($cfg.windowTitle) { [string]$cfg.windowTitle } else { "" }

# 保存用户剪贴板,结束时恢复
$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

try {
    # 记录截图前已存在的顶层窗口
    $before = [WinApi]::VisibleWindows()

    # 启动真实终端(系统默认终端宿主:conhost 或 Windows Terminal 均可)
    if ($windowTitle) {
        $proc = Start-Process $shellName -PassThru -ArgumentList @(
            "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = '$windowTitle'")
    }
    else {
        $proc = Start-Process $shellName -PassThru
    }
    $procNames = @($shellName -replace '\.exe$', '') + @("WindowsTerminal", "OpenConsole", "conhost")

    $hwnd = Find-NewTerminalWindow -BeforeSet $before -ProcessNames $procNames -TitleMatch $windowTitle
    if ($hwnd -eq [IntPtr]::Zero -and $windowTitle) {
        Write-Warning "按标题 '$windowTitle' 没找到窗口,退回按进程名找新窗口"
        $hwnd = Find-NewTerminalWindow -BeforeSet $before -ProcessNames $procNames -TitleMatch ""
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的终端窗口" }

    # 像人一样:拉到前台,摆个合适的尺寸
    Start-Sleep -Milliseconds 800
    [WinApi]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
    Focus-Window $hwnd
    Start-Sleep -Milliseconds 300
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1000 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 640 }
    [WinApi]::MoveWindow($hwnd, 80, 80, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 500

    # 初始化命令(不截图)
    if ($cfg.workingDir) {
        Send-CommandText -Text ("cd " + $cfg.workingDir) -Typing $typing -Target $hwnd
        Start-Sleep -Milliseconds 700
    }
    if ($cfg.initCommands) {
        foreach ($c in $cfg.initCommands) {
            Send-CommandText -Text $c -Typing $typing -Target $hwnd
            Start-Sleep -Milliseconds 700
        }
    }

    # 逐步执行:一条命令 -> 等它跑完 -> 需要截图就截
    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-CommandText -Text ([string]$step.command) -Typing $typing -Target $hwnd
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            # 原样击键(如 Ctrl+- 缩小终端字号: "^-"),用于让长输出完整入镜
            Ensure-Foreground $hwnd | Out-Null
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
    if ($null -ne $savedClip) { try { Set-Clipboard -Value $savedClip } catch {} }
}
