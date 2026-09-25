# real_terminal_shot.ps1 — 在真实终端里像真人一样执行命令,并截取真实终端窗口 PNG
#
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File real_terminal_shot.ps1 -Scenario scenario.json -OutDir screenshots
#
# scenario.json 结构:
# {
#   "shell": "powershell",              // powershell | cmd
#   "workingDir": "%TEMP%\\poc-work\\x", // 终端启动后先 cd 过去(可选,%VAR% 会自动展开)
#   "initCommands": [],                 // 截图前静默执行的命令(可选)
#   "windowWidth": 1000, "windowHeight": 640,  // 终端窗口尺寸(像素,可选)
#   "settleMs": 1000,                   // 每条命令后的默认等待(可选,默认 1000)
#   "typing": false,                    // true=逐字键入(仅纯英文键盘环境);默认粘贴
#   "steps": [
#     { "command": "python --version" },   // 执行一条命令
#     { "wait": 1500 },                    // 额外等待(编译/运行慢时)
#     { "shot": "01-version.png" }         // 截当前终端窗口
#   ]
# }
#
# 设计约定(真人风格):
#   - 一次只执行一条命令,跑完、看结果,再执行下一条;不用管道、不用 && 串联
#   - 命令文本按日常手敲的样子写(短、直接、不炫技)
#   - 输入默认走剪贴板粘贴:中文输入法开着也不会被劫持;typing=true 才逐字敲
#   - 窗口先激活、拉好尺寸再操作;敲完回车到截图之间留人眼可读的间隔

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

function Find-NewTerminalWindow {
    param($BeforeSet, $ProcessNames)
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            if ($BeforeSet -contains $h) { continue }
            $pname = [WinApi]::ProcNameOf($h)
            if ($ProcessNames -notcontains $pname) { continue }
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

function Send-CommandText {
    # 把一条命令送进终端。默认剪贴板粘贴(绕开中文输入法);
    # typing=true 时逐字 SendKeys(需要系统处于英文输入状态)。
    param([string]$Text, [bool]$Typing)
    if ($Typing) {
        foreach ($ch in $Text.ToCharArray()) {
            $s = "$ch"
            if ($ch -match '[+^%~(){}\[\]]') { $s = "{$ch}" }
            [System.Windows.Forms.SendKeys]::SendWait($s)
            Start-Sleep -Milliseconds (Get-Random -Minimum 8 -Maximum 35)
        }
    }
    else {
        Set-ClipboardWithRetry -Text $Text
        Start-Sleep -Milliseconds 120
        [System.Windows.Forms.SendKeys]::SendWait("^v")
        Start-Sleep -Milliseconds 250
    }
    # 像人一样:敲完看一眼再回车
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 450)
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
    Focus-Window $h
    Start-Sleep -Milliseconds 250
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

# 保存用户剪贴板,结束时恢复
$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

try {
    # 记录截图前已存在的顶层窗口
    $before = [WinApi]::VisibleWindows()

    # 启动真实终端(系统默认终端宿主:conhost 或 Windows Terminal 均可)
    $proc = Start-Process $shellName -PassThru
    $procNames = @($shellName -replace '\.exe$', '') + @("WindowsTerminal", "OpenConsole", "conhost")

    $hwnd = Find-NewTerminalWindow -BeforeSet $before -ProcessNames $procNames
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
        Send-CommandText -Text ("cd " + $cfg.workingDir) -Typing $typing
        Start-Sleep -Milliseconds 700
    }
    if ($cfg.initCommands) {
        foreach ($c in $cfg.initCommands) {
            Send-CommandText -Text $c -Typing $typing
            Start-Sleep -Milliseconds 700
        }
    }

    # 逐步执行:一条命令 -> 等它跑完 -> 需要截图就截
    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-CommandText -Text ([string]$step.command) -Typing $typing
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            # 原样击键(如 Ctrl+- 缩小终端字号: "^-"),用于让长输出完整入镜
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
