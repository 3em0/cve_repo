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
#   "charDelayMs": 8,                   // console 输入模式每个字符之间的间隔(可选)
#   "input": "console",                 // console(默认,AttachConsole+WriteConsoleInput,不需要前台)
#                                       //   | sendinput(逐字符 Unicode SendInput,需要前台)
#   "capture": "printwindow",           // printwindow(默认,PrintWindow 抓窗口自身像素)
#                                       //   | screen(置顶后用 CopyFromScreen 抓屏幕)
#   "typing": false,                    // 仅 sendinput 模式有效:true=逐字符慢速投递
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
#   - 窗口先摆好位置尺寸再操作;敲完回车到截图之间留人眼可读的间隔
#
# 本机加固(同一台机器上可能同时有多个 agent 会话在跑本脚本):
#   1. 给本会话终端打唯一窗口标题,按标题认领自己的窗口,不会抢到别人的终端
#   2. 默认用 AttachConsole + WriteConsoleInput 把按键记录直接写进目标控制台输入
#      缓冲区(见同目录 console_send.ps1):不需要前台焦点,所以别的会话抢不走焦点、
#      也敲不进本窗口;同时绕开共享剪贴板、中文输入法与 Ctrl 修饰键状态
#      (实测踩过:剪贴板被别的会话覆盖、WM_CHAR 被修饰键打乱成 Ctrl+X/Y/N)
#   3. 截图默认用 PrintWindow 抓窗口自身像素:窗口被遮挡/不在前台也能抓到真内容
#   原始实现(剪贴板粘贴 + 置顶 + CopyFromScreen)保留为 input=sendinput/capture=screen。

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
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int X, int Y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
    public const uint SWP_NOMOVE = 0x2;
    public const uint SWP_NOSIZE = 0x1;
    public const uint SWP_SHOWWINDOW = 0x40;

    // ---- 无焦点截图:PrintWindow(PW_RENDERFULLCONTENT) ----
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);

    // ---- 备用:Unicode SendInput(需要前台) ----
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public KEYBDINPUT ki; public ulong pad; }
    [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint n, INPUT[] inputs, int size);
    public const uint KEYEVENTF_UNICODE = 0x0004;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public const uint INPUT_KEYBOARD = 1;
    public static void TypeText(string s, bool withEnter) {
        var list = new List<INPUT>();
        foreach (char c in s) {
            INPUT down = new INPUT(); down.type = INPUT_KEYBOARD;
            down.ki.wVk = 0; down.ki.wScan = c; down.ki.dwFlags = KEYEVENTF_UNICODE;
            INPUT up = down; up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            list.Add(down); list.Add(up);
        }
        if (withEnter) {
            INPUT e1 = new INPUT(); e1.type = INPUT_KEYBOARD; e1.ki.wVk = 0x0D;
            INPUT e2 = e1; e2.ki.dwFlags = KEYEVENTF_KEYUP;
            list.Add(e1); list.Add(e2);
        }
        SendInput((uint)list.Count, list.ToArray(), Marshal.SizeOf(typeof(INPUT)));
    }
    public static void TypeChar(string c) { TypeText(c, false); }
    public static void TypeEnter() { TypeText("", true); }

    public static string TitleOf(IntPtr h) {
        var sb = new StringBuilder(512);
        GetWindowTextW(h, sb, 512);
        return sb.ToString();
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
}
"@

[WinApi]::SetProcessDPIAware() | Out-Null

function Find-TerminalWindowByTitle {
    # 只认自己那一个唯一标题,避免同一台机器上并发的其它会话抢窗口
    param([string]$Title)
    $deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            if ([WinApi]::TitleOf($h) -eq $Title) { return $h }
        }
        Start-Sleep -Milliseconds 250
    }
    return [IntPtr]::Zero
}

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
    # 仅 capture=screen / input=sendinput 时需要。从后台启动的终端窗口不会自动获得
    # 前台(Windows 前台锁),单靠 SetForegroundWindow 会被拒;SetWindowPos(HWND_TOPMOST)
    # 不受前台锁限制,先抬到最前再解除 topmost,最后校验是否真的在前台。
    param([IntPtr]$h)
    for ($i = 0; $i -lt 12; $i++) {
        [WinApi]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
        [WinApi]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE
        [WinApi]::BringWindowToTop($h) | Out-Null
        [WinApi]::SetWindowPos($h, [WinApi]::HWND_TOPMOST, 0, 0, 0, 0,
            ([WinApi]::SWP_NOMOVE -bor [WinApi]::SWP_NOSIZE -bor [WinApi]::SWP_SHOWWINDOW)) | Out-Null
        [WinApi]::SetForegroundWindow($h) | Out-Null
        [WinApi]::SetWindowPos($h, [WinApi]::HWND_NOTOPMOST, 0, 0, 0, 0,
            ([WinApi]::SWP_NOMOVE -bor [WinApi]::SWP_NOSIZE -bor [WinApi]::SWP_SHOWWINDOW)) | Out-Null
        [WinApi]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 250
        if ([WinApi]::GetForegroundWindow() -eq $h) { return $true }
    }
    return $false
}

function Send-CommandText {
    # console 模式:调用 console_send.ps1(AttachConsole + WriteConsoleInput),
    #               把按键记录直接写进目标控制台输入缓冲区 —— 不需要前台焦点,
    #               别的会话既抢不走焦点也敲不进来。
    # sendinput 模式:逐字符 Unicode SendInput 到前台窗口。
    param([string]$Text, [bool]$Typing, [IntPtr]$Hwnd, [string]$Mode, [int]$CharDelay = 8)
    if ($Mode -eq "console") {
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
        & powershell -NoProfile -ExecutionPolicy Bypass -File $script:ConsoleSend `
            -TargetPid $script:ShellPid -TextB64 $b64 -DelayMs $CharDelay | Out-Null
        return
    }
    if ($Hwnd -ne [IntPtr]::Zero) { Focus-Window $Hwnd | Out-Null }
    if ($Typing) {
        foreach ($ch in $Text.ToCharArray()) {
            [WinApi]::TypeChar("$ch")
            Start-Sleep -Milliseconds (Get-Random -Minimum 12 -Maximum 40)
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 250 -Maximum 500)
        [WinApi]::TypeEnter()
    }
    else {
        [WinApi]::TypeText($Text, $true)
    }
}

function Get-WindowBoundsPixels {
    param([IntPtr]$h)
    $r = New-Object WinApi+RECT
    # DWM 扩展边界 = 去掉 Win11 不可见缩放边框;失败则退回 GetWindowRect
    $hr = [WinApi]::DwmGetWindowAttribute($h, 9, [ref]$r, [System.Runtime.InteropServices.Marshal]::SizeOf([type][WinApi+RECT]))
    if ($hr -ne 0 -or ($r.Right - $r.Left) -le 0 -or ($r.Bottom - $r.Top) -le 0) {
        [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
    }
    return $r
}

function Save-WindowShot {
    # printwindow:抓窗口自身的绘制结果,被遮挡/不在前台也能拿到真内容
    # screen     :置顶后 CopyFromScreen,抓屏幕上该矩形区域
    param([IntPtr]$h, [string]$Path, [string]$Mode)
    $r = $null
    for ($i = 0; $i -lt 10; $i++) {
        if ($Mode -ne "printwindow") { Focus-Window $h | Out-Null }
        Start-Sleep -Milliseconds 300
        $r = Get-WindowBoundsPixels $h
        if (($r.Right - $r.Left) -gt 200 -and ($r.Bottom - $r.Top) -gt 150) { break }
        Start-Sleep -Milliseconds 500
    }
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) {
        throw ("窗口尺寸无效({0},{1},{2},{3}),本次截图中止" -f $r.Left, $r.Top, $r.Right, $r.Bottom)
    }
    Start-Sleep -Milliseconds 350
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    if ($Mode -eq "printwindow") {
        $hdc = $g.GetHdc()
        [WinApi]::PrintWindow($h, $hdc, 2) | Out-Null   # PW_RENDERFULLCONTENT
        $g.ReleaseHdc($hdc)
    }
    else {
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
$inputMode = if ($cfg.input) { [string]$cfg.input } else { "console" }
$captureMode = if ($cfg.capture) { [string]$cfg.capture } else { "printwindow" }
$typing = [bool]$cfg.typing
$charDelay = if ($cfg.charDelayMs) { [int]$cfg.charDelayMs } else { 8 }
$script:ConsoleSend = Join-Path $PSScriptRoot "console_send.ps1"
$script:ShellPid = 0

# 本会话终端唯一标题:同机并发跑本脚本时用来认领自己的窗口
$tag = "CVESHOT-" + ([guid]::NewGuid().ToString("N").Substring(0, 10))

# 注意:console 输入模式完全不碰系统剪贴板,也不会去抢前台焦点。

try {
    # 记录截图前已存在的顶层窗口(标题认领失败时的回退依据)
    $before = [WinApi]::VisibleWindows()

    # 启动真实终端(系统默认终端宿主:Windows Terminal 或 conhost)
    $titleCmd = "`$Host.UI.RawUI.WindowTitle='$tag'"
    $proc = Start-Process $shellName -ArgumentList @("-NoExit", "-Command", $titleCmd) -PassThru
    $script:ShellPid = [int]$proc.Id
    $procNames = @($shellName -replace '\.exe$', '') + @("WindowsTerminal", "OpenConsole", "conhost")

    $hwnd = Find-TerminalWindowByTitle -Title $tag
    if ($hwnd -eq [IntPtr]::Zero) {
        Write-Output "WARN 未能按标题认领窗口,退回“新窗口”启发式"
        $hwnd = Find-NewTerminalWindow -BeforeSet $before -ProcessNames $procNames
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的终端窗口" }

    # 像人一样:摆个合适的尺寸,只显示不激活(SW_SHOWNOACTIVATE),
    # 这样别的会话的键盘注入不会落到本窗口。
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1000 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 640 }
    [WinApi]::MoveWindow($hwnd, 80, 80, $ww, $wh, $true) | Out-Null
    Start-Sleep -Milliseconds 300
    if ($inputMode -eq "console") {
        [WinApi]::ShowWindow($hwnd, 4) | Out-Null   # SW_SHOWNOACTIVATE
    }
    else {
        [WinApi]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
        Focus-Window $hwnd | Out-Null
    }
    Start-Sleep -Milliseconds 1200

    # 初始化命令(不截图)
    if ($cfg.workingDir) {
        Send-CommandText -Text ("cd " + $cfg.workingDir) -Typing $typing -Hwnd $hwnd -Mode $inputMode -CharDelay $charDelay
        Start-Sleep -Milliseconds 1200
    }
    if ($cfg.initCommands) {
        foreach ($c in $cfg.initCommands) {
            Send-CommandText -Text $c -Typing $typing -Hwnd $hwnd -Mode $inputMode -CharDelay $charDelay
            Start-Sleep -Milliseconds 1200
        }
    }

    # 逐步执行:一条命令 -> 等它跑完 -> 需要截图就截
    $settleMs = if ($cfg.settleMs) { [int]$cfg.settleMs } else { 1000 }
    $shots = @()
    foreach ($step in $cfg.steps) {
        if ($step.PSObject.Properties["command"]) {
            Send-CommandText -Text ([string]$step.command) -Typing $typing -Hwnd $hwnd -Mode $inputMode -CharDelay $charDelay
            Start-Sleep -Milliseconds $settleMs
        }
        elseif ($step.PSObject.Properties["keys"]) {
            # 原样击键(如 Ctrl+- 缩小终端字号: "^-"),仅 sendinput 模式可用
            if ($inputMode -ne "console") {
                Focus-Window $hwnd | Out-Null
                [System.Windows.Forms.SendKeys]::SendWait([string]$step.keys)
                Start-Sleep -Milliseconds 600
            }
        }
        elseif ($step.PSObject.Properties["wait"]) {
            Start-Sleep -Milliseconds ([int]$step.wait)
        }
        elseif ($step.PSObject.Properties["shot"]) {
            $p = Join-Path $OutDir ([string]$step.shot)
            Save-WindowShot -h $hwnd -Path $p -Mode $captureMode
            $shots += $p
        }
    }

    Write-Output ("DONE " + ($shots -join "; "))
}
catch {
    Write-Output ("FAILED: " + $_.Exception.Message)
    throw
}
