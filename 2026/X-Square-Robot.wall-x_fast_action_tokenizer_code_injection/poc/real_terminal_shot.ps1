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
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int X, int Y, int cx, int cy, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr LoadKeyboardLayoutW(string pwszKLID, uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int cb);

    // KEYEVENTF_UNICODE 直投字符:不走剪贴板,也不经过中文输入法。
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTKEY { [FieldOffset(0)] public uint type; [FieldOffset(8)] public KEYBDINPUT ki; }
    [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint nInputs, INPUTKEY[] pInputs, int cbSize);

    public static uint SendUnicodeChar(char c) {
        var inputs = new INPUTKEY[2];
        inputs[0].type = 1; inputs[0].ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = 0x0004 };
        inputs[1].type = 1; inputs[1].ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = 0x0004 | 0x0002 };
        return SendInput(2, inputs, Marshal.SizeOf(typeof(INPUTKEY)));
    }
    public static uint SendVirtualKey(ushort vk) {
        var inputs = new INPUTKEY[2];
        inputs[0].type = 1; inputs[0].ki = new KEYBDINPUT { wVk = vk, wScan = 0, dwFlags = 0 };
        inputs[1].type = 1; inputs[1].ki = new KEYBDINPUT { wVk = vk, wScan = 0, dwFlags = 0x0002 };
        return SendInput(2, inputs, Marshal.SizeOf(typeof(INPUTKEY)));
    }

    // 直接把按键写进目标控制台的输入缓冲区:不依赖窗口是否在前台,
    // 也不经过剪贴板与中文输入法(同一台机器上别的会话抢前台时仍然可靠)。
    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_EVENT_RECORD {
        public int bKeyDown; public ushort wRepeatCount; public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode; public char UnicodeChar; public uint dwControlKeyState;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct CONSOLE_INPUT_RECORD {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
    }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool WriteConsoleInputW(IntPtr h, CONSOLE_INPUT_RECORD[] recs, uint len, out uint written);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);

    public static string WriteConsoleLine(uint pid, string text) {
        FreeConsole();   // 调用方自己可能已挂着一个控制台,先脱开才能 Attach
        if (!AttachConsole(pid)) return "AttachConsole failed, err=" + Marshal.GetLastWin32Error();
        try {
            IntPtr h = CreateFileW("CONIN$", 0xC0000000u, 3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
            if (h == (IntPtr)(-1)) return "CreateFile(CONIN$) failed, err=" + Marshal.GetLastWin32Error();
            try {
                var recs = new List<CONSOLE_INPUT_RECORD>();
                foreach (char c in text) {
                    recs.Add(MakeKey(c, true));
                    recs.Add(MakeKey(c, false));
                }
                recs.Add(MakeKey('\r', true));
                recs.Add(MakeKey('\r', false));
                uint written;
                if (!WriteConsoleInputW(h, recs.ToArray(), (uint)recs.Count, out written)) {
                    return "WriteConsoleInput failed, err=" + Marshal.GetLastWin32Error();
                }
                return "";
            }
            finally { CloseHandle(h); }
        }
        finally { FreeConsole(); }
    }
    private static CONSOLE_INPUT_RECORD MakeKey(char c, bool down) {
        var r = new CONSOLE_INPUT_RECORD();
        r.EventType = 0x0001;
        r.KeyEvent = new KEY_EVENT_RECORD {
            bKeyDown = down ? 1 : 0, wRepeatCount = 1,
            wVirtualKeyCode = (c == '\r') ? (ushort)0x0D : (ushort)0,
            wVirtualScanCode = 0, UnicodeChar = c, dwControlKeyState = 0
        };
        return r;
    }

    public static List<IntPtr> VisibleWindows() {
        var result = new List<IntPtr>();
        EnumWindows((h, l) => { if (IsWindowVisible(h)) result.Add(h); return true; }, IntPtr.Zero);
        return result;
    }
    public static string TitleOf(IntPtr h) {
        var sb = new System.Text.StringBuilder(512);
        GetWindowTextW(h, sb, sb.Capacity);
        return sb.ToString();
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
    param($BeforeSet, $ProcessNames, $TitleFilter)
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            if ($BeforeSet -contains $h) { continue }
            $pname = [WinApi]::ProcNameOf($h)
            if ($ProcessNames -notcontains $pname) { continue }
            # 多会话并发的机器上,只有标题匹配的那一个窗口才是本次启动的终端
            if ($TitleFilter -and ([WinApi]::TitleOf($h) -notlike ("*" + $TitleFilter + "*"))) { continue }
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

function Claim-Window {
    # 同一台机器上可能有别的会话也在开终端抢前台:发命令与截图之前,
    # 把目标窗口临时置顶并抢回前台,保证按键和 CopyFromScreen 都落在正确窗口上。
    param([IntPtr]$h)
    # HWND_TOPMOST(-1),SWP_NOSIZE|SWP_NOMOVE|SWP_NOACTIVATE
    [WinApi]::SetWindowPos($h, [IntPtr](-1), 0, 0, 0, 0, 0x0001 -bor 0x0002 -bor 0x0010) | Out-Null
    Focus-Window $h
    Start-Sleep -Milliseconds 250
}

function Set-ClipboardWithRetry {
    # 剪贴板偶发被占(云剪贴板/输入法/其它窗口 OpenClipboard):重试 6 次,
    # 每次先试 Set-Clipboard 再试 WinForms Clipboard.SetText,全失败才抛错。
    # 并发会话加固:写完立刻回读校验——同一台机器上别的会话也在写剪贴板时,
    # 只写不校验会把别人的命令粘进本窗口(实测发生过),校验失败就重写。
    param([string]$Text)
    for ($i = 0; $i -lt 10; $i++) {
        $written = $false
        try { Set-Clipboard -Value $Text; $written = $true } catch {}
        if (-not $written) {
            try { [System.Windows.Forms.Clipboard]::SetText($Text); $written = $true } catch {}
        }
        if ($written) {
            Start-Sleep -Milliseconds 25
            try {
                $back = Get-Clipboard -Raw
                if ($null -ne $back -and $back.TrimEnd("`r", "`n") -eq $Text.TrimEnd("`r", "`n")) { return }
            }
            catch {}
        }
        Start-Sleep -Milliseconds 250
    }
    throw "剪贴板连续 10 次写入/回读校验失败(可能被其它进程长期占用),本次粘贴中止"
}

function Send-CommandText {
    # 把一条命令送进终端。
    #   inputMode=wmchar(可选):直接向控制台窗口 PostMessage WM_CHAR —— 绕开剪贴板
    #     (同机其它会话会抢写剪贴板)与输入法(中文输入法会把键入变成拼音候选);
    #   默认剪贴板粘贴;typing=true 时逐字 SendKeys(需要系统处于英文输入状态)。
    param([string]$Text, [bool]$Typing)
    if ($script:inputMode -eq "console" -and $script:targetPid -gt 0) {
        # 直接写目标控制台输入缓冲区:与前台焦点无关,最稳
        $err = [WinApi]::WriteConsoleLine([uint32]$script:targetPid, $Text)
        if ($err -ne "") {
            Write-Output ("[warn] 控制台注入失败 ($err),本条命令可能未送达")
        }
        return
    }
    if ($script:inputMode -eq "unicode" -and $script:targetWindow -ne [IntPtr]::Zero) {
        Claim-Window $script:targetWindow
        foreach ($ch in $Text.ToCharArray()) {
            [WinApi]::SendUnicodeChar($ch) | Out-Null
            Start-Sleep -Milliseconds (Get-Random -Minimum 6 -Maximum 18)
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 400)
        [WinApi]::SendVirtualKey(0x0D) | Out-Null   # Enter
        return
    }
    if ($script:inputMode -eq "wmchar" -and $script:targetWindow -ne [IntPtr]::Zero) {
        Claim-Window $script:targetWindow
        foreach ($ch in $Text.ToCharArray()) {
            [WinApi]::PostMessageW($script:targetWindow, 0x0102, [IntPtr][int][char]$ch, [IntPtr]::Zero) | Out-Null
            Start-Sleep -Milliseconds (Get-Random -Minimum 6 -Maximum 18)
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 400)
        [WinApi]::PostMessageW($script:targetWindow, 0x0102, [IntPtr]13, [IntPtr]::Zero) | Out-Null
        return
    }
    if ($script:targetWindow -and $script:targetWindow -ne [IntPtr]::Zero) {
        Claim-Window $script:targetWindow   # 抢回前台,否则按键会落进别的会话窗口
    }
    if ($Typing) {
        if ($script:inputMode -eq "typing-en" -and $script:targetWindow -ne [IntPtr]::Zero) {
            # 把该窗口的输入语言切到 en-US:中文输入法按窗口生效,切掉它,
            # 逐字 SendKeys 就不会被拼成拼音候选。全程不碰剪贴板。
            $hkl = [WinApi]::LoadKeyboardLayoutW("00000409", 0x00000001)
            if ($hkl -ne [IntPtr]::Zero) {
                [WinApi]::PostMessageW($script:targetWindow, 0x0050, [IntPtr]::Zero, $hkl) | Out-Null
                Start-Sleep -Milliseconds 350
            }
        }
        foreach ($ch in $Text.ToCharArray()) {
            $s = "$ch"
            if ($ch -match '[+^%~(){}\[\]]') { $s = "{$ch}" }
            [System.Windows.Forms.SendKeys]::SendWait($s)
            Start-Sleep -Milliseconds (Get-Random -Minimum 8 -Maximum 35)
        }
    }
    else {
        Set-ClipboardWithRetry -Text $Text
        Start-Sleep -Milliseconds 30      # 回读校验刚做完,尽快粘贴以缩小被抢写窗口
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
    Claim-Window $h
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
$script:inputMode = if ($cfg.inputMode) { [string]$cfg.inputMode } else { "clipboard" }
$script:targetWindow = [IntPtr]::Zero
$script:targetPid = 0

# 保存用户剪贴板,结束时恢复
$savedClip = $null
try { $savedClip = Get-Clipboard -Raw } catch { $savedClip = $null }

try {
    # 记录截图前已存在的顶层窗口
    $before = [WinApi]::VisibleWindows()

    # 启动真实终端(系统默认终端宿主:conhost 或 Windows Terminal 均可)
    # windowTitle 可选:给出时用唯一标题启动,并把窗口选择锁定到该标题,
    # 避免同一台机器上其它会话新开的 PowerShell 窗口被误当成目标窗口。
    $titleFilter = if ($cfg.windowTitle) { [string]$cfg.windowTitle } else { $null }
    if ($titleFilter) {
        $proc = Start-Process $shellName -PassThru -ArgumentList @(
            "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = '$titleFilter'"
        )
    }
    else {
        $proc = Start-Process $shellName -PassThru
    }
    $procNames = @($shellName -replace '\.exe$', '') + @("WindowsTerminal", "OpenConsole", "conhost")

    $hwnd = Find-NewTerminalWindow -BeforeSet $before -ProcessNames $procNames -TitleFilter $titleFilter
    if ($hwnd -eq [IntPtr]::Zero) { throw "未能找到新开的终端窗口" }
    $script:targetWindow = $hwnd   # 后续发命令/截图前都用它抢回前台
    $script:targetPid = $proc.Id   # inputMode=console 时直接写这个进程的控制台

    # 像人一样:拉到前台,摆个合适的尺寸
    Start-Sleep -Milliseconds 800
    [WinApi]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
    Claim-Window $hwnd
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
