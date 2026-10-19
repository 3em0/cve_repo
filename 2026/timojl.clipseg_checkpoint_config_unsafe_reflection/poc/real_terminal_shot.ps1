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
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] public static extern bool FreeConsole();
    [DllImport("kernel32.dll")] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] buf, uint len, out uint written);
    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
    public const uint SWP_NOMOVE = 0x0002;
    public const uint SWP_NOSIZE = 0x0004;
    public const uint SWP_SHOWWINDOW = 0x0040;
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

[StructLayout(LayoutKind.Sequential)]
public struct KEY_EVENT_RECORD {
    public int bKeyDown; public ushort wRepeatCount; public ushort wVirtualKeyCode;
    public ushort wVirtualScanCode; public char UnicodeChar; public uint dwControlKeyState;
}

[StructLayout(LayoutKind.Sequential)]
public struct INPUT_RECORD { public ushort EventType; public ushort pad; public KEY_EVENT_RECORD KeyEvent; }

public static class Inject {
    // 把一整行(含回车)做成真实键盘事件记录:控制键状态显式写 0,
    // 因此不会像 WM_CHAR 那样受全局键盘状态影响(别的会话按住 Ctrl 时字符会被掩成控制符)
    public static INPUT_RECORD[] Make(string text) {
        var list = new System.Collections.Generic.List<INPUT_RECORD>();
        foreach (char c in text) { list.Add(Key(true, 0, c)); list.Add(Key(false, 0, c)); }
        list.Add(Key(true, 0x0D, '\r')); list.Add(Key(false, 0x0D, '\r'));
        return list.ToArray();
    }
    static INPUT_RECORD Key(bool down, ushort vk, char c) {
        var r = new INPUT_RECORD();
        r.EventType = 1;
        r.KeyEvent.bKeyDown = down ? 1 : 0;
        r.KeyEvent.wRepeatCount = 1;
        r.KeyEvent.wVirtualKeyCode = vk;
        r.KeyEvent.wVirtualScanCode = 0;
        r.KeyEvent.UnicodeChar = c;
        r.KeyEvent.dwControlKeyState = 0;
        return r;
    }
}
"@

[WinApi]::SetProcessDPIAware() | Out-Null

function Get-WindowPid {
    param([IntPtr]$h)
    $p = 0
    [WinApi]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
    return [int]$p
}

function Get-WindowTitle {
    param([IntPtr]$h)
    $sb = New-Object System.Text.StringBuilder 256
    [void][WinApi]::GetWindowText($h, $sb, 256)
    return $sb.ToString()
}

function Show-VisibleWindowDump {
    # 找不到终端时把桌面上的可见窗口列出来,便于定位(不截图,只打印)
    Write-Output "--- visible windows ---"
    foreach ($h in [WinApi]::VisibleWindows()) {
        $r = New-Object WinApi+RECT
        [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
        $w = $r.Right - $r.Left
        $ht = $r.Bottom - $r.Top
        if ($w -lt 100 -or $ht -lt 100) { continue }
        Write-Output ("  pid=" + (Get-WindowPid $h) + " " + [WinApi]::ProcNameOf($h) + " " + $w + "x" + $ht + " '" + (Get-WindowTitle $h) + "'")
    }
    Write-Output "--- end ---"
}

function Get-ProcessFamily {
    # 我们启动的 powershell 可能由 conhost / OpenConsole / WindowsTerminal 托管,
    # 窗口所属进程是它的祖先(WT 场景)或它自己(conhost 场景)。只认这条进程链,
    # 避免把桌面上同时出现的其它 PowerShell 窗口误当成自己的终端。
    param([int]$RootPid)
    $procs = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction SilentlyContinue
    $byId = @{}
    foreach ($p in $procs) { $byId[[int]$p.ProcessId] = [int]$p.ParentProcessId }
    $family = New-Object 'System.Collections.Generic.HashSet[int]'
    [void]$family.Add($RootPid)
    $cur = $RootPid
    for ($i = 0; $i -lt 8; $i++) {
        if (-not $byId.ContainsKey($cur)) { break }
        $par = $byId[$cur]
        if ($par -le 0 -or $family.Contains($par)) { break }
        [void]$family.Add($par)
        $cur = $par
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($k in @($byId.Keys)) {
            if ($family.Contains([int]$byId[$k]) -and -not $family.Contains([int]$k)) {
                [void]$family.Add([int]$k)
                $changed = $true
            }
        }
    }
    return $family
}

function Find-TerminalWindow {
    # 优先按唯一标题找:Windows Terminal 会把新标签托管的窗口标题设成标签标题,
    # 这种情况下窗口属于一个*已存在*的 WindowsTerminal 进程,pid 链与进程快照都不可靠。
    param($BeforeSet, $ProcessNames, $Family, $TitleToken)
    $deadline = (Get-Date).AddSeconds(15)
    $fallback = [IntPtr]::Zero
    while ((Get-Date) -lt $deadline) {
        foreach ($h in [WinApi]::VisibleWindows()) {
            $r = New-Object WinApi+RECT
            [WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
            if (($r.Right - $r.Left) -lt 200 -or ($r.Bottom - $r.Top) -lt 150) { continue }
            if ($TitleToken -and (Get-WindowTitle $h) -like "*$TitleToken*") { return $h }
            $pname = [WinApi]::ProcNameOf($h)
            if ($ProcessNames -notcontains $pname) { continue }
            if (-not ($Family -contains (Get-WindowPid $h))) { continue }
            if ($BeforeSet -notcontains $h) { return $h }
            if ($fallback -eq [IntPtr]::Zero) { $fallback = $h }
        }
        Start-Sleep -Milliseconds 250
    }
    return $fallback
}

function Focus-Window {
    param([IntPtr]$h)
    # 先敲一下 ALT,解除 SetForegroundWindow 的前台锁
    [WinApi]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
    [WinApi]::SetForegroundWindow($h) | Out-Null
    [WinApi]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
    # 前台锁更顽固时:把当前前台线程与本线程挂到目标窗口的输入队列上再抢
    $fg = [WinApi]::GetForegroundWindow()
    if ($fg -ne $h) {
        $pidFg = 0; $pidT = 0
        $thFg = if ($fg -ne [IntPtr]::Zero) { [WinApi]::GetWindowThreadProcessId($fg, [ref]$pidFg) } else { 0 }
        $thT = [WinApi]::GetWindowThreadProcessId($h, [ref]$pidT)
        $me = [WinApi]::GetCurrentThreadId()
        $attached = @()
        foreach ($t in @($thFg, $me)) {
            if ($t -ne 0 -and $t -ne $thT -and $attached -notcontains $t) {
                [WinApi]::AttachThreadInput($t, $thT, $true) | Out-Null
                $attached += $t
            }
        }
        [WinApi]::ShowWindow($h, 9) | Out-Null
        [WinApi]::BringWindowToTop($h) | Out-Null
        [WinApi]::SetForegroundWindow($h) | Out-Null
        [WinApi]::SetFocus($h) | Out-Null
        foreach ($t in $attached) { [WinApi]::AttachThreadInput($t, $thT, $false) | Out-Null }
    }
    Start-Sleep -Milliseconds 200
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

function Assert-TerminalFocus {
    # 安全闸:SendKeys 只会送给前台窗口。桌面同时开着别的会话时,抢不到前台就宁可不敲,
    # 绝不能把命令打进别人的终端。
    param([IntPtr]$h)
    for ($i = 0; $i -lt 12; $i++) {
        if ([WinApi]::GetForegroundWindow() -eq $h) { return $true }
        Focus-Window $h
        Start-Sleep -Milliseconds 300
    }
    return ([WinApi]::GetForegroundWindow() -eq $h)
}

function Send-ConsoleInput {
    # 首选输入路径:AttachConsole + WriteConsoleInput,把整行(含回车)作为真实键盘事件写进目标控制台。
    # 不依赖前台焦点,也不依赖全局键盘状态 —— 这台桌面上同时跑着别的 agent 会话,
    # 它们用 SendKeys/剪贴板时会抢焦点、按住 Ctrl,导致 WM_CHAR 注入的字符被掩成控制符(实测 'e' 变 ^E)。
    param([int]$ConsolePid, [string]$Text)
    if ($ConsolePid -le 0) { return $false }
    [void][WinApi]::FreeConsole()
    if (-not [WinApi]::AttachConsole([uint32]$ConsolePid)) { return $false }
    $hIn = [WinApi]::CreateFileW('CONIN$', [uint32]3221225472, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($hIn -eq [IntPtr]::Zero -or $hIn -eq [IntPtr](-1)) { [void][WinApi]::FreeConsole(); return $false }
    $records = [Inject]::Make($Text)
    $written = 0
    $ok = [WinApi]::WriteConsoleInputW($hIn, $records, [uint32]$records.Length, [ref]$written)
    [void][WinApi]::FreeConsole()
    return ($ok -and $written -eq $records.Length)
}

function Send-CommandText {
    # 输入优先级:WriteConsoleInput(最忠实、无焦点依赖) > WM_CHAR/WM_KEYDOWN 注入 > SendKeys 兜底。
    param([string]$Text, [bool]$Typing)
    $h = $script:TermHwnd
    if (-not $Typing -and $script:ConsolePid -gt 0) {
        if (Send-ConsoleInput -ConsolePid $script:ConsolePid -Text $Text) { return }
        Write-Output "WARN WriteConsoleInput 失败,退回 WM_CHAR 注入"
    }
    if ($h -ne [IntPtr]::Zero -and -not $Typing) {
        foreach ($ch in $Text.ToCharArray()) {
            [void][WinApi]::SendMessageW($h, 0x0102, [IntPtr][int][char]$ch, [IntPtr]1)   # WM_CHAR
            Start-Sleep -Milliseconds (Get-Random -Minimum 35 -Maximum 50)
        }
        Start-Sleep -Milliseconds 250
        [void][WinApi]::SendMessage($h, 0x0100, [IntPtr]0x0D, [IntPtr]0x001C0001)        # WM_KEYDOWN VK_RETURN
        [void][WinApi]::SendMessage($h, 0x0101, [IntPtr]0x0D, [IntPtr]0xC01C0001)        # WM_KEYUP   VK_RETURN
        return
    }
    if ($script:TermHwnd -ne [IntPtr]::Zero) {
        if (-not (Assert-TerminalFocus -h $script:TermHwnd)) {
            throw "终端窗口抢不到前台,已中止输入(避免把命令打进其它窗口)"
        }
    }
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
    # 不置顶、不抢前台:实测对 conhost 窗口调 SetWindowPos(HWND_TOPMOST) 会把窗口压成 0x0,
    # 而 CopyFromScreen 在窗口被别的会话盖住时只会拍到遮挡窗口的像素。
    # PrintWindow(PW_RENDERFULLCONTENT) 直接取窗口自身的绘制结果,被盖住也能拿到干净画面。
    [void][WinApi]::SendMessage($h, 0x0114, [IntPtr]6, [IntPtr]::Zero)   # WM_HSCROLL SB_LEFT:把横向视口拉回最左
    Start-Sleep -Milliseconds 250
    $r = Get-WindowBoundsPixels $h
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    if ($w -lt 50 -or $ht -lt 50 -or $w -gt 20000 -or $ht -gt 20000) {
        # 被最小化或被系统挪走时先还原再重测
        [WinApi]::ShowWindow($h, 9) | Out-Null
        Start-Sleep -Milliseconds 600
        $r = Get-WindowBoundsPixels $h
        $w = $r.Right - $r.Left
        $ht = $r.Bottom - $r.Top
        Write-Output ("shot retry rect " + $w + "x" + $ht)
    }
    if ($w -lt 50 -or $ht -lt 50 -or $w -gt 20000 -or $ht -gt 20000) {
        throw ("窗口尺寸异常,拒绝截图: " + $w + "x" + $ht)
    }
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [WinApi]::PrintWindow($h, $hdc, 2)   # PW_RENDERFULLCONTENT
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    if (-not $ok) {
        Write-Output ("WARN PrintWindow 失败,退回屏幕截取: " + (Split-Path $Path -Leaf))
        $g2 = [System.Drawing.Graphics]::FromImage($bmp)
        $g2.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $ht)))
        $g2.Dispose()
    }
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("shot " + (Split-Path $Path -Leaf) + " " + $w + "x" + $ht + " printwindow=" + $ok)
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

$script:TermHwnd = [IntPtr]::Zero
$script:ConsolePid = 0

try {
    # 记录截图前已存在的顶层窗口
    $before = [WinApi]::VisibleWindows()

    # 启动真实终端。显式用 conhost 承载,避免 Windows Terminal 把新会话挂成已有窗口的标签页
    # (那样窗口属于别的进程,既认领不到,也会连累桌面上同时运行的其它会话)
    $titleToken = "CLIPSEG 77c4e2d repro"
    $bootCmd = "`$Host.UI.RawUI.WindowTitle='$titleToken'; try { `$Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(168,3000); `$Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(168,58) } catch { }"
    $shellExe = if ($shellName -match '\.exe$') { $shellName } else { "$shellName.exe" }
    $proc = Start-Process conhost.exe -ArgumentList @($shellExe, '-NoExit', '-NoLogo', '-Command', $bootCmd) -PassThru
    $procNames = @("conhost", "WindowsTerminal", "OpenConsole", "powershell", "pwsh", "cmd")
    Write-Output ("started conhost pid " + $proc.Id + " hosting " + $shellExe + " title '" + $titleToken + "'")

    # 进程树要等新进程真正起来才看得到父链(WT 场景下窗口属于祖先进程)
    $family = $null
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 400
        $family = Get-ProcessFamily -RootPid $proc.Id
        if ($family.Count -gt 1) { break }
    }
    Write-Output ("process family: " + (($family | Sort-Object) -join ','))

    $hwnd = Find-TerminalWindow -BeforeSet $before -ProcessNames $procNames -Family $family -TitleToken $titleToken
    if ($hwnd -eq [IntPtr]::Zero) {
        Show-VisibleWindowDump
        throw "未能找到新开的终端窗口"
    }
    $script:TermHwnd = $hwnd
    $script:ConsolePid = Get-WindowPid $hwnd
    Write-Output ("terminal window pid " + $script:ConsolePid + " title '" + (Get-WindowTitle $hwnd) + "'")

    # 像人一样:拉到前台,摆个合适的尺寸(conhost 已按 168x58 字符网格自适应,够大就不动它)
    Start-Sleep -Milliseconds 800
    [WinApi]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
    Focus-Window $hwnd
    Start-Sleep -Milliseconds 300
    $ww = if ($cfg.windowWidth) { [int]$cfg.windowWidth } else { 1000 }
    $wh = if ($cfg.windowHeight) { [int]$cfg.windowHeight } else { 640 }
    for ($i = 0; $i -lt 4; $i++) {
        $rb = Get-WindowBoundsPixels $hwnd
        $cw = $rb.Right - $rb.Left
        $ch = $rb.Bottom - $rb.Top
        Write-Output ("terminal size " + $cw + "x" + $ch)
        if ($cw -ge [int]($ww * 0.85) -and $ch -ge [int]($wh * 0.85)) { break }
        [WinApi]::MoveWindow($hwnd, 40, 40, $ww, $wh, $true) | Out-Null
        Start-Sleep -Milliseconds 400
    }

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
